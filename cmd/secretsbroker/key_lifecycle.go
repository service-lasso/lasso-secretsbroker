package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	localWrapperVersion = 2
	localWrapperMaxSize = 1 << 20
)

var (
	errInvalidMasterKey     = errors.New("invalid portable master key format")
	errStoreAlreadyExists   = errors.New("local encrypted store already exists")
	errUnsupportedOSWrapper = errors.New("os wrapper provider is unsupported")
	errInvalidWrapper       = errors.New("local key wrapper is invalid")
	errLegacyWrapper        = errors.New("legacy local key wrapper is insecure and must be re-enrolled")
	errWrapperUnavailable   = errors.New("local key wrapper is unavailable for the current user")
	errWrapperAccess        = errors.New("local key wrapper permissions are not private")
	errOneTimeRevealMissing = errors.New("generated bootstrap requires explicit one-time reveal")
)

type vaultRootIdentityMetadata struct {
	VaultID             string              `json:"vaultId"`
	RootActorID         string              `json:"rootActorId"`
	CreatedAt           time.Time           `json:"createdAt"`
	BootstrapSource     string              `json:"bootstrapSource"`
	KeySourceType       string              `json:"keySourceType"`
	KeyID               string              `json:"keyId"`
	KeyVersion          string              `json:"keyVersion"`
	LocalMachineContext localMachineContext `json:"localMachineContext"`
	LossSemantics       vaultLossSemantics  `json:"lossSemantics"`
	AuditExpectations   []string            `json:"auditExpectations"`
}

type localMachineContext struct {
	OS       string `json:"os"`
	Username string `json:"username,omitempty"`
	Machine  string `json:"machine,omitempty"`
}

type vaultLossSemantics struct {
	RecoverableWithoutKey bool   `json:"recoverableWithoutKey"`
	NextAction            string `json:"nextAction"`
	Message               string `json:"message"`
}

type bootstrapKeyMetadata struct {
	KeyID                  string             `json:"keyId"`
	KeyVersion             string             `json:"keyVersion"`
	SourceType             string             `json:"sourceType"`
	Fingerprint            string             `json:"fingerprint"`
	Generated              bool               `json:"generated"`
	OneTimeRevealAvailable bool               `json:"oneTimeRevealAvailable"`
	LossSemantics          vaultLossSemantics `json:"lossSemantics"`
}

type bootstrapOneTimeReveal struct {
	MasterKey string `json:"masterKey"`
	Warning   string `json:"warning"`
}

type localKeyWrapper struct {
	Version     int       `json:"version"`
	ServiceID   string    `json:"serviceId"`
	APIVersion  string    `json:"apiVersion"`
	KeyID       string    `json:"keyId"`
	KeyVersion  string    `json:"keyVersion"`
	WrapperKind string    `json:"wrapperKind"`
	OS          string    `json:"os"`
	User        string    `json:"user"`
	Machine     string    `json:"machine"`
	Alg         string    `json:"alg"`
	Ciphertext  string    `json:"ciphertext"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type keyLifecycleResponse struct {
	ServiceID        string                     `json:"serviceId"`
	APIVersion       string                     `json:"apiVersion"`
	Outcome          string                     `json:"outcome"`
	State            string                     `json:"state"`
	Ready            bool                       `json:"ready"`
	KeyID            string                     `json:"keyId,omitempty"`
	KeyVersion       string                     `json:"keyVersion,omitempty"`
	StorePath        string                     `json:"storePath,omitempty"`
	WrapperPath      string                     `json:"wrapperPath,omitempty"`
	Wrapper          *wrapperStatusDetail       `json:"wrapper,omitempty"`
	RootIdentity     *vaultRootIdentityMetadata `json:"rootIdentity,omitempty"`
	BootstrapKey     *bootstrapKeyMetadata      `json:"bootstrapKey,omitempty"`
	OneTimeReveal    *bootstrapOneTimeReveal    `json:"oneTimeReveal,omitempty"`
	SecretCount      int                        `json:"secretCount"`
	NextAction       string                     `json:"nextAction"`
	RecoveryGuidance string                     `json:"recoveryGuidance"`
}

type wrapperStatusDetail struct {
	Available     bool   `json:"available"`
	Supported     bool   `json:"supported"`
	WrapperKind   string `json:"wrapperKind"`
	OS            string `json:"os"`
	User          string `json:"user,omitempty"`
	Machine       string `json:"machine,omitempty"`
	KeyID         string `json:"keyId,omitempty"`
	KeyVersion    string `json:"keyVersion,omitempty"`
	State         string `json:"state"`
	NextAction    string `json:"nextAction"`
	FailureReason string `json:"failureReason,omitempty"`
}

type wrapperContext struct {
	OS          string
	User        string
	Machine     string
	Kind        string
	Supported   bool
	Unsupported string
}

func runKeyInitialize(args []string) error {
	fs := flag.NewFlagSet("key initialize", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	audit := addAuditCommandOptions(fs)
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	generate := fs.Bool("generate", false, "generate a portable master key when no key is supplied")
	oneTimeReveal := fs.Bool("one-time-reveal", false, "include generated key material in this initialize response only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterial(*masterKey, *masterKeyFile)
	if errors.Is(err, errLocked) && *generate {
		generated, genErr := generatePortableMasterKey()
		if genErr != nil {
			return genErr
		}
		material = keyMaterial{Value: generated, Source: "generated"}
	} else if err != nil {
		return err
	}
	if material.Source == "generated" && !*oneTimeReveal {
		return errOneTimeRevealMissing
	}
	backend := audit.newBackend(*storePath, material.Value)
	res, err := backend.initializeStoreWithSource(material.Value, material.Source, *oneTimeReveal)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runKeyUnlock(args []string) error {
	fs := flag.NewFlagSet("key unlock", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	audit := addAuditCommandOptions(fs)
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterialWithWrapper(*masterKey, *masterKeyFile, *wrapperPath)
	if err != nil {
		return err
	}
	backend := audit.newBackend(*storePath, material.Value)
	res, err := backend.unlockWithMasterKey(material.Value)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runKeyImport(args []string) error {
	return runKeyWrapOperation("key import", args, "key_import")
}

func runKeyRewrap(args []string) error {
	return runKeyWrapOperation("key rewrap", args, "key_rewrap")
}

func runKeyWrapOperation(name string, args []string, operation string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	audit := addAuditCommandOptions(fs)
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path")
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	osName := fs.String("os", runtime.GOOS, "wrapper OS override for validation/testing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterial(*masterKey, *masterKeyFile)
	if err != nil {
		return err
	}
	backend := audit.newBackend(*storePath, material.Value)
	res, err := backend.importOrRewrapMasterKey(*wrapperPath, material.Value, wrapperContextFor(*osName), operation)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runKeyWrapperStatus(args []string) error {
	fs := flag.NewFlagSet("key wrapper-status", flag.ContinueOnError)
	audit := addAuditCommandOptions(fs)
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path")
	osName := fs.String("os", runtime.GOOS, "wrapper OS override for validation/testing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	backend := audit.newBackend(defaultStorePath(), "")
	res := wrapperStatusResponse(*wrapperPath, wrapperContextFor(*osName))
	_ = backend.audit("key_wrapper_status", "", res.Outcome, "", "")
	return encodeIndented(os.Stdout, res)
}

func (b *localBackend) initializeStore(masterKey string) (keyLifecycleResponse, error) {
	return b.initializeStoreWithSource(masterKey, "supplied", false)
}

func (b *localBackend) initializeStoreWithSource(masterKey, keySourceType string, revealGenerated bool) (keyLifecycleResponse, error) {
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	keySourceType = normalizeBootstrapKeySource(keySourceType)
	if err := validatePortableMasterKey(masterKey); err != nil {
		_ = b.audit("key_initialize", "", "locked", "", "")
		return keyLifecycleResponse{}, err
	}
	if _, err := os.Stat(b.storePath); err == nil {
		_ = b.audit("key_initialize", "", "degraded", "", "")
		return keyLifecycleResponse{}, errStoreAlreadyExists
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = b.audit("key_initialize", "", "degraded", "", "")
		return keyLifecycleResponse{}, err
	}
	keyID := masterKeyID(masterKey)
	now := b.now()
	vaultID := vaultIDFor(keyID, b.storePath)
	rootIdentity := rootIdentityFor(vaultID, keyID, keySourceType, now)
	store := localStoreFile{Version: localStoreVersion, ServiceID: serviceID, VaultID: vaultID, KeyID: keyID, KeyVersion: masterKeyVersion, RootIdentity: &rootIdentity, CreatedAt: now, UpdatedAt: now, Secrets: map[string]secretEntry{}, Tombstones: map[string]localSecretTombstone{}}
	if err := b.saveStore(store); err != nil {
		_ = b.audit("key_initialize", "", "degraded", "", "")
		return keyLifecycleResponse{}, errBackendDegraded
	}
	_ = b.writeAuditEvent(auditEvent{TS: now, Operation: "key_initialize", KeyID: keyID, Outcome: "ready", State: "ready"})
	if keySourceType == "generated" {
		_ = b.writeAuditEvent(auditEvent{TS: now, Operation: "key_generated", KeyID: keyID, Outcome: "ready"})
	} else {
		_ = b.writeAuditEvent(auditEvent{TS: now, Operation: "supplied_key_used", KeyID: keyID, Outcome: "ready"})
	}
	_ = b.writeAuditEvent(auditEvent{TS: now, Operation: "vault_created", KeyID: keyID, Outcome: "ready", State: "ready"})
	_ = b.writeAuditEvent(auditEvent{TS: now, Operation: "root_identity_created", KeyID: keyID, Outcome: "ready", State: rootIdentity.RootActorID})
	_ = b.writeAuditEvent(auditEvent{TS: now, Operation: "setup_completed", KeyID: keyID, Outcome: "ready", State: "ready"})
	bootstrapKey := bootstrapKeyFor(masterKey, keySourceType, revealGenerated)
	res := keyLifecycleResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", State: "ready", Ready: true, KeyID: keyID, KeyVersion: masterKeyVersion, StorePath: b.storePath, RootIdentity: &rootIdentity, BootstrapKey: &bootstrapKey, SecretCount: 0, NextAction: "import_or_rewrap_for_local_os", RecoveryGuidance: "Store the portable master key securely, separately from encrypted store backups. If this key is lost without recovery material, recreate the vault and old encrypted secrets are not recoverable."}
	if keySourceType == "generated" && revealGenerated {
		res.OneTimeReveal = &bootstrapOneTimeReveal{MasterKey: strings.TrimSpace(masterKey), Warning: "One-time reveal only. Store this portable vault key now; the broker will not persist or re-reveal it."}
	}
	return res, nil
}

func (b *localBackend) unlockWithMasterKey(masterKey string) (keyLifecycleResponse, error) {
	if err := validatePortableMasterKey(masterKey); err != nil {
		_ = b.audit("key_unlock", "", "locked", "", "")
		return keyLifecycleResponse{}, err
	}
	b.masterKey = strings.TrimSpace(masterKey)
	state, secretCount, err := b.validateStoreForKey()
	if err != nil {
		_ = b.audit("key_unlock", "", state, "", "")
		_ = b.writeAuditEvent(auditEvent{TS: b.now(), Operation: "vault_unlock_failure", KeyID: masterKeyID(masterKey), Outcome: state, State: state})
		return keyLifecycleResponse{}, err
	}
	_ = b.audit("key_unlock", "", "ready", "", "")
	return keyLifecycleResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", State: "ready", Ready: true, KeyID: masterKeyID(masterKey), KeyVersion: masterKeyVersion, StorePath: b.storePath, SecretCount: secretCount, NextAction: "operate_or_rewrap_for_local_os", RecoveryGuidance: "If this machine should unlock without manual key entry, run key import or key rewrap for the current OS/user wrapper."}, nil
}

func normalizeBootstrapKeySource(source string) string {
	source = strings.TrimSpace(source)
	switch source {
	case "generated":
		return "generated"
	case "file":
		return "supplied_file"
	case "flag/env":
		return "supplied"
	default:
		if source == "" || source == "none" {
			return "supplied"
		}
		return scrubAuditField(source)
	}
}

func vaultIDFor(keyID, storePath string) string {
	sum := sha256.Sum256([]byte(serviceID + ":" + strings.TrimSpace(keyID) + ":" + filepath.Clean(storePath)))
	return "vault-" + hex.EncodeToString(sum[:])[:16]
}

func rootIdentityFor(vaultID, keyID, keySourceType string, createdAt time.Time) vaultRootIdentityMetadata {
	ctx := wrapperContextFor(runtime.GOOS)
	sum := sha256.Sum256([]byte(serviceID + ":root-owner:" + vaultID + ":" + keyID))
	return vaultRootIdentityMetadata{
		VaultID:         vaultID,
		RootActorID:     "root-" + hex.EncodeToString(sum[:])[:16],
		CreatedAt:       createdAt.UTC(),
		BootstrapSource: "key_initialize",
		KeySourceType:   keySourceType,
		KeyID:           keyID,
		KeyVersion:      masterKeyVersion,
		LocalMachineContext: localMachineContext{
			OS:       ctx.OS,
			Username: ctx.User,
			Machine:  ctx.Machine,
		},
		LossSemantics:     defaultVaultLossSemantics(),
		AuditExpectations: []string{"vault_created", "root_identity_created", "key_generated", "supplied_key_used", "setup_completed", "vault_unlock_failure"},
	}
}

func bootstrapKeyFor(masterKey, source string, revealAvailable bool) bootstrapKeyMetadata {
	source = normalizeBootstrapKeySource(source)
	return bootstrapKeyMetadata{
		KeyID:                  masterKeyID(masterKey),
		KeyVersion:             masterKeyVersion,
		SourceType:             source,
		Fingerprint:            masterKeyID(masterKey),
		Generated:              source == "generated",
		OneTimeRevealAvailable: source == "generated" && revealAvailable,
		LossSemantics:          defaultVaultLossSemantics(),
	}
}

func defaultVaultLossSemantics() vaultLossSemantics {
	return vaultLossSemantics{
		RecoverableWithoutKey: false,
		NextAction:            "recreate_vault_if_key_and_recovery_are_lost",
		Message:               "If the vault key is lost and no managed recovery material exists, the vault cannot be unlocked; recreate the vault and old encrypted secrets are not recoverable.",
	}
}

func (b *localBackend) importOrRewrapMasterKey(wrapperPath, masterKey string, ctx wrapperContext, operation string) (keyLifecycleResponse, error) {
	return b.importOrRewrapMasterKeyWithProvider(wrapperPath, masterKey, ctx, operation, platformKeyWrapperProvider())
}

func (b *localBackend) importOrRewrapMasterKeyWithProvider(wrapperPath, masterKey string, ctx wrapperContext, operation string, provider keyWrapperProvider) (keyLifecycleResponse, error) {
	if !ctx.Supported {
		_ = b.audit(operation, "", "degraded", "", "")
		return keyLifecycleResponse{}, errUnsupportedOSWrapper
	}
	if err := validatePortableMasterKey(masterKey); err != nil {
		_ = b.audit(operation, "", "locked", "", "")
		return keyLifecycleResponse{}, err
	}
	b.masterKey = strings.TrimSpace(masterKey)
	state, secretCount, err := b.validateStoreForKey()
	if err != nil {
		_ = b.audit(operation, "", state, "", "")
		return keyLifecycleResponse{}, err
	}
	wrapper, err := wrapMasterKeyWithProvider(wrapperPath, masterKey, ctx, b.now(), provider)
	if err != nil {
		_ = b.audit(operation, "", "degraded", "", "")
		return keyLifecycleResponse{}, err
	}
	_ = b.audit(operation, "", "ready", "", "")
	detail := wrapper.detail(true, "ready", "")
	return keyLifecycleResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", State: "ready", Ready: true, KeyID: wrapper.KeyID, KeyVersion: wrapper.KeyVersion, StorePath: b.storePath, WrapperPath: wrapperPath, Wrapper: &detail, SecretCount: secretCount, NextAction: "operate_normally", RecoveryGuidance: "Keep the portable master key in secure offline storage; this wrapper is only for the current OS/user/machine."}, nil
}

func (b *localBackend) validateStoreForKey() (string, int, error) {
	if b.locked() {
		return "locked", 0, errLocked
	}
	if _, err := os.Stat(b.storePath); errors.Is(err, os.ErrNotExist) {
		return "setup_needed", 0, errMissingRef
	}
	store, err := b.loadStore()
	if err != nil {
		return "degraded", 0, errBackendDegraded
	}
	if store.KeyID != "" && store.KeyID != masterKeyID(b.masterKey) {
		return "locked", len(store.Secrets), errInvalidBackupKey
	}
	if store.KeyVersion != "" && store.KeyVersion != masterKeyVersion {
		return "locked", len(store.Secrets), errInvalidBackupKey
	}
	for _, entry := range store.Secrets {
		if entry.Payload.KeyID != "" && entry.Payload.KeyID != masterKeyID(b.masterKey) {
			return "locked", len(store.Secrets), errInvalidBackupKey
		}
		if _, err := b.decrypt(entry.Payload); err != nil {
			return "degraded", len(store.Secrets), errBackendDegraded
		}
	}
	return "ready", len(store.Secrets), nil
}

func validatePortableMasterKey(masterKey string) error {
	masterKey = strings.TrimSpace(masterKey)
	if masterKey == "" {
		return errLocked
	}
	decoded, err := base64.RawURLEncoding.DecodeString(masterKey)
	if err != nil || len(decoded) != 32 {
		return errInvalidMasterKey
	}
	return nil
}

func defaultWrapperPath() string { return filepath.Join("data", "secretsbroker-wrapper.json") }

func wrapperContextFor(osName string) wrapperContext {
	ctx := wrapperContext{OS: strings.TrimSpace(osName), Supported: true}
	if ctx.OS == "" {
		ctx.OS = runtime.GOOS
	}
	switch {
	case ctx.OS == "windows" && runtime.GOOS == "windows":
		ctx.Kind = "dpapi-user-scope"
	default:
		ctx.Kind = "unsupported"
		ctx.Supported = false
		ctx.Unsupported = "No implemented OS keystore wrapper is available on this host. Use explicit portable-key unlock/import until provider support exists."
	}
	if current, err := user.Current(); err == nil && current != nil {
		ctx.User = firstNonEmpty(current.Username, current.Uid)
	}
	if host, err := os.Hostname(); err == nil {
		ctx.Machine = host
	}
	return ctx
}

func wrapperStatusResponse(path string, ctx wrapperContext) keyLifecycleResponse {
	detail := wrapperStatus(path, ctx)
	state := detail.State
	outcome := state
	if !detail.Supported {
		outcome = "degraded"
	} else if !detail.Available {
		outcome = "locked"
	}
	return keyLifecycleResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: outcome, State: state, Ready: state == "ready", WrapperPath: path, Wrapper: &detail, NextAction: detail.NextAction, RecoveryGuidance: recoveryGuidanceForWrapper(detail)}
}

func wrapperStatus(path string, ctx wrapperContext) wrapperStatusDetail {
	return wrapperStatusWithProvider(path, ctx, platformKeyWrapperProvider())
}

func wrapperStatusWithProvider(path string, ctx wrapperContext, provider keyWrapperProvider) wrapperStatusDetail {
	if !ctx.Supported {
		return wrapperStatusDetail{Available: false, Supported: false, WrapperKind: ctx.Kind, OS: ctx.OS, State: "degraded", NextAction: "use_portable_key_unlock", FailureReason: ctx.Unsupported}
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return wrapperStatusDetail{Available: false, Supported: true, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, State: "locked", NextAction: "import_portable_key"}
	} else if err != nil {
		return wrapperStatusDetail{Available: true, Supported: true, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, State: "degraded", NextAction: "import_portable_key", FailureReason: "wrapper metadata could not be read"}
	}
	// Converge owner and DACL state before reading even safe wrapper metadata.
	// This prevents status inspection from bypassing upgrade repair or exposing
	// metadata from a path whose private-custody state cannot be proven.
	if err := provider.SecurePath(filepath.Dir(path), true); err != nil {
		return wrapperStatusDetail{Available: true, Supported: true, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, State: "degraded", NextAction: "import_portable_key", FailureReason: wrapperFailureReason(errWrapperAccess)}
	}
	if err := provider.SecurePath(path, false); err != nil {
		return wrapperStatusDetail{Available: true, Supported: true, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, State: "degraded", NextAction: "import_portable_key", FailureReason: wrapperFailureReason(errWrapperAccess)}
	}
	wrapper, err := readLocalKeyWrapper(path)
	if err != nil {
		return wrapperStatusDetail{Available: true, Supported: true, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, State: "degraded", NextAction: "import_portable_key", FailureReason: "wrapper metadata could not be read"}
	}
	key, err := unwrapMasterKeyWithProvider(path, ctx, provider)
	if err != nil {
		return wrapperStatusDetail{Available: true, Supported: true, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, KeyID: wrapper.KeyID, KeyVersion: wrapper.KeyVersion, State: "degraded", NextAction: "import_portable_key", FailureReason: wrapperFailureReason(err)}
	}
	zeroBytes(key)
	return wrapper.detail(true, "ready", "")
}

func (w localKeyWrapper) detail(available bool, state string, failure string) wrapperStatusDetail {
	next := "operate_normally"
	if state == "degraded" || state == "locked" {
		next = "import_portable_key"
	}
	return wrapperStatusDetail{Available: available, Supported: true, WrapperKind: w.WrapperKind, OS: w.OS, User: w.User, Machine: w.Machine, KeyID: w.KeyID, KeyVersion: w.KeyVersion, State: state, NextAction: next, FailureReason: failure}
}

func recoveryGuidanceForWrapper(detail wrapperStatusDetail) string {
	if !detail.Supported {
		return "Use a portable master-key file/env/flag on this OS until a supported wrapper provider is available."
	}
	if !detail.Available || detail.State == "locked" {
		return "Import the matching portable master key to enroll this machine's local wrapper."
	}
	if detail.State == "degraded" {
		return "Re-import the portable master key and re-wrap, or restore wrapper/store metadata from backup."
	}
	return "Local wrapper metadata is present. Keep the portable master key stored separately for recovery."
}

func wrapMasterKey(path, masterKey string, ctx wrapperContext, now time.Time) (localKeyWrapper, error) {
	return wrapMasterKeyWithProvider(path, masterKey, ctx, now, platformKeyWrapperProvider())
}

func wrapMasterKeyWithProvider(path, masterKey string, ctx wrapperContext, now time.Time, provider keyWrapperProvider) (localKeyWrapper, error) {
	if !ctx.Supported {
		return localKeyWrapper{}, errUnsupportedOSWrapper
	}
	if err := validatePortableMasterKey(masterKey); err != nil {
		return localKeyWrapper{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return localKeyWrapper{}, err
	}
	if err := provider.SecurePath(filepath.Dir(path), true); err != nil {
		return localKeyWrapper{}, errWrapperAccess
	}
	plaintext := []byte(strings.TrimSpace(masterKey))
	defer zeroBytes(plaintext)
	protected, err := provider.Protect(plaintext)
	if err != nil {
		return localKeyWrapper{}, errWrapperUnavailable
	}
	defer zeroBytes(protected)
	createdAt := now
	if _, statErr := os.Stat(path); statErr == nil {
		// Existing wrappers can retain an inherited DACL or a different default
		// owner after an OS/toolchain upgrade. Converge the metadata before
		// reading the wrapper, then fail closed if the resulting state is not
		// exactly private.
		if err := provider.SecurePath(path, false); err != nil {
			return localKeyWrapper{}, errWrapperAccess
		}
		if existing, readErr := readLocalKeyWrapper(path); readErr == nil && !existing.CreatedAt.IsZero() {
			createdAt = existing.CreatedAt
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return localKeyWrapper{}, statErr
	}
	wrapper := localKeyWrapper{Version: localWrapperVersion, ServiceID: serviceID, APIVersion: apiVersion, KeyID: masterKeyID(masterKey), KeyVersion: masterKeyVersion, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, Alg: provider.Algorithm(), Ciphertext: base64.StdEncoding.EncodeToString(protected), CreatedAt: createdAt, UpdatedAt: now}
	bytes, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return localKeyWrapper{}, err
	}
	if err := writePrivateWrapperAtomically(path, bytes, provider); err != nil {
		return localKeyWrapper{}, err
	}
	return wrapper, nil
}

func unwrapMasterKey(path string, ctx wrapperContext) ([]byte, error) {
	return unwrapMasterKeyWithProvider(path, ctx, platformKeyWrapperProvider())
}

func unwrapMasterKeyWithProvider(path string, ctx wrapperContext, provider keyWrapperProvider) ([]byte, error) {
	if !ctx.Supported {
		return nil, errUnsupportedOSWrapper
	}
	if _, err := os.Stat(path); err != nil { // #nosec G703 -- the startup-owned wrapper path is secured and validated by the provider immediately below.
		return nil, err
	}
	// SecurePath is idempotent and repairs legacy/default ownership and ACL
	// metadata without reading or rewriting wrapper ciphertext.
	if err := provider.SecurePath(filepath.Dir(path), true); err != nil {
		return nil, errWrapperAccess
	}
	if err := provider.SecurePath(path, false); err != nil {
		return nil, errWrapperAccess
	}
	wrapper, err := readLocalKeyWrapper(path)
	if err != nil {
		return nil, err
	}
	if wrapper.OS != ctx.OS || wrapper.WrapperKind != ctx.Kind || wrapper.User != ctx.User || wrapper.Machine != ctx.Machine || wrapper.Alg != provider.Algorithm() {
		return nil, errInvalidWrapper
	}
	protected, err := base64.StdEncoding.DecodeString(wrapper.Ciphertext)
	if err != nil || len(protected) == 0 {
		return nil, errInvalidWrapper
	}
	defer zeroBytes(protected)
	plaintext, err := provider.Unprotect(protected)
	if err != nil {
		return nil, errWrapperUnavailable
	}
	if err := validatePortableMasterKey(string(plaintext)); err != nil || wrapper.KeyID != masterKeyID(string(plaintext)) || wrapper.KeyVersion != masterKeyVersion {
		zeroBytes(plaintext)
		return nil, errInvalidWrapper
	}
	return plaintext, nil
}

func readLocalKeyWrapper(path string) (localKeyWrapper, error) {
	file, err := openValidatedRegularFile(path, localWrapperMaxSize, true)
	if err != nil {
		return localKeyWrapper{}, err
	}
	defer file.Close()
	bytes, err := io.ReadAll(io.LimitReader(file, localWrapperMaxSize+1))
	if err != nil {
		return localKeyWrapper{}, err
	}
	if len(bytes) > localWrapperMaxSize {
		return localKeyWrapper{}, errInvalidWrapper
	}
	var wrapper localKeyWrapper
	if err := json.Unmarshal(bytes, &wrapper); err != nil {
		return localKeyWrapper{}, errInvalidWrapper
	}
	if wrapper.Version == 1 {
		return localKeyWrapper{}, errLegacyWrapper
	}
	if wrapper.Version != localWrapperVersion || wrapper.ServiceID != serviceID || wrapper.APIVersion != apiVersion || wrapper.Ciphertext == "" || wrapper.KeyID == "" || wrapper.Alg == "" {
		return localKeyWrapper{}, errInvalidWrapper
	}
	return wrapper, nil
}

func wrapperFailureReason(err error) string {
	switch {
	case errors.Is(err, errLegacyWrapper):
		return "legacy wrapper must be re-enrolled"
	case errors.Is(err, errWrapperAccess):
		return "wrapper permissions are not private"
	case errors.Is(err, errWrapperUnavailable):
		return "wrapper cannot be decrypted by the current user"
	default:
		return "wrapper metadata or protected payload is invalid"
	}
}
