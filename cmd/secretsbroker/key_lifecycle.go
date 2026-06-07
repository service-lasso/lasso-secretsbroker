package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	localWrapperVersion = 1
	localWrapperAlg     = "AES-256-GCM"
)

var (
	errInvalidMasterKey     = errors.New("invalid portable master key format")
	errStoreAlreadyExists   = errors.New("local encrypted store already exists")
	errUnsupportedOSWrapper = errors.New("os wrapper provider is unsupported")
	errInvalidWrapper       = errors.New("local key wrapper is invalid")
)

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
	Nonce       string    `json:"nonce"`
	Ciphertext  string    `json:"ciphertext"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type keyLifecycleResponse struct {
	ServiceID        string               `json:"serviceId"`
	APIVersion       string               `json:"apiVersion"`
	Outcome          string               `json:"outcome"`
	State            string               `json:"state"`
	Ready            bool                 `json:"ready"`
	KeyID            string               `json:"keyId,omitempty"`
	KeyVersion       string               `json:"keyVersion,omitempty"`
	StorePath        string               `json:"storePath,omitempty"`
	WrapperPath      string               `json:"wrapperPath,omitempty"`
	Wrapper          *wrapperStatusDetail `json:"wrapper,omitempty"`
	SecretCount      int                  `json:"secretCount"`
	NextAction       string               `json:"nextAction"`
	RecoveryGuidance string               `json:"recoveryGuidance"`
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
	auditPath := fs.String("audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterial(*masterKey, *masterKeyFile)
	if err != nil {
		return err
	}
	backend := newLocalBackend(*storePath, *auditPath, material.Value)
	res, err := backend.initializeStore(material.Value)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runKeyUnlock(args []string) error {
	fs := flag.NewFlagSet("key unlock", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	auditPath := fs.String("audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterial(*masterKey, *masterKeyFile)
	if err != nil {
		return err
	}
	backend := newLocalBackend(*storePath, *auditPath, material.Value)
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
	auditPath := fs.String("audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
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
	backend := newLocalBackend(*storePath, *auditPath, material.Value)
	res, err := backend.importOrRewrapMasterKey(*wrapperPath, material.Value, wrapperContextFor(*osName), operation)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runKeyWrapperStatus(args []string) error {
	fs := flag.NewFlagSet("key wrapper-status", flag.ContinueOnError)
	auditPath := fs.String("audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path")
	osName := fs.String("os", runtime.GOOS, "wrapper OS override for validation/testing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	backend := newLocalBackend(defaultStorePath(), *auditPath, "")
	res := wrapperStatusResponse(*wrapperPath, wrapperContextFor(*osName))
	_ = backend.audit("key_wrapper_status", "", res.Outcome, "", "")
	return encodeIndented(os.Stdout, res)
}

func (b *localBackend) initializeStore(masterKey string) (keyLifecycleResponse, error) {
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
	store := localStoreFile{Version: localStoreVersion, ServiceID: serviceID, KeyID: masterKeyID(masterKey), KeyVersion: masterKeyVersion, CreatedAt: b.now(), UpdatedAt: b.now(), Secrets: map[string]secretEntry{}}
	if err := b.saveStore(store); err != nil {
		_ = b.audit("key_initialize", "", "degraded", "", "")
		return keyLifecycleResponse{}, errBackendDegraded
	}
	_ = b.audit("key_initialize", "", "ready", "", "")
	return keyLifecycleResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", State: "ready", Ready: true, KeyID: masterKeyID(masterKey), KeyVersion: masterKeyVersion, StorePath: b.storePath, SecretCount: 0, NextAction: "import_or_rewrap_for_local_os", RecoveryGuidance: "Store the portable master key securely, separately from encrypted store backups."}, nil
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
		return keyLifecycleResponse{}, err
	}
	_ = b.audit("key_unlock", "", "ready", "", "")
	return keyLifecycleResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", State: "ready", Ready: true, KeyID: masterKeyID(masterKey), KeyVersion: masterKeyVersion, StorePath: b.storePath, SecretCount: secretCount, NextAction: "operate_or_rewrap_for_local_os", RecoveryGuidance: "If this machine should unlock without manual key entry, run key import or key rewrap for the current OS/user wrapper."}, nil
}

func (b *localBackend) importOrRewrapMasterKey(wrapperPath, masterKey string, ctx wrapperContext, operation string) (keyLifecycleResponse, error) {
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
	wrapper, err := wrapMasterKey(wrapperPath, masterKey, ctx, b.now())
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
	switch ctx.OS {
	case "windows":
		ctx.Kind = "dpapi-user-scope"
	case "darwin":
		ctx.Kind = "keychain-service-item"
	case "linux":
		ctx.Kind = "protected-file-user-scope"
	default:
		ctx.Kind = "unsupported"
		ctx.Supported = false
		ctx.Unsupported = "No supported local wrapper provider for this OS. Use explicit portable-key unlock/import until provider support exists."
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
	if !ctx.Supported {
		return wrapperStatusDetail{Available: false, Supported: false, WrapperKind: ctx.Kind, OS: ctx.OS, State: "degraded", NextAction: "use_portable_key_unlock", FailureReason: ctx.Unsupported}
	}
	wrapper, err := readLocalKeyWrapper(path)
	if errors.Is(err, os.ErrNotExist) {
		return wrapperStatusDetail{Available: false, Supported: true, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, State: "locked", NextAction: "import_portable_key"}
	}
	if err != nil {
		return wrapperStatusDetail{Available: true, Supported: true, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, State: "degraded", NextAction: "import_portable_key", FailureReason: "wrapper metadata could not be read"}
	}
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
	if !ctx.Supported {
		return localKeyWrapper{}, errUnsupportedOSWrapper
	}
	block, err := aes.NewCipher(localWrapperKey(ctx))
	if err != nil {
		return localKeyWrapper{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return localKeyWrapper{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return localKeyWrapper{}, err
	}
	createdAt := now
	if existing, err := readLocalKeyWrapper(path); err == nil && !existing.CreatedAt.IsZero() {
		createdAt = existing.CreatedAt
	}
	wrapper := localKeyWrapper{Version: localWrapperVersion, ServiceID: serviceID, APIVersion: apiVersion, KeyID: masterKeyID(masterKey), KeyVersion: masterKeyVersion, WrapperKind: ctx.Kind, OS: ctx.OS, User: ctx.User, Machine: ctx.Machine, Alg: localWrapperAlg, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, []byte(strings.TrimSpace(masterKey)), nil)), CreatedAt: createdAt, UpdatedAt: now}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return localKeyWrapper{}, err
	}
	bytes, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return localKeyWrapper{}, err
	}
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		return localKeyWrapper{}, err
	}
	return wrapper, nil
}

func readLocalKeyWrapper(path string) (localKeyWrapper, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return localKeyWrapper{}, err
	}
	var wrapper localKeyWrapper
	if err := json.Unmarshal(bytes, &wrapper); err != nil {
		return localKeyWrapper{}, errInvalidWrapper
	}
	if wrapper.Version != localWrapperVersion || wrapper.ServiceID != serviceID || wrapper.APIVersion != apiVersion || wrapper.Alg != localWrapperAlg || wrapper.Ciphertext == "" || wrapper.Nonce == "" || wrapper.KeyID == "" {
		return localKeyWrapper{}, errInvalidWrapper
	}
	return wrapper, nil
}

func localWrapperKey(ctx wrapperContext) []byte {
	sum := sha256.Sum256([]byte("service-lasso:@secretsbroker:local-wrapper:" + ctx.OS + ":" + ctx.Kind + ":" + ctx.User + ":" + ctx.Machine))
	return sum[:]
}
