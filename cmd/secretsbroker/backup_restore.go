package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backupArtifactVersion = 2

var (
	errInvalidBackupArtifact = errors.New("invalid backup artifact")
	errInvalidBackupKey      = errors.New("backup key material cannot decrypt artifact")
	errMissingBackupPath     = errors.New("backup path is required")
	errMissingNewMasterKey   = errors.New("new master key is required")
)

type backupArtifact struct {
	Version         int            `json:"version"`
	ServiceID       string         `json:"serviceId"`
	APIVersion      string         `json:"apiVersion"`
	CreatedAt       time.Time      `json:"createdAt"`
	StoreKeyID      string         `json:"storeKeyId"`
	StoreKeyVersion string         `json:"storeKeyVersion"`
	SecretCount     int            `json:"secretCount"`
	Store           localStoreFile `json:"store"`
	Integrity       string         `json:"integrity"`
}

type backupCreateResponse struct {
	ServiceID       string    `json:"serviceId"`
	APIVersion      string    `json:"apiVersion"`
	Outcome         string    `json:"outcome"`
	Path            string    `json:"path"`
	CreatedAt       time.Time `json:"createdAt"`
	StoreKeyID      string    `json:"storeKeyId"`
	StoreKeyVersion string    `json:"storeKeyVersion"`
	SecretCount     int       `json:"secretCount"`
	Warning         string    `json:"warning"`
}

type backupRestoreResponse struct {
	ServiceID       string    `json:"serviceId"`
	APIVersion      string    `json:"apiVersion"`
	Outcome         string    `json:"outcome"`
	Path            string    `json:"path"`
	RestoredAt      time.Time `json:"restoredAt"`
	StoreKeyID      string    `json:"storeKeyId"`
	StoreKeyVersion string    `json:"storeKeyVersion"`
	SecretCount     int       `json:"secretCount"`
}

type keyRotateResponse struct {
	ServiceID       string    `json:"serviceId"`
	APIVersion      string    `json:"apiVersion"`
	Outcome         string    `json:"outcome"`
	RotatedAt       time.Time `json:"rotatedAt"`
	OldKeyID        string    `json:"oldKeyId"`
	NewKeyID        string    `json:"newKeyId"`
	StoreKeyVersion string    `json:"storeKeyVersion"`
	SecretCount     int       `json:"secretCount"`
}

func runBackup(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown backup command %q", "")
	}
	switch args[0] {
	case "create":
		return runBackupCreate(args[1:])
	case "restore":
		return runBackupRestore(args[1:])
	default:
		return fmt.Errorf("unknown backup command %q", args[0])
	}
}

func runBackupCreate(args []string) error {
	fs := flag.NewFlagSet("backup create", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	audit := addAuditCommandOptions(fs)
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path used when explicit master-key input is absent")
	outPath := fs.String("out", getenvDefault("SECRETSBROKER_BACKUP_PATH", ""), "backup artifact output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterialForStore(*masterKey, *masterKeyFile, *wrapperPath, *storePath)
	if err != nil {
		return err
	}
	res, err := audit.newBackend(*storePath, material.Value).createBackup(*outPath)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runBackupRestore(args []string) error {
	fs := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	audit := addAuditCommandOptions(fs)
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path used when explicit master-key input is absent")
	inPath := fs.String("in", getenvDefault("SECRETSBROKER_BACKUP_PATH", ""), "backup artifact input path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterialForStore(*masterKey, *masterKeyFile, *wrapperPath, *storePath)
	if err != nil {
		return err
	}
	res, err := audit.newBackend(*storePath, material.Value).restoreBackup(*inPath)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runKeyRotate(args []string) error {
	fs := flag.NewFlagSet("key rotate", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	audit := addAuditCommandOptions(fs)
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "current portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing current portable master key")
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path used when explicit current master-key input is absent")
	newMasterKey := fs.String("new-master-key", getenvDefault("SECRETSBROKER_NEW_MASTER_KEY", ""), "new portable master key")
	newMasterKeyFile := fs.String("new-master-key-file", getenvDefault("SECRETSBROKER_NEW_MASTER_KEY_FILE", ""), "file containing new portable master key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	current, err := loadKeyMaterialForStore(*masterKey, *masterKeyFile, *wrapperPath, *storePath)
	if err != nil {
		return err
	}
	next, err := loadKeyMaterial(*newMasterKey, *newMasterKeyFile)
	if errors.Is(err, errLocked) {
		return errMissingNewMasterKey
	}
	if err != nil {
		return err
	}
	res, err := audit.newBackend(*storePath, current.Value).rotateMasterKey(next.Value)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func (b *localBackend) createBackup(path string) (backupCreateResponse, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return backupCreateResponse{}, errMissingBackupPath
	}
	if b.locked() {
		_ = b.audit("backup_create", "", "locked", "", "")
		return backupCreateResponse{}, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		_ = b.audit("backup_create", "", "degraded", "", "")
		return backupCreateResponse{}, errBackendDegraded
	}
	if err := b.verifyStoreDecryptable(store); err != nil {
		_ = b.audit("backup_create", "", "degraded", "", "")
		return backupCreateResponse{}, errInvalidBackupKey
	}
	now := b.now()
	artifact := backupArtifact{
		Version:         backupArtifactVersion,
		ServiceID:       serviceID,
		APIVersion:      apiVersion,
		CreatedAt:       now,
		StoreKeyID:      masterKeyID(b.masterKey),
		StoreKeyVersion: masterKeyVersion,
		SecretCount:     len(store.Secrets),
		Store:           store,
	}
	artifact.Integrity, err = signBackupArtifact(artifact, b.masterKey)
	if err != nil {
		_ = b.audit("backup_create", "", "degraded", "", "")
		return backupCreateResponse{}, err
	}
	if err := writeBackupArtifact(path, artifact); err != nil {
		_ = b.audit("backup_create", "", "degraded", "", "")
		return backupCreateResponse{}, err
	}
	_ = b.audit("backup_create", "", "ready", "", "")
	return backupCreateResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", Path: path, CreatedAt: now, StoreKeyID: artifact.StoreKeyID, StoreKeyVersion: artifact.StoreKeyVersion, SecretCount: artifact.SecretCount, Warning: "Backup contains encrypted secret payloads only. Keep it with the matching portable master key or recovery material."}, nil
}

func (b *localBackend) restoreBackup(path string) (backupRestoreResponse, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return backupRestoreResponse{}, errMissingBackupPath
	}
	if b.locked() {
		_ = b.audit("backup_restore", "", "locked", "", "")
		return backupRestoreResponse{}, errLocked
	}
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	artifact, err := readBackupArtifact(path)
	if err != nil {
		_ = b.audit("backup_restore", "", "invalid_ref", "", "")
		return backupRestoreResponse{}, err
	}
	if artifact.StoreKeyID != "" && artifact.StoreKeyID != masterKeyID(b.masterKey) {
		_ = b.audit("backup_restore", "", "locked", "", "")
		return backupRestoreResponse{}, errInvalidBackupKey
	}
	if err := verifyBackupArtifactIntegrity(artifact, b.masterKey); err != nil {
		_ = b.audit("backup_restore", "", "invalid_ref", "", "")
		return backupRestoreResponse{}, errInvalidBackupArtifact
	}
	if err := b.verifyStoreDecryptable(artifact.Store); err != nil {
		_ = b.audit("backup_restore", "", "locked", "", "")
		return backupRestoreResponse{}, errInvalidBackupKey
	}
	restored := artifact.Store
	restored.UpdatedAt = b.now()
	if err := b.saveStore(restored); err != nil {
		_ = b.audit("backup_restore", "", "degraded", "", "")
		return backupRestoreResponse{}, errBackendDegraded
	}
	_ = b.audit("backup_restore", "", "ready", "", "")
	return backupRestoreResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", Path: path, RestoredAt: b.now(), StoreKeyID: artifact.StoreKeyID, StoreKeyVersion: artifact.StoreKeyVersion, SecretCount: artifact.SecretCount}, nil
}

func (b *localBackend) rotateMasterKey(newMasterKey string) (keyRotateResponse, error) {
	return b.rotateMasterKeyWithReceipt(newMasterKey, nil)
}

func (b *localBackend) rotateMasterKeyWithReceipt(newMasterKey string, receipt *lifecycleOperationReceipt) (keyRotateResponse, error) {
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	newMasterKey = strings.TrimSpace(newMasterKey)
	if newMasterKey == "" {
		return keyRotateResponse{}, errMissingNewMasterKey
	}
	if b.locked() {
		_ = b.audit("key_rotate", "", "locked", "", "")
		return keyRotateResponse{}, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		_ = b.audit("key_rotate", "", "degraded", "", "")
		return keyRotateResponse{}, errBackendDegraded
	}
	plaintext := make(map[string]string, len(store.Secrets))
	for ref, entry := range store.Secrets {
		value, err := b.decrypt(entry.Payload)
		if err != nil {
			_ = b.audit("key_rotate", ref, "degraded", "", "")
			return keyRotateResponse{}, errInvalidBackupKey
		}
		plaintext[ref] = value
	}
	tombstonePlaintext := make(map[string]string, len(store.Tombstones))
	for ref, tombstone := range store.Tombstones {
		value, err := b.decrypt(tombstone.Entry.Payload)
		if err != nil {
			_ = b.audit("key_rotate", ref, "degraded", "", "")
			return keyRotateResponse{}, errInvalidBackupKey
		}
		tombstonePlaintext[ref] = value
	}
	oldKeyID := masterKeyID(b.masterKey)
	b.masterKey = newMasterKey
	for ref, value := range plaintext {
		entry := store.Secrets[ref]
		payload, err := b.encrypt(value)
		if err != nil {
			_ = b.audit("key_rotate", ref, "degraded", "", "")
			return keyRotateResponse{}, err
		}
		entry.Payload = payload
		entry.Metadata.UpdatedAt = b.now()
		store.Secrets[ref] = entry
	}
	for ref, value := range tombstonePlaintext {
		tombstone := store.Tombstones[ref]
		payload, err := b.encrypt(value)
		if err != nil {
			_ = b.audit("key_rotate", ref, "degraded", "", "")
			return keyRotateResponse{}, err
		}
		tombstone.Entry.Payload = payload
		tombstone.Entry.Metadata.UpdatedAt = b.now()
		store.Tombstones[ref] = tombstone
	}
	store.KeyID = masterKeyID(newMasterKey)
	store.KeyVersion = masterKeyVersion
	store.UpdatedAt = b.now()
	if receipt != nil {
		if store.LifecycleOps == nil {
			store.LifecycleOps = map[string]lifecycleOperationReceipt{}
		}
		store.LifecycleOps[receipt.OperationID] = *receipt
	}
	if err := b.saveStore(store); err != nil {
		_ = b.audit("key_rotate", "", "degraded", "", "")
		return keyRotateResponse{}, errBackendDegraded
	}
	_ = b.audit("key_rotate", "", "ready", "", "")
	return keyRotateResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", RotatedAt: b.now(), OldKeyID: oldKeyID, NewKeyID: masterKeyID(newMasterKey), StoreKeyVersion: masterKeyVersion, SecretCount: len(store.Secrets)}, nil
}

func (b *localBackend) verifyStoreDecryptable(store localStoreFile) error {
	for _, entry := range store.Secrets {
		if _, err := b.decrypt(entry.Payload); err != nil {
			return err
		}
	}
	for _, tombstone := range store.Tombstones {
		if _, err := b.decrypt(tombstone.Entry.Payload); err != nil {
			return err
		}
	}
	return nil
}

func writeBackupArtifact(path string, artifact backupArtifact) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, bytes, 0o600)
}

func readBackupArtifact(path string) (backupArtifact, error) {
	file, err := openValidatedRegularFile(path, maxManagedBackupSize, true)
	if err != nil {
		return backupArtifact{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxManagedBackupSize {
		return backupArtifact{}, errInvalidBackupArtifact
	}
	bytes, err := io.ReadAll(io.LimitReader(file, maxManagedBackupSize+1))
	if err != nil || int64(len(bytes)) > maxManagedBackupSize {
		return backupArtifact{}, errInvalidBackupArtifact
	}
	var artifact backupArtifact
	if err := json.Unmarshal(bytes, &artifact); err != nil {
		return backupArtifact{}, errInvalidBackupArtifact
	}
	if artifact.Version != backupArtifactVersion || artifact.ServiceID != serviceID || artifact.APIVersion != apiVersion || artifact.Store.Version != localStoreVersion || artifact.Store.Secrets == nil || artifact.Integrity == "" {
		return backupArtifact{}, errInvalidBackupArtifact
	}
	if artifact.SecretCount != len(artifact.Store.Secrets) {
		return backupArtifact{}, errInvalidBackupArtifact
	}
	return artifact, nil
}

func signBackupArtifact(artifact backupArtifact, masterKey string) (string, error) {
	artifact.Integrity = ""
	canonical, err := json.Marshal(artifact)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte("service-lasso:@secretsbroker:backup:v2:" + strings.TrimSpace(masterKey)))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(canonical)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func verifyBackupArtifactIntegrity(artifact backupArtifact, masterKey string) error {
	expected, err := signBackupArtifact(artifact, masterKey)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(expected), []byte(strings.TrimSpace(artifact.Integrity))) {
		return errInvalidBackupArtifact
	}
	return nil
}

func encodeIndented(out *os.File, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
