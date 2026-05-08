package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backupArtifactVersion = 1

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
	auditPath := fs.String("audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	outPath := fs.String("out", getenvDefault("SECRETSBROKER_BACKUP_PATH", ""), "backup artifact output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterial(*masterKey, *masterKeyFile)
	if err != nil {
		return err
	}
	res, err := newLocalBackend(*storePath, *auditPath, material.Value).createBackup(*outPath)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runBackupRestore(args []string) error {
	fs := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	auditPath := fs.String("audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	inPath := fs.String("in", getenvDefault("SECRETSBROKER_BACKUP_PATH", ""), "backup artifact input path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterial(*masterKey, *masterKeyFile)
	if err != nil {
		return err
	}
	res, err := newLocalBackend(*storePath, *auditPath, material.Value).restoreBackup(*inPath)
	if err != nil {
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runKeyRotate(args []string) error {
	fs := flag.NewFlagSet("key rotate", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	auditPath := fs.String("audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "current portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing current portable master key")
	newMasterKey := fs.String("new-master-key", getenvDefault("SECRETSBROKER_NEW_MASTER_KEY", ""), "new portable master key")
	newMasterKeyFile := fs.String("new-master-key-file", getenvDefault("SECRETSBROKER_NEW_MASTER_KEY_FILE", ""), "file containing new portable master key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	current, err := loadKeyMaterial(*masterKey, *masterKeyFile)
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
	res, err := newLocalBackend(*storePath, *auditPath, current.Value).rotateMasterKey(next.Value)
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
	artifact, err := readBackupArtifact(path)
	if err != nil {
		_ = b.audit("backup_restore", "", "invalid_ref", "", "")
		return backupRestoreResponse{}, err
	}
	if artifact.StoreKeyID != "" && artifact.StoreKeyID != masterKeyID(b.masterKey) {
		_ = b.audit("backup_restore", "", "locked", "", "")
		return backupRestoreResponse{}, errInvalidBackupKey
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
	store.UpdatedAt = b.now()
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
	bytes, err := os.ReadFile(path)
	if err != nil {
		return backupArtifact{}, err
	}
	var artifact backupArtifact
	if err := json.Unmarshal(bytes, &artifact); err != nil {
		return backupArtifact{}, errInvalidBackupArtifact
	}
	if artifact.Version != backupArtifactVersion || artifact.ServiceID != serviceID || artifact.APIVersion != apiVersion || artifact.Store.Version != localStoreVersion || artifact.Store.Secrets == nil {
		return backupArtifact{}, errInvalidBackupArtifact
	}
	if artifact.SecretCount != len(artifact.Store.Secrets) {
		return backupArtifact{}, errInvalidBackupArtifact
	}
	return artifact, nil
}

func encodeIndented(out *os.File, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
