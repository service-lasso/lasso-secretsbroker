package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	managedBackupSchema  = "service-lasso.secretsbroker.backup-metadata.v1"
	maxManagedBackupSize = 64 << 20
	restorePlanTTL       = 5 * time.Minute
)

var (
	errLifecycleInvalidRequest = errors.New("invalid lifecycle management request")
	errLifecycleAudit          = errors.New("lifecycle audit unavailable")
	errLifecycleStalePlan      = errors.New("lifecycle plan is stale")
	errLifecycleConflict       = errors.New("lifecycle operation conflicts with current state")
)

type lifecycleStatusResponse struct {
	ServiceID   string                       `json:"serviceId"`
	APIVersion  string                       `json:"apiVersion"`
	Outcome     string                       `json:"outcome"`
	Key         lifecycleKeyStatus           `json:"key"`
	Wrapper     wrapperStatusDetail          `json:"wrapper"`
	Recovery    recoveryPolicyStatusResponse `json:"recovery"`
	Backups     []managedBackupMetadata      `json:"backups"`
	AuditStatus string                       `json:"auditStatus"`
	NextAction  string                       `json:"nextAction"`
}

type lifecycleKeyStatus struct {
	Available   bool   `json:"available"`
	KeyID       string `json:"keyId,omitempty"`
	KeyVersion  string `json:"keyVersion,omitempty"`
	SecretCount int    `json:"secretCount"`
}

type lifecycleOperationRequest struct {
	RequestID         string                 `json:"requestId"`
	ServiceID         string                 `json:"serviceId"`
	OperationID       string                 `json:"operationId"`
	Reason            string                 `json:"reason"`
	BackupID          string                 `json:"backupId,omitempty"`
	PlanToken         string                 `json:"planToken,omitempty"`
	ExpectedKeyID     string                 `json:"expectedKeyId,omitempty"`
	ExpectedStoreHash string                 `json:"expectedStoreHash,omitempty"`
	Confirm           bool                   `json:"confirm"`
	Actor             *lifecycleRequestActor `json:"actor,omitempty"`
}

type lifecycleRequestActor struct {
	ActorID   string `json:"actorId"`
	ActorKind string `json:"actorKind"`
}

type managedBackupMetadata struct {
	Schema          string    `json:"schema"`
	BackupID        string    `json:"backupId"`
	CreatedAt       time.Time `json:"createdAt"`
	StoreKeyID      string    `json:"storeKeyId"`
	StoreKeyVersion string    `json:"storeKeyVersion"`
	SecretCount     int       `json:"secretCount"`
	SizeBytes       int64     `json:"sizeBytes"`
	ArtifactHash    string    `json:"artifactHash"`
	Verification    string    `json:"verification"`
}

type lifecycleBackupResponse struct {
	ServiceID   string                  `json:"serviceId"`
	APIVersion  string                  `json:"apiVersion"`
	Outcome     string                  `json:"outcome"`
	Applied     bool                    `json:"applied"`
	Backup      *managedBackupMetadata  `json:"backup,omitempty"`
	Backups     []managedBackupMetadata `json:"backups,omitempty"`
	AuditStatus string                  `json:"auditStatus"`
	NextAction  string                  `json:"nextAction"`
}

type lifecycleRestoreResponse struct {
	ServiceID            string                 `json:"serviceId"`
	APIVersion           string                 `json:"apiVersion"`
	Outcome              string                 `json:"outcome"`
	Applied              bool                   `json:"applied"`
	Backup               *managedBackupMetadata `json:"backup,omitempty"`
	PlanToken            string                 `json:"planToken,omitempty"`
	PlanExpiresAt        *time.Time             `json:"planExpiresAt,omitempty"`
	ExpectedKeyID        string                 `json:"expectedKeyId,omitempty"`
	ExpectedStoreHash    string                 `json:"expectedStoreHash,omitempty"`
	RequiresConfirmation bool                   `json:"requiresConfirmation"`
	AuditStatus          string                 `json:"auditStatus"`
	NextAction           string                 `json:"nextAction"`
}

type lifecycleRotateResponse struct {
	ServiceID            string    `json:"serviceId"`
	APIVersion           string    `json:"apiVersion"`
	Outcome              string    `json:"outcome"`
	Applied              bool      `json:"applied"`
	RotatedAt            time.Time `json:"rotatedAt,omitempty"`
	OldKeyID             string    `json:"oldKeyId,omitempty"`
	NewKeyID             string    `json:"newKeyId,omitempty"`
	KeyVersion           string    `json:"keyVersion,omitempty"`
	SecretCount          int       `json:"secretCount"`
	RequiresConfirmation bool      `json:"requiresConfirmation"`
	AuditStatus          string    `json:"auditStatus"`
	NextAction           string    `json:"nextAction"`
}

func (b *localBackend) lifecycleStatus() (lifecycleStatusResponse, error) {
	res := lifecycleStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", AuditStatus: "audit_recorded", NextAction: "operate_normally"}
	store, err := b.loadStore()
	if err != nil {
		res.Outcome, res.AuditStatus, res.NextAction = "degraded", "audit_unavailable", "repair_broker_store"
		return res, errBackendDegraded
	}
	res.Key = lifecycleKeyStatus{Available: !b.locked(), KeyID: store.KeyID, KeyVersion: store.KeyVersion, SecretCount: len(store.Secrets)}
	res.Wrapper = wrapperStatusWithProvider(b.wrapperPath, wrapperContextFor(""), b.lifecycleWrapperProvider())
	res.Wrapper.User = ""
	res.Wrapper.Machine = ""
	if res.Recovery, err = b.recoveryPolicyStatus(); err != nil {
		res.Outcome, res.NextAction = "degraded", "repair_recovery_policy_metadata"
	}
	if res.Backups, err = b.listManagedBackups(); err != nil {
		res.Outcome, res.NextAction = "degraded", "repair_backup_inventory"
	}
	if err := b.auditLifecycle("lifecycle_status", "", "ready", "", ""); err != nil {
		res.AuditStatus = "audit_unavailable"
		return res, errLifecycleAudit
	}
	return res, err
}

func (b *localBackend) createManagedBackup(req lifecycleOperationRequest) (lifecycleBackupResponse, error) {
	res := lifecycleBackupResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "degraded", Applied: false, AuditStatus: "audit_unavailable", NextAction: "restore_audit_and_retry"}
	if err := validateLifecycleMutationRequest(req, false); err != nil {
		res.Outcome, res.NextAction = "policy_denied", "provide_operation_id_and_audit_reason"
		return res, err
	}
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()
	if err := b.auditLifecycle("backup_create_authorized", "", "ready", req.ServiceID, req.RequestID); err != nil {
		return res, errLifecycleAudit
	}
	backupID := backupIDForOperation(b.masterKey, req.OperationID)
	path, err := b.managedBackupPath(backupID)
	if err != nil {
		return res, err
	}
	if existing, inspectErr := b.inspectManagedBackup(backupID); inspectErr == nil {
		res.Outcome, res.Applied, res.Backup, res.AuditStatus, res.NextAction = "ready", false, &existing, "audit_recorded", "backup_already_created"
		return res, nil
	} else if _, statErr := os.Lstat(path); statErr == nil {
		return res, errLifecycleConflict
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return res, statErr
	}
	store, err := b.loadStore()
	if err != nil || b.verifyStoreDecryptable(store) != nil {
		return res, errBackendDegraded
	}
	now := b.now().UTC()
	artifact := backupArtifact{Version: backupArtifactVersion, ServiceID: serviceID, APIVersion: apiVersion, CreatedAt: now, StoreKeyID: masterKeyID(b.masterKey), StoreKeyVersion: masterKeyVersion, SecretCount: len(store.Secrets), Store: store}
	artifact.Integrity, err = signBackupArtifact(artifact, b.masterKey)
	if err != nil {
		return res, err
	}
	artifactBytes, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return res, err
	}
	if err := writePrivateFileExclusive(path, artifactBytes); err != nil {
		return res, err
	}
	metadata, err := b.inspectManagedBackup(backupID)
	if err != nil {
		return res, err
	}
	if err := b.auditLifecycle("backup_create", backupID, "ready", req.ServiceID, req.RequestID); err != nil {
		return res, errLifecycleAudit
	}
	res.Outcome, res.Applied, res.Backup, res.AuditStatus, res.NextAction = "ready", true, &metadata, "audit_recorded", "retain_backup_separately_from_recovery_material"
	return res, nil
}

func (b *localBackend) listManagedBackups() ([]managedBackupMetadata, error) {
	entries, err := os.ReadDir(b.backupRoot)
	if errors.Is(err, os.ErrNotExist) {
		return []managedBackupMetadata{}, nil
	}
	if err != nil {
		return nil, err
	}
	backups := make([]managedBackupMetadata, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		backupID := strings.TrimSuffix(entry.Name(), ".json")
		metadata, inspectErr := b.inspectManagedBackup(backupID)
		if inspectErr != nil {
			metadata = managedBackupMetadata{Schema: managedBackupSchema, BackupID: backupID, Verification: "invalid"}
		}
		backups = append(backups, metadata)
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.After(backups[j].CreatedAt) })
	return backups, nil
}

func (b *localBackend) verifyManagedBackup(req lifecycleOperationRequest) (lifecycleBackupResponse, error) {
	res := lifecycleBackupResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "invalid_ref", Applied: false, AuditStatus: "audit_unavailable", NextAction: "select_valid_backup"}
	if !validLifecycleID(req.BackupID) {
		return res, errLifecycleInvalidRequest
	}
	metadata, err := b.inspectManagedBackup(req.BackupID)
	if err != nil {
		_ = b.auditLifecycle("backup_verify", req.BackupID, "invalid_ref", req.ServiceID, req.RequestID)
		return res, err
	}
	if err := b.auditLifecycle("backup_verify", req.BackupID, "ready", req.ServiceID, req.RequestID); err != nil {
		res.Outcome, res.NextAction = "degraded", "restore_audit_and_retry"
		return res, errLifecycleAudit
	}
	res.Outcome, res.Backup, res.AuditStatus, res.NextAction = "ready", &metadata, "audit_recorded", "backup_verified"
	return res, nil
}

func (b *localBackend) restoreManagedBackupPlan(req lifecycleOperationRequest) (lifecycleRestoreResponse, error) {
	res := lifecycleRestoreResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "invalid_ref", RequiresConfirmation: true, AuditStatus: "audit_unavailable", NextAction: "select_valid_backup"}
	if err := validateLifecycleMutationRequest(req, false); err != nil || !validLifecycleID(req.BackupID) {
		return res, errLifecycleInvalidRequest
	}
	metadata, err := b.inspectManagedBackup(req.BackupID)
	if err != nil {
		return res, err
	}
	storeHash, err := fileSHA256(b.storePath, maxManagedBackupSize)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, err
	}
	keyID := masterKeyID(b.masterKey)
	expiresAt := b.now().UTC().Add(restorePlanTTL)
	plan := signLifecyclePlan(b.masterKey, "restore", req.OperationID, req.BackupID, keyID, storeHash, expiresAt)
	if err := b.auditLifecycle("backup_restore_plan", req.BackupID, "ready", req.ServiceID, req.RequestID); err != nil {
		res.Outcome, res.NextAction = "degraded", "restore_audit_and_retry"
		return res, errLifecycleAudit
	}
	res.Outcome, res.Backup, res.PlanToken, res.PlanExpiresAt, res.ExpectedKeyID, res.ExpectedStoreHash, res.AuditStatus, res.NextAction = "ready", &metadata, plan, &expiresAt, keyID, storeHash, "audit_recorded", "confirm_exact_restore_plan"
	return res, nil
}

func (b *localBackend) restoreManagedBackupApply(req lifecycleOperationRequest) (lifecycleRestoreResponse, error) {
	res := lifecycleRestoreResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "conflict", RequiresConfirmation: true, AuditStatus: "audit_unavailable", NextAction: "create_fresh_restore_plan"}
	if err := validateLifecycleMutationRequest(req, true); err != nil || !validLifecycleID(req.BackupID) || !validSafeMetadataID(req.ExpectedKeyID) || strings.TrimSpace(req.ExpectedStoreHash) == "" {
		return res, errLifecycleInvalidRequest
	}
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	currentStore, loadErr := b.loadStore()
	if loadErr != nil {
		return res, errBackendDegraded
	}
	if receipt, exists := currentStore.LifecycleOps[req.OperationID]; exists {
		if receipt.Kind != "restore" || receipt.BackupID != req.BackupID || receipt.ExpectedKeyID != req.ExpectedKeyID || receipt.ExpectedStoreHash != req.ExpectedStoreHash {
			return res, errLifecycleConflict
		}
		if err := b.auditLifecycle("backup_restore_retry", req.BackupID, "ready", req.ServiceID, req.RequestID); err != nil {
			return res, errLifecycleAudit
		}
		res.Outcome, res.Applied, res.RequiresConfirmation, res.AuditStatus, res.NextAction = "ready", false, false, "audit_recorded", "restore_already_applied"
		return res, nil
	}
	now := b.now().UTC()
	if !verifyLifecyclePlan(b.masterKey, req.PlanToken, "restore", req.OperationID, req.BackupID, req.ExpectedKeyID, req.ExpectedStoreHash, now) {
		return res, errLifecycleStalePlan
	}
	if req.ExpectedKeyID != masterKeyID(b.masterKey) {
		return res, errLifecycleConflict
	}
	currentHash, err := fileSHA256(b.storePath, maxManagedBackupSize)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, err
	}
	if currentHash != req.ExpectedStoreHash {
		return res, errLifecycleStalePlan
	}
	metadata, artifact, err := b.loadManagedBackup(req.BackupID)
	if err != nil {
		return res, err
	}
	if err := b.auditLifecycle("backup_restore_authorized", req.BackupID, "ready", req.ServiceID, req.RequestID); err != nil {
		return res, errLifecycleAudit
	}
	restored := artifact.Store
	restored.UpdatedAt = b.now().UTC()
	if restored.LifecycleOps == nil {
		restored.LifecycleOps = map[string]lifecycleOperationReceipt{}
	}
	restored.LifecycleOps[req.OperationID] = lifecycleOperationReceipt{Kind: "restore", OperationID: req.OperationID, BackupID: req.BackupID, ExpectedKeyID: req.ExpectedKeyID, ExpectedStoreHash: req.ExpectedStoreHash, SecretCount: len(restored.Secrets), AppliedAt: restored.UpdatedAt}
	if err := b.saveStore(restored); err != nil {
		return res, err
	}
	if err := b.auditLifecycle("backup_restore", req.BackupID, "ready", req.ServiceID, req.RequestID); err != nil {
		return res, errLifecycleAudit
	}
	res.Outcome, res.Applied, res.Backup, res.RequiresConfirmation, res.AuditStatus, res.NextAction = "ready", true, &metadata, false, "audit_recorded", "restart_and_verify_broker"
	return res, nil
}

func (b *localBackend) rotateManagedMasterKey(req lifecycleOperationRequest) (lifecycleRotateResponse, error) {
	res := lifecycleRotateResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "policy_denied", RequiresConfirmation: true, AuditStatus: "audit_unavailable", NextAction: "confirm_key_rotation"}
	if err := validateLifecycleMutationRequest(req, true); err != nil || !validSafeMetadataID(req.ExpectedKeyID) {
		return res, errLifecycleInvalidRequest
	}
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()
	provider := b.lifecycleWrapperProvider()
	material, recoveryErr := loadKeyMaterialForStoreWithProvider("", "", b.wrapperPath, b.storePath, provider)
	if recoveryErr != nil {
		return res, errLifecycleConflict
	}
	b.masterKey = material.Value
	store, loadErr := b.loadStore()
	if loadErr != nil {
		return res, errBackendDegraded
	}
	if receipt, exists := store.LifecycleOps[req.OperationID]; exists {
		if receipt.Kind != "rotate" || receipt.ExpectedKeyID != req.ExpectedKeyID {
			return res, errLifecycleConflict
		}
		if err := b.auditLifecycle("key_rotate_retry", "", "ready", req.ServiceID, req.RequestID); err != nil {
			return res, errLifecycleAudit
		}
		res.Outcome, res.Applied, res.RotatedAt, res.OldKeyID, res.NewKeyID, res.KeyVersion, res.SecretCount, res.RequiresConfirmation, res.AuditStatus, res.NextAction = "ready", false, receipt.AppliedAt, receipt.OldKeyID, receipt.NewKeyID, receipt.KeyVersion, receipt.SecretCount, false, "audit_recorded", "rotation_already_applied"
		return res, nil
	}
	if req.ExpectedKeyID != masterKeyID(b.masterKey) {
		return res, errLifecycleConflict
	}
	if err := b.auditLifecycle("key_rotate_authorized", "", "ready", req.ServiceID, req.RequestID); err != nil {
		return res, errLifecycleAudit
	}
	newKey, err := generatePortableMasterKey()
	if err != nil {
		return res, err
	}
	oldKey := b.masterKey
	pendingWrapper := rotationPendingWrapperPath(b.wrapperPath)
	if _, err := wrapMasterKeyWithProvider(pendingWrapper, newKey, wrapperContextFor(""), b.now(), provider); err != nil {
		return res, err
	}
	receipt := lifecycleOperationReceipt{Kind: "rotate", OperationID: req.OperationID, ExpectedKeyID: req.ExpectedKeyID, OldKeyID: masterKeyID(oldKey), NewKeyID: masterKeyID(newKey), KeyVersion: masterKeyVersion, SecretCount: len(store.Secrets), AppliedAt: b.now().UTC()}
	rotated, err := b.rotateMasterKeyWithReceipt(newKey, &receipt)
	if err != nil {
		_ = os.Remove(pendingWrapper)
		return res, err
	}
	if err := atomicReplacePrivateFile(pendingWrapper, b.wrapperPath); err != nil {
		return res, errLifecycleConflict
	}
	if err := provider.SecurePath(b.wrapperPath, false); err != nil {
		return res, errLifecycleConflict
	}
	if err := provider.ValidatePath(b.wrapperPath, false); err != nil {
		return res, errLifecycleConflict
	}
	if err := b.auditLifecycle("key_rotate", "", "ready", req.ServiceID, req.RequestID); err != nil {
		return res, errLifecycleAudit
	}
	res.Outcome, res.Applied, res.RotatedAt, res.OldKeyID, res.NewKeyID, res.KeyVersion, res.SecretCount, res.RequiresConfirmation, res.AuditStatus, res.NextAction = "ready", true, rotated.RotatedAt, rotated.OldKeyID, rotated.NewKeyID, rotated.StoreKeyVersion, rotated.SecretCount, false, "audit_recorded", "create_and_verify_rotated_backup"
	return res, nil
}

func (b *localBackend) inspectManagedBackup(backupID string) (managedBackupMetadata, error) {
	metadata, _, err := b.loadManagedBackup(backupID)
	return metadata, err
}

func (b *localBackend) loadManagedBackup(backupID string) (managedBackupMetadata, backupArtifact, error) {
	path, err := b.managedBackupPath(backupID)
	if err != nil {
		return managedBackupMetadata{}, backupArtifact{}, err
	}
	lstat, err := os.Lstat(path)
	if err != nil || !lstat.Mode().IsRegular() || lstat.Size() <= 0 || lstat.Size() > maxManagedBackupSize {
		return managedBackupMetadata{}, backupArtifact{}, errInvalidBackupArtifact
	}
	file, err := os.Open(path)
	if err != nil {
		return managedBackupMetadata{}, backupArtifact{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(lstat, info) || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxManagedBackupSize {
		return managedBackupMetadata{}, backupArtifact{}, errInvalidBackupArtifact
	}
	bytes, err := io.ReadAll(io.LimitReader(file, maxManagedBackupSize+1))
	if err != nil || int64(len(bytes)) > maxManagedBackupSize {
		return managedBackupMetadata{}, backupArtifact{}, errInvalidBackupArtifact
	}
	var artifact backupArtifact
	if err := json.Unmarshal(bytes, &artifact); err != nil {
		return managedBackupMetadata{}, backupArtifact{}, errInvalidBackupArtifact
	}
	if artifact.Version != backupArtifactVersion || artifact.ServiceID != serviceID || artifact.APIVersion != apiVersion || artifact.Store.Version != localStoreVersion || artifact.Store.Secrets == nil || artifact.SecretCount != len(artifact.Store.Secrets) || verifyBackupArtifactIntegrity(artifact, b.masterKey) != nil || artifact.StoreKeyID != masterKeyID(b.masterKey) || b.verifyStoreDecryptable(artifact.Store) != nil {
		return managedBackupMetadata{}, backupArtifact{}, errInvalidBackupArtifact
	}
	hashBytes := sha256.Sum256(bytes)
	hash := "sha256:" + hex.EncodeToString(hashBytes[:])
	return managedBackupMetadata{Schema: managedBackupSchema, BackupID: backupID, CreatedAt: artifact.CreatedAt, StoreKeyID: artifact.StoreKeyID, StoreKeyVersion: artifact.StoreKeyVersion, SecretCount: artifact.SecretCount, SizeBytes: info.Size(), ArtifactHash: hash, Verification: "verified"}, artifact, nil
}

func (b *localBackend) managedBackupPath(backupID string) (string, error) {
	if !validLifecycleID(backupID) {
		return "", errLifecycleInvalidRequest
	}
	root, err := filepath.Abs(b.backupRoot)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, backupID+".json")
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", errLifecycleInvalidRequest
	}
	return path, nil
}

func validateLifecycleMutationRequest(req lifecycleOperationRequest, requireConfirm bool) error {
	if !validLifecycleID(req.OperationID) || strings.TrimSpace(req.Reason) == "" || len(strings.TrimSpace(req.Reason)) > 256 || (requireConfirm && !req.Confirm) || !validLifecycleActor(req.Actor) {
		return errLifecycleInvalidRequest
	}
	return nil
}

func validLifecycleActor(actor *lifecycleRequestActor) bool {
	if actor == nil {
		return true
	}
	for _, value := range []string{actor.ActorID, actor.ActorKind} {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 256 || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return false
		}
	}
	return true
}

func validLifecycleID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func fileSHA256(path string, maxSize int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	limited := io.LimitReader(file, maxSize+1)
	hash := sha256.New()
	n, err := io.Copy(hash, limited)
	if err != nil {
		return "", err
	}
	if n > maxSize {
		return "", errInvalidBackupArtifact
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func backupIDForOperation(masterKey, operationID string) string {
	key := sha256.Sum256([]byte("service-lasso:@secretsbroker:backup-id:" + strings.TrimSpace(masterKey)))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(strings.TrimSpace(operationID)))
	return "backup-" + hex.EncodeToString(mac.Sum(nil))[:24]
}

func signLifecyclePlan(masterKey, operation, operationID, backupID, keyID, storeHash string, expiresAt time.Time) string {
	payload := strings.Join([]string{operation, operationID, backupID, keyID, storeHash, expiresAt.UTC().Format(time.RFC3339Nano)}, "\n")
	key := sha256.Sum256([]byte("service-lasso:@secretsbroker:lifecycle-plan:" + strings.TrimSpace(masterKey)))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(expiresAt.UTC().Format(time.RFC3339Nano))) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyLifecyclePlan(masterKey, token, operation, operationID, backupID, keyID, storeHash string, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	expiresRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, string(expiresRaw))
	if err != nil || !expiresAt.After(now) || expiresAt.After(now.Add(restorePlanTTL+time.Second)) {
		return false
	}
	expected := signLifecyclePlan(masterKey, operation, operationID, backupID, keyID, storeHash, expiresAt)
	return hmac.Equal([]byte(expected), []byte(token))
}

func (b *localBackend) auditLifecycle(operation, subject, outcome, requestServiceID, requestID string) error {
	return b.writeAuditEvent(auditEvent{TS: b.now(), Operation: operation, Ref: subject, Outcome: outcome, ServiceID: requestServiceID, RequestID: requestID})
}

func registerLifecycleManagementHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/management/lifecycle/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/management/lifecycle/status.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		res, err := backend.lifecycleStatus()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("/v1/management/lifecycle/backups", func(w http.ResponseWriter, r *http.Request) {
		if !security.require(w, r) {
			return
		}
		switch r.Method {
		case http.MethodGet:
			backups, err := backend.listManagedBackups()
			res := lifecycleBackupResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", Backups: backups, AuditStatus: "audit_recorded", NextAction: "select_backup_or_create_new"}
			if err != nil {
				res.Outcome, res.AuditStatus, res.NextAction = "degraded", "audit_unavailable", "repair_backup_inventory"
				writeJSON(w, http.StatusServiceUnavailable, res)
				return
			}
			if err := backend.auditLifecycle("backup_list", "", "ready", "", ""); err != nil {
				res.Outcome, res.AuditStatus, res.NextAction = "degraded", "audit_unavailable", "restore_audit_and_retry"
				writeJSON(w, http.StatusServiceUnavailable, res)
				return
			}
			writeJSON(w, http.StatusOK, res)
		case http.MethodPost:
			var req lifecycleOperationRequest
			if err := decodeLifecycleJSON(w, r, &req); err != nil {
				writeDecodeError(w, err)
				return
			}
			res, err := backend.createManagedBackup(req)
			writeLifecycleResult(w, err, res)
		default:
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET or POST /v1/management/lifecycle/backups.", "invalid_ref", "")
		}
	})
	registerLifecycleAction(mux, security, "/v1/management/lifecycle/backups/verify", func(req lifecycleOperationRequest) (any, error) { return backend.verifyManagedBackup(req) })
	registerLifecycleAction(mux, security, "/v1/management/lifecycle/restore/dry-run", func(req lifecycleOperationRequest) (any, error) { return backend.restoreManagedBackupPlan(req) })
	registerLifecycleAction(mux, security, "/v1/management/lifecycle/restore/apply", func(req lifecycleOperationRequest) (any, error) { return backend.restoreManagedBackupApply(req) })
	registerLifecycleAction(mux, security, "/v1/management/lifecycle/key/rotate", func(req lifecycleOperationRequest) (any, error) { return backend.rotateManagedMasterKey(req) })
}

func registerLifecycleAction(mux *http.ServeMux, security localAPISecurity, path string, handler func(lifecycleOperationRequest) (any, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST "+path+".", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req lifecycleOperationRequest
		if err := decodeLifecycleJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := handler(req)
		writeLifecycleResult(w, err, res)
	})
}

func decodeLifecycleJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecretBearingRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeLifecycleResult(w http.ResponseWriter, err error, res any) {
	status := http.StatusOK
	switch {
	case err == nil:
	case errors.Is(err, errLifecycleInvalidRequest):
		status = http.StatusBadRequest
	case errors.Is(err, errLifecycleStalePlan), errors.Is(err, errLifecycleConflict):
		status = http.StatusConflict
	case errors.Is(err, os.ErrNotExist):
		status = http.StatusNotFound
	default:
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, res)
}
