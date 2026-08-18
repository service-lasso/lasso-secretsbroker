package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const lifecycleSecret = "lifecycle-secret-value-must-never-leak"

func managementLifecycleBackend(t *testing.T) *localBackend {
	t.Helper()
	dir := t.TempDir()
	key, err := generatePortableMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	backend := newLocalBackend(filepath.Join(dir, "store.json"), filepath.Join(dir, "audit.jsonl"), key)
	backend.wrapperProvider = testKeyWrapperProvider{}
	ctx := testWrapperContext()
	backend.wrapperContextOverride = &ctx
	backend.wrapperPath = filepath.Join(dir, "wrapper.json")
	backend.backupRoot = filepath.Join(dir, "backups")
	clock := time.Date(2026, 8, 14, 3, 0, 0, 0, time.UTC)
	backend.now = func() time.Time { return clock }
	if _, err := backend.initializeStore(key); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/runtime/TOKEN", Value: lifecycleSecret}); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapMasterKeyWithProvider(backend.wrapperPath, key, backend.lifecycleWrapperContext(), backend.now(), backend.lifecycleWrapperProvider()); err != nil {
		t.Fatal(err)
	}
	return backend
}

func TestLifecycleManagementBackupPlanRestoreAndNoLeak(t *testing.T) {
	backend := managementLifecycleBackend(t)
	created, err := backend.createManagedBackup(lifecycleOperationRequest{RequestID: "req-create", ServiceID: "@serviceadmin", OperationID: "op-create", Reason: "release recovery checkpoint"})
	if err != nil {
		t.Fatal(err)
	}
	if !created.Applied || created.Backup == nil || created.Backup.Verification != "verified" || created.Backup.BackupID == "" {
		t.Fatalf("create = %#v", created)
	}
	encoded, _ := json.Marshal(created)
	assertLifecycleNoLeak(t, encoded, lifecycleSecret, backend.masterKey, backend.storePath, backend.backupRoot)
	retried, err := backend.createManagedBackup(lifecycleOperationRequest{RequestID: "req-create-retry", ServiceID: "@serviceadmin", OperationID: "op-create", Reason: "release recovery checkpoint"})
	if err != nil || retried.Applied || retried.Backup == nil || retried.Backup.BackupID != created.Backup.BackupID {
		t.Fatalf("create retry = %#v err=%v", retried, err)
	}

	backups, err := backend.listManagedBackups()
	if err != nil || len(backups) != 1 || backups[0].BackupID != created.Backup.BackupID {
		t.Fatalf("backups=%#v err=%v", backups, err)
	}

	plan, err := backend.restoreManagedBackupPlan(lifecycleOperationRequest{RequestID: "req-plan", ServiceID: "@serviceadmin", OperationID: "op-restore", Reason: "undo accidental edit", BackupID: created.Backup.BackupID})
	if err != nil || plan.PlanToken == "" || plan.ExpectedKeyID == "" || plan.ExpectedStoreHash == "" || !plan.RequiresConfirmation {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/runtime/TOKEN", Value: "changed-after-backup"}); err != nil {
		t.Fatal(err)
	}
	stale := lifecycleOperationRequest{RequestID: "req-apply", ServiceID: "@serviceadmin", OperationID: "op-restore", Reason: "undo accidental edit", BackupID: created.Backup.BackupID, PlanToken: plan.PlanToken, ExpectedKeyID: plan.ExpectedKeyID, ExpectedStoreHash: plan.ExpectedStoreHash, Confirm: true}
	if _, err := backend.restoreManagedBackupApply(stale); !errors.Is(err, errLifecycleStalePlan) {
		t.Fatalf("stale apply err=%v", err)
	}

	fresh, err := backend.restoreManagedBackupPlan(lifecycleOperationRequest{RequestID: "req-plan-2", ServiceID: "@serviceadmin", OperationID: "op-restore-2", Reason: "undo accidental edit", BackupID: created.Backup.BackupID})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := backend.restoreManagedBackupApply(lifecycleOperationRequest{RequestID: "req-apply-2", ServiceID: "@serviceadmin", OperationID: "op-restore-2", Reason: "undo accidental edit", BackupID: created.Backup.BackupID, PlanToken: fresh.PlanToken, ExpectedKeyID: fresh.ExpectedKeyID, ExpectedStoreHash: fresh.ExpectedStoreHash, Confirm: true})
	if err != nil || !applied.Applied || applied.RequiresConfirmation {
		t.Fatalf("apply=%#v err=%v", applied, err)
	}
	resolved := backend.resolve(resolveRequest{ServiceID: "api", Refs: []string{"services/api/runtime/TOKEN"}})
	if got := resolved.Results[0].Value; got != lifecycleSecret {
		t.Fatalf("restored value mismatch")
	}
	retry, err := backend.restoreManagedBackupApply(lifecycleOperationRequest{RequestID: "req-apply-retry", ServiceID: "@serviceadmin", OperationID: "op-restore-2", Reason: "retry after response loss", BackupID: created.Backup.BackupID, PlanToken: fresh.PlanToken, ExpectedKeyID: fresh.ExpectedKeyID, ExpectedStoreHash: fresh.ExpectedStoreHash, Confirm: true})
	if err != nil || retry.Applied || retry.RequiresConfirmation || retry.NextAction != "restore_already_applied" {
		t.Fatalf("restore retry=%#v err=%v", retry, err)
	}
}

func TestLifecycleManagementRejectsTamperAndAuditUnavailable(t *testing.T) {
	backend := managementLifecycleBackend(t)
	created, err := backend.createManagedBackup(lifecycleOperationRequest{RequestID: "req-create", ServiceID: "@serviceadmin", OperationID: "op-create", Reason: "release checkpoint"})
	if err != nil {
		t.Fatal(err)
	}
	path, _ := backend.managedBackupPath(created.Backup.BackupID)
	artifactBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var artifact backupArtifact
	if err := json.Unmarshal(artifactBytes, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact.CreatedAt = artifact.CreatedAt.Add(time.Second)
	tampered, _ := json.Marshal(artifact)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.inspectManagedBackup(created.Backup.BackupID); !errors.Is(err, errInvalidBackupArtifact) {
		t.Fatalf("tampered backup err=%v", err)
	}

	blocked := managementLifecycleBackend(t)
	blocked.auditPath = t.TempDir()
	if _, err := blocked.createManagedBackup(lifecycleOperationRequest{RequestID: "req-audit", ServiceID: "@serviceadmin", OperationID: "op-audit", Reason: "must fail closed"}); !errors.Is(err, errLifecycleAudit) {
		t.Fatalf("audit failure err=%v", err)
	}
	entries, readErr := os.ReadDir(blocked.backupRoot)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("audit failure created backup: %#v", entries)
	}
}

func TestLifecycleHTTPRequiresAuthAndReturnsOnlyMetadata(t *testing.T) {
	backend := managementLifecycleBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "lifecycle-api-token"}))
	defer server.Close()

	unauthenticated, err := http.Get(server.URL + "/v1/management/lifecycle/status")
	if err != nil {
		t.Fatal(err)
	}
	unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", unauthenticated.StatusCode)
	}

	createBody := []byte(`{"requestId":"req-http","serviceId":"@serviceadmin","operationId":"op-http","reason":"operator checkpoint","actor":{"actorId":"local-root","actorKind":"local-root"}}`)
	res, payload := postJSON(t, server.URL+"/v1/management/lifecycle/backups", "lifecycle-api-token", createBody)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d body=%s", res.StatusCode, payload)
	}
	assertLifecycleNoLeak(t, payload, lifecycleSecret, backend.masterKey, backend.storePath, backend.backupRoot, "lifecycle-api-token")
	if !bytes.Contains(payload, []byte(`"verification":"verified"`)) || bytes.Contains(payload, []byte(`"path"`)) {
		t.Fatalf("unsafe or incomplete create response: %s", payload)
	}

	invalidActorBody := []byte(`{"requestId":"req-http-invalid","serviceId":"@serviceadmin","operationId":"op-http-invalid","reason":"operator checkpoint","actor":{"actorId":"local-root\nforged","actorKind":"local-root"}}`)
	invalidActorRes, invalidActorPayload := postJSON(t, server.URL+"/v1/management/lifecycle/backups", "lifecycle-api-token", invalidActorBody)
	if invalidActorRes.StatusCode != http.StatusBadRequest || !bytes.Contains(invalidActorPayload, []byte(`"outcome":"policy_denied"`)) {
		t.Fatalf("invalid actor status=%d body=%s", invalidActorRes.StatusCode, invalidActorPayload)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/management/lifecycle/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer lifecycle-api-token")
	statusRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	statusPayload, err := io.ReadAll(statusRes.Body)
	statusRes.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if statusRes.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", statusRes.StatusCode, statusPayload)
	}
	assertLifecycleNoLeak(t, statusPayload, lifecycleSecret, backend.masterKey, backend.storePath, backend.backupRoot, "lifecycle-api-token")
}

func TestLifecycleManagedRotationUpdatesStoreAndWrapper(t *testing.T) {
	backend := managementLifecycleBackend(t)
	oldKey := backend.masterKey
	rotated, err := backend.rotateManagedMasterKey(lifecycleOperationRequest{RequestID: "req-rotate", ServiceID: "@serviceadmin", OperationID: "op-rotate", Reason: "scheduled key rotation", ExpectedKeyID: masterKeyID(oldKey), Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rotated.Applied || rotated.NewKeyID == rotated.OldKeyID || rotated.NewKeyID != masterKeyID(backend.masterKey) {
		t.Fatalf("rotation=%#v", rotated)
	}
	wrapper, err := readLocalKeyWrapper(backend.wrapperPath)
	if err != nil || wrapper.KeyID != rotated.NewKeyID {
		t.Fatalf("wrapper=%#v err=%v", wrapper, err)
	}
	resolved := backend.resolve(resolveRequest{ServiceID: "api", Refs: []string{"services/api/runtime/TOKEN"}})
	if resolved.Results[0].Value != lifecycleSecret {
		t.Fatalf("rotated store not resolvable")
	}
	encoded, _ := json.Marshal(rotated)
	assertLifecycleNoLeak(t, encoded, lifecycleSecret, oldKey, backend.masterKey)
	retry, err := backend.rotateManagedMasterKey(lifecycleOperationRequest{RequestID: "req-rotate-retry", ServiceID: "@serviceadmin", OperationID: "op-rotate", Reason: "retry after response loss", ExpectedKeyID: masterKeyID(oldKey), Confirm: true})
	if err != nil || retry.Applied || retry.NextAction != "rotation_already_applied" || retry.NewKeyID != rotated.NewKeyID {
		t.Fatalf("rotation retry=%#v err=%v", retry, err)
	}
}

func TestLifecycleManagedRotationRecoversStoreWrapperCrashWindow(t *testing.T) {
	backend := managementLifecycleBackend(t)
	oldKey := backend.masterKey
	newKey, err := generatePortableMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	pending := rotationPendingWrapperPath(backend.wrapperPath)
	if _, err := wrapMasterKeyWithProvider(pending, newKey, backend.lifecycleWrapperContext(), backend.now(), backend.lifecycleWrapperProvider()); err != nil {
		t.Fatal(err)
	}
	receipt := lifecycleOperationReceipt{Kind: "rotate", OperationID: "op-crash", ExpectedKeyID: masterKeyID(oldKey), OldKeyID: masterKeyID(oldKey), NewKeyID: masterKeyID(newKey), KeyVersion: masterKeyVersion, SecretCount: 1, AppliedAt: backend.now()}
	if _, err := backend.rotateMasterKeyWithReceipt(newKey, &receipt); err != nil {
		t.Fatal(err)
	}
	canonical, err := readLocalKeyWrapper(backend.wrapperPath)
	if err != nil || canonical.KeyID != masterKeyID(oldKey) {
		t.Fatalf("canonical wrapper unexpectedly changed before recovery: %#v err=%v", canonical, err)
	}
	recovered, err := loadKeyMaterialForStoreWithProvider("", "", backend.wrapperPath, backend.storePath, backend.lifecycleWrapperProvider(), backend.lifecycleWrapperContext())
	if err != nil || recovered.Value != newKey || recovered.Source != "os-wrapper-rotation-recovery" {
		t.Fatalf("recovered=%#v err=%v", recovered, err)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending wrapper remained after recovery: %v", err)
	}
	restarted := newLocalBackend(backend.storePath, backend.auditPath, recovered.Value)
	store, err := restarted.loadStore()
	if err != nil || restarted.verifyStoreDecryptable(store) != nil || store.KeyID != masterKeyID(newKey) {
		t.Fatalf("restarted store invalid: key=%q err=%v", store.KeyID, err)
	}
}

func TestLifecycleManagedRotationRollsStoreBackWhenWrapperRefreshFails(t *testing.T) {
	backend := managementLifecycleBackend(t)
	oldKey := backend.masterKey
	backend.wrapperPath = t.TempDir()
	if _, err := backend.rotateManagedMasterKey(lifecycleOperationRequest{RequestID: "req-rotate-fail", ServiceID: "@serviceadmin", OperationID: "op-rotate-fail", Reason: "failure proof", ExpectedKeyID: masterKeyID(oldKey), Confirm: true}); err == nil {
		t.Fatal("expected wrapper refresh failure")
	}
	if backend.masterKey != oldKey {
		t.Fatal("failed rotation did not restore in-memory key")
	}
	store, err := backend.loadStore()
	if err != nil || store.KeyID != masterKeyID(oldKey) || backend.verifyStoreDecryptable(store) != nil {
		t.Fatalf("store was not rolled back: key=%q err=%v", store.KeyID, err)
	}
	newStore, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(newStore, []byte(lifecycleSecret)) {
		t.Fatal("compensated store leaked plaintext")
	}
	resolved := backend.resolve(resolveRequest{ServiceID: "api", Refs: []string{"services/api/runtime/TOKEN"}})
	if resolved.Results[0].Value != lifecycleSecret {
		t.Fatal("compensated store is not resolvable with the original key")
	}
}

func assertLifecycleNoLeak(t *testing.T, payload []byte, secrets ...string) {
	t.Helper()
	text := string(payload)
	for _, secret := range secrets {
		if strings.TrimSpace(secret) != "" && strings.Contains(text, secret) {
			t.Fatalf("payload leaked sensitive material: %s", text)
		}
	}
}
