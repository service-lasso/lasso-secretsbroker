package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupRestoreCreatesEncryptedPortableArtifact(t *testing.T) {
	backend := testBackend(t)
	_, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/DB_PASSWORD", Value: "db-secret-value", Metadata: map[string]string{"sourceId": "local-test"}})
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "secretsbroker-backup.json")
	created, err := backend.createBackup(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if created.Outcome != "ready" || created.SecretCount != 1 || created.StoreKeyID != masterKeyID("test-master-key") {
		t.Fatalf("backup response = %#v", created)
	}
	artifactBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(artifactBytes), "db-secret-value") {
		t.Fatalf("backup leaked plaintext secret: %s", string(artifactBytes))
	}

	restored := newLocalBackend(filepath.Join(t.TempDir(), "restored-store.json"), filepath.Join(t.TempDir(), "restored-audit.jsonl"), "test-master-key")
	restored.now = backend.now
	restoreRes, err := restored.restoreBackup(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if restoreRes.Outcome != "ready" || restoreRes.SecretCount != 1 {
		t.Fatalf("restore response = %#v", restoreRes)
	}
	resolved := restored.resolve(resolveRequest{ServiceID: "api", Refs: []string{"services/api/DB_PASSWORD"}})
	if resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != "db-secret-value" {
		t.Fatalf("restored resolve = %#v", resolved.Results[0])
	}
}

func TestRestoreWithWrongOrMissingKeyFailsSafely(t *testing.T) {
	backend := testBackend(t)
	_, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/API_TOKEN", Value: "token-secret"})
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "backup.json")
	if _, err := backend.createBackup(backupPath); err != nil {
		t.Fatal(err)
	}

	locked := newLocalBackend(filepath.Join(t.TempDir(), "locked-store.json"), filepath.Join(t.TempDir(), "locked-audit.jsonl"), "")
	if _, err := locked.restoreBackup(backupPath); !errors.Is(err, errLocked) {
		t.Fatalf("locked restore err = %v", err)
	}
	wrongKey := newLocalBackend(filepath.Join(t.TempDir(), "wrong-store.json"), filepath.Join(t.TempDir(), "wrong-audit.jsonl"), "wrong-master-key")
	if _, err := wrongKey.restoreBackup(backupPath); !errors.Is(err, errInvalidBackupKey) {
		t.Fatalf("wrong key restore err = %v", err)
	}
	if _, err := os.Stat(wrongKey.storePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-key restore should not write store, stat err = %v", err)
	}
}

func TestRestoreWithWrongKeyRejectsEmptyBackupByKeyID(t *testing.T) {
	backend := testBackend(t)
	backupPath := filepath.Join(t.TempDir(), "empty-backup.json")
	created, err := backend.createBackup(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if created.SecretCount != 0 || created.StoreKeyID != masterKeyID("test-master-key") {
		t.Fatalf("empty backup response = %#v", created)
	}
	wrongKey := newLocalBackend(filepath.Join(t.TempDir(), "wrong-empty-store.json"), filepath.Join(t.TempDir(), "wrong-empty-audit.jsonl"), "wrong-master-key")
	if _, err := wrongKey.restoreBackup(backupPath); !errors.Is(err, errInvalidBackupKey) {
		t.Fatalf("wrong key empty restore err = %v", err)
	}
	if _, err := os.Stat(wrongKey.storePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-key empty restore should not write store, stat err = %v", err)
	}
}

func TestKeyRotationReencryptsStoreAndPreservesResolvability(t *testing.T) {
	backend := testBackend(t)
	_, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/SESSION_KEY", Value: "session-secret"})
	if err != nil {
		t.Fatal(err)
	}
	oldBytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(oldBytes), masterKeyID("test-master-key")) {
		t.Fatalf("old store missing original key id: %s", string(oldBytes))
	}

	rotated, err := backend.rotateMasterKey("next-master-key")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Outcome != "ready" || rotated.OldKeyID != masterKeyID("test-master-key") || rotated.NewKeyID != masterKeyID("next-master-key") || rotated.SecretCount != 1 {
		t.Fatalf("rotation response = %#v", rotated)
	}
	resolved := backend.resolve(resolveRequest{ServiceID: "api", Refs: []string{"services/api/SESSION_KEY"}})
	if resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != "session-secret" {
		t.Fatalf("rotated resolve = %#v", resolved.Results[0])
	}
	newBytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(newBytes), "session-secret") {
		t.Fatalf("rotated store leaked plaintext secret: %s", string(newBytes))
	}
	if strings.Contains(string(newBytes), masterKeyID("test-master-key")) || !strings.Contains(string(newBytes), masterKeyID("next-master-key")) {
		t.Fatalf("rotated store key metadata not updated: %s", string(newBytes))
	}
	staleKey := newLocalBackend(backend.storePath, filepath.Join(t.TempDir(), "stale-audit.jsonl"), "test-master-key")
	staleResolved := staleKey.resolve(resolveRequest{ServiceID: "api", Refs: []string{"services/api/SESSION_KEY"}})
	if staleResolved.Results[0].Outcome != "degraded" || staleResolved.Results[0].Value != "" {
		t.Fatalf("stale key resolve = %#v", staleResolved.Results[0])
	}
}

func TestBackupArtifactValidationRejectsTamperedMetadata(t *testing.T) {
	backend := testBackend(t)
	_, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/SECRET", Value: "value"})
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "backup.json")
	if _, err := backend.createBackup(backupPath); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	var artifact backupArtifact
	if err := json.Unmarshal(bytes, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact.SecretCount = 99
	tampered, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.restoreBackup(backupPath); !errors.Is(err, errInvalidBackupArtifact) {
		t.Fatalf("tampered restore err = %v", err)
	}
}
