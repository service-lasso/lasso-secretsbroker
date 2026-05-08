package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lifecycleTestKey(seed byte) string {
	bytes := make([]byte, 32)
	for i := range bytes {
		bytes[i] = seed
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func lifecycleBackend(t *testing.T, masterKey string) *localBackend {
	t.Helper()
	b := newLocalBackend(filepath.Join(t.TempDir(), "store.json"), filepath.Join(t.TempDir(), "audit.jsonl"), masterKey)
	b.now = func() time.Time { return time.Date(2026, 5, 8, 21, 0, 0, 0, time.UTC) }
	return b
}

func TestInitializeUnlockImportAndRewrapMasterKeyLifecycle(t *testing.T) {
	key := lifecycleTestKey(7)
	backend := lifecycleBackend(t, key)

	initialized, err := backend.initializeStore(key)
	if err != nil {
		t.Fatal(err)
	}
	if initialized.State != "ready" || initialized.KeyID != masterKeyID(key) || initialized.SecretCount != 0 || strings.Contains(initialized.RecoveryGuidance, key) {
		t.Fatalf("initialize response = %#v", initialized)
	}

	unlocked, err := backend.unlockWithMasterKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !unlocked.Ready || unlocked.Outcome != "ready" || unlocked.KeyVersion != masterKeyVersion {
		t.Fatalf("unlock response = %#v", unlocked)
	}

	wrapperPath := filepath.Join(t.TempDir(), "wrapper.json")
	imported, err := backend.importOrRewrapMasterKey(wrapperPath, key, wrapperContextFor("linux"), "key_import")
	if err != nil {
		t.Fatal(err)
	}
	if imported.Wrapper == nil || !imported.Wrapper.Available || imported.Wrapper.KeyID != masterKeyID(key) || imported.Wrapper.OS != "linux" {
		t.Fatalf("import response = %#v", imported)
	}
	wrapperBytes, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wrapperBytes), key) {
		t.Fatalf("wrapper leaked portable key: %s", string(wrapperBytes))
	}

	rewrapped, err := backend.importOrRewrapMasterKey(wrapperPath, key, wrapperContextFor("linux"), "key_rewrap")
	if err != nil {
		t.Fatal(err)
	}
	if rewrapped.Outcome != "ready" || rewrapped.Wrapper == nil || rewrapped.Wrapper.State != "ready" {
		t.Fatalf("rewrap response = %#v", rewrapped)
	}
}

func TestUnlockFailureWrongKeyAndCorruptedCiphertext(t *testing.T) {
	key := lifecycleTestKey(8)
	wrong := lifecycleTestKey(9)
	backend := lifecycleBackend(t, key)
	if _, err := backend.initializeStore(key); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/TOKEN", Value: "secret-token"}); err != nil {
		t.Fatal(err)
	}

	wrongBackend := newLocalBackend(backend.storePath, filepath.Join(t.TempDir(), "wrong-audit.jsonl"), wrong)
	if _, err := wrongBackend.unlockWithMasterKey(wrong); !errors.Is(err, errInvalidBackupKey) {
		t.Fatalf("wrong-key unlock err = %v", err)
	}

	bytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	var store localStoreFile
	if err := json.Unmarshal(bytes, &store); err != nil {
		t.Fatal(err)
	}
	entry := store.Secrets["services/api/TOKEN"]
	entry.Payload.Ciphertext = "corrupted-ciphertext"
	store.Secrets["services/api/TOKEN"] = entry
	corrupted, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backend.storePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.unlockWithMasterKey(key); !errors.Is(err, errBackendDegraded) {
		t.Fatalf("corrupted unlock err = %v", err)
	}
}

func TestImportUnsupportedWrapperAndInvalidKeyFailClosed(t *testing.T) {
	key := lifecycleTestKey(10)
	backend := lifecycleBackend(t, key)
	if _, err := backend.initializeStore(key); err != nil {
		t.Fatal(err)
	}
	wrapperPath := filepath.Join(t.TempDir(), "wrapper.json")
	if _, err := backend.importOrRewrapMasterKey(wrapperPath, key, wrapperContextFor("plan9"), "key_import"); !errors.Is(err, errUnsupportedOSWrapper) {
		t.Fatalf("unsupported wrapper err = %v", err)
	}
	if _, err := os.Stat(wrapperPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported wrapper should not write file, stat err = %v", err)
	}
	if _, err := backend.importOrRewrapMasterKey(wrapperPath, "not-a-valid-portable-key", wrapperContextFor("linux"), "key_import"); !errors.Is(err, errInvalidMasterKey) {
		t.Fatalf("invalid key err = %v", err)
	}
}

func TestWrapperStatusReportsRecoveryGuidanceWithoutKeyMaterial(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing-wrapper.json")
	missing := wrapperStatusResponse(missingPath, wrapperContextFor("linux"))
	if missing.Outcome != "locked" || missing.Wrapper == nil || missing.Wrapper.NextAction != "import_portable_key" || !strings.Contains(missing.RecoveryGuidance, "Import") {
		t.Fatalf("missing wrapper status = %#v", missing)
	}

	unsupported := wrapperStatusResponse(missingPath, wrapperContextFor("plan9"))
	if unsupported.Outcome != "degraded" || unsupported.Wrapper == nil || unsupported.Wrapper.Supported || unsupported.Wrapper.NextAction != "use_portable_key_unlock" {
		t.Fatalf("unsupported wrapper status = %#v", unsupported)
	}
}
