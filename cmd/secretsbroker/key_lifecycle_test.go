package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testKeyWrapperProvider struct{}

func (testKeyWrapperProvider) Algorithm() string { return "test-protected-wrapper" }
func (testKeyWrapperProvider) Protect(value []byte) ([]byte, error) {
	return append([]byte("protected:"), value...), nil
}
func (testKeyWrapperProvider) Unprotect(value []byte) ([]byte, error) {
	if !bytes.HasPrefix(value, []byte("protected:")) {
		return nil, errWrapperUnavailable
	}
	return append([]byte(nil), value[len("protected:"):]...), nil
}
func (testKeyWrapperProvider) SecurePath(string, bool) error   { return nil }
func (testKeyWrapperProvider) ValidatePath(string, bool) error { return nil }

func testWrapperContext() wrapperContext {
	return wrapperContext{OS: "test", User: "test-user", Machine: "test-machine", Kind: "test-user-scope", Supported: true}
}

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
	if initialized.RootIdentity == nil || initialized.RootIdentity.VaultID == "" || initialized.RootIdentity.RootActorID == "" || initialized.RootIdentity.KeySourceType != "supplied" {
		t.Fatalf("initialize response missing root identity metadata: %#v", initialized.RootIdentity)
	}
	if initialized.BootstrapKey == nil || initialized.BootstrapKey.SourceType != "supplied" || initialized.BootstrapKey.Fingerprint != masterKeyID(key) {
		t.Fatalf("initialize response missing bootstrap key metadata: %#v", initialized.BootstrapKey)
	}

	unlocked, err := backend.unlockWithMasterKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !unlocked.Ready || unlocked.Outcome != "ready" || unlocked.KeyVersion != masterKeyVersion {
		t.Fatalf("unlock response = %#v", unlocked)
	}

	wrapperPath := filepath.Join(t.TempDir(), "wrapper.json")
	ctx := testWrapperContext()
	provider := testKeyWrapperProvider{}
	imported, err := backend.importOrRewrapMasterKeyWithProvider(wrapperPath, key, ctx, "key_import", provider)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Wrapper == nil || !imported.Wrapper.Available || imported.Wrapper.KeyID != masterKeyID(key) || imported.Wrapper.OS != "test" {
		t.Fatalf("import response = %#v", imported)
	}
	wrapperBytes, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wrapperBytes), key) {
		t.Fatalf("wrapper leaked portable key: %s", string(wrapperBytes))
	}

	rewrapped, err := backend.importOrRewrapMasterKeyWithProvider(wrapperPath, key, ctx, "key_rewrap", provider)
	if err != nil {
		t.Fatal(err)
	}
	if rewrapped.Outcome != "ready" || rewrapped.Wrapper == nil || rewrapped.Wrapper.State != "ready" {
		t.Fatalf("rewrap response = %#v", rewrapped)
	}
}

func TestInitializeStoreCreatesRootIdentityAndSafeAuditContract(t *testing.T) {
	key := lifecycleTestKey(11)
	backend := lifecycleBackend(t, key)

	initialized, err := backend.initializeStoreWithSource(key, "file", false)
	if err != nil {
		t.Fatal(err)
	}
	if initialized.OneTimeReveal != nil {
		t.Fatalf("supplied-key bootstrap must not include one-time reveal: %#v", initialized.OneTimeReveal)
	}
	if initialized.RootIdentity == nil || initialized.RootIdentity.KeySourceType != "supplied_file" || initialized.RootIdentity.LossSemantics.RecoverableWithoutKey {
		t.Fatalf("root identity metadata = %#v", initialized.RootIdentity)
	}
	if initialized.BootstrapKey == nil || initialized.BootstrapKey.Generated || initialized.BootstrapKey.OneTimeRevealAvailable {
		t.Fatalf("bootstrap key metadata = %#v", initialized.BootstrapKey)
	}

	bytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), key) {
		t.Fatalf("store leaked supplied key material: %s", string(bytes))
	}
	var store localStoreFile
	if err := json.Unmarshal(bytes, &store); err != nil {
		t.Fatal(err)
	}
	if store.VaultID != initialized.RootIdentity.VaultID || store.RootIdentity == nil || store.RootIdentity.RootActorID != initialized.RootIdentity.RootActorID {
		t.Fatalf("stored root identity = %#v", store.RootIdentity)
	}

	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	audit := string(auditBytes)
	if strings.Contains(audit, key) {
		t.Fatalf("audit leaked supplied key material: %s", audit)
	}
	for _, want := range []string{"supplied_key_used", "vault_created", "root_identity_created", "setup_completed"} {
		if !strings.Contains(audit, want) {
			t.Fatalf("audit missing %q: %s", want, audit)
		}
	}
}

func TestGeneratedBootstrapOneTimeRevealIsResponseOnly(t *testing.T) {
	key := lifecycleTestKey(12)
	backend := lifecycleBackend(t, key)

	initialized, err := backend.initializeStoreWithSource(key, "generated", true)
	if err != nil {
		t.Fatal(err)
	}
	if initialized.OneTimeReveal == nil || initialized.OneTimeReveal.MasterKey != key {
		t.Fatalf("generated bootstrap missing one-time reveal: %#v", initialized.OneTimeReveal)
	}
	if initialized.BootstrapKey == nil || !initialized.BootstrapKey.Generated || !initialized.BootstrapKey.OneTimeRevealAvailable {
		t.Fatalf("generated bootstrap key metadata = %#v", initialized.BootstrapKey)
	}

	storeBytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storeBytes), key) {
		t.Fatalf("store leaked generated key material: %s", string(storeBytes))
	}
	if strings.Contains(string(auditBytes), key) {
		t.Fatalf("audit leaked generated key material: %s", string(auditBytes))
	}
	for _, want := range []string{"key_generated", "vault_created", "root_identity_created", "setup_completed"} {
		if !strings.Contains(string(auditBytes), want) {
			t.Fatalf("audit missing %q: %s", want, string(auditBytes))
		}
	}
}

func TestGeneratedBootstrapRequiresExplicitOneTimeReveal(t *testing.T) {
	key := lifecycleTestKey(13)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	err := runKeyInitialize([]string{"--store", storePath, "--audit", auditPath, "--generate"})
	if !errors.Is(err, errOneTimeRevealMissing) {
		t.Fatalf("generated initialize err = %v, want %v", err, errOneTimeRevealMissing)
	}

	backend := newLocalBackend(filepath.Join(dir, "generated-store.json"), filepath.Join(dir, "generated-audit.jsonl"), key)
	if _, err := backend.initializeStoreWithSource(key, "generated", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backend.storePath); err != nil {
		t.Fatalf("direct generated bootstrap should still initialize store: %v", err)
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
	wrongAudit, err := os.ReadFile(wrongBackend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wrongAudit), "vault_unlock_failure") || strings.Contains(string(wrongAudit), wrong) {
		t.Fatalf("wrong-key audit = %s", string(wrongAudit))
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
	if _, err := backend.importOrRewrapMasterKeyWithProvider(wrapperPath, "not-a-valid-portable-key", testWrapperContext(), "key_import", testKeyWrapperProvider{}); !errors.Is(err, errInvalidMasterKey) {
		t.Fatalf("invalid key err = %v", err)
	}
}

func TestWrapperStatusReportsRecoveryGuidanceWithoutKeyMaterial(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing-wrapper.json")
	ctx := testWrapperContext()
	detail := wrapperStatusWithProvider(missingPath, ctx, testKeyWrapperProvider{})
	missing := keyLifecycleResponse{Outcome: detail.State, Wrapper: &detail, RecoveryGuidance: recoveryGuidanceForWrapper(detail)}
	if missing.Outcome != "locked" || missing.Wrapper == nil || missing.Wrapper.NextAction != "import_portable_key" || !strings.Contains(missing.RecoveryGuidance, "Import") {
		t.Fatalf("missing wrapper status = %#v", missing)
	}

	unsupported := wrapperStatusResponse(missingPath, wrapperContextFor("plan9"))
	if unsupported.Outcome != "degraded" || unsupported.Wrapper == nil || unsupported.Wrapper.Supported || unsupported.Wrapper.NextAction != "use_portable_key_unlock" {
		t.Fatalf("unsupported wrapper status = %#v", unsupported)
	}
}
