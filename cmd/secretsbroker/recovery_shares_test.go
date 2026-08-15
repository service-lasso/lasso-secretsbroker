package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func recoveryShareBackend(t *testing.T, masterKey string) *localBackend {
	t.Helper()
	b := lifecycleBackend(t, masterKey)
	b.now = func() time.Time { return time.Date(2026, 6, 7, 13, 45, 0, 0, time.UTC) }
	if _, err := b.initializeStore(masterKey); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecoveryShareGenerateAndImportRefreshesWrapper(t *testing.T) {
	key := lifecycleTestKey(21)
	backend := recoveryShareBackend(t, key)
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/RECOVERY_TOKEN", Value: "recoverable-secret"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	outputs := []string{
		filepath.Join(dir, "share-1.json"),
		filepath.Join(dir, "share-2.json"),
		filepath.Join(dir, "share-3.json"),
	}

	generated, err := backend.generateRecoveryShares(recoveryShareGenerateRequest{PolicyID: "policy-break-glass", Threshold: 2, Outputs: outputs, ServiceID: "@operator", RequestID: "req-generate"})
	if err != nil {
		t.Fatal(err)
	}
	if generated.Outcome != "ready" || generated.KeyID != masterKeyID(key) || generated.Policy == nil || generated.Policy.Threshold != 2 || len(generated.Shares) != 3 {
		t.Fatalf("generated response = %#v", generated)
	}
	storeBytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storeBytes), key) || strings.Contains(string(storeBytes), "recoverable-secret") {
		t.Fatalf("store leaked recovery material or secret: %s", string(storeBytes))
	}
	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditBytes), key) || strings.Contains(string(auditBytes), "recoverable-secret") {
		t.Fatalf("audit leaked recovery material or secret: %s", string(auditBytes))
	}
	for _, output := range outputs {
		bytes, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(bytes), key) || strings.Contains(string(bytes), "recoverable-secret") {
			t.Fatalf("share file leaked portable key or secret: %s", string(bytes))
		}
		var share recoveryShareFile
		if err := json.Unmarshal(bytes, &share); err != nil {
			t.Fatal(err)
		}
		if share.Share == "" || share.ShareFingerprint == "" || share.KeyID != masterKeyID(key) {
			t.Fatalf("share metadata = %#v", share)
		}
	}

	wrapperPath := filepath.Join(t.TempDir(), "wrapper.json")
	recovered := newLocalBackend(backend.storePath, filepath.Join(t.TempDir(), "recovery-audit.jsonl"), "")
	recovered.now = backend.now
	imported, err := recovered.importRecoverySharesWithProvider(recoveryShareImportRequest{Inputs: outputs[:2], WrapperPath: wrapperPath, OS: "test", ServiceID: "@operator", RequestID: "req-import"}, testWrapperContext(), testKeyWrapperProvider{})
	if err != nil {
		t.Fatal(err)
	}
	if imported.Outcome != "ready" || imported.Wrapper == nil || imported.Wrapper.KeyID != masterKeyID(key) || imported.SecretCount != 1 {
		t.Fatalf("import response = %#v", imported)
	}
	resolved := recovered.resolve(resolveRequest{ServiceID: "api", Refs: []string{"services/api/RECOVERY_TOKEN"}})
	if resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != "recoverable-secret" {
		t.Fatalf("recovered resolve = %#v", resolved.Results[0])
	}
	wrapperBytes, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wrapperBytes), key) || strings.Contains(string(wrapperBytes), "recoverable-secret") {
		t.Fatalf("wrapper leaked recovery material or secret: %s", string(wrapperBytes))
	}
}

func TestRecoveryShareImportFailuresFailClosed(t *testing.T) {
	key := lifecycleTestKey(22)
	backend := recoveryShareBackend(t, key)
	dir := t.TempDir()
	outputs := []string{
		filepath.Join(dir, "share-1.json"),
		filepath.Join(dir, "share-2.json"),
		filepath.Join(dir, "share-3.json"),
	}
	if _, err := backend.generateRecoveryShares(recoveryShareGenerateRequest{PolicyID: "policy-fail-closed", Threshold: 2, Outputs: outputs}); err != nil {
		t.Fatal(err)
	}

	wrapperPath := filepath.Join(t.TempDir(), "too-few-wrapper.json")
	recovered := newLocalBackend(backend.storePath, filepath.Join(t.TempDir(), "too-few-audit.jsonl"), "")
	if _, err := recovered.importRecoverySharesWithProvider(recoveryShareImportRequest{Inputs: outputs[:1], WrapperPath: wrapperPath, OS: "test"}, testWrapperContext(), testKeyWrapperProvider{}); !errors.Is(err, errInsufficientRecoveryShares) {
		t.Fatalf("too few shares err = %v", err)
	}
	if _, err := os.Stat(wrapperPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("too few shares should not write wrapper, stat err = %v", err)
	}

	tamperedPath := filepath.Join(t.TempDir(), "tampered-share.json")
	bytes, err := os.ReadFile(outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	var tampered recoveryShareFile
	if err := json.Unmarshal(bytes, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.ShareFingerprint = "share-tampered"
	tamperedBytes, err := json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedPath, tamperedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.importRecoverySharesWithProvider(recoveryShareImportRequest{Inputs: []string{tamperedPath, outputs[1]}, WrapperPath: filepath.Join(t.TempDir(), "tampered-wrapper.json"), OS: "test"}, testWrapperContext(), testKeyWrapperProvider{}); !errors.Is(err, errInvalidRecoveryShare) {
		t.Fatalf("tampered share err = %v", err)
	}

	unsupportedWrapper := filepath.Join(t.TempDir(), "unsupported-wrapper.json")
	if _, err := recovered.importRecoveryShares(recoveryShareImportRequest{Inputs: outputs[:2], WrapperPath: unsupportedWrapper, OS: "plan9"}); !errors.Is(err, errUnsupportedOSWrapper) {
		t.Fatalf("unsupported wrapper err = %v", err)
	}
	if _, err := os.Stat(unsupportedWrapper); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported wrapper should not write file, stat err = %v", err)
	}

	corruptedStorePath := filepath.Join(t.TempDir(), "corrupted-store.json")
	if err := os.WriteFile(corruptedStorePath, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupted := newLocalBackend(corruptedStorePath, filepath.Join(t.TempDir(), "corrupted-audit.jsonl"), "")
	corruptedWrapper := filepath.Join(t.TempDir(), "corrupted-wrapper.json")
	if _, err := corrupted.importRecoverySharesWithProvider(recoveryShareImportRequest{Inputs: outputs[:2], WrapperPath: corruptedWrapper, OS: "test"}, testWrapperContext(), testKeyWrapperProvider{}); !errors.Is(err, errBackendDegraded) {
		t.Fatalf("corrupted store err = %v", err)
	}
	if _, err := os.Stat(corruptedWrapper); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupted store should not write wrapper, stat err = %v", err)
	}
}

func TestRecoveryShareAgeEnvelopeGenerateAndImport(t *testing.T) {
	key := lifecycleTestKey(24)
	backend := recoveryShareBackend(t, key)
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/ENVELOPED_TOKEN", Value: "enveloped-secret"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	outputs := []string{
		filepath.Join(dir, "share-1.json"),
		filepath.Join(dir, "share-2.json"),
		filepath.Join(dir, "share-3.json"),
	}
	identities := make([]*age.X25519Identity, 0, len(outputs))
	recipients := make([]string, 0, len(outputs))
	identityStrings := make([]string, 0, len(outputs))
	for range outputs {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
		recipients = append(recipients, identity.Recipient().String())
		identityStrings = append(identityStrings, identity.String())
	}

	generated, err := backend.generateRecoveryShares(recoveryShareGenerateRequest{PolicyID: "policy-age-break-glass", Threshold: 2, Outputs: outputs, AgeRecipients: recipients, ServiceID: "@operator", RequestID: "req-age-generate"})
	if err != nil {
		t.Fatal(err)
	}
	if generated.Outcome != "ready" || generated.Policy == nil || len(generated.Policy.RecipientFingerprints) != len(outputs) || len(generated.Shares) != len(outputs) {
		t.Fatalf("generated response = %#v", generated)
	}
	for i, share := range generated.Shares {
		if share.EnvelopeFormat != recoveryShareEnvelopeAgeX25519V1 || share.RecipientFingerprint == "" || share.RecipientFingerprint != generated.Policy.RecipientFingerprints[i] {
			t.Fatalf("share metadata = %#v policy = %#v", share, generated.Policy)
		}
	}

	var plaintextShare string
	for _, output := range outputs {
		bytes, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(bytes), key) || strings.Contains(string(bytes), "enveloped-secret") {
			t.Fatalf("encrypted share file leaked portable key or secret: %s", string(bytes))
		}
		for _, identity := range identityStrings {
			if strings.Contains(string(bytes), identity) {
				t.Fatalf("encrypted share file leaked recipient identity: %s", string(bytes))
			}
		}
		var share recoveryShareFile
		if err := json.Unmarshal(bytes, &share); err != nil {
			t.Fatal(err)
		}
		if share.Share != "" || share.Envelope == nil || share.Envelope.Ciphertext == "" || share.Envelope.RecipientFingerprint == "" {
			t.Fatalf("encrypted share file metadata = %#v", share)
		}
		decryptedShare, err := recoverySharePlaintext(share, []age.Identity{identities[0], identities[1], identities[2]})
		if err != nil {
			t.Fatal(err)
		}
		if plaintextShare == "" {
			plaintextShare = decryptedShare
		}
		if strings.Contains(string(bytes), decryptedShare) {
			t.Fatalf("encrypted share file leaked plaintext share: %s", string(bytes))
		}
	}

	wrapperPath := filepath.Join(t.TempDir(), "wrapper.json")
	recovered := newLocalBackend(backend.storePath, filepath.Join(t.TempDir(), "recovery-audit.jsonl"), "")
	recovered.now = backend.now
	imported, err := recovered.importRecoverySharesWithProvider(recoveryShareImportRequest{Inputs: outputs[:2], AgeIdentities: identityStrings[:2], WrapperPath: wrapperPath, OS: "test", ServiceID: "@operator", RequestID: "req-age-import"}, testWrapperContext(), testKeyWrapperProvider{})
	if err != nil {
		t.Fatal(err)
	}
	if imported.Outcome != "ready" || imported.Wrapper == nil || imported.Wrapper.KeyID != masterKeyID(key) || imported.SecretCount != 1 {
		t.Fatalf("import response = %#v", imported)
	}
	resolved := recovered.resolve(resolveRequest{ServiceID: "api", Refs: []string{"services/api/ENVELOPED_TOKEN"}})
	if resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != "enveloped-secret" {
		t.Fatalf("recovered resolve = %#v", resolved.Results[0])
	}
	auditBytes, err := os.ReadFile(recovered.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditBytes), key) || strings.Contains(string(auditBytes), plaintextShare) || strings.Contains(string(auditBytes), "enveloped-secret") {
		t.Fatalf("audit leaked recovery material or secret: %s", string(auditBytes))
	}
}

func TestRecoveryShareAgeEnvelopeRejectsWrongIdentityAndMalformedEnvelope(t *testing.T) {
	key := lifecycleTestKey(25)
	backend := recoveryShareBackend(t, key)
	dir := t.TempDir()
	outputs := []string{
		filepath.Join(dir, "share-1.json"),
		filepath.Join(dir, "share-2.json"),
	}
	firstIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	secondIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.generateRecoveryShares(recoveryShareGenerateRequest{PolicyID: "policy-age-fail-closed", Threshold: 2, Outputs: outputs, AgeRecipients: []string{firstIdentity.Recipient().String(), secondIdentity.Recipient().String()}}); err != nil {
		t.Fatal(err)
	}

	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recovered := newLocalBackend(backend.storePath, filepath.Join(t.TempDir(), "wrong-identity-audit.jsonl"), "")
	if _, err := recovered.importRecoveryShares(recoveryShareImportRequest{Inputs: outputs, AgeIdentities: []string{wrongIdentity.String()}, WrapperPath: filepath.Join(t.TempDir(), "wrong-wrapper.json"), OS: "linux"}); !errors.Is(err, errInvalidRecoveryShare) {
		t.Fatalf("wrong identity err = %v", err)
	}

	malformedBytes, err := os.ReadFile(outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	var malformed recoveryShareFile
	if err := json.Unmarshal(malformedBytes, &malformed); err != nil {
		t.Fatal(err)
	}
	malformed.Envelope.Ciphertext = "not-valid-base64"
	malformedPath := filepath.Join(t.TempDir(), "malformed-share.json")
	bytes, err := json.MarshalIndent(malformed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformedPath, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.importRecoveryShares(recoveryShareImportRequest{Inputs: []string{malformedPath, outputs[1]}, AgeIdentities: []string{firstIdentity.String(), secondIdentity.String()}, WrapperPath: filepath.Join(t.TempDir(), "malformed-wrapper.json"), OS: "linux"}); !errors.Is(err, errInvalidRecoveryShare) {
		t.Fatalf("malformed envelope err = %v", err)
	}
}

func TestRecoveryShareGenerateRequiresExplicitSafePolicy(t *testing.T) {
	key := lifecycleTestKey(23)
	backend := recoveryShareBackend(t, key)

	if _, err := backend.generateRecoveryShares(recoveryShareGenerateRequest{Threshold: 1}); !errors.Is(err, errRecoveryShareOutputRequired) {
		t.Fatalf("missing output err = %v", err)
	}
	out := filepath.Join(t.TempDir(), "share.json")
	if _, err := backend.generateRecoveryShares(recoveryShareGenerateRequest{Threshold: 2, Outputs: []string{out}}); !errors.Is(err, errInvalidRecoveryPolicy) {
		t.Fatalf("invalid threshold err = %v", err)
	}
}
