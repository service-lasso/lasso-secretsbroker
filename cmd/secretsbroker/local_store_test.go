package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalBackendWriteSeparatesMetadataAndEncryptedPayload(t *testing.T) {
	backend := testBackend(t)
	res, err := backend.writeSecret(writeSecretRequest{Ref: "openclaw/anthropic/api_key", Value: "secret-value", Metadata: map[string]string{"sourceId": "local-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "ready" {
		t.Fatalf("outcome = %q", res.Outcome)
	}
	bytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), "secret-value") {
		t.Fatalf("store contains plaintext secret: %s", string(bytes))
	}
	var store localStoreFile
	if err := json.Unmarshal(bytes, &store); err != nil {
		t.Fatal(err)
	}
	entry := store.Secrets["openclaw/anthropic/api_key"]
	if entry.Metadata.SourceID != "local-test" {
		t.Fatalf("sourceId = %q", entry.Metadata.SourceID)
	}
	if entry.Payload.Ciphertext == "" || entry.Payload.Nonce == "" {
		t.Fatalf("encrypted payload missing: %#v", entry.Payload)
	}
	if entry.Payload.KeyID != masterKeyID("test-master-key") || entry.Payload.KeyVersion != masterKeyVersion {
		t.Fatalf("key metadata missing: %#v", entry.Payload)
	}
}

func TestLocalBackendResolveBatchOutcomes(t *testing.T) {
	backend := testBackend(t)
	_, err := backend.writeSecret(writeSecretRequest{Ref: "openclaw/anthropic/api_key", Value: "secret-value"})
	if err != nil {
		t.Fatal(err)
	}

	res := backend.resolve(resolveRequest{RequestID: "req-1", ServiceID: "openclaw", Refs: []string{"openclaw/anthropic/api_key", "openclaw/missing", "bad ref"}})
	if len(res.Results) != 3 {
		t.Fatalf("results = %d", len(res.Results))
	}
	if res.Results[0].Outcome != "ready" || res.Results[0].Value != "secret-value" {
		t.Fatalf("ready result = %#v", res.Results[0])
	}
	if res.Results[1].Outcome != "missing_ref" || res.Results[1].Value != "" {
		t.Fatalf("missing result = %#v", res.Results[1])
	}
	if res.Results[2].Outcome != "invalid_ref" || res.Results[2].Value != "" {
		t.Fatalf("invalid result = %#v", res.Results[2])
	}

	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditBytes), "secret-value") {
		t.Fatalf("audit contains plaintext secret: %s", string(auditBytes))
	}
	for _, want := range []string{"ready", "missing_ref", "invalid_ref"} {
		if !strings.Contains(string(auditBytes), want) {
			t.Fatalf("audit missing %q: %s", want, string(auditBytes))
		}
	}
}

func TestLockedBackendResolveDoesNotRevealValues(t *testing.T) {
	backend := testBackend(t)
	_, err := backend.writeSecret(writeSecretRequest{Ref: "openclaw/anthropic/api_key", Value: "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	locked := newLocalBackend(backend.storePath, backend.auditPath, "")
	res := locked.resolve(resolveRequest{Refs: []string{"openclaw/anthropic/api_key"}})
	if res.Results[0].Outcome != "locked" {
		t.Fatalf("outcome = %#v", res.Results[0])
	}
	if res.Results[0].Value != "" {
		t.Fatalf("locked result leaked value")
	}
}

func TestValidSecretRef(t *testing.T) {
	valid := []string{"openclaw/anthropic/api_key", "workspace-local/github/token"}
	invalid := []string{"", "/leading", "trailing/", "has space/ref", "a//b", "a/../b"}
	for _, ref := range valid {
		if !validSecretRef(ref) {
			t.Fatalf("expected valid ref %q", ref)
		}
	}
	for _, ref := range invalid {
		if validSecretRef(ref) {
			t.Fatalf("expected invalid ref %q", ref)
		}
	}
}

func testBackend(t *testing.T) *localBackend {
	t.Helper()
	dir := t.TempDir()
	backend := newLocalBackend(filepath.Join(dir, "store.json"), filepath.Join(dir, "audit.jsonl"), "test-master-key")
	fixed := time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)
	backend.now = func() time.Time { return fixed }
	return backend
}
