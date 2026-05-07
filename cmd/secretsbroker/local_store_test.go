package main

import (
	"encoding/json"
	"errors"
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

func TestGeneratedSecretCaptureEnforcesWritebackPolicyAndRedactsAudit(t *testing.T) {
	backend := testBackend(t)
	res, err := backend.captureGeneratedSecret(generatedSecretCaptureRequest{
		RequestID:         "req-writeback-1",
		Identity:          writebackIdentity{ServiceID: "api-service", ExpiresAt: "2026-05-07T00:05:00Z"},
		Policy:            writebackPolicy{AllowedNamespaces: []string{"services/api-service"}, AllowedOperations: []string{"create", "update", "rotate"}},
		Operation:         "create",
		Namespace:         "services/api-service",
		Ref:               "runtime/API_TOKEN",
		Value:             "generated-secret-value",
		RefreshRequired:   true,
		ReconnectRequired: true,
		InvalidateRefs:    []string{"services/api-service/runtime/API_TOKEN"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "ready" || res.Ref != "services/api-service/runtime/API_TOKEN" {
		t.Fatalf("capture response = %#v", res)
	}
	resolved := backend.resolve(resolveRequest{ServiceID: "api-service", Refs: []string{"services/api-service/runtime/API_TOKEN"}})
	if resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != "generated-secret-value" {
		t.Fatalf("resolved generated secret = %#v", resolved.Results[0])
	}
	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditBytes), "generated-secret-value") {
		t.Fatalf("audit contains plaintext generated secret: %s", string(auditBytes))
	}
	for _, want := range []string{"writeback_capture", "api-service", "ready"} {
		if !strings.Contains(string(auditBytes), want) {
			t.Fatalf("audit missing %q: %s", want, string(auditBytes))
		}
	}
}

func TestGeneratedSecretCaptureDistinctFailureOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		backend     func(t *testing.T) *localBackend
		req         generatedSecretCaptureRequest
		wantErr     error
		wantOutcome string
	}{
		{
			name:        "policy denied",
			backend:     testBackend,
			req:         generatedSecretCaptureRequest{Identity: writebackIdentity{ServiceID: "api", ExpiresAt: "2026-05-07T00:05:00Z"}, Policy: writebackPolicy{AllowedNamespaces: []string{"other"}, AllowedOperations: []string{"create"}}, Operation: "create", Namespace: "services/api", Ref: "runtime/token", Value: "secret"},
			wantErr:     errPolicyDenied,
			wantOutcome: "policy_denied",
		},
		{
			name:        "expired identity",
			backend:     testBackend,
			req:         generatedSecretCaptureRequest{Identity: writebackIdentity{ServiceID: "api", ExpiresAt: "2026-05-06T23:59:00Z"}, Policy: writebackPolicy{AllowedNamespaces: []string{"services/api"}, AllowedOperations: []string{"create"}}, Operation: "create", Namespace: "services/api", Ref: "runtime/token", Value: "secret"},
			wantErr:     errIdentityExpired,
			wantOutcome: "identity_expired",
		},
		{
			name:        "locked broker",
			backend:     func(t *testing.T) *localBackend { b := testBackend(t); b.masterKey = ""; return b },
			req:         generatedSecretCaptureRequest{Identity: writebackIdentity{ServiceID: "api", ExpiresAt: "2026-05-07T00:05:00Z"}, Policy: writebackPolicy{AllowedNamespaces: []string{"services/api"}, AllowedOperations: []string{"create"}}, Operation: "create", Namespace: "services/api", Ref: "runtime/token", Value: "secret"},
			wantErr:     errLocked,
			wantOutcome: "locked",
		},
		{
			name:        "source auth required",
			backend:     testBackend,
			req:         generatedSecretCaptureRequest{Identity: writebackIdentity{ServiceID: "api", ExpiresAt: "2026-05-07T00:05:00Z"}, Policy: writebackPolicy{AllowedNamespaces: []string{"services/api"}, AllowedOperations: []string{"create"}}, Operation: "create", Namespace: "services/api", Ref: "runtime/token", Value: "secret", SourceAuthRequired: true},
			wantErr:     errSourceAuthRequired,
			wantOutcome: "source_auth_required",
		},
		{
			name: "degraded backend",
			backend: func(t *testing.T) *localBackend {
				b := testBackend(t)
				if err := os.MkdirAll(b.storePath, 0o700); err != nil {
					t.Fatal(err)
				}
				return b
			},
			req:         generatedSecretCaptureRequest{Identity: writebackIdentity{ServiceID: "api", ExpiresAt: "2026-05-07T00:05:00Z"}, Policy: writebackPolicy{AllowedNamespaces: []string{"services/api"}, AllowedOperations: []string{"create"}}, Operation: "create", Namespace: "services/api", Ref: "runtime/token", Value: "secret"},
			wantErr:     errBackendDegraded,
			wantOutcome: "degraded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := tt.backend(t).captureGeneratedSecret(tt.req)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if res.Outcome != tt.wantOutcome {
				t.Fatalf("outcome = %q, want %q", res.Outcome, tt.wantOutcome)
			}
		})
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
