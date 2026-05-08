package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNormalizeSourceLifecycleStates(t *testing.T) {
	tests := []struct {
		outcome    string
		state      string
		nextAction string
		retryable  bool
	}{
		{outcome: "ready", state: "connected"},
		{outcome: "missing_ref", state: "missing", nextAction: "check_ref"},
		{outcome: "policy_denied", state: "denied", nextAction: "review_policy"},
		{outcome: "source_auth_required", state: "auth_required", nextAction: "reconnect_source"},
		{outcome: "identity_expired", state: "revoked", nextAction: "renew_identity"},
		{outcome: "locked", state: "reconnect_required", nextAction: "unlock_or_unseal_source"},
		{outcome: "invalid_ref", state: "config_error", nextAction: "fix_source_mapping"},
		{outcome: "source_unavailable", state: "degraded", nextAction: "retry_or_inspect_source", retryable: true},
	}
	for _, tt := range tests {
		t.Run(tt.outcome, func(t *testing.T) {
			got := normalizeSourceLifecycle(tt.outcome)
			if got.State != tt.state || got.Outcome != tt.outcome || got.NextAction != tt.nextAction || got.Retryable != tt.retryable {
				t.Fatalf("lifecycle = %#v", got)
			}
			if tt.retryable && got.RetryAfterMs <= 0 {
				t.Fatalf("retryable lifecycle missing retryAfterMs: %#v", got)
			}
		})
	}
}

func TestSourceResolveResultCarriesNormalizedLifecycle(t *testing.T) {
	t.Setenv("SOURCE_LIFECYCLE_SECRET", "secret-value")
	cfg := sourceConfigFile{Sources: []sourceConfig{
		{SourceID: "env-ready", Kind: "env", Enabled: true, Refs: map[string]sourceRefConfig{"ready/ref": {Env: "SOURCE_LIFECYCLE_SECRET"}}},
		{SourceID: "env-missing", Kind: "env", Enabled: true, Refs: map[string]sourceRefConfig{"missing/ref": {Env: "SOURCE_LIFECYCLE_MISSING"}}},
	}}
	ready := cfg.resolve("ready/ref")
	if ready.Outcome != "ready" || ready.Lifecycle.State != "connected" || ready.Value != "secret-value" {
		t.Fatalf("ready result = %#v", ready)
	}
	missing := cfg.resolve("missing/ref")
	if missing.Outcome != "source_unavailable" || missing.Lifecycle.State != "degraded" || !missing.Lifecycle.Retryable || missing.Value != "" {
		t.Fatalf("missing env result = %#v", missing)
	}
}

func TestSourceRegistryExposesSafeLifecycleMetadata(t *testing.T) {
	t.Setenv("REGISTRY_ENV_SECRET", "do-not-leak")
	backend := testBackend(t)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{
		{SourceID: "env-source", Kind: "env", Enabled: true, Namespaces: []string{"services/api"}, Refs: map[string]sourceRefConfig{"services/api/SECRET": {Env: "REGISTRY_ENV_SECRET"}}},
		{SourceID: "vault-auth", Kind: "vault", Enabled: true, Address: "https://vault.invalid", TokenEnv: "MISSING_VAULT_TOKEN", Refs: map[string]sourceRefConfig{"vault/ref": {Path: "secret/data/ref", Field: "value"}}},
		{SourceID: "bad-source", Kind: "unknown", Enabled: true},
	}}
	registry := defaultSourceRegistry(backend)
	byID := map[string]SourceStatus{}
	for _, source := range registry.Sources {
		byID[source.SourceID] = source
	}
	if byID["local"].State != "connected" || byID["local"].Outcome != "ready" {
		t.Fatalf("local status = %#v", byID["local"])
	}
	if byID["env-source"].State != "connected" || byID["env-source"].Outcome != "ready" {
		t.Fatalf("env status = %#v", byID["env-source"])
	}
	if byID["vault-auth"].State != "auth_required" || byID["vault-auth"].NextAction != "reconnect_source" {
		t.Fatalf("vault status = %#v", byID["vault-auth"])
	}
	if byID["bad-source"].State != "config_error" || byID["bad-source"].NextAction != "fix_source_mapping" {
		t.Fatalf("bad status = %#v", byID["bad-source"])
	}
	if strings.Contains(string(mustJSON(t, registry)), "do-not-leak") {
		t.Fatalf("source registry leaked secret value: %#v", registry)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	bytes, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func TestSourceLifecycleAuditRedactsValues(t *testing.T) {
	backend := testBackend(t)
	if err := os.Setenv("AUDIT_SOURCE_SECRET", "audit-secret-value"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("AUDIT_SOURCE_SECRET")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{SourceID: "env-audit", Kind: "env", Enabled: true, Refs: map[string]sourceRefConfig{"services/api/AUDIT_SECRET": {Env: "AUDIT_SOURCE_SECRET"}}}}}
	res := backend.resolve(resolveRequest{RequestID: "req-audit", ServiceID: "api", Refs: []string{"services/api/AUDIT_SECRET"}})
	if res.Results[0].Outcome != "ready" || res.Results[0].Value != "audit-secret-value" {
		t.Fatalf("resolve = %#v", res.Results[0])
	}
	bytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(bytes)
	if strings.Contains(text, "audit-secret-value") {
		t.Fatalf("audit leaked source secret: %s", text)
	}
	for _, want := range []string{"source_lifecycle", "connected", "env-audit", "ready"} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit missing %q: %s", want, text)
		}
	}
}
