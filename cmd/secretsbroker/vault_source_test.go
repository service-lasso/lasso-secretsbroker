package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultSourceAdapterKVv2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"data":{"data":{"api_key":"vault-secret"}}}`)
	}))
	defer server.Close()

	cfg := sourceConfigFile{Sources: []sourceConfig{{SourceID: "vault-prod", Kind: "vault", Enabled: true, Address: server.URL, Token: "test-token", Refs: map[string]sourceRefConfig{"prod/openclaw/api_key": {Path: "secret/data/openclaw", Field: "api_key"}}}}}
	res := cfg.resolve("prod/openclaw/api_key")
	if res.Outcome != "ready" || res.Value != "vault-secret" || res.SourceID != "vault-prod" {
		t.Fatalf("vault result = %#v", res)
	}
}

func TestVaultSourceAdapterStatusMapping(t *testing.T) {
	tests := []struct {
		status  int
		body    string
		outcome string
	}{
		{status: http.StatusUnauthorized, outcome: "source_auth_required"},
		{status: http.StatusForbidden, outcome: "policy_denied"},
		{status: http.StatusNotFound, outcome: "missing_ref"},
		{status: http.StatusBadRequest, body: `{"errors":["invalid source mapping"]}`, outcome: "invalid_ref"},
		{status: http.StatusTooManyRequests, body: `{"errors":["rate limit exceeded"]}`, outcome: "degraded"},
		{status: http.StatusServiceUnavailable, body: `{"sealed":true}`, outcome: "locked"},
		{status: http.StatusInternalServerError, outcome: "source_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.outcome, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			source := sourceConfig{SourceID: "vault", Kind: "openbao", Enabled: true, Address: server.URL, Token: "token"}
			res := source.resolve("ref", sourceRefConfig{Path: "secret/data/ref", Field: "value"})
			if res.Outcome != tt.outcome {
				t.Fatalf("outcome = %#v", res)
			}
		})
	}
}

func TestVaultSourceOutcomeBodyMappingIsMetadataOnly(t *testing.T) {
	secretMarker := "SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"outcome":"policy_denied","errors":["%s"]}`, secretMarker)
	}))
	defer server.Close()

	source := sourceConfig{SourceID: "vault", Kind: "vault", Enabled: true, Address: server.URL, Token: "token"}
	res := source.resolve("ref", sourceRefConfig{Path: "secret/data/ref", Field: "value"})
	if res.Outcome != "policy_denied" || res.Value != "" {
		t.Fatalf("outcome = %#v", res)
	}
	assertNoSecretMaterial(t, []byte(res.Message), secretMarker, "token")
}

func TestVaultSourceMissingTokenRequiresAuth(t *testing.T) {
	source := sourceConfig{SourceID: "vault", Kind: "vault", Address: "https://vault.invalid"}
	res := source.resolve("ref", sourceRefConfig{Path: "secret/data/ref", Field: "value"})
	if res.Outcome != "source_auth_required" {
		t.Fatalf("outcome = %#v", res)
	}
}

func TestVaultSourceUsesTokenEnv(t *testing.T) {
	t.Setenv("VAULT_TEST_TOKEN", "env-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "env-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"data":{"api_key":"flat-secret"}}`)
	}))
	defer server.Close()

	source := sourceConfig{SourceID: "vault", Kind: "vault", Address: server.URL, TokenEnv: "VAULT_TEST_TOKEN"}
	res := source.resolve("ref", sourceRefConfig{Path: "secret/data/ref", Field: "api_key"})
	if res.Outcome != "ready" || res.Value != "flat-secret" {
		t.Fatalf("result = %#v", res)
	}
}
