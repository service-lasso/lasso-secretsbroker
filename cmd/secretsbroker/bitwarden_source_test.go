package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBitwardenBWSSourceAdapterAPISuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secrets/secret-123" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer fake-bws-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"data":{"value":"bws-secret-value"}}`)
	}))
	defer server.Close()

	cfg := sourceConfigFile{Sources: []sourceConfig{{SourceID: "bws-prod", Kind: "bitwarden-bws", Enabled: true, Address: server.URL, Token: "fake-bws-token", Refs: map[string]sourceRefConfig{"prod/openclaw/api_key": {Path: "secret-123"}}}}}
	res := cfg.resolve("prod/openclaw/api_key")
	if res.Outcome != "ready" || res.Value != "bws-secret-value" || res.SourceID != "bws-prod" {
		t.Fatalf("bitwarden result = %#v", res)
	}
}

func TestBitwardenBWSSourceAdapterStatusMapping(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		outcome string
	}{
		{name: "auth required", status: http.StatusUnauthorized, outcome: "source_auth_required"},
		{name: "policy denied", status: http.StatusForbidden, outcome: "policy_denied"},
		{name: "missing ref", status: http.StatusNotFound, outcome: "missing_ref"},
		{name: "degraded", status: http.StatusTooManyRequests, outcome: "degraded"},
		{name: "identity expired body", status: http.StatusUnauthorized, body: `{"outcome":"identity_expired","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"}`, outcome: "identity_expired"},
		{name: "unavailable", status: http.StatusInternalServerError, outcome: "source_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			source := sourceConfig{SourceID: "bws", Kind: "bitwarden-bws", Enabled: true, Address: server.URL, Token: "fake-bws-token"}
			res := source.resolve("ref", sourceRefConfig{Path: "secret-123"})
			if res.Outcome != tt.outcome || res.Value != "" {
				t.Fatalf("outcome = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message, "outcome": res.Outcome})
		})
	}
}

func TestBitwardenBWSSourceAdapterRequiresTokenAndMapping(t *testing.T) {
	missingToken := sourceConfig{SourceID: "bws", Kind: "bitwarden-bws", Enabled: true, Address: "https://bws.invalid"}
	res := missingToken.resolve("ref", sourceRefConfig{Path: "secret-123"})
	if res.Outcome != "source_auth_required" {
		t.Fatalf("missing token outcome = %#v", res)
	}

	missingMapping := sourceConfig{SourceID: "bws", Kind: "bitwarden-bws", Enabled: true, Address: "https://bws.invalid", Token: "fake-bws-token"}
	res = missingMapping.resolve("ref", sourceRefConfig{})
	if res.Outcome != "invalid_ref" {
		t.Fatalf("missing mapping outcome = %#v", res)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
}

func TestBitwardenBWSSourceAdapterBoundsAPIResponseWithoutLeaking(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"value":"`+strings.Repeat("A", 64)+`SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE"}`)
	}))
	defer server.Close()

	source := sourceConfig{SourceID: "bws", Kind: "bitwarden-bws", Enabled: true, Address: server.URL, Token: "fake-bws-token"}
	res := source.resolve("ref", sourceRefConfig{Path: "secret-123", MaxStdoutBytes: 16})
	if res.Outcome != "source_unavailable" || res.Value != "" {
		t.Fatalf("oversized result = %#v", res)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
}

func TestBitwardenBWSSourceAdapterCLISuccessAndOutcomes(t *testing.T) {
	cases := []struct {
		mode        string
		wantOutcome string
		wantValue   string
	}{
		{mode: "success", wantOutcome: "ready", wantValue: "bws-cli-secret"},
		{mode: "auth-required", wantOutcome: "source_auth_required"},
		{mode: "policy-denied", wantOutcome: "policy_denied"},
		{mode: "missing-ref", wantOutcome: "missing_ref"},
		{mode: "degraded", wantOutcome: "degraded"},
		{mode: "invalid-ref", wantOutcome: "invalid_ref"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			source, refCfg := bitwardenBWSCLIFixture(t, tc.mode)
			res := source.resolve("ref", refCfg)
			if res.Outcome != tc.wantOutcome || res.Value != tc.wantValue {
				t.Fatalf("cli result = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
		})
	}
}

func TestBitwardenBWSSourceAdapterCLIHandlesFailureTimeoutAndLimit(t *testing.T) {
	cases := []struct {
		name string
		mode string
	}{
		{name: "failure", mode: "failure"},
		{name: "timeout", mode: "timeout"},
		{name: "invalid json", mode: "invalid-json"},
		{name: "oversized", mode: "oversized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source, refCfg := bitwardenBWSCLIFixture(t, tc.mode)
			refCfg.TimeoutMs = 50
			if tc.mode == "oversized" {
				refCfg.MaxStdoutBytes = 16
			}
			res := source.resolve("ref", refCfg)
			if res.Outcome != "source_unavailable" || res.Value != "" {
				t.Fatalf("cli result = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
		})
	}
}

func TestBitwardenBWSSourceStatusReportsContractCapabilities(t *testing.T) {
	caps := capabilitiesForSourceKind("bitwarden-bws")
	for _, capability := range []string{"read", "reveal", "write/update", "audit", "migration", "health"} {
		assertContains(t, caps, capability)
	}
	for _, capability := range []string{"rotate/reset", "policy", "value-search"} {
		assertNotContains(t, caps, capability)
	}
}

func TestBitwardenBWSSourceRegistryStateAndNoTokenLeak(t *testing.T) {
	backend := newLocalBackend("store.json", "audit.jsonl", "master-key")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID:   "bws-prod",
		Kind:       "bitwarden-bws",
		Enabled:    true,
		Address:    "https://bws.example.com",
		TokenEnv:   "MISSING_BWS_TOKEN",
		Namespaces: []string{"prod/*"},
		Refs:       map[string]sourceRefConfig{"prod/openclaw/api_key": {Path: "secret-123"}},
	}}}

	registry := defaultSourceRegistry(backend)
	if len(registry.Sources) != 2 {
		t.Fatalf("sources = %#v", registry.Sources)
	}
	bws := registry.Sources[1]
	if bws.SourceID != "bws-prod" || bws.State != "auth_required" || bws.Outcome != "source_auth_required" {
		t.Fatalf("bws source = %#v", bws)
	}
	assertContains(t, bws.Capabilities, "write/update")
	assertContains(t, bws.Capabilities, "migration")
	assertContains(t, bws.Namespaces, "prod/*")
	assertNoSecretMaterialSurfaces(t, map[string]string{
		"sourceID":   bws.SourceID,
		"kind":       bws.Kind,
		"outcome":    bws.Outcome,
		"nextAction": bws.NextAction,
	})
}

func bitwardenBWSCLIFixture(t *testing.T, mode string) (sourceConfig, sourceRefConfig) {
	t.Helper()
	command, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	source := sourceConfig{
		SourceID:            "bws-cli",
		Kind:                "bitwarden-bws",
		Enabled:             true,
		Token:               "fake-bws-token",
		TrustedDirs:         []string{filepath.Dir(command)},
		AllowSymlinkCommand: true,
	}
	refCfg := sourceRefConfig{
		Path:           "secret-123",
		Command:        command,
		Args:           []string{"-test.run=TestBitwardenBWSSourceHelperProcess", "--", mode},
		TimeoutMs:      2000,
		MaxStdoutBytes: 4096,
	}
	return source, refCfg
}

func TestBitwardenBWSSourceHelperProcess(t *testing.T) {
	args := os.Args
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator == -1 || separator+1 >= len(args) {
		return
	}
	if os.Getenv("BWS_ACCESS_TOKEN") == "" || os.Getenv("BITWARDEN_BWS_SECRET_ID") != "secret-123" {
		os.Exit(3)
	}
	switch args[separator+1] {
	case "success":
		os.Stdout.WriteString(`{"value":"bws-cli-secret"}`)
	case "auth-required":
		os.Stdout.WriteString(`{"outcome":"source_auth_required","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"}`)
	case "policy-denied":
		os.Stdout.WriteString(`{"outcome":"policy_denied","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE"}`)
	case "missing-ref":
		os.Stdout.WriteString(`{"outcome":"missing_ref","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"}`)
	case "degraded":
		os.Stdout.WriteString(`{"outcome":"degraded","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"}`)
	case "invalid-ref":
		os.Stdout.WriteString(`{"outcome":"invalid_ref","message":"-----BEGIN SERVICE LASSO FAKE PRIVATE KEY-----"}`)
	case "invalid-json":
		os.Stdout.WriteString(`not-json SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE`)
	case "oversized":
		os.Stdout.WriteString(strings.Repeat("A", 64) + "SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE")
	case "failure":
		os.Stdout.WriteString(`SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE`)
		os.Stderr.WriteString(`SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE`)
		os.Exit(2)
	case "timeout":
		time.Sleep(2 * time.Second)
	}
	os.Exit(0)
}
