package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	vaultMigrationToken       = "vault-migration-token-sentinel"
	vaultMigrationSecret      = "vault-migration-secret-sentinel"
	vaultMigrationRemoteBody  = "vault-remote-body-sentinel"
	vaultMigrationMappedPath  = "secret/data/serviceadmin"
	vaultMigrationMappedField = "session_key"
)

type vaultKVProtocolFixture struct {
	mu              sync.Mutex
	token           string
	data            map[string]any
	version         int
	getCount        int
	postCount       int
	forceGetStatus  int
	forcePostStatus int
	mismatchRead    bool
	lastCAS         int
	lastIdempotency string
}

func (f *vaultKVProtocolFixture) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/v1/"+vaultMigrationMappedPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Header.Get("X-Vault-Token") != f.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.getCount++
		if f.forceGetStatus != 0 {
			w.WriteHeader(f.forceGetStatus)
			fmt.Fprint(w, vaultMigrationRemoteBody)
			return
		}
		if f.version == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		data := make(map[string]any, len(f.data))
		for key, value := range f.data {
			data[key] = value
		}
		if f.mismatchRead {
			data[vaultMigrationMappedField] = "different-remote-value"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": f.version}}})
	case http.MethodPost:
		f.postCount++
		f.lastIdempotency = r.Header.Get("X-Service-Lasso-Idempotency-Key")
		if f.forcePostStatus != 0 {
			w.WriteHeader(f.forcePostStatus)
			fmt.Fprint(w, vaultMigrationRemoteBody)
			return
		}
		var payload struct {
			Data    map[string]any `json:"data"`
			Options struct {
				CAS int `json:"cas"`
			} `json:"options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.lastCAS = payload.Options.CAS
		if payload.Options.CAS != f.version {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.data = payload.Data
		f.version++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": f.version}})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestVaultKVMigrationExecutorPreservesFieldsUsesCASAndVerifies(t *testing.T) {
	for _, kind := range []string{"vault", "openbao"} {
		t.Run(kind, func(t *testing.T) {
			fixture := &vaultKVProtocolFixture{token: vaultMigrationToken, version: 7, data: map[string]any{"sibling": "preserve-me", vaultMigrationMappedField: "old-value"}}
			server := httptest.NewServer(http.HandlerFunc(fixture.handler))
			defer server.Close()
			executor := mustVaultKVMigrationExecutor(t, vaultMigrationSource(kind, server.URL, true))
			write := executor.Write(providerMigrationWriteRequest{OperationID: "vault-kv-write", IdempotencyKey: "safe-idempotency-key", TargetProviderID: kind + "-target", Ref: vaultMigrationRef(), Value: vaultMigrationSecret})
			if write.Outcome != "applied" {
				t.Fatalf("write=%#v", write)
			}
			verified := executor.Verify(providerMigrationVerifyRequest{OperationID: "vault-kv-write", IdempotencyKey: "safe-idempotency-key", TargetProviderID: kind + "-target", Ref: vaultMigrationRef(), ExpectedValue: vaultMigrationSecret})
			if verified.Outcome != "verified" {
				t.Fatalf("verify=%#v", verified)
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if fixture.lastCAS != 7 || fixture.version != 8 || fixture.data["sibling"] != "preserve-me" || fixture.data[vaultMigrationMappedField] != vaultMigrationSecret || fixture.lastIdempotency != "safe-idempotency-key" {
				t.Fatalf("protocol state=%#v", fixture)
			}
			if fixture.getCount != 2 || fixture.postCount != 1 {
				t.Fatalf("calls get=%d post=%d", fixture.getCount, fixture.postCount)
			}
		})
	}
}

func TestVaultKVMigrationExecutorAlreadyEqualSkipsWrite(t *testing.T) {
	fixture := &vaultKVProtocolFixture{token: vaultMigrationToken, version: 3, data: map[string]any{vaultMigrationMappedField: vaultMigrationSecret}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	executor := mustVaultKVMigrationExecutor(t, vaultMigrationSource("vault", server.URL, true))
	result := executor.Write(providerMigrationWriteRequest{IdempotencyKey: "safe-idempotency-key", Ref: vaultMigrationRef(), Value: vaultMigrationSecret})
	if result.Outcome != "applied" || fixture.postCount != 0 || fixture.getCount != 1 {
		t.Fatalf("result=%#v get=%d post=%d", result, fixture.getCount, fixture.postCount)
	}
}

func TestVaultKVMigrationExecutorRefreshesTokenEnvPerOperation(t *testing.T) {
	t.Setenv("VAULT_MIGRATION_TEST_TOKEN", "initial-token")
	fixture := &vaultKVProtocolFixture{token: "refreshed-token", data: map[string]any{}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	source := vaultMigrationSource("vault", server.URL, true)
	source.Token = ""
	source.TokenEnv = "VAULT_MIGRATION_TEST_TOKEN"
	executor := mustVaultKVMigrationExecutor(t, source)
	t.Setenv("VAULT_MIGRATION_TEST_TOKEN", "refreshed-token")
	result := executor.Write(providerMigrationWriteRequest{Ref: vaultMigrationRef(), Value: vaultMigrationSecret})
	if result.Outcome != "applied" || fixture.postCount != 1 {
		t.Fatalf("result=%#v posts=%d", result, fixture.postCount)
	}
}

func TestVaultKVMigrationApplyIsConnectionScopedVerifiedAndRestartSafe(t *testing.T) {
	fixture := &vaultKVProtocolFixture{token: vaultMigrationToken, data: map[string]any{}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	backend := managedTestBackend(t)
	ref := vaultMigrationRef()
	writeManagedTestSecret(t, backend, ref, vaultMigrationSecret)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{vaultMigrationSource("vault", server.URL, true)}}
	backend.configureProviderMigrationExecutors()

	status := backend.providerConfigStatusResponse()
	provider := providerStatusByID(t, status, "vault-migration-target")
	if migrationApplyMaturity(provider.Operations) != OperationMaturityValidated {
		t.Fatalf("connection operations=%#v", provider.Operations)
	}
	if migrationApplyMaturity(providerCapabilitiesByKind("vault").Operations) != OperationMaturityPlanned {
		t.Fatal("provider family capability must remain planned")
	}

	req := migrationPlanRequest{RequestID: "req-vault-migration", ServiceID: "@serviceadmin", OperationID: "vault-migration-operation", SourceProviderID: "local", TargetProviderID: "vault-migration-target", Refs: []string{ref}, Reason: "approved Vault migration", Confirm: true}
	applied, err := backend.migrationApply(req)
	if err != nil || !applied.Applied || applied.Outcome != "applied" || len(applied.Results) != 1 || !applied.Results[0].Verified {
		t.Fatalf("applied=%#v err=%v", applied, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), vaultMigrationSecret, vaultMigrationToken, vaultMigrationRemoteBody)
	assertVaultMigrationSourceUnchanged(t, backend, ref)
	fixture.mu.Lock()
	getCount, postCount := fixture.getCount, fixture.postCount
	fixture.mu.Unlock()

	restarted := newLocalBackend(backend.storePath, backend.auditPath, backend.masterKey)
	restarted.sources = backend.sources
	restarted.configureProviderMigrationExecutors()
	retried, err := restarted.migrationApply(req)
	if err != nil || !retried.Applied || retried.Outcome != "applied" {
		t.Fatalf("retried=%#v err=%v", retried, err)
	}
	fixture.mu.Lock()
	if fixture.getCount != getCount || fixture.postCount != postCount {
		t.Fatalf("restart retry repeated remote calls: before=%d/%d after=%d/%d", getCount, postCount, fixture.getCount, fixture.postCount)
	}
	fixture.mu.Unlock()
	assertVaultMigrationPersistenceRedacted(t, restarted)
}

func TestVaultKVMigrationRegistrationFailsClosedUnlessFullyConfigured(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*sourceConfig)
		want   string
	}{
		{name: "disabled capability", mutate: func(source *sourceConfig) { source.EnableMigrationTarget = false }, want: "ready"},
		{name: "missing token", mutate: func(source *sourceConfig) { source.Token = "" }, want: "source_auth_required"},
		{name: "unsafe address", mutate: func(source *sourceConfig) {
			source.Address = "https://user:password@vault.invalid/tenant?credential=value"
		}, want: "invalid_ref"},
		{name: "remote plaintext HTTP", mutate: func(source *sourceConfig) { source.Address = "http://vault.invalid" }, want: "invalid_ref"},
		{name: "invalid mapping", mutate: func(source *sourceConfig) {
			source.Refs[vaultMigrationRef()] = sourceRefConfig{Path: "../escape", Field: vaultMigrationMappedField}
		}, want: "invalid_ref"},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := managedTestBackend(t)
			source := vaultMigrationSource("vault", "https://vault.invalid", true)
			test.mutate(&source)
			backend.sources = sourceConfigFile{Sources: []sourceConfig{source}}
			backend.configureProviderMigrationExecutors()
			if _, ok := backend.providerMigrationExecutor(source.SourceID); ok {
				t.Fatal("invalid or disabled source registered an executor")
			}
			registry := defaultSourceRegistry(backend)
			if len(registry.Sources) != 2 || registry.Sources[1].Outcome != test.want || migrationApplyMaturity(registry.Sources[1].Operations) == OperationMaturityValidated {
				t.Fatalf("source status=%#v", registry.Sources)
			}
		})
	}
}

func TestVaultKVMigrationExecutorMapsRemoteFailuresWithoutLeakingBodies(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		want   string
	}{
		{name: "auth", status: http.StatusUnauthorized, want: "source_auth_required"},
		{name: "policy", status: http.StatusForbidden, want: "policy_denied"},
		{name: "rate limit", status: http.StatusTooManyRequests, want: "rate_limited"},
		{name: "unavailable", status: http.StatusServiceUnavailable, want: "source_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := &vaultKVProtocolFixture{token: vaultMigrationToken, forceGetStatus: test.status}
			server := httptest.NewServer(http.HandlerFunc(fixture.handler))
			defer server.Close()
			executor := mustVaultKVMigrationExecutor(t, vaultMigrationSource("vault", server.URL, true))
			result := executor.Write(providerMigrationWriteRequest{Ref: vaultMigrationRef(), Value: vaultMigrationSecret})
			if result.Outcome != test.want {
				t.Fatalf("result=%#v", result)
			}
			assertNoSecretMaterial(t, mustManagedJSON(t, result), vaultMigrationSecret, vaultMigrationToken, vaultMigrationRemoteBody)
		})
	}
}

func TestVaultKVMigrationExecutorMapsCASAndVerificationConflict(t *testing.T) {
	fixture := &vaultKVProtocolFixture{token: vaultMigrationToken, version: 2, data: map[string]any{vaultMigrationMappedField: "old-value"}, forcePostStatus: http.StatusBadRequest}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	executor := mustVaultKVMigrationExecutor(t, vaultMigrationSource("vault", server.URL, true))
	result := executor.Write(providerMigrationWriteRequest{Ref: vaultMigrationRef(), Value: vaultMigrationSecret})
	if result.Outcome != "conflict" {
		t.Fatalf("CAS result=%#v", result)
	}
	fixture.forcePostStatus = 0
	if result = executor.Write(providerMigrationWriteRequest{Ref: vaultMigrationRef(), Value: vaultMigrationSecret}); result.Outcome != "applied" {
		t.Fatalf("write result=%#v", result)
	}
	fixture.mismatchRead = true
	verified := executor.Verify(providerMigrationVerifyRequest{Ref: vaultMigrationRef(), ExpectedValue: vaultMigrationSecret})
	if verified.Outcome != "verification_failed" {
		t.Fatalf("verify result=%#v", verified)
	}
}

func TestVaultKVMigrationExecutorRejectsRedirectsOversizeAndTimeout(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		redirected := 0
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
		defer target.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer server.Close()
		executor := mustVaultKVMigrationExecutor(t, vaultMigrationSource("vault", server.URL, true))
		result := executor.Write(providerMigrationWriteRequest{Ref: vaultMigrationRef(), Value: vaultMigrationSecret})
		if result.Outcome != "source_unavailable" || redirected != 0 {
			t.Fatalf("redirect result=%#v followed=%d", result, redirected)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", 65)) }))
		defer server.Close()
		source := vaultMigrationSource("vault", server.URL, true)
		mapping := source.Refs[vaultMigrationRef()]
		mapping.MaxBytes = 64
		source.Refs[vaultMigrationRef()] = mapping
		executor := mustVaultKVMigrationExecutor(t, source)
		if result := executor.Write(providerMigrationWriteRequest{Ref: vaultMigrationRef(), Value: vaultMigrationSecret}); result.Outcome != "source_unavailable" {
			t.Fatalf("oversize result=%#v", result)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(250 * time.Millisecond) }))
		defer server.Close()
		source := vaultMigrationSource("vault", server.URL, true)
		mapping := source.Refs[vaultMigrationRef()]
		mapping.TimeoutMs = 100
		source.Refs[vaultMigrationRef()] = mapping
		executor := mustVaultKVMigrationExecutor(t, source)
		started := time.Now()
		result := executor.Write(providerMigrationWriteRequest{Ref: vaultMigrationRef(), Value: vaultMigrationSecret})
		if result.Outcome != "source_unavailable" || time.Since(started) > time.Second {
			t.Fatalf("timeout result=%#v elapsed=%s", result, time.Since(started))
		}
	})
}

func TestVaultKVMigrationCASConflictIsTypedThroughMigrationAPI(t *testing.T) {
	fixture := &vaultKVProtocolFixture{token: vaultMigrationToken, version: 1, data: map[string]any{vaultMigrationMappedField: "old"}, forcePostStatus: http.StatusBadRequest}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	backend := managedTestBackend(t)
	ref := vaultMigrationRef()
	writeManagedTestSecret(t, backend, ref, vaultMigrationSecret)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{vaultMigrationSource("openbao", server.URL, true)}}
	backend.configureProviderMigrationExecutors()
	req := migrationPlanRequest{RequestID: "req-openbao-conflict", ServiceID: "@serviceadmin", OperationID: "openbao-cas-conflict", SourceProviderID: "local", TargetProviderID: "vault-migration-target", Refs: []string{ref}, Reason: "approved conflict proof", Confirm: true}
	res, err := backend.migrationApply(req)
	if err != nil || res.Outcome != "partial_failure" || res.Applied || len(res.Results) != 1 || res.Results[0].Outcome != "conflict" || res.Results[0].ExpectedAction != "refresh_target_version_and_retry" {
		t.Fatalf("res=%#v err=%v", res, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, res), vaultMigrationSecret, vaultMigrationToken, vaultMigrationRemoteBody)
	fixture.mu.Lock()
	fixture.forcePostStatus = 0
	fixture.mu.Unlock()
	res, err = backend.migrationApply(req)
	if err != nil || !res.Applied || res.Outcome != "applied" || !res.Results[0].Verified || res.Results[0].Attempts != 2 {
		t.Fatalf("retried=%#v err=%v", res, err)
	}
}

func vaultMigrationSource(kind, address string, enabled bool) sourceConfig {
	return sourceConfig{
		SourceID: "vault-migration-target", Kind: kind, DisplayName: "Vault migration target", Enabled: true, EnableMigrationTarget: enabled,
		Address: address, Token: vaultMigrationToken,
		Refs: map[string]sourceRefConfig{vaultMigrationRef(): {Path: vaultMigrationMappedPath, Field: vaultMigrationMappedField, TimeoutMs: 1000, MaxBytes: 4096}},
	}
}

func vaultMigrationRef() string {
	return "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
}

func mustVaultKVMigrationExecutor(t *testing.T, source sourceConfig) *vaultKVMigrationExecutor {
	t.Helper()
	executor, err := newVaultKVMigrationExecutor(source)
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func providerStatusByID(t *testing.T, status providerConfigStatusResponse, providerID string) providerConfigStatus {
	t.Helper()
	for _, provider := range status.Providers {
		if provider.ProviderID == providerID {
			return provider
		}
	}
	t.Fatalf("missing provider %s", providerID)
	return providerConfigStatus{}
}

func migrationApplyMaturity(operations []OperationCapability) OperationMaturity {
	for _, operation := range operations {
		if operation.Path == "/v1/providers/migration/apply" {
			return operation.Maturity
		}
	}
	return OperationMaturityUnavailable
}

func assertVaultMigrationSourceUnchanged(t *testing.T, backend *localBackend, ref string) {
	t.Helper()
	resolved := backend.resolve(resolveRequest{RequestID: "req-vault-source-proof", ServiceID: "@serviceadmin", Purpose: "source recovery proof", Refs: []string{ref}})
	if len(resolved.Results) != 1 || resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != vaultMigrationSecret {
		t.Fatalf("source not recoverable: %#v", resolved.Results)
	}
}

func assertVaultMigrationPersistenceRedacted(t *testing.T, backend *localBackend) {
	t.Helper()
	store, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, store, vaultMigrationSecret, vaultMigrationToken, vaultMigrationRemoteBody, vaultMigrationMappedPath)
	assertNoSecretMaterial(t, audit, vaultMigrationSecret, vaultMigrationToken, vaultMigrationRemoteBody, vaultMigrationMappedPath)
	if strings.Contains(string(store), filepath.Clean(vaultMigrationMappedPath)) {
		t.Fatal("provider path leaked into durable operation state")
	}
}

func TestVaultKVMigrationRequestBodyBoundIsEnforced(t *testing.T) {
	fixture := &vaultKVProtocolFixture{token: vaultMigrationToken, data: map[string]any{}}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	source := vaultMigrationSource("vault", server.URL, true)
	mapping := source.Refs[vaultMigrationRef()]
	mapping.MaxBytes = 64
	source.Refs[vaultMigrationRef()] = mapping
	executor := mustVaultKVMigrationExecutor(t, source)
	result := executor.Write(providerMigrationWriteRequest{Ref: vaultMigrationRef(), Value: strings.Repeat("s", 256)})
	if result.Outcome != "invalid_ref" || fixture.postCount != 0 {
		t.Fatalf("result=%#v posts=%d", result, fixture.postCount)
	}
	assertNoSecretMaterial(t, bytes.TrimSpace(mustManagedJSON(t, result)), strings.Repeat("s", 256), vaultMigrationToken)
}
