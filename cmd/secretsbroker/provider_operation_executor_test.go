package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const testProviderResponseBody = "provider-response-body-must-never-leak"

type deterministicMigrationExecutor struct {
	mu             sync.Mutex
	values         map[string]string
	writeCalls     map[string]int
	verifyCalls    map[string]int
	writeOutcomes  map[string]string
	verifyOutcomes map[string]string
}

func newDeterministicMigrationExecutor() *deterministicMigrationExecutor {
	return &deterministicMigrationExecutor{
		values:         map[string]string{},
		writeCalls:     map[string]int{},
		verifyCalls:    map[string]int{},
		writeOutcomes:  map[string]string{},
		verifyOutcomes: map[string]string{},
	}
}

func (e *deterministicMigrationExecutor) Write(req providerMigrationWriteRequest) providerMigrationExecutorResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writeCalls[req.Ref]++
	outcome := firstNonEmpty(e.writeOutcomes[req.Ref], "applied")
	if outcome == "applied" {
		e.values[req.Ref] = req.Value
	}
	return providerMigrationExecutorResult{Outcome: outcome}
}

func (e *deterministicMigrationExecutor) Verify(req providerMigrationVerifyRequest) providerMigrationExecutorResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.verifyCalls[req.Ref]++
	if outcome := e.verifyOutcomes[req.Ref]; outcome != "" {
		return providerMigrationExecutorResult{Outcome: outcome}
	}
	if e.values[req.Ref] != req.ExpectedValue {
		return providerMigrationExecutorResult{Outcome: "verification_failed"}
	}
	return providerMigrationExecutorResult{Outcome: "verified"}
}

func TestProviderMigrationExecutorEndToEndIsVerifiedDurableAndIdempotent(t *testing.T) {
	backend, executor, refs, values := executableMigrationTestBackend(t)
	req := migrationPlanRequest{RequestID: "req-executor-success", ServiceID: "@serviceadmin", OperationID: "migration-executor-success", SourceProviderID: "local", TargetProviderID: "vault-test-double", Refs: refs, Confirm: true, Reason: "approved deterministic migration"}

	applied, err := backend.migrationApply(req)
	if err != nil || !applied.Applied || applied.Outcome != "applied" || applied.AuditStatus != "audit_recorded" {
		t.Fatalf("applied=%#v err=%v", applied, err)
	}
	for _, item := range applied.Results {
		if item.Outcome != "migrated" || !item.Verified || item.Attempts != 1 {
			t.Fatalf("item=%#v", item)
		}
		if executor.values[item.Ref] != values[item.Ref] || executor.writeCalls[item.Ref] != 1 || executor.verifyCalls[item.Ref] != 1 {
			t.Fatalf("executor state ref=%s writes=%d verifies=%d", item.Ref, executor.writeCalls[item.Ref], executor.verifyCalls[item.Ref])
		}
	}
	assertMigrationSourcesUnchanged(t, backend, values)
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), values[refs[0]], values[refs[1]], providerCredentialValue, testProviderResponseBody)

	storeBeforeRetry := readRotationStore(t, backend)
	retried, err := backend.migrationApply(req)
	if err != nil || !retried.Applied || retried.Outcome != "applied" {
		t.Fatalf("retried=%#v err=%v", retried, err)
	}
	if !bytes.Equal(storeBeforeRetry, readRotationStore(t, backend)) {
		t.Fatal("exact verified retry rewrote durable operation state")
	}
	for _, ref := range refs {
		if executor.writeCalls[ref] != 1 || executor.verifyCalls[ref] != 1 {
			t.Fatalf("exact retry repeated executor calls for %s: writes=%d verifies=%d", ref, executor.writeCalls[ref], executor.verifyCalls[ref])
		}
	}
}

func TestProviderMigrationPartialFailureResumesAfterRestartWithoutRewritingVerifiedRefs(t *testing.T) {
	backend, executor, refs, values := executableMigrationTestBackend(t)
	executor.writeOutcomes[refs[1]] = "rate_limited"
	req := migrationPlanRequest{RequestID: "req-executor-partial", ServiceID: "@serviceadmin", OperationID: "migration-executor-partial", SourceProviderID: "local", TargetProviderID: "vault-test-double", Refs: refs, Confirm: true, Reason: "approved resumable migration"}

	partial, err := backend.migrationApply(req)
	if err != nil || partial.Applied || partial.Outcome != "partial_failure" {
		t.Fatalf("partial=%#v err=%v", partial, err)
	}
	if !partial.Results[0].Verified || partial.Results[1].Outcome != "rate_limited" {
		t.Fatalf("partial results=%#v", partial.Results)
	}
	assertMigrationSourcesUnchanged(t, backend, values)

	restarted := newLocalBackend(backend.storePath, backend.auditPath, backend.masterKey)
	restarted.sources = backend.sources
	restarted.registerProviderMigrationExecutor("vault-test-double", executor)
	executor.writeOutcomes[refs[1]] = "applied"
	resumed, err := restarted.migrationApply(req)
	if err != nil || !resumed.Applied || resumed.Outcome != "applied" {
		t.Fatalf("resumed=%#v err=%v", resumed, err)
	}
	if executor.writeCalls[refs[0]] != 1 || executor.verifyCalls[refs[0]] != 1 {
		t.Fatalf("verified ref was repeated after restart: writes=%d verifies=%d", executor.writeCalls[refs[0]], executor.verifyCalls[refs[0]])
	}
	if executor.writeCalls[refs[1]] != 2 || executor.verifyCalls[refs[1]] != 1 {
		t.Fatalf("failed ref did not resume exactly once: writes=%d verifies=%d", executor.writeCalls[refs[1]], executor.verifyCalls[refs[1]])
	}
	assertMigrationSourcesUnchanged(t, restarted, values)
	assertMigrationPersistenceIsMetadataOnly(t, restarted, values)
}

func TestProviderMigrationVerificationRetryDoesNotRewriteTarget(t *testing.T) {
	backend, executor, refs, _ := executableMigrationTestBackend(t)
	ref := refs[0]
	executor.verifyOutcomes[ref] = "verification_failed"
	req := migrationPlanRequest{RequestID: "req-verify-retry", ServiceID: "@serviceadmin", OperationID: "migration-verify-retry", SourceProviderID: "local", TargetProviderID: "vault-test-double", Refs: []string{ref}, Confirm: true, Reason: "approved verification retry"}

	partial, err := backend.migrationApply(req)
	if err != nil || partial.Outcome != "partial_failure" || partial.Results[0].Outcome != "verification_failed" {
		t.Fatalf("partial=%#v err=%v", partial, err)
	}
	executor.verifyOutcomes[ref] = "verified"
	resumed, err := backend.migrationApply(req)
	if err != nil || resumed.Outcome != "applied" || !resumed.Results[0].Verified {
		t.Fatalf("resumed=%#v err=%v", resumed, err)
	}
	if executor.writeCalls[ref] != 1 || executor.verifyCalls[ref] != 2 {
		t.Fatalf("verification retry calls writes=%d verifies=%d", executor.writeCalls[ref], executor.verifyCalls[ref])
	}
}

func TestProviderMigrationChangedPlanConflictsWithoutExecutorCalls(t *testing.T) {
	backend, executor, refs, _ := executableMigrationTestBackend(t)
	req := migrationPlanRequest{RequestID: "req-plan-conflict", ServiceID: "@serviceadmin", OperationID: "migration-plan-conflict", SourceProviderID: "local", TargetProviderID: "vault-test-double", Refs: []string{refs[0]}, Confirm: true, Reason: "approved migration"}
	if _, err := backend.migrationApply(req); err != nil {
		t.Fatal(err)
	}
	req.Refs = refs
	conflict, err := backend.migrationApply(req)
	if !errors.Is(err, errMigrationPlanConflict) || conflict.Outcome != "conflict" || conflict.Applied || conflict.NextAction != "create_new_operation_id_for_changed_plan" {
		t.Fatalf("conflict=%#v err=%v", conflict, err)
	}
	if executor.writeCalls[refs[0]] != 1 || executor.writeCalls[refs[1]] != 0 {
		t.Fatalf("changed plan reached executor: %#v", executor.writeCalls)
	}
	req.Refs = []string{refs[0]}
	req.TargetProviderID = "openbao-without-executor"
	conflict, err = backend.migrationApply(req)
	if !errors.Is(err, errMigrationPlanConflict) || conflict.Outcome != "conflict" {
		t.Fatalf("changed target conflict=%#v err=%v", conflict, err)
	}
}

func TestProviderMigrationAuditPreflightFailsClosedBeforeExecutor(t *testing.T) {
	backend, executor, refs, values := executableMigrationTestBackend(t)
	blockedAudit := filepath.Join(t.TempDir(), "audit-is-directory")
	if err := os.Mkdir(blockedAudit, 0o700); err != nil {
		t.Fatal(err)
	}
	backend.auditPath = blockedAudit
	res, err := backend.migrationApply(migrationPlanRequest{RequestID: "req-audit-preflight", ServiceID: "@serviceadmin", OperationID: "migration-audit-preflight", SourceProviderID: "local", TargetProviderID: "vault-test-double", Refs: refs, Confirm: true, Reason: "approved migration"})
	if !errors.Is(err, errProviderAuditUnavailable) || res.Outcome != "audit_unavailable" || res.Applied {
		t.Fatalf("res=%#v err=%v", res, err)
	}
	for _, ref := range refs {
		if executor.writeCalls[ref] != 0 || executor.verifyCalls[ref] != 0 {
			t.Fatalf("audit preflight failure reached executor for %s", ref)
		}
	}
	assertMigrationSourcesUnchanged(t, backend, values)
}

func TestProviderMigrationEmptyAuditPathFailsClosedBeforeExecutor(t *testing.T) {
	backend, executor, refs, _ := executableMigrationTestBackend(t)
	backend.auditPath = ""
	res, err := backend.migrationApply(migrationPlanRequest{RequestID: "req-empty-audit", ServiceID: "@serviceadmin", OperationID: "migration-empty-audit", SourceProviderID: "local", TargetProviderID: "vault-test-double", Refs: refs, Confirm: true, Reason: "approved migration"})
	if !errors.Is(err, errProviderAuditUnavailable) || res.Outcome != "audit_unavailable" || res.Applied {
		t.Fatalf("res=%#v err=%v", res, err)
	}
	for _, ref := range refs {
		if executor.writeCalls[ref] != 0 || executor.verifyCalls[ref] != 0 {
			t.Fatalf("empty audit path reached executor for %s", ref)
		}
	}
}

func TestProviderMigrationExecutorHTTPApplyAndPlanConflictAreTypedAndRedacted(t *testing.T) {
	backend, _, refs, values := executableMigrationTestBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()
	req := migrationPlanRequest{RequestID: "req-http-executor", ServiceID: "@serviceadmin", OperationID: "migration-http-executor", SourceProviderID: "local", TargetProviderID: "vault-test-double", Refs: []string{refs[0]}, Confirm: true, Reason: "approved HTTP migration"}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	applied := postRotationTestRequest(t, server.URL+"/v1/providers/migration/apply", body)
	if applied.StatusCode != http.StatusOK || !bytes.Contains(applied.Body, []byte(`"outcome":"applied"`)) || !bytes.Contains(applied.Body, []byte(`"verified":true`)) {
		t.Fatalf("status=%d body=%s", applied.StatusCode, applied.Body)
	}
	assertNoSecretMaterial(t, applied.Body, values[refs[0]], providerCredentialValue, testProviderResponseBody, "test-token")

	req.Refs = refs
	body, err = json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	conflict := postRotationTestRequest(t, server.URL+"/v1/providers/migration/apply", body)
	if conflict.StatusCode != http.StatusConflict || !bytes.Contains(conflict.Body, []byte(`"outcome":"conflict"`)) || !bytes.Contains(conflict.Body, []byte(`"applied":false`)) {
		t.Fatalf("status=%d body=%s", conflict.StatusCode, conflict.Body)
	}
	assertNoSecretMaterial(t, conflict.Body, values[refs[0]], values[refs[1]], providerCredentialValue, testProviderResponseBody, "test-token")
}

func TestProviderMigrationTypedExecutorFailuresAreMetadataOnly(t *testing.T) {
	for _, test := range []struct {
		name          string
		writeOutcome  string
		verifyOutcome string
		want          string
	}{
		{name: "auth expired", writeOutcome: "source_auth_required", want: "source_auth_required"},
		{name: "rate limited", writeOutcome: "rate_limited", want: "rate_limited"},
		{name: "unavailable", writeOutcome: "source_unavailable", want: "source_unavailable"},
		{name: "verification", verifyOutcome: "verification_failed", want: "verification_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend, executor, refs, values := executableMigrationTestBackend(t)
			ref := refs[0]
			executor.writeOutcomes[ref] = test.writeOutcome
			executor.verifyOutcomes[ref] = test.verifyOutcome
			res, err := backend.migrationApply(migrationPlanRequest{RequestID: "req-typed-failure", ServiceID: "@serviceadmin", OperationID: "migration-typed-" + safeOperationToken(test.name), SourceProviderID: "local", TargetProviderID: "vault-test-double", Refs: []string{ref}, Confirm: true, Reason: "approved failure proof"})
			if err != nil || res.Outcome != "partial_failure" || res.Applied || len(res.Results) != 1 || res.Results[0].Outcome != test.want {
				t.Fatalf("res=%#v err=%v", res, err)
			}
			assertNoSecretMaterial(t, mustManagedJSON(t, res), values[ref], providerCredentialValue, testProviderResponseBody)
			assertMigrationPersistenceIsMetadataOnly(t, backend, values)
		})
	}
}

func executableMigrationTestBackend(t *testing.T) (*localBackend, *deterministicMigrationExecutor, []string, map[string]string) {
	t.Helper()
	backend := managedTestBackend(t)
	refs := []string{"services/@serviceadmin/runtime/API_KEY", "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"}
	values := map[string]string{refs[0]: "executor-source-secret-one", refs[1]: "executor-source-secret-two"}
	for _, ref := range refs {
		writeManagedTestSecret(t, backend, ref, values[ref])
	}
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "vault-test-double", Kind: "vault", Enabled: true, Address: "https://vault.invalid", Token: providerCredentialValue,
		Refs: map[string]sourceRefConfig{"services/fixture/runtime/TARGET": {Path: "secret/data/fixture", Field: "value"}},
	}, {
		SourceID: "openbao-without-executor", Kind: "openbao", Enabled: true, Address: "https://openbao.invalid", Token: providerCredentialValue,
		Refs: map[string]sourceRefConfig{"services/fixture/runtime/TARGET": {Path: "secret/data/fixture", Field: "value"}},
	}}}
	executor := newDeterministicMigrationExecutor()
	backend.registerProviderMigrationExecutor("vault-test-double", executor)
	return backend, executor, refs, values
}

func assertMigrationSourcesUnchanged(t *testing.T, backend *localBackend, values map[string]string) {
	t.Helper()
	refs := make([]string, 0, len(values))
	for ref := range values {
		refs = append(refs, ref)
	}
	resolved := backend.resolve(resolveRequest{RequestID: "req-source-recovery-proof", ServiceID: "@serviceadmin", Purpose: "migration source recovery proof", Refs: refs})
	for _, result := range resolved.Results {
		if result.Outcome != "ready" || result.Value != values[result.Ref] {
			t.Fatalf("source changed or became unrecoverable: %#v", result)
		}
	}
}

func assertMigrationPersistenceIsMetadataOnly(t *testing.T, backend *localBackend, values map[string]string) {
	t.Helper()
	storeBytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		assertNoSecretMaterial(t, storeBytes, value)
		assertNoSecretMaterial(t, auditBytes, value)
	}
	assertNoSecretMaterial(t, storeBytes, providerCredentialValue, testProviderResponseBody)
	assertNoSecretMaterial(t, auditBytes, providerCredentialValue, testProviderResponseBody)
}
