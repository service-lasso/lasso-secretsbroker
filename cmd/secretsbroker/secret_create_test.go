package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestManagedCreateSignedPlanApplyRetryAndRestart(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/CREATED_BY_ADMIN"
	request := managedCreateRequest{RequestID: "create-plan", ServiceID: "@serviceadmin", Ref: ref, OperationID: "create-admin-1", GenerationMode: "operator_supplied", Reason: "approved initial credential"}

	plan, err := backend.managedCreateDryRun(request)
	if err != nil || plan.Outcome != "dry_run_ready" || plan.Plan == nil || !plan.RequiresConfirmation || plan.AuditStatus != "audit_recorded" {
		t.Fatalf("create plan = %#v err=%v", plan, err)
	}
	request.RequestID = "create-apply"
	request.Confirm = true
	request.Value = "operator-create-fixture-secret"
	request.Plan = plan.Plan
	applied, err := backend.managedCreateApply(request)
	if err != nil || applied.Outcome != "applied" || !applied.Applied || applied.Metadata == nil || applied.Metadata.Version == "" {
		t.Fatalf("create apply = %#v err=%v", applied, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), request.Value)

	storeBeforeRetry, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := backend.managedCreateApply(request)
	if err != nil || retry.Outcome != "already_applied" || retry.Applied || retry.Metadata == nil || retry.Metadata.Version != applied.Metadata.Version {
		t.Fatalf("create retry = %#v err=%v", retry, err)
	}
	storeAfterRetry, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storeBeforeRetry, storeAfterRetry) {
		t.Fatal("exact create retry rewrote the encrypted store")
	}

	restarted := newLocalBackend(backend.storePath, backend.auditPath, backend.masterKey)
	restarted.now = backend.now
	restartRetry, err := restarted.managedCreateApply(request)
	if err != nil || restartRetry.Outcome != "already_applied" || restartRetry.Applied {
		t.Fatalf("restart retry = %#v err=%v", restartRetry, err)
	}
	resolved := restarted.resolve(resolveRequest{RequestID: "resolve-create", ServiceID: "@serviceadmin", Refs: []string{ref}})
	if len(resolved.Results) != 1 || resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != request.Value {
		t.Fatalf("resolved created secret = %#v", resolved)
	}
	storePayload, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, storePayload, request.Value)
}

func TestManagedCreateBrokerGeneratedNoOverwriteAndAuditFailClosed(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/BROKER_GENERATED_ADMIN"
	request := managedCreateRequest{RequestID: "create-generated-plan", ServiceID: "@serviceadmin", Ref: ref, OperationID: "create-generated-1", GenerationMode: "broker_generated", Reason: "approved generated credential"}
	plan, err := backend.managedCreateDryRun(request)
	if err != nil || plan.Plan == nil {
		t.Fatalf("generated plan = %#v err=%v", plan, err)
	}
	request.Plan, request.Confirm = plan.Plan, true
	applied, err := backend.managedCreateApply(request)
	if err != nil || !applied.Applied || applied.Metadata == nil {
		t.Fatalf("generated apply = %#v err=%v", applied, err)
	}
	resolved := backend.resolve(resolveRequest{RequestID: "resolve-generated", ServiceID: "@serviceadmin", Refs: []string{ref}})
	if len(resolved.Results) != 1 || len(resolved.Results[0].Value) < 40 {
		t.Fatalf("broker-generated value was not persisted: %#v", resolved)
	}
	generatedValue := resolved.Results[0].Value
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), generatedValue)

	conflictRequest := managedCreateRequest{RequestID: "create-conflict", ServiceID: "@serviceadmin", Ref: ref, OperationID: "create-generated-2", GenerationMode: "broker_generated", Reason: "must not overwrite"}
	conflict, err := backend.managedCreateDryRun(conflictRequest)
	if !errors.Is(err, errManagedCreateConflict) || conflict.Outcome != "conflict" {
		t.Fatalf("existing-ref create = %#v err=%v", conflict, err)
	}
	resolvedAfter := backend.resolve(resolveRequest{RequestID: "resolve-after-conflict", ServiceID: "@serviceadmin", Refs: []string{ref}})
	if resolvedAfter.Results[0].Value != generatedValue {
		t.Fatal("conflicting create changed the existing secret")
	}

	failRef := "services/@serviceadmin/runtime/AUDIT_FAIL_CLOSED"
	failPlan, err := signManagedCreatePlan(managedCreatePlan{Ref: failRef, OperationID: "create-audit-fail", GenerationMode: "operator_supplied", ExpectedState: "missing", ExpiresAt: backend.now().Add(managedCreatePlanTTL)}, backend.masterKey)
	if err != nil {
		t.Fatal(err)
	}
	backend.auditPath = t.TempDir()
	failure, err := backend.managedCreateApply(managedCreateRequest{RequestID: "create-audit-fail", ServiceID: "@serviceadmin", Ref: failRef, OperationID: "create-audit-fail", GenerationMode: "operator_supplied", Reason: "audit failure proof", Value: "must-never-persist", Confirm: true, Plan: &failPlan})
	if err == nil || failure.Outcome != "audit_unavailable" || failure.Applied {
		t.Fatalf("audit unavailable create = %#v err=%v", failure, err)
	}
	store, loadErr := backend.loadStore()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, exists := store.Secrets[failRef]; exists {
		t.Fatal("audit-unavailable create mutated the store")
	}
}

func TestManagedCreateHTTPContractRejectsPlanTamperingAndSecretEcho(t *testing.T) {
	backend := managedTestBackend(t)
	state := "ready"
	server := newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"})
	plan, err := backend.managedCreateDryRun(managedCreateRequest{RequestID: "http-plan", ServiceID: "@serviceadmin", Ref: "services/app/runtime/HTTP_CREATED", OperationID: "http-create-1", GenerationMode: "operator_supplied", Reason: "approved HTTP create"})
	if err != nil || plan.Plan == nil {
		t.Fatal(err)
	}
	tampered := *plan.Plan
	tampered.Ref = "services/app/runtime/TAMPERED"
	payload, _ := json.Marshal(managedCreateRequest{RequestID: "http-apply", ServiceID: "@serviceadmin", Ref: tampered.Ref, OperationID: tampered.OperationID, GenerationMode: tampered.GenerationMode, Reason: "tamper proof", Value: "http-create-secret", Confirm: true, Plan: &tampered})
	req := httptest.NewRequest(http.MethodPost, "/v1/management/secrets/create/apply", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer test-token")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != 409 || !bytes.Contains(recorder.Body.Bytes(), []byte(`"outcome":"stale_plan"`)) {
		t.Fatalf("tampered HTTP create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertNoSecretMaterial(t, recorder.Body.Bytes(), "http-create-secret", "test-token")
}
