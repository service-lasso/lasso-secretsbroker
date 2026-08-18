package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalRotationStageActivateRollbackIsMetadataOnly(t *testing.T) {
	backend := testBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, "original-secret-value")
	currentVersion := currentSecretVersion(t, backend, ref)

	backend.now = func() time.Time { return time.Date(2026, 5, 7, 0, 1, 0, 0, time.UTC) }
	staged, err := backend.stageRotationVersion(rotationVersionRequest{
		RequestID:              "req-stage-a",
		ServiceID:              "@serviceadmin",
		Ref:                    ref,
		OperationID:            "rotate-a",
		ExpectedCurrentVersion: currentVersion,
		Reason:                 "operator approved",
		Confirm:                true,
		Value:                  "candidate-secret-value",
	})
	if err != nil {
		t.Fatal(err)
	}
	if staged.Outcome != "staged" || staged.Applied || staged.StagedVersion == nil || staged.StagedVersion.VersionID != "rv-rotate-a" {
		t.Fatalf("staged response = %#v", staged)
	}
	resolvedBeforeActivate := backend.resolve(resolveRequest{RequestID: "req-resolve-before-activate", ServiceID: "@serviceadmin", Purpose: "test", Refs: []string{ref}})
	if resolvedBeforeActivate.Results[0].Value != "original-secret-value" {
		t.Fatalf("stage changed active value: %#v", resolvedBeforeActivate.Results[0])
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, staged), "original-secret-value", "candidate-secret-value")

	backend.now = func() time.Time { return time.Date(2026, 5, 7, 0, 2, 0, 0, time.UTC) }
	activated, err := backend.activateRotationVersion(rotationVersionRequest{
		RequestID:              "req-activate-a",
		ServiceID:              "@serviceadmin",
		Ref:                    ref,
		OperationID:            "rotate-a",
		VersionID:              "rv-rotate-a",
		ExpectedCurrentVersion: currentVersion,
		Reason:                 "consumer preflight passed",
		Confirm:                true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Applied || activated.Outcome != "applied" || activated.ActiveVersionID != "rv-rotate-a" || activated.PreviousVersionID != currentVersion || activated.PreviousVersion == nil {
		t.Fatalf("activated response = %#v", activated)
	}
	resolvedAfterActivate := backend.resolve(resolveRequest{RequestID: "req-resolve-after-activate", ServiceID: "@serviceadmin", Purpose: "test", Refs: []string{ref}})
	if resolvedAfterActivate.Results[0].Value != "candidate-secret-value" {
		t.Fatalf("activate did not change active value: %#v", resolvedAfterActivate.Results[0])
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, activated), "original-secret-value", "candidate-secret-value")

	backend.now = func() time.Time { return time.Date(2026, 5, 7, 0, 3, 0, 0, time.UTC) }
	rolledBack, err := backend.rollbackRotationVersion(rotationVersionRequest{
		RequestID: "req-rollback-a",
		ServiceID: "@serviceadmin",
		Ref:       ref,
		VersionID: currentVersion,
		Reason:    "simulated consumer failure",
		Confirm:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rolledBack.Applied || rolledBack.Outcome != "rolled_back" || rolledBack.ActiveVersionID != currentVersion || rolledBack.PreviousVersionID != "rv-rotate-a" {
		t.Fatalf("rolled back response = %#v", rolledBack)
	}
	resolvedAfterRollback := backend.resolve(resolveRequest{RequestID: "req-resolve-after-rollback", ServiceID: "@serviceadmin", Purpose: "test", Refs: []string{ref}})
	if resolvedAfterRollback.Results[0].Value != "original-secret-value" {
		t.Fatalf("rollback did not restore active value: %#v", resolvedAfterRollback.Results[0])
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, rolledBack), "original-secret-value", "candidate-secret-value")

	storeBytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, storeBytes, "original-secret-value", "candidate-secret-value")
	assertNoSecretMaterial(t, auditBytes, "original-secret-value", "candidate-secret-value")
	for _, want := range []string{"rotation_stage", "rotation_activate", "rotation_rollback"} {
		if !strings.Contains(string(auditBytes), want) {
			t.Fatalf("audit missing %q: %s", want, auditBytes)
		}
	}
}

func TestRotationStageRequiresExplicitConfirmationWithoutStoreMutation(t *testing.T) {
	backend, ref, currentVersion := rotationAuditTestBackend(t)
	before := readRotationStore(t, backend)

	denied, err := backend.stageRotationVersion(rotationVersionRequest{
		RequestID:              "req-stage-without-confirmation",
		ServiceID:              "@serviceadmin",
		Ref:                    ref,
		OperationID:            "rotate-without-confirmation",
		ExpectedCurrentVersion: currentVersion,
		Reason:                 "operator approved",
		Value:                  "candidate-secret-value",
	})
	if !errors.Is(err, errPolicyDenied) || denied.Outcome != "policy_denied" || denied.Applied || !denied.RequiresConfirmation {
		t.Fatalf("denied=%#v err=%v", denied, err)
	}
	assertRotationStoreUnchanged(t, backend, before)
	assertNoSecretMaterial(t, mustManagedJSON(t, denied), "candidate-secret-value")
}

func TestRotationActivateRequiresExpectedCurrentVersion(t *testing.T) {
	backend := testBackend(t)
	ref := "services/@serviceadmin/runtime/API_KEY"
	writeManagedTestSecret(t, backend, ref, "original-secret-value")
	_, err := backend.stageRotationVersion(rotationVersionRequest{RequestID: "req-stage-conflict", ServiceID: "@serviceadmin", Ref: ref, OperationID: "rotate-conflict", Reason: "operator approved", Confirm: true, Value: "candidate-secret-value"})
	if err != nil {
		t.Fatal(err)
	}

	conflict, err := backend.activateRotationVersion(rotationVersionRequest{
		RequestID:              "req-activate-conflict",
		ServiceID:              "@serviceadmin",
		Ref:                    ref,
		OperationID:            "rotate-conflict",
		VersionID:              "rv-rotate-conflict",
		ExpectedCurrentVersion: "stale-version",
		Reason:                 "consumer preflight passed",
		Confirm:                true,
	})
	if !errors.Is(err, errRotationConflict) || conflict.Outcome != "conflict" || conflict.NextAction != "refresh_current_version_and_retry" {
		t.Fatalf("conflict = %#v err=%v", conflict, err)
	}
	resolved := backend.resolve(resolveRequest{RequestID: "req-conflict-resolve", ServiceID: "@serviceadmin", Purpose: "test", Refs: []string{ref}})
	if resolved.Results[0].Value != "original-secret-value" {
		t.Fatalf("conflict changed active value: %#v", resolved.Results[0])
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, conflict), "original-secret-value", "candidate-secret-value")
}

func TestRotationExactStageRetryConvergesWithoutStoreMutation(t *testing.T) {
	backend, ref, currentVersion := rotationAuditTestBackend(t)
	backend.now = func() time.Time { return time.Date(2026, 5, 8, 0, 1, 0, 0, time.UTC) }
	req := rotationVersionRequest{
		RequestID:              "req-stage-retry",
		ServiceID:              "@serviceadmin",
		Ref:                    ref,
		OperationID:            "rotate-stage-retry",
		ExpectedCurrentVersion: currentVersion,
		Reason:                 "operator approved",
		Confirm:                true,
		Value:                  "candidate-secret-value",
	}
	first, err := backend.stageRotationVersion(req)
	if err != nil {
		t.Fatal(err)
	}
	beforeRetry := readRotationStore(t, backend)
	retried, err := backend.stageRotationVersion(req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != "staged" || retried.Outcome != "staged" || retried.Applied || retried.StagedVersion == nil || retried.StagedVersion.VersionID != "rv-rotate-stage-retry" {
		t.Fatalf("first=%#v retried=%#v", first, retried)
	}
	assertRotationStoreUnchanged(t, backend, beforeRetry)
	assertNoSecretMaterial(t, mustManagedJSON(t, retried), "original-secret-value", "candidate-secret-value")
}

func TestRotationExactActivateRetryReturnsStableConflict(t *testing.T) {
	backend, ref, currentVersion := rotationAuditTestBackend(t)
	stageReq := rotationVersionRequest{RequestID: "req-stage-activate-retry", ServiceID: "@serviceadmin", Ref: ref, OperationID: "rotate-activate-retry", ExpectedCurrentVersion: currentVersion, Reason: "operator approved", Confirm: true, Value: "candidate-secret-value"}
	if _, err := backend.stageRotationVersion(stageReq); err != nil {
		t.Fatal(err)
	}
	req := rotationVersionRequest{RequestID: "req-activate-retry", ServiceID: "@serviceadmin", Ref: ref, OperationID: "rotate-activate-retry", VersionID: "rv-rotate-activate-retry", ExpectedCurrentVersion: currentVersion, Reason: "consumer preflight passed", Confirm: true}
	if _, err := backend.activateRotationVersion(req); err != nil {
		t.Fatal(err)
	}
	beforeRetry := readRotationStore(t, backend)
	retried, err := backend.activateRotationVersion(req)
	if !errors.Is(err, errRotationConflict) || retried.Outcome != "conflict" || retried.Applied || retried.NextAction != "refresh_current_version_and_retry" {
		t.Fatalf("retried=%#v err=%v", retried, err)
	}
	assertRotationStoreUnchanged(t, backend, beforeRetry)
	assertNoSecretMaterial(t, mustManagedJSON(t, retried), "original-secret-value", "candidate-secret-value")
}

func TestRotationExactRollbackRetryReturnsAlreadyActiveWithoutToggling(t *testing.T) {
	for _, test := range []struct {
		name            string
		explicitVersion bool
	}{
		{name: "explicit version", explicitVersion: true},
		{name: "implicit previous version", explicitVersion: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend, ref, originalVersion := activatedRotationAuditTestBackend(t)
			req := rotationVersionRequest{RequestID: "req-rollback-retry", ServiceID: "@serviceadmin", Ref: ref, OperationID: "rollback-retry", Reason: "simulated consumer failure", Confirm: true}
			if test.explicitVersion {
				req.VersionID = originalVersion
			}
			first, err := backend.rollbackRotationVersion(req)
			if err != nil || !first.Applied || first.Outcome != "rolled_back" {
				t.Fatalf("first=%#v err=%v", first, err)
			}
			beforeRetry := readRotationStore(t, backend)
			retried, err := backend.rollbackRotationVersion(req)
			if !errors.Is(err, errRotationConflict) || retried.Outcome != "conflict" || retried.Applied || retried.NextAction != "already_active" || retried.ActiveVersionID != originalVersion {
				t.Fatalf("retried=%#v err=%v", retried, err)
			}
			assertRotationStoreUnchanged(t, backend, beforeRetry)
			resolved := backend.resolve(resolveRequest{RequestID: "req-resolve-after-rollback-retry", ServiceID: "@serviceadmin", Purpose: "test", Refs: []string{ref}})
			if resolved.Results[0].Value != "original-secret-value" {
				t.Fatalf("retry toggled active value: %#v", resolved.Results[0])
			}
			assertNoSecretMaterial(t, mustManagedJSON(t, retried), "original-secret-value", "candidate-secret-value")
		})
	}
}

func TestRotationRetireIsIdempotentAndRejectsActiveVersion(t *testing.T) {
	t.Run("successful retry is a no-op", func(t *testing.T) {
		backend, ref, originalVersion := activatedRotationAuditTestBackend(t)
		req := rotationVersionRequest{RequestID: "req-retire-retry", ServiceID: "@serviceadmin", Ref: ref, VersionID: originalVersion, Reason: "consumer convergence confirmed", Confirm: true}
		first, err := backend.retireRotationVersion(req)
		if err != nil || !first.Applied || first.Outcome != "retired" {
			t.Fatalf("first=%#v err=%v", first, err)
		}
		beforeRetry := readRotationStore(t, backend)
		retried, err := backend.retireRotationVersion(req)
		if err != nil || retried.Applied || retried.Outcome != "retired" {
			t.Fatalf("retried=%#v err=%v", retried, err)
		}
		assertRotationStoreUnchanged(t, backend, beforeRetry)
		assertNoSecretMaterial(t, mustManagedJSON(t, retried), "original-secret-value", "candidate-secret-value")
	})

	t.Run("active version is denied", func(t *testing.T) {
		backend, ref, _ := activatedRotationAuditTestBackend(t)
		before := readRotationStore(t, backend)
		denied, err := backend.retireRotationVersion(rotationVersionRequest{RequestID: "req-retire-active", ServiceID: "@serviceadmin", Ref: ref, VersionID: "rv-rotate-setup", Reason: "invalid active retirement", Confirm: true})
		if !errors.Is(err, errRotationConflict) || denied.Outcome != "conflict" || denied.Applied || denied.NextAction != "cannot_retire_active_version" {
			t.Fatalf("denied=%#v err=%v", denied, err)
		}
		assertRotationStoreUnchanged(t, backend, before)
		assertNoSecretMaterial(t, mustManagedJSON(t, denied), "original-secret-value", "candidate-secret-value")
	})
}

func TestRotationRetentionPruningIsBoundedAndPersistent(t *testing.T) {
	backend, ref, currentVersion := rotationAuditTestBackend(t)
	values := []string{"candidate-secret-one", "candidate-secret-two", "candidate-secret-three"}
	for index, value := range values {
		operationID := fmt.Sprintf("retain-%d", index+1)
		backend.now = func() time.Time { return time.Date(2026, 5, 9, 0, index*2+1, 0, 0, time.UTC) }
		if _, err := backend.stageRotationVersion(rotationVersionRequest{RequestID: "req-stage-" + operationID, ServiceID: "@serviceadmin", Ref: ref, OperationID: operationID, ExpectedCurrentVersion: currentVersion, Reason: "operator approved", Confirm: true, Value: value}); err != nil {
			t.Fatal(err)
		}
		backend.now = func() time.Time { return time.Date(2026, 5, 9, 0, index*2+2, 0, 0, time.UTC) }
		activated, err := backend.activateRotationVersion(rotationVersionRequest{RequestID: "req-activate-" + operationID, ServiceID: "@serviceadmin", Ref: ref, OperationID: operationID, VersionID: "rv-" + operationID, ExpectedCurrentVersion: currentVersion, Reason: "consumer preflight passed", Confirm: true})
		if err != nil {
			t.Fatal(err)
		}
		currentVersion = activated.ActiveVersionID
	}
	store, err := backend.loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(store.Rotations[ref].Retained); got != 3 {
		t.Fatalf("retained before prune=%d, want 3", got)
	}
	backend.now = func() time.Time { return time.Date(2026, 5, 9, 0, 8, 0, 0, time.UTC) }
	retired, err := backend.retireRotationVersion(rotationVersionRequest{RequestID: "req-retention-prune", ServiceID: "@serviceadmin", Ref: ref, RetentionLimit: 1, Reason: "bounded retention policy", Confirm: true})
	if err != nil || !retired.Applied || retired.Outcome != "retired" {
		t.Fatalf("retired=%#v err=%v", retired, err)
	}
	store, err = backend.loadStore()
	if err != nil {
		t.Fatal(err)
	}
	ledger := store.Rotations[ref]
	if len(ledger.Retained) != 1 || ledger.PreviousVersionID != "rv-retain-2" {
		t.Fatalf("pruned ledger=%#v", ledger)
	}
	if _, ok := ledger.Retained["rv-retain-2"]; !ok {
		t.Fatalf("newest retained version missing: %#v", ledger.Retained)
	}
	restarted := newLocalBackend(backend.storePath, backend.auditPath, backend.masterKey)
	persisted, err := restarted.loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if got := persisted.Rotations[ref]; len(got.Retained) != 1 || got.PreviousVersionID != "rv-retain-2" || got.ActiveVersionID != "rv-retain-3" {
		t.Fatalf("persisted ledger=%#v", got)
	}
	resolved := restarted.resolve(resolveRequest{RequestID: "req-resolve-persisted-retention", ServiceID: "@serviceadmin", Purpose: "test", Refs: []string{ref}})
	if resolved.Results[0].Value != "candidate-secret-three" {
		t.Fatalf("active value after reload=%#v", resolved.Results[0])
	}
	assertNoSecretMaterial(t, readRotationStore(t, restarted), append([]string{"original-secret-value"}, values...)...)
}

func TestRotationHTTPStageStatusActivateContract(t *testing.T) {
	backend := testBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, "original-secret-value")
	currentVersion := currentSecretVersion(t, backend, ref)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	stageBody := []byte(`{"requestId":"req-http-stage","serviceId":"@serviceadmin","ref":"` + ref + `","operationId":"rotate-http","expectedCurrentVersion":"` + currentVersion + `","reason":"operator approved","confirm":true,"value":"candidate-secret-value"}`)
	stage := postRotationTestRequest(t, server.URL+"/v1/management/secrets/rotation/stage", stageBody)
	if stage.StatusCode != http.StatusOK {
		t.Fatalf("stage status=%d body=%s", stage.StatusCode, stage.Body)
	}
	if !bytes.Contains(stage.Body, []byte(`"outcome":"staged"`)) || bytes.Contains(stage.Body, []byte("candidate-secret-value")) {
		t.Fatalf("stage body=%s", stage.Body)
	}

	statusBody := []byte(`{"requestId":"req-http-status","serviceId":"@serviceadmin","ref":"` + ref + `"}`)
	status := postRotationTestRequest(t, server.URL+"/v1/management/secrets/rotation/status", statusBody)
	if status.StatusCode != http.StatusOK || !bytes.Contains(status.Body, []byte(`"state":"staged"`)) {
		t.Fatalf("status=%d body=%s", status.StatusCode, status.Body)
	}

	activateBody := []byte(`{"requestId":"req-http-activate","serviceId":"@serviceadmin","ref":"` + ref + `","operationId":"rotate-http","versionId":"rv-rotate-http","expectedCurrentVersion":"` + currentVersion + `","reason":"consumer preflight passed","confirm":true}`)
	activate := postRotationTestRequest(t, server.URL+"/v1/management/secrets/rotation/activate", activateBody)
	if activate.StatusCode != http.StatusOK || !bytes.Contains(activate.Body, []byte(`"outcome":"applied"`)) {
		t.Fatalf("activate status=%d body=%s", activate.StatusCode, activate.Body)
	}
	assertNoSecretMaterial(t, activate.Body, "original-secret-value", "candidate-secret-value", "test-token")
}

func TestRotationHTTPStageWithoutConfirmationFailsClosed(t *testing.T) {
	backend := testBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, "original-secret-value")
	currentVersion := currentSecretVersion(t, backend, ref)
	before := readRotationStore(t, backend)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"requestId":"req-http-no-confirm","serviceId":"@serviceadmin","ref":"` + ref + `","operationId":"rotate-http-no-confirm","expectedCurrentVersion":"` + currentVersion + `","reason":"operator approved","value":"candidate-secret-value"}`)
	result := postRotationTestRequest(t, server.URL+"/v1/management/secrets/rotation/stage", body)
	if result.StatusCode != http.StatusForbidden || !bytes.Contains(result.Body, []byte(`"outcome":"policy_denied"`)) {
		t.Fatalf("status=%d body=%s", result.StatusCode, result.Body)
	}
	assertNoSecretMaterial(t, result.Body, "candidate-secret-value", "test-token")
	assertRotationStoreUnchanged(t, backend, before)
}

func TestRotationHTTPAuditUnavailableFailsClosedWithoutLeakingCandidate(t *testing.T) {
	backend, ref, currentVersion := rotationAuditTestBackend(t)
	makeRotationAuditUnavailable(t, backend)
	before := readRotationStore(t, backend)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"requestId":"req-http-audit-down","serviceId":"@serviceadmin","ref":"` + ref + `","operationId":"rotate-http-audit-down","expectedCurrentVersion":"` + currentVersion + `","reason":"operator approved","confirm":true,"value":"candidate-secret-value"}`)
	result := postRotationTestRequest(t, server.URL+"/v1/management/secrets/rotation/stage", body)
	if result.StatusCode != http.StatusServiceUnavailable || !bytes.Contains(result.Body, []byte(`"outcome":"audit_unavailable"`)) {
		t.Fatalf("status=%d body=%s", result.StatusCode, result.Body)
	}
	assertNoSecretMaterial(t, result.Body, "candidate-secret-value", "test-token")
	assertRotationStoreUnchanged(t, backend, before)
}

func currentSecretVersion(t *testing.T, backend *localBackend, ref string) string {
	t.Helper()
	store, err := backend.loadStore()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := store.Secrets[ref]
	if !ok {
		t.Fatalf("missing ref %s", ref)
	}
	return entry.Metadata.Version
}

type rotationHTTPResult struct {
	StatusCode int
	Body       []byte
}

func postRotationTestRequest(t *testing.T, url string, body []byte) rotationHTTPResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	payload, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return rotationHTTPResult{StatusCode: res.StatusCode, Body: payload}
}

func TestRotationVersionResponseJSONDoesNotRequireRawValues(t *testing.T) {
	response := rotationVersionResponse{ServiceID: serviceID, APIVersion: apiVersion, Ref: "services/a/runtime/B", Operation: "rotation_status", Mode: "status", Outcome: "ready"}
	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(`"value"`)) {
		t.Fatalf("rotation response should not expose value fields: %s", payload)
	}
}

func TestRotationMutationsFailClosedWhenAuditUnavailable(t *testing.T) {
	t.Run("stage", func(t *testing.T) {
		backend, ref, currentVersion := rotationAuditTestBackend(t)
		makeRotationAuditUnavailable(t, backend)
		before := readRotationStore(t, backend)

		res, err := backend.stageRotationVersion(rotationVersionRequest{
			RequestID:              "req-stage-audit-down",
			ServiceID:              "@serviceadmin",
			Ref:                    ref,
			OperationID:            "rotate-audit-down",
			ExpectedCurrentVersion: currentVersion,
			Reason:                 "operator approved",
			Confirm:                true,
			Value:                  "candidate-secret-value",
		})
		assertRotationAuditUnavailable(t, res, err)
		assertRotationStoreUnchanged(t, backend, before)
	})

	t.Run("activate", func(t *testing.T) {
		backend, ref, currentVersion := rotationAuditTestBackend(t)
		_, err := backend.stageRotationVersion(rotationVersionRequest{
			RequestID:              "req-stage-before-audit-down",
			ServiceID:              "@serviceadmin",
			Ref:                    ref,
			OperationID:            "rotate-before-audit-down",
			ExpectedCurrentVersion: currentVersion,
			Reason:                 "operator approved",
			Confirm:                true,
			Value:                  "candidate-secret-value",
		})
		if err != nil {
			t.Fatal(err)
		}
		makeRotationAuditUnavailable(t, backend)
		before := readRotationStore(t, backend)

		res, err := backend.activateRotationVersion(rotationVersionRequest{
			RequestID:              "req-activate-audit-down",
			ServiceID:              "@serviceadmin",
			Ref:                    ref,
			OperationID:            "rotate-before-audit-down",
			VersionID:              "rv-rotate-before-audit-down",
			ExpectedCurrentVersion: currentVersion,
			Reason:                 "consumer preflight passed",
			Confirm:                true,
		})
		assertRotationAuditUnavailable(t, res, err)
		assertRotationStoreUnchanged(t, backend, before)
	})

	t.Run("rollback", func(t *testing.T) {
		backend, ref, currentVersion := activatedRotationAuditTestBackend(t)
		makeRotationAuditUnavailable(t, backend)
		before := readRotationStore(t, backend)

		res, err := backend.rollbackRotationVersion(rotationVersionRequest{
			RequestID: "req-rollback-audit-down",
			ServiceID: "@serviceadmin",
			Ref:       ref,
			VersionID: currentVersion,
			Reason:    "simulated consumer failure",
			Confirm:   true,
		})
		assertRotationAuditUnavailable(t, res, err)
		assertRotationStoreUnchanged(t, backend, before)
	})

	t.Run("retire", func(t *testing.T) {
		backend, ref, currentVersion := activatedRotationAuditTestBackend(t)
		makeRotationAuditUnavailable(t, backend)
		before := readRotationStore(t, backend)

		res, err := backend.retireRotationVersion(rotationVersionRequest{
			RequestID: "req-retire-audit-down",
			ServiceID: "@serviceadmin",
			Ref:       ref,
			VersionID: currentVersion,
			Reason:    "consumer convergence confirmed",
			Confirm:   true,
		})
		assertRotationAuditUnavailable(t, res, err)
		assertRotationStoreUnchanged(t, backend, before)
	})
}

func TestRotationStateSurvivesBrokerProcessRestart(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	eventsPath := filepath.Join(dir, "events.jsonl")
	address := freeRotationTestAddress(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"

	process := startRotationBrokerProcess(t, address, storePath, auditPath, eventsPath)
	write := postRotationProcessRequest(t, address, "/v1/secrets", `{"ref":"`+ref+`","value":"original-secret-value"}`)
	if write.StatusCode != http.StatusOK {
		t.Fatalf("write status=%d body=%s", write.StatusCode, write.Body)
	}
	var written writeSecretResponse
	if err := json.Unmarshal(write.Body, &written); err != nil {
		t.Fatal(err)
	}

	stage := postRotationProcessRequest(t, address, "/v1/management/secrets/rotation/stage", `{"requestId":"req-process-stage","serviceId":"@serviceadmin","ref":"`+ref+`","operationId":"rotate-process","expectedCurrentVersion":"`+written.Metadata.Version+`","reason":"operator approved","confirm":true,"value":"candidate-secret-value"}`)
	if stage.StatusCode != http.StatusOK {
		t.Fatalf("stage status=%d body=%s", stage.StatusCode, stage.Body)
	}
	activate := postRotationProcessRequest(t, address, "/v1/management/secrets/rotation/activate", `{"requestId":"req-process-activate","serviceId":"@serviceadmin","ref":"`+ref+`","operationId":"rotate-process","versionId":"rv-rotate-process","expectedCurrentVersion":"`+written.Metadata.Version+`","reason":"consumer preflight passed","confirm":true}`)
	if activate.StatusCode != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", activate.StatusCode, activate.Body)
	}
	stopRotationBrokerProcess(t, process)

	process = startRotationBrokerProcess(t, address, storePath, auditPath, eventsPath)
	defer stopRotationBrokerProcess(t, process)
	status := postRotationProcessRequest(t, address, "/v1/management/secrets/rotation/status", `{"requestId":"req-process-status","serviceId":"@serviceadmin","ref":"`+ref+`"}`)
	if status.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", status.StatusCode, status.Body)
	}
	var persisted rotationVersionResponse
	if err := json.Unmarshal(status.Body, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.ActiveVersionID != "rv-rotate-process" || persisted.PreviousVersionID != written.Metadata.Version {
		t.Fatalf("persisted rotation metadata = %#v", persisted)
	}

	reveal := postRotationProcessRequest(t, address, "/v1/management/secrets/reveal", `{"requestId":"req-process-reveal","serviceId":"@serviceadmin","ref":"`+ref+`","reason":"restart persistence check","confirm":true}`)
	if reveal.StatusCode != http.StatusOK {
		t.Fatalf("reveal status=%d body=%s", reveal.StatusCode, reveal.Body)
	}
	var revealed managedSecretActionResponse
	if err := json.Unmarshal(reveal.Body, &revealed); err != nil {
		t.Fatal(err)
	}
	if revealed.Value != "candidate-secret-value" {
		t.Fatalf("revealed value did not survive restart: outcome=%s", revealed.Outcome)
	}
}

func TestRotationBrokerProcessHelper(t *testing.T) {
	if os.Getenv("SECRETSBROKER_ROTATION_PROCESS_HELPER") != "1" {
		return
	}
	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		fmt.Fprintln(os.Stderr, "missing broker helper arguments")
		os.Exit(2)
	}
	if err := run(os.Args[separator+1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rotationAuditTestBackend(t *testing.T) (*localBackend, string, string) {
	t.Helper()
	backend := testBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, "original-secret-value")
	return backend, ref, currentSecretVersion(t, backend, ref)
}

func activatedRotationAuditTestBackend(t *testing.T) (*localBackend, string, string) {
	t.Helper()
	backend, ref, currentVersion := rotationAuditTestBackend(t)
	_, err := backend.stageRotationVersion(rotationVersionRequest{RequestID: "req-stage-setup", ServiceID: "@serviceadmin", Ref: ref, OperationID: "rotate-setup", ExpectedCurrentVersion: currentVersion, Reason: "operator approved", Confirm: true, Value: "candidate-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = backend.activateRotationVersion(rotationVersionRequest{RequestID: "req-activate-setup", ServiceID: "@serviceadmin", Ref: ref, OperationID: "rotate-setup", VersionID: "rv-rotate-setup", ExpectedCurrentVersion: currentVersion, Reason: "consumer preflight passed", Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	return backend, ref, currentVersion
}

func makeRotationAuditUnavailable(t *testing.T, backend *localBackend) {
	t.Helper()
	blockedPath := filepath.Join(t.TempDir(), "audit-is-a-directory")
	if err := os.Mkdir(blockedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	backend.auditPath = blockedPath
}

func readRotationStore(t *testing.T, backend *localBackend) []byte {
	t.Helper()
	payload, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertRotationStoreUnchanged(t *testing.T, backend *localBackend, before []byte) {
	t.Helper()
	after := readRotationStore(t, backend)
	if !bytes.Equal(before, after) {
		t.Fatal("rotation store changed while audit was unavailable")
	}
}

func assertRotationAuditUnavailable(t *testing.T, res rotationVersionResponse, err error) {
	t.Helper()
	if !errors.Is(err, errRotationAuditUnavailable) {
		t.Fatalf("error = %v, want rotation audit unavailable", err)
	}
	if res.Outcome != "audit_unavailable" || res.AuditStatus != "audit_unavailable" || res.Applied || res.NextAction != "restore_audit_and_retry" {
		t.Fatalf("response = %#v", res)
	}
}

func freeRotationTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func startRotationBrokerProcess(t *testing.T, address, storePath, auditPath, eventsPath string) *exec.Cmd {
	t.Helper()
	stdout, err := os.Create(filepath.Join(t.TempDir(), "broker-stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(filepath.Join(t.TempDir(), "broker-stderr.log"))
	if err != nil {
		stdout.Close()
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRotationBrokerProcessHelper$", "--", "serve", "--listen", address, "--mode", "development", "--transport", "loopback-http", "--state", "ready", "--store", storePath, "--audit", auditPath, "--events", eventsPath, "--master-key", "test-master-key", "--api-token", "test-token")
	command.Env = append(os.Environ(), "SECRETSBROKER_ROTATION_PROCESS_HELPER=1")
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		t.Fatal(err)
	}
	stdout.Close()
	stderr.Close()
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	})
	waitForRotationBroker(t, address, command)
	return command
}

func stopRotationBrokerProcess(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if command == nil || command.ProcessState != nil {
		return
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("stop broker process: %v", err)
	}
	if _, err := command.Process.Wait(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("wait for broker process: %v", err)
		}
	}
}

func waitForRotationBroker(t *testing.T, address string, command *exec.Cmd) {
	t.Helper()
	client := &http.Client{Timeout: 250 * time.Millisecond, Transport: &http.Transport{DisableKeepAlives: true}}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if command.ProcessState != nil {
			t.Fatalf("broker process exited before readiness: %v", command.ProcessState)
		}
		response, err := client.Get("http://" + address + "/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("broker process did not become ready at %s", address)
}

func postRotationProcessRequest(t *testing.T, address, path, body string) rotationHTTPResult {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://"+address+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-token")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return rotationHTTPResult{StatusCode: response.StatusCode, Body: payload}
}
