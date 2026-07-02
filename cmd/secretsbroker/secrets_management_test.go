package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const managedSecretValue = "fixture-managed-secret-value"

func TestManagedSecretsListAndMetadataSearchAreMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	writeManagedTestSecret(t, backend, "services/@serviceadmin/runtime/SESSION_SIGNING_KEY", managedSecretValue)
	writeManagedTestSecret(t, backend, "services/payments/runtime/PAYMENTS_SIGNING_REF", "payments-fixture-value")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "vault-dev", Kind: "vault", DisplayName: "Vault dev", Enabled: true, Address: "https://vault.invalid", Token: "token-fixture", Refs: map[string]sourceRefConfig{
			"services/search/runtime/EXTERNAL_ONLY_REF": {Path: "secret/data/search", Field: "value"},
		},
	}}}

	res, err := backend.listManagedSecrets("serviceadmin", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "ready" || len(res.Results) != 1 {
		t.Fatalf("metadata search response = %#v", res)
	}
	if res.Results[0].Ref != "services/@serviceadmin/runtime/SESSION_SIGNING_KEY" || res.Results[0].ValueSearch != "supported" {
		t.Fatalf("metadata row = %#v", res.Results[0])
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, res), managedSecretValue, "payments-fixture-value", "token-fixture")

	all, err := backend.listManagedSecrets("", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Results) != 3 {
		t.Fatalf("expected local and configured source refs, got %#v", all.Results)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, all), managedSecretValue, "payments-fixture-value", "token-fixture")
}

func TestManagedValueSearchReturnsRefsOnlyAndOmitsUnsupportedSources(t *testing.T) {
	backend := managedTestBackend(t)
	writeManagedTestSecret(t, backend, "services/@serviceadmin/runtime/SESSION_SIGNING_KEY", managedSecretValue)
	writeManagedTestSecret(t, backend, "services/worker/runtime/OTHER_REF", "unmatched-fixture-value")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "file-source", Kind: "file", Enabled: true, Refs: map[string]sourceRefConfig{
			"services/file/runtime/FILE_ONLY_REF": {Path: "C:/not-used"},
		},
	}}}

	res, err := backend.listManagedSecrets("managed-secret", true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ValueSearch || len(res.Results) != 1 || res.Results[0].Ref != "services/@serviceadmin/runtime/SESSION_SIGNING_KEY" {
		t.Fatalf("value search response = %#v", res)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, res), managedSecretValue, "unmatched-fixture-value")
}

func TestProvisioningStatusIsMetadataOnlyAndDistinguishesOutcomes(t *testing.T) {
	backend := managedTestBackend(t)
	readyRef := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, readyRef, managedSecretValue)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "vault-dev", Kind: "vault", DisplayName: "Vault dev", Enabled: true, Address: "https://vault.invalid", Token: "provider-token-fixture", Refs: map[string]sourceRefConfig{
			"services/search/runtime/EXTERNAL_ONLY_REF": {Path: "secret/data/search", Field: "value"},
		},
	}, {
		SourceID: "vault-auth-required", Kind: "vault", DisplayName: "Vault auth required", Enabled: true, Address: "https://vault.invalid", Refs: map[string]sourceRefConfig{
			"services/payments/runtime/AUTH_REQUIRED_REF": {Path: "secret/data/payments", Field: "value"},
		},
	}}}

	res, err := backend.listProvisioningStatus("", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "ready" || len(res.Results) != 3 {
		t.Fatalf("provisioning response = %#v", res)
	}
	byRef := map[string]provisioningStatusRecord{}
	for _, result := range res.Results {
		byRef[result.Ref] = result
	}
	if got := byRef[readyRef]; got.ProvisionedState != "ready" || got.LastOutcome != "ready" || got.DesiredOperation != "none" || got.GeneratedValuePolicy.Kind != "opaque" {
		t.Fatalf("ready provisioning record = %#v", got)
	}
	if got := byRef["services/search/runtime/EXTERNAL_ONLY_REF"]; got.ProvisionedState != "pending" || got.LastOutcome != "ready" || got.NextAction != "writeback_generated_value_or_mark_ready" {
		t.Fatalf("source ready provisioning record = %#v", got)
	}
	if got := byRef["services/payments/runtime/AUTH_REQUIRED_REF"]; got.ProvisionedState != "blocked" || got.LastOutcome != "source_auth_required" || got.NextAction != "reconnect_source" {
		t.Fatalf("auth-required provisioning record = %#v", got)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, res), managedSecretValue, "provider-token-fixture")

	missing, err := backend.listProvisioningStatus("", "services/missing/runtime/NEW_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if len(missing.Results) != 1 || missing.Results[0].ProvisionedState != "not_planned" || missing.Results[0].LastOutcome != "missing_ref" {
		t.Fatalf("missing provisioning record = %#v", missing)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, missing), managedSecretValue, "provider-token-fixture")
}

func TestProvisioningStatusHTTPContractIsMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/provisioning/status?ref="+ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got := readClose(t, res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("provisioning status=%d body=%s", res.StatusCode, got)
	}
	if !bytes.Contains(got, []byte(`"provisionedState":"ready"`)) || !bytes.Contains(got, []byte(`"generatedValuePolicy"`)) {
		t.Fatalf("provisioning body=%s", got)
	}
	assertNoSecretMaterial(t, got, managedSecretValue, "test-token")
}

func TestManagedRevealIsOnlyRawValueSuccessPath(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)

	list, err := backend.listManagedSecrets("SESSION", false)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, list), managedSecretValue)

	reveal, err := backend.revealManagedSecret(managedSecretActionRequest{RequestID: "req-reveal", ServiceID: "@serviceadmin", Ref: ref, Reason: "operator audit reason"})
	if err != nil {
		t.Fatal(err)
	}
	if reveal.Outcome != "ready" || reveal.Value != managedSecretValue || reveal.TTLSeconds != revealTTLSeconds || reveal.AuditStatus != "audit_recorded" {
		t.Fatalf("reveal response = %#v", reveal)
	}

	denied, err := backend.revealManagedSecret(managedSecretActionRequest{RequestID: "req-denied", ServiceID: "@serviceadmin", Ref: ref})
	if err == nil || denied.Value != "" || denied.Outcome == "ready" {
		t.Fatalf("missing reason should fail closed without value: %#v err=%v", denied, err)
	}
}

func TestManagedDryRunApplyAndPolicyContractsDoNotReturnRawValues(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)

	dryRun, err := backend.managedEditDryRun(managedSecretActionRequest{RequestID: "req-edit-dry-run", ServiceID: "@serviceadmin", Ref: ref})
	if err != nil {
		t.Fatal(err)
	}
	if dryRun.Outcome != "dry_run_ready" || !dryRun.RequiresConfirmation || dryRun.Applied || dryRun.Value != "" {
		t.Fatalf("edit dry-run = %#v", dryRun)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, dryRun), managedSecretValue, "replacement-value")

	blocked, err := backend.managedEditApply(managedSecretActionRequest{RequestID: "req-edit-blocked", ServiceID: "@serviceadmin", Ref: ref, Value: "replacement-value"})
	if err == nil || blocked.Applied || blocked.Value != "" || blocked.Outcome != "policy_denied" {
		t.Fatalf("unconfirmed edit apply should fail closed: %#v err=%v", blocked, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, blocked), managedSecretValue, "replacement-value")

	applied, err := backend.managedEditApply(managedSecretActionRequest{RequestID: "req-edit-apply", ServiceID: "@serviceadmin", Ref: ref, Reason: "approved", Confirm: true, Value: "replacement-value"})
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied || applied.Outcome != "applied" || applied.Value != "" {
		t.Fatalf("edit apply = %#v", applied)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), managedSecretValue, "replacement-value")

	reset, err := backend.managedResetDryRun(managedSecretActionRequest{RequestID: "req-reset-dry-run", ServiceID: "@serviceadmin", Ref: ref})
	if err != nil || reset.Outcome != "dry_run_ready" || reset.Value != "" {
		t.Fatalf("reset dry-run = %#v err=%v", reset, err)
	}

	preview, err := backend.managedPolicyPreview(managedSecretActionRequest{RequestID: "req-policy-preview", ServiceID: "@serviceadmin", Ref: ref})
	if err != nil || preview.Mode != "preview" || preview.Outcome != "dry_run_ready" {
		t.Fatalf("policy preview = %#v err=%v", preview, err)
	}

	policy, err := backend.managedPolicyApply(managedSecretActionRequest{RequestID: "req-policy-apply", ServiceID: "@serviceadmin", Ref: ref, Reason: "approved", Confirm: true, Policy: "policy/serviceadmin/reveal"})
	if err != nil || !policy.Applied || policy.Value != "" || policy.Record.Policy != "policy/serviceadmin/reveal" {
		t.Fatalf("policy apply = %#v err=%v", policy, err)
	}
}

func TestManagedPolicyDeniedAttemptsStartScopedLockout(t *testing.T) {
	backend := managedTestBackend(t)
	now := time.Date(2026, 6, 6, 1, 45, 0, 0, time.UTC)
	backend.now = func() time.Time { return now }
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)

	for i := 1; i <= localAPILockoutThreshold; i++ {
		res, err := backend.managedEditApply(managedSecretActionRequest{RequestID: "req-denied", ServiceID: "@serviceadmin", Ref: ref, Value: "replacement-value"})
		if !errors.Is(err, errPolicyDenied) && !errors.Is(err, errLockoutActive) {
			t.Fatalf("denied edit apply err=%v res=%#v", err, res)
		}
		if i < localAPILockoutThreshold && res.LockoutActive {
			t.Fatalf("lockout started too early on attempt %d: %#v", i, res)
		}
		if i == localAPILockoutThreshold {
			if res.Outcome != "lockout_active" || !res.LockoutActive || res.LockoutScope != "management:edit:@serviceadmin:"+ref || res.RetryAfterSeconds < 1 || res.Value != "" || res.Applied {
				t.Fatalf("lockout response = %#v", res)
			}
			assertNoSecretMaterial(t, mustManagedJSON(t, res), managedSecretValue, "replacement-value")
		}
	}

	otherRef := "services/@serviceadmin/runtime/OTHER_KEY"
	writeManagedTestSecret(t, backend, otherRef, "other-managed-value")
	other, err := backend.managedEditApply(managedSecretActionRequest{RequestID: "req-other", ServiceID: "@serviceadmin", Ref: otherRef, Reason: "approved", Confirm: true, Value: "other-replacement"})
	if err != nil || !other.Applied {
		t.Fatalf("lockout should not block unrelated ref: %#v err=%v", other, err)
	}

	locked, err := backend.managedEditApply(managedSecretActionRequest{RequestID: "req-active", ServiceID: "@serviceadmin", Ref: ref, Reason: "approved", Confirm: true, Value: "replacement-value"})
	if !errors.Is(err, errLockoutActive) || locked.Outcome != "lockout_active" || locked.Applied || locked.Value != "" {
		t.Fatalf("active lockout should block valid apply until cooldown: %#v err=%v", locked, err)
	}

	now = now.Add(localAPILockoutCooldown + time.Second)
	applied, err := backend.managedEditApply(managedSecretActionRequest{RequestID: "req-after-cooldown", ServiceID: "@serviceadmin", Ref: ref, Reason: "approved", Confirm: true, Value: "replacement-value"})
	if err != nil || !applied.Applied || applied.Outcome != "applied" {
		t.Fatalf("apply after cooldown = %#v err=%v", applied, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), managedSecretValue, "replacement-value")
}

func TestManagedRevealLockoutHTTPResponseIsMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	for i := 1; i <= localAPILockoutThreshold; i++ {
		body := []byte(`{"requestId":"req-http-denied","serviceId":"@serviceadmin","ref":"` + ref + `"}`)
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/management/secrets/reveal", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		payload := readClose(t, res.Body)
		if i < localAPILockoutThreshold && res.StatusCode != http.StatusForbidden {
			t.Fatalf("attempt %d status=%d body=%s", i, res.StatusCode, payload)
		}
		if i == localAPILockoutThreshold {
			if res.StatusCode != http.StatusLocked || !bytes.Contains(payload, []byte(`"lockoutActive":true`)) || !bytes.Contains(payload, []byte(`"outcome":"lockout_active"`)) {
				t.Fatalf("lockout status=%d body=%s", res.StatusCode, payload)
			}
			assertNoSecretMaterial(t, payload, managedSecretValue, "test-token")
		}
	}
}

func TestRotationDryRunPlansLocalRefsAndPartialDenialsMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	readyRef := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	deniedRef := "services/deny/runtime/DENY_ME"
	writeManagedTestSecret(t, backend, readyRef, managedSecretValue)
	writeManagedTestSecret(t, backend, deniedRef, "rotation-deny-fixture-value")

	plan, err := backend.rotationDryRun(rotationDryRunRequest{RequestID: "req-rotation-plan", ServiceID: "@serviceadmin", OperationID: "rotate-campaign-a", Refs: []string{deniedRef, readyRef}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcome != "partial_failure" || plan.Applied || !plan.RequiresConfirmation || plan.StaleAfterSeconds != rotationPlanStaleAfterSeconds {
		t.Fatalf("rotation plan = %#v", plan)
	}
	if plan.Summary.SelectedCount != 2 || plan.Summary.ReadyCount != 1 || plan.Summary.DeniedCount != 1 {
		t.Fatalf("rotation summary = %#v", plan.Summary)
	}
	if plan.Results[0].Ref != readyRef || plan.Results[0].CapabilityResult != "supported" || plan.Results[0].PolicyResult != "allowed" || plan.Results[0].IdempotencyKey == "" {
		t.Fatalf("ready rotation item = %#v", plan.Results[0])
	}
	if plan.Results[1].Ref != deniedRef || plan.Results[1].Outcome != "policy_denied" || plan.Results[1].PolicyResult != "denied" {
		t.Fatalf("denied rotation item = %#v", plan.Results[1])
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, plan), managedSecretValue, "rotation-deny-fixture-value", "replacement-value")
}

func TestRotationDryRunReportsProviderCapabilityWithoutRawValues(t *testing.T) {
	backend := managedTestBackend(t)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "file-source", Kind: "file", Enabled: true, Refs: map[string]sourceRefConfig{
			"services/file/runtime/FILE_ONLY_REF": {Path: "C:/not-used"},
		},
	}}}

	plan, err := backend.rotationDryRun(rotationDryRunRequest{RequestID: "req-file-rotation", ServiceID: "@serviceadmin", OperationID: "rotate-file-source", Refs: []string{"services/file/runtime/FILE_ONLY_REF"}})
	if err == nil || plan.Outcome != "unsupported" || plan.Summary.UnsupportedCount != 1 {
		t.Fatalf("provider capability plan = %#v err=%v", plan, err)
	}
	if len(plan.Results) != 1 || plan.Results[0].ProviderKind != "file" || plan.Results[0].CapabilityResult != "unsupported" || plan.Results[0].NextAction != "inspect_provider_capabilities" {
		t.Fatalf("provider rotation item = %#v", plan.Results)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, plan), "file-source-token", "replacement-value")
}

func TestManagedHTTPContractAndFailClosedErrors(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	listReq, err := http.NewRequest(http.MethodGet, server.URL+"/v1/management/secrets?search=SESSION", nil)
	if err != nil {
		t.Fatal(err)
	}
	listReq.Header.Set("Authorization", "Bearer test-token")
	listRes, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	listBody := readClose(t, listRes.Body)
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRes.StatusCode, listBody)
	}
	assertNoSecretMaterial(t, listBody, managedSecretValue)

	revealBody := []byte(`{"requestId":"req-http-reveal","serviceId":"@serviceadmin","ref":"` + ref + `","reason":"operator approved"}`)
	revealReq, err := http.NewRequest(http.MethodPost, server.URL+"/v1/management/secrets/reveal", bytes.NewReader(revealBody))
	if err != nil {
		t.Fatal(err)
	}
	revealReq.Header.Set("Content-Type", "application/json")
	revealReq.Header.Set("X-SecretsBroker-Token", "test-token")
	revealRes, err := http.DefaultClient.Do(revealReq)
	if err != nil {
		t.Fatal(err)
	}
	revealed := readClose(t, revealRes.Body)
	if revealRes.StatusCode != http.StatusOK || !bytes.Contains(revealed, []byte(managedSecretValue)) {
		t.Fatalf("reveal status=%d body=%s", revealRes.StatusCode, revealed)
	}

	missingBody := []byte(`{"requestId":"req-missing","serviceId":"@serviceadmin","ref":"services/missing/runtime/NOPE","reason":"operator approved"}`)
	missingReq, err := http.NewRequest(http.MethodPost, server.URL+"/v1/management/secrets/reveal", bytes.NewReader(missingBody))
	if err != nil {
		t.Fatal(err)
	}
	missingReq.Header.Set("Content-Type", "application/json")
	missingReq.Header.Set("Authorization", "Bearer test-token")
	missingRes, err := http.DefaultClient.Do(missingReq)
	if err != nil {
		t.Fatal(err)
	}
	missing := readClose(t, missingRes.Body)
	if missingRes.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status=%d body=%s", missingRes.StatusCode, missing)
	}
	assertNoSecretMaterial(t, missing, managedSecretValue)
}

func TestRotationDryRunHTTPContractIsMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"requestId":"req-http-rotation","serviceId":"@serviceadmin","operationId":"rotation-http-a","refs":["` + ref + `"],"reason":"operator approved"}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/management/secrets/rotation/dry-run", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got := readClose(t, res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("rotation dry-run status=%d body=%s", res.StatusCode, got)
	}
	if !bytes.Contains(got, []byte(`"operation":"credential_rotation"`)) || !bytes.Contains(got, []byte(`"outcome":"dry_run_ready"`)) {
		t.Fatalf("rotation dry-run body=%s", got)
	}
	assertNoSecretMaterial(t, got, managedSecretValue, "replacement-value")
}

func TestManagedListLockedFailsClosed(t *testing.T) {
	backend := newLocalBackend(t.TempDir()+"/store.json", t.TempDir()+"/audit.jsonl", "")
	res, err := backend.listManagedSecrets("", false)
	if err == nil || res.Outcome != "locked" || len(res.Results) != 0 {
		t.Fatalf("locked list should fail closed: %#v err=%v", res, err)
	}
}

func managedTestBackend(t *testing.T) *localBackend {
	t.Helper()
	return testBackend(t)
}

func writeManagedTestSecret(t *testing.T, backend *localBackend, ref, value string) {
	t.Helper()
	_, err := backend.writeSecret(writeSecretRequest{Ref: ref, Value: value, Metadata: map[string]string{"sourceId": "local-test"}})
	if err != nil {
		t.Fatal(err)
	}
}

func mustManagedJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertNoSecretMaterial(t *testing.T, payload []byte, forbidden ...string) {
	t.Helper()
	lower := strings.ToLower(string(payload))
	for _, secret := range forbidden {
		if secret != "" && strings.Contains(lower, strings.ToLower(secret)) {
			t.Fatalf("payload leaked secret material %q: %s", secret, payload)
		}
	}
	for _, marker := range []string{"correct-horse-battery-staple", "private key", "bearer test-token", "token-fixture"} {
		if strings.Contains(lower, marker) {
			t.Fatalf("payload contains forbidden marker %q: %s", marker, payload)
		}
	}
}

func readClose(t *testing.T, body io.ReadCloser) []byte {
	t.Helper()
	defer body.Close()
	payload, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
