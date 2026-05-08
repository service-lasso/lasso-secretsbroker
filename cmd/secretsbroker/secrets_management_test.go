package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
