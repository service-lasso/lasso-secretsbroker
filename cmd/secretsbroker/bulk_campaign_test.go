package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBulkCampaignCreateRevalidateApplyAndStatusAreMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	readyRef := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	deniedRef := "services/deny/runtime/DENY_ME"
	writeManagedTestSecret(t, backend, readyRef, managedSecretValue)
	writeManagedTestSecret(t, backend, deniedRef, "bulk-denied-secret-value")

	created, err := backend.bulkCampaignCreate(bulkCampaignRequest{
		RequestID:   "req-bulk-create",
		ServiceID:   "@serviceadmin",
		CampaignID:  "campaign-a",
		Operation:   "rotate_reset",
		Refs:        []string{deniedRef, readyRef},
		Reason:      "operator planning",
		OperationID: "op-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Outcome != "partial_failure" || created.Summary.ApplicableCount != 1 || created.Summary.DeniedCount != 1 || created.Applied {
		t.Fatalf("created campaign = %#v", created)
	}
	if created.PlanToken == "" || created.Results[0].IdempotencyKey == "" || !created.Results[0].RetrySafe {
		t.Fatalf("missing retry-safe identifiers: %#v", created.Results)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, created), managedSecretValue, "bulk-denied-secret-value", "replacement-value")

	revalidated, err := backend.bulkCampaignRevalidate(bulkCampaignRequest{
		RequestID:  "req-bulk-revalidate",
		ServiceID:  "@serviceadmin",
		PlanToken:  created.PlanToken,
		Operation:  "rotate_reset",
		Refs:       []string{readyRef, deniedRef},
		CampaignID: "campaign-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if revalidated.Outcome != "partial_failure" || revalidated.RequiresRevalidation {
		t.Fatalf("revalidated campaign = %#v", revalidated)
	}

	applied, err := backend.bulkCampaignApply(bulkCampaignRequest{
		RequestID:  "req-bulk-apply",
		ServiceID:  "@serviceadmin",
		PlanToken:  created.PlanToken,
		Operation:  "rotate_reset",
		Confirm:    true,
		Reason:     "approved campaign",
		CampaignID: "campaign-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Outcome != "partial_failure" || !applied.Applied || applied.Summary.AppliedCount != 1 || applied.Summary.DeniedCount != 1 {
		t.Fatalf("applied campaign = %#v", applied)
	}
	if applied.Results[0].Outcome != "applied" || !applied.Results[0].Applied || applied.Results[1].Outcome != "policy_denied" {
		t.Fatalf("applied items = %#v", applied.Results)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), managedSecretValue, "bulk-denied-secret-value", "approved campaign")

	status, err := backend.bulkCampaignStatus(bulkCampaignRequest{RequestID: "req-bulk-status", ServiceID: "@serviceadmin", PlanToken: created.PlanToken})
	if err != nil {
		t.Fatal(err)
	}
	if status.Outcome != applied.Outcome || status.Summary.AppliedCount != 1 {
		t.Fatalf("status = %#v", status)
	}
}

func TestBulkCampaignApplyFailsClosedForMissingOrStalePlan(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)

	blocked, err := backend.bulkCampaignApply(bulkCampaignRequest{RequestID: "req-no-reason", ServiceID: "@serviceadmin", Operation: "rotate_reset", Refs: []string{ref}, Confirm: true})
	if err == nil || blocked.Outcome != "policy_denied" || blocked.Applied {
		t.Fatalf("missing plan/reason should fail closed: %#v err=%v", blocked, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, blocked), managedSecretValue)

	stale, err := backend.bulkCampaignApply(bulkCampaignRequest{RequestID: "req-stale", ServiceID: "@serviceadmin", Operation: "rotate_reset", PlanToken: "missing-plan", Confirm: true, Reason: "approved"})
	if err == nil || stale.Outcome != "stale_plan" || stale.Applied {
		t.Fatalf("stale plan should fail closed: %#v err=%v", stale, err)
	}
}

func TestBulkCampaignUnsupportedAuthRequiredAndPolicyStates(t *testing.T) {
	backend := managedTestBackend(t)
	localRef := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, localRef, managedSecretValue)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "file-source", Kind: "file", Enabled: true, Refs: map[string]sourceRefConfig{
			"services/file/runtime/FILE_ONLY_REF": {Path: "C:/not-used"},
		},
	}}}

	unsupported, err := backend.bulkCampaignCreate(bulkCampaignRequest{RequestID: "req-unsupported", ServiceID: "@serviceadmin", Operation: "update_edit", Refs: []string{"services/file/runtime/FILE_ONLY_REF"}})
	if err == nil || unsupported.Outcome != "unsupported" || unsupported.Summary.UnsupportedCount != 1 {
		t.Fatalf("unsupported campaign = %#v err=%v", unsupported, err)
	}

	authRequired, err := backend.bulkCampaignCreate(bulkCampaignRequest{RequestID: "req-migrate", ServiceID: "@serviceadmin", Operation: "migrate_remap_provider", Refs: []string{localRef}})
	if err == nil || authRequired.Outcome != "source_auth_required" || authRequired.Summary.AuthRequiredCount != 1 {
		t.Fatalf("auth-required campaign = %#v err=%v", authRequired, err)
	}

	policyDenied, err := backend.bulkCampaignCreate(bulkCampaignRequest{RequestID: "req-policy", ServiceID: "@serviceadmin", Operation: "apply_policy", Refs: []string{localRef}})
	if err == nil || policyDenied.Outcome != "policy_denied" || policyDenied.Summary.DeniedCount != 1 {
		t.Fatalf("policy campaign = %#v err=%v", policyDenied, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, unsupported), managedSecretValue, "file-source-token")
	assertNoSecretMaterial(t, mustManagedJSON(t, authRequired), managedSecretValue)
	assertNoSecretMaterial(t, mustManagedJSON(t, policyDenied), managedSecretValue)
}

func TestBulkCampaignHTTPContractIsMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"requestId":"req-http-bulk","serviceId":"@serviceadmin","campaignId":"bulk-http-a","operation":"rotate_reset","refs":["` + ref + `"],"reason":"operator approved"}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/management/secrets/campaigns/create", bytes.NewReader(body))
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
		t.Fatalf("campaign create status=%d body=%s", res.StatusCode, got)
	}
	if !bytes.Contains(got, []byte(`"operation":"rotate_reset"`)) || !bytes.Contains(got, []byte(`"outcome":"dry_run_ready"`)) || !bytes.Contains(got, []byte(`"planToken"`)) {
		t.Fatalf("campaign create body=%s", got)
	}
	assertNoSecretMaterial(t, got, managedSecretValue, "test-token")
}
