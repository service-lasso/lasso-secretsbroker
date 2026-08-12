package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
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
	if !errors.Is(err, errUnsupportedProvider) {
		t.Fatalf("metadata-only apply should fail closed: %v", err)
	}
	if applied.Outcome != "unsupported" || applied.Applied || applied.Summary.UnsupportedCount != 1 || applied.Summary.DeniedCount != 1 {
		t.Fatalf("applied campaign = %#v", applied)
	}
	if applied.Results[0].Outcome != "unsupported" || applied.Results[0].Applied || applied.Results[1].Outcome != "policy_denied" {
		t.Fatalf("applied items = %#v", applied.Results)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), managedSecretValue, "bulk-denied-secret-value", "approved campaign")

	status, err := backend.bulkCampaignStatus(bulkCampaignRequest{RequestID: "req-bulk-status", ServiceID: "@serviceadmin", PlanToken: created.PlanToken})
	if err != nil {
		t.Fatal(err)
	}
	if status.Outcome != revalidated.Outcome || status.Summary.ApplicableCount != 1 {
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

type bulkMigrationTestExecutor struct {
	mu             sync.Mutex
	values         map[string]string
	writeCalls     map[string]int
	verifyCalls    map[string]int
	writeOutcomes  map[string]string
	verifyOutcomes map[string]string
	callOrder      []string
	active         int
	maxActive      int
	delay          time.Duration
}

func newBulkMigrationTestExecutor() *bulkMigrationTestExecutor {
	return &bulkMigrationTestExecutor{
		values:         map[string]string{},
		writeCalls:     map[string]int{},
		verifyCalls:    map[string]int{},
		writeOutcomes:  map[string]string{},
		verifyOutcomes: map[string]string{},
	}
}

func (e *bulkMigrationTestExecutor) Write(req providerMigrationWriteRequest) providerMigrationExecutorResult {
	e.beginCall()
	defer e.endCall()
	if e.delay > 0 {
		time.Sleep(e.delay)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writeCalls[req.Ref]++
	e.callOrder = append(e.callOrder, "write:"+req.Ref)
	outcome := firstNonEmpty(e.writeOutcomes[req.Ref], "applied")
	if outcome == "applied" {
		e.values[req.Ref] = req.Value
	}
	return providerMigrationExecutorResult{Outcome: outcome}
}

func (e *bulkMigrationTestExecutor) Verify(req providerMigrationVerifyRequest) providerMigrationExecutorResult {
	e.beginCall()
	defer e.endCall()
	if e.delay > 0 {
		time.Sleep(e.delay)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.verifyCalls[req.Ref]++
	e.callOrder = append(e.callOrder, "verify:"+req.Ref)
	if outcome := e.verifyOutcomes[req.Ref]; outcome != "" {
		return providerMigrationExecutorResult{Outcome: outcome}
	}
	if e.values[req.Ref] != req.ExpectedValue {
		return providerMigrationExecutorResult{Outcome: "verification_failed"}
	}
	return providerMigrationExecutorResult{Outcome: "verified"}
}

func (e *bulkMigrationTestExecutor) beginCall() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active++
	if e.active > e.maxActive {
		e.maxActive = e.active
	}
}

func (e *bulkMigrationTestExecutor) endCall() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active--
}

func TestBulkProviderMigrationUsesRegisteredVaultOpenBaoAndAWSExecutorLayer(t *testing.T) {
	for _, kind := range []string{"vault", "openbao", "aws-secrets-manager"} {
		t.Run(kind, func(t *testing.T) {
			backend, executor, refs, values := executableBulkMigrationBackend(t, kind, 1)
			plan := createAndRevalidateBulkMigration(t, backend, "campaign-"+safeOperationToken(kind), refs)
			applied, err := backend.bulkCampaignApply(bulkMigrationApplyRequest(plan, "req-bulk-provider-"+safeOperationToken(kind)))
			if err != nil || !applied.Applied || applied.Outcome != "applied" || applied.Summary.AppliedCount != 1 || !applied.Results[0].Verified || applied.Results[0].Attempts != 1 {
				t.Fatalf("applied=%#v err=%v", applied, err)
			}
			executor.mu.Lock()
			if executor.writeCalls[refs[0]] != 1 || executor.verifyCalls[refs[0]] != 1 || executor.values[refs[0]] != values[refs[0]] || executor.maxActive != 1 {
				t.Fatalf("executor=%#v", executor)
			}
			executor.mu.Unlock()
			assertMigrationSourcesUnchanged(t, backend, values)
			assertBulkCampaignPersistenceRedacted(t, backend, values)
		})
	}
}

func TestBulkProviderMigrationConcurrentExactApplyIsSingleFlight(t *testing.T) {
	backend, executor, refs, _ := executableBulkMigrationBackend(t, "vault", 2)
	executor.delay = 25 * time.Millisecond
	plan := createAndRevalidateBulkMigration(t, backend, "campaign-concurrent", refs)
	results := make(chan bulkCampaignResponse, 2)
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			res, err := backend.bulkCampaignApply(bulkMigrationApplyRequest(plan, "req-concurrent-"+string(rune('a'+index))))
			results <- res
			errs <- err
		}(i)
	}
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if result.Outcome != "applied" || !result.Applied {
			t.Fatalf("result=%#v", result)
		}
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.maxActive != 1 {
		t.Fatalf("max active provider calls=%d", executor.maxActive)
	}
	for _, ref := range refs {
		if executor.writeCalls[ref] != 1 || executor.verifyCalls[ref] != 1 {
			t.Fatalf("duplicate provider calls ref=%s writes=%d verifies=%d", ref, executor.writeCalls[ref], executor.verifyCalls[ref])
		}
	}
	wantOrder := []string{"write:" + refs[0], "verify:" + refs[0], "write:" + refs[1], "verify:" + refs[1]}
	if len(executor.callOrder) != len(wantOrder) {
		t.Fatalf("provider call order=%#v", executor.callOrder)
	}
	for index := range wantOrder {
		if executor.callOrder[index] != wantOrder[index] {
			t.Fatalf("provider call order=%#v want=%#v", executor.callOrder, wantOrder)
		}
	}
}

func TestBulkProviderMigrationBackpressureStopsAndDefersRemainingRefs(t *testing.T) {
	for _, outcome := range []string{"rate_limited", "source_auth_required", "source_unavailable"} {
		t.Run(outcome, func(t *testing.T) {
			backend, executor, refs, _ := executableBulkMigrationBackend(t, "vault", 3)
			executor.writeOutcomes[refs[0]] = outcome
			plan := createAndRevalidateBulkMigration(t, backend, "campaign-backpressure-"+outcome, refs)
			partial, err := backend.bulkCampaignApply(bulkMigrationApplyRequest(plan, "req-backpressure-"+outcome))
			if err != nil || partial.Outcome != "partial_failure" || partial.Applied || partial.Results[0].Outcome != outcome || partial.Results[1].Outcome != "skipped" || partial.Results[2].Outcome != "skipped" {
				t.Fatalf("partial=%#v err=%v", partial, err)
			}
			executor.mu.Lock()
			if executor.writeCalls[refs[0]] != 1 || executor.writeCalls[refs[1]] != 0 || executor.writeCalls[refs[2]] != 0 || executor.maxActive != 1 {
				t.Fatalf("executor=%#v", executor)
			}
			executor.mu.Unlock()
		})
	}
}

func TestBulkProviderMigrationRateLimitedCampaignResumesAfterRestart(t *testing.T) {
	backend, executor, refs, values := executableBulkMigrationBackend(t, "aws-secrets-manager", 3)
	executor.writeOutcomes[refs[0]] = "rate_limited"
	plan := createAndRevalidateBulkMigration(t, backend, "campaign-rate-restart", refs)
	request := bulkMigrationApplyRequest(plan, "req-rate-first")
	partial, err := backend.bulkCampaignApply(request)
	if err != nil || partial.Outcome != "partial_failure" || partial.Results[0].Outcome != "rate_limited" || partial.Summary.SkippedCount != 2 {
		t.Fatalf("partial=%#v err=%v", partial, err)
	}

	restarted := newLocalBackend(backend.storePath, backend.auditPath, backend.masterKey)
	restarted.now = backend.now
	restarted.sources = backend.sources
	restarted.registerProviderMigrationExecutor("bulk-target", executor)
	status, err := restarted.bulkCampaignStatus(bulkCampaignRequest{RequestID: "req-rate-status", ServiceID: "@serviceadmin", PlanToken: plan.PlanToken})
	if err != nil || status.Outcome != "partial_failure" || status.Results[0].Outcome != "rate_limited" || status.Results[1].Outcome != "skipped" {
		t.Fatalf("restart status=%#v err=%v", status, err)
	}
	executor.mu.Lock()
	executor.writeOutcomes[refs[0]] = "applied"
	executor.mu.Unlock()
	request.RequestID = "req-rate-resume"
	resumed, err := restarted.bulkCampaignApply(request)
	if err != nil || resumed.Outcome != "applied" || !resumed.Applied || resumed.Summary.AppliedCount != 3 {
		t.Fatalf("resumed=%#v err=%v", resumed, err)
	}
	executor.mu.Lock()
	if executor.writeCalls[refs[0]] != 2 || executor.verifyCalls[refs[0]] != 1 || executor.writeCalls[refs[1]] != 1 || executor.writeCalls[refs[2]] != 1 || executor.maxActive != 1 {
		t.Fatalf("executor=%#v", executor)
	}
	executor.mu.Unlock()
	assertMigrationSourcesUnchanged(t, restarted, values)
	assertBulkCampaignPersistenceRedacted(t, restarted, values)
}

func TestBulkProviderMigrationExpiredRevalidationFailsBeforeProvider(t *testing.T) {
	backend, executor, refs, values := executableBulkMigrationBackend(t, "vault", 1)
	plan := createAndRevalidateBulkMigration(t, backend, "campaign-expired", refs)
	if plan.RevalidatedAt == nil {
		t.Fatal("expected durable revalidation timestamp")
	}
	expiredAt := plan.RevalidatedAt.Add(time.Duration(plan.StaleAfterSeconds+1) * time.Second)
	backend.now = func() time.Time { return expiredAt }

	res, err := backend.bulkCampaignApply(bulkMigrationApplyRequest(plan, "req-expired"))
	if !errors.Is(err, errBackendDegraded) || res.Outcome != "stale_plan" || res.Applied || res.NextAction != "create_fresh_campaign_plan" {
		t.Fatalf("res=%#v err=%v", res, err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if len(executor.writeCalls) != 0 || len(executor.verifyCalls) != 0 {
		t.Fatalf("expired plan reached provider: %#v", executor)
	}
	assertMigrationSourcesUnchanged(t, backend, values)
}

func TestBulkProviderMigrationMixedFailureAndVerificationRetryAreTyped(t *testing.T) {
	backend, executor, refs, values := executableBulkMigrationBackend(t, "openbao", 3)
	deniedRef := "services/deny/runtime/DENY_BULK_MIGRATION"
	writeManagedTestSecret(t, backend, deniedRef, "bulk-denied-value")
	values[deniedRef] = "bulk-denied-value"
	refs = append(refs, deniedRef)
	executor.verifyOutcomes[refs[1]] = "verification_failed"
	plan := createAndRevalidateBulkMigration(t, backend, "campaign-mixed", refs)
	partial, err := backend.bulkCampaignApply(bulkMigrationApplyRequest(plan, "req-mixed-first"))
	if err != nil || partial.Outcome != "partial_failure" || !partial.Applied || partial.Summary.AppliedCount != 2 || partial.Summary.DeniedCount != 1 || partial.Summary.FailedCount != 1 {
		t.Fatalf("partial=%#v err=%v", partial, err)
	}
	executor.mu.Lock()
	if executor.writeCalls[refs[1]] != 1 || executor.verifyCalls[refs[1]] != 1 {
		t.Fatalf("verification calls=%#v/%#v", executor.writeCalls, executor.verifyCalls)
	}
	executor.verifyOutcomes[refs[1]] = "verified"
	executor.mu.Unlock()
	restarted := newLocalBackend(backend.storePath, backend.auditPath, backend.masterKey)
	restarted.now = backend.now
	restarted.sources = backend.sources
	restarted.registerProviderMigrationExecutor("bulk-target", executor)
	resumed, err := restarted.bulkCampaignApply(bulkMigrationApplyRequest(plan, "req-mixed-resume"))
	if err != nil || resumed.Outcome != "partial_failure" || resumed.Summary.AppliedCount != 3 || resumed.Summary.DeniedCount != 1 {
		t.Fatalf("resumed=%#v err=%v", resumed, err)
	}
	executor.mu.Lock()
	if executor.writeCalls[refs[1]] != 1 || executor.verifyCalls[refs[1]] != 2 {
		t.Fatalf("verification retry rewrote target: writes=%d verifies=%d", executor.writeCalls[refs[1]], executor.verifyCalls[refs[1]])
	}
	executor.mu.Unlock()
	assertMigrationSourcesUnchanged(t, restarted, values)
}

func TestBulkProviderMigrationStalePlanAndHighRiskConfirmationFailBeforeProvider(t *testing.T) {
	backend, executor, refs, _ := executableBulkMigrationBackend(t, "vault", 2)
	plan := createAndRevalidateBulkMigration(t, backend, "campaign-stale", refs)
	base := bulkMigrationApplyRequest(plan, "req-stale-base")
	cases := []bulkCampaignRequest{
		func() bulkCampaignRequest { value := base; value.Operation = "rotate_reset"; return value }(),
		func() bulkCampaignRequest { value := base; value.TargetProviderID = "changed-target"; return value }(),
		func() bulkCampaignRequest { value := base; value.Refs = refs[:1]; return value }(),
	}
	for _, request := range cases {
		res, err := backend.bulkCampaignApply(request)
		if err == nil || res.Outcome != "stale_plan" || res.Applied {
			t.Fatalf("res=%#v err=%v", res, err)
		}
	}
	missingConfirm := base
	missingConfirm.HighRiskConfirm = ""
	res, err := backend.bulkCampaignApply(missingConfirm)
	if !errors.Is(err, errPolicyDenied) || res.Outcome != "policy_denied" || res.Applied {
		t.Fatalf("high-risk res=%#v err=%v", res, err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	for _, ref := range refs {
		if executor.writeCalls[ref] != 0 || executor.verifyCalls[ref] != 0 {
			t.Fatalf("failed precondition reached provider ref=%s", ref)
		}
	}
}

func TestBulkProviderMigrationAuditFailureStopsBeforeProvider(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		auditPath func(*testing.T) string
	}{
		{name: "missing", auditPath: func(*testing.T) string { return "" }},
		{name: "unwritable", auditPath: func(t *testing.T) string {
			blockedAudit := filepath.Join(t.TempDir(), "audit-is-directory")
			if err := os.Mkdir(blockedAudit, 0o700); err != nil {
				t.Fatal(err)
			}
			return blockedAudit
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			backend, executor, refs, values := executableBulkMigrationBackend(t, "vault", 2)
			plan := createAndRevalidateBulkMigration(t, backend, "campaign-audit-"+testCase.name, refs)
			backend.auditPath = testCase.auditPath(t)
			res, err := backend.bulkCampaignApply(bulkMigrationApplyRequest(plan, "req-audit-blocked-"+testCase.name))
			if !errors.Is(err, errProviderAuditUnavailable) || res.Outcome != "audit_unavailable" || res.Applied {
				t.Fatalf("res=%#v err=%v", res, err)
			}
			executor.mu.Lock()
			for _, ref := range refs {
				if executor.writeCalls[ref] != 0 || executor.verifyCalls[ref] != 0 {
					t.Fatalf("audit failure reached provider ref=%s", ref)
				}
			}
			executor.mu.Unlock()
			assertMigrationSourcesUnchanged(t, backend, values)
		})
	}
}

func TestBulkProviderMigrationRequiresExecutableTarget(t *testing.T) {
	backend, _, refs, _ := executableBulkMigrationBackend(t, "vault", 1)
	backend.providerExecutors = map[string]providerMigrationExecutor{}
	created, err := backend.bulkCampaignCreate(bulkCampaignRequest{RequestID: "req-missing-target", ServiceID: "@serviceadmin", CampaignID: "campaign-missing-target", OperationID: "op-missing-target", Operation: "migrate_remap_provider", TargetProviderID: "bulk-target", Refs: refs, Reason: "plan missing target"})
	if !errors.Is(err, errUnsupportedProvider) || created.Outcome != "unsupported" || created.Applied || created.Summary.UnsupportedCount != 1 {
		t.Fatalf("created=%#v err=%v", created, err)
	}
}

func executableBulkMigrationBackend(t *testing.T, kind string, refCount int) (*localBackend, *bulkMigrationTestExecutor, []string, map[string]string) {
	t.Helper()
	backend := managedTestBackend(t)
	allRefs := []string{
		"services/@serviceadmin/runtime/API_KEY",
		"services/@serviceadmin/runtime/DB_PASSWORD",
		"services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
	}
	refs := append([]string{}, allRefs[:refCount]...)
	values := map[string]string{}
	for index, ref := range refs {
		value := "bulk-provider-source-secret-" + string(rune('a'+index))
		values[ref] = value
		writeManagedTestSecret(t, backend, ref, value)
	}
	source := sourceConfig{
		SourceID: "bulk-target", Kind: kind, Enabled: true, Address: "https://provider.invalid", Token: providerCredentialValue,
		Refs: map[string]sourceRefConfig{"services/fixture/runtime/TARGET": {Path: "secret/data/fixture", Field: "value"}},
	}
	if kind == "aws-secrets-manager" {
		source.Region = "us-east-1"
		source.Refs = map[string]sourceRefConfig{"services/fixture/runtime/TARGET": {Path: "service-lasso/fixture", Field: "value", VersionStage: "AWSCURRENT"}}
	}
	backend.sources = sourceConfigFile{Sources: []sourceConfig{source}}
	executor := newBulkMigrationTestExecutor()
	backend.registerProviderMigrationExecutor(source.SourceID, executor)
	return backend, executor, refs, values
}

func createAndRevalidateBulkMigration(t *testing.T, backend *localBackend, campaignID string, refs []string) bulkCampaignResponse {
	t.Helper()
	created, err := backend.bulkCampaignCreate(bulkCampaignRequest{RequestID: "req-create-" + campaignID, ServiceID: "@serviceadmin", CampaignID: campaignID, OperationID: "op-" + campaignID, Operation: "migrate_remap_provider", TargetProviderID: "bulk-target", Refs: refs, Reason: "operator migration planning"})
	if err != nil || (created.Outcome != "dry_run_ready" && created.Outcome != "partial_failure") || !created.Durable || created.MaxConcurrency != 1 || created.BackpressurePolicy != "stop_and_defer_remaining" {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	revalidated, err := backend.bulkCampaignRevalidate(bulkCampaignRequest{RequestID: "req-revalidate-" + campaignID, ServiceID: "@serviceadmin", PlanToken: created.PlanToken})
	if err != nil || revalidated.RequiresRevalidation || revalidated.PlanToken != created.PlanToken {
		t.Fatalf("revalidated=%#v err=%v", revalidated, err)
	}
	return revalidated
}

func bulkMigrationApplyRequest(plan bulkCampaignResponse, requestID string) bulkCampaignRequest {
	return bulkCampaignRequest{RequestID: requestID, ServiceID: "@serviceadmin", PlanToken: plan.PlanToken, Confirm: true, Reason: "approved provider bulk migration", HighRiskConfirm: plan.CampaignID}
}

func assertBulkCampaignPersistenceRedacted(t *testing.T, backend *localBackend, values map[string]string) {
	t.Helper()
	store, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		assertNoSecretMaterial(t, store, value)
		assertNoSecretMaterial(t, audit, value)
	}
	assertNoSecretMaterial(t, store, providerCredentialValue, testProviderResponseBody, "approved provider bulk migration", "secret/data/fixture", "service-lasso/fixture")
	assertNoSecretMaterial(t, audit, providerCredentialValue, testProviderResponseBody, "approved provider bulk migration", "secret/data/fixture", "service-lasso/fixture")
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
