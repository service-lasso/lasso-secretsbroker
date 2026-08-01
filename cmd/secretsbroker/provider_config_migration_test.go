package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const providerCredentialValue = "fixture-provider-credential-value"

func TestProviderCapabilitiesAndStatusAreSafeMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "vault-dev", Kind: "vault", DisplayName: "Vault dev", Enabled: true, Address: "https://vault.invalid", Token: providerCredentialValue, Namespaces: []string{"services/*"}, Refs: map[string]sourceRefConfig{
			"services/api/runtime/API_TOKEN": {Path: "secret/data/api", Field: "token"},
		},
	}}}

	capabilities := backend.providerCapabilitiesResponse()
	if capabilities.Outcome != "ready" || len(capabilities.Capabilities) == 0 {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	localCapabilities := providerCapabilitiesByKind("local-encrypted-store").Capabilities
	for _, capability := range []string{"read", "reveal", "write/update", "rotate/reset", "audit", "migration", "health"} {
		assertContains(t, localCapabilities, capability)
	}
	for _, capability := range []string{"policy", "value-search", "value_search"} {
		assertNotContains(t, localCapabilities, capability)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, capabilities), providerCredentialValue)
	vaultCapabilities := providerCapabilitiesByKind("vault").Capabilities
	for _, capability := range []string{"read", "reveal", "write/update", "rotate/reset", "policy", "audit", "migration", "health"} {
		assertContains(t, vaultCapabilities, capability)
	}
	assertNotContains(t, vaultCapabilities, "value-search")

	status := backend.providerConfigStatusResponse()
	if status.Outcome != "ready" || len(status.Providers) != 2 {
		t.Fatalf("status = %#v", status)
	}
	if status.Providers[1].ProviderID != "vault-dev" || status.Providers[1].CredentialHandle == providerCredentialValue {
		t.Fatalf("provider status leaked or missed handle: %#v", status.Providers[1])
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, status), providerCredentialValue)
}

func TestProviderConfigValidationRejectsPlaintextAndCoversAuthUnsupported(t *testing.T) {
	backend := managedTestBackend(t)

	valid, err := backend.validateProviderConfig(providerConfigRequest{RequestID: "req-valid", ServiceID: "@serviceadmin", ProviderID: "vault-prod", ProviderKind: "vault", Address: "https://vault.example.invalid", CredentialRef: "secret://local/provider/vault-prod/token", Namespaces: []string{"services/*"}})
	if err != nil || valid.Outcome != "ready" || valid.Provider.CredentialHandle == "" {
		t.Fatalf("valid provider config = %#v err=%v", valid, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, valid), providerCredentialValue)

	plaintext, err := backend.validateProviderConfig(providerConfigRequest{RequestID: "req-plain", ServiceID: "@serviceadmin", ProviderID: "vault-prod", ProviderKind: "vault", Address: "https://vault.example.invalid", CredentialValue: providerCredentialValue})
	if err == nil || plaintext.Outcome != "policy_denied" || strings.Contains(string(mustManagedJSON(t, plaintext)), providerCredentialValue) {
		t.Fatalf("plaintext credential should fail closed without echo: %#v err=%v", plaintext, err)
	}

	authRequired, err := backend.validateProviderConfig(providerConfigRequest{RequestID: "req-auth", ServiceID: "@serviceadmin", ProviderID: "vault-prod", ProviderKind: "vault", Address: "https://vault.example.invalid"})
	if err == nil || authRequired.Outcome != "source_auth_required" {
		t.Fatalf("auth required response = %#v err=%v", authRequired, err)
	}

	unsupported, err := backend.validateProviderConfig(providerConfigRequest{RequestID: "req-unsupported", ServiceID: "@serviceadmin", ProviderID: "cloud-x", ProviderKind: "cloud-x"})
	if err == nil || unsupported.Outcome != "unsupported" {
		t.Fatalf("unsupported response = %#v err=%v", unsupported, err)
	}
}

func TestProviderConfigApplyRequiresConfirmationOperationAndReason(t *testing.T) {
	backend := managedTestBackend(t)
	req := providerConfigRequest{RequestID: "req-apply", ServiceID: "@serviceadmin", ProviderID: "vault-prod", ProviderKind: "vault", Address: "https://vault.example.invalid", CredentialRef: "secret://local/provider/vault-prod/token"}

	blocked, err := backend.applyProviderConfig(req)
	if err == nil || blocked.Applied || blocked.Outcome != "policy_denied" {
		t.Fatalf("unconfirmed apply should fail closed: %#v err=%v", blocked, err)
	}

	req.Confirm = true
	req.Reason = "operator approved provider migration setup"
	req.OperationID = "provider-config-2026-05-08-a"
	applied, err := backend.applyProviderConfig(req)
	if err != nil || !applied.Applied || applied.Outcome != "applied" {
		t.Fatalf("provider apply = %#v err=%v", applied, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), providerCredentialValue)
}

func TestMigrationDryRunMetadataOnlyPartialDenialAndApplyGating(t *testing.T) {
	backend := managedTestBackend(t)
	writeManagedTestSecret(t, backend, "services/@serviceadmin/runtime/SESSION_SIGNING_KEY", managedSecretValue)
	writeManagedTestSecret(t, backend, "services/deny/runtime/DENY_ME", "deny-value-fixture")

	dryRun, err := backend.migrationDryRun(migrationPlanRequest{RequestID: "req-migrate-dry-run", ServiceID: "@serviceadmin", OperationID: "migration-op-a", SourceProviderID: "local", TargetProviderID: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if dryRun.Outcome != "partial_failure" || len(dryRun.Results) != 2 || !dryRun.RequiresConfirmation || dryRun.Applied {
		t.Fatalf("migration dry-run = %#v", dryRun)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, dryRun), managedSecretValue, "deny-value-fixture")

	blocked, err := backend.migrationApply(migrationPlanRequest{RequestID: "req-migrate-blocked", ServiceID: "@serviceadmin", OperationID: "migration-op-a", SourceProviderID: "local", TargetProviderID: "local"})
	if err == nil || blocked.Applied || blocked.Outcome != "policy_denied" {
		t.Fatalf("unconfirmed migration apply should fail closed: %#v err=%v", blocked, err)
	}

	applied, err := backend.migrationApply(migrationPlanRequest{RequestID: "req-migrate-apply", ServiceID: "@serviceadmin", OperationID: "migration-op-a", SourceProviderID: "local", TargetProviderID: "local", Confirm: true, Reason: "approved migration"})
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied || applied.Outcome != "partial_failure" || len(applied.Results) != 2 {
		t.Fatalf("migration apply = %#v", applied)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), managedSecretValue, "deny-value-fixture")
}

func TestMigrationUnsupportedTargetAndLockedFailClosed(t *testing.T) {
	backend := managedTestBackend(t)
	writeManagedTestSecret(t, backend, "services/@serviceadmin/runtime/SESSION_SIGNING_KEY", managedSecretValue)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{SourceID: "vault-readonly", Kind: "vault", Enabled: true, Address: "https://vault.invalid", Token: "token-fixture", Refs: map[string]sourceRefConfig{"services/api/runtime/API_TOKEN": {Path: "secret/data/api", Field: "token"}}}}}

	planned, err := backend.migrationDryRun(migrationPlanRequest{RequestID: "req-vault-target", ServiceID: "@serviceadmin", OperationID: "migration-op-b", TargetProviderID: "vault-readonly"})
	if err != nil || planned.Outcome != "dry_run_ready" || len(planned.Results) == 0 {
		t.Fatalf("remote target dry-run response = %#v err=%v", planned, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, planned), managedSecretValue, "token-fixture")

	locked := newLocalBackend(t.TempDir()+"/store.json", t.TempDir()+"/audit.jsonl", "")
	lockedPlan, err := locked.migrationDryRun(migrationPlanRequest{RequestID: "req-locked", ServiceID: "@serviceadmin", OperationID: "migration-op-c", TargetProviderID: "local"})
	if err == nil || lockedPlan.Outcome != "locked" || len(lockedPlan.Results) != 0 {
		t.Fatalf("locked migration response = %#v err=%v", lockedPlan, err)
	}
}

func TestMigrationDryRunPlansConfiguredRemoteProviderTargets(t *testing.T) {
	backend := managedTestBackend(t)
	writeManagedTestSecret(t, backend, "services/@serviceadmin/runtime/SESSION_SIGNING_KEY", managedSecretValue)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{
		{SourceID: "vault-ready", Kind: "vault", Enabled: true, Address: "https://vault.invalid", Token: "vault-token-fixture", Refs: map[string]sourceRefConfig{"services/api/runtime/API_TOKEN": {Path: "secret/data/api", Field: "token"}}},
		{SourceID: "openbao-ready", Kind: "openbao", Enabled: true, Address: "https://openbao.invalid", Token: "openbao-token-fixture", Refs: map[string]sourceRefConfig{"services/api/runtime/API_TOKEN": {Path: "secret/data/api", Field: "token"}}},
		{SourceID: "aws-ready", Kind: "aws-secrets-manager", Enabled: true, Address: "https://aws.invalid", Token: "aws-token-fixture", Refs: map[string]sourceRefConfig{"services/api/runtime/API_TOKEN": {Path: "service-lasso/api/token"}}},
	}}

	for _, target := range []string{"vault-ready", "openbao-ready", "aws-ready"} {
		t.Run(target, func(t *testing.T) {
			plan, err := backend.migrationDryRun(migrationPlanRequest{RequestID: "req-remote-plan", ServiceID: "@serviceadmin", OperationID: "migration-op-remote", SourceProviderID: "local", TargetProviderID: target, Refs: []string{"services/@serviceadmin/runtime/SESSION_SIGNING_KEY"}})
			if err != nil || plan.Outcome != "dry_run_ready" || plan.Applied || len(plan.Results) != 1 {
				t.Fatalf("remote migration dry-run = %#v err=%v", plan, err)
			}
			item := plan.Results[0]
			if item.State != "planned" || item.Outcome != "dry_run_ready" || item.Risk != "medium" || item.ExpectedAction != "write_value_to_remote_provider_after_revalidation" {
				t.Fatalf("remote migration item = %#v", item)
			}
			if item.Recovery != "source_retained_until_target_verification_succeeds" {
				t.Fatalf("remote migration recovery should preserve source until verification: %#v", item)
			}
			assertNoSecretMaterial(t, mustManagedJSON(t, plan), managedSecretValue, "vault-token-fixture", "openbao-token-fixture", "aws-token-fixture")
		})
	}
}

func TestMigrationApplyRemoteProviderFailsClosedUntilExecutorExists(t *testing.T) {
	backend := managedTestBackend(t)
	writeManagedTestSecret(t, backend, "services/@serviceadmin/runtime/SESSION_SIGNING_KEY", managedSecretValue)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "aws-ready", Kind: "aws-secrets-manager", Enabled: true, Address: "https://aws.invalid", Token: "aws-token-fixture", Refs: map[string]sourceRefConfig{"services/api/runtime/API_TOKEN": {Path: "service-lasso/api/token"}},
	}}}

	apply, err := backend.migrationApply(migrationPlanRequest{RequestID: "req-remote-apply", ServiceID: "@serviceadmin", OperationID: "migration-op-remote", SourceProviderID: "local", TargetProviderID: "aws-ready", Refs: []string{"services/@serviceadmin/runtime/SESSION_SIGNING_KEY"}, Confirm: true, Reason: "approved remote migration"})
	if err == nil || apply.Applied || apply.Outcome != "unsupported" || apply.NextAction != "implement_provider_operation_executor" || len(apply.Results) != 1 {
		t.Fatalf("remote migration apply should fail closed: %#v err=%v", apply, err)
	}
	item := apply.Results[0]
	if item.State != "failed" || item.Outcome != "unsupported" || item.ExpectedAction != "implement_provider_operation_executor" {
		t.Fatalf("remote migration apply item = %#v", item)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, apply), managedSecretValue, "aws-token-fixture")
}

func TestProviderConfigMigrationHTTPContract(t *testing.T) {
	backend := managedTestBackend(t)
	writeManagedTestSecret(t, backend, "services/@serviceadmin/runtime/SESSION_SIGNING_KEY", managedSecretValue)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	statusReq, err := http.NewRequest(http.MethodGet, server.URL+"/v1/providers/config/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	statusReq.Header.Set("Authorization", "Bearer test-token")
	statusRes, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	statusBody := readClose(t, statusRes.Body)
	if statusRes.StatusCode != http.StatusOK {
		t.Fatalf("status code=%d body=%s", statusRes.StatusCode, statusBody)
	}
	assertNoSecretMaterial(t, statusBody, managedSecretValue, providerCredentialValue)

	validateBody := []byte(`{"requestId":"req-http-validate","serviceId":"@serviceadmin","providerId":"vault-prod","providerKind":"vault","address":"https://vault.example.invalid","credentialRef":"secret://local/provider/vault-prod/token"}`)
	validateReq, err := http.NewRequest(http.MethodPost, server.URL+"/v1/providers/config/validate", bytes.NewReader(validateBody))
	if err != nil {
		t.Fatal(err)
	}
	validateReq.Header.Set("Content-Type", "application/json")
	validateReq.Header.Set("X-SecretsBroker-Token", "test-token")
	validateRes, err := http.DefaultClient.Do(validateReq)
	if err != nil {
		t.Fatal(err)
	}
	validatePayload := readClose(t, validateRes.Body)
	if validateRes.StatusCode != http.StatusOK {
		t.Fatalf("validate code=%d body=%s", validateRes.StatusCode, validatePayload)
	}
	assertNoSecretMaterial(t, validatePayload, providerCredentialValue)

	migrationBody := []byte(`{"requestId":"req-http-migrate","serviceId":"@serviceadmin","operationId":"migration-http-a","sourceProviderId":"local","targetProviderId":"local"}`)
	migrationReq, err := http.NewRequest(http.MethodPost, server.URL+"/v1/providers/migration/dry-run", bytes.NewReader(migrationBody))
	if err != nil {
		t.Fatal(err)
	}
	migrationReq.Header.Set("Content-Type", "application/json")
	migrationReq.Header.Set("Authorization", "Bearer test-token")
	migrationRes, err := http.DefaultClient.Do(migrationReq)
	if err != nil {
		t.Fatal(err)
	}
	migrationPayload := readClose(t, migrationRes.Body)
	if migrationRes.StatusCode != http.StatusOK {
		t.Fatalf("migration code=%d body=%s", migrationRes.StatusCode, migrationPayload)
	}
	assertNoSecretMaterial(t, migrationPayload, managedSecretValue)
}
