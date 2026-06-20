package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSecretsSyncDryRunReadyContractIsMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)

	res, err := backend.syncDryRun(syncDryRunRequest{
		RequestID:     "req-sync-ready",
		ServiceID:     "@serviceadmin",
		OperationID:   "sync-plan-a",
		Refs:          []string{ref},
		DestinationID: "github-actions-service-lasso",
		Reason:        "CI runner needs metadata-only plan",
		Secrets:       &serviceSecretsPolicy{Manage: []string{"services/@serviceadmin/*"}},
		Destination: syncDestinationConfig{
			DestinationID: "github-actions-service-lasso",
			Kind:          "github-actions",
			Enabled:       true,
			CredentialRef: "providers/github/service-lasso-sync/app",
			AuthModel:     "github-app",
			Scope: syncDestinationScope{
				Owner:           "service-lasso",
				Repository:      "service-lasso",
				Environment:     "demo",
				SecretsLocation: "environment",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "dry_run_ready" || res.Applied || !res.RequiresConfirmation || res.Summary.ReadyCount != 1 || res.Summary.HighRiskCount != 1 {
		t.Fatalf("sync dry-run response = %#v", res)
	}
	if len(res.Results) != 1 || res.Results[0].DestinationName != "SERVICE_LASSO_SESSION_SIGNING_KEY" || res.Results[0].IdempotencyKey == "" || res.Results[0].RefHash == "" {
		t.Fatalf("sync dry-run item = %#v", res.Results)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, res), managedSecretValue, "test-master-key", "CI runner needs metadata-only plan", "providers/github/service-lasso-sync/app-private-key")
}

func TestSecretsSyncDryRunFailsClosedForPolicyAuthAuditCollisionAndNoLeak(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)

	denied, err := backend.syncDryRun(syncDryRunRequest{
		RequestID:     "req-sync-denied",
		ServiceID:     "@serviceadmin",
		Refs:          []string{ref},
		DestinationID: "github-actions-service-lasso",
		Secrets:       &serviceSecretsPolicy{Manage: []string{"services/other/*"}},
		Destination:   readySyncDestination(),
	})
	if !errors.Is(err, errPolicyDenied) || denied.Outcome != "policy_denied" || denied.Summary.DeniedCount != 1 {
		t.Fatalf("policy denied sync = %#v err=%v", denied, err)
	}

	authRequired, err := backend.syncDryRun(syncDryRunRequest{
		RequestID:     "req-sync-auth",
		ServiceID:     "@serviceadmin",
		Refs:          []string{ref},
		DestinationID: "github-actions-service-lasso",
		Secrets:       &serviceSecretsPolicy{Manage: []string{"services/@serviceadmin/*"}},
		Destination: syncDestinationConfig{
			DestinationID: "github-actions-service-lasso",
			Kind:          "github-actions",
			Enabled:       true,
			Scope:         syncDestinationScope{Owner: "service-lasso", Repository: "service-lasso", SecretsLocation: "repository"},
		},
	})
	if !errors.Is(err, errSourceAuthRequired) || authRequired.Outcome != "destination_auth_required" || authRequired.Summary.AuthRequiredCount != 1 {
		t.Fatalf("auth required sync = %#v err=%v", authRequired, err)
	}

	auditUnavailableDest := readySyncDestination()
	auditUnavailableDest.AuditStatus = "audit_unavailable"
	auditUnavailable, err := backend.syncDryRun(syncDryRunRequest{
		RequestID:     "req-sync-audit",
		ServiceID:     "@serviceadmin",
		Refs:          []string{ref},
		DestinationID: "github-actions-service-lasso",
		Secrets:       &serviceSecretsPolicy{Manage: []string{"services/@serviceadmin/*"}},
		Destination:   auditUnavailableDest,
	})
	if err == nil || auditUnavailable.Outcome != "audit_unavailable" || auditUnavailable.Summary.AuditUnavailableCount != 1 {
		t.Fatalf("audit unavailable sync = %#v err=%v", auditUnavailable, err)
	}

	collision, err := backend.syncDryRun(syncDryRunRequest{
		RequestID:      "req-sync-collision",
		ServiceID:      "@serviceadmin",
		Refs:           []string{ref},
		DestinationID:  "github-actions-service-lasso",
		Secrets:        &serviceSecretsPolicy{Manage: []string{"services/@serviceadmin/*"}},
		Destination:    readySyncDestination(),
		CollisionState: "unmanaged_collision",
	})
	if err == nil || collision.Outcome != "unmanaged_collision" || collision.Summary.UnmanagedCollisionCount != 1 {
		t.Fatalf("collision sync = %#v err=%v", collision, err)
	}

	plaintextCredential, err := backend.syncDryRun(syncDryRunRequest{
		RequestID:       "req-sync-plain-credential",
		ServiceID:       "@serviceadmin",
		Refs:            []string{ref},
		DestinationID:   "github-actions-service-lasso",
		Secrets:         &serviceSecretsPolicy{Manage: []string{"services/@serviceadmin/*"}},
		Destination:     readySyncDestination(),
		CredentialValue: "ghp_plaintext_token_value",
	})
	if !errors.Is(err, errPolicyDenied) || plaintextCredential.Outcome != "policy_denied" {
		t.Fatalf("plaintext credential sync = %#v err=%v", plaintextCredential, err)
	}

	for _, payload := range [][]byte{mustManagedJSON(t, denied), mustManagedJSON(t, authRequired), mustManagedJSON(t, auditUnavailable), mustManagedJSON(t, collision), mustManagedJSON(t, plaintextCredential)} {
		assertNoSecretMaterial(t, payload, managedSecretValue, "ghp_plaintext_token_value", "SecretString", "encrypted_value_payload", "private-key")
	}
}

func TestSecretsSyncDryRunHTTPAndCLIContractAreMetadataOnly(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, managedSecretValue)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"requestId":"req-http-sync","serviceId":"@serviceadmin","operationId":"sync-plan-http","refs":["` + ref + `"],"destinationId":"github-actions-service-lasso","secrets":{"manage":["services/@serviceadmin/*"]},"destination":{"destinationId":"github-actions-service-lasso","kind":"github-actions","enabled":true,"credentialRef":"providers/github/service-lasso-sync/app","scope":{"owner":"service-lasso","repository":"service-lasso","secretsLocation":"repository"}},"credentialValue":"ghp_plaintext_token_value"}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/management/secrets/sync/dry-run", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	httpRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got := readClose(t, httpRes.Body)
	if httpRes.StatusCode != http.StatusForbidden {
		t.Fatalf("sync dry-run status=%d body=%s", httpRes.StatusCode, got)
	}
	assertNoSecretMaterial(t, got, managedSecretValue, "test-token", "ghp_plaintext_token_value")

	var safe bytes.Buffer
	err = executeAdmin([]string{
		"sync", "dry-run",
		"--ref", ref,
		"--service-id", "@serviceadmin",
		"--policy-ref", "services/@serviceadmin/*",
		"--destination-id", "github-actions-service-lasso",
		"--owner", "service-lasso",
		"--repository", "service-lasso",
		"--secrets-location", "repository",
		"--credential-ref", "providers/github/service-lasso-sync/app",
		"--store", backend.storePath,
		"--audit", backend.auditPath,
		"--master-key", "test-master-key",
	}, &safe)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, safe.Bytes(), managedSecretValue, "test-master-key")
	if !bytes.Contains(safe.Bytes(), []byte(`"operation": "secrets_sync"`)) || !bytes.Contains(safe.Bytes(), []byte(`"outcome": "dry_run_ready"`)) {
		t.Fatalf("CLI sync dry-run body=%s", safe.String())
	}

	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, auditBytes, managedSecretValue, "ghp_plaintext_token_value", "test-token")
	if !strings.Contains(string(auditBytes), "secrets_sync_dry_run") {
		t.Fatalf("audit missing sync dry run: %s", auditBytes)
	}
}

func readySyncDestination() syncDestinationConfig {
	return syncDestinationConfig{
		DestinationID: "github-actions-service-lasso",
		Kind:          "github-actions",
		Enabled:       true,
		CredentialRef: "providers/github/service-lasso-sync/app",
		AuthModel:     "github-app",
		Scope:         syncDestinationScope{Owner: "service-lasso", Repository: "service-lasso", SecretsLocation: "repository"},
	}
}

func TestSecretsSyncDryRunRepresentsGitHubScopes(t *testing.T) {
	for _, scope := range []syncDestinationScope{
		{Owner: "service-lasso", Repository: "service-lasso", SecretsLocation: "repository"},
		{Owner: "service-lasso", Repository: "service-lasso", Environment: "demo", SecretsLocation: "environment"},
		{Owner: "service-lasso", SecretsLocation: "organization", Visibility: "selected", SelectedRepositories: []string{"service-lasso"}, EnterpriseURL: "https://github.example.invalid"},
	} {
		dest := readySyncDestination()
		dest.Scope = scope
		normalized := normalizeSyncDestination(syncDryRunRequest{DestinationID: dest.DestinationID, Destination: dest})
		if normalized.Scope.SecretsLocation == "" || normalized.Kind != "github-actions" {
			t.Fatalf("normalized scope = %#v", normalized)
		}
		if syncDestinationScopeLabel(normalized.Scope) == "" {
			t.Fatalf("empty scope label for %#v", normalized.Scope)
		}
	}
}
