package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const telemetrySecretValue = "fixture-telemetry-secret-value"

func TestTelemetryCountsOperationalMetadataWithoutSecretMaterial(t *testing.T) {
	backend := testBackend(t)
	ref := "services/api/runtime/API_TOKEN"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: ref, Value: telemetrySecretValue}); err != nil {
		t.Fatal(err)
	}
	_ = backend.audit("local_api_auth", "", "unauthorized", "@operator", "req-auth")
	backend.resolve(resolveRequest{
		RequestID: "req-policy-denied",
		ServiceID: "api",
		Secrets:   &serviceSecretsPolicy{Resolve: []string{"services/api/other/*"}},
		Refs:      []string{ref},
	})

	res, err := buildTelemetryResponse(backend)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, encoded, telemetrySecretValue, "test-master-key", ref)
	if res.Outcome != "ready" || res.Safety.ValueMaterialIncluded {
		t.Fatalf("unsafe telemetry response: %#v", res)
	}
	if !hasOperationCount(res.Counters.Operations, "write", "ready", 1) {
		t.Fatalf("missing write ready counter: %#v", res.Counters.Operations)
	}
	if !hasOperationCount(res.Counters.Operations, "resolve", "policy_denied", 1) {
		t.Fatalf("missing resolve policy_denied counter: %#v", res.Counters.Operations)
	}
	if !hasOutcomeCount(res.Counters.PolicyDecisions, "denied", 1) {
		t.Fatalf("missing policy denied counter: %#v", res.Counters.PolicyDecisions)
	}
	if res.Counters.LocalAPIAuthFailures != 1 {
		t.Fatalf("auth failure count = %d", res.Counters.LocalAPIAuthFailures)
	}
	if len(res.Counters.SourceStates) == 0 || len(res.Counters.ProviderStates) == 0 {
		t.Fatalf("missing source/provider state counters: %#v", res.Counters)
	}
}

func TestTelemetryEndpointAndAdminCLIAreMetadataOnly(t *testing.T) {
	backend := testBackend(t)
	ref := "services/api/runtime/API_TOKEN"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: ref, Value: telemetrySecretValue}); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(newHandler(runtimeState{}, backend, localAPISecurity{token: "local-token"}))
	defer server.Close()
	resp, err := http.Get(server.URL + "/v1/telemetry")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("telemetry status = %d", resp.StatusCode)
	}
	var apiBody telemetryResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiBody); err != nil {
		t.Fatal(err)
	}
	apiEncoded, err := json.Marshal(apiBody)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, apiEncoded, telemetrySecretValue, ref)

	var cli bytes.Buffer
	if err := executeAdmin([]string{"telemetry", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &cli); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, cli.Bytes(), telemetrySecretValue, "test-master-key", ref)
	if !strings.Contains(cli.String(), "operations") || !strings.Contains(cli.String(), "providerStates") {
		t.Fatalf("telemetry CLI missing counters: %s", cli.String())
	}
}

func hasOperationCount(counters []telemetryOperationCounter, operation, outcome string, count int) bool {
	for _, counter := range counters {
		if counter.Operation == operation && counter.Outcome == outcome && counter.Count == count {
			return true
		}
	}
	return false
}

func hasOutcomeCount(counters []telemetryOutcomeCounter, outcome string, count int) bool {
	for _, counter := range counters {
		if counter.Outcome == outcome && counter.Count == count {
			return true
		}
	}
	return false
}
