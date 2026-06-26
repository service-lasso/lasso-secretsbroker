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

func TestTelemetryOTelPreviewIsDryRunAndRedacted(t *testing.T) {
	t.Setenv("SECRETSBROKER_OTEL_ENABLED", "1")
	t.Setenv("SECRETSBROKER_OTEL_EXPORT_MODE", "dry-run")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.example.invalid/v1/traces?token=SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer ghp_fakeTelemetryHeaderToken1234567890")

	backend := testBackend(t)
	ref := "services/api/runtime/API_TOKEN"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: ref, Value: telemetrySecretValue}); err != nil {
		t.Fatal(err)
	}
	_ = backend.audit("provider_validate", "providers/vault/token", "source_auth_required", "@operator", "req-provider")

	res, err := buildTelemetryResponse(backend)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(
		t,
		encoded,
		telemetrySecretValue,
		ref,
		"providers/vault/token",
		"SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE",
		"ghp_fakeTelemetryHeaderToken1234567890",
	)
	if res.ContractVersion != secretsBrokerTelemetryContractVersion {
		t.Fatalf("contract version = %q", res.ContractVersion)
	}
	if res.Exporter.Status != "configured" || !res.Exporter.EndpointConfigured || !res.Exporter.HeadersConfigured {
		t.Fatalf("exporter = %#v", res.Exporter)
	}
	if res.Exporter.EndpointValueReturned || res.Exporter.HeadersValueReturned || res.Exporter.BodyValueReturned {
		t.Fatalf("exporter leaked returned values: %#v", res.Exporter)
	}
	if res.ExportPreview.Mode != "dry_run" || res.ExportPreview.Status != "not_sent" || res.ExportPreview.SignalCount != len(res.Signals) {
		t.Fatalf("export preview = %#v signals=%d", res.ExportPreview, len(res.Signals))
	}
	if res.ExportPreview.EndpointValueReturned || res.ExportPreview.HeadersValueReturned || res.ExportPreview.BodyValueReturned {
		t.Fatalf("export preview leaked returned values: %#v", res.ExportPreview)
	}
	if !hasSignal(res.Signals, "secretsbroker.operation.count") || !hasSignal(res.Signals, "secretsbroker.audit.record.count") {
		t.Fatalf("missing OTel-shaped signals: %#v", res.Signals)
	}
	allowed := map[string]bool{}
	for _, key := range res.Redaction.AllowedAttributes {
		allowed[key] = true
	}
	for _, signal := range res.Signals {
		if signal.TraceID == "" || signal.SpanID == "" || signal.CorrelationID == "" {
			t.Fatalf("signal missing trace identifiers: %#v", signal)
		}
		for key := range signal.Attributes {
			if !allowed[key] {
				t.Fatalf("signal used non-allowlisted attribute %q in %#v", key, signal)
			}
		}
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

func hasSignal(signals []telemetrySignalPreview, name string) bool {
	for _, signal := range signals {
		if signal.Name == name {
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
