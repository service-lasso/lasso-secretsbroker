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
	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/telemetry?token=SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
	req.Header.Set("authorization", "Bearer ghp_fakeTelemetryHeaderToken1234567890")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("telemetry status = %d", resp.StatusCode)
	}
	expectedIdentity := telemetryAPIIdentity(http.MethodGet, "/v1/telemetry")
	if resp.Header.Get(telemetryCorrelationIDHeader) != expectedIdentity.CorrelationID {
		t.Fatalf("correlation header = %q, want %q", resp.Header.Get(telemetryCorrelationIDHeader), expectedIdentity.CorrelationID)
	}
	if resp.Header.Get(telemetryTraceIDHeader) != expectedIdentity.TraceID {
		t.Fatalf("trace id header = %q, want %q", resp.Header.Get(telemetryTraceIDHeader), expectedIdentity.TraceID)
	}
	if got := resp.Header.Get(telemetryTraceparentHeader); got != expectedIdentity.Traceparent || got == req.Header.Get("traceparent") {
		t.Fatalf("traceparent header = %q, expected broker-generated %q", got, expectedIdentity.Traceparent)
	}
	var apiBody telemetryResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiBody); err != nil {
		t.Fatal(err)
	}
	apiEncoded, err := json.Marshal(apiBody)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, apiEncoded, telemetrySecretValue, ref, "SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE", "ghp_fakeTelemetryHeaderToken1234567890")
	if apiBody.TraceContext.Propagation != "w3c-trace-context" || apiBody.TraceContext.IncomingHeadersAccepted || apiBody.TraceContext.IncomingHeadersReturned || apiBody.TraceContext.RawHeadersReturned {
		t.Fatalf("unsafe trace context posture: %#v", apiBody.TraceContext)
	}
	if apiBody.TraceContext.ResponseHeaders.Traceparent != telemetryTraceparentHeader || !apiBody.TraceContext.RouteTemplateOnly {
		t.Fatalf("trace context response headers = %#v", apiBody.TraceContext)
	}

	var cli bytes.Buffer
	if err := executeAdmin([]string{"telemetry", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &cli); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, cli.Bytes(), telemetrySecretValue, "test-master-key", ref)
	if !strings.Contains(cli.String(), "operations") || !strings.Contains(cli.String(), "providerStates") {
		t.Fatalf("telemetry CLI missing counters: %s", cli.String())
	}
}

func TestTelemetryRecordsHTTPRequestLatencyBucketsWithoutRawRouteMaterial(t *testing.T) {
	backend := testBackend(t)
	server := httptest.NewServer(newHandler(runtimeState{}, backend, localAPISecurity{token: "local-token"}))
	defer server.Close()

	sentinelPath := "SERVICE_LASSO_FAKE_OTEL_PATH_SECRET_DO_NOT_USE"
	healthResp, err := http.Get(server.URL + "/health?token=" + sentinelPath)
	if err != nil {
		t.Fatal(err)
	}
	healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", healthResp.StatusCode)
	}
	missingResp, err := http.Get(server.URL + "/v1/unknown/" + sentinelPath + "?credential=" + sentinelPath)
	if err != nil {
		t.Fatal(err)
	}
	missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing route status = %d", missingResp.StatusCode)
	}

	resp, err := http.Get(server.URL + "/v1/telemetry")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("telemetry status = %d", resp.StatusCode)
	}
	var body telemetryResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, encoded, sentinelPath)
	if len(body.DurationHistograms) == 0 {
		t.Fatalf("missing duration histograms: %#v", body)
	}
	if !hasDurationHistogram(body.DurationHistograms, "/health", "ready") {
		t.Fatalf("missing health duration histogram: %#v", body.DurationHistograms)
	}
	if !hasDurationHistogram(body.DurationHistograms, "/unmatched", "client_error") {
		t.Fatalf("missing sanitized unmatched duration histogram: %#v", body.DurationHistograms)
	}
	if !hasSignal(body.Signals, "secretsbroker.api.request.duration_bucket") {
		t.Fatalf("missing API request duration signal: %#v", body.Signals)
	}
	allowed := map[string]bool{}
	for _, key := range body.Redaction.AllowedAttributes {
		allowed[key] = true
	}
	for _, signal := range body.Signals {
		for key := range signal.Attributes {
			if !allowed[key] {
				t.Fatalf("signal used non-allowlisted attribute %q in %#v", key, signal)
			}
		}
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
		if signal.TraceID == "" || signal.SpanID == "" || signal.CorrelationID == "" || !validTraceparent(signal.Traceparent, signal.TraceID, signal.SpanID) {
			t.Fatalf("signal missing trace identifiers: %#v", signal)
		}
		for key := range signal.Attributes {
			if !allowed[key] {
				t.Fatalf("signal used non-allowlisted attribute %q in %#v", key, signal)
			}
		}
	}
}

func TestTelemetryExportActionSendsSanitizedMetadataOnlyWhenExplicitlyEnabled(t *testing.T) {
	var collectorBody bytes.Buffer
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("collector method = %s", r.Method)
		}
		if got := r.Header.Get("authorization"); !strings.Contains(got, "ghp_fakeTelemetryHeaderToken1234567890") {
			t.Fatalf("collector did not receive configured header")
		}
		if _, err := collectorBody.ReadFrom(r.Body); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer collector.Close()

	t.Setenv("SECRETSBROKER_OTEL_ENABLED", "1")
	t.Setenv("SECRETSBROKER_OTEL_EXPORT_MODE", "export")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL+"/v1/traces?token=SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer ghp_fakeTelemetryHeaderToken1234567890,x-safe-route=local")

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
	if res.ExportPreview.Mode != "export_configured" || res.ExportPreview.Status != "not_sent" {
		t.Fatalf("export preview = %#v", res.ExportPreview)
	}
	result := sendTelemetryExportFromResponse(res, collector.Client())
	encodedResult, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(
		t,
		encodedResult,
		telemetrySecretValue,
		ref,
		"providers/vault/token",
		"SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE",
		"ghp_fakeTelemetryHeaderToken1234567890",
		collector.URL,
	)
	assertNoSecretMaterial(
		t,
		collectorBody.Bytes(),
		telemetrySecretValue,
		ref,
		"providers/vault/token",
		"SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE",
		"ghp_fakeTelemetryHeaderToken1234567890",
	)
	if result.Mode != "export" || result.Status != "sent" || result.ExporterStatusCode == nil || *result.ExporterStatusCode != http.StatusAccepted {
		t.Fatalf("export result = %#v", result)
	}
	if !result.EndpointConfigured || result.EndpointValueReturned || !result.HeadersConfigured || result.HeadersValueReturned || result.BodyValueReturned {
		t.Fatalf("export result leaked unsafe state: %#v", result)
	}
	var payload telemetryExportPayload
	if err := json.Unmarshal(collectorBody.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Resource.ServiceName != "secretsbroker" || len(payload.Signals) == 0 {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestTelemetryExportActionBlocksUnsafeConfigurationWithoutLeaking(t *testing.T) {
	t.Setenv("SECRETSBROKER_OTEL_ENABLED", "1")
	t.Setenv("SECRETSBROKER_OTEL_EXPORT_MODE", "export")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "file:///tmp/SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "")

	backend := testBackend(t)
	ref := "services/api/runtime/API_TOKEN"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: ref, Value: telemetrySecretValue}); err != nil {
		t.Fatal(err)
	}
	res, err := buildTelemetryResponse(backend)
	if err != nil {
		t.Fatal(err)
	}
	result := sendTelemetryExportFromResponse(res, http.DefaultClient)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, encoded, telemetrySecretValue, ref, "SERVICE_LASSO_FAKE_OTEL_TOKEN_DO_NOT_USE")
	if result.Status != "blocked" || result.EndpointValueReturned || result.HeadersValueReturned || result.BodyValueReturned {
		t.Fatalf("unsupported endpoint result = %#v", result)
	}

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "bad header=Bearer ghp_fakeTelemetryHeaderToken1234567890")
	res, err = buildTelemetryResponse(backend)
	if err != nil {
		t.Fatal(err)
	}
	result = sendTelemetryExportFromResponse(res, http.DefaultClient)
	encoded, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, encoded, "ghp_fakeTelemetryHeaderToken1234567890", "127.0.0.1:9")
	if result.Status != "blocked" || !result.HeadersConfigured {
		t.Fatalf("unsupported header result = %#v", result)
	}
}

func validTraceparent(value string, traceID string, spanID string) bool {
	return value == "00-"+traceID+"-"+spanID+"-01" &&
		len(traceID) == 32 &&
		len(spanID) == 16 &&
		len(value) == 55 &&
		strings.Count(value, "-") == 3
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

func hasDurationHistogram(histograms []telemetryDurationHistogram, operation, outcome string) bool {
	for _, histogram := range histograms {
		if histogram.Operation == operation && histogram.Outcome == outcome && len(histogram.Buckets) > 0 {
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
