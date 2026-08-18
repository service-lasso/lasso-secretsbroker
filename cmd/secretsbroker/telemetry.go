package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const secretsBrokerTelemetryContractVersion = "service-lasso.secretsbroker.telemetry-preview.v1"

const (
	telemetryCorrelationIDHeader = "x-service-lasso-correlation-id"
	telemetryTraceIDHeader       = "x-service-lasso-trace-id"
	telemetryTraceparentHeader   = "traceparent"
)

type telemetryResponse struct {
	ContractVersion    string                       `json:"contractVersion"`
	ServiceID          string                       `json:"serviceId"`
	APIVersion         string                       `json:"apiVersion"`
	Outcome            string                       `json:"outcome"`
	GeneratedAt        time.Time                    `json:"generatedAt"`
	TraceContext       telemetryTraceContextPreview `json:"traceContext"`
	Exporter           telemetryExporterPreview     `json:"exporter"`
	Resource           telemetryResourcePreview     `json:"resource"`
	Redaction          telemetryAttributePolicy     `json:"redaction"`
	ExportPreview      telemetryExportPreview       `json:"exportPreview"`
	Counters           telemetryCounters            `json:"counters"`
	DurationHistograms []telemetryDurationHistogram `json:"durationHistograms"`
	Signals            []telemetrySignalPreview     `json:"signals"`
	Safety             telemetrySafety              `json:"safety"`
}

type telemetryExporterPreview struct {
	Status                string `json:"status"`
	Protocol              string `json:"protocol"`
	EndpointConfigured    bool   `json:"endpointConfigured"`
	EndpointValueReturned bool   `json:"endpointValueReturned"`
	HeadersValueReturned  bool   `json:"headersValueReturned"`
	HeadersConfigured     bool   `json:"headersConfigured"`
	BodyValueReturned     bool   `json:"bodyValueReturned"`
	Reason                string `json:"reason"`
}

type telemetryResourcePreview struct {
	ServiceName       string `json:"serviceName"`
	ServiceNamespace  string `json:"serviceNamespace"`
	ServiceInstanceID string `json:"serviceInstanceId"`
}

type telemetryTraceContextPreview struct {
	Propagation             string                       `json:"propagation"`
	ResponseHeaders         telemetryTraceContextHeaders `json:"responseHeaders"`
	IncomingHeadersAccepted bool                         `json:"incomingHeadersAccepted"`
	IncomingHeadersReturned bool                         `json:"incomingHeadersReturned"`
	RawHeadersReturned      bool                         `json:"rawHeadersReturned"`
	RouteTemplateOnly       bool                         `json:"routeTemplateOnly"`
	TraceparentSampled      bool                         `json:"traceparentSampled"`
	Safety                  telemetryTraceContextSafety  `json:"safety"`
}

type telemetryTraceContextHeaders struct {
	CorrelationID string `json:"correlationId"`
	TraceID       string `json:"traceId"`
	Traceparent   string `json:"traceparent"`
}

type telemetryTraceContextSafety struct {
	RequestBodiesReturned  bool `json:"requestBodiesReturned"`
	ResponseBodiesReturned bool `json:"responseBodiesReturned"`
	QueryStringsReturned   bool `json:"queryStringsReturned"`
}

type telemetryAttributePolicy struct {
	Mode                  string   `json:"mode"`
	RedactedValue         string   `json:"redactedValue"`
	AllowedAttributes     []string `json:"allowedAttributes"`
	ForbiddenFieldClasses []string `json:"forbiddenFieldClasses"`
	PatternClasses        []string `json:"patternClasses"`
	OmittedFieldExamples  []string `json:"omittedFieldExamples"`
}

type telemetryExportPreview struct {
	Mode                  string   `json:"mode"`
	Status                string   `json:"status"`
	Protocol              string   `json:"protocol"`
	ContentType           string   `json:"contentType"`
	SignalCount           int      `json:"signalCount"`
	EndpointConfigured    bool     `json:"endpointConfigured"`
	EndpointValueReturned bool     `json:"endpointValueReturned"`
	HeadersValueReturned  bool     `json:"headersValueReturned"`
	BodyValueReturned     bool     `json:"bodyValueReturned"`
	AllowedAttributeCount int      `json:"allowedAttributeCount"`
	DroppedFieldClasses   []string `json:"droppedFieldClasses"`
	SafeEnvelopeFields    []string `json:"safeEnvelopeFields"`
	Reason                string   `json:"reason"`
}

type telemetryExportActionResult struct {
	Mode                  string `json:"mode"`
	Status                string `json:"status"`
	Protocol              string `json:"protocol"`
	ContentType           string `json:"contentType"`
	SignalCount           int    `json:"signalCount"`
	EndpointConfigured    bool   `json:"endpointConfigured"`
	EndpointValueReturned bool   `json:"endpointValueReturned"`
	HeadersConfigured     bool   `json:"headersConfigured"`
	HeadersValueReturned  bool   `json:"headersValueReturned"`
	BodyValueReturned     bool   `json:"bodyValueReturned"`
	ExporterStatusCode    *int   `json:"exporterStatusCode"`
	Reason                string `json:"reason"`
}

type telemetryExportPayload struct {
	Resource telemetryResourcePreview `json:"resource"`
	Signals  []telemetrySignalPreview `json:"signals"`
}

type telemetryCounters struct {
	Operations           []telemetryOperationCounter `json:"operations"`
	PolicyDecisions      []telemetryOutcomeCounter   `json:"policyDecisions"`
	LocalAPIAuthFailures int                         `json:"localApiAuthFailures"`
	ActiveLockouts       int                         `json:"activeLockouts"`
	ProviderStates       []telemetryStateCounter     `json:"providerStates"`
	SourceStates         []telemetryStateCounter     `json:"sourceStates"`
	AuditRecords         []telemetryAuditCounter     `json:"auditRecords"`
}

type telemetryOperationCounter struct {
	Operation string `json:"operation"`
	Outcome   string `json:"outcome"`
	Count     int    `json:"count"`
}

type telemetryOutcomeCounter struct {
	Outcome string `json:"outcome"`
	Count   int    `json:"count"`
}

type telemetryStateCounter struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Outcome string `json:"outcome"`
	Count   int    `json:"count"`
}

type telemetryAuditCounter struct {
	AuditStatus string `json:"auditStatus"`
	Outcome     string `json:"outcome"`
	Count       int    `json:"count"`
}

type telemetryDurationHistogram struct {
	Operation string         `json:"operation"`
	Outcome   string         `json:"outcome,omitempty"`
	Buckets   map[string]int `json:"buckets"`
}

type telemetryRequestSummary struct {
	RouteTemplate string `json:"routeTemplate"`
	RouteGroup    string `json:"routeGroup"`
	Method        string `json:"method"`
	StatusClass   string `json:"statusClass"`
	Outcome       string `json:"outcome"`
	DurationMs    int    `json:"durationMs"`
	Mutating      bool   `json:"mutating"`
}

type telemetryRequestRecorder struct {
	mu           sync.Mutex
	capacity     int
	requests     []telemetryRequestSummary
	droppedCount int
}

type telemetrySignalPreview struct {
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	TraceID       string         `json:"traceId"`
	SpanID        string         `json:"spanId"`
	Traceparent   string         `json:"traceparent"`
	CorrelationID string         `json:"correlationId"`
	Attributes    map[string]any `json:"attributes"`
}

type telemetrySafety struct {
	LowCardinalityLabels  bool `json:"lowCardinalityLabels"`
	ValueMaterialIncluded bool `json:"valueMaterialIncluded"`
}

func newTelemetryRequestRecorder(capacity int) *telemetryRequestRecorder {
	if capacity < 1 {
		capacity = 50
	}
	return &telemetryRequestRecorder{capacity: capacity}
}

func (r *telemetryRequestRecorder) record(request telemetryRequestSummary) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) >= r.capacity {
		copy(r.requests, r.requests[1:])
		r.requests[len(r.requests)-1] = request
		r.droppedCount++
		return
	}
	r.requests = append(r.requests, request)
}

func (r *telemetryRequestRecorder) snapshot() ([]telemetryRequestSummary, int) {
	if r == nil {
		return nil, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]telemetryRequestSummary(nil), r.requests...), r.droppedCount
}

func buildTelemetryResponse(backend *localBackend) (telemetryResponse, error) {
	res := telemetryResponse{
		ContractVersion:    secretsBrokerTelemetryContractVersion,
		ServiceID:          serviceID,
		APIVersion:         apiVersion,
		Outcome:            "ready",
		GeneratedAt:        time.Now().UTC(),
		TraceContext:       telemetryTraceContextPreviewStatus(),
		Exporter:           telemetryExporterStatusFromEnv(),
		Resource:           telemetryResourcePreview{ServiceName: "secretsbroker", ServiceNamespace: "service-lasso", ServiceInstanceID: "local-broker"},
		Redaction:          secretsBrokerTelemetryAttributePolicy(),
		DurationHistograms: []telemetryDurationHistogram{},
		Safety:             telemetrySafety{LowCardinalityLabels: true, ValueMaterialIncluded: false},
	}
	res.ExportPreview = telemetryExportPreviewFromEnv(res.Exporter, 0, res.Redaction)
	if backend == nil {
		res.Outcome = "degraded"
		return res, errBackendDegraded
	}

	audit, err := exportAuditEvents(backend.auditPath, "", "", true)
	if err != nil {
		res.Outcome = "degraded"
		return res, err
	}
	res.Counters.Operations = auditOperationCounters(audit.Events)
	res.Counters.PolicyDecisions = policyDecisionCounters(audit.Events)
	res.Counters.LocalAPIAuthFailures = localAPIAuthFailureCount(audit.Events)
	res.Counters.ActiveLockouts = activeLockoutCount(backend)
	res.Counters.AuditRecords = auditRecordCounters(audit.Events)
	res.Counters.SourceStates = sourceStateCounters(defaultSourceRegistry(backend).Sources)
	res.Counters.ProviderStates = providerStateCounters(backend.providerConfigStatusResponse().Providers)
	var requests []telemetryRequestSummary
	if backend.telemetry != nil {
		requests, _ = backend.telemetry.snapshot()
	}
	res.DurationHistograms = requestDurationHistograms(requests)
	res.Signals = buildTelemetrySignals(res.Counters)
	res.Signals = append(res.Signals, buildRequestDurationSignals(requests)...)
	res.ExportPreview = telemetryExportPreviewFromEnv(res.Exporter, len(res.Signals), res.Redaction)
	return res, nil
}

func activeLockoutCount(backend *localBackend) int {
	if backend == nil {
		return 0
	}
	count := backend.lockouts.activeCount()
	if backend.localAPILockouts != nil && backend.localAPILockouts != backend.lockouts {
		count += backend.localAPILockouts.activeCount()
	}
	return count
}

func registerTelemetryHandlers(mux *http.ServeMux, backend *localBackend) {
	mux.HandleFunc("/v1/telemetry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/telemetry.", "invalid_ref", "")
			return
		}
		res, err := buildTelemetryResponse(backend)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, errBackendDegraded) {
				status = http.StatusServiceUnavailable
			}
			writeJSON(w, status, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("/v1/telemetry/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/telemetry/export.", "invalid_ref", "")
			return
		}
		res, err := buildTelemetryResponse(backend)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, sendTelemetryExportFromResponse(res, http.DefaultClient))
			return
		}
		writeJSON(w, http.StatusOK, sendTelemetryExportFromResponse(res, http.DefaultClient))
	})
}

func telemetryTraceContextPreviewStatus() telemetryTraceContextPreview {
	return telemetryTraceContextPreview{
		Propagation: "w3c-trace-context",
		ResponseHeaders: telemetryTraceContextHeaders{
			CorrelationID: telemetryCorrelationIDHeader,
			TraceID:       telemetryTraceIDHeader,
			Traceparent:   telemetryTraceparentHeader,
		},
		IncomingHeadersAccepted: false,
		IncomingHeadersReturned: false,
		RawHeadersReturned:      false,
		RouteTemplateOnly:       true,
		TraceparentSampled:      true,
		Safety: telemetryTraceContextSafety{
			RequestBodiesReturned:  false,
			ResponseBodiesReturned: false,
			QueryStringsReturned:   false,
		},
	}
}

func auditOperationCounters(events []auditEvent) []telemetryOperationCounter {
	counts := map[string]int{}
	for _, event := range events {
		event = normalizeAuditEvent(event)
		counts[event.Operation+"\x00"+event.Outcome]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]telemetryOperationCounter, 0, len(keys))
	for _, key := range keys {
		operation, outcome := splitCounterKey(key)
		out = append(out, telemetryOperationCounter{Operation: operation, Outcome: outcome, Count: counts[key]})
	}
	return out
}

func policyDecisionCounters(events []auditEvent) []telemetryOutcomeCounter {
	counts := map[string]int{}
	for _, event := range events {
		event = normalizeAuditEvent(event)
		if event.Operation == "policy_decision" {
			counts[event.Outcome]++
		}
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]telemetryOutcomeCounter, 0, len(keys))
	for _, key := range keys {
		out = append(out, telemetryOutcomeCounter{Outcome: key, Count: counts[key]})
	}
	return out
}

func localAPIAuthFailureCount(events []auditEvent) int {
	count := 0
	for _, event := range events {
		event = normalizeAuditEvent(event)
		if event.Operation == "local_api_auth" && event.Outcome != "ready" {
			count++
		}
	}
	return count
}

func auditRecordCounters(events []auditEvent) []telemetryAuditCounter {
	counts := map[string]int{}
	for _, event := range events {
		event = normalizeAuditEvent(event)
		counts[event.AuditStatus+"\x00"+event.Outcome]++
	}
	keys := sortedKeys(counts)
	out := make([]telemetryAuditCounter, 0, len(keys))
	for _, key := range keys {
		status, outcome := splitCounterKey(key)
		out = append(out, telemetryAuditCounter{AuditStatus: status, Outcome: outcome, Count: counts[key]})
	}
	return out
}

func sourceStateCounters(sources []SourceStatus) []telemetryStateCounter {
	out := make([]telemetryStateCounter, 0, len(sources))
	for _, source := range sources {
		out = append(out, telemetryStateCounter{ID: source.SourceID, State: source.State, Outcome: source.Outcome, Count: 1})
	}
	sort.Slice(out, func(i, j int) bool { return stateCounterLess(out[i], out[j]) })
	return out
}

func providerStateCounters(providers []providerConfigStatus) []telemetryStateCounter {
	out := make([]telemetryStateCounter, 0, len(providers))
	for _, provider := range providers {
		out = append(out, telemetryStateCounter{ID: provider.ProviderID, State: provider.State, Outcome: provider.Outcome, Count: 1})
	}
	sort.Slice(out, func(i, j int) bool { return stateCounterLess(out[i], out[j]) })
	return out
}

func sortedKeys(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func splitCounterKey(key string) (string, string) {
	for i := 0; i < len(key); i++ {
		if key[i] == 0 {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}

func stateCounterLess(a, b telemetryStateCounter) bool {
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	if a.State != b.State {
		return a.State < b.State
	}
	return a.Outcome < b.Outcome
}

func secretsBrokerTelemetryAttributePolicy() telemetryAttributePolicy {
	return telemetryAttributePolicy{
		Mode:          "allowlist",
		RedactedValue: "[REDACTED]",
		AllowedAttributes: []string{
			"broker.audit.status",
			"broker.api.duration_bucket",
			"broker.api.method",
			"broker.api.mutating",
			"broker.api.route",
			"broker.api.route_group",
			"broker.api.status_class",
			"broker.lockout.active_count",
			"broker.operation",
			"broker.operation.count",
			"broker.operation.duration_ms",
			"broker.operation.outcome",
			"broker.policy.outcome",
			"broker.provider.id",
			"broker.provider.outcome",
			"broker.provider.state",
			"broker.source.id",
			"broker.source.outcome",
			"broker.source.state",
			"service.api_version",
			"service.id",
			"service.namespace",
			"service.version",
		},
		ForbiddenFieldClasses: []string{
			"raw secret values",
			"provider credentials and tokens",
			"cookies and authorization headers",
			"signing key material and recovery material",
			"raw request or response bodies",
			"raw URL paths and query strings",
			"environment values",
			"provider response bodies",
			"raw refs and raw config values",
		},
		PatternClasses: []string{
			"bearer tokens",
			"GitHub-style tokens",
			"AWS access keys",
			"signing-key blocks",
			"basic-auth URLs",
			"sensitive key-value pairs",
			"Service Lasso secret regression sentinels",
		},
		OmittedFieldExamples: []string{
			"value",
			"credentialValue",
			"authorization",
			"cookie",
			"requestBody",
			"responseBody",
			"providerResponse",
			"env",
			"ref",
			"config",
		},
	}
}

func telemetryExporterStatusFromEnv() telemetryExporterPreview {
	enabled := envBoolDefault("SECRETSBROKER_OTEL_ENABLED", false)
	endpointConfigured := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) != ""
	headersConfigured := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")) != ""
	status := "disabled"
	reason := "OTLP export is disabled by default; set SECRETSBROKER_OTEL_ENABLED and OTEL_EXPORTER_OTLP_ENDPOINT to prepare a dry-run envelope."
	if enabled && endpointConfigured {
		status = "configured"
		reason = "OTLP export is configured for preview only; /v1/telemetry does not send telemetry."
	}
	return telemetryExporterPreview{
		Status:                status,
		Protocol:              "otlp-http",
		EndpointConfigured:    endpointConfigured,
		EndpointValueReturned: false,
		HeadersConfigured:     headersConfigured,
		HeadersValueReturned:  false,
		BodyValueReturned:     false,
		Reason:                reason,
	}
}

func telemetryExportPreviewFromEnv(exporter telemetryExporterPreview, signalCount int, policy telemetryAttributePolicy) telemetryExportPreview {
	mode := "disabled"
	reason := "The preview endpoint did not send telemetry."
	requestedMode := strings.ToLower(strings.TrimSpace(os.Getenv("SECRETSBROKER_OTEL_EXPORT_MODE")))
	if exporter.Status == "configured" && requestedMode == "dry-run" {
		mode = "dry_run"
		reason = "Dry-run OTLP export envelope is ready; the broker does not send telemetry from this preview API."
	} else if exporter.Status == "configured" && requestedMode == "export" {
		mode = "export_configured"
		reason = "Explicit OTLP export is configured; the preview endpoint still does not send telemetry."
	}
	return telemetryExportPreview{
		Mode:                  mode,
		Status:                "not_sent",
		Protocol:              "otlp-http",
		ContentType:           "application/json",
		SignalCount:           signalCount,
		EndpointConfigured:    exporter.EndpointConfigured,
		EndpointValueReturned: false,
		HeadersValueReturned:  false,
		BodyValueReturned:     false,
		AllowedAttributeCount: len(policy.AllowedAttributes),
		DroppedFieldClasses:   append([]string(nil), policy.ForbiddenFieldClasses...),
		SafeEnvelopeFields:    []string{"resource", "signals.kind", "signals.name", "signals.traceId", "signals.spanId", "signals.traceparent", "signals.correlationId", "signals.attributes"},
		Reason:                reason,
	}
}

func sendTelemetryExportFromResponse(res telemetryResponse, client *http.Client) telemetryExportActionResult {
	requestedMode := strings.ToLower(strings.TrimSpace(os.Getenv("SECRETSBROKER_OTEL_EXPORT_MODE")))
	mode := "disabled"
	if res.Exporter.Status == "configured" && requestedMode == "export" {
		mode = "export"
	}
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	headers, headersOK := parseTelemetryOtlpHeaders()
	statusCode := (*int)(nil)
	base := telemetryExportActionResult{
		Mode:                  mode,
		Protocol:              "otlp-http",
		ContentType:           "application/json",
		SignalCount:           len(res.Signals),
		EndpointConfigured:    res.Exporter.EndpointConfigured,
		EndpointValueReturned: false,
		HeadersConfigured:     strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")) != "",
		HeadersValueReturned:  false,
		BodyValueReturned:     false,
		ExporterStatusCode:    statusCode,
	}
	if mode != "export" {
		base.Status = "not_sent"
		base.Reason = "Telemetry export is disabled; set SECRETSBROKER_OTEL_ENABLED, OTEL_EXPORTER_OTLP_ENDPOINT, and SECRETSBROKER_OTEL_EXPORT_MODE=export to send the sanitized envelope."
		return base
	}
	if !headersOK {
		base.Status = "blocked"
		base.Reason = "OTLP export headers are configured with an unsupported header shape."
		return base
	}
	if !isTelemetryHTTPEndpoint(endpoint) {
		base.Status = "blocked"
		base.Reason = "OTLP export requires an HTTP(S) endpoint."
		return base
	}
	if client == nil {
		client = http.DefaultClient
	}
	payload, err := json.Marshal(buildTelemetryExportPayload(res))
	if err != nil {
		base.Status = "blocked"
		base.Reason = "OTLP export payload could not be encoded."
		return base
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		base.Status = "blocked"
		base.Reason = "OTLP export endpoint could not be prepared."
		return base
	}
	req.Header.Set("content-type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		base.Status = "failed"
		base.Reason = "OTLP export failed before the configured endpoint accepted the sanitized envelope."
		return base
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	code := resp.StatusCode
	base.ExporterStatusCode = &code
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		base.Status = "sent"
		base.Reason = "Sanitized telemetry was sent to the configured OTLP HTTP endpoint."
	} else {
		base.Status = "failed"
		base.Reason = "The configured OTLP HTTP endpoint returned a non-success response."
	}
	return base
}

func buildTelemetryExportPayload(res telemetryResponse) telemetryExportPayload {
	return telemetryExportPayload{
		Resource: res.Resource,
		Signals:  append([]telemetrySignalPreview(nil), res.Signals...),
	}
}

func parseTelemetryOtlpHeaders() (map[string]string, bool) {
	rawHeaders := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
	if rawHeaders == "" {
		return map[string]string{}, true
	}
	headers := map[string]string{}
	for _, entry := range strings.Split(rawHeaders, ",") {
		separator := strings.Index(entry, "=")
		if separator <= 0 {
			return nil, false
		}
		name := strings.ToLower(strings.TrimSpace(entry[:separator]))
		value := strings.TrimSpace(entry[separator+1:])
		if !validTelemetryHeaderName(name) || name == "content-type" {
			return nil, false
		}
		headers[name] = value
	}
	return headers, true
}

func validTelemetryHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			continue
		}
		if strings.ContainsRune("!#$%&'*+.^_`|~-", ch) {
			continue
		}
		return false
	}
	return true
}

func isTelemetryHTTPEndpoint(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

func buildTelemetrySignals(counters telemetryCounters) []telemetrySignalPreview {
	signals := []telemetrySignalPreview{
		telemetrySignal("metric", "secretsbroker.lockout.active", map[string]any{
			"broker.lockout.active_count": counters.ActiveLockouts,
		}),
	}
	for _, counter := range counters.Operations {
		signals = append(signals, telemetrySignal("metric", "secretsbroker.operation.count", map[string]any{
			"broker.operation":         counter.Operation,
			"broker.operation.outcome": counter.Outcome,
			"broker.operation.count":   counter.Count,
		}))
	}
	for _, counter := range counters.PolicyDecisions {
		signals = append(signals, telemetrySignal("metric", "secretsbroker.policy.decision.count", map[string]any{
			"broker.policy.outcome":  counter.Outcome,
			"broker.operation.count": counter.Count,
		}))
	}
	for _, counter := range counters.ProviderStates {
		signals = append(signals, telemetrySignal("metric", "secretsbroker.provider.state", map[string]any{
			"broker.provider.id":      counter.ID,
			"broker.provider.state":   counter.State,
			"broker.provider.outcome": counter.Outcome,
			"broker.operation.count":  counter.Count,
		}))
	}
	for _, counter := range counters.SourceStates {
		signals = append(signals, telemetrySignal("metric", "secretsbroker.source.state", map[string]any{
			"broker.source.id":       counter.ID,
			"broker.source.state":    counter.State,
			"broker.source.outcome":  counter.Outcome,
			"broker.operation.count": counter.Count,
		}))
	}
	for _, counter := range counters.AuditRecords {
		signals = append(signals, telemetrySignal("metric", "secretsbroker.audit.record.count", map[string]any{
			"broker.audit.status":      counter.AuditStatus,
			"broker.operation.outcome": counter.Outcome,
			"broker.operation.count":   counter.Count,
		}))
	}
	return signals
}

func requestDurationHistograms(requests []telemetryRequestSummary) []telemetryDurationHistogram {
	counts := map[string]map[string]int{}
	for _, request := range requests {
		key := request.RouteTemplate + "\x00" + request.Outcome
		if counts[key] == nil {
			counts[key] = map[string]int{}
		}
		counts[key][telemetryDurationBucket(request.DurationMs)]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]telemetryDurationHistogram, 0, len(keys))
	for _, key := range keys {
		operation, outcome := splitCounterKey(key)
		out = append(out, telemetryDurationHistogram{Operation: operation, Outcome: outcome, Buckets: counts[key]})
	}
	return out
}

func buildRequestDurationSignals(requests []telemetryRequestSummary) []telemetrySignalPreview {
	counts := map[string]int{}
	exemplars := map[string]telemetryRequestSummary{}
	for _, request := range requests {
		bucket := telemetryDurationBucket(request.DurationMs)
		key := request.RouteTemplate + "\x00" + request.RouteGroup + "\x00" + request.Method + "\x00" + request.StatusClass + "\x00" + request.Outcome + "\x00" + bucket + "\x00" + fmt.Sprint(request.Mutating)
		counts[key]++
		exemplars[key] = request
	}
	keys := sortedKeys(counts)
	out := make([]telemetrySignalPreview, 0, len(keys))
	for _, key := range keys {
		parts := strings.Split(key, "\x00")
		if len(parts) != 7 {
			continue
		}
		request := exemplars[key]
		out = append(out, telemetrySignal("metric", "secretsbroker.api.request.duration_bucket", map[string]any{
			"broker.api.route":           parts[0],
			"broker.api.route_group":     parts[1],
			"broker.api.method":          parts[2],
			"broker.api.status_class":    parts[3],
			"broker.operation.outcome":   parts[4],
			"broker.api.duration_bucket": parts[5],
			"broker.api.mutating":        request.Mutating,
			"broker.operation.count":     counts[key],
		}))
	}
	return out
}

func telemetrySignal(kind string, name string, attrs map[string]any) telemetrySignalPreview {
	traceID := telemetryHash("trace:"+name, 32)
	spanID := telemetryHash("span:"+name, 16)
	return telemetrySignalPreview{
		Kind:          kind,
		Name:          name,
		TraceID:       traceID,
		SpanID:        spanID,
		Traceparent:   telemetryTraceparent(traceID, spanID),
		CorrelationID: "sl-" + telemetryHash("correlation:"+name, 16),
		Attributes:    sanitizeTelemetryAttributes(attrs),
	}
}

func telemetryTraceparent(traceID string, spanID string) string {
	if len(traceID) != 32 || len(spanID) != 16 {
		return ""
	}
	return "00-" + traceID + "-" + spanID + "-01"
}

func telemetryAPIIdentity(method string, routeTemplate string) telemetrySignalPreview {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	routeTemplate = strings.TrimSpace(routeTemplate)
	if routeTemplate == "" {
		routeTemplate = "/"
	}
	seed := method + ":" + routeTemplate
	traceID := telemetryHash("api-request-trace:"+seed, 32)
	spanID := telemetryHash("api-request-span:"+seed, 16)
	return telemetrySignalPreview{
		Kind:          "span",
		Name:          "secretsbroker.api.request",
		TraceID:       traceID,
		SpanID:        spanID,
		Traceparent:   telemetryTraceparent(traceID, spanID),
		CorrelationID: "sl-" + telemetryHash("api-request-correlation:"+seed, 16),
		Attributes: sanitizeTelemetryAttributes(map[string]any{
			"broker.operation":         "api_request",
			"broker.operation.outcome": "ready",
			"service.id":               serviceID,
			"service.api_version":      apiVersion,
		}),
	}
}

func applyTelemetryResponseHeaders(w http.ResponseWriter, r *http.Request) {
	method := "GET"
	path := "/"
	if r != nil {
		method = r.Method
		if r.URL != nil {
			path = r.URL.Path
		}
	}
	identity := telemetryAPIIdentity(method, path)
	w.Header().Set(telemetryCorrelationIDHeader, identity.CorrelationID)
	w.Header().Set(telemetryTraceIDHeader, identity.TraceID)
	w.Header().Set(telemetryTraceparentHeader, identity.Traceparent)
}

type telemetryStatusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *telemetryStatusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func recordTelemetryHTTPRequest(recorder *telemetryRequestRecorder, r *http.Request, statusCode int, duration time.Duration) {
	if recorder == nil || r == nil {
		return
	}
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		method = http.MethodGet
	}
	routeTemplate := telemetryRouteTemplate(r.URL.Path)
	recorder.record(telemetryRequestSummary{
		RouteTemplate: routeTemplate,
		RouteGroup:    telemetryRouteGroup(routeTemplate),
		Method:        method,
		StatusClass:   telemetryStatusClass(statusCode),
		Outcome:       telemetryRequestOutcome(statusCode),
		DurationMs:    max(0, int(duration.Milliseconds())),
		Mutating:      telemetryMutatingMethod(method),
	})
}

func telemetryRouteTemplate(path string) string {
	switch strings.TrimSpace(path) {
	case "/health":
		return "/health"
	case "/ready":
		return "/ready"
	case "/status":
		return "/status"
	case "/state":
		return "/state"
	case "/capabilities":
		return "/capabilities"
	case "/v1/secrets":
		return "/v1/secrets"
	case "/v1/writeback":
		return "/v1/writeback"
	case "/v1/resolve":
		return "/v1/resolve"
	case "/v1/provisioning/status":
		return "/v1/provisioning/status"
	case "/v1/provisioning/operations/plan":
		return "/v1/provisioning/operations/plan"
	case "/v1/provisioning/operations/apply":
		return "/v1/provisioning/operations/apply"
	case "/v1/sources/status":
		return "/v1/sources/status"
	case "/v1/providers/capabilities":
		return "/v1/providers/capabilities"
	case "/v1/providers/config/status":
		return "/v1/providers/config/status"
	case "/v1/providers/config/validate":
		return "/v1/providers/config/validate"
	case "/v1/providers/config/apply":
		return "/v1/providers/config/apply"
	case "/v1/providers/migration/dry-run":
		return "/v1/providers/migration/dry-run"
	case "/v1/providers/migration/apply":
		return "/v1/providers/migration/apply"
	case "/v1/telemetry":
		return "/v1/telemetry"
	case "/v1/telemetry/export":
		return "/v1/telemetry/export"
	case "/v1/events":
		return "/v1/events"
	case "/v1/recovery/policy":
		return "/v1/recovery/policy"
	case "/v1/management/lockouts/clear":
		return "/v1/management/lockouts/clear"
	case "/v1/management/secrets":
		return "/v1/management/secrets"
	case "/v1/management/secrets/value-search":
		return "/v1/management/secrets/value-search"
	case "/v1/management/secrets/reveal":
		return "/v1/management/secrets/reveal"
	case "/v1/management/secrets/edit/dry-run":
		return "/v1/management/secrets/edit/dry-run"
	case "/v1/management/secrets/edit/apply":
		return "/v1/management/secrets/edit/apply"
	case "/v1/management/secrets/reset/dry-run":
		return "/v1/management/secrets/reset/dry-run"
	case "/v1/management/secrets/reset/apply":
		return "/v1/management/secrets/reset/apply"
	case "/v1/management/secrets/rotation/dry-run":
		return "/v1/management/secrets/rotation/dry-run"
	case "/v1/management/secrets/campaigns/create":
		return "/v1/management/secrets/campaigns/create"
	case "/v1/management/secrets/campaigns/revalidate":
		return "/v1/management/secrets/campaigns/revalidate"
	case "/v1/management/secrets/campaigns/apply":
		return "/v1/management/secrets/campaigns/apply"
	case "/v1/management/secrets/campaigns/status":
		return "/v1/management/secrets/campaigns/status"
	case "/v1/management/secrets/sync/dry-run":
		return "/v1/management/secrets/sync/dry-run"
	case "/v1/management/secrets/policy/preview":
		return "/v1/management/secrets/policy/preview"
	case "/v1/management/secrets/policy/apply":
		return "/v1/management/secrets/policy/apply"
	default:
		return "/unmatched"
	}
}

func telemetryRouteGroup(routeTemplate string) string {
	trimmed := strings.Trim(routeTemplate, "/")
	if trimmed == "" {
		return "root"
	}
	parts := strings.Split(trimmed, "/")
	if parts[0] == "v1" && len(parts) > 1 {
		return parts[1]
	}
	return parts[0]
}

func telemetryStatusClass(statusCode int) string {
	if statusCode < 100 {
		return "unknown"
	}
	return fmt.Sprintf("%dxx", statusCode/100)
}

func telemetryRequestOutcome(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "ready"
	case statusCode >= 300 && statusCode < 400:
		return "redirect"
	case statusCode >= 400 && statusCode < 500:
		return "client_error"
	case statusCode >= 500:
		return "server_error"
	default:
		return "unknown"
	}
}

func telemetryMutatingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func telemetryDurationBucket(durationMs int) string {
	switch {
	case durationMs < 50:
		return "lt_50ms"
	case durationMs < 250:
		return "50_249ms"
	case durationMs < 1000:
		return "250_999ms"
	default:
		return "1s_plus"
	}
}

func telemetryHash(value string, length int) string {
	sum := sha256.Sum256([]byte("service-lasso:secretsbroker:telemetry:" + value))
	hexValue := hex.EncodeToString(sum[:])
	if length > len(hexValue) {
		return hexValue
	}
	return hexValue[:length]
}

func sanitizeTelemetryAttributes(attrs map[string]any) map[string]any {
	policy := secretsBrokerTelemetryAttributePolicy()
	allowed := map[string]bool{}
	for _, key := range policy.AllowedAttributes {
		allowed[key] = true
	}
	clean := map[string]any{}
	for key, value := range attrs {
		if !allowed[key] {
			continue
		}
		switch typed := value.(type) {
		case string:
			clean[key] = redactTelemetryString(typed)
		case int, int64, float64, bool:
			clean[key] = typed
		default:
			clean[key] = redactTelemetryString(toTelemetryString(typed))
		}
	}
	return clean
}

func toTelemetryString(value any) string {
	if value == nil {
		return ""
	}
	clean := strings.ToValidUTF8(fmt.Sprint(value), "")
	clean = strings.ReplaceAll(clean, "\x00", "")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\r", " ")
	return strings.TrimSpace(clean)
}

func redactTelemetryString(value string) string {
	redacted := strings.TrimSpace(value)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/-]{12,}`),
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`https?://[^\s/:]+:[^\s/@]{6,}@`),
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
		regexp.MustCompile(`SERVICE_LASSO_FAKE_[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z0-9_]*_DO_NOT_USE`),
		regexp.MustCompile(`(?i)\b(api[_-]?key|auth|authorization|bearer|cookie|credential|env|password|private[_-]?key|secret|token)\b\s*[:=]\s*("[^"]+"|'[^']+'|[^\s,;]+)`),
	}
	for _, pattern := range patterns {
		redacted = pattern.ReplaceAllString(redacted, "[REDACTED]")
	}
	return redacted
}
