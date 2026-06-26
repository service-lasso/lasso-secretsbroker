package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const secretsBrokerTelemetryContractVersion = "service-lasso.secretsbroker.telemetry-preview.v1"

type telemetryResponse struct {
	ContractVersion    string                       `json:"contractVersion"`
	ServiceID          string                       `json:"serviceId"`
	APIVersion         string                       `json:"apiVersion"`
	Outcome            string                       `json:"outcome"`
	GeneratedAt        time.Time                    `json:"generatedAt"`
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

type telemetrySignalPreview struct {
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	TraceID       string         `json:"traceId"`
	SpanID        string         `json:"spanId"`
	CorrelationID string         `json:"correlationId"`
	Attributes    map[string]any `json:"attributes"`
}

type telemetrySafety struct {
	LowCardinalityLabels  bool `json:"lowCardinalityLabels"`
	ValueMaterialIncluded bool `json:"valueMaterialIncluded"`
}

func buildTelemetryResponse(backend *localBackend) (telemetryResponse, error) {
	res := telemetryResponse{
		ContractVersion:    secretsBrokerTelemetryContractVersion,
		ServiceID:          serviceID,
		APIVersion:         apiVersion,
		Outcome:            "ready",
		GeneratedAt:        time.Now().UTC(),
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
	res.Counters.ActiveLockouts = 0
	res.Counters.AuditRecords = auditRecordCounters(audit.Events)
	res.Counters.SourceStates = sourceStateCounters(defaultSourceRegistry(backend).Sources)
	res.Counters.ProviderStates = providerStateCounters(backend.providerConfigStatusResponse().Providers)
	res.Signals = buildTelemetrySignals(res.Counters)
	res.ExportPreview = telemetryExportPreviewFromEnv(res.Exporter, len(res.Signals), res.Redaction)
	return res, nil
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
}

func auditOperationCounters(events []auditEvent) []telemetryOperationCounter {
	counts := map[string]int{}
	for _, event := range events {
		event = normalizeAuditEvent(event)
		counts[event.Operation+"\x00"+event.Outcome]++
	}
	keys := sortedKeys(counts)
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
	keys := sortedKeys(counts)
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
			"broker.lockout.active_count",
			"broker.operation",
			"broker.operation.count",
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
	if exporter.Status == "configured" && strings.EqualFold(strings.TrimSpace(os.Getenv("SECRETSBROKER_OTEL_EXPORT_MODE")), "dry-run") {
		mode = "dry_run"
		reason = "Dry-run OTLP export envelope is ready; the broker does not send telemetry from this preview API."
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
		SafeEnvelopeFields:    []string{"resource", "signals.kind", "signals.name", "signals.traceId", "signals.spanId", "signals.correlationId", "signals.attributes"},
		Reason:                reason,
	}
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

func telemetrySignal(kind string, name string, attrs map[string]any) telemetrySignalPreview {
	return telemetrySignalPreview{
		Kind:          kind,
		Name:          name,
		TraceID:       telemetryHash("trace:"+name, 32),
		SpanID:        telemetryHash("span:"+name, 16),
		CorrelationID: "sl-" + telemetryHash("correlation:"+name, 16),
		Attributes:    sanitizeTelemetryAttributes(attrs),
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
