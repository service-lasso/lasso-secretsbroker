package main

import (
	"errors"
	"net/http"
	"sort"
	"time"
)

type telemetryResponse struct {
	ServiceID          string                       `json:"serviceId"`
	APIVersion         string                       `json:"apiVersion"`
	Outcome            string                       `json:"outcome"`
	GeneratedAt        time.Time                    `json:"generatedAt"`
	Counters           telemetryCounters            `json:"counters"`
	DurationHistograms []telemetryDurationHistogram `json:"durationHistograms"`
	Safety             telemetrySafety              `json:"safety"`
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

type telemetrySafety struct {
	LowCardinalityLabels  bool `json:"lowCardinalityLabels"`
	ValueMaterialIncluded bool `json:"valueMaterialIncluded"`
}

func buildTelemetryResponse(backend *localBackend) (telemetryResponse, error) {
	res := telemetryResponse{
		ServiceID:          serviceID,
		APIVersion:         apiVersion,
		Outcome:            "ready",
		GeneratedAt:        time.Now().UTC(),
		DurationHistograms: []telemetryDurationHistogram{},
		Safety:             telemetrySafety{LowCardinalityLabels: true, ValueMaterialIncluded: false},
	}
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
