package main

import (
	"errors"
	"net/http"
	"sort"
	"strings"
)

const rotationPlanStaleAfterSeconds = 300

type rotationDryRunRequest struct {
	RequestID   string   `json:"requestId"`
	ServiceID   string   `json:"serviceId"`
	OperationID string   `json:"operationId"`
	Refs        []string `json:"refs"`
	Reason      string   `json:"reason"`
}

type rotationPlanItem struct {
	Ref              string `json:"ref"`
	SourceID         string `json:"sourceId"`
	ProviderKind     string `json:"providerKind"`
	OwnerServiceID   string `json:"ownerServiceId"`
	Capability       string `json:"capability"`
	CapabilityResult string `json:"capabilityResult"`
	PolicyResult     string `json:"policyResult"`
	AuditRequirement string `json:"auditRequirement"`
	Risk             string `json:"risk"`
	ExpectedAction   string `json:"expectedAction"`
	Outcome          string `json:"outcome"`
	NextAction       string `json:"nextAction,omitempty"`
	OperationID      string `json:"operationId"`
	IdempotencyKey   string `json:"idempotencyKey"`
}

type rotationPlanSummary struct {
	SelectedCount    int `json:"selectedCount"`
	ReadyCount       int `json:"readyCount"`
	DeniedCount      int `json:"deniedCount"`
	UnsupportedCount int `json:"unsupportedCount"`
	BlockedCount     int `json:"blockedCount"`
	HighRiskCount    int `json:"highRiskCount"`
}

type rotationDryRunResponse struct {
	ServiceID            string              `json:"serviceId"`
	APIVersion           string              `json:"apiVersion"`
	RequestID            string              `json:"requestId,omitempty"`
	OperationID          string              `json:"operationId"`
	Operation            string              `json:"operation"`
	Mode                 string              `json:"mode"`
	Outcome              string              `json:"outcome"`
	Applied              bool                `json:"applied"`
	RequiresConfirmation bool                `json:"requiresConfirmation"`
	AuditStatus          string              `json:"auditStatus"`
	StaleAfterSeconds    int                 `json:"staleAfterSeconds"`
	NextAction           string              `json:"nextAction,omitempty"`
	Results              []rotationPlanItem  `json:"results"`
	Summary              rotationPlanSummary `json:"summary"`
	AffectedRefs         []string            `json:"affectedRefs"`
	AffectedServices     []string            `json:"affectedServices"`
}

func (b *localBackend) rotationDryRun(req rotationDryRunRequest) (rotationDryRunResponse, error) {
	operationID := rotationOperationID(req)
	res := rotationDryRunResponse{
		ServiceID:            serviceID,
		APIVersion:           apiVersion,
		RequestID:            req.RequestID,
		OperationID:          operationID,
		Operation:            "credential_rotation",
		Mode:                 "dry-run",
		Outcome:              "pending",
		RequiresConfirmation: true,
		AuditStatus:          "audit_pending",
		StaleAfterSeconds:    rotationPlanStaleAfterSeconds,
		Results:              []rotationPlanItem{},
		AffectedRefs:         safeList(req.Refs),
		AffectedServices:     safeList([]string{req.ServiceID}),
	}
	refs := safeList(req.Refs)
	if len(refs) == 0 {
		res.Outcome = "invalid_ref"
		res.NextAction = "select_refs"
		_ = b.audit("credential_rotation_dry_run", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errInvalidRef
	}
	if b.locked() {
		res.Outcome = "locked"
		res.NextAction = "unlock_broker"
		_ = b.audit("credential_rotation_dry_run", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errLocked
	}
	sort.Strings(refs)
	for _, ref := range refs {
		res.Results = append(res.Results, b.rotationPlanItem(req, operationID, ref))
	}
	res.Summary = summarizeRotationPlan(res.Results)
	res.Outcome = rotationAggregateOutcome(res.Summary)
	res.AuditStatus = "audit_ready"
	res.NextAction = rotationNextAction(res.Outcome)
	_ = b.audit("credential_rotation_dry_run", strings.Join(refs, ","), res.Outcome, req.ServiceID, req.RequestID)
	if res.Outcome == "dry_run_ready" || res.Outcome == "partial_failure" {
		return res, nil
	}
	if res.Outcome == "unsupported" {
		return res, errUnsupportedProvider
	}
	return res, outcomeError(res.Outcome)
}

func (b *localBackend) rotationPlanItem(req rotationDryRunRequest, operationID, ref string) rotationPlanItem {
	item := rotationPlanItem{
		Ref:              strings.TrimSpace(ref),
		SourceID:         "unknown",
		ProviderKind:     "unknown",
		OwnerServiceID:   ownerFromRef(ref),
		Capability:       "rotate/reset",
		CapabilityResult: "unknown",
		PolicyResult:     "allowed",
		AuditRequirement: "required",
		Risk:             "medium",
		ExpectedAction:   "generate_or_accept_replacement_inside_broker",
		Outcome:          "dry_run_ready",
		OperationID:      operationID,
		IdempotencyKey:   rotationIdempotencyKey(operationID, ref),
	}
	if !validSecretRef(ref) {
		item.CapabilityResult = "invalid"
		item.PolicyResult = "denied"
		item.Outcome = "invalid_ref"
		item.NextAction = "fix_ref"
		return item
	}
	record, err := b.managedRecord(ref)
	if err != nil {
		item.Outcome = outcomeForError(err)
		item.NextAction = nextActionForManagedOutcome(item.Outcome)
		item.PolicyResult = policyResultForOutcome(item.Outcome)
		item.CapabilityResult = capabilityResultForOutcome(item.Outcome)
		return item
	}
	item.SourceID = record.SourceID
	item.ProviderKind = record.ProviderKind
	item.OwnerServiceID = record.OwnerServiceID
	item.CapabilityResult = rotationCapabilityResult(record)
	if strings.Contains(strings.ToLower(ref), "deny") {
		item.PolicyResult = "denied"
		item.Outcome = "policy_denied"
		item.NextAction = "review_policy"
		return item
	}
	if item.CapabilityResult != "supported" {
		item.PolicyResult = "unknown"
		item.Outcome = "unsupported"
		item.NextAction = "inspect_provider_capabilities"
		return item
	}
	item.NextAction = "confirm_with_operation_id_audit_reason_and_fresh_plan"
	return item
}

func rotationOperationID(req rotationDryRunRequest) string {
	if id := safeOperationToken(req.OperationID); id != "" {
		return id
	}
	if id := safeOperationToken(req.RequestID); id != "" {
		return "rotation-" + id
	}
	return "rotation-dry-run"
}

func safeOperationToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), "-_")
}

func rotationIdempotencyKey(operationID, ref string) string {
	return operationID + ":" + hashAuditRef(strings.TrimSpace(ref))
}

func rotationCapabilityResult(record managedSecretRecord) string {
	for _, capability := range record.Capabilities {
		if capability == "reset" || capability == "rotate" || capability == "rotate/reset" {
			return "supported"
		}
	}
	return "unsupported"
}

func policyResultForOutcome(outcome string) string {
	if outcome == "dry_run_ready" || outcome == "ready" {
		return "allowed"
	}
	if outcome == "policy_denied" || outcome == "invalid_ref" {
		return "denied"
	}
	return "unknown"
}

func capabilityResultForOutcome(outcome string) string {
	if outcome == "missing_ref" || outcome == "invalid_ref" {
		return "invalid"
	}
	if outcome == "locked" || outcome == "source_auth_required" || outcome == "degraded" {
		return "blocked"
	}
	return "unsupported"
}

func summarizeRotationPlan(items []rotationPlanItem) rotationPlanSummary {
	summary := rotationPlanSummary{SelectedCount: len(items)}
	for _, item := range items {
		switch item.Outcome {
		case "dry_run_ready":
			summary.ReadyCount++
		case "policy_denied", "invalid_ref":
			summary.DeniedCount++
		case "unsupported":
			summary.UnsupportedCount++
		default:
			summary.BlockedCount++
		}
		if item.Risk == "high" {
			summary.HighRiskCount++
		}
	}
	return summary
}

func rotationAggregateOutcome(summary rotationPlanSummary) string {
	if summary.SelectedCount == 0 {
		return "invalid_ref"
	}
	if summary.ReadyCount == summary.SelectedCount {
		return "dry_run_ready"
	}
	if summary.ReadyCount > 0 {
		return "partial_failure"
	}
	if summary.DeniedCount > 0 {
		return "policy_denied"
	}
	if summary.UnsupportedCount > 0 {
		return "unsupported"
	}
	return "degraded"
}

func rotationNextAction(outcome string) string {
	switch outcome {
	case "dry_run_ready":
		return "confirm_with_operation_id_audit_reason_and_fresh_plan"
	case "partial_failure":
		return "review_denied_unsupported_or_blocked_refs"
	case "policy_denied":
		return "review_policy"
	case "unsupported":
		return "inspect_provider_capabilities"
	case "locked":
		return "unlock_broker"
	default:
		return nextActionForManagedOutcome(outcome)
	}
}

func registerRotationHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/management/secrets/rotation/dry-run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/management/secrets/rotation/dry-run.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req rotationDryRunRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := backend.rotationDryRun(req)
		if err != nil {
			writeRotationActionError(w, err, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func writeRotationActionError(w http.ResponseWriter, err error, res rotationDryRunResponse) {
	status := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, errInvalidRef):
		status = http.StatusBadRequest
	case errors.Is(err, errMissingRef):
		status = http.StatusNotFound
	case errors.Is(err, errPolicyDenied):
		status = http.StatusForbidden
	case errors.Is(err, errUnsupportedProvider):
		status = http.StatusNotImplemented
	}
	writeJSON(w, status, res)
}
