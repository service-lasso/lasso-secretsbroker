package main

import (
	"errors"
	"net/http"
	"sort"
	"strings"
)

const syncDryRunStaleAfterSeconds = 300

type syncDryRunRequest struct {
	RequestID       string                `json:"requestId"`
	ServiceID       string                `json:"serviceId"`
	OperationID     string                `json:"operationId"`
	Refs            []string              `json:"refs"`
	DestinationID   string                `json:"destinationId"`
	Destination     syncDestinationConfig `json:"destination,omitempty"`
	Reason          string                `json:"reason"`
	Secrets         *serviceSecretsPolicy `json:"secrets,omitempty"`
	CredentialValue string                `json:"credentialValue,omitempty"`
	DriftState      string                `json:"driftState,omitempty"`
	CollisionState  string                `json:"collisionState,omitempty"`
}

type syncDestinationConfig struct {
	DestinationID   string               `json:"destinationId"`
	Kind            string               `json:"kind"`
	DisplayName     string               `json:"displayName,omitempty"`
	Enabled         bool                 `json:"enabled"`
	Scope           syncDestinationScope `json:"scope"`
	CredentialRef   string               `json:"credentialRef,omitempty"`
	AuthModel       string               `json:"authModel,omitempty"`
	NameTemplate    string               `json:"nameTemplate,omitempty"`
	Granularity     string               `json:"granularity,omitempty"`
	CollisionPolicy string               `json:"collisionPolicy,omitempty"`
	DeletePolicy    string               `json:"deletePolicy,omitempty"`
	State           string               `json:"state,omitempty"`
	Outcome         string               `json:"outcome,omitempty"`
	AuditStatus     string               `json:"auditStatus,omitempty"`
}

type syncDestinationScope struct {
	Owner                string   `json:"owner,omitempty"`
	Repository           string   `json:"repository,omitempty"`
	Environment          string   `json:"environment,omitempty"`
	SecretsLocation      string   `json:"secretsLocation,omitempty"`
	Visibility           string   `json:"visibility,omitempty"`
	SelectedRepositories []string `json:"selectedRepositories,omitempty"`
	EnterpriseURL        string   `json:"enterpriseUrl,omitempty"`
}

type syncDryRunItem struct {
	Ref                string `json:"ref"`
	RefHash            string `json:"refHash"`
	SourceID           string `json:"sourceId"`
	ProviderKind       string `json:"providerKind"`
	OwnerServiceID     string `json:"ownerServiceId"`
	DestinationName    string `json:"destinationName"`
	Capability         string `json:"capability"`
	CapabilityResult   string `json:"capabilityResult"`
	PolicyResult       string `json:"policyResult"`
	AuditRequirement   string `json:"auditRequirement"`
	Risk               string `json:"risk"`
	DriftState         string `json:"driftState"`
	DeleteBehavior     string `json:"deleteBehavior"`
	ExpectedAction     string `json:"expectedAction"`
	Outcome            string `json:"outcome"`
	NextAction         string `json:"nextAction"`
	IdempotencyKey     string `json:"idempotencyKey"`
	DestinationScope   string `json:"destinationScope,omitempty"`
	DestinationOutcome string `json:"destinationOutcome,omitempty"`
}

type syncDryRunSummary struct {
	SelectedCount           int `json:"selectedCount"`
	ReadyCount              int `json:"readyCount"`
	DeniedCount             int `json:"deniedCount"`
	UnsupportedCount        int `json:"unsupportedCount"`
	BlockedCount            int `json:"blockedCount"`
	HighRiskCount           int `json:"highRiskCount"`
	DriftUnknownCount       int `json:"driftUnknownCount"`
	AuthRequiredCount       int `json:"authRequiredCount"`
	AuditUnavailableCount   int `json:"auditUnavailableCount"`
	UnmanagedCollisionCount int `json:"unmanagedCollisionCount"`
}

type syncDryRunResponse struct {
	ServiceID            string                `json:"serviceId"`
	APIVersion           string                `json:"apiVersion"`
	RequestID            string                `json:"requestId,omitempty"`
	OperationID          string                `json:"operationId"`
	Operation            string                `json:"operation"`
	Mode                 string                `json:"mode"`
	Outcome              string                `json:"outcome"`
	Applied              bool                  `json:"applied"`
	RequiresConfirmation bool                  `json:"requiresConfirmation"`
	AuditStatus          string                `json:"auditStatus"`
	StaleAfterSeconds    int                   `json:"staleAfterSeconds"`
	NextAction           string                `json:"nextAction"`
	Destination          syncDestinationConfig `json:"destination"`
	Results              []syncDryRunItem      `json:"results"`
	Summary              syncDryRunSummary     `json:"summary"`
	AffectedRefs         []string              `json:"affectedRefs"`
	AffectedServices     []string              `json:"affectedServices"`
}

func (b *localBackend) syncDryRun(req syncDryRunRequest) (syncDryRunResponse, error) {
	req.Refs = safeList(req.Refs)
	dest := normalizeSyncDestination(req)
	res := syncDryRunResponse{
		ServiceID:            serviceID,
		APIVersion:           apiVersion,
		RequestID:            req.RequestID,
		OperationID:          firstNonEmpty(safeOperationToken(req.OperationID), "sync-plan-"+hashAuditRef(strings.Join(req.Refs, ","))),
		Operation:            "secrets_sync",
		Mode:                 "dry-run",
		Outcome:              "pending",
		Applied:              false,
		RequiresConfirmation: true,
		AuditStatus:          "audit_ready",
		StaleAfterSeconds:    syncDryRunStaleAfterSeconds,
		NextAction:           "confirm_with_operation_id_audit_reason_and_fresh_plan",
		Destination:          dest,
		Results:              []syncDryRunItem{},
		AffectedRefs:         req.Refs,
		AffectedServices:     safeList([]string{req.ServiceID}),
	}
	if len(req.Refs) == 0 {
		res.Outcome = "invalid_ref"
		res.NextAction = "select_refs"
		_ = b.audit("secrets_sync_dry_run", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errInvalidRef
	}
	if b.locked() {
		res.Outcome = "locked"
		res.NextAction = "unlock_broker"
		_ = b.audit("secrets_sync_dry_run", strings.Join(req.Refs, ","), res.Outcome, req.ServiceID, req.RequestID)
		return res, errLocked
	}
	refs := append([]string(nil), req.Refs...)
	sort.Strings(refs)
	for _, ref := range refs {
		res.Results = append(res.Results, b.syncDryRunItem(req, dest, res.OperationID, ref))
	}
	res.Summary = summarizeSyncDryRun(res.Results)
	res.Outcome = syncDryRunAggregateOutcome(res.Summary)
	res.NextAction = syncDryRunNextAction(res.Outcome)
	_ = b.audit("secrets_sync_dry_run", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID)
	if res.Outcome == "dry_run_ready" || res.Outcome == "partial_failure" {
		return res, nil
	}
	return res, syncDryRunError(res.Outcome)
}

func (b *localBackend) syncDryRunItem(req syncDryRunRequest, dest syncDestinationConfig, operationID, ref string) syncDryRunItem {
	item := syncDryRunItem{
		Ref:                strings.TrimSpace(ref),
		RefHash:            hashAuditRef(strings.TrimSpace(ref)),
		SourceID:           "unknown",
		ProviderKind:       "unknown",
		OwnerServiceID:     ownerFromRef(ref),
		DestinationName:    syncDestinationName(dest.NameTemplate, ref),
		Capability:         "sync/write",
		CapabilityResult:   "supported",
		PolicyResult:       "allowed",
		AuditRequirement:   "required",
		Risk:               "high",
		DriftState:         firstNonEmpty(normalizeSyncDrift(req.DriftState), "unknown"),
		DeleteBehavior:     firstNonEmpty(dest.DeletePolicy, "delete_managed_destination_secret"),
		ExpectedAction:     "encrypt_and_create_or_update_github_actions_secret",
		Outcome:            "dry_run_ready",
		NextAction:         "confirm_with_operation_id_audit_reason_and_fresh_plan",
		IdempotencyKey:     syncIdempotencyKey(operationID, ref),
		DestinationScope:   syncDestinationScopeLabel(dest.Scope),
		DestinationOutcome: firstNonEmpty(dest.Outcome, "ready"),
	}
	if !validSecretRef(ref) {
		item.Outcome = "invalid_ref"
		item.PolicyResult = "denied"
		item.CapabilityResult = "invalid"
		item.NextAction = "fix_ref"
		return item
	}
	record, err := b.managedRecord(ref)
	if err != nil {
		item.Outcome = outcomeForError(err)
		item.PolicyResult = policyResultForOutcome(item.Outcome)
		item.CapabilityResult = capabilityResultForOutcome(item.Outcome)
		item.NextAction = syncNextActionForOutcome(item.Outcome)
		return item
	}
	item.SourceID = record.SourceID
	item.ProviderKind = record.ProviderKind
	item.OwnerServiceID = record.OwnerServiceID
	if !syncSourceCapabilitySupported(record) {
		item.Outcome = "unsupported"
		item.CapabilityResult = "unsupported"
		item.PolicyResult = "unknown"
		item.NextAction = "inspect_source_capabilities"
		return item
	}
	if decision := evaluateSyncPolicy(req, ref); decision.Outcome != "allowed" {
		item.Outcome = "policy_denied"
		item.PolicyResult = decision.Outcome
		item.NextAction = decision.NextAction
		return item
	}
	if strings.TrimSpace(req.CredentialValue) != "" {
		item.Outcome = "policy_denied"
		item.PolicyResult = "denied"
		item.NextAction = "replace_plaintext_destination_credential_with_credential_ref"
		return item
	}
	if dest.Kind != "github-actions" {
		item.Outcome = "unsupported"
		item.CapabilityResult = "unsupported"
		item.PolicyResult = "unknown"
		item.NextAction = "select_supported_destination_kind"
		return item
	}
	if !dest.Enabled || dest.State != "configured" || strings.TrimSpace(dest.CredentialRef) == "" {
		item.Outcome = "destination_auth_required"
		item.CapabilityResult = "blocked"
		item.PolicyResult = "unknown"
		item.NextAction = "configure_destination_credential_ref"
		return item
	}
	if dest.AuditStatus == "audit_unavailable" {
		item.Outcome = "audit_unavailable"
		item.CapabilityResult = "blocked"
		item.PolicyResult = "unknown"
		item.NextAction = "restore_audit_before_sync"
		return item
	}
	if strings.TrimSpace(req.CollisionState) == "unmanaged_collision" {
		item.Outcome = "unmanaged_collision"
		item.CapabilityResult = "blocked"
		item.NextAction = "review_destination_secret_ownership"
		return item
	}
	return item
}

func normalizeSyncDestination(req syncDryRunRequest) syncDestinationConfig {
	dest := req.Destination
	dest.DestinationID = firstNonEmpty(dest.DestinationID, req.DestinationID)
	dest.Kind = firstNonEmpty(strings.TrimSpace(dest.Kind), "github-actions")
	dest.DisplayName = firstNonEmpty(dest.DisplayName, dest.DestinationID)
	dest.AuthModel = firstNonEmpty(dest.AuthModel, "github-app")
	dest.NameTemplate = firstNonEmpty(dest.NameTemplate, "SERVICE_LASSO_{{ refBase | upper }}")
	dest.Granularity = firstNonEmpty(dest.Granularity, "secret-ref")
	dest.CollisionPolicy = firstNonEmpty(dest.CollisionPolicy, "fail_if_unmanaged")
	dest.DeletePolicy = firstNonEmpty(dest.DeletePolicy, "delete_managed_destination_secret")
	dest.State = firstNonEmpty(dest.State, "configured")
	dest.Outcome = firstNonEmpty(dest.Outcome, "ready")
	dest.AuditStatus = firstNonEmpty(dest.AuditStatus, "audit_available")
	if strings.TrimSpace(dest.DestinationID) != "" && !dest.Enabled {
		dest.Enabled = true
	}
	dest.Scope.SelectedRepositories = safeList(dest.Scope.SelectedRepositories)
	return dest
}

func evaluateSyncPolicy(req syncDryRunRequest, ref string) secretPolicyDecision {
	if strings.Contains(strings.ToLower(ref), "deny") {
		return secretPolicyDecision{ServiceID: req.ServiceID, Operation: "manage", Ref: ref, Outcome: "denied", NextAction: "review_policy", ReasonCode: "policy_name_denied"}
	}
	return evaluateServiceSecretsPolicy(req.ServiceID, "manage", ref, req.Secrets)
}

func syncSourceCapabilitySupported(record managedSecretRecord) bool {
	for _, capability := range record.Capabilities {
		switch capability {
		case "reveal", "read", "metadata":
			return true
		}
	}
	return false
}

func syncDestinationName(template, ref string) string {
	base := refName(ref)
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 32
		}
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, base)
	safe = strings.Trim(safe, "_")
	if safe == "" {
		safe = "SECRET"
	}
	template = firstNonEmpty(template, "SERVICE_LASSO_{{ refBase | upper }}")
	return strings.ReplaceAll(template, "{{ refBase | upper }}", safe)
}

func syncDestinationScopeLabel(scope syncDestinationScope) string {
	switch strings.TrimSpace(scope.SecretsLocation) {
	case "environment":
		return strings.Join(safeList([]string{"environment", scope.Owner, scope.Repository, scope.Environment}), "/")
	case "organization":
		return strings.Join(safeList([]string{"organization", scope.Owner, scope.Visibility}), "/")
	default:
		return strings.Join(safeList([]string{"repository", scope.Owner, scope.Repository}), "/")
	}
}

func syncIdempotencyKey(operationID, ref string) string {
	return strings.Join([]string{safeOperationToken(operationID), hashAuditRef(strings.TrimSpace(ref))}, ":")
}

func normalizeSyncDrift(value string) string {
	switch strings.TrimSpace(value) {
	case "not_checked", "unknown", "missing", "managed_current", "managed_stale", "destination_changed_metadata", "unmanaged_collision":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func summarizeSyncDryRun(items []syncDryRunItem) syncDryRunSummary {
	summary := syncDryRunSummary{SelectedCount: len(items)}
	for _, item := range items {
		switch item.Outcome {
		case "dry_run_ready":
			summary.ReadyCount++
		case "policy_denied", "invalid_ref":
			summary.DeniedCount++
		case "unsupported":
			summary.UnsupportedCount++
		case "destination_auth_required", "source_auth_required":
			summary.AuthRequiredCount++
			summary.BlockedCount++
		case "audit_unavailable":
			summary.AuditUnavailableCount++
			summary.BlockedCount++
		case "unmanaged_collision":
			summary.UnmanagedCollisionCount++
			summary.BlockedCount++
		default:
			summary.BlockedCount++
		}
		if item.Risk == "high" {
			summary.HighRiskCount++
		}
		if item.DriftState == "unknown" {
			summary.DriftUnknownCount++
		}
	}
	return summary
}

func syncDryRunAggregateOutcome(summary syncDryRunSummary) string {
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
	if summary.AuthRequiredCount > 0 {
		return "destination_auth_required"
	}
	if summary.AuditUnavailableCount > 0 {
		return "audit_unavailable"
	}
	if summary.UnmanagedCollisionCount > 0 {
		return "unmanaged_collision"
	}
	return "degraded"
}

func syncDryRunNextAction(outcome string) string {
	switch outcome {
	case "dry_run_ready":
		return "confirm_with_operation_id_audit_reason_and_fresh_plan"
	case "partial_failure":
		return "review_denied_unsupported_or_blocked_items"
	case "destination_auth_required":
		return "configure_destination_credential_ref"
	case "audit_unavailable":
		return "restore_audit_before_sync"
	case "unmanaged_collision":
		return "review_destination_secret_ownership"
	case "unsupported":
		return "select_supported_destination_kind"
	default:
		return syncNextActionForOutcome(outcome)
	}
}

func syncNextActionForOutcome(outcome string) string {
	switch outcome {
	case "destination_auth_required":
		return "configure_destination_credential_ref"
	case "destination_unavailable":
		return "inspect_destination_status"
	case "audit_unavailable":
		return "restore_audit_before_sync"
	case "unsupported":
		return "select_supported_destination_kind"
	case "unmanaged_collision":
		return "review_destination_secret_ownership"
	default:
		return nextActionForManagedOutcome(outcome)
	}
}

func syncDryRunError(outcome string) error {
	switch outcome {
	case "invalid_ref":
		return errInvalidRef
	case "locked":
		return errLocked
	case "policy_denied":
		return errPolicyDenied
	case "unsupported":
		return errUnsupportedProvider
	case "destination_auth_required", "source_auth_required":
		return errSourceAuthRequired
	default:
		return errBackendDegraded
	}
}

func registerSyncDryRunHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/management/secrets/sync/dry-run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/management/secrets/sync/dry-run.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req syncDryRunRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := backend.syncDryRun(req)
		if err != nil {
			writeSyncDryRunError(w, err, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func writeSyncDryRunError(w http.ResponseWriter, err error, res syncDryRunResponse) {
	status := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, errInvalidRef):
		status = http.StatusBadRequest
	case errors.Is(err, errPolicyDenied):
		status = http.StatusForbidden
	case errors.Is(err, errSourceAuthRequired):
		status = http.StatusFailedDependency
	case errors.Is(err, errUnsupportedProvider):
		status = http.StatusNotImplemented
	}
	writeJSON(w, status, res)
}
