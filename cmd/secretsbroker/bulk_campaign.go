package main

import (
	"errors"
	"net/http"
	"sort"
	"strings"
)

const bulkCampaignStaleAfterSeconds = 300

type bulkCampaignRequest struct {
	RequestID        string   `json:"requestId"`
	ServiceID        string   `json:"serviceId"`
	CampaignID       string   `json:"campaignId"`
	PlanToken        string   `json:"planToken"`
	OperationID      string   `json:"operationId"`
	Operation        string   `json:"operation"`
	Refs             []string `json:"refs"`
	TargetProviderID string   `json:"targetProviderId,omitempty"`
	TargetPolicy     string   `json:"targetPolicy,omitempty"`
	Reason           string   `json:"reason"`
	Confirm          bool     `json:"confirm"`
	HighRiskConfirm  string   `json:"highRiskConfirm,omitempty"`
}

type bulkCampaignItem struct {
	Ref              string `json:"ref"`
	SourceID         string `json:"sourceId"`
	ProviderKind     string `json:"providerKind"`
	OwnerServiceID   string `json:"ownerServiceId"`
	Operation        string `json:"operation"`
	CapabilityResult string `json:"capabilityResult"`
	PolicyResult     string `json:"policyResult"`
	AuditRequirement string `json:"auditRequirement"`
	Risk             string `json:"risk"`
	ExpectedAction   string `json:"expectedAction"`
	Outcome          string `json:"outcome"`
	NextAction       string `json:"nextAction,omitempty"`
	IdempotencyKey   string `json:"idempotencyKey"`
	OperationItemID  string `json:"operationItemId"`
	Recovery         string `json:"recovery,omitempty"`
	TargetProviderID string `json:"targetProviderId,omitempty"`
	TargetPolicy     string `json:"targetPolicy,omitempty"`
	ProviderAction   string `json:"providerAction,omitempty"`
	Applied          bool   `json:"applied"`
	RetrySafe        bool   `json:"retrySafe"`
}

type bulkCampaignSummary struct {
	SelectedCount     int `json:"selectedCount"`
	ApplicableCount   int `json:"applicableCount"`
	DeniedCount       int `json:"deniedCount"`
	UnsupportedCount  int `json:"unsupportedCount"`
	AuthRequiredCount int `json:"authRequiredCount"`
	SkippedCount      int `json:"skippedCount"`
	AppliedCount      int `json:"appliedCount"`
	FailedCount       int `json:"failedCount"`
	StaleCount        int `json:"staleCount"`
	HighRiskCount     int `json:"highRiskCount"`
}

type bulkCampaignResponse struct {
	ServiceID            string              `json:"serviceId"`
	APIVersion           string              `json:"apiVersion"`
	RequestID            string              `json:"requestId,omitempty"`
	CampaignID           string              `json:"campaignId"`
	PlanToken            string              `json:"planToken"`
	OperationID          string              `json:"operationId"`
	Operation            string              `json:"operation"`
	Mode                 string              `json:"mode"`
	Outcome              string              `json:"outcome"`
	Applied              bool                `json:"applied"`
	RequiresConfirmation bool                `json:"requiresConfirmation"`
	RequiresAuditReason  bool                `json:"requiresAuditReason"`
	RequiresRevalidation bool                `json:"requiresRevalidation"`
	AuditStatus          string              `json:"auditStatus"`
	StaleAfterSeconds    int                 `json:"staleAfterSeconds"`
	NextAction           string              `json:"nextAction,omitempty"`
	Results              []bulkCampaignItem  `json:"results"`
	Summary              bulkCampaignSummary `json:"summary"`
	AffectedRefs         []string            `json:"affectedRefs"`
	AffectedServices     []string            `json:"affectedServices"`
	UnsupportedFamilies  []string            `json:"unsupportedFamilies,omitempty"`
}

func (b *localBackend) bulkCampaignCreate(req bulkCampaignRequest) (bulkCampaignResponse, error) {
	res, err := b.buildBulkCampaign(req, "create", false)
	if b != nil && b.campaigns != nil && (res.Outcome == "dry_run_ready" || res.Outcome == "partial_failure") {
		b.campaigns[res.PlanToken] = res
	}
	_ = b.audit("bulk_campaign_create", strings.Join(safeList(req.Refs), ","), res.Outcome, req.ServiceID, req.RequestID)
	return res, err
}

func (b *localBackend) bulkCampaignRevalidate(req bulkCampaignRequest) (bulkCampaignResponse, error) {
	if strings.TrimSpace(req.PlanToken) == "" {
		res := baseBulkCampaignResponse(req, "revalidate")
		res.Outcome = "stale_plan"
		res.NextAction = "create_fresh_campaign_plan"
		_ = b.audit("bulk_campaign_revalidate", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errPolicyDenied
	}
	if stored, ok := b.campaigns[strings.TrimSpace(req.PlanToken)]; ok {
		req.Operation = firstNonEmpty(req.Operation, stored.Operation)
		if len(safeList(req.Refs)) == 0 {
			req.Refs = safeList(stored.AffectedRefs)
		}
		req.CampaignID = firstNonEmpty(req.CampaignID, stored.CampaignID)
		req.OperationID = firstNonEmpty(req.OperationID, stored.OperationID)
		req.TargetPolicy = firstNonEmpty(req.TargetPolicy, stored.firstTargetPolicy())
		req.TargetProviderID = firstNonEmpty(req.TargetProviderID, stored.firstTargetProvider())
	}
	res, err := b.buildBulkCampaign(req, "revalidate", false)
	res.PlanToken = firstNonEmpty(req.PlanToken, res.PlanToken)
	if res.Outcome == "dry_run_ready" || res.Outcome == "partial_failure" {
		res.RequiresRevalidation = false
		b.campaigns[res.PlanToken] = res
	}
	_ = b.audit("bulk_campaign_revalidate", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID)
	return res, err
}

func (b *localBackend) bulkCampaignApply(req bulkCampaignRequest) (bulkCampaignResponse, error) {
	if !req.Confirm || strings.TrimSpace(req.Reason) == "" || strings.TrimSpace(req.PlanToken) == "" {
		res := baseBulkCampaignResponse(req, "apply")
		res.Outcome = "policy_denied"
		res.NextAction = "revalidate_confirm_and_provide_audit_reason"
		_ = b.audit("bulk_campaign_apply", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errPolicyDenied
	}
	stored, ok := b.campaigns[strings.TrimSpace(req.PlanToken)]
	if !ok {
		res := baseBulkCampaignResponse(req, "apply")
		res.Outcome = "stale_plan"
		res.NextAction = "create_fresh_campaign_plan"
		_ = b.audit("bulk_campaign_apply", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	if req.Operation != "" && normalizeCampaignOperation(req.Operation) != stored.Operation {
		res := stored.withRequest(req, "apply")
		res.Outcome = "stale_plan"
		res.NextAction = "create_fresh_campaign_plan"
		res.Summary = summarizeBulkCampaign(markBulkItemsStale(res.Results))
		res.Results = markBulkItemsStale(res.Results)
		_ = b.audit("bulk_campaign_apply", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	res := stored.withRequest(req, "apply")
	res.RequiresConfirmation = false
	res.RequiresAuditReason = false
	res.RequiresRevalidation = false
	res.AuditStatus = "audit_recorded"
	for i := range res.Results {
		if res.Results[i].Outcome == "dry_run_ready" {
			res.Results[i].Outcome = applyOutcomeForBulkOperation(res.Operation)
			res.Results[i].Applied = true
			res.Results[i].NextAction = "monitor_campaign_status"
			res.Results[i].Recovery = recoveryForBulkOperation(res.Operation)
			_ = b.audit("bulk_campaign_item_apply", res.Results[i].Ref, res.Results[i].Outcome, req.ServiceID, req.RequestID)
		} else {
			res.Results[i].Applied = false
			res.Results[i].NextAction = firstNonEmpty(res.Results[i].NextAction, "review_item_status")
			_ = b.audit("bulk_campaign_item_apply", res.Results[i].Ref, res.Results[i].Outcome, req.ServiceID, req.RequestID)
		}
	}
	res.Summary = summarizeBulkCampaign(res.Results)
	res.Applied = res.Summary.AppliedCount > 0
	res.Outcome = bulkApplyAggregateOutcome(res.Summary)
	res.NextAction = bulkCampaignNextAction(res.Outcome)
	b.campaigns[res.PlanToken] = res
	_ = b.audit("bulk_campaign_apply", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID)
	if res.Outcome == "applied" || res.Outcome == "partial_failure" {
		return res, nil
	}
	return res, outcomeErrorForBulkCampaign(res.Outcome)
}

func (b *localBackend) bulkCampaignStatus(req bulkCampaignRequest) (bulkCampaignResponse, error) {
	if strings.TrimSpace(req.PlanToken) == "" && strings.TrimSpace(req.CampaignID) == "" {
		res := baseBulkCampaignResponse(req, "status")
		res.Outcome = "invalid_ref"
		res.NextAction = "provide_plan_token_or_campaign_id"
		return res, errInvalidRef
	}
	for _, campaign := range b.campaigns {
		if campaign.PlanToken == strings.TrimSpace(req.PlanToken) || campaign.CampaignID == strings.TrimSpace(req.CampaignID) {
			return campaign.withRequest(req, "status"), nil
		}
	}
	res := baseBulkCampaignResponse(req, "status")
	res.Outcome = "stale_plan"
	res.NextAction = "create_fresh_campaign_plan"
	return res, errBackendDegraded
}

func (b *localBackend) buildBulkCampaign(req bulkCampaignRequest, mode string, apply bool) (bulkCampaignResponse, error) {
	req.Operation = normalizeCampaignOperation(req.Operation)
	res := baseBulkCampaignResponse(req, mode)
	if req.Operation == "" {
		res.Outcome = "invalid_ref"
		res.NextAction = "select_operation"
		return res, errInvalidRef
	}
	if len(res.AffectedRefs) == 0 {
		res.Outcome = "invalid_ref"
		res.NextAction = "select_refs"
		return res, errInvalidRef
	}
	if b.locked() {
		res.Outcome = "locked"
		res.NextAction = "unlock_broker"
		return res, errLocked
	}
	refs := safeList(req.Refs)
	sort.Strings(refs)
	for _, ref := range refs {
		res.Results = append(res.Results, b.bulkCampaignItem(req, res.CampaignID, ref, apply))
	}
	res.Summary = summarizeBulkCampaign(res.Results)
	res.Outcome = bulkPlanAggregateOutcome(res.Summary)
	res.AuditStatus = "audit_ready"
	res.NextAction = bulkCampaignNextAction(res.Outcome)
	if res.Outcome == "dry_run_ready" || res.Outcome == "partial_failure" {
		return res, nil
	}
	return res, outcomeErrorForBulkCampaign(res.Outcome)
}

func (b *localBackend) bulkCampaignItem(req bulkCampaignRequest, campaignID, ref string, apply bool) bulkCampaignItem {
	item := bulkCampaignItem{
		Ref:              strings.TrimSpace(ref),
		SourceID:         "unknown",
		ProviderKind:     "unknown",
		OwnerServiceID:   ownerFromRef(ref),
		Operation:        req.Operation,
		CapabilityResult: "unknown",
		PolicyResult:     "allowed",
		AuditRequirement: "required",
		Risk:             riskForBulkOperation(req.Operation),
		ExpectedAction:   expectedActionForBulkOperation(req.Operation),
		Outcome:          "dry_run_ready",
		NextAction:       "revalidate_confirm_and_apply",
		IdempotencyKey:   bulkIdempotencyKey(campaignID, req.Operation, ref),
		OperationItemID:  bulkOperationItemID(campaignID, ref),
		Recovery:         recoveryForBulkOperation(req.Operation),
		TargetProviderID: strings.TrimSpace(req.TargetProviderID),
		TargetPolicy:     strings.TrimSpace(req.TargetPolicy),
		RetrySafe:        true,
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
		item.NextAction = nextActionForManagedOutcome(item.Outcome)
		return item
	}
	item.SourceID = record.SourceID
	item.ProviderKind = record.ProviderKind
	item.OwnerServiceID = record.OwnerServiceID
	item.CapabilityResult = campaignCapabilityResult(record, req.Operation)
	if strings.Contains(strings.ToLower(ref), "deny") {
		item.Outcome = "policy_denied"
		item.PolicyResult = "denied"
		item.NextAction = "review_policy"
		return item
	}
	if req.Operation == "migrate_remap_provider" && strings.TrimSpace(req.TargetProviderID) == "" {
		item.Outcome = "source_auth_required"
		item.PolicyResult = "unknown"
		item.CapabilityResult = "blocked"
		item.NextAction = "select_target_provider"
		return item
	}
	if req.Operation == "apply_policy" && strings.TrimSpace(req.TargetPolicy) == "" {
		item.Outcome = "policy_denied"
		item.PolicyResult = "denied"
		item.NextAction = "select_target_policy"
		return item
	}
	if item.CapabilityResult != "supported" {
		item.Outcome = "unsupported"
		item.PolicyResult = "unknown"
		item.NextAction = "inspect_provider_capabilities"
		return item
	}
	item.ProviderAction = providerActionForBulkOperation(req.Operation)
	return item
}

func baseBulkCampaignResponse(req bulkCampaignRequest, mode string) bulkCampaignResponse {
	operation := normalizeCampaignOperation(req.Operation)
	campaignID := campaignID(req)
	return bulkCampaignResponse{
		ServiceID:            serviceID,
		APIVersion:           apiVersion,
		RequestID:            req.RequestID,
		CampaignID:           campaignID,
		PlanToken:            firstNonEmpty(strings.TrimSpace(req.PlanToken), bulkPlanToken(campaignID, operation, req.Refs)),
		OperationID:          firstNonEmpty(safeOperationToken(req.OperationID), campaignID),
		Operation:            operation,
		Mode:                 mode,
		Outcome:              "pending",
		RequiresConfirmation: mode != "status",
		RequiresAuditReason:  mode == "apply" || mode == "create" || mode == "revalidate",
		RequiresRevalidation: mode == "create",
		AuditStatus:          "audit_pending",
		StaleAfterSeconds:    bulkCampaignStaleAfterSeconds,
		Results:              []bulkCampaignItem{},
		AffectedRefs:         safeList(req.Refs),
		AffectedServices:     safeList([]string{req.ServiceID}),
		UnsupportedFamilies:  unsupportedBulkFamilies(operation),
	}
}

func (r bulkCampaignResponse) withRequest(req bulkCampaignRequest, mode string) bulkCampaignResponse {
	r.RequestID = req.RequestID
	r.Mode = mode
	return r
}

func (r bulkCampaignResponse) firstTargetPolicy() string {
	for _, item := range r.Results {
		if item.TargetPolicy != "" {
			return item.TargetPolicy
		}
	}
	return ""
}

func (r bulkCampaignResponse) firstTargetProvider() string {
	for _, item := range r.Results {
		if item.TargetProviderID != "" {
			return item.TargetProviderID
		}
	}
	return ""
}

func normalizeCampaignOperation(operation string) string {
	switch strings.ToLower(strings.TrimSpace(operation)) {
	case "rotate", "reset", "rotate_reset", "rotate/reset", "credential_rotation":
		return "rotate_reset"
	case "edit", "update", "update_edit":
		return "update_edit"
	case "policy", "apply_policy":
		return "apply_policy"
	case "migration", "migrate", "migrate_remap", "migrate_remap_provider":
		return "migrate_remap_provider"
	case "mark_action_required", "mark-auth-required", "mark_reconnect_required":
		return "mark_action_required"
	default:
		return ""
	}
}

func campaignID(req bulkCampaignRequest) string {
	if id := safeOperationToken(req.CampaignID); id != "" {
		return id
	}
	if id := safeOperationToken(req.OperationID); id != "" {
		return "campaign-" + id
	}
	if id := safeOperationToken(req.RequestID); id != "" {
		return "campaign-" + id
	}
	return "campaign-plan"
}

func bulkPlanToken(campaignID, operation string, refs []string) string {
	refs = safeList(refs)
	sort.Strings(refs)
	return campaignID + ":" + operation + ":" + hashAuditRef(strings.Join(refs, ","))
}

func bulkIdempotencyKey(campaignID, operation, ref string) string {
	return strings.Join([]string{campaignID, operation, hashAuditRef(strings.TrimSpace(ref))}, ":")
}

func bulkOperationItemID(campaignID, ref string) string {
	return campaignID + ":item:" + hashAuditRef(strings.TrimSpace(ref))
}

func campaignCapabilityResult(record managedSecretRecord, operation string) string {
	required := requiredCapabilityForBulkOperation(operation)
	if required == "" {
		return "unsupported"
	}
	for _, capability := range record.Capabilities {
		if capability == required {
			return "supported"
		}
		if operation == "rotate_reset" && (capability == "reset" || capability == "rotate" || capability == "rotate/reset") {
			return "supported"
		}
		if operation == "migrate_remap_provider" && (capability == "migration_source" || capability == "metadata") {
			return "supported"
		}
		if operation == "mark_action_required" && capability == "metadata" {
			return "supported"
		}
	}
	return "unsupported"
}

func requiredCapabilityForBulkOperation(operation string) string {
	switch operation {
	case "rotate_reset":
		return "rotate/reset"
	case "update_edit":
		return "edit"
	case "apply_policy":
		return "policy"
	case "migrate_remap_provider":
		return "migration_source"
	case "mark_action_required":
		return "metadata"
	default:
		return ""
	}
}

func riskForBulkOperation(operation string) string {
	switch operation {
	case "migrate_remap_provider", "rotate_reset":
		return "high"
	case "update_edit", "apply_policy":
		return "medium"
	default:
		return "low"
	}
}

func expectedActionForBulkOperation(operation string) string {
	switch operation {
	case "rotate_reset":
		return "generate_or_accept_replacement_inside_broker"
	case "update_edit":
		return "apply_caller_supplied_value_inside_broker_when_supported"
	case "apply_policy":
		return "bind_target_policy_to_ref"
	case "migrate_remap_provider":
		return "copy_or_remap_value_inside_broker_to_target_provider"
	case "mark_action_required":
		return "record_provider_action_required_metadata"
	default:
		return "inspect_operation"
	}
}

func providerActionForBulkOperation(operation string) string {
	switch operation {
	case "rotate_reset":
		return "rotate_or_reset"
	case "update_edit":
		return "write_secret"
	case "apply_policy":
		return "apply_policy"
	case "migrate_remap_provider":
		return "migrate_or_remap"
	case "mark_action_required":
		return "mark_action_required"
	default:
		return "unsupported"
	}
}

func applyOutcomeForBulkOperation(operation string) string {
	switch operation {
	case "migrate_remap_provider":
		return "migrated"
	case "mark_action_required":
		return "applied"
	default:
		return "applied"
	}
}

func recoveryForBulkOperation(operation string) string {
	switch operation {
	case "rotate_reset":
		return "retry_with_same_idempotency_key_or_restore_from_backup"
	case "migrate_remap_provider":
		return "retry_after_fix_or_restore_from_backup"
	default:
		return "retry_with_same_idempotency_key_after_fix"
	}
}

func unsupportedBulkFamilies(operation string) []string {
	switch operation {
	case "update_edit":
		return []string{"remote_plaintext_spreadsheet_editing", "bulk_raw_value_reveal"}
	default:
		return []string{"bulk_raw_value_reveal"}
	}
}

func summarizeBulkCampaign(items []bulkCampaignItem) bulkCampaignSummary {
	summary := bulkCampaignSummary{SelectedCount: len(items)}
	for _, item := range items {
		switch item.Outcome {
		case "dry_run_ready":
			summary.ApplicableCount++
		case "policy_denied", "invalid_ref":
			summary.DeniedCount++
		case "unsupported":
			summary.UnsupportedCount++
		case "source_auth_required":
			summary.AuthRequiredCount++
		case "skipped":
			summary.SkippedCount++
		case "applied", "migrated":
			summary.AppliedCount++
		case "failed":
			summary.FailedCount++
		case "stale_plan":
			summary.StaleCount++
		default:
			summary.FailedCount++
		}
		if item.Risk == "high" {
			summary.HighRiskCount++
		}
	}
	return summary
}

func bulkPlanAggregateOutcome(summary bulkCampaignSummary) string {
	if summary.SelectedCount == 0 {
		return "invalid_ref"
	}
	if summary.ApplicableCount == summary.SelectedCount {
		return "dry_run_ready"
	}
	if summary.ApplicableCount > 0 {
		return "partial_failure"
	}
	if summary.DeniedCount > 0 {
		return "policy_denied"
	}
	if summary.UnsupportedCount > 0 {
		return "unsupported"
	}
	if summary.AuthRequiredCount > 0 {
		return "source_auth_required"
	}
	if summary.StaleCount > 0 {
		return "stale_plan"
	}
	return "degraded"
}

func bulkApplyAggregateOutcome(summary bulkCampaignSummary) string {
	if summary.AppliedCount > 0 && (summary.DeniedCount > 0 || summary.UnsupportedCount > 0 || summary.AuthRequiredCount > 0 || summary.FailedCount > 0 || summary.StaleCount > 0) {
		return "partial_failure"
	}
	if summary.AppliedCount > 0 {
		return "applied"
	}
	return bulkPlanAggregateOutcome(summary)
}

func bulkCampaignNextAction(outcome string) string {
	switch outcome {
	case "dry_run_ready":
		return "revalidate_confirm_and_apply"
	case "applied":
		return "read_campaign_status"
	case "partial_failure":
		return "review_denied_unsupported_or_failed_items"
	case "stale_plan":
		return "create_fresh_campaign_plan"
	case "source_auth_required":
		return "reconnect_provider_or_select_supported_target"
	case "unsupported":
		return "inspect_provider_capabilities"
	default:
		return nextActionForManagedOutcome(outcome)
	}
}

func markBulkItemsStale(items []bulkCampaignItem) []bulkCampaignItem {
	stale := make([]bulkCampaignItem, len(items))
	for i, item := range items {
		item.Outcome = "stale_plan"
		item.NextAction = "create_fresh_campaign_plan"
		item.Applied = false
		stale[i] = item
	}
	return stale
}

func outcomeErrorForBulkCampaign(outcome string) error {
	switch outcome {
	case "invalid_ref":
		return errInvalidRef
	case "locked":
		return errLocked
	case "policy_denied":
		return errPolicyDenied
	case "source_auth_required":
		return errSourceAuthRequired
	case "unsupported":
		return errUnsupportedProvider
	default:
		return errBackendDegraded
	}
}

func registerBulkCampaignHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	registerBulkCampaignAction(mux, security, "/v1/management/secrets/campaigns/create", backend.bulkCampaignCreate)
	registerBulkCampaignAction(mux, security, "/v1/management/secrets/campaigns/revalidate", backend.bulkCampaignRevalidate)
	registerBulkCampaignAction(mux, security, "/v1/management/secrets/campaigns/apply", backend.bulkCampaignApply)
	registerBulkCampaignAction(mux, security, "/v1/management/secrets/campaigns/status", backend.bulkCampaignStatus)
}

func registerBulkCampaignAction(mux *http.ServeMux, security localAPISecurity, path string, handler func(bulkCampaignRequest) (bulkCampaignResponse, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST "+path+".", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req bulkCampaignRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := handler(req)
		if err != nil {
			writeBulkCampaignActionError(w, err, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func writeBulkCampaignActionError(w http.ResponseWriter, err error, res bulkCampaignResponse) {
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
