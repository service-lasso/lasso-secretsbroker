package main

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
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
	Verified         bool   `json:"verified"`
	Attempts         int    `json:"attempts,omitempty"`
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
	Durable              bool                `json:"durable"`
	MaxConcurrency       int                 `json:"maxConcurrency"`
	BackpressurePolicy   string              `json:"backpressurePolicy"`
	CreatedAt            time.Time           `json:"createdAt"`
	RevalidatedAt        *time.Time          `json:"revalidatedAt,omitempty"`
	UpdatedAt            time.Time           `json:"updatedAt"`
}

func (b *localBackend) bulkCampaignCreate(req bulkCampaignRequest) (bulkCampaignResponse, error) {
	b.bulkCampaignMu.Lock()
	defer b.bulkCampaignMu.Unlock()
	res, err := b.buildBulkCampaign(req, "create", false)
	res.CreatedAt = b.now()
	res.UpdatedAt = res.CreatedAt
	if res.Outcome == "dry_run_ready" || res.Outcome == "partial_failure" {
		if auditErr := b.audit("bulk_campaign_create", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID); auditErr != nil {
			return bulkCampaignAuditFailure(res), errProviderAuditUnavailable
		}
		res.AuditStatus = "audit_recorded"
		if persistErr := b.persistBulkCampaign(res); persistErr != nil {
			return bulkCampaignPersistenceFailure(res), errBackendDegraded
		}
		return res, err
	}
	_ = b.audit("bulk_campaign_create", strings.Join(safeList(req.Refs), ","), res.Outcome, req.ServiceID, req.RequestID)
	return res, err
}

func (b *localBackend) bulkCampaignRevalidate(req bulkCampaignRequest) (bulkCampaignResponse, error) {
	b.bulkCampaignMu.Lock()
	defer b.bulkCampaignMu.Unlock()
	if strings.TrimSpace(req.PlanToken) == "" {
		res := baseBulkCampaignResponse(req, "revalidate")
		res.Outcome = "stale_plan"
		res.NextAction = "create_fresh_campaign_plan"
		_ = b.audit("bulk_campaign_revalidate", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errPolicyDenied
	}
	stored, ok, loadErr := b.loadBulkCampaign(strings.TrimSpace(req.PlanToken))
	if loadErr != nil {
		return bulkCampaignPersistenceFailure(baseBulkCampaignResponse(req, "revalidate")), errBackendDegraded
	}
	if !ok {
		res := baseBulkCampaignResponse(req, "revalidate")
		res.Outcome = "stale_plan"
		res.NextAction = "create_fresh_campaign_plan"
		_ = b.audit("bulk_campaign_revalidate", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	if bulkCampaignRequestConflicts(req, stored) {
		return staleBulkCampaignResponse(stored.withRequest(req, "revalidate")), errBackendDegraded
	}
	req.Operation = stored.Operation
	req.Refs = safeList(stored.AffectedRefs)
	req.CampaignID = stored.CampaignID
	req.OperationID = stored.OperationID
	req.TargetPolicy = stored.firstTargetPolicy()
	req.TargetProviderID = stored.firstTargetProvider()
	res, err := b.buildBulkCampaign(req, "revalidate", false)
	res.PlanToken = stored.PlanToken
	res.CreatedAt = stored.CreatedAt
	if res.CreatedAt.IsZero() {
		res.CreatedAt = b.now()
	}
	revalidatedAt := b.now()
	res.RevalidatedAt = &revalidatedAt
	res.UpdatedAt = revalidatedAt
	if res.Outcome == "dry_run_ready" || res.Outcome == "partial_failure" {
		res.RequiresRevalidation = false
		if auditErr := b.audit("bulk_campaign_revalidate", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID); auditErr != nil {
			return bulkCampaignAuditFailure(res), errProviderAuditUnavailable
		}
		res.AuditStatus = "audit_recorded"
		if persistErr := b.persistBulkCampaign(res); persistErr != nil {
			return bulkCampaignPersistenceFailure(res), errBackendDegraded
		}
		return res, err
	}
	_ = b.audit("bulk_campaign_revalidate", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID)
	return res, err
}

func (b *localBackend) bulkCampaignApply(req bulkCampaignRequest) (bulkCampaignResponse, error) {
	b.bulkCampaignMu.Lock()
	defer b.bulkCampaignMu.Unlock()
	if !req.Confirm || strings.TrimSpace(req.Reason) == "" || strings.TrimSpace(req.PlanToken) == "" {
		res := baseBulkCampaignResponse(req, "apply")
		res.Outcome = "policy_denied"
		res.NextAction = "revalidate_confirm_and_provide_audit_reason"
		_ = b.audit("bulk_campaign_apply", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errPolicyDenied
	}
	stored, ok, loadErr := b.loadBulkCampaign(strings.TrimSpace(req.PlanToken))
	if loadErr != nil {
		return bulkCampaignPersistenceFailure(baseBulkCampaignResponse(req, "apply")), errBackendDegraded
	}
	if !ok {
		res := baseBulkCampaignResponse(req, "apply")
		res.Outcome = "stale_plan"
		res.NextAction = "create_fresh_campaign_plan"
		_ = b.audit("bulk_campaign_apply", "", res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	if stored.RequiresRevalidation || bulkCampaignPlanExpired(b.now(), stored) || bulkCampaignRequestConflicts(req, stored) {
		res := staleBulkCampaignResponse(stored.withRequest(req, "apply"))
		_ = b.audit("bulk_campaign_apply", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	if stored.Operation != "migrate_remap_provider" {
		res := stored.withRequest(req, "apply")
		res.Outcome = "unsupported"
		res.Applied = false
		res.NextAction = "use_provider_migration_campaign_or_implement_operation_executor"
		for i := range res.Results {
			if res.Results[i].Outcome == "dry_run_ready" {
				res.Results[i].Outcome = "unsupported"
				res.Results[i].Applied = false
				res.Results[i].NextAction = res.NextAction
			}
		}
		res.Summary = summarizeBulkCampaign(res.Results)
		return res, errUnsupportedProvider
	}
	if strings.TrimSpace(req.HighRiskConfirm) != stored.CampaignID {
		res := stored.withRequest(req, "apply")
		res.Outcome = "policy_denied"
		res.Applied = false
		res.NextAction = "confirm_exact_campaign_id_for_high_risk_migration"
		return res, errPolicyDenied
	}
	if strings.TrimSpace(b.auditPath) == "" || b.audit("bulk_campaign_apply_authorized", stored.firstTargetProvider(), "ready", req.ServiceID, req.RequestID) != nil {
		return bulkCampaignAuditFailure(stored.withRequest(req, "apply")), errProviderAuditUnavailable
	}
	res := stored.withRequest(req, "apply")
	res.RequiresConfirmation = false
	res.RequiresAuditReason = false
	res.RequiresRevalidation = false
	res.AuditStatus = "audit_recorded"
	backpressure := false
	for i := range res.Results {
		if res.Results[i].Applied && res.Results[i].Verified {
			continue
		}
		if !bulkCampaignItemRetryable(res.Results[i]) {
			continue
		}
		if backpressure {
			res.Results[i].Outcome = "skipped"
			res.Results[i].Applied = false
			res.Results[i].NextAction = "retry_after_provider_backoff"
			continue
		}
		res.Results[i] = b.executeBulkMigrationItem(req, res.Results[i])
		_ = b.audit("bulk_campaign_item_apply", res.Results[i].Ref, res.Results[i].Outcome, req.ServiceID, req.RequestID)
		res.Summary = summarizeBulkCampaign(res.Results)
		res.Applied = res.Summary.AppliedCount > 0
		res.Outcome = bulkApplyAggregateOutcome(res.Summary)
		res.NextAction = bulkCampaignNextAction(res.Outcome)
		res.UpdatedAt = b.now()
		if persistErr := b.persistBulkCampaign(res); persistErr != nil {
			return bulkCampaignPersistenceFailure(res), errBackendDegraded
		}
		if bulkCampaignBackpressureOutcome(res.Results[i].Outcome) {
			backpressure = true
		}
	}
	res.Summary = summarizeBulkCampaign(res.Results)
	res.Applied = res.Summary.AppliedCount > 0
	res.Outcome = bulkApplyAggregateOutcome(res.Summary)
	res.NextAction = bulkCampaignNextAction(res.Outcome)
	res.UpdatedAt = b.now()
	if persistErr := b.persistBulkCampaign(res); persistErr != nil {
		return bulkCampaignPersistenceFailure(res), errBackendDegraded
	}
	_ = b.audit("bulk_campaign_apply", strings.Join(res.AffectedRefs, ","), res.Outcome, req.ServiceID, req.RequestID)
	if res.Outcome == "applied" || res.Outcome == "partial_failure" {
		return res, nil
	}
	return res, outcomeErrorForBulkCampaign(res.Outcome)
}

func (b *localBackend) bulkCampaignStatus(req bulkCampaignRequest) (bulkCampaignResponse, error) {
	b.bulkCampaignMu.Lock()
	defer b.bulkCampaignMu.Unlock()
	if strings.TrimSpace(req.PlanToken) == "" && strings.TrimSpace(req.CampaignID) == "" {
		res := baseBulkCampaignResponse(req, "status")
		res.Outcome = "invalid_ref"
		res.NextAction = "provide_plan_token_or_campaign_id"
		return res, errInvalidRef
	}
	store, err := b.loadStore()
	if err != nil {
		return bulkCampaignPersistenceFailure(baseBulkCampaignResponse(req, "status")), errBackendDegraded
	}
	for _, campaign := range store.Campaigns {
		if campaign.PlanToken == strings.TrimSpace(req.PlanToken) || campaign.CampaignID == strings.TrimSpace(req.CampaignID) {
			return campaign.withRequest(req, "status"), nil
		}
	}
	res := baseBulkCampaignResponse(req, "status")
	res.Outcome = "stale_plan"
	res.NextAction = "create_fresh_campaign_plan"
	return res, errBackendDegraded
}

func (b *localBackend) loadBulkCampaign(planToken string) (bulkCampaignResponse, bool, error) {
	store, err := b.loadStore()
	if err != nil {
		return bulkCampaignResponse{}, false, err
	}
	campaign, ok := store.Campaigns[strings.TrimSpace(planToken)]
	return campaign, ok, nil
}

func (b *localBackend) persistBulkCampaign(campaign bulkCampaignResponse) error {
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	if strings.TrimSpace(campaign.PlanToken) == "" {
		return errInvalidRef
	}
	store, err := b.loadStore()
	if err != nil {
		return err
	}
	if campaign.CreatedAt.IsZero() {
		campaign.CreatedAt = b.now()
	}
	campaign.UpdatedAt = b.now()
	store.Campaigns[campaign.PlanToken] = campaign
	store.UpdatedAt = campaign.UpdatedAt
	if err := b.saveStore(store); err != nil {
		return err
	}
	if b.campaigns != nil {
		b.campaigns[campaign.PlanToken] = campaign
	}
	return nil
}

func bulkCampaignRequestConflicts(req bulkCampaignRequest, stored bulkCampaignResponse) bool {
	if req.Operation != "" && normalizeCampaignOperation(req.Operation) != stored.Operation {
		return true
	}
	if req.CampaignID != "" && safeOperationToken(req.CampaignID) != stored.CampaignID {
		return true
	}
	if req.OperationID != "" && safeOperationToken(req.OperationID) != stored.OperationID {
		return true
	}
	if req.TargetProviderID != "" && strings.TrimSpace(req.TargetProviderID) != stored.firstTargetProvider() {
		return true
	}
	if req.TargetPolicy != "" && strings.TrimSpace(req.TargetPolicy) != stored.firstTargetPolicy() {
		return true
	}
	if len(safeList(req.Refs)) > 0 {
		requested := safeList(req.Refs)
		storedRefs := safeList(stored.AffectedRefs)
		sort.Strings(requested)
		sort.Strings(storedRefs)
		if strings.Join(requested, "\n") != strings.Join(storedRefs, "\n") {
			return true
		}
	}
	return false
}

func bulkCampaignPlanExpired(now time.Time, stored bulkCampaignResponse) bool {
	if stored.RevalidatedAt == nil || stored.RevalidatedAt.IsZero() {
		return true
	}
	revalidatedAt := stored.RevalidatedAt.UTC()
	now = now.UTC()
	if revalidatedAt.After(now.Add(time.Second)) {
		return true
	}
	return now.Sub(revalidatedAt) > time.Duration(stored.StaleAfterSeconds)*time.Second
}

func staleBulkCampaignResponse(res bulkCampaignResponse) bulkCampaignResponse {
	res.Outcome = "stale_plan"
	res.Applied = false
	res.NextAction = "create_fresh_campaign_plan"
	res.Results = markBulkItemsStale(res.Results)
	res.Summary = summarizeBulkCampaign(res.Results)
	return res
}

func bulkCampaignAuditFailure(res bulkCampaignResponse) bulkCampaignResponse {
	res.Outcome = "audit_unavailable"
	res.Applied = false
	res.AuditStatus = "audit_unavailable"
	res.NextAction = "restore_audit_and_retry"
	for i := range res.Results {
		if !res.Results[i].Applied {
			res.Results[i].Outcome = "audit_unavailable"
			res.Results[i].NextAction = res.NextAction
		}
	}
	res.Summary = summarizeBulkCampaign(res.Results)
	return res
}

func bulkCampaignPersistenceFailure(res bulkCampaignResponse) bulkCampaignResponse {
	res.Outcome = "degraded"
	res.Applied = false
	res.NextAction = "restore_campaign_store_and_retry"
	return res
}

func (b *localBackend) executeBulkMigrationItem(req bulkCampaignRequest, item bulkCampaignItem) bulkCampaignItem {
	migration, _ := b.migrationApply(migrationPlanRequest{
		RequestID:        req.RequestID,
		ServiceID:        req.ServiceID,
		OperationID:      item.OperationItemID,
		SourceProviderID: "local",
		TargetProviderID: item.TargetProviderID,
		Refs:             []string{item.Ref},
		Reason:           req.Reason,
		Confirm:          true,
	})
	item.Applied = false
	item.Verified = false
	if len(migration.Results) == 1 {
		result := migration.Results[0]
		item.Outcome = result.Outcome
		item.Applied = result.Outcome == "migrated" && result.Verified
		item.Verified = result.Verified
		item.Attempts = result.Attempts
		item.PolicyResult = result.PolicyResult
		item.Recovery = result.Recovery
		item.NextAction = firstNonEmpty(result.ExpectedAction, providerMigrationRetryAction(result.Outcome))
		if item.Applied {
			item.NextAction = "monitor_campaign_status"
		}
		return item
	}
	item.Outcome = firstNonEmpty(migration.Outcome, "degraded")
	item.NextAction = firstNonEmpty(migration.NextAction, "review_item_status")
	return item
}

func bulkCampaignItemRetryable(item bulkCampaignItem) bool {
	if item.ProviderAction != "migrate_or_remap" || item.PolicyResult == "denied" || item.CapabilityResult != "supported" {
		return false
	}
	switch item.Outcome {
	case "dry_run_ready", "rate_limited", "source_auth_required", "source_unavailable", "verification_failed", "degraded", "conflict", "invalid_ref", "policy_denied", "unsupported", "skipped", "audit_unavailable":
		return true
	default:
		return false
	}
}

func bulkCampaignBackpressureOutcome(outcome string) bool {
	switch strings.TrimSpace(outcome) {
	case "rate_limited", "source_auth_required", "source_unavailable", "degraded", "audit_unavailable":
		return true
	default:
		return false
	}
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
		IdempotencyKey:   bulkIdempotencyKey(campaignID, req.Operation, req.TargetProviderID, ref),
		OperationItemID:  bulkOperationItemID(campaignID, req.Operation, req.TargetProviderID, ref),
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
	if req.Operation == "migrate_remap_provider" {
		if item.ProviderKind != "local-encrypted-store" {
			item.Outcome = "unsupported"
			item.CapabilityResult = "unsupported"
			item.NextAction = "select_local_encrypted_store_source"
			return item
		}
		target := b.lookupProvider(strings.TrimSpace(req.TargetProviderID))
		if target.Outcome != "ready" {
			item.Outcome = providerMigrationOutcome(target)
			item.CapabilityResult = "blocked"
			item.NextAction = providerNextAction(item.Outcome)
			return item
		}
		if !providerCanPlanMigrationTarget(target.ProviderKind) {
			item.Outcome = "unsupported"
			item.CapabilityResult = "unsupported"
			item.NextAction = "select_supported_target_provider"
			return item
		}
		if _, ok := b.providerMigrationExecutor(strings.TrimSpace(req.TargetProviderID)); !ok {
			item.Outcome = "unsupported"
			item.CapabilityResult = "unsupported"
			item.NextAction = "configure_executable_target_provider"
			return item
		}
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
		PlanToken:            firstNonEmpty(strings.TrimSpace(req.PlanToken), bulkPlanToken(campaignID, operation, req.TargetProviderID, req.TargetPolicy, req.Refs)),
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
		Durable:              true,
		MaxConcurrency:       1,
		BackpressurePolicy:   "stop_and_defer_remaining",
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

func bulkPlanToken(campaignID, operation, targetProviderID, targetPolicy string, refs []string) string {
	refs = safeList(refs)
	sort.Strings(refs)
	return campaignID + ":" + operation + ":" + hashAuditRef(strings.Join([]string{strings.TrimSpace(targetProviderID), strings.TrimSpace(targetPolicy), strings.Join(refs, ",")}, "\n"))
}

func bulkIdempotencyKey(campaignID, operation, targetProviderID, ref string) string {
	operationItemID := bulkOperationItemID(campaignID, operation, targetProviderID, ref)
	return providerMigrationItemIdempotencyKey(operationItemID, targetProviderID, ref)
}

func bulkOperationItemID(campaignID, operation, targetProviderID, ref string) string {
	return campaignID + ":item:" + hashAuditRef(strings.Join([]string{strings.TrimSpace(operation), strings.TrimSpace(targetProviderID), strings.TrimSpace(ref)}, "\n"))
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
		case "failed", "rate_limited", "source_unavailable", "verification_failed", "conflict", "degraded", "audit_unavailable":
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
	if summary.FailedCount > 0 || summary.SkippedCount > 0 {
		return "partial_failure"
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
