package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const managedCreatePlanTTL = 5 * time.Minute

var errManagedCreateConflict = errors.New("managed secret create conflict")

type managedCreatePlan struct {
	Ref            string    `json:"ref"`
	OperationID    string    `json:"operationId"`
	GenerationMode string    `json:"generationMode"`
	ExpectedState  string    `json:"expectedState"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Signature      string    `json:"signature"`
}

type managedCreateRequest struct {
	RequestID      string             `json:"requestId"`
	ServiceID      string             `json:"serviceId"`
	Ref            string             `json:"ref"`
	OperationID    string             `json:"operationId"`
	GenerationMode string             `json:"generationMode"`
	Reason         string             `json:"reason"`
	Value          string             `json:"value,omitempty"`
	Confirm        bool               `json:"confirm"`
	Plan           *managedCreatePlan `json:"plan,omitempty"`
}

type managedCreateReceipt struct {
	Kind           string    `json:"kind"`
	OperationID    string    `json:"operationId"`
	Ref            string    `json:"ref"`
	GenerationMode string    `json:"generationMode"`
	Version        string    `json:"version"`
	AppliedAt      time.Time `json:"appliedAt"`
}

type managedCreateResponse struct {
	ServiceID            string             `json:"serviceId"`
	APIVersion           string             `json:"apiVersion"`
	RequestID            string             `json:"requestId,omitempty"`
	OperationID          string             `json:"operationId"`
	Ref                  string             `json:"ref"`
	Operation            string             `json:"operation"`
	Mode                 string             `json:"mode"`
	GenerationMode       string             `json:"generationMode"`
	Outcome              string             `json:"outcome"`
	Applied              bool               `json:"applied"`
	RequiresConfirmation bool               `json:"requiresConfirmation"`
	AuditStatus          string             `json:"auditStatus"`
	PolicyResult         string             `json:"policyResult"`
	NextAction           string             `json:"nextAction,omitempty"`
	Plan                 *managedCreatePlan `json:"plan,omitempty"`
	Metadata             *SecretMetadata    `json:"metadata,omitempty"`
	AffectedRefs         []string           `json:"affectedRefs"`
	AffectedServices     []string           `json:"affectedServices"`
}

func normalizeManagedCreateMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "broker_generated":
		return "broker_generated"
	case "operator_supplied":
		return "operator_supplied"
	default:
		return ""
	}
}

func baseManagedCreateResponse(req managedCreateRequest, mode string) managedCreateResponse {
	return managedCreateResponse{
		ServiceID: serviceID, APIVersion: apiVersion, RequestID: strings.TrimSpace(req.RequestID),
		OperationID: safeOperationToken(req.OperationID), Ref: strings.TrimSpace(req.Ref), Operation: "create", Mode: mode,
		GenerationMode: normalizeManagedCreateMode(req.GenerationMode), Outcome: "pending", AuditStatus: "audit_pending", PolicyResult: "unknown",
		AffectedRefs: safeList([]string{req.Ref}), AffectedServices: safeList([]string{firstNonEmpty(req.ServiceID, ownerFromRef(req.Ref))}),
	}
}

func (b *localBackend) managedCreateDryRun(req managedCreateRequest) (managedCreateResponse, error) {
	res := baseManagedCreateResponse(req, "dry-run")
	res.RequiresConfirmation = true
	if !validSecretRef(req.Ref) || safeOperationToken(req.OperationID) == "" || strings.TrimSpace(req.Reason) == "" || res.GenerationMode == "" {
		return b.managedCreateFailure("management_create_dry_run", req, res, "policy_denied", "provide_ref_operation_id_generation_mode_and_audit_reason", errPolicyDenied)
	}
	if b.locked() {
		return b.managedCreateFailure("management_create_dry_run", req, res, "locked", "unlock_broker", errLocked)
	}
	store, err := b.loadStore()
	if err != nil {
		return b.managedCreateFailure("management_create_dry_run", req, res, "degraded", "inspect_local_store", errBackendDegraded)
	}
	ref := strings.TrimSpace(req.Ref)
	if _, exists := store.Secrets[ref]; exists || b.configuredSourceHasRef(ref) {
		return b.managedCreateFailure("management_create_dry_run", req, res, "conflict", "choose_unused_ref_or_edit_existing_secret", errManagedCreateConflict)
	}
	if tombstone, exists := store.Tombstones[ref]; exists && tombstone.State == "decommissioned" {
		return b.managedCreateFailure("management_create_dry_run", req, res, "conflict", "restore_or_retire_existing_tombstone", errManagedCreateConflict)
	}
	plan, err := signManagedCreatePlan(managedCreatePlan{Ref: ref, OperationID: safeOperationToken(req.OperationID), GenerationMode: res.GenerationMode, ExpectedState: "missing", ExpiresAt: b.now().Add(managedCreatePlanTTL)}, b.masterKey)
	if err != nil {
		return b.managedCreateFailure("management_create_dry_run", req, res, "locked", "unlock_broker", errLocked)
	}
	if err := b.requireManagedCreateAudit("management_create_dry_run", req, "dry_run_ready"); err != nil {
		return b.managedCreateFailureWithoutAudit(res, "audit_unavailable", "restore_audit_and_retry", err)
	}
	res.Outcome = "dry_run_ready"
	res.AuditStatus = "audit_recorded"
	res.PolicyResult = "allowed"
	res.NextAction = "confirm_signed_plan_before_expiry"
	res.Plan = &plan
	return res, nil
}

func (b *localBackend) managedCreateApply(req managedCreateRequest) (managedCreateResponse, error) {
	b.managementMu.Lock()
	defer b.managementMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()

	res := baseManagedCreateResponse(req, "apply")
	if !validSecretRef(req.Ref) || safeOperationToken(req.OperationID) == "" || strings.TrimSpace(req.Reason) == "" || !req.Confirm || req.Plan == nil || res.GenerationMode == "" {
		return b.managedCreateFailure("management_create_apply", req, res, "policy_denied", "confirm_with_audit_reason_and_fresh_plan", errPolicyDenied)
	}
	plan := *req.Plan
	if verifyManagedCreatePlan(plan, b.masterKey, b.now()) != nil || plan.Ref != strings.TrimSpace(req.Ref) || plan.OperationID != safeOperationToken(req.OperationID) || plan.GenerationMode != res.GenerationMode || plan.ExpectedState != "missing" {
		return b.managedCreateFailure("management_create_apply", req, res, "stale_plan", "run_fresh_create_dry_run", errManagedCreateConflict)
	}
	if res.GenerationMode == "operator_supplied" && strings.TrimSpace(req.Value) == "" {
		return b.managedCreateFailure("management_create_apply", req, res, "policy_denied", "provide_value_and_confirm_fresh_plan", errPolicyDenied)
	}
	if res.GenerationMode == "broker_generated" && req.Value != "" {
		return b.managedCreateFailure("management_create_apply", req, res, "policy_denied", "remove_operator_value_for_broker_generated_create", errPolicyDenied)
	}
	if b.locked() {
		return b.managedCreateFailure("management_create_apply", req, res, "locked", "unlock_broker", errLocked)
	}
	store, err := b.loadStore()
	if err != nil {
		return b.managedCreateFailure("management_create_apply", req, res, "degraded", "inspect_local_store", errBackendDegraded)
	}
	if receipt, exists := store.ManagementOps[plan.OperationID]; exists {
		entry, present := store.Secrets[receipt.Ref]
		if receipt.Kind == "create" && receipt.Ref == plan.Ref && receipt.GenerationMode == plan.GenerationMode && present && entry.Metadata.Version == receipt.Version {
			if err := b.requireManagedCreateAudit("management_create_apply", req, "already_applied"); err != nil {
				return b.managedCreateFailureWithoutAudit(res, "audit_unavailable", "restore_audit_and_retry", err)
			}
			res.Outcome, res.Applied, res.AuditStatus, res.PolicyResult, res.NextAction = "already_applied", false, "audit_recorded", "allowed", "secret_already_created_by_exact_operation"
			res.Metadata = &entry.Metadata
			return res, nil
		}
		return b.managedCreateFailure("management_create_apply", req, res, "conflict", "use_new_operation_id_after_inspecting_existing_receipt", errManagedCreateConflict)
	}
	if _, exists := store.Secrets[plan.Ref]; exists || b.configuredSourceHasRef(plan.Ref) {
		return b.managedCreateFailure("management_create_apply", req, res, "conflict", "run_fresh_create_dry_run", errManagedCreateConflict)
	}
	if tombstone, exists := store.Tombstones[plan.Ref]; exists && tombstone.State == "decommissioned" {
		return b.managedCreateFailure("management_create_apply", req, res, "conflict", "restore_or_retire_existing_tombstone", errManagedCreateConflict)
	}
	if err := b.requireManagedCreateAudit("management_create_apply", req, "authorized"); err != nil {
		return b.managedCreateFailureWithoutAudit(res, "audit_unavailable", "restore_audit_and_retry", err)
	}
	value := req.Value
	if plan.GenerationMode == "broker_generated" {
		value, err = generateManagedSecretValue()
		if err != nil {
			return b.managedCreateFailureWithoutAudit(res, "degraded", "retry_after_secure_random_source_recovers", errBackendDegraded)
		}
	}
	payload, err := b.encrypt(value)
	value = ""
	if err != nil {
		return b.managedCreateFailureWithoutAudit(res, "degraded", "inspect_encryption_state", errBackendDegraded)
	}
	now := b.now()
	metadata := SecretMetadata{SourceID: "management:create:" + plan.GenerationMode, Version: now.Format(time.RFC3339Nano), CreatedAt: now, UpdatedAt: now}
	store.Secrets[plan.Ref] = secretEntry{Ref: plan.Ref, Metadata: metadata, Payload: payload}
	store.ManagementOps[plan.OperationID] = managedCreateReceipt{Kind: "create", OperationID: plan.OperationID, Ref: plan.Ref, GenerationMode: plan.GenerationMode, Version: metadata.Version, AppliedAt: now}
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		return b.managedCreateFailureWithoutAudit(res, "degraded", "retry_exact_operation_or_restore_store", errBackendDegraded)
	}
	_ = b.audit("management_create_apply", plan.Ref, "applied", req.ServiceID, req.RequestID)
	res.Outcome, res.Applied, res.AuditStatus, res.PolicyResult, res.NextAction = "applied", true, "audit_recorded", "allowed", "secret_created"
	res.Metadata = &metadata
	return res, nil
}

func generateManagedSecretValue() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func signManagedCreatePlan(plan managedCreatePlan, key string) (managedCreatePlan, error) {
	if strings.TrimSpace(key) == "" {
		return plan, errLocked
	}
	plan.Signature = ""
	payload, err := json.Marshal(plan)
	if err != nil {
		return plan, err
	}
	mac := hmac.New(sha256.New, []byte("service-lasso:managed-create-plan:v1:"+key))
	_, _ = mac.Write(payload)
	plan.Signature = "hmac-sha256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return plan, nil
}

func verifyManagedCreatePlan(plan managedCreatePlan, key string, now time.Time) error {
	if plan.Signature == "" || !validSecretRef(plan.Ref) || safeOperationToken(plan.OperationID) == "" || normalizeManagedCreateMode(plan.GenerationMode) == "" || plan.ExpectedState != "missing" || !plan.ExpiresAt.After(now) {
		return errManagedCreateConflict
	}
	signature := plan.Signature
	signed, err := signManagedCreatePlan(plan, key)
	if err != nil || !constantTimeTokenEqual(signature, signed.Signature) {
		return errManagedCreateConflict
	}
	return nil
}

func (b *localBackend) requireManagedCreateAudit(operation string, req managedCreateRequest, outcome string) error {
	if b == nil || strings.TrimSpace(b.auditPath) == "" || b.audit(operation, req.Ref, outcome, req.ServiceID, req.RequestID) != nil {
		return errDecommissionAuditUnavailable
	}
	return nil
}

func (b *localBackend) managedCreateFailure(operation string, req managedCreateRequest, res managedCreateResponse, outcome, nextAction string, operationErr error) (managedCreateResponse, error) {
	res.Outcome, res.Applied, res.PolicyResult, res.NextAction = outcome, false, "denied", nextAction
	if b == nil || strings.TrimSpace(b.auditPath) == "" || b.audit(operation, req.Ref, outcome, req.ServiceID, req.RequestID) != nil {
		return b.managedCreateFailureWithoutAudit(res, "audit_unavailable", "restore_audit_and_retry", errDecommissionAuditUnavailable)
	}
	res.AuditStatus = "audit_recorded"
	return res, operationErr
}

func (b *localBackend) managedCreateFailureWithoutAudit(res managedCreateResponse, outcome, nextAction string, err error) (managedCreateResponse, error) {
	res.Outcome, res.Applied, res.AuditStatus, res.PolicyResult, res.NextAction = outcome, false, "audit_unavailable", "denied", nextAction
	return res, err
}

func registerManagedCreateHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	registerManagedCreateAction(mux, security, "/v1/management/secrets/create/dry-run", backend.managedCreateDryRun)
	registerManagedCreateAction(mux, security, "/v1/management/secrets/create/apply", backend.managedCreateApply)
}

func registerManagedCreateAction(mux *http.ServeMux, security localAPISecurity, path string, handler func(managedCreateRequest) (managedCreateResponse, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST "+path+".", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req managedCreateRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := handler(req)
		if err == nil {
			writeJSON(w, http.StatusOK, res)
			return
		}
		switch {
		case errors.Is(err, errInvalidRef), errors.Is(err, errPolicyDenied):
			writeJSON(w, http.StatusBadRequest, res)
		case errors.Is(err, errManagedCreateConflict):
			writeJSON(w, http.StatusConflict, res)
		default:
			writeJSON(w, http.StatusServiceUnavailable, res)
		}
	})
}
