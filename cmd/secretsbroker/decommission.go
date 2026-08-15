package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const decommissionPlanTTL = 5 * time.Minute

var (
	errDecommissionAuditUnavailable = errors.New("decommission audit unavailable")
	errDecommissionDependency       = errors.New("decommission dependency check blocked")
	errDecommissionStalePlan        = errors.New("decommission plan is stale")
)

type localSecretTombstone struct {
	Ref                string      `json:"ref"`
	State              string      `json:"state"`
	Version            string      `json:"version"`
	DecommissionID     string      `json:"decommissionOperationId"`
	RestoreOperationID string      `json:"restoreOperationId,omitempty"`
	DecommissionedAt   time.Time   `json:"decommissionedAt"`
	RestoredAt         time.Time   `json:"restoredAt,omitempty"`
	Entry              secretEntry `json:"entry"`
}

type decommissionPlan struct {
	Ref                string    `json:"ref"`
	OperationID        string    `json:"operationId"`
	ExpectedVersion    string    `json:"expectedVersion"`
	DependencyStatus   string    `json:"dependencyStatus"`
	DependencySnapshot string    `json:"dependencySnapshot"`
	ExpiresAt          time.Time `json:"expiresAt"`
	Signature          string    `json:"signature"`
}

type decommissionRequest struct {
	RequestID          string            `json:"requestId"`
	ServiceID          string            `json:"serviceId"`
	Ref                string            `json:"ref"`
	OperationID        string            `json:"operationId"`
	Reason             string            `json:"reason"`
	Confirm            bool              `json:"confirm"`
	DependencyStatus   string            `json:"dependencyStatus"`
	DependencySnapshot string            `json:"dependencySnapshot"`
	Dependencies       []string          `json:"dependencies"`
	ExpectedVersion    string            `json:"expectedVersion"`
	Plan               *decommissionPlan `json:"plan,omitempty"`
}

type decommissionTombstoneMetadata struct {
	State              string    `json:"state"`
	Version            string    `json:"version"`
	DecommissionID     string    `json:"decommissionOperationId"`
	RestoreOperationID string    `json:"restoreOperationId,omitempty"`
	DecommissionedAt   time.Time `json:"decommissionedAt"`
	RestoredAt         time.Time `json:"restoredAt,omitempty"`
}

type decommissionResponse struct {
	ServiceID            string                         `json:"serviceId"`
	APIVersion           string                         `json:"apiVersion"`
	RequestID            string                         `json:"requestId,omitempty"`
	OperationID          string                         `json:"operationId,omitempty"`
	Ref                  string                         `json:"ref"`
	Operation            string                         `json:"operation"`
	Mode                 string                         `json:"mode"`
	Outcome              string                         `json:"outcome"`
	Applied              bool                           `json:"applied"`
	RequiresConfirmation bool                           `json:"requiresConfirmation"`
	AuditStatus          string                         `json:"auditStatus"`
	PolicyResult         string                         `json:"policyResult"`
	NextAction           string                         `json:"nextAction,omitempty"`
	ExpectedVersion      string                         `json:"expectedVersion,omitempty"`
	DependencyStatus     string                         `json:"dependencyStatus"`
	DependencySnapshot   string                         `json:"dependencySnapshot,omitempty"`
	Dependencies         []string                       `json:"dependencies"`
	Recoverable          bool                           `json:"recoverable"`
	Plan                 *decommissionPlan              `json:"plan,omitempty"`
	Tombstone            *decommissionTombstoneMetadata `json:"tombstone,omitempty"`
	AffectedRefs         []string                       `json:"affectedRefs"`
	AffectedServices     []string                       `json:"affectedServices"`
}

func (b *localBackend) decommissionDryRun(req decommissionRequest) (decommissionResponse, error) {
	res := baseDecommissionResponse(req, "decommission", "dry-run")
	res.RequiresConfirmation = true
	fail := func(outcome, nextAction string, operationErr error) (decommissionResponse, error) {
		return b.decommissionFailureWithAudit("management_decommission_dry_run", req, res, outcome, nextAction, operationErr)
	}
	if !validSecretRef(req.Ref) || safeOperationToken(req.OperationID) == "" {
		return fail("invalid_ref", "provide_valid_ref_and_operation_id", errInvalidRef)
	}
	if b.locked() {
		return fail("locked", "unlock_broker", errLocked)
	}
	store, err := b.loadStore()
	if err != nil {
		return fail("degraded", "inspect_local_store", errBackendDegraded)
	}
	entry, ok := store.Secrets[strings.TrimSpace(req.Ref)]
	if !ok {
		if b.configuredSourceHasRef(req.Ref) {
			res.PolicyResult = "unsupported"
			return fail("unsupported", "use_provider_specific_decommission", errUnsupportedProvider)
		}
		return fail("missing_ref", "check_ref", errMissingRef)
	}
	res.ExpectedVersion = entry.Metadata.Version
	res.DependencyStatus = strings.ToLower(strings.TrimSpace(req.DependencyStatus))
	dependencySnapshot := strings.TrimSpace(req.DependencySnapshot)
	res.Dependencies = safeDecommissionDependencies(req.Dependencies)
	if res.DependencyStatus != "clear" || !validDependencySnapshot(dependencySnapshot) || len(res.Dependencies) != 0 || len(res.Dependencies) != len(safeList(req.Dependencies)) {
		res.PolicyResult = "denied"
		return fail("dependency_blocked", "clear_dependencies_and_refresh_snapshot", errDecommissionDependency)
	}
	res.DependencySnapshot = dependencySnapshot
	plan := decommissionPlan{
		Ref:                strings.TrimSpace(req.Ref),
		OperationID:        safeOperationToken(req.OperationID),
		ExpectedVersion:    entry.Metadata.Version,
		DependencyStatus:   "clear",
		DependencySnapshot: res.DependencySnapshot,
		ExpiresAt:          b.now().Add(decommissionPlanTTL),
	}
	signed, err := signDecommissionPlan(plan, b.masterKey)
	if err != nil {
		return fail("locked", "unlock_broker", errLocked)
	}
	if err := b.audit("management_decommission_dry_run", req.Ref, "dry_run_ready", req.ServiceID, req.RequestID); err != nil {
		return decommissionAuditUnavailable(res), errDecommissionAuditUnavailable
	}
	res.Outcome = "dry_run_ready"
	res.AuditStatus = "audit_recorded"
	res.PolicyResult = "allowed"
	res.NextAction = "confirm_signed_plan_before_expiry"
	res.Plan = &signed
	res.Recoverable = true
	return res, nil
}

func validDependencySnapshot(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func safeDecommissionDependencies(values []string) []string {
	clean := make([]string, 0, len(values))
	for _, value := range safeList(values) {
		if len(value) > 128 || (!strings.HasPrefix(value, "@") && !strings.HasPrefix(value, "service:")) || !validSecretRef(value) {
			continue
		}
		clean = append(clean, value)
	}
	return clean
}

func (b *localBackend) decommissionApply(req decommissionRequest) (decommissionResponse, error) {
	b.decommissionMu.Lock()
	defer b.decommissionMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()

	res := baseDecommissionResponse(req, "decommission", "apply")
	fail := func(outcome, nextAction string, operationErr error) (decommissionResponse, error) {
		return b.decommissionFailureWithAudit("management_decommission_apply", req, res, outcome, nextAction, operationErr)
	}
	if !validSecretRef(req.Ref) || !req.Confirm || strings.TrimSpace(req.Reason) == "" || req.Plan == nil {
		res.PolicyResult = "denied"
		return fail("policy_denied", "confirm_with_audit_reason_and_fresh_plan", errPolicyDenied)
	}
	plan := *req.Plan
	if err := verifyDecommissionPlan(plan, b.masterKey, b.now()); err != nil || strings.TrimSpace(req.Ref) != plan.Ref || safeOperationToken(req.OperationID) != plan.OperationID {
		return fail("stale_plan", "run_fresh_decommission_dry_run", errDecommissionStalePlan)
	}
	res.OperationID = plan.OperationID
	res.ExpectedVersion = plan.ExpectedVersion
	res.DependencyStatus = plan.DependencyStatus
	res.DependencySnapshot = plan.DependencySnapshot
	if b.locked() {
		return fail("locked", "unlock_broker", errLocked)
	}
	store, err := b.loadStore()
	if err != nil {
		return fail("degraded", "inspect_local_store", errBackendDegraded)
	}
	if tombstone, ok := store.Tombstones[plan.Ref]; ok && tombstone.State == "decommissioned" {
		if tombstone.DecommissionID != plan.OperationID || tombstone.Version != plan.ExpectedVersion {
			return fail("stale_plan", "inspect_tombstone_and_run_fresh_plan", errDecommissionStalePlan)
		}
		if err := b.audit("management_decommission_apply", plan.Ref, "applied", req.ServiceID, req.RequestID); err != nil {
			return decommissionAuditUnavailable(res), errDecommissionAuditUnavailable
		}
		return decommissionAppliedResponse(res, tombstone, "already_decommissioned"), nil
	}
	entry, ok := store.Secrets[plan.Ref]
	if !ok {
		return fail("missing_ref", "check_ref_or_tombstone", errMissingRef)
	}
	if entry.Metadata.Version != plan.ExpectedVersion {
		return fail("stale_plan", "run_fresh_decommission_dry_run", errDecommissionStalePlan)
	}
	if err := b.requireDecommissionAudit("management_decommission_apply", req); err != nil {
		return decommissionAuditUnavailable(res), err
	}
	now := b.now()
	tombstone := localSecretTombstone{Ref: plan.Ref, State: "decommissioned", Version: entry.Metadata.Version, DecommissionID: plan.OperationID, DecommissionedAt: now, Entry: entry}
	store.Tombstones[plan.Ref] = tombstone
	delete(store.Secrets, plan.Ref)
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		return fail("degraded", "retry_or_restore_store", errBackendDegraded)
	}
	_ = b.audit("management_decommission_apply", plan.Ref, "applied", req.ServiceID, req.RequestID)
	return decommissionAppliedResponse(res, tombstone, "retain_tombstone_until_recovery_window_expires"), nil
}

func (b *localBackend) decommissionRestore(req decommissionRequest) (decommissionResponse, error) {
	b.decommissionMu.Lock()
	defer b.decommissionMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()

	res := baseDecommissionResponse(req, "decommission_restore", "apply")
	fail := func(outcome, nextAction string, operationErr error) (decommissionResponse, error) {
		return b.decommissionFailureWithAudit("management_decommission_restore", req, res, outcome, nextAction, operationErr)
	}
	expectedVersion := strings.TrimSpace(req.ExpectedVersion)
	if !validSecretRef(req.Ref) || safeOperationToken(req.OperationID) == "" || !req.Confirm || strings.TrimSpace(req.Reason) == "" || expectedVersion == "" {
		res.PolicyResult = "denied"
		return fail("policy_denied", "confirm_restore_with_operation_id_expected_version_and_audit_reason", errPolicyDenied)
	}
	if b.locked() {
		return fail("locked", "unlock_broker", errLocked)
	}
	store, err := b.loadStore()
	if err != nil {
		return fail("degraded", "inspect_local_store", errBackendDegraded)
	}
	tombstone, ok := store.Tombstones[strings.TrimSpace(req.Ref)]
	if !ok || tombstone.Version != expectedVersion {
		return fail("stale_plan", "inspect_current_tombstone", errDecommissionStalePlan)
	}
	res.ExpectedVersion = expectedVersion
	operationID := safeOperationToken(req.OperationID)
	if active, exists := store.Secrets[tombstone.Ref]; exists {
		if tombstone.State == "restored" && tombstone.RestoreOperationID == operationID && active.Metadata.Version == tombstone.Version {
			if err := b.audit("management_decommission_restore", tombstone.Ref, "applied", req.ServiceID, req.RequestID); err != nil {
				return decommissionAuditUnavailable(res), errDecommissionAuditUnavailable
			}
			return decommissionRestoredResponse(res, tombstone, "already_restored"), nil
		}
		return fail("stale_plan", "inspect_active_secret_before_restore", errDecommissionStalePlan)
	}
	if tombstone.State != "decommissioned" {
		return fail("stale_plan", "inspect_current_tombstone", errDecommissionStalePlan)
	}
	if err := b.requireDecommissionAudit("management_decommission_restore", req); err != nil {
		return decommissionAuditUnavailable(res), err
	}
	now := b.now()
	store.Secrets[tombstone.Ref] = tombstone.Entry
	tombstone.State = "restored"
	tombstone.RestoreOperationID = operationID
	tombstone.RestoredAt = now
	store.Tombstones[tombstone.Ref] = tombstone
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		return fail("degraded", "retry_or_restore_store", errBackendDegraded)
	}
	_ = b.audit("management_decommission_restore", tombstone.Ref, "applied", req.ServiceID, req.RequestID)
	return decommissionRestoredResponse(res, tombstone, "secret_restored_from_encrypted_tombstone"), nil
}

func (b *localBackend) configuredSourceHasRef(ref string) bool {
	for _, source := range b.sources.enabledSources() {
		if _, ok := source.Refs[strings.TrimSpace(ref)]; ok {
			return true
		}
	}
	return false
}

func signDecommissionPlan(plan decommissionPlan, key string) (decommissionPlan, error) {
	if strings.TrimSpace(key) == "" {
		return plan, errLocked
	}
	plan.Signature = ""
	payload, err := json.Marshal(plan)
	if err != nil {
		return plan, err
	}
	mac := hmac.New(sha256.New, []byte("service-lasso:decommission-plan:v1:"+key))
	_, _ = mac.Write(payload)
	plan.Signature = "hmac-sha256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return plan, nil
}

func verifyDecommissionPlan(plan decommissionPlan, key string, now time.Time) error {
	if strings.TrimSpace(plan.Signature) == "" || strings.TrimSpace(plan.Ref) == "" || strings.TrimSpace(plan.OperationID) == "" || strings.TrimSpace(plan.ExpectedVersion) == "" || plan.DependencyStatus != "clear" || strings.TrimSpace(plan.DependencySnapshot) == "" || !plan.ExpiresAt.After(now) {
		return errDecommissionStalePlan
	}
	signature := plan.Signature
	signed, err := signDecommissionPlan(plan, key)
	if err != nil || !constantTimeTokenEqual(signature, signed.Signature) {
		return errDecommissionStalePlan
	}
	return nil
}

func (b *localBackend) requireDecommissionAudit(operation string, req decommissionRequest) error {
	if b == nil || strings.TrimSpace(b.auditPath) == "" {
		return errDecommissionAuditUnavailable
	}
	if err := b.audit(operation, req.Ref, "ready", req.ServiceID, req.RequestID); err != nil {
		return errDecommissionAuditUnavailable
	}
	return nil
}

func baseDecommissionResponse(req decommissionRequest, operation, mode string) decommissionResponse {
	return decommissionResponse{
		ServiceID:            serviceID,
		APIVersion:           apiVersion,
		RequestID:            strings.TrimSpace(req.RequestID),
		OperationID:          safeOperationToken(req.OperationID),
		Ref:                  strings.TrimSpace(req.Ref),
		Operation:            operation,
		Mode:                 mode,
		Outcome:              "pending",
		RequiresConfirmation: mode != "dry-run",
		AuditStatus:          "audit_pending",
		PolicyResult:         "unknown",
		DependencyStatus:     "unknown",
		Dependencies:         []string{},
		AffectedRefs:         safeList([]string{req.Ref}),
		AffectedServices:     safeList([]string{firstNonEmpty(req.ServiceID, ownerFromRef(req.Ref))}),
	}
}

func decommissionFailure(res decommissionResponse, outcome, nextAction string, _ error) decommissionResponse {
	res.Outcome = outcome
	res.Applied = false
	res.NextAction = nextAction
	if res.PolicyResult == "unknown" {
		res.PolicyResult = "denied"
	}
	return res
}

func (b *localBackend) decommissionFailureWithAudit(operation string, req decommissionRequest, res decommissionResponse, outcome, nextAction string, operationErr error) (decommissionResponse, error) {
	res = decommissionFailure(res, outcome, nextAction, operationErr)
	if b == nil || strings.TrimSpace(b.auditPath) == "" {
		return res, operationErr
	}
	if err := b.audit(operation, req.Ref, outcome, req.ServiceID, req.RequestID); err == nil {
		res.AuditStatus = "audit_recorded"
	} else {
		res.AuditStatus = "audit_unavailable"
	}
	return res, operationErr
}

func decommissionAuditUnavailable(res decommissionResponse) decommissionResponse {
	res = decommissionFailure(res, "audit_unavailable", "restore_audit_and_retry", errDecommissionAuditUnavailable)
	res.AuditStatus = "audit_unavailable"
	return res
}

func decommissionAppliedResponse(res decommissionResponse, tombstone localSecretTombstone, nextAction string) decommissionResponse {
	res.Outcome = "applied"
	res.Applied = true
	res.RequiresConfirmation = false
	res.AuditStatus = "audit_recorded"
	res.PolicyResult = "allowed"
	res.NextAction = nextAction
	res.Recoverable = true
	metadata := tombstoneMetadata(tombstone)
	res.Tombstone = &metadata
	return res
}

func decommissionRestoredResponse(res decommissionResponse, tombstone localSecretTombstone, nextAction string) decommissionResponse {
	res = decommissionAppliedResponse(res, tombstone, nextAction)
	res.Recoverable = false
	return res
}

func tombstoneMetadata(tombstone localSecretTombstone) decommissionTombstoneMetadata {
	return decommissionTombstoneMetadata{State: tombstone.State, Version: tombstone.Version, DecommissionID: tombstone.DecommissionID, RestoreOperationID: tombstone.RestoreOperationID, DecommissionedAt: tombstone.DecommissionedAt, RestoredAt: tombstone.RestoredAt}
}

func registerDecommissionHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	registerDecommissionAction(mux, security, "/v1/management/secrets/decommission/dry-run", backend.decommissionDryRun)
	registerDecommissionAction(mux, security, "/v1/management/secrets/decommission/apply", backend.decommissionApply)
	registerDecommissionAction(mux, security, "/v1/management/secrets/decommission/restore", backend.decommissionRestore)
}

func registerDecommissionAction(mux *http.ServeMux, security localAPISecurity, path string, handler func(decommissionRequest) (decommissionResponse, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST "+path+".", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req decommissionRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := handler(req)
		if err != nil {
			writeDecommissionError(w, err, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func writeDecommissionError(w http.ResponseWriter, err error, res decommissionResponse) {
	status := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, errInvalidRef):
		status = http.StatusBadRequest
	case errors.Is(err, errMissingRef):
		status = http.StatusNotFound
	case errors.Is(err, errPolicyDenied), errors.Is(err, errUnsupportedProvider):
		status = http.StatusForbidden
	case errors.Is(err, errDecommissionDependency), errors.Is(err, errDecommissionStalePlan):
		status = http.StatusConflict
	}
	writeJSON(w, status, res)
}
