package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

var errInvalidRecoveryPolicy = errors.New("invalid recovery policy metadata")

type recoveryPolicyMetadata struct {
	PolicyID              string     `json:"policyId"`
	KeyID                 string     `json:"keyId"`
	KeyVersion            string     `json:"keyVersion"`
	Threshold             int        `json:"threshold"`
	ShareCount            int        `json:"shareCount"`
	ShareFingerprints     []string   `json:"shareFingerprints"`
	RecipientFingerprints []string   `json:"recipientFingerprints,omitempty"`
	CreatedAt             time.Time  `json:"createdAt"`
	RotatedAt             *time.Time `json:"rotatedAt,omitempty"`
	RevokedAt             *time.Time `json:"revokedAt,omitempty"`
	Status                string     `json:"status"`
	NextAction            string     `json:"nextAction"`
}

type recoveryPolicyRequest struct {
	RequestID             string     `json:"requestId,omitempty"`
	ServiceID             string     `json:"serviceId,omitempty"`
	PolicyID              string     `json:"policyId"`
	KeyID                 string     `json:"keyId"`
	KeyVersion            string     `json:"keyVersion"`
	Threshold             int        `json:"threshold"`
	ShareCount            int        `json:"shareCount"`
	ShareFingerprints     []string   `json:"shareFingerprints"`
	RecipientFingerprints []string   `json:"recipientFingerprints,omitempty"`
	CreatedAt             *time.Time `json:"createdAt,omitempty"`
	RotatedAt             *time.Time `json:"rotatedAt,omitempty"`
	RevokedAt             *time.Time `json:"revokedAt,omitempty"`
	Status                string     `json:"status,omitempty"`
}

type recoveryPolicyStatusResponse struct {
	ServiceID  string                  `json:"serviceId"`
	APIVersion string                  `json:"apiVersion"`
	Outcome    string                  `json:"outcome"`
	Policy     *recoveryPolicyMetadata `json:"policy,omitempty"`
	NextAction string                  `json:"nextAction"`
}

func (b *localBackend) recoveryPolicyStatus() (recoveryPolicyStatusResponse, error) {
	res := recoveryPolicyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "setup_needed", NextAction: "enroll_recovery_policy"}
	store, err := b.loadStore()
	if err != nil {
		res.Outcome = "degraded"
		res.NextAction = "inspect_recovery_policy_state"
		_ = b.auditRecoveryPolicy("recovery_policy_status", nil, "degraded", "", "")
		return res, errBackendDegraded
	}
	if store.Recovery == nil {
		_ = b.auditRecoveryPolicy("recovery_policy_status", nil, "setup_needed", "", "")
		return res, nil
	}
	policy, err := normalizeRecoveryPolicyRequest(recoveryPolicyRequest{
		PolicyID:              store.Recovery.PolicyID,
		KeyID:                 store.Recovery.KeyID,
		KeyVersion:            store.Recovery.KeyVersion,
		Threshold:             store.Recovery.Threshold,
		ShareCount:            store.Recovery.ShareCount,
		ShareFingerprints:     store.Recovery.ShareFingerprints,
		RecipientFingerprints: store.Recovery.RecipientFingerprints,
		CreatedAt:             &store.Recovery.CreatedAt,
		RotatedAt:             store.Recovery.RotatedAt,
		RevokedAt:             store.Recovery.RevokedAt,
		Status:                store.Recovery.Status,
	}, b.now())
	if err != nil {
		res.Outcome = "degraded"
		res.NextAction = "repair_recovery_policy_metadata"
		_ = b.auditRecoveryPolicy("recovery_policy_status", store.Recovery, "degraded", "", "")
		return res, errInvalidRecoveryPolicy
	}
	res.Outcome = policy.Status
	res.Policy = &policy
	res.NextAction = policy.NextAction
	_ = b.auditRecoveryPolicy("recovery_policy_status", &policy, policy.Status, "", "")
	return res, nil
}

func (b *localBackend) upsertRecoveryPolicy(req recoveryPolicyRequest) (recoveryPolicyStatusResponse, error) {
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	res := recoveryPolicyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "degraded", NextAction: "repair_recovery_policy_metadata"}
	store, err := b.loadStore()
	if err != nil {
		_ = b.auditRecoveryPolicy("recovery_policy_update", nil, "degraded", req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	if req.CreatedAt == nil && store.Recovery != nil && store.Recovery.PolicyID == strings.TrimSpace(req.PolicyID) && !store.Recovery.CreatedAt.IsZero() {
		createdAt := store.Recovery.CreatedAt
		req.CreatedAt = &createdAt
	}
	policy, err := normalizeRecoveryPolicyRequest(req, b.now())
	if err != nil {
		_ = b.auditRecoveryPolicy("recovery_policy_update", nil, "policy_denied", req.ServiceID, req.RequestID)
		res.Outcome = "policy_denied"
		res.NextAction = "provide_complete_safe_recovery_metadata"
		return res, err
	}
	operation := "recovery_policy_create"
	if store.Recovery != nil {
		operation = "recovery_policy_update"
	}
	store.Recovery = &policy
	store.UpdatedAt = b.now()
	if err := b.saveStore(store); err != nil {
		_ = b.auditRecoveryPolicy(operation, &policy, "degraded", req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	_ = b.auditRecoveryPolicy(operation, &policy, policy.Status, req.ServiceID, req.RequestID)
	return recoveryPolicyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: policy.Status, Policy: &policy, NextAction: policy.NextAction}, nil
}

func (b *localBackend) revokeRecoveryPolicy(policyID, serviceIDValue, requestID string) (recoveryPolicyStatusResponse, error) {
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	store, err := b.loadStore()
	if err != nil {
		_ = b.auditRecoveryPolicy("recovery_policy_revoke", nil, "degraded", serviceIDValue, requestID)
		return recoveryPolicyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "degraded", NextAction: "inspect_recovery_policy_state"}, errBackendDegraded
	}
	if store.Recovery == nil || strings.TrimSpace(policyID) == "" || store.Recovery.PolicyID != strings.TrimSpace(policyID) {
		_ = b.auditRecoveryPolicy("recovery_policy_revoke", store.Recovery, "missing_ref", serviceIDValue, requestID)
		return recoveryPolicyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "missing_ref", NextAction: "enroll_recovery_policy"}, errMissingRef
	}
	now := b.now()
	req := recoveryPolicyRequest{
		PolicyID:              store.Recovery.PolicyID,
		KeyID:                 store.Recovery.KeyID,
		KeyVersion:            store.Recovery.KeyVersion,
		Threshold:             store.Recovery.Threshold,
		ShareCount:            store.Recovery.ShareCount,
		ShareFingerprints:     store.Recovery.ShareFingerprints,
		RecipientFingerprints: store.Recovery.RecipientFingerprints,
		CreatedAt:             &store.Recovery.CreatedAt,
		RotatedAt:             store.Recovery.RotatedAt,
		RevokedAt:             &now,
		Status:                "revoked",
		ServiceID:             serviceIDValue,
		RequestID:             requestID,
	}
	policy, err := normalizeRecoveryPolicyRequest(req, now)
	if err != nil {
		_ = b.auditRecoveryPolicy("recovery_policy_revoke", store.Recovery, "degraded", serviceIDValue, requestID)
		return recoveryPolicyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "degraded", NextAction: "repair_recovery_policy_metadata"}, err
	}
	store.Recovery = &policy
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		_ = b.auditRecoveryPolicy("recovery_policy_revoke", &policy, "degraded", serviceIDValue, requestID)
		return recoveryPolicyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "degraded", NextAction: "inspect_recovery_policy_state"}, errBackendDegraded
	}
	_ = b.auditRecoveryPolicy("recovery_policy_revoke", &policy, policy.Status, serviceIDValue, requestID)
	return recoveryPolicyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: policy.Status, Policy: &policy, NextAction: policy.NextAction}, nil
}

func normalizeRecoveryPolicyRequest(req recoveryPolicyRequest, now time.Time) (recoveryPolicyMetadata, error) {
	policy := recoveryPolicyMetadata{
		PolicyID:              scrubAuditField(req.PolicyID),
		KeyID:                 scrubAuditField(req.KeyID),
		KeyVersion:            scrubAuditField(req.KeyVersion),
		Threshold:             req.Threshold,
		ShareCount:            req.ShareCount,
		ShareFingerprints:     normalizeSafeFingerprints(req.ShareFingerprints),
		RecipientFingerprints: normalizeSafeFingerprints(req.RecipientFingerprints),
		Status:                scrubAuditField(req.Status),
	}
	if policy.KeyVersion == "" {
		policy.KeyVersion = masterKeyVersion
	}
	if policy.Status == "" {
		policy.Status = "active"
	}
	if req.CreatedAt != nil {
		policy.CreatedAt = req.CreatedAt.UTC()
	} else {
		policy.CreatedAt = now.UTC()
	}
	if req.RotatedAt != nil {
		rotated := req.RotatedAt.UTC()
		policy.RotatedAt = &rotated
	}
	if req.RevokedAt != nil {
		revoked := req.RevokedAt.UTC()
		policy.RevokedAt = &revoked
	}
	if policy.Status == "rotated" && policy.RotatedAt == nil {
		rotated := now.UTC()
		policy.RotatedAt = &rotated
	}
	if policy.Status == "revoked" && policy.RevokedAt == nil {
		revoked := now.UTC()
		policy.RevokedAt = &revoked
	}
	if err := validateRecoveryPolicyMetadata(policy); err != nil {
		return recoveryPolicyMetadata{}, err
	}
	policy.NextAction = nextActionForRecoveryPolicy(policy)
	return policy, nil
}

func validateRecoveryPolicyMetadata(policy recoveryPolicyMetadata) error {
	if !validSafeMetadataID(policy.PolicyID) || !validSafeMetadataID(policy.KeyID) || !validSafeMetadataID(policy.KeyVersion) {
		return errInvalidRecoveryPolicy
	}
	if policy.Threshold < 1 || policy.ShareCount < 1 || policy.Threshold > policy.ShareCount {
		return errInvalidRecoveryPolicy
	}
	if len(policy.ShareFingerprints) != policy.ShareCount || hasDuplicate(policy.ShareFingerprints) {
		return errInvalidRecoveryPolicy
	}
	for _, value := range append(append([]string{}, policy.ShareFingerprints...), policy.RecipientFingerprints...) {
		if !validSafeMetadataID(value) {
			return errInvalidRecoveryPolicy
		}
	}
	switch policy.Status {
	case "active", "rotated", "revoked":
	default:
		return errInvalidRecoveryPolicy
	}
	if policy.CreatedAt.IsZero() {
		return errInvalidRecoveryPolicy
	}
	if policy.Status == "rotated" && policy.RotatedAt == nil {
		return errInvalidRecoveryPolicy
	}
	if policy.Status == "revoked" && policy.RevokedAt == nil {
		return errInvalidRecoveryPolicy
	}
	return nil
}

func normalizeSafeFingerprints(values []string) []string {
	clean := make([]string, 0, len(values))
	for _, value := range values {
		value = scrubAuditField(value)
		if value != "" {
			clean = append(clean, value)
		}
	}
	return clean
}

func validSafeMetadataID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func hasDuplicate(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func nextActionForRecoveryPolicy(policy recoveryPolicyMetadata) string {
	switch policy.Status {
	case "active":
		return "monitor_recovery_policy"
	case "rotated":
		return "verify_new_recovery_material"
	case "revoked":
		return "enroll_replacement_recovery_policy"
	default:
		return "repair_recovery_policy_metadata"
	}
}

func (b *localBackend) auditRecoveryPolicy(operation string, policy *recoveryPolicyMetadata, outcome, requestServiceID, requestID string) error {
	event := auditEvent{TS: b.now(), Operation: operation, Outcome: outcome, ServiceID: requestServiceID, RequestID: requestID}
	if policy != nil {
		event.PolicyID = policy.PolicyID
		event.KeyID = policy.KeyID
		event.State = policy.Status
	}
	return b.writeAuditEvent(event)
}

func registerRecoveryPolicyHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/recovery/policy", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			res, err := backend.recoveryPolicyStatus()
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, res)
				return
			}
			writeJSON(w, http.StatusOK, res)
		case http.MethodPost:
			if !security.require(w, r) {
				return
			}
			var req recoveryPolicyRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSecretBearingRequestBytes))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				writeAPIError(w, http.StatusBadRequest, "invalid_recovery_policy", "Recovery policy metadata must use the safe metadata contract.", "policy_denied", "provide_complete_safe_recovery_metadata")
				return
			}
			res, err := backend.upsertRecoveryPolicy(req)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, res)
				return
			}
			writeJSON(w, http.StatusOK, res)
		default:
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET or POST /v1/recovery/policy.", "invalid_ref", "")
		}
	})
}
