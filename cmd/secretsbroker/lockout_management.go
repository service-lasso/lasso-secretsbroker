package main

import (
	"errors"
	"net/http"
	"strings"
)

type lockoutClearRequest struct {
	RequestID string `json:"requestId"`
	ServiceID string `json:"serviceId"`
	Scope     string `json:"scope"`
	Reason    string `json:"reason"`
}

type lockoutClearResponse struct {
	ServiceID    string `json:"serviceId"`
	APIVersion   string `json:"apiVersion"`
	RequestID    string `json:"requestId,omitempty"`
	Operation    string `json:"operation"`
	Outcome      string `json:"outcome"`
	Cleared      bool   `json:"cleared"`
	LockoutScope string `json:"lockoutScope"`
	AuditStatus  string `json:"auditStatus"`
	NextAction   string `json:"nextAction,omitempty"`
}

func clearLockout(backend *localBackend, security localAPISecurity, req lockoutClearRequest) (lockoutClearResponse, error) {
	scope := scrubLockoutScope(req.Scope)
	reason := scrubAuditField(req.Reason)
	service := firstNonEmpty(req.ServiceID, "@operator")
	res := lockoutClearResponse{
		ServiceID:    serviceID,
		APIVersion:   apiVersion,
		RequestID:    req.RequestID,
		Operation:    "lockout_clear",
		Outcome:      "pending",
		LockoutScope: scope,
		AuditStatus:  "audit_pending",
	}
	if scope == "" || strings.TrimSpace(reason) == "" {
		res.Outcome = "policy_denied"
		res.NextAction = "provide_scope_and_audit_reason"
		if backend != nil {
			if err := backend.audit("lockout_clear", scope, res.Outcome, service, req.RequestID); err != nil {
				res.Outcome = "audit_unavailable"
				res.AuditStatus = "audit_unavailable"
				res.NextAction = "restore_audit_and_retry"
				return res, err
			}
		}
		res.AuditStatus = "audit_recorded"
		return res, errPolicyDenied
	}

	var target *lockoutStore
	switch {
	case strings.HasPrefix(scope, "local_api:"):
		target = security.lockouts
	default:
		if backend != nil && backend.lockouts != nil {
			target = backend.lockouts
		}
	}
	auditResult := func(cleared bool) error {
		if backend == nil {
			return nil
		}
		outcome := "not_found"
		if cleared {
			outcome = "cleared"
		}
		return backend.audit("lockout_clear", scope, outcome, service, req.RequestID)
	}
	cleared, err := target.clearAfterAudit(scope, auditResult)
	if err != nil {
		res.Outcome = "audit_unavailable"
		res.AuditStatus = "audit_unavailable"
		res.NextAction = "restore_audit_and_retry"
		return res, err
	}
	res.Cleared = cleared
	res.AuditStatus = "audit_recorded"
	if cleared {
		res.Outcome = "cleared"
		res.NextAction = "retry_operation"
	} else {
		res.Outcome = "not_found"
		res.NextAction = "check_lockout_scope"
	}
	return res, nil
}

func scrubLockoutScope(scope string) string {
	scope = scrubAuditField(scope)
	if scope == "" || strings.ContainsAny(scope, " \r\n\t") {
		return ""
	}
	for _, prefix := range []string{"local_api:", "management:", "writeback:"} {
		if strings.HasPrefix(scope, prefix) {
			return scope
		}
	}
	return ""
}

func registerLockoutManagementHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/management/lockouts/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/management/lockouts/clear.", "invalid_ref", "")
			return
		}
		if !security.requireValidToken(w, r) {
			return
		}
		var req lockoutClearRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := clearLockout(backend, security, req)
		if err != nil {
			status := http.StatusForbidden
			if !errors.Is(err, errPolicyDenied) {
				status = http.StatusServiceUnavailable
			}
			writeJSON(w, status, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}
