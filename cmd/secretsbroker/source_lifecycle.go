package main

import "strings"

const defaultSourceRetryAfterMs = 30000

type SourceLifecycle struct {
	State        string `json:"state"`
	Outcome      string `json:"outcome"`
	NextAction   string `json:"nextAction,omitempty"`
	Retryable    bool   `json:"retryable"`
	RetryAfterMs int    `json:"retryAfterMs,omitempty"`
}

func normalizeSourceLifecycle(outcome string) SourceLifecycle {
	outcome = strings.TrimSpace(outcome)
	if outcome == "" {
		outcome = "source_unavailable"
	}
	switch outcome {
	case "ready":
		return SourceLifecycle{State: "connected", Outcome: outcome, Retryable: false}
	case "missing_ref":
		return SourceLifecycle{State: "missing", Outcome: outcome, NextAction: "check_ref", Retryable: false}
	case "policy_denied":
		return SourceLifecycle{State: "denied", Outcome: outcome, NextAction: "review_policy", Retryable: false}
	case "source_auth_required":
		return SourceLifecycle{State: "auth_required", Outcome: outcome, NextAction: "reconnect_source", Retryable: false}
	case "identity_expired":
		return SourceLifecycle{State: "revoked", Outcome: outcome, NextAction: "renew_identity", Retryable: false}
	case "locked":
		return SourceLifecycle{State: "reconnect_required", Outcome: outcome, NextAction: "unlock_or_unseal_source", Retryable: false}
	case "invalid_ref":
		return SourceLifecycle{State: "config_error", Outcome: outcome, NextAction: "fix_source_mapping", Retryable: false}
	case "source_unavailable", "degraded":
		return SourceLifecycle{State: "degraded", Outcome: outcome, NextAction: "retry_or_inspect_source", Retryable: true, RetryAfterMs: defaultSourceRetryAfterMs}
	default:
		return SourceLifecycle{State: "degraded", Outcome: outcome, NextAction: "inspect_source", Retryable: true, RetryAfterMs: defaultSourceRetryAfterMs}
	}
}

func disabledSourceLifecycle() SourceLifecycle {
	return SourceLifecycle{State: "disabled", Outcome: "disabled", NextAction: "enable_source", Retryable: false}
}
