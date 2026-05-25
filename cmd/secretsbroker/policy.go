package main

import "strings"

type serviceSecretsPolicy struct {
	Resolve   []string `json:"resolve,omitempty"`
	Writeback []string `json:"writeback,omitempty"`
	Manage    []string `json:"manage,omitempty"`
}

type secretPolicyDecision struct {
	ServiceID  string `json:"serviceId"`
	Operation  string `json:"operation"`
	Ref        string `json:"ref"`
	Outcome    string `json:"outcome"`
	NextAction string `json:"nextAction"`
	ReasonCode string `json:"reasonCode"`
}

func evaluateServiceSecretsPolicy(serviceID, operation, ref string, policy *serviceSecretsPolicy) secretPolicyDecision {
	serviceID = strings.TrimSpace(serviceID)
	operation = strings.TrimSpace(operation)
	ref = strings.Trim(strings.TrimSpace(ref), "/")
	decision := secretPolicyDecision{
		ServiceID:  serviceID,
		Operation:  operation,
		Ref:        ref,
		Outcome:    "unknown",
		NextAction: "provide_service_secret_policy",
		ReasonCode: "policy_missing",
	}
	if serviceID == "" || operation == "" || !validSecretRef(ref) {
		decision.Outcome = "denied"
		decision.NextAction = "provide_valid_service_identity_and_ref"
		decision.ReasonCode = "invalid_policy_subject"
		return decision
	}
	if policy == nil {
		return decision
	}
	if (operation == "resolve" || operation == "writeback") && serviceRefOwnerMismatch(serviceID, ref) {
		decision.Outcome = "denied"
		decision.NextAction = "use_matching_service_identity"
		decision.ReasonCode = "service_id_mismatch"
		return decision
	}
	patterns, known := policyPatternsForOperation(operation, *policy)
	if !known {
		decision.Outcome = "unknown"
		decision.NextAction = "use_supported_policy_operation"
		decision.ReasonCode = "policy_operation_unknown"
		return decision
	}
	if len(patterns) == 0 {
		decision.Outcome = "denied"
		decision.NextAction = "add_service_secret_policy_assignment"
		decision.ReasonCode = "policy_empty"
		return decision
	}
	for _, pattern := range patterns {
		if secretPolicyPatternMatches(ref, pattern) {
			decision.Outcome = "allowed"
			decision.NextAction = ""
			decision.ReasonCode = "policy_match"
			return decision
		}
	}
	decision.Outcome = "denied"
	decision.NextAction = "add_service_secret_policy_assignment"
	decision.ReasonCode = "policy_no_match"
	return decision
}

func policyPatternsForOperation(operation string, policy serviceSecretsPolicy) ([]string, bool) {
	switch operation {
	case "resolve":
		return safeList(policy.Resolve), true
	case "writeback":
		return safeList(policy.Writeback), true
	case "reveal", "edit", "reset", "migration", "policy_apply", "manage":
		return safeList(policy.Manage), true
	default:
		return nil, false
	}
}

func secretPolicyPatternMatches(ref, pattern string) bool {
	ref = strings.Trim(strings.TrimSpace(ref), "/")
	pattern = strings.Trim(strings.TrimSpace(pattern), "/")
	if ref == "" || pattern == "" || strings.Contains(pattern, "..") || strings.ContainsAny(pattern, " \t\r\n") {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return ref == prefix || strings.HasPrefix(ref, prefix+"/")
	}
	return ref == pattern
}

func serviceRefOwnerMismatch(serviceID, ref string) bool {
	owner := ownerFromRef(ref)
	return owner != "" && owner != "unknown" && owner != serviceID
}
