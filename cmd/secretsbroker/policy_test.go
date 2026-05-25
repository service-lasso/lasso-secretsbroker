package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEvaluateServiceSecretsPolicyDecisions(t *testing.T) {
	policy := &serviceSecretsPolicy{
		Resolve:   []string{"services/api/runtime/*"},
		Writeback: []string{"services/api/generated/*"},
		Manage:    []string{"services/api/runtime/*"},
	}
	tests := []struct {
		name       string
		serviceID  string
		operation  string
		ref        string
		policy     *serviceSecretsPolicy
		want       string
		reasonCode string
	}{
		{name: "resolve allowed by prefix", serviceID: "api", operation: "resolve", ref: "services/api/runtime/API_TOKEN", policy: policy, want: "allowed", reasonCode: "policy_match"},
		{name: "writeback denied by namespace", serviceID: "api", operation: "writeback", ref: "services/api/runtime/API_TOKEN", policy: policy, want: "denied", reasonCode: "policy_no_match"},
		{name: "manage uses management assignment", serviceID: "@serviceadmin", operation: "reveal", ref: "services/api/runtime/API_TOKEN", policy: policy, want: "allowed", reasonCode: "policy_match"},
		{name: "missing policy is unknown", serviceID: "api", operation: "resolve", ref: "services/api/runtime/API_TOKEN", policy: nil, want: "unknown", reasonCode: "policy_missing"},
		{name: "unknown operation is unknown", serviceID: "api", operation: "rotate", ref: "services/api/runtime/API_TOKEN", policy: policy, want: "unknown", reasonCode: "policy_operation_unknown"},
		{name: "malformed ref is denied", serviceID: "api", operation: "resolve", ref: "services/api/../API_TOKEN", policy: policy, want: "denied", reasonCode: "invalid_policy_subject"},
		{name: "service id mismatch is denied", serviceID: "worker", operation: "resolve", ref: "services/api/runtime/API_TOKEN", policy: policy, want: "denied", reasonCode: "service_id_mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := evaluateServiceSecretsPolicy(tt.serviceID, tt.operation, tt.ref, tt.policy)
			if decision.Outcome != tt.want || decision.ReasonCode != tt.reasonCode {
				t.Fatalf("decision = %#v, want outcome %q reason %q", decision, tt.want, tt.reasonCode)
			}
		})
	}
}

func TestResolveHonorsManifestPolicyWithoutLeakingValue(t *testing.T) {
	backend := testBackend(t)
	allowedRef := "services/api/runtime/API_TOKEN"
	deniedRef := "services/api/private/ROOT_TOKEN"
	allowedValue := "allowed-secret-value"
	deniedValue := "denied-secret-value"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: allowedRef, Value: allowedValue}); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.writeSecret(writeSecretRequest{Ref: deniedRef, Value: deniedValue}); err != nil {
		t.Fatal(err)
	}

	res := backend.resolve(resolveRequest{
		RequestID: "req-policy-resolve",
		ServiceID: "api",
		Secrets:   &serviceSecretsPolicy{Resolve: []string{"services/api/runtime/*"}},
		Refs:      []string{allowedRef, deniedRef},
	})
	if len(res.Results) != 2 {
		t.Fatalf("results = %#v", res.Results)
	}
	if res.Results[0].Outcome != "ready" || res.Results[0].Value != allowedValue {
		t.Fatalf("allowed result = %#v", res.Results[0])
	}
	if res.Results[1].Outcome != "policy_denied" || res.Results[1].Value != "" {
		t.Fatalf("denied result = %#v", res.Results[1])
	}
	encoded, err := json.Marshal(res.Results[1])
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, encoded, deniedValue)
}

func TestWritebackHonorsManifestPolicyWithoutLeakingValue(t *testing.T) {
	backend := testBackend(t)
	value := "generated-secret-value"
	allowed := generatedSecretCaptureRequest{
		RequestID: "req-writeback-allowed",
		Identity:  writebackIdentity{ServiceID: "api", ExpiresAt: "2026-05-07T00:05:00Z"},
		Policy:    writebackPolicy{AllowedNamespaces: []string{"services/api"}, AllowedOperations: []string{"create"}},
		Secrets:   &serviceSecretsPolicy{Writeback: []string{"services/api/generated/*"}},
		Operation: "create",
		Namespace: "services/api",
		Ref:       "generated/API_TOKEN",
		Value:     value,
	}
	res, err := backend.captureGeneratedSecret(allowed)
	if err != nil || res.Outcome != "ready" {
		t.Fatalf("allowed writeback = %#v err=%v", res, err)
	}

	denied := allowed
	denied.RequestID = "req-writeback-denied"
	denied.Ref = "runtime/API_TOKEN"
	res, err = backend.captureGeneratedSecret(denied)
	if !errors.Is(err, errPolicyDenied) || res.Outcome != "policy_denied" {
		t.Fatalf("denied writeback = %#v err=%v", res, err)
	}
	encoded, marshalErr := json.Marshal(res)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), value) {
		t.Fatalf("policy-denied writeback leaked value: %s", encoded)
	}
}
