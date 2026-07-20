package main

import (
	"net/http/httptest"
	"testing"
)

func TestOperationManifestRecordsAreCompleteAndRegistered(t *testing.T) {
	validMaturity := map[OperationMaturity]bool{
		OperationMaturityUnavailable: true,
		OperationMaturityPlanned:     true,
		OperationMaturityReadOnly:    true,
		OperationMaturityDryRun:      true,
		OperationMaturityExecutable:  true,
		OperationMaturityValidated:   true,
	}
	validClassification := map[OperationClassification]bool{
		OperationClassificationRead:     true,
		OperationClassificationMutation: true,
	}
	validScope := map[OperationScope]bool{
		OperationScopeBrokerLocal:    true,
		OperationScopeProviderRemote: true,
		OperationScopeSourceBoundary: true,
		OperationScopeMixed:          true,
	}

	backend := managedTestBackend(t)
	state := "ready"
	handler := newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "manifest-test-token"})
	seenIDs := map[string]bool{}
	seenRoutes := map[string]bool{}
	for _, operation := range defaultOperationManifest() {
		if operation.OperationID == "" || operation.Method == "" || operation.Path == "" {
			t.Fatalf("operation identity is incomplete: %#v", operation)
		}
		if seenIDs[operation.OperationID] {
			t.Fatalf("duplicate operation id %q", operation.OperationID)
		}
		seenIDs[operation.OperationID] = true
		key := operation.Method + " " + operation.Path
		if seenRoutes[key] {
			t.Fatalf("duplicate operation route %q", key)
		}
		seenRoutes[key] = true
		if !validMaturity[operation.Maturity] || !validClassification[operation.Classification] || !validScope[operation.Scope] {
			t.Fatalf("invalid operation classification for %s: %#v", key, operation)
		}
		if operation.LimitationCode == "" || operation.ReasonCode == "" || operation.NextAction == "" || operation.ProviderKinds == nil {
			t.Fatalf("operation safe decision fields are incomplete for %s: %#v", key, operation)
		}
		if operation.Classification == OperationClassificationMutation && operation.Maturity == OperationMaturityReadOnly {
			t.Fatalf("mutation cannot have read-only maturity: %s", key)
		}

		request := httptest.NewRequest(operation.Method, operation.Path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == 404 {
			t.Errorf("manifest route is not registered: %s", key)
		}
	}
}

func TestProviderOperationMatricesDoNotClaimUnimplementedRemoteApply(t *testing.T) {
	tests := []struct {
		kind     string
		path     string
		maturity OperationMaturity
	}{
		{kind: "local-encrypted-store", path: "/v1/management/secrets/edit/apply", maturity: OperationMaturityValidated},
		{kind: "local-encrypted-store", path: "/v1/providers/migration/apply", maturity: OperationMaturityPlanned},
		{kind: "local-encrypted-store", path: "/v1/management/secrets/policy/apply", maturity: OperationMaturityPlanned},
		{kind: "vault", path: "/v1/resolve", maturity: OperationMaturityValidated},
		{kind: "vault", path: "/v1/management/secrets/edit/dry-run", maturity: OperationMaturityDryRun},
		{kind: "vault", path: "/v1/management/secrets/edit/apply", maturity: OperationMaturityUnavailable},
		{kind: "vault", path: "/v1/management/secrets/rotation/dry-run", maturity: OperationMaturityPlanned},
		{kind: "openbao", path: "/v1/management/secrets/reset/apply", maturity: OperationMaturityUnavailable},
		{kind: "aws-secrets-manager", path: "/v1/management/secrets/rotation/dry-run", maturity: OperationMaturityDryRun},
		{kind: "aws-secrets-manager", path: "/v1/management/secrets/reset/apply", maturity: OperationMaturityUnavailable},
		{kind: "env", path: "/v1/resolve", maturity: OperationMaturityValidated},
		{kind: "env", path: "/v1/management/secrets/edit/apply", maturity: OperationMaturityUnavailable},
		{kind: "file", path: "/v1/management/secrets/edit/apply", maturity: OperationMaturityUnavailable},
		{kind: "exec", path: "/v1/management/secrets/edit/apply", maturity: OperationMaturityUnavailable},
	}

	for _, test := range tests {
		t.Run(test.kind+test.path, func(t *testing.T) {
			operation := findProviderOperation(t, providerOperationCapabilitiesForKind(test.kind), test.path)
			if operation.Maturity != test.maturity {
				t.Fatalf("maturity = %q; want %q; operation=%#v", operation.Maturity, test.maturity, operation)
			}
		})
	}
}

func TestConnectionLifecycleAndAuditStateFailClosed(t *testing.T) {
	tests := []struct {
		name        string
		lifecycle   SourceLifecycle
		auditStatus string
		limitation  string
		nextAction  string
	}{
		{name: "auth-required", lifecycle: normalizeSourceLifecycle("source_auth_required"), auditStatus: "audit_available", limitation: "source_auth_required", nextAction: "reconnect_source"},
		{name: "policy-denied", lifecycle: normalizeSourceLifecycle("policy_denied"), auditStatus: "audit_available", limitation: "policy_denied", nextAction: "review_policy"},
		{name: "audit-unavailable", lifecycle: normalizeSourceLifecycle("ready"), auditStatus: "audit_unavailable", limitation: "audit_unavailable", nextAction: "restore_audit"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := providerOperationCapabilitiesForSource("vault", test.lifecycle, test.auditStatus)
			for _, operation := range operations {
				if operation.Maturity == OperationMaturityPlanned || operation.Maturity == OperationMaturityUnavailable {
					continue
				}
				if test.auditStatus == "audit_unavailable" && !operation.AuditRequired {
					continue
				}
				t.Fatalf("operation did not fail closed: %#v", operation)
			}
			resolve := findProviderOperation(t, operations, "/v1/resolve")
			if resolve.Maturity != OperationMaturityUnavailable || resolve.LimitationCode != test.limitation || resolve.NextAction != test.nextAction {
				t.Fatalf("resolve fail-closed result = %#v", resolve)
			}
		})
	}
}

func TestMissingAuditConfigurationDisablesAuditedSourceOperations(t *testing.T) {
	backend := newLocalBackend(t.TempDir()+"/store.json", "", "test-master-key")
	registry := defaultSourceRegistry(backend)
	if registry.Sources[0].AuditStatus != "audit_unavailable" {
		t.Fatalf("audit status = %q", registry.Sources[0].AuditStatus)
	}
	resolve := findProviderOperation(t, registry.Sources[0].Operations, "/v1/resolve")
	if resolve.Maturity != OperationMaturityUnavailable || resolve.LimitationCode != "audit_unavailable" {
		t.Fatalf("audited operation should fail closed: %#v", resolve)
	}
}

func TestProviderAndSourceResponsesIncludeConnectionScopedOperations(t *testing.T) {
	backend := managedTestBackend(t)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "vault-auth", Kind: "vault", DisplayName: "Vault auth required", Enabled: true, Address: "https://vault.invalid",
	}}}

	registry := defaultSourceRegistry(backend)
	vaultSource := registry.Sources[1]
	if vaultSource.Outcome != "source_auth_required" {
		t.Fatalf("vault source outcome = %q", vaultSource.Outcome)
	}
	if findProviderOperation(t, vaultSource.Operations, "/v1/resolve").Maturity != OperationMaturityUnavailable {
		t.Fatalf("auth-required source resolve should be unavailable")
	}

	status := backend.providerConfigStatusResponse()
	if status.ContractVersion != contractVersion || status.ManifestVersion != operationManifestVersion {
		t.Fatalf("provider status manifest identity = %q/%q", status.ContractVersion, status.ManifestVersion)
	}
	vaultProvider := status.Providers[1]
	if vaultProvider.ProviderID != "vault-auth" || findProviderOperation(t, vaultProvider.Operations, "/v1/resolve").Maturity != OperationMaturityUnavailable {
		t.Fatalf("provider connection operations do not reflect auth state: %#v", vaultProvider)
	}

	for _, kind := range []string{"local-encrypted-store", "vault", "openbao", "aws-secrets-manager", "env", "file", "exec"} {
		capability := providerCapabilitiesByKind(kind)
		if !capability.Supported || len(capability.Operations) == 0 {
			t.Fatalf("provider family %q has no explicit operation matrix: %#v", kind, capability)
		}
	}
	capabilities := backend.providerCapabilitiesResponse()
	if capabilities.ContractVersion != contractVersion || capabilities.ManifestVersion != operationManifestVersion {
		t.Fatalf("provider capability manifest identity = %q/%q", capabilities.ContractVersion, capabilities.ManifestVersion)
	}
}

func findProviderOperation(t *testing.T, operations []OperationCapability, path string) OperationCapability {
	t.Helper()
	for _, operation := range operations {
		if operation.Path == path {
			return operation
		}
	}
	t.Fatalf("missing provider operation %s", path)
	return OperationCapability{}
}
