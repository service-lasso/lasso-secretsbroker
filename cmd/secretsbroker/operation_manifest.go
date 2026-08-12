package main

import (
	"net/http"
	"strings"
)

const operationManifestVersion = "1.0.0"

type OperationMaturity string

const (
	OperationMaturityUnavailable OperationMaturity = "unavailable"
	OperationMaturityPlanned     OperationMaturity = "planned"
	OperationMaturityReadOnly    OperationMaturity = "read-only"
	OperationMaturityDryRun      OperationMaturity = "dry-run"
	OperationMaturityExecutable  OperationMaturity = "executable"
	OperationMaturityValidated   OperationMaturity = "validated"
)

type OperationClassification string

const (
	OperationClassificationRead     OperationClassification = "read"
	OperationClassificationMutation OperationClassification = "mutation"
)

type OperationScope string

const (
	OperationScopeBrokerLocal    OperationScope = "broker-local"
	OperationScopeProviderRemote OperationScope = "provider-remote"
	OperationScopeSourceBoundary OperationScope = "source-boundary"
	OperationScopeMixed          OperationScope = "mixed"
)

type OperationCompletionMode string

const (
	OperationCompletionSynchronous  OperationCompletionMode = "synchronous"
	OperationCompletionAsynchronous OperationCompletionMode = "asynchronous"
)

// OperationCapability is the canonical machine-readable release statement for
// one Broker HTTP operation. Codes are intentionally safe for logs and UI.
type OperationCapability struct {
	OperationID            string                  `json:"operationId"`
	Method                 string                  `json:"method"`
	Path                   string                  `json:"path"`
	Maturity               OperationMaturity       `json:"maturity"`
	Classification         OperationClassification `json:"classification"`
	AuthenticationRequired bool                    `json:"authenticationRequired"`
	PolicyRequired         bool                    `json:"policyRequired"`
	AuditRequired          bool                    `json:"auditRequired"`
	Scope                  OperationScope          `json:"scope"`
	ProviderKinds          []string                `json:"providerKinds"`
	CompletionMode         OperationCompletionMode `json:"completionMode"`
	StatusPath             string                  `json:"statusPath,omitempty"`
	LimitationCode         string                  `json:"limitationCode"`
	ReasonCode             string                  `json:"reasonCode"`
	NextAction             string                  `json:"nextAction"`
}

func operationManifestID(method, path string) string {
	replacer := strings.NewReplacer("/", "_", "-", "_", "{", "", "}", "")
	return strings.ToLower(method) + strings.Trim(replacer.Replace(path), "_")
}

func supportedProviderKinds() []string {
	return []string{
		"local-encrypted-store",
		"vault",
		"openbao",
		"aws-secrets-manager",
		"env",
		"file",
		"exec",
		"bitwarden-bws",
		"onepassword-cli",
	}
}

func manifestOperation(method, path string, maturity OperationMaturity, classification OperationClassification, authRequired, policyRequired, auditRequired bool, scope OperationScope, providerKinds []string, limitationCode string) OperationCapability {
	reasonCode, nextAction := maturityCodes(maturity)
	return OperationCapability{
		OperationID:            operationManifestID(method, path),
		Method:                 method,
		Path:                   path,
		Maturity:               maturity,
		Classification:         classification,
		AuthenticationRequired: authRequired,
		PolicyRequired:         policyRequired,
		AuditRequired:          auditRequired,
		Scope:                  scope,
		ProviderKinds:          append([]string{}, providerKinds...),
		CompletionMode:         OperationCompletionSynchronous,
		LimitationCode:         limitationCode,
		ReasonCode:             reasonCode,
		NextAction:             nextAction,
	}
}

func maturityCodes(maturity OperationMaturity) (string, string) {
	switch maturity {
	case OperationMaturityReadOnly:
		return "implemented_read_only", "read_when_authorized"
	case OperationMaturityDryRun:
		return "implemented_dry_run", "review_plan_before_apply"
	case OperationMaturityExecutable:
		return "implemented_executable", "satisfy_runtime_preconditions"
	case OperationMaturityValidated:
		return "implemented_and_validated", "invoke_with_required_controls"
	case OperationMaturityPlanned:
		return "planning_only_not_executable", "do_not_enable_apply"
	default:
		return "operation_not_implemented", "do_not_enable_operation"
	}
}

func defaultOperationManifest() []OperationCapability {
	providers := supportedProviderKinds()
	local := []string{"local-encrypted-store"}
	localAndAWS := []string{"local-encrypted-store", "aws-secrets-manager"}

	return []OperationCapability{
		manifestOperation(http.MethodGet, "/health", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeBrokerLocal, nil, "liveness_only"),
		manifestOperation(http.MethodGet, "/ready", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeBrokerLocal, nil, "readiness_only"),
		manifestOperation(http.MethodGet, "/status", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeBrokerLocal, nil, "metadata_only"),
		manifestOperation(http.MethodGet, "/state", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeBrokerLocal, nil, "metadata_only"),
		manifestOperation(http.MethodGet, "/capabilities", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeBrokerLocal, nil, "release_metadata_only"),
		manifestOperation(http.MethodPost, "/v1/secrets", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "local_store_only"),
		manifestOperation(http.MethodPost, "/v1/writeback", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "local_store_only"),
		manifestOperation(http.MethodPost, "/v1/resolve", OperationMaturityValidated, OperationClassificationRead, true, true, true, OperationScopeMixed, providers, "runtime_controls_revalidated"),
		manifestOperation(http.MethodGet, "/v1/provisioning/status", OperationMaturityReadOnly, OperationClassificationRead, true, false, false, OperationScopeMixed, providers, "metadata_only"),
		manifestOperation(http.MethodPost, "/v1/provisioning/operations/plan", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "no_secret_mutation"),
		manifestOperation(http.MethodPost, "/v1/provisioning/operations/apply", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "broker_generated_local_values_only"),
		manifestOperation(http.MethodGet, "/v1/sources/status", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeMixed, providers, "metadata_only"),
		manifestOperation(http.MethodGet, "/v1/providers/capabilities", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeMixed, providers, "provider_family_upper_bound"),
		manifestOperation(http.MethodGet, "/v1/providers/config/status", OperationMaturityReadOnly, OperationClassificationRead, true, false, false, OperationScopeMixed, providers, "metadata_only"),
		manifestOperation(http.MethodGet, "/v1/telemetry", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeBrokerLocal, nil, "redacted_metadata_only"),
		manifestOperation(http.MethodPost, "/v1/telemetry/export", OperationMaturityExecutable, OperationClassificationMutation, false, false, false, OperationScopeProviderRemote, nil, "configured_exporter_only"),
		manifestOperation(http.MethodGet, "/v1/events", OperationMaturityReadOnly, OperationClassificationRead, false, false, false, OperationScopeBrokerLocal, nil, "metadata_only"),
		manifestOperation(http.MethodGet, "/v1/recovery/policy", OperationMaturityReadOnly, OperationClassificationRead, false, false, true, OperationScopeBrokerLocal, local, "recovery_metadata_only"),
		manifestOperation(http.MethodPost, "/v1/recovery/policy", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "metadata_only_no_share_material"),
		manifestOperation(http.MethodPost, "/v1/management/lockouts/clear", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, nil, "scoped_lockout_only"),
		manifestOperation(http.MethodPost, "/v1/providers/config/validate", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "configuration_validation_only"),
		manifestOperation(http.MethodPost, "/v1/providers/config/apply", OperationMaturityPlanned, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "configuration_not_persisted"),
		manifestOperation(http.MethodPost, "/v1/providers/migration/dry-run", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "local_target_only"),
		manifestOperation(http.MethodPost, "/v1/providers/migration/apply", OperationMaturityPlanned, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "migration_items_not_copied"),
		manifestOperation(http.MethodGet, "/v1/management/secrets", OperationMaturityReadOnly, OperationClassificationRead, true, false, false, OperationScopeMixed, providers, "metadata_only"),
		manifestOperation(http.MethodGet, "/v1/management/secrets/value-search", OperationMaturityValidated, OperationClassificationRead, true, true, true, OperationScopeMixed, localAndAWS, "values_never_returned"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/reveal", OperationMaturityValidated, OperationClassificationRead, true, true, true, OperationScopeMixed, providers, "single_ref_ttl_bounded"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/edit/dry-run", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "no_secret_mutation"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/edit/apply", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "local_store_only"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/reset/dry-run", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "no_secret_mutation"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/reset/apply", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "local_store_only"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/decommission/dry-run", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "signed_expected_version_dependency_plan"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/decommission/apply", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "encrypted_recoverable_tombstone"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/decommission/restore", OperationMaturityValidated, OperationClassificationMutation, true, true, true, OperationScopeBrokerLocal, local, "encrypted_tombstone_restore"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/rotation/dry-run", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, localAndAWS, "no_rotation_apply_route"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/campaigns/create", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "plan_state_only"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/campaigns/revalidate", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "plan_state_only"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/campaigns/apply", OperationMaturityPlanned, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "provider_mutations_not_executed"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/campaigns/status", OperationMaturityReadOnly, OperationClassificationRead, true, false, false, OperationScopeBrokerLocal, nil, "in_memory_campaign_metadata_only"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/sync/dry-run", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "no_sync_apply_route"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/policy/preview", OperationMaturityDryRun, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "no_policy_mutation"),
		manifestOperation(http.MethodPost, "/v1/management/secrets/policy/apply", OperationMaturityPlanned, OperationClassificationMutation, true, true, true, OperationScopeMixed, providers, "policy_binding_not_persisted"),
	}
}

func operationCapabilityForRoute(method, path string) (OperationCapability, bool) {
	for _, operation := range defaultOperationManifest() {
		if operation.Method == method && operation.Path == path {
			return operation, true
		}
	}
	return OperationCapability{}, false
}

func providerOperationCapabilitiesForKind(kind string) []OperationCapability {
	return providerOperationCapabilities(kind, normalizeSourceLifecycle("ready"), "audit_available", false)
}

func providerOperationCapabilitiesForSource(kind string, lifecycle SourceLifecycle, auditStatus string) []OperationCapability {
	return providerOperationCapabilities(kind, lifecycle, auditStatus, true)
}

func providerOperationCapabilities(kind string, lifecycle SourceLifecycle, auditStatus string, connectionScoped bool) []OperationCapability {
	kind = strings.ToLower(strings.TrimSpace(kind))
	routes := [][2]string{
		{http.MethodPost, "/v1/resolve"},
		{http.MethodGet, "/v1/management/secrets/value-search"},
		{http.MethodPost, "/v1/management/secrets/reveal"},
		{http.MethodPost, "/v1/secrets"},
		{http.MethodPost, "/v1/writeback"},
		{http.MethodPost, "/v1/provisioning/operations/apply"},
		{http.MethodPost, "/v1/management/secrets/edit/dry-run"},
		{http.MethodPost, "/v1/management/secrets/edit/apply"},
		{http.MethodPost, "/v1/management/secrets/reset/dry-run"},
		{http.MethodPost, "/v1/management/secrets/reset/apply"},
		{http.MethodPost, "/v1/management/secrets/decommission/dry-run"},
		{http.MethodPost, "/v1/management/secrets/decommission/apply"},
		{http.MethodPost, "/v1/management/secrets/decommission/restore"},
		{http.MethodPost, "/v1/management/secrets/rotation/dry-run"},
		{http.MethodPost, "/v1/providers/migration/dry-run"},
		{http.MethodPost, "/v1/providers/migration/apply"},
		{http.MethodPost, "/v1/management/secrets/sync/dry-run"},
		{http.MethodPost, "/v1/management/secrets/policy/preview"},
		{http.MethodPost, "/v1/management/secrets/policy/apply"},
	}
	operations := make([]OperationCapability, 0, len(routes))
	for _, route := range routes {
		operation, ok := operationCapabilityForRoute(route[0], route[1])
		if !ok {
			continue
		}
		operation.ProviderKinds = []string{kind}
		operation.Scope = providerScope(kind)
		operation.Maturity = providerOperationMaturity(kind, operation.Path)
		operation.ReasonCode, operation.NextAction = maturityCodes(operation.Maturity)
		operation.LimitationCode = providerOperationLimitation(kind, operation.Path, operation.Maturity)
		if connectionScoped {
			operation = applyConnectionState(operation, lifecycle, auditStatus)
		} else if operation.Maturity != OperationMaturityUnavailable {
			operation.ReasonCode = "provider_family_upper_bound"
			operation.NextAction = "inspect_source_or_provider_status"
		}
		operations = append(operations, operation)
	}
	return operations
}

func providerScope(kind string) OperationScope {
	if kind == "local-encrypted-store" {
		return OperationScopeBrokerLocal
	}
	if kind == "env" || kind == "file" || kind == "exec" {
		return OperationScopeSourceBoundary
	}
	return OperationScopeProviderRemote
}

func providerOperationMaturity(kind, path string) OperationMaturity {
	contract, supported := adapterContractForKind(kind)
	has := func(capability AdapterCapability) bool {
		return supported && adapterHasCapability(contract, capability)
	}
	local := kind == "local-encrypted-store"

	switch path {
	case "/v1/resolve":
		if has(AdapterCapabilityRead) {
			return OperationMaturityValidated
		}
	case "/v1/management/secrets/reveal":
		if has(AdapterCapabilityReveal) {
			return OperationMaturityValidated
		}
	case "/v1/management/secrets/value-search":
		if local || has(AdapterCapabilityValueSearch) {
			return OperationMaturityValidated
		}
	case "/v1/secrets", "/v1/writeback", "/v1/provisioning/operations/apply", "/v1/management/secrets/edit/apply", "/v1/management/secrets/reset/apply", "/v1/management/secrets/decommission/apply", "/v1/management/secrets/decommission/restore":
		if local {
			return OperationMaturityValidated
		}
	case "/v1/management/secrets/edit/dry-run", "/v1/management/secrets/decommission/dry-run":
		if local || has(AdapterCapabilityWrite) {
			return OperationMaturityDryRun
		}
	case "/v1/management/secrets/reset/dry-run", "/v1/management/secrets/rotation/dry-run":
		if local || kind == "aws-secrets-manager" {
			return OperationMaturityDryRun
		}
		if has(AdapterCapabilityRotate) {
			return OperationMaturityPlanned
		}
	case "/v1/providers/migration/dry-run":
		if has(AdapterCapabilityMigration) {
			return OperationMaturityDryRun
		}
	case "/v1/providers/migration/apply":
		if has(AdapterCapabilityMigration) {
			return OperationMaturityPlanned
		}
	case "/v1/management/secrets/sync/dry-run":
		if has(AdapterCapabilityRead) {
			return OperationMaturityDryRun
		}
	case "/v1/management/secrets/policy/preview":
		if local || has(AdapterCapabilityPolicy) {
			return OperationMaturityDryRun
		}
	case "/v1/management/secrets/policy/apply":
		if local || has(AdapterCapabilityPolicy) {
			return OperationMaturityPlanned
		}
	}
	return OperationMaturityUnavailable
}

func providerOperationLimitation(kind, path string, maturity OperationMaturity) string {
	switch maturity {
	case OperationMaturityUnavailable:
		if kind == "local-encrypted-store" {
			return "local_operation_not_available"
		}
		return "provider_operation_not_implemented"
	case OperationMaturityPlanned:
		if path == "/v1/providers/migration/apply" {
			return "migration_items_not_copied"
		}
		if path == "/v1/management/secrets/policy/apply" {
			return "policy_binding_not_persisted"
		}
		return "provider_apply_path_not_implemented"
	case OperationMaturityDryRun:
		return "planning_only_no_provider_mutation"
	case OperationMaturityValidated:
		return "runtime_auth_policy_audit_revalidated"
	default:
		return "runtime_preconditions_apply"
	}
}

func applyConnectionState(operation OperationCapability, lifecycle SourceLifecycle, auditStatus string) OperationCapability {
	if operation.Maturity == OperationMaturityUnavailable || operation.Maturity == OperationMaturityPlanned {
		return operation
	}
	if lifecycle.Outcome != "ready" {
		operation.Maturity = OperationMaturityUnavailable
		operation.LimitationCode = firstNonEmpty(lifecycle.Outcome, "source_not_ready")
		operation.ReasonCode = "source_operation_blocked"
		operation.NextAction = firstNonEmpty(lifecycle.NextAction, "inspect_source_status")
		return operation
	}
	if operation.AuditRequired && auditStatus != "audit_available" && auditStatus != "audit_ready" && auditStatus != "audit_recorded" {
		operation.Maturity = OperationMaturityUnavailable
		operation.LimitationCode = "audit_unavailable"
		operation.ReasonCode = "source_operation_blocked"
		operation.NextAction = "restore_audit"
		return operation
	}
	operation.ReasonCode = "source_operation_available"
	operation.NextAction = "invoke_with_required_controls"
	return operation
}
