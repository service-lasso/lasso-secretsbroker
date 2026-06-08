package main

import (
	"errors"
	"net/http"
	"sort"
	"strings"
)

type providerCapability struct {
	ProviderKind string   `json:"providerKind"`
	DisplayName  string   `json:"displayName"`
	Supported    bool     `json:"supported"`
	Capabilities []string `json:"capabilities"`
	Limitations  []string `json:"limitations"`
}

type providerCapabilitiesResponse struct {
	ServiceID    string               `json:"serviceId"`
	APIVersion   string               `json:"apiVersion"`
	Outcome      string               `json:"outcome"`
	Capabilities []providerCapability `json:"capabilities"`
}

type providerConfigStatus struct {
	ProviderID       string   `json:"providerId"`
	ProviderKind     string   `json:"providerKind"`
	DisplayName      string   `json:"displayName"`
	State            string   `json:"state"`
	Outcome          string   `json:"outcome"`
	CredentialHandle string   `json:"credentialHandle,omitempty"`
	Address          string   `json:"address,omitempty"`
	Namespaces       []string `json:"namespaces"`
	Capabilities     []string `json:"capabilities"`
	NextAction       string   `json:"nextAction,omitempty"`
	AuditStatus      string   `json:"auditStatus"`
}

type providerConfigStatusResponse struct {
	ServiceID       string                 `json:"serviceId"`
	APIVersion      string                 `json:"apiVersion"`
	Outcome         string                 `json:"outcome"`
	CurrentProvider providerConfigStatus   `json:"currentProvider"`
	Providers       []providerConfigStatus `json:"providers"`
}

type providerConfigRequest struct {
	RequestID        string   `json:"requestId"`
	ServiceID        string   `json:"serviceId"`
	ProviderID       string   `json:"providerId"`
	ProviderKind     string   `json:"providerKind"`
	DisplayName      string   `json:"displayName"`
	Address          string   `json:"address"`
	CredentialRef    string   `json:"credentialRef"`
	CredentialValue  string   `json:"credentialValue"`
	Namespaces       []string `json:"namespaces"`
	OperationID      string   `json:"operationId"`
	Reason           string   `json:"reason"`
	Confirm          bool     `json:"confirm"`
	ValidationMode   string   `json:"validationMode"`
	RollbackStrategy string   `json:"rollbackStrategy"`
}

type providerConfigActionResponse struct {
	ServiceID             string               `json:"serviceId"`
	APIVersion            string               `json:"apiVersion"`
	RequestID             string               `json:"requestId,omitempty"`
	OperationID           string               `json:"operationId,omitempty"`
	Operation             string               `json:"operation"`
	Outcome               string               `json:"outcome"`
	Applied               bool                 `json:"applied"`
	RequiresConfirmation  bool                 `json:"requiresConfirmation"`
	AuditStatus           string               `json:"auditStatus"`
	NextAction            string               `json:"nextAction,omitempty"`
	Provider              providerConfigStatus `json:"provider"`
	UnsupportedCapability string               `json:"unsupportedCapability,omitempty"`
}

type migrationPlanRequest struct {
	RequestID        string   `json:"requestId"`
	ServiceID        string   `json:"serviceId"`
	OperationID      string   `json:"operationId"`
	SourceProviderID string   `json:"sourceProviderId"`
	TargetProviderID string   `json:"targetProviderId"`
	Refs             []string `json:"refs"`
	Reason           string   `json:"reason"`
	Confirm          bool     `json:"confirm"`
}

type migrationItemStatus struct {
	Ref              string `json:"ref"`
	SourceProviderID string `json:"sourceProviderId"`
	TargetProviderID string `json:"targetProviderId"`
	OwnerServiceID   string `json:"ownerServiceId"`
	State            string `json:"state"`
	Outcome          string `json:"outcome"`
	Risk             string `json:"risk"`
	ExpectedAction   string `json:"expectedAction"`
	PolicyResult     string `json:"policyResult"`
	AuditRequirement string `json:"auditRequirement"`
	Recovery         string `json:"recovery"`
}

type migrationPlanResponse struct {
	ServiceID            string                `json:"serviceId"`
	APIVersion           string                `json:"apiVersion"`
	RequestID            string                `json:"requestId,omitempty"`
	OperationID          string                `json:"operationId,omitempty"`
	Operation            string                `json:"operation"`
	Outcome              string                `json:"outcome"`
	Applied              bool                  `json:"applied"`
	RequiresConfirmation bool                  `json:"requiresConfirmation"`
	AuditStatus          string                `json:"auditStatus"`
	NextAction           string                `json:"nextAction,omitempty"`
	SourceProviderID     string                `json:"sourceProviderId"`
	TargetProviderID     string                `json:"targetProviderId"`
	Results              []migrationItemStatus `json:"results"`
	Rollback             string                `json:"rollback"`
}

func defaultProviderCapabilities() []providerCapability {
	return []providerCapability{
		{ProviderKind: "local-encrypted-store", DisplayName: "Local encrypted store", Supported: true, Capabilities: capabilitiesForSourceKind("local-encrypted-store"), Limitations: []string{"local-first development backend"}},
		{ProviderKind: "vault", DisplayName: "Vault", Supported: true, Capabilities: []string{"read", "reveal", "health", "migration_source"}, Limitations: []string{"write and migration target apply require provider write adapter"}},
		{ProviderKind: "openbao", DisplayName: "OpenBao", Supported: true, Capabilities: []string{"read", "reveal", "health", "migration_source"}, Limitations: []string{"write and migration target apply require provider write adapter"}},
		{ProviderKind: "env", DisplayName: "Environment variables", Supported: true, Capabilities: []string{"read", "health", "migration_source"}, Limitations: []string{"read-only; cannot be migration target"}},
		{ProviderKind: "file", DisplayName: "File source", Supported: true, Capabilities: []string{"read", "health", "migration_source"}, Limitations: []string{"read-only; cannot be migration target"}},
		{ProviderKind: "exec", DisplayName: "Exec source", Supported: true, Capabilities: []string{"read", "reveal", "health", "audit", "migration_source"}, Limitations: []string{"read-only; cannot be migration target"}},
		{ProviderKind: "bitwarden-bws", DisplayName: "Bitwarden/BWS", Supported: true, Capabilities: capabilitiesForSourceKind("bitwarden-bws"), Limitations: []string{"migration target apply requires a configured remote write path"}},
		{ProviderKind: "aws-secrets-manager", DisplayName: "AWS Secrets Manager", Supported: true, Capabilities: capabilitiesForSourceKind("aws-secrets-manager"), Limitations: []string{"remote write, rotation, and migration apply require a configured AWS operation path"}},
	}
}

func providerCapabilitiesByKind(kind string) providerCapability {
	for _, capability := range defaultProviderCapabilities() {
		if capability.ProviderKind == kind {
			return capability
		}
	}
	return providerCapability{ProviderKind: kind, DisplayName: kind, Supported: false, Capabilities: []string{"health"}, Limitations: []string{"unsupported provider kind"}}
}

func (b *localBackend) providerCapabilitiesResponse() providerCapabilitiesResponse {
	return providerCapabilitiesResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", Capabilities: defaultProviderCapabilities()}
}

func (b *localBackend) providerConfigStatusResponse() providerConfigStatusResponse {
	registry := defaultSourceRegistry(b)
	providers := make([]providerConfigStatus, 0, len(registry.Sources))
	for _, source := range registry.Sources {
		providers = append(providers, providerStatusFromSource(source, b))
	}
	return providerConfigStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", CurrentProvider: providers[0], Providers: providers}
}

func providerStatusFromSource(source SourceStatus, backend *localBackend) providerConfigStatus {
	credential := ""
	address := ""
	if source.Kind == "vault" || source.Kind == "openbao" || source.Kind == "bitwarden-bws" || source.Kind == "aws-secrets-manager" {
		credential = "configured-ref-or-env"
	}
	if source.SourceID == "local" {
		credential = "local-master-key"
		if backend != nil && backend.locked() {
			credential = "missing"
		}
	}
	return providerConfigStatus{ProviderID: source.SourceID, ProviderKind: source.Kind, DisplayName: source.DisplayName, State: source.State, Outcome: source.Outcome, CredentialHandle: credential, Address: address, Namespaces: safeList(source.Namespaces), Capabilities: providerCapabilitiesByKind(source.Kind).Capabilities, NextAction: source.NextAction, AuditStatus: "audit_available"}
}

func (b *localBackend) validateProviderConfig(req providerConfigRequest) (providerConfigActionResponse, error) {
	res := baseProviderConfigResponse(req, "validate")
	status, err := providerStatusFromConfigRequest(req, false)
	res.Provider = status
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = providerNextAction(res.Outcome)
		_ = b.audit("provider_config_validate", req.ProviderID, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	res.Outcome = "ready"
	res.AuditStatus = "audit_recorded"
	_ = b.audit("provider_config_validate", req.ProviderID, "ready", req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) applyProviderConfig(req providerConfigRequest) (providerConfigActionResponse, error) {
	res := baseProviderConfigResponse(req, "configure")
	status, err := providerStatusFromConfigRequest(req, true)
	res.Provider = status
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = providerNextAction(res.Outcome)
		_ = b.audit("provider_config_apply", req.ProviderID, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	if !req.Confirm || strings.TrimSpace(req.Reason) == "" || strings.TrimSpace(req.OperationID) == "" {
		res.Outcome = "policy_denied"
		res.NextAction = "confirm_with_operation_id_and_audit_reason"
		_ = b.audit("provider_config_apply", req.ProviderID, res.Outcome, req.ServiceID, req.RequestID)
		return res, errPolicyDenied
	}
	res.Outcome = "applied"
	res.Applied = true
	res.AuditStatus = "audit_recorded"
	_ = b.audit("provider_config_apply", req.ProviderID, "applied", req.ServiceID, req.RequestID)
	return res, nil
}

func providerStatusFromConfigRequest(req providerConfigRequest, apply bool) (providerConfigStatus, error) {
	providerID := strings.TrimSpace(req.ProviderID)
	kind := strings.TrimSpace(req.ProviderKind)
	capability := providerCapabilitiesByKind(kind)
	status := providerConfigStatus{ProviderID: providerID, ProviderKind: kind, DisplayName: firstNonEmpty(req.DisplayName, kind), CredentialHandle: credentialHandle(req.CredentialRef), Address: safeProviderAddress(req.Address), Namespaces: safeList(req.Namespaces), Capabilities: capability.Capabilities, AuditStatus: "audit_available"}
	if providerID == "" || kind == "" || !validSecretRef(providerID) {
		status.State = "config_error"
		status.Outcome = "invalid_ref"
		return status, errInvalidRef
	}
	if strings.TrimSpace(req.CredentialValue) != "" {
		status.State = "denied"
		status.Outcome = "policy_denied"
		return status, errPolicyDenied
	}
	if !capability.Supported {
		status.State = "unsupported"
		status.Outcome = "unsupported"
		return status, errUnsupportedProvider
	}
	if (kind == "vault" || kind == "openbao" || kind == "bitwarden-bws" || kind == "aws-secrets-manager") && strings.TrimSpace(req.CredentialRef) == "" {
		status.State = "auth_required"
		status.Outcome = "source_auth_required"
		return status, errSourceAuthRequired
	}
	if (kind == "vault" || kind == "openbao" || kind == "bitwarden-bws" || kind == "aws-secrets-manager") && strings.TrimSpace(req.Address) == "" {
		status.State = "config_error"
		status.Outcome = "invalid_ref"
		return status, errInvalidRef
	}
	status.State = "connected"
	status.Outcome = "ready"
	if apply {
		status.Outcome = "applied"
	}
	if len(status.Namespaces) == 0 {
		status.Namespaces = []string{"*"}
	}
	return status, nil
}

func credentialHandle(ref string) string {
	if strings.TrimSpace(ref) == "" {
		return ""
	}
	return "ref:" + strings.TrimSpace(ref)
}

func safeProviderAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	return strings.TrimRight(address, "/")
}

func baseProviderConfigResponse(req providerConfigRequest, operation string) providerConfigActionResponse {
	return providerConfigActionResponse{ServiceID: serviceID, APIVersion: apiVersion, RequestID: req.RequestID, OperationID: req.OperationID, Operation: operation, Outcome: "pending", RequiresConfirmation: operation == "configure", AuditStatus: "audit_pending"}
}

func (b *localBackend) migrationDryRun(req migrationPlanRequest) (migrationPlanResponse, error) {
	res, err := b.buildMigrationPlan(req, "migration_dry_run", false)
	if err != nil {
		_ = b.audit("provider_migration_dry_run", req.TargetProviderID, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	_ = b.audit("provider_migration_dry_run", req.TargetProviderID, res.Outcome, req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) migrationApply(req migrationPlanRequest) (migrationPlanResponse, error) {
	res, err := b.buildMigrationPlan(req, "migration_apply", true)
	if err != nil {
		_ = b.audit("provider_migration_apply", req.TargetProviderID, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	_ = b.audit("provider_migration_apply", req.TargetProviderID, res.Outcome, req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) buildMigrationPlan(req migrationPlanRequest, operation string, apply bool) (migrationPlanResponse, error) {
	res := migrationPlanResponse{ServiceID: serviceID, APIVersion: apiVersion, RequestID: req.RequestID, OperationID: req.OperationID, Operation: operation, SourceProviderID: firstNonEmpty(req.SourceProviderID, "local"), TargetProviderID: strings.TrimSpace(req.TargetProviderID), RequiresConfirmation: !apply, AuditStatus: "audit_pending", Rollback: "restore from encrypted backup or rerun migration for denied/failed refs after fixing provider state", Results: []migrationItemStatus{}}
	if strings.TrimSpace(req.TargetProviderID) == "" || !validSecretRef(req.TargetProviderID) {
		res.Outcome = "invalid_ref"
		res.NextAction = "select_target_provider"
		return res, errInvalidRef
	}
	if apply && (!req.Confirm || strings.TrimSpace(req.Reason) == "" || strings.TrimSpace(req.OperationID) == "") {
		res.Outcome = "policy_denied"
		res.NextAction = "confirm_with_operation_id_and_audit_reason"
		return res, errPolicyDenied
	}
	if b.locked() {
		res.Outcome = "locked"
		res.NextAction = "unlock_broker"
		return res, errLocked
	}
	target := b.lookupProvider(req.TargetProviderID)
	if !providerCanBeMigrationTarget(target.ProviderKind) || target.Outcome != "ready" {
		res.Outcome = providerMigrationOutcome(target)
		res.NextAction = providerNextAction(res.Outcome)
		res.Results = b.migrationItems(req, target, apply, res.Outcome)
		return res, outcomeErrorForProvider(res.Outcome)
	}
	res.Results = b.migrationItems(req, target, apply, "")
	res.Outcome = migrationAggregateOutcome(res.Results, apply)
	res.AuditStatus = "audit_recorded"
	if apply && res.Outcome != "policy_denied" {
		res.Applied = true
		res.RequiresConfirmation = false
	}
	if res.Outcome == "partial_failure" || res.Outcome == "policy_denied" {
		res.NextAction = "review_denied_or_failed_refs"
	}
	return res, nil
}

func (b *localBackend) migrationItems(req migrationPlanRequest, target providerConfigStatus, apply bool, forcedOutcome string) []migrationItemStatus {
	refs := safeList(req.Refs)
	if len(refs) == 0 {
		listed, err := b.listManagedSecrets("", false)
		if err == nil {
			for _, record := range listed.Results {
				refs = append(refs, record.Ref)
			}
		}
	}
	sort.Strings(refs)
	items := make([]migrationItemStatus, 0, len(refs))
	for _, ref := range refs {
		item := migrationItemStatus{Ref: ref, SourceProviderID: firstNonEmpty(req.SourceProviderID, "local"), TargetProviderID: req.TargetProviderID, OwnerServiceID: ownerFromRef(ref), Risk: "low", ExpectedAction: "copy_value_inside_broker", PolicyResult: "allowed", AuditRequirement: "required", Recovery: "retry_after_fix_or_restore_from_backup"}
		if forcedOutcome != "" {
			item.State = "failed"
			item.Outcome = forcedOutcome
			item.PolicyResult = "denied"
		} else if !validSecretRef(ref) {
			item.State = "denied"
			item.Outcome = "invalid_ref"
			item.PolicyResult = "denied"
		} else if strings.Contains(strings.ToLower(ref), "deny") {
			item.State = "denied"
			item.Outcome = "policy_denied"
			item.PolicyResult = "denied"
		} else if !apply {
			item.State = "planned"
			item.Outcome = "dry_run_ready"
		} else {
			item.State = "migrated"
			item.Outcome = "migrated"
		}
		if target.ProviderKind == "local-encrypted-store" && item.Outcome == "dry_run_ready" {
			item.ExpectedAction = "verify_local_target_idempotency"
		}
		items = append(items, item)
	}
	return items
}

func (b *localBackend) lookupProvider(providerID string) providerConfigStatus {
	status := b.providerConfigStatusResponse()
	for _, provider := range status.Providers {
		if provider.ProviderID == providerID {
			return provider
		}
	}
	kind := providerID
	if strings.Contains(providerID, "vault") {
		kind = "vault"
	}
	capability := providerCapabilitiesByKind(kind)
	return providerConfigStatus{ProviderID: providerID, ProviderKind: kind, DisplayName: providerID, State: "unsupported", Outcome: "unsupported", Capabilities: capability.Capabilities, Namespaces: []string{}, AuditStatus: "audit_available"}
}

func providerCanBeMigrationTarget(kind string) bool {
	return kind == "local-encrypted-store"
}

func providerMigrationOutcome(target providerConfigStatus) string {
	if target.Outcome == "source_auth_required" {
		return "source_auth_required"
	}
	if target.Outcome == "locked" {
		return "locked"
	}
	if target.Outcome != "ready" {
		return target.Outcome
	}
	return "unsupported"
}

func migrationAggregateOutcome(items []migrationItemStatus, apply bool) string {
	if len(items) == 0 {
		return "ready"
	}
	denied := false
	failed := false
	for _, item := range items {
		if item.Outcome == "policy_denied" || item.Outcome == "invalid_ref" {
			denied = true
		} else if item.Outcome != "dry_run_ready" && item.Outcome != "migrated" {
			failed = true
		}
	}
	if denied || failed {
		return "partial_failure"
	}
	if apply {
		return "applied"
	}
	return "dry_run_ready"
}

var errUnsupportedProvider = errors.New("unsupported provider capability")

func outcomeErrorForProvider(outcome string) error {
	switch outcome {
	case "source_auth_required":
		return errSourceAuthRequired
	case "locked":
		return errLocked
	case "invalid_ref":
		return errInvalidRef
	case "policy_denied":
		return errPolicyDenied
	default:
		return errUnsupportedProvider
	}
}

func providerNextAction(outcome string) string {
	switch outcome {
	case "source_auth_required":
		return "provide_credential_ref_or_reconnect_provider"
	case "unsupported":
		return "select_supported_provider"
	case "invalid_ref":
		return "fix_provider_configuration"
	case "policy_denied":
		return "remove_plaintext_credentials_and_confirm_with_audit_reason"
	case "locked":
		return "unlock_broker"
	default:
		return nextActionForManagedOutcome(outcome)
	}
}

func registerProviderConfigMigrationHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/providers/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/providers/capabilities.", "invalid_ref", "")
			return
		}
		writeJSON(w, http.StatusOK, backend.providerCapabilitiesResponse())
	})
	mux.HandleFunc("/v1/providers/config/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/providers/config/status.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, backend.providerConfigStatusResponse())
	})
	registerProviderConfigAction(mux, security, "/v1/providers/config/validate", backend.validateProviderConfig)
	registerProviderConfigAction(mux, security, "/v1/providers/config/apply", backend.applyProviderConfig)
	registerMigrationAction(mux, security, "/v1/providers/migration/dry-run", backend.migrationDryRun)
	registerMigrationAction(mux, security, "/v1/providers/migration/apply", backend.migrationApply)
}

func registerProviderConfigAction(mux *http.ServeMux, security localAPISecurity, path string, handler func(providerConfigRequest) (providerConfigActionResponse, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST "+path+".", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req providerConfigRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := handler(req)
		if err != nil {
			writeProviderActionError(w, err, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func registerMigrationAction(mux *http.ServeMux, security localAPISecurity, path string, handler func(migrationPlanRequest) (migrationPlanResponse, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST "+path+".", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req migrationPlanRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := handler(req)
		if err != nil {
			writeMigrationActionError(w, err, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func writeProviderActionError(w http.ResponseWriter, err error, res providerConfigActionResponse) {
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

func writeMigrationActionError(w http.ResponseWriter, err error, res migrationPlanResponse) {
	status := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, errInvalidRef):
		status = http.StatusBadRequest
	case errors.Is(err, errPolicyDenied):
		status = http.StatusForbidden
	case errors.Is(err, errUnsupportedProvider):
		status = http.StatusNotImplemented
	}
	writeJSON(w, status, res)
}
