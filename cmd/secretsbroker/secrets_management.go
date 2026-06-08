package main

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

const revealTTLSeconds = 60

type managedSecretRecord struct {
	Ref            string         `json:"ref"`
	Name           string         `json:"name"`
	SourceID       string         `json:"sourceId"`
	ProviderKind   string         `json:"providerKind"`
	OwnerServiceID string         `json:"ownerServiceId"`
	WorkspaceID    string         `json:"workspaceId"`
	State          string         `json:"state"`
	Outcome        string         `json:"outcome"`
	Capabilities   []string       `json:"capabilities"`
	Policy         string         `json:"policy"`
	AuditStatus    string         `json:"auditStatus"`
	ValueSearch    string         `json:"valueSearch"`
	UpdatedAt      *time.Time     `json:"updatedAt,omitempty"`
	Metadata       SecretMetadata `json:"metadata,omitempty"`
}

type managedSecretsResponse struct {
	ServiceID   string                `json:"serviceId"`
	APIVersion  string                `json:"apiVersion"`
	Query       string                `json:"query,omitempty"`
	ValueSearch bool                  `json:"valueSearch"`
	Outcome     string                `json:"outcome"`
	Results     []managedSecretRecord `json:"results"`
}

type managedSecretActionRequest struct {
	RequestID string `json:"requestId"`
	ServiceID string `json:"serviceId"`
	Ref       string `json:"ref"`
	Reason    string `json:"reason"`
	Value     string `json:"value"`
	Policy    string `json:"policy"`
	Confirm   bool   `json:"confirm"`
}

type managedSecretActionResponse struct {
	ServiceID             string               `json:"serviceId"`
	APIVersion            string               `json:"apiVersion"`
	RequestID             string               `json:"requestId,omitempty"`
	Ref                   string               `json:"ref"`
	Operation             string               `json:"operation"`
	Mode                  string               `json:"mode"`
	Outcome               string               `json:"outcome"`
	Applied               bool                 `json:"applied"`
	RequiresConfirmation  bool                 `json:"requiresConfirmation"`
	AuditStatus           string               `json:"auditStatus"`
	NextAction            string               `json:"nextAction,omitempty"`
	Value                 string               `json:"value,omitempty"`
	TTLSeconds            int                  `json:"ttlSeconds,omitempty"`
	Metadata              *SecretMetadata      `json:"metadata,omitempty"`
	Record                *managedSecretRecord `json:"record,omitempty"`
	AffectedRefs          []string             `json:"affectedRefs"`
	AffectedServices      []string             `json:"affectedServices"`
	UnsupportedCapability string               `json:"unsupportedCapability,omitempty"`
	LockoutActive         bool                 `json:"lockoutActive,omitempty"`
	LockoutScope          string               `json:"lockoutScope,omitempty"`
	RetryAfterSeconds     int                  `json:"retryAfterSeconds,omitempty"`
}

func (b *localBackend) listManagedSecrets(query string, valueSearch bool) (managedSecretsResponse, error) {
	if b.locked() {
		return managedSecretsResponse{ServiceID: serviceID, APIVersion: apiVersion, Query: query, ValueSearch: valueSearch, Outcome: "locked", Results: []managedSecretRecord{}}, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		return managedSecretsResponse{ServiceID: serviceID, APIVersion: apiVersion, Query: query, ValueSearch: valueSearch, Outcome: "degraded", Results: []managedSecretRecord{}}, errBackendDegraded
	}
	records := make([]managedSecretRecord, 0, len(store.Secrets)+configuredSourceRefCount(b.sources))
	for ref, entry := range store.Secrets {
		record := managedRecordFromLocalEntry(ref, entry)
		matches := managedRecordMatches(record, query)
		if valueSearch {
			matches = b.localValueMatches(entry, query)
		}
		if matches {
			records = append(records, record)
		}
	}
	for _, source := range b.sources.enabledSources() {
		for ref := range source.Refs {
			if _, ok := store.Secrets[ref]; ok {
				continue
			}
			record := managedRecordFromSource(ref, source)
			if !valueSearch && managedRecordMatches(record, query) {
				records = append(records, record)
			} else if valueSearch && sourceSupportsValueSearch(source.Kind) && b.sourceValueMatches(source, ref, query) {
				records = append(records, record)
			}
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Ref < records[j].Ref })
	return managedSecretsResponse{ServiceID: serviceID, APIVersion: apiVersion, Query: query, ValueSearch: valueSearch, Outcome: "ready", Results: records}, nil
}

func managedRecordFromLocalEntry(ref string, entry secretEntry) managedSecretRecord {
	updated := entry.Metadata.UpdatedAt
	return managedSecretRecord{
		Ref:            ref,
		Name:           refName(ref),
		SourceID:       firstNonEmpty(entry.Metadata.SourceID, localStoreSource),
		ProviderKind:   "local-encrypted-store",
		OwnerServiceID: ownerFromRef(ref),
		WorkspaceID:    workspaceFromRef(ref),
		State:          "present",
		Outcome:        "ready",
		Capabilities:   []string{"metadata", "reveal", "edit", "reset", "policy", "value_search"},
		Policy:         "local-writeback-policy",
		AuditStatus:    "audit_available",
		ValueSearch:    "supported",
		UpdatedAt:      &updated,
		Metadata:       entry.Metadata,
	}
}

func managedRecordFromSource(ref string, source sourceConfig) managedSecretRecord {
	lifecycle := sourceRegistryLifecycle(source)
	state := "present"
	if lifecycle.Outcome != "ready" {
		state = lifecycle.State
	}
	return managedSecretRecord{
		Ref:            ref,
		Name:           refName(ref),
		SourceID:       source.SourceID,
		ProviderKind:   source.Kind,
		OwnerServiceID: ownerFromRef(ref),
		WorkspaceID:    workspaceFromRef(ref),
		State:          state,
		Outcome:        lifecycle.Outcome,
		Capabilities:   managedCapabilitiesForSourceKind(source.Kind),
		Policy:         "source-read-policy",
		AuditStatus:    "audit_available",
		ValueSearch:    valueSearchStatusForSourceKind(source.Kind),
	}
}

func managedCapabilitiesForSourceKind(kind string) []string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "aws-secrets-manager":
		return []string{"metadata", "reveal", "edit", "reset", "policy", "rotate/reset", "value_search"}
	default:
		return []string{"metadata", "reveal"}
	}
}

func valueSearchStatusForSourceKind(kind string) string {
	if sourceSupportsValueSearch(kind) {
		return "supported"
	}
	return "unsupported"
}

func sourceSupportsValueSearch(kind string) bool {
	contract, ok := adapterContractForKind(kind)
	return ok && adapterHasCapability(contract, AdapterCapabilityValueSearch)
}

func (b *localBackend) localValueMatches(entry secretEntry, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return false
	}
	value, err := b.decrypt(entry.Payload)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(value), query)
}

func (b *localBackend) sourceValueMatches(source sourceConfig, ref string, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return false
	}
	refCfg, ok := source.Refs[ref]
	if !ok {
		return false
	}
	res := source.resolve(ref, refCfg)
	return res.Outcome == "ready" && strings.Contains(strings.ToLower(res.Value), query)
}

func managedRecordMatches(record managedSecretRecord, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{record.Ref, record.Name, record.SourceID, record.ProviderKind, record.OwnerServiceID, record.WorkspaceID, record.State, record.Outcome, record.Policy}, " "))
	return strings.Contains(haystack, query)
}

func configuredSourceRefCount(cfg sourceConfigFile) int {
	count := 0
	for _, source := range cfg.enabledSources() {
		count += len(source.Refs)
	}
	return count
}

func refName(ref string) string {
	parts := strings.Split(strings.Trim(ref, "/"), "/")
	if len(parts) == 0 {
		return ref
	}
	return parts[len(parts)-1]
}

func ownerFromRef(ref string) string {
	parts := strings.Split(strings.Trim(ref, "/"), "/")
	if len(parts) >= 2 && parts[0] == "services" {
		return parts[1]
	}
	if len(parts) >= 1 && strings.HasPrefix(parts[0], "@") {
		return parts[0]
	}
	return "unknown"
}

func workspaceFromRef(ref string) string {
	parts := strings.Split(strings.Trim(ref, "/"), "/")
	if len(parts) >= 3 && parts[0] == "workspaces" {
		return parts[1]
	}
	if len(parts) >= 1 && parts[0] == "services" {
		return "service"
	}
	return "local"
}

func (b *localBackend) revealManagedSecret(req managedSecretActionRequest) (managedSecretActionResponse, error) {
	res := baseManagedActionResponse(req, "reveal", "apply")
	if b.managementLockoutActive(req, "reveal", &res) {
		return res, errLockoutActive
	}
	if err := validateManagedAction(req, true); err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		if errors.Is(err, errPolicyDenied) {
			b.recordManagementPolicyDenied(req, "reveal", &res)
			if res.LockoutActive {
				return res, errLockoutActive
			}
		}
		_ = b.audit("management_reveal", req.Ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	resolved := b.resolve(resolveRequest{RequestID: req.RequestID, ServiceID: req.ServiceID, Purpose: "managed_reveal", Refs: []string{req.Ref}})
	if len(resolved.Results) != 1 || resolved.Results[0].Outcome != "ready" {
		outcome := "missing_ref"
		if len(resolved.Results) == 1 {
			outcome = resolved.Results[0].Outcome
		}
		res.Outcome = outcome
		res.NextAction = nextActionForManagedOutcome(outcome)
		if outcome == "policy_denied" {
			b.recordManagementPolicyDenied(req, "reveal", &res)
			if res.LockoutActive {
				return res, errLockoutActive
			}
		}
		_ = b.audit("management_reveal", req.Ref, outcome, req.ServiceID, req.RequestID)
		return res, outcomeError(outcome)
	}
	result := resolved.Results[0]
	res.Outcome = "ready"
	res.Value = result.Value
	res.TTLSeconds = revealTTLSeconds
	res.AuditStatus = "audit_recorded"
	res.Metadata = result.Metadata
	b.recordManagementSuccess(req, "reveal")
	_ = b.audit("management_reveal", req.Ref, "ready", req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) managedEditDryRun(req managedSecretActionRequest) (managedSecretActionResponse, error) {
	return b.managedDryRun(req, "edit")
}

func (b *localBackend) managedResetDryRun(req managedSecretActionRequest) (managedSecretActionResponse, error) {
	return b.managedDryRun(req, "reset")
}

func (b *localBackend) managedPolicyPreview(req managedSecretActionRequest) (managedSecretActionResponse, error) {
	return b.managedDryRun(req, "policy")
}

func (b *localBackend) managedDryRun(req managedSecretActionRequest, operation string) (managedSecretActionResponse, error) {
	res := baseManagedActionResponse(req, operation, dryRunMode(operation))
	if err := validateManagedAction(req, false); err != nil {
		res.Outcome = "invalid_ref"
		res.NextAction = "provide_valid_ref"
		_ = b.audit("management_"+operation+"_dry_run", req.Ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	record, err := b.managedRecord(req.Ref)
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		_ = b.audit("management_"+operation+"_dry_run", req.Ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	res.Outcome = "dry_run_ready"
	res.RequiresConfirmation = true
	res.Record = &record
	res.AuditStatus = "audit_ready"
	res.NextAction = "confirm_and_apply_with_audit_reason"
	_ = b.audit("management_"+operation+"_dry_run", req.Ref, "dry_run_ready", req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) managedEditApply(req managedSecretActionRequest) (managedSecretActionResponse, error) {
	return b.managedWriteApply(req, "edit")
}

func (b *localBackend) managedResetApply(req managedSecretActionRequest) (managedSecretActionResponse, error) {
	return b.managedWriteApply(req, "reset")
}

func (b *localBackend) managedWriteApply(req managedSecretActionRequest, operation string) (managedSecretActionResponse, error) {
	res := baseManagedActionResponse(req, operation, "apply")
	if b.managementLockoutActive(req, operation, &res) {
		return res, errLockoutActive
	}
	if err := validateManagedAction(req, true); err != nil || !req.Confirm || strings.TrimSpace(req.Value) == "" {
		res.Outcome = "policy_denied"
		res.NextAction = "run_dry_run_confirm_reason_and_value"
		b.recordManagementPolicyDenied(req, operation, &res)
		_ = b.audit("management_"+operation+"_apply", req.Ref, res.Outcome, req.ServiceID, req.RequestID)
		if res.LockoutActive {
			return res, errLockoutActive
		}
		return res, errPolicyDenied
	}
	written, err := b.writeSecret(writeSecretRequest{Ref: req.Ref, Value: req.Value, Metadata: map[string]string{"sourceId": "management:" + operation}})
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		return res, err
	}
	record := managedRecordFromLocalEntry(req.Ref, secretEntry{Ref: req.Ref, Metadata: written.Metadata})
	res.Outcome = "applied"
	res.Applied = true
	res.AuditStatus = "audit_recorded"
	res.Metadata = &written.Metadata
	res.Record = &record
	b.recordManagementSuccess(req, operation)
	_ = b.audit("management_"+operation+"_apply", req.Ref, "applied", req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) managedPolicyApply(req managedSecretActionRequest) (managedSecretActionResponse, error) {
	res := baseManagedActionResponse(req, "policy", "apply")
	if b.managementLockoutActive(req, "policy", &res) {
		return res, errLockoutActive
	}
	if err := validateManagedAction(req, true); err != nil || !req.Confirm || strings.TrimSpace(req.Policy) == "" {
		res.Outcome = "policy_denied"
		res.NextAction = "preview_confirm_reason_and_policy"
		b.recordManagementPolicyDenied(req, "policy", &res)
		_ = b.audit("management_policy_apply", req.Ref, res.Outcome, req.ServiceID, req.RequestID)
		if res.LockoutActive {
			return res, errLockoutActive
		}
		return res, errPolicyDenied
	}
	record, err := b.managedRecord(req.Ref)
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		return res, err
	}
	record.Policy = req.Policy
	res.Outcome = "applied"
	res.Applied = true
	res.AuditStatus = "audit_recorded"
	res.Record = &record
	b.recordManagementSuccess(req, "policy")
	_ = b.audit("management_policy_apply", req.Ref, "applied", req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) managedRecord(ref string) (managedSecretRecord, error) {
	if !validSecretRef(ref) {
		return managedSecretRecord{}, errInvalidRef
	}
	if b.locked() {
		return managedSecretRecord{}, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		return managedSecretRecord{}, errBackendDegraded
	}
	if entry, ok := store.Secrets[ref]; ok {
		return managedRecordFromLocalEntry(ref, entry), nil
	}
	for _, source := range b.sources.enabledSources() {
		if _, ok := source.Refs[ref]; ok {
			return managedRecordFromSource(ref, source), nil
		}
	}
	return managedSecretRecord{}, errMissingRef
}

func baseManagedActionResponse(req managedSecretActionRequest, operation, mode string) managedSecretActionResponse {
	return managedSecretActionResponse{ServiceID: serviceID, APIVersion: apiVersion, RequestID: req.RequestID, Ref: strings.TrimSpace(req.Ref), Operation: operation, Mode: mode, Outcome: "pending", AuditStatus: "audit_pending", AffectedRefs: safeList([]string{req.Ref}), AffectedServices: safeList([]string{req.ServiceID})}
}

func (b *localBackend) managementLockoutActive(req managedSecretActionRequest, operation string, res *managedSecretActionResponse) bool {
	if b == nil || res == nil || b.lockouts == nil {
		return false
	}
	decision := b.lockouts.active(managementLockoutScope(req, operation))
	if !decision.Active {
		return false
	}
	applyManagementLockout(res, decision)
	_ = b.audit("management_lockout", req.Ref, "lockout_active", req.ServiceID, req.RequestID)
	return true
}

func (b *localBackend) recordManagementPolicyDenied(req managedSecretActionRequest, operation string, res *managedSecretActionResponse) {
	if b == nil || res == nil || b.lockouts == nil {
		return
	}
	decision, started := b.lockouts.recordFailure(managementLockoutScope(req, operation))
	if started {
		applyManagementLockout(res, decision)
		_ = b.audit("management_lockout", req.Ref, "lockout_active", req.ServiceID, req.RequestID)
	}
}

func (b *localBackend) recordManagementSuccess(req managedSecretActionRequest, operation string) {
	if b == nil || b.lockouts == nil {
		return
	}
	b.lockouts.recordSuccess(managementLockoutScope(req, operation))
}

func applyManagementLockout(res *managedSecretActionResponse, decision lockoutDecision) {
	res.Outcome = "lockout_active"
	res.NextAction = "wait_or_clear_lockout"
	res.Value = ""
	res.Applied = false
	res.LockoutActive = true
	res.LockoutScope = decision.Scope
	res.RetryAfterSeconds = decision.RetryAfterSeconds
}

func managementLockoutScope(req managedSecretActionRequest, operation string) string {
	service := strings.TrimSpace(req.ServiceID)
	if service == "" {
		service = "@operator"
	}
	ref := strings.TrimSpace(req.Ref)
	if ref == "" || !validSecretRef(ref) {
		ref = "unknown"
	}
	return strings.Join([]string{"management", strings.TrimSpace(operation), service, ref}, ":")
}

func dryRunMode(operation string) string {
	if operation == "policy" {
		return "preview"
	}
	return "dry-run"
}

func validateManagedAction(req managedSecretActionRequest, requireReason bool) error {
	if !validSecretRef(req.Ref) {
		return errInvalidRef
	}
	if requireReason && strings.TrimSpace(req.Reason) == "" {
		return errPolicyDenied
	}
	return nil
}

func outcomeForError(err error) string {
	switch {
	case errors.Is(err, errInvalidRef):
		return "invalid_ref"
	case errors.Is(err, errLocked):
		return "locked"
	case errors.Is(err, errMissingRef):
		return "missing_ref"
	case errors.Is(err, errPolicyDenied):
		return "policy_denied"
	case errors.Is(err, errSourceAuthRequired):
		return "source_auth_required"
	case errors.Is(err, errBackendDegraded):
		return "degraded"
	case errors.Is(err, errUnsupportedProvider):
		return "unsupported"
	default:
		return "degraded"
	}
}

func outcomeError(outcome string) error {
	switch outcome {
	case "invalid_ref":
		return errInvalidRef
	case "locked":
		return errLocked
	case "source_auth_required":
		return errSourceAuthRequired
	case "policy_denied":
		return errPolicyDenied
	case "missing_ref":
		return errMissingRef
	default:
		return errBackendDegraded
	}
}

func nextActionForManagedOutcome(outcome string) string {
	switch outcome {
	case "locked":
		return "unlock_broker"
	case "missing_ref":
		return "check_ref"
	case "invalid_ref":
		return "fix_ref"
	case "policy_denied":
		return "review_policy_and_reason"
	case "source_auth_required":
		return "reconnect_source"
	case "source_unavailable", "degraded":
		return "retry_or_inspect_source"
	default:
		return "inspect_status"
	}
}

func registerSecretsManagementHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/management/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/management/secrets.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		res, err := backend.listManagedSecrets(r.URL.Query().Get("search"), false)
		if err != nil {
			writeManagementError(w, err, res.Outcome, "List managed secrets failed.")
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("/v1/management/secrets/value-search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/management/secrets/value-search.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		res, err := backend.listManagedSecrets(r.URL.Query().Get("query"), true)
		if err != nil {
			writeManagementError(w, err, res.Outcome, "Value search failed closed.")
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	registerManagedAction(mux, security, "/v1/management/secrets/reveal", backend.revealManagedSecret)
	registerManagedAction(mux, security, "/v1/management/secrets/edit/dry-run", backend.managedEditDryRun)
	registerManagedAction(mux, security, "/v1/management/secrets/edit/apply", backend.managedEditApply)
	registerManagedAction(mux, security, "/v1/management/secrets/reset/dry-run", backend.managedResetDryRun)
	registerManagedAction(mux, security, "/v1/management/secrets/reset/apply", backend.managedResetApply)
	registerManagedAction(mux, security, "/v1/management/secrets/policy/preview", backend.managedPolicyPreview)
	registerManagedAction(mux, security, "/v1/management/secrets/policy/apply", backend.managedPolicyApply)
}

func registerManagedAction(mux *http.ServeMux, security localAPISecurity, path string, handler func(managedSecretActionRequest) (managedSecretActionResponse, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST "+path+".", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req managedSecretActionRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := handler(req)
		if err != nil {
			writeManagementActionError(w, err, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func writeManagementError(w http.ResponseWriter, err error, outcome, message string) {
	status := http.StatusServiceUnavailable
	if errors.Is(err, errInvalidRef) {
		status = http.StatusBadRequest
	}
	writeAPIError(w, status, outcomeForError(err), message, outcome, nextActionForManagedOutcome(outcome))
}

func writeManagementActionError(w http.ResponseWriter, err error, res managedSecretActionResponse) {
	status := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, errInvalidRef):
		status = http.StatusBadRequest
	case errors.Is(err, errMissingRef):
		status = http.StatusNotFound
	case errors.Is(err, errPolicyDenied):
		status = http.StatusForbidden
	case errors.Is(err, errLockoutActive):
		status = http.StatusLocked
	case errors.Is(err, errSourceAuthRequired):
		status = http.StatusFailedDependency
	}
	writeJSON(w, status, res)
}
