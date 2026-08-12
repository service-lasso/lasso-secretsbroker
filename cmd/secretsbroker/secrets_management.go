package main

import (
	"crypto/rand"
	"encoding/base64"
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

type generatedValuePolicyMetadata struct {
	Kind           string `json:"kind"`
	LengthClass    string `json:"lengthClass"`
	EntropyClass   string `json:"entropyClass"`
	RotationPolicy string `json:"rotationPolicy"`
}

type provisioningStatusRecord struct {
	Ref                  string                       `json:"ref"`
	Namespace            string                       `json:"namespace"`
	OwnerServiceID       string                       `json:"ownerServiceId"`
	SourceID             string                       `json:"sourceId"`
	ProviderID           string                       `json:"providerId"`
	ProviderKind         string                       `json:"providerKind"`
	DesiredOperation     string                       `json:"desiredOperation"`
	ProvisionedState     string                       `json:"provisionedState"`
	LastOperationID      string                       `json:"lastOperationId,omitempty"`
	LastOutcome          string                       `json:"lastOutcome"`
	NextAction           string                       `json:"nextAction,omitempty"`
	AuditStatus          string                       `json:"auditStatus"`
	PolicyResult         string                       `json:"policyResult"`
	GeneratedValuePolicy generatedValuePolicyMetadata `json:"generatedValuePolicy"`
	UpdatedAt            *time.Time                   `json:"updatedAt,omitempty"`
}

type provisioningStatusResponse struct {
	ServiceID  string                     `json:"serviceId"`
	APIVersion string                     `json:"apiVersion"`
	Query      string                     `json:"query,omitempty"`
	Ref        string                     `json:"ref,omitempty"`
	Outcome    string                     `json:"outcome"`
	Results    []provisioningStatusRecord `json:"results"`
}

type provisioningOperationRequest struct {
	RequestID             string                       `json:"requestId"`
	ServiceID             string                       `json:"serviceId"`
	Ref                   string                       `json:"ref"`
	Operation             string                       `json:"operation"`
	GenerationMode        string                       `json:"generationMode"`
	Reason                string                       `json:"reason"`
	Confirm               bool                         `json:"confirm"`
	Identity              writebackIdentity            `json:"identity"`
	IdentityLease         *launchIdentityLease         `json:"identityLease,omitempty"`
	Policy                writebackPolicy              `json:"policy"`
	Secrets               *serviceSecretsPolicy        `json:"secrets,omitempty"`
	GeneratedValuePolicy  generatedValuePolicyMetadata `json:"generatedValuePolicy"`
	RequiresWriteback     bool                         `json:"requiresWriteback"`
	RequireBrokerGenerate bool                         `json:"requireBrokerGenerate"`
}

type provisioningOperationResponse struct {
	ServiceID             string                       `json:"serviceId"`
	APIVersion            string                       `json:"apiVersion"`
	RequestID             string                       `json:"requestId,omitempty"`
	OwnerServiceID        string                       `json:"ownerServiceId"`
	Namespace             string                       `json:"namespace"`
	Ref                   string                       `json:"ref"`
	Operation             string                       `json:"operation"`
	Mode                  string                       `json:"mode"`
	GenerationMode        string                       `json:"generationMode"`
	Outcome               string                       `json:"outcome"`
	Applied               bool                         `json:"applied"`
	RequiresConfirmation  bool                         `json:"requiresConfirmation"`
	WritebackEndpoint     string                       `json:"writebackEndpoint,omitempty"`
	NextAction            string                       `json:"nextAction,omitempty"`
	AuditStatus           string                       `json:"auditStatus"`
	PolicyResult          string                       `json:"policyResult"`
	ProvisionedState      string                       `json:"provisionedState"`
	LastOutcome           string                       `json:"lastOutcome"`
	GeneratedValuePolicy  generatedValuePolicyMetadata `json:"generatedValuePolicy"`
	UnsupportedCapability string                       `json:"unsupportedCapability,omitempty"`
	AffectedRefs          []string                     `json:"affectedRefs"`
	AffectedServices      []string                     `json:"affectedServices"`
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

func (b *localBackend) listProvisioningStatus(query, refFilter string) (provisioningStatusResponse, error) {
	query = strings.TrimSpace(query)
	refFilter = strings.TrimSpace(refFilter)
	res := provisioningStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Query: query, Ref: refFilter, Outcome: "ready", Results: []provisioningStatusRecord{}}
	if refFilter != "" && !validSecretRef(refFilter) {
		res.Outcome = "invalid_ref"
		return res, errInvalidRef
	}
	if b.locked() {
		res.Outcome = "locked"
		return res, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		res.Outcome = "degraded"
		return res, errBackendDegraded
	}
	seen := map[string]bool{}
	for ref, entry := range store.Secrets {
		record := provisioningRecordFromLocalEntry(ref, entry)
		seen[ref] = true
		if provisioningRecordMatches(record, query, refFilter) {
			res.Results = append(res.Results, record)
		}
	}
	for _, source := range b.sources.enabledSources() {
		for ref := range source.Refs {
			if seen[ref] {
				continue
			}
			record := provisioningRecordFromSource(ref, source)
			seen[ref] = true
			if provisioningRecordMatches(record, query, refFilter) {
				res.Results = append(res.Results, record)
			}
		}
	}
	if refFilter != "" && !seen[refFilter] {
		res.Results = append(res.Results, missingProvisioningRecord(refFilter))
	}
	sort.Slice(res.Results, func(i, j int) bool { return res.Results[i].Ref < res.Results[j].Ref })
	return res, nil
}

func (b *localBackend) planProvisioningOperation(req provisioningOperationRequest) (provisioningOperationResponse, error) {
	ref := strings.TrimSpace(req.Ref)
	operation := normalizeWritebackOperation(req.Operation)
	generationMode := normalizeProvisioningGenerationMode(req.GenerationMode)
	if req.RequireBrokerGenerate {
		generationMode = "broker_generated"
	}
	res := provisioningOperationResponse{
		ServiceID:            serviceID,
		APIVersion:           apiVersion,
		RequestID:            req.RequestID,
		OwnerServiceID:       ownerFromRef(ref),
		Namespace:            namespaceFromRef(ref),
		Ref:                  ref,
		Operation:            operation,
		Mode:                 "plan",
		GenerationMode:       generationMode,
		Outcome:              "pending",
		AuditStatus:          "audit_pending",
		PolicyResult:         "unknown",
		GeneratedValuePolicy: firstGeneratedValuePolicy(req.GeneratedValuePolicy, defaultGeneratedValuePolicy(ref)),
		AffectedRefs:         safeList([]string{ref}),
		AffectedServices:     safeList([]string{firstNonEmpty(req.ServiceID, ownerFromRef(ref))}),
	}
	if !validSecretRef(ref) || !validWritebackOperation(operation) || !validProvisioningGenerationMode(generationMode) {
		res.Outcome = "invalid_ref"
		res.NextAction = "provide_valid_ref_operation_and_generation_mode"
		_ = b.audit("provisioning_plan", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errInvalidRef
	}
	status, err := b.listProvisioningStatus("", ref)
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForProvisioningOutcome(res.Outcome)
		_ = b.audit("provisioning_plan", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	if len(status.Results) == 1 {
		res.ProvisionedState = status.Results[0].ProvisionedState
		res.LastOutcome = status.Results[0].LastOutcome
		res.PolicyResult = status.Results[0].PolicyResult
	}
	if generationMode == "broker_generated" {
		res.Outcome = "ready"
		res.RequiresConfirmation = true
		res.PolicyResult = "allowed"
		res.AuditStatus = "audit_ready"
		res.NextAction = "call_broker_generated_apply_with_signed_identity_policy_and_audit_reason"
		_ = b.audit("provisioning_plan", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, nil
	}
	res.Outcome = "ready"
	res.RequiresConfirmation = true
	res.WritebackEndpoint = "/v1/writeback"
	res.NextAction = "submit_signed_writeback_with_value_and_audit_reason"
	res.AuditStatus = "audit_ready"
	if res.PolicyResult == "unknown" {
		res.PolicyResult = "allowed"
	}
	_ = b.audit("provisioning_plan", ref, res.Outcome, req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) applyProvisioningOperation(req provisioningOperationRequest) (provisioningOperationResponse, error) {
	ref := strings.TrimSpace(req.Ref)
	operation := normalizeWritebackOperation(req.Operation)
	generationMode := normalizeProvisioningGenerationMode(req.GenerationMode)
	if req.RequireBrokerGenerate {
		generationMode = "broker_generated"
	}
	res := provisioningOperationResponse{
		ServiceID:            serviceID,
		APIVersion:           apiVersion,
		RequestID:            req.RequestID,
		OwnerServiceID:       ownerFromRef(ref),
		Namespace:            namespaceFromRef(ref),
		Ref:                  ref,
		Operation:            operation,
		Mode:                 "apply",
		GenerationMode:       generationMode,
		Outcome:              "pending",
		AuditStatus:          "audit_pending",
		PolicyResult:         "unknown",
		GeneratedValuePolicy: firstGeneratedValuePolicy(req.GeneratedValuePolicy, defaultGeneratedValuePolicy(ref)),
		AffectedRefs:         safeList([]string{ref}),
		AffectedServices:     safeList([]string{firstNonEmpty(firstNonEmpty(req.ServiceID, req.Identity.ServiceID), ownerFromRef(ref))}),
	}
	if !validSecretRef(ref) || !validWritebackOperation(operation) || !validProvisioningGenerationMode(generationMode) || !validBrokerGeneratedProvisioningOperation(operation) {
		res.Outcome = "invalid_ref"
		res.NextAction = "provide_valid_ref_operation_and_generation_mode"
		_ = b.audit("provisioning_apply", ref, res.Outcome, firstNonEmpty(req.Identity.ServiceID, req.ServiceID), req.RequestID)
		return res, errInvalidRef
	}
	if generationMode != "broker_generated" {
		res.Outcome = "unsupported"
		res.PolicyResult = "unsupported"
		res.AuditStatus = "audit_ready"
		res.UnsupportedCapability = "caller_provided_apply"
		res.NextAction = "use_signed_writeback_endpoint_for_caller_provided_values"
		_ = b.audit("provisioning_apply", ref, res.Outcome, firstNonEmpty(req.Identity.ServiceID, req.ServiceID), req.RequestID)
		return res, errUnsupportedProvider
	}
	if !req.Confirm || strings.TrimSpace(req.Reason) == "" {
		res.Outcome = "policy_denied"
		res.PolicyResult = "denied"
		res.AuditStatus = "audit_required"
		res.NextAction = "confirm_with_audit_reason"
		_ = b.audit("provisioning_apply", ref, res.Outcome, firstNonEmpty(req.Identity.ServiceID, req.ServiceID), req.RequestID)
		return res, errPolicyDenied
	}
	value, err := generateBrokerProvisioningValue(res.GeneratedValuePolicy)
	if err != nil {
		res.Outcome = "policy_denied"
		res.PolicyResult = "denied"
		res.AuditStatus = "audit_ready"
		res.NextAction = "provide_supported_generated_value_policy"
		_ = b.audit("provisioning_apply", ref, res.Outcome, firstNonEmpty(req.Identity.ServiceID, req.ServiceID), req.RequestID)
		return res, errPolicyDenied
	}
	capture, err := b.captureGeneratedSecret(generatedSecretCaptureRequest{
		RequestID:       req.RequestID,
		Identity:        req.Identity,
		IdentityLease:   req.IdentityLease,
		Policy:          req.Policy,
		Secrets:         req.Secrets,
		Operation:       operation,
		Namespace:       namespaceFromRef(ref),
		Ref:             refName(ref),
		Value:           value,
		Metadata:        map[string]string{"sourceId": "broker-generated:" + firstNonEmpty(firstNonEmpty(req.Identity.ServiceID, req.ServiceID), ownerFromRef(ref))},
		RefreshRequired: operation == "rotate" || operation == "update",
		InvalidateRefs:  []string{ref},
	})
	res.LastOutcome = capture.Outcome
	res.ProvisionedState = provisioningStateForOutcome(capture.Outcome)
	if err != nil {
		res.Outcome = capture.Outcome
		res.PolicyResult = policyResultForProvisioningOutcome(capture.Outcome)
		res.AuditStatus = "audit_recorded"
		res.NextAction = nextActionForProvisioningOutcome(capture.Outcome)
		_ = b.audit("provisioning_apply", ref, res.Outcome, firstNonEmpty(req.Identity.ServiceID, req.ServiceID), req.RequestID)
		return res, err
	}
	res.Outcome = "applied"
	res.Applied = true
	res.PolicyResult = "allowed"
	res.AuditStatus = "audit_recorded"
	res.ProvisionedState = "ready"
	res.LastOutcome = capture.Outcome
	res.NextAction = "refresh_service_or_continue_startup"
	_ = b.audit("provisioning_apply", ref, res.Outcome, firstNonEmpty(req.Identity.ServiceID, req.ServiceID), req.RequestID)
	return res, nil
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

func provisioningRecordFromLocalEntry(ref string, entry secretEntry) provisioningStatusRecord {
	updated := entry.Metadata.UpdatedAt
	sourceID := firstNonEmpty(entry.Metadata.SourceID, localStoreSource)
	return provisioningStatusRecord{
		Ref:                  ref,
		Namespace:            namespaceFromRef(ref),
		OwnerServiceID:       ownerFromRef(ref),
		SourceID:             sourceID,
		ProviderID:           sourceID,
		ProviderKind:         "local-encrypted-store",
		DesiredOperation:     "none",
		ProvisionedState:     "ready",
		LastOperationID:      entry.Metadata.Version,
		LastOutcome:          "ready",
		AuditStatus:          "audit_available",
		PolicyResult:         "allowed",
		GeneratedValuePolicy: defaultGeneratedValuePolicy(ref),
		UpdatedAt:            &updated,
	}
}

func provisioningRecordFromSource(ref string, source sourceConfig) provisioningStatusRecord {
	lifecycle := sourceRegistryLifecycle(source)
	return provisioningStatusRecord{
		Ref:                  ref,
		Namespace:            namespaceFromRef(ref),
		OwnerServiceID:       ownerFromRef(ref),
		SourceID:             source.SourceID,
		ProviderID:           source.SourceID,
		ProviderKind:         source.Kind,
		DesiredOperation:     "create",
		ProvisionedState:     provisioningStateForOutcome(lifecycle.Outcome),
		LastOutcome:          lifecycle.Outcome,
		NextAction:           firstNonEmpty(lifecycle.NextAction, nextActionForProvisioningOutcome(lifecycle.Outcome)),
		AuditStatus:          "audit_available",
		PolicyResult:         policyResultForProvisioningOutcome(lifecycle.Outcome),
		GeneratedValuePolicy: defaultGeneratedValuePolicy(ref),
	}
}

func missingProvisioningRecord(ref string) provisioningStatusRecord {
	return provisioningStatusRecord{
		Ref:                  ref,
		Namespace:            namespaceFromRef(ref),
		OwnerServiceID:       ownerFromRef(ref),
		SourceID:             localStoreSource,
		ProviderID:           localStoreSource,
		ProviderKind:         "local-encrypted-store",
		DesiredOperation:     "create",
		ProvisionedState:     "not_planned",
		LastOutcome:          "missing_ref",
		NextAction:           "declare_writeback_or_configure_source_ref",
		AuditStatus:          "audit_available",
		PolicyResult:         "unknown",
		GeneratedValuePolicy: defaultGeneratedValuePolicy(ref),
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

func provisioningRecordMatches(record provisioningStatusRecord, query, refFilter string) bool {
	if refFilter != "" && record.Ref != refFilter {
		return false
	}
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{record.Ref, record.Namespace, record.OwnerServiceID, record.SourceID, record.ProviderID, record.ProviderKind, record.DesiredOperation, record.ProvisionedState, record.LastOutcome, record.PolicyResult}, " "))
	return strings.Contains(haystack, query)
}

func namespaceFromRef(ref string) string {
	ref = strings.Trim(ref, "/")
	parts := strings.Split(ref, "/")
	if len(parts) <= 1 {
		return ref
	}
	return strings.Join(parts[:len(parts)-1], "/")
}

func defaultGeneratedValuePolicy(ref string) generatedValuePolicyMetadata {
	return generatedValuePolicyMetadata{
		Kind:           "opaque",
		LengthClass:    "policy_default",
		EntropyClass:   "policy_default",
		RotationPolicy: "service_policy",
	}
}

func firstGeneratedValuePolicy(candidate, fallback generatedValuePolicyMetadata) generatedValuePolicyMetadata {
	if strings.TrimSpace(candidate.Kind) != "" {
		fallback.Kind = strings.TrimSpace(candidate.Kind)
	}
	if strings.TrimSpace(candidate.LengthClass) != "" {
		fallback.LengthClass = strings.TrimSpace(candidate.LengthClass)
	}
	if strings.TrimSpace(candidate.EntropyClass) != "" {
		fallback.EntropyClass = strings.TrimSpace(candidate.EntropyClass)
	}
	if strings.TrimSpace(candidate.RotationPolicy) != "" {
		fallback.RotationPolicy = strings.TrimSpace(candidate.RotationPolicy)
	}
	return fallback
}

func normalizeProvisioningGenerationMode(mode string) string {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return "caller_provided"
	}
	return mode
}

func validProvisioningGenerationMode(mode string) bool {
	switch mode {
	case "caller_provided", "broker_generated":
		return true
	default:
		return false
	}
}

func validBrokerGeneratedProvisioningOperation(operation string) bool {
	switch operation {
	case "create", "update", "rotate":
		return true
	default:
		return false
	}
}

func generateBrokerProvisioningValue(policy generatedValuePolicyMetadata) (string, error) {
	length := 32
	switch strings.TrimSpace(policy.LengthClass) {
	case "", "policy_default", "32_bytes":
		length = 32
	case "16_bytes":
		length = 16
	case "64_bytes":
		length = 64
	default:
		return "", errPolicyDenied
	}
	switch strings.TrimSpace(policy.EntropyClass) {
	case "", "policy_default", "cryptographic":
	default:
		return "", errPolicyDenied
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", errBackendDegraded
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func provisioningStateForOutcome(outcome string) string {
	switch outcome {
	case "ready":
		return "pending"
	case "missing_ref", "disabled":
		return "not_planned"
	case "policy_denied", "source_auth_required", "locked", "invalid_ref":
		return "blocked"
	case "source_unavailable", "degraded":
		return "failed"
	case "stale":
		return "stale"
	default:
		return "blocked"
	}
}

func policyResultForProvisioningOutcome(outcome string) string {
	switch outcome {
	case "ready", "missing_ref", "source_auth_required", "locked", "source_unavailable", "degraded", "disabled":
		return "unknown"
	case "policy_denied":
		return "denied"
	default:
		return "unknown"
	}
}

func nextActionForProvisioningOutcome(outcome string) string {
	switch outcome {
	case "ready":
		return "writeback_generated_value_or_mark_ready"
	case "missing_ref":
		return "check_ref"
	case "policy_denied":
		return "review_policy"
	case "source_auth_required":
		return "reconnect_source"
	case "locked":
		return "unlock_broker"
	case "disabled":
		return "enable_source"
	case "source_unavailable", "degraded":
		return "retry_or_inspect_source"
	default:
		return "inspect_status"
	}
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
	case errors.Is(err, errRotationConflict):
		return "conflict"
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
	case "conflict":
		return "refresh_current_version_and_retry"
	case "source_auth_required":
		return "reconnect_source"
	case "source_unavailable", "degraded":
		return "retry_or_inspect_source"
	default:
		return "inspect_status"
	}
}

func registerSecretsManagementHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/provisioning/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/provisioning/status.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		res, err := backend.listProvisioningStatus(r.URL.Query().Get("search"), r.URL.Query().Get("ref"))
		if err != nil {
			writeManagementError(w, err, res.Outcome, "Provisioning status failed closed.")
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("/v1/provisioning/operations/plan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/provisioning/operations/plan.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req provisioningOperationRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := backend.planProvisioningOperation(req)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, res)
		case errors.Is(err, errInvalidRef):
			writeJSON(w, http.StatusBadRequest, res)
		case errors.Is(err, errLocked):
			writeJSON(w, http.StatusServiceUnavailable, res)
		case errors.Is(err, errUnsupportedProvider):
			writeJSON(w, http.StatusNotImplemented, res)
		default:
			writeJSON(w, http.StatusServiceUnavailable, res)
		}
	})
	mux.HandleFunc("/v1/provisioning/operations/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/provisioning/operations/apply.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req provisioningOperationRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		ref := strings.TrimSpace(req.Ref)
		operation := normalizeWritebackOperation(req.Operation)
		if req.RequireBrokerGenerate || normalizeProvisioningGenerationMode(req.GenerationMode) == "broker_generated" {
			peer := transportPeerIdentityFromContext(r.Context())
			leaseReq := generatedSecretCaptureRequest{Identity: req.Identity, IdentityLease: req.IdentityLease, Operation: operation, Namespace: namespaceFromRef(ref), Ref: refName(ref)}
			if err := backend.authorizeWritebackLaunchLease(&leaseReq, firstNonEmpty(backend.launchIdentitySigningKey, security.token), peer); err != nil {
				writeLaunchIdentityAPIError(w, err)
				return
			}
		}
		res, err := backend.applyProvisioningOperation(req)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, res)
		case errors.Is(err, errInvalidRef):
			writeJSON(w, http.StatusBadRequest, res)
		case errors.Is(err, errPolicyDenied):
			writeJSON(w, http.StatusForbidden, res)
		case errors.Is(err, errUnsupportedProvider):
			writeJSON(w, http.StatusNotImplemented, res)
		case errors.Is(err, errLocked):
			writeJSON(w, http.StatusServiceUnavailable, res)
		default:
			writeJSON(w, http.StatusServiceUnavailable, res)
		}
	})
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
