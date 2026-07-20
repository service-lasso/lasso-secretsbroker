package main

import (
	"net/http"
	"os"
	"strings"
)

type SourceRegistry struct {
	SourceConfig sourceConfigSecurity `json:"sourceConfig"`
	Sources      []SourceStatus       `json:"sources"`
}

type SourceStatus struct {
	SourceID         string                `json:"sourceId"`
	Kind             string                `json:"kind"`
	DisplayName      string                `json:"displayName"`
	Enabled          bool                  `json:"enabled"`
	Critical         bool                  `json:"critical"`
	Priority         int                   `json:"priority"`
	Capabilities     []string              `json:"capabilities"`
	Operations       []OperationCapability `json:"operations"`
	Namespaces       []string              `json:"namespaces"`
	State            string                `json:"state"`
	Outcome          string                `json:"outcome"`
	NextAction       string                `json:"nextAction,omitempty"`
	Retryable        bool                  `json:"retryable"`
	RetryAfterMs     int                   `json:"retryAfterMs,omitempty"`
	Lifecycle        SourceLifecycle       `json:"lifecycle"`
	AuditStatus      string                `json:"auditStatus"`
	AffectedRefs     []string              `json:"affectedRefs"`
	AffectedServices []string              `json:"affectedServices"`
}

type sourceStatusResponse struct {
	ServiceID       string               `json:"serviceId"`
	APIVersion      string               `json:"apiVersion"`
	ContractVersion string               `json:"contractVersion"`
	ManifestVersion string               `json:"manifestVersion"`
	SourceConfig    sourceConfigSecurity `json:"sourceConfig"`
	Sources         []SourceStatus       `json:"sources"`
}

func defaultSourceRegistry(backend *localBackend) SourceRegistry {
	outcome := "locked"
	if backend != nil && !backend.locked() {
		outcome = "ready"
	}
	auditStatus := auditStatusForBackend(backend)
	localLifecycle := normalizeSourceLifecycle(outcome)
	localStatus := SourceStatus{
		SourceID:         "local",
		Kind:             "local-encrypted-store",
		DisplayName:      "Local encrypted store",
		Enabled:          true,
		Critical:         true,
		Priority:         0,
		Capabilities:     capabilitiesForSourceKind("local-encrypted-store"),
		Namespaces:       []string{"*"},
		State:            localLifecycle.State,
		Outcome:          localLifecycle.Outcome,
		NextAction:       localLifecycle.NextAction,
		Retryable:        localLifecycle.Retryable,
		RetryAfterMs:     localLifecycle.RetryAfterMs,
		Lifecycle:        localLifecycle,
		AuditStatus:      auditStatus,
		AffectedRefs:     []string{},
		AffectedServices: []string{},
	}
	localStatus.Operations = providerOperationCapabilitiesForSource(localStatus.Kind, localStatus.Lifecycle, localStatus.AuditStatus)
	sources := []SourceStatus{localStatus}
	if backend != nil {
		for _, source := range backend.sources.Sources {
			lifecycle := sourceRegistryLifecycle(source)
			status := SourceStatus{
				SourceID:         source.SourceID,
				Kind:             source.Kind,
				DisplayName:      firstNonEmpty(source.DisplayName, source.SourceID),
				Enabled:          source.Enabled,
				Critical:         source.Critical,
				Priority:         source.Priority,
				Capabilities:     capabilitiesForSourceKind(source.Kind),
				Namespaces:       safeList(source.Namespaces),
				State:            lifecycle.State,
				Outcome:          lifecycle.Outcome,
				NextAction:       lifecycle.NextAction,
				Retryable:        lifecycle.Retryable,
				RetryAfterMs:     lifecycle.RetryAfterMs,
				Lifecycle:        lifecycle,
				AuditStatus:      auditStatus,
				AffectedRefs:     []string{},
				AffectedServices: []string{},
			}
			status.Operations = providerOperationCapabilitiesForSource(status.Kind, status.Lifecycle, status.AuditStatus)
			if len(status.Namespaces) == 0 {
				status.Namespaces = []string{"*"}
			}
			sources = append(sources, status)
		}
	}
	configSecurity := defaultSourceConfigSecurity()
	if backend != nil {
		configSecurity = normalizeSourceConfigSecurity(backend.sources.Security)
	}
	return SourceRegistry{SourceConfig: configSecurity, Sources: sources}
}

func auditStatusForBackend(backend *localBackend) string {
	if backend == nil || strings.TrimSpace(backend.auditPath) == "" {
		return "audit_unavailable"
	}
	return "audit_available"
}

func sourceRegistryLifecycle(source sourceConfig) SourceLifecycle {
	if !source.Enabled {
		return disabledSourceLifecycle()
	}
	switch strings.ToLower(strings.TrimSpace(source.Kind)) {
	case "env", "file", "exec":
		if len(source.Refs) == 0 {
			return normalizeSourceLifecycle("missing_ref")
		}
	case "onepassword-cli":
		if len(source.Refs) == 0 {
			return normalizeSourceLifecycle("missing_ref")
		}
		if !sourceHasCommandMapping(source) {
			return normalizeSourceLifecycle("invalid_ref")
		}
	case "vault", "openbao":
		if strings.TrimSpace(source.Address) == "" {
			return normalizeSourceLifecycle("invalid_ref")
		}
		if strings.TrimSpace(firstNonEmpty(source.Token, os.Getenv(source.TokenEnv))) == "" {
			return normalizeSourceLifecycle("source_auth_required")
		}
	case "bitwarden-bws":
		if len(source.Refs) == 0 {
			return normalizeSourceLifecycle("missing_ref")
		}
		if strings.TrimSpace(source.Address) == "" && !sourceHasCommandMapping(source) {
			return normalizeSourceLifecycle("invalid_ref")
		}
		if strings.TrimSpace(firstNonEmpty(source.Token, os.Getenv(source.TokenEnv))) == "" {
			return normalizeSourceLifecycle("source_auth_required")
		}
	case "aws-secrets-manager":
		if len(source.Refs) == 0 {
			return normalizeSourceLifecycle("missing_ref")
		}
		if strings.TrimSpace(source.Address) == "" && strings.TrimSpace(source.Region) == "" {
			return normalizeSourceLifecycle("invalid_ref")
		}
		if strings.TrimSpace(firstNonEmpty(source.Token, os.Getenv(source.TokenEnv))) == "" {
			return normalizeSourceLifecycle("source_auth_required")
		}
	default:
		return normalizeSourceLifecycle("invalid_ref")
	}
	return normalizeSourceLifecycle("ready")
}

func capabilitiesForSourceKind(kind string) []string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "local-encrypted-store":
		contract, ok := adapterContractForKind(kind)
		if ok {
			return append(adapterCapabilityNames(contract.Capabilities), "health")
		}
		return []string{"read", "reveal", "write/update", "rotate/reset", "audit", "migration", "health"}
	case "exec":
		contract, ok := adapterContractForKind(kind)
		if ok {
			return append(adapterCapabilityNames(contract.Capabilities), "health")
		}
		return []string{"read", "reveal", "audit", "migration", "health"}
	case "env":
		contract, ok := adapterContractForKind(kind)
		if ok {
			return append(adapterCapabilityNames(contract.Capabilities), "health")
		}
		return []string{"read", "reveal", "migration", "health"}
	case "file":
		contract, ok := adapterContractForKind(kind)
		if ok {
			return append(adapterCapabilityNames(contract.Capabilities), "health")
		}
		return []string{"read", "reveal", "migration", "health"}
	case "bitwarden-bws":
		contract, ok := adapterContractForKind(kind)
		if ok {
			return append(adapterCapabilityNames(contract.Capabilities), "health")
		}
		return []string{"read", "reveal", "write/update", "audit", "migration", "health"}
	case "aws-secrets-manager":
		contract, ok := adapterContractForKind(kind)
		if ok {
			return append(adapterCapabilityNames(contract.Capabilities), "health")
		}
		return []string{"read", "reveal", "write/update", "rotate/reset", "policy", "value-search", "audit", "migration", "health"}
	case "onepassword-cli":
		contract, ok := adapterContractForKind(kind)
		if ok {
			return append(adapterCapabilityNames(contract.Capabilities), "health")
		}
		return []string{"read", "reveal", "audit", "migration", "health"}
	case "vault", "openbao":
		contract, ok := adapterContractForKind(kind)
		if ok {
			return append(adapterCapabilityNames(contract.Capabilities), "health")
		}
		return []string{"read", "reveal", "write/update", "rotate/reset", "policy", "audit", "migration", "health"}
	default:
		return []string{"health"}
	}
}

func sourceHasCommandMapping(source sourceConfig) bool {
	for _, ref := range source.Refs {
		if strings.TrimSpace(ref.Command) != "" {
			return true
		}
	}
	return false
}

func registerSourceRegistryHandlers(mux *http.ServeMux, backend *localBackend) {
	mux.HandleFunc("/v1/sources/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/sources/status.", "invalid_ref", "")
			return
		}
		registry := defaultSourceRegistry(backend)
		writeJSON(w, http.StatusOK, sourceStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, ContractVersion: contractVersion, ManifestVersion: operationManifestVersion, SourceConfig: registry.SourceConfig, Sources: registry.Sources})
	})
}
