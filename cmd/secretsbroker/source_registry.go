package main

import (
	"net/http"
	"os"
	"strings"
)

type SourceRegistry struct {
	Sources []SourceStatus `json:"sources"`
}

type SourceStatus struct {
	SourceID         string          `json:"sourceId"`
	Kind             string          `json:"kind"`
	DisplayName      string          `json:"displayName"`
	Enabled          bool            `json:"enabled"`
	Critical         bool            `json:"critical"`
	Priority         int             `json:"priority"`
	Capabilities     []string        `json:"capabilities"`
	Namespaces       []string        `json:"namespaces"`
	State            string          `json:"state"`
	Outcome          string          `json:"outcome"`
	NextAction       string          `json:"nextAction,omitempty"`
	Retryable        bool            `json:"retryable"`
	RetryAfterMs     int             `json:"retryAfterMs,omitempty"`
	Lifecycle        SourceLifecycle `json:"lifecycle"`
	AffectedRefs     []string        `json:"affectedRefs"`
	AffectedServices []string        `json:"affectedServices"`
}

type sourceStatusResponse struct {
	ServiceID  string         `json:"serviceId"`
	APIVersion string         `json:"apiVersion"`
	Sources    []SourceStatus `json:"sources"`
}

func defaultSourceRegistry(backend *localBackend) SourceRegistry {
	outcome := "locked"
	if backend != nil && !backend.locked() {
		outcome = "ready"
	}
	localLifecycle := normalizeSourceLifecycle(outcome)
	sources := []SourceStatus{
		{
			SourceID:         "local",
			Kind:             "local-encrypted-store",
			DisplayName:      "Local encrypted store",
			Enabled:          true,
			Critical:         true,
			Priority:         0,
			Capabilities:     []string{"read", "write", "health"},
			Namespaces:       []string{"*"},
			State:            localLifecycle.State,
			Outcome:          localLifecycle.Outcome,
			NextAction:       localLifecycle.NextAction,
			Retryable:        localLifecycle.Retryable,
			RetryAfterMs:     localLifecycle.RetryAfterMs,
			Lifecycle:        localLifecycle,
			AffectedRefs:     []string{},
			AffectedServices: []string{},
		},
	}
	if backend != nil {
		for _, source := range backend.sources.enabledSources() {
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
				AffectedRefs:     []string{},
				AffectedServices: []string{},
			}
			if len(status.Namespaces) == 0 {
				status.Namespaces = []string{"*"}
			}
			sources = append(sources, status)
		}
	}
	return SourceRegistry{Sources: sources}
}

func sourceRegistryLifecycle(source sourceConfig) SourceLifecycle {
	if !source.Enabled {
		return disabledSourceLifecycle()
	}
	switch source.Kind {
	case "env", "file", "exec":
		if len(source.Refs) == 0 {
			return normalizeSourceLifecycle("missing_ref")
		}
	case "vault", "openbao":
		if strings.TrimSpace(source.Address) == "" {
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
	switch kind {
	case "env", "file", "exec", "vault", "openbao":
		return []string{"read", "health"}
	default:
		return []string{"health"}
	}
}

func registerSourceRegistryHandlers(mux *http.ServeMux, backend *localBackend) {
	mux.HandleFunc("/v1/sources/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/sources/status.", "invalid_ref", "")
			return
		}
		registry := defaultSourceRegistry(backend)
		writeJSON(w, http.StatusOK, sourceStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Sources: registry.Sources})
	})
}
