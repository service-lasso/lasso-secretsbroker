package main

import "net/http"

type SourceRegistry struct {
	Sources []SourceStatus `json:"sources"`
}

type SourceStatus struct {
	SourceID         string   `json:"sourceId"`
	Kind             string   `json:"kind"`
	DisplayName      string   `json:"displayName"`
	Enabled          bool     `json:"enabled"`
	Critical         bool     `json:"critical"`
	Priority         int      `json:"priority"`
	Capabilities     []string `json:"capabilities"`
	Namespaces       []string `json:"namespaces"`
	State            string   `json:"state"`
	AffectedRefs     []string `json:"affectedRefs"`
	AffectedServices []string `json:"affectedServices"`
}

type sourceStatusResponse struct {
	ServiceID  string         `json:"serviceId"`
	APIVersion string         `json:"apiVersion"`
	Sources    []SourceStatus `json:"sources"`
}

func defaultSourceRegistry(backend *localBackend) SourceRegistry {
	state := "locked"
	if backend != nil && !backend.locked() {
		state = "ready"
	}
	return SourceRegistry{Sources: []SourceStatus{
		{
			SourceID:         "local",
			Kind:             "local-encrypted-store",
			DisplayName:      "Local encrypted store",
			Enabled:          true,
			Critical:         true,
			Priority:         0,
			Capabilities:     []string{"read", "write", "health"},
			Namespaces:       []string{"*"},
			State:            state,
			AffectedRefs:     []string{},
			AffectedServices: []string{},
		},
	}}
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
