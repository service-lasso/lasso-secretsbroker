package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

type ramFileOwner struct {
	WorkspaceID string `json:"workspaceId"`
	ServiceID   string `json:"serviceId"`
}

type ramFileUsage struct {
	mu          sync.Mutex
	downloads   uint64
	servedBytes uint64
	lastAccess  time.Time
}

type ramFileMetadata struct {
	GrantID      string `json:"grantId"`
	WorkspaceID  string `json:"workspaceId"`
	ServiceID    string `json:"serviceId"`
	Path         string `json:"path"`
	SizeBytes    int    `json:"sizeBytes"`
	CreatedAt    string `json:"createdAt"`
	Downloads    uint64 `json:"downloads"`
	ServedBytes  uint64 `json:"servedBytes"`
	LastAccessAt string `json:"lastAccessAt,omitempty"`
}

type ramStatusResponse struct {
	ServiceID     string            `json:"serviceId"`
	Outcome       string            `json:"outcome"`
	State         string            `json:"state"`
	GeneratedAt   string            `json:"generatedAt"`
	CapacityBytes int               `json:"capacityBytes"`
	UsedBytes     int               `json:"usedBytes"`
	ActiveGrants  int               `json:"activeGrants"`
	FileCount     int               `json:"fileCount"`
	Downloads     uint64            `json:"downloads"`
	ServedBytes   uint64            `json:"servedBytes"`
	Files         []ramFileMetadata `json:"files"`
	NextCursor    string            `json:"nextCursor,omitempty"`
}

func (s *ramFileStore) status(cursor, limit int) ramStatusResponse {
	result := ramStatusResponse{ServiceID: "@secretsbroker", Outcome: "unavailable", State: "stopped", GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), CapacityBytes: maxRAMStoreBytes, Files: []ramFileMetadata{}}
	if s == nil {
		return result
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.baseURL != "" && !s.closed {
		result.State = "listening"
		result.Outcome = "ready"
	}
	result.UsedBytes = s.bytes
	result.ActiveGrants = len(s.grants)
	// Order only names and references; never clone plaintext for management.
	rows := make([]ramFileMetadata, 0)
	for _, grant := range s.grants {
		for name, content := range grant.files {
			usage := grant.usage[name]
			usage.mu.Lock()
			row := ramFileMetadata{GrantID: grant.id, WorkspaceID: grant.identity.WorkspaceID, ServiceID: grant.identity.ServiceID, Path: name, SizeBytes: len(content), CreatedAt: grant.created.Format(time.RFC3339Nano), Downloads: usage.downloads, ServedBytes: usage.servedBytes}
			if !usage.lastAccess.IsZero() {
				row.LastAccessAt = usage.lastAccess.Format(time.RFC3339Nano)
			}
			usage.mu.Unlock()
			rows = append(rows, row)
			result.Downloads += row.Downloads
			result.ServedBytes += row.ServedBytes
		}
	}
	result.FileCount = len(rows)
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.WorkspaceID != b.WorkspaceID {
			return a.WorkspaceID < b.WorkspaceID
		}
		if a.ServiceID != b.ServiceID {
			return a.ServiceID < b.ServiceID
		}
		if a.GrantID != b.GrantID {
			return a.GrantID < b.GrantID
		}
		return a.Path < b.Path
	})
	if cursor >= len(rows) {
		return result
	}
	end := cursor + limit
	if end < len(rows) {
		result.NextCursor = strconv.Itoa(end)
	} else {
		end = len(rows)
	}
	result.Files = rows[cursor:end]
	return result
}

func registerRAMStatusHandler(mux *http.ServeMux, b *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/file-grants/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, 405, "method_not_allowed", "Use GET.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		params, err := parseRAMStatusQuery(r)
		if err {
			writeAPIError(w, 400, "invalid_request", "Invalid inventory pagination.", "invalid_ref", "")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		status := b.ramFiles.status(params[0], params[1])
		// Bound actual encoded metadata too: unusual signed owner identifiers
		// must not turn pagination into an oversized protected IPC response.
		for {
			encoded, err := json.Marshal(status)
			if err == nil && len(encoded) <= 768<<10 {
				break
			}
			if len(status.Files) <= 1 {
				writeAPIError(w, 503, "inventory_unavailable", "Inventory metadata exceeds the response budget.", "backend_degraded", "")
				return
			}
			status.Files = status.Files[:len(status.Files)/2]
			status.NextCursor = strconv.Itoa(params[0] + len(status.Files))
		}
		writeJSON(w, 200, status)
	})
}

func parseRAMStatusQuery(r *http.Request) ([2]int, bool) {
	result := [2]int{0, 100}
	values := r.URL.Query()
	for name, entries := range values {
		if len(entries) != 1 || (name != "cursor" && name != "limit") {
			return result, true
		}
		raw := entries[0]
		if len(raw) == 0 || len(raw) > 6 {
			return result, true
		}
		for _, c := range raw {
			if c < '0' || c > '9' {
				return result, true
			}
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			return result, true
		}
		if name == "limit" {
			if value < 1 || value > 200 {
				return result, true
			}
			result[1] = value
		} else {
			if value > maxRAMGrants*128 {
				return result, true
			}
			result[0] = value
		}
	}
	return result, false
}
