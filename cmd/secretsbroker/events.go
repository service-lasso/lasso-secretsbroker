package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultOperationalEventLimit = 50
	maxOperationalEventLimit     = 200
)

var errInvalidEventFilter = errors.New("invalid event filter")

type operationalEvent struct {
	ID         string    `json:"id"`
	TS         time.Time `json:"ts"`
	Family     string    `json:"family"`
	Severity   string    `json:"severity"`
	Operation  string    `json:"operation"`
	ServiceID  string    `json:"serviceId,omitempty"`
	ProviderID string    `json:"providerId,omitempty"`
	SourceID   string    `json:"sourceId,omitempty"`
	PolicyID   string    `json:"policyId,omitempty"`
	KeyID      string    `json:"keyId,omitempty"`
	RefPrefix  string    `json:"refPrefix,omitempty"`
	RefHash    string    `json:"refHash,omitempty"`
	Outcome    string    `json:"outcome"`
	RequestID  string    `json:"requestId,omitempty"`
}

type eventSafety struct {
	MetadataOnly          bool `json:"metadataOnly"`
	RawRefIncluded        bool `json:"rawRefIncluded"`
	ValueMaterialIncluded bool `json:"valueMaterialIncluded"`
}

type eventsResponse struct {
	ServiceID   string             `json:"serviceId"`
	APIVersion  string             `json:"apiVersion"`
	Outcome     string             `json:"outcome"`
	GeneratedAt time.Time          `json:"generatedAt"`
	Limit       int                `json:"limit"`
	NextCursor  string             `json:"nextCursor,omitempty"`
	Events      []operationalEvent `json:"events"`
	Safety      eventSafety        `json:"safety"`
}

type eventFilters struct {
	Since      *time.Time
	Until      *time.Time
	ServiceID  string
	ProviderID string
	SourceID   string
	Operation  string
	Outcome    string
	Severity   string
	Family     string
	RefPrefix  string
	RefHash    string
	Limit      int
	Cursor     int
}

type eventFilterError struct {
	Field   string
	Message string
}

func (e eventFilterError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func (b *localBackend) writeOperationalEvent(audit auditEvent) error {
	if strings.TrimSpace(b.eventPath) == "" {
		return nil
	}
	b.eventMu.Lock()
	defer b.eventMu.Unlock()
	event := operationalEventFromAudit(audit)
	events, err := loadOperationalEvents(b.eventPath)
	if err != nil {
		return err
	}
	events = append(events, event)
	if len(events) > maxOperationalEventLimit {
		events = events[len(events)-maxOperationalEventLimit:]
	}
	return saveOperationalEvents(b.eventPath, events)
}

func operationalEventFromAudit(audit auditEvent) operationalEvent {
	audit = normalizeAuditEvent(audit)
	event := operationalEvent{
		TS:         audit.TS,
		Family:     eventFamily(audit),
		Severity:   eventSeverity(audit.Outcome),
		Operation:  audit.Operation,
		ServiceID:  audit.ServiceID,
		ProviderID: audit.ProviderID,
		SourceID:   audit.SourceID,
		PolicyID:   audit.PolicyID,
		KeyID:      audit.KeyID,
		RefPrefix:  safeRefPrefix(audit.Ref),
		RefHash:    audit.RefHash,
		Outcome:    audit.Outcome,
		RequestID:  audit.RequestID,
	}
	event.ID = strings.Join([]string{event.TS.Format(time.RFC3339Nano), event.Family, event.Operation, event.Outcome, event.RefHash}, ":")
	return event
}

func eventFamily(audit auditEvent) string {
	if audit.AuditStatus != "" && audit.AuditStatus != "audit_recorded" {
		return "audit_unavailable"
	}
	switch {
	case audit.Operation == "local_api_auth" && audit.Outcome != "ready":
		return "auth_failure"
	case audit.Operation == "lockout_clear":
		return "lockout_cleared"
	case strings.Contains(audit.Operation, "lockout"):
		return "lockout_started"
	case audit.Operation == "policy_decision":
		return "policy_decision"
	case audit.Operation == "source_lifecycle" && audit.Outcome == "ready":
		return "source_recovered"
	case audit.Operation == "source_lifecycle" && audit.Outcome == "source_auth_required":
		return "source_auth_required"
	case audit.Operation == "source_lifecycle":
		return "source_unavailable"
	case strings.HasPrefix(audit.Operation, "provider_") && audit.Outcome == "ready":
		return "provider_recovered"
	case strings.HasPrefix(audit.Operation, "provider_") && audit.Outcome == "source_auth_required":
		return "source_auth_required"
	case strings.HasPrefix(audit.Operation, "provider_"):
		return "provider_unavailable"
	case audit.Operation == "management_reveal":
		return "management_reveal"
	case strings.Contains(audit.Operation, "rotation"):
		return "rotation_action"
	case strings.Contains(audit.Operation, "delete"):
		return "delete_action"
	case strings.HasPrefix(audit.Operation, "management_"):
		return "management_apply"
	case strings.HasPrefix(audit.Operation, "key_"):
		return "key_lifecycle"
	case strings.HasPrefix(audit.Operation, "recovery_policy_"):
		return "key_lifecycle"
	case strings.HasPrefix(audit.Operation, "backup_"):
		return "backup_restore"
	default:
		return "audit_recorded"
	}
}

func eventSeverity(outcome string) string {
	switch outcome {
	case "ready", "allowed", "cleared", "not_found":
		return "info"
	case "degraded", "invalid_ref", "identity_expired":
		return "error"
	default:
		return "warning"
	}
}

func safeRefPrefix(ref string) string {
	ref = strings.Trim(strings.TrimSpace(ref), "/")
	if ref == "" {
		return ""
	}
	for _, lockoutPrefix := range []string{"local_api:", "management:", "writeback:"} {
		if strings.HasPrefix(ref, lockoutPrefix) {
			return strings.TrimSuffix(lockoutPrefix, ":")
		}
	}
	parts := strings.Split(ref, "/")
	if len(parts) <= 2 {
		return strings.Join(parts, "/")
	}
	return strings.Join(parts[:2], "/")
}

func loadOperationalEvents(path string) ([]operationalEvent, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []operationalEvent{}, nil
	}
	if err != nil {
		return nil, errBackendDegraded
	}
	defer file.Close()
	events := []operationalEvent{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event operationalEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, errBackendDegraded
		}
		events = append(events, normalizeOperationalEvent(event))
	}
	if err := scanner.Err(); err != nil {
		return nil, errBackendDegraded
	}
	return events, nil
}

func saveOperationalEvents(path string, events []operationalEvent) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var builder strings.Builder
	enc := json.NewEncoder(&builder)
	for _, event := range events {
		if err := enc.Encode(normalizeOperationalEvent(event)); err != nil {
			return err
		}
	}
	return writePrivateFileAtomically(path, []byte(builder.String()))
}

func normalizeOperationalEvent(event operationalEvent) operationalEvent {
	event.Family = scrubAuditField(event.Family)
	event.Severity = scrubAuditField(event.Severity)
	event.Operation = scrubAuditField(event.Operation)
	event.ServiceID = scrubAuditField(event.ServiceID)
	event.ProviderID = scrubAuditField(event.ProviderID)
	event.SourceID = scrubAuditField(event.SourceID)
	event.PolicyID = scrubAuditField(event.PolicyID)
	event.KeyID = scrubAuditField(event.KeyID)
	event.RefPrefix = scrubAuditField(event.RefPrefix)
	event.RefHash = scrubAuditField(event.RefHash)
	event.Outcome = scrubAuditField(event.Outcome)
	event.RequestID = scrubAuditField(event.RequestID)
	event.ID = scrubAuditField(event.ID)
	if event.Family == "" {
		event.Family = "audit_recorded"
	}
	if event.Severity == "" {
		event.Severity = eventSeverity(event.Outcome)
	}
	if event.Outcome == "" {
		event.Outcome = "degraded"
	}
	return event
}

func parseEventFilters(values url.Values) (eventFilters, error) {
	filters := eventFilters{Limit: defaultOperationalEventLimit}
	var err error
	if filters.Since, err = parseEventTime(values.Get("since"), "since"); err != nil {
		return filters, err
	}
	if filters.Until, err = parseEventTime(values.Get("until"), "until"); err != nil {
		return filters, err
	}
	if filters.Since != nil && filters.Until != nil && filters.Since.After(*filters.Until) {
		return filters, eventFilterError{Field: "since", Message: "must be before until"}
	}
	filters.ServiceID = scrubAuditField(values.Get("serviceId"))
	filters.ProviderID = scrubAuditField(values.Get("providerId"))
	filters.SourceID = scrubAuditField(values.Get("sourceId"))
	filters.Operation = scrubAuditField(values.Get("operation"))
	filters.Outcome = scrubAuditField(values.Get("outcome"))
	filters.Severity = scrubAuditField(values.Get("severity"))
	filters.Family = scrubAuditField(values.Get("family"))
	filters.RefPrefix = scrubAuditField(values.Get("refPrefix"))
	filters.RefHash = scrubAuditField(values.Get("refHash"))
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > maxOperationalEventLimit {
			return filters, eventFilterError{Field: "limit", Message: "must be an integer from 1 to 200"}
		}
		filters.Limit = limit
	}
	if raw := strings.TrimSpace(values.Get("cursor")); raw != "" {
		cursor, err := strconv.Atoi(raw)
		if err != nil || cursor < 0 {
			return filters, eventFilterError{Field: "cursor", Message: "must be a non-negative integer"}
		}
		filters.Cursor = cursor
	}
	return filters, nil
}

func parseEventTime(value, field string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, eventFilterError{Field: field, Message: "must be RFC3339"}
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func buildEventsResponse(path string, filters eventFilters) (eventsResponse, error) {
	res := eventsResponse{
		ServiceID:   serviceID,
		APIVersion:  apiVersion,
		Outcome:     "ready",
		GeneratedAt: time.Now().UTC(),
		Limit:       filters.Limit,
		Events:      []operationalEvent{},
		Safety:      eventSafety{MetadataOnly: true, RawRefIncluded: false, ValueMaterialIncluded: false},
	}
	events, err := loadOperationalEvents(path)
	if err != nil {
		res.Outcome = "degraded"
		return res, err
	}
	filtered := make([]operationalEvent, 0, len(events))
	for _, event := range events {
		if eventMatchesFilters(event, filters) {
			filtered = append(filtered, event)
		}
	}
	if filters.Cursor > len(filtered) {
		return res, eventFilterError{Field: "cursor", Message: "is beyond the filtered event set"}
	}
	end := filters.Cursor + filters.Limit
	if end > len(filtered) {
		end = len(filtered)
	}
	res.Events = append(res.Events, filtered[filters.Cursor:end]...)
	if end < len(filtered) {
		res.NextCursor = strconv.Itoa(end)
	}
	return res, nil
}

func (b *localBackend) buildEventsResponse(filters eventFilters) (eventsResponse, error) {
	b.eventMu.RLock()
	defer b.eventMu.RUnlock()
	return buildEventsResponse(b.eventPath, filters)
}

func eventMatchesFilters(event operationalEvent, filters eventFilters) bool {
	if filters.Since != nil && event.TS.Before(*filters.Since) {
		return false
	}
	if filters.Until != nil && event.TS.After(*filters.Until) {
		return false
	}
	if filters.ServiceID != "" && event.ServiceID != filters.ServiceID {
		return false
	}
	if filters.ProviderID != "" && event.ProviderID != filters.ProviderID {
		return false
	}
	if filters.SourceID != "" && event.SourceID != filters.SourceID {
		return false
	}
	if filters.Operation != "" && event.Operation != filters.Operation {
		return false
	}
	if filters.Outcome != "" && event.Outcome != filters.Outcome {
		return false
	}
	if filters.Severity != "" && event.Severity != filters.Severity {
		return false
	}
	if filters.Family != "" && event.Family != filters.Family {
		return false
	}
	if filters.RefHash != "" && event.RefHash != filters.RefHash {
		return false
	}
	if filters.RefPrefix != "" && !strings.HasPrefix(event.RefPrefix, filters.RefPrefix) {
		return false
	}
	return true
}

func registerEventsHandlers(mux *http.ServeMux, backend *localBackend) {
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET /v1/events.", "invalid_ref", "")
			return
		}
		filters, err := parseEventFilters(r.URL.Query())
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_event_filter", err.Error(), "invalid_ref", "adjust_event_filter")
			return
		}
		res, err := backend.buildEventsResponse(filters)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}
