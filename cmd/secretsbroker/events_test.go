package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const operationalEventSecretValue = "fixture-operational-event-secret-value"

func TestOperationalEventsRetainFilterAndStayMetadataOnly(t *testing.T) {
	backend := testBackend(t)
	ref := "services/api/runtime/API_TOKEN"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: ref, Value: operationalEventSecretValue}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxOperationalEventLimit+5; i++ {
		backend.now = func() time.Time {
			return time.Date(2026, 5, 7, 0, 0, i, 0, time.UTC)
		}
		_ = backend.writeAuditEvent(auditEvent{
			TS:        backend.now(),
			Operation: "policy_decision",
			ServiceID: "api-" + strconv.Itoa(i),
			Ref:       ref,
			Outcome:   "denied",
			RequestID: "req-" + strconv.Itoa(i),
		})
	}

	res, err := buildEventsResponse(backend.eventPath, eventFilters{Limit: maxOperationalEventLimit})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != maxOperationalEventLimit {
		t.Fatalf("event count = %d, want %d", len(res.Events), maxOperationalEventLimit)
	}
	if res.Events[0].RequestID != "req-5" {
		t.Fatalf("retention did not drop oldest events first: %#v", res.Events[0])
	}
	filtered, err := buildEventsResponse(backend.eventPath, eventFilters{Limit: 10, ServiceID: "api-204", Family: "policy_decision", RefPrefix: "services/api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Events) != 1 || filtered.Events[0].Outcome != "denied" || filtered.Events[0].Severity != "warning" {
		t.Fatalf("filtered events = %#v", filtered.Events)
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, encoded, operationalEventSecretValue, "test-master-key", ref)
	if strings.Contains(string(encoded), ref) {
		t.Fatalf("events exposed raw ref: %s", string(encoded))
	}
	if !res.Safety.MetadataOnly || res.Safety.RawRefIncluded || res.Safety.ValueMaterialIncluded {
		t.Fatalf("unsafe event safety flags: %#v", res.Safety)
	}
}

func TestOperationalEventsEndpointPaginationAndInvalidFilters(t *testing.T) {
	backend := testBackend(t)
	for i := 0; i < 3; i++ {
		_ = backend.writeAuditEvent(auditEvent{TS: backend.now().Add(time.Duration(i) * time.Second), Operation: "provider_status", ProviderID: "vault", Outcome: "degraded"})
	}
	server := httptest.NewServer(newHandler(runtimeState{}, backend, localAPISecurity{}))
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/events?family=provider_unavailable&limit=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d", resp.StatusCode)
	}
	var page eventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 || page.NextCursor != "2" {
		t.Fatalf("first page = %#v", page)
	}

	bad, err := http.Get(server.URL + "/v1/events?limit=0")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad filter status = %d", bad.StatusCode)
	}
	var envelope ErrorEnvelope
	if err := json.NewDecoder(bad.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != "invalid_event_filter" {
		t.Fatalf("bad filter error = %#v", envelope.Error)
	}
}

func TestAdminEventsCLIReadsMetadataOnlyEvents(t *testing.T) {
	backend := testBackend(t)
	ref := "services/api/runtime/API_TOKEN"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: ref, Value: operationalEventSecretValue}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := executeAdmin([]string{"events", "list", "--events", backend.eventPath, "--family", "audit_recorded", "--limit", "1"}, &out); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, out.Bytes(), operationalEventSecretValue, "test-master-key", ref)
	if !strings.Contains(out.String(), "events") || !strings.Contains(out.String(), "audit_recorded") {
		t.Fatalf("events CLI output missing expected metadata: %s", out.String())
	}
}
