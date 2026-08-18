package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const operationalEventSecretValue = "fixture-operational-event-secret-value"

func TestOperationalEventsConcurrentWritesRetainEveryAuditProjection(t *testing.T) {
	backend := testBackend(t)
	const count = 32
	var wg sync.WaitGroup
	errs := make(chan error, count)
	readerDone := make(chan struct{})
	readerErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-readerDone:
				readerErr <- nil
				return
			default:
				if _, err := backend.buildEventsResponse(eventFilters{Limit: count}); err != nil {
					readerErr <- err
					return
				}
			}
		}
	}()
	for index := 0; index < count; index++ {
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- backend.writeOperationalEvent(auditEvent{
				TS:        backend.now().Add(time.Duration(index) * time.Millisecond),
				Operation: "lockout_clear",
				Outcome:   "cleared",
				ServiceID: "@operator",
				RequestID: fmt.Sprintf("req-concurrent-%d", index),
			})
		}()
	}
	wg.Wait()
	close(errs)
	close(readerDone)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-readerErr; err != nil {
		t.Fatal(err)
	}

	res, err := backend.buildEventsResponse(eventFilters{Limit: count, Family: "lockout_cleared"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != count {
		t.Fatalf("event count = %d, want %d", len(res.Events), count)
	}
	seen := map[string]bool{}
	for _, event := range res.Events {
		seen[event.RequestID] = true
	}
	for index := 0; index < count; index++ {
		if !seen[fmt.Sprintf("req-concurrent-%d", index)] {
			t.Fatalf("missing concurrent event %d", index)
		}
	}
}

func TestOperationalEventLockoutScopeUsesStablePrefixAndHashOnly(t *testing.T) {
	backend := testBackend(t)
	scope := `local_api:\\.\pipe\service-lasso-secretsbroker-sensitive-workspace`
	if err := backend.writeAuditEvent(auditEvent{
		TS:        backend.now(),
		Operation: "lockout_clear",
		Outcome:   "cleared",
		ServiceID: "@operator",
		Ref:       scope,
		RequestID: "req-lockout-safe-prefix",
	}); err != nil {
		t.Fatal(err)
	}
	res, err := backend.buildEventsResponse(eventFilters{Limit: 10, Family: "lockout_cleared"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || res.Events[0].RefPrefix != "local_api" || res.Events[0].RefHash != hashAuditRef(scope) {
		t.Fatalf("lockout event metadata = %#v", res.Events)
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), scope) || strings.Contains(string(encoded), `\\.\pipe`) {
		t.Fatalf("lockout event exposed raw IPC scope: %s", string(encoded))
	}
}

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

func TestOperationalEventFamiliesAndSourceFilter(t *testing.T) {
	backend := testBackend(t)
	ref := "services/api/runtime/API_TOKEN"
	events := []auditEvent{
		{TS: backend.now(), Operation: "local_api_auth", Outcome: "unauthorized", ServiceID: "@operator", RequestID: "req-auth"},
		{TS: backend.now().Add(time.Second), Operation: "source_lifecycle", Outcome: "source_auth_required", SourceID: "vault-prod", Ref: ref, ServiceID: "api", RequestID: "req-source-auth"},
		{TS: backend.now().Add(2 * time.Second), Operation: "source_lifecycle", Outcome: "ready", SourceID: "vault-prod", Ref: ref, ServiceID: "api", RequestID: "req-source-ready"},
		{TS: backend.now().Add(3 * time.Second), Operation: "provider_config_validate", Outcome: "source_auth_required", ProviderID: "vault-prod", ServiceID: "@serviceadmin", RequestID: "req-provider-auth"},
		{TS: backend.now().Add(4 * time.Second), Operation: "credential_rotation_dry_run", Outcome: "dry_run_ready", Ref: ref, ServiceID: "@serviceadmin", RequestID: "req-rotation"},
		{TS: backend.now().Add(5 * time.Second), Operation: "management_delete_apply", Outcome: "applied", Ref: ref, ServiceID: "@serviceadmin", RequestID: "req-delete"},
	}
	for _, event := range events {
		if err := backend.writeAuditEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	cases := map[string]string{
		"req-auth":          "auth_failure",
		"req-source-auth":   "source_auth_required",
		"req-source-ready":  "source_recovered",
		"req-provider-auth": "source_auth_required",
		"req-rotation":      "rotation_action",
		"req-delete":        "delete_action",
	}
	res, err := buildEventsResponse(backend.eventPath, eventFilters{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range res.Events {
		if want, ok := cases[event.RequestID]; ok && event.Family != want {
			t.Fatalf("%s family = %q, want %q", event.RequestID, event.Family, want)
		}
	}

	filtered, err := buildEventsResponse(backend.eventPath, eventFilters{Limit: 20, SourceID: "vault-prod", Family: "source_auth_required"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Events) != 1 || filtered.Events[0].RequestID != "req-source-auth" || filtered.Events[0].SourceID != "vault-prod" {
		t.Fatalf("source filtered events = %#v", filtered.Events)
	}
	encoded, err := json.Marshal(filtered)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, encoded, operationalEventSecretValue, ref)
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

func TestAdminEventsCLIFiltersBySourceID(t *testing.T) {
	backend := testBackend(t)
	_ = backend.writeAuditEvent(auditEvent{TS: backend.now(), Operation: "source_lifecycle", SourceID: "vault-prod", Outcome: "source_auth_required", Ref: "services/api/runtime/API_TOKEN"})
	_ = backend.writeAuditEvent(auditEvent{TS: backend.now(), Operation: "source_lifecycle", SourceID: "env-dev", Outcome: "source_auth_required", Ref: "services/api/runtime/API_TOKEN"})

	var out bytes.Buffer
	if err := executeAdmin([]string{"events", "list", "--events", backend.eventPath, "--source-id", "vault-prod", "--family", "source_auth_required", "--limit", "10"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"sourceId": "vault-prod"`) || strings.Contains(out.String(), `"sourceId": "env-dev"`) {
		t.Fatalf("source-id filter output = %s", out.String())
	}
}
