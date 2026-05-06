package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultStatus(t *testing.T) {
	status := defaultStatus("")
	if status.ServiceID != "@secretsbroker" {
		t.Fatalf("service id = %q", status.ServiceID)
	}
	if status.APIVersion != apiVersion {
		t.Fatalf("api version = %q", status.APIVersion)
	}
	if status.State != "setup_needed" {
		t.Fatalf("state = %q", status.State)
	}
	if status.Ready {
		t.Fatalf("setup_needed should not be ready")
	}

	ready := defaultStatus("ready")
	if !ready.Ready {
		t.Fatalf("ready state should report Ready")
	}
}

func TestCapabilitiesExposeBootstrapContract(t *testing.T) {
	caps := defaultCapabilities()
	if caps.ServiceID != "@secretsbroker" {
		t.Fatalf("service id = %q", caps.ServiceID)
	}
	if caps.APIVersion != apiVersion {
		t.Fatalf("api version = %q", caps.APIVersion)
	}
	assertContains(t, caps.Endpoints, "GET /capabilities")
	assertContains(t, caps.Endpoints, "GET /ready")
	assertContains(t, caps.Features, "readiness")
	assertContains(t, caps.FutureFeatures, "batched-resolve")
	assertContains(t, caps.Outcomes, "source_auth_required")
	assertContains(t, caps.Outcomes, "policy_denied")
}

func TestReadyEndpointDistinguishesLivenessFromReadiness(t *testing.T) {
	state := "locked"
	affectedRefs := []string{"openclaw/anthropic/api_key"}
	affectedServices := []string{"openclaw"}
	server := httptest.NewServer(newHandler(runtimeState{state: &state, affectedRefs: &affectedRefs, affectedServices: &affectedServices}))
	defer server.Close()

	res, err := http.Get(server.URL + "/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d", res.StatusCode)
	}
	var body StateResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Ready {
		t.Fatalf("locked state should not be ready")
	}
	if body.Outcome != "locked" {
		t.Fatalf("outcome = %q", body.Outcome)
	}
	if body.KeyState != "locked" {
		t.Fatalf("keyState = %q", body.KeyState)
	}
	if body.NextAction != "unlock_broker" {
		t.Fatalf("nextAction = %q", body.NextAction)
	}
	assertContains(t, body.AffectedRefs, "openclaw/anthropic/api_key")
	assertContains(t, body.AffectedServices, "openclaw")

	state = "ready"
	res, err = http.Get(server.URL + "/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ready status code = %d", res.StatusCode)
	}
}

func TestLifecycleStateOutcomesAndActions(t *testing.T) {
	tests := []struct {
		state      string
		ready      bool
		keyState   string
		nextAction string
	}{
		{state: "setup_needed", ready: false, keyState: "not_initialized", nextAction: "run_setup"},
		{state: "ready", ready: true, keyState: "available", nextAction: ""},
		{state: "locked", ready: false, keyState: "locked", nextAction: "unlock_broker"},
		{state: "source_auth_required", ready: false, keyState: "available", nextAction: "reconnect_source"},
		{state: "degraded", ready: false, keyState: "available", nextAction: "inspect_sources"},
		{state: "policy_denied", ready: false, keyState: "available", nextAction: "review_policy"},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			got := defaultState(tt.state)
			if got.Outcome != tt.state {
				t.Fatalf("outcome = %q", got.Outcome)
			}
			if got.Ready != tt.ready {
				t.Fatalf("ready = %v", got.Ready)
			}
			if got.KeyState != tt.keyState {
				t.Fatalf("keyState = %q", got.KeyState)
			}
			if got.NextAction != tt.nextAction {
				t.Fatalf("nextAction = %q", got.NextAction)
			}
		})
	}
}

func TestUnknownStateNormalizesToDegraded(t *testing.T) {
	got := defaultState("surprise")
	if got.State != "degraded" {
		t.Fatalf("state = %q", got.State)
	}
	if got.NextAction != "inspect_sources" {
		t.Fatalf("nextAction = %q", got.NextAction)
	}
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%q not found in %#v", want, values)
}
