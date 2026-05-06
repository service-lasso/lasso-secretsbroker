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
	server := httptest.NewServer(newHandler(&state))
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

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%q not found in %#v", want, values)
}
