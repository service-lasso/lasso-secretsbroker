package main

import "testing"

func TestDefaultStatus(t *testing.T) {
	status := defaultStatus("")
	if status.ServiceID != "@secretsbroker" {
		t.Fatalf("service id = %q", status.ServiceID)
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
