package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultSourceRegistryReflectsLocalKeyState(t *testing.T) {
	locked := defaultSourceRegistry(newLocalBackend("store.json", "audit.jsonl", ""))
	if len(locked.Sources) != 1 {
		t.Fatalf("sources = %d", len(locked.Sources))
	}
	if locked.Sources[0].SourceID != "local" || locked.Sources[0].State != "locked" {
		t.Fatalf("locked source = %#v", locked.Sources[0])
	}
	assertContains(t, locked.Sources[0].Capabilities, "read")
	assertContains(t, locked.Sources[0].Namespaces, "*")

	ready := defaultSourceRegistry(newLocalBackend("store.json", "audit.jsonl", "master-key"))
	if ready.Sources[0].State != "ready" {
		t.Fatalf("ready source = %#v", ready.Sources[0])
	}
}

func TestSourceStatusEndpointDoesNotRequireSecretToken(t *testing.T) {
	backend := newLocalBackend("store.json", "audit.jsonl", "master-key")
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{}))
	defer server.Close()

	res, err := http.Get(server.URL + "/v1/sources/status")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var body sourceStatusResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sources) != 1 || body.Sources[0].SourceID != "local" || body.Sources[0].State != "ready" {
		t.Fatalf("body = %#v", body)
	}
}
