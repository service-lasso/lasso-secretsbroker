package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalStoreHTTPWriteAndResolve(t *testing.T) {
	backend := testBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	writeBody := []byte(`{"ref":"openclaw/anthropic/api_key","value":"secret-value","metadata":{"sourceId":"local-test"}}`)
	writeReq, err := http.NewRequest(http.MethodPost, server.URL+"/v1/secrets", bytes.NewReader(writeBody))
	if err != nil {
		t.Fatal(err)
	}
	writeReq.Header.Set("Content-Type", "application/json")
	writeReq.Header.Set("Authorization", "Bearer test-token")
	writeRes, err := http.DefaultClient.Do(writeReq)
	if err != nil {
		t.Fatal(err)
	}
	defer writeRes.Body.Close()
	if writeRes.StatusCode != http.StatusOK {
		t.Fatalf("write status = %d", writeRes.StatusCode)
	}
	var written writeSecretResponse
	if err := json.NewDecoder(writeRes.Body).Decode(&written); err != nil {
		t.Fatal(err)
	}
	if written.Outcome != "ready" || written.Ref != "openclaw/anthropic/api_key" {
		t.Fatalf("write response = %#v", written)
	}

	resolveBody := []byte(`{"requestId":"req-1","serviceId":"openclaw","refs":["openclaw/anthropic/api_key"]}`)
	resolveReq, err := http.NewRequest(http.MethodPost, server.URL+"/v1/resolve", bytes.NewReader(resolveBody))
	if err != nil {
		t.Fatal(err)
	}
	resolveReq.Header.Set("Content-Type", "application/json")
	resolveReq.Header.Set("X-SecretsBroker-Token", "test-token")
	resolveRes, err := http.DefaultClient.Do(resolveReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resolveRes.Body.Close()
	if resolveRes.StatusCode != http.StatusOK {
		t.Fatalf("resolve status = %d", resolveRes.StatusCode)
	}
	var resolved resolveResponse
	if err := json.NewDecoder(resolveRes.Body).Decode(&resolved); err != nil {
		t.Fatal(err)
	}
	if len(resolved.Results) != 1 || resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != "secret-value" {
		t.Fatalf("resolve response = %#v", resolved)
	}
}
