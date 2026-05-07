package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecretsbrokerResolveReturnsOpenClawExecProviderValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/resolve" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		var req brokerResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.ServiceID != "openclaw" || req.Purpose != "secretref-exec-provider" {
			t.Fatalf("broker request = %#v", req)
		}
		json.NewEncoder(w).Encode(brokerResolveResponse{ServiceID: "@secretsbroker", APIVersion: apiVersion, Results: []brokerResolveResult{{Ref: "openclaw/anthropic/api_key", Outcome: "ready", Value: "secret-value"}}})
	}))
	defer server.Close()

	var out strings.Builder
	err := resolveFromBroker(resolverConfig{BrokerURL: server.URL, Token: "test-token", Policy: []string{"openclaw/*"}, Timeout: time.Second, Stdin: strings.NewReader(`{"protocolVersion":1,"provider":"service-lasso-secretsbroker","ids":["openclaw/anthropic/api_key"]}`), Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	var res execSecretResponse
	if err := json.Unmarshal([]byte(out.String()), &res); err != nil {
		t.Fatal(err)
	}
	if res.ProtocolVersion != 1 || res.Values["openclaw/anthropic/api_key"] != "secret-value" {
		t.Fatalf("response = %#v", res)
	}
	if strings.Contains(out.String(), "error") || strings.Contains(out.String(), "stderr") {
		t.Fatalf("unexpected error protocol output: %s", out.String())
	}
}

func TestSecretsbrokerResolveEnforcesOpenClawPolicyBeforeBrokerCall(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer server.Close()

	var out strings.Builder
	err := resolveFromBroker(resolverConfig{BrokerURL: server.URL, Token: "test-token", Policy: []string{"openclaw/*"}, Timeout: time.Second, Stdin: strings.NewReader(`{"protocolVersion":1,"provider":"service-lasso-secretsbroker","ids":["other/service_key"]}`), Stdout: &out})
	if err == nil {
		t.Fatal("expected policy error")
	}
	if called {
		t.Fatal("broker was called for denied ref")
	}
	var res execSecretResponse
	if err := json.Unmarshal([]byte(out.String()), &res); err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "policy_denied" || res.Errors["other/service_key"] != "policy_denied" || len(res.Values) != 0 {
		t.Fatalf("response = %#v", res)
	}
}

func TestSecretsbrokerResolveMapsTypedBrokerErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		result brokerResolveResult
		want   string
	}{
		{name: "locked http error", status: http.StatusServiceUnavailable, body: `{"error":{"code":"locked","outcome":"locked"}}`, want: "locked"},
		{name: "missing ref result", status: http.StatusOK, result: brokerResolveResult{Ref: "openclaw/missing", Outcome: "missing_ref"}, want: "missing_ref"},
		{name: "source auth result", status: http.StatusOK, result: brokerResolveResult{Ref: "openclaw/token", Outcome: "source_auth_required"}, want: "source_auth_required"},
		{name: "policy result", status: http.StatusOK, result: brokerResolveResult{Ref: "openclaw/token", Outcome: "policy_denied"}, want: "policy_denied"},
		{name: "degraded result", status: http.StatusOK, result: brokerResolveResult{Ref: "openclaw/token", Outcome: "source_unavailable"}, want: "degraded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				if tt.status == http.StatusOK {
					json.NewEncoder(w).Encode(brokerResolveResponse{Results: []brokerResolveResult{tt.result}})
					return
				}
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			var out strings.Builder
			err := resolveFromBroker(resolverConfig{BrokerURL: server.URL, Token: "test-token", Policy: []string{"openclaw/*"}, Timeout: time.Second, Stdin: strings.NewReader(`{"protocolVersion":1,"provider":"service-lasso-secretsbroker","ids":["openclaw/token"]}`), Stdout: &out})
			if tt.status != http.StatusOK && err == nil {
				t.Fatal("expected http error")
			}
			var res execSecretResponse
			if err := json.Unmarshal([]byte(out.String()), &res); err != nil {
				t.Fatal(err)
			}
			if res.Outcome != tt.want {
				t.Fatalf("outcome = %q, want %q, response %s", res.Outcome, tt.want, out.String())
			}
		})
	}
}
