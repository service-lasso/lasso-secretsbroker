package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const openBaoTestRef = "services/api/API_TOKEN"

type openBaoTestServer struct {
	server *httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	paths  []string
	value  string
}

func newOpenBaoTestServer(t *testing.T, value string) *openBaoTestServer {
	t.Helper()
	owner := &openBaoTestServer{value: value}
	owner.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner.hits.Add(1)
		owner.mu.Lock()
		owner.paths = append(owner.paths, r.Method+" "+r.URL.RequestURI())
		owner.mu.Unlock()
		if r.Header.Get("X-Vault-Token") != "openbao-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = fmt.Fprintf(w, `{"data":{"data":{"value":%q},"metadata":{"version":1,"created_time":"2026-05-07T00:00:00Z","deletion_time":"","destroyed":false}}}`, owner.value)
		case http.MethodPost, http.MethodPatch:
			_, _ = fmt.Fprint(w, `{"data":{"version":1,"created_time":"2026-05-07T00:00:00Z","deletion_time":"","destroyed":false}}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(owner.server.Close)
	return owner
}

func (s *openBaoTestServer) requestPaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

func openBaoSource(id, address string, priority int) sourceConfig {
	return sourceConfig{
		SourceID: id,
		Kind:     "openbao",
		Enabled:  true,
		Priority: priority,
		Address:  address,
		Token:    "openbao-token",
		Refs: map[string]sourceRefConfig{
			openBaoTestRef: {Path: "secret/data/services/api/API_TOKEN", Field: "value"},
		},
	}
}

func localSecret(t *testing.T, backend *localBackend, value string) {
	t.Helper()
	if _, err := backend.writeSecret(writeSecretRequest{Ref: openBaoTestRef, Value: value}); err != nil {
		t.Fatal(err)
	}
}

func TestResolvePrefersEnabledOpenBaoOverLocalStore(t *testing.T) {
	openBao := newOpenBaoTestServer(t, "openbao-value")
	backend := testBackend(t)
	localSecret(t, backend, "local-value")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{openBaoSource("openbao-primary", openBao.server.URL, 50)}}

	res := backend.resolve(resolveRequest{Refs: []string{openBaoTestRef}, RequestID: "req-openbao-first"})
	if len(res.Results) != 1 {
		t.Fatalf("results = %#v", res.Results)
	}
	got := res.Results[0]
	if got.Outcome != "ready" || got.Value != "openbao-value" {
		t.Fatalf("resolve result = %#v", got)
	}
	if got.Metadata == nil || got.Metadata.SourceID != "openbao-primary" || got.Metadata.Version != "source" {
		t.Fatalf("resolve metadata = %#v", got.Metadata)
	}
	if openBao.hits.Load() == 0 {
		t.Fatal("OpenBao source was not consulted")
	}
}

func TestResolveFallsBackToLocalForUnmappedOpenBaoRef(t *testing.T) {
	openBao := newOpenBaoTestServer(t, "openbao-value")
	backend := testBackend(t)
	localSecret(t, backend, "local-value")
	source := openBaoSource("openbao-primary", openBao.server.URL, 50)
	source.Refs = map[string]sourceRefConfig{"other/ref": {Path: "secret/data/other", Field: "value"}}
	backend.sources = sourceConfigFile{Sources: []sourceConfig{source}}

	res := backend.resolve(resolveRequest{Refs: []string{openBaoTestRef}, RequestID: "req-local-fallback"})
	got := res.Results[0]
	if got.Outcome != "ready" || got.Value != "local-value" {
		t.Fatalf("resolve result = %#v", got)
	}
	if got.Metadata == nil || got.Metadata.SourceID == "openbao-primary" {
		t.Fatalf("local metadata = %#v", got.Metadata)
	}
	if openBao.hits.Load() != 0 {
		t.Fatal("OpenBao was consulted for an unmapped ref")
	}
}

func TestResolveDoesNotFallBackWhenMappedOpenBaoFails(t *testing.T) {
	var hits atomic.Int32
	openBao := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer openBao.Close()
	backend := testBackend(t)
	localSecret(t, backend, "local-value")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{openBaoSource("openbao-primary", openBao.URL, 50)}}

	res := backend.resolve(resolveRequest{Refs: []string{openBaoTestRef}, RequestID: "req-openbao-fail-closed"})
	got := res.Results[0]
	if got.Outcome != "source_unavailable" || got.Value != "" || got.Metadata != nil {
		t.Fatalf("resolve result = %#v", got)
	}
	if hits.Load() == 0 {
		t.Fatal("OpenBao source was not consulted")
	}
}

func TestResolvePrefersHighestPriorityOpenBaoSource(t *testing.T) {
	low := newOpenBaoTestServer(t, "openbao-low")
	high := newOpenBaoTestServer(t, "openbao-high")
	backend := testBackend(t)
	localSecret(t, backend, "local-value")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{
		openBaoSource("openbao-low", low.server.URL, 20),
		openBaoSource("openbao-high", high.server.URL, 10),
	}}

	res := backend.resolve(resolveRequest{Refs: []string{openBaoTestRef}, RequestID: "req-openbao-priority"})
	got := res.Results[0]
	if got.Outcome != "ready" || got.Value != "openbao-high" || got.Metadata == nil || got.Metadata.SourceID != "openbao-high" {
		t.Fatalf("resolve result = %#v", got)
	}
	if high.hits.Load() == 0 || low.hits.Load() != 0 {
		t.Fatalf("priority hits high=%d low=%d", high.hits.Load(), low.hits.Load())
	}
}

func TestResolveIgnoresDisabledOpenBaoSource(t *testing.T) {
	openBao := newOpenBaoTestServer(t, "openbao-value")
	backend := testBackend(t)
	localSecret(t, backend, "local-value")
	source := openBaoSource("openbao-primary", openBao.server.URL, 50)
	source.Enabled = false
	backend.sources = sourceConfigFile{Sources: []sourceConfig{source}}

	res := backend.resolve(resolveRequest{Refs: []string{openBaoTestRef}, RequestID: "req-openbao-disabled"})
	got := res.Results[0]
	if got.Outcome != "ready" || got.Value != "local-value" {
		t.Fatalf("resolve result = %#v", got)
	}
	if openBao.hits.Load() != 0 {
		t.Fatal("disabled OpenBao source was consulted")
	}
}

func TestKVFacadeDefaultsToEnabledOpenBao(t *testing.T) {
	openBao := newOpenBaoTestServer(t, "openbao-kv-value")
	backend := testBackend(t)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "openbao-primary",
		Kind:     "openbao",
		Enabled:  true,
		Address:  openBao.server.URL,
		Token:    "openbao-token",
	}}}
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	got := kvDo(t, server, http.MethodGet, "/v1/kv/data/apps/db", nil)
	payload := kvRead(t, got)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("get status=%d body=%s", got.StatusCode, payload)
	}
	var current kvDataResponse
	if err := json.Unmarshal(payload, &current); err != nil {
		t.Fatal(err)
	}
	if current.Data.Data["value"] != "openbao-kv-value" {
		t.Fatalf("get payload=%s", payload)
	}

	put := kvDo(t, server, http.MethodPost, "/v1/kv/data/apps/db", []byte(`{"data":{"value":"openbao-kv-written"}}`))
	if put.StatusCode != http.StatusOK {
		t.Fatalf("put status=%d body=%s", put.StatusCode, kvRead(t, put))
	}
	paths := openBao.requestPaths()
	if !containsPath(paths, "GET /v1/secret/data/apps/db") || !containsPath(paths, "POST /v1/secret/data/apps/db") {
		t.Fatalf("OpenBao requests = %v", paths)
	}
}

func TestKVFacadeExplicitLocalSourceStaysLocal(t *testing.T) {
	openBao := newOpenBaoTestServer(t, "openbao-kv-value")
	backend := testBackend(t)
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "legacy/token", Value: "local-kv-value"}); err != nil {
		t.Fatal(err)
	}
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "openbao-primary",
		Kind:     "openbao",
		Enabled:  true,
		Address:  openBao.server.URL,
		Token:    "openbao-token",
	}}}
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	got := kvDo(t, server, http.MethodGet, "/v1/kv/data/legacy/token?source=local", nil)
	payload := kvRead(t, got)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("get status=%d body=%s", got.StatusCode, payload)
	}
	var current kvDataResponse
	if err := json.Unmarshal(payload, &current); err != nil {
		t.Fatal(err)
	}
	if current.Data.Data["value"] != "local-kv-value" {
		t.Fatalf("local get payload=%s", payload)
	}
	if openBao.hits.Load() != 0 {
		t.Fatalf("explicit local source used OpenBao: %v", openBao.requestPaths())
	}
}

func containsPath(paths []string, want string) bool {
	for _, value := range paths {
		if value == want || strings.HasPrefix(value, want+"?") {
			return true
		}
	}
	return false
}
