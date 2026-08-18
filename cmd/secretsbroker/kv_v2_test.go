package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const kvSentinel = "kv-sentinel-alpha"

func TestKVFacadePutGetListSoftDeleteAndCAS(t *testing.T) {
	backend := testBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	putBody := []byte(`{"data":{"username":"demo-user","password":"` + kvSentinel + `"}}`)
	put := kvDo(t, server, http.MethodPost, "/v1/kv/data/apps/db", putBody)
	if put.StatusCode != http.StatusOK {
		t.Fatalf("put status=%d body=%s", put.StatusCode, kvRead(t, put))
	}
	var written kvWriteResponse
	if err := json.Unmarshal(kvRead(t, put), &written); err != nil || written.Data.Version != 1 {
		t.Fatalf("put version=%d err=%v", written.Data.Version, err)
	}

	listed := kvDo(t, server, http.MethodGet, "/v1/kv/metadata/?list=true", nil)
	listPayload := kvRead(t, listed)
	if listed.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.StatusCode, listPayload)
	}
	assertNoSecretMaterial(t, listPayload, kvSentinel)
	var keys kvListResponse
	if err := json.Unmarshal(listPayload, &keys); err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys.Data.Keys, ",") != "apps/" {
		t.Fatalf("root keys=%v", keys.Data.Keys)
	}

	nested := kvDo(t, server, http.MethodGet, "/v1/kv/metadata/apps?list=true", nil)
	nestedPayload := kvRead(t, nested)
	assertNoSecretMaterial(t, nestedPayload, kvSentinel)
	var nestedKeys kvListResponse
	if err := json.Unmarshal(nestedPayload, &nestedKeys); err != nil {
		t.Fatal(err)
	}
	if strings.Join(nestedKeys.Data.Keys, ",") != "db" {
		t.Fatalf("apps keys=%v", nestedKeys.Data.Keys)
	}

	got := kvDo(t, server, http.MethodGet, "/v1/kv/data/apps/db", nil)
	gotPayload := kvRead(t, got)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("get status=%d body=%s", got.StatusCode, gotPayload)
	}
	var current kvDataResponse
	if err := json.Unmarshal(gotPayload, &current); err != nil {
		t.Fatal(err)
	}
	if current.Data.Data["password"] != kvSentinel || current.Data.Metadata.Version != 1 {
		t.Fatalf("get payload=%s", gotPayload)
	}

	conflict := kvDo(t, server, http.MethodPost, "/v1/kv/data/apps/db", []byte(`{"data":{"password":"kv-sentinel-beta"},"options":{"cas":0}}`))
	if conflict.StatusCode != http.StatusBadRequest {
		t.Fatalf("cas status=%d body=%s", conflict.StatusCode, kvRead(t, conflict))
	}

	patched := kvDo(t, server, http.MethodPatch, "/v1/kv/data/apps/db", []byte(`{"data":{"role":"reader"},"options":{"cas":1}}`))
	if patched.StatusCode != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", patched.StatusCode, kvRead(t, patched))
	}

	afterPatch := kvDo(t, server, http.MethodGet, "/v1/kv/data/apps/db", nil)
	var merged kvDataResponse
	if err := json.Unmarshal(kvRead(t, afterPatch), &merged); err != nil {
		t.Fatal(err)
	}
	if merged.Data.Data["password"] != kvSentinel || merged.Data.Data["role"] != "reader" || merged.Data.Metadata.Version != 2 {
		t.Fatalf("patched payload=%v version=%d", merged.Data.Data, merged.Data.Metadata.Version)
	}

	deleted := kvDo(t, server, http.MethodPost, "/v1/kv/delete/apps/db", nil)
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleted.StatusCode, kvRead(t, deleted))
	}
	missing := kvDo(t, server, http.MethodGet, "/v1/kv/data/apps/db", nil)
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted get status=%d body=%s", missing.StatusCode, kvRead(t, missing))
	}
	meta := kvDo(t, server, http.MethodGet, "/v1/kv/metadata/apps/db", nil)
	metaPayload := kvRead(t, meta)
	assertNoSecretMaterial(t, metaPayload, kvSentinel)
	var metadata kvMetadataResponse
	if err := json.Unmarshal(metaPayload, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Data.CurrentVersion != 2 || strings.TrimSpace(metadata.Data.Versions["2"].DeletionTime) == "" {
		t.Fatalf("metadata after delete=%s", metaPayload)
	}

	undeleted := kvDo(t, server, http.MethodPost, "/v1/kv/undelete/apps/db", []byte(`{"versions":[2]}`))
	if undeleted.StatusCode != http.StatusNoContent {
		t.Fatalf("undelete status=%d body=%s", undeleted.StatusCode, kvRead(t, undeleted))
	}
	restored := kvDo(t, server, http.MethodGet, "/v1/kv/data/apps/db", nil)
	var restoredBody kvDataResponse
	if err := json.Unmarshal(kvRead(t, restored), &restoredBody); err != nil {
		t.Fatal(err)
	}
	if restoredBody.Data.Data["password"] != kvSentinel {
		t.Fatalf("restored payload=%v", restoredBody.Data.Data)
	}

	unauth := kvDoUnauth(t, server, http.MethodGet, "/v1/kv/data/apps/db")
	if unauth.StatusCode == http.StatusOK {
		t.Fatalf("unauthenticated read succeeded")
	}
}

func TestKVFacadeLegacySecretReadsAsValueField(t *testing.T) {
	backend := testBackend(t)
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "legacy/token", Value: kvSentinel}); err != nil {
		t.Fatal(err)
	}
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	got := kvDo(t, server, http.MethodGet, "/v1/kv/data/legacy/token", nil)
	payload := kvRead(t, got)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", got.StatusCode, payload)
	}
	var current kvDataResponse
	if err := json.Unmarshal(payload, &current); err != nil {
		t.Fatal(err)
	}
	if current.Data.Data["value"] != kvSentinel {
		t.Fatalf("legacy payload=%s", payload)
	}

	resolved := backend.resolve(resolveRequest{Refs: []string{"legacy/token"}})
	if len(resolved.Results) != 1 || resolved.Results[0].Value != kvSentinel {
		t.Fatalf("resolve=%v", resolved.Results)
	}
}

func TestKVFacadeOpenBaoProxyForwardsKVShape(t *testing.T) {
	const remoteToken = "bao-operator-token"
	var seenPath string
	var seenToken string
	var seenMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenToken = r.Header.Get("X-Vault-Token")
		seenMethod = r.Method
		if r.URL.Query().Get("list") == "true" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"keys":["apps/"]}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"password":"` + kvSentinel + `"},"metadata":{"version":4,"created_time":"2026-08-18T00:00:00Z","deletion_time":"","destroyed":false}}}`))
	}))
	defer upstream.Close()

	backend := testBackend(t)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "openbao-dev",
		Kind:     "openbao",
		Enabled:  true,
		Address:  upstream.URL,
		Token:    remoteToken,
		Mount:    "secret",
	}}}
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	listed := kvDo(t, server, http.MethodGet, "/v1/kv/metadata/?list=true&source=openbao-dev", nil)
	listPayload := kvRead(t, listed)
	if listed.StatusCode != http.StatusOK {
		t.Fatalf("proxy list status=%d body=%s", listed.StatusCode, listPayload)
	}
	assertNoSecretMaterial(t, listPayload, kvSentinel, remoteToken)
	if seenPath != "/v1/secret/metadata" || seenMethod != http.MethodGet {
		t.Fatalf("proxy list path=%s method=%s", seenPath, seenMethod)
	}

	got := kvDo(t, server, http.MethodGet, "/v1/kv/data/apps/db?source=openbao-dev", nil)
	payload := kvRead(t, got)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("proxy get status=%d body=%s", got.StatusCode, payload)
	}
	if seenPath != "/v1/secret/data/apps/db" || seenToken != remoteToken {
		t.Fatalf("proxy get path=%s token=%s", seenPath, seenToken)
	}
	if !strings.Contains(string(payload), kvSentinel) {
		t.Fatalf("proxy get missing value: %s", payload)
	}
}

func TestKVChildKeysAreImmediateOnly(t *testing.T) {
	keys := kvChildKeys([]string{"apps/db", "apps/cache", "apps/nested/key", "other"}, "")
	if strings.Join(keys, ",") != "apps/,other" {
		t.Fatalf("root=%v", keys)
	}
	nested := kvChildKeys([]string{"apps/db", "apps/cache", "apps/nested/key", "other"}, "apps")
	if strings.Join(nested, ",") != "cache,db,nested/" {
		t.Fatalf("apps=%v", nested)
	}
}

func kvDo(t *testing.T, server *httptest.Server, method, path string, body []byte) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func kvDoUnauth(t *testing.T, server *httptest.Server, method, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func kvRead(t *testing.T, res *http.Response) []byte {
	t.Helper()
	defer res.Body.Close()
	payload, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
