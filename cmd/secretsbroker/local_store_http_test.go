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

func TestHTTPGeneratedSecretWritebackCapture(t *testing.T) {
	backend := testBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"requestId":"req-writeback-http","identity":{"serviceId":"api-service","expiresAt":"2026-05-07T00:05:00Z"},"policy":{"allowedNamespaces":["services/api-service"],"allowedOperations":["create","update"]},"operation":"create","namespace":"services/api-service","ref":"runtime/API_TOKEN","value":"generated-http-secret","refreshRequired":true}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/writeback", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("writeback status = %d", res.StatusCode)
	}
	var captured generatedSecretCaptureResponse
	if err := json.NewDecoder(res.Body).Decode(&captured); err != nil {
		t.Fatal(err)
	}
	if captured.Outcome != "ready" || !captured.RefreshRequired || captured.Ref != "services/api-service/runtime/API_TOKEN" {
		t.Fatalf("writeback response = %#v", captured)
	}
}

func TestHTTPGeneratedSecretWritebackLockoutResponseIsMetadataOnly(t *testing.T) {
	backend := testBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"requestId":"req-writeback-http-lockout","identity":{"serviceId":"api-service","expiresAt":"2026-05-07T00:05:00Z"},"policy":{"allowedNamespaces":["services/api-service"],"allowedOperations":["create"]},"operation":"create","namespace":"services/api-service","ref":"runtime/API_TOKEN","value":"generated-http-secret","sourceAuthRequired":true}`)
	for i := 1; i <= localAPILockoutThreshold; i++ {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/writeback", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		payload, readErr := io.ReadAll(res.Body)
		res.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if i < localAPILockoutThreshold {
			if res.StatusCode != http.StatusFailedDependency {
				t.Fatalf("attempt %d status=%d body=%s", i, res.StatusCode, payload)
			}
			continue
		}
		if res.StatusCode != http.StatusLocked || !bytes.Contains(payload, []byte(`"lockoutActive":true`)) || !bytes.Contains(payload, []byte(`"lockoutScope":"writeback:source_auth:create:api-service:services/api-service/runtime/API_TOKEN"`)) {
			t.Fatalf("lockout status=%d body=%s", res.StatusCode, payload)
		}
		if bytes.Contains(payload, []byte("generated-http-secret")) || bytes.Contains(payload, []byte("test-token")) {
			t.Fatalf("writeback lockout response leaked sensitive input: %s", payload)
		}
	}
}

func TestHTTPManagementLockoutClearRequiresReasonAndClearsScope(t *testing.T) {
	backend := testBackend(t)
	ref := "services/@serviceadmin/runtime/API_TOKEN"
	writeManagedTestSecret(t, backend, ref, "management-clear-secret")
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	deniedBody := []byte(`{"requestId":"req-reveal-denied","serviceId":"@serviceadmin","ref":"` + ref + `"}`)
	for i := 1; i <= localAPILockoutThreshold; i++ {
		res, payload := postJSON(t, server.URL+"/v1/management/secrets/reveal", "test-token", deniedBody)
		if i < localAPILockoutThreshold {
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("attempt %d status=%d body=%s", i, res.StatusCode, payload)
			}
			continue
		}
		if res.StatusCode != http.StatusLocked || !bytes.Contains(payload, []byte(`"lockoutActive":true`)) {
			t.Fatalf("lockout status=%d body=%s", res.StatusCode, payload)
		}
		assertNoSecretMaterial(t, payload, "management-clear-secret", "test-token")
	}

	scope := "management:reveal:@serviceadmin:" + ref
	missingReason := []byte(`{"requestId":"req-clear-denied","serviceId":"@operator","scope":"` + scope + `"}`)
	res, payload := postJSON(t, server.URL+"/v1/management/lockouts/clear", "test-token", missingReason)
	if res.StatusCode != http.StatusForbidden || bytes.Contains(payload, []byte("management-clear-secret")) || bytes.Contains(payload, []byte("test-token")) {
		t.Fatalf("missing reason clear status=%d body=%s", res.StatusCode, payload)
	}

	clearBody := []byte(`{"requestId":"req-clear-ok","serviceId":"@operator","scope":"` + scope + `","reason":"operator reviewed denial"}`)
	res, payload = postJSON(t, server.URL+"/v1/management/lockouts/clear", "test-token", clearBody)
	if res.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte(`"outcome":"cleared"`)) || !bytes.Contains(payload, []byte(`"cleared":true`)) {
		t.Fatalf("clear status=%d body=%s", res.StatusCode, payload)
	}
	assertNoSecretMaterial(t, payload, "management-clear-secret", "test-token")

	revealBody := []byte(`{"requestId":"req-reveal-ok","serviceId":"@serviceadmin","ref":"` + ref + `","reason":"operator check","confirm":true,"noEcho":true}`)
	res, payload = postJSON(t, server.URL+"/v1/management/secrets/reveal", "test-token", revealBody)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("post-clear reveal status=%d body=%s", res.StatusCode, payload)
	}
}

func TestHTTPLocalAPILockoutClearAcceptsValidTokenDuringLockout(t *testing.T) {
	backend := testBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	writeBody := []byte(`{"ref":"services/api/runtime/API_TOKEN","value":"local-api-clear-secret"}`)
	for i := 1; i <= localAPILockoutThreshold; i++ {
		res, payload := postJSON(t, server.URL+"/v1/secrets", "wrong-token", writeBody)
		if i < localAPILockoutThreshold {
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("attempt %d status=%d body=%s", i, res.StatusCode, payload)
			}
			continue
		}
		if res.StatusCode != http.StatusLocked || bytes.Contains(payload, []byte("wrong-token")) || bytes.Contains(payload, []byte("test-token")) {
			t.Fatalf("local api lockout status=%d body=%s", res.StatusCode, payload)
		}
	}

	clearBody := []byte(`{"requestId":"req-clear-local-api","serviceId":"@operator","scope":"local_api:127.0.0.1","reason":"operator verified local client"}`)
	res, payload := postJSON(t, server.URL+"/v1/management/lockouts/clear", "test-token", clearBody)
	if res.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte(`"outcome":"cleared"`)) {
		t.Fatalf("local api clear status=%d body=%s", res.StatusCode, payload)
	}
	assertNoSecretMaterial(t, payload, "local-api-clear-secret", "test-token", "wrong-token")

	res, payload = postJSON(t, server.URL+"/v1/secrets", "test-token", writeBody)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("post-clear write status=%d body=%s", res.StatusCode, payload)
	}
}

func TestSecretBearingEndpointRejectsOversizedBodyWithoutLeakingToken(t *testing.T) {
	backend := testBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := `{"ref":"openclaw/anthropic/api_key","value":"` + strings.Repeat("x", maxSecretBearingRequestBytes) + `"}`
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/secrets", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", res.StatusCode)
	}
	payload, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("test-token")) || bytes.Contains(payload, []byte(strings.Repeat("x", 64))) {
		t.Fatalf("oversized error leaked sensitive input: %s", payload)
	}
}

func postJSON(t *testing.T, url, token string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	payload, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, payload
}

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
