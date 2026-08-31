package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLaunchIdentityLeaseTransportBinding(t *testing.T) {
	backend := testBackend(t)
	backend.now = func() time.Time { return time.Date(2026, 5, 7, 0, 1, 0, 0, time.UTC) }
	key := "transport-binding-key"
	peer := transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-1000"}

	lease := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-transport-ok")
	lease.TransportBinding = &launchTransportBinding{Kind: peer.Kind, Subject: peer.Subject}
	lease = mustSignLaunchIdentityLease(t, lease, key)
	if err := backend.verifyLaunchIdentityLease(&lease, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, peer); err != nil {
		t.Fatalf("bound lease should authorize matching transport peer: %v", err)
	}

	mismatch := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-transport-mismatch")
	mismatch.TransportBinding = &launchTransportBinding{Kind: peer.Kind, Subject: peer.Subject}
	mismatch = mustSignLaunchIdentityLease(t, mismatch, key)
	err := backend.verifyLaunchIdentityLease(&mismatch, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-2000"})
	if !errors.Is(err, errPolicyDenied) {
		t.Fatalf("mismatched transport peer error = %v, want policy denied", err)
	}

	missing := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-transport-missing")
	missing.TransportBinding = &launchTransportBinding{Kind: "unix-uid", Subject: "501"}
	missing = mustSignLaunchIdentityLease(t, missing, key)
	err = backend.verifyLaunchIdentityLease(&missing, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, transportPeerIdentity{})
	if !errors.Is(err, errPolicyDenied) {
		t.Fatalf("missing transport peer error = %v, want policy denied", err)
	}
}

func TestProductionLaunchIdentityRequiresTrustedIssuerAndTransportBinding(t *testing.T) {
	backend := testBackend(t)
	backend.production = true
	backend.now = func() time.Time { return time.Date(2026, 5, 7, 0, 1, 0, 0, time.UTC) }
	key := "production-lease-key"
	peer := transportPeerIdentity{Kind: "unix-uid", Subject: "1000"}

	valid := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-production-valid")
	valid.TransportBinding = &launchTransportBinding{Kind: peer.Kind, Subject: peer.Subject}
	valid = mustSignLaunchIdentityLease(t, valid, key)
	if err := backend.verifyLaunchIdentityLease(&valid, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, peer); err != nil {
		t.Fatalf("valid production lease rejected: %v", err)
	}

	wrongIssuer := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-production-wrong-issuer")
	wrongIssuer.Issuer = "untrusted-launcher"
	wrongIssuer.TransportBinding = &launchTransportBinding{Kind: peer.Kind, Subject: peer.Subject}
	wrongIssuer = mustSignLaunchIdentityLease(t, wrongIssuer, key)
	if err := backend.verifyLaunchIdentityLease(&wrongIssuer, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, peer); !errors.Is(err, errPolicyDenied) {
		t.Fatalf("wrong issuer error = %v, want policy denied", err)
	}

	unbound := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-production-unbound")
	unbound = mustSignLaunchIdentityLease(t, unbound, key)
	if err := backend.verifyLaunchIdentityLease(&unbound, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, peer); !errors.Is(err, errPolicyDenied) {
		t.Fatalf("unbound production lease error = %v, want policy denied", err)
	}
}

func TestHTTPResolveHonorsTransportBoundLaunchLease(t *testing.T) {
	backend := testBackend(t)
	backend.now = func() time.Time { return time.Date(2026, 5, 7, 0, 1, 0, 0, time.UTC) }
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "services/api-service/runtime/API_TOKEN", Value: "transport-bound-secret"}); err != nil {
		t.Fatal(err)
	}
	state := "ready"
	handler := newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"})
	peer := transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-1000"}

	matchingLease := boundTestLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-http-transport-ok", peer)
	matchingBody := []byte(`{"requestId":"req-transport-ok","serviceId":"api-service","identityLease":` + mustLeaseJSON(t, matchingLease) + `,"refs":["services/api-service/runtime/API_TOKEN"]}`)
	res := serveTransportBoundRequest(t, handler, http.MethodPost, "/v1/resolve", "test-token", matchingBody, peer)
	if res.Code != http.StatusOK {
		t.Fatalf("matching transport-bound resolve status=%d body=%s", res.Code, res.Body.String())
	}
	var resolved resolveResponse
	if err := json.NewDecoder(res.Body).Decode(&resolved); err != nil {
		t.Fatal(err)
	}
	if len(resolved.Results) != 1 || resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != "transport-bound-secret" {
		t.Fatalf("matching transport-bound resolve = %#v", resolved)
	}

	mismatchedLease := boundTestLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-http-transport-mismatch", peer)
	mismatchedBody := []byte(`{"requestId":"req-transport-mismatch","serviceId":"api-service","identityLease":` + mustLeaseJSON(t, mismatchedLease) + `,"refs":["services/api-service/runtime/API_TOKEN"]}`)
	res = serveTransportBoundRequest(t, handler, http.MethodPost, "/v1/resolve", "test-token", mismatchedBody, transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-2000"})
	if res.Code != http.StatusForbidden || !bytes.Contains(res.Body.Bytes(), []byte(`"code":"policy_denied"`)) {
		t.Fatalf("mismatched transport-bound resolve status=%d body=%s", res.Code, res.Body.String())
	}
	assertNoSecretMaterial(t, res.Body.Bytes(), "transport-bound-secret", "test-token")

	missingPeerLease := boundTestLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-http-transport-missing-peer", peer)
	missingPeerBody := []byte(`{"requestId":"req-transport-missing-peer","serviceId":"api-service","identityLease":` + mustLeaseJSON(t, missingPeerLease) + `,"refs":["services/api-service/runtime/API_TOKEN"]}`)
	res = serveTransportBoundRequest(t, handler, http.MethodPost, "/v1/resolve", "test-token", missingPeerBody, transportPeerIdentity{})
	if res.Code != http.StatusForbidden || !bytes.Contains(res.Body.Bytes(), []byte(`"code":"policy_denied"`)) {
		t.Fatalf("missing-peer transport-bound resolve status=%d body=%s", res.Code, res.Body.String())
	}
	assertNoSecretMaterial(t, res.Body.Bytes(), "transport-bound-secret", "test-token")
}

func TestHTTPWritebackHonorsTransportBoundLaunchLease(t *testing.T) {
	backend := testBackend(t)
	backend.now = func() time.Time { return time.Date(2026, 5, 7, 0, 1, 0, 0, time.UTC) }
	state := "ready"
	handler := newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"})
	peer := transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-1000"}

	matchingLease := boundTestLaunchIdentityLease(t, backend, "api-service", nil, []string{"services/api-service"}, []string{"create"}, "jti-writeback-transport-ok", peer)
	matchingBody := []byte(`{"requestId":"req-writeback-transport-ok","identity":{"serviceId":"api-service","expiresAt":"2026-05-07T00:05:00Z"},"identityLease":` + mustLeaseJSON(t, matchingLease) + `,"policy":{"allowedNamespaces":["services/api-service"],"allowedOperations":["create"]},"operation":"create","namespace":"services/api-service","ref":"runtime/API_TOKEN","value":"transport-writeback-secret"}`)
	res := serveTransportBoundRequest(t, handler, http.MethodPost, "/v1/writeback", "test-token", matchingBody, peer)
	if res.Code != http.StatusOK || !bytes.Contains(res.Body.Bytes(), []byte(`"outcome":"ready"`)) {
		t.Fatalf("matching transport-bound writeback status=%d body=%s", res.Code, res.Body.String())
	}

	missingPeerLease := boundTestLaunchIdentityLease(t, backend, "api-service", nil, []string{"services/api-service"}, []string{"create"}, "jti-writeback-transport-missing-peer", peer)
	missingPeerBody := []byte(`{"requestId":"req-writeback-transport-missing-peer","identity":{"serviceId":"api-service","expiresAt":"2026-05-07T00:05:00Z"},"identityLease":` + mustLeaseJSON(t, missingPeerLease) + `,"policy":{"allowedNamespaces":["services/api-service"],"allowedOperations":["create"]},"operation":"create","namespace":"services/api-service","ref":"runtime/MISSING_PEER","value":"blocked-writeback-secret"}`)
	res = serveTransportBoundRequest(t, handler, http.MethodPost, "/v1/writeback", "test-token", missingPeerBody, transportPeerIdentity{})
	if res.Code != http.StatusForbidden || !bytes.Contains(res.Body.Bytes(), []byte(`"code":"policy_denied"`)) {
		t.Fatalf("missing-peer transport-bound writeback status=%d body=%s", res.Code, res.Body.String())
	}
	assertNoSecretMaterial(t, res.Body.Bytes(), "blocked-writeback-secret", "test-token")
}

func boundTestLaunchIdentityLease(t *testing.T, backend *localBackend, serviceID string, refs, namespaces, operations []string, jti string, peer transportPeerIdentity) launchIdentityLease {
	t.Helper()
	lease := testLaunchIdentityLease(t, backend, serviceID, refs, namespaces, operations, jti)
	lease.TransportBinding = &launchTransportBinding{Kind: peer.Kind, Subject: peer.Subject}
	return mustSignLaunchIdentityLease(t, lease, "test-token")
}

func serveTransportBoundRequest(t *testing.T, handler http.Handler, method, path, token string, body []byte, peer transportPeerIdentity) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req = req.WithContext(contextWithTransportPeerIdentity(req.Context(), peer))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func mustSignLaunchIdentityLease(t *testing.T, lease launchIdentityLease, key string) launchIdentityLease {
	t.Helper()
	signed, err := signLaunchIdentityLease(lease, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
