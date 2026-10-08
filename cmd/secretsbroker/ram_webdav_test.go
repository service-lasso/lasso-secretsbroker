package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestRAMNativeWindowsUNC(t *testing.T) {
	if runtime.GOOS != "windows" || os.Getenv("SERVICE_LASSO_TEST_NATIVE_UNC") != "1" {
		t.Skip("native UNC qualification explicitly selected on Windows")
	}
	b, _ := ramFixture(t)
	grant, err := b.ramFiles.create("native-unc", []ramFileInput{{"key", "synthetic-unc-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	port := strings.Split(strings.TrimPrefix(grant.BaseURL, "http://"), ":")[1]
	name := `\\127.0.0.1@` + port + `\DavWWWRoot\` + grant.Token + `\key`
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal("native UNC client could not read the granted file")
	}
	if string(content) != "synthetic-unc-secret" {
		t.Fatal("native UNC bytes did not match")
	}
}

func ramFixture(t *testing.T) (*localBackend, func()) {
	t.Helper()
	b := testBackend(t)
	close, err := b.startRAMWebDAV()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(close)
	return b, close
}
func davRequest(t *testing.T, method, url, token string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.Get("Cache-Control") == "" {
		t.Fatal("missing cache prohibition")
	}
	return res.StatusCode, string(body)
}
func TestRAMWebDAVReadsIsolationRotationRevocation(t *testing.T) {
	b, _ := ramFixture(t)
	s := b.ramFiles
	first, err := s.create("service-A", []ramFileInput{{"password", "synthetic-first"}, {"nested/key", "synthetic-key"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.create("service-B", []ramFileInput{{"private", "synthetic-other"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{first.BaseURL + "/" + first.Token + "/password", first.BaseURL + "/files/password"} {
		token := ""
		if strings.Contains(url, "/files/") {
			token = first.Token
		}
		code, body := davRequest(t, "GET", url, token, nil)
		if code != 200 || body != "synthetic-first" {
			t.Fatal("file read failed")
		}
	}
	code, _ := davRequest(t, "GET", first.BaseURL+"/"+first.Token+"/private", "", nil)
	if code != 404 {
		t.Fatal("foreign grant visible")
	}
	code, body := davRequest(t, "PROPFIND", first.BaseURL+"/"+first.Token+"/", "", map[string]string{"Depth": "1"})
	if code != 207 || !strings.Contains(body, "nested/") || strings.Contains(body, "synthetic-first") || strings.Contains(body, second.Token) {
		t.Fatal("invalid scoped directory listing")
	}
	if _, err := s.create("service-A", []ramFileInput{{"../bad", "x"}}); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	code, _ = davRequest(t, "GET", first.BaseURL+"/"+first.Token+"/password", "", nil)
	if code != 200 {
		t.Fatal("invalid replacement destroyed grant")
	}
	replacement, err := s.create("service-A", []ramFileInput{{"password", "synthetic-rotated"}})
	if err != nil {
		t.Fatal(err)
	}
	if first.Token == replacement.Token {
		t.Fatal("token reused")
	}
	s.revoke(first.Token)
	code, _ = davRequest(t, "GET", first.BaseURL+"/"+first.Token+"/password", "", nil)
	if code != 404 {
		t.Fatal("old grant still live")
	}
	code, body = davRequest(t, "GET", replacement.BaseURL+"/"+replacement.Token+"/password", "", nil)
	if code != 200 || body != "synthetic-rotated" {
		t.Fatal("old revocation removed successor")
	}
	s.revoke(replacement.Token)
	code, _ = davRequest(t, "GET", replacement.BaseURL+"/"+replacement.Token+"/password", "", nil)
	if code != 404 {
		t.Fatal("revoked grant still live")
	}
	code, _ = davRequest(t, "GET", second.BaseURL+"/"+second.Token+"/private", "", nil)
	if code != 200 {
		t.Fatal("revocation crossed services")
	}
}
func TestRAMWebDAVDeniesUnsafeRequestsAndBounds(t *testing.T) {
	b, _ := ramFixture(t)
	s := b.ramFiles
	grant, err := s.create("owner", []ramFileInput{{"key", "synthetic"}})
	if err != nil {
		t.Fatal(err)
	}
	base := grant.BaseURL + "/" + grant.Token
	for _, tc := range []struct {
		method, path string
		headers      map[string]string
	}{
		{"PUT", "/key", nil}, {"DELETE", "/key", nil}, {"MOVE", "/key", nil}, {"PROPFIND", "/", map[string]string{"Depth": "infinity"}},
		{"GET", "/../key", nil}, {"GET", "/%2e%2e/key", nil}, {"GET", "/key?token=x", nil},
		{"GET", "/key", map[string]string{"Host": "evil.example"}}, {"GET", "/key", map[string]string{"Origin": "http://evil.example"}}, {"GET", "/key", map[string]string{"X-Forwarded-For": "127.0.0.1"}},
	} {
		t.Run(tc.method+tc.path+fmt.Sprint(tc.headers), func(t *testing.T) {
			code, _ := davRequest(t, tc.method, base+tc.path, "", tc.headers)
			if code < 400 {
				t.Fatal("unsafe request accepted")
			}
		})
	}
	req := httptest.NewRequest("GET", base+"/key", nil)
	req.Host = strings.TrimPrefix(grant.BaseURL, "http://")
	req.RemoteAddr = "192.0.2.1:5000"
	res := httptest.NewRecorder()
	s.ServeHTTP(res, req)
	if res.Code != 403 {
		t.Fatal("external peer accepted")
	}
	for _, p := range []string{"/absolute", "a\\b", "a/../b", "a//b", "a%2fb", "a:b", ".", "a b"} {
		if _, err := s.create("bad", []ramFileInput{{p, "x"}}); err == nil {
			t.Fatalf("path accepted %q", p)
		}
	}
	for _, files := range [][]ramFileInput{{{"key", strings.Repeat("x", maxRAMFileBytes+1)}}, {{"a", "x"}, {"a/b", "x"}}, {{"a", "x"}, {"a", "y"}}} {
		if _, err := s.create("bad", files); err == nil {
			t.Fatal("invalid bound/conflict accepted")
		}
	}
	s.mu.Lock()
	s.bytes = maxRAMStoreBytes
	s.mu.Unlock()
	if _, err := s.create("full", []ramFileInput{{"key", "x"}}); err == nil {
		t.Fatal("aggregate bound ignored")
	}
}
func TestRAMFileGrantAPIRequiresOperatorAndScopedLeaseAndNeverPersists(t *testing.T) {
	b, close := ramFixture(t)
	handler := newHandler(runtimeState{}, b, localAPISecurity{token: "test-token"})
	lease := testLaunchIdentityLease(t, b, "app", []string{"services/app/*"}, nil, []string{"resolve"}, "jti-ram-file-grant")
	req := ramGrantRequest{ServiceID: "app", InstanceID: strings.Repeat("a", 64), IdentityLease: &lease, Files: []ramFileInput{{"key", "synthetic-private-secret"}}}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	request := func(token string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/file-grants", bytes.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if res := request("", body); res.Code != 401 {
		t.Fatalf("unauth grant status %d", res.Code)
	}
	invalid := req
	invalid.IdentityLease = nil
	bad, _ := json.Marshal(invalid)
	if res := request("test-token", bad); res.Code != 401 {
		t.Fatal("unsigned grant accepted")
	}
	res := request("test-token", body)
	if res.Code != 201 {
		t.Fatalf("signed grant status %d: %s", res.Code, res.Body.String())
	}
	var grant ramGrantResponse
	if err := json.Unmarshal(res.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if request("test-token", body).Code != 401 {
		t.Fatal("lease replay accepted")
	}
	for _, p := range []string{b.storePath, b.auditPath, b.eventPath} {
		data, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(req.Files[0].Content)) || bytes.Contains(data, []byte(grant.Token)) {
			t.Fatal("plaintext persisted")
		}
	}
	close()
	if len(b.ramFiles.grants) != 0 || b.ramFiles.bytes != 0 {
		t.Fatal("RAM survived provider shutdown")
	}
	fresh := newRAMFileStore()
	if _, ok := fresh.grants[sha256.Sum256([]byte(grant.Token))]; ok {
		t.Fatal("grant survived restart")
	}
}

func TestRAMFileGrantProductionPeerBindingAndRequestBounds(t *testing.T) {
	b, _ := ramFixture(t)
	b.production = true
	b.launchIdentitySigningKey = "test-token"
	b.launchIdentityIssuer = "service-lasso-local-launcher"
	handler := newHandler(runtimeState{}, b, localAPISecurity{token: "test-token"})
	peer := transportPeerIdentity{Kind: "unix-uid", Subject: "1000"}
	lease := boundTestLaunchIdentityLease(t, b, "app", []string{"services/app/*"}, nil, []string{"resolve"}, "jti-ram-production", peer)
	req := ramGrantRequest{ServiceID: "app", InstanceID: strings.Repeat("b", 64), IdentityLease: &lease, Files: []ramFileInput{{"key", "synthetic"}}}
	body, _ := json.Marshal(req)
	bad := serveTransportBoundRequest(t, handler, "POST", "/v1/file-grants", "test-token", body, transportPeerIdentity{Kind: "unix-uid", Subject: "1001"})
	if bad.Code != 403 {
		t.Fatal("foreign IPC peer accepted")
	}
	good := serveTransportBoundRequest(t, handler, "POST", "/v1/file-grants", "test-token", body, peer)
	if good.Code != 201 {
		t.Fatalf("bound IPC status %d", good.Code)
	}
	huge := serveTransportBoundRequest(t, handler, "POST", "/v1/file-grants", "test-token", []byte(`{"instanceId":"`+strings.Repeat("a", maxSecretBearingRequestBytes+1)+`"}`), peer)
	if huge.Code != 413 {
		t.Fatalf("unbounded request status %d", huge.Code)
	}
}

func TestRAMGrantCountLimitAndReplacement(t *testing.T) {
	store := newRAMFileStore()
	store.baseURL = "http://127.0.0.1:8080"
	for i := 0; i < maxRAMGrants; i++ {
		if _, err := store.create(fmt.Sprintf("owner-%d", i), []ramFileInput{{"key", ""}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.create("new-owner", []ramFileInput{{"key", ""}}); err == nil {
		t.Fatal("grant count exceeded")
	}
	if _, err := store.create("owner-0", []ramFileInput{{"key", "replacement"}}); err != nil {
		t.Fatal("bounded replacement rejected")
	}
}
