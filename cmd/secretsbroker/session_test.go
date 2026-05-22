package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionStatusAndGenerate(t *testing.T) {
	locked := sessionStatus("")
	if locked.Configured || locked.State != "locked" {
		t.Fatalf("locked session = %#v", locked)
	}
	ready := sessionStatus("token")
	if !ready.Configured || ready.State != "ready" {
		t.Fatalf("ready session = %#v", ready)
	}
	token, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "sbk_") {
		t.Fatalf("token = %q", token)
	}
}

func TestLocalAPISecurityRequiresConfiguredToken(t *testing.T) {
	sec := localAPISecurity{}
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	res := httptest.NewRecorder()
	if sec.require(res, req) {
		t.Fatalf("unconfigured security should reject")
	}
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", res.Code)
	}
}

func TestConstantTimeTokenEqualTrimsAndRejectsMismatches(t *testing.T) {
	if !constantTimeTokenEqual(" secret-token ", "secret-token") {
		t.Fatalf("trimmed matching tokens should pass")
	}
	if constantTimeTokenEqual("secret-token-extra", "secret-token") {
		t.Fatalf("different length token should reject")
	}
	if constantTimeTokenEqual("", "secret-token") {
		t.Fatalf("empty token should reject")
	}
}

func TestLocalAPISecurityAcceptsBearerAndRejectsWrongToken(t *testing.T) {
	sec := localAPISecurity{token: "secret-token"}
	badReq := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	badReq.Header.Set("Authorization", "Bearer wrong")
	badRes := httptest.NewRecorder()
	if sec.require(badRes, badReq) {
		t.Fatalf("wrong token should reject")
	}
	if badRes.Code != http.StatusUnauthorized {
		t.Fatalf("bad status = %d", badRes.Code)
	}

	goodReq := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	goodReq.Header.Set("Authorization", "Bearer secret-token")
	goodRes := httptest.NewRecorder()
	if !sec.require(goodRes, goodReq) {
		t.Fatalf("good bearer token should pass")
	}
}

func TestLocalAPISecurityLocksOutRepeatedInvalidTokens(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	backend := newLocalBackend(filepath.Join(dir, "store.json"), auditPath, "test-master-key")
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	lockouts := newLockoutStore(func() time.Time { return now })
	sec := localAPISecurity{token: "secret-token", lockouts: lockouts, audit: backend.audit}

	for i := 1; i <= localAPILockoutThreshold; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer wrong-token")
		res := httptest.NewRecorder()
		if sec.require(res, req) {
			t.Fatalf("invalid token attempt %d should reject", i)
		}
		if i < localAPILockoutThreshold && res.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d", i, res.Code)
		}
		if i == localAPILockoutThreshold {
			if res.Code != http.StatusLocked {
				t.Fatalf("lockout status = %d", res.Code)
			}
			var body ErrorEnvelope
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code != "lockout_active" || !body.Error.LockoutActive || body.Error.LockoutScope != "local_api:127.0.0.1" {
				t.Fatalf("lockout body = %#v", body.Error)
			}
			if body.Error.RetryAfterSeconds <= 0 {
				t.Fatalf("retryAfterSeconds = %d", body.Error.RetryAfterSeconds)
			}
			encoded := res.Body.String()
			if strings.Contains(encoded, "wrong-token") || strings.Contains(encoded, "secret-token") {
				t.Fatalf("lockout response leaked token material: %s", encoded)
			}
		}
	}

	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	auditText := string(auditBytes)
	for _, want := range []string{"local_api_auth", "unauthorized", "local_api_lockout", "lockout_active"} {
		if !strings.Contains(auditText, want) {
			t.Fatalf("audit missing %q: %s", want, auditText)
		}
	}
	if strings.Contains(auditText, "wrong-token") || strings.Contains(auditText, "secret-token") {
		t.Fatalf("audit leaked token material: %s", auditText)
	}

	lockedReq := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	lockedReq.RemoteAddr = "127.0.0.1:5000"
	lockedReq.Header.Set("Authorization", "Bearer secret-token")
	lockedRes := httptest.NewRecorder()
	if sec.require(lockedRes, lockedReq) {
		t.Fatalf("active lockout should reject even a valid token until cooldown expires")
	}
	if lockedRes.Code != http.StatusLocked {
		t.Fatalf("active lockout status = %d", lockedRes.Code)
	}

	now = now.Add(localAPILockoutCooldown + time.Second)
	goodReq := httptest.NewRequest(http.MethodPost, "/v1/resolve", nil)
	goodReq.RemoteAddr = "127.0.0.1:5000"
	goodReq.Header.Set("Authorization", "Bearer secret-token")
	goodRes := httptest.NewRecorder()
	if !sec.require(goodRes, goodReq) {
		t.Fatalf("valid token should pass after cooldown")
	}
}
