package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
