package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type sessionStatusResponse struct {
	ServiceID  string `json:"serviceId"`
	APIVersion string `json:"apiVersion"`
	Configured bool   `json:"configured"`
	Source     string `json:"source"`
	State      string `json:"state"`
}

type sessionGenerateResponse struct {
	ServiceID  string `json:"serviceId"`
	APIVersion string `json:"apiVersion"`
	Token      string `json:"token"`
	Warning    string `json:"warning"`
}

func runSession(args []string) error {
	if len(args) == 0 {
		return printSessionStatus(args)
	}
	switch args[0] {
	case "status":
		return printSessionStatus(args[1:])
	case "generate":
		return printGeneratedSessionToken()
	default:
		return fmt.Errorf("unknown session command %q", args[0])
	}
}

func printSessionStatus(args []string) error {
	fs := flag.NewFlagSet("session status", flag.ContinueOnError)
	apiToken := fs.String("api-token", getenvDefault("SECRETSBROKER_API_TOKEN", ""), "local API token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(sessionStatus(*apiToken))
}

func printGeneratedSessionToken() error {
	token, err := generateSessionToken()
	if err != nil {
		return err
	}
	res := sessionGenerateResponse{ServiceID: serviceID, APIVersion: apiVersion, Token: token, Warning: "Store this local API token securely. Secret-bearing endpoints require it."}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func sessionStatus(token string) sessionStatusResponse {
	configured := strings.TrimSpace(token) != ""
	state := "locked"
	source := "none"
	if configured {
		state = "ready"
		source = "flag/env"
	}
	return sessionStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Configured: configured, Source: source, State: state}
}

func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "sbk_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

type localAPISecurity struct {
	token    string
	lockouts *lockoutStore
	audit    func(operation, ref, outcome, requestServiceID, requestID string) error
}

func (s localAPISecurity) require(w http.ResponseWriter, r *http.Request) bool {
	expected := strings.TrimSpace(s.token)
	if expected == "" {
		writeAPIError(w, http.StatusServiceUnavailable, "security_not_configured", "Secret-bearing endpoints require SECRETSBROKER_API_TOKEN or --api-token.", "policy_denied", "configure_api_token")
		return false
	}
	scope := localAPILockoutScope(r)
	if decision := s.lockouts.active(scope); decision.Active {
		s.auditOutcome("local_api_lockout", "lockout_active")
		writeLockoutAPIError(w, decision)
		return false
	}
	got := bearerToken(r.Header.Get("Authorization"))
	if got == "" {
		got = strings.TrimSpace(r.Header.Get("X-SecretsBroker-Token"))
	}
	if got == "" || !constantTimeTokenEqual(got, expected) {
		s.auditOutcome("local_api_auth", "unauthorized")
		decision, started := s.lockouts.recordFailure(scope)
		if started {
			s.auditOutcome("local_api_lockout", "lockout_active")
			writeLockoutAPIError(w, decision)
			return false
		}
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "A valid local API token is required.", "policy_denied", "authenticate_local_session")
		return false
	}
	s.lockouts.recordSuccess(scope)
	return true
}

func (s localAPISecurity) auditOutcome(operation, outcome string) {
	if s.audit != nil {
		_ = s.audit(operation, "", outcome, "@operator", "")
	}
}

func writeLockoutAPIError(w http.ResponseWriter, decision lockoutDecision) {
	writeScopedLockoutAPIError(w, decision.Scope, decision.RetryAfterSeconds, "Local API authentication is temporarily locked for this scope.")
}

func writeScopedLockoutAPIError(w http.ResponseWriter, scope string, retryAfterSeconds int, message string) {
	if strings.TrimSpace(message) == "" {
		message = "Operation is temporarily locked for this scope."
	}
	writeJSON(w, http.StatusLocked, ErrorEnvelope{Error: APIError{
		Code:              "lockout_active",
		Message:           message,
		Outcome:           "policy_denied",
		NextAction:        "wait_or_clear_lockout",
		AffectedRefs:      []string{},
		AffectedServices:  []string{},
		LockoutActive:     true,
		LockoutScope:      scope,
		RetryAfterSeconds: retryAfterSeconds,
	}})
}

func constantTimeTokenEqual(got, expected string) bool {
	got = strings.TrimSpace(got)
	expected = strings.TrimSpace(expected)
	if got == "" || expected == "" {
		return false
	}
	gotHash := sha256.Sum256([]byte(got))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(gotHash[:], expectedHash[:]) == 1
}

func bearerToken(header string) string {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
