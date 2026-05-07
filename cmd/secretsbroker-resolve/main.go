package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	protocolVersion = 1
	providerName    = "service-lasso-secretsbroker"
	apiVersion      = "secretsbroker.local/v1"
)

type execSecretRequest struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Provider        string   `json:"provider"`
	IDs             []string `json:"ids"`
}

type execSecretResponse struct {
	ProtocolVersion int               `json:"protocolVersion"`
	Values          map[string]string `json:"values,omitempty"`
	Errors          map[string]string `json:"errors,omitempty"`
	Error           string            `json:"error,omitempty"`
	Outcome         string            `json:"outcome,omitempty"`
}

type brokerResolveRequest struct {
	RequestID string   `json:"requestId"`
	ServiceID string   `json:"serviceId"`
	Purpose   string   `json:"purpose"`
	Refs      []string `json:"refs"`
}

type brokerResolveResponse struct {
	ServiceID  string                `json:"serviceId"`
	APIVersion string                `json:"apiVersion"`
	RequestID  string                `json:"requestId,omitempty"`
	Results    []brokerResolveResult `json:"results"`
}

type brokerResolveResult struct {
	Ref     string `json:"ref"`
	Outcome string `json:"outcome"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message,omitempty"`
}

type brokerErrorEnvelope struct {
	Error struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		Outcome    string `json:"outcome"`
		NextAction string `json:"nextAction,omitempty"`
	} `json:"error"`
}

type resolverConfig struct {
	BrokerURL string
	Token     string
	Policy    []string
	Timeout   time.Duration
	Stdin     io.Reader
	Stdout    io.Writer
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("secretsbroker-resolve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	brokerURL := fs.String("broker-url", getenvDefault("SECRETSBROKER_URL", "http://127.0.0.1:17890"), "local @secretsbroker URL")
	token := fs.String("api-token", getenvDefault("SECRETSBROKER_API_TOKEN", ""), "local API token")
	tokenFile := fs.String("api-token-file", getenvDefault("SECRETSBROKER_API_TOKEN_FILE", ""), "file containing local API token")
	policy := fs.String("allow", getenvDefault("SECRETSBROKER_RESOLVE_ALLOW", "openclaw/*"), "comma-separated allowed SecretRef prefixes")
	timeoutMs := fs.Int("timeout-ms", 3000, "broker request timeout in milliseconds")
	if err := fs.Parse(args); err != nil {
		writeProtocolError(stdout, "invalid_request", "invalid resolver flags")
		return err
	}
	resolvedToken := strings.TrimSpace(*token)
	if resolvedToken == "" && strings.TrimSpace(*tokenFile) != "" {
		bytes, err := os.ReadFile(strings.TrimSpace(*tokenFile))
		if err != nil {
			writeProtocolError(stdout, "policy_denied", "local API token file could not be read")
			return err
		}
		resolvedToken = strings.TrimSpace(string(bytes))
	}
	cfg := resolverConfig{BrokerURL: *brokerURL, Token: resolvedToken, Policy: splitCSV(*policy), Timeout: time.Duration(*timeoutMs) * time.Millisecond, Stdin: stdin, Stdout: stdout}
	return resolveFromBroker(cfg)
}

func resolveFromBroker(cfg resolverConfig) error {
	var req execSecretRequest
	if err := json.NewDecoder(cfg.Stdin).Decode(&req); err != nil {
		writeProtocolError(cfg.Stdout, "invalid_request", "request body is not valid JSON")
		return err
	}
	if req.ProtocolVersion != protocolVersion || req.Provider != providerName {
		writeProtocolError(cfg.Stdout, "invalid_request", "unsupported SecretRef exec provider request")
		return errors.New("unsupported request")
	}
	if len(req.IDs) == 0 {
		return writeProtocolResponse(cfg.Stdout, execSecretResponse{ProtocolVersion: protocolVersion, Values: map[string]string{}})
	}
	for _, id := range req.IDs {
		if !allowedRef(id, cfg.Policy) {
			writeRefError(cfg.Stdout, req.IDs, id, "policy_denied")
			return errors.New("policy denied")
		}
	}
	if strings.TrimSpace(cfg.Token) == "" {
		writeProtocolError(cfg.Stdout, "policy_denied", "local API token is not configured")
		return errors.New("missing local api token")
	}

	body, err := json.Marshal(brokerResolveRequest{RequestID: "openclaw-secretref", ServiceID: "openclaw", Purpose: "secretref-exec-provider", Refs: req.IDs})
	if err != nil {
		writeProtocolError(cfg.Stdout, "degraded", "request could not be encoded")
		return err
	}
	httpReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.BrokerURL, "/")+"/v1/resolve", bytes.NewReader(body))
	if err != nil {
		writeProtocolError(cfg.Stdout, "degraded", "broker URL is invalid")
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+cfg.Token)
	client := http.Client{Timeout: cfg.Timeout}
	res, err := client.Do(httpReq)
	if err != nil {
		writeProtocolError(cfg.Stdout, "degraded", "local @secretsbroker is unavailable")
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		outcome := brokerHTTPOutcome(res.Body)
		writeProtocolError(cfg.Stdout, outcome, "local @secretsbroker returned "+outcome)
		return errors.New(outcome)
	}
	var broker brokerResolveResponse
	if err := json.NewDecoder(res.Body).Decode(&broker); err != nil {
		writeProtocolError(cfg.Stdout, "degraded", "broker response was not valid JSON")
		return err
	}
	values := map[string]string{}
	errorsByRef := map[string]string{}
	for _, result := range broker.Results {
		if result.Outcome == "ready" {
			values[result.Ref] = result.Value
		} else {
			errorsByRef[result.Ref] = normalizeOutcome(result.Outcome)
		}
	}
	if len(errorsByRef) > 0 {
		return writeProtocolResponse(cfg.Stdout, execSecretResponse{ProtocolVersion: protocolVersion, Values: values, Errors: errorsByRef, Outcome: firstOutcome(errorsByRef)})
	}
	return writeProtocolResponse(cfg.Stdout, execSecretResponse{ProtocolVersion: protocolVersion, Values: values})
}

func allowedRef(ref string, allowed []string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.ContainsAny(ref, " \t\r\n") || strings.Contains(ref, "..") {
		return false
	}
	for _, pattern := range allowed {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if pattern == "*" || ref == pattern {
			return true
		}
		if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(ref, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

func brokerHTTPOutcome(body io.Reader) string {
	var envelope brokerErrorEnvelope
	if err := json.NewDecoder(io.LimitReader(body, 65536)).Decode(&envelope); err == nil {
		return normalizeOutcome(firstNonEmpty(envelope.Error.Outcome, envelope.Error.Code))
	}
	return "degraded"
}

func normalizeOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "locked", "missing_ref", "policy_denied", "source_auth_required", "degraded":
		return strings.TrimSpace(outcome)
	case "source_unavailable":
		return "degraded"
	default:
		return "degraded"
	}
}

func firstOutcome(errorsByRef map[string]string) string {
	for _, outcome := range errorsByRef {
		return outcome
	}
	return ""
}

func writeRefError(w io.Writer, ids []string, ref string, outcome string) {
	errorsByRef := map[string]string{}
	for _, id := range ids {
		if id == ref {
			errorsByRef[id] = outcome
		}
	}
	_ = writeProtocolResponse(w, execSecretResponse{ProtocolVersion: protocolVersion, Values: map[string]string{}, Errors: errorsByRef, Outcome: outcome})
}

func writeProtocolError(w io.Writer, outcome, message string) {
	_ = writeProtocolResponse(w, execSecretResponse{ProtocolVersion: protocolVersion, Error: message, Outcome: normalizeOutcome(outcome)})
}

func writeProtocolResponse(w io.Writer, res execSecretResponse) error {
	if res.Values == nil && res.Errors == nil && res.Error == "" {
		res.Values = map[string]string{}
	}
	return json.NewEncoder(w).Encode(res)
}

func getenvDefault(name, fallback string) string {
	if value := os.Getenv(name); strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func firstNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
