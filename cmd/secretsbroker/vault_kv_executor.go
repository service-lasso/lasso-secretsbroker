package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultVaultKVMigrationTimeout  = 3 * time.Second
	maximumVaultKVMigrationTimeout  = 30 * time.Second
	defaultVaultKVMigrationMaxBytes = 64 * 1024
	maximumVaultKVMigrationMaxBytes = 1024 * 1024
)

type vaultKVMigrationExecutor struct {
	source  sourceConfig
	baseURL url.URL
	client  *http.Client
}

type vaultKVReadResult struct {
	Data    map[string]any
	Version int
	Outcome string
}

func (b *localBackend) configureProviderMigrationExecutors() {
	if b == nil {
		return
	}
	b.registerLocalStoreMigrationExecutor()
	for _, source := range b.sources.enabledSources() {
		if !source.EnableMigrationTarget {
			continue
		}
		var executor providerMigrationExecutor
		var err error
		switch strings.ToLower(strings.TrimSpace(source.Kind)) {
		case "vault", "openbao":
			executor, err = newVaultKVMigrationExecutor(source)
		case "aws-secrets-manager":
			executor, err = newAWSSecretsManagerMigrationExecutor(source)
		default:
			continue
		}
		if err != nil {
			continue
		}
		b.registerProviderMigrationExecutor(source.SourceID, executor)
	}
}

func newVaultKVMigrationExecutor(source sourceConfig) (*vaultKVMigrationExecutor, error) {
	kind := strings.ToLower(strings.TrimSpace(source.Kind))
	if !source.Enabled || !source.EnableMigrationTarget || (kind != "vault" && kind != "openbao") {
		return nil, errors.New("vault migration target is not explicitly enabled")
	}
	baseURL, err := validatedVaultKVBaseURL(source.Address)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(firstNonEmpty(source.Token, os.Getenv(source.TokenEnv))) == "" {
		return nil, errors.New("vault migration target authentication is missing")
	}
	if len(source.Refs) == 0 {
		return nil, errors.New("vault migration target has no ref mappings")
	}
	for ref, mapping := range source.Refs {
		if !validSecretRef(ref) || !validVaultKVMapping(mapping) {
			return nil, errors.New("vault migration target mapping is invalid")
		}
	}
	return &vaultKVMigrationExecutor{
		source:  source,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: maximumVaultKVMigrationTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func validatedVaultKVBaseURL(address string) (url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(address))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return url.URL{}, errors.New("vault migration target address is invalid")
	}
	if parsed.Scheme == "http" && !vaultKVLoopbackHost(parsed.Hostname()) {
		return url.URL{}, errors.New("vault migration target requires HTTPS outside loopback")
	}
	return url.URL{Scheme: parsed.Scheme, Host: parsed.Host}, nil
}

func vaultKVLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func validVaultKVMapping(mapping sourceRefConfig) bool {
	path := strings.Trim(strings.TrimSpace(mapping.Path), "/")
	field := strings.TrimSpace(mapping.Field)
	if path == "" || len(path) > 2048 || field == "" || len(field) > 256 || strings.ContainsAny(path, "\\?#%") || strings.ContainsAny(field, "\r\n") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return strings.Contains("/"+path+"/", "/data/")
}

func (e *vaultKVMigrationExecutor) Write(req providerMigrationWriteRequest) providerMigrationExecutorResult {
	mapping, ok := e.source.Refs[req.Ref]
	if !ok || !validVaultKVMapping(mapping) {
		return providerMigrationExecutorResult{Outcome: "invalid_ref"}
	}
	current := e.read(mapping)
	if current.Outcome != "ready" && current.Outcome != "missing_ref" {
		return providerMigrationExecutorResult{Outcome: current.Outcome}
	}
	if current.Outcome == "ready" {
		if value, ok := current.Data[mapping.Field].(string); ok && value == req.Value {
			return providerMigrationExecutorResult{Outcome: "applied"}
		}
	} else {
		current.Data = map[string]any{}
		current.Version = 0
	}
	current.Data[mapping.Field] = req.Value
	payload, err := json.Marshal(map[string]any{
		"data":    current.Data,
		"options": map[string]int{"cas": current.Version},
	})
	if err != nil || len(payload) > vaultKVMigrationMaxBytes(mapping) {
		return providerMigrationExecutorResult{Outcome: "invalid_ref"}
	}
	status, _, outcome := e.request(http.MethodPost, mapping, bytes.NewReader(payload), req.IdempotencyKey)
	if outcome != "ready" {
		return providerMigrationExecutorResult{Outcome: outcome}
	}
	if status < 200 || status >= 300 {
		return providerMigrationExecutorResult{Outcome: vaultKVStatusOutcome(status, true)}
	}
	return providerMigrationExecutorResult{Outcome: "applied"}
}

func (e *vaultKVMigrationExecutor) Verify(req providerMigrationVerifyRequest) providerMigrationExecutorResult {
	mapping, ok := e.source.Refs[req.Ref]
	if !ok || !validVaultKVMapping(mapping) {
		return providerMigrationExecutorResult{Outcome: "invalid_ref"}
	}
	current := e.read(mapping)
	if current.Outcome != "ready" {
		if current.Outcome == "missing_ref" || current.Outcome == "invalid_ref" {
			return providerMigrationExecutorResult{Outcome: "verification_failed"}
		}
		return providerMigrationExecutorResult{Outcome: current.Outcome}
	}
	value, ok := current.Data[mapping.Field].(string)
	if !ok || value != req.ExpectedValue {
		return providerMigrationExecutorResult{Outcome: "verification_failed"}
	}
	return providerMigrationExecutorResult{Outcome: "verified"}
}

func (e *vaultKVMigrationExecutor) read(mapping sourceRefConfig) vaultKVReadResult {
	status, body, outcome := e.request(http.MethodGet, mapping, nil, "")
	if outcome != "ready" {
		return vaultKVReadResult{Outcome: outcome}
	}
	if status < 200 || status >= 300 {
		return vaultKVReadResult{Outcome: vaultKVStatusOutcome(status, false)}
	}
	var payload struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if len(body) == 0 || json.Unmarshal(body, &payload) != nil || payload.Data.Data == nil || payload.Data.Metadata.Version <= 0 {
		return vaultKVReadResult{Outcome: "source_unavailable"}
	}
	return vaultKVReadResult{Data: payload.Data.Data, Version: payload.Data.Metadata.Version, Outcome: "ready"}
}

func (e *vaultKVMigrationExecutor) request(method string, mapping sourceRefConfig, body io.Reader, idempotencyKey string) (int, []byte, string) {
	endpoint, err := e.endpoint(mapping.Path)
	if err != nil {
		return 0, nil, "invalid_ref"
	}
	token := strings.TrimSpace(firstNonEmpty(e.source.Token, os.Getenv(e.source.TokenEnv)))
	if token == "" {
		return 0, nil, "source_auth_required"
	}
	ctx, cancel := context.WithTimeout(context.Background(), vaultKVMigrationTimeout(mapping))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, nil, "invalid_ref"
	}
	req.Header.Set("X-Vault-Token", token)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		if strings.TrimSpace(idempotencyKey) != "" {
			req.Header.Set("X-Service-Lasso-Idempotency-Key", idempotencyKey)
		}
	}
	res, err := e.client.Do(req)
	if err != nil {
		return 0, nil, "source_unavailable"
	}
	defer res.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(res.Body, int64(vaultKVMigrationMaxBytes(mapping))+1))
	if err != nil || len(responseBody) > vaultKVMigrationMaxBytes(mapping) {
		return res.StatusCode, nil, "source_unavailable"
	}
	return res.StatusCode, responseBody, "ready"
}

func (e *vaultKVMigrationExecutor) endpoint(path string) (string, error) {
	mapping := sourceRefConfig{Path: path, Field: "value"}
	if !validVaultKVMapping(mapping) {
		return "", errors.New("vault migration target path is invalid")
	}
	endpoint := e.baseURL
	endpoint.Path = "/v1/" + strings.Trim(strings.TrimSpace(path), "/")
	return endpoint.String(), nil
}

func vaultKVStatusOutcome(status int, write bool) string {
	switch status {
	case http.StatusUnauthorized:
		return "source_auth_required"
	case http.StatusForbidden:
		return "policy_denied"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusConflict, http.StatusPreconditionFailed:
		return "conflict"
	case http.StatusBadRequest:
		if write {
			return "conflict"
		}
		return "invalid_ref"
	case http.StatusNotFound:
		if write {
			return "invalid_ref"
		}
		return "missing_ref"
	}
	if status >= 500 || status == http.StatusRequestTimeout || (status >= 300 && status < 400) {
		return "source_unavailable"
	}
	return "invalid_ref"
}

func vaultKVMigrationTimeout(mapping sourceRefConfig) time.Duration {
	timeout := time.Duration(firstPositive(mapping.TimeoutMs, int(defaultVaultKVMigrationTimeout/time.Millisecond))) * time.Millisecond
	if timeout < 100*time.Millisecond {
		return 100 * time.Millisecond
	}
	if timeout > maximumVaultKVMigrationTimeout {
		return maximumVaultKVMigrationTimeout
	}
	return timeout
}

func vaultKVMigrationMaxBytes(mapping sourceRefConfig) int {
	limit := firstPositive(mapping.MaxBytes, firstPositive(mapping.MaxStdoutBytes, defaultVaultKVMigrationMaxBytes))
	if limit > maximumVaultKVMigrationMaxBytes {
		return maximumVaultKVMigrationMaxBytes
	}
	return limit
}
