package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type sourceConfigFile struct {
	Sources []sourceConfig `json:"sources"`
}

type sourceConfig struct {
	SourceID            string                     `json:"sourceId"`
	Kind                string                     `json:"kind"`
	DisplayName         string                     `json:"displayName"`
	Enabled             bool                       `json:"enabled"`
	Critical            bool                       `json:"critical"`
	Priority            int                        `json:"priority"`
	Namespaces          []string                   `json:"namespaces"`
	TrustedDirs         []string                   `json:"trustedDirs"`
	AllowSymlinkCommand bool                       `json:"allowSymlinkCommand"`
	Address             string                     `json:"address"`
	Region              string                     `json:"region"`
	AccountID           string                     `json:"accountId"`
	Token               string                     `json:"token"`
	TokenEnv            string                     `json:"tokenEnv"`
	Refs                map[string]sourceRefConfig `json:"refs"`
}

type sourceRefConfig struct {
	Env            string   `json:"env"`
	Path           string   `json:"path"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	MaxBytes       int      `json:"maxBytes"`
	TimeoutMs      int      `json:"timeoutMs"`
	MaxStdoutBytes int      `json:"maxStdoutBytes"`
	UnsafeStdout   bool     `json:"unsafeStdout"`
	Field          string   `json:"field"`
	VersionID      string   `json:"versionId"`
	VersionStage   string   `json:"versionStage"`
}

type sourceResolveResult struct {
	Found     bool
	Value     string
	SourceID  string
	Outcome   string
	Message   string
	Lifecycle SourceLifecycle
}

func loadSourceConfig(path string) (sourceConfigFile, error) {
	if strings.TrimSpace(path) == "" {
		return sourceConfigFile{}, nil
	}
	bytes, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return sourceConfigFile{}, nil
	}
	if err != nil {
		return sourceConfigFile{}, err
	}
	var cfg sourceConfigFile
	if err := json.Unmarshal(bytes, &cfg); err != nil {
		return sourceConfigFile{}, err
	}
	return cfg, nil
}

func (cfg sourceConfigFile) enabledSources() []sourceConfig {
	sources := make([]sourceConfig, 0, len(cfg.Sources))
	for _, source := range cfg.Sources {
		if source.Enabled {
			sources = append(sources, source)
		}
	}
	sort.SliceStable(sources, func(i, j int) bool { return sources[i].Priority < sources[j].Priority })
	return sources
}

func (cfg sourceConfigFile) resolve(ref string) sourceResolveResult {
	for _, source := range cfg.enabledSources() {
		refCfg, ok := source.Refs[ref]
		if !ok {
			continue
		}
		result := source.resolve(ref, refCfg)
		result.Found = true
		result.SourceID = source.SourceID
		result.Lifecycle = normalizeSourceLifecycle(result.Outcome)
		return result
	}
	return sourceResolveResult{Found: false, Outcome: "missing_ref", Message: "Secret ref was not found.", Lifecycle: normalizeSourceLifecycle("missing_ref")}
}

func (s sourceConfig) resolve(ref string, refCfg sourceRefConfig) sourceResolveResult {
	switch strings.ToLower(strings.TrimSpace(s.Kind)) {
	case "env":
		return resolveEnv(refCfg)
	case "file":
		return s.resolveFile(refCfg)
	case "exec":
		return s.resolveExec(refCfg)
	case "vault", "openbao":
		return s.resolveVault(refCfg)
	case "onepassword-cli":
		return s.resolveOnePasswordCLI(ref, refCfg)
	case "bitwarden-bws":
		return s.resolveBitwardenBWS(refCfg)
	case "aws-secrets-manager":
		return s.resolveAWSSecretsManager(refCfg)
	default:
		return sourceResolveResult{Outcome: "invalid_ref", Message: fmt.Sprintf("Unsupported source kind %q.", s.Kind)}
	}
}

func resolveEnv(refCfg sourceRefConfig) sourceResolveResult {
	if strings.TrimSpace(refCfg.Env) == "" {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "Env source mapping is missing env name."}
	}
	value := os.Getenv(refCfg.Env)
	if strings.TrimSpace(value) == "" {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Mapped environment variable is empty or missing."}
	}
	return sourceResolveResult{Outcome: "ready", Value: value}
}

func (s sourceConfig) resolveFile(refCfg sourceRefConfig) sourceResolveResult {
	if err := validateFileConfig(s, refCfg); err != nil {
		if errors.Is(err, errFilePathOutsideTrustedDirs) {
			return sourceResolveResult{Outcome: "policy_denied", Message: "File source path is outside trustedDirs."}
		}
		return sourceResolveResult{Outcome: "invalid_ref", Message: err.Error()}
	}
	maxBytes := firstPositive(refCfg.MaxBytes, firstPositive(refCfg.MaxStdoutBytes, 65536))
	file, err := os.Open(refCfg.Path)
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Mapped file could not be read."}
	}
	defer file.Close()
	bytes, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Mapped file could not be read."}
	}
	if len(bytes) > maxBytes {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Mapped file exceeded byte limit."}
	}
	value := strings.TrimSpace(string(bytes))
	if value == "" {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Mapped file is empty."}
	}
	return sourceResolveResult{Outcome: "ready", Value: value}
}

var errFilePathOutsideTrustedDirs = errors.New("file path is outside trustedDirs")

func validateFileConfig(source sourceConfig, refCfg sourceRefConfig) error {
	path := strings.TrimSpace(refCfg.Path)
	if path == "" {
		return errors.New("file source mapping is missing path")
	}
	if len(source.TrustedDirs) == 0 {
		return nil
	}
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return errors.New("file source path is invalid")
	}
	for _, dir := range source.TrustedDirs {
		cleanDir, err := filepath.Abs(strings.TrimSpace(dir))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(cleanDir, cleanPath)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return nil
		}
	}
	return errFilePathOutsideTrustedDirs
}

func (s sourceConfig) resolveExec(refCfg sourceRefConfig) sourceResolveResult {
	if err := validateExecConfig(s, refCfg); err != nil {
		return sourceResolveResult{Outcome: "invalid_ref", Message: err.Error()}
	}
	timeout := time.Duration(firstPositive(refCfg.TimeoutMs, 2000)) * time.Millisecond
	maxStdout := firstPositive(refCfg.MaxStdoutBytes, 4096)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, refCfg.Command, refCfg.Args...)
	cmd.Env = []string{}
	stdout := newBoundedOutput(maxStdout)
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source timed out."}
	}
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source failed."}
	}
	if stdout.Exceeded() {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source stdout exceeded limit."}
	}
	out := stdout.Bytes()
	value := ""
	if refCfg.UnsafeStdout {
		value = strings.TrimSpace(string(out))
	} else {
		var payload execSourceProtocolPayload
		if err := json.Unmarshal(out, &payload); err != nil {
			return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source did not return JSON value protocol."}
		}
		if outcome := normalizeExecProtocolOutcome(payload.Outcome); outcome != "" && outcome != "ready" {
			return sourceResolveResult{Outcome: outcome, Message: execProtocolOutcomeMessage(outcome)}
		}
		value = strings.TrimSpace(payload.Value)
	}
	if value == "" {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source returned empty value."}
	}
	return sourceResolveResult{Outcome: "ready", Value: value}
}

type execSourceProtocolPayload struct {
	Value   string `json:"value"`
	Outcome string `json:"outcome"`
}

type boundedOutput struct {
	limit int
	buf   bytes.Buffer
}

func newBoundedOutput(limit int) *boundedOutput {
	return &boundedOutput{limit: firstPositive(limit, 4096)}
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	remaining := w.limit + 1 - w.buf.Len()
	if remaining > 0 {
		if len(p) < remaining {
			remaining = len(p)
		}
		_, _ = w.buf.Write(p[:remaining])
	}
	return len(p), nil
}

func (w *boundedOutput) Bytes() []byte {
	return w.buf.Bytes()
}

func (w *boundedOutput) Exceeded() bool {
	return w.buf.Len() > w.limit
}

func normalizeExecProtocolOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "", "ready":
		return strings.TrimSpace(outcome)
	case "source_auth_required", "policy_denied", "missing_ref", "source_unavailable", "invalid_ref":
		return strings.TrimSpace(outcome)
	default:
		return "source_unavailable"
	}
}

func execProtocolOutcomeMessage(outcome string) string {
	switch outcome {
	case "source_auth_required":
		return "Exec source reported authentication is required."
	case "policy_denied":
		return "Exec source policy denied access."
	case "missing_ref":
		return "Exec source reported the ref was not found."
	case "invalid_ref":
		return "Exec source protocol mapping is invalid."
	default:
		return "Exec source reported unavailable state."
	}
}

func (s sourceConfig) resolveOnePasswordCLI(ref string, refCfg sourceRefConfig) sourceResolveResult {
	if err := validateOnePasswordCLIConfig(s, refCfg); err != nil {
		if errors.Is(err, errOnePasswordCommandOutsideTrustedDirs) {
			return sourceResolveResult{Outcome: "policy_denied", Message: "1Password CLI command is outside trustedDirs."}
		}
		return sourceResolveResult{Outcome: "invalid_ref", Message: err.Error()}
	}
	timeout := time.Duration(firstPositive(refCfg.TimeoutMs, 5000)) * time.Millisecond
	maxOutput := firstPositive(refCfg.MaxStdoutBytes, firstPositive(refCfg.MaxBytes, 32768))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, refCfg.Command, onePasswordCLIArgs(refCfg)...)
	cmd.Env = append(os.Environ(),
		"OP_ITEM_REF="+refCfg.Path,
		"OP_FIELD_REF="+refCfg.Field,
		"SERVICE_LASSO_SECRET_REF="+ref,
		"SERVICE_LASSO_SOURCE_ID="+s.SourceID,
	)
	stdout := newBoundedOutput(maxOutput)
	stderr := newBoundedOutput(maxOutput)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "1Password CLI timed out."}
	}
	if stdout.Exceeded() || stderr.Exceeded() {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "1Password CLI output exceeded limit."}
	}
	if err != nil {
		if outcome := onePasswordCLIOutcomeFromOutput(stdout.Bytes(), stderr.Bytes()); outcome != "" {
			return sourceResolveResult{Outcome: outcome, Message: onePasswordCLIOutcomeMessage(outcome)}
		}
		return sourceResolveResult{Outcome: "source_unavailable", Message: "1Password CLI is unavailable or failed."}
	}
	return decodeOnePasswordCLIValue(stdout.Bytes(), refCfg)
}

var errOnePasswordCommandOutsideTrustedDirs = errors.New("onepassword-cli command is outside trustedDirs")

func validateOnePasswordCLIConfig(source sourceConfig, refCfg sourceRefConfig) error {
	if strings.TrimSpace(refCfg.Command) == "" {
		return errors.New("1Password CLI source mapping is missing command")
	}
	if strings.TrimSpace(refCfg.Path) == "" {
		return errors.New("1Password CLI source mapping is missing item/ref path")
	}
	if len(source.TrustedDirs) > 0 {
		cleanCommand, err := filepath.Abs(strings.TrimSpace(refCfg.Command))
		if err != nil {
			return errors.New("1Password CLI command path is invalid")
		}
		allowed := false
		for _, dir := range source.TrustedDirs {
			cleanDir, err := filepath.Abs(strings.TrimSpace(dir))
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(cleanDir, cleanCommand)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errOnePasswordCommandOutsideTrustedDirs
		}
	}
	return validateExecConfig(source, refCfg)
}

func onePasswordCLIArgs(refCfg sourceRefConfig) []string {
	if len(refCfg.Args) > 0 {
		return append([]string{}, refCfg.Args...)
	}
	path := strings.TrimSpace(refCfg.Path)
	field := strings.TrimSpace(refCfg.Field)
	if strings.HasPrefix(strings.ToLower(path), "op://") {
		return []string{"read", path}
	}
	if field == "" {
		return []string{"item", "get", path, "--format", "json"}
	}
	return []string{"item", "get", path, "--fields", "label=" + field, "--format", "json"}
}

func decodeOnePasswordCLIValue(output []byte, refCfg sourceRefConfig) sourceResolveResult {
	if outcome := onePasswordCLIOutcomeFromOutput(output, nil); outcome != "" && outcome != "ready" {
		return sourceResolveResult{Outcome: outcome, Message: onePasswordCLIOutcomeMessage(outcome)}
	}
	value, ok := onePasswordCLIValueFromJSON(output, refCfg)
	if !ok {
		value = strings.TrimSpace(string(output))
	}
	if strings.TrimSpace(value) == "" {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "1Password CLI returned empty value."}
	}
	return sourceResolveResult{Outcome: "ready", Value: strings.TrimSpace(value)}
}

type onePasswordCLIPayload struct {
	Value   string           `json:"value"`
	Outcome string           `json:"outcome"`
	Field   map[string]any   `json:"field"`
	Fields  []map[string]any `json:"fields"`
	Details struct {
		Fields []map[string]any `json:"fields"`
	} `json:"details"`
}

func onePasswordCLIValueFromJSON(output []byte, refCfg sourceRefConfig) (string, bool) {
	var payload onePasswordCLIPayload
	if err := json.Unmarshal(output, &payload); err != nil {
		return "", false
	}
	if strings.TrimSpace(payload.Value) != "" {
		return payload.Value, true
	}
	fieldName := strings.TrimSpace(refCfg.Field)
	if value, ok := onePasswordFieldValue(payload.Field, fieldName); ok {
		return value, true
	}
	for _, field := range append(payload.Fields, payload.Details.Fields...) {
		if value, ok := onePasswordFieldValue(field, fieldName); ok {
			return value, true
		}
	}
	return "", false
}

func onePasswordFieldValue(field map[string]any, fieldName string) (string, bool) {
	if field == nil {
		return "", false
	}
	if fieldName != "" {
		matched := false
		for _, key := range []string{"id", "label", "name"} {
			if text, ok := field[key].(string); ok && strings.EqualFold(strings.TrimSpace(text), fieldName) {
				matched = true
				break
			}
		}
		if !matched {
			return "", false
		}
	}
	if text, ok := field["value"].(string); ok && strings.TrimSpace(text) != "" {
		return text, true
	}
	return "", false
}

func onePasswordCLIOutcomeFromOutput(stdout, stderr []byte) string {
	for _, output := range [][]byte{stdout, stderr} {
		var payload onePasswordCLIPayload
		if len(strings.TrimSpace(string(output))) > 0 && json.Unmarshal(output, &payload) == nil {
			if outcome := normalizeOnePasswordCLIOutcome(payload.Outcome); outcome != "" {
				return outcome
			}
		}
		text := strings.ToLower(string(output))
		switch {
		case strings.Contains(text, "not signed in") || strings.Contains(text, "sign in") || strings.Contains(text, "not currently signed in"):
			return "source_auth_required"
		case strings.Contains(text, "session expired") || strings.Contains(text, "session has expired") || strings.Contains(text, "identity expired"):
			return "identity_expired"
		case strings.Contains(text, "permission denied") || strings.Contains(text, "access denied") || strings.Contains(text, "not authorized"):
			return "policy_denied"
		case strings.Contains(text, "not found") || strings.Contains(text, "does not exist") || strings.Contains(text, "field") && strings.Contains(text, "missing"):
			return "missing_ref"
		case strings.Contains(text, "invalid"):
			return "invalid_ref"
		}
	}
	return ""
}

func normalizeOnePasswordCLIOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "", "ready":
		return strings.TrimSpace(outcome)
	case "source_auth_required", "identity_expired", "policy_denied", "missing_ref", "source_unavailable", "invalid_ref":
		return strings.TrimSpace(outcome)
	default:
		return "source_unavailable"
	}
}

func onePasswordCLIOutcomeMessage(outcome string) string {
	switch outcome {
	case "source_auth_required":
		return "1Password CLI authentication is required."
	case "identity_expired":
		return "1Password CLI session expired."
	case "policy_denied":
		return "1Password CLI policy denied access."
	case "missing_ref":
		return "1Password CLI item or field was not found."
	case "invalid_ref":
		return "1Password CLI source mapping is invalid."
	default:
		return "1Password CLI source is unavailable."
	}
}

func (s sourceConfig) resolveVault(refCfg sourceRefConfig) sourceResolveResult {
	if strings.TrimSpace(s.Address) == "" || strings.TrimSpace(refCfg.Path) == "" || strings.TrimSpace(refCfg.Field) == "" {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "Vault/OpenBao source mapping requires address, path, and field."}
	}
	token := firstNonEmpty(s.Token, os.Getenv(s.TokenEnv))
	if strings.TrimSpace(token) == "" {
		return sourceResolveResult{Outcome: "source_auth_required", Message: "Vault/OpenBao token is missing."}
	}
	url := strings.TrimRight(s.Address, "/") + "/v1/" + strings.TrimLeft(refCfg.Path, "/")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "Vault/OpenBao URL is invalid."}
	}
	req.Header.Set("X-Vault-Token", token)
	client := http.Client{Timeout: time.Duration(firstPositive(refCfg.TimeoutMs, 3000)) * time.Millisecond}
	res, err := client.Do(req)
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Vault/OpenBao source is unavailable."}
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return sourceResolveResult{Outcome: "source_auth_required", Message: "Vault/OpenBao token is unauthorized or expired."}
	case http.StatusForbidden:
		return sourceResolveResult{Outcome: "policy_denied", Message: "Vault/OpenBao policy denied access."}
	case http.StatusNotFound:
		return sourceResolveResult{Outcome: "missing_ref", Message: "Vault/OpenBao path or field was not found."}
	case http.StatusBadRequest:
		return sourceResolveResult{Outcome: "invalid_ref", Message: "Vault/OpenBao source mapping is invalid."}
	case http.StatusTooManyRequests:
		return sourceResolveResult{Outcome: "degraded", Message: "Vault/OpenBao source is degraded."}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if outcome := vaultOutcomeFromBody(res.Body, refCfg); outcome != "" {
			if outcome == "locked" {
				return sourceResolveResult{Outcome: "locked", Message: "Vault/OpenBao source is sealed."}
			}
			return sourceResolveResult{Outcome: outcome, Message: vaultOutcomeMessage(outcome)}
		}
		if vaultResponseSealed(res.Body, firstPositive(refCfg.MaxStdoutBytes, 65536)) {
			return sourceResolveResult{Outcome: "locked", Message: "Vault/OpenBao source is sealed."}
		}
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Vault/OpenBao source returned a non-success status."}
	}
	limit := int64(firstPositive(refCfg.MaxStdoutBytes, firstPositive(refCfg.MaxBytes, 65536)))
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Vault/OpenBao response could not be read safely."}
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Vault/OpenBao response was not JSON."}
	}
	value, ok := vaultField(payload, refCfg.Field)
	if !ok || strings.TrimSpace(value) == "" {
		return sourceResolveResult{Outcome: "missing_ref", Message: "Vault/OpenBao field was not found."}
	}
	return sourceResolveResult{Outcome: "ready", Value: value}
}

type vaultPayload struct {
	Outcome string `json:"outcome"`
	Errors  []any  `json:"errors"`
	Sealed  bool   `json:"sealed"`
}

func vaultOutcomeFromBody(body io.Reader, refCfg sourceRefConfig) string {
	limit := int64(firstPositive(refCfg.MaxStdoutBytes, firstPositive(refCfg.MaxBytes, 65536)))
	bytes, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(bytes)) > limit || len(strings.TrimSpace(string(bytes))) == 0 {
		return ""
	}
	var payload vaultPayload
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return ""
	}
	if payload.Sealed {
		return "locked"
	}
	if outcome := normalizeVaultOutcome(payload.Outcome); outcome != "" {
		return outcome
	}
	for _, item := range payload.Errors {
		if outcome := normalizeVaultOutcome(fmt.Sprint(item)); outcome != "" {
			return outcome
		}
	}
	return ""
}

func vaultResponseSealed(body io.Reader, maxBytes int) bool {
	limit := int64(firstPositive(maxBytes, 65536))
	bytes, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(bytes)) > limit {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return false
	}
	sealed, _ := payload["sealed"].(bool)
	return sealed
}

func normalizeVaultOutcome(outcome string) string {
	cleaned := strings.ToLower(strings.TrimSpace(outcome))
	if cleaned == "" || cleaned == "ready" {
		return strings.TrimSpace(outcome)
	}
	switch {
	case strings.Contains(cleaned, "expired"), strings.Contains(cleaned, "source_auth_required"), strings.Contains(cleaned, "permission denied with invalid token"):
		return "source_auth_required"
	case strings.Contains(cleaned, "sealed"), strings.Contains(cleaned, "locked"):
		return "locked"
	case strings.Contains(cleaned, "permission denied"), strings.Contains(cleaned, "access denied"), strings.Contains(cleaned, "policy_denied"):
		return "policy_denied"
	case strings.Contains(cleaned, "not found"), strings.Contains(cleaned, "missing_ref"), strings.Contains(cleaned, "no value found"):
		return "missing_ref"
	case strings.Contains(cleaned, "rate limit"), strings.Contains(cleaned, "throttl"), strings.Contains(cleaned, "degraded"):
		return "degraded"
	case strings.Contains(cleaned, "invalid"), strings.Contains(cleaned, "invalid_ref"):
		return "invalid_ref"
	case strings.Contains(cleaned, "unavailable"), strings.Contains(cleaned, "timeout"), strings.Contains(cleaned, "connection"):
		return "source_unavailable"
	default:
		return ""
	}
}

func vaultOutcomeMessage(outcome string) string {
	switch outcome {
	case "source_auth_required":
		return "Vault/OpenBao authentication is required."
	case "locked":
		return "Vault/OpenBao source is sealed."
	case "policy_denied":
		return "Vault/OpenBao policy denied access."
	case "missing_ref":
		return "Vault/OpenBao path or field was not found."
	case "invalid_ref":
		return "Vault/OpenBao source mapping is invalid."
	case "degraded":
		return "Vault/OpenBao source is degraded."
	default:
		return "Vault/OpenBao source is unavailable."
	}
}

func vaultField(payload map[string]any, field string) (string, bool) {
	data, ok := payload["data"].(map[string]any)
	if !ok {
		return "", false
	}
	if nested, ok := data["data"].(map[string]any); ok {
		data = nested
	}
	value, ok := data[field]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func (s sourceConfig) resolveBitwardenBWS(refCfg sourceRefConfig) sourceResolveResult {
	if strings.TrimSpace(refCfg.Path) == "" {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "Bitwarden/BWS source mapping requires a secret id path."}
	}
	token := firstNonEmpty(s.Token, os.Getenv(s.TokenEnv))
	if strings.TrimSpace(token) == "" {
		return sourceResolveResult{Outcome: "source_auth_required", Message: "Bitwarden/BWS access token is missing or expired."}
	}
	if strings.TrimSpace(refCfg.Command) != "" {
		return s.resolveBitwardenBWSCLI(refCfg, token)
	}
	return s.resolveBitwardenBWSAPI(refCfg, token)
}

func (s sourceConfig) resolveAWSSecretsManager(refCfg sourceRefConfig) sourceResolveResult {
	if strings.TrimSpace(refCfg.Path) == "" {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "AWS Secrets Manager source mapping requires a secret id path."}
	}
	token := firstNonEmpty(s.Token, os.Getenv(s.TokenEnv))
	if strings.TrimSpace(token) == "" {
		return sourceResolveResult{Outcome: "source_auth_required", Message: "AWS Secrets Manager identity is missing or expired."}
	}
	endpoint, err := awsSecretsManagerEndpoint(s)
	if err != nil {
		return sourceResolveResult{Outcome: "invalid_ref", Message: err.Error()}
	}
	requestBody, err := json.Marshal(awsSecretsManagerGetSecretValueRequest{
		SecretID:     strings.TrimSpace(refCfg.Path),
		VersionID:    strings.TrimSpace(refCfg.VersionID),
		VersionStage: strings.TrimSpace(refCfg.VersionStage),
	})
	if err != nil {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "AWS Secrets Manager request could not be prepared."}
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "AWS Secrets Manager request is invalid."}
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	req.Header.Set("Authorization", "Bearer "+token)
	client := http.Client{Timeout: time.Duration(firstPositive(refCfg.TimeoutMs, 5000)) * time.Millisecond}
	res, err := client.Do(req)
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "AWS Secrets Manager source is unavailable."}
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return awsSecretsManagerStatusResult(res.StatusCode, res.Header.Get("x-amzn-ErrorType"), res.Body, refCfg)
	}
	return decodeAWSSecretsManagerValue(res.Body, refCfg)
}

type awsSecretsManagerGetSecretValueRequest struct {
	SecretID     string `json:"SecretId"`
	VersionID    string `json:"VersionId,omitempty"`
	VersionStage string `json:"VersionStage,omitempty"`
}

type awsSecretsManagerPayload struct {
	ARN          string         `json:"ARN"`
	Name         string         `json:"Name"`
	SecretString string         `json:"SecretString"`
	SecretBinary string         `json:"SecretBinary"`
	Outcome      string         `json:"outcome"`
	Type         string         `json:"__type"`
	Code         string         `json:"code"`
	Message      string         `json:"message"`
	Data         map[string]any `json:"data"`
	Secret       map[string]any `json:"secret"`
}

func awsSecretsManagerEndpoint(source sourceConfig) (string, error) {
	if address := strings.TrimSpace(source.Address); address != "" {
		return strings.TrimRight(address, "/"), nil
	}
	region := strings.TrimSpace(source.Region)
	if region == "" {
		return "", errors.New("AWS Secrets Manager source requires address or region")
	}
	return "https://secretsmanager." + region + ".amazonaws.com", nil
}

func awsSecretsManagerStatusResult(status int, errorType string, body io.Reader, refCfg sourceRefConfig) sourceResolveResult {
	if outcome := awsSecretsManagerOutcomeFromBody(errorType, body, refCfg); outcome != "" && outcome != "ready" {
		return sourceResolveResult{Outcome: outcome, Message: awsSecretsManagerOutcomeMessage(outcome)}
	}
	switch status {
	case http.StatusUnauthorized:
		return sourceResolveResult{Outcome: "source_auth_required", Message: "AWS Secrets Manager identity is missing or expired."}
	case http.StatusForbidden:
		return sourceResolveResult{Outcome: "policy_denied", Message: "AWS Secrets Manager policy denied access."}
	case http.StatusNotFound:
		return sourceResolveResult{Outcome: "missing_ref", Message: "AWS Secrets Manager secret was not found."}
	case http.StatusTooManyRequests:
		return sourceResolveResult{Outcome: "degraded", Message: "AWS Secrets Manager source is degraded."}
	default:
		return sourceResolveResult{Outcome: "source_unavailable", Message: "AWS Secrets Manager source returned a non-success status."}
	}
}

func awsSecretsManagerOutcomeFromBody(errorType string, body io.Reader, refCfg sourceRefConfig) string {
	limit := int64(firstPositive(refCfg.MaxStdoutBytes, firstPositive(refCfg.MaxBytes, 65536)))
	bytes, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(bytes)) > limit {
		return "source_unavailable"
	}
	payload := awsSecretsManagerPayload{}
	if len(strings.TrimSpace(string(bytes))) > 0 {
		_ = json.Unmarshal(bytes, &payload)
	}
	outcome := firstNonEmpty(payload.Outcome, payload.Type)
	outcome = firstNonEmpty(outcome, payload.Code)
	outcome = firstNonEmpty(outcome, errorType)
	return normalizeAWSSecretsManagerOutcome(outcome)
}

func decodeAWSSecretsManagerValue(body io.Reader, refCfg sourceRefConfig) sourceResolveResult {
	limit := int64(firstPositive(refCfg.MaxStdoutBytes, firstPositive(refCfg.MaxBytes, 65536)))
	bytes, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(bytes)) > limit {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "AWS Secrets Manager response could not be read safely."}
	}
	var payload awsSecretsManagerPayload
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "AWS Secrets Manager response was not JSON."}
	}
	if outcome := normalizeAWSSecretsManagerOutcome(payload.Outcome); outcome != "" && outcome != "ready" {
		return sourceResolveResult{Outcome: outcome, Message: awsSecretsManagerOutcomeMessage(outcome)}
	}
	value, ok := awsSecretsManagerField(payload, refCfg.Field)
	if !ok || strings.TrimSpace(value) == "" {
		return sourceResolveResult{Outcome: "missing_ref", Message: "AWS Secrets Manager secret value was not found."}
	}
	return sourceResolveResult{Outcome: "ready", Value: value}
}

func awsSecretsManagerField(payload awsSecretsManagerPayload, field string) (string, bool) {
	field = strings.TrimSpace(field)
	if field == "" {
		if strings.TrimSpace(payload.SecretString) != "" {
			return payload.SecretString, true
		}
		return "", false
	}
	var nested map[string]any
	if payload.SecretString != "" && json.Unmarshal([]byte(payload.SecretString), &nested) == nil {
		if value, ok := nested[field]; ok {
			text, ok := value.(string)
			return text, ok
		}
	}
	for _, candidate := range []map[string]any{payload.Data, payload.Secret} {
		if candidate == nil {
			continue
		}
		if value, ok := candidate[field]; ok {
			text, ok := value.(string)
			return text, ok
		}
	}
	return "", false
}

func normalizeAWSSecretsManagerOutcome(outcome string) string {
	cleaned := strings.ToLower(strings.TrimSpace(outcome))
	if cleaned == "" || cleaned == "ready" {
		return strings.TrimSpace(outcome)
	}
	switch {
	case strings.Contains(cleaned, "expiredtoken"), strings.Contains(cleaned, "expired"):
		return "identity_expired"
	case strings.Contains(cleaned, "unrecognizedclient"), strings.Contains(cleaned, "invalidclienttoken"), strings.Contains(cleaned, "missingauthentication"), strings.Contains(cleaned, "source_auth_required"):
		return "source_auth_required"
	case strings.Contains(cleaned, "accessdenied"), strings.Contains(cleaned, "notauthorized"), strings.Contains(cleaned, "policy_denied"):
		return "policy_denied"
	case strings.Contains(cleaned, "resourcenotfound"), strings.Contains(cleaned, "notfound"), strings.Contains(cleaned, "missing_ref"):
		return "missing_ref"
	case strings.Contains(cleaned, "throttl"), strings.Contains(cleaned, "limitexceeded"), strings.Contains(cleaned, "degraded"):
		return "degraded"
	case strings.Contains(cleaned, "invalidrequest"), strings.Contains(cleaned, "invalidparameter"), strings.Contains(cleaned, "invalid_ref"):
		return "invalid_ref"
	case strings.Contains(cleaned, "source_unavailable"), strings.Contains(cleaned, "internalservice"), strings.Contains(cleaned, "serviceunavailable"):
		return "source_unavailable"
	default:
		return "source_unavailable"
	}
}

func awsSecretsManagerOutcomeMessage(outcome string) string {
	switch outcome {
	case "source_auth_required":
		return "AWS Secrets Manager authentication is required."
	case "identity_expired":
		return "AWS Secrets Manager identity expired."
	case "policy_denied":
		return "AWS Secrets Manager policy denied access."
	case "missing_ref":
		return "AWS Secrets Manager secret was not found."
	case "invalid_ref":
		return "AWS Secrets Manager source mapping is invalid."
	case "degraded":
		return "AWS Secrets Manager source is degraded."
	default:
		return "AWS Secrets Manager source is unavailable."
	}
}

func (s sourceConfig) resolveBitwardenBWSAPI(refCfg sourceRefConfig, token string) sourceResolveResult {
	if strings.TrimSpace(s.Address) == "" {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "Bitwarden/BWS API source requires address or command."}
	}
	secretURL, err := url.JoinPath(strings.TrimRight(s.Address, "/"), "v1", "secrets", strings.TrimLeft(refCfg.Path, "/"))
	if err != nil {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "Bitwarden/BWS API URL is invalid."}
	}
	req, err := http.NewRequest(http.MethodGet, secretURL, nil)
	if err != nil {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "Bitwarden/BWS API request is invalid."}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := http.Client{Timeout: time.Duration(firstPositive(refCfg.TimeoutMs, 5000)) * time.Millisecond}
	res, err := client.Do(req)
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Bitwarden/BWS API is unavailable."}
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return bitwardenStatusResult(res.StatusCode, res.Body, refCfg)
	}
	return decodeBitwardenBWSValue(res.Body, refCfg, "Bitwarden/BWS API")
}

func (s sourceConfig) resolveBitwardenBWSCLI(refCfg sourceRefConfig, token string) sourceResolveResult {
	if err := validateExecConfig(s, refCfg); err != nil {
		return sourceResolveResult{Outcome: "invalid_ref", Message: err.Error()}
	}
	timeout := time.Duration(firstPositive(refCfg.TimeoutMs, 5000)) * time.Millisecond
	maxStdout := firstPositive(refCfg.MaxStdoutBytes, 65536)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, refCfg.Command, refCfg.Args...)
	cmd.Env = append(os.Environ(), "BWS_ACCESS_TOKEN="+token, "BITWARDEN_BWS_SECRET_ID="+refCfg.Path)
	stdout := newBoundedOutput(maxStdout)
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Bitwarden/BWS CLI timed out."}
	}
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Bitwarden/BWS CLI failed."}
	}
	if stdout.Exceeded() {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Bitwarden/BWS CLI output exceeded limit."}
	}
	return decodeBitwardenBWSValue(bytes.NewReader(stdout.Bytes()), refCfg, "Bitwarden/BWS CLI")
}

func bitwardenStatusResult(status int, body io.Reader, refCfg sourceRefConfig) sourceResolveResult {
	if outcome := bitwardenOutcomeFromBody(body, refCfg); outcome != "" && outcome != "ready" {
		return sourceResolveResult{Outcome: outcome, Message: bitwardenOutcomeMessage(outcome)}
	}
	switch status {
	case http.StatusUnauthorized:
		return sourceResolveResult{Outcome: "source_auth_required", Message: "Bitwarden/BWS access token is missing or expired."}
	case http.StatusForbidden:
		return sourceResolveResult{Outcome: "policy_denied", Message: "Bitwarden/BWS policy denied access."}
	case http.StatusNotFound:
		return sourceResolveResult{Outcome: "missing_ref", Message: "Bitwarden/BWS secret was not found."}
	case http.StatusTooManyRequests:
		return sourceResolveResult{Outcome: "degraded", Message: "Bitwarden/BWS source is degraded."}
	default:
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Bitwarden/BWS source returned a non-success status."}
	}
}

func bitwardenOutcomeFromBody(body io.Reader, refCfg sourceRefConfig) string {
	limit := int64(firstPositive(refCfg.MaxStdoutBytes, 65536))
	bytes, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(bytes)) > limit || len(strings.TrimSpace(string(bytes))) == 0 {
		return ""
	}
	var payload bitwardenBWSPayload
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return ""
	}
	return normalizeBitwardenOutcome(payload.Outcome)
}

func decodeBitwardenBWSValue(body io.Reader, refCfg sourceRefConfig, label string) sourceResolveResult {
	limit := int64(firstPositive(refCfg.MaxStdoutBytes, 65536))
	bytes, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(bytes)) > limit {
		return sourceResolveResult{Outcome: "source_unavailable", Message: label + " response could not be read safely."}
	}
	var payload bitwardenBWSPayload
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: label + " response was not JSON."}
	}
	if outcome := normalizeBitwardenOutcome(payload.Outcome); outcome != "" && outcome != "ready" {
		return sourceResolveResult{Outcome: outcome, Message: bitwardenOutcomeMessage(outcome)}
	}
	value, ok := bitwardenBWSField(payload, firstNonEmpty(refCfg.Field, "value"))
	if !ok || strings.TrimSpace(value) == "" {
		return sourceResolveResult{Outcome: "missing_ref", Message: label + " value field was not found."}
	}
	return sourceResolveResult{Outcome: "ready", Value: value}
}

type bitwardenBWSPayload struct {
	Value   string         `json:"value"`
	Outcome string         `json:"outcome"`
	Data    map[string]any `json:"data"`
	Secret  map[string]any `json:"secret"`
}

func bitwardenBWSField(payload bitwardenBWSPayload, field string) (string, bool) {
	field = strings.TrimSpace(field)
	if field == "" {
		field = "value"
	}
	if field == "value" && payload.Value != "" {
		return payload.Value, true
	}
	for _, candidate := range []map[string]any{payload.Data, payload.Secret} {
		if candidate == nil {
			continue
		}
		if value, ok := candidate[field]; ok {
			text, ok := value.(string)
			return text, ok
		}
	}
	return "", false
}

func normalizeBitwardenOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "", "ready":
		return strings.TrimSpace(outcome)
	case "source_auth_required", "identity_expired", "policy_denied", "missing_ref", "source_unavailable", "degraded", "invalid_ref":
		return strings.TrimSpace(outcome)
	default:
		return "source_unavailable"
	}
}

func bitwardenOutcomeMessage(outcome string) string {
	switch outcome {
	case "source_auth_required":
		return "Bitwarden/BWS authentication is required."
	case "identity_expired":
		return "Bitwarden/BWS identity expired."
	case "policy_denied":
		return "Bitwarden/BWS policy denied access."
	case "missing_ref":
		return "Bitwarden/BWS secret was not found."
	case "invalid_ref":
		return "Bitwarden/BWS source mapping is invalid."
	case "degraded":
		return "Bitwarden/BWS source is degraded."
	default:
		return "Bitwarden/BWS source is unavailable."
	}
}

func validateExecConfig(source sourceConfig, refCfg sourceRefConfig) error {
	command := strings.TrimSpace(refCfg.Command)
	if command == "" {
		return errors.New("exec source mapping is missing command")
	}
	if !filepath.IsAbs(command) && runtime.GOOS != "windows" {
		return errors.New("exec command must be absolute")
	}
	if len(source.TrustedDirs) > 0 {
		cleanCommand, err := filepath.Abs(command)
		if err != nil {
			return err
		}
		allowed := false
		for _, dir := range source.TrustedDirs {
			cleanDir, err := filepath.Abs(dir)
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(cleanDir, cleanCommand)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("exec command is outside trustedDirs")
		}
	}
	if !source.AllowSymlinkCommand {
		if info, err := os.Lstat(command); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("exec command symlink is not allowed")
		}
	}
	return nil
}

func firstPositive(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
