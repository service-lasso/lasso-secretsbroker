package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	Token               string                     `json:"token"`
	TokenEnv            string                     `json:"tokenEnv"`
	Refs                map[string]sourceRefConfig `json:"refs"`
}

type sourceRefConfig struct {
	Env            string   `json:"env"`
	Path           string   `json:"path"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	TimeoutMs      int      `json:"timeoutMs"`
	MaxStdoutBytes int      `json:"maxStdoutBytes"`
	UnsafeStdout   bool     `json:"unsafeStdout"`
	Field          string   `json:"field"`
}

type sourceResolveResult struct {
	Found    bool
	Value    string
	SourceID string
	Outcome  string
	Message  string
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
		return result
	}
	return sourceResolveResult{Found: false, Outcome: "missing_ref", Message: "Secret ref was not found."}
}

func (s sourceConfig) resolve(ref string, refCfg sourceRefConfig) sourceResolveResult {
	switch strings.ToLower(strings.TrimSpace(s.Kind)) {
	case "env":
		return resolveEnv(refCfg)
	case "file":
		return resolveFile(refCfg)
	case "exec":
		return s.resolveExec(refCfg)
	case "vault", "openbao":
		return s.resolveVault(refCfg)
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

func resolveFile(refCfg sourceRefConfig) sourceResolveResult {
	if strings.TrimSpace(refCfg.Path) == "" {
		return sourceResolveResult{Outcome: "invalid_ref", Message: "File source mapping is missing path."}
	}
	bytes, err := os.ReadFile(refCfg.Path)
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Mapped file could not be read."}
	}
	value := strings.TrimSpace(string(bytes))
	if value == "" {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Mapped file is empty."}
	}
	return sourceResolveResult{Outcome: "ready", Value: value}
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
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source timed out."}
	}
	if err != nil {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source failed."}
	}
	if len(out) > maxStdout {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source stdout exceeded limit."}
	}
	value := ""
	if refCfg.UnsafeStdout {
		value = strings.TrimSpace(string(out))
	} else {
		var payload struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(out, &payload); err != nil {
			return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source did not return JSON value protocol."}
		}
		value = strings.TrimSpace(payload.Value)
	}
	if value == "" {
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Exec source returned empty value."}
	}
	return sourceResolveResult{Outcome: "ready", Value: value}
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
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if vaultResponseSealed(res.Body, firstPositive(refCfg.MaxStdoutBytes, 65536)) {
			return sourceResolveResult{Outcome: "locked", Message: "Vault/OpenBao source is sealed."}
		}
		return sourceResolveResult{Outcome: "source_unavailable", Message: "Vault/OpenBao source returned a non-success status."}
	}
	limit := int64(firstPositive(refCfg.MaxStdoutBytes, 65536))
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
