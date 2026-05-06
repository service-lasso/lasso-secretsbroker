package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
