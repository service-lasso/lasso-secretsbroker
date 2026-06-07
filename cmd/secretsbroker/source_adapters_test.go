package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnvSourceAdapter(t *testing.T) {
	t.Setenv("TEST_SECRET", "env-secret")
	cfg := sourceConfigFile{Sources: []sourceConfig{{SourceID: "env-local", Kind: "env", Enabled: true, Refs: map[string]sourceRefConfig{"openclaw/env": {Env: "TEST_SECRET"}}}}}
	res := cfg.resolve("openclaw/env")
	if res.Outcome != "ready" || res.Value != "env-secret" || res.SourceID != "env-local" {
		t.Fatalf("env result = %#v", res)
	}
}

func TestFileSourceAdapter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := sourceConfigFile{Sources: []sourceConfig{{SourceID: "file-local", Kind: "file", Enabled: true, Refs: map[string]sourceRefConfig{"openclaw/file": {Path: path}}}}}
	res := cfg.resolve("openclaw/file")
	if res.Outcome != "ready" || res.Value != "file-secret" {
		t.Fatalf("file result = %#v", res)
	}
}

func TestSourcePriorityAndMissing(t *testing.T) {
	t.Setenv("LOW", "low")
	t.Setenv("HIGH", "high")
	cfg := sourceConfigFile{Sources: []sourceConfig{
		{SourceID: "low", Kind: "env", Enabled: true, Priority: 20, Refs: map[string]sourceRefConfig{"ref": {Env: "LOW"}}},
		{SourceID: "high", Kind: "env", Enabled: true, Priority: 10, Refs: map[string]sourceRefConfig{"ref": {Env: "HIGH"}}},
	}}
	res := cfg.resolve("ref")
	if res.SourceID != "high" || res.Value != "high" {
		t.Fatalf("priority result = %#v", res)
	}
	missing := cfg.resolve("missing")
	if missing.Outcome != "missing_ref" {
		t.Fatalf("missing result = %#v", missing)
	}
}

func TestExecSourceRejectsUntrustedCommand(t *testing.T) {
	cfg := sourceConfig{SourceID: "exec", Kind: "exec", Enabled: true, TrustedDirs: []string{filepath.Join(t.TempDir(), "trusted")}}
	res := cfg.resolve("ref", sourceRefConfig{Command: filepath.Join(t.TempDir(), "tool"), UnsafeStdout: true})
	if res.Outcome != "invalid_ref" {
		t.Fatalf("exec result = %#v", res)
	}
}

func TestExecSourceAdapterJSONProtocolSuccess(t *testing.T) {
	cfg, refCfg := execSourceFixture(t, "success-json")
	res := cfg.resolve("ref", refCfg)
	if res.Outcome != "ready" || res.Value != "exec-secret" {
		t.Fatalf("exec result = %#v", res)
	}
}

func TestExecSourceAdapterNormalizesProtocolOutcomes(t *testing.T) {
	cases := []struct {
		name        string
		mode        string
		wantOutcome string
	}{
		{name: "auth required", mode: "auth-required", wantOutcome: "source_auth_required"},
		{name: "missing ref", mode: "missing-ref", wantOutcome: "missing_ref"},
		{name: "policy denied", mode: "policy-denied", wantOutcome: "policy_denied"},
		{name: "invalid mapping", mode: "invalid-ref", wantOutcome: "invalid_ref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, refCfg := execSourceFixture(t, tc.mode)
			res := cfg.resolve("ref", refCfg)
			if res.Outcome != tc.wantOutcome || res.Value != "" {
				t.Fatalf("exec result = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
		})
	}
}

func TestExecSourceAdapterRejectsInvalidProtocolWithoutLeakingOutput(t *testing.T) {
	cfg, refCfg := execSourceFixture(t, "invalid-json")
	res := cfg.resolve("ref", refCfg)
	if res.Outcome != "source_unavailable" || res.Value != "" {
		t.Fatalf("exec result = %#v", res)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
}

func TestExecSourceAdapterBoundsStdoutWithoutLeakingOutput(t *testing.T) {
	cfg, refCfg := execSourceFixture(t, "oversized")
	refCfg.MaxStdoutBytes = 16
	res := cfg.resolve("ref", refCfg)
	if res.Outcome != "source_unavailable" || res.Value != "" {
		t.Fatalf("exec result = %#v", res)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
}

func TestExecSourceAdapterHandlesFailureAndTimeoutWithoutLeakingOutput(t *testing.T) {
	cases := []struct {
		name string
		mode string
	}{
		{name: "command failure", mode: "failure"},
		{name: "timeout", mode: "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, refCfg := execSourceFixture(t, tc.mode)
			refCfg.TimeoutMs = 50
			res := cfg.resolve("ref", refCfg)
			if res.Outcome != "source_unavailable" || res.Value != "" {
				t.Fatalf("exec result = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
		})
	}
}

func TestExecSourceStatusReportsContractCapabilities(t *testing.T) {
	caps := capabilitiesForSourceKind("exec")
	for _, capability := range []string{"read", "reveal", "audit", "migration", "health"} {
		assertContains(t, caps, capability)
	}
}

func execSourceFixture(t *testing.T, mode string) (sourceConfig, sourceRefConfig) {
	t.Helper()
	command, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	source := sourceConfig{
		SourceID:            "exec-local",
		Kind:                "exec",
		Enabled:             true,
		TrustedDirs:         []string{filepath.Dir(command)},
		AllowSymlinkCommand: true,
	}
	refCfg := sourceRefConfig{
		Command:        command,
		Args:           []string{"-test.run=TestExecSourceHelperProcess", "--", mode},
		TimeoutMs:      2000,
		MaxStdoutBytes: 4096,
	}
	return source, refCfg
}

func TestExecSourceHelperProcess(t *testing.T) {
	args := os.Args
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator == -1 || separator+1 >= len(args) {
		return
	}
	switch args[separator+1] {
	case "success-json":
		os.Stdout.WriteString(`{"value":"exec-secret"}`)
	case "auth-required":
		os.Stdout.WriteString(`{"outcome":"source_auth_required","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"}`)
	case "missing-ref":
		os.Stdout.WriteString(`{"outcome":"missing_ref","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE"}`)
	case "policy-denied":
		os.Stdout.WriteString(`{"outcome":"policy_denied","message":"-----BEGIN SERVICE LASSO FAKE PRIVATE KEY-----"}`)
	case "invalid-ref":
		os.Stdout.WriteString(`{"outcome":"invalid_ref","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"}`)
	case "invalid-json":
		os.Stdout.WriteString(`not-json SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE`)
	case "oversized":
		os.Stdout.WriteString(strings.Repeat("A", 64) + "SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE")
	case "failure":
		os.Stdout.WriteString(`SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE`)
		os.Stderr.WriteString(`SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE`)
		os.Exit(2)
	case "timeout":
		time.Sleep(2 * time.Second)
	}
	os.Exit(0)
}
