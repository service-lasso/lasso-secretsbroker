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

func TestEnvSourceAdapterNormalizesFailureStatesWithoutLeakingValues(t *testing.T) {
	t.Setenv("ENV_SOURCE_FAKE_SECRET", "SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE")
	t.Setenv("ENV_SOURCE_EMPTY_SECRET", "")
	cfg := sourceConfigFile{Sources: []sourceConfig{{SourceID: "env-local", Kind: "env", Enabled: true, Refs: map[string]sourceRefConfig{
		"openclaw/empty":   {Env: "ENV_SOURCE_EMPTY_SECRET"},
		"openclaw/invalid": {Env: " "},
		"openclaw/ready":   {Env: "ENV_SOURCE_FAKE_SECRET"},
		"openclaw/unset":   {Env: "ENV_SOURCE_UNSET_SECRET"},
	}}}}

	tests := []struct {
		ref         string
		wantOutcome string
		wantState   string
	}{
		{ref: "openclaw/empty", wantOutcome: "source_unavailable", wantState: "degraded"},
		{ref: "openclaw/invalid", wantOutcome: "invalid_ref", wantState: "config_error"},
		{ref: "openclaw/unset", wantOutcome: "source_unavailable", wantState: "degraded"},
		{ref: "openclaw/missing", wantOutcome: "missing_ref", wantState: "missing"},
	}
	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			res := cfg.resolve(tc.ref)
			if res.Outcome != tc.wantOutcome || res.Lifecycle.State != tc.wantState || res.Value != "" {
				t.Fatalf("env result = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{
				"message":    res.Message,
				"sourceID":   res.SourceID,
				"outcome":    res.Outcome,
				"state":      res.Lifecycle.State,
				"nextAction": res.Lifecycle.NextAction,
			})
		})
	}

	ready := cfg.resolve("openclaw/ready")
	if ready.Outcome != "ready" || ready.Value == "" {
		t.Fatalf("ready env result = %#v", ready)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": ready.Message})
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

func TestFileSourceAdapterNormalizesFailuresWithoutLeakingContents(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret.txt")
	oversizedPath := filepath.Join(dir, "oversized.txt")
	emptyPath := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(secretPath, []byte("SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oversizedPath, []byte("0123456789SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(emptyPath, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := sourceConfigFile{Sources: []sourceConfig{{
		SourceID:    "file-local",
		Kind:        "file",
		Enabled:     true,
		TrustedDirs: []string{dir},
		Refs: map[string]sourceRefConfig{
			"openclaw/empty":      {Path: emptyPath},
			"openclaw/invalid":    {Path: " "},
			"openclaw/missing":    {Path: filepath.Join(dir, "missing.txt")},
			"openclaw/oversized":  {Path: oversizedPath, MaxBytes: 8},
			"openclaw/ready":      {Path: secretPath},
			"openclaw/unreadable": {Path: dir},
			"openclaw/untrusted":  {Path: filepath.Join(t.TempDir(), "outside.txt")},
		},
	}}}

	tests := []struct {
		ref         string
		wantOutcome string
		wantState   string
	}{
		{ref: "openclaw/empty", wantOutcome: "source_unavailable", wantState: "degraded"},
		{ref: "openclaw/invalid", wantOutcome: "invalid_ref", wantState: "config_error"},
		{ref: "openclaw/missing", wantOutcome: "source_unavailable", wantState: "degraded"},
		{ref: "openclaw/oversized", wantOutcome: "source_unavailable", wantState: "degraded"},
		{ref: "openclaw/unreadable", wantOutcome: "source_unavailable", wantState: "degraded"},
		{ref: "openclaw/untrusted", wantOutcome: "policy_denied", wantState: "denied"},
	}
	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			res := cfg.resolve(tc.ref)
			if res.Outcome != tc.wantOutcome || res.Lifecycle.State != tc.wantState || res.Value != "" {
				t.Fatalf("file result = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{
				"message":    res.Message,
				"sourceID":   res.SourceID,
				"outcome":    res.Outcome,
				"state":      res.Lifecycle.State,
				"nextAction": res.Lifecycle.NextAction,
			})
		})
	}

	ready := cfg.resolve("openclaw/ready")
	if ready.Outcome != "ready" || ready.Value == "" {
		t.Fatalf("ready file result = %#v", ready)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": ready.Message})
}

func TestFileSourceStatusReportsContractCapabilities(t *testing.T) {
	caps := capabilitiesForSourceKind("file")
	for _, capability := range []string{"read", "reveal", "migration", "health"} {
		assertContains(t, caps, capability)
	}
	for _, capability := range []string{"write/update", "rotate/reset", "policy", "value-search", "audit"} {
		assertNotContains(t, caps, capability)
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

func TestOnePasswordCLIAdapterJSONProtocolSuccess(t *testing.T) {
	cfg, refCfg := onePasswordCLIFixture(t, "success-json")
	res := cfg.resolve("openclaw/op", refCfg)
	if res.Outcome != "ready" || res.Value != "op-secret" {
		t.Fatalf("1Password CLI result = %#v", res)
	}
}

func TestOnePasswordCLIAdapterDefaultArgsUseDocumentedCLIForms(t *testing.T) {
	cases := []struct {
		name string
		ref  sourceRefConfig
		want []string
	}{
		{
			name: "secret reference",
			ref:  sourceRefConfig{Path: "op://local/api/password", Field: "password"},
			want: []string{"read", "op://local/api/password"},
		},
		{
			name: "item metadata json",
			ref:  sourceRefConfig{Path: "api-item"},
			want: []string{"item", "get", "api-item", "--format", "json"},
		},
		{
			name: "item field json",
			ref:  sourceRefConfig{Path: "api-item", Field: "password"},
			want: []string{"item", "get", "api-item", "--fields", "label=password", "--format", "json"},
		},
		{
			name: "custom args override defaults",
			ref:  sourceRefConfig{Path: "api-item", Field: "password", Args: []string{"read", "op://custom/ref"}},
			want: []string{"read", "op://custom/ref"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := onePasswordCLIArgs(tc.ref)
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("args = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestOnePasswordCLIAdapterNormalizesFailuresWithoutLeakingOutput(t *testing.T) {
	cases := []struct {
		name        string
		mode        string
		wantOutcome string
	}{
		{name: "not signed in", mode: "auth-required", wantOutcome: "source_auth_required"},
		{name: "expired session", mode: "identity-expired", wantOutcome: "identity_expired"},
		{name: "policy denied", mode: "policy-denied", wantOutcome: "policy_denied"},
		{name: "missing item", mode: "missing-item", wantOutcome: "missing_ref"},
		{name: "missing field", mode: "missing-field", wantOutcome: "missing_ref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, refCfg := onePasswordCLIFixture(t, tc.mode)
			res := cfg.resolve("openclaw/op", refCfg)
			if res.Outcome != tc.wantOutcome || res.Value != "" {
				t.Fatalf("1Password CLI result = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message, "outcome": res.Outcome})
		})
	}
}

func TestOnePasswordCLIAdapterHandlesUnavailableTimeoutAndOutputLimit(t *testing.T) {
	t.Run("unavailable cli", func(t *testing.T) {
		trusted := t.TempDir()
		source := sourceConfig{SourceID: "op-local", Kind: "onepassword-cli", Enabled: true, TrustedDirs: []string{trusted}}
		res := source.resolve("openclaw/op", sourceRefConfig{Command: filepath.Join(trusted, "missing-op"), Path: "op://local/api/password"})
		if res.Outcome != "source_unavailable" || res.Value != "" {
			t.Fatalf("1Password CLI unavailable result = %#v", res)
		}
		assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
	})

	t.Run("timeout", func(t *testing.T) {
		cfg, refCfg := onePasswordCLIFixture(t, "timeout")
		refCfg.TimeoutMs = 50
		res := cfg.resolve("openclaw/op", refCfg)
		if res.Outcome != "source_unavailable" || res.Value != "" {
			t.Fatalf("1Password CLI timeout result = %#v", res)
		}
		assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
	})

	t.Run("output limit", func(t *testing.T) {
		cfg, refCfg := onePasswordCLIFixture(t, "oversized")
		refCfg.MaxStdoutBytes = 16
		res := cfg.resolve("openclaw/op", refCfg)
		if res.Outcome != "source_unavailable" || res.Value != "" {
			t.Fatalf("1Password CLI oversized result = %#v", res)
		}
		assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
	})
}

func TestOnePasswordCLIAdapterRejectsInvalidMappingAndUntrustedCommand(t *testing.T) {
	cfg, refCfg := onePasswordCLIFixture(t, "success-json")
	refCfg.Path = " "
	res := cfg.resolve("openclaw/op", refCfg)
	if res.Outcome != "invalid_ref" {
		t.Fatalf("missing path result = %#v", res)
	}

	cfg, refCfg = onePasswordCLIFixture(t, "success-json")
	cfg.TrustedDirs = []string{filepath.Join(t.TempDir(), "trusted")}
	res = cfg.resolve("openclaw/op", refCfg)
	if res.Outcome != "policy_denied" {
		t.Fatalf("untrusted command result = %#v", res)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
}

func TestOnePasswordCLIStatusReportsContractCapabilities(t *testing.T) {
	caps := capabilitiesForSourceKind("onepassword-cli")
	for _, capability := range []string{"read", "reveal", "audit", "migration", "health"} {
		assertContains(t, caps, capability)
	}
	for _, capability := range []string{"write/update", "rotate/reset", "policy", "value-search"} {
		assertNotContains(t, caps, capability)
	}
}

func TestEnvSourceStatusReportsContractCapabilities(t *testing.T) {
	caps := capabilitiesForSourceKind("env")
	for _, capability := range []string{"read", "reveal", "migration", "health"} {
		assertContains(t, caps, capability)
	}
	for _, capability := range []string{"write/update", "rotate/reset", "policy", "value-search", "audit"} {
		assertNotContains(t, caps, capability)
	}
}

func assertNotContains(t *testing.T, values []string, forbidden string) {
	t.Helper()
	for _, value := range values {
		if value == forbidden {
			t.Fatalf("values should not contain %q: %#v", forbidden, values)
		}
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

func onePasswordCLIFixture(t *testing.T, mode string) (sourceConfig, sourceRefConfig) {
	t.Helper()
	command, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	source := sourceConfig{
		SourceID:            "op-local",
		Kind:                "onepassword-cli",
		Enabled:             true,
		TrustedDirs:         []string{filepath.Dir(command)},
		AllowSymlinkCommand: true,
	}
	refCfg := sourceRefConfig{
		Command:        command,
		Args:           []string{"-test.run=TestOnePasswordCLIHelperProcess", "--", mode},
		Path:           "op://local/api/password",
		Field:          "password",
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

func TestOnePasswordCLIHelperProcess(t *testing.T) {
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
		os.Stdout.WriteString(`{"value":"op-secret"}`)
	case "auth-required":
		os.Stderr.WriteString(`not signed in SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE`)
		os.Exit(2)
	case "identity-expired":
		os.Stdout.WriteString(`{"outcome":"identity_expired","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"}`)
		os.Exit(2)
	case "policy-denied":
		os.Stderr.WriteString(`permission denied SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE`)
		os.Exit(2)
	case "missing-item":
		os.Stdout.WriteString(`{"outcome":"missing_ref","message":"SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE"}`)
		os.Exit(2)
	case "missing-field":
		os.Stderr.WriteString(`field missing SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE`)
		os.Exit(2)
	case "oversized":
		os.Stdout.WriteString(strings.Repeat("A", 64) + "SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE")
	case "timeout":
		time.Sleep(2 * time.Second)
	}
	os.Exit(0)
}
