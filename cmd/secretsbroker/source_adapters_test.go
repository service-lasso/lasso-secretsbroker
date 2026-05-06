package main

import (
	"os"
	"path/filepath"
	"testing"
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
