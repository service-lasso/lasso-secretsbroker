package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixtureReadsStayWithinLeafDirectory(t *testing.T) {
	directory := t.TempDir()
	base := filepath.Join(directory, "certificates")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(base, "allowed.der")
	outside := filepath.Join(directory, "outside.der")
	for _, p := range []string{allowed, outside} {
		if err := os.WriteFile(p, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := fixtureBytes(root, base, allowed)
	if err != nil || string(got) != "fixture" {
		t.Fatalf("contained fixture: %v", err)
	}
	if _, err := fixtureBytes(root, base, outside); err == nil {
		t.Fatal("outside path accepted")
	}
	if err := os.Symlink(outside, filepath.Join(base, "escape.der")); err == nil {
		if _, err := fixtureBytes(root, base, filepath.Join(base, "escape.der")); err == nil {
			t.Fatal("symlink escape accepted")
		}
	}
	if err := os.WriteFile(allowed, []byte(strings.Repeat("x", 1048577)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureBytes(root, base, allowed); err == nil {
		t.Fatal("oversized fixture accepted")
	}
}
