//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsPathGuardNativeTypesAndInvalidInputs(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "regular-file")
	if err := os.WriteFile(file, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		name, path string
		directory  bool
		want       error
	}{
		{"file", file, false, nil},
		{"directory", directory, true, nil},
		{"file-as-directory", file, true, errWrapperAccess},
		{"directory-as-file", directory, false, errWrapperAccess},
		{"missing", filepath.Join(directory, "missing"), false, os.ErrNotExist},
	} {
		t.Run(target.name, func(t *testing.T) {
			err := rejectWindowsReparsePoint(target.path, target.directory)
			if !errors.Is(err, target.want) {
				t.Fatalf("native path guard error = %v, want %v", err, target.want)
			}
		})
	}
	if err := rejectWindowsReparsePoint(file+"\x00suffix", false); err == nil {
		t.Fatal("NUL path accepted")
	}
}

func TestWindowsPathGuardRejectsDirectAndAncestorLinks(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "regular-file")
	if err := os.WriteFile(file, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		name, path string
		directory  bool
	}{
		{"file-link", file, false},
		{"directory-link", directory, true},
	} {
		t.Run(target.name, func(t *testing.T) {
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(target.path, link); err != nil {
				t.Skipf("Windows symlink creation unavailable: %v", err)
			}
			if err := rejectWindowsReparsePoint(link, target.directory); !errors.Is(err, errWrapperAccess) {
				t.Fatalf("direct link error = %v", err)
			}
			if target.directory {
				if err := rejectWindowsReparsePoint(filepath.Join(link, "regular-file"), false); !errors.Is(err, errWrapperAccess) {
					t.Fatalf("ancestor link error = %v", err)
				}
			}
		})
	}
}
