//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func useReplaceImplementation(t *testing.T, implementation func(string, string) error) {
	t.Helper()
	original := replaceFileAtomicallyImpl
	replaceFileAtomicallyImpl = implementation
	t.Cleanup(func() { replaceFileAtomicallyImpl = original })
}

func TestReplaceFileAtomicallyRetriesTransientDenials(t *testing.T) {
	calls := 0
	useReplaceImplementation(t, func(source, target string) error {
		calls++
		if calls < 3 {
			return &os.LinkError{Op: "rename", Old: source, New: target, Err: windows.ERROR_ACCESS_DENIED}
		}
		return nil
	})
	if err := replaceFileAtomicallyRetrying("source", "target"); err != nil {
		t.Fatalf("retrying replace = %v", err)
	}
	if calls != 3 {
		t.Fatalf("replace calls = %d, want 3", calls)
	}
}

func TestReplaceFileAtomicallyDoesNotRetryPermanentFailures(t *testing.T) {
	calls := 0
	useReplaceImplementation(t, func(string, string) error {
		calls++
		return &os.LinkError{Op: "rename", Err: windows.ERROR_FILE_NOT_FOUND}
	})
	err := replaceFileAtomicallyRetrying("source", "target")
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("retrying replace = %v, want file-not-found", err)
	}
	if calls != 1 {
		t.Fatalf("replace calls = %d, want 1", calls)
	}
}

func TestReplaceFileAtomicallyBoundsTransientRetries(t *testing.T) {
	calls := 0
	useReplaceImplementation(t, func(string, string) error {
		calls++
		return &os.LinkError{Op: "rename", Err: windows.ERROR_SHARING_VIOLATION}
	})
	err := replaceFileAtomicallyRetrying("source", "target")
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("retrying replace = %v, want sharing violation", err)
	}
	if calls != atomicReplaceAttempts {
		t.Fatalf("replace calls = %d, want %d", calls, atomicReplaceAttempts)
	}
}

func TestWritePrivateFileAtomicallyRetriesTransientDenial(t *testing.T) {
	realReplace := replaceFileAtomically
	calls := 0
	useReplaceImplementation(t, func(source, target string) error {
		calls++
		if calls == 1 {
			return &os.LinkError{Op: "rename", Old: source, New: target, Err: windows.ERROR_ACCESS_DENIED}
		}
		return realReplace(source, target)
	})
	path := filepath.Join(t.TempDir(), "credential.json")
	if err := writePrivateFileAtomically(path, []byte("protected")); err != nil {
		t.Fatalf("atomic write = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "protected" || calls != 2 {
		t.Fatalf("content = %q, replace calls = %d", content, calls)
	}
}
