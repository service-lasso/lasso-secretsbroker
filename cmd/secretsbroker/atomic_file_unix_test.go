//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateFileAtomicallyUsesOwnerOnlyHandles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(directory, "credential.json")
	if err := writePrivateFileAtomically(path, []byte("protected")); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private modes = directory %o file %o", directoryInfo.Mode().Perm(), fileInfo.Mode().Perm())
	}
}

func TestWritePrivateFileAtomicallyRejectsSymlinkIndirection(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := writePrivateFileAtomically(filepath.Join(linkedDirectory, "credential.json"), []byte("blocked")); err == nil {
		t.Fatal("private write unexpectedly followed a symlinked parent")
	}

	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedTarget := filepath.Join(realDirectory, "credential.json")
	if err := os.Symlink(target, linkedTarget); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := writePrivateFileAtomically(linkedTarget, []byte("blocked")); err == nil {
		t.Fatal("private write unexpectedly replaced a symlink target")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "preserve" {
		t.Fatal("private write changed a symlink target")
	}
}

func TestCanonicalUnixSecurityPathRejectsUntrustedAliases(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	canonical, err := canonicalUnixSecurityPath(filepath.Join(alias, "credential.json"))
	if err != nil {
		t.Fatal(err)
	}
	if canonical == "" || !pathHasSymlinkOrReparseComponent(canonical) {
		t.Fatal("untrusted alias was not rejected")
	}
}
