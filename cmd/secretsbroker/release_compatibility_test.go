package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runCompatibilityBinary(t *testing.T, binary string, args ...string) []byte {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compatible release command failed: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "release-compatibility-master-key") {
		t.Fatal("compatible release command exposed key material")
	}
	return output
}

func TestBackupRestoreAcrossCompatibleReleaseBinary(t *testing.T) {
	previousBinary := strings.TrimSpace(os.Getenv("SECRETSBROKER_PREVIOUS_RELEASE_BINARY"))
	if previousBinary == "" {
		t.Skip("exact previous release binary is provided by the cross-platform validation workflow")
	}
	if !filepath.IsAbs(previousBinary) {
		t.Fatal("previous release binary path must be absolute")
	}
	info, err := os.Lstat(previousBinary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("previous release binary is not a regular file: %v", err)
	}

	root := t.TempDir()
	key := "release-compatibility-master-key"
	previousBackup := filepath.Join(root, "previous-release-backup.json")
	previousOutput := runCompatibilityBinary(
		t,
		previousBinary,
		"backup", "create",
		"--store", filepath.Join(root, "previous-release-store.json"),
		"--audit", filepath.Join(root, "previous-release-audit.jsonl"),
		"--master-key", key,
		"--out", previousBackup,
	)
	var previousCreated backupCreateResponse
	if err := json.Unmarshal(previousOutput, &previousCreated); err != nil {
		t.Fatalf("previous release backup response was not JSON: %v", err)
	}
	if previousCreated.Outcome != "ready" || previousCreated.SecretCount != 0 {
		t.Fatalf("previous release backup response = %#v", previousCreated)
	}

	current := newLocalBackend(
		filepath.Join(root, "current-restored-store.json"),
		filepath.Join(root, "current-audit.jsonl"),
		key,
	)
	restored, err := current.restoreBackup(previousBackup)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Outcome != "ready" || restored.SecretCount != 0 {
		t.Fatalf("current restore response = %#v", restored)
	}

	currentBackup := filepath.Join(root, "current-release-backup.json")
	created, err := current.createBackup(currentBackup)
	if err != nil {
		t.Fatal(err)
	}
	if created.Outcome != "ready" || created.SecretCount != 0 {
		t.Fatalf("current backup response = %#v", created)
	}
	previousRestoreOutput := runCompatibilityBinary(
		t,
		previousBinary,
		"backup", "restore",
		"--store", filepath.Join(root, "previous-release-restored-store.json"),
		"--audit", filepath.Join(root, "previous-release-restore-audit.jsonl"),
		"--master-key", key,
		"--in", currentBackup,
	)
	var previousRestored backupRestoreResponse
	if err := json.Unmarshal(previousRestoreOutput, &previousRestored); err != nil {
		t.Fatalf("previous release restore response was not JSON: %v", err)
	}
	if previousRestored.Outcome != "ready" || previousRestored.SecretCount != 0 {
		t.Fatalf("previous release restore response = %#v", previousRestored)
	}
}
