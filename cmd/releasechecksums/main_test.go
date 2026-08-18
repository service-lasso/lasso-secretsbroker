package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseChecksumsWriteAndVerify(t *testing.T) {
	dir := createReleaseFixture(t)
	if err := run("write", dir); err != nil {
		t.Fatalf("write checksums: %v", err)
	}
	if err := run("verify", dir); err != nil {
		t.Fatalf("verify checksums: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, checksumManifestName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(releaseAssetNames) {
		t.Fatalf("got %d checksum lines, want %d", len(lines), len(releaseAssetNames))
	}
}

func TestReleaseChecksumsRejectInvalidEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, dir string)
	}{
		{
			name: "tampered archive",
			mutate: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, "secretsbroker-linux.tar.gz"), []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing entry",
			mutate: func(t *testing.T, dir string) {
				t.Helper()
				mutateChecksumLines(t, dir, func(lines []string) []string { return lines[1:] })
			},
		},
		{
			name: "duplicate entry",
			mutate: func(t *testing.T, dir string) {
				t.Helper()
				mutateChecksumLines(t, dir, func(lines []string) []string { return append(lines, lines[0]) })
			},
		},
		{
			name: "extra entry",
			mutate: func(t *testing.T, dir string) {
				t.Helper()
				mutateChecksumLines(t, dir, func(lines []string) []string {
					return append(lines, strings.Repeat("0", 64)+"  unexpected.zip")
				})
			},
		},
		{
			name: "malformed digest",
			mutate: func(t *testing.T, dir string) {
				t.Helper()
				mutateChecksumLines(t, dir, func(lines []string) []string {
					parts := strings.Split(lines[0], "  ")
					lines[0] = strings.Repeat("g", 64) + "  " + parts[1]
					return lines
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := createReleaseFixture(t)
			if err := run("write", dir); err != nil {
				t.Fatalf("write checksums: %v", err)
			}
			test.mutate(t, dir)
			if err := run("verify", dir); err == nil {
				t.Fatal("verification unexpectedly succeeded")
			}
		})
	}
}

func TestReleaseChecksumsRequireManifestContract(t *testing.T) {
	dir := createReleaseFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(`{"artifact":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("write", dir); err == nil {
		t.Fatal("write unexpectedly accepted a manifest without checksum policy")
	}
}

func createReleaseFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	contents := map[string]string{
		"secretsbroker-win32.zip":     "windows",
		"secretsbroker-linux.tar.gz":  "linux",
		"secretsbroker-darwin.tar.gz": "darwin",
		"service.json":                `{"artifact":{"platforms":{"win32":{"checksum":{"algorithm":"sha256","assetName":"SHA256SUMS.txt"}},"linux":{"checksum":{"algorithm":"sha256","assetName":"SHA256SUMS.txt"}},"darwin":{"checksum":{"algorithm":"sha256","assetName":"SHA256SUMS.txt"}}}}}`,
	}
	for name, content := range contents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mutateChecksumLines(t *testing.T, dir string, mutate func([]string) []string) {
	t.Helper()
	path := filepath.Join(dir, checksumManifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lines = mutate(lines)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
