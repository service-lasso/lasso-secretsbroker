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

func TestVerifyFileDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "download.tar.gz")
	if err := os.WriteFile(path, []byte("verified download"), 0o600); err != nil {
		t.Fatal(err)
	}
	const digest = "636a193cc46913f6e164b8428da57752de7db348e95903e5f0e3c2e66a300525"
	if err := verifyFileDigest(digest, path); err != nil {
		t.Fatalf("verify exact file digest: %v", err)
	}
	if err := verifyFileDigest(strings.Repeat("0", 64), path); err == nil {
		t.Fatal("verify-file unexpectedly accepted a digest mismatch")
	}
	if err := verifyFileDigest("BFB1FF", path); err == nil {
		t.Fatal("verify-file unexpectedly accepted a malformed digest")
	}
}

func createReleaseFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	contents := map[string]string{
		"secretsbroker-win32.zip":       "windows",
		"secretsbroker-linux.tar.gz":    "linux",
		"secretsbroker-darwin.tar.gz":   "darwin",
		"secretsbroker-win32.cdx.json":  `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		"secretsbroker-linux.cdx.json":  `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		"secretsbroker-darwin.cdx.json": `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		"service.json":                  `{"artifact":{"platforms":{"win32":{"checksum":{"algorithm":"sha256","assetName":"SHA256SUMS.txt"}},"linux":{"checksum":{"algorithm":"sha256","assetName":"SHA256SUMS.txt"}},"darwin":{"checksum":{"algorithm":"sha256","assetName":"SHA256SUMS.txt"}}}}}`,
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

func TestCompatibilityInventory(t *testing.T) {
	dir := createCompatibilityFixture(t)
	if err := run("write-compat", dir); err != nil {
		t.Fatal(err)
	}
	if err := run("verify-compat", dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, checksumManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(data)), "\n")); got != 13 {
		t.Fatalf("got %d rows, want 13", got)
	}
	// Ordinary mode detects the compatibility set and cannot silently omit it.
	if err := run("verify", dir); err != nil {
		t.Fatal(err)
	}
}

func TestCompatibilityInventoryRejectsInvalidEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"missing compatibility row", func(t *testing.T, d string) {
			mutateChecksumLines(t, d, func(lines []string) []string { return lines[1:] })
		}},
		{"duplicate", func(t *testing.T, d string) {
			mutateChecksumLines(t, d, func(lines []string) []string { return append(lines, lines[0]) })
		}},
		{"unexpected row", func(t *testing.T, d string) {
			mutateChecksumLines(t, d, func(lines []string) []string { return append(lines, strings.Repeat("0", 64)+"  unexpected") })
		}},
		{"path row", func(t *testing.T, d string) {
			mutateChecksumLines(t, d, func(lines []string) []string { lines[0] = strings.Repeat("0", 64) + "  ../service.json"; return lines })
		}},
		{"unexpected file", func(t *testing.T, d string) {
			if err := os.WriteFile(filepath.Join(d, "unexpected"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, name := range compatibilityAssetNames {
		asset := name
		tests = append(tests, struct {
			name   string
			mutate func(*testing.T, string)
		}{"tampered " + asset, func(t *testing.T, d string) {
			if err := os.WriteFile(filepath.Join(d, asset), []byte("tampered"), 0600); err != nil {
				t.Fatal(err)
			}
		}})
		tests = append(tests, struct {
			name   string
			mutate func(*testing.T, string)
		}{"missing " + asset, func(t *testing.T, d string) {
			if err := os.Remove(filepath.Join(d, asset)); err != nil {
				t.Fatal(err)
			}
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := createCompatibilityFixture(t)
			if err := run("write-compat", d); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, d)
			if err := run("verify-compat", d); err == nil {
				t.Fatal("accepted invalid compatibility evidence")
			}
		})
	}
}

func TestCompatibilityInventoryCannotDowngrade(t *testing.T) {
	for _, mode := range []string{"write-compat", "verify-compat"} {
		t.Run(mode, func(t *testing.T) {
			d := createReleaseFixture(t)
			if err := run("write", d); err != nil {
				t.Fatal(err)
			}
			if err := run(mode, d); err == nil {
				t.Fatal("accepted missing entire compatibility set")
			}
		})
	}
	for _, name := range compatibilityAssetNames {
		t.Run(name, func(t *testing.T) {
			d := createReleaseFixture(t)
			if err := os.WriteFile(filepath.Join(d, name), []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run("write", d); err == nil {
				t.Fatal("accepted partial compatibility inventory")
			}
		})
	}
}

func TestCompatibilityInventoryRejectsSymlink(t *testing.T) {
	for _, name := range append(append([]string(nil), compatibilityAssetNames...), checksumManifestName) {
		t.Run(name, func(t *testing.T) {
			d := createCompatibilityFixture(t)
			if err := run("write-compat", d); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target")
			original, err := os.ReadFile(filepath.Join(d, name))
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(target, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(filepath.Join(d, name)); err != nil {
				t.Fatal(err)
			}
			if err = os.Symlink(target, filepath.Join(d, name)); err != nil {
				t.Skipf("symlink unsupported: %v", err)
			}
			for _, mode := range []string{"write-compat", "verify-compat"} {
				if err = run(mode, d); err == nil {
					t.Fatalf("%s accepted symlink", mode)
				}
			}
		})
	}
}

func createCompatibilityFixture(t *testing.T) string {
	t.Helper()
	d := createReleaseFixture(t)
	for _, name := range compatibilityAssetNames {
		if err := os.WriteFile(filepath.Join(d, name), []byte("compatibility "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestCompatibilityRejectsOldSevenRowManifest(t *testing.T) {
	d := createReleaseFixture(t)
	if err := run("write", d); err != nil {
		t.Fatal(err)
	}
	for _, name := range compatibilityAssetNames {
		if err := os.WriteFile(filepath.Join(d, name), []byte("compatibility "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"verify", "verify-compat"} {
		if err := run(mode, d); err == nil {
			t.Fatalf("%s accepted defective seven-row manifest beside thirteen payloads", mode)
		}
	}
}
