package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const checksumManifestName = "SHA256SUMS.txt"

var releaseAssetNames = []string{
	"secretsbroker-win32.zip",
	"secretsbroker-linux.tar.gz",
	"secretsbroker-darwin.tar.gz",
	"secretsbroker-win32.cdx.json",
	"secretsbroker-linux.cdx.json",
	"secretsbroker-darwin.cdx.json",
	"service.json",
}

type serviceManifest struct {
	Artifact struct {
		Platforms map[string]struct {
			Checksum struct {
				Algorithm string `json:"algorithm"`
				AssetName string `json:"assetName"`
			} `json:"checksum"`
		} `json:"platforms"`
	} `json:"artifact"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: releasechecksums <write|verify> <release-directory>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "release checksum verification failed: %v\n", err)
		os.Exit(1)
	}
}

func run(mode, releaseDir string) error {
	absDir, err := filepath.Abs(releaseDir)
	if err != nil {
		return fmt.Errorf("resolve release directory: %w", err)
	}
	info, err := os.Lstat(absDir) // #nosec G703 -- release directory is an explicit local CLI input and must be a real directory below.
	if err != nil {
		return fmt.Errorf("inspect release directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("release directory must be a real directory")
	}
	if err := validateServiceManifest(absDir); err != nil {
		return err
	}

	switch mode {
	case "write":
		return writeChecksums(absDir)
	case "verify":
		return verifyChecksums(absDir)
	default:
		return fmt.Errorf("unsupported mode %q", mode)
	}
}

func validateServiceManifest(releaseDir string) error {
	path := filepath.Join(releaseDir, "service.json")
	data, err := readRegularFile(path, 1<<20)
	if err != nil {
		return fmt.Errorf("read service manifest: %w", err)
	}
	var manifest serviceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse service manifest: %w", err)
	}
	for _, platform := range []string{"win32", "linux", "darwin"} {
		definition, ok := manifest.Artifact.Platforms[platform]
		if !ok || definition.Checksum.Algorithm != "sha256" || definition.Checksum.AssetName != checksumManifestName {
			return fmt.Errorf("service manifest platform %s must require sha256 through SHA256SUMS.txt", platform)
		}
	}
	if definition, ok := manifest.Artifact.Platforms["default"]; ok {
		if definition.Checksum.Algorithm != "sha256" || definition.Checksum.AssetName != checksumManifestName {
			return errors.New("service manifest default platform must require sha256 through SHA256SUMS.txt")
		}
	}
	return nil
}

func writeChecksums(releaseDir string) error {
	digests := make(map[string]string, len(releaseAssetNames))
	for _, name := range releaseAssetNames {
		digest, err := digestRegularFile(filepath.Join(releaseDir, name))
		if err != nil {
			return fmt.Errorf("digest %s: %w", name, err)
		}
		digests[name] = digest
	}

	names := append([]string(nil), releaseAssetNames...)
	sort.Strings(names)
	var output strings.Builder
	for _, name := range names {
		fmt.Fprintf(&output, "%s  %s\n", digests[name], name)
	}

	temp, err := os.CreateTemp(releaseDir, ".SHA256SUMS.txt.*.tmp")
	if err != nil {
		return fmt.Errorf("create checksum temporary file: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath) // #nosec G703 -- tempPath is returned by CreateTemp inside the validated release directory.
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("protect checksum temporary file: %w", err)
	}
	if _, err := io.WriteString(temp, output.String()); err != nil {
		return fmt.Errorf("write checksum temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync checksum temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close checksum temporary file: %w", err)
	}
	if err := os.Rename(tempPath, filepath.Join(releaseDir, checksumManifestName)); err != nil { // #nosec G703 -- both paths are fixed children of the validated release directory.
		return fmt.Errorf("publish checksum manifest: %w", err)
	}
	committed = true
	return verifyChecksums(releaseDir)
}

func verifyChecksums(releaseDir string) error {
	path := filepath.Join(releaseDir, checksumManifestName)
	data, err := readRegularFile(path, 1<<20)
	if err != nil {
		return fmt.Errorf("read checksum manifest: %w", err)
	}

	expected := make(map[string]struct{}, len(releaseAssetNames))
	for _, name := range releaseAssetNames {
		expected[name] = struct{}{}
	}
	observed := make(map[string]string, len(releaseAssetNames))
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || len(parts[0]) != sha256.Size*2 || strings.ToLower(parts[0]) != parts[0] {
			return fmt.Errorf("invalid checksum entry")
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return fmt.Errorf("invalid checksum digest")
		}
		name := parts[1]
		if _, ok := expected[name]; !ok || filepath.Base(name) != name {
			return fmt.Errorf("unexpected checksum entry %q", name)
		}
		if _, duplicate := observed[name]; duplicate {
			return fmt.Errorf("duplicate checksum entry %q", name)
		}
		observed[name] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read checksum manifest: %w", err)
	}
	if len(observed) != len(expected) {
		return fmt.Errorf("checksum manifest has %d entries; expected %d", len(observed), len(expected))
	}
	for _, name := range releaseAssetNames {
		digest, err := digestRegularFile(filepath.Join(releaseDir, name))
		if err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}
		if observed[name] != digest {
			return fmt.Errorf("checksum mismatch for %s", name)
		}
	}
	return nil
}

func openRegularFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path) // #nosec G703 -- path is a fixed allowlisted release asset child and is type-checked below.
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("path must be a regular file")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- Lstat rejects links and SameFile below closes the replacement race.
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return nil, errors.New("file identity changed during open")
	}
	return file, nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}

func digestRegularFile(path string) (string, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
