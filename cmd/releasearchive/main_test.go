package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReleaseArchivesAreDeterministicAndNormalized(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(source, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "config", "example.env"), []byte("EXAMPLE=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "secretsbroker"), []byte("binary-fixture"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"zip", "tar.gz"} {
		t.Run(format, func(t *testing.T) {
			first := filepath.Join(t.TempDir(), "first."+format)
			second := filepath.Join(t.TempDir(), "second."+format)
			if err := writeArchive(source, first, format); err != nil {
				t.Fatal(err)
			}
			if err := writeArchive(source, second, format); err != nil {
				t.Fatal(err)
			}
			firstBytes, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			secondBytes, err := os.ReadFile(second)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(firstBytes, secondBytes) {
				t.Fatal("release archive bytes are not reproducible")
			}
			assertArchiveEntries(t, first, format, []string{"config/", "config/example.env", "secretsbroker"})
		})
	}
}

func TestReleaseArchiveRefusesSymlinkOutput(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "service.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	target := filepath.Join(destination, "target.zip")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(destination, "release.zip")
	if err := os.Symlink(target, output); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := writeArchive(source, output, "zip"); err == nil {
		t.Fatal("release archive unexpectedly followed a symlink output")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "preserve" {
		t.Fatal("release archive changed the symlink target")
	}
}

func assertArchiveEntries(t *testing.T, archivePath, format string, expected []string) {
	t.Helper()
	observed := []string{}
	if format == "zip" {
		reader, err := zip.OpenReader(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		for _, entry := range reader.File {
			observed = append(observed, entry.Name)
			if !entry.Modified.Equal(archiveTime) {
				t.Fatalf("zip entry %s has non-normalized time %s", entry.Name, entry.Modified)
			}
		}
	} else {
		file, err := os.Open(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			t.Fatal(err)
		}
		defer gzipReader.Close()
		reader := tar.NewReader(gzipReader)
		for {
			header, err := reader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			observed = append(observed, header.Name)
			if !header.ModTime.Equal(archiveTime) || header.Uid != 0 || header.Gid != 0 {
				t.Fatalf("tar entry %s metadata is not normalized", header.Name)
			}
		}
	}
	if !reflect.DeepEqual(observed, expected) {
		t.Fatalf("archive entries = %#v, want %#v", observed, expected)
	}
}
