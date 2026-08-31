package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type goModule struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version"`
	Main    bool      `json:"Main"`
	Replace *goModule `json:"Replace"`
}

type component struct {
	Type    string `json:"type"`
	BomRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type bom struct {
	BomFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     bomMetadata `json:"metadata"`
	Components   []component `json:"components"`
}

type bomMetadata struct {
	Component  component     `json:"component"`
	Properties []bomProperty `json:"properties"`
}

type bomProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func main() {
	output := flag.String("output", "", "CycloneDX JSON output path")
	platform := flag.String("platform", "", "release platform")
	version := flag.String("version", firstNonEmpty(os.Getenv("SERVICE_LASSO_RELEASE_VERSION"), os.Getenv("GITHUB_SHA"), "development"), "release version or commit")
	flag.Parse()
	if *output == "" || *platform == "" {
		fmt.Fprintln(os.Stderr, "usage: sbom --output <path> --platform <platform> [--version <version>]")
		os.Exit(2)
	}

	command := exec.Command("go", "list", "-m", "-json", "all")
	stdout, err := command.StdoutPipe()
	if err != nil {
		fail(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		fail(err)
	}
	document, err := buildSBOM(stdout, *platform, *version)
	waitErr := command.Wait()
	if err != nil {
		fail(err)
	}
	if waitErr != nil {
		fail(waitErr)
	}
	if err := writeAtomic(*output, document); err != nil {
		fail(err)
	}
}

func buildSBOM(input io.Reader, platform, version string) ([]byte, error) {
	if strings.TrimSpace(platform) == "" || strings.TrimSpace(version) == "" {
		return nil, errors.New("platform and version are required")
	}
	decoder := json.NewDecoder(input)
	var mainModule goModule
	components := make([]component, 0)
	for {
		var module goModule
		if err := decoder.Decode(&module); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go module: %w", err)
		}
		if module.Main {
			mainModule = module
			continue
		}
		effective := module
		if module.Replace != nil {
			effective = *module.Replace
			if effective.Version == "" {
				return nil, fmt.Errorf("local replacement for %s cannot be represented without leaking a path", module.Path)
			}
		}
		if effective.Path == "" || effective.Version == "" {
			return nil, fmt.Errorf("module %s has no immutable version", module.Path)
		}
		ref := "pkg:golang/" + effective.Path + "@" + effective.Version
		components = append(components, component{Type: "library", BomRef: ref, Name: effective.Path, Version: effective.Version, PURL: ref})
	}
	if mainModule.Path == "" {
		return nil, errors.New("main module is missing")
	}
	sort.Slice(components, func(i, j int) bool { return components[i].BomRef < components[j].BomRef })
	mainRef := "pkg:golang/" + mainModule.Path + "@" + version
	identity := mainRef + "\n" + platform
	for _, item := range components {
		identity += "\n" + item.BomRef
	}
	digest := sha256.Sum256([]byte(identity))
	digest[6] = (digest[6] & 0x0f) | 0x50
	digest[8] = (digest[8] & 0x3f) | 0x80
	uuid := fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(digest[0:4]), hex.EncodeToString(digest[4:6]), hex.EncodeToString(digest[6:8]), hex.EncodeToString(digest[8:10]), hex.EncodeToString(digest[10:16]))
	document := bom{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuid,
		Version:      1,
		Metadata: bomMetadata{
			Component:  component{Type: "application", BomRef: mainRef, Name: mainModule.Path, Version: version, PURL: mainRef},
			Properties: []bomProperty{{Name: "service-lasso:platform", Value: platform}},
		},
		Components: components,
	}
	return json.MarshalIndent(document, "", "  ")
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, ".sbom-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
