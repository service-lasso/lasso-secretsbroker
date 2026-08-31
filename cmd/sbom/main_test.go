package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildSBOMIsDeterministicAndPathFree(t *testing.T) {
	modules := strings.Join([]string{
		`{"Path":"github.com/service-lasso/lasso-secretsbroker","Main":true}`,
		`{"Path":"golang.org/x/sys","Version":"v0.47.0","Dir":"C:\\private\\module"}`,
		`{"Path":"filippo.io/age","Version":"v1.3.2"}`,
	}, "\n")
	first, err := buildSBOM(strings.NewReader(modules), "win32", "test-sha")
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildSBOM(strings.NewReader(modules), "win32", "test-sha")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("SBOM output is not deterministic")
	}
	if bytes.Contains(first, []byte(`C:\private`)) {
		t.Fatal("SBOM leaked a local module path")
	}
	var parsed bom
	if err := json.Unmarshal(first, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.BomFormat != "CycloneDX" || parsed.SpecVersion != "1.6" || len(parsed.Components) != 2 {
		t.Fatalf("unexpected SBOM: %#v", parsed)
	}
	if parsed.Components[0].Name != "filippo.io/age" || parsed.Components[1].Name != "golang.org/x/sys" {
		t.Fatalf("components are not sorted: %#v", parsed.Components)
	}
}

func TestBuildSBOMRejectsLocalReplacement(t *testing.T) {
	modules := strings.Join([]string{
		`{"Path":"github.com/service-lasso/lasso-secretsbroker","Main":true}`,
		`{"Path":"example.invalid/module","Version":"v1.0.0","Replace":{"Path":"../local"}}`,
	}, "\n")
	if _, err := buildSBOM(strings.NewReader(modules), "linux", "test-sha"); err == nil {
		t.Fatal("local replacement unexpectedly accepted")
	}
}
