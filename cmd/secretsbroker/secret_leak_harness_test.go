package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

type secretLeakSentinel struct {
	Label string
	Value string
}

type secretLeakFinding struct {
	Path  string
	Kind  string
	Label string
}

var serviceLassoSecretLeakSentinels = []secretLeakSentinel{
	{Label: "service-lasso-fake-token", Value: "SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE"},
	{Label: "service-lasso-fake-password", Value: "SERVICE_LASSO_FAKE_SECRET_SENTINEL_PASSWORD_DO_NOT_USE"},
	{Label: "service-lasso-fake-private-key", Value: "-----BEGIN SERVICE LASSO FAKE PRIVATE KEY-----"},
}

var secretLeakCredentialShapes = []struct {
	label   string
	pattern *regexp.Regexp
}{
	{label: "bearer-token", pattern: regexp.MustCompile(`Bearer\s+[A-Za-z0-9._~+/-]{24,}`)},
	{label: "basic-auth-url", pattern: regexp.MustCompile(`https?://[^\s/:]+:[^\s/@]{6,}@`)},
	{label: "github-token", pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{30,}`)},
	{label: "private-key-block", pattern: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

func scanForSecretMaterial(path string, surfaces map[string]string) []secretLeakFinding {
	findings := []secretLeakFinding{}
	for key, value := range surfaces {
		currentPath := path + "." + key
		for _, sentinel := range serviceLassoSecretLeakSentinels {
			if strings.Contains(value, sentinel.Value) {
				findings = append(findings, secretLeakFinding{Path: currentPath, Kind: "sentinel", Label: sentinel.Label})
			}
		}
		for _, shape := range secretLeakCredentialShapes {
			if shape.pattern.MatchString(value) {
				findings = append(findings, secretLeakFinding{Path: currentPath, Kind: "credential-shape", Label: shape.label})
			}
		}
	}
	return findings
}

func assertNoSecretMaterialSurfaces(t *testing.T, surfaces map[string]string) {
	t.Helper()
	findings := scanForSecretMaterial("$", surfaces)
	if len(findings) > 0 {
		t.Fatalf("secret material leak detected: %#v", findings)
	}
}

func TestSecretLeakHarnessDetectsSentinelsAndAllowsMetadata(t *testing.T) {
	findings := scanForSecretMaterial("$", map[string]string{
		"stdout": "resolved value " + serviceLassoSecretLeakSentinels[0].Value,
	})
	if len(findings) != 1 || findings[0].Kind != "sentinel" || findings[0].Label != "service-lasso-fake-token" {
		t.Fatalf("unexpected findings: %#v", findings)
	}

	assertNoSecretMaterialSurfaces(t, map[string]string{
		"diagnostic": "ref=api.DB_PASSWORD status=policy-denied required=true fingerprint=0123456789abcdef",
	})
}

func TestSecretLeakHarnessCoversBrokerDiagnostics(t *testing.T) {
	diagnostic := fmt.Sprintf("source=local-store ref=%s status=resolved valuePresent=true", "api.DB_PASSWORD")
	assertNoSecretMaterialSurfaces(t, map[string]string{"diagnostic": diagnostic})

	findings := scanForSecretMaterial("$", map[string]string{
		"log": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
	})
	if len(findings) != 1 || findings[0].Label != "bearer-token" {
		t.Fatalf("expected bearer token shape finding, got %#v", findings)
	}
}
