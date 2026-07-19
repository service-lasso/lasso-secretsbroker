package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type parityFixture struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Contract      string              `json:"contract"`
	ServiceID     string              `json:"serviceId"`
	APIVersion    string              `json:"apiVersion"`
	Cases         []parityFixtureCase `json:"cases"`
}

type parityFixtureCase struct {
	Name               string          `json:"name"`
	Scenario           string          `json:"scenario,omitempty"`
	Kind               string          `json:"kind"`
	Method             string          `json:"method"`
	Path               string          `json:"path"`
	RequiresAuth       *bool           `json:"requiresAuth"`
	Request            json.RawMessage `json:"request"`
	ExpectedStatus     int             `json:"expectedStatus"`
	ResponseSchema     string          `json:"responseSchema,omitempty"`
	ExpectedResponse   json.RawMessage `json:"expectedResponse"`
	RedactionForbidden []string        `json:"redactionForbidden"`
}

func TestParityFixturesArePortableAndRedacted(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "conformance", "fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected at least one parity fixture")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			bytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture parityFixture
			if err := json.Unmarshal(bytes, &fixture); err != nil {
				t.Fatalf("fixture is not valid JSON: %v", err)
			}
			if fixture.SchemaVersion != 1 {
				t.Fatalf("schemaVersion = %d", fixture.SchemaVersion)
			}
			if fixture.Contract != "secretsbroker.parity.v1" {
				t.Fatalf("contract = %q", fixture.Contract)
			}
			if fixture.ServiceID != serviceID || fixture.APIVersion != apiVersion {
				t.Fatalf("identity = %q/%q", fixture.ServiceID, fixture.APIVersion)
			}
			if len(fixture.Cases) == 0 {
				t.Fatalf("fixture has no cases")
			}
			for _, tc := range fixture.Cases {
				t.Run(tc.Name, func(t *testing.T) {
					validateParityFixtureCase(t, tc)
				})
			}
		})
	}
}

func TestBaselineHTTPParityFixtureMatchesGoImplementation(t *testing.T) {
	fixture := loadParityFixture(t, filepath.Join("..", "..", "conformance", "fixtures", "baseline-http.json"))
	backend := testBackend(t)
	_, err := backend.writeSecret(writeSecretRequest{Ref: "openclaw/openai/api_key", Value: "secret-value", Metadata: map[string]string{"sourceId": localStoreSource}})
	if err != nil {
		t.Fatal(err)
	}
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{SourceID: "disabled-source", Kind: "env", Enabled: false, Refs: map[string]sourceRefConfig{"disabled/ref": {Env: "DISABLED_SECRET"}}}}}
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "local-api-token"}))
	defer server.Close()

	client := server.Client()
	for _, tc := range fixture.Cases {
		if tc.Kind != "http" {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			method := strings.TrimSpace(tc.Method)
			var body io.Reader
			if len(tc.Request) > 0 {
				body = bytes.NewReader(tc.Request)
			}
			req, err := http.NewRequest(method, server.URL+tc.Path, body)
			if err != nil {
				t.Fatal(err)
			}
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			if tc.RequiresAuth != nil && *tc.RequiresAuth {
				req.Header.Set("Authorization", "Bearer local-api-token")
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			payload, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tc.ExpectedStatus {
				t.Fatalf("status = %d body = %s", res.StatusCode, payload)
			}
			var actual any
			if err := json.Unmarshal(payload, &actual); err != nil {
				t.Fatalf("response is not JSON: %v: %s", err, payload)
			}
			var expected any
			if err := json.Unmarshal(tc.ExpectedResponse, &expected); err != nil {
				t.Fatalf("fixture expectedResponse is not JSON: %v", err)
			}
			assertJSONSubset(t, expected, actual)
			for _, forbidden := range tc.RedactionForbidden {
				if forbidden != "" && strings.Contains(string(payload), forbidden) {
					t.Fatalf("response contains forbidden token %q: %s", forbidden, payload)
				}
			}
		})
	}
}

func loadParityFixture(t *testing.T, path string) parityFixture {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture parityFixture
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	return fixture
}

func assertJSONSubset(t *testing.T, expected, actual any) {
	t.Helper()
	if reason := jsonSubsetMismatch(expected, actual); reason != "" {
		t.Fatal(reason)
	}
}

func jsonSubsetMismatch(expected, actual any) string {
	switch want := expected.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok {
			return "expected object"
		}
		for key, expectedValue := range want {
			actualValue, ok := got[key]
			if !ok {
				return "missing key " + key
			}
			if reason := jsonSubsetMismatch(expectedValue, actualValue); reason != "" {
				return key + ": " + reason
			}
		}
		return ""
	case []any:
		got, ok := actual.([]any)
		if !ok {
			return "expected array"
		}
		if len(got) < len(want) {
			return "array too short"
		}
		for _, expectedValue := range want {
			matched := false
			for _, candidate := range got {
				if jsonSubsetMismatch(expectedValue, candidate) == "" {
					matched = true
					break
				}
			}
			if !matched {
				return "array missing expected subset"
			}
		}
		return ""
	default:
		if !reflect.DeepEqual(expected, actual) {
			return "expected value does not match"
		}
		return ""
	}
}

func validateParityFixtureCase(t *testing.T, tc parityFixtureCase) {
	t.Helper()
	if strings.TrimSpace(tc.Name) == "" {
		t.Fatalf("case name is required")
	}
	switch tc.Kind {
	case "http":
		if tc.RequiresAuth == nil {
			t.Fatalf("http case requires requiresAuth")
		}
		if strings.TrimSpace(tc.Method) == "" || !strings.HasPrefix(tc.Path, "/") {
			t.Fatalf("invalid http method/path: %q %q", tc.Method, tc.Path)
		}
	case "cli", "audit":
		// Reserved fixture kinds for future parity runners.
	default:
		t.Fatalf("unknown fixture kind %q", tc.Kind)
	}
	if tc.ExpectedStatus == 0 {
		t.Fatalf("expectedStatus is required")
	}
	if tc.Kind == "http" && strings.TrimSpace(tc.ResponseSchema) != "" {
		if _, ok := contractSchemaTypes()[tc.ResponseSchema]; !ok {
			t.Fatalf("unknown responseSchema %q", tc.ResponseSchema)
		}
	}
	if len(tc.ExpectedResponse) == 0 || !json.Valid(tc.ExpectedResponse) {
		t.Fatalf("expectedResponse must be valid JSON")
	}
	combined := string(tc.ExpectedResponse) + string(tc.Request)
	for _, forbidden := range tc.RedactionForbidden {
		forbidden = strings.TrimSpace(forbidden)
		if forbidden == "" {
			continue
		}
		if strings.Contains(string(tc.ExpectedResponse), forbidden) {
			t.Fatalf("expectedResponse contains forbidden redaction token %q", forbidden)
		}
		if strings.Contains(combined, "local-api-token") && forbidden != "local-api-token" {
			t.Fatalf("fixture should not embed local API tokens")
		}
	}
}
