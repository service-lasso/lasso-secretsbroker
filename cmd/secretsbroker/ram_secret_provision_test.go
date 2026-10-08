package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRAMLegacyRenderedCredentialStaysLiteral(t *testing.T) {
	files := []ramFileInput{{Path: "password", Content: "synthetic-${literal.VALUE}"}}
	outputs, err := (&localBackend{}).renderRAMSecretFiles(files, nil, resolveRequest{})
	if err != nil || len(outputs) != 1 || outputs[0].Content != files[0].Content {
		t.Fatal("legacy already-rendered bytes changed")
	}
	if _, err := (&localBackend{}).renderRAMSecretFiles(files, []ramSecretBinding{}, resolveRequest{}); err == nil {
		t.Fatal("explicit provisioning without a binding accepted an unresolved reference")
	}
}

func TestRAMBrokerResolvesVaultAndReturnsOnlyPath(t *testing.T) {
	b, _ := ramFixture(t)
	const ref = "services/app/app.KEY"
	const value = "synthetic-value-${nested.SECRET}"
	if _, err := b.writeSecret(writeSecretRequest{Ref: ref, Value: value}); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(runtimeState{}, b, localAPISecurity{token: "test-token"})
	sequence := 0
	provision := func(files []ramFileInput, bindings []ramSecretBinding) *httptest.ResponseRecorder {
		sequence++
		lease := testLaunchIdentityLease(t, b, "app", []string{"services/app/*"}, nil, []string{"resolve"}, fmt.Sprintf("provision-%d", sequence))
		req := ramGrantRequest{ServiceID: "app", IdentityLease: &lease, InstanceID: strings.Repeat("c", 64), Files: files, Bindings: bindings}
		body, _ := json.Marshal(req)
		r := httptest.NewRequest("POST", "/v1/file-grants", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	files := []ramFileInput{{Path: "credential", Content: "${app.KEY}"}}
	bindings := []ramSecretBinding{{Selector: "app.KEY", Ref: ref, Required: true}}
	res := provision(files, bindings)
	if res.Code != 201 {
		t.Fatalf("provision status %d", res.Code)
	}
	if strings.Contains(res.Body.String(), value) {
		t.Fatal("value returned to caller")
	}
	var grant ramGrantResponse
	if err := json.Unmarshal(res.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.Directory != grant.BaseURL+"/"+grant.Token {
		t.Fatal("missing returned directory")
	}
	code, content := davRequest(t, "GET", grant.Directory+"/credential", "", nil)
	if code != 200 || content != value {
		t.Fatal("returned path did not serve original vault bytes")
	}
	for _, tc := range []struct {
		name     string
		files    []ramFileInput
		bindings []ramSecretBinding
		status   int
	}{
		{"foreign-ref", files, []ramSecretBinding{{"app.KEY", "services/other/app.KEY", true}}, 403},
		{"missing-required", files, []ramSecretBinding{{"app.KEY", "services/app/app.MISSING", true}}, 400},
		{"missing-used-optional", files, []ramSecretBinding{{"app.KEY", "services/app/app.MISSING", false}}, 400},
		{"unbound-selector", []ramFileInput{{"credential", "${app.OTHER}"}}, bindings, 400},
		{"malformed-selector", []ramFileInput{{"credential", "${app.KEY}${"}}, bindings, 400},
		{"duplicate-binding", files, append(append([]ramSecretBinding{}, bindings...), bindings[0]), 400},
		{"unsafe-path", []ramFileInput{{"../credential", "${app.KEY}"}}, bindings, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := provision(tc.files, tc.bindings).Code; got != tc.status {
				t.Fatalf("status %d want %d", got, tc.status)
			}
			if code, _ := davRequest(t, "GET", grant.Directory+"/credential", "", nil); code != 200 {
				t.Fatal("failed request replaced valid grant")
			}
		})
	}
	for _, p := range []string{b.storePath, b.auditPath, b.eventPath} {
		data, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(value)) || bytes.Contains(data, []byte(grant.Token)) {
			t.Fatal("private bytes persisted")
		}
	}
}

func TestRAMTemplateBoundsBeforeExpansion(t *testing.T) {
	value := strings.Repeat("x", maxRAMFileBytes)
	if _, err := renderRAMTemplate("${app.KEY}${app.KEY}", map[string]string{"app.KEY": value}); err == nil {
		t.Fatal("expanded file bound ignored")
	}
	if out, err := renderRAMTemplate("${app.KEY}", map[string]string{"app.KEY": value}); err != nil || out != value {
		t.Fatal("boundary size rejected")
	}
	if _, err := ramBindingRefs([]ramSecretBinding{{"app.KEY", "services/app/app.KEY", true}, {"app.KEY", "services/app/app.OTHER", true}}); err == nil {
		t.Fatal("duplicate selector accepted")
	}
}
