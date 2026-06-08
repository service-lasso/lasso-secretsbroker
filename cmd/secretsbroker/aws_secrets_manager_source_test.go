package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const awsSourceSecretValue = "SERVICE_LASSO_FAKE_SECRET_SENTINEL_AWS_VALUE_DO_NOT_USE"
const awsSourceTokenValue = "SERVICE_LASSO_FAKE_SECRET_SENTINEL_AWS_TOKEN_DO_NOT_USE"

func TestAWSSecretsManagerSourceAdapterSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if r.Header.Get("X-Amz-Target") != "secretsmanager.GetSecretValue" {
			t.Fatalf("target = %s", r.Header.Get("X-Amz-Target"))
		}
		if r.Header.Get("Authorization") != "Bearer "+awsSourceTokenValue {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req awsSecretsManagerGetSecretValueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.SecretID != "service-lasso/prod/api" || req.VersionStage != "AWSCURRENT" {
			t.Fatalf("request = %#v", req)
		}
		fmt.Fprint(w, `{"ARN":"arn:aws:secretsmanager:us-east-1:123456789012:secret:service-lasso/prod/api","Name":"service-lasso/prod/api","SecretString":"{\"api_key\":\"`+awsSourceSecretValue+`\"}"}`)
	}))
	defer server.Close()

	cfg := sourceConfigFile{Sources: []sourceConfig{{
		SourceID:  "aws-prod",
		Kind:      "aws-secrets-manager",
		Enabled:   true,
		Address:   server.URL,
		AccountID: "123456789012",
		Region:    "us-east-1",
		Token:     awsSourceTokenValue,
		Refs: map[string]sourceRefConfig{
			"prod/openclaw/api_key": {Path: "service-lasso/prod/api", Field: "api_key", VersionStage: "AWSCURRENT"},
		},
	}}}

	res := cfg.resolve("prod/openclaw/api_key")
	if res.Outcome != "ready" || res.Value != awsSourceSecretValue || res.SourceID != "aws-prod" {
		t.Fatalf("aws result = %#v", res)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message, "outcome": res.Outcome, "sourceID": res.SourceID})
}

func TestAWSSecretsManagerSourceAdapterStatusMapping(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		errorType string
		body      string
		outcome   string
	}{
		{name: "auth required", status: http.StatusUnauthorized, outcome: "source_auth_required"},
		{name: "expired identity header", status: http.StatusBadRequest, errorType: "ExpiredTokenException", outcome: "identity_expired"},
		{name: "policy denied", status: http.StatusForbidden, errorType: "AccessDeniedException", outcome: "policy_denied"},
		{name: "missing ref", status: http.StatusNotFound, errorType: "ResourceNotFoundException", outcome: "missing_ref"},
		{name: "degraded", status: http.StatusTooManyRequests, errorType: "ThrottlingException", outcome: "degraded"},
		{name: "invalid mapping body", status: http.StatusBadRequest, body: `{"__type":"InvalidParameterException","message":"` + awsSourceSecretValue + `"}`, outcome: "invalid_ref"},
		{name: "unavailable", status: http.StatusInternalServerError, errorType: "InternalServiceError", outcome: "source_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.errorType != "" {
					w.Header().Set("x-amzn-ErrorType", tt.errorType)
				}
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			source := sourceConfig{SourceID: "aws", Kind: "aws-secrets-manager", Enabled: true, Address: server.URL, Token: awsSourceTokenValue}
			res := source.resolve("ref", sourceRefConfig{Path: "service-lasso/prod/api"})
			if res.Outcome != tt.outcome || res.Value != "" {
				t.Fatalf("outcome = %#v", res)
			}
			assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message, "outcome": res.Outcome})
		})
	}
}

func TestAWSSecretsManagerSourceAdapterRequiresTokenEndpointAndMapping(t *testing.T) {
	missingToken := sourceConfig{SourceID: "aws", Kind: "aws-secrets-manager", Enabled: true, Region: "us-east-1"}
	res := missingToken.resolve("ref", sourceRefConfig{Path: "service-lasso/prod/api"})
	if res.Outcome != "source_auth_required" {
		t.Fatalf("missing token outcome = %#v", res)
	}

	missingEndpoint := sourceConfig{SourceID: "aws", Kind: "aws-secrets-manager", Enabled: true, Token: awsSourceTokenValue}
	res = missingEndpoint.resolve("ref", sourceRefConfig{Path: "service-lasso/prod/api"})
	if res.Outcome != "invalid_ref" {
		t.Fatalf("missing endpoint outcome = %#v", res)
	}

	missingMapping := sourceConfig{SourceID: "aws", Kind: "aws-secrets-manager", Enabled: true, Address: "https://aws.invalid", Token: awsSourceTokenValue}
	res = missingMapping.resolve("ref", sourceRefConfig{})
	if res.Outcome != "invalid_ref" {
		t.Fatalf("missing mapping outcome = %#v", res)
	}
	assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
}

func TestAWSSecretsManagerSourceAdapterBoundsResponseAndTimeoutWithoutLeaking(t *testing.T) {
	t.Run("oversized response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"SecretString":"`+strings.Repeat("A", 64)+awsSourceSecretValue+`"}`)
		}))
		defer server.Close()

		source := sourceConfig{SourceID: "aws", Kind: "aws-secrets-manager", Enabled: true, Address: server.URL, Token: awsSourceTokenValue}
		res := source.resolve("ref", sourceRefConfig{Path: "service-lasso/prod/api", MaxStdoutBytes: 16})
		if res.Outcome != "source_unavailable" || res.Value != "" {
			t.Fatalf("oversized result = %#v", res)
		}
		assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(150 * time.Millisecond)
			fmt.Fprint(w, `{"SecretString":"`+awsSourceSecretValue+`"}`)
		}))
		defer server.Close()

		source := sourceConfig{SourceID: "aws", Kind: "aws-secrets-manager", Enabled: true, Address: server.URL, Token: awsSourceTokenValue}
		res := source.resolve("ref", sourceRefConfig{Path: "service-lasso/prod/api", TimeoutMs: 20})
		if res.Outcome != "source_unavailable" || res.Value != "" {
			t.Fatalf("timeout result = %#v", res)
		}
		assertNoSecretMaterialSurfaces(t, map[string]string{"message": res.Message})
	})
}

func TestAWSSecretsManagerSourceStatusReportsContractCapabilities(t *testing.T) {
	caps := capabilitiesForSourceKind("aws-secrets-manager")
	for _, capability := range []string{"read", "reveal", "write/update", "rotate/reset", "policy", "value-search", "audit", "migration", "health"} {
		assertContains(t, caps, capability)
	}
}

func TestAWSSecretsManagerSourceRegistryAndManagedListAreMetadataOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"SecretString":"{\"api_key\":\"`+awsSourceSecretValue+`\"}"}`)
	}))
	defer server.Close()

	backend := newLocalBackend("store.json", "audit.jsonl", "master-key")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID:    "aws-prod",
		Kind:        "aws-secrets-manager",
		DisplayName: "AWS prod",
		Enabled:     true,
		Address:     server.URL,
		AccountID:   "123456789012",
		Region:      "us-east-1",
		Token:       awsSourceTokenValue,
		Namespaces:  []string{"prod/*"},
		Refs: map[string]sourceRefConfig{
			"prod/openclaw/api_key": {Path: "service-lasso/prod/api", Field: "api_key"},
		},
	}}}

	registry := defaultSourceRegistry(backend)
	if len(registry.Sources) != 2 {
		t.Fatalf("sources = %#v", registry.Sources)
	}
	aws := registry.Sources[1]
	if aws.SourceID != "aws-prod" || aws.State != "connected" || aws.Outcome != "ready" {
		t.Fatalf("aws source = %#v", aws)
	}
	assertContains(t, aws.Capabilities, "value-search")
	assertContains(t, aws.Namespaces, "prod/*")
	assertNoSecretMaterial(t, mustManagedJSON(t, registry), awsSourceSecretValue, awsSourceTokenValue)

	list, err := backend.listManagedSecrets("aws-prod", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Results) != 1 || list.Results[0].ProviderKind != "aws-secrets-manager" || list.Results[0].ValueSearch != "supported" {
		t.Fatalf("managed list = %#v", list)
	}
	assertContains(t, list.Results[0].Capabilities, "rotate/reset")
	assertNoSecretMaterial(t, mustManagedJSON(t, list), awsSourceSecretValue, awsSourceTokenValue)

	search, err := backend.listManagedSecrets("AWS_VALUE", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(search.Results) != 1 || search.Results[0].Ref != "prod/openclaw/api_key" {
		t.Fatalf("value search = %#v", search)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, search), awsSourceSecretValue, awsSourceTokenValue)
}
