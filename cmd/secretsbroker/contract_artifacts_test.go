package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const updateContractEnvironment = "UPDATE_CONTRACT"

type contractRoute struct {
	Method   string
	Path     string
	Summary  string
	Auth     bool
	Request  any
	Response any
	Query    []contractQueryParameter
}

type contractQueryParameter struct {
	Name        string
	Description string
	Type        string
	Format      string
}

func contractRoutes() []contractRoute {
	managedAction := func(path, summary string) contractRoute {
		return contractRoute{Method: http.MethodPost, Path: path, Summary: summary, Auth: true, Request: managedSecretActionRequest{}, Response: managedSecretActionResponse{}}
	}
	bulkAction := func(path, summary string) contractRoute {
		return contractRoute{Method: http.MethodPost, Path: path, Summary: summary, Auth: true, Request: bulkCampaignRequest{}, Response: bulkCampaignResponse{}}
	}
	providerAction := func(path, summary string) contractRoute {
		return contractRoute{Method: http.MethodPost, Path: path, Summary: summary, Auth: true, Request: providerConfigRequest{}, Response: providerConfigActionResponse{}}
	}
	migrationAction := func(path, summary string) contractRoute {
		return contractRoute{Method: http.MethodPost, Path: path, Summary: summary, Auth: true, Request: migrationPlanRequest{}, Response: migrationPlanResponse{}}
	}
	decommissionAction := func(path, summary string) contractRoute {
		return contractRoute{Method: http.MethodPost, Path: path, Summary: summary, Auth: true, Request: decommissionRequest{}, Response: decommissionResponse{}}
	}
	createAction := func(path, summary string) contractRoute {
		return contractRoute{Method: http.MethodPost, Path: path, Summary: summary, Auth: true, Request: managedCreateRequest{}, Response: managedCreateResponse{}}
	}

	return []contractRoute{
		{Method: http.MethodGet, Path: "/health", Summary: "Broker liveness", Response: HealthResponse{}},
		{Method: http.MethodGet, Path: "/ready", Summary: "Broker readiness", Response: StateResponse{}},
		{Method: http.MethodGet, Path: "/status", Summary: "Safe broker status", Response: Status{}},
		{Method: http.MethodGet, Path: "/state", Summary: "Typed broker lifecycle state", Response: StateResponse{}},
		{Method: http.MethodGet, Path: "/capabilities", Summary: "Broker routes, features and outcomes", Response: CapabilitiesResponse{}},
		{Method: http.MethodPost, Path: "/v1/secrets", Summary: "Write a local secret", Auth: true, Request: writeSecretRequest{}, Response: writeSecretResponse{}},
		{Method: http.MethodPost, Path: "/v1/writeback", Summary: "Capture a generated secret", Auth: true, Request: generatedSecretCaptureRequest{}, Response: generatedSecretCaptureResponse{}},
		{Method: http.MethodPost, Path: "/v1/resolve", Summary: "Resolve a batch of secret references", Auth: true, Request: resolveRequest{}, Response: resolveResponse{}},
		{Method: http.MethodGet, Path: "/v1/provisioning/status", Summary: "List generated-secret provisioning status", Auth: true, Response: provisioningStatusResponse{}, Query: []contractQueryParameter{{Name: "search", Type: "string"}, {Name: "ref", Type: "string"}}},
		{Method: http.MethodPost, Path: "/v1/provisioning/operations/plan", Summary: "Plan a provisioning operation", Auth: true, Request: provisioningOperationRequest{}, Response: provisioningOperationResponse{}},
		{Method: http.MethodPost, Path: "/v1/provisioning/operations/apply", Summary: "Apply a provisioning operation", Auth: true, Request: provisioningOperationRequest{}, Response: provisioningOperationResponse{}},
		{Method: http.MethodGet, Path: "/v1/sources/status", Summary: "List source lifecycle and capability status", Response: sourceStatusResponse{}},
		{Method: http.MethodGet, Path: "/v1/providers/capabilities", Summary: "List provider capabilities", Response: providerCapabilitiesResponse{}},
		{Method: http.MethodGet, Path: "/v1/providers/config/status", Summary: "List safe provider configuration status", Auth: true, Response: providerConfigStatusResponse{}},
		{Method: http.MethodGet, Path: "/v1/telemetry", Summary: "Read redacted telemetry", Response: telemetryResponse{}},
		{Method: http.MethodPost, Path: "/v1/telemetry/export", Summary: "Export redacted telemetry", Response: telemetryExportActionResult{}},
		{Method: http.MethodGet, Path: "/v1/events", Summary: "List bounded operational events", Response: eventsResponse{}, Query: eventContractQueryParameters()},
		{Method: http.MethodGet, Path: "/v1/recovery/policy", Summary: "Read recovery policy metadata", Response: recoveryPolicyStatusResponse{}},
		{Method: http.MethodPost, Path: "/v1/recovery/policy", Summary: "Create or update recovery policy metadata", Auth: true, Request: recoveryPolicyRequest{}, Response: recoveryPolicyStatusResponse{}},
		{Method: http.MethodGet, Path: "/v1/management/lifecycle/status", Summary: "Read key, wrapper, recovery and backup metadata", Auth: true, Response: lifecycleStatusResponse{}},
		{Method: http.MethodGet, Path: "/v1/management/lifecycle/backups", Summary: "List broker-owned encrypted backups", Auth: true, Response: lifecycleBackupResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/lifecycle/backups", Summary: "Create a broker-owned encrypted backup", Auth: true, Request: lifecycleOperationRequest{}, Response: lifecycleBackupResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/lifecycle/backups/verify", Summary: "Verify an encrypted backup", Auth: true, Request: lifecycleOperationRequest{}, Response: lifecycleBackupResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/lifecycle/restore/dry-run", Summary: "Plan an exact backup restore", Auth: true, Request: lifecycleOperationRequest{}, Response: lifecycleRestoreResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/lifecycle/restore/apply", Summary: "Apply an exact backup restore", Auth: true, Request: lifecycleOperationRequest{}, Response: lifecycleRestoreResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/lifecycle/key/rotate", Summary: "Rotate the broker master key and local wrapper", Auth: true, Request: lifecycleOperationRequest{}, Response: lifecycleRotateResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/lockouts/clear", Summary: "Clear a scoped local API lockout", Auth: true, Request: lockoutClearRequest{}, Response: lockoutClearResponse{}},
		providerAction("/v1/providers/config/validate", "Validate provider configuration"),
		providerAction("/v1/providers/config/apply", "Apply provider configuration"),
		migrationAction("/v1/providers/migration/dry-run", "Plan provider migration"),
		migrationAction("/v1/providers/migration/apply", "Apply provider migration"),
		{Method: http.MethodGet, Path: "/v1/management/secrets", Summary: "List managed secret metadata", Auth: true, Response: managedSecretsResponse{}, Query: []contractQueryParameter{{Name: "search", Type: "string"}}},
		{Method: http.MethodGet, Path: "/v1/management/secrets/value-search", Summary: "Search secret values without returning them", Auth: true, Response: managedSecretsResponse{}, Query: []contractQueryParameter{{Name: "query", Type: "string"}}},
		createAction("/v1/management/secrets/create/dry-run", "Plan a no-overwrite local secret create"),
		createAction("/v1/management/secrets/create/apply", "Create a local secret from an exact signed plan"),
		managedAction("/v1/management/secrets/reveal", "Reveal one managed secret under policy"),
		managedAction("/v1/management/secrets/edit/dry-run", "Preview a managed secret edit"),
		managedAction("/v1/management/secrets/edit/apply", "Apply a managed secret edit"),
		managedAction("/v1/management/secrets/reset/dry-run", "Preview a managed secret reset"),
		managedAction("/v1/management/secrets/reset/apply", "Apply a managed secret reset"),
		decommissionAction("/v1/management/secrets/decommission/dry-run", "Plan a local secret decommission"),
		decommissionAction("/v1/management/secrets/decommission/apply", "Decommission a local secret into an encrypted tombstone"),
		decommissionAction("/v1/management/secrets/decommission/restore", "Restore a local secret from an encrypted tombstone"),
		{Method: http.MethodPost, Path: "/v1/management/secrets/rotation/dry-run", Summary: "Preview credential rotation", Auth: true, Request: rotationDryRunRequest{}, Response: rotationDryRunResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/secrets/rotation/status", Summary: "Read local rotation version metadata", Auth: true, Request: rotationVersionRequest{}, Response: rotationVersionResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/secrets/rotation/stage", Summary: "Stage a local secret version", Auth: true, Request: rotationVersionRequest{}, Response: rotationVersionResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/secrets/rotation/activate", Summary: "Activate a staged local secret version", Auth: true, Request: rotationVersionRequest{}, Response: rotationVersionResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/secrets/rotation/rollback", Summary: "Roll back to a retained local secret version", Auth: true, Request: rotationVersionRequest{}, Response: rotationVersionResponse{}},
		{Method: http.MethodPost, Path: "/v1/management/secrets/rotation/retire", Summary: "Retire retained local secret versions", Auth: true, Request: rotationVersionRequest{}, Response: rotationVersionResponse{}},
		bulkAction("/v1/management/secrets/campaigns/create", "Create a bulk secret campaign"),
		bulkAction("/v1/management/secrets/campaigns/revalidate", "Revalidate a bulk secret campaign"),
		bulkAction("/v1/management/secrets/campaigns/apply", "Apply a bulk secret campaign"),
		bulkAction("/v1/management/secrets/campaigns/status", "Read bulk secret campaign status"),
		{Method: http.MethodPost, Path: "/v1/management/secrets/sync/dry-run", Summary: "Preview secret synchronisation", Auth: true, Request: syncDryRunRequest{}, Response: syncDryRunResponse{}},
		managedAction("/v1/management/secrets/policy/preview", "Preview a managed secret policy change"),
		managedAction("/v1/management/secrets/policy/apply", "Apply a managed secret policy change"),
	}
}

func eventContractQueryParameters() []contractQueryParameter {
	params := []contractQueryParameter{
		{Name: "since", Type: "string", Format: "date-time"},
		{Name: "until", Type: "string", Format: "date-time"},
		{Name: "serviceId", Type: "string"},
		{Name: "providerId", Type: "string"},
		{Name: "sourceId", Type: "string"},
		{Name: "operation", Type: "string"},
		{Name: "outcome", Type: "string"},
		{Name: "severity", Type: "string"},
		{Name: "family", Type: "string"},
		{Name: "refPrefix", Type: "string"},
		{Name: "refHash", Type: "string"},
		{Name: "limit", Description: "Maximum 200", Type: "integer"},
		{Name: "cursor", Type: "integer"},
	}
	return params
}

func TestContractArtefactsAreCurrent(t *testing.T) {
	assertGeneratedContractFile(t, filepath.Join("..", "..", "contract", "v1", "openapi.json"), renderOpenAPIContract(t))
	assertGeneratedContractFile(t, filepath.Join("..", "..", "conformance", "fixtures", "contract-states.json"), renderCanonicalStateFixture(t))
}

func TestAdvertisedHTTPRoutesHaveSchemas(t *testing.T) {
	want := map[string]bool{}
	for _, route := range contractRoutes() {
		key := route.Method + " " + route.Path
		if want[key] {
			t.Fatalf("duplicate contract route %s", key)
		}
		want[key] = true
	}
	got := advertisedHTTPRoutes(defaultCapabilities().Endpoints)
	manifest := map[string]bool{}
	for _, operation := range defaultCapabilities().Operations {
		key := operation.Method + " " + operation.Path
		if manifest[key] {
			t.Fatalf("duplicate manifest route %s", key)
		}
		manifest[key] = true
	}
	for key := range got {
		if !want[key] {
			t.Errorf("advertised HTTP route has no schema: %s", key)
		}
	}
	for key := range want {
		if !got[key] {
			t.Errorf("schema route is not advertised by /capabilities: %s", key)
		}
		if !manifest[key] {
			t.Errorf("schema route has no operation manifest entry: %s", key)
		}
	}
	for key := range manifest {
		if !want[key] {
			t.Errorf("operation manifest route has no schema: %s", key)
		}
	}
}

func TestCanonicalFixtureResponsesUseGoContractTypes(t *testing.T) {
	fixture := canonicalStateFixture(t)
	types := contractSchemaTypes()
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			typ, ok := types[tc.ResponseSchema]
			if !ok {
				t.Fatalf("response schema %q is not a Go contract type", tc.ResponseSchema)
			}
			value := reflect.New(typ).Interface()
			decoder := json.NewDecoder(bytes.NewReader(tc.ExpectedResponse))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(value); err != nil {
				t.Fatalf("fixture response does not match %s: %v", tc.ResponseSchema, err)
			}
		})
	}
}

func contractSchemaTypes() map[string]reflect.Type {
	types := map[string]reflect.Type{}
	register := func(value any) {
		typ := indirectType(reflect.TypeOf(value))
		types[typ.Name()] = typ
	}
	register(ErrorEnvelope{})
	for _, route := range contractRoutes() {
		if route.Request != nil {
			register(route.Request)
		}
		register(route.Response)
	}
	return types
}

func advertisedHTTPRoutes(endpoints []string) map[string]bool {
	routes := map[string]bool{}
	for _, endpoint := range endpoints {
		parts := strings.SplitN(strings.TrimSpace(endpoint), " ", 2)
		if len(parts) != 2 || strings.EqualFold(parts[0], "CLI") {
			continue
		}
		methods := strings.Split(parts[0], "|")
		pathAlternatives := strings.Split(parts[1], "|")
		paths := []string{pathAlternatives[0]}
		base := pathAlternatives[0][:strings.LastIndex(pathAlternatives[0], "/")+1]
		for _, alternative := range pathAlternatives[1:] {
			paths = append(paths, base+alternative)
		}
		for _, method := range methods {
			for _, path := range paths {
				routes[strings.ToUpper(method)+" "+path] = true
			}
		}
	}
	return routes
}

func renderOpenAPIContract(t *testing.T) []byte {
	t.Helper()
	builder := newContractSchemaBuilder()
	paths := map[string]any{}
	for _, route := range contractRoutes() {
		capability, ok := operationCapabilityForRoute(route.Method, route.Path)
		if !ok {
			t.Fatalf("missing operation capability for %s %s", route.Method, route.Path)
		}
		operation := map[string]any{
			"operationId":  contractOperationID(route),
			"summary":      route.Summary,
			"x-capability": capability,
			"responses": map[string]any{
				"200": contractJSONResponse("Successful response", builder.reference(route.Response)),
				"default": contractJSONResponse("Typed failure response", map[string]any{
					"oneOf": []any{builder.reference(route.Response), builder.reference(ErrorEnvelope{})},
				}),
			},
		}
		if route.Auth {
			operation["security"] = []any{map[string]any{"localBearerToken": []any{}}, map[string]any{"localHeaderToken": []any{}}}
		} else {
			operation["security"] = []any{}
		}
		if route.Request != nil {
			operation["requestBody"] = map[string]any{
				"required": true,
				"content":  map[string]any{"application/json": map[string]any{"schema": builder.reference(route.Request)}},
			}
		}
		if len(route.Query) > 0 {
			parameters := make([]any, 0, len(route.Query))
			for _, query := range route.Query {
				schema := map[string]any{"type": query.Type}
				if query.Format != "" {
					schema["format"] = query.Format
				}
				parameter := map[string]any{"name": query.Name, "in": "query", "required": false, "schema": schema}
				if query.Description != "" {
					parameter["description"] = query.Description
				}
				parameters = append(parameters, parameter)
			}
			operation["parameters"] = parameters
		}
		pathItem, _ := paths[route.Path].(map[string]any)
		if pathItem == nil {
			pathItem = map[string]any{}
			paths[route.Path] = pathItem
		}
		pathItem[strings.ToLower(route.Method)] = operation
	}
	document := map[string]any{
		"openapi":           "3.1.0",
		"jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
		"info": map[string]any{
			"title":       "Service Lasso Secrets Broker local API",
			"version":     contractVersion,
			"description": "Canonical metadata-safe contract generated from the Go request and response DTOs. Unknown response fields are compatible additions.",
		},
		"servers": []any{map[string]any{"url": "http://127.0.0.1:17890", "description": "Development loopback transport"}},
		"paths":   paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"localBearerToken": map[string]any{"type": "http", "scheme": "bearer"},
				"localHeaderToken": map[string]any{"type": "apiKey", "in": "header", "name": "X-SecretsBroker-Token"},
			},
			"schemas": builder.schemas,
		},
		"x-service-id":                 serviceID,
		"x-api-version":                apiVersion,
		"x-contract-version":           contractVersion,
		"x-operation-manifest-version": operationManifestVersion,
		"x-compatibility": map[string]any{
			"unknownResponseFields": "ignore",
			"breakingChanges":       "new major contract version",
		},
	}
	return mustIndentedJSON(t, document)
}

func contractOperationID(route contractRoute) string {
	return operationManifestID(route.Method, route.Path)
}

func contractJSONResponse(description string, schema map[string]any) map[string]any {
	return map[string]any{
		"description": description,
		"content":     map[string]any{"application/json": map[string]any{"schema": schema}},
	}
}

type contractSchemaBuilder struct {
	schemas  map[string]any
	building map[reflect.Type]bool
}

func newContractSchemaBuilder() *contractSchemaBuilder {
	return &contractSchemaBuilder{schemas: map[string]any{}, building: map[reflect.Type]bool{}}
}

func (b *contractSchemaBuilder) reference(value any) map[string]any {
	typ := indirectType(reflect.TypeOf(value))
	name := typ.Name()
	if name == "" {
		panic("contract component type must be named")
	}
	b.ensureComponent(typ)
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func (b *contractSchemaBuilder) ensureComponent(typ reflect.Type) {
	typ = indirectType(typ)
	name := typ.Name()
	if _, ok := b.schemas[name]; ok || b.building[typ] {
		return
	}
	b.building[typ] = true
	b.schemas[name] = b.schemaFor(typ)
	delete(b.building, typ)
}

func (b *contractSchemaBuilder) schemaFor(typ reflect.Type) map[string]any {
	typ = indirectType(typ)
	if typ.PkgPath() == "time" && typ.Name() == "Time" {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch typ.Kind() {
	case reflect.Struct:
		properties := map[string]any{}
		required := []string{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			jsonName, options := parseJSONTag(field)
			if jsonName == "-" || jsonName == "" {
				continue
			}
			properties[jsonName] = b.fieldSchema(field.Type)
			if !options["omitempty"] {
				required = append(required, jsonName)
			}
		}
		sort.Strings(required)
		schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": true}
		if len(required) > 0 {
			schema["required"] = required
		}
		return schema
	case reflect.String:
		schema := map[string]any{"type": "string"}
		switch typ.Name() {
		case "OperationMaturity":
			schema["enum"] = []string{"unavailable", "planned", "read-only", "dry-run", "executable", "validated"}
		case "OperationClassification":
			schema["enum"] = []string{"read", "mutation"}
		case "OperationScope":
			schema["enum"] = []string{"broker-local", "provider-remote", "source-boundary", "mixed"}
		case "OperationCompletionMode":
			schema["enum"] = []string{"synchronous", "asynchronous"}
		}
		return schema
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": b.fieldSchema(typ.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": b.fieldSchema(typ.Elem())}
	case reflect.Interface:
		return map[string]any{}
	default:
		panic(fmt.Sprintf("unsupported contract schema type %s", typ))
	}
}

func (b *contractSchemaBuilder) fieldSchema(typ reflect.Type) map[string]any {
	typ = indirectType(typ)
	if typ.PkgPath() == "time" && typ.Name() == "Time" {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	if typ.Name() != "" && typ.Kind() == reflect.Struct {
		b.ensureComponent(typ)
		return map[string]any{"$ref": "#/components/schemas/" + typ.Name()}
	}
	return b.schemaFor(typ)
}

func parseJSONTag(field reflect.StructField) (string, map[string]bool) {
	tag := field.Tag.Get("json")
	if tag == "" {
		return field.Name, map[string]bool{}
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	if name == "" {
		name = field.Name
	}
	options := map[string]bool{}
	for _, option := range parts[1:] {
		options[option] = true
	}
	return name, options
}

func indirectType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}

func canonicalStateFixture(t *testing.T) parityFixture {
	t.Helper()
	fixedTime := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	forbidden := []string{"raw-secret-value", "local-api-token", "portable-master-key", "provider-credential"}
	noAuth := false
	auth := true
	stateCase := func(name, scenario, state string) parityFixtureCase {
		return parityFixtureCase{
			Name: name, Scenario: scenario, Kind: "http", Method: http.MethodGet, Path: "/state", RequiresAuth: &noAuth,
			ExpectedStatus: http.StatusOK, ResponseSchema: "StateResponse", ExpectedResponse: mustRawContractJSON(t, stateResponse(state, nil, nil)), RedactionForbidden: forbidden,
		}
	}
	sourceResponse := func(source SourceStatus) sourceStatusResponse {
		return sourceStatusResponse{
			ServiceID: serviceID, APIVersion: apiVersion, ContractVersion: contractVersion, ManifestVersion: operationManifestVersion, SourceConfig: sourceConfigSecurity{Configured: true, Checked: true, State: "valid", Outcome: "ready"}, Sources: []SourceStatus{source},
		}
	}
	sourceWithAudit := func(id, kind, name, outcome, auditStatus string) SourceStatus {
		lifecycle := normalizeSourceLifecycle(outcome)
		status := SourceStatus{
			SourceID: id, Kind: kind, DisplayName: name, Enabled: true, Critical: true, Priority: 0,
			Capabilities: capabilitiesForSourceKind(kind), Namespaces: []string{"*"}, State: lifecycle.State, Outcome: lifecycle.Outcome,
			NextAction: lifecycle.NextAction, Retryable: lifecycle.Retryable, RetryAfterMs: lifecycle.RetryAfterMs, Lifecycle: lifecycle, AuditStatus: auditStatus,
			AffectedRefs: []string{}, AffectedServices: []string{},
		}
		status.Operations = providerOperationCapabilitiesForSource(kind, lifecycle, status.AuditStatus)
		return status
	}
	source := func(id, kind, name, outcome string) SourceStatus {
		return sourceWithAudit(id, kind, name, outcome, "audit_available")
	}
	unsupportedProvider := providerConfigStatus{ProviderID: "future-provider", ProviderKind: "future-provider", DisplayName: "Future provider", State: "unsupported", Outcome: "unsupported", Namespaces: []string{}, Capabilities: []string{"health"}, AuditStatus: "audit_available"}
	unsupportedProvider.Operations = providerOperationCapabilitiesForSource(unsupportedProvider.ProviderKind, normalizeSourceLifecycle(unsupportedProvider.Outcome), unsupportedProvider.AuditStatus)
	unsupported := providerConfigActionResponse{
		ServiceID: serviceID, APIVersion: apiVersion, RequestID: "req-contract-unsupported", OperationID: "op-contract-unsupported",
		Operation: "provider_config_validate", Outcome: "unsupported", Applied: false, RequiresConfirmation: false, AuditStatus: "audit_recorded",
		NextAction: "select_supported_provider", Provider: unsupportedProvider,
		UnsupportedCapability: "provider_configuration",
	}
	auditUnavailable := syncDryRunResponse{
		ServiceID: serviceID, APIVersion: apiVersion, RequestID: "req-contract-audit", OperationID: "op-contract-audit", Operation: "secrets_sync",
		Mode: "dry-run", Outcome: "audit_unavailable", Applied: false, RequiresConfirmation: true, AuditStatus: "audit_unavailable", StaleAfterSeconds: 300,
		NextAction: "restore_audit_before_sync", Destination: syncDestinationConfig{DestinationID: "github-actions", Kind: "github-actions", DisplayName: "GitHub Actions", Enabled: true, Scope: syncDestinationScope{Owner: "service-lasso", Repository: "example", SecretsLocation: "repository"}, State: "ready", Outcome: "ready", AuditStatus: "audit_unavailable"},
		Results: []syncDryRunItem{}, Summary: syncDryRunSummary{SelectedCount: 1, AuditUnavailableCount: 1}, AffectedRefs: []string{"services/example/runtime/API_TOKEN"}, AffectedServices: []string{"example"},
	}
	policyDenied := ErrorEnvelope{Error: APIError{Code: "policy_denied", Message: "The requested operation was denied by policy.", Outcome: "policy_denied", RequestID: "req-contract-denied", NextAction: "review_policy", AffectedRefs: []string{}, AffectedServices: []string{}}}

	return parityFixture{
		SchemaVersion: 1,
		Contract:      "secretsbroker.parity.v1",
		ServiceID:     serviceID,
		APIVersion:    apiVersion,
		Cases: []parityFixtureCase{
			{Name: "capabilities-operation-manifest", Scenario: "operation-manifest", Kind: "http", Method: http.MethodGet, Path: "/capabilities", RequiresAuth: &noAuth, ExpectedStatus: http.StatusOK, ResponseSchema: "CapabilitiesResponse", ExpectedResponse: mustRawContractJSON(t, defaultCapabilities()), RedactionForbidden: forbidden},
			stateCase("state-ready", "ready", "ready"),
			stateCase("state-setup-needed", "setup-needed", "setup_needed"),
			stateCase("state-locked", "locked", "locked"),
			stateCase("state-degraded", "degraded", "degraded"),
			{Name: "source-local-ready", Scenario: "local-store", Kind: "http", Method: http.MethodGet, Path: "/v1/sources/status", RequiresAuth: &noAuth, ExpectedStatus: http.StatusOK, ResponseSchema: "sourceStatusResponse", ExpectedResponse: mustRawContractJSON(t, sourceResponse(source("local", "local-encrypted-store", "Local encrypted store", "ready"))), RedactionForbidden: forbidden},
			{Name: "source-openbao-auth-required", Scenario: "auth-required", Kind: "http", Method: http.MethodGet, Path: "/v1/sources/status", RequiresAuth: &noAuth, ExpectedStatus: http.StatusOK, ResponseSchema: "sourceStatusResponse", ExpectedResponse: mustRawContractJSON(t, sourceResponse(source("openbao-primary", "openbao", "Primary OpenBao", "source_auth_required"))), RedactionForbidden: forbidden},
			{Name: "source-aws-auth-required", Scenario: "auth-required", Kind: "http", Method: http.MethodGet, Path: "/v1/sources/status", RequiresAuth: &noAuth, ExpectedStatus: http.StatusOK, ResponseSchema: "sourceStatusResponse", ExpectedResponse: mustRawContractJSON(t, sourceResponse(source("aws-production", "aws-secrets-manager", "AWS Secrets Manager", "source_auth_required"))), RedactionForbidden: forbidden},
			{Name: "source-vault-policy-denied", Scenario: "policy-denied", Kind: "http", Method: http.MethodGet, Path: "/v1/sources/status", RequiresAuth: &noAuth, ExpectedStatus: http.StatusOK, ResponseSchema: "sourceStatusResponse", ExpectedResponse: mustRawContractJSON(t, sourceResponse(source("vault-policy-denied", "vault", "Vault policy denied", "policy_denied"))), RedactionForbidden: forbidden},
			{Name: "source-vault-audit-unavailable", Scenario: "audit-unavailable", Kind: "http", Method: http.MethodGet, Path: "/v1/sources/status", RequiresAuth: &noAuth, ExpectedStatus: http.StatusOK, ResponseSchema: "sourceStatusResponse", ExpectedResponse: mustRawContractJSON(t, sourceResponse(sourceWithAudit("vault-audit-unavailable", "vault", "Vault audit unavailable", "ready", "audit_unavailable"))), RedactionForbidden: forbidden},
			{Name: "operation-policy-denied", Scenario: "policy-denied", Kind: "http", Method: http.MethodPost, Path: "/v1/writeback", RequiresAuth: &auth, ExpectedStatus: http.StatusForbidden, ResponseSchema: "ErrorEnvelope", ExpectedResponse: mustRawContractJSON(t, policyDenied), RedactionForbidden: forbidden},
			{Name: "provider-unsupported", Scenario: "unsupported", Kind: "http", Method: http.MethodPost, Path: "/v1/providers/config/validate", RequiresAuth: &auth, ExpectedStatus: http.StatusNotImplemented, ResponseSchema: "providerConfigActionResponse", ExpectedResponse: mustRawContractJSON(t, unsupported), RedactionForbidden: forbidden},
			{Name: "sync-audit-unavailable", Scenario: "audit-unavailable", Kind: "http", Method: http.MethodPost, Path: "/v1/management/secrets/sync/dry-run", RequiresAuth: &auth, ExpectedStatus: http.StatusServiceUnavailable, ResponseSchema: "syncDryRunResponse", ExpectedResponse: mustRawContractJSON(t, auditUnavailable), RedactionForbidden: forbidden},
			{Name: "events-empty-safe", Scenario: "events", Kind: "http", Method: http.MethodGet, Path: "/v1/events", RequiresAuth: &noAuth, ExpectedStatus: http.StatusOK, ResponseSchema: "eventsResponse", ExpectedResponse: mustRawContractJSON(t, eventsResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", GeneratedAt: fixedTime, Limit: 50, Events: []operationalEvent{}, Safety: eventSafety{MetadataOnly: true, RawRefIncluded: false, ValueMaterialIncluded: false}}), RedactionForbidden: forbidden},
		},
	}
}

func renderCanonicalStateFixture(t *testing.T) []byte {
	t.Helper()
	return mustIndentedJSON(t, canonicalStateFixture(t))
}

func mustRawContractJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	bytes, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func mustIndentedJSON(t *testing.T, value any) []byte {
	t.Helper()
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(bytes, '\n')
}

func assertGeneratedContractFile(t *testing.T, path string, generated []byte) {
	t.Helper()
	if os.Getenv(updateContractEnvironment) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, generated, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated contract artefact %s: %v; run UPDATE_CONTRACT=1 go test ./cmd/secretsbroker -run TestContractArtefactsAreCurrent", path, err)
	}
	if !bytes.Equal(existing, generated) {
		t.Fatalf("generated contract artefact is stale: %s; run UPDATE_CONTRACT=1 go test ./cmd/secretsbroker -run TestContractArtefactsAreCurrent", path)
	}
}
