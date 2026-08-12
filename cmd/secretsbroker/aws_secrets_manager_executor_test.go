package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	awsMigrationAccessKey   = "AWS_ACCESS_KEY_TEST_ONLY"
	awsMigrationSecretKey   = "aws-secret-key-sentinel-test-only"
	awsMigrationSession     = "aws-session-token-sentinel-test-only"
	awsMigrationSecret      = "aws-migration-secret-sentinel"
	awsMigrationRemoteBody  = "aws-remote-body-sentinel"
	awsMigrationMappedField = "session_key"
)

var awsMigrationFixedTime = time.Date(2026, 8, 12, 10, 30, 0, 0, time.UTC)

type awsSecretsManagerProtocolFixture struct {
	mu                sync.Mutex
	secretString      string
	version           int
	getCount          int
	putCount          int
	forceGetStatus    int
	forceGetType      string
	forcePutStatus    int
	forcePutType      string
	mismatchRead      bool
	lastClientToken   string
	lastSecretID      string
	lastAmzDate       string
	signatureFailures []string
}

func (f *awsSecretsManagerProtocolFixture) handler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	beforeSignatureFailures := len(f.signatureFailures)
	f.validateSignature(r, body)
	if len(f.signatureFailures) != beforeSignatureFailures {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"__type":"UnrecognizedClientException","message":"`+awsMigrationRemoteBody+`"}`)
		return
	}
	target := r.Header.Get("X-Amz-Target")
	switch target {
	case "secretsmanager.GetSecretValue":
		f.getCount++
		if f.forceGetStatus != 0 {
			w.WriteHeader(f.forceGetStatus)
			fmt.Fprintf(w, `{"__type":%q,"message":%q}`, f.forceGetType, awsMigrationRemoteBody)
			return
		}
		var request awsSecretsManagerGetSecretValueRequest
		if json.Unmarshal(body, &request) != nil || request.SecretID != awsMigrationSecretID() || request.VersionStage != "AWSCURRENT" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		secretString := f.secretString
		if f.mismatchRead {
			secretString = `{"session_key":"different-remote-value","sibling":"preserve-me"}`
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:test", "Name": "test", "SecretString": secretString, "VersionId": fmt.Sprintf("version-%d", f.version)})
	case "secretsmanager.PutSecretValue":
		f.putCount++
		if f.forcePutStatus != 0 {
			w.WriteHeader(f.forcePutStatus)
			fmt.Fprintf(w, `{"__type":%q,"message":%q}`, f.forcePutType, awsMigrationRemoteBody)
			return
		}
		var request awsSecretsManagerPutSecretValueRequest
		if json.Unmarshal(body, &request) != nil || request.SecretID != awsMigrationSecretID() || len(request.ClientRequestToken) != 64 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.lastClientToken = request.ClientRequestToken
		f.lastSecretID = request.SecretID
		f.secretString = request.SecretString
		f.version++
		_ = json.NewEncoder(w).Encode(map[string]any{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:test", "Name": "test", "VersionId": fmt.Sprintf("version-%d", f.version)})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (f *awsSecretsManagerProtocolFixture) validateSignature(r *http.Request, body []byte) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
		f.signatureFailures = append(f.signatureFailures, "method_or_content_type")
		return
	}
	expected, err := http.NewRequest(http.MethodPost, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		f.signatureFailures = append(f.signatureFailures, "request")
		return
	}
	expected.Header.Set("Content-Type", "application/x-amz-json-1.1")
	expected.Header.Set("X-Amz-Target", r.Header.Get("X-Amz-Target"))
	amzDate := r.Header.Get("X-Amz-Date")
	f.lastAmzDate = amzDate
	signedAt, parseErr := time.Parse("20060102T150405Z", amzDate)
	if parseErr != nil {
		f.signatureFailures = append(f.signatureFailures, "X-Amz-Date")
		return
	}
	awsSignSecretsManagerRequest(expected, body, "us-east-1", awsSecretsManagerCredentials{accessKeyID: awsMigrationAccessKey, secretAccessKey: awsMigrationSecretKey, sessionToken: awsMigrationSession}, signedAt)
	for _, header := range []string{"Authorization", "X-Amz-Date", "X-Amz-Content-Sha256", "X-Amz-Security-Token"} {
		if r.Header.Get(header) != expected.Header.Get(header) {
			f.signatureFailures = append(f.signatureFailures, header)
		}
	}
}

func TestAWSSecretsManagerMigrationExecutorUsesSigV4PreservesFieldsAndVerifies(t *testing.T) {
	setAWSMigrationEnvironment(t)
	fixture := &awsSecretsManagerProtocolFixture{secretString: `{"sibling":"preserve-me","session_key":"old-value"}`, version: 7}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	executor := mustAWSSecretsManagerMigrationExecutor(t, awsMigrationSource(server.URL, true))
	idempotencyKey := "aws-safe-idempotency-key"
	write := executor.Write(providerMigrationWriteRequest{OperationID: "aws-write", IdempotencyKey: idempotencyKey, TargetProviderID: "aws-migration-target", Ref: awsMigrationRef(), Value: awsMigrationSecret})
	if write.Outcome != "applied" {
		t.Fatalf("write=%#v", write)
	}
	verified := executor.Verify(providerMigrationVerifyRequest{OperationID: "aws-write", IdempotencyKey: idempotencyKey, TargetProviderID: "aws-migration-target", Ref: awsMigrationRef(), ExpectedValue: awsMigrationSecret})
	if verified.Outcome != "verified" {
		t.Fatalf("verify=%#v", verified)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	var remote map[string]any
	if json.Unmarshal([]byte(fixture.secretString), &remote) != nil || remote["sibling"] != "preserve-me" || remote[awsMigrationMappedField] != awsMigrationSecret {
		t.Fatalf("remote=%#v", remote)
	}
	if fixture.getCount != 2 || fixture.putCount != 1 || fixture.lastClientToken != awsSecretsManagerClientRequestToken(providerMigrationWriteRequest{IdempotencyKey: idempotencyKey}) || fixture.lastSecretID != awsMigrationSecretID() || fixture.lastAmzDate != awsMigrationFixedTime.Format("20060102T150405Z") || len(fixture.signatureFailures) != 0 {
		t.Fatalf("fixture=%#v", fixture)
	}
}

func TestAWSSignSecretsManagerRequestMatchesFixedSigV4Vector(t *testing.T) {
	body := []byte(`{"SecretId":"service-lasso/prod/serviceadmin","VersionStage":"AWSCURRENT"}`)
	req, err := http.NewRequest(http.MethodPost, "https://secretsmanager.us-east-1.amazonaws.com/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	awsSignSecretsManagerRequest(req, body, "us-east-1", awsSecretsManagerCredentials{accessKeyID: awsMigrationAccessKey, secretAccessKey: awsMigrationSecretKey, sessionToken: awsMigrationSession}, awsMigrationFixedTime)
	wantAuthorization := "AWS4-HMAC-SHA256 Credential=AWS_ACCESS_KEY_TEST_ONLY/20260812/us-east-1/secretsmanager/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-target, Signature=47692711d5ccd17779369cc749b412c0a712737e9ed8243caf004c3e5942d65d"
	if req.Header.Get("Authorization") != wantAuthorization || req.Header.Get("X-Amz-Date") != "20260812T103000Z" || req.Header.Get("X-Amz-Content-Sha256") != "05b121ded35812be1474595b325f9cb14f6ed11dd44957169f8c04d6030d94e5" || req.Header.Get("X-Amz-Security-Token") != awsMigrationSession {
		t.Fatalf("signed headers=%#v", req.Header)
	}
}

func TestAWSSecretsManagerMigrationExecutorAlreadyEqualSkipsWrite(t *testing.T) {
	setAWSMigrationEnvironment(t)
	fixture := &awsSecretsManagerProtocolFixture{secretString: `{"sibling":"preserve-me","session_key":"` + awsMigrationSecret + `"}`, version: 3}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	executor := mustAWSSecretsManagerMigrationExecutor(t, awsMigrationSource(server.URL, true))
	result := executor.Write(providerMigrationWriteRequest{IdempotencyKey: "safe-key", Ref: awsMigrationRef(), Value: awsMigrationSecret})
	if result.Outcome != "applied" || fixture.putCount != 0 || fixture.getCount != 1 {
		t.Fatalf("result=%#v get=%d put=%d", result, fixture.getCount, fixture.putCount)
	}
}

func TestAWSSecretsManagerMigrationApplyIsConnectionScopedVerifiedAndRestartSafe(t *testing.T) {
	setAWSMigrationEnvironment(t)
	fixture := &awsSecretsManagerProtocolFixture{secretString: `{"sibling":"preserve-me","session_key":"old"}`, version: 1}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	backend := managedTestBackend(t)
	ref := awsMigrationRef()
	writeManagedTestSecret(t, backend, ref, awsMigrationSecret)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{awsMigrationSource(server.URL, true)}}
	backend.configureProviderMigrationExecutors()
	provider := providerStatusByID(t, backend.providerConfigStatusResponse(), "aws-migration-target")
	if migrationApplyMaturity(provider.Operations) != OperationMaturityValidated || migrationApplyMaturity(providerCapabilitiesByKind("aws-secrets-manager").Operations) != OperationMaturityPlanned {
		t.Fatalf("connection operations=%#v family=%#v", provider.Operations, providerCapabilitiesByKind("aws-secrets-manager").Operations)
	}
	req := migrationPlanRequest{RequestID: "req-aws-migration", ServiceID: "@serviceadmin", OperationID: "aws-migration-operation", SourceProviderID: "local", TargetProviderID: "aws-migration-target", Refs: []string{ref}, Reason: "approved AWS migration", Confirm: true}
	applied, err := backend.migrationApply(req)
	if err != nil || !applied.Applied || applied.Outcome != "applied" || len(applied.Results) != 1 || !applied.Results[0].Verified {
		t.Fatalf("applied=%#v err=%v", applied, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), awsMigrationSecret, awsMigrationAccessKey, awsMigrationSecretKey, awsMigrationSession, awsMigrationRemoteBody, awsMigrationSecretID())
	assertAWSMigrationSourceUnchanged(t, backend, ref)
	fixture.mu.Lock()
	getCount, putCount := fixture.getCount, fixture.putCount
	fixture.mu.Unlock()

	restarted := newLocalBackend(backend.storePath, backend.auditPath, backend.masterKey)
	restarted.sources = backend.sources
	restarted.configureProviderMigrationExecutors()
	retried, err := restarted.migrationApply(req)
	if err != nil || !retried.Applied || retried.Outcome != "applied" {
		t.Fatalf("retried=%#v err=%v", retried, err)
	}
	fixture.mu.Lock()
	if fixture.getCount != getCount || fixture.putCount != putCount {
		t.Fatalf("restart retry repeated remote calls: before=%d/%d after=%d/%d", getCount, putCount, fixture.getCount, fixture.putCount)
	}
	fixture.mu.Unlock()
	assertAWSMigrationPersistenceRedacted(t, restarted)
}

func TestAWSSecretsManagerMigrationApplyRetriesVerificationWithoutDuplicateWrite(t *testing.T) {
	setAWSMigrationEnvironment(t)
	fixture := &awsSecretsManagerProtocolFixture{secretString: `{"sibling":"preserve-me","session_key":"old"}`, version: 1, mismatchRead: true}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	backend := managedTestBackend(t)
	ref := awsMigrationRef()
	writeManagedTestSecret(t, backend, ref, awsMigrationSecret)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{awsMigrationSource(server.URL, true)}}
	backend.configureProviderMigrationExecutors()
	req := migrationPlanRequest{RequestID: "req-aws-verification-retry", ServiceID: "@serviceadmin", OperationID: "aws-verification-retry", SourceProviderID: "local", TargetProviderID: "aws-migration-target", Refs: []string{ref}, Reason: "approved AWS verification retry", Confirm: true}
	failed, err := backend.migrationApply(req)
	if err != nil || failed.Outcome != "partial_failure" || failed.Applied || len(failed.Results) != 1 || failed.Results[0].Outcome != "verification_failed" || failed.Results[0].Attempts != 1 {
		t.Fatalf("failed=%#v err=%v", failed, err)
	}
	fixture.mu.Lock()
	if fixture.putCount != 1 {
		t.Fatalf("initial writes=%d", fixture.putCount)
	}
	fixture.mismatchRead = false
	fixture.mu.Unlock()
	retried, err := backend.migrationApply(req)
	if err != nil || !retried.Applied || retried.Outcome != "applied" || !retried.Results[0].Verified || retried.Results[0].Attempts != 1 {
		t.Fatalf("retried=%#v err=%v", retried, err)
	}
	fixture.mu.Lock()
	if fixture.putCount != 1 {
		t.Fatalf("verification retry duplicated write: %d", fixture.putCount)
	}
	fixture.mu.Unlock()
	assertAWSMigrationPersistenceRedacted(t, backend)
}

func TestAWSSecretsManagerMigrationExecutorRefreshesCredentialsPerOperation(t *testing.T) {
	setAWSMigrationEnvironment(t)
	fixture := &awsSecretsManagerProtocolFixture{secretString: `{"session_key":"old"}`, version: 1}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	executor := mustAWSSecretsManagerMigrationExecutor(t, awsMigrationSource(server.URL, true))
	t.Setenv("AWS_MIGRATION_SECRET_ACCESS_KEY", "rotated-invalid-key")
	if result := executor.Write(providerMigrationWriteRequest{Ref: awsMigrationRef(), Value: awsMigrationSecret}); result.Outcome != "source_auth_required" {
		t.Fatalf("stale credential result=%#v", result)
	}
	t.Setenv("AWS_MIGRATION_SECRET_ACCESS_KEY", awsMigrationSecretKey)
	if result := executor.Write(providerMigrationWriteRequest{Ref: awsMigrationRef(), Value: awsMigrationSecret}); result.Outcome != "applied" {
		t.Fatalf("refreshed credential result=%#v", result)
	}
	t.Setenv("AWS_MIGRATION_ACCESS_KEY_ID", "")
	if result := executor.Verify(providerMigrationVerifyRequest{Ref: awsMigrationRef(), ExpectedValue: awsMigrationSecret}); result.Outcome != "source_auth_required" {
		t.Fatalf("missing credential result=%#v", result)
	}
}

func TestAWSSecretsManagerMigrationRegistrationFailsClosedUnlessFullyConfigured(t *testing.T) {
	setAWSMigrationEnvironment(t)
	for _, test := range []struct {
		name   string
		mutate func(*sourceConfig)
		want   string
	}{
		{name: "disabled capability", mutate: func(source *sourceConfig) { source.EnableMigrationTarget = false }, want: "source_auth_required"},
		{name: "missing credential handle", mutate: func(source *sourceConfig) { source.SecretAccessKeyEnv = "" }, want: "source_auth_required"},
		{name: "missing credential value", mutate: func(source *sourceConfig) { source.SecretAccessKeyEnv = "AWS_MIGRATION_MISSING_SECRET" }, want: "source_auth_required"},
		{name: "unsafe address", mutate: func(source *sourceConfig) { source.Address = "https://user:password@aws.invalid/path?credential=value" }, want: "invalid_ref"},
		{name: "remote plaintext HTTP", mutate: func(source *sourceConfig) { source.Address = "http://aws.invalid" }, want: "invalid_ref"},
		{name: "invalid mapping", mutate: func(source *sourceConfig) {
			source.Refs[awsMigrationRef()] = sourceRefConfig{Path: "secret", VersionID: "immutable-version"}
		}, want: "invalid_ref"},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := managedTestBackend(t)
			source := awsMigrationSource("https://aws.invalid", true)
			test.mutate(&source)
			backend.sources = sourceConfigFile{Sources: []sourceConfig{source}}
			backend.configureProviderMigrationExecutors()
			if _, ok := backend.providerMigrationExecutor(source.SourceID); ok {
				t.Fatal("invalid or disabled source registered an executor")
			}
			registry := defaultSourceRegistry(backend)
			if len(registry.Sources) != 2 || registry.Sources[1].Outcome != test.want || migrationApplyMaturity(registry.Sources[1].Operations) == OperationMaturityValidated {
				t.Fatalf("source status=%#v", registry.Sources)
			}
		})
	}
}

func TestAWSSecretsManagerMigrationExecutorMapsRemoteFailuresWithoutLeakingBodies(t *testing.T) {
	setAWSMigrationEnvironment(t)
	for _, test := range []struct {
		name       string
		status     int
		errorType  string
		writeError bool
		want       string
	}{
		{name: "expired auth", status: http.StatusBadRequest, errorType: "ExpiredTokenException", want: "source_auth_required"},
		{name: "policy", status: http.StatusForbidden, errorType: "AccessDeniedException", want: "policy_denied"},
		{name: "rate limit", status: http.StatusBadRequest, errorType: "ThrottlingException", want: "rate_limited"},
		{name: "unavailable", status: http.StatusServiceUnavailable, errorType: "InternalServiceError", want: "source_unavailable"},
		{name: "version conflict", status: http.StatusBadRequest, errorType: "ResourceExistsException", writeError: true, want: "conflict"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := &awsSecretsManagerProtocolFixture{secretString: `{"session_key":"old"}`, version: 1}
			if test.writeError {
				fixture.forcePutStatus, fixture.forcePutType = test.status, test.errorType
			} else {
				fixture.forceGetStatus, fixture.forceGetType = test.status, test.errorType
			}
			server := httptest.NewServer(http.HandlerFunc(fixture.handler))
			defer server.Close()
			executor := mustAWSSecretsManagerMigrationExecutor(t, awsMigrationSource(server.URL, true))
			result := executor.Write(providerMigrationWriteRequest{IdempotencyKey: "safe-key", Ref: awsMigrationRef(), Value: awsMigrationSecret})
			if result.Outcome != test.want {
				t.Fatalf("result=%#v", result)
			}
			assertNoSecretMaterial(t, mustManagedJSON(t, result), awsMigrationSecret, awsMigrationAccessKey, awsMigrationSecretKey, awsMigrationSession, awsMigrationRemoteBody, awsMigrationSecretID())
		})
	}
}

func TestAWSSecretsManagerMigrationExecutorVerificationMismatchIsTyped(t *testing.T) {
	setAWSMigrationEnvironment(t)
	fixture := &awsSecretsManagerProtocolFixture{secretString: `{"session_key":"old"}`, version: 1, mismatchRead: true}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	executor := mustAWSSecretsManagerMigrationExecutor(t, awsMigrationSource(server.URL, true))
	result := executor.Verify(providerMigrationVerifyRequest{Ref: awsMigrationRef(), ExpectedValue: awsMigrationSecret})
	if result.Outcome != "verification_failed" {
		t.Fatalf("result=%#v", result)
	}
}

func TestAWSSecretsManagerMigrationExecutorRejectsRedirectOversizeAndTimeout(t *testing.T) {
	setAWSMigrationEnvironment(t)
	t.Run("redirect", func(t *testing.T) {
		redirected := 0
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
		defer target.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer server.Close()
		executor := mustAWSSecretsManagerMigrationExecutor(t, awsMigrationSource(server.URL, true))
		result := executor.Write(providerMigrationWriteRequest{Ref: awsMigrationRef(), Value: awsMigrationSecret})
		if result.Outcome != "source_unavailable" || redirected != 0 {
			t.Fatalf("result=%#v redirected=%d", result, redirected)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", 129)) }))
		defer server.Close()
		source := awsMigrationSource(server.URL, true)
		mapping := source.Refs[awsMigrationRef()]
		mapping.MaxBytes = 128
		source.Refs[awsMigrationRef()] = mapping
		executor := mustAWSSecretsManagerMigrationExecutor(t, source)
		if result := executor.Write(providerMigrationWriteRequest{Ref: awsMigrationRef(), Value: awsMigrationSecret}); result.Outcome != "source_unavailable" {
			t.Fatalf("result=%#v", result)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(250 * time.Millisecond) }))
		defer server.Close()
		source := awsMigrationSource(server.URL, true)
		mapping := source.Refs[awsMigrationRef()]
		mapping.TimeoutMs = 100
		source.Refs[awsMigrationRef()] = mapping
		executor := mustAWSSecretsManagerMigrationExecutor(t, source)
		started := time.Now()
		result := executor.Write(providerMigrationWriteRequest{Ref: awsMigrationRef(), Value: awsMigrationSecret})
		if result.Outcome != "source_unavailable" || time.Since(started) > time.Second {
			t.Fatalf("result=%#v elapsed=%s", result, time.Since(started))
		}
	})
}

func setAWSMigrationEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_MIGRATION_ACCESS_KEY_ID", awsMigrationAccessKey)
	t.Setenv("AWS_MIGRATION_SECRET_ACCESS_KEY", awsMigrationSecretKey)
	t.Setenv("AWS_MIGRATION_SESSION_TOKEN", awsMigrationSession)
}

func awsMigrationSource(address string, enabled bool) sourceConfig {
	return sourceConfig{
		SourceID: "aws-migration-target", Kind: "aws-secrets-manager", DisplayName: "AWS migration target", Enabled: true, EnableMigrationTarget: enabled,
		Address: address, Region: "us-east-1", AccessKeyIDEnv: "AWS_MIGRATION_ACCESS_KEY_ID", SecretAccessKeyEnv: "AWS_MIGRATION_SECRET_ACCESS_KEY", SessionTokenEnv: "AWS_MIGRATION_SESSION_TOKEN",
		Refs: map[string]sourceRefConfig{awsMigrationRef(): {Path: awsMigrationSecretID(), Field: awsMigrationMappedField, VersionStage: "AWSCURRENT", TimeoutMs: 1000, MaxBytes: 4096}},
	}
}

func awsMigrationRef() string {
	return "services/@serviceadmin/runtime/AWS_SESSION_KEY"
}

func awsMigrationSecretID() string {
	return "service-lasso/prod/serviceadmin"
}

func mustAWSSecretsManagerMigrationExecutor(t *testing.T, source sourceConfig) *awsSecretsManagerMigrationExecutor {
	t.Helper()
	executor, err := newAWSSecretsManagerMigrationExecutor(source)
	if err != nil {
		t.Fatal(err)
	}
	executor.now = func() time.Time { return awsMigrationFixedTime }
	return executor
}

func assertAWSMigrationSourceUnchanged(t *testing.T, backend *localBackend, ref string) {
	t.Helper()
	resolved := backend.resolve(resolveRequest{RequestID: "req-aws-source-proof", ServiceID: "@serviceadmin", Purpose: "source recovery proof", Refs: []string{ref}})
	if len(resolved.Results) != 1 || resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != awsMigrationSecret {
		t.Fatalf("source not recoverable: %#v", resolved.Results)
	}
}

func assertAWSMigrationPersistenceRedacted(t *testing.T, backend *localBackend) {
	t.Helper()
	store, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, store, awsMigrationSecret, awsMigrationAccessKey, awsMigrationSecretKey, awsMigrationSession, awsMigrationRemoteBody, awsMigrationSecretID())
	assertNoSecretMaterial(t, audit, awsMigrationSecret, awsMigrationAccessKey, awsMigrationSecretKey, awsMigrationSession, awsMigrationRemoteBody, awsMigrationSecretID())
}
