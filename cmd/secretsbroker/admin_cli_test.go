package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const adminCLISecretValue = "fixture-admin-cli-secret-value"

func TestAdminCLIStatusProvidersAndMetadataOutputAreScrubbed(t *testing.T) {
	backend := managedTestBackend(t)
	writeManagedTestSecret(t, backend, "services/@serviceadmin/runtime/SESSION_SIGNING_KEY", adminCLISecretValue)
	keyPath := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(keyPath, []byte("test-master-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	var status bytes.Buffer
	if err := executeAdmin([]string{"status", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key-file", keyPath}, &status); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, status.Bytes(), adminCLISecretValue, "test-master-key")
	if !bytes.Contains(status.Bytes(), []byte("providerKind")) || !bytes.Contains(status.Bytes(), []byte("local-encrypted-store")) {
		t.Fatalf("status missing provider summary: %s", status.String())
	}

	var providers bytes.Buffer
	if err := executeAdmin([]string{"providers", "status", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &providers); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, providers.Bytes(), adminCLISecretValue, "test-master-key")

	var list bytes.Buffer
	if err := executeAdmin([]string{"secrets", "list", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &list); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, list.Bytes(), adminCLISecretValue, "test-master-key")
	if !bytes.Contains(list.Bytes(), []byte("SESSION_SIGNING_KEY")) {
		t.Fatalf("list missing metadata ref: %s", list.String())
	}

	var search bytes.Buffer
	if err := executeAdmin([]string{"secrets", "value-search", "--query", "admin-cli-secret", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &search); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, search.Bytes(), adminCLISecretValue, "test-master-key")
}

func TestAdminCLIRevealRequiresConfirmReasonAndSupportsNoEcho(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, adminCLISecretValue)

	var denied bytes.Buffer
	err := executeAdmin([]string{"secrets", "reveal", "--ref", ref, "--reason", "operator check", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &denied)
	if !errors.Is(err, errPolicyDenied) {
		t.Fatalf("expected policy denied without confirm, got %v body=%s", err, denied.String())
	}
	assertNoSecretMaterial(t, denied.Bytes(), adminCLISecretValue)

	var noEcho bytes.Buffer
	if err := executeAdmin([]string{"secrets", "reveal", "--ref", ref, "--reason", "operator check", "--confirm", "--no-echo", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &noEcho); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, noEcho.Bytes(), adminCLISecretValue)
	if !bytes.Contains(noEcho.Bytes(), []byte("value_suppressed_by_no_echo")) {
		t.Fatalf("no-echo response missing guidance: %s", noEcho.String())
	}

	var reveal bytes.Buffer
	if err := executeAdmin([]string{"secrets", "reveal", "--ref", ref, "--reason", "operator check", "--confirm", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &reveal); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(reveal.Bytes(), []byte(adminCLISecretValue)) {
		t.Fatalf("explicit reveal did not include value: %s", reveal.String())
	}
}

func TestAdminCLIProviderValidationMigrationAndAuditAreScrubbed(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, adminCLISecretValue)

	var validate bytes.Buffer
	if err := executeAdmin([]string{"providers", "validate", "--provider-id", "vault-dev", "--provider-kind", "vault", "--address", "https://vault.example.invalid", "--credential-ref", "secret://local/provider/vault-dev/token", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &validate); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, validate.Bytes(), adminCLISecretValue, "raw-token-value")
	if bytes.Contains(validate.Bytes(), []byte("credentialValue")) {
		t.Fatalf("provider validation exposed credential value field: %s", validate.String())
	}

	var rejected bytes.Buffer
	err := executeAdmin([]string{"providers", "validate", "--provider-id", "vault-dev", "--provider-kind", "vault", "--address", "https://vault.example.invalid", "--credential-value", "raw-token-value", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &rejected)
	if !errors.Is(err, errPolicyDenied) {
		t.Fatalf("plaintext credential should be denied, got %v body=%s", err, rejected.String())
	}
	assertNoSecretMaterial(t, rejected.Bytes(), "raw-token-value", adminCLISecretValue)

	var migration bytes.Buffer
	if err := executeAdmin([]string{"migration", "dry-run", "--source-provider", "local", "--target-provider", "local", "--ref", ref, "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &migration); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, migration.Bytes(), adminCLISecretValue, "test-master-key")
	if !bytes.Contains(migration.Bytes(), []byte("dry_run_ready")) {
		t.Fatalf("migration dry run missing outcome: %s", migration.String())
	}

	if err := backend.audit("management_reveal", ref, "ready", "@operator", "req-1"); err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	if err := executeAdmin([]string{"audit", "export", "--operation", "management_reveal", "--audit", backend.auditPath}, &audit); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, audit.Bytes(), adminCLISecretValue, "test-master-key")
	var exported adminAuditExportResponse
	if err := json.Unmarshal(audit.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.Events) == 0 || exported.Events[0].Operation != "management_reveal" {
		t.Fatalf("audit export = %#v", exported)
	}
	if exported.Events[0].RefHash == "" || exported.Events[0].ReasonCode != "ready" || exported.Events[0].ActorKind != "operator" || exported.Events[0].AuditStatus != "audit_recorded" {
		t.Fatalf("audit event missing normalized metadata: %#v", exported.Events[0])
	}

	var hashOnly bytes.Buffer
	if err := executeAdmin([]string{"audit", "export", "--operation", "management_reveal", "--ref-hash-only", "--audit", backend.auditPath}, &hashOnly); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, hashOnly.Bytes(), adminCLISecretValue, "test-master-key")
	if bytes.Contains(hashOnly.Bytes(), []byte(ref)) {
		t.Fatalf("hash-only audit export exposed raw ref: %s", hashOnly.String())
	}
	var hashOnlyExport adminAuditExportResponse
	if err := json.Unmarshal(hashOnly.Bytes(), &hashOnlyExport); err != nil {
		t.Fatal(err)
	}
	if len(hashOnlyExport.Events) == 0 || hashOnlyExport.Events[0].Ref != "" || hashOnlyExport.Events[0].RefHash == "" {
		t.Fatalf("hash-only audit export = %#v", hashOnlyExport)
	}
}

func TestAdminLaunchLeaseIssuesTransportBoundSignedLease(t *testing.T) {
	var out bytes.Buffer
	err := executeAdmin([]string{
		"launch-lease", "issue",
		"--service-id", "api-service",
		"--workspace-id", "workspace-local",
		"--allowed-ref", "services/api-service/runtime/*",
		"--allowed-namespace", "services/api-service",
		"--operation", "resolve",
		"--operation", "create",
		"--jti", "jti-admin-launch-lease",
		"--issued-at", "2026-06-27T03:45:00Z",
		"--expires-at", "2026-06-27T03:50:00Z",
		"--transport-binding-kind", "windows-sid",
		"--transport-binding-subject", "S-1-5-21-1000",
		"--signing-key", "issuer-secret-key",
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, out.Bytes(), "issuer-secret-key")

	var issued adminLaunchLeaseIssueResponse
	if err := json.Unmarshal(out.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Outcome != "ready" || issued.Lease.Signature == "" {
		t.Fatalf("launch lease response missing signed ready lease: %#v", issued)
	}
	if issued.Lease.TransportBinding == nil || issued.Lease.TransportBinding.Kind != "windows-sid" || issued.Lease.TransportBinding.Subject != "S-1-5-21-1000" {
		t.Fatalf("transport binding = %#v", issued.Lease.TransportBinding)
	}

	backend := testBackend(t)
	backend.now = func() time.Time { return time.Date(2026, 6, 27, 3, 46, 0, 0, time.UTC) }
	peer := transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-1000"}
	if err := backend.verifyLaunchIdentityLease(&issued.Lease, "issuer-secret-key", "api-service", "workspace-local", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, peer); err != nil {
		t.Fatalf("issued transport-bound lease should verify: %v", err)
	}

	replayBackend := testBackend(t)
	replayBackend.now = backend.now
	if err := replayBackend.verifyLaunchIdentityLease(&issued.Lease, "issuer-secret-key", "api-service", "workspace-local", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-9999"}); !errors.Is(err, errPolicyDenied) {
		t.Fatalf("mismatched transport-bound lease err=%v, want policy denied", err)
	}
}

func TestAdminLaunchLeaseRejectsIncompleteTransportBinding(t *testing.T) {
	var out bytes.Buffer
	err := executeAdmin([]string{
		"launch-lease", "issue",
		"--service-id", "api-service",
		"--allowed-ref", "services/api-service/runtime/*",
		"--operation", "resolve",
		"--jti", "jti-incomplete-binding",
		"--issued-at", "2026-06-27T03:45:00Z",
		"--transport-binding-kind", "windows-sid",
		"--signing-key", "issuer-secret-key",
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "transport binding requires both kind and subject") {
		t.Fatalf("expected incomplete transport binding rejection, got err=%v body=%s", err, out.String())
	}
	assertNoSecretMaterial(t, out.Bytes(), "issuer-secret-key")
}

func TestAdminCLILockedListFailsClosed(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "store.json")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var out bytes.Buffer
	err := executeAdmin([]string{"secrets", "list", "--store", storePath, "--audit", auditPath}, &out)
	if !errors.Is(err, errLocked) {
		t.Fatalf("locked list err=%v body=%s", err, out.String())
	}
	assertNoSecretMaterial(t, out.Bytes(), adminCLISecretValue)
	if !strings.Contains(out.String(), "locked") {
		t.Fatalf("locked response missing outcome: %s", out.String())
	}
}
