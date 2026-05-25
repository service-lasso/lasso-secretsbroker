package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
