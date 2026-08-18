package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const decommissionSecretValue = "fixture-decommission-secret-value"

func TestLocalDecommissionSignedPlanApplyRetryRestartAndRestore(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, decommissionSecretValue)
	version := currentDecommissionVersion(t, backend, ref)

	plan, err := backend.decommissionDryRun(decommissionRequest{
		RequestID:          "req-decommission-plan",
		ServiceID:          "@serviceadmin",
		Ref:                ref,
		OperationID:        "decommission-serviceadmin-session",
		DependencyStatus:   "clear",
		DependencySnapshot: "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil || plan.Outcome != "dry_run_ready" || plan.Plan == nil || plan.Plan.Signature == "" || plan.ExpectedVersion != version || !plan.Recoverable {
		t.Fatalf("plan = %#v err=%v", plan, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, plan), decommissionSecretValue, backend.masterKey)

	request := decommissionRequest{
		RequestID:   "req-decommission-apply",
		ServiceID:   "@serviceadmin",
		Ref:         ref,
		OperationID: plan.OperationID,
		Reason:      "service dependency review approved",
		Confirm:     true,
		Plan:        plan.Plan,
	}
	applied, err := backend.decommissionApply(request)
	if err != nil || !applied.Applied || applied.Outcome != "applied" || applied.Tombstone == nil || applied.Tombstone.State != "decommissioned" || !applied.Recoverable {
		t.Fatalf("applied = %#v err=%v", applied, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, applied), decommissionSecretValue, backend.masterKey)
	assertDecommissioned(t, backend, ref, version)

	storeBeforeRetry := readDecommissionStore(t, backend)
	retried, err := backend.decommissionApply(request)
	if err != nil || !retried.Applied || retried.NextAction != "already_decommissioned" {
		t.Fatalf("retry = %#v err=%v", retried, err)
	}
	if !bytes.Equal(storeBeforeRetry, readDecommissionStore(t, backend)) {
		t.Fatal("idempotent decommission retry changed the store")
	}

	restarted := newLocalBackend(backend.storePath, backend.auditPath, backend.masterKey)
	restarted.eventPath = backend.eventPath
	assertDecommissioned(t, restarted, ref, version)
	inventory, err := restarted.listManagedSecrets("", false)
	if err != nil {
		t.Fatal(err)
	}
	var tombstoneRecord *managedSecretRecord
	for index := range inventory.Results {
		if inventory.Results[index].Ref == ref {
			tombstoneRecord = &inventory.Results[index]
			break
		}
	}
	if tombstoneRecord == nil || tombstoneRecord.State != "decommissioned" || tombstoneRecord.Outcome != "decommissioned" || tombstoneRecord.Tombstone == nil || tombstoneRecord.Tombstone.Version != version || !reflect.DeepEqual(tombstoneRecord.Capabilities, []string{"metadata", "restore"}) {
		t.Fatalf("restart tombstone inventory = %#v", tombstoneRecord)
	}
	restoreRequest := decommissionRequest{RequestID: "req-decommission-restore", ServiceID: "@serviceadmin", Ref: ref, OperationID: "restore-serviceadmin-session", ExpectedVersion: version, Reason: "rollback after consumer validation failure", Confirm: true}
	restored, err := restarted.decommissionRestore(restoreRequest)
	if err != nil || !restored.Applied || restored.Tombstone == nil || restored.Tombstone.State != "restored" || restored.Recoverable {
		t.Fatalf("restored = %#v err=%v", restored, err)
	}
	resolved := restarted.resolve(resolveRequest{RequestID: "req-after-restore", ServiceID: "@serviceadmin", Purpose: "decommission-restore-test", Refs: []string{ref}})
	if len(resolved.Results) != 1 || resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != decommissionSecretValue {
		t.Fatalf("restored resolution = %#v", resolved)
	}

	storeBeforeRestoreRetry := readDecommissionStore(t, restarted)
	restoredAgain, err := restarted.decommissionRestore(restoreRequest)
	if err != nil || !restoredAgain.Applied || restoredAgain.NextAction != "already_restored" {
		t.Fatalf("restore retry = %#v err=%v", restoredAgain, err)
	}
	if !bytes.Equal(storeBeforeRestoreRetry, readDecommissionStore(t, restarted)) {
		t.Fatal("idempotent restore retry changed the store")
	}

	audit, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"management_decommission_dry_run", "management_decommission_apply", "management_decommission_restore"} {
		if !bytes.Contains(audit, []byte(operation)) {
			t.Fatalf("audit missing %s: %s", operation, audit)
		}
	}
	assertNoSecretMaterial(t, audit, decommissionSecretValue, backend.masterKey)
}

func TestLocalDecommissionFailsClosedForDependenciesStalePlansAndUnsupportedSources(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/API_KEY"
	writeManagedTestSecret(t, backend, ref, decommissionSecretValue)

	blocked, err := backend.decommissionDryRun(decommissionRequest{RequestID: "req-dependency-blocked", ServiceID: "@serviceadmin", Ref: ref, OperationID: "decommission-blocked", DependencyStatus: "blocked", DependencySnapshot: "sha256:" + strings.Repeat("b", 64), Dependencies: []string{"@api"}})
	if !errors.Is(err, errDecommissionDependency) || blocked.Outcome != "dependency_blocked" || blocked.Plan != nil || len(blocked.Dependencies) != 1 {
		t.Fatalf("dependency response = %#v err=%v", blocked, err)
	}
	unsafeMetadata, err := backend.decommissionDryRun(decommissionRequest{RequestID: "req-unsafe-dependency", ServiceID: "@serviceadmin", Ref: ref, OperationID: "decommission-unsafe", DependencyStatus: "clear", DependencySnapshot: decommissionSecretValue, Dependencies: []string{decommissionSecretValue}})
	if !errors.Is(err, errDecommissionDependency) || unsafeMetadata.Outcome != "dependency_blocked" {
		t.Fatalf("unsafe dependency response = %#v err=%v", unsafeMetadata, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, unsafeMetadata), decommissionSecretValue)

	plan, err := backend.decommissionDryRun(decommissionRequest{RequestID: "req-stale-plan", ServiceID: "@serviceadmin", Ref: ref, OperationID: "decommission-stale", DependencyStatus: "clear", DependencySnapshot: "sha256:" + strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	tamperedPlan := *plan.Plan
	tamperedPlan.ExpectedVersion = decommissionSecretValue
	tampered, err := backend.decommissionApply(decommissionRequest{RequestID: "req-tampered-apply", ServiceID: "@serviceadmin", Ref: ref, OperationID: plan.OperationID, Reason: "approved", Confirm: true, Plan: &tamperedPlan})
	if !errors.Is(err, errDecommissionStalePlan) || tampered.Outcome != "stale_plan" {
		t.Fatalf("tampered response = %#v err=%v", tampered, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, tampered), decommissionSecretValue)
	previousNow := backend.now
	backend.now = func() time.Time { return previousNow().Add(time.Minute) }
	writeManagedTestSecret(t, backend, ref, "replacement-after-plan")
	stale, err := backend.decommissionApply(decommissionRequest{RequestID: "req-stale-apply", ServiceID: "@serviceadmin", Ref: ref, OperationID: plan.OperationID, Reason: "approved", Confirm: true, Plan: plan.Plan})
	if !errors.Is(err, errDecommissionStalePlan) || stale.Outcome != "stale_plan" || stale.Applied {
		t.Fatalf("stale response = %#v err=%v", stale, err)
	}
	resolved := backend.resolve(resolveRequest{RequestID: "req-stale-resolve", ServiceID: "@serviceadmin", Purpose: "stale-plan-test", Refs: []string{ref}})
	if resolved.Results[0].Value != "replacement-after-plan" {
		t.Fatalf("stale plan mutated current value: %#v", resolved.Results[0])
	}

	denied, err := backend.decommissionApply(decommissionRequest{RequestID: "req-denied", ServiceID: "@serviceadmin", Ref: ref, OperationID: plan.OperationID, Plan: plan.Plan})
	if !errors.Is(err, errPolicyDenied) || denied.Outcome != "policy_denied" || denied.Applied {
		t.Fatalf("denied response = %#v err=%v", denied, err)
	}

	locked := newLocalBackend(filepath.Join(t.TempDir(), "store.json"), filepath.Join(t.TempDir(), "audit.jsonl"), "")
	lockedPlan, err := locked.decommissionDryRun(decommissionRequest{RequestID: "req-locked", ServiceID: "@serviceadmin", Ref: ref, OperationID: "decommission-locked", DependencyStatus: "clear", DependencySnapshot: "sha256:" + strings.Repeat("d", 64)})
	if !errors.Is(err, errLocked) || lockedPlan.Outcome != "locked" {
		t.Fatalf("locked response = %#v err=%v", lockedPlan, err)
	}

	remote := managedTestBackend(t)
	remote.sources = sourceConfigFile{Sources: []sourceConfig{{SourceID: "vault-ready", Kind: "vault", Enabled: true, Address: "https://vault.invalid", Token: "provider-token-fixture", Refs: map[string]sourceRefConfig{ref: {Path: "secret/data/serviceadmin", Field: "api_key"}}}}}
	unsupported, err := remote.decommissionDryRun(decommissionRequest{RequestID: "req-remote", ServiceID: "@serviceadmin", Ref: ref, OperationID: "decommission-remote", DependencyStatus: "clear", DependencySnapshot: "sha256:" + strings.Repeat("e", 64)})
	if !errors.Is(err, errUnsupportedProvider) || unsupported.Outcome != "unsupported" || unsupported.Plan != nil {
		t.Fatalf("unsupported response = %#v err=%v", unsupported, err)
	}
	assertNoSecretMaterial(t, mustManagedJSON(t, unsupported), "provider-token-fixture")
}

func TestLocalDecommissionAuditUnavailablePreservesActiveStoreAndHTTPIsSafe(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, decommissionSecretValue)
	plan, err := backend.decommissionDryRun(decommissionRequest{RequestID: "req-audit-plan", ServiceID: "@serviceadmin", Ref: ref, OperationID: "decommission-audit-down", DependencyStatus: "clear", DependencySnapshot: "sha256:" + strings.Repeat("f", 64)})
	if err != nil {
		t.Fatal(err)
	}
	before := readDecommissionStore(t, backend)
	blockedAudit := filepath.Join(t.TempDir(), "audit-is-directory")
	if err := os.Mkdir(blockedAudit, 0o700); err != nil {
		t.Fatal(err)
	}
	backend.auditPath = blockedAudit

	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()
	body, err := json.Marshal(decommissionRequest{RequestID: "req-audit-apply", ServiceID: "@serviceadmin", Ref: ref, OperationID: plan.OperationID, Reason: "approved", Confirm: true, Plan: plan.Plan})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/management/secrets/decommission/apply", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || !bytes.Contains(payload, []byte(`"outcome":"audit_unavailable"`)) {
		t.Fatalf("status=%d body=%s", response.StatusCode, payload)
	}
	assertNoSecretMaterial(t, payload, decommissionSecretValue, "test-token", backend.masterKey)
	if !bytes.Equal(before, readDecommissionStore(t, backend)) {
		t.Fatal("store changed when audit was unavailable")
	}
}

func TestLocalDecommissionTombstoneSurvivesBrokerProcessRestart(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	eventsPath := filepath.Join(dir, "events.jsonl")
	address := freeDecommissionAddress(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"

	process := startDecommissionBrokerProcess(t, address, storePath, auditPath, eventsPath)
	writePayload := postDecommissionProcessJSON(t, address, "/v1/secrets", writeSecretRequest{Ref: ref, Value: decommissionSecretValue})
	var written writeSecretResponse
	if err := json.Unmarshal(writePayload, &written); err != nil {
		t.Fatal(err)
	}
	planPayload := postDecommissionProcessJSON(t, address, "/v1/management/secrets/decommission/dry-run", decommissionRequest{RequestID: "req-process-plan", ServiceID: "@serviceadmin", Ref: ref, OperationID: "decommission-process", DependencyStatus: "clear", DependencySnapshot: "sha256:" + strings.Repeat("1", 64)})
	var plan decommissionResponse
	if err := json.Unmarshal(planPayload, &plan); err != nil || plan.Plan == nil {
		t.Fatalf("decode plan: %v body=%s", err, planPayload)
	}
	applyPayload := postDecommissionProcessJSON(t, address, "/v1/management/secrets/decommission/apply", decommissionRequest{RequestID: "req-process-apply", ServiceID: "@serviceadmin", Ref: ref, OperationID: plan.OperationID, Reason: "approved process test", Confirm: true, Plan: plan.Plan})
	var applied decommissionResponse
	if err := json.Unmarshal(applyPayload, &applied); err != nil || !applied.Applied {
		t.Fatalf("decode apply: %v body=%s", err, applyPayload)
	}
	stopDecommissionBrokerProcess(t, process)

	process = startDecommissionBrokerProcess(t, address, storePath, auditPath, eventsPath)
	defer stopDecommissionBrokerProcess(t, process)
	restorePayload := postDecommissionProcessJSON(t, address, "/v1/management/secrets/decommission/restore", decommissionRequest{RequestID: "req-process-restore", ServiceID: "@serviceadmin", Ref: ref, OperationID: "restore-process", ExpectedVersion: written.Metadata.Version, Reason: "consumer rollback", Confirm: true})
	var restored decommissionResponse
	if err := json.Unmarshal(restorePayload, &restored); err != nil || !restored.Applied || restored.Tombstone == nil || restored.Tombstone.State != "restored" {
		t.Fatalf("decode restore: %v body=%s", err, restorePayload)
	}
	revealPayload := postDecommissionProcessJSON(t, address, "/v1/management/secrets/reveal", managedSecretActionRequest{RequestID: "req-process-reveal", ServiceID: "@serviceadmin", Ref: ref, Reason: "process restart proof", Confirm: true})
	var revealed managedSecretActionResponse
	if err := json.Unmarshal(revealPayload, &revealed); err != nil || revealed.Value != decommissionSecretValue {
		t.Fatalf("decode reveal: %v outcome=%s", err, revealed.Outcome)
	}
}

func TestLocalDecommissionTombstoneSurvivesBackupRestoreAndMasterKeyRotation(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/API_KEY"
	writeManagedTestSecret(t, backend, ref, decommissionSecretValue)
	version := currentDecommissionVersion(t, backend, ref)
	plan, err := backend.decommissionDryRun(decommissionRequest{RequestID: "req-portable-plan", ServiceID: "@serviceadmin", Ref: ref, OperationID: "decommission-portable", DependencyStatus: "clear", DependencySnapshot: "sha256:" + strings.Repeat("2", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.decommissionApply(decommissionRequest{RequestID: "req-portable-apply", ServiceID: "@serviceadmin", Ref: ref, OperationID: plan.OperationID, Reason: "approved", Confirm: true, Plan: plan.Plan}); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(t.TempDir(), "decommission-backup.json")
	if _, err := backend.createBackup(backupPath); err != nil {
		t.Fatal(err)
	}
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, backupBytes, decommissionSecretValue, backend.masterKey)

	restored := newLocalBackend(filepath.Join(t.TempDir(), "restored-store.json"), filepath.Join(t.TempDir(), "restored-audit.jsonl"), backend.masterKey)
	if _, err := restored.restoreBackup(backupPath); err != nil {
		t.Fatal(err)
	}
	assertDecommissioned(t, restored, ref, version)

	if _, err := restored.rotateMasterKey("next-master-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.decommissionRestore(decommissionRequest{RequestID: "req-portable-restore", ServiceID: "@serviceadmin", Ref: ref, OperationID: "restore-portable", ExpectedVersion: version, Reason: "recovery proof", Confirm: true}); err != nil {
		t.Fatal(err)
	}
	resolved := restored.resolve(resolveRequest{RequestID: "req-portable-resolve", ServiceID: "@serviceadmin", Purpose: "backup-key-rotation-test", Refs: []string{ref}})
	if len(resolved.Results) != 1 || resolved.Results[0].Outcome != "ready" || resolved.Results[0].Value != decommissionSecretValue {
		t.Fatalf("restored after key rotation = %#v", resolved)
	}
	storeBytes := readDecommissionStore(t, restored)
	assertNoSecretMaterial(t, storeBytes, decommissionSecretValue, "test-master-key")
}

func TestDecommissionBrokerProcessHelper(t *testing.T) {
	if os.Getenv("SECRETSBROKER_DECOMMISSION_PROCESS_HELPER") != "1" {
		return
	}
	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		fmt.Fprintln(os.Stderr, "missing broker helper arguments")
		os.Exit(2)
	}
	if err := run(os.Args[separator+1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func currentDecommissionVersion(t *testing.T, backend *localBackend, ref string) string {
	t.Helper()
	store, err := backend.loadStore()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := store.Secrets[ref]
	if !ok {
		t.Fatalf("missing secret %s", ref)
	}
	return entry.Metadata.Version
}

func assertDecommissioned(t *testing.T, backend *localBackend, ref, version string) {
	t.Helper()
	store, err := backend.loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Secrets[ref]; ok {
		t.Fatalf("active secret %s still exists", ref)
	}
	tombstone, ok := store.Tombstones[ref]
	if !ok || tombstone.State != "decommissioned" || tombstone.Version != version {
		t.Fatalf("tombstone = %#v", tombstone)
	}
	payload := readDecommissionStore(t, backend)
	if strings.Contains(string(payload), decommissionSecretValue) {
		t.Fatal("store tombstone exposed plaintext")
	}
}

func readDecommissionStore(t *testing.T, backend *localBackend) []byte {
	t.Helper()
	payload, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func freeDecommissionAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func startDecommissionBrokerProcess(t *testing.T, address, storePath, auditPath, eventsPath string) *exec.Cmd {
	t.Helper()
	logFile, err := os.Create(filepath.Join(t.TempDir(), "broker.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestDecommissionBrokerProcessHelper$", "--", "serve", "--listen", address, "--mode", "development", "--transport", "loopback-http", "--state", "ready", "--store", storePath, "--audit", auditPath, "--events", eventsPath, "--master-key", "test-master-key", "--api-token", "test-token")
	command.Env = append(os.Environ(), "SECRETSBROKER_DECOMMISSION_PROCESS_HELPER=1")
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	_ = logFile.Close()
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	})
	client := &http.Client{Timeout: 250 * time.Millisecond, Transport: &http.Transport{DisableKeepAlives: true}}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, requestErr := client.Get("http://" + address + "/health")
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return command
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("broker process did not become ready at %s", address)
	return nil
}

func stopDecommissionBrokerProcess(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if command == nil || command.ProcessState != nil {
		return
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("stop broker process: %v", err)
	}
	if _, err := command.Process.Wait(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("wait broker process: %v", err)
		}
	}
}

func postDecommissionProcessJSON(t *testing.T, address, path string, body any) []byte {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+address+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responsePayload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status=%d body=%s", path, response.StatusCode, responsePayload)
	}
	return responsePayload
}
