package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestAuditChainSerializesConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	const writers = 32
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			backend := newLocalBackend(filepath.Join(dir, fmt.Sprintf("store-%d.json", index)), auditPath, "test-master-key")
			backend.auditHashChain = true
			errs <- backend.audit("concurrent_write", fmt.Sprintf("services/test/ref-%d", index), "ready", "test", fmt.Sprintf("request-%d", index))
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	exported, err := exportAuditEvents(auditPath, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Outcome != "ready" || exported.Chain.Status != "verified" || exported.Chain.Verified != writers || len(exported.Events) != writers {
		t.Fatalf("concurrent chain = %#v", exported)
	}
	operational, err := buildEventsResponse(defaultEventsPath(auditPath), eventFilters{Limit: writers})
	if err != nil {
		t.Fatal(err)
	}
	if operational.Outcome != "ready" || len(operational.Events) != writers {
		t.Fatalf("concurrent operational events = %#v", operational)
	}
}

func TestAuditChainSerializesIndependentProcesses(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	const writers = 8
	type helperProcess struct {
		command *exec.Cmd
		output  *bytes.Buffer
	}
	commands := make([]helperProcess, 0, writers)
	for i := 0; i < writers; i++ {
		command := exec.Command(os.Args[0], "-test.run=^TestAuditChainProcessHelper$")
		command.Env = append(os.Environ(),
			"SECRETSBROKER_AUDIT_CHAIN_PROCESS_HELPER=1",
			"SECRETSBROKER_AUDIT_CHAIN_PROCESS_PATH="+auditPath,
			fmt.Sprintf("SECRETSBROKER_AUDIT_CHAIN_PROCESS_INDEX=%d", i),
		)
		output := &bytes.Buffer{}
		command.Stdout = output
		command.Stderr = output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, helperProcess{command: command, output: output})
	}
	for _, process := range commands {
		if err := process.command.Wait(); err != nil {
			t.Fatalf("helper failed: %v: %s", err, process.output.String())
		}
	}
	exported, err := exportAuditEvents(auditPath, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Outcome != "ready" || exported.Chain.Status != "verified" || exported.Chain.Verified != writers || len(exported.Events) != writers {
		t.Fatalf("cross-process chain = %#v", exported)
	}
}

func TestAuditChainProcessHelper(t *testing.T) {
	if os.Getenv("SECRETSBROKER_AUDIT_CHAIN_PROCESS_HELPER") != "1" {
		return
	}
	index := os.Getenv("SECRETSBROKER_AUDIT_CHAIN_PROCESS_INDEX")
	backend := newLocalBackend("", os.Getenv("SECRETSBROKER_AUDIT_CHAIN_PROCESS_PATH"), "")
	backend.auditHashChain = true
	if err := backend.audit("process_write", "services/test/ref-"+index, "ready", "test", "request-"+index); err != nil {
		t.Fatal(err)
	}
}

func TestAuditChainIsStickyAndCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	chained := newLocalBackend(filepath.Join(dir, "store.json"), auditPath, "test-master-key")
	chained.auditHashChain = true
	if err := chained.audit("key_initialize", "", "ready", "@operator", "request-1"); err != nil {
		t.Fatal(err)
	}

	writerWithoutFlag := newLocalBackend(filepath.Join(dir, "store.json"), auditPath, "test-master-key")
	if err := writerWithoutFlag.audit("backup_create", "", "ready", "@operator", "request-2"); err != nil {
		t.Fatal(err)
	}
	exported, err := exportAuditEvents(auditPath, "", "", false)
	if err != nil || exported.Chain.Status != "verified" || exported.Chain.Verified != 2 {
		t.Fatalf("sticky chain = %#v err=%v", exported, err)
	}

	file, err := os.OpenFile(auditPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"operation":"tampered"}`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := chained.audit("key_rotate", "", "ready", "@operator", "request-3"); !errors.Is(err, errAuditChainInvalid) {
		t.Fatalf("corrupt-tail append err = %v", err)
	}
	if _, err := exportAuditEvents(auditPath, "", "", false); !errors.Is(err, errBackendDegraded) {
		t.Fatalf("corrupt-tail export err = %v", err)
	}
}

func TestAuditExportVerifiesCompleteLogBeforeFiltering(t *testing.T) {
	backend := testBackend(t)
	backend.auditHashChain = true
	for i, operation := range []string{"key_initialize", "backup_create", "key_rotate"} {
		if err := backend.audit(operation, "", "ready", "@operator", fmt.Sprintf("request-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := exportAuditEvents(backend.auditPath, "backup_create", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Chain.Status != "verified" || exported.Chain.Verified != 3 || len(exported.Events) != 1 || exported.Events[0].Operation != "backup_create" {
		t.Fatalf("filtered export = %#v", exported)
	}
}

func TestLegacyPrefixIsExplicitlyDegradedAndPostChainGapIsInvalid(t *testing.T) {
	backend := testBackend(t)
	if err := backend.audit("legacy", "", "ready", "@operator", "legacy-1"); err != nil {
		t.Fatal(err)
	}
	backend.auditHashChain = true
	if err := backend.audit("chained", "", "ready", "@operator", "chain-1"); err != nil {
		t.Fatal(err)
	}
	exported, err := exportAuditEvents(backend.auditPath, "", "", false)
	if err != nil || exported.Outcome != "degraded" || exported.Chain.Status != "partial" || exported.Chain.Unchecked != 1 || exported.Chain.Verified != 1 {
		t.Fatalf("legacy prefix = %#v err=%v", exported, err)
	}

	file, err := os.OpenFile(backend.auditPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{\"ts\":\"2026-08-14T00:00:00Z\",\"operation\":\"gap\",\"outcome\":\"ready\"}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	exported, err = exportAuditEvents(backend.auditPath, "", "", false)
	if err != nil || exported.Outcome != "degraded" || exported.Chain.Status != "invalid" || exported.Chain.Failed == 0 {
		t.Fatalf("post-chain gap = %#v err=%v", exported, err)
	}
}

func TestPrivilegedCLICommandsHonorSharedAuditChainEnvironment(t *testing.T) {
	t.Setenv("SECRETSBROKER_AUDIT_HASH_CHAIN", "1")
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store.json")
	key := lifecycleTestKey(71)
	nextKey := lifecycleTestKey(72)

	initAudit := filepath.Join(dir, "init-audit.jsonl")
	if err := runCommandSilently(func() error {
		return runKeyInitialize([]string{"--store", storePath, "--audit", initAudit, "--master-key", key})
	}); err != nil {
		t.Fatal(err)
	}
	assertAuditOperationVerified(t, initAudit, "key_initialize")

	unlockAudit := filepath.Join(dir, "unlock-audit.jsonl")
	if err := runCommandSilently(func() error {
		return runKeyUnlock([]string{"--store", storePath, "--audit", unlockAudit, "--master-key", key})
	}); err != nil {
		t.Fatal(err)
	}
	assertAuditOperationVerified(t, unlockAudit, "key_unlock")

	backupPath := filepath.Join(dir, "backup.json")
	backupAudit := filepath.Join(dir, "backup-audit.jsonl")
	if err := runCommandSilently(func() error {
		return runBackupCreate([]string{"--store", storePath, "--audit", backupAudit, "--master-key", key, "--out", backupPath})
	}); err != nil {
		t.Fatal(err)
	}
	assertAuditOperationVerified(t, backupAudit, "backup_create")

	restoreAudit := filepath.Join(dir, "restore-audit.jsonl")
	if err := runCommandSilently(func() error {
		return runBackupRestore([]string{"--store", filepath.Join(dir, "restored-store.json"), "--audit", restoreAudit, "--master-key", key, "--in", backupPath})
	}); err != nil {
		t.Fatal(err)
	}
	assertAuditOperationVerified(t, restoreAudit, "backup_restore")

	rotateAudit := filepath.Join(dir, "rotate-audit.jsonl")
	if err := runCommandSilently(func() error {
		return runKeyRotate([]string{"--store", storePath, "--audit", rotateAudit, "--master-key", key, "--new-master-key", nextKey})
	}); err != nil {
		t.Fatal(err)
	}
	assertAuditOperationVerified(t, rotateAudit, "key_rotate")

	if runtime.GOOS == "windows" {
		wrapperAudit := filepath.Join(dir, "wrapper-audit.jsonl")
		if err := runCommandSilently(func() error {
			return runKeyImport([]string{"--store", storePath, "--audit", wrapperAudit, "--wrapper", filepath.Join(dir, "wrapper.json"), "--master-key", nextKey, "--os", "windows"})
		}); err != nil {
			t.Fatal(err)
		}
		assertAuditOperationVerified(t, wrapperAudit, "key_import")
	}

	recoveryAudit := filepath.Join(dir, "recovery-audit.jsonl")
	if err := runCommandSilently(func() error {
		return runKeyRecoveryGenerate([]string{"--store", storePath, "--audit", recoveryAudit, "--master-key", nextKey, "--policy-id", "missing-policy", "--threshold", "1", "--share-out", filepath.Join(dir, "share.json")})
	}); err != nil {
		t.Fatal(err)
	}
	assertAuditOperationVerified(t, recoveryAudit, "recovery_share_generate")
}

func assertAuditOperationVerified(t *testing.T, path, operation string) {
	t.Helper()
	exported, err := exportAuditEvents(path, operation, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Outcome != "ready" || exported.Chain.Status != "verified" || exported.Chain.Verified == 0 || len(exported.Events) == 0 {
		t.Fatalf("%s audit = %#v", operation, exported)
	}
}

func runCommandSilently(run func() error) error {
	previous := os.Stdout
	output, err := os.CreateTemp("", "secretsbroker-audit-command-*.json")
	if err != nil {
		return err
	}
	os.Stdout = output
	defer func() {
		os.Stdout = previous
		_ = output.Close()
		_ = os.Remove(output.Name())
	}()
	return run()
}

func TestAuditRecordsNeverContainSensitiveInputs(t *testing.T) {
	backend := testBackend(t)
	backend.auditHashChain = true
	secret := "portable-master-key-secret-token"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "services/api/runtime/token", Value: secret}); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), secret) {
		t.Fatalf("audit leaked sensitive input: %s", string(bytes))
	}
}
