//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsDPAPIWrapperUsesPrivateCurrentUserCustody(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-wrapper")
	storePath := filepath.Join(directory, "store.json")
	auditPath := filepath.Join(directory, "audit.jsonl")
	wrapperPath := filepath.Join(directory, "wrapper.json")
	key := lifecycleTestKey(41)
	backend := newLocalBackend(storePath, auditPath, key)
	if _, err := backend.initializeStore(key); err != nil {
		t.Fatal(err)
	}

	result, err := backend.importOrRewrapMasterKey(wrapperPath, key, wrapperContextFor("windows"), "key_import")
	if err != nil {
		t.Fatal(err)
	}
	if result.Wrapper == nil || result.Wrapper.WrapperKind != "dpapi-user-scope" || result.Wrapper.State != "ready" {
		t.Fatalf("wrapper result = %#v", result)
	}

	raw, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(key)) {
		t.Fatal("wrapper contains portable master key plaintext")
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document["version"] != float64(2) || document["alg"] != windowsDPAPIAlgorithm || document["nonce"] != nil {
		t.Fatalf("wrapper contract = %#v", document)
	}
	provider := windowsDPAPIKeyWrapperProvider{}
	if err := provider.ValidatePath(directory, true); err != nil {
		t.Fatalf("private directory ACL: %v", err)
	}
	if err := provider.ValidatePath(wrapperPath, false); err != nil {
		t.Fatalf("private wrapper ACL: %v", err)
	}
	staleTemp := filepath.Join(directory, ".wrapper.json.crash-residue.tmp")
	if err := os.WriteFile(staleTemp, []byte("dpapi-ciphertext-only-residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.importOrRewrapMasterKey(wrapperPath, key, wrapperContextFor("windows"), "key_rewrap"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staleTemp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale wrapper temp was not removed: %v", err)
	}

	material, err := loadKeyMaterialWithWrapper("", "", wrapperPath)
	if err != nil {
		t.Fatal(err)
	}
	if material.Source != "os-wrapper" || material.Value != key {
		t.Fatalf("wrapper material source=%q keyMatch=%v", material.Source, material.Value == key)
	}

	legacy := localKeyWrapper{Version: 1, ServiceID: serviceID, APIVersion: apiVersion, KeyID: masterKeyID(key), KeyVersion: masterKeyVersion, WrapperKind: "dpapi-user-scope", OS: "windows", User: wrapperContextFor("windows").User, Machine: wrapperContextFor("windows").Machine, Alg: "AES-256-GCM", Ciphertext: base64.StdEncoding.EncodeToString([]byte("legacy")), CreatedAt: time.Now(), UpdatedAt: time.Now()}
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(directory, "legacy-wrapper.json")
	if err := os.WriteFile(legacyPath, legacyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provider.SecurePath(legacyPath, false); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKeyMaterialWithWrapper("", "", legacyPath); !errors.Is(err, errLegacyWrapper) {
		t.Fatalf("legacy wrapper error = %v", err)
	}
}

func TestWindowsDPAPIWrapperRejectsBroadACLAndReparseTraversal(t *testing.T) {
	provider := windowsDPAPIKeyWrapperProvider{}
	broadDirectory := filepath.Join(t.TempDir(), "broad")
	if err := os.MkdirAll(broadDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	broadFile := filepath.Join(broadDirectory, "wrapper.json")
	if err := os.WriteFile(broadFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provider.ValidatePath(broadFile, false); !errors.Is(err, errWrapperAccess) {
		t.Fatalf("broad inherited ACL validation error = %v", err)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	targetFile := filepath.Join(target, "wrapper.json")
	if err := os.WriteFile(targetFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "wrapper-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symlink creation unavailable: %v", err)
	}
	if err := provider.ValidatePath(filepath.Join(link, "wrapper.json"), false); !errors.Is(err, errWrapperAccess) {
		t.Fatalf("reparse traversal validation error = %v", err)
	}
}

func TestWindowsDPAPIWrapperSecuresRepositoryLocalDirectory(t *testing.T) {
	base := filepath.Join(".tmp", "test")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(base, "dpapi-provider-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.WriteFile(filepath.Join(directory, "existing-store.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := windowsDPAPIKeyWrapperProvider{}
	if err := provider.SecurePath(directory, true); err != nil {
		t.Fatalf("secure repository-local directory: %T %v", err, err)
	}
	if err := provider.ValidatePath(directory, true); err != nil {
		t.Fatalf("validate repository-local directory: %T %v", err, err)
	}
}

func TestWindowsDPAPIWrapperOnlyBrokerRestartResolvesSecret(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-wrapper-restart")
	storePath := filepath.Join(directory, "store.json")
	auditPath := filepath.Join(directory, "audit.jsonl")
	eventsPath := filepath.Join(directory, "events.jsonl")
	wrapperPath := filepath.Join(directory, "wrapper.json")
	logPath := filepath.Join(t.TempDir(), "broker.log")
	key := lifecycleTestKey(42)
	secretValue := "dpapi-wrapper-restart-secret-sentinel"
	backend := newLocalBackend(storePath, auditPath, key)
	if _, err := backend.initializeStore(key); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.writeSecret(writeSecretRequest{Ref: "services/wrapper-test/API_TOKEN", Value: secretValue}); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.importOrRewrapMasterKey(wrapperPath, key, wrapperContextFor("windows"), "key_import"); err != nil {
		t.Fatal(err)
	}

	address := freeWrapperTestAddress(t)
	command := startWrapperOnlyBrokerProcess(t, address, storePath, auditPath, eventsPath, wrapperPath, logPath)
	lease := testLaunchIdentityLease(t, backend, "wrapper-test", []string{"services/wrapper-test/*"}, nil, []string{"resolve"}, "jti-dpapi-wrapper-restart")
	body := []byte(`{"requestId":"req-dpapi-wrapper","serviceId":"wrapper-test","identityLease":` + mustLeaseJSON(t, lease) + `,"refs":["services/wrapper-test/API_TOKEN"]}`)
	request, err := http.NewRequest(http.MethodPost, "http://"+address+"/v1/resolve", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-SecretsBroker-Token", "test-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	payload, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte(secretValue)) {
		t.Fatalf("resolve status=%d payload=%s", response.StatusCode, payload)
	}
	stopWrapperOnlyBrokerProcess(t, command)

	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{wrapperPath, storePath, auditPath, eventsPath, logPath} {
		content, readErr := os.ReadFile(path)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if bytes.Contains(content, []byte(secretValue)) {
			t.Fatalf("secret leaked to %s", filepath.Base(path))
		}
		if bytes.Contains(content, []byte(key)) {
			t.Fatalf("portable key leaked to %s", filepath.Base(path))
		}
	}
	if bytes.Contains(logBytes, []byte(secretValue)) || bytes.Contains(logBytes, []byte(key)) {
		t.Fatal("broker log leaked secret or portable key")
	}
}

func TestWindowsDPAPIWrapperCorruptionFailsClosed(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-wrapper-corrupt")
	wrapperPath := filepath.Join(directory, "wrapper.json")
	key := lifecycleTestKey(43)
	backend := newLocalBackend(filepath.Join(directory, "store.json"), filepath.Join(directory, "audit.jsonl"), key)
	if _, err := backend.initializeStore(key); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.importOrRewrapMasterKey(wrapperPath, key, wrapperContextFor("windows"), "key_import"); err != nil {
		t.Fatal(err)
	}
	wrapper, err := readLocalKeyWrapper(wrapperPath)
	if err != nil {
		t.Fatal(err)
	}
	wrapper.Ciphertext = base64.StdEncoding.EncodeToString([]byte("corrupted-dpapi-payload"))
	bytes, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapperPath, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	provider := windowsDPAPIKeyWrapperProvider{}
	if err := provider.SecurePath(wrapperPath, false); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKeyMaterialWithWrapper("", "", wrapperPath); !errors.Is(err, errWrapperUnavailable) {
		t.Fatalf("corrupted wrapper error = %v", err)
	}
	detail := wrapperStatus(wrapperPath, wrapperContextFor("windows"))
	if detail.State != "degraded" || detail.FailureReason != "wrapper cannot be decrypted by the current user" {
		t.Fatalf("corrupted wrapper status = %#v", detail)
	}
}

func TestWindowsDPAPIWrapperProcessHelper(t *testing.T) {
	if os.Getenv("SECRETSBROKER_DPAPI_PROCESS_HELPER") != "1" {
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
		os.Exit(2)
	}
	if err := serve(os.Args[separator+1:]); err != nil {
		os.Exit(3)
	}
}

func startWrapperOnlyBrokerProcess(t *testing.T, address, storePath, auditPath, eventsPath, wrapperPath, logPath string) *exec.Cmd {
	t.Helper()
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestWindowsDPAPIWrapperProcessHelper$", "--", "--listen", address, "--mode", "development", "--transport", "loopback-http", "--state", "ready", "--store", storePath, "--audit", auditPath, "--events", eventsPath, "--wrapper", wrapperPath, "--api-token", "test-token")
	command.Env = []string{"SECRETSBROKER_DPAPI_PROCESS_HELPER=1"}
	for _, entry := range os.Environ() {
		upper := strings.ToUpper(entry)
		if strings.HasPrefix(upper, "SECRETSBROKER_MASTER_KEY=") || strings.HasPrefix(upper, "SECRETSBROKER_MASTER_KEY_FILE=") || strings.HasPrefix(upper, "SECRETSBROKER_WRAPPER_PATH=") || strings.HasPrefix(upper, "SECRETSBROKER_DPAPI_PROCESS_HELPER=") {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	_ = logFile.Close()
	t.Cleanup(func() { stopWrapperOnlyBrokerProcess(t, command) })
	client := &http.Client{Timeout: 250 * time.Millisecond, Transport: &http.Transport{DisableKeepAlives: true}}
	deadline := time.Now().Add(15 * time.Second)
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
	logBytes, _ := os.ReadFile(logPath)
	t.Fatalf("wrapper-only broker did not become ready: %s", logBytes)
	return nil
}

func stopWrapperOnlyBrokerProcess(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if command == nil || command.ProcessState != nil {
		return
	}
	_ = command.Process.Kill()
	_, _ = command.Process.Wait()
}

func freeWrapperTestAddress(t *testing.T) string {
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
