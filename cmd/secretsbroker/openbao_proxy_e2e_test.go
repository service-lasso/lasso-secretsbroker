package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestOpenBaoProxyE2E proves the KV v2 facade proxies into a real OpenBao
// backend. It is skipped unless OPENBAO_E2E_BIN points at a bao binary;
// scripts/verify-openbao-proxy-e2e.* acquire the pinned binary and set it.
func TestOpenBaoProxyE2E(t *testing.T) {
	bin := strings.TrimSpace(os.Getenv("OPENBAO_E2E_BIN"))
	if bin == "" {
		t.Skip("set OPENBAO_E2E_BIN to a bao binary to run the OpenBao proxy e2e")
	}

	const remoteToken = "root"
	const sentinel = "kv-sentinel-e2e-alpha"

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	server := exec.Command(bin, "server", "-dev", "-dev-root-token-id="+remoteToken, "-dev-listen-address="+addr, "-dev-no-store-token")
	server.Stdout = os.Stderr
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatalf("start OpenBao: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_, _ = server.Process.Wait()
	})

	base := "http://" + addr
	waitForOpenBao(t, base)

	seed := []byte(`{"data":{"password":"` + sentinel + `"}}`)
	req, err := http.NewRequest(http.MethodPost, base+"/v1/secret/data/apps/db", bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", remoteToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("seed OpenBao: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		t.Fatalf("seed OpenBao status=%d", res.StatusCode)
	}

	backend := testBackend(t)
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{
		SourceID: "openbao-dev",
		Kind:     "openbao",
		Enabled:  true,
		Address:  base,
		Token:    remoteToken,
		Mount:    "secret",
		Refs: map[string]sourceRefConfig{
			"apps/db":      {Path: "secret/data/apps/db", Field: "password"},
			"apps/missing": {Path: "secret/data/apps/missing", Field: "password"},
		},
	}}}
	for _, item := range []struct{ ref, value string }{
		{ref: "apps/db", value: "local-sentinel"},
		{ref: "apps/missing", value: "local-missing"},
	} {
		if _, err := backend.writeSecret(writeSecretRequest{Ref: item.ref, Value: item.value}); err != nil {
			t.Fatal(err)
		}
	}
	state := "ready"
	broker := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer broker.Close()

	got := kvDo(t, broker, http.MethodGet, "/v1/kv/data/apps/db?source=openbao-dev", nil)
	payload := kvRead(t, got)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("proxy get status=%d body=%s", got.StatusCode, payload)
	}
	if !strings.Contains(string(payload), sentinel) {
		t.Fatalf("proxy get missing proxied value: %s", payload)
	}

	listed := kvDo(t, broker, http.MethodGet, "/v1/kv/metadata/?list=true&source=openbao-dev", nil)
	listPayload := kvRead(t, listed)
	if listed.StatusCode != http.StatusOK {
		t.Fatalf("proxy list status=%d body=%s", listed.StatusCode, listPayload)
	}
	if !strings.Contains(string(listPayload), "apps/") {
		t.Fatalf("proxy list missing apps/: %s", listPayload)
	}

	openBaoFirst := backend.resolve(resolveRequest{Refs: []string{"apps/db"}, RequestID: "e2e-openbao-first"})
	if len(openBaoFirst.Results) != 1 {
		t.Fatalf("OpenBao-first results = %#v", openBaoFirst.Results)
	}
	first := openBaoFirst.Results[0]
	if first.Outcome != "ready" || first.Value != sentinel || first.Metadata == nil || first.Metadata.SourceID != "openbao-dev" {
		t.Fatalf("OpenBao-first resolve = %#v", first)
	}

	failClosed := backend.resolve(resolveRequest{Refs: []string{"apps/missing"}, RequestID: "e2e-openbao-missing"})
	if len(failClosed.Results) != 1 {
		t.Fatalf("OpenBao missing results = %#v", failClosed.Results)
	}
	missing := failClosed.Results[0]
	if missing.Outcome != "missing_ref" || missing.Value != "" || missing.Metadata != nil {
		t.Fatalf("OpenBao missing resolve = %#v", missing)
	}

	defaultRead := kvDo(t, broker, http.MethodGet, "/v1/kv/data/apps/db", nil)
	defaultPayload := kvRead(t, defaultRead)
	if defaultRead.StatusCode != http.StatusOK || !bytes.Contains(defaultPayload, []byte(sentinel)) || bytes.Contains(defaultPayload, []byte("local-sentinel")) {
		t.Fatalf("default KV read did not use OpenBao: status=%d body=%s", defaultRead.StatusCode, defaultPayload)
	}

	localRead := kvDo(t, broker, http.MethodGet, "/v1/kv/data/apps/db?source=local", nil)
	localPayload := kvRead(t, localRead)
	if localRead.StatusCode != http.StatusOK || !bytes.Contains(localPayload, []byte("local-sentinel")) || bytes.Contains(localPayload, []byte(sentinel)) {
		t.Fatalf("explicit local KV read did not use local store: status=%d body=%s", localRead.StatusCode, localPayload)
	}

	write := kvDo(t, broker, http.MethodPost, "/v1/kv/data/apps/written", []byte(`{"data":{"password":"broker-written"}}`))
	if write.StatusCode != http.StatusOK {
		t.Fatalf("default KV write status=%d body=%s", write.StatusCode, kvRead(t, write))
	}
	directReq, err := http.NewRequest(http.MethodGet, base+"/v1/secret/data/apps/written", nil)
	if err != nil {
		t.Fatal(err)
	}
	directReq.Header.Set("X-Vault-Token", remoteToken)
	directRes, err := http.DefaultClient.Do(directReq)
	if err != nil {
		t.Fatal(err)
	}
	defer directRes.Body.Close()
	directPayload, err := io.ReadAll(directRes.Body)
	if err != nil {
		t.Fatal(err)
	}
	if directRes.StatusCode != http.StatusOK || !bytes.Contains(directPayload, []byte("broker-written")) {
		t.Fatalf("default KV write did not reach OpenBao: status=%d body=%s", directRes.StatusCode, directPayload)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForOpenBao(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(base + "/v1/sys/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("OpenBao dev server did not become ready")
}
