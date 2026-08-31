package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSourceRegistryReflectsLocalKeyState(t *testing.T) {
	locked := defaultSourceRegistry(newLocalBackend("store.json", "audit.jsonl", ""))
	if len(locked.Sources) != 1 {
		t.Fatalf("sources = %d", len(locked.Sources))
	}
	if locked.Sources[0].SourceID != "local" || locked.Sources[0].State != "reconnect_required" || locked.Sources[0].Outcome != "locked" {
		t.Fatalf("locked source = %#v", locked.Sources[0])
	}
	assertContains(t, locked.Sources[0].Capabilities, "read")
	assertContains(t, locked.Sources[0].Capabilities, "reveal")
	assertContains(t, locked.Sources[0].Capabilities, "write/update")
	assertContains(t, locked.Sources[0].Capabilities, "rotate/reset")
	assertContains(t, locked.Sources[0].Capabilities, "audit")
	assertContains(t, locked.Sources[0].Capabilities, "migration")
	assertContains(t, locked.Sources[0].Capabilities, "health")
	assertNotContains(t, locked.Sources[0].Capabilities, "policy")
	assertNotContains(t, locked.Sources[0].Capabilities, "value-search")
	assertContains(t, locked.Sources[0].Namespaces, "*")

	ready := defaultSourceRegistry(newLocalBackend("store.json", "audit.jsonl", "master-key"))
	if ready.Sources[0].State != "connected" || ready.Sources[0].Outcome != "ready" {
		t.Fatalf("ready source = %#v", ready.Sources[0])
	}
}

func TestLocalEncryptedStoreSourceStatusUsesAdapterContractCapabilities(t *testing.T) {
	caps := capabilitiesForSourceKind("local-encrypted-store")
	for _, capability := range []string{"read", "reveal", "write/update", "rotate/reset", "audit", "migration", "health"} {
		assertContains(t, caps, capability)
	}
	for _, capability := range []string{"policy", "value-search"} {
		assertNotContains(t, caps, capability)
	}
}

func TestSourceRegistryMapsVaultAuthStateWithoutTokenLeak(t *testing.T) {
	backend := newLocalBackend("store.json", "audit.jsonl", "master-key")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{
		{SourceID: "vault-prod", Kind: "vault", DisplayName: "Vault prod", Enabled: true, Address: "https://vault.example.com", TokenEnv: "MISSING_VAULT_TOKEN", Namespaces: []string{"prod/*"}},
	}}

	registry := defaultSourceRegistry(backend)
	if len(registry.Sources) != 2 {
		t.Fatalf("sources = %#v", registry.Sources)
	}
	vault := registry.Sources[1]
	if vault.SourceID != "vault-prod" || vault.State != "auth_required" || vault.Outcome != "source_auth_required" {
		t.Fatalf("vault source = %#v", vault)
	}
	assertContains(t, vault.Capabilities, "read")
	assertContains(t, vault.Capabilities, "reveal")
	assertContains(t, vault.Capabilities, "write/update")
	assertContains(t, vault.Capabilities, "rotate/reset")
	assertContains(t, vault.Capabilities, "policy")
	assertContains(t, vault.Capabilities, "audit")
	assertContains(t, vault.Capabilities, "migration")
	assertContains(t, vault.Capabilities, "health")
	assertNotContains(t, vault.Capabilities, "value-search")
	assertContains(t, vault.Namespaces, "prod/*")
	assertNoSecretMaterial(t, mustManagedJSON(t, registry), "MISSING_VAULT_TOKEN")
}

func TestVaultOpenBaoCapabilitiesUseAdapterContract(t *testing.T) {
	for _, kind := range []string{"vault", "openbao"} {
		t.Run(kind, func(t *testing.T) {
			caps := capabilitiesForSourceKind(kind)
			for _, capability := range []string{"read", "reveal", "write/update", "rotate/reset", "policy", "audit", "migration", "health"} {
				assertContains(t, caps, capability)
			}
			assertNotContains(t, caps, "value-search")
		})
	}
}

func TestSourceStatusEndpointDoesNotRequireSecretToken(t *testing.T) {
	backend := newLocalBackend("store.json", "audit.jsonl", "master-key")
	backend.sources = sourceConfigFile{Sources: []sourceConfig{{SourceID: "disabled-source", Kind: "env", Enabled: false, Refs: map[string]sourceRefConfig{"disabled/ref": {Env: "SHOULD_NOT_LEAK"}}}}}
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{}))
	defer server.Close()

	res, err := http.Get(server.URL + "/v1/sources/status")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var body sourceStatusResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sources) != 2 || body.Sources[0].SourceID != "local" || body.Sources[0].State != "connected" || body.Sources[0].Outcome != "ready" {
		t.Fatalf("body = %#v", body)
	}
	if body.Sources[1].SourceID != "disabled-source" || body.Sources[1].State != "disabled" || body.Sources[1].NextAction != "enable_source" {
		t.Fatalf("disabled body = %#v", body.Sources[1])
	}
}

func TestSourceConfigSecurityFlagsBroadPortableModes(t *testing.T) {
	unsafe := classifySourceConfigMode(0o644, "linux")
	if unsafe.Outcome != "degraded" || unsafe.State != "broad_access" || !unsafe.BroadReadable || unsafe.BroadWritable {
		t.Fatalf("unsafe mode = %#v", unsafe)
	}
	writable := classifySourceConfigMode(0o666, "linux")
	if writable.Outcome != "degraded" || !writable.BroadReadable || !writable.BroadWritable {
		t.Fatalf("writable mode = %#v", writable)
	}
	protected := classifySourceConfigMode(0o600, "linux")
	if protected.Outcome != "ready" || protected.State != "protected" || protected.BroadReadable || protected.BroadWritable {
		t.Fatalf("protected mode = %#v", protected)
	}
	windows := classifySourceConfigMode(0o666, "windows")
	if windows.Outcome != "not_verified" || windows.NextAction != "review_os_acl" {
		t.Fatalf("windows mode = %#v", windows)
	}
}

func TestSourceConfigSecurityStatusDoesNotExposeConfigPathOrSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sources.json")
	config := `{"sources":[{"sourceId":"vault-prod","kind":"vault","enabled":true,"address":"https://vault.example.invalid","token":"SOURCE_CONFIG_TOKEN_SHOULD_NOT_LEAK","refs":{"services/api/runtime/API_TOKEN":{"path":"secret/data/api","field":"token"}}}]}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadSourceConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	backend := newLocalBackend("store.json", "audit.jsonl", "master-key")
	backend.sources = cfg
	registry := defaultSourceRegistry(backend)
	payload := mustManagedJSON(t, registry)
	assertNoSecretMaterial(t, payload, "SOURCE_CONFIG_TOKEN_SHOULD_NOT_LEAK")
	if strings.Contains(string(payload), configPath) {
		t.Fatalf("source config status exposed raw path: %s", payload)
	}
	if registry.SourceConfig.PathHash == "" || registry.SourceConfig.Mode == "" || !registry.SourceConfig.Configured || !registry.SourceConfig.Checked {
		t.Fatalf("source config security missing metadata: %#v", registry.SourceConfig)
	}
}
