package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const mcpAdapterSecretValue = "fixture-mcp-adapter-secret-value"

func TestAdminMCPToolsExposeReadOnlyAndDisabledBoundaries(t *testing.T) {
	var out bytes.Buffer
	if err := executeAdmin([]string{"mcp", "tools"}, &out); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, out.Bytes(), mcpAdapterSecretValue, "test-master-key")

	var res mcpToolsResponse
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.ProtocolVersion != mcpProtocolVersion || !res.Safety.MetadataOnly || res.Safety.ValueMaterialIncluded || res.Safety.MutatingToolsEnabled {
		t.Fatalf("unexpected MCP tools response safety/version: %#v", res)
	}
	if !mcpToolNamed(res.Tools, "secretsbroker.status") || !mcpToolNamed(res.Tools, "secretsbroker.secrets.reveal") {
		t.Fatalf("expected read-only and disabled tools in response: %#v", res.Tools)
	}
}

func TestAdminMCPMetadataCallsDoNotExposeSecretValues(t *testing.T) {
	backend := managedTestBackend(t)
	ref := "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
	writeManagedTestSecret(t, backend, ref, mcpAdapterSecretValue)
	if err := backend.audit("policy_decision", ref, "policy_denied", "@serviceadmin", "mcp-req-1"); err != nil {
		t.Fatal(err)
	}

	var list bytes.Buffer
	if err := executeAdmin([]string{"mcp", "call", "--tool", "secretsbroker.secrets.metadata.list", "--query", "SESSION", "--store", backend.storePath, "--audit", backend.auditPath, "--events", backend.eventPath, "--master-key", "test-master-key"}, &list); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, list.Bytes(), mcpAdapterSecretValue, "test-master-key")
	if !bytes.Contains(list.Bytes(), []byte("SESSION_SIGNING_KEY")) {
		t.Fatalf("metadata list missing safe ref metadata: %s", list.String())
	}
	var listRes mcpToolCallResponse
	if err := json.Unmarshal(list.Bytes(), &listRes); err != nil {
		t.Fatal(err)
	}
	if listRes.IsError || !listRes.Safety.MetadataOnly || listRes.Safety.ValueMaterialIncluded {
		t.Fatalf("unsafe metadata call response: %#v", listRes)
	}

	var events bytes.Buffer
	if err := executeAdmin([]string{"mcp", "call", "--tool", "secretsbroker.events.list", "--family", "policy_decision", "--limit", "5", "--events", backend.eventPath}, &events); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, events.Bytes(), mcpAdapterSecretValue, "test-master-key", ref)
	if strings.Contains(events.String(), ref) {
		t.Fatalf("MCP events exposed raw ref: %s", events.String())
	}
}

func TestAdminMCPSecretBearingToolsReturnUnsupported(t *testing.T) {
	var out bytes.Buffer
	if err := executeAdmin([]string{"mcp", "call", "--tool", "secretsbroker.secrets.reveal"}, &out); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, out.Bytes(), mcpAdapterSecretValue, "test-master-key")
	if !bytes.Contains(out.Bytes(), []byte("unsupported")) {
		t.Fatalf("disabled tool response missing unsupported outcome: %s", out.String())
	}
	var res mcpToolCallResponse
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !res.Safety.MetadataOnly || res.Safety.MutatingToolsEnabled {
		t.Fatalf("disabled tool did not fail closed: %#v", res)
	}
}

func mcpToolNamed(tools []mcpToolDefinition, name string) bool {
	for _, tool := range tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}
