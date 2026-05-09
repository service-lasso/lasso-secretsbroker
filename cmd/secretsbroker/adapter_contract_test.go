package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExternalAdapterContractsCoverRequiredFamilies(t *testing.T) {
	contracts := adapterContractsByKind()
	required := []string{
		"local-encrypted-store",
		"vault-openbao",
		"aws-secrets-manager",
		"onepassword-cli",
		"bitwarden-bws",
		"env",
		"file",
		"exec",
	}
	for _, kind := range required {
		contract, ok := contracts[kind]
		if !ok {
			t.Fatalf("missing adapter contract for %s", kind)
		}
		if !adapterHasCapability(contract, AdapterCapabilityRead) {
			t.Fatalf("%s should declare read capability: %#v", kind, contract.Capabilities)
		}
		if contract.DisplayName == "" || contract.AuthModel == "" || contract.ReconnectModel == "" || len(contract.FailureStates) == 0 {
			t.Fatalf("%s contract is incomplete: %#v", kind, contract)
		}
		if contract.FixturePolicy == "" || !strings.Contains(strings.ToLower(contract.FixturePolicy), "fake") {
			t.Fatalf("%s fixture policy must require fake values: %q", kind, contract.FixturePolicy)
		}
	}
}

func TestAdapterContractsReportExpectedCapabilityMatrix(t *testing.T) {
	contracts := adapterContractsByKind()

	if !adapterHasCapability(contracts["vault-openbao"], AdapterCapabilityPolicy) || !adapterHasCapability(contracts["vault-openbao"], AdapterCapabilityRotate) {
		t.Fatalf("vault/openbao capabilities = %#v", contracts["vault-openbao"].Capabilities)
	}
	if adapterHasCapability(contracts["env"], AdapterCapabilityWrite) || adapterHasCapability(contracts["file"], AdapterCapabilityRotate) {
		t.Fatalf("env/file should stay read/reveal/migration only")
	}
	if !adapterHasCapability(contracts["aws-secrets-manager"], AdapterCapabilityValueSearch) {
		t.Fatalf("aws capability names = %#v", adapterCapabilityNames(contracts["aws-secrets-manager"].Capabilities))
	}
}

func TestAdapterDiagnosticsAreMetadataOnly(t *testing.T) {
	source := sourceConfig{SourceID: "vault-prod", Kind: "vault-openbao"}
	diagnostic := buildAdapterDiagnostic(source, "api/DB_PASSWORD", AdapterCapabilityRead, normalizeSourceLifecycle("source_auth_required"))
	payload, err := json.Marshal(diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, payload, "SERVICE_LASSO_FAKE_SECRET_SENTINEL_TOKEN_DO_NOT_USE")
	var diagnosticFields map[string]any
	if err := json.Unmarshal(payload, &diagnosticFields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range defaultAdapterDiagnosticsSpec().ForbiddenFields {
		if _, ok := diagnosticFields[forbidden]; ok {
			t.Fatalf("diagnostic contains forbidden field %q: %s", forbidden, payload)
		}
	}
	if !strings.Contains(string(payload), "api/DB_PASSWORD") || strings.Contains(string(payload), "token") {
		t.Fatalf("diagnostic should include ref metadata only: %s", payload)
	}
}

func TestAdapterContractLookupNormalizesKinds(t *testing.T) {
	contract, ok := adapterContractForKind(" Vault-OpenBao ")
	if !ok || contract.Kind != "vault-openbao" {
		t.Fatalf("lookup result = %#v ok=%v", contract, ok)
	}
}
