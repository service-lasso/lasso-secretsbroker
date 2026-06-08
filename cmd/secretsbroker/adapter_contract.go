package main

import "strings"

type AdapterCapability string

const (
	AdapterCapabilityRead        AdapterCapability = "read"
	AdapterCapabilityReveal      AdapterCapability = "reveal"
	AdapterCapabilityWrite       AdapterCapability = "write/update"
	AdapterCapabilityRotate      AdapterCapability = "rotate/reset"
	AdapterCapabilityPolicy      AdapterCapability = "policy"
	AdapterCapabilityValueSearch AdapterCapability = "value-search"
	AdapterCapabilityAudit       AdapterCapability = "audit"
	AdapterCapabilityMigration   AdapterCapability = "migration"
)

type AdapterAuthModel string

const (
	AdapterAuthLocalKey      AdapterAuthModel = "local-key"
	AdapterAuthToken         AdapterAuthModel = "token"
	AdapterAuthExternalCLI   AdapterAuthModel = "external-cli-session"
	AdapterAuthProcess       AdapterAuthModel = "process-boundary"
	AdapterAuthFilesystem    AdapterAuthModel = "filesystem-policy"
	AdapterAuthEnvironment   AdapterAuthModel = "environment-scope"
	AdapterAuthNotApplicable AdapterAuthModel = "not-applicable"
)

type AdapterFailureState string

const (
	AdapterFailureLocked            AdapterFailureState = "locked"
	AdapterFailureAuthRequired      AdapterFailureState = "source_auth_required"
	AdapterFailureIdentityExpired   AdapterFailureState = "identity_expired"
	AdapterFailurePolicyDenied      AdapterFailureState = "policy_denied"
	AdapterFailureMissingRef        AdapterFailureState = "missing_ref"
	AdapterFailureSourceUnavailable AdapterFailureState = "source_unavailable"
	AdapterFailureDegraded          AdapterFailureState = "degraded"
	AdapterFailureInvalidMapping    AdapterFailureState = "invalid_ref"
)

type AdapterContract struct {
	Kind              string                 `json:"kind"`
	DisplayName       string                 `json:"displayName"`
	Capabilities      []AdapterCapability    `json:"capabilities"`
	AuthModel         AdapterAuthModel       `json:"authModel"`
	ReconnectModel    string                 `json:"reconnectModel"`
	FailureStates     []AdapterFailureState  `json:"failureStates"`
	DefaultTimeoutMs  int                    `json:"defaultTimeoutMs"`
	MaxOutputBytes    int                    `json:"maxOutputBytes"`
	Diagnostics       AdapterDiagnosticsSpec `json:"diagnostics"`
	FixturePolicy     string                 `json:"fixturePolicy"`
	FollowUpIssueHint string                 `json:"followUpIssueHint"`
}

type AdapterDiagnosticsSpec struct {
	SecretSafeFields []string `json:"secretSafeFields"`
	ForbiddenFields  []string `json:"forbiddenFields"`
}

type AdapterDiagnostic struct {
	Kind         string            `json:"kind"`
	SourceID     string            `json:"sourceId"`
	Ref          string            `json:"ref,omitempty"`
	State        string            `json:"state"`
	Outcome      string            `json:"outcome"`
	NextAction   string            `json:"nextAction,omitempty"`
	Retryable    bool              `json:"retryable"`
	RetryAfterMs int               `json:"retryAfterMs,omitempty"`
	Capability   AdapterCapability `json:"capability,omitempty"`
	MessageCode  string            `json:"messageCode,omitempty"`
}

func externalAdapterContracts() []AdapterContract {
	return []AdapterContract{
		{
			Kind:              "local-encrypted-store",
			DisplayName:       "Local encrypted store",
			Capabilities:      []AdapterCapability{AdapterCapabilityRead, AdapterCapabilityReveal, AdapterCapabilityWrite, AdapterCapabilityRotate, AdapterCapabilityAudit, AdapterCapabilityMigration},
			AuthModel:         AdapterAuthLocalKey,
			ReconnectModel:    "unlock portable master key or rewrap local store; never expose key material in diagnostics",
			FailureStates:     []AdapterFailureState{AdapterFailureLocked, AdapterFailureMissingRef, AdapterFailurePolicyDenied, AdapterFailureDegraded},
			DefaultTimeoutMs:  1000,
			MaxOutputBytes:    0,
			Diagnostics:       defaultAdapterDiagnosticsSpec(),
			FixturePolicy:     "fake deterministic values only; no live key material or provider tokens",
			FollowUpIssueHint: "local encrypted store baseline",
		},
		{
			Kind:              "vault-openbao",
			DisplayName:       "Vault/OpenBao",
			Capabilities:      []AdapterCapability{AdapterCapabilityRead, AdapterCapabilityReveal, AdapterCapabilityWrite, AdapterCapabilityRotate, AdapterCapabilityPolicy, AdapterCapabilityAudit, AdapterCapabilityMigration},
			AuthModel:         AdapterAuthToken,
			ReconnectModel:    "refresh or reissue token; sealed backends require unseal outside Service Lasso",
			FailureStates:     []AdapterFailureState{AdapterFailureAuthRequired, AdapterFailureLocked, AdapterFailurePolicyDenied, AdapterFailureMissingRef, AdapterFailureSourceUnavailable, AdapterFailureDegraded, AdapterFailureInvalidMapping},
			DefaultTimeoutMs:  3000,
			MaxOutputBytes:    65536,
			Diagnostics:       defaultAdapterDiagnosticsSpec(),
			FixturePolicy:     "httptest JSON fixtures with fake values only; assert diagnostics omit response values and tokens",
			FollowUpIssueHint: "Vault/OpenBao adapter",
		},
		{
			Kind:              "aws-secrets-manager",
			DisplayName:       "AWS Secrets Manager",
			Capabilities:      []AdapterCapability{AdapterCapabilityRead, AdapterCapabilityReveal, AdapterCapabilityWrite, AdapterCapabilityRotate, AdapterCapabilityPolicy, AdapterCapabilityValueSearch, AdapterCapabilityAudit, AdapterCapabilityMigration},
			AuthModel:         AdapterAuthToken,
			ReconnectModel:    "refresh AWS identity or profile/session; report account/region metadata only",
			FailureStates:     []AdapterFailureState{AdapterFailureAuthRequired, AdapterFailureIdentityExpired, AdapterFailurePolicyDenied, AdapterFailureMissingRef, AdapterFailureSourceUnavailable, AdapterFailureDegraded, AdapterFailureInvalidMapping},
			DefaultTimeoutMs:  5000,
			MaxOutputBytes:    65536,
			Diagnostics:       defaultAdapterDiagnosticsSpec(),
			FixturePolicy:     "mock SDK responses with fake secret strings only; scrub request/response logs",
			FollowUpIssueHint: "AWS Secrets Manager adapter",
		},
		{
			Kind:              "onepassword-cli",
			DisplayName:       "1Password CLI",
			Capabilities:      []AdapterCapability{AdapterCapabilityRead, AdapterCapabilityReveal, AdapterCapabilityAudit, AdapterCapabilityMigration},
			AuthModel:         AdapterAuthExternalCLI,
			ReconnectModel:    "operator signs in or refreshes CLI session outside durable logs",
			FailureStates:     []AdapterFailureState{AdapterFailureAuthRequired, AdapterFailureIdentityExpired, AdapterFailurePolicyDenied, AdapterFailureMissingRef, AdapterFailureSourceUnavailable, AdapterFailureInvalidMapping},
			DefaultTimeoutMs:  5000,
			MaxOutputBytes:    32768,
			Diagnostics:       defaultAdapterDiagnosticsSpec(),
			FixturePolicy:     "fake CLI executable/output protocol only; never run with real account data in tests",
			FollowUpIssueHint: "1Password CLI adapter",
		},
		{
			Kind:              "bitwarden-bws",
			DisplayName:       "Bitwarden/BWS",
			Capabilities:      []AdapterCapability{AdapterCapabilityRead, AdapterCapabilityReveal, AdapterCapabilityWrite, AdapterCapabilityAudit, AdapterCapabilityMigration},
			AuthModel:         AdapterAuthToken,
			ReconnectModel:    "refresh access token or unlock CLI/session; report project/vault ids only",
			FailureStates:     []AdapterFailureState{AdapterFailureAuthRequired, AdapterFailureIdentityExpired, AdapterFailurePolicyDenied, AdapterFailureMissingRef, AdapterFailureSourceUnavailable, AdapterFailureDegraded, AdapterFailureInvalidMapping},
			DefaultTimeoutMs:  5000,
			MaxOutputBytes:    65536,
			Diagnostics:       defaultAdapterDiagnosticsSpec(),
			FixturePolicy:     "fake API/CLI fixtures only; assert token and value strings are absent from diagnostics",
			FollowUpIssueHint: "Bitwarden/BWS adapter",
		},
		{
			Kind:              "env",
			DisplayName:       "Environment source",
			Capabilities:      []AdapterCapability{AdapterCapabilityRead, AdapterCapabilityReveal, AdapterCapabilityMigration},
			AuthModel:         AdapterAuthEnvironment,
			ReconnectModel:    "restart or reconfigure broker process with required environment variables",
			FailureStates:     []AdapterFailureState{AdapterFailureMissingRef, AdapterFailureSourceUnavailable, AdapterFailureInvalidMapping},
			DefaultTimeoutMs:  0,
			MaxOutputBytes:    0,
			Diagnostics:       defaultAdapterDiagnosticsSpec(),
			FixturePolicy:     "test-only environment variables with fake values; diagnostics may include env names only",
			FollowUpIssueHint: "env source adapter",
		},
		{
			Kind:              "file",
			DisplayName:       "File source",
			Capabilities:      []AdapterCapability{AdapterCapabilityRead, AdapterCapabilityReveal, AdapterCapabilityMigration},
			AuthModel:         AdapterAuthFilesystem,
			ReconnectModel:    "fix file path, permissions, mount state, or allowlist policy",
			FailureStates:     []AdapterFailureState{AdapterFailurePolicyDenied, AdapterFailureMissingRef, AdapterFailureSourceUnavailable, AdapterFailureInvalidMapping},
			DefaultTimeoutMs:  0,
			MaxOutputBytes:    65536,
			Diagnostics:       defaultAdapterDiagnosticsSpec(),
			FixturePolicy:     "temporary files containing fake values only; report path metadata without contents",
			FollowUpIssueHint: "file source adapter",
		},
		{
			Kind:              "exec",
			DisplayName:       "Exec source",
			Capabilities:      []AdapterCapability{AdapterCapabilityRead, AdapterCapabilityReveal, AdapterCapabilityAudit, AdapterCapabilityMigration},
			AuthModel:         AdapterAuthProcess,
			ReconnectModel:    "repair trusted command, timeout, output protocol, or external auth backing the command",
			FailureStates:     []AdapterFailureState{AdapterFailureAuthRequired, AdapterFailurePolicyDenied, AdapterFailureMissingRef, AdapterFailureSourceUnavailable, AdapterFailureInvalidMapping},
			DefaultTimeoutMs:  2000,
			MaxOutputBytes:    4096,
			Diagnostics:       defaultAdapterDiagnosticsSpec(),
			FixturePolicy:     "trusted fake executable only; stdout value is consumed but never echoed in diagnostics",
			FollowUpIssueHint: "exec source adapter",
		},
	}
}

func defaultAdapterDiagnosticsSpec() AdapterDiagnosticsSpec {
	return AdapterDiagnosticsSpec{
		SecretSafeFields: []string{"kind", "sourceId", "ref", "state", "outcome", "nextAction", "retryable", "retryAfterMs", "capability", "messageCode"},
		ForbiddenFields:  []string{"value", "secret", "token", "password", "privateKey", "credential", "rawOutput", "stdout", "stderr"},
	}
}

func adapterContractsByKind() map[string]AdapterContract {
	contracts := map[string]AdapterContract{}
	for _, contract := range externalAdapterContracts() {
		contracts[contract.Kind] = contract
	}
	if contract, ok := contracts["vault-openbao"]; ok {
		contracts["vault"] = contract
		contracts["openbao"] = contract
	}
	return contracts
}

func adapterContractForKind(kind string) (AdapterContract, bool) {
	contract, ok := adapterContractsByKind()[strings.ToLower(strings.TrimSpace(kind))]
	return contract, ok
}

func adapterCapabilityNames(capabilities []AdapterCapability) []string {
	names := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		names = append(names, string(capability))
	}
	return names
}

func adapterHasCapability(contract AdapterContract, capability AdapterCapability) bool {
	for _, candidate := range contract.Capabilities {
		if candidate == capability {
			return true
		}
	}
	return false
}

func buildAdapterDiagnostic(source sourceConfig, ref string, capability AdapterCapability, lifecycle SourceLifecycle) AdapterDiagnostic {
	return AdapterDiagnostic{
		Kind:         strings.ToLower(strings.TrimSpace(source.Kind)),
		SourceID:     source.SourceID,
		Ref:          ref,
		State:        lifecycle.State,
		Outcome:      lifecycle.Outcome,
		NextAction:   lifecycle.NextAction,
		Retryable:    lifecycle.Retryable,
		RetryAfterMs: lifecycle.RetryAfterMs,
		Capability:   capability,
		MessageCode:  lifecycle.Outcome,
	}
}
