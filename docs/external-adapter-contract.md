# External source adapter contract

Secrets Broker adapters expose secret values to the broker resolution path, but all operator-facing surfaces must remain metadata-only. Adapter diagnostics, status APIs, audit events, issue comments, PR bodies, logs, and fixtures must not contain raw credentials or secret values.

## Base contract

Each adapter family must define:

- `kind`: stable source kind used in config and status output.
- `capabilities`: whether the source supports read, reveal, write/update, rotate/reset, policy checks, value search, audit, or migration.
- `authModel`: how the adapter authenticates without persisting raw credential material in broker diagnostics.
- `reconnectModel`: how an operator recovers expired auth, locked stores, unavailable sources, or degraded state.
- `failureStates`: normalized broker outcomes such as `source_auth_required`, `identity_expired`, `policy_denied`, `missing_ref`, `source_unavailable`, `locked`, `degraded`, and `invalid_ref`.
- `defaultTimeoutMs` and `maxOutputBytes`: bounded execution/response limits.
- `diagnostics`: allowlisted metadata fields and forbidden raw-value fields.
- `fixturePolicy`: deterministic fake values only.

The implementation scaffold is `cmd/secretsbroker/adapter_contract.go`.

## Capability matrix

| Adapter family | read | reveal | write/update | rotate/reset | policy | value search | audit | migration |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Local encrypted store | yes | yes | yes | yes | no | no | yes | yes |
| Vault/OpenBao | yes | yes | yes | yes | yes | no | yes | yes |
| AWS Secrets Manager | yes | yes | yes | yes | yes | yes | yes | yes |
| 1Password CLI | yes | yes | no | no | no | no | yes | yes |
| Bitwarden/BWS | yes | yes | yes | no | no | no | yes | yes |
| env source | yes | yes | no | no | no | no | no | yes |
| file source | yes | yes | no | no | no | no | no | yes |
| exec source | yes | yes | no | no | no | no | yes | yes |

## Metadata-only diagnostics

Allowed diagnostic fields:

- source kind and source id
- secret ref identifier
- normalized state/outcome
- retryable flag and retry-after metadata
- next action code
- capability name
- message code

Forbidden fields/markers:

- raw `value`
- `secret`, `token`, `password`, `privateKey`, or `credential` material
- raw command output such as stdout/stderr
- provider response bodies that can contain values

Adapters should convert provider-specific errors into normalized outcomes. Examples:

- expired Vault token -> `source_auth_required`
- sealed Vault/OpenBao -> `locked`
- missing AWS secret id -> `missing_ref`
- AWS access denied -> `policy_denied`
- 1Password CLI not signed in -> `source_auth_required`
- file missing or unreadable -> `source_unavailable`
- untrusted exec command -> `invalid_ref`

## Timeout and output limits

Adapters must be bounded:

- network/provider requests use finite timeouts
- command adapters run with context deadlines
- file/provider/exec outputs have explicit max byte limits
- outputs over the configured limit fail closed as `source_unavailable`
- diagnostics should report only the limit and outcome, not captured content

## Fixture policy

Tests must use fake deterministic material only. Fixtures can include fake sentinel values inside contained inputs to prove detection, but generated outputs and diagnostics must pass the no-leak harness.

Recommended fixtures:

- local encrypted store: temp store with fake values
- Vault/OpenBao: `httptest` server returning fake JSON values
- AWS Secrets Manager: mocked SDK responses with fake secret strings
- 1Password CLI: fake executable implementing a minimal JSON protocol
- Bitwarden/BWS: fake API/CLI output with fake strings
- env: `t.Setenv` with fake values
- file: temp files with fake values
- exec: trusted temp executable returning fake protocol output

## Follow-up adapter issues

This plan issue creates separate implementation issues for each family so each adapter can be built, tested, and reviewed independently:

- local encrypted store baseline: #46
- Vault/OpenBao: #47
- AWS Secrets Manager: #48
- 1Password CLI: #49
- Bitwarden/BWS: #50
- env source: #51
- file source: #52
- exec source: #53
