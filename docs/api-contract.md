# Versioned API contract

Status: canonical local API contract  
Issue: #131

## Purpose

Service Lasso core, Service Admin and other broker clients must consume the same request, response, lifecycle and capability shapes as the Go broker. The repository therefore publishes a versioned OpenAPI 3.1 contract and safe conformance fixtures rather than requiring clients to recreate language-specific models by hand.

Canonical artefacts:

- `contract/v1/openapi.json` — OpenAPI 3.1 operations and JSON Schema components for every HTTP route advertised by `/capabilities`
- `conformance/fixtures/baseline-http.json` — executable baseline HTTP parity cases
- `conformance/fixtures/contract-states.json` — canonical safe response examples for lifecycle, source, provider, event and failure scenarios

The Go request and response DTOs are the implementation source of truth. `cmd/secretsbroker/contract_artifacts_test.go` derives the OpenAPI schemas and canonical state fixtures from those types.

## Contract identities

The identities have different purposes:

- broker API family: `secretsbroker.local/v1`
- published contract version: `1.0.0`
- fixture family: `secretsbroker.parity.v1`

`GET /capabilities` exposes `contractVersion` so clients can record and enforce the contract they were tested against.

## Compatibility rules

Within contract major version `1`:

- existing JSON field names, meanings and types remain stable
- existing route methods and paths remain stable
- existing lifecycle states and outcomes remain stable
- response objects may gain optional fields; clients must ignore unknown response fields
- enum-like state and outcome values may gain compatible values; clients must preserve unknown values for diagnostics and fail closed for mutating operations
- request fields may become optional, but an existing optional field must not become required
- security requirements must not be weakened

A change requires a new contract major version when it removes or renames a field, changes a field type or meaning, removes or changes a route, makes an optional request field required, or changes an existing state/outcome incompatibly.

Broker implementation versions may change without changing the contract version when their external behaviour remains compatible.

## Generation and drift checks

Regenerate the committed artefacts after changing an HTTP DTO or route:

```bash
UPDATE_CONTRACT=1 go test ./cmd/secretsbroker -run TestContractArtefactsAreCurrent
```

PowerShell:

```powershell
$env:UPDATE_CONTRACT = "1"
go test ./cmd/secretsbroker -run TestContractArtefactsAreCurrent
Remove-Item Env:UPDATE_CONTRACT
```

Normal `go test ./...` runs the same generator without write mode and fails when the committed OpenAPI or fixture output differs. It also fails when:

- an HTTP route advertised by `/capabilities` has no contract operation
- a contract operation is not advertised by `/capabilities`
- a canonical fixture declares an unknown Go response type
- a fixture response contains a field not present in its declared Go type
- fixture identity, format or redaction requirements are invalid

Because the repository test scripts run `go test ./...`, these checks apply in the normal Windows, Linux and macOS GitHub Actions matrix.

## Required safe scenarios

`contract-states.json` covers:

- ready
- setup needed
- locked
- source authentication required
- policy denied
- unsupported capability
- degraded
- audit unavailable
- empty metadata-safe event output

Source examples cover the local encrypted store, OpenBao and AWS Secrets Manager. They contain no real values, bearer tokens, provider credentials, private keys, master keys or environment material.

## Consumer rules

Service Admin and Service Lasso core should:

1. Generate or validate client types from `contract/v1/openapi.json`.
2. Run adapter tests against the committed fixtures from this repository.
3. Treat `sourceId`, `kind`, `displayName`, `state`, `outcome`, `capabilities`, `lifecycle` and `nextAction` exactly as published.
4. Ignore unknown compatible response fields while failing closed on unknown mutation capabilities or lifecycle outcomes.
5. Never copy fixture shapes into independently maintained hand-written models.

Fixtures may be consumed directly from a pinned repository revision or copied by an automated, revision-recording sync step. Manual copies are not a conformance mechanism.

## Secret-safety boundary

Schemas describe secret-bearing request fields where the API requires them, but never contain example values. Fixtures and generated documents must never include real or realistic credentials, raw secret values, session tokens, provider tokens, private keys, portable master keys, recovery shares, encrypted store payloads or environment dumps.
