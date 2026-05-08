# Node and Go Secrets Broker Parity Contract

Status: baseline conformance contract
Issue: #26

## Purpose

`@secretsbroker` may have Go and Node implementations, but Service Lasso clients must see one stable contract. This document defines the shared behavior every implementation must satisfy, plus the fixture format used for conformance checks.

The contract is intentionally implementation-neutral: fixture files are JSON and can be consumed by Go tests, Node tests, or external harnesses.

## Compatibility rules

Implementations MUST:

- expose the same service identity: `@secretsbroker`
- expose the same API version: `secretsbroker.local/v1`
- return JSON for all HTTP API responses
- use the canonical endpoint paths and methods listed below
- preserve documented response field names and typed outcomes
- never include plaintext secret values, bearer tokens, source tokens, or master keys in error responses, status/source status payloads, audit events, or diagnostics
- accept and emit portable fixture JSON without language-specific extensions

Implementations MAY:

- include additional metadata fields when clients can safely ignore them
- support additional source adapters behind the same lifecycle/status model
- support stronger production transports, as long as HTTP parity fixtures remain valid for compatibility testing

## Shared HTTP API behavior

| Endpoint | Auth | Contract |
| --- | --- | --- |
| `GET /health` | none | liveness JSON with `ok`, `serviceId`, and `state` |
| `GET /ready` | none | readiness/state JSON; non-ready states SHOULD use non-2xx readiness status where supported |
| `GET /status` | none | human/operator safe status without secret values |
| `GET /state` | none | typed state object with `outcome`, `keyState`, `nextAction`, affected refs/services |
| `GET /capabilities` | none | implementation capabilities, endpoints, and typed outcomes |
| `GET /v1/sources/status` | none | safe source registry/lifecycle status; no source credentials or values |
| `POST /v1/secrets` | local API token | write one local secret value |
| `POST /v1/writeback` | local API token | capture generated secret write-back with identity/policy checks |
| `POST /v1/resolve` | local API token | batched secret resolution |

Secret-bearing endpoints MUST require a configured local API token and MUST fail closed when no token is configured.

Supported request authentication forms:

```http
Authorization: Bearer <token>
X-SecretsBroker-Token: <token>
```

Implementations MUST NOT echo either token form in errors, logs, audit events, or diagnostics.

## Shared CLI behavior

Implementations SHOULD provide equivalent CLI entrypoints even if the underlying binary/package differs:

| Command | Contract |
| --- | --- |
| `secretsbroker serve` | start the local broker transport |
| `secretsbroker status` | emit safe status JSON |
| `secretsbroker key status` | report master-key/key-state metadata without key material |
| `secretsbroker key generate` | emit newly generated key material only to the direct caller |
| `secretsbroker key rotate` | rotate local encrypted-store payloads to new key material |
| `secretsbroker backup create` | create encrypted backup artifact without plaintext values |
| `secretsbroker backup restore` | restore encrypted backup only when decryptable with supplied key material |
| `secretsbroker session status` | report local API token configured/not configured without revealing token |
| `secretsbroker session generate` | emit generated local API token only to the direct caller |
| `secretsbroker version` | print implementation version |

## Secret refs and namespaces

Secret refs MUST be slash-delimited relative refs.

Valid refs:

- are non-empty
- do not start or end with `/`
- do not contain whitespace
- do not contain `.` or `..` path segments
- do not contain empty path segments

Examples:

```text
openclaw/openai/api_key
services/api/runtime/API_TOKEN
```

Write-back namespaces use the same ref validation rules. A write-back `namespace` plus relative `ref` is normalized into one full ref by trimming leading/trailing slashes and joining with `/`.

Namespace policy checks MUST occur before storing generated values.

## Outcomes and lifecycle compatibility

All implementations MUST preserve these outcome strings where the scenario applies:

- `ready`
- `setup_needed`
- `locked`
- `missing_ref`
- `invalid_ref`
- `policy_denied`
- `identity_expired`
- `source_auth_required`
- `source_unavailable`
- `degraded`
- `disabled`

Source status MUST map low-level outcomes into canonical lifecycle states:

- `connected`
- `missing`
- `denied`
- `auth_required`
- `revoked`
- `reconnect_required`
- `config_error`
- `degraded`
- `disabled`

Clients should key user flows from lifecycle `state` and `nextAction`, while preserving raw `outcome` for diagnostics and tests.

## Error envelope

HTTP errors MUST use this envelope:

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Safe fixed human message.",
    "outcome": "policy_denied",
    "requestId": "optional-request-id",
    "nextAction": "review_policy",
    "affectedRefs": [],
    "affectedServices": []
  }
}
```

Rules:

- `affectedRefs` and `affectedServices` MUST be arrays, not null.
- `message` MUST be safe fixed text and MUST NOT include secret values, request body values, bearer tokens, source tokens, master keys, or provider raw credential errors.
- `code` and `outcome` SHOULD be stable strings that tests can match.

## Audit event compatibility

Audit events MUST be metadata-only JSON objects. Implementations MAY add fields, but these baseline fields are portable:

```json
{
  "ts": "2026-05-08T00:00:00Z",
  "operation": "resolve",
  "ref": "openclaw/openai/api_key",
  "outcome": "ready",
  "state": "connected",
  "sourceId": "local",
  "serviceId": "openclaw",
  "requestId": "req-1"
}
```

Audit events MUST NOT include plaintext secret values or credentials.

## Backup/restore compatibility

Backup artifacts MUST remain encrypted-at-rest artifacts. A conforming implementation MUST:

- include version/service/API metadata
- include encrypted store payloads only, never plaintext values
- include key id/version metadata for operator diagnostics
- reject malformed artifacts
- reject wrong-key restores before overwriting the active store

## Fixture format

Conformance fixtures live under `conformance/fixtures/*.json`.

Top-level shape:

```json
{
  "schemaVersion": 1,
  "contract": "secretsbroker.parity.v1",
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "cases": [
    {
      "name": "case-name",
      "kind": "http",
      "method": "POST",
      "path": "/v1/resolve",
      "requiresAuth": true,
      "request": {},
      "expectedStatus": 200,
      "expectedResponse": {},
      "redactionForbidden": ["secret-value", "local-api-token"]
    }
  ]
}
```

Case rules:

- `name`, `kind`, `method`, `path`, `expectedStatus`, and `expectedResponse` are required.
- `kind` currently supports `http`, `cli`, or `audit`.
- `requiresAuth` is required for HTTP cases.
- `redactionForbidden` lists strings that MUST NOT appear in response/error/audit output for that case.
- Implementations may ignore unknown top-level/case fields for forward compatibility.

## Baseline conformance flow

Every implementation SHOULD provide a test runner that can:

1. Load every fixture in `conformance/fixtures`.
2. Verify fixture schema basics.
3. Start or simulate the implementation in a known state.
4. Execute each HTTP/CLI/audit case.
5. Compare required fields in `expectedResponse` and `expectedStatus`.
6. Check that all `redactionForbidden` strings are absent from emitted responses, errors, logs, and audit events.

The Go implementation includes a fixture schema/redaction test in `cmd/secretsbroker/parity_fixture_test.go`. Future Node implementations can reuse the same fixture files and mirror the same assertions in their test runner.
