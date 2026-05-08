# Secrets management API contract

This contract powers the Service Admin `Secrets Broker > Secrets` management table.

The contract is metadata-first. List/search/value-search responses return safe refs and status metadata only. Raw values are returned only by the explicit reveal endpoint after local API auth, policy/audit checks, and a requested audit reason.

## Safety boundaries

- List/search endpoints never return `value`, plaintext, ciphertext, provider credentials, tokens, or backend credential payloads.
- Broker-backed value search runs inside Secrets Broker and returns matching refs/metadata only.
- Service Admin must not receive all plaintext values for client-side indexing.
- Denied, locked, missing, auth-required, unavailable, unsupported, and degraded states fail closed with typed outcomes.
- Edit/reset/policy operations expose dry-run/preview before apply.
- Apply requests are secret-bearing where relevant and use the same local API auth and body-size guardrails as existing write/resolve endpoints.
- Audit entries record operation/ref/outcome/request identity only; they do not include raw values.

## Endpoints

All endpoints require the local API token when configured, via `Authorization: Bearer <token>` or `X-SecretsBroker-Token`.

### `GET /v1/management/secrets?search=<metadata-query>`

Returns metadata-only records from the local encrypted store and configured source refs.

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "query": "session",
  "valueSearch": false,
  "outcome": "ready",
  "results": [
    {
      "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
      "name": "SESSION_SIGNING_KEY",
      "sourceId": "local",
      "providerKind": "local-encrypted-store",
      "ownerServiceId": "@serviceadmin",
      "workspaceId": "local",
      "state": "present",
      "outcome": "ready",
      "capabilities": ["metadata", "reveal", "edit", "reset", "policy"],
      "policy": "local-writeback-policy",
      "auditStatus": "audit_available",
      "valueSearch": "supported"
    }
  ]
}
```

### `GET /v1/management/secrets/value-search?query=<broker-query>`

Optional broker-backed value search. The broker may inspect local/provider values internally, but it returns refs/metadata only. Unsupported providers are omitted from matches and represented through metadata capability/status.

### `POST /v1/management/secrets/reveal`

Explicit reveal path. This is the only management endpoint that may return a raw value.

Request:

```json
{
  "requestId": "req-reveal-1",
  "serviceId": "@serviceadmin",
  "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
  "reason": "operator troubleshooting"
}
```

Success response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "req-reveal-1",
  "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
  "operation": "reveal",
  "outcome": "ready",
  "value": "<raw value only on explicit reveal success>",
  "metadata": { "sourceId": "local", "version": "..." },
  "ttlSeconds": 60,
  "auditStatus": "audit_recorded"
}
```

### `POST /v1/management/secrets/edit/dry-run`
### `POST /v1/management/secrets/edit/apply`

Dry-run validates ref, policy, backend state, and audit requirements. Apply requires a value and explicit confirmation/audit reason. Responses do not include raw values.

### `POST /v1/management/secrets/reset/dry-run`
### `POST /v1/management/secrets/reset/apply`

Dry-run validates reset/rotate readiness. Apply stores caller-provided replacement material (or a future provider-generated value) without returning the raw value.

### `POST /v1/management/secrets/policy/preview`
### `POST /v1/management/secrets/policy/apply`

Preview/apply policy changes. This first contract records the requested policy handle/status and returns metadata-only outcomes; provider-specific enforcement can be expanded behind the same response shape.

## Typed outcomes

Common outcomes: `ready`, `dry_run_ready`, `applied`, `missing_ref`, `invalid_ref`, `locked`, `policy_denied`, `source_auth_required`, `source_unavailable`, `unsupported`, `degraded`, `audit_unavailable`.
