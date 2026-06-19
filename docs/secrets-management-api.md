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

### `POST /v1/management/secrets/rotation/dry-run`

Metadata-only credential rotation planning. The first broker-side slice is dry-run only: it reports local encrypted-store rotation/reset readiness and provider capability results, but it does not generate replacement material, mutate secrets, call external provider apply APIs, or return raw values.

Request:

```json
{
  "requestId": "req-rotation-1",
  "serviceId": "@serviceadmin",
  "operationId": "rotation-campaign-2026-05-23-a",
  "refs": [
    "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
  ],
  "reason": "operator rotation planning"
}
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "req-rotation-1",
  "operationId": "rotation-campaign-2026-05-23-a",
  "operation": "credential_rotation",
  "mode": "dry-run",
  "outcome": "dry_run_ready",
  "applied": false,
  "requiresConfirmation": true,
  "auditStatus": "audit_ready",
  "staleAfterSeconds": 300,
  "nextAction": "confirm_with_operation_id_audit_reason_and_fresh_plan",
  "results": [
    {
      "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
      "sourceId": "local-test",
      "providerKind": "local-encrypted-store",
      "ownerServiceId": "@serviceadmin",
      "capability": "rotate/reset",
      "capabilityResult": "supported",
      "policyResult": "allowed",
      "auditRequirement": "required",
      "risk": "medium",
      "expectedAction": "generate_or_accept_replacement_inside_broker",
      "outcome": "dry_run_ready",
      "nextAction": "confirm_with_operation_id_audit_reason_and_fresh_plan",
      "operationId": "rotation-campaign-2026-05-23-a",
      "idempotencyKey": "rotation-campaign-2026-05-23-a:sha256:..."
    }
  ],
  "summary": {
    "selectedCount": 1,
    "readyCount": 1,
    "deniedCount": 0,
    "unsupportedCount": 0,
    "blockedCount": 0,
    "highRiskCount": 0
  },
  "affectedRefs": [
    "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
  ],
  "affectedServices": [
    "@serviceadmin"
  ]
}
```

Provider-backed refs are represented as metadata-only capability results. A provider/source that does not currently advertise rotate/reset support returns `unsupported` with `nextAction: "inspect_provider_capabilities"`. Unknown policy, audit, provider auth, or broker state fails closed and must be rechecked with a fresh dry-run before any later apply path.

### `POST /v1/management/secrets/campaigns/create`
### `POST /v1/management/secrets/campaigns/revalidate`
### `POST /v1/management/secrets/campaigns/apply`
### `POST /v1/management/secrets/campaigns/status`

Bulk operation campaigns are the metadata-safe apply contract for multi-ref operations. They are designed for Service Admin bulk workflow Stage 2/3 and must be preceded by a campaign create/revalidate plan. They never return raw secret values, provider credentials, tokens, private keys, cookies, passwords, raw environment values, or recovery material.

Supported operation families:

- `rotate_reset`
- `update_edit`
- `apply_policy`
- `migrate_remap_provider`
- `mark_action_required`

Create builds a non-mutating plan and returns a server-side `planToken`, retry-safe `operationItemId` values, and per-item `idempotencyKey` values.

```json
{
  "requestId": "req-campaign-create",
  "serviceId": "@serviceadmin",
  "campaignId": "campaign-2026-06-19-a",
  "operationId": "bulk-rotate-a",
  "operation": "rotate_reset",
  "refs": [
    "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
  ],
  "reason": "operator campaign planning"
}
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "req-campaign-create",
  "campaignId": "campaign-2026-06-19-a",
  "planToken": "campaign-2026-06-19-a:rotate_reset:sha256:...",
  "operationId": "bulk-rotate-a",
  "operation": "rotate_reset",
  "mode": "create",
  "outcome": "dry_run_ready",
  "applied": false,
  "requiresConfirmation": true,
  "requiresAuditReason": true,
  "requiresRevalidation": true,
  "auditStatus": "audit_ready",
  "staleAfterSeconds": 300,
  "nextAction": "revalidate_confirm_and_apply",
  "results": [
    {
      "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
      "sourceId": "local-test",
      "providerKind": "local-encrypted-store",
      "ownerServiceId": "@serviceadmin",
      "operation": "rotate_reset",
      "capabilityResult": "supported",
      "policyResult": "allowed",
      "auditRequirement": "required",
      "risk": "high",
      "expectedAction": "generate_or_accept_replacement_inside_broker",
      "outcome": "dry_run_ready",
      "nextAction": "revalidate_confirm_and_apply",
      "idempotencyKey": "campaign-2026-06-19-a:rotate_reset:sha256:...",
      "operationItemId": "campaign-2026-06-19-a:item:sha256:...",
      "recovery": "retry_with_same_idempotency_key_or_restore_from_backup",
      "providerAction": "rotate_or_reset",
      "applied": false,
      "retrySafe": true
    }
  ],
  "summary": {
    "selectedCount": 1,
    "applicableCount": 1,
    "deniedCount": 0,
    "unsupportedCount": 0,
    "authRequiredCount": 0,
    "skippedCount": 0,
    "appliedCount": 0,
    "failedCount": 0,
    "staleCount": 0,
    "highRiskCount": 1
  },
  "affectedRefs": [
    "services/@serviceadmin/runtime/SESSION_SIGNING_KEY"
  ],
  "affectedServices": [
    "@serviceadmin"
  ],
  "unsupportedFamilies": [
    "bulk_raw_value_reveal"
  ]
}
```

Apply requires `planToken`, `confirm: true`, and `reason`. The broker reuses the server-side plan, records campaign-level and per-item audit events, and applies only ready items. Denied, unsupported, auth-required, skipped, failed, and stale items remain typed per item. A missing or unknown `planToken` returns `stale_plan` and applies nothing.

Campaign apply is retry-safe by `idempotencyKey` and `operationItemId`. The first implementation records metadata-level campaign outcomes and local-store-supported item outcomes; provider-specific live remote writes may continue returning typed `unsupported` until a provider operation path exists.

### `POST /v1/management/secrets/policy/preview`
### `POST /v1/management/secrets/policy/apply`

Preview/apply policy changes. This first contract records the requested policy handle/status and returns metadata-only outcomes; provider-specific enforcement can be expanded behind the same response shape.

## Typed outcomes

Common outcomes: `ready`, `dry_run_ready`, `applied`, `migrated`, `partial_failure`, `missing_ref`, `invalid_ref`, `locked`, `policy_denied`, `source_auth_required`, `source_unavailable`, `unsupported`, `degraded`, `audit_unavailable`, `stale_plan`, `skipped`, `failed`.
