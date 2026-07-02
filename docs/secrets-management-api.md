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
- Provisioning status is metadata-only. It reports generated value policy classes and per-ref status, never generated values, master keys, provider credentials, tokens, private keys, cookies, passwords, environment values, or recovery material.
- Provisioning operation planning is metadata-only. Caller-provided generation currently plans the existing signed write-back path. Broker-generated apply is available only through the explicit apply endpoint, and still requires confirmation, audit reason, local API auth, signed launch identity, namespace/ref policy, and operation policy.

## Endpoints

All endpoints require the local API token when configured, via `Authorization: Bearer <token>` or `X-SecretsBroker-Token`.

### `GET /v1/provisioning/status?ref=<secret-ref>&search=<metadata-query>`

Returns metadata-only first-run generated/provisioned secret status for Service Lasso and Service Admin.

The endpoint reports local encrypted-store refs, configured source refs, and an explicit `missing_ref` record when a valid `ref` query does not exist in either place. It is intended for first-run and operator dashboards that need to explain whether a generated/service secret is ready, pending, blocked, failed, stale, or not planned without reading secret values.

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
  "outcome": "ready",
  "results": [
    {
      "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
      "namespace": "services/@serviceadmin/runtime",
      "ownerServiceId": "@serviceadmin",
      "sourceId": "local",
      "providerId": "local",
      "providerKind": "local-encrypted-store",
      "desiredOperation": "none",
      "provisionedState": "ready",
      "lastOperationId": "2026-05-07T00:00:00Z",
      "lastOutcome": "ready",
      "auditStatus": "audit_available",
      "policyResult": "allowed",
      "generatedValuePolicy": {
        "kind": "opaque",
        "lengthClass": "policy_default",
        "entropyClass": "policy_default",
        "rotationPolicy": "service_policy"
      }
    }
  ]
}
```

Per-ref `provisionedState` values: `not_planned`, `pending`, `ready`, `blocked`, `failed`, and `stale`.

Per-ref `lastOutcome` values include `ready`, `missing_ref`, `locked`, `policy_denied`, `source_auth_required`, `source_unavailable`, `degraded`, `disabled`, and `stale`.

The endpoint is read-only. A `pending` record does not generate, write, rotate, or migrate a value; callers must use the existing signed write-back path or a future explicit generation operation to change broker state.

### `POST /v1/provisioning/operations/plan`

Plans a first-run generated secret operation without writing, generating, revealing, or rotating a value. This endpoint lets Service Lasso and Service Admin choose the safe next action while keeping the existing signed `/v1/writeback` endpoint as the only current apply path for caller-provided values.

Request:

```json
{
  "requestId": "req-provision-plan-1",
  "serviceId": "@serviceadmin",
  "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
  "operation": "create",
  "generationMode": "caller_provided",
  "reason": "first-run setup planning",
  "generatedValuePolicy": {
    "kind": "session-signing-key",
    "lengthClass": "32_bytes",
    "entropyClass": "cryptographic",
    "rotationPolicy": "first_run_then_operator_rotation"
  }
}
```

Success response for caller-provided generation:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "req-provision-plan-1",
  "ownerServiceId": "@serviceadmin",
  "namespace": "services/@serviceadmin/runtime",
  "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
  "operation": "create",
  "mode": "plan",
  "generationMode": "caller_provided",
  "outcome": "ready",
  "applied": false,
  "requiresConfirmation": true,
  "writebackEndpoint": "/v1/writeback",
  "nextAction": "submit_signed_writeback_with_value_and_audit_reason",
  "auditStatus": "audit_ready",
  "policyResult": "allowed",
  "provisionedState": "not_planned",
  "lastOutcome": "missing_ref",
  "generatedValuePolicy": {
    "kind": "session-signing-key",
    "lengthClass": "32_bytes",
    "entropyClass": "cryptographic",
    "rotationPolicy": "first_run_then_operator_rotation"
  }
}
```

Broker-generated planning requests use `"generationMode": "broker_generated"` or `"requireBrokerGenerate": true`. The plan response stays metadata-only and points callers to the apply endpoint when broker-owned generation is desired.

### `POST /v1/provisioning/operations/apply`

Applies a broker-generated first-run secret value without returning the generated value. This endpoint is intended for local encrypted-store first-run bootstrap where Service Lasso wants the broker to generate and store secret material rather than passing a caller-generated value to `/v1/writeback`.

The endpoint requires:

- local API token
- `generationMode: "broker_generated"` or `requireBrokerGenerate: true`
- `confirm: true`
- non-empty audit `reason`
- signed `identityLease` scoped to the same service, ref, namespace, and operation
- `policy.allowedNamespaces` containing the target namespace
- `policy.allowedOperations` containing the requested operation
- supported operation: `create`, `update`, or `rotate`
- supported generated value policy length class: `policy_default`, `16_bytes`, `32_bytes`, or `64_bytes`
- supported entropy class: `policy_default` or `cryptographic`

Request:

```json
{
  "requestId": "req-provision-apply-1",
  "serviceId": "@serviceadmin",
  "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
  "operation": "create",
  "generationMode": "broker_generated",
  "reason": "first-run setup",
  "confirm": true,
  "identity": {
    "serviceId": "@serviceadmin",
    "expiresAt": "2026-05-07T00:05:00Z"
  },
  "identityLease": {
    "issuer": "@service-lasso",
    "serviceId": "@serviceadmin",
    "allowedRefs": ["services/@serviceadmin/runtime/SESSION_SIGNING_KEY"],
    "allowedNamespaces": ["services/@serviceadmin/runtime"],
    "allowedOperations": ["create"],
    "issuedAt": "2026-05-07T00:00:00Z",
    "expiresAt": "2026-05-07T00:05:00Z",
    "jti": "lease-id",
    "signature": "<lease signature>"
  },
  "policy": {
    "allowedNamespaces": ["services/@serviceadmin/runtime"],
    "allowedOperations": ["create"]
  },
  "generatedValuePolicy": {
    "kind": "session-signing-key",
    "lengthClass": "32_bytes",
    "entropyClass": "cryptographic",
    "rotationPolicy": "first_run_then_operator_rotation"
  }
}
```

Success response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "req-provision-apply-1",
  "ownerServiceId": "@serviceadmin",
  "namespace": "services/@serviceadmin/runtime",
  "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
  "operation": "create",
  "mode": "apply",
  "generationMode": "broker_generated",
  "outcome": "applied",
  "applied": true,
  "requiresConfirmation": false,
  "nextAction": "refresh_service_or_continue_startup",
  "auditStatus": "audit_recorded",
  "policyResult": "allowed",
  "provisionedState": "ready",
  "lastOutcome": "ready",
  "generatedValuePolicy": {
    "kind": "session-signing-key",
    "lengthClass": "32_bytes",
    "entropyClass": "cryptographic",
    "rotationPolicy": "first_run_then_operator_rotation"
  },
  "affectedRefs": ["services/@serviceadmin/runtime/SESSION_SIGNING_KEY"],
  "affectedServices": ["@serviceadmin"]
}
```

The generated value is written to the local encrypted store through the same write-back capture path used by `/v1/writeback`. Responses, audit records, events, telemetry, diagnostics, and docs fixtures must not include the generated value.

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

Common outcomes: `ready`, `dry_run_ready`, `applied`, `migrated`, `partial_failure`, `missing_ref`, `invalid_ref`, `locked`, `policy_denied`, `source_auth_required`, `source_unavailable`, `unsupported`, `degraded`, `audit_unavailable`, `stale`, `stale_plan`, `skipped`, `failed`.
