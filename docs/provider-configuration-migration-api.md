# Provider configuration and migration API contract

This contract powers the Service Admin `Secrets Broker > Configuration` surface.

It is safe-by-default: provider configuration/status/validation/migration responses return handles, capabilities, refs, statuses, and audit outcomes only. They never return provider credentials, raw secret values, ciphertext, or migration payload material.

Legacy capability names are provider-family upper bounds. Action enablement must
use the connection-scoped `operations` matrix documented in
`operation-capability-manifest.md`.

## Safety boundaries

- Provider credentials are accepted only as refs/handles such as `credentialRef`; plaintext credential payloads are rejected and are not echoed.
- Configuration status returns `credentialHandle` only, never token/password/client-secret values.
- Migration dry-run returns metadata only: refs, source/target provider ids, policy result, risk, expected action, audit requirement, and recovery guidance.
- Migration apply requires `confirm: true`, an `operationId`, and an audit `reason`.
- Migration apply response reports per-ref status and does not return migrated raw values.
- Unsupported provider capabilities, auth-required, invalid config, locked store, and partial failures fail closed with typed outcomes.
- Audit events record operation/provider/ref/outcome/request identity only.

## Endpoints

All non-public endpoints require the local API token when configured, via `Authorization: Bearer <token>` or `X-SecretsBroker-Token`.

### `GET /v1/providers/capabilities`

Returns supported provider kinds and safe capability metadata.

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "contractVersion": "1.1.0",
  "manifestVersion": "1.0.0",
  "outcome": "ready",
  "capabilities": [
    {
      "providerKind": "local-encrypted-store",
      "displayName": "Local encrypted store",
      "supported": true,
      "capabilities": ["read", "reveal", "write", "rotate", "policy", "value_search", "audit", "migration_source", "migration_target"],
      "operations": [
        {
          "operationId": "postv1_management_secrets_edit_apply",
          "method": "POST",
          "path": "/v1/management/secrets/edit/apply",
          "maturity": "validated",
          "classification": "mutation",
          "authenticationRequired": true,
          "policyRequired": true,
          "auditRequired": true,
          "scope": "broker-local",
          "providerKinds": ["local-encrypted-store"],
          "limitationCode": "runtime_auth_policy_audit_revalidated",
          "reasonCode": "provider_family_upper_bound",
          "nextAction": "inspect_source_or_provider_status"
        }
      ],
      "limitations": ["local-first development backend"]
    }
  ]
}
```

### `GET /v1/providers/config/status`

Returns current and configured providers as safe metadata.

### `POST /v1/providers/config/validate`

Validates provider configuration without persisting it and without returning credentials.

Request:

```json
{
  "requestId": "req-provider-validate",
  "serviceId": "@serviceadmin",
  "providerId": "vault-prod",
  "providerKind": "vault",
  "address": "https://vault.example.invalid",
  "credentialRef": "secret://local/provider/vault-prod/token",
  "namespaces": ["services/*"]
}
```

### `POST /v1/providers/config/apply` (planned)

The current handler validates confirmation, operation id and audit reason, but
it does not persist provider configuration. A fully authorized request therefore
fails closed with `outcome: "unsupported"`, `applied: false`,
`unsupportedCapability: "provider_configuration_persistence"`, and
`nextAction: "implement_persisted_provider_configuration"`. Its manifest
maturity is `planned`; clients must not enable it as an executable configuration
action or interpret it as a successful mutation.

### `POST /v1/providers/migration/dry-run`

Builds a metadata-only migration plan.

```json
{
  "requestId": "req-migration-dry-run",
  "serviceId": "@serviceadmin",
  "operationId": "migration-2026-05-08-a",
  "sourceProviderId": "local",
  "targetProviderId": "local",
  "refs": ["services/@serviceadmin/runtime/SESSION_SIGNING_KEY"]
}
```

Configured remote targets whose adapter contract supports write/update and
migration, including Vault/OpenBao and AWS Secrets Manager, are valid dry-run
targets. Remote dry-runs return per-ref `planned` items with
`expectedAction: "write_value_to_remote_provider_after_revalidation"` and
`recovery: "source_retained_until_target_verification_succeeds"` so clients can
show the exact remote operation path without copying or returning secret values.

Plans validate refs against the selected source provider rather than the union
of all managed refs. An omitted `refs` list expands only from that source: local
encrypted-store entries for `local`, or configured mappings for the named
remote source. Missing refs and non-ready source auth/lifecycle states become
per-ref failures, so a plan cannot describe a nonexistent or currently
unreadable source value as ready to migrate.

Provider configuration responses expose only the `http`/`https` origin. URL
user information, path, query, and fragment are stripped so accidentally
embedded credentials or request details cannot enter Admin responses, audit
evidence, or diagnostics. Invalid/non-HTTP provider addresses fail validation.

The Broker records every migration dry-run in the configured metadata-only
audit/event sinks. Apply requires a durable metadata-only authorization record
before an executor can receive source material, then records the typed outcome
after durable operation state is updated. If either
sink cannot accept the record, the response fails closed with
`outcome: "audit_unavailable"`, `auditStatus: "audit_unavailable"`,
`applied: false`, and `nextAction: "restore_audit_and_retry"`. Per-ref items are
also marked `audit_unavailable`; provider credentials, source values, and raw
provider bodies are never returned.

### `POST /v1/providers/migration/apply` (executor-gated; advertised as planned)

The handler validates confirmation, operation id, audit reason, selected-source
inventory, provider readiness, and exact target capability. It then requires an
explicit in-process executor registration for the selected provider id. Without
that registration every target fails closed with `outcome: "unsupported"`,
`applied: false`, and `nextAction: "implement_provider_operation_executor"`.
Vault/OpenBao KV v2 sources can register the production executor only when the
exact source sets `enableMigrationTarget: true` and its address, token/token env,
and every ref path/field mapping pass validation. That connection reports
validated migration apply. Disabled or incomplete Vault/OpenBao sources, AWS,
and all provider-family upper bounds remain `planned`; Service Admin must not
enable apply from those records.

The executor seam receives an operation-scoped idempotency key and source value
inside the Broker process. A ref is reported `migrated` only after a separate
target verification succeeds. Durable operation state contains only provider
ids, refs, a plan fingerprint, typed outcomes, attempt counts and verification
flags. It never contains a source value, credential, ciphertext copy, or remote
response body.

The Vault/OpenBao executor uses a bounded, no-redirect HTTP client. It performs
an authenticated KV v2 read, preserves sibling fields, and writes with CAS 0 or
the observed metadata version. A separately authenticated bounded readback must
match before the operation is verified. HTTP 401/403/429, CAS conflicts,
unavailable endpoints and readback mismatch become typed metadata-only results;
the provider body, token, mapped provider path and transport error are not
returned or persisted.

An exact retry skips already verified refs. A retry after `partial_failure`
resumes failed refs; a ref whose write succeeded but verification failed retries
verification without issuing a duplicate write. This state survives Broker
restart. Reusing an operation id with different source, target, or refs returns
HTTP 409 with `outcome: "conflict"` and
`nextAction: "create_new_operation_id_for_changed_plan"`. Source entries remain
unchanged and recoverable after both partial and successful migration.

## Typed outcomes

Common outcomes: `ready`, `applied`, `dry_run_ready`, `partial_failure`, `conflict`, `invalid_ref`, `locked`, `policy_denied`, `source_auth_required`, `rate_limited`, `source_unavailable`, `verification_failed`, `unsupported`, `degraded`, `audit_unavailable`.
