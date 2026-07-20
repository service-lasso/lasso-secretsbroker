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

The current handler validates confirmation, operation id and audit reason and
reports an apply-shaped result, but it does not persist provider configuration.
Its manifest maturity is `planned`; clients must not enable it as an executable
configuration action.

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

### `POST /v1/providers/migration/apply` (planned)

The current handler reports per-ref metadata outcomes after confirmation,
operation id and audit reason. It does not copy local values or perform remote
provider writes. Its manifest maturity is `planned`.

## Typed outcomes

Common outcomes: `ready`, `applied`, `dry_run_ready`, `partial_failure`, `invalid_ref`, `locked`, `policy_denied`, `source_auth_required`, `source_unavailable`, `unsupported`, `degraded`, `audit_unavailable`.
