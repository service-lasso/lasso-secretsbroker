# Secrets Sync design

Status: planning baseline
Issue: #95
Parent feedback: service-lasso/lasso-serviceadmin#97

## Purpose

Secrets Sync is the controlled movement of broker-managed secret material into an external destination that cannot call `@secretsbroker` directly. GitHub Actions secrets are the concrete first target to evaluate because CI/CD runners often need credentials before they can reach an on-prem Service Lasso runtime.

The capability is useful, but it is also a deliberate copy of sensitive material into a second trust boundary. Service Lasso should support it only as an explicit, audited destination workflow. It must not become a generic export, plaintext backup, or spreadsheet-style secret editor.

## Reference model

HashiCorp Vault Secrets Sync is an enterprise/HCP feature that keeps Vault as the system of record and propagates selected KVv2 secrets one way into external destinations such as GitHub Repository Actions secrets. The upstream model uses destination configuration, secret associations, async sync status, name templates, granularity choices, access checks, deletion propagation, retries, and reconciliation scans.

References:

- https://developer.hashicorp.com/vault/docs/sync
- https://developer.hashicorp.com/vault/docs/sync/github
- https://docs.github.com/en/rest/actions

Service Lasso should borrow the safety shape, not imply Vault Enterprise parity. The local-first broker should begin with a metadata-only dry-run contract, then add a narrowly scoped GitHub Actions destination only after auth, policy, audit, events, and operator confirmation semantics are testable.

## Decision

Proceed with a first implementation issue for a provider-neutral metadata-only sync plan/dry-run contract. Do not implement live GitHub writes in the first slice.

The first safe slice should answer these questions without moving secret values:

- Which broker refs are eligible to sync?
- Which destination kind and scope would receive each ref?
- Which destination secret name would be created or updated?
- Which policy, source capability, audit, auth, and lockout checks pass or fail?
- Which items are unsupported, denied, stale, blocked, or high risk?
- Which exact action is required before an apply path could be enabled?

## Target model

A sync destination is a configured external sink. It is distinct from a source/provider used for broker resolution.

```json
{
  "destinationId": "github-actions-service-lasso",
  "kind": "github-actions",
  "displayName": "GitHub Actions - service-lasso",
  "enabled": true,
  "scope": {
    "owner": "service-lasso",
    "repository": "service-lasso",
    "environment": "demo",
    "secretsLocation": "environment"
  },
  "credentialRef": "providers/github/service-lasso-sync/app",
  "nameTemplate": "SERVICE_LASSO_{{ refBase | upper }}",
  "granularity": "secret-ref",
  "collisionPolicy": "fail_if_unmanaged",
  "deletePolicy": "delete_managed_destination_secret",
  "state": "configured",
  "outcome": "ready",
  "auditStatus": "audit_available"
}
```

Destination metadata is safe to list only after redaction. It may include destination id, kind, owner/repo/environment names, selected repository names, capability flags, status, outcome, last sync timestamps, and next action. It must not include GitHub app private keys, installation tokens, personal access tokens, generated JWTs, REST request bodies, encrypted secret payloads, plaintext values, or provider error bodies.

## GitHub as first target

Supported first target: GitHub Actions secrets.

Scopes to represent explicitly:

- repository secrets
- environment secrets
- organization secrets with visibility and selected repository constraints
- GitHub Enterprise Server base URL, when configured

Authentication preference:

- Prefer a GitHub App installation with read/write Secrets permission and the narrowest repository or organization installation scope.
- Allow a credential-ref model for fine-grained or personal access tokens only as a bootstrap/development option, and report the weaker lifecycle/risk in the dry-run.
- Store only a `credentialRef` in destination config. Raw app private keys, installation tokens, and access tokens stay in broker-controlled secret storage and never appear in fixtures, docs examples, logs, events, issue comments, or PR bodies.

GitHub API behavior to account for:

- Secret create/update paths require fetching the destination public key and sending encrypted secret material to GitHub.
- Repository, environment, and organization secret APIs are different surfaces and must be represented as different destination scopes.
- Organization secrets have repository visibility/selection policy that cannot be treated as a simple repository write.
- GitHub cannot return plaintext secret values for drift comparison, so drift detection must use broker-owned metadata, operation ids, hashes/HMACs of canonical source material, and GitHub metadata such as updated timestamps where available.

## Directionality

Secrets Sync is one-way from `@secretsbroker` to the destination.

Out of scope:

- importing destination secret values back into `@secretsbroker`
- bidirectional sync
- treating destination values as source-of-truth
- reconciling out-of-band GitHub edits by reading plaintext values
- syncing into GitHub repository files, workflow files, variables, Dependabot secrets, Codespaces secrets, or arbitrary REST endpoints in the first target

If a destination secret changes outside Service Lasso, the broker can detect only metadata drift when available. It should report `drift_unknown` or `destination_changed_metadata` and require operator review rather than overwriting blindly.

## Association model

A sync association maps one broker ref to one destination secret identity.

```json
{
  "associationId": "assoc-01J...",
  "sourceRef": "services/api/runtime/API_TOKEN",
  "sourceRefHash": "sha256:...",
  "destinationId": "github-actions-service-lasso",
  "destinationKind": "github-actions",
  "destinationName": "SERVICE_LASSO_API_TOKEN",
  "destinationScope": {
    "owner": "service-lasso",
    "repository": "service-lasso",
    "environment": "demo",
    "secretsLocation": "environment"
  },
  "status": "planned",
  "outcome": "dry_run_ready",
  "managedBy": "@secretsbroker",
  "operationId": "sync-plan-2026-06-19-a",
  "lastPlannedAt": "2026-06-19T00:00:00Z"
}
```

The broker should own association metadata even when the external destination stores only a secret name and encrypted value. The association is the audit and drift anchor.

## Dry-run contract

First implementation endpoint:

```http
POST /v1/management/secrets/sync/dry-run
Authorization: Bearer <local-api-token>
Content-Type: application/json
```

Request:

```json
{
  "requestId": "req-sync-dry-run-1",
  "serviceId": "@serviceadmin",
  "operationId": "sync-plan-2026-06-19-a",
  "refs": [
    "services/api/runtime/API_TOKEN"
  ],
  "destinationId": "github-actions-service-lasso",
  "reason": "CI runner needs API_TOKEN through GitHub Actions"
}
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "req-sync-dry-run-1",
  "operationId": "sync-plan-2026-06-19-a",
  "operation": "secrets_sync",
  "mode": "dry-run",
  "outcome": "dry_run_ready",
  "applied": false,
  "requiresConfirmation": true,
  "auditStatus": "audit_ready",
  "staleAfterSeconds": 300,
  "nextAction": "confirm_with_operation_id_audit_reason_and_fresh_plan",
  "destination": {
    "destinationId": "github-actions-service-lasso",
    "kind": "github-actions",
    "scope": {
      "owner": "service-lasso",
      "repository": "service-lasso",
      "environment": "demo",
      "secretsLocation": "environment"
    },
    "authModel": "github-app",
    "state": "configured",
    "outcome": "ready"
  },
  "results": [
    {
      "ref": "services/api/runtime/API_TOKEN",
      "refHash": "sha256:...",
      "sourceId": "local",
      "providerKind": "local-encrypted-store",
      "ownerServiceId": "api",
      "destinationName": "SERVICE_LASSO_API_TOKEN",
      "capability": "sync/write",
      "capabilityResult": "supported",
      "policyResult": "allowed",
      "auditRequirement": "required",
      "risk": "high",
      "driftState": "unknown",
      "deleteBehavior": "delete_managed_destination_secret",
      "expectedAction": "encrypt_and_create_or_update_github_actions_secret",
      "outcome": "dry_run_ready",
      "nextAction": "confirm_with_operation_id_audit_reason_and_fresh_plan",
      "idempotencyKey": "sync-plan-2026-06-19-a:sha256:..."
    }
  ],
  "summary": {
    "selectedCount": 1,
    "readyCount": 1,
    "deniedCount": 0,
    "unsupportedCount": 0,
    "blockedCount": 0,
    "highRiskCount": 1,
    "driftUnknownCount": 1
  },
  "affectedRefs": [
    "services/api/runtime/API_TOKEN"
  ],
  "affectedServices": [
    "api"
  ]
}
```

The dry-run response may include refs and destination names but not values, ciphertext, GitHub public-key encrypted payloads, credentials, raw provider responses, or destination request bodies.

## Apply gate

Live apply should remain out of scope until the dry-run contract, destination config, and redaction tests are merged. When later approved, apply must:

- require local API auth, policy allow, audit availability, an audit reason, typed/high-risk confirmation, and a fresh non-stale dry-run
- revalidate source state, destination state, provider capability, policy, audit, lockout, and credential-ref auth immediately before write
- use an idempotency key/operation id per destination item
- encrypt values only in memory for the GitHub API request
- record per-item audit and event metadata without values or request bodies
- never retry secret-bearing writes blindly after ambiguous network failures
- return partial success/failure metadata with explicit retry/recovery guidance

## Drift and reconciliation

Initial dry-run drift states:

- `not_checked`: dry-run did not contact destination.
- `unknown`: destination cannot expose enough metadata to decide.
- `missing`: destination secret metadata is absent.
- `managed_current`: broker metadata says the last managed write matches the planned source version.
- `managed_stale`: broker metadata says the source changed after the last managed write.
- `destination_changed_metadata`: destination metadata changed outside broker-owned operation metadata.
- `unmanaged_collision`: a destination secret with the planned name exists but is not owned by the association.

Do not compare plaintext destination values. For later apply, the broker may persist a redacted association record with source ref hash, source version, destination name, destination updated timestamp, operation id, and a keyed digest of source material. The digest key must stay broker-owned and must not be exportable in diagnostics.

Reconciliation should begin as an operator-triggered dry-run, not a background daemon. Background retries/reconciliation can be a later issue after lockout, events, and idempotency behavior are proven.

## Deletion semantics

Deleting a source ref or association can remove a managed destination secret only when all of these are true:

- the association is broker-owned
- the destination name still matches the association
- policy allows deletion
- audit is available
- the destination collision state is not unmanaged
- the operator confirms the delete behavior in a fresh plan

Default behavior should be `delete_managed_destination_secret` for confirmed managed associations, `leave_unmanaged_destination_secret` for collisions/unknown ownership, and `block_until_reviewed` when policy/audit/auth state is unknown.

## Failure semantics

Dry-run outcomes:

- `dry_run_ready`
- `missing_ref`
- `invalid_ref`
- `locked`
- `policy_denied`
- `source_auth_required`
- `source_unavailable`
- `destination_auth_required`
- `destination_unavailable`
- `destination_policy_denied`
- `audit_unavailable`
- `unsupported`
- `unmanaged_collision`
- `drift_unknown`
- `degraded`

Apply outcomes, when later approved:

- `applied`
- `skipped`
- `partial_failure`
- all dry-run failure outcomes

All failures return metadata-only `nextAction` values. Raw errors from GitHub or other destinations must be mapped to typed outcomes and safe message codes.

## Redaction and audit requirements

Forbidden everywhere outside the broker value path:

- raw source values
- GitHub access tokens, app private keys, installation tokens, generated JWTs, and authorization headers
- GitHub REST request bodies containing encrypted secret material
- destination provider response bodies that can contain request echoes
- keyed digest secrets, recovery material, cookies, passwords, private keys, and environment dumps

Required audit fields:

- `operation`
- `requestId`
- `operationId`
- `serviceId`
- `actorKind`
- `ref` or `refHash` according to export mode
- `destinationId`
- `destinationKind`
- `destinationScope`
- `destinationName`
- `outcome`
- `reasonCode`
- `auditStatus`

Audit export must support `refHash`-only mode and should support destination-name hashing for high-sensitivity deployments.

## First executable issue

Tracked as [lasso-secretsbroker#101](https://github.com/service-lasso/lasso-secretsbroker/issues/101).

Implement:

```text
feat(sync): add metadata-only Secrets Sync dry-run contract
```

Scope:

- destination config structs and safe status metadata for `github-actions`
- `POST /v1/management/secrets/sync/dry-run`
- headless CLI command such as `secretsbroker admin sync dry-run`
- provider-neutral result/status/outcome vocabulary from this design
- GitHub target scope representation for repository, environment, organization, and GitHub Enterprise URL
- policy/audit/auth/lockout fail-closed checks using current broker primitives
- redaction tests proving values and destination credentials never reach responses, audit, events, logs, or fixtures

Out of scope for that issue:

- live GitHub writes
- background reconciliation
- app installation token minting
- PAT storage UI
- import/bidirectional sync
- Dependabot/Codespaces/variables sync

Live GitHub apply should be a later issue only after the dry-run contract is validated and reviewed.
