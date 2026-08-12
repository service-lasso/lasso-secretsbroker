# Operation capability manifest

Status: canonical release capability contract  
Issue: #133

## Purpose

Legacy `capabilities` and `endpoints` arrays remain available for compatible
clients, but they are not sufficient to enable an action. A capability name can
describe an adapter design or a planning path even when no provider mutation is
implemented. `GET /capabilities` therefore publishes a versioned `operations`
manifest, and source/provider status responses publish the same operation shape
scoped to each connection.

Contract version `1.1.0` adds manifest version `1.0.0` without removing the
contract `1.x` fields. The OpenAPI schema for `OperationCapability` is the
canonical schema.

## Record shape

Every operation record contains:

- stable `operationId`, `method`, and `path`;
- `maturity`: `unavailable`, `planned`, `read-only`, `dry-run`, `executable`,
  or `validated`;
- `classification`: `read` or `mutation`;
- `authenticationRequired`, `policyRequired`, and `auditRequired`;
- `scope`: `broker-local`, `provider-remote`, `source-boundary`, or `mixed`;
- explicit `providerKinds`;
- `completionMode`: `synchronous` or `asynchronous`;
- `statusPath`, only when an asynchronous operation status route is actually
  implemented and advertised;
- safe `limitationCode`, `reasonCode`, and `nextAction` values.

`validated` is an executable implementation covered by contract/provider tests.
`executable` performs its advertised effect but has narrower validation.
`dry-run` computes a plan without applying the provider mutation. `planned`
means that the route or model exists but the advertised mutation is not
implemented. `read-only` never authorises a mutation.

## Consumer enablement rule

For a mutation, Service Admin must find the exact operation on the selected
source or provider connection and require maturity `executable` or `validated`.
It must not enable apply from a legacy capability string, a provider-family
upper bound, an endpoint string, or a `planned`/`dry-run` record.

For reads, the selected connection must report `read-only`, `executable`, or
`validated` for the exact operation. Every invocation still re-evaluates its
declared auth, policy, audit, confirmation, lockout, and identity controls.

Current management routes complete synchronously. Service Admin must treat an
empty `statusPath` as authoritative and must not poll a secret-operation status
endpoint that is not present in this manifest. When the broker adds durable
asynchronous delete, decommission, or provider mutation work, it must first add
the implemented status route to the OpenAPI contract, advertised endpoint list,
and operation manifest.

Connection lifecycle wins over family capability. `source_auth_required`,
`policy_denied`, `audit_unavailable`, locked, disabled, invalid, and degraded
states downgrade affected connection operations to `unavailable` with a safe
recovery action.

Local decommission is advertised as three synchronous operations: signed
dependency/version dry-run, recoverable encrypted-tombstone apply, and exact-
version restore. Provider-scoped matrices keep these operations unavailable
unless the selected provider is the local encrypted store. Hard delete and
disable are not advertised.

## Current provider operation matrix

This table summarises the connection-ready baseline. The runtime arrays are the
machine-readable authority.

| Operation | Local encrypted store | Vault/OpenBao | AWS Secrets Manager | env/file/exec |
| --- | --- | --- | --- | --- |
| Resolve/reveal | validated | validated | validated | validated |
| Metadata-only value search | validated | unavailable | validated | unavailable |
| Edit dry-run | dry-run | dry-run | dry-run | unavailable |
| Edit apply | validated | unavailable | unavailable | unavailable |
| Reset/rotation dry-run | dry-run | planned | dry-run | unavailable |
| Reset apply | validated | unavailable | unavailable | unavailable |
| Rotation status | read-only | unavailable | unavailable | unavailable |
| Rotation stage/activate/rollback/retire | validated | unavailable | unavailable | unavailable |
| Policy preview | dry-run | dry-run | dry-run | unavailable |
| Policy apply | planned | planned | planned | unavailable |
| Migration dry-run | dry-run | dry-run | dry-run | dry-run |
| Migration apply | planned | validated* | validated** | planned |
| Secrets Sync dry-run | dry-run | dry-run | dry-run | dry-run |

`validated*` applies only to a Vault/OpenBao connection whose source config
explicitly sets `enableMigrationTarget: true` and passes address, auth and KV v2
mapping validation. The family capability and every disabled/incomplete
connection remain `planned`.

`validated**` applies only to an AWS Secrets Manager connection whose source
config explicitly sets `enableMigrationTarget: true` and passes region,
endpoint, SigV4 credential-handle, credential-availability, and ref mapping
validation. The family capability and every disabled/incomplete connection
remain `planned`.

The current provider configuration apply handler validates and reports an apply
result but does not persist a connection. Bulk campaign apply does not yet use
the provider executor layer. Provider-family upper bounds never authorize apply.

## Drift and conformance gates

Normal Go tests fail when:

- an OpenAPI/production contract route has no operation manifest entry;
- a manifest entry has no OpenAPI/production contract route;
- an advertised HTTP route has no matching manifest and schema entry;
- a manifest route is not registered by the production handler;
- an operation record has an invalid maturity/classification/scope or missing
  decision code;
- source/provider lifecycle or audit state leaves a blocked operation usable;
- generated OpenAPI or canonical fixture output is stale.

`conformance/fixtures/contract-states.json` includes the full
`capabilities-operation-manifest` response plus ready and blocked connection
matrices. Secret values, credentials, tokens, recovery material, and raw
provider responses remain forbidden.
