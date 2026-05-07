# Write-back policy and generated secret capture

_Status: initial bounded contract implemented for issue #9._

`@secretsbroker` accepts generated or refreshed secrets through `POST /v1/writeback` only when the caller presents an explicit launch identity and write-back policy.

## Endpoint

```http
POST /v1/writeback
Authorization: Bearer <local-api-token>
Content-Type: application/json
```

Request shape:

```json
{
  "requestId": "req-123",
  "identity": {
    "serviceId": "api-service",
    "expiresAt": "2026-05-07T00:05:00Z"
  },
  "policy": {
    "allowedNamespaces": ["services/api-service"],
    "allowedOperations": ["create", "update", "rotate"]
  },
  "operation": "create",
  "namespace": "services/api-service",
  "ref": "runtime/API_TOKEN",
  "value": "<generated secret value>",
  "refreshRequired": true,
  "reconnectRequired": true,
  "invalidateRefs": ["services/api-service/runtime/API_TOKEN"]
}
```

Response shape:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "req-123",
  "ownerServiceId": "api-service",
  "operation": "create",
  "namespace": "services/api-service",
  "ref": "services/api-service/runtime/API_TOKEN",
  "outcome": "ready",
  "refreshRequired": true,
  "reconnectRequired": true,
  "invalidatedRefs": ["services/api-service/runtime/API_TOKEN"],
  "metadata": {
    "sourceId": "generated:api-service",
    "version": "<timestamp>",
    "createdAt": "<timestamp>",
    "updatedAt": "<timestamp>"
  }
}
```

## Policy model

- `identity.serviceId` scopes ownership and audit attribution.
- `identity.expiresAt` is optional in local bootstrap mode, but when present it must be a future RFC3339 timestamp.
- `policy.allowedNamespaces` must include the requested namespace, or `*`.
- `policy.allowedOperations` must include the requested operation.
- Supported operations are `create`, `update`, `rotate`, and `delete`.
- The stored secret ref is `namespace/ref`; the payload is encrypted in the local store.

This first slice keeps policy explicit in the capture request so Service Lasso can pass a scoped launch-time grant. Later policy storage can move the grants into durable broker-owned config without changing the outcome vocabulary.

## Outcomes

`POST /v1/writeback` returns typed outcomes without exposing secret payload values:

- `ready`: capture succeeded.
- `invalid_ref`: namespace/ref/operation shape is malformed.
- `identity_expired`: launch identity is missing, invalid, or expired.
- `policy_denied`: namespace or operation is outside the supplied grant.
- `locked`: local broker store is locked.
- `source_auth_required`: source/backend authentication must be reconnected before write-back.
- `degraded`: backend/store write path is degraded.

## Refresh, invalidation, and reconnect semantics

The capture API echoes these caller-supplied control hints for Service Lasso/operator clients:

- `refreshRequired`: consumers should refresh materialized env/config using the captured value.
- `reconnectRequired`: the generating service or dependent clients may need reconnect/restart after capture.
- `invalidateRefs`: specific refs whose cached/materialized values should be invalidated.

## Audit redaction

Every write-back attempt records an audit event with operation, ref, outcome, request id, and service id. Secret payload values are never written to audit JSONL.
