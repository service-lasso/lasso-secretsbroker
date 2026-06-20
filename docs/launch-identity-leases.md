# Signed launch identity leases

Status: implemented for issue #29

`POST /v1/resolve` and `POST /v1/writeback` require a signed `identityLease` object in addition to the local API token. The local API token authenticates access to the loopback broker API. The lease scopes the launched service to the refs, namespaces, operations, workspace, and expiry that the Service Lasso launcher issued for that run.

## Signing model

The local Service Lasso launcher is the issuer. The broker verifies leases with `SECRETSBROKER_LAUNCH_IDENTITY_SIGNING_KEY` or `--launch-identity-signing-key`. In bootstrap mode, when that key is not configured, the broker falls back to the local API token as the HMAC key so older local deployments can migrate without adding a second secret immediately.

The signature algorithm is HMAC-SHA-256 over the canonical JSON lease payload, excluding `signature`. The signature is encoded as:

```text
hmac-sha256:<base64url-no-padding>
```

## Lease shape

```json
{
  "issuer": "service-lasso-local-launcher",
  "serviceId": "api-service",
  "workspaceId": "workspace-local",
  "allowedRefs": ["services/api-service/runtime/*"],
  "allowedNamespaces": ["services/api-service"],
  "allowedOperations": ["resolve", "create", "update", "rotate"],
  "issuedAt": "2026-06-20T08:00:00Z",
  "expiresAt": "2026-06-20T08:05:00Z",
  "jti": "01J...",
  "signature": "hmac-sha256:..."
}
```

Required claims:

- `issuer`, `serviceId`, `issuedAt`, `expiresAt`, `jti`, and `signature`
- at least one of `allowedRefs` or `allowedNamespaces`
- `allowedOperations`, using `resolve` for resolve requests and write-back operations such as `create`, `update`, `rotate`, or `delete`

`jti` values are one-time use until their expiry. Replaying a lease returns `identity_replayed`.

## Enforcement

The broker rejects the request before reading or writing secret values when:

- the lease is missing, unsigned, malformed, or tampered: `identity_invalid`
- the lease is expired: `identity_expired`
- the `jti` has already been used: `identity_replayed`
- the request service, workspace, refs, namespace, or operation exceed the signed scope: `policy_denied`

Audit records use metadata only: operation, request id, service id, safe ref/hash where applicable, and typed outcome. Lease signatures, API tokens, and secret values are never written to audit JSONL.
