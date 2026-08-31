# Signed launch identity leases

Status: implemented for issue #29

`POST /v1/resolve` and `POST /v1/writeback` require a signed `identityLease` object in addition to the local API token. The local API token authenticates access to the loopback broker API. The lease scopes the launched service to the refs, namespaces, operations, workspace, and expiry that the Service Lasso launcher issued for that run.

## Signing model

The local Service Lasso launcher is the issuer. The broker requires an exact match with `SECRETSBROKER_LAUNCH_IDENTITY_ISSUER` / `--launch-identity-issuer` (default `service-lasso-local-launcher`) and verifies leases with `SECRETSBROKER_LAUNCH_IDENTITY_SIGNING_KEY` or `--launch-identity-signing-key`. Production requires a nonempty dedicated signing key; API-token fallback is rejected. Development/bootstrap mode retains the local API-token fallback so older local deployments can migrate.

The signature algorithm is HMAC-SHA-256 over the canonical JSON lease payload, excluding `signature`. The signature is encoded as:

```text
hmac-sha256:<base64url-no-padding>
```

The broker ships a bounded launcher-compatible issuer helper so the Service Lasso launcher can generate the exact signed payload shape the broker enforces:

```powershell
$env:SECRETSBROKER_LAUNCH_IDENTITY_SIGNING_KEY = "<launcher-owned-hmac-key>"
secretsbroker admin launch-lease issue `
  --service-id api-service `
  --workspace-id workspace-local `
  --allowed-ref "services/api-service/runtime/*" `
  --operation resolve `
  --jti "<one-time-id>" `
  --transport-binding-kind windows-sid `
  --transport-binding-subject "S-1-5-21-..."
```

For bootstrap compatibility only, the helper can fall back to `SECRETSBROKER_API_TOKEN` when the dedicated launch signing key is not configured. Production launchers should use a distinct signing key and avoid passing secrets as command-line flags.

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
  "transportBinding": {
    "kind": "windows-sid",
    "subject": "S-1-5-21-..."
  },
  "signature": "hmac-sha256:..."
}
```

Required claims:

- `issuer`, `serviceId`, `issuedAt`, `expiresAt`, `jti`, and `signature`
- at least one of `allowedRefs` or `allowedNamespaces`
- `allowedOperations`, using `resolve` for resolve requests and write-back operations such as `create`, `update`, `rotate`, or `delete`

Transport binding:

- `transportBinding.kind`: `windows-sid` for Windows named-pipe clients or `unix-uid` for Unix socket clients.
- `transportBinding.subject`: the broker-observed local peer subject, such as a Windows user SID or Unix UID.

`transportBinding` is part of the signed lease payload. It is mandatory in production and the broker requires the request to arrive through an authenticated IPC transport with matching local peer metadata. An absent production binding, loopback HTTP, or a mismatched local peer fails closed. It remains optional only in development/bootstrap compatibility mode.

`jti` values are one-time use until their expiry. Replaying a lease returns `identity_replayed`.

## Enforcement

The broker rejects the request before reading or writing secret values when:

- the lease is missing, unsigned, malformed, or tampered: `identity_invalid`
- the lease is expired: `identity_expired`
- the `jti` has already been used: `identity_replayed`
- the issuer does not exactly match the configured trusted launcher issuer: `policy_denied`
- the request service, workspace, refs, namespace, or operation exceed the signed scope: `policy_denied`
- production omits a transport binding, or the authenticated IPC peer does not match it: `policy_denied`

Audit records use metadata only: operation, request id, service id, safe ref/hash where applicable, and typed outcome. Lease signatures, API tokens, and secret values are never written to audit JSONL.
