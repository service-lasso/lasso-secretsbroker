# Secrets Broker Local API and Bootstrap Contract

Status: initial contract  
Issue: #11  
Service id: `@secretsbroker`  
API version: `secretsbroker.local/v1`

## Purpose

This contract defines the stable local process boundary between Service Lasso core, Service Admin, `secretsbroker-resolve`, and the `@secretsbroker` daemon.

Service Lasso core should keep only a tiny bootstrap client/state machine:

1. locate/start `@secretsbroker`
2. check process liveness
3. check API capabilities/version
4. check readiness/state
5. call resolve/write-back APIs when materializing dependent services
6. map typed broker outcomes into startup diagnostics

The daemon in this repo owns storage, unlock, policy, audit, source adapters, resolve/write-back behavior, and external provider/source state.

## Transport shape

Preferred production transports:

- Windows: named pipe
- macOS/Linux: Unix domain socket

Development/bootstrap compatibility transport:

- loopback HTTP bound to `127.0.0.1`

The daemon exposes loopback HTTP for development/bootstrap and now has explicit transport selection for production mode. Production mode rejects loopback HTTP and selects the OS IPC transport with `--transport auto`; Unix-like platforms can serve over a Unix socket with same-UID peer credential checks, while Windows can serve over a named pipe with a restricted security descriptor and connected-client token identity checks. Named pipe/Unix socket transports preserve the same request/response schema. See `docs/os-authenticated-ipc-transport.md`.

## Cross-cutting response rules

- API version is visible in `status` and `capabilities` responses.
- Secret values are never returned by status/capabilities/state/source-status/telemetry endpoints.
- Secret-bearing endpoints require local API token authentication for the loopback HTTP transport.
- Resolve responses may include secret material only for requested refs allowed by policy.
- Error responses use the typed error envelope below.
- Batch APIs must report per-ref outcomes rather than failing the whole batch whenever practical.

## Typed outcomes

Canonical outcome strings:

- `setup_needed`
- `locked`
- `ready`
- `source_auth_required`
- `degraded`
- `policy_denied`
- `missing_ref`
- `invalid_ref`
- `source_unavailable`
- `identity_invalid`
- `identity_expired`
- `identity_replayed`

## Endpoints

### `GET /health`

Liveness only. This answers whether the broker process is reachable, not whether secrets are usable.

Example response:

```json
{
  "ok": true,
  "serviceId": "@secretsbroker",
  "state": "setup_needed"
}
```

### `GET /ready`

Readiness for secret resolution. This should be true only when the current lifecycle state is `ready`.

Example ready response:

```json
{
  "serviceId": "@secretsbroker",
  "ready": true,
  "state": "ready",
  "outcome": "ready"
}
```

Example not-ready response:

HTTP status: `503`

```json
{
  "serviceId": "@secretsbroker",
  "ready": false,
  "state": "locked",
  "outcome": "locked"
}
```

### `GET /status`

Human/operator-friendly status summary. Safe for logs and UI diagnostics.

Example response:

```json
{
  "serviceId": "@secretsbroker",
  "name": "Service Lasso Secrets Broker",
  "version": "0.1.0",
  "apiVersion": "secretsbroker.local/v1",
  "state": "setup_needed",
  "ready": false,
  "localFirst": true,
  "backend": "local",
  "description": "Lean local-first Vault-like broker bootstrap skeleton. Secrets storage/resolution is intentionally not implemented yet.",
  "checkedAt": "2026-05-07T00:00:00Z"
}
```

### `GET /state`

Machine-oriented lifecycle state used by bootstrap clients.

Example response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "state": "setup_needed",
  "ready": false,
  "outcome": "setup_needed",
  "keyState": "not_initialized",
  "nextAction": "run_setup",
  "affectedRefs": [],
  "affectedServices": []
}
```

### `GET /capabilities`

Version and feature discovery.

Example response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "version": "0.1.0",
  "transports": ["loopback-http"],
  "endpoints": [
    "GET /health",
    "GET /ready",
    "GET /status",
    "GET /state",
    "GET /capabilities",
    "POST /v1/secrets",
    "POST /v1/resolve",
    "GET /v1/telemetry",
    "GET|POST /v1/recovery/policy",
    "POST /v1/management/lockouts/clear",
    "GET /v1/sources/status"
  ],
  "features": [
    "liveness",
    "readiness",
    "status",
    "state",
    "capabilities",
    "local-encrypted-store",
    "batched-resolve",
    "signed-launch-identity-leases",
    "typed-errors",
    "audit-redaction",
    "audited-lockout-clear",
    "recovery-policy-metadata",
    "recovery-policy-status",
    "source-status",
    "metadata-only-telemetry"
  ],
  "futureFeatures": [
    "write-back"
  ],
  "outcomes": [
    "setup_needed",
    "locked",
    "ready",
    "source_auth_required",
    "degraded",
    "policy_denied",
    "missing_ref",
    "invalid_ref",
    "source_unavailable",
    "identity_invalid",
    "identity_expired",
    "identity_replayed"
  ]
}
```

### `GET /v1/telemetry`

Read-only metadata telemetry for Service Admin and headless checks. It reports operational counters plus an OpenTelemetry-shaped preview contract:

- `contractVersion`: `service-lasso.secretsbroker.telemetry-preview.v1`
- `exporter`: configured/disabled status without endpoint or header values
- `traceContext`: W3C Trace Context-shaped response-header posture
- `redaction`: allowlisted attributes and omitted field classes
- `exportPreview`: dry-run/not-sent envelope metadata
- `signals`: metric previews for operation counts, policy decisions, provider/source states, audit outcomes, and active lockout counts with deterministic `traceId`, `spanId`, `traceparent`, and Service Lasso `correlationId`

Safe read-only API responses include `x-service-lasso-correlation-id`, `x-service-lasso-trace-id`, and `traceparent` headers generated by the broker. The preview does not accept, store, or return incoming trace headers. Header values are derived from safe route templates only; raw query strings, request bodies, response bodies, refs, and credential-bearing headers are never used as trace material.

The endpoint never sends telemetry and never returns raw refs, secret values, provider credentials, tokens, cookies, private keys, recovery material, environment values, raw request/response bodies, raw query strings, incoming trace headers, OTLP endpoint values, OTLP headers, exported payload bodies, provider response bodies, or raw config values.

## Recovery policy metadata contract

Endpoint:

```text
GET /v1/recovery/policy
POST /v1/recovery/policy
```

`GET` returns safe recovery lifecycle metadata. `POST` requires local API authentication and creates or updates the metadata contract. This endpoint records metadata only; it does not accept, generate, import, or return recovery shares, portable master key bytes, recipient private keys, passphrases, source credentials, API tokens, or plaintext secret values.

Request:

```json
{
  "requestId": "01HV...",
  "serviceId": "@operator",
  "policyId": "recovery-policy-1",
  "keyId": "mk-safe-key",
  "keyVersion": "v1",
  "threshold": 2,
  "shareCount": 3,
  "shareFingerprints": ["share-fp-1", "share-fp-2", "share-fp-3"],
  "recipientFingerprints": ["age-recipient-1", "age-recipient-2", "age-recipient-3"],
  "status": "active"
}
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "outcome": "active",
  "policy": {
    "policyId": "recovery-policy-1",
    "keyId": "mk-safe-key",
    "keyVersion": "v1",
    "threshold": 2,
    "shareCount": 3,
    "shareFingerprints": ["share-fp-1", "share-fp-2", "share-fp-3"],
    "recipientFingerprints": ["age-recipient-1", "age-recipient-2", "age-recipient-3"],
    "createdAt": "2026-06-07T00:00:00Z",
    "status": "active",
    "nextAction": "monitor_recovery_policy"
  },
  "nextAction": "monitor_recovery_policy"
}
```

Invalid or incomplete metadata fails closed with `policy_denied` and `provide_complete_safe_recovery_metadata`. Corrupted stored metadata reports `degraded` and `repair_recovery_policy_metadata`.

## Batched resolve contract

Endpoint:

```text
POST /v1/resolve
```

Request:

```json
{
  "requestId": "01HV...",
  "workspaceId": "workspace-local",
  "serviceId": "openclaw",
  "purpose": "service-start",
  "refs": [
    "openclaw/anthropic/api_key",
    "openclaw/telegram/bot_token"
  ]
}
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "01HV...",
  "results": [
    {
      "ref": "openclaw/anthropic/api_key",
      "outcome": "ready",
      "value": "<plaintext only for allowed resolve calls>",
      "metadata": {
        "sourceId": "local",
        "version": "current"
      }
    },
    {
      "ref": "openclaw/telegram/bot_token",
      "outcome": "policy_denied",
      "message": "Service secret policy denied resolve.",
      "policyResult": "denied",
      "nextAction": "add_service_secret_policy_assignment",
      "reasonCode": "policy_no_match"
    }
  ]
}
```

Rules:

- Values are present only for refs allowed by policy and only on resolve endpoints.
- Missing/denied/invalid/auth-required entries use per-result outcomes.
- Resolve policy denials include only safe metadata: `policyResult`, `nextAction`, and `reasonCode`.
- Policy decision and resolve audit records must redact secret values and credential material.

## Planned write-back contract

Endpoint:

```text
POST /v1/write-back
```

Request:

```json
{
  "requestId": "01HW...",
  "workspaceId": "workspace-local",
  "serviceId": "openclaw",
  "operation": "generated_secret_capture",
  "items": [
    {
      "ref": "openclaw/webhook/signing_secret",
      "value": "<plaintext accepted by write-back endpoint only>",
      "policy": "rotate-on-next-deploy"
    }
  ]
}
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "01HW...",
  "results": [
    {
      "ref": "openclaw/webhook/signing_secret",
      "outcome": "ready",
      "version": "2026-05-07T00:00:00Z"
    }
  ]
}
```

Planned write-back operations:

- `generated_secret_capture`
- `refresh`
- `invalidate`
- `reconnect`

## Source status contract

Endpoint:

```text
GET /v1/sources/status
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "sourceConfig": {
    "configured": true,
    "checked": true,
    "platform": "linux",
    "pathHash": "sha256:...",
    "mode": "0644",
    "state": "broad_access",
    "outcome": "degraded",
    "nextAction": "restrict_source_config_permissions",
    "broadReadable": true
  },
  "sources": [
    {
      "sourceId": "local",
      "kind": "local-encrypted-store",
      "outcome": "ready",
      "critical": true
    },
    {
      "sourceId": "vault-prod",
      "kind": "vault",
      "outcome": "identity_expired",
      "critical": false,
      "affectedRefs": ["billing/stripe/api_key"],
      "affectedServices": ["billing"]
    }
  ]
}
```

`sourceConfig` is metadata-only. It reports config-file permission diagnostics without returning the
raw source config path, source tokens, provider credentials, mapped file contents, or resolved values.
On platforms where POSIX-style mode bits are meaningful, owner-only config files should be `0600`.
Broad group/other access is reported as degraded. On Windows, ACL review is required and the mode-bit
check reports `outcome: "not_verified"` rather than claiming protection.

## Error envelope

All endpoint-level errors should use this safe envelope:

```json
{
  "error": {
    "code": "locked",
    "message": "Secrets Broker is locked. Import or unwrap the portable master key before resolving refs.",
    "outcome": "locked",
    "requestId": "01HX...",
    "nextAction": "unlock_broker",
    "affectedRefs": [],
    "affectedServices": []
  }
}
```

Rules:

- `code` is stable and machine-readable.
- `message` is safe for logs/UI.
- `outcome` should be one of the typed outcomes when applicable.
- Secret values must never appear in errors.

## Bootstrap client minimum

A Service Lasso bootstrap client can implement against this contract without knowing broker internals:

1. start process from `service.json`
2. wait for `GET /health`
3. read `GET /capabilities` and confirm compatible `apiVersion`
4. read `GET /state` or `GET /ready`
5. block only dependent refs/services when state/outcome is not globally ready
6. call resolve/write-back endpoints once those features are advertised

## Versioning

- Current API version: `secretsbroker.local/v1`
- Compatible additions may add fields/endpoints/features.
- Breaking schema changes require a new API version string.
- Clients should ignore unknown fields and check feature names before calling optional endpoints.
