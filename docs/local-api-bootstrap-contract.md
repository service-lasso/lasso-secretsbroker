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

The initial daemon exposes loopback HTTP. Named pipe/Unix socket transports should preserve the same request/response schema.

## Cross-cutting response rules

- API version is visible in `status` and `capabilities` responses.
- Secret values are never returned by status/capabilities/state/source-status endpoints.
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
- `identity_expired`

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
    "GET /capabilities"
  ],
  "features": [
    "liveness",
    "readiness",
    "status",
    "state",
    "capabilities"
  ],
  "futureFeatures": [
    "batched-resolve",
    "write-back",
    "source-status",
    "typed-errors",
    "audit-redaction"
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
    "identity_expired"
  ]
}
```

## Planned resolve contract

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
      "outcome": "source_auth_required",
      "message": "Telegram source needs reconnect before this ref can be resolved.",
      "nextAction": "reconnect_source"
    }
  ]
}
```

Rules:

- Values are present only for refs allowed by policy and only on resolve endpoints.
- Missing/denied/invalid/auth-required entries use per-result outcomes.
- Audit records must redact secret values.

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

## Planned source status contract

Endpoint:

```text
GET /v1/sources/status
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
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
