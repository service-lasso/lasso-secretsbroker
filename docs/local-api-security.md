# Local API Security and Session Model

Status: foundation slice  
Issue: #7

## Purpose

Secret-bearing APIs must not be broad plaintext dump surfaces.

This slice establishes the first local access boundary for the loopback HTTP development transport while documenting the intended Vault-like local IPC/session model.

## Current implemented model

Secret-bearing endpoints require a local API token:

- `POST /v1/secrets`
- `POST /v1/writeback`
- `POST /v1/resolve`

Safe bootstrap/status endpoints remain unauthenticated:

- `GET /health`
- `GET /ready`
- `GET /status`
- `GET /state`
- `GET /capabilities`

## Token configuration

Provide the token to the daemon with:

```text
SECRETSBROKER_API_TOKEN=<token>
```

or:

```powershell
secretsbroker serve --api-token <token>
```

Requests may authenticate with either:

```http
Authorization: Bearer <token>
```

or:

```http
X-SecretsBroker-Token: <token>
```

If no token is configured, secret-bearing endpoints return `503 security_not_configured` rather than accepting unauthenticated access.

Token checks trim whitespace, hash both presented and expected tokens, and then compare fixed-size digests in constant time. This avoids length-dependent token comparison behavior while keeping responses generic.

Repeated invalid local API tokens are tracked by local API client scope. Three invalid attempts for the same scope start a five-minute cooldown for secret-bearing endpoints. The lockout response includes safe metadata only and does not echo the presented token or expected token.

Repeated policy-denied management reveal/apply attempts are also tracked with narrow scopes:

- `management:reveal:<serviceId>:<ref>`
- `management:edit:<serviceId>:<ref>`
- `management:reset:<serviceId>:<ref>`
- `management:policy:<serviceId>:<ref>`

Three denied attempts for the same management operation/ref/service start the same five-minute cooldown. The cooldown blocks that exact reveal/apply scope while unrelated refs, unrelated operations, and read-only status/list/dry-run surfaces remain available.

Secret-bearing endpoints cap request bodies at 1 MiB before JSON decode. Oversized requests return `413 request_too_large` with a safe fixed message; request content and bearer tokens are not echoed.

## CLI helpers

Generate a local development token:

```powershell
secretsbroker session generate
```

Check whether token configuration is present without revealing it:

```powershell
secretsbroker session status
```

## Error behavior

Missing/invalid token:

```json
{
  "error": {
    "code": "unauthorized",
    "message": "A valid local API token is required.",
    "outcome": "policy_denied",
    "nextAction": "authenticate_local_session",
    "affectedRefs": [],
    "affectedServices": []
  }
}
```

Active lockout:

```json
{
  "error": {
    "code": "lockout_active",
    "message": "Local API authentication is temporarily locked for this scope.",
    "outcome": "policy_denied",
    "nextAction": "wait_or_clear_lockout",
    "affectedRefs": [],
    "affectedServices": [],
    "lockoutActive": true,
    "lockoutScope": "local_api:127.0.0.1",
    "retryAfterSeconds": 300
  }
}
```

Management reveal/apply lockout response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "requestId": "req-edit",
  "ref": "services/@serviceadmin/runtime/API_TOKEN",
  "operation": "edit",
  "mode": "apply",
  "outcome": "lockout_active",
  "applied": false,
  "requiresConfirmation": false,
  "auditStatus": "audit_pending",
  "nextAction": "wait_or_clear_lockout",
  "affectedRefs": ["services/@serviceadmin/runtime/API_TOKEN"],
  "affectedServices": ["@serviceadmin"],
  "lockoutActive": true,
  "lockoutScope": "management:edit:@serviceadmin:services/@serviceadmin/runtime/API_TOKEN",
  "retryAfterSeconds": 300
}
```

The management lockout response never includes raw secret values, submitted replacement values, provider credentials, local API tokens, auth headers, private keys, cookies, passwords, or environment values.

No server token configured:

```json
{
  "error": {
    "code": "security_not_configured",
    "message": "Secret-bearing endpoints require SECRETSBROKER_API_TOKEN or --api-token.",
    "outcome": "policy_denied",
    "nextAction": "configure_api_token",
    "affectedRefs": [],
    "affectedServices": []
  }
}
```

Oversized body:

```json
{
  "error": {
    "code": "request_too_large",
    "message": "Request body exceeds the local API size limit.",
    "outcome": "policy_denied",
    "nextAction": "reduce_request_size",
    "affectedRefs": [],
    "affectedServices": []
  }
}
```

## Planned production model

Preferred transports:

- Windows named pipe with OS-authenticated local client identity
- Unix socket with filesystem permissions and peer credential checks where available
- loopback HTTP only for development/bootstrap compatibility

Planned session model:

- short-lived scoped sessions/tokens
- service identity authentication for launched services
- per-service/ref policy checks before resolve/write-back
- lease/renew/revoke for runtime identities where applicable
- audit events for allow/deny/resolve/write-back without plaintext values
- durable audited lockout clear workflow for management clients

## Non-goals for this slice

- full policy engine
- named pipe/Unix socket implementation
- service identity leases
- user-facing unlock/setup wizard
- broad plaintext dump command
