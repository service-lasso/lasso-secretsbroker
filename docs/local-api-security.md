# Local API Security and Session Model

Status: foundation slice  
Issue: #7

## Purpose

Secret-bearing APIs must not be broad plaintext dump surfaces.

This slice establishes the first local access boundary for the loopback HTTP development transport while documenting the intended Vault-like local IPC/session model.

## Current implemented model

Secret-bearing endpoints require a local API token:

- `POST /v1/secrets`
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

## Non-goals for this slice

- full policy engine
- named pipe/Unix socket implementation
- service identity leases
- user-facing unlock/setup wizard
- broad plaintext dump command
