# Local Encrypted Store and Resolve API

Status: MVP contract  
Issue: #3  
API version: `secretsbroker.local/v1`

## Purpose

This document defines the first local backend for `@secretsbroker`:

```text
Service Lasso -> @secretsbroker -> local encrypted store
```

The MVP is intentionally small but establishes the important invariants:

- secret metadata is stored separately from encrypted payload values
- plaintext values do not appear in normal logs, diagnostics, status, or audit records
- secret refs are namespace-aware strings such as `openclaw/anthropic/api_key`
- runtime clients resolve refs through a batched API
- missing/locked/invalid outcomes are typed per ref where possible

## Local store file

Default path:

```text
./data/secretsbroker-store.json
```

Override:

```text
SECRETSBROKER_STORE_PATH=C:\path\to\secretsbroker-store.json
```

The store is JSON so early development remains inspectable, but secret values are encrypted with AES-GCM.

Illustrative shape:

```json
{
  "version": 1,
  "serviceId": "@secretsbroker",
  "createdAt": "2026-05-07T00:00:00Z",
  "updatedAt": "2026-05-07T00:00:00Z",
  "secrets": {
    "openclaw/anthropic/api_key": {
      "ref": "openclaw/anthropic/api_key",
      "metadata": {
        "sourceId": "local",
        "version": "2026-05-07T00:00:00Z",
        "createdAt": "2026-05-07T00:00:00Z",
        "updatedAt": "2026-05-07T00:00:00Z"
      },
      "payload": {
        "alg": "AES-256-GCM",
        "keyId": "mk-0123456789abcdef",
        "keyVersion": "v1",
        "nonce": "base64...",
        "ciphertext": "base64..."
      }
    }
  }
}
```

## Key material

MVP key sources:

```text
SECRETSBROKER_MASTER_KEY=<development/local key material>
SECRETSBROKER_MASTER_KEY_FILE=./data/master-key.txt
```

No master key means the local store is `locked` for secret read/write/resolve operations.

Portable master-key identity and key metadata are documented in `docs/portable-master-key.md`. OS wrapper unlock/enrollment remains future scope.

## Audit log

Default path:

```text
./data/secretsbroker-audit.jsonl
```

Override:

```text
SECRETSBROKER_AUDIT_PATH=C:\path\to\secretsbroker-audit.jsonl
```

Audit events are JSON Lines and must not include plaintext secret values.

Example:

```json
{"ts":"2026-05-07T00:00:00Z","operation":"resolve","ref":"openclaw/anthropic/api_key","outcome":"ready","serviceId":"openclaw"}
```

## Write endpoint

MVP local write endpoint:

```text
POST /v1/secrets
```

Request:

```json
{
  "ref": "openclaw/anthropic/api_key",
  "value": "plaintext accepted only by this write endpoint",
  "metadata": {
    "sourceId": "local"
  }
}
```

Response:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "ref": "openclaw/anthropic/api_key",
  "outcome": "ready",
  "metadata": {
    "sourceId": "local",
    "version": "2026-05-07T00:00:00Z"
  }
}
```

The response never echoes the plaintext value.

## Batched resolve endpoint

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
  "identityLease": {
    "issuer": "service-lasso-local-launcher",
    "serviceId": "openclaw",
    "workspaceId": "workspace-local",
    "allowedRefs": ["openclaw/*"],
    "allowedOperations": ["resolve"],
    "issuedAt": "2026-05-07T00:00:00Z",
    "expiresAt": "2026-05-07T00:05:00Z",
    "jti": "01J...",
    "signature": "hmac-sha256:..."
  },
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
      "value": "plaintext only on successful resolve result",
      "metadata": {
        "sourceId": "local",
        "version": "2026-05-07T00:00:00Z"
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

- HTTP resolve requests require a signed launch identity lease as documented in `docs/launch-identity-leases.md`.
- Batch response reports per-ref outcomes.
- Missing refs use `missing_ref`, not generic failure.
- Invalid refs use `invalid_ref`.
- Denied refs use `policy_denied` with safe policy metadata only: `policyResult`, `nextAction`, and `reasonCode`.
- Locked store uses `locked` per requested ref.
- `value` is present only when outcome is `ready`.
- Policy decisions and resolve outcomes are audited with metadata only. Audit logs redact values.

## Ref validation

MVP refs must:

- be non-empty
- contain only path-like segments separated by `/`
- not start or end with `/`
- not include `..`
- not include whitespace

This intentionally supports namespace-aware refs like:

```text
openclaw/anthropic/api_key
billing/stripe/api_key
workspace-local/github/token
```

## Out of scope

- portable master-key import/unwrap
- OS wrapper storage
- policy engine
- source adapters
- Service Admin UI
- Service Lasso manifest resolver integration
