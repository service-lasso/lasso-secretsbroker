# Provider Connection and Source Registry Model

Status: initial model  
Issue: #12

## Purpose

`@secretsbroker` needs one consistent source model for local encrypted storage and future backends such as Vault/OpenBao, AWS Secrets Manager, 1Password, Bitwarden/BWS, env, file, and exec.

The model separates:

- visible source/connection metadata
- encrypted secret material
- source health/state
- audit events
- namespace/ref mapping

## Core entities

### Source registry entry

A source registry entry describes a configured backend/source without revealing secret values.

```json
{
  "sourceId": "local",
  "kind": "local-encrypted-store",
  "displayName": "Local encrypted store",
  "enabled": true,
  "critical": true,
  "priority": 0,
  "capabilities": ["read", "write", "health"],
  "namespaces": ["*"],
  "state": "ready",
  "affectedRefs": [],
  "affectedServices": []
}
```

### Provider connection metadata

Provider connection metadata is visible and listable. It should be safe for UI/status surfaces.

```json
{
  "connectionId": "openai-primary",
  "sourceId": "local",
  "provider": "openai",
  "workspaceId": "workspace-local",
  "displayName": "OpenAI primary",
  "state": "ready",
  "createdAt": "2026-05-07T00:00:00Z",
  "updatedAt": "2026-05-07T00:00:00Z"
}
```

### Provider connection secrets

Secret payloads are encrypted and stored separately from visible metadata.

```json
{
  "connectionId": "openai-primary",
  "ref": "openclaw/openai/api_key",
  "sourceId": "local",
  "payload": {
    "alg": "AES-256-GCM",
    "keyId": "mk-0123456789abcdef",
    "keyVersion": "v1",
    "nonce": "base64...",
    "ciphertext": "base64..."
  }
}
```

### Provider connection audit

Audit records never include secret values.

```json
{
  "ts": "2026-05-07T00:00:00Z",
  "actor": "service:openclaw",
  "sourceId": "local",
  "ref": "openclaw/openai/api_key",
  "action": "resolve",
  "outcome": "ready"
}
```

## Capabilities

Canonical capability names:

- `read`
- `write`
- `write-back`
- `health`
- `lease`
- `renew`
- `revoke`
- `reconnect`
- `auth-required`

## Source states

Canonical source states align with broker outcomes:

- `ready`
- `setup_needed`
- `locked`
- `source_auth_required`
- `degraded`
- `source_unavailable`
- `identity_expired`
- `policy_denied`

## Namespace mapping

A source can claim namespaces:

```json
{
  "sourceId": "vault-prod",
  "namespaces": ["prod/*", "billing/*"]
}
```

Resolution should choose the highest-priority enabled source whose namespace mapping matches the ref.

The local store can act as default fallback with namespace `*`.

## Reconnect/source-auth transitions

- missing or expired auth should become `source_auth_required` or `identity_expired`
- optional source outage should become `degraded` or `source_unavailable`
- affected refs/services should be reported by identifier only
- unrelated refs/services should continue when possible

## Current implemented MVP

This slice adds an in-process registry with the default local source:

- `sourceId`: `local`
- `kind`: `local-encrypted-store`
- `capabilities`: `read`, `write`, `health`
- `namespaces`: `*`
- state follows broker store/key state:
  - no master key => `locked`
  - master key available => `ready`

Endpoint:

```text
GET /v1/sources/status
```

Secret values are not returned.

## Out of scope

- env/file/exec adapters
- Vault/OpenBao adapter
- AWS/1Password/Bitwarden/BWS adapters
- persistent registry config UI
- policy engine
