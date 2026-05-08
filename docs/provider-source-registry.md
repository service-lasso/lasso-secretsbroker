# Provider Connection and Source Registry Model

Status: lifecycle normalization implemented
Issues: #12, #24

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
  "state": "connected",
  "outcome": "ready",
  "nextAction": "",
  "retryable": false,
  "lifecycle": {
    "state": "connected",
    "outcome": "ready",
    "retryable": false
  },
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

## Source lifecycle states

Source lifecycle states are normalized for UI/API consumers while preserving the lower-level broker outcome that caused the state:

| Lifecycle state | Common outcomes | Meaning | Next action |
| --- | --- | --- | --- |
| `connected` | `ready` | Source is configured and usable. | none |
| `missing` | `missing_ref` | Requested ref/path/field is absent. | `check_ref` |
| `denied` | `policy_denied` | Source policy denied the request. | `review_policy` |
| `auth_required` | `source_auth_required` | Credentials are missing, expired, or unauthorized. | `reconnect_source` |
| `revoked` | `identity_expired` | Launch/session identity is no longer valid. | `renew_identity` |
| `reconnect_required` | `locked` | Local store is locked or external source is sealed. | `unlock_or_unseal_source` |
| `config_error` | `invalid_ref` | Source or ref mapping is invalid. | `fix_source_mapping` |
| `degraded` | `source_unavailable`, `degraded` | Source is temporarily unavailable or refresh failed. | `retry_or_inspect_source` |
| `disabled` | `disabled` | Source is configured but disabled. | `enable_source` |

`degraded` outcomes are retryable and include bounded `retryAfterMs` metadata. Status and audit surfaces report refs, source ids, states, outcomes, and next actions only; they must not include raw credentials or secret values.

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

The implemented registry includes the default local source plus configured `env`, `file`, `exec`, `vault`, and `openbao` sources:

- `sourceId`: visible stable source identifier
- `kind`: `local-encrypted-store`, `env`, `file`, `exec`, `vault`, or `openbao`
- `capabilities`: source-safe capabilities such as `read`, `write`, and `health`
- `namespaces`: claimed namespaces or `*`
- `state`/`outcome`/`nextAction`/`retryable`: normalized lifecycle view
- `lifecycle`: structured lifecycle object mirroring the normalized fields

Local source state follows broker store/key state:
- no master key => lifecycle `reconnect_required`, outcome `locked`
- master key available => lifecycle `connected`, outcome `ready`

Endpoint:

```text
GET /v1/sources/status
```

Secret values are not returned. Source lifecycle audit events also redact values and record only operation, source id, ref, state, outcome, service id, and request id.

## Out of scope

- AWS/1Password/Bitwarden/BWS adapters
- persistent registry config UI
- policy engine
- active background refresh scheduler beyond per-request lifecycle normalization
