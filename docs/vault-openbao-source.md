# Vault and OpenBao Source Adapter

Status: contract-backed adapter MVP
Issue: #47

## Purpose

Clustered/enterprise deployments may keep secret material in HashiCorp Vault or OpenBao while preserving the stable Service Lasso-facing broker contract:

```text
Service Lasso -> @secretsbroker -> Vault/OpenBao cluster
```

## Source config

Vault/OpenBao sources use the same `SECRETSBROKER_SOURCES_PATH` config as env/file/exec sources.

Example:

```json
{
  "sources": [
    {
      "sourceId": "vault-prod",
      "kind": "vault",
      "displayName": "Vault prod",
      "enabled": true,
      "critical": false,
      "priority": 50,
      "namespaces": ["prod/*"],
      "address": "https://vault.example.com",
      "tokenEnv": "VAULT_TOKEN",
      "refs": {
        "prod/openclaw/anthropic_api_key": {
          "path": "secret/data/openclaw/anthropic",
          "field": "api_key"
        }
      }
    }
  ]
}
```

OpenBao uses the same API shape for this MVP:

```json
{ "kind": "openbao" }
```

## Capability and operation model

Vault/OpenBao capability/status output follows the shared adapter contract in `docs/external-adapter-contract.md`:

- `read` and `reveal` are implemented through bounded HTTP reads.
- `write/update`, `rotate/reset`, `policy`, `audit`, and `migration` are advertised for provider planning and Service Admin capability checks.
- Remote write, rotation, policy apply, and migration target apply still require a configured provider operation path before apply is allowed.
- `value-search` is intentionally not advertised for Vault/OpenBao.

## Auth and backend state mapping

- no token/token env missing -> `source_auth_required`
- configured source without an address -> `invalid_ref` in source status
- HTTP 401/403 -> `source_auth_required` or `policy_denied`
- HTTP 404 -> `missing_ref`
- HTTP 400 -> `invalid_ref`
- HTTP 429 or explicit rate-limit/degraded response -> `degraded`
- sealed response body (`{"sealed":true}` on a non-2xx response) -> `locked`
- unreachable/5xx without sealed evidence -> `source_unavailable`
- successful value -> `ready`

`GET /v1/sources/status` reports configured Vault/OpenBao sources without returning tokens. It performs local config/auth-state classification only; it does not poll external clusters on every status request.

## KV response shape

The MVP supports common KV v2 response shape:

```json
{
  "data": {
    "data": {
      "api_key": "value"
    }
  }
}
```

It also accepts a flat `data` object for lightweight OpenBao/Vault-compatible test doubles:

```json
{
  "data": {
    "api_key": "value"
  }
}
```

## Security notes

- tokens are read from env or explicit source token only
- tokens are not returned by status/capabilities/source status
- resolved secret values are returned only through authenticated `POST /v1/resolve`
- audit records include ref/source/outcome only

## Out of scope

- Vault login methods
- token renewal/revoke
- lease handling
- write-back
- namespace auto-discovery
- Service Admin reconnect UX
