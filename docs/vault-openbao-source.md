# Vault and OpenBao Source Adapter

Status: validated read adapter plus explicitly enabled KV v2 migration target
Issues: #47, #146

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
      "enableMigrationTarget": true,
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
- Migration target apply is validated only for the exact enabled connection when
  `enableMigrationTarget: true`, address, token/token env, and every ref path and
  field mapping pass local validation.
- A disabled or incomplete connection remains planned/unsupported. The
  provider-family capability is also still planning metadata and never enables
  apply by itself.
- General write/update, rotate/reset and policy apply remain unavailable or
  planned; the executable mutation is limited to verified KV v2 migration.
- `value-search` is intentionally not advertised for Vault/OpenBao.

Service Admin must use the connection-scoped operation manifest. Vault/OpenBao
read/reveal are validated. Migration apply is validated only on an explicitly
enabled and fully configured connection; all other remote apply operations are
unavailable or planned.

## Auth and backend state mapping

- no token/token env missing -> `source_auth_required`
- configured source without an address -> `invalid_ref` in source status
- HTTP 401/403 -> `source_auth_required` or `policy_denied`
- HTTP 404 -> `missing_ref`
- HTTP 400 -> `invalid_ref`
- HTTP 429 -> `rate_limited`
- KV v2 CAS conflict (HTTP 400/409/412 on write) -> `conflict`
- sealed response body (`{"sealed":true}` on a non-2xx response) -> `locked`
- unreachable/5xx without sealed evidence -> `source_unavailable`
- successful value -> `ready`

`GET /v1/sources/status` reports configured Vault/OpenBao sources without returning tokens. It performs local config/auth-state classification only; it does not poll external clusters on every status request.

## KV v2 migration protocol

Reads use the common KV v2 response shape, including metadata version for CAS:

```json
{
  "data": {
    "data": { "api_key": "value" },
    "metadata": { "version": 7 }
  }
}
```

The read-only source adapter also accepts a flat `data` object for lightweight
compatibility. Migration target apply does not: it requires KV v2 metadata so it
can write with a compare-and-set version.

Before writing, the executor reads the current target. It preserves sibling
fields, skips the POST when the mapped field is already equal, and otherwise
POSTs `{data, options: {cas}}`. A separate bounded GET must return the expected
field value before the durable operation is marked migrated. Source values are
not deleted.

The validated matrix for this release is the Vault/OpenBao KV v2 HTTP protocol
implemented by bounded `httptest` protocol suites for both provider kinds.
Live-cluster certification for named HashiCorp Vault and OpenBao product
versions remains tracked by #134; this document does not claim a live version
that has not been exercised with external credentials.

## Security notes

- tokens are read from env or explicit source token only
- tokens are not returned by status/capabilities/source status
- authenticated requests never follow redirects
- remote targets require HTTPS; plaintext HTTP is accepted only for loopback testing
- request/response bodies and timeouts are bounded per mapping and capped by the Broker
- remote bodies and transport errors are reduced to typed outcomes and never returned
- resolved secret values are returned only through authenticated `POST /v1/resolve`
- audit records include ref/source/outcome only

## Out of scope

- Vault login methods
- token renewal/revoke
- lease handling
- general provider write-back outside verified migration
- namespace auto-discovery
- Service Admin reconnect UX
