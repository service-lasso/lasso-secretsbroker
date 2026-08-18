# OpenBao-compatible KV v2 facade

Status: executable
Issues: #164

Secrets Broker is the out-of-the-box encrypted store. Operators can point a
configured `vault` or `openbao` source at a real OpenBao/Vault cluster instead.
Service Admin talks only to Broker. Both backends speak the same KV v2 JSON.

```text
Service Admin / Service Lasso
        |
        v
  @secretsbroker /v1/kv/*
        |
        +-- local encrypted store (default, ?source=local)
        |
        +-- OpenBao or Vault KV v2 (?source=<sourceId>&mount=secret)
```

This is not an ACL/policy engine and it does not auto-onboard env vars.

## Routes

All routes require the local API token when configured.

| Method | Path | OpenBao equivalent |
| --- | --- | --- |
| GET | `/v1/kv/data/{path}` | GET `/v1/{mount}/data/{path}` |
| POST | `/v1/kv/data/{path}` | POST `/v1/{mount}/data/{path}` |
| PATCH | `/v1/kv/data/{path}` | PATCH `/v1/{mount}/data/{path}` |
| GET | `/v1/kv/metadata/{path}?list=true` | GET `/v1/{mount}/metadata/{path}?list=true` |
| GET | `/v1/kv/metadata/{path}` | GET `/v1/{mount}/metadata/{path}` |
| POST | `/v1/kv/delete/{path}` | POST `/v1/{mount}/delete/{path}` |
| POST | `/v1/kv/undelete/{path}` | POST `/v1/{mount}/undelete/{path}` |

Query parameters:

- `source` defaults to `local`. A configured Vault/OpenBao `sourceId` proxies
  the request to `{address}/v1/{mount}/...` with `X-Vault-Token`.
- `mount` defaults to `secret`, or the source `mount` field when set.
- `version` selects a historic version on GET data.
- `list=true` lists immediate child keys only.

## JSON shapes

Write:

```json
{
  "data": { "username": "demo-user", "password": "value" },
  "options": { "cas": 1 }
}
```

Read:

```json
{
  "data": {
    "data": { "username": "demo-user", "password": "value" },
    "metadata": {
      "created_time": "2026-08-18T00:00:00Z",
      "deletion_time": "",
      "destroyed": false,
      "version": 2,
      "custom_metadata": null
    }
  }
}
```

List (keys only, never values):

```json
{ "data": { "keys": ["apps/", "other"] } }
```

Empty lists and missing/deleted data versions return OpenBao-style
`{"errors":["..."]}` with HTTP 404. CAS mismatches return HTTP 400.

## Local store mapping

- The KV path is the local secret ref (`apps/db`).
- A legacy single-string secret reads as `{ "value": "<plaintext>" }`.
- A write with a single `value` field keeps `/v1/resolve` returning that string.
- Multi-field writes store the JSON object; resolve returns that JSON string.
- Soft delete keeps the encrypted payload and sets `deletion_time`. Undelete
  clears it. Destroy is out of scope for this slice.
- Version history is capped at 10.

## Remote OpenBao/Vault

The proxy does not follow redirects, requires HTTPS outside loopback, bounds
response size, and never logs bodies. Broker still authenticates the operator
token; OpenBao authenticates with the source token/token env.
