# AWS Secrets Manager source

`aws-secrets-manager` is a Secrets Broker source kind behind the stable `@secretsbroker` contract. It may reveal secret values to broker resolution and broker-internal value-search paths, but status, diagnostics, management lists, audit events, logs, and fixtures remain metadata-only.

The connection-scoped operation manifest is authoritative for action
enablement. Read/reveal and metadata-only value search are validated; rotation
planning is dry-run. Migration apply becomes validated only for an exact source
that explicitly enables and fully configures the production migration executor.
Remote edit, reset, rotation, policy, and sync apply remain non-executable.

## Source config

AWS sources use the same `SECRETSBROKER_SOURCES_PATH` config as other external adapters:

```json
{
  "sources": [
    {
      "sourceId": "aws-prod",
      "kind": "aws-secrets-manager",
      "enabled": true,
      "region": "us-east-1",
      "tokenEnv": "AWS_TEST_SESSION_TOKEN",
      "namespaces": ["prod/*"],
      "refs": {
        "prod/openclaw/api_key": {
          "path": "service-lasso/prod/api",
          "field": "api_key"
        }
      }
    }
  ]
}
```

`address` may be set for tests or local AWS-compatible mocks. If `address` is omitted, `region` is used to derive the Secrets Manager endpoint. Tests use fake tokens and fake secret strings only.
Private-PKI compatible endpoints can use the digest-pinned trust contract in
`docs/source-tls-trust.md`.

The read-adapter fixture above is retained for compatibility. A production
migration target must instead add explicit signing credential handles and opt in:

```json
{
  "sourceId": "aws-prod",
  "kind": "aws-secrets-manager",
  "enabled": true,
  "enableMigrationTarget": true,
  "region": "us-east-1",
  "accessKeyIdEnv": "AWS_ACCESS_KEY_ID",
  "secretAccessKeyEnv": "AWS_SECRET_ACCESS_KEY",
  "sessionTokenEnv": "AWS_SESSION_TOKEN",
  "refs": {
    "prod/openclaw/api_key": {
      "path": "service-lasso/prod/api",
      "field": "api_key",
      "versionStage": "AWSCURRENT"
    }
  }
}
```

These fields are environment-variable names, not credential values. The Broker
resolves the access key, secret access key, and optional session token for every
provider operation so rotated session credentials take effect without
persisting them. Missing handles or values fail closed and migration apply stays
planned. Custom non-loopback endpoints require HTTPS; redirects are never
followed.

## Validated migration operation matrix

| Provider protocol | Operation | Local evidence | Release status |
| --- | --- | --- | --- |
| AWS Secrets Manager JSON 1.1, SigV4 service `secretsmanager` | `PutSecretValue` with deterministic `ClientRequestToken` | fixed-clock signed `httptest` protocol fixture | validated for a fully configured connection |
| AWS Secrets Manager JSON 1.1, SigV4 service `secretsmanager` | independent `GetSecretValue` at `AWSCURRENT` | signed readback, value comparison, retry/restart tests | validated for a fully configured connection |

The executor migrates into an existing Secrets Manager secret; it does not call
`CreateSecret`. A field mapping requires the current `SecretString` to be a JSON
object and preserves sibling fields. An empty field mapping replaces the entire
`SecretString`. The write uses a stable 64-character request token derived from
the Broker's durable per-ref idempotency key, and an independently authenticated
readback must match before the ref is reported migrated. Source data remains
unchanged and recoverable throughout.

This matrix is deterministic local protocol evidence only. It does not claim
live AWS account, IAM-policy, endpoint-version, or cloud certification proof.

## Failure mapping

- missing token or auth identity -> `source_auth_required`
- expired identity -> `identity_expired` for read; `source_auth_required` for migration retry
- access denied -> `policy_denied`
- missing secret id or field -> `missing_ref`
- throttling or rate limits during migration -> `rate_limited`
- duplicate request-token/version conflicts -> `conflict`
- invalid request or mapping -> `invalid_ref`
- timeout, unavailable endpoint, oversized response, or malformed payload -> `source_unavailable`

## Safety boundaries

- SecretString values may be returned only to resolve/reveal call paths.
- Value search may inspect provider values internally but returns refs and metadata only.
- Source status reports source id, kind, capability, lifecycle, namespace, and next action metadata only.
- Provider tokens, session material, raw response bodies, and secret values must not appear in errors, diagnostics, audit payloads, logs, screenshots, persisted fixtures, or issue/PR evidence.
