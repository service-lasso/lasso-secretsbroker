# AWS Secrets Manager source

`aws-secrets-manager` is a Secrets Broker source kind behind the stable `@secretsbroker` contract. It may reveal secret values to broker resolution and broker-internal value-search paths, but status, diagnostics, management lists, audit events, logs, and fixtures remain metadata-only.

The connection-scoped operation manifest is authoritative for action
enablement. Read/reveal and metadata-only value search are validated; rotation
planning is dry-run; remote edit, reset, rotation, policy, migration, and sync
apply paths are not currently executable.

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

## Failure mapping

- missing token or auth identity -> `source_auth_required`
- expired identity -> `identity_expired`
- access denied -> `policy_denied`
- missing secret id or field -> `missing_ref`
- throttling or rate limits -> `degraded`
- invalid request or mapping -> `invalid_ref`
- timeout, unavailable endpoint, oversized response, or malformed payload -> `source_unavailable`

## Safety boundaries

- SecretString values may be returned only to resolve/reveal call paths.
- Value search may inspect provider values internally but returns refs and metadata only.
- Source status reports source id, kind, capability, lifecycle, namespace, and next action metadata only.
- Provider tokens, session material, raw response bodies, and secret values must not appear in errors, diagnostics, audit payloads, logs, screenshots, persisted fixtures, or issue/PR evidence.
