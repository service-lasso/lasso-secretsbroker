# OpenClaw SecretRef exec resolver

_Status: initial bounded adapter contract implemented for issue #8._

`secretsbroker-resolve` is a small command for OpenClaw's `exec` SecretRef provider. It lets OpenClaw resolve `openclaw/*` refs through local `@secretsbroker` without storing upstream provider API keys directly in OpenClaw env/config.

## Command

```text
secretsbroker-resolve
```

The command reads one JSON request from stdin and writes one JSON response to stdout. It does not use stderr as a secret transport.

OpenClaw exec provider request:

```json
{"protocolVersion":1,"provider":"service-lasso-secretsbroker","ids":["openclaw/anthropic/api_key"]}
```

Successful response:

```json
{"protocolVersion":1,"values":{"openclaw/anthropic/api_key":"...secret..."}}
```

Typed error response:

```json
{"protocolVersion":1,"values":{},"errors":{"openclaw/anthropic/api_key":"locked"},"outcome":"locked"}
```

Transport/setup errors use the same protocol envelope:

```json
{"protocolVersion":1,"error":"local @secretsbroker is unavailable","outcome":"degraded"}
```

## Local broker connection

Defaults:

- broker URL: `http://127.0.0.1:17890`
- allowed refs: `openclaw/*`
- timeout: `3000ms`

Configuration options:

```text
--broker-url <url>       override local broker URL
--api-token <token>      local broker API token
--api-token-file <path>  file containing local broker API token
--allow <patterns>       comma-separated allowlist, default openclaw/*
--timeout-ms <ms>        broker request timeout
```

Equivalent env vars:

- `SECRETSBROKER_URL`
- `SECRETSBROKER_API_TOKEN`
- `SECRETSBROKER_API_TOKEN_FILE`
- `SECRETSBROKER_RESOLVE_ALLOW`

The resolver authenticates to `POST /v1/resolve` using the local API token. The token identifies the local broker session; the resolver sends `serviceId: "openclaw"` and `purpose: "secretref-exec-provider"` in the broker resolve request for audit attribution.

## Policy

The resolver enforces an OpenClaw-scoped policy before contacting the broker.

Default allowlist:

```text
openclaw/*
```

Denied refs produce `policy_denied` and are not sent to `@secretsbroker`.

## Typed outcomes

The resolver preserves or maps broker outcomes into OpenClaw-readable typed errors:

- `locked`
- `missing_ref`
- `policy_denied`
- `source_auth_required`
- `degraded`

`source_unavailable` is reported as `degraded` for the exec provider boundary.

## Startup boundary

`@secretsbroker` must be started independently by Service Lasso before OpenClaw uses `secretsbroker-resolve` for SecretRefs. This avoids a circular dependency where OpenClaw would need broker-backed secrets to start the broker itself.
