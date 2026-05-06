# Env, File, and Exec Source Adapters

Status: MVP  
Issue: #5

## Purpose

`@secretsbroker` can resolve refs from the local encrypted store and, when configured, from simple external local sources:

- `env`
- `file`
- `exec`

These are sources behind the stable broker contract, not replacements for `@secretsbroker`.

## Source config

Default: no external sources configured.

Configure with:

```text
SECRETSBROKER_SOURCES_PATH=./config/sources.json
```

or:

```powershell
secretsbroker serve --sources ./config/sources.json
```

Example:

```json
{
  "sources": [
    {
      "sourceId": "env-local",
      "kind": "env",
      "displayName": "Local env",
      "enabled": true,
      "critical": false,
      "priority": 10,
      "namespaces": ["openclaw/*"],
      "refs": {
        "openclaw/anthropic/api_key": { "env": "ANTHROPIC_API_KEY" }
      }
    },
    {
      "sourceId": "file-local",
      "kind": "file",
      "enabled": true,
      "priority": 20,
      "refs": {
        "openclaw/telegram/bot_token": { "path": "./secrets/telegram-token.txt" }
      }
    },
    {
      "sourceId": "exec-local",
      "kind": "exec",
      "enabled": true,
      "priority": 30,
      "trustedDirs": ["C:/tools/secrets"],
      "refs": {
        "openclaw/github/token": {
          "command": "C:/tools/secrets/read-secret.exe",
          "args": ["openclaw/github/token"],
          "timeoutMs": 2000,
          "maxStdoutBytes": 4096
        }
      }
    }
  ]
}
```

## Resolution order

1. local encrypted store
2. enabled configured sources by priority
3. missing ref

Each ref in a batched resolve response gets an independent outcome.

## Env adapter

Reads an exact environment variable name from the source config.

Outcomes:

- `ready` when env var exists and is non-empty
- `missing_ref` when the ref is not mapped
- `source_unavailable` when mapped env var is empty/missing

## File adapter

Reads a file path from the source config.

Rules:

- file value is trimmed of surrounding whitespace
- empty file is `source_unavailable`
- missing file is `source_unavailable`
- value is returned only through authenticated resolve

## Exec adapter hardening

The exec adapter is intentionally strict:

- no shell execution
- command must be configured exactly
- command must be absolute when the OS/path format can determine that
- command must live under one configured `trustedDirs` entry when `trustedDirs` is set
- symlink commands are rejected unless `allowSymlinkCommand` is true
- args are fixed in config
- timeout defaults to 2000ms
- max stdout defaults to 4096 bytes
- stderr is never treated as secret
- JSON protocol mode is default: stdout must be `{ "value": "..." }`
- simple stdout mode requires `unsafeStdout: true`

Outcomes:

- `ready` when command succeeds and returns a non-empty value
- `source_unavailable` for command failures/timeouts/empty output
- `invalid_ref` for invalid source config

## Source status

`GET /v1/sources/status` includes configured env/file/exec sources without exposing values.

## Audit

Each source resolve attempt is audited by ref/source/outcome without secret values.
