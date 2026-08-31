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
      "trustedDirs": ["./secrets"],
      "refs": {
        "openclaw/telegram/bot_token": {
          "path": "./secrets/telegram-token.txt",
          "maxBytes": 65536
        }
      }
    },
    {
      "sourceId": "exec-local",
      "kind": "exec",
      "enabled": true,
      "allowExecInProduction": true,
      "priority": 30,
      "trustedDirs": ["C:/tools/secrets"],
      "refs": {
        "openclaw/github/token": {
          "command": "C:/tools/secrets/read-secret.exe",
          "commandSha256": "<reviewed-lowercase-sha256>",
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
- when `trustedDirs` is configured on the source, mapped files must resolve under one trusted directory
- `maxBytes` limits the file read and defaults to 65536 bytes
- empty file is `source_unavailable`
- missing or unreadable file is `source_unavailable`
- files over the configured byte limit are `source_unavailable`
- value is returned only through authenticated resolve
- diagnostics and status output must not include file contents
- production requires at least one `trustedDirs` entry and rejects symlink/reparse components

## Exec adapter hardening

The exec adapter is intentionally strict:

- no shell execution
- command must be configured exactly
- production exec is disabled unless `allowExecInProduction` is explicitly true
- production command paths must be absolute regular files under a configured `trustedDirs` entry
- production rejects every symlink/reparse component and requires an exact lowercase `commandSha256`
- args are fixed in config
- the generic exec adapter receives an empty environment
- timeout defaults to 2000ms
- max stdout defaults to 4096 bytes
- production rejects timeout values over 30 seconds and output limits over 1 MiB
- stderr is never treated as secret
- JSON protocol mode is default: stdout must be `{ "value": "..." }`
- simple stdout mode requires `unsafeStdout: true`

Outcomes:

- `ready` when command succeeds and returns a non-empty value
- `source_unavailable` for command failures/timeouts/empty output
- `invalid_ref` for invalid source config

## Source status

`GET /v1/sources/status` includes configured env/file/exec sources without exposing values.

When a source config path is configured, the response also includes a metadata-only `sourceConfig`
summary. The summary reports whether the config was checked, the platform, a path hash, the observed
permission state, and safe lifecycle fields such as `state`, `outcome`, and `nextAction`. It never
includes the raw config path, source tokens, provider credentials, mapped file contents, or resolved
values. Source configuration is opened as a bounded regular file and durable writes use owner-only
permissions (`0600`/`0700` on Unix and an owner-only ACL on Windows).

## Audit

Each source resolve attempt is audited by ref/source/outcome without secret values.
