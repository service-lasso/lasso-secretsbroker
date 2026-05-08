# Secrets Broker Headless Admin CLI

Status: implemented contract slice  
Issue: #40  
Service id: `@secretsbroker`

## Purpose

Headless/server operators need a safe CLI surface for Secrets Broker when Service Admin is unavailable or intentionally not installed. The CLI mirrors existing local API/admin contracts and stays metadata-first by default.

## Safety defaults

- Status, list, search, provider status, migration dry-run, and audit export output metadata only.
- Provider credentials, portable master keys, wrapper plaintext, raw env values, tokens, passwords, cookies, private keys, and secret values are never printed by default.
- Raw secret values are printed only by `admin secrets reveal` when all of these are present:
  - a valid ref
  - `--reason <audit reason>`
  - `--confirm`
  - not `--no-echo`
- `--no-echo` performs the reveal/audit check but suppresses the value and returns reveal metadata/guidance only.
- Failure states fail closed with typed outcomes such as `locked`, `missing_ref`, `invalid_ref`, `policy_denied`, `source_auth_required`, `unsupported`, and `degraded`.

## Commands

All commands support the existing local store flags where applicable:

```text
--store <path>
--audit <path>
--master-key <key>
--master-key-file <path>
--sources <path>
```

### Status / health summary

```powershell
secretsbroker admin status --master-key-file .\secure\portable-master-key.txt
```

Returns service status, health, lifecycle state, capabilities, and provider config summary. Output contains status metadata only.

### List/search secret metadata

```powershell
secretsbroker admin secrets list --master-key-file .\secure\portable-master-key.txt
secretsbroker admin secrets search --query SESSION --master-key-file .\secure\portable-master-key.txt
secretsbroker admin secrets value-search --query signing --master-key-file .\secure\portable-master-key.txt
```

List and search never return raw values. Value-search may inspect broker-held values internally, but output remains refs/status/metadata only.

### Controlled reveal

```powershell
secretsbroker admin secrets reveal `
  --ref services/@serviceadmin/runtime/SESSION_SIGNING_KEY `
  --reason "operator troubleshooting" `
  --confirm `
  --master-key-file .\secure\portable-master-key.txt
```

This is the only CLI path that may print a raw value. Prefer `--no-echo` when the operator only needs to verify access and create an audit record:

```powershell
secretsbroker admin secrets reveal `
  --ref services/@serviceadmin/runtime/SESSION_SIGNING_KEY `
  --reason "verify access without printing" `
  --confirm `
  --no-echo `
  --master-key-file .\secure\portable-master-key.txt
```

### Provider status and config validation

```powershell
secretsbroker admin providers capabilities
secretsbroker admin providers status --master-key-file .\secure\portable-master-key.txt
secretsbroker admin providers validate `
  --provider-id vault-dev `
  --provider-kind vault `
  --address https://vault.example.invalid `
  --credential-ref secret://local/provider/vault-dev/token
```

Validation rejects plaintext credential payloads and reports credential refs/handles only.

### Migration dry-run/apply status

```powershell
secretsbroker admin migration dry-run `
  --source-provider local `
  --target-provider local `
  --ref services/@serviceadmin/runtime/SESSION_SIGNING_KEY
```

Migration dry-run is metadata-only. Apply requires `--confirm`, `--operation-id`, and `--reason` and still does not print raw values.

### Audit export

```powershell
secretsbroker admin audit export --audit .\data\secretsbroker-audit.jsonl --operation management_reveal
```

Audit export returns operation/ref/outcome/timestamp/request metadata only. Audit events must not contain raw values.

### Unlock/import/re-wrap

Master-key lifecycle commands are part of the same headless operator workflow and are documented in `docs/master-key-lifecycle.md`:

```text
secretsbroker key initialize
secretsbroker key unlock
secretsbroker key import
secretsbroker key rewrap
secretsbroker key wrapper-status
```
