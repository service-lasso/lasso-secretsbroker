# Master-Key Unlock, Import, and Local Re-Wrap Workflow

Status: implemented contract slice  
Issue: #39  
Service id: `@secretsbroker`

## Purpose

Secrets Broker uses one portable master key to encrypt the local vault payloads. Each machine can additionally keep a local OS/user-scoped wrapper for that same portable key so the encrypted store remains portable without requiring the operator to paste the key on every start.

Canonical model:

```text
portable master key -> encrypts vault payloads
current OS/user wrapper -> protects a local copy of the portable master key
```

The portable key is sensitive secret material. API/CLI lifecycle responses expose only status, key id fingerprints, wrapper metadata, next actions, and recovery guidance. They never echo supplied key material or unwrapped key bytes.

## Lifecycle states

| State | Meaning | Typical next action |
| --- | --- | --- |
| `setup_needed` | No local encrypted store exists yet. | `initialize_store` |
| `locked` | A store exists, but the current process cannot access matching master-key material. | `unlock_with_portable_key` or `import_portable_key` |
| `ready` | Store exists and supplied/wrapped key material can decrypt current payloads. | operate normally |
| `source_auth_required` | A configured source needs reconnect/auth before affected refs can resolve. | `reconnect_source` |
| `degraded` | Store/source is partially unusable, including corrupted ciphertext or invalid wrapper payloads. | inspect diagnostics/recover from backup |

## CLI contract

### Initialize local encrypted store

```powershell
secretsbroker key initialize `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --master-key-file .\secure\portable-master-key.txt
```

Creates an empty encrypted local store if one does not already exist and validates the portable key format. The response includes `outcome`, `state`, `keyId`, `storePath`, and `nextAction`; it does not include the portable key.

First initialization also creates the Service Lasso vault root owner identity and stores safe metadata under `rootIdentity`. The root identity is the vault owner for bootstrap/recovery contract purposes and is not OS root/admin. The store records only metadata such as vault id, root actor id, key id/fingerprint, key source type, machine context, and loss semantics.

### Initialize with broker-generated key

```powershell
secretsbroker key initialize `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --generate `
  --one-time-reveal
```

When the broker generates the bootstrap key, `--one-time-reveal` is required for the CLI setup ceremony. The generated key appears only in the initialize response. The store, wrapper, audit log, event log, and later status metadata contain only safe key id/fingerprint and source metadata.

### Unlock with portable master key

```powershell
secretsbroker key unlock `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --master-key-file .\secure\portable-master-key.txt
```

Validates that the supplied key matches the existing store metadata and can decrypt every stored payload. Wrong keys and corrupted ciphertext fail closed with `locked` or `degraded` outcomes and no plaintext output.

### Import existing vault on a new machine

```powershell
secretsbroker key import `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --wrapper .\data\secretsbroker-wrapper.json `
  --master-key-file .\secure\portable-master-key.txt
```

Use after copying an encrypted store to a new machine. Import validates the portable key, verifies it against the copied store, then writes a local OS/user wrapper for future unlocks. The response exposes wrapper metadata only.

### Re-wrap for current OS/user/machine

```powershell
secretsbroker key rewrap `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --wrapper .\data\secretsbroker-wrapper.json `
  --master-key-file .\secure\portable-master-key.txt
```

Re-wraps the same portable key for the current OS/user/machine context. Re-wrap is auditable and fail-closed: unsupported wrapper providers, unreadable wrappers, wrong keys, corrupted ciphertext, or store verification failures do not write a new wrapper.

### OS wrapper status

```powershell
secretsbroker key wrapper-status --wrapper .\data\secretsbroker-wrapper.json
```

Reports whether a local wrapper exists, whether the current OS wrapper provider is supported, the wrapper kind, OS, key id, and recovery guidance. It never unwraps or returns the portable key.

## Recovery guidance

- If the store is `setup_needed`, initialize it with a secure portable key.
- If the store is `locked`, supply/import the matching portable key or restore a backup with the matching key.
- If ciphertext or wrapper payloads are corrupted, restore the encrypted store and wrapper from backup, or import the portable key again and re-wrap.
- If the OS wrapper provider is unsupported, keep using explicit portable-key file/env/flag unlock until a supported wrapper provider is available.

## Audit rules

Lifecycle operations emit audit events with operation, outcome, timestamp, and safe metadata only:

- `key_initialize`
- `key_generated`
- `supplied_key_used`
- `vault_created`
- `root_identity_created`
- `setup_completed`
- `vault_unlock_failure`
- `key_unlock`
- `key_import`
- `key_rewrap`
- `key_wrapper_status`

Audit payloads must never contain the portable master key, plaintext secrets, wrapper plaintext, or submitted key material.
