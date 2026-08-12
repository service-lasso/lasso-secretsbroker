# Vault Root Identity and Bootstrap Key Contract

Status: implemented contract slice
Issue: #127
Service id: `@secretsbroker`

## Purpose

The Secrets Broker owns the local vault and creates the Service Lasso vault root owner identity when the vault is first initialized. This identity is the vault owner for Service Lasso bootstrap and recovery metadata. It is not OS root, an administrator account, or a general host privilege claim.

## Bootstrap Sources

Fresh vault initialization supports two key source types:

- `supplied` or `supplied_file`: Service Lasso core, an operator, or a headless/container launcher supplies the portable vault key through the existing key material inputs.
- `generated`: the broker generates a new 256-bit portable vault key for an explicit setup ceremony.

Generated-key initialization through the CLI requires `--one-time-reveal`. The reveal appears only in that initialize response and is not written to the store, audit log, event log, wrapper, or status metadata. Supplied-key initialization never includes a reveal.

## Safe Metadata

The initialized store records metadata only:

- `vaultId`
- `rootIdentity.rootActorId`
- `rootIdentity.createdAt`
- `rootIdentity.bootstrapSource`
- `rootIdentity.keySourceType`
- `rootIdentity.keyId`
- `rootIdentity.keyVersion`
- `rootIdentity.localMachineContext.os`
- `rootIdentity.localMachineContext.username`
- `rootIdentity.localMachineContext.machine`
- `rootIdentity.lossSemantics`
- `rootIdentity.auditExpectations`

The key metadata returned to setup flows includes only the key id/fingerprint, version, source type, generated/reveal booleans, and loss semantics. It does not include raw key material unless this is the generated-key one-time reveal response.

## Loss Semantics

If the vault key is lost and no managed recovery material exists, the vault cannot be unlocked. The operator must recreate the vault; old encrypted secrets are not recoverable. Broker responses expose this as safe metadata so Service Lasso core and Service Admin can show the consequence without storing or displaying secret material.

## Audit Events

Bootstrap emits safe metadata-only audit records for:

- `vault_created`
- `root_identity_created`
- `key_generated`
- `supplied_key_used`
- `setup_completed`
- `vault_unlock_failure`

Audit records include safe fields such as key id, operation, outcome, state, service id, actor kind, request id, and audit status. They must never contain raw vault keys, plaintext secrets, wrapper plaintext, recovery shares, API tokens, provider credentials, or submitted key material.

## CLI Examples

Supplied key for headless/container bootstrap:

```powershell
secretsbroker key initialize `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --master-key-file .\secure\portable-master-key.txt
```

Broker-generated key for an explicit setup ceremony:

```powershell
secretsbroker key initialize `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --generate `
  --one-time-reveal
```

The setup flow must persist or hand off the revealed key outside broker state immediately, then enroll wrapper and recovery material. The broker will not re-reveal the generated key.
