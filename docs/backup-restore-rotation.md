# Backup, Restore, and Key Rotation

Status: implemented foundation slice
Issue: #23

## Goals

The local-first Secrets Broker can now create encrypted backup artifacts, restore them into a fresh instance when the matching portable master key is available, and rotate/re-encrypt local store payloads under a new portable master key.

The backup flow never exports plaintext secret values. Backup artifacts contain the encrypted local store plus metadata needed for diagnostics and recovery planning.

## Backup artifact format

`secretsbroker backup create` writes a JSON artifact:

```json
{
  "version": 1,
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "createdAt": "2026-05-08T00:00:00Z",
  "storeKeyId": "mk-0123456789abcdef",
  "storeKeyVersion": "v1",
  "secretCount": 2,
  "store": {
    "version": 1,
    "serviceId": "@secretsbroker",
    "secrets": {
      "services/api/DB_PASSWORD": {
        "metadata": { "sourceId": "local" },
        "payload": {
          "alg": "AES-256-GCM",
          "keyId": "mk-0123456789abcdef",
          "keyVersion": "v1",
          "nonce": "...",
          "ciphertext": "..."
        }
      }
    }
  }
}
```

The artifact is safe from plaintext secret export, but it is still sensitive operational data. Store it separately from the portable master key or recovery material.

## Create a backup

```powershell
secretsbroker backup create `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --master-key-file .\secure\portable-master-key.txt `
  --out .\backups\secretsbroker-backup.json
```

The broker verifies the current key can decrypt stored payloads before writing the artifact. Missing or wrong key material fails safely instead of creating a misleading backup.

## Restore into a fresh instance

```powershell
secretsbroker backup restore `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --master-key-file .\secure\portable-master-key.txt `
  --in .\backups\secretsbroker-backup.json
```

Restore validates:

- artifact version, service id, API version, store version, and secret count
- required portable master key availability
- that every encrypted payload decrypts with the supplied key

A missing key returns locked behavior. A wrong key returns an actionable backup-key failure and does not write the target store.

## Rotate the portable master key

```powershell
secretsbroker key rotate `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --master-key-file .\secure\old-portable-master-key.txt `
  --new-master-key-file .\secure\new-portable-master-key.txt
```

Rotation decrypts all current payloads using the existing key, re-encrypts them under the new key, updates payload key metadata, writes an audit event, and preserves resolvability for callers using the new key.

Keep the previous key until the rotated backup and store are verified, then retire it according to the operator's key-retention policy.

## Audit and recovery limits

Audit events are emitted for:

- `backup_create`
- `backup_restore`
- `key_rotate`

Events include operation, outcome, timestamp, and scoped ref where relevant. They never include plaintext secret values.

What can be recovered:

- an encrypted backup plus the matching portable master key can restore all local encrypted store entries
- a rotated store can be backed up and restored with the new portable master key

What cannot be recovered:

- without the matching portable master key or future recovery shares, encrypted payloads cannot be decrypted
- source-backed secrets that were never materialized into the local store must still be recovered from their source provider
- a tampered or incompatible backup artifact is rejected rather than partially restored
