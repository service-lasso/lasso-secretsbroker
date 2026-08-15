# Backup, Restore, and Key Rotation

Status: implemented foundation slice
Issue: #23

## Goals

The local-first Secrets Broker can now create encrypted backup artifacts, restore them into a fresh instance when the matching portable master key is available, and rotate/re-encrypt local store payloads under a new portable master key.

The backup flow never exports plaintext secret values. Backup artifacts contain the encrypted local store plus metadata needed for diagnostics and recovery planning.

## Authenticated lifecycle management API

Service Admin and other authenticated local operators use the Broker lifecycle
API rather than the path- and key-bearing break-glass CLI:

- `GET /v1/management/lifecycle/status` returns key fingerprint/version,
  wrapper state, recovery-policy metadata and the safe backup inventory.
- `GET|POST /v1/management/lifecycle/backups` lists or creates an encrypted
  backup in the Broker-owned backup root.
- `POST /v1/management/lifecycle/backups/verify` rechecks the selected artifact.
- `POST /v1/management/lifecycle/restore/dry-run` binds a five-minute plan to
  the exact backup, key fingerprint and current store digest.
- `POST /v1/management/lifecycle/restore/apply` requires that exact plan and
  explicit confirmation before atomically replacing the store.
- `POST /v1/management/lifecycle/key/rotate` generates new key material inside
  the Broker, re-encrypts the store and refreshes the local OS wrapper. Key
  bytes are never accepted or returned by this HTTP route.

Backup files are addressed by opaque `backupId` values. The API never accepts
or returns filesystem paths, portable key bytes, recovery shares, passphrases,
encrypted payload bodies or plaintext secret values. Backup artifacts are
authenticated with the matching portable key in addition to encrypting each
secret payload. Files are size-bounded, regular-file checked, confined to the
configured backup root and published without overwriting an existing ID.

Mutating requests require a bounded operation id and audit reason. Restore and
rotation additionally require explicit confirmation and expected-state
evidence. An unavailable audit sink rejects authorization before any local
mutation. The recovery-share ceremony remains CLI-only: Service Admin may show
policy/share fingerprints and next actions, but must never collect or render
share contents.

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
