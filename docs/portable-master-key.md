# Portable Master Key and Unlock Foundation

Status: foundation slice  
Issue: #4

## Purpose

The local encrypted store must be portable across operating systems while still allowing each machine to protect its local unlock material.

Canonical model:

```text
portable master key -> encrypts vault payloads
local machine wrapper -> protects/unlocks local copy of portable master key
```

The encrypted vault/store should be movable between Windows, macOS, and Linux. A copied vault on a new machine should enter `locked` until the operator imports the portable master key and enrolls/re-wraps it for that machine.

## MVP implemented in this slice

This slice establishes the platform-independent key identity and payload metadata foundation:

- master key material can be supplied from:
  - `SECRETSBROKER_MASTER_KEY`
  - `SECRETSBROKER_MASTER_KEY_FILE`
  - `--master-key`
  - `--master-key-file`
- `secretsbroker key generate` creates a portable random 256-bit master key and stable key id
- `secretsbroker key status` reports whether key material is available without revealing it
- encrypted payload records include:
  - `keyId`
  - `keyVersion`
  - `alg`
  - `nonce`
  - `ciphertext`
- key id is a stable `mk-<sha256-prefix>` fingerprint of the portable master key
- missing key material leaves the broker in locked behavior for local store read/write/resolve

## Key status examples

No key:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "available": false,
  "keyId": "",
  "keyVersion": "",
  "source": "none",
  "state": "locked"
}
```

Key from env/file/flag:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "available": true,
  "keyId": "mk-0123456789abcdef",
  "keyVersion": "v1",
  "source": "env",
  "state": "ready"
}
```

## Generate portable key

```powershell
secretsbroker key generate
```

Output:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "keyId": "mk-0123456789abcdef",
  "keyVersion": "v1",
  "masterKey": "base64url-random-key-material",
  "warning": "Store this portable master key securely. It can decrypt local vault payloads."
}
```

This command intentionally prints the generated key once. Operators should store it in a secure out-of-band location until OS-wrapper enrollment exists.

## Local wrapper enrollment

Issue #39 adds the first implemented local wrapper lifecycle commands:

```text
secretsbroker key initialize --master-key-file <file>
secretsbroker key unlock --master-key-file <file>
secretsbroker key import --master-key-file <file>
secretsbroker key rewrap --master-key-file <file>
secretsbroker key wrapper-status
```

The detailed contract is documented in `docs/master-key-lifecycle.md`.

Wrapper metadata records the intended provider:

- Windows: DPAPI user scope metadata
- macOS: Keychain service item metadata
- Linux: protected file user-scope metadata

The local wrapper stores/protects a local copy of the same portable master key for the current OS/user/machine. The encrypted vault payload format remains platform-independent.

## Copied vault flow

1. Copy encrypted store file to new machine.
2. Start broker without local wrapper/key.
3. Broker reports `locked`.
4. Operator runs `secretsbroker key import --master-key-file <file>` with the portable master key.
5. Broker validates the key format and verifies it against existing payload metadata/decryption.
6. Broker writes or refreshes the local wrapper for the current OS/user/machine.
7. Broker reports `ready` with status/metadata only.

## Recovery shares

Shamir/recovery shares are a future design topic. This slice does not implement recovery shares.

Design note:

- recovery shares should reconstruct/import the same portable master key
- shares must not be stored beside the encrypted vault
- recovery events should be audited

## Security notes

- Secret values are never stored in plaintext.
- The portable master key must be treated as sensitive secret material.
- Key ids are fingerprints only; they are safe for diagnostics.
- A wrong master key produces decrypt failures and `degraded` resolve outcomes, not plaintext output.
