# Secure Initialization and Recovery-Key Model

Status: design recommendation
Issue: #55
Service id: `@secretsbroker`

## Purpose

This note defines the recommended initialization and recovery-key model for the local-first Secrets Broker. It answers whether PGP-based initialization should be the primary path, how operators can initialize without Keybase, how recovery material should be generated and stored, and what must stay out of UI, logs, diagnostics, and support artifacts.

This is a design contract, not a production-readiness claim. The implemented foundation remains the portable master key, local encrypted store, local wrapper, backup/restore, rotation flows, and recovery policy metadata surfaces documented in `docs/portable-master-key.md`, `docs/master-key-lifecycle.md`, `docs/backup-restore-rotation.md`, `docs/local-api-bootstrap-contract.md`, and `docs/threat-model.md`.

Current implementation note for #58: the broker persists and reports recovery policy/share metadata through API and CLI status surfaces. It still does not generate threshold shares, import shares, or create recipient envelopes; those remain follow-up implementation slices.

## Recommendation

Use a local-first initialization flow built around:

1. A randomly generated 256-bit portable master key.
2. A local OS/user wrapper for routine unlock on each enrolled machine.
3. Threshold recovery shares for break-glass recovery.
4. Optional recipient-encrypted share envelopes for operators who want each share protected at rest.
5. Metadata-only audit and diagnostics.

Do not make PGP or Keybase the primary initialization dependency.

PGP can be supported later as an optional recipient-envelope backend for organizations that already manage PGP keys well, but it should not be the default because it brings key discovery, expiry, revocation, UX, and tooling complexity into the most sensitive bootstrap path. Keybase should not be required at all.

For the default no-Keybase path, prefer:

- Shamir threshold recovery shares for reconstructing the same portable master key.
- `age`/X25519 recipient encryption as the first optional share-envelope format, because it is compact, file-based, and does not depend on public keyservers or social identity systems.
- OS key stores/wrappers for daily machine-local unlock where available.

## Threat Assumptions

The default model assumes:

- The broker is local-first and managed by Service Lasso on operator-controlled infrastructure.
- A privileged local attacker can read process memory, environment variables, command lines, and files the OS permits. The model can reduce accidental exposure and offline theft risk, but it cannot defeat a fully privileged host compromise.
- Encrypted stores and backups may be copied. They must remain unusable without matching portable master key material or valid recovery shares.
- Recovery share holders are trusted to protect their share out of band.
- Service Admin is optional and must not become the only way to unlock or recover the broker.
- Vault/OpenBao can be a backend/source later, but the Service Lasso-facing broker contract remains `@secretsbroker`.

## Initialization Workflow

The recommended first implementation should be CLI-first and UI-safe:

1. Operator runs a local initialize command.
2. Broker generates a portable master key in memory.
3. Broker initializes the empty encrypted local store.
4. Broker enrolls a local wrapper for the current OS/user/machine when supported.
5. Operator chooses a recovery policy, for example 2-of-3 or 3-of-5.
6. Broker generates threshold recovery shares for the portable master key.
7. Broker writes each share only to the explicit output target selected by the operator.
8. Broker stores only safe recovery metadata in broker state.
9. Broker emits audit events with operation, outcome, key id fingerprint, threshold, share count, wrapper kind, and request id.

Safe recovery metadata may include:

- key id fingerprint
- recovery policy id
- threshold and share count
- share fingerprints
- recipient fingerprints where recipient envelopes are used
- creation, rotation, and revocation timestamps
- operator-supplied reason text after redaction and length limits

Safe metadata must not include:

- portable master key bytes
- recovery share contents
- unwrapped share plaintext
- recipient private keys
- passphrases
- local API tokens
- source provider credentials
- plaintext secret values

## Recovery Workflow

Recovery should reconstruct or import the same portable master key. It should not create a new key unless the operator explicitly chooses a rotation after successful recovery.

Recommended flow:

1. Operator starts broker against an encrypted store without usable local wrapper material.
2. Broker reports `locked` with safe key id and next action metadata.
3. Operator supplies the threshold number of recovery shares through a local CLI prompt or explicit files.
4. Broker reconstructs the portable master key in memory.
5. Broker verifies the key against store metadata and decryptability before writing anything.
6. Broker writes or refreshes the current machine wrapper only after verification succeeds.
7. Broker audits recovery success or failure without share contents.

Failure behavior:

- Too few shares: fail `locked`, no state mutation.
- Shares for the wrong key id: fail `locked`, no state mutation.
- Corrupted store or unverifiable payloads: fail `degraded`, no wrapper mutation.
- Unsupported wrapper provider: keep the store recoverable through explicit portable-key or recovery-share unlock, but do not claim durable local unlock.

## Rotation Workflow

Recovery material must rotate with the portable master key:

1. Verify the current key can decrypt all local payloads.
2. Generate or accept a new portable master key.
3. Re-encrypt all local payloads under the new key.
4. Generate a new recovery bundle for the new key.
5. Enroll or refresh local wrappers for approved machines.
6. Write audit events for old key id, new key id, threshold metadata, and outcome.
7. Keep old key material only until backups and recovery shares for the new key are verified.

Partial rotation must fail closed. A rotation must not leave mixed-key payloads unless the payload format and recovery docs explicitly support staged key versions and validation proves all active versions are recoverable.

## PGP and No-Keybase Decision

PGP is not recommended as the default initialization path.

Reasons:

- It usually needs extra key management decisions before bootstrap can begin.
- Public key discovery often depends on systems outside Service Lasso control.
- Keybase is not a suitable required dependency for local/on-prem Service Lasso deployments.
- PGP revocation, subkeys, expiry, and trust signatures are easy to mishandle in an operator setup wizard.
- A PGP-first design can make recovery depend on personal key hygiene rather than an explicit Service Lasso recovery policy.

Acceptable future PGP role:

- Optional recipient envelope for a recovery share.
- Explicit operator-provided public key file only.
- No keyserver lookup during initialization.
- No Keybase lookup.
- Audit only safe key fingerprint metadata.

Recommended default role for `age`/X25519:

- Optional recipient envelope for a recovery share.
- Operator supplies recipient strings or public key files directly.
- Broker stores only recipient fingerprints and envelope metadata.
- Share plaintext is never persisted by the broker unless the operator explicitly chooses a plaintext share output target.

## UI and Service Admin Rules

Service Admin may eventually guide initialization, but it must not become a plaintext recovery-material surface.

Allowed UI behavior:

- Show lifecycle state, key id fingerprint, wrapper status, threshold policy metadata, and recovery next actions.
- Start a local-only initialization or recovery ceremony that delegates sensitive material handling to the broker/CLI.
- Show whether required shares were accepted, rejected, or insufficient.
- Show audit status and recovery policy health.

Disallowed UI behavior:

- Render the portable master key by default.
- Render recovery shares in tables, routes, page titles, breadcrumbs, logs, diagnostics, screenshots, support bundles, local storage, or session storage.
- Upload shares or keys to a remote Service Admin backend.
- Copy/export all recovery shares from a bulk UI.
- Treat provider credentials, tokens, cookies, passphrases, private keys, or source secrets as diagnostic content.

## Audit Contract

Initialization and recovery audit events should include safe metadata only:

- operation name, outcome, and timestamp
- request id
- key id fingerprint
- wrapper kind and support status
- recovery policy id
- threshold and share count
- share fingerprints
- recipient fingerprints
- reason code or operator reason after redaction
- failure code and next action

Audit events must never include:

- plaintext secret values
- portable master key material
- recovery share plaintext
- recipient private keys
- passphrases
- API tokens
- source provider credentials
- raw request bodies that may contain sensitive material

## Implementation Slices

Recommended follow-up implementation sequence:

1. Add a recovery policy and share metadata contract.
2. Add CLI-first threshold recovery share generation and recovery import.
3. Add optional `age`/X25519 recipient envelopes for individual shares.
4. Add wrapper and recovery-policy status surfaces to API/CLI.
5. Add a Service Admin initialization guide only after the broker CLI/API contract is proven.

Each implementation slice must include no-secret serialization tests and negative tests for wrong shares, insufficient shares, corrupted stores, unsupported wrappers, and audit redaction.
