# SPEC-203: Compatible Broker prepublication candidate

Active Development / release preparation. Owner explicitly authorizes candidate
preparation and independent review (2026-10-11); publication/deployment prohibited.

- CAND-1: Freeze current develop-derived source in a fresh issue worktree. Bind
  full SHA/tree, source archive, exact Go toolchain/build flags/platform and
  clean-state proof. File-grants/status and vault-to-file DAV-6 must be present.
- CAND-2: Use original official packaging and complete official seven-payload
  checksum inventory, including resolver, manifests/config, SBOM and archives.
  Intel macOS11 compatibility uses its documented maintained toolchain and
  separate full thirteen-payload qualification contract (SPEC-188/191/194).
  A prepared compatibility archive without original native receipt is partial,
  never a qualified release. Preserve previous immutable release identity.
- CAND-3: Independently review whole relevant source/packaging closure before
  candidate execution, then record actual source/toolchain/runtime inputs and
  exact packaged byte hashes. Execute original Go/security/harness/native/IPC
  acceptance and real Core/Echo integration; preserve all original assertions,
  deadlines, unsupported-input refusal and actual failed evidence.
- CAND-4: Preserve source, prepublication candidate and published-package claims
  distinctly. No release dispatch, creation/upload/publication, tag promotion,
  deployment or provider setting changes. No protected published pin substitution.
- CAND-5: Push each intentional commit; deliver through develop PR with exact
  source/review/artifact/test evidence. Coordinate Core1750 and Echo17 without
  mutating other workers or authorizing Core native effects through Broker proof.
