# Go toolchain and vulnerability release gate

Issue: #155

Secrets Broker is a security boundary. Its release artifacts must use a currently supported patched Go toolchain and must not ship with reachable vulnerabilities reported by the official Go vulnerability database.

## Pinned release inputs

- The exact Go patch release is declared in `go.mod`; workflows use `actions/setup-go` with `go-version-file`.
- Source and binary scanning use the pinned command module `golang.org/x/vuln/cmd/govulncheck@v1.6.0`.
- Scanner findings are not suppressed or allowlisted to make a release pass.

## Required release sequence

Every release also publishes `SHA256SUMS.txt` for the exact Windows, Linux,
and macOS archives plus `service.json`. The release job generates and verifies
that manifest before creating the GitHub release. Consumers must use the
checksum contract inside every `artifact.platforms` entry in `service.json`;
a missing, duplicate, unexpected, malformed, or mismatched entry fails before
extraction or start.

1. Run the complete repository test suite on Windows, Linux, and macOS.
2. Run `govulncheck ./...` before packaging on every host.
3. Build the platform-native broker and resolver artifacts.
4. Run `govulncheck -mode=binary` against both staged executables.
5. Retain metadata-only evidence containing the Go version, scanner pin, binary name, SHA-256, and verification outcome.
6. Stop publication if either source or binary scanning reports a reachable vulnerability.

The Windows pull-request and release lanes also create a short-lived,
non-administrator local account, run the strict named-pipe verifier under that
real second principal, require an access-denied `summary.json`, and remove the
account in a `finally` block. No account password is printed, persisted in
evidence, or passed on a command line.

The macOS release archive contains universal `arm64` and `x86_64` Broker and
resolver binaries. Packaging verifies both slices with `lipo` before the
archive and binary-vulnerability gates run; an Intel-only binary produced on an
Apple Silicon runner is not an acceptable macOS artifact.

Binary scanning is symbol-level evidence; a finding requires investigation and remediation, not an unsupported claim that every reported path is practically exploitable. Conversely, uncertainty is not grounds for bypassing the release gate.

## Update and incident cadence

- Check the official Go stable download feed and vulnerability database before each release qualification.
- Move to the newest supported patch release when it is published and rerun the full three-OS matrix.
- For a reachable vulnerability affecting a released artifact, stop promotion, create a P0 security issue, rebuild with the patched toolchain or dependency, and publish a replacement only after source and binary gates are green.
- Record exact candidate SHA, Go version, scanner version, binary digests, and release tag in the handoff.
