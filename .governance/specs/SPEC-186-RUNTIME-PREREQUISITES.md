# Broker runtime prerequisites - issue #186

Active requirements:
- OS-1: Go 1.26 Darwin binaries require macOS 12 or newer, on x86_64 and arm64.
- OS-2: Package a read-only check that fails closed for unsupported/unparseable
  host versions and succeeds for supported versions before manual execution.
  It does not replace Core preflight or automatically guard direct manifest launch.
- OS-3: Preserve toolchain, cryptography, system roots, hostname/chain validation,
  Windows/Linux artifacts and explicit release authority.
- OS-4: Keep actual Big Sur load failure distinct from supported-host qualification.

Acceptance: actual macOS 11.7.11 must return a clear unsupported prerequisite
from the helper; macOS 12 and newer must pass its version check. Neither outcome
proves Broker startup, bootstrap, secret resolution or supported-host acceptance.
A supported Mac requires exact packaged binaries, serve/bootstrap and encrypted
store/resolve evidence before working-release claims.

Evidence: published 2026.8.31-f340883 x86_64 executable SHA-256
`a937ba86b0fa2fc971569ec6481f98c4884809a596543d918785bc0d80f98da4`
was copied into an owned private fixture on actual macOS 11.7.11. Mach-O declares
minos 12.0; --help exits 134 with missing `_SecTrustCopyCertificateChain`.
Original private fixtures remain retained. No Big Sur compatible candidate exists
in this change; no unsupported toolchain patch or security downgrade is accepted.

References: https://go.dev/wiki/MinimumRequirements and
https://go.dev/doc/go1.25#darwin. Go maintenance policy:
https://go.dev/doc/devel/release#policy.
