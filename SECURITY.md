# Security Policy

## Supported versions

Until Service Lasso 1.0 reaches GA, only Broker `main` and the exact Broker
candidate pinned by the Release 1 programme receive security fixes. After GA,
the latest Release 1.x Broker line is supported unless a release notice states
otherwise. Superseded dated releases and development snapshots are unsupported.

## Reporting a vulnerability

Use GitHub private vulnerability reporting. Do not open a public vulnerability
issue or include tokens, secret values, master/signing keys, recovery material,
local IPC addresses, paths, command lines, logs, screenshots, or exploit data
in public evidence. If private reporting is unavailable, contact the repository
owner privately with the minimum safe reproduction.

Include the affected version/commit, preconditions, impact, safe reproduction,
and any known mitigation. We will acknowledge, assess production reachability,
coordinate remediation and an advisory, and preserve a disclosure timeline.

## Remediation targets

- Critical production findings: triage within 24 hours; fix or fail-closed
  mitigation targeted within 72 hours.
- High production findings: triage within 2 business days; fix targeted within
  7 days.
- Medium production findings: fix targeted within 30 days.
- Low production findings: fix targeted within 90 days.

Release 1.0 fails for any known unremediated production vulnerability. These
targets do not claim immunity from unknown or future vulnerabilities.

## Release evidence

Release evidence binds the exact commit, Go graph, source and packaged-binary
scans, three platform archives, SBOMs, checksums, provenance/attestations,
signatures, asset sizes/digests, and downloaded-content verification. A clean
`govulncheck` result is narrower than the complete release decision.

