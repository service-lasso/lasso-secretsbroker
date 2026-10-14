# Private-PKI source TLS trust

## Canonical operator guidance

Start with [docs/security/broker-operator-tasks.md](https://github.com/service-lasso/service-lasso/blob/develop/docs/security/broker-operator-tasks.md) for the shared Service Lasso reader journey. This page retains Broker-owned command, API and security contracts; follow those contracts when configuring this component. Migration: [Broker #182](https://github.com/service-lasso/lasso-secretsbroker/issues/182), [Core #1420](https://github.com/service-lasso/service-lasso/issues/1420), source reviewed at `fc6fc7b481dc8f9b6657a5d397a73b4a88384e2b`. Source documentation does not prove installed-release, provider or platform acceptance.

Service Lasso Secrets Broker verifies HTTPS source certificates with the host
system trust store by default. Operators that use an internal certificate
authority can append one bounded CA bundle for Vault/OpenBao, Bitwarden/BWS,
AWS-compatible endpoints, and their enabled migration executors.

Set both variables in production:

```text
SECRETSBROKER_SOURCE_CA_FILE=<absolute path to PEM CA bundle>
SECRETSBROKER_SOURCE_CA_SHA256=sha256:<64 lowercase hex characters>
```

The SHA-256 value is the digest of the exact CA file bytes. Production rejects
a custom CA without the pin, a pin without the file, a mismatch, a relative or
indirect path, an empty or oversized file, and a file with no valid PEM
certificates. The file must be a regular file of at most 1 MiB and every path
component must be free of symlink or Windows reparse indirection.

The pinned certificates are appended to the operating system root pool. The
Broker keeps normal hostname and certificate-chain verification enabled,
requires at least TLS 1.2 for the custom trust transport, and never enables an
insecure skip-verification mode. Redirects remain disabled for credentialed
source operations.

Development/bootstrap mode may load the absolute CA file without a digest pin
to ease local setup. This compatibility does not apply when the source is
marked production. A supplied pin is always validated and must match.

To calculate the pin in PowerShell:

```powershell
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath C:\absolute\path\source-ca.pem).Hash.ToLowerInvariant()
$env:SECRETSBROKER_SOURCE_CA_SHA256 = "sha256:$hash"
```

The CA bundle is public certificate material, not a private key. Its integrity
is bound by the digest pin; access to the two environment variables remains an
operator/service-manager authority boundary.
