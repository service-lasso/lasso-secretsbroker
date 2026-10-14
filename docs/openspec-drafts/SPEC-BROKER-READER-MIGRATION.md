# Broker reader migration

Status: active documentation specification. Issue: Broker #182; parent Core #1420 / #1265; Core SPEC-002 AC-4AJ.3.

Centralize the reader entry point for exactly the 14 source paths recorded in Core docs/components/broker-migration-decisions.json at Broker develop fc6fc7b481dc8f9b6657a5d397a73b4a88384e2b. Link each to its recorded Core develop destination. Keep Broker-owned API, CLI, schema and security details at the existing paths; readers need these component contracts after the central operator guide. Do not replace them with generic redirects.

AC-1: All 14 audited paths name the canonical reader guide, source revision, owning issue and component-contract boundary. No extra reader paths are migrated.
AC-2: Except packaging corrections, existing component content remains intact. IPC identity/connection operations, custody versus CLI reveal, secret-output exclusions, fail-closed recovery and provider TLS rules remain unchanged.
AC-3: Packaging describes the actual scripts: broker/resolver binaries, config, service.json, SBOM; Windows ZIP, Linux amd64 and macOS universal tar.gz. Packaging does not imply publication.
AC-4: Develop-only issue branch and PR instructions supersede copied branch instructions. No release-promotion input is used.
AC-5: Validate path coverage, local references, unchanged contracts and exact-head hosted gates before merge. Documentation acceptance is separate from installed-release, live-provider and independent assurance evidence.

Non-goals: production implementation, command/schema/security changes, provider operations, publication, deployment or macOS newcomer acceptance.