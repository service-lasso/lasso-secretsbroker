# Packaging

## Canonical operator guidance

Start with [docs/service-authoring/overview.md](https://github.com/service-lasso/service-lasso/blob/develop/docs/service-authoring/overview.md) and [docs/service-authoring/05-validate-release.md](https://github.com/service-lasso/service-lasso/blob/develop/docs/service-authoring/05-validate-release.md) for the shared Service Lasso reader journey. This page retains Broker-owned command, API and security contracts; follow those contracts when configuring this component. Migration: [Broker #182](https://github.com/service-lasso/lasso-secretsbroker/issues/182), [Core #1420](https://github.com/service-lasso/service-lasso/issues/1420), source reviewed at `fc6fc7b481dc8f9b6657a5d397a73b4a88384e2b`. Source documentation does not prove installed-release, provider or platform acceptance.

Reference packaging scripts:
- `scripts/package.ps1`
- `scripts/package.sh`

Current Broker payload (the packaging scripts are authoritative):
- build `secretsbroker` and `secretsbroker-resolve` into platform archives under `dist/`
- include `service.json`, both binaries, `config/` and `sbom.cdx.json`; emit a companion CycloneDX file under `dist/`
- Windows uses a ZIP; Linux amd64 and universal macOS use tar.gz. macOS builds amd64 and arm64 binaries and verifies both with `lipo` before archiving. Local packaging creates artifacts and does not publish a release.

## App Artifact Modes

Service repos publish installable service archives from their own releases.

Apps that consume Service Lasso can then produce two useful runtime artifact modes:
- `runtime` / bootstrap-download: the app ships `services/<service-id>/service.json`, and Service Lasso downloads the service archive from that manifest during install/acquire.
- `bundled`: the app package step has already run Service Lasso package/acquire behavior and stored the service archive under `services/<service-id>/.state/artifacts/<tag>/<assetName>` before the app artifact is published.

Bundled app artifacts should not need a first-run service archive download. The service manifest still remains the source of truth for release metadata; the bundled archive is the already-acquired payload that matches that manifest.
