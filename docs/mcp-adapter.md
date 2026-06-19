# Secrets Broker MCP Adapter

Status: first read-only adapter slice

Issue: [lasso-secretsbroker#94](https://github.com/service-lasso/lasso-secretsbroker/issues/94)

## Purpose

The Secrets Broker MCP adapter exposes a small, metadata-only tool surface for AI clients and headless operators that need to inspect broker state without receiving raw secret material. This first slice is an adapter available through the existing headless admin CLI; it does not start a long-running MCP transport server yet.

The shape follows the current MCP tools model: tools have stable names, JSON input schemas, and call results include text content plus structured JSON. The adapter intentionally keeps mutation and reveal operations disabled until separate policy, audit, consent, and transport hardening work is approved.

## Commands

List available tools:

```powershell
secretsbroker admin mcp tools
```

Call a tool:

```powershell
secretsbroker admin mcp call --tool secretsbroker.status
secretsbroker admin mcp call --tool secretsbroker.secrets.metadata.list --query SESSION --master-key-file .\secure\portable-master-key.txt
secretsbroker admin mcp call --tool secretsbroker.events.list --family policy_decision --limit 25
```

The adapter uses the same safe admin options as the other headless commands:

```text
--store <path>
--audit <path>
--events <path>
--sources <path>
--master-key <value>
--master-key-file <path>
```

## Read-Only Tools

| Tool | Purpose | Secret safety |
| --- | --- | --- |
| `secretsbroker.status` | Broker health, lifecycle, provider, and recovery metadata. | No raw secret values or portable master-key bytes. |
| `secretsbroker.sources.status` | Source capability and lifecycle state. | Source ids, kinds, namespaces, and outcomes only. |
| `secretsbroker.providers.status` | Provider configuration status and capability metadata. | Credential handles only; no credential values. |
| `secretsbroker.telemetry.summary` | Low-cardinality operational counters. | Ref-hash-only audit reads; no values. |
| `secretsbroker.events.list` | Bounded operational event query. | Metadata-only events with `refHash`/safe prefixes, no raw values. |
| `secretsbroker.secrets.metadata.list` | Managed secret metadata search. | Refs and metadata only; no reveal/value fields. |

## Disabled Tool Names

These tool names are listed so clients can discover the boundary explicitly, but calls return `unsupported` with `isError: true`:

- `secretsbroker.secrets.reveal`
- `secretsbroker.secrets.write`
- `secretsbroker.secrets.rotate`

They must remain disabled until there is an approved MCP transport/auth model, human consent flow, policy allow check, audit reason, and redaction test coverage for the specific operation.

## Result Safety Contract

Every adapter response includes safety metadata:

- `metadataOnly: true`
- `valueMaterialIncluded: false`
- `mutatingToolsEnabled: false`

MCP results also serialize the structured JSON into a text content block for client compatibility. Tests must prove representative outputs do not include raw secret values, provider credentials, bearer tokens, private keys, passwords, portable master-key bytes, or recovery material.

