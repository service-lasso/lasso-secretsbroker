# OS-Authenticated IPC Transport

Status: Windows and Unix identity-check foundation
Issue: #31

## Purpose

Loopback HTTP remains useful for development and bootstrap, but production secret-bearing traffic should move to an OS-authenticated local IPC boundary:

- Windows named pipe with local client identity checks.
- Unix socket with owner-only filesystem permissions and peer credential checks where available.
- Loopback HTTP bound to `127.0.0.1`, `::1`, or `localhost` only for development/bootstrap compatibility.

## Current implementation

The daemon now has explicit transport selection:

```powershell
secretsbroker serve --transport loopback-http --listen 127.0.0.1:17890
secretsbroker serve --mode production --transport auto
secretsbroker serve --transport unix-socket --unix-socket /tmp/service-lasso-secretsbroker.sock
secretsbroker serve --transport windows-named-pipe --named-pipe \\.\pipe\service-lasso-secretsbroker
```

Equivalent environment variables:

```text
SECRETSBROKER_MODE=development|production
SECRETSBROKER_TRANSPORT=auto|loopback-http|unix-socket|windows-named-pipe
SECRETSBROKER_LISTEN=127.0.0.1:17890
SECRETSBROKER_UNIX_SOCKET=/tmp/service-lasso-secretsbroker.sock
SECRETSBROKER_NAMED_PIPE=\\.\pipe\service-lasso-secretsbroker
```

Implemented behavior:

- `loopback-http` rejects non-loopback bind addresses.
- `production` mode rejects `loopback-http`.
- `auto` chooses `loopback-http` in development mode.
- `auto` chooses the platform IPC transport in production mode: Windows named pipe on Windows, Unix socket elsewhere.
- Unix-like platforms can serve HTTP over a Unix socket, set the socket path to owner-only mode, and check OS peer credentials before passing a connection to the HTTP server. Linux uses `SO_PEERCRED`; macOS/FreeBSD use `LOCAL_PEERCRED`.
- Windows can serve HTTP over a named pipe with a restricted security descriptor and a connected-client identity check before passing the connection to the HTTP server.
- Authenticated IPC listeners attach safe local peer metadata to each accepted request: `windows-sid` for Windows named-pipe peers and `unix-uid` for Unix socket peers. Signed launch identity leases can optionally bind to that transport subject for secret-bearing resolve/write-back requests.

## Production gate

The broker must not silently fall back to loopback HTTP in production mode. If the requested IPC listener cannot enforce the required local identity boundary, startup fails before serving secret-bearing APIs.

## Windows named-pipe behavior

Current Windows named-pipe support:

- The pipe path must be under `\\.\pipe\`.
- The pipe security descriptor limits access to the broker user SID, local administrators, and LocalSystem.
- The listener identifies the connected client process with `GetNamedPipeClientProcessId`, inspects the client process token, and accepts only the same user SID, LocalSystem, or an enabled local Administrators group membership.
- Connections that cannot be identified or authorized are closed before the HTTP server sees the request.
- Identity metadata must be safe: no access tokens, environment values, command lines, or raw credentials in responses, logs, or audit events.
- Secret-bearing endpoints still require the existing local API token/session/launch-identity checks on top of the named-pipe boundary. When a launch identity lease includes `transportBinding`, the request is denied unless the authenticated pipe peer matches that signed binding.

Remaining hardening:

- Define the final Service Lasso launcher policy for administrator and service-account access.
- Add cross-user denial evidence in an integration environment that can create a second local Windows principal.
- Extend launcher-issued leases to include `transportBinding` by default once the core launcher has a stable broker transport identity policy.

## Unix socket requirements

Current Unix socket support enforces same-UID peer credentials on platforms where Go exposes the required OS APIs:

- Linux: `SO_PEERCRED`.
- macOS and FreeBSD: `LOCAL_PEERCRED`.

Unsupported Unix-like platforms fail closed before serving secret-bearing APIs until an equivalent peer-credential check is implemented. The socket path remains owner-only, and endpoint token/session/launch-identity checks still apply on top of the IPC boundary.

## Compatibility

Existing bootstrap clients can keep using:

```powershell
secretsbroker serve --listen 127.0.0.1:17890
```

Secret-bearing HTTP endpoints still require the local API token and existing launch identity checks. The IPC work changes the process boundary; it does not remove endpoint authentication or policy checks.

## Launch identity transport binding

Launch identity leases support an optional signed `transportBinding` object:

```json
{
  "kind": "windows-sid",
  "subject": "S-1-5-21-..."
}
```

Supported binding kinds:

- `windows-sid`: the connected Windows named-pipe client process token user SID.
- `unix-uid`: the connected Unix socket peer UID.

If a lease omits `transportBinding`, existing token/session and lease scope checks continue unchanged. If a lease includes it, the broker requires an authenticated IPC listener to provide matching peer metadata before `POST /v1/resolve` or `POST /v1/writeback` can proceed. Loopback HTTP does not provide OS peer identity, so transport-bound leases fail closed on loopback.
