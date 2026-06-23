# OS-Authenticated IPC Transport

Status: foundation slice
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
- Unix-like platforms can serve HTTP over a Unix socket and set the socket path to owner-only mode.
- Windows named-pipe configuration is parsed and validated, but serving fails closed until the listener enforces local client identity checks.

## Production gate

The broker must not silently fall back to loopback HTTP in production mode. If the requested IPC listener cannot enforce the required local identity boundary, startup fails before serving secret-bearing APIs.

## Windows named-pipe requirements

Before enabling the Windows named-pipe listener:

- The pipe path must be under `\\.\pipe\`.
- The pipe security descriptor must limit access to the current user, local administrators, and LocalSystem as appropriate for the Service Lasso launcher model.
- The listener must identify the connected local client process or user token before accepting secret-bearing requests.
- Identity metadata must be safe: no access tokens, environment values, command lines, or raw credentials in responses, logs, or audit events.
- Tests must cover unauthorized client rejection and safe error output.

## Unix socket requirements

Current Unix socket support is a first serving path. Closure-grade production work still needs peer credential checks where the platform exposes them. Until then, the socket path is owner-only and production startup uses the Unix socket instead of loopback HTTP, but validation must not claim full peer identity enforcement.

## Compatibility

Existing bootstrap clients can keep using:

```powershell
secretsbroker serve --listen 127.0.0.1:17890
```

Secret-bearing HTTP endpoints still require the local API token and existing launch identity checks. The IPC work changes the process boundary; it does not remove endpoint authentication or policy checks.
