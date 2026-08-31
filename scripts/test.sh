#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OS_NAME="$(uname -s)"
cd "$ROOT"

for path in service.json verify/service-harness.json cmd/secretsbroker/main.go go.mod; do
  if [[ ! -f "$path" ]]; then
    echo "Missing required file: $path" >&2
    exit 1
  fi
done

SERVICE_ID=$(python3 - <<'PY'
import json, pathlib
print(json.loads(pathlib.Path('service.json').read_text())['id'])
PY
)
if [[ "$SERVICE_ID" != "@secretsbroker" ]]; then
  echo "service.json id mismatch" >&2
  exit 1
fi

python3 - <<'PY'
import json
import pathlib

supported_action_modes = {'built-in', 'command', 'workflow', 'handler'}
manifest_paths = [pathlib.Path('service.json'), *pathlib.Path('services').glob('**/service.json')]
for manifest_path in manifest_paths:
    manifest = json.loads(manifest_path.read_text())
    for action_name, action in manifest.get('actions', {}).items():
        mode = action.get('mode')
        if mode and mode not in supported_action_modes:
            raise SystemExit(f'{manifest_path} action {action_name} uses unsupported mode {mode}')
PY

CONTRACT_ID=$(python3 - <<'PY'
import json, pathlib
print(json.loads(pathlib.Path('verify/service-harness.json').read_text())['serviceId'])
PY
)
if [[ "$CONTRACT_ID" != "@secretsbroker" ]]; then
  echo "service-harness.json serviceId mismatch" >&2
  exit 1
fi

go test ./...

TMP="$ROOT/.tmp/test"
mkdir -p "$TMP"
go build -o "$TMP/secretsbroker" ./cmd/secretsbroker
go build -o "$TMP/secretsbroker-resolve" ./cmd/secretsbroker-resolve

STATUS_JSON="$($TMP/secretsbroker status)"
STATUS_JSON="$STATUS_JSON" python3 - <<'PY'
import json, os
payload = json.loads(os.environ['STATUS_JSON'])
assert payload['serviceId'] == '@secretsbroker'
assert payload['state'] == 'setup_needed'
PY

PORT=17891
"$TMP/secretsbroker" serve --listen "127.0.0.1:$PORT" >"$TMP/server.log" 2>&1 &
PID=$!
cleanup() { kill "$PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT
for _ in $(seq 1 20); do
  if python3 - <<PY
import json, urllib.request
try:
    payload=json.load(urllib.request.urlopen('http://127.0.0.1:$PORT/health', timeout=1))
    raise SystemExit(0 if payload.get('ok') and payload.get('serviceId') == '@secretsbroker' else 1)
except Exception:
    raise SystemExit(1)
PY
  then
    echo "Secrets Broker tests passed ($OS_NAME)"
    exit 0
  fi
  sleep 0.25
done

echo "health endpoint did not become ready" >&2
cat "$TMP/server.log" >&2 || true
exit 1
