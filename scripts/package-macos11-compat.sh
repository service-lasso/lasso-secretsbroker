#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OWNED="${1:?supply completed private compatibility build directory}"
export GOTOOLCHAIN=local GOENV=off GOFLAGS= GOWORK=off GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0
export GOROOT="$OWNED/go" GOCACHE="$OWNED/cache" GOMODCACHE="$OWNED/modcache"
export PATH="$GOROOT/bin:$PATH"
STAGING="$ROOT/dist/secretsbroker-darwin-amd64-macos11"
test ! -e "$STAGING"
mkdir -p "$STAGING"
cp "$OWNED/artifacts/secretsbroker" "$OWNED/artifacts/secretsbroker-resolve" "$STAGING/"
cp "$OWNED/artifacts/provenance.json" "$STAGING/toolchain-provenance.json"
cp -R "$ROOT/config" "$STAGING/config"
python3 - "$ROOT/service.json" "$STAGING/service.json" "$ROOT/dist/service-darwin-amd64-macos11.json" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1]));doc['artifact']['platforms']['darwin']['assetName']='secretsbroker-darwin-amd64-macos11.tar.gz'
doc['description']+=' Explicit custom maintained-Go 1.26.8 compatibility profile for Intel macOS 11; ARM64 uses the official modern artifact.'
for p in sys.argv[2:]: open(p,'w').write(json.dumps(doc,indent=2)+'\n')
PY
printf '%s\n' 'Custom maintained-Go 1.26.8 Darwin Intel compatibility variant. Private four-file upstream delta; not official Go macOS 11 support. See toolchain-provenance.json.' > "$STAGING/COMPATIBILITY.txt"
cp "$ROOT/scripts/check-macos11-compat-runtime.sh" "$STAGING/check-macos-runtime.sh"
chmod +x "$STAGING/"secretsbroker* "$STAGING/check-macos-runtime.sh"
cd "$ROOT"
go run ./cmd/sbom --output "$STAGING/sbom.cdx.json" --platform darwin-amd64-macos11
cp "$STAGING/sbom.cdx.json" "$ROOT/dist/secretsbroker-darwin-amd64-macos11.cdx.json"
go run ./cmd/releasearchive --source "$STAGING" --output "$ROOT/dist/secretsbroker-darwin-amd64-macos11.tar.gz" --format tar.gz
