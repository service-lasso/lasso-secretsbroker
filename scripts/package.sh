#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
OS_NAME=$(uname -s)
case "$OS_NAME" in
  Linux*) PLATFORM="linux"; GOOS_VALUE="linux" ;;
  Darwin*) PLATFORM="darwin"; GOOS_VALUE="darwin" ;;
  *) echo "Unsupported OS for package.sh: $OS_NAME" >&2; exit 1 ;;
esac
STAGING="$DIST/secretsbroker-$PLATFORM"
TAR_PATH="$DIST/secretsbroker-$PLATFORM.tar.gz"

mkdir -p "$DIST"
rm -rf "$STAGING"
mkdir -p "$STAGING"

(
  cd "$ROOT"
  GOOS="$GOOS_VALUE" GOARCH=amd64 go build -o "$STAGING/secretsbroker" ./cmd/secretsbroker
  GOOS="$GOOS_VALUE" GOARCH=amd64 go build -o "$STAGING/secretsbroker-resolve" ./cmd/secretsbroker-resolve
)

cp -R "$ROOT/config" "$STAGING/config"
cp "$ROOT/service.json" "$STAGING/service.json"
chmod +x "$STAGING/secretsbroker" "$STAGING/secretsbroker-resolve"

rm -f "$TAR_PATH"
tar -czf "$TAR_PATH" -C "$STAGING" .
echo "Created $TAR_PATH"
