#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
OS_NAME=$(uname -s)
case "$OS_NAME" in
  Linux*) PLATFORM="linux" ;;
  Darwin*) PLATFORM="darwin" ;;
  *) echo "Unsupported OS for package.sh: $OS_NAME" >&2; exit 1 ;;
esac
STAGING="$DIST/secretsbroker-$PLATFORM"
TAR_PATH="$DIST/secretsbroker-$PLATFORM.tar.gz"

mkdir -p "$DIST"
rm -rf "$STAGING"
mkdir -p "$STAGING"

(
  cd "$ROOT"
  if [[ "$PLATFORM" == "darwin" ]]; then
    command -v lipo >/dev/null 2>&1 || {
      echo "lipo is required to build the universal macOS release artifact" >&2
      exit 1
    }
    UNIVERSAL_STAGING="$STAGING/.universal"
    mkdir -p "$UNIVERSAL_STAGING"
    for ARCH in amd64 arm64; do
      CGO_ENABLED=0 GOOS=darwin GOARCH="$ARCH" go build -trimpath -o "$UNIVERSAL_STAGING/secretsbroker-$ARCH" ./cmd/secretsbroker
      CGO_ENABLED=0 GOOS=darwin GOARCH="$ARCH" go build -trimpath -o "$UNIVERSAL_STAGING/secretsbroker-resolve-$ARCH" ./cmd/secretsbroker-resolve
    done
    lipo "$UNIVERSAL_STAGING/secretsbroker-amd64" "$UNIVERSAL_STAGING/secretsbroker-arm64" -create -output "$STAGING/secretsbroker"
    lipo "$UNIVERSAL_STAGING/secretsbroker-resolve-amd64" "$UNIVERSAL_STAGING/secretsbroker-resolve-arm64" -create -output "$STAGING/secretsbroker-resolve"
    lipo "$STAGING/secretsbroker" -verify_arch x86_64 arm64
    lipo "$STAGING/secretsbroker-resolve" -verify_arch x86_64 arm64
    rm -rf "$UNIVERSAL_STAGING"
  else
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$STAGING/secretsbroker" ./cmd/secretsbroker
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$STAGING/secretsbroker-resolve" ./cmd/secretsbroker-resolve
  fi
)

cp -R "$ROOT/config" "$STAGING/config"
cp "$ROOT/service.json" "$STAGING/service.json"
(cd "$ROOT" && go run ./cmd/sbom --output "$STAGING/sbom.cdx.json" --platform "$PLATFORM")
cp "$STAGING/sbom.cdx.json" "$DIST/secretsbroker-$PLATFORM.cdx.json"
chmod +x "$STAGING/secretsbroker" "$STAGING/secretsbroker-resolve"

rm -f "$TAR_PATH"
(cd "$ROOT" && go run ./cmd/releasearchive --source "$STAGING" --output "$TAR_PATH" --format tar.gz)
echo "Created $TAR_PATH"
