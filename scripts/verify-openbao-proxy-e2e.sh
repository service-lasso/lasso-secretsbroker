#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="2.7.1"
CACHE="$ROOT/.tmp/openbao-e2e"

case "$(uname -s)" in
  Linux*) OS="linux" ;;
  Darwin*) OS="darwin" ;;
  *) echo "Unsupported OS for verify-openbao-proxy-e2e.sh" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

ASSET="openbao_${VERSION}_${OS}_${ARCH}.tar.gz"
case "$OS-$ARCH" in
  linux-amd64) SHA="0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243" ;;
  darwin-arm64) SHA="15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91" ;;
  *) echo "No pinned digest for $OS-$ARCH" >&2; exit 1 ;;
esac

mkdir -p "$CACHE"
ARCHIVE="$CACHE/$ASSET"
if [ ! -f "$ARCHIVE" ]; then
  curl -fsSL "https://github.com/openbao/openbao/releases/download/v$VERSION/$ASSET" -o "$ARCHIVE"
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
fi
if [ "$ACTUAL" != "$SHA" ]; then
  echo "OpenBao archive digest mismatch: expected $SHA, got $ACTUAL" >&2
  exit 1
fi

BIN_DIR="$CACHE/bin"
mkdir -p "$BIN_DIR"
tar -xzf "$ARCHIVE" -C "$BIN_DIR"

export OPENBAO_E2E_BIN="$BIN_DIR/bao"
cd "$ROOT"
go test ./cmd/secretsbroker -run '^TestOpenBaoProxyE2E$' -count=1 -v
