#!/bin/sh
# Read-only prerequisite check; do not invoke either Go binary on older macOS.
set -eu
version=$(/usr/bin/sw_vers -productVersion) || {
  echo 'Secrets Broker: unable to determine macOS version.' >&2
  exit 2
}
case "$version" in
  ''|*[!0-9.]*|.*|*.|*..*)
    echo 'Secrets Broker: unable to parse macOS version.' >&2
    exit 2
    ;;
esac
major=${version%%.*}
# Bound input before arithmetic; sw_vers normally returns a two-digit major.
case "$major" in
  [1-9]|[1-9][0-9]) ;;
  *) echo 'Secrets Broker: unable to parse macOS version.' >&2; exit 2 ;;
esac
if [ "$major" -lt 12 ]; then
  echo 'Secrets Broker requires macOS 12 or newer (Go 1.26 runtime). This host is unsupported.' >&2
  exit 2
fi
echo 'Secrets Broker macOS version prerequisite satisfied; runtime qualification is still required.'