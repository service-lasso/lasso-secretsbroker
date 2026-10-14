#!/bin/sh
set -eu
test "$(/usr/bin/uname -m)" = x86_64 || { echo 'This custom compatibility profile requires Intel macOS.' >&2; exit 2; }
version=$(/usr/bin/sw_vers -productVersion)
case "$version" in ''|*[!0-9.]*|.*|*.|*..*) exit 2;; esac
major=${version%%.*}
case "$major" in [1-9]|[1-9][0-9]) ;; *) exit 2;; esac
test "$major" -ge 11 || { echo 'This custom compatibility profile requires macOS 11 or newer.' >&2; exit 2; }
echo 'Custom maintained-Go Intel macOS version prerequisite satisfied; runtime qualification remains required.'
