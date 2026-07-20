#!/usr/bin/env bash
# Clear macOS Gatekeeper quarantine so pktana opens after download.
# Usage:
#   ./pktana-desktop/scripts/fix-macos-gatekeeper.sh /Applications/pktana.app
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script only runs on macOS."
  exit 1
fi

TARGET="${1:-/Applications/pktana.app}"

if [[ ! -e "$TARGET" ]]; then
  echo "Not found: $TARGET"
  echo "Usage: $0 /Applications/pktana.app"
  exit 1
fi

echo "Clearing Gatekeeper quarantine on: $TARGET"
xattr -cr "$TARGET"

if [[ "$TARGET" == *.app ]]; then
  echo "Ad-hoc codesigning..."
  codesign --force --deep --sign - "$TARGET" || true
  BIN="$TARGET/Contents/Resources/bin/pktana"
  if [[ -x "$BIN" ]]; then
    codesign --force --sign - "$BIN" || true
    codesign --force --deep --sign - "$TARGET" || true
  fi
fi

echo "Done. Open pktana again (Right-click → Open if macOS still warns)."
