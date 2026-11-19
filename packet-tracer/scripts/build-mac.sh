#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS installers (.dmg / .zip) must be built on a Mac."
  echo "Run this script on macOS, or use GitHub Actions with macos-latest."
  exit 1
fi

npm install
npm run dist:mac
echo ""
echo "Built artifacts in $ROOT/dist/"
