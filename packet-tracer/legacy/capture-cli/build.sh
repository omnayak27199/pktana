#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if command -v make >/dev/null 2>&1; then
    exec make "$@"
fi

VERSION="$(tr -d ' \t\r\n' < VERSION)"
BUILD_DIR="build"

cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --parallel

echo ""
echo "Built $ROOT/$BUILD_DIR/pktana-tracer (v${VERSION})"
