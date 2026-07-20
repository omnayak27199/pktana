#!/usr/bin/env bash
# Copy repo-root wiki into pktana-cli so cargo publish can embed the docs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/crates/pktana-cli/wiki"
cp -a "$ROOT/wiki/"*.md "$ROOT/crates/pktana-cli/wiki/"
echo "Synced wiki/*.md -> crates/pktana-cli/wiki/"
