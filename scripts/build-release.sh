#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is not installed on this build machine" >&2
  exit 1
fi

echo "Building pktana release binary..."
cargo build --release -p pktana-cli --features pcap,tui

echo
echo "Built:"
echo "  ${ROOT_DIR}/target/release/pktana"
