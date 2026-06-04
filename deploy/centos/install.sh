#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/usr/local/bin"
TARGET="${INSTALL_DIR}/pktana"

if [[ ! -f "./pktana" ]]; then
  echo "error: pktana binary not found in current directory" >&2
  exit 1
fi

install -m 0755 "./pktana" "${TARGET}"

echo "Installed pktana to ${TARGET}"
echo ""
echo "========================================="
echo "  Installation Complete!"
echo "========================================="
echo ""
echo "Start the web UI:    pktana web 8080"
echo "Install AI analysis: pktana ai install"
echo "Check AI status:     pktana ai st"
echo ""

