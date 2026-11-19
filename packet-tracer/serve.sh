#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PORT="${1:-8765}"
echo "pktana Packet Tracer — learning lab"
echo "Open http://127.0.0.1:${PORT}/"
echo "Press Ctrl+C to stop."
if command -v python3 >/dev/null 2>&1; then
  exec python3 -m http.server "$PORT"
fi
exec python -m SimpleHTTPServer "$PORT"
