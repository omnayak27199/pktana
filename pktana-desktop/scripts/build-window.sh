#!/usr/bin/env bash
# Build pktana Windows installer (.exe / portable).
# Must run on Windows (Git Bash / MSYS2 / WSL2 with Windows toolchain)
# or use GitHub Actions windows-latest.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP="$ROOT/pktana-desktop"
cd "$ROOT"

is_windows() {
  case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) return 0 ;;
  esac
  # WSL often reports Linux; allow explicit override
  if [[ "${PKTANA_FORCE_WINDOWS_BUILD:-}" == "1" ]]; then
    return 0
  fi
  return 1
}

if ! is_windows; then
  echo "Windows .exe installer must be built on Windows (or GitHub Actions windows-latest)."
  echo "This machine is $(uname -s). Push to GitHub and download the desktop-windows artifact."
  echo ""
  echo "On Windows (Git Bash):"
  echo "  ./pktana-desktop/scripts/build-window.sh"
  echo "Or:"
  echo "  pktana-desktop\\scripts\\build-window.bat"
  exit 1
fi

echo "==> Checking toolchain..."
command -v cargo >/dev/null || { echo "cargo not found. Install Rust from https://rustup.rs/"; exit 1; }
command -v npm >/dev/null || { echo "npm not found. Install Node.js 20+ from https://nodejs.org/"; exit 1; }

# Npcap SDK / WinPcap is required for the pcap crate on Windows.
# Prefer Npcap SDK if present; otherwise try vcpkg or system pkg-config.
if [[ -n "${NPCAP_SDK:-}" && -d "${NPCAP_SDK}" ]]; then
  export LIB="${NPCAP_SDK}/Lib/x64;${LIB:-}"
  export INCLUDE="${NPCAP_SDK}/Include;${INCLUDE:-}"
  echo "Using NPCAP_SDK=${NPCAP_SDK}"
elif [[ -d "/c/Npc_SDK" ]]; then
  export NPCAP_SDK="/c/Npc_SDK"
  export LIB="${NPCAP_SDK}/Lib/x64;${LIB:-}"
  export INCLUDE="${NPCAP_SDK}/Include;${INCLUDE:-}"
  echo "Using NPCAP_SDK=${NPCAP_SDK}"
else
  echo "Note: if cargo fails on pcap, install Npcap SDK from https://npcap.com/#download"
  echo "      and set NPCAP_SDK to the SDK folder (e.g. C:\\\\Npc_SDK)."
fi

echo "==> Building native pktana.exe (pcap + TUI)..."
cargo build --release --features pcap,tui -p pktana-cli

BIN_SRC="$ROOT/target/release/pktana.exe"
if [[ ! -f "$BIN_SRC" ]]; then
  # Some toolchains omit .exe in path checks under MSYS
  BIN_SRC="$ROOT/target/release/pktana"
fi
if [[ ! -f "$BIN_SRC" ]]; then
  echo "Build failed: pktana.exe not found under target/release/"
  exit 1
fi

mkdir -p "$DESKTOP/resources/bin"
cp -f "$BIN_SRC" "$DESKTOP/resources/bin/pktana.exe"
# Electron main.js also looks for bare "pktana" on PATH; keep .exe name for Windows.
"$DESKTOP/resources/bin/pktana.exe" --version || true

echo "==> Packaging Electron Windows installer..."
cd "$DESKTOP"
npm install
npm run dist:win

echo ""
echo "Artifacts in $DESKTOP/dist/"
ls -la "$DESKTOP/dist/" || true
echo ""
echo "Live capture tip: install Npcap (https://npcap.com/) with WinPcap API compat, then run pktana as Administrator if needed."
