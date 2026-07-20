#!/usr/bin/env bash
# Build pktana macOS .app / .dmg (must run on macOS or macos-latest CI).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP="$ROOT/pktana-desktop"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS .app/.dmg must be built on a Mac (or GitHub Actions macos-latest)."
  echo "This machine is $(uname -s). Push to GitHub and download the desktop-macos artifact."
  exit 1
fi

echo "==> Installing libpcap (Homebrew) if needed..."
if ! brew list libpcap >/dev/null 2>&1; then
  brew install libpcap
fi

export PKG_CONFIG_PATH="$(brew --prefix libpcap)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

echo "==> Building native pktana (libpcap + TUI)..."
cargo build --release --features pcap,tui -p pktana-cli

mkdir -p "$DESKTOP/resources/bin"
cp -f "$ROOT/target/release/pktana" "$DESKTOP/resources/bin/pktana"
chmod +x "$DESKTOP/resources/bin/pktana"
"$DESKTOP/resources/bin/pktana" --version || true

echo "==> Packaging Electron .app / .dmg..."
cd "$DESKTOP"
npm install
npm run dist:mac

# Extra pass: ad-hoc sign any .app left in dist (afterPack also signs).
while IFS= read -r -d '' app; do
  echo "Ad-hoc codesign: $app"
  codesign --force --deep --sign - "$app" || true
done < <(find "$DESKTOP/dist" -name '*.app' -print0 2>/dev/null || true)

echo ""
echo "Artifacts in $DESKTOP/dist/"
ls -la "$DESKTOP/dist/" || true
echo ""
echo "If macOS says the app is damaged after download:"
echo "  ./pktana-desktop/scripts/fix-macos-gatekeeper.sh /Applications/pktana.app"
echo "Live capture tip: install Wireshark once for ChmodBPF, or run with admin rights."
