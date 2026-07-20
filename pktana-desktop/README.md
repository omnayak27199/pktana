# pktana Desktop (macOS)

Wireshark-style **native macOS app** for pktana.

The window hosts the real **`web.rs` Web UI**. Live capture uses **libpcap** (same stack Wireshark uses on Mac). DPI / DLP / IDPS run in-process.

Linux-only host panels (ethtool, XDP/DPDK, `/proc` netns) show empty or N/A on macOS — that is expected.

## Quick start (development on a Mac)

```bash
# 1) Build the Rust backend
cd /path/to/pktana
brew install libpcap
export PKG_CONFIG_PATH="$(brew --prefix libpcap)/lib/pkgconfig"
cargo build --release --features pcap,tui -p pktana-cli
mkdir -p pktana-desktop/resources/bin
cp target/release/pktana pktana-desktop/resources/bin/pktana

# 2) Run the desktop shell
cd pktana-desktop
npm install
npm start
```

## Build installer (.dmg)

```bash
./pktana-desktop/scripts/build-mac.sh
# → pktana-desktop/dist/pktana-0.6.0-mac-*.dmg
```

Or download the `desktop-macos` artifact from GitHub Actions.

## Capture permissions

macOS blocks raw capture unless BPF devices are readable:

1. Install [Wireshark](https://www.wireshark.org/) once (installs **ChmodBPF**), **or**
2. Run pktana as administrator when capturing.

Then open interfaces (`en0`, `en1`, …) from the Web UI and start capture — same flow as on Linux.

## Fallback

If no native binary is present, the app can start `./docker_mac.sh` (Linux engine in Docker). Prefer the native binary for real Mac interface capture.
