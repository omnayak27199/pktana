# pktana Desktop (macOS & Windows)

Wireshark-style **desktop app** for pktana.

The window hosts the real **`web.rs` Web UI**. Live capture uses **libpcap** (macOS) or **Npcap** (Windows). DPI / DLP / IDPS run in-process.

Linux-only host panels (ethtool, XDP/DPDK, `/proc` netns) show empty or N/A on desktop OS — that is expected.

## Quick start (development)

### macOS

```bash
brew install libpcap
export PKG_CONFIG_PATH="$(brew --prefix libpcap)/lib/pkgconfig"
cargo build --release --features pcap,tui -p pktana-cli
mkdir -p pktana-desktop/resources/bin
cp target/release/pktana pktana-desktop/resources/bin/pktana
cd pktana-desktop && npm install && npm start
```

### Windows

1. Install [Rust](https://rustup.rs/), [Node.js 20+](https://nodejs.org/), and [Npcap SDK](https://npcap.com/#download).
2. Set `NPCAP_SDK` (e.g. `C:\Npc_SDK`).
3. Build and run:

```bat
cargo build --release --features pcap,tui -p pktana-cli
mkdir pktana-desktop\resources\bin
copy target\release\pktana.exe pktana-desktop\resources\bin\pktana.exe
cd pktana-desktop
npm install
npm start
```

## Build installers

| Platform | Command | Output |
|---|---|---|
| **macOS** | `./pktana-desktop/scripts/build-mac.sh` | `.dmg` + `.zip` in `dist/` |
| **Windows** | `./pktana-desktop/scripts/build-window.sh` or `scripts\build-window.bat` | NSIS `.exe` + portable in `dist/` |

Or download artifacts from GitHub Actions:

- **Desktop macOS** → `desktop-macos`
- **Desktop Windows** → `desktop-windows`

## Capture permissions

| OS | Requirement |
|---|---|
| macOS | Install Wireshark once (**ChmodBPF**), or run as admin |
| Windows | Install [Npcap](https://npcap.com/) (WinPcap API compat), run as Administrator if needed |

## Fallback (macOS / Linux only)

If no native binary is present, the app can start `./docker_mac.sh`. Prefer the native binary for real host interface capture.
