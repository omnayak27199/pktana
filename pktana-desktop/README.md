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

1. Install [Rust](https://rustup.rs/), [Node.js 20+](https://nodejs.org/), [Npcap SDK](https://npcap.com/#download) (build), and [Npcap](https://npcap.com/) (runtime).
2. Set `NPCAP_SDK` (e.g. `C:\Npc_SDK`).
3. Build and run:

```bat
pktana-desktop\scripts\build-window.bat
```

If the app says it is missing `pktana.exe`, the installer was packaged without the capture engine (fixed in current `main` via `afterPack` copy). Rebuild/redownload after that fix, and install Npcap.

## Build installers

| Platform | Command | Output |
|---|---|---|
| **macOS** | `./pktana-desktop/scripts/build-mac.sh` | `.dmg` + `.zip` in `dist/` |
| **Windows** | `./pktana-desktop/scripts/build-window.sh` or `scripts\build-window.bat` | NSIS `.exe` + portable in `dist/` |

Or download artifacts from GitHub Actions:

- **Desktop macOS** → `desktop-macos`
- **Desktop Windows** → `desktop-windows`

## macOS: “app is damaged and can’t be opened”

This is **Gatekeeper quarantine**, not a corrupt file. Apple blocks unsigned apps downloaded from the internet (GitHub Releases / Actions artifacts).

**Fix (on the Mac):**

```bash
# After dragging pktana.app into Applications:
xattr -cr /Applications/pktana.app

# Or run the helper:
./pktana-desktop/scripts/fix-macos-gatekeeper.sh /Applications/pktana.app
```

Then open **pktana** again (first time: Right-click → **Open** if macOS still warns).

Fully removing the warning for all users requires an **Apple Developer ID** certificate + notarization. CI currently uses **ad-hoc** signing only.

## Capture permissions

| OS | Requirement |
|---|---|
| macOS | Install Wireshark once (**ChmodBPF**), or run as admin |
| Windows | Install [Npcap](https://npcap.com/) (WinPcap API compat), run as Administrator if needed |

## Fallback (macOS / Linux only)

If no native binary is present, the app can start `./docker_mac.sh`. Prefer the native binary for real host interface capture.
