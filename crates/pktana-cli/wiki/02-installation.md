# Installation

## Requirements

- Linux (kernel 3.x or newer)
- Rust 1.70+ (for building from source)
- `libpcap-dev` (only needed for live capture feature)
- Root / `CAP_NET_RAW` capability for live packet capture

---

## Option 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/omnayak27199/pktana
cd pktana

# Full build with TUI and live capture support
cargo build --release --features pcap,tui

# The binary is at:
./target/release/pktana
```

### Install system-wide

```bash
sudo cp target/release/pktana /usr/local/bin/
```

---

## Option 2: Install from crates.io

```bash
cargo install pktana-cli --features pcap,tui
```

> **Note**: requires `libpcap-dev` installed on the build host.

---

## Option 3: Pre-built Packages

### Ubuntu / Debian (.deb)

```bash
# Download from the GitHub releases page
wget https://github.com/omnayak27199/pktana/releases/latest/download/pktana_0.6.0_amd64.deb
sudo dpkg -i pktana_0.6.0_amd64.deb
```

Package installs:
- Binary: `/usr/bin/pktana`
- Runtime dependencies: `libpcap0.8`, `libc6`

### RHEL / Rocky / AlmaLinux / CentOS (.rpm)

```bash
wget https://github.com/omnayak27199/pktana/releases/latest/download/pktana-0.6.0-1.x86_64.rpm
sudo rpm -ivh pktana-0.6.0-1.x86_64.rpm
```

---

## Build Feature Combinations

| Build Command | Features | Use case |
|---|---|---|
| `cargo build --release` | none | CLI-only, no live capture, no TUI |
| `cargo build --release --features pcap` | pcap | CLI with live capture |
| `cargo build --release --features tui` | tui | TUI dashboard (offline pcap only) |
| `cargo build --release --features pcap,tui` | pcap + tui | Full CLI + TUI + Web UI |
| `cargo build --release --features pcap,tui,ai` | all | Experimental AI features |

---

## Dependency Notes

### libpcap

libpcap is **only needed when building with `--features pcap`**. To install:

```bash
# Debian / Ubuntu
sudo apt install libpcap-dev

# RHEL / Rocky / AlmaLinux
sudo dnf install libpcap-devel

# openssl-sys (needed for TLS in reqwest, if building with ai feature)
sudo apt install libssl-dev perl           # Debian/Ubuntu
sudo dnf install openssl-devel perl        # RHEL
```

### Runtime Capabilities

Live packet capture requires elevated privileges:

```bash
# Run as root
sudo pktana capture eth0

# OR grant capability to the binary (allows non-root capture)
sudo setcap cap_net_raw+ep /usr/local/bin/pktana
pktana capture eth0   # now works without sudo
```

---

## Verify Installation

```bash
pktana --version
# pktana v0.6.0 — Linux Packet Analyzer
# License: Apache-2.0
# https://github.com/omnayak27199/pktana

pktana interfaces
# Lists available capture interfaces

pktana route
# Shows routing table (no root needed)

pktana conn
# Shows active connections (no root needed for your own processes)
```

---

## Docker

```bash
docker build -t pktana .
docker run --rm --net=host --privileged pktana capture eth0
```

See `docker-build.sh` in the repository root for the full multi-stage build script.
