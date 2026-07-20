# pktana

**A high-performance, zero-dependency network inspection toolkit for Linux — written in Rust.**

> Replaces `tcpdump`, `ethtool`, `ss`, `ip route`, `iftop`, and Wireshark with a single binary,
> plus a multi-window **browser UI** for parallel per-interface capture.
> Built for production infrastructure, network security, and cloud-native environments.

[![CI](https://github.com/omnayak27199/pktana/actions/workflows/ci.yml/badge.svg)](https://github.com/omnayak27199/pktana/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.6.0-green.svg)](https://github.com/omnayak27199/pktana/releases/tag/v0.6.0)
[![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20RHEL%20%2F%20Rocky%20%2F%20Ubuntu%20%2F%20Debian-lightgrey.svg)]()
[![crates.io](https://img.shields.io/crates/v/pktana-cli.svg)](https://crates.io/crates/pktana-cli)
[![Website](https://img.shields.io/badge/website-pktana.online-orange.svg)](https://pktana.online)

🌐 **Website**: [pktana.online](https://pktana.online)
📦 **crates.io**: [pktana-cli](https://crates.io/crates/pktana-cli) · [pktana-core](https://crates.io/crates/pktana-core)
📥 **Downloads**: [GitHub Releases](https://github.com/omnayak27199/pktana/releases/tag/v0.6.0)

---

## What's new in v0.6.0

- 🛡 **DLP engine (Sophos-style)** — detect credentials, PAN/PCI, SSN, IBAN, private keys, cloud API keys, and bulk PII in HTTP/FTP/SMTP payloads; custom regex identifiers supported.
- 🚨 **IDPS engine (Suricata-style)** — signature matching, DPI risk bridge, port-scan / SSH brute / DNS-tunnel / NTP-amp heuristics, JA3 blocklists, and custom Suricata rules.
- 🎛 **Conditional security policy** — per-engine monitor / drop / redirect actions, interface-scoped policy rules, per-rule overrides, and clear-on-disable stats.
- 🪟 **Web / CLI / TUI / MCP integration** — security config, alerts, flows, and per-interface stats available across every capture path.
- 📊 **Per-interface security stats** — live alert counts and flow summaries that reset cleanly when an engine is disabled.

See [v0.6.0_release_note.md](v0.6.0_release_note.md) and [CHANGELOG.md](CHANGELOG.md) for the full list.

---

## Why pktana?

Modern infrastructure teams need deep network visibility without installing 5 separate tools. pktana is a **single signed package** that gives you:

| What you need | Old way | pktana |
|---|---|---|
| Packet capture & decode | `tcpdump` + Wireshark | `pktana capture eth0` |
| Deep protocol inspection (L2–L7) | Wireshark + manual analysis | `pktana inspect <hex>` |
| TLS JA3 fingerprinting | custom scripts / SIEM | built into `pktana inspect` |
| QUIC / HTTP2 / gRPC detection | Wireshark plugins | built into `pktana inspect` |
| Tunnel inner-frame decode (VXLAN/GRE) | custom scripts | built into `pktana inspect` |
| Risk scoring & app classification | Palo Alto / Fortinet | built into `pktana inspect` |
| Data loss prevention (DLP) | Sophos / Forcepoint | built-in DLP engine (Web / CLI / TUI) |
| Intrusion detection / prevention | Suricata / Snort | built-in IDPS engine (signatures + heuristics) |
| NIC stats & hardware offloads | `ethtool` | `pktana ethtool eth0` |
| Active connections + GeoIP | `ss -tulnp` + separate tool | `pktana conn` |
| Routing table | `ip route` | `pktana route` |
| Dataplane / XDP / DPDK / SR-IOV | custom scripts | `pktana dp eth0` |
| Live bandwidth dashboard + GeoIP | `iftop` | `pktana stats eth0` |
| Wireshark-like TUI | Wireshark (GUI only) | `pktana tui eth0` |
| Multi-interface web dashboard | Wireshark | `pktana web 8080` |
| Offline GeoIP lookup | `geoiplookup` binary | `pktana geoip <IP>` |

---

## Features

### Deep Packet Inspection (L2–L7) — Enterprise Grade

#### Protocol Decoding
- **L2**: Ethernet, ARP (request/reply/gratuitous), QinQ/802.1Q VLAN stacks, OUI vendor lookup
- **L3**: IPv4 (DSCP, ECN, ID, DF/MF, TTL, fragmentation), **IPv6** (next header name, hop limit)
- **L4**: TCP (full options: MSS, WSCALE, SACK, Timestamps), UDP, ICMP (30+ type/code messages)
- **TLS 1.0–1.3**: SNI, **JA3** (raw string + MD5 hash), **ALPN** list, cipher suites, elliptic curves, GREASE filtering, deprecation warning for TLS 1.0/1.1 (RFC 8996)
- **QUIC / HTTP3**: long/short header decode, version decode (RFC 9000 v1, RFC 9369 v2, gQUIC, drafts, GREASE)
- **HTTP/2**: PRI magic + frame-type parsing, **gRPC** `:path` header extraction via HPACK
- **HTTP/1.x**: method, URL, status code, key headers
- **WebSocket**: Upgrade detection + per-frame opcode (Text/Binary/Close/Ping/Pong), mask
- **DNS**: query name, QTYPE, RCode (NXDOMAIN), **Shannon entropy on longest label** for DGA/tunneling heuristic
- **DHCP**: full DORA state machine and option decoding (with `dhcp-dora` tag filter)
- **SSH**: banner extraction (version + software), SSHv1 deprecation warning
- **SIP / VoIP**: INVITE/BYE/REGISTER/OPTIONS/CANCEL/ACK, SIP URI, Call-ID, From, To, User-Agent
- **NTP**: version, mode with name (Client/Server/Broadcast/monlist), stratum, **amplification risk flag** (mode 7 — DDoS vector)
- **BGP**: message type (OPEN/UPDATE/NOTIFICATION/KEEPALIVE), AS number, Router ID
- **SMTP**, **RDP**, **MySQL**, **PostgreSQL**, **Redis**, **MongoDB**, **SNMP**, **LDAP**, **Kerberos**, **IKE**, **SSDP**, **Syslog**, **Geneve**
- **Tunnel inner-frame re-inspection**: VXLAN (UDP/4789), GRE (IP proto 47), Geneve — re-decodes inner Ethernet frame and extracts inner src/dst IP, protocol, ports, and application protocol

#### Anomaly Detection
SYN+FIN, NULL scan (no flags), SYN+RST, zero-window SYN, TTL=0, broadcast source MAC, malformed TCP data offset, fragmented packets, short ARP/UDP/ICMP headers, ARP MAC mismatch, ICMP redirect.

#### Risk Scoring & Classification
- **Composite 0–100 risk score** with visual `█` bar — aggregates signals: deprecated TLS, SSHv1, NTP monlist, DNS entropy spike, NULL scan, zero-window SYN, tunneling, broadcast source.
- **App category**: Web Browsing, Encrypted Transport, VoIP / UC, Database, File Transfer, Tunneling / Overlay, Remote Access, DNS / Infrastructure, Monitoring / Mgmt, Generic TCP/UDP.

#### Auto-Diagnosis Engine
OS fingerprinting via TTL (Linux=64 / Windows=128 / Cisco=255) and TCP options. DSCP/QoS class labelling, DNS rcode explanation, HTTP status classification, DHCP state machine, VLAN/QinQ tagging, fragmentation notice, DGA/tunneling entropy alert.

---

### Multi-Window Web UI (`pktana web [PORT]`)

The web UI brings full Wireshark-style packet analysis to your browser, with a unique **multi-window architecture** so you can monitor many interfaces simultaneously.

#### Architecture
- **Host-scoped activity bar** (left): Server Info, PCAP Analyzer, Connections, Terminal.
- **Per-interface windows** (top strip): every interface you open becomes a Chrome-tab-style window with its own state, packet store, and flow tables.
- **Per-window inner tabs**: 📊 Packets, 🔗 Flows, 📈 Protocols, ⚙️ Hardware.
- **No auto-start**: opening a window doesn't start capture — click ▶ Start Capture per window.
- **Per-window Pause / Resume**: pause stops only the current interface; the Resume button only appears in the paused window.
- **Live SSE stream** for each session, independent backend session per window (DashMap-tracked).

#### What you get per window
- Wireshark-style packet table with WS-style protocol colors and per-row risk badges
- Click-to-expand DPI decode (every L2–L7 field, every JA3/ALPN/QUIC/SIP/BGP/NTP field)
- Flow table (proto · src · dst · pkts · bytes · category)
- Protocol breakdown + top talkers with GeoIP
- Hardware tab (per interface): NIC driver, ethtool, dataplane (XDP/DPDK/SR-IOV)
- Toolbar filters: protocol, search, handshake tags (TCP SYN / TLS / DNS / DHCP DORA), copy & format helpers
- Pause/Resume per window, Stop Capture per window, × Close window

#### Host-scoped tools
- **Connections**: TCP/UDP socket list + GeoIP + PID, refresh on demand.
- **PCAP Analyzer**: drop a file path or upload a `.pcap` and it opens in a new analysis window.
- **Terminal**: in-browser xterm.js shell (when enabled).
- **Security (DLP / IDPS)**: enable engines, set monitor/drop/redirect actions, review alerts & flows, manage custom identifiers and Suricata rules.
- **Theme toggle**: polished light & dark themes with full contrast coverage.

#### REST + SSE API
- `GET  /api/nic` · `GET  /api/route` · `GET  /api/conn` · `GET  /api/geoip?ip=…`
- `GET  /api/ethtool?iface=…` · `GET  /api/dp?iface=…` · `GET  /api/interfaces`
- `POST /api/sessions/create` · `GET /api/sessions` · `POST /api/sessions/{id}/stop` · `DELETE /api/sessions/{id}`
- `GET  /api/inspect?session=…&iface=…[&filter=…][&flow_analyze=true]` (Server-Sent Events)
- `GET  /api/inspect?session=…&read=/path/to/file.pcap` (offline pcap stream)
- `GET/POST /api/security/config` · `GET /api/security/alerts` · `GET /api/security/flows` · `GET /api/security/stats`

---

### DLP & IDPS Security Engines

Inline security inspection runs on every capture path (live, pcap, Web, TUI, MCP):

#### DLP (Data Loss Prevention)
- Built-in identifiers for cleartext credentials, bearer tokens, session cookies, payment cards (PAN/PCI), SSN, IBAN, passport patterns, bulk email/phone, private keys, and cloud API keys
- Protocol-aware scanners for HTTP, FTP, and SMTP
- Custom Sophos-style regex identifiers with category and severity
- Actions: **monitor**, **drop**, or **redirect** (with optional redirect target)

#### IDPS (Intrusion Detection / Prevention)
- Suricata-style signature catalog plus custom rule lines
- Heuristics: port scan, SSH brute-force, DNS tunneling, NTP amplification, suspicious ports, Telnet, large ICMP
- DPI risk bridge and JA3 fingerprint blocklists
- Per-signature thresholds (count within time window) before alerting

#### Policy & operations
- Conditional policy rules (interface, engine, addresses, ports)
- Per-interface / per-session alert and flow stats; clear-on-disable resets engine state
- Configurable from Web UI, CLI, TUI, and MCP tools

---

### Wireshark-Like TUI (`pktana tui eth0`)
- **5-tab layout**: Overview, Packets, Flows, Stats, Help
- **Detail popup** with Original / Layers / Hex sub-tabs
- All DPI fields displayed: JA3, ALPN, QUIC version, SSH banner, SIP details, NTP amplification risk, BGP ASN, tunnel inner frame, DNS entropy, risk score with bar, app category
- Per-protocol color coding: TLS=green, HTTP=blue, DNS=cyan, QUIC=bright-green, SIP=magenta, BGP/NTP=red
- Real-time bandwidth sparkline, top-10 talkers with GeoIP country
- BPF filter and interface selection

---

### Live Capture (`pktana <iface>` / `pktana capture <iface>`)
- Color-coded protocol column: TLS, HTTP, DNS, QUIC, SSH, ARP, ICMP, SIP, BGP
- **DPI-enriched Info column**: TLS SNI+ALPN, HTTP method+path, DNS query name, SSH banner, SIP method, BGP message type, QUIC version, NTP mode
- RST packets highlighted in red
- **End-of-capture summary**: protocol breakdown table + top-5 talkers with bytes

---

### Connection Table (`pktana conn`)
- TCP/UDP/TCP6/UDP6 sockets from `/proc/net/{tcp,udp,tcp6,udp6}`
- PID → process name resolution
- **GeoIP country** for every remote IP (offline, no API call)
- **Service name** for well-known remote/local ports (HTTP, HTTPS, DNS, SSH, …)
- **Color-coded state**: ESTABLISHED=green, LISTEN=cyan, TIME_WAIT/CLOSE_WAIT=yellow, SYN*=bold yellow

---

### Live Stats Dashboard (`pktana stats eth0`)
- Real-time PPS/BPS with 1-second sliding window
- Per-protocol breakdown with ASCII bar chart (up to 6 protocols)
- Top-10 talkers by packet count with **GeoIP country name**
- BPF filter support, Ctrl+C to exit

---

### NIC & Dataplane Inspection
- XDP eBPF program detection, AF_XDP zero-copy socket detection
- DPDK binding / userspace driver detection
- SR-IOV VF/PF topology, VF count
- Per-queue IRQ → CPU affinity (smp_affinity), PCIe link speed/width
- Hardware offloads: checksum, TSO, LRO, GRO, RSS

---

### GeoIP Lookup (`pktana geoip <IP>`)
- Offline IP → country code + continent + country name
- Private, loopback, CGNAT, link-local ranges labelled automatically
- Bulk lookup: `pktana geoip 8.8.8.8 1.1.1.1 9.9.9.9`

---

### Other Commands
- `pktana route` — IPv4 + IPv6 routing table from procfs (CIDR, gateway, metric, type)
- `pktana watch eth0` — auto-refresh NIC counter view (default 2s, configurable)
- `pktana hex <HEX>` — quick one-line decode
- `pktana file <FILE>` — batch hex packet decode with flow table
- `pktana demo` — built-in sample packets for testing
- `pktana help <command>` — full per-command documentation page

---

## Installation

### macOS desktop app (Wireshark-style)

Native **pktana.app** wraps the same `web.rs` UI and uses **libpcap** for live capture on Mac interfaces (`en0`, …):

```bash
./pktana-desktop/scripts/build-mac.sh   # on a Mac, or use GitHub Actions
open pktana-desktop/dist/*.dmg
```

See [pktana-desktop/README.md](pktana-desktop/README.md). For a Linux engine in Docker instead: `./docker_mac.sh start`.

### macOS (full features via Docker)

Native macOS cannot provide Linux `/proc`, ethtool, or XDP. On a Mac, run **full Linux pktana** (same `web.rs` Web UI) inside Docker Desktop:

```bash
./docker_mac.sh start 8080
open http://127.0.0.1:8080
```

See `Dockerfile.web` and `./docker_mac.sh help`. Capture is inside the container network; drop PCAP files into `./pcaps` for offline analysis.

### Automatic Install (Recommended)

Detects your OS and installs the appropriate native package or builds from source:

```bash
curl -fsSL https://raw.githubusercontent.com/omnayak27199/pktana/main/install.sh | bash
```

### RHEL / Rocky / AlmaLinux / CentOS Stream 9

```bash
sudo dnf install -y \
  https://github.com/omnayak27199/pktana/releases/latest/download/pktana-0.6.0-1.el9.x86_64.rpm
```

### RHEL / CentOS 7

```bash
sudo yum install -y \
  https://github.com/omnayak27199/pktana/releases/latest/download/pktana-0.6.0-1.el7.x86_64.rpm
```

### Ubuntu 22.04 / 24.04 · Debian 12

```bash
curl -L -o pktana.deb \
  https://github.com/omnayak27199/pktana/releases/latest/download/pktana_0.6.0_amd64_ubuntu24.04.deb
sudo apt install -y ./pktana.deb
```

(Replace `ubuntu24.04` with `ubuntu22.04` or `debian12` for the matching `.deb`.)

### Verify the RPM signature

```bash
rpm --checksig pktana-0.6.0-1.el9.x86_64.rpm
```

### Build from source

```bash
git clone https://github.com/omnayak27199/pktana
cd pktana
cargo build --release --features pcap,tui
./target/release/pktana --version
```

### As a Rust dependency

```bash
cargo add pktana-core   # DPI engine library
cargo add pktana-cli    # full CLI binary
```

---

## Usage

```bash
# Live packet capture (color-coded, DPI-enriched)
sudo pktana eth0
sudo pktana eth0 100                     # stop after 100 packets
sudo pktana capture eth0 'port 443'      # BPF filter

# Web UI — multi-window per-interface dashboard
sudo pktana web 8080                     # starts as background daemon
sudo pktana web 8080 -f                  # foreground mode

# Wireshark-like TUI dashboard
sudo pktana tui eth0
sudo pktana tui capture.pcap             # browse a pcap file

# Deep packet inspection (hex input — all DPI fields)
pktana inspect 45000028...
pktana inspect -f packet.hex

# Active connections (GeoIP + state colors + service names)
pktana conn

# NIC information
pktana nic eth0

# Dataplane / XDP / DPDK / SR-IOV
pktana dp eth0

# ethtool equivalent
pktana ethtool eth0

# Routing table (IPv4 + IPv6)
pktana route

# Live stats dashboard (GeoIP top talkers)
sudo pktana stats eth0
sudo pktana stats eth0 'port 443'

# Watch mode (auto-refresh every N seconds)
pktana watch eth0 2

# GeoIP lookup (offline, bulk)
pktana geoip 8.8.8.8 1.1.1.1

# Batch hex packet decode
pktana file packets.txt

# Full help
pktana help
pktana help inspect
pktana help tui
pktana help web
```

---

## Architecture

```
pktana/
├── crates/
│   ├── pktana-core/            # Library: parser, DPI engine, NIC/route/conn inspection
│   │   └── src/
│   │       ├── dpi.rs          # L2–L7 DPI engine:
│   │       │                   #   TLS JA3 + ALPN + ciphers, QUIC/HTTP3, HTTP/2, gRPC,
│   │       │                   #   WebSocket, SSH banner, SIP/VoIP, NTP full, BGP,
│   │       │                   #   VXLAN/GRE inner-frame re-inspection, IPv6, DNS entropy,
│   │       │                   #   risk scoring (0-100), app category classification
│   │       ├── capture.rs      # Live capture (libpcap)
│   │       ├── flow_analyzer.rs# Stateful flow analysis (handshakes, DHCP DORA, etc.)
│   │       ├── nic.rs          # NIC info + XDP/DPDK/SR-IOV/AF_XDP detection
│   │       ├── ethtool.rs      # Driver, offload, IRQ, queue, PCIe info
│   │       ├── connections.rs  # TCP/UDP connection table (procfs)
│   │       ├── routes.rs       # IPv4/IPv6 routing table (procfs)
│   │       ├── geoip.rs        # Offline GeoIP lookup (embedded dataset)
│   │       ├── parser.rs       # Ethernet frame parser
│   │       └── packet.rs       # Packet data model
│   └── pktana-cli/             # Binary: command dispatcher + output rendering
│       └── src/
│           ├── main.rs         # All CLI commands + DPI display helpers
│           ├── tui.rs          # Wireshark-like TUI (ratatui + crossterm)
│           └── web.rs          # Embedded HTTP server + multi-window Web UI
├── deploy/centos/              # RPM spec + install script
├── .github/workflows/
│   ├── ci.yml                  # fmt, clippy, test on push/PR
│   └── release.yml             # Build & upload RPM + .deb + tarballs to GitHub Release
└── docker-build.sh             # Local multi-distro build helper
```

See [docs/architecture.md](docs/architecture.md) for detailed design notes.

---

## Embedding pktana-core in your project

```toml
[dependencies]
pktana-core = "0.6.0"
```

```rust
use pktana_core::inspect;

let dp = inspect(&raw_bytes);
println!("{}", dp.one_liner());
println!("Risk: {}/100  Category: {:?}", dp.risk_score, dp.app_category);
if let Some(ja3) = &dp.tls_ja3_raw {
    println!("JA3 raw: {ja3}");
}
for finding in dp.diagnose() {
    println!("  ▶ {finding}");
}
```

---

## Performance

- Zero heap allocation in the hot packet path
- Memory safe — written in Rust with no `unsafe` blocks in the core library
- Reads NIC/connection/route data directly from `sysfs`/`procfs` — no external commands
- Single static binary, minimal runtime footprint
- Per-session DashMap state in the web server — many parallel captures without lock contention

---

## Building releases locally (optional)

Pre-built artifacts are published automatically by GitHub Actions on every release tag. To reproduce a build locally:

```bash
# RPM (RHEL 9 example)
./docker-build.sh el9

# .deb (Ubuntu 24.04 example)
./docker-build.sh ubuntu24

# Manage build containers
./docker-build.sh ls
./docker-build.sh kill all
```

The CI workflow [`.github/workflows/release.yml`](.github/workflows/release.yml) builds all 5 artifacts in parallel and attaches them to the GitHub Release.

---

## Commercial Use

pktana is licensed under **Apache 2.0** — free for personal and open-source use.

For **commercial licensing**, OEM embedding, support contracts, or custom feature development:

📧 **omnayak27199@gmail.com**

---

## Contributing

Issues and PRs welcome. Please run before submitting:

```bash
cargo fmt --all
cargo clippy --all-targets --features pcap,tui -- -D warnings
cargo test --all
```

---

## License

Copyright 2025–2026 Omprakash (omnayak27199@gmail.com)
Licensed under the [Apache License 2.0](LICENSE).
