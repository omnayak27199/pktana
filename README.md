# pktana

**A high-performance, zero-dependency network inspection toolkit for Linux — written in Rust.**

> Replaces `tcpdump`, `ethtool`, `ss`, `ip route`, `iftop`, and Wireshark with a single binary.  
> Built for production infrastructure, network security, and cloud-native environments.

[![CI](https://github.com/omnayak27199/pktana/actions/workflows/ci.yml/badge.svg)](https://github.com/omnayak27199/pktana/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.3.1-green.svg)](https://github.com/omnayak27199/pktana/releases/tag/v0.3.1)
[![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20RHEL%20%2F%20Rocky-lightgrey.svg)]()
[![crates.io](https://img.shields.io/crates/v/pktana-cli.svg)](https://crates.io/crates/pktana-cli)
[![Website](https://img.shields.io/badge/website-pktana.online-orange.svg)](https://pktana.online)

🌐 **Website**: [pktana.online](https://pktana.online)  
📦 **crates.io**: [pktana-cli](https://crates.io/crates/pktana-cli) · [pktana-core](https://crates.io/crates/pktana-core)

---

## Why pktana?

Modern infrastructure teams need deep network visibility without installing 5 separate tools. pktana is a **single signed RPM** that gives you:

| What you need | Old way | pktana |
|---|---|---|
| Packet capture & decode | `tcpdump` + Wireshark | `pktana capture eth0` |
| Deep protocol inspection (L2–L7) | Wireshark + manual analysis | `pktana inspect <hex>` |
| TLS JA3 fingerprinting | custom scripts / SIEM | built into `pktana inspect` |
| QUIC / HTTP2 / gRPC detection | Wireshark plugins | built into `pktana inspect` |
| Tunnel inner-frame decode (VXLAN/GRE) | custom scripts | built into `pktana inspect` |
| Risk scoring & app classification | Palo Alto / Fortinet | built into `pktana inspect` |
| NIC stats & hardware offloads | `ethtool` | `pktana ethtool eth0` |
| Active connections + GeoIP | `ss -tulnp` + separate tool | `pktana conn` |
| Routing table | `ip route` | `pktana route` |
| Dataplane / XDP / DPDK / SR-IOV | custom scripts | `pktana dp eth0` |
| Live bandwidth dashboard + GeoIP | `iftop` | `pktana stats eth0` |
| Wireshark-like TUI | Wireshark (GUI only) | `pktana tui eth0` |
| Offline GeoIP lookup | `geoiplookup` binary | `pktana geoip <IP>` |

---

## Features

### Deep Packet Inspection (L2–L7) — Enterprise Grade

#### Protocol Decoding
- **L2**: Ethernet, ARP (request/reply/gratuitous), QinQ/802.1Q VLAN stacks, OUI vendor lookup
- **L3**: IPv4 (DSCP, ECN, ID, DF/MF, TTL, fragmentation), **IPv6** (next header name, hop limit)
- **L4**: TCP (full options: MSS, WSCALE, SACK, Timestamps), UDP, ICMP (30+ type/code messages)
- **TLS 1.0–1.3**: SNI extraction, **JA3 fingerprint raw string** (MD5 → JA3 hash), **ALPN** list, cipher suites, elliptic curves, GREASE filtering, TLS 1.0/1.1 deprecation warning (RFC 8996)
- **QUIC / HTTP3**: long/short header decode, version decode (RFC 9000 v1, RFC 9369 v2, gQUIC, drafts, GREASE)
- **HTTP/2**: PRI magic + frame-type parsing, **gRPC** `:path` header extraction via HPACK
- **HTTP/1.x**: method, URL, status code, key headers
- **WebSocket**: Upgrade header detection + per-frame opcode (Text/Binary/Close/Ping/Pong), mask
- **DNS**: query name, QTYPE, RCode (NXDOMAIN), **Shannon entropy on longest label** for DGA/tunneling heuristic
- **DHCP**: message type, client options
- **SSH**: banner extraction (version + software), SSHv1 deprecation warning in red
- **SIP / VoIP**: all methods (INVITE/BYE/REGISTER/OPTIONS/CANCEL/ACK), SIP URI, Call-ID, From, To, User-Agent
- **NTP**: version, mode with name (Client/Server/Broadcast/monlist), stratum with description, **amplification risk flag** (mode 7 — DDoS vector)
- **BGP**: message type (OPEN/UPDATE/NOTIFICATION/KEEPALIVE), AS number, Router ID
- **SMTP**, **RDP**, **MySQL**, **PostgreSQL**, **Redis**, **MongoDB**, **SNMP**, **LDAP**, **Kerberos**, **IKE**, **SSDP**, **Syslog**, **Geneve**
- **Tunnel inner-frame re-inspection**: VXLAN (UDP/4789), GRE (IP proto 47), Geneve — re-decodes the inner Ethernet frame and extracts inner src/dst IP, protocol, ports, and application protocol

#### Anomaly Detection
- SYN+FIN, NULL scan (no flags), SYN+RST, zero-window SYN, TTL=0, broadcast source MAC, malformed TCP data offset, fragmented packets, short ARP/UDP/ICMP headers, ARP MAC mismatch, ICMP redirect

#### Risk Scoring & Classification
- **Composite 0–100 risk score** with visual `█` bar — aggregates signals: deprecated TLS, SSHv1, NTP monlist, DNS entropy spike, NULL scan, zero-window SYN, tunneling, broadcast source
- **App category**: Web Browsing, Encrypted Transport, VoIP / UC, Database, File Transfer, Tunneling / Overlay, Remote Access, DNS / Infrastructure, Monitoring / Mgmt, Generic TCP/UDP

#### Auto-Diagnosis Engine
- OS fingerprinting via TTL (Linux=64 / Windows=128 / Cisco=255) and TCP options
- DSCP/QoS class labelling, DNS rcode explanation, HTTP status classification, DHCP state machine, VLAN/QinQ tagging, fragmentation notice, DGA/tunneling entropy alert

---

### Wireshark-Like TUI (`pktana tui eth0`)
- **5-tab layout**: Overview, Packets, Flows, Stats, Help
- **Detail popup** with Original / Layers / Hex sub-tabs
- All new DPI fields displayed: JA3, ALPN, QUIC version, SSH banner, SIP details, NTP amplification risk, BGP ASN, tunnel inner frame, DNS entropy, risk score with bar, app category
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

### RHEL / Rocky Linux / AlmaLinux / CentOS Stream 9

```bash
sudo dnf install https://github.com/omnayak27199/pktana/releases/download/v0.3.0/pktana-0.3.0-1.el9.x86_64.rpm
```

`libpcap` is installed automatically as a dependency.

### Verify the RPM signature

```bash
rpm --checksig pktana-0.3.0-1.el9.x86_64.rpm
```

### Build from source

```bash
git clone https://github.com/omnayak27199/pktana
cd pktana
cargo build --release --features pcap,tui
./target/release/pktana --version
```

---

## Usage

```bash
# Live packet capture (color-coded, DPI-enriched)
sudo pktana eth0
sudo pktana eth0 100                     # stop after 100 packets
sudo pktana capture eth0 'port 443'     # BPF filter

# Deep packet inspection (hex input — all DPI fields)
pktana inspect 45000028...
pktana inspect -f packet.hex

# Wireshark-like TUI dashboard
sudo pktana tui eth0

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
pktana help stats
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
│           └── tui.rs          # Wireshark-like TUI (ratatui + crossterm)
├── deploy/centos/              # RPM spec + install script
└── .github/workflows/          # CI: fmt, clippy, build, sign RPM, publish
```

See [docs/architecture.md](docs/architecture.md) for detailed design notes.

---

## Embedding pktana-core in your project

```toml
[dependencies]
pktana-core = "0.3.0"
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
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

---

## License

Copyright 2026 Omprakash (omnayak27199@gmail.com)  
Licensed under the [Apache License 2.0](LICENSE).
[![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20RHEL%20%2F%20Rocky-lightgrey.svg)]()

---

## Why pktana?

Modern infrastructure teams need deep network visibility without installing 5 separate tools. pktana is a **single signed RPM** that gives you:

| What you need | Old way | pktana |
|---|---|---|
| Packet capture & decode | `tcpdump` + Wireshark | `pktana capture eth0` |
| NIC stats & offloads | `ethtool` | `pktana ethtool eth0` |
| Active connections | `ss -tulnp` | `pktana conn` |
| Routing table | `ip route` | `pktana route` |
| Dataplane / XDP / DPDK info | custom scripts | `pktana dp eth0` |
| Deep packet inspection | Wireshark + manual analysis | `pktana inspect` |
| Live bandwidth dashboard | `iftop` | `pktana stats eth0` |

---

## Features

### Deep Packet Inspection (L2–L7)
- Full decode: Ethernet → VLAN/QinQ → IPv4/IPv6 → TCP/UDP/ICMP
- Application detection: HTTP, TLS+SNI, DNS, DHCP, SSH, SMTP, RDP, MySQL, PostgreSQL, Redis, MongoDB, BGP, NTP, SNMP, VXLAN, Geneve
- Anomaly detection: SYN+FIN, NULL scan, zero-window, TTL=0, broadcast source, malformed headers
- OS fingerprinting via TCP options (MSS, WSCALE, SACK)
- DSCP/QoS classification, ICMP traceroute detection, TLS version deprecation warnings

### NIC & Dataplane Inspection
- XDP eBPF program detection, AF_XDP zero-copy socket detection
- DPDK binding / userspace driver detection
- SR-IOV VF/PF topology
- Per-queue IRQ affinity, CPU NUMA mapping
- Hardware offloads: checksum, TSO, LRO, RSS

### Connection & Route Tables
- TCP/UDP/UDP6/TCP6 connection state with PID → process name resolution
- IPv4 + IPv6 routing table from `/proc/net/route` and `/proc/net/ipv6_route`

### Live Capture & Stats
- Packet capture with BPF filter support
- Real-time bandwidth dashboard with per-protocol breakdown and top talkers
- DNS query decode inline in capture output
- Watch mode for continuous monitoring

---

## Installation

### RHEL / Rocky Linux / CentOS 9

```bash
sudo dnf install https://github.com/omnayak27199/pktana/releases/download/v0.1.0/pktana-0.1.0-1.el9.x86_64.rpm
```

`libpcap` is installed automatically as a dependency.

### Verify the RPM signature

```bash
rpm --checksig pktana-0.1.0-1.el9.x86_64.rpm
```

### Build from source

```bash
git clone https://github.com/omnayak27199/pktana
cd pktana
cargo build --release --features pcap
./target/release/pktana --version
```

---

## Usage

```bash
# Live packet capture
pktana capture eth0

# Deep packet inspection (hex input)
pktana inspect 450000...

# NIC information
pktana nic eth0

# Dataplane / XDP / DPDK
pktana dp eth0

# ethtool equivalent
pktana ethtool eth0

# Active connections (like ss -tulnp)
pktana conn

# Routing table (like ip route)
pktana route

# Live stats dashboard
pktana stats eth0

# Watch mode (refresh every N seconds)
pktana watch eth0 5

# Decode a hex packet file
pktana file packets.txt

# Full help
pktana help
pktana help <command>
```

---

## Architecture

```
pktana/
├── crates/
│   ├── pktana-core/        # Library: parser, DPI engine, NIC/route/conn inspection
│   │   └── src/
│   │       ├── dpi.rs      # L2–L7 deep packet inspection engine
│   │       ├── capture.rs  # Live capture (libpcap)
│   │       ├── nic.rs      # NIC info + XDP/DPDK/SR-IOV detection
│   │       ├── ethtool.rs  # Driver, offload, IRQ, queue info
│   │       ├── connections.rs  # TCP/UDP connection table
│   │       ├── routes.rs   # IPv4/IPv6 routing table
│   │       ├── parser.rs   # Ethernet frame parser
│   │       └── packet.rs   # Packet data model
│   └── pktana-cli/         # Binary: command dispatcher + output rendering
├── deploy/centos/          # RPM spec + install script
└── .github/workflows/      # CI: fmt, clippy, build, sign RPM, publish
```

See [docs/architecture.md](docs/architecture.md) for detailed design notes.

---

## Performance

- **Zero heap allocation** in the hot packet path
- **Memory safe** — written in Rust with no `unsafe` blocks in the core library
- Reads NIC/connection/route data directly from `sysfs`/`procfs` — no external commands
- Single static binary, minimal runtime footprint

---

## Embedding pktana-core in your project

```toml
[dependencies]
pktana-core = "0.1.0"
```

```rust
use pktana_core::inspect;

let pkt = inspect(&raw_bytes);
println!("{}", pkt.one_liner());
for diagnosis in pkt.diagnose() {
    println!("  {diagnosis}");
}
```

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
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

---

## License

Copyright 2026 Omprakash (omnayak27199@gmail.com)  
Licensed under the [Apache License 2.0](LICENSE).

