# pktana

**A high-performance, zero-dependency network inspection toolkit for Linux — written in Rust.**

> Replaces `tcpdump`, `ethtool`, `ss`, `ip route`, and `iftop` with a single binary.  
> Built for production infrastructure, network security, and cloud-native environments.

[![CI](https://github.com/omnayak27199/pktana/actions/workflows/ci.yml/badge.svg)](https://github.com/omnayak27199/pktana/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](https://github.com/omnayak27199/pktana/releases/tag/v0.1.0)
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

