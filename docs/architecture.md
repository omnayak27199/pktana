# pktana Architecture

## Overview

`pktana` is a Linux-native enterprise packet analysis platform — a single Rust binary (and RPM) that combines deep packet inspection, live capture, flow analysis, NIC telemetry, connection tracking, routing visibility, and a Wireshark-like TUI.

## Crate layout

The workspace is split into two crates:

```
pktana/
├── crates/
│   ├── pktana-core/            # Library crate
│   │   └── src/
│   │       ├── dpi.rs          # L2–L7 DPI engine (see below)
│   │       ├── capture.rs      # Live capture (libpcap feature-gate)
│   │       ├── nic.rs          # NIC info + XDP/DPDK/SR-IOV/AF_XDP detection
│   │       ├── ethtool.rs      # Driver, offload, IRQ, queue, PCIe info
│   │       ├── connections.rs  # TCP/UDP connection table (procfs)
│   │       ├── routes.rs       # IPv4/IPv6 routing table (procfs)
│   │       ├── geoip.rs        # Offline GeoIP lookup (embedded dataset)
│   │       ├── process.rs      # PID → process name resolution
│   │       ├── flow.rs         # Flow key + aggregation
│   │       ├── parser.rs       # Ethernet frame parser (PacketSummary)
│   │       └── packet.rs       # Packet data model (PacketSummary, TransportHeader)
│   └── pktana-cli/             # Binary crate
│       └── src/
│           ├── main.rs         # All CLI commands + DPI display helpers
│           └── tui.rs          # Wireshark-like TUI (ratatui + crossterm)
└── deploy/centos/              # RPM spec + install script
```

---

## DPI Engine (`dpi.rs`)

The DPI engine is the core of pktana. It parses every byte of a raw frame from L2 to L7 in a single pass and populates a `DeepPacket` struct.

### Entry point

```rust
pub fn inspect(raw: &[u8]) -> DeepPacket
```

Called with raw frame bytes; returns a fully-decoded `DeepPacket`. No libpcap or external tools needed.

### Layer-by-layer pipeline

```
Raw bytes
  └─ Ethernet (src/dst MAC, OUI vendor, EtherType)
       ├─ VLAN / QinQ (802.1Q stack)
       ├─ ARP
       ├─ IPv4 → TCP / UDP / ICMP / GRE(→ inner frame)
       │    └─ Application: HTTP, TLS, DNS, DHCP, SSH, SIP, NTP, BGP,
       │                     SMTP, RDP, MySQL, Redis, SNMP, LDAP, …
       └─ IPv6 → (next header decode)
```

### `DeepPacket` struct — key fields

| Category | Fields |
|---|---|
| L2 Ethernet | `eth_src`, `eth_dst`, `eth_vendor_src/dst`, `vlan_tags`, `ether_type` |
| ARP | `arp` (operation, sender/target MAC+IP) |
| IPv4 | `ip_src/dst`, `ip_ttl`, `ip_proto`, `ip_dscp`, `ip_flag_df/mf`, `ip_fragment` |
| IPv6 | `ipv6_src/dst`, `ipv6_next_header`, `ipv6_hop_limit` |
| TCP | `tcp_src/dst_port`, `tcp_seq/ack`, `tcp_flags_str`, `tcp_window`, `tcp_mss`, `tcp_window_scale`, `tcp_sack_*`, `tcp_timestamp` |
| UDP | `udp_src/dst_port`, `udp_len`, `udp_checksum` |
| ICMP | `icmp_type`, `icmp_code`, `icmp_type_str`, `icmp_id`, `icmp_seq` |
| Application | `app_proto`, `app_detail` |
| TLS | `tls_ciphers`, `tls_alpn`, `tls_ja3_raw` |
| QUIC | `quic_detected`, `quic_version`, `quic_packet_type` |
| HTTP/2 | `http2_detected`, `grpc_path` |
| WebSocket | `ws_upgrade` |
| SSH | `ssh_banner` |
| SIP | `sip_method`, `sip_uri`, `sip_call_id` |
| NTP | `ntp_version`, `ntp_mode`, `ntp_stratum`, `ntp_amplification_risk` |
| BGP | `bgp_msg_type`, `bgp_asn` |
| DNS | `dns_query_name`, `dns_label_entropy` |
| Tunnel | `tunnel_type`, `inner_ip_src/dst`, `inner_proto`, `inner_src/dst_port`, `inner_app_proto` |
| Risk | `risk_score` (0–100), `risk_reasons`, `app_category` |
| Misc | `payload`, `anomalies`, `frame_len` |

### Notable DPI functions

| Function | Purpose |
|---|---|
| `parse_tls_client_hello()` | Full TLS ClientHello: JA3 raw string, ALPN, cipher suites, curves, GREASE filter |
| `detect_quic()` | QUIC long/short header, version decode (RFC 9000/9369, gQUIC, drafts) |
| `detect_http2()` + `parse_h2_frames()` | PRI magic + H2 frame parsing |
| `hpack_find_literal()` | Naive HPACK literal scan for `:path` / `content-type` (gRPC detection) |
| `detect_websocket()` | Upgrade header + WebSocket frame opcode |
| `detect_ssh_banner()` | SSH banner, SSHv1 detection |
| `detect_sip()` | SIP method/URI/Call-ID/From/To/UA |
| `detect_ntp_full()` | NTP version/mode/stratum + monlist amplification risk |
| `detect_bgp()` | BGP marker, message type, OPEN ASN + Router-ID |
| `parse_ipv6()` | IPv6 header decode |
| `inspect_vxlan_inner()` | VXLAN inner-frame re-inspection |
| `parse_gre()` + `inspect_gre_inner()` | GRE header + inner-frame re-inspection |
| `shannon_entropy()` | Shannon entropy for DNS label DGA/tunneling heuristic |
| `DeepPacket::compute_risk()` | 0-100 composite risk score |
| `DeepPacket::classify_app_category()` | Application category string |
| `DeepPacket::diagnose()` | Rule-based human-readable findings list |

### Content-sniffing order (TCP)

The engine content-sniffs before falling back to port-based dispatch:

1. HTTP/2 PRI magic (`50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30`)
2. WebSocket Upgrade header
3. SSH banner (`SSH-`)
4. BGP marker (`ff ff … ff`)
5. SIP methods (INVITE, BYE, REGISTER, …)
6. Port-based dispatch (TLS/443, HTTP/80, DNS/53, …)

---

## Capture layer (`capture.rs`)

- Feature-gated: `--features pcap`
- `LinuxCaptureEngine::capture_streaming()` — streaming callback API
- BPF filter string passed directly to libpcap
- PCAP export optional

---

## CLI layer (`main.rs`)

All commands share a set of DPI display helpers:

| Helper | Purpose |
|---|---|
| `dp_proto_label()` | App-layer-aware protocol label (QUIC, HTTP2, TLS, SSH, …) |
| `dp_proto_color()` | Wraps label with ANSI color codes per protocol |
| `dp_src_str()` / `dp_dst_str()` | `ip:port` or IPv6 or MAC from DeepPacket |
| `dp_info_str()` | Rich Info column: SNI, ALPN, HTTP method, DNS name, SIP method, BGP, NTP, QUIC |
| `print_deep_packet()` | Full inspect output: 15+ sections including risk bar and JA3 |

---

## TUI layer (`tui.rs`)

Built on **ratatui** + **crossterm**:

- 5-tab layout: Overview, Packets, Flows, Stats, Help
- Detail popup: Original (one-liner) / Layers (DPI fields) / Hex (payload dump)
- `dpi_lines()` renders all `DeepPacket` fields including new v0.3.0 additions
- Real-time bandwidth sparkline, GeoIP top-talker table

---

## NIC & Dataplane (`nic.rs`, `ethtool.rs`)

All data read from sysfs/procfs — no subprocess calls:

| Data | Source |
|---|---|
| Interface state, MAC, MTU, speed | `/sys/class/net/<iface>/` |
| RX/TX counters | `/sys/class/net/<iface>/statistics/` |
| Driver, firmware, IRQ | `/sys/bus/pci/devices/<addr>/` |
| XDP prog IDs | `/sys/class/net/<iface>/xdp/prog_ids` |
| AF_XDP sockets | `/proc/net/xdp` |
| DPDK binding | `/sys/bus/pci/drivers/vfio-pci/` |
| SR-IOV VF count | `/sys/class/net/<iface>/device/sriov_*` |
| PCIe link speed/width | `/sys/bus/pci/devices/<addr>/link*/` |
| IRQ CPU affinity | `/proc/irq/<n>/smp_affinity` |
| Hardware features | `/sys/class/net/<iface>/features/` |
| Extended statistics | `/sys/class/net/<iface>/statistics/` (driver-specific) |

---

## Why Rust

- Memory safety for hostile packet inputs — no buffer overruns in the parser
- Predictable, low-latency performance — no GC pauses
- Zero external runtime dependencies on customer machines (Rust/Cargo are build-time only)
- Single compiled binary — easy to distribute as an RPM

---

## Distribution

- Build: `make pktana` — runs `cargo fmt`, `clippy -D warnings`, `cargo test`, then `rpmbuild`
- RPM installs to `/usr/bin/pktana` with `Requires: libpcap >= 1.5`
- Signed RPM for RHEL 9 / Rocky Linux 9 / AlmaLinux 9 / CentOS Stream 9
- CI: GitHub Actions — fmt → clippy → build → sign → publish release asset

## MVP design

The current scaffold is split into two crates.

### `pktana-core`

Responsibilities:

- raw frame decoding
- protocol parsing
- packet summary generation
- flow key construction
- flow aggregation
- future parser and capture abstractions

### `pktana-cli`

Responsibilities:

- user input handling
- batch analysis workflows
- demo mode
- rendering summaries and flow statistics

## Planned module evolution

### Capture layer

Future Linux capture modes:

- `libpcap` feature-gated MVP path
- `AF_PACKET`
- `eBPF`
- `XDP`

Current implementation details:

- `LinuxCaptureEngine::list_interfaces()` for discovery
- `LinuxCaptureEngine::capture()` for bounded live ingestion
- optional BPF filter string passed to `pcap`
- decoded frames are fed into the same parser pipeline as file/hex inputs

Deployment implication:

- current `pcap` mode is useful for fast iteration
- enterprise Linux distribution should move to native `AF_PACKET` capture for fewer runtime dependencies on CentOS/RHEL systems
- Rust/Cargo are build-time tools only and should not be required on customer machines

### Parsing layer

Current:

- Ethernet
- IPv4
- TCP
- UDP

Future:

- IPv6
- ICMP
- ARP
- DNS
- TLS
- HTTP
- VXLAN
- GRE

### Flow engine

Current:

- flow key generation from parsed IPv4/TCP/UDP packets
- packet and byte counters

Future:

- TCP stream reassembly
- timeouts
- session state
- anomaly signals

### Storage and control plane

Planned later:

- indexed flow store
- search API
- role-based access control
- distributed sensors
- central management

## Why Rust

- memory safety for hostile packet inputs
- predictable performance
- good fit for concurrent packet pipelines
- suitable for Linux systems programming
- lets us ship a single compiled binary instead of a source-runtime environment

## Distribution strategy

Recommended production distribution for CentOS:

- build release binaries in CI or a controlled Linux builder
- package as tar.gz and RPM
- install to `/usr/local/bin/pktana` or `/usr/bin/pktana`
- avoid requiring Rust, Cargo, or developer headers on customer systems

Suggested packaging pipeline:

- build `pktana` release binary on a CentOS-compatible builder
- create source tarball with binary and docs
- build RPM with `rpmbuild`
- publish RPM to internal repo or artifact storage
