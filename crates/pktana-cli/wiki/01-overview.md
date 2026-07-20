# Overview & Architecture

## What is pktana?

pktana is a **Linux-native network packet analyzer** built in Rust. It provides:

- **Zero external dependencies at runtime** — no libpcap required for most features; live capture optionally uses libpcap via a compile-time feature flag
- **Deep Packet Inspection (DPI)** — layer-by-layer dissection from Ethernet to L7 application protocols
- **Three interfaces** — CLI commands, TUI dashboard, and browser-based Web UI
- **Embedded library** — the `pktana-core` crate is a pure-Rust library usable in any Rust project
- **No kernel modules, no eBPF required** — reads from standard Linux procfs/sysfs

pktana replaces multiple tools:

| Traditional Tool | pktana Equivalent |
|---|---|
| `tcpdump -i eth0` | `pktana capture eth0` |
| `wireshark` | `pktana tui eth0` or `pktana web` |
| `ethtool eth0` | `pktana ethtool eth0` |
| `ss -tunap` | `pktana conn` |
| `ip route show` | `pktana route` |
| `iftop -i eth0` | `pktana stats eth0` |
| `watch -n1 ip -s link` | `pktana watch eth0` |

---

## Project Structure

```
pktana/                        # Cargo workspace root
├── crates/
│   ├── pktana-core/           # Library crate — pure Rust, no framework
│   │   └── src/
│   │       ├── lib.rs         # Public API re-exports
│   │       ├── dpi.rs         # Deep Packet Inspection engine (~2700 lines)
│   │       ├── flow_analyzer.rs  # Stateful flow analysis
│   │       ├── capture.rs     # Live/offline packet capture
│   │       ├── connections.rs # /proc/net/tcp* parser
│   │       ├── routes.rs      # /proc/net/route* parser
│   │       ├── nic.rs         # /sys/class/net/* parser
│   │       ├── ethtool.rs     # ethtool-equivalent sysfs reader
│   │       ├── process.rs     # /proc socket→PID mapper
│   │       ├── geoip.rs       # Embedded offline GeoIP
│   │       ├── flow.rs        # Passive flow table
│   │       ├── packet.rs      # Ethernet/IP/TCP header structs
│   │       ├── parser.rs      # Hex/bytes multi-frame parser
│   │       └── buffer_pool.rs # Zero-copy buffer pool
│   └── pktana-cli/            # Binary crate
│       └── src/
│           ├── main.rs        # CLI dispatcher + all command handlers
│           ├── tui.rs         # TUI dashboard (ratatui + crossterm)
│           └── web.rs         # Embedded HTTP + SSE server (~3700 lines)
├── wiki/                      # This documentation
└── docs/                      # Additional architecture documents
```

---

## Design Goals

### 1. Zero Runtime Dependencies
Most features work on any Linux system without installing anything. procfs and sysfs are the data sources for connections, routes, NIC info, and process mapping. The `pcap` crate (libpcap) is opt-in via a compile-time feature.

### 2. Pure Rust DPI
The DPI engine (`dpi.rs`) is a hand-written, allocation-minimal packet dissector. It handles 40+ protocols across all layers. No C bindings, no regex, no external parsers.

### 3. Three Interfaces for Three Use Cases
- **CLI** — scriptable, pipe-friendly, works over SSH
- **TUI** — interactive terminal analysis with keyboard navigation
- **Web UI** — full Wireshark-style multi-session interface accessible from any browser

### 4. Embeddable Library
`pktana-core` is published to crates.io and can be used as a library in any Rust project. See [Library API](09-library-api.md).

### 5. Memory Safety & Performance
- `DashMap` for lock-free concurrent session state
- `BufferPool` for zero-copy packet buffers in hot paths
- SSE (Server-Sent Events) for streaming packets to the browser without WebSocket overhead
- Batch rendering in the web UI (100ms timer) to avoid DOM thrashing at high packet rates

---

## High-Level Data Flow

```
Network Interface / pcap file
        │
        ▼
  LinuxCaptureEngine
  (capture.rs, pcap feature)
        │
        ▼
   CapturePacket { data: &[u8], timestamp }
        │
        ├──► inspect(&data)  →  DeepPacket      (dpi.rs)
        │         │
        │         ├──► FlowAnalyzer::analyze()   (flow_analyzer.rs)
        │         ├──► geoip_lookup()             (geoip.rs)
        │         ├──► build_socket_process_map() (process.rs)
        │         └──► risk scoring, anomalies
        │
        └──► Output
               ├── CLI: colored terminal output
               ├── TUI: ratatui widgets
               └── Web: JSON over SSE → browser
```

---

## Feature Flags

| Flag | Enables | Required for |
|------|---------|--------------|
| `pcap` | `pcap` crate (libpcap) | `capture`, `record`, `tui`, `web` live mode |
| `tui` | `ratatui` + `crossterm` | `pktana tui` command |
| `ai` | `reqwest`, `serde`, `serde_json` | AI analysis features (experimental) |

Default build has **no features** enabled. Most packages are built with `--features pcap,tui`.
