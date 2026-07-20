# Architecture & Internals

This page describes the internal design decisions, module interactions, and performance characteristics of pktana.

---

## Workspace Design

pktana is a Cargo workspace with two crates:

```
pktana-core  — pure library, no binary, minimal dependencies
pktana-cli   — thin binary wrapper, all CLI/TUI/web UI code
```

This separation means:
- `pktana-core` can be used as a library by other projects
- The CLI binary only pulls in `ratatui`/`crossterm` when the `tui` feature is enabled
- The web server code is entirely in `pktana-cli/web.rs` and never affects the library

---

## DPI Pipeline

```
Raw bytes (&[u8])
    │
    ▼
parse_ethernet()        → eth_src, eth_dst, ether_type
    │
    ├─ VLAN?   → strip tag(s), recurse
    ├─ ARP?    → parse_arp()
    └─ IPv4?   → parse_ipv4()
                    │
                    ├─ TCP  → parse_tcp() → parse_tcp_options()
                    │           └─ payload → detect_app_proto()
                    ├─ UDP  → parse_udp()
                    │           └─ payload → detect_app_proto()
                    └─ ICMP → parse_icmp()
                                    │
                    ┌───────────────┘
                    ▼
              detect_app_proto(port, data)
                    │
                    ├─ TLS (443, 8443) → detect_tls()
                    │                     ├─ ClientHello → extract JA3
                    │                     └─ ServerHello → negotiate
                    ├─ DNS (53)        → detect_dns()
                    ├─ DHCP (67/68)    → detect_dhcp()
                    ├─ HTTP (80, 8080) → detect_http()
                    ├─ SSH (22)        → detect_ssh()
                    └─ ... (40+ protocols)
                    │
                    ▼
              detect_anomalies()
              compute_risk_score()
```

The entire pipeline is a single function call with **no heap allocations in the hot path** for fields that can be stored inline. String fields are only allocated when a field is actually present.

---

## Capture Pipeline

```
LinuxCaptureEngine::capture_streaming(config, callback)
    │
    │  (pcap feature)
    ▼
pcap::Capture::from_device()
    → set_promiscuous()
    → set_snaplen()
    → set_filter() (BPF compiled by libpcap)
    → activate()
    │
    ▼  for each packet from pcap:
CapturePacket { timestamp_sec, timestamp_usec, data: Cow::Borrowed(&raw) }
    │
    └─► callback(pkt)  → user code, inspect(), etc.
```

`CapturePacket.data` is a `Cow<[u8]>` — it borrows from the pcap buffer for zero-copy access. `into_owned()` converts to an owned `Vec<u8>` when the packet needs to outlive the buffer.

---

## Multi-Session State (Web Server)

The web server maintains a global `DashMap<String, CaptureSession>`:

```rust
lazy_static! {
    static ref SESSIONS: DashMap<String, CaptureSession> = DashMap::new();
    static ref PROCESS_MAP: DashMap<SocketId, ProcessInfo> = DashMap::new();
}
```

`DashMap` is a sharded concurrent HashMap — no global lock for reads or writes on different keys. This means multiple sessions (one per interface) can capture simultaneously without blocking each other.

Each `CaptureSession` tracks:
- Session ID (UUID-like string)
- Interface name
- BPF filter
- Status (Active / Stopped / Paused)
- Packet count and bytes captured

---

## Web Server Architecture

pktana implements a minimal HTTP/1.1 server from scratch — no framework (no Actix, no Axum, no Tokio). Each incoming connection is handled by a new OS thread:

```
TcpListener::bind(port)
    │
    └─ for each TcpStream:
           std::thread::spawn(|| handle_client(stream))
```

The `handle_client` function reads the HTTP request (up to 8192 bytes), matches on the request line, and dispatches to the appropriate handler.

### SSE (Server-Sent Events)

Live packet streaming uses SSE because:
- No WebSocket upgrade negotiation needed
- Works through proxies and load balancers
- Browser EventSource API auto-reconnects
- One-directional (server → client) is all that's needed

The SSE handler pattern:
```
1. Write HTTP/1.1 200 OK + SSE headers
2. Clone the TcpStream (write half)
3. Start capture in the same thread
4. For each packet: format JSON → write_all() → check for disconnect
5. On disconnect: mark session Stopped
```

The write socket is cloned (`try_clone()`). If the client disconnects, `write_all()` returns an error, and the capture loop exits.

---

## JavaScript Architecture (Web UI)

The entire frontend is a single-file HTML/JS/CSS application (~3700 lines) served directly from the Rust binary. No build step, no npm, no bundler.

### Multi-Session State

Each open interface window is a `Sessions[id]` object:
```javascript
Sessions[id] = {
    id, iface, isOffline,
    status: 'active',
    packetStore: [],     // up to 10,000 packets
    flows: {},
    protoStats: {},
    talkerStats: {},
    geoCache: {},
    packetCount: 0,
    byteCount: 0,
    baseTs: null,
    eventSource: null,
    autoScroll: true,
    paused: false
}
```

`activeId` is the currently visible session. Legacy globals (`packetStore`, `flows`, etc.) are mirrors of the active session's state.

### Batch Rendering

Packets arrive from SSE at high rate. Instead of updating the DOM on every packet:

```javascript
// Each SSE message pushes to a buffer:
packetBuffer.push(parsedData);

// A 100ms timer drains the buffer in batches:
setInterval(() => {
    if (!isPaused) processPendingPackets();
}, 100);
```

This prevents DOM thrashing at high packet rates (100k+ pps) and keeps the UI responsive.

### Memory Management

The DOM table is capped at `MAX_PACKETS_IN_MEMORY = 10000` rows:
```javascript
while (tbody.children.length > MAX_PACKETS_IN_MEMORY)
    tbody.removeChild(tbody.firstChild);
```

`packetStore` also holds the last 10,000 packets for on-click detail lookup.

---

## procfs / sysfs Readers

pktana reads Linux kernel interfaces directly — no external commands:

| Data | Source |
|------|--------|
| TCP connections | `/proc/net/tcp`, `/proc/net/tcp6` |
| UDP connections | `/proc/net/udp`, `/proc/net/udp6` |
| Routing table (IPv4) | `/proc/net/route` |
| Routing table (IPv6) | `/proc/net/ipv6_route` |
| Process names | `/proc/<pid>/comm` |
| Process command lines | `/proc/<pid>/cmdline` |
| Socket→PID mapping | `/proc/<pid>/fd/` → `/proc/<pid>/net/` |
| NIC state | `/sys/class/net/<iface>/operstate` |
| NIC MAC | `/sys/class/net/<iface>/address` |
| NIC MTU | `/sys/class/net/<iface>/mtu` |
| NIC statistics | `/sys/class/net/<iface>/statistics/` |
| NIC speed | `/sys/class/net/<iface>/speed` |
| NIC driver | `/sys/bus/pci/drivers/` / `/sys/class/net/<iface>/device/driver/` |
| XDP programs | `/sys/class/net/<iface>/xdp_bpf_progs/` |
| Kernel version | `/proc/version` |
| System uptime | `/proc/uptime` |
| Memory info | `/proc/meminfo` |
| Hostname | `/proc/sys/kernel/hostname` |

### IPv6 Address Byte Order

IPv6 addresses in `/proc/net/tcp6` and `/proc/net/ipv6_route` are stored as **4 groups of 4 bytes in little-endian order** (not a simple 16-byte big-endian). pktana reverses each 4-byte group independently:

```rust
for group in 0..4 {
    bytes[group * 4..group * 4 + 4].reverse();
}
```

This matches the kernel's `%pi6` format in procfs.

---

## GeoIP Engine

The GeoIP database is embedded in the binary at compile time using `include_bytes!()`. No network calls, no external files needed. The database is a custom binary format optimized for binary prefix search.

---

## Error Handling

pktana uses a custom `CliError` enum in the binary:

```rust
enum CliError {
    Parse(ParseError),
    Capture(CaptureError),
    Io(std::io::Error),
    Usage(String),
}
```

All `From` impls are provided so `?` works throughout. Errors are printed to stderr with ANSI color and the process exits with a non-zero code.

---

## Feature Flag Isolation

The `pcap` and `tui` features are carefully isolated:
- `pktana-core/src/capture.rs` guards all `pcap::` usage with `#[cfg(feature = "pcap")]`
- `pktana-cli/src/main.rs` guards TUI command routing with `#[cfg(feature = "tui")]`
- `pktana-cli/src/tui.rs` is only compiled with `tui` feature
- Without `pcap`, `LinuxCaptureEngine::capture_streaming()` returns `CaptureError::Unsupported`
- Without `tui`, the `tui` CLI command prints "TUI support not compiled in"
