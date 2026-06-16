# Library API — pktana-core

`pktana-core` is published to crates.io as a standalone library crate. You can embed it in any Rust project to gain packet inspection, connection listing, routing table access, and GeoIP lookup without writing any system code.

---

## Adding to your project

```toml
[dependencies]
pktana-core = "0.5.0"

# For live packet capture:
pktana-core = { version = "0.5.0", features = ["pcap"] }
```

---

## Core: DPI

```rust
use pktana_core::{inspect, DeepPacket};

let raw: &[u8] = &[/* raw Ethernet frame bytes */];
let dp: DeepPacket = inspect(raw);

// Access parsed fields:
println!("src={:?} dst={:?} proto={:?}", dp.ip_src, dp.ip_dst, dp.app_proto);
println!("risk={} anomalies={:?}", dp.risk_score, dp.anomalies);

// One-liner summary
println!("{}", dp.one_liner());

// Full detail text
for line in &dp.app_detail {
    println!("{}", line);
}
```

### `DeepPacket` key methods

| Method | Returns | Description |
|--------|---------|-------------|
| `one_liner()` | `String` | Short protocol summary (used in packet tables) |
| `full_detail()` | `String` | Complete layer-by-layer decode text |

---

## Core: Hex Dump

```rust
use pktana_core::hex_dump;

let data: &[u8] = &[0x45, 0x00, 0x00, 0x28, /* ... */];
let lines: Vec<String> = hex_dump(data, 64); // first 64 bytes
for line in &lines {
    println!("{}", line);
}
```

Output format: `  0000  45 00 00 28 ...  |E..(...|`

---

## Capture

```rust
use pktana_core::{LinuxCaptureEngine, CaptureConfig, CapturePacket};

// List interfaces
let ifaces = LinuxCaptureEngine::list_interfaces().unwrap();
for iface in &ifaces {
    println!("{}: {:?}", iface.name, iface.addresses);
}

// Live capture (requires pcap feature + root)
let config = CaptureConfig {
    interface: "eth0".to_string(),
    promiscuous: true,
    snapshot_len: 65_535,
    filter: Some("tcp port 443".to_string()),
    max_packets: 100,
    pcap_export: None,
};

LinuxCaptureEngine::capture_streaming(&config, |pkt: CapturePacket<'_>| {
    let dp = inspect(&pkt.data);
    println!("[{}] {} → {} ({})", pkt.timestamp_sec, dp.eth_src, dp.eth_dst, dp.app_proto.as_deref().unwrap_or("?"));
    true // return false to stop capture
}).unwrap();
```

### `CaptureConfig` fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interface` | `String` | `"eth0"` | Interface name |
| `promiscuous` | `bool` | `true` | Promiscuous mode |
| `snapshot_len` | `i32` | `65535` | Max bytes per packet |
| `filter` | `Option<String>` | `None` | BPF filter expression |
| `max_packets` | `usize` | `10` | Stop after this many packets |
| `pcap_export` | `Option<String>` | `None` | Path to save pcap file |

### Read from pcap file

```rust
LinuxCaptureEngine::read_pcap_file("/tmp/capture.pcap", |pkt| {
    let dp = inspect(&pkt.data);
    println!("{}", dp.one_liner());
    true
}).unwrap();
```

---

## Flow Analyzer

```rust
use pktana_core::{FlowAnalyzer, inspect};

let mut analyzer = FlowAnalyzer::new();

// Process packets one by one
let dp = inspect(&raw_bytes);
let events: Vec<String> = analyzer.analyze_packet(&dp);
for event in events {
    println!("Flow event: {}", event);
}

// Get overall summary
let summary = analyzer.get_summary();
println!("TCP: {}/{} complete", summary.complete_tcp_handshakes, summary.total_tcp_flows);
println!("DNS: {} resolved, {} NXDOMAIN", summary.resolved_dns, summary.nxdomain_count);
```

---

## Active Connections

```rust
use pktana_core::{list_connections, Connection};

let connections: Vec<Connection> = list_connections();
for c in &connections {
    println!("{} {}:{} → {}:{} [{}] PID={:?} {}",
        c.proto, c.local_ip, c.local_port,
        c.remote_ip, c.remote_port,
        c.state, c.pid, c.process.as_deref().unwrap_or("")
    );
}
```

### `Connection` fields

| Field | Type | Description |
|-------|------|-------------|
| `proto` | `&'static str` | `"tcp"` or `"udp"` |
| `local_ip` | `String` | Local IP address |
| `local_port` | `u16` | Local port |
| `remote_ip` | `String` | Remote IP address |
| `remote_port` | `u16` | Remote port |
| `state` | `&'static str` | `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, etc. |
| `pid` | `Option<u32>` | Process ID (if found) |
| `process` | `Option<String>` | Process name (if found) |

---

## Routing Table

```rust
use pktana_core::{list_routes, routes_for_iface, RouteEntry};

// All routes (IPv4 + IPv6)
let routes: Vec<RouteEntry> = list_routes();
for r in &routes {
    println!("{} via {} dev {} metric {}",
        r.destination, r.gateway, r.interface, r.metric
    );
}

// Routes for a specific interface
let eth0_routes = routes_for_iface("eth0");
```

### `RouteEntry` fields

| Field | Type | Description |
|-------|------|-------------|
| `interface` | `String` | Interface name |
| `destination` | `String` | Destination network |
| `prefix_len` | `u8` | Prefix length (CIDR) |
| `gateway` | `String` | Next-hop gateway (`0.0.0.0` = direct) |
| `metric` | `u32` | Route metric |
| `summary` | `String` | Human-readable summary line |
| `is_default` | `bool` | `true` for the default route |

---

## NIC Information

```rust
use pktana_core::{get_nic_info, list_nics, NicInfo, get_nic_dataplane, NicDataplane};

// All NICs
let nics = list_nics();

// Single NIC
let info: NicInfo = get_nic_info("eth0");
println!("eth0: {} state={} speed={:?}Mbps rx={}B tx={}B",
    info.mac, info.state, info.speed_mbps, info.rx_bytes, info.tx_bytes
);

// Dataplane detection
let dp: NicDataplane = get_nic_dataplane("eth0");
println!("bypass mode: {}", dp.bypass_mode);
```

### `NicInfo` key fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Interface name |
| `state` | `String` | `up`, `down`, `dormant`, `unknown` |
| `mac` | `String` | MAC address |
| `mtu` | `u32` | MTU in bytes |
| `speed_mbps` | `Option<u32>` | Link speed (from sysfs) |
| `duplex` | `Option<String>` | `full`, `half` |
| `driver` | `Option<String>` | Kernel driver name |
| `ip_addresses` | `Vec<String>` | All IP addresses with prefix |
| `rx_bytes` | `u64` | Bytes received |
| `tx_bytes` | `u64` | Bytes transmitted |
| `rx_packets` | `u64` | Packets received |
| `tx_packets` | `u64` | Packets transmitted |
| `rx_errors` | `u64` | RX errors |
| `tx_errors` | `u64` | TX errors |
| `rx_dropped` | `u64` | RX dropped |
| `tx_dropped` | `u64` | TX dropped |

---

## GeoIP

```rust
use pktana_core::{geoip_lookup, geoip_lookup_str, GeoInfo};

// By IpAddr
use std::net::IpAddr;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
let info: GeoInfo = geoip_lookup(ip);
println!("{}: {} ({})", info.ip, info.country_name, info.country_code);

// By string
let info2 = geoip_lookup_str("1.1.1.1");
println!("continent: {}", info2.continent);
```

### `GeoInfo` fields

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `String` | Input IP address |
| `country_name` | `String` | Full country name |
| `country_code` | `String` | ISO 3166-1 alpha-2 code, `"--"` for unknown |
| `continent` | `String` | Continent name |

---

## Process-to-Socket Mapping

```rust
use pktana_core::{build_socket_process_map, lookup_process, ProcessInfo, SocketId};
use std::net::{IpAddr, Ipv4Addr};

// Build the full process map (scans /proc)
let map = build_socket_process_map();

// Look up a specific socket
let socket_id = SocketId::new(
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 52366,
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443,
);
if let Some(info) = map.get(&socket_id) {
    println!("PID {} ({}): {}", info.pid, info.name, info.cmdline);
}
```

---

## Ethtool

```rust
use pktana_core::{get_ethtool_report, EthtoolReport};

let report: EthtoolReport = get_ethtool_report("eth0");
println!("driver: {} speed: {:?}Mbps", report.driver, report.speed_mbps);
for queue_irq in &report.queues {
    println!("queue {:?}: irq {:?}", queue_irq.queue, queue_irq.irq);
}
```

---

## Packet Parser (Batch)

```rust
use pktana_core::{analyze_bytes, analyze_hex, analyze_hex_file, build_flow_table};

// Parse a raw Ethernet frame
let parsed = analyze_bytes(&raw_bytes);

// Parse from hex string
let parsed = analyze_hex("ffffffffffff001122334455...").unwrap();

// Parse multiple frames from a hex file
let (packets, errors) = analyze_hex_file("/tmp/frames.hex").unwrap();

// Build a passive flow table from a packet list
let flow_table = build_flow_table(&packets);
for (key, record) in &flow_table {
    println!("{:?}: {} packets, {} bytes", key, record.packet_count, record.byte_count);
}
```

---

## Buffer Pool

For high-performance applications that need to minimize allocations:

```rust
use pktana_core::{BufferPool, PacketBuffer};

let pool = BufferPool::new(32, 65536); // 32 buffers of 64KB each

let mut buf: PacketBuffer = pool.acquire();
// fill buf with packet bytes
let dp = inspect(&buf);
pool.release(buf); // return to pool
```
