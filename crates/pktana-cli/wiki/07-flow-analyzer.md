# Flow Analyzer

The Flow Analyzer (`flow_analyzer.rs`) provides **stateful multi-packet protocol analysis**. Unlike the DPI engine which analyzes individual packets, the Flow Analyzer tracks state across packets to detect complete protocol sequences.

---

## Supported Analysis

| Protocol | What is tracked |
|----------|----------------|
| **TCP Handshake** | SYN → SYN+ACK → ACK sequence; RTT computation; retransmit detection |
| **TLS Handshake** | ClientHello → ServerHello → Certificate → Finished; SNI, JA3, cipher negotiation |
| **DHCP DORA** | Discover → Offer → Request → Ack; full lease timing (ms precision) |
| **DNS Transactions** | Query → Response matching by Transaction ID; latency, NXDOMAIN detection |

---

## Using the Flow Analyzer

```rust
use pktana_core::{FlowAnalyzer, inspect};

let mut analyzer = FlowAnalyzer::new();

// For each captured packet:
let dp = inspect(&raw_bytes);
let events: Vec<String> = analyzer.analyze_packet(&dp);

// events contains human-readable descriptions of completed or transitioning flows
for event in events {
    println!("{}", event);
}

// Get a summary at any time
let summary = analyzer.get_summary();
println!("TCP flows: {}, complete: {}", summary.total_tcp_flows, summary.complete_tcp_handshakes);
```

---

## `FlowId` — Bidirectional Flow Key

```rust
pub struct FlowId {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}
```

- `from_packet(dp: &DeepPacket) -> Option<FlowId>` — extract a flow key from a parsed packet
- `reverse(&self) -> FlowId` — get the reverse-direction key (for bidirectional matching)
- Implements `Hash` + `Eq` for use as `HashMap` key

---

## TCP Handshake Analysis

Tracks the three-way handshake (3WHS) and computes RTT.

### State Machine

```
Init
  │
  │  SYN received
  ▼
SynSent { seq, timestamp }
  │
  │  SYN+ACK received (ack == syn_seq+1)
  ▼
SynAckReceived { syn_seq, syn_ack_seq, timestamp }
  │
  │  ACK received (ack == syn_ack_seq+1)
  ▼
Established { timestamp, rtt_ms }   ← COMPLETE
  │
  │  RST or timeout
  ▼
Failed { reason }
```

### Output Events

| Event | Description |
|-------|-------------|
| `TCP SYN: 1.2.3.4:port → 5.6.7.8:80` | SYN observed |
| `TCP Handshake COMPLETE: ... RTT=2.4ms` | 3WHS complete with RTT |
| `TCP SYN Retransmit: ...` | Duplicate SYN detected |
| `TCP RST: ... (handshake failed)` | RST during handshake |

### `TcpHandshakeAnalysis` struct

```rust
pub struct TcpHandshakeAnalysis {
    pub state: TcpHandshakeState,
    pub complete: bool,
    pub syn_retransmits: u32,
    pub flags_observed: Vec<String>,
}
```

---

## TLS Handshake Analysis

Tracks TLS from ClientHello through the complete handshake.

### State Machine

```
Init
  │
  │  ClientHello (Record type 22, Handshake type 1)
  ▼
ClientHelloSent { version, sni, ciphers, alpn, ja3 }
  │
  │  ServerHello (Handshake type 2)
  ▼
ServerHelloReceived { negotiated_version, negotiated_cipher }
  │
  │  Certificate (Handshake type 11) — optional
  ▼
CertificateReceived { ... }
  │
  │  Finished (Handshake type 20)
  ▼
Complete { ... }   ← COMPLETE
```

### Output Events

| Event | Description |
|-------|-------------|
| `TLS ClientHello: SNI=example.com JA3=abc...` | ClientHello seen |
| `TLS 1.3 Handshake COMPLETE: SNI=example.com ALPN=h2` | Complete with version |
| `TLS Deprecated: TLS 1.1 in use — RFC 8996` | Old version warning |

---

## DHCP DORA Analysis

Tracks the full DHCP lease acquisition sequence.

### State Machine

```
Init
  │
  │  DHCP Discover (broadcast, message type 1)
  ▼
DiscoverSent { client_mac, timestamp }
  │
  │  DHCP Offer (message type 2)
  ▼
OfferReceived { offered_ip }
  │
  │  DHCP Request (message type 3)
  ▼
RequestSent { requested_ip }
  │
  │  DHCP Ack (message type 5)
  ▼
Complete { assigned_ip, lease_secs, total_ms }   ← COMPLETE
  │
  │  DHCP Nak (message type 6)
  ▼
Failed { reason }
```

### Output Events

| Event | Description |
|-------|-------------|
| `DHCP Discover: client MAC aa:bb:cc:dd:ee:ff` | Discover packet |
| `DHCP Offer: 192.168.1.50 offered to client` | Offer packet |
| `DHCP DORA COMPLETE: 192.168.1.50 assigned. Lease=86400s Total=12.3ms` | Full DORA done |
| `DHCP Nak: server rejected request` | Failure case |

**Total DORA time** is measured from Discover to Ack with millisecond precision using packet timestamps.

---

## DNS Transaction Analysis

Matches DNS queries and responses using Transaction ID (16-bit field in DNS header).

### State Machine

```
Init
  │
  │  DNS Query (QR=0)
  ▼
QuerySent { txid, name, qtype, timestamp }
  │
  │  DNS Response (QR=1, same txid)
  ▼
Complete { name, rcode, answers, rtt_ms }   ← COMPLETE
  │
  │  Timeout (no response)
  ▼
Timeout
```

### Output Events

| Event | Description |
|-------|-------------|
| `DNS Query: example.com (A)` | Query detected |
| `DNS Response: example.com → 93.184.216.34 NOERROR RTT=8ms` | Response matched |
| `DNS NXDOMAIN: nonexistent.example.com` | Domain not found |
| `DNS High Entropy: xkd93nf8.example.com (entropy=4.2) — DGA suspected` | DGA warning |

---

## `FlowAnalyzerSummary`

```rust
pub struct FlowAnalyzerSummary {
    pub total_tcp_flows: usize,
    pub complete_tcp_handshakes: usize,
    pub failed_tcp_handshakes: usize,
    pub syn_retransmits: usize,
    pub total_tls_flows: usize,
    pub complete_tls_handshakes: usize,
    pub total_dhcp_flows: usize,
    pub complete_dhcp_dora: usize,
    pub failed_dhcp: usize,
    pub total_dns_transactions: usize,
    pub resolved_dns: usize,
    pub nxdomain_count: usize,
    pub dga_suspected: usize,
}
```

---

## Flow Analysis in the CLI

```bash
# capture command with flow analysis output interspersed
sudo pktana capture eth0 --analyze
```

## Flow Analysis in the TUI

Press `a` to toggle flow analysis mode. Events appear in the status bar as they are detected.

## Flow Analysis in the Web UI

Live capture always runs with `flow_analyze=true`. Flow events appear in:
- The **Flows** panel (per-session flow table)
- Status bar notifications in the Packets panel
