# DPI Engine

The Deep Packet Inspection engine (`dpi.rs`) is the core of pktana. It is a pure-Rust, zero-allocation-hot-path packet dissector that performs layer-by-layer protocol analysis on raw Ethernet frames.

---

## Entry Point

```rust
use pktana_core::inspect;

let raw_bytes: &[u8] = /* raw Ethernet frame */;
let dp: DeepPacket = inspect(raw_bytes);
```

That single call traverses all layers and returns a `DeepPacket` struct with every parsed field.

---

## `DeepPacket` Struct

`DeepPacket` contains all parsed data from a single packet, organized by layer. All fields are populated in a single pass — there is no lazy evaluation.

### Layer 2 — Ethernet

| Field | Type | Byte Offset | Description |
|-------|------|-------------|-------------|
| `frame_len` | `usize` | — | Total frame length in bytes |
| `eth_src` | `String` | 6..12 | Source MAC address (`aa:bb:cc:dd:ee:ff`) |
| `eth_dst` | `String` | 0..6 | Destination MAC address |
| `eth_vendor_src` | `Option<String>` | — | OUI vendor lookup for source MAC (first 3 bytes) |
| `eth_vendor_dst` | `Option<String>` | — | OUI vendor lookup for dest MAC (first 3 bytes) |
| `vlan_tags` | `Vec<VlanTag>` | 12.. | 802.1Q/QinQ VLAN tag stack (each tag is 4 bytes) |
| `ether_type` | `u16` | 12..14 | EtherType value (after any VLAN tags) |
| `ether_type_name` | `Option<String>` | — | Human-readable EtherType name |
| `arp` | `Option<ArpDetail>` | 14.. | ARP fields (if EtherType == 0x0806) |

**EtherType dispatch table**:

| EtherType | Value | Action |
|-----------|-------|--------|
| IPv4 | `0x0800` | Parse IPv4 header at offset 14 |
| IPv6 | `0x86DD` | Parse IPv6 header at offset 14 |
| ARP | `0x0806` | Parse ARP at offset 14 |
| 802.1Q VLAN | `0x8100` | Read 4-byte tag, recurse with inner EtherType |
| 802.1ad QinQ | `0x88A8` | Read 4-byte outer tag, recurse |

### Layer 3 — IPv4

The IPv4 header starts at byte offset 14 (after Ethernet header, assuming no VLAN tags).

| Field | Type | IPv4 Offset | Description |
|-------|------|-------------|-------------|
| `ip_version` | `Option<u8>` | 0 (bits 7-4) | IP version (4 or 6) |
| `ip_hdr_len` | `Option<u8>` | 0 (bits 3-0) | Header length in 32-bit words × 4 = bytes (min 20) |
| `ip_dscp` | `Option<u8>` | 1 (bits 7-2) | Differentiated Services Code Point |
| `ip_ecn` | `Option<u8>` | 1 (bits 1-0) | Explicit Congestion Notification |
| `ip_total_len` | `Option<u16>` | 2..4 | Total IP packet length including header |
| `ip_id` | `Option<u16>` | 4..6 | Identification field (used for fragmentation) |
| `ip_flag_df` | `bool` | 6 bit 6 | Don't Fragment flag |
| `ip_flag_mf` | `bool` | 6 bit 5 | More Fragments flag |
| `ip_fragment` | `bool` | 6..8 | True if fragment offset > 0 |
| `ip_ttl` | `Option<u8>` | 8 | Time-to-Live |
| `ip_proto` | `Option<u8>` | 9 | Protocol number (6=TCP, 17=UDP, 1=ICMP, 47=GRE) |
| `ip_proto_name` | `Option<String>` | — | Protocol name |
| `ip_src` | `Option<Ipv4Addr>` | 12..16 | Source IPv4 address |
| `ip_dst` | `Option<Ipv4Addr>` | 16..20 | Destination IPv4 address |

IPv6 addresses are stored separately:

| Field | Type | IPv6 Offset | Description |
|-------|------|-------------|-------------|
| `ipv6_src` | `Option<Ipv6Addr>` | 8..24 | Source IPv6 address |
| `ipv6_dst` | `Option<Ipv6Addr>` | 24..40 | Destination IPv6 address |

### Layer 4 — TCP

The TCP header starts at `ip_hdr_len` bytes past the IP header start.

| Field | Type | TCP Offset | Description |
|-------|------|------------|-------------|
| `tcp_src_port` | `Option<u16>` | 0..2 | Source port |
| `tcp_dst_port` | `Option<u16>` | 2..4 | Destination port |
| `tcp_seq` | `Option<u32>` | 4..8 | Sequence number |
| `tcp_ack` | `Option<u32>` | 8..12 | Acknowledgement number |
| `tcp_hdr_len` | `Option<u8>` | 12 (bits 7-4) | Header length in 32-bit words × 4 = bytes (min 20) |
| `tcp_flags` | `Option<u16>` | 12..14 | Raw TCP flags bitmap (lower 9 bits) |
| `tcp_flags_str` | `Option<String>` | — | Human flags: `SYN`, `SYN+ACK`, `RST+ACK`, etc. |
| `tcp_window` | `Option<u16>` | 14..16 | Receive window size |
| `tcp_urgent` | `Option<u16>` | 18..20 | Urgent pointer (valid only when URG flag set) |
| `tcp_payload_len` | `Option<usize>` | — | TCP payload = total_len − ip_hdr_len − tcp_hdr_len |
| `tcp_mss` | `Option<u16>` | options | Maximum Segment Size option (kind=2) |
| `tcp_window_scale` | `Option<u8>` | options | Window scale option (kind=3) |
| `tcp_sack_permitted` | `bool` | options | SACK permitted option (kind=4) |
| `tcp_sack_blocks` | `Vec<(u32, u32)>` | options | SACK block ranges (kind=5), up to 4 blocks |
| `tcp_timestamp` | `Option<(u32, u32)>` | options | TCP timestamp option (kind=8): TSval, TSecr |

**TCP flag bit positions** (low byte of the 16-bit flags field):

| Bit | Flag | Meaning |
|-----|------|---------|
| 0 | FIN | No more data from sender |
| 1 | SYN | Synchronize sequence numbers |
| 2 | RST | Reset the connection |
| 3 | PSH | Push buffered data |
| 4 | ACK | Acknowledgement field significant |
| 5 | URG | Urgent pointer field significant |
| 6 | ECE | ECN-Echo |
| 7 | CWR | Congestion Window Reduced |
| 8 | NS | Nonce sum (experimental) |

### Layer 4 — UDP

| Field | Type | UDP Offset | Description |
|-------|------|------------|-------------|
| `udp_src_port` | `Option<u16>` | 0..2 | Source port |
| `udp_dst_port` | `Option<u16>` | 2..4 | Destination port |
| `udp_len` | `Option<u16>` | 4..6 | UDP length (header + payload) |
| `udp_checksum` | `Option<u16>` | 6..8 | UDP checksum |
| `udp_payload_len` | `Option<usize>` | — | `udp_len - 8` |

### Layer 4 — ICMP

| Field | Type | ICMP Offset | Description |
|-------|------|-------------|-------------|
| `icmp_type` | `Option<u8>` | 0 | ICMP type code |
| `icmp_code` | `Option<u8>` | 1 | ICMP code |
| `icmp_checksum` | `Option<u16>` | 2..4 | ICMP checksum |
| `icmp_id` | `Option<u16>` | 4..6 | Identifier (Echo Request/Reply only) |
| `icmp_seq` | `Option<u16>` | 6..8 | Sequence number (Echo Request/Reply only) |
| `icmp_type_str` | `Option<String>` | — | Human type: `Echo Request`, `Dest Unreachable`, `Redirect`, etc. |

### Layer 7 — Application

| Field | Type | Description |
|-------|------|-------------|
| `app_proto` | `Option<String>` | Detected application protocol (e.g. `"TLS"`, `"DNS"`, `"HTTP"`) |
| `app_detail` | `Vec<String>` | Detailed protocol lines for display (one entry per field) |
| `app_category` | `Option<String>` | Traffic category bucket |

### TLS Enhanced Fields

| Field | Type | Description |
|-------|------|-------------|
| `tls_version` | `Option<String>` | Negotiated TLS version string (e.g. `"TLS 1.3"`) |
| `tls_sni` | `Option<String>` | Server Name Indication from ClientHello |
| `tls_session_id` | `Option<String>` | Session ID hex string |
| `tls_ciphers` | `Vec<u16>` | Offered cipher suite IDs (ClientHello) |
| `tls_cipher_names` | `Vec<String>` | Human-readable cipher suite names |
| `tls_alpn` | `Vec<String>` | ALPN protocol names (e.g. `["h2", "http/1.1"]`) |
| `tls_ja3_raw` | `Option<String>` | JA3 fingerprint input string (before MD5) |
| `tls_ja3` | `Option<String>` | JA3 MD5 fingerprint hash (32 hex chars) |

### Detection Flags

| Field | Type | Description |
|-------|------|-------------|
| `quic_detected` | `bool` | QUIC/HTTP3 detected (UDP 443 with QUIC long header) |
| `http2_detected` | `bool` | HTTP/2 detected (`PRI * HTTP/2.0` preface) |

### Risk & Anomalies

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | `u8` | Composite risk score 0–100 |
| `risk_reasons` | `Vec<String>` | Human-readable reasons contributing to risk score |
| `anomalies` | `Vec<String>` | Protocol anomalies detected (e.g. `"SYN+FIN"`, `"DGA suspected"`) |

### Payload

| Field | Type | Description |
|-------|------|-------------|
| `payload` | `Vec<u8>` | Raw application payload bytes (first 256 bytes for display) |

---

## Dissection Pipeline

```
inspect(raw: &[u8]) → DeepPacket

 1. Ethernet header (bytes 0..14)
    ├── dst MAC: bytes 0..6
    ├── src MAC: bytes 6..12
    └── EtherType dispatch at bytes 12..14:
        ├── 0x8100 / 0x88A8  → read 4-byte VLAN tag, recurse with inner EtherType
        ├── 0x0806           → ARP dissection (28 bytes)
        ├── 0x0800           → IPv4 (header at byte 14)
        └── 0x86DD           → IPv6 (fixed 40-byte header at byte 14)

 2. IPv4 header (starts at byte 14)
    ├── ihl = byte[14] & 0x0F  → header length = ihl * 4
    └── Protocol dispatch at byte[23]:
        ├── 6  → TCP header at byte (14 + ihl*4)
        ├── 17 → UDP header at byte (14 + ihl*4)
        ├── 1  → ICMP header at byte (14 + ihl*4)
        └── 47 → GRE header → inner Ethernet re-inspect

 3. Application payload dispatch (port-based + heuristic)
    ├── TCP 80/8080/3000/8000  → HTTP/1.x request/response parse
    ├── TCP 443/8443            → TLS record parse → ClientHello/ServerHello
    ├── UDP 443/8443 + QUIC hdr → QUIC/HTTP3
    ├── TCP 443 + HTTP2 preface → HTTP/2 + gRPC
    ├── UDP 53 / TCP 53         → DNS wire format parse
    ├── UDP 67/68               → DHCP options parse
    ├── TCP 22                  → SSH banner (first 255 bytes)
    ├── TCP 25/587/465          → SMTP banner/command parse
    ├── TCP/UDP 5060            → SIP header parse
    ├── UDP 123                 → NTP fixed 48-byte header
    ├── TCP 179                 → BGP fixed header + message type
    ├── TCP 3306                → MySQL greeting packet
    ├── TCP 5432                → PostgreSQL startup magic (0x00030000)
    ├── TCP 6379                → Redis RESP protocol (*N\r\n$M\r\n)
    ├── TCP 27017               → MongoDB OP_MSG / OP_QUERY wire
    ├── TCP/UDP 389             → LDAP BER encoding
    ├── TCP/UDP 88              → Kerberos ASN.1 tag
    ├── UDP 161/162             → SNMP BER encoding
    ├── UDP 500/4500            → IKE/IPsec SA payload
    ├── UDP 1900                → SSDP (HTTP-like over UDP)
    ├── TCP/UDP 514             → Syslog RFC 3164/5424
    ├── UDP 4789                → VXLAN (8-byte header) → inner Ethernet re-inspect
    └── UDP 6081                → Geneve (variable header) → inner Ethernet re-inspect

 4. Anomaly detection pass  (see Anomaly Detection section)
 5. Risk scoring pass        (see Risk Scoring section)
```

---

## Application Protocol Detection

### TLS / HTTPS

pktana fully decodes TLS ClientHello and ServerHello by reading the TLS record layer and handshake message:

**TLS record header** (5 bytes):
- Byte 0: Content type (0x16 = Handshake)
- Bytes 1..2: Legacy record version (0x0301 for TLS 1.x)
- Bytes 3..4: Record length

**Handshake message header** (4 bytes after record header):
- Byte 0: Handshake type (0x01 = ClientHello, 0x02 = ServerHello)
- Bytes 1..3: Message length (24-bit big-endian)

**ClientHello fields parsed** (starting at TLS offset 9):
- Bytes 0..1: Client version
- Bytes 2..33: Random (32 bytes)
- Byte 34: Session ID length, followed by session ID bytes
- Next 2 bytes: Cipher suites length, followed by cipher suite list (2 bytes each)
- Next byte: Compression methods length + methods
- Next 2 bytes: Extensions total length
- Extensions loop — each extension: 2-byte type, 2-byte length, data:
  - Type 0x0000 (SNI): server_name_list → parse hostname
  - Type 0x000A (supported_groups): elliptic curve IDs
  - Type 0x000B (ec_point_formats): point format list
  - Type 0x0010 (ALPN): protocol name list
  - Type 0x002B (supported_versions): TLS 1.3 advertised here

**JA3 fingerprint calculation** (step by step):

1. Collect: `SSLVersion` (client hello legacy version as decimal)
2. Collect: `Ciphers` — all offered cipher suite IDs as decimal, joined by `-`, **excluding** GREASE values (`0x?A?A` pattern where both nibbles match: `0x0A0A`, `0x1A1A`, `0x2A2A`, ..., `0xFAFA`)
3. Collect: `Extensions` — extension type IDs in order as decimal, joined by `-`, GREASE filtered
4. Collect: `EllipticCurves` — supported_groups extension values as decimal, joined by `-`, GREASE filtered
5. Collect: `EllipticCurvePointFormats` — ec_point_formats values as decimal, joined by `-`
6. Concatenate: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
7. Compute MD5 of that ASCII string → 32-character hex digest = JA3 fingerprint

**Example JA3 raw string**:
```
771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
```

**Example JA3 hash**: `cd08e31494f9531f560d64c695473da9`

GREASE filtering ensures the fingerprint is stable regardless of which GREASE placeholder values the client inserts.

### DNS

DNS wire format parsing (RFC 1035):

**DNS header** (12 bytes):
- Bytes 0..1: Transaction ID
- Bytes 2..3: Flags (QR bit, opcode, AA, TC, RD, RA, RCODE)
- Bytes 4..5: QDCOUNT (question count)
- Bytes 6..7: ANCOUNT (answer count)
- Bytes 8..9: NSCOUNT
- Bytes 10..11: ARCOUNT

**Domain name decoding**: Labels are length-prefixed sequences. A length byte of `0xC0` indicates a pointer (compression) — the next byte gives the offset from the start of the DNS payload to jump to.

**Shannon entropy formula** for DGA detection:

```
H(X) = -∑ p(c) × log₂(p(c))
```

Where `p(c)` is the frequency of character `c` in the domain label (excluding dots). Applied only to labels longer than 6 characters. Thresholds:

| Entropy | Flag |
|---------|------|
| > 3.5 bits/char | Potential DGA domain |
| Label length > 50 chars | Unusually long label |
| > 4 subdomains | Excessive subdomain depth |

**Example**: The DGA domain `x3f9q2p.evil.com` has label `x3f9q2p` with entropy ≈ 3.81 bits/char → flagged.

**Legitimate domain**: `google.com` has entropy ≈ 2.92 bits/char → not flagged.

### HTTP/1.x

Request line parsed as `METHOD SP Request-URI SP HTTP/version CRLF`. pktana reads:
- Method: up to 8 bytes before first space
- URI: between first and second space
- Version: after second space

Response status line: `HTTP/1.x SP status_code SP reason CRLF`

Headers parsed (case-insensitive first-match):
- `Host:`
- `User-Agent:`
- `Content-Type:`
- `Content-Length:`
- `Transfer-Encoding:`

### HTTP/2 + gRPC

HTTP/2 connection preface detection: the first 24 bytes of the TCP payload are compared against the magic string `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`.

After the preface, HTTP/2 frames are parsed:
- Frame header: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream ID
- HEADERS frames (type 0x1): HPACK-encoded headers
- SETTINGS frames (type 0x4): connection parameters
- DATA frames (type 0x0): payload data

HPACK static table lookup for common pseudo-headers:
- Index 2: `:method GET`
- Index 3: `:method POST`
- Index 4: `:path /`
- Index 5: `:path /index.html`
- Index 7: `:scheme https`
- Index 8: `:status 200`

gRPC detection: `content-type: application/grpc` in HEADERS frame.

### QUIC/HTTP3

QUIC long header format (RFC 9000):
- Byte 0: Header form (bit 7 = 1 for long header) + packet type (bits 4-5)
- Bytes 1..4: Version (0x00000001 = QUIC v1, 0xFF000020 = draft-32, etc.)
- Byte 5: Destination Connection ID length
- Next N bytes: Destination Connection ID
- Next byte: Source Connection ID length
- Next M bytes: Source Connection ID

QUIC short headers (bit 7 = 0) are detected but not fully parsed.

### DHCP

DHCP message structure (RFC 2131):
- Byte 0: op (1=BOOTREQUEST, 2=BOOTREPLY)
- Byte 1: htype (1=Ethernet)
- Byte 2: hlen (6 for MAC)
- Byte 3: hops
- Bytes 4..7: xid (transaction ID)
- Bytes 8..9: secs
- Bytes 10..11: flags
- Bytes 12..15: ciaddr (client IP)
- Bytes 16..19: yiaddr (your/offered IP)
- Bytes 20..23: siaddr (server IP)
- Bytes 24..27: giaddr (gateway IP)
- Bytes 28..43: chaddr (client hardware address)
- Bytes 44..107: sname (server hostname)
- Bytes 108..235: file (boot filename)
- Bytes 236..239: magic cookie (0x63825363)
- Bytes 240+: options (TLV format)

DHCP options parsed:
- 1: Subnet mask
- 3: Router
- 6: DNS servers
- 12: Hostname
- 15: Domain name
- 51: IP address lease time
- 53: DHCP message type (1=Discover, 2=Offer, 3=Request, 4=Decline, 5=Ack, 6=Nak, 7=Release, 8=Inform)
- 54: DHCP server identifier
- 255: End

### SSH

SSH identification string (RFC 4253): the first packet after TCP connection establishment contains a banner in the form `SSH-protoversion-softwareversion SP comments CR LF`. pktana reads up to 255 bytes of the first payload to extract:
- Protocol version (`2.0`, `1.99`, `1.5`)
- Software name and version (e.g. `OpenSSH_8.9p1`)

### SIP/VoIP

SIP request line: `Method SP Request-URI SP SIP/2.0 CRLF`

Methods recognized: INVITE, REGISTER, BYE, ACK, CANCEL, OPTIONS, SUBSCRIBE, NOTIFY, REFER, INFO, UPDATE, PRACK

Headers parsed:
- `From:` (with `tag=` parameter)
- `To:`
- `Call-ID:`
- `CSeq:`
- `Via:`
- `Content-Type:` (for SDP detection)

### NTP

NTP packet (RFC 5905), 48 bytes fixed:
- Byte 0: LI (bits 7-6) + VN (bits 5-3) + Mode (bits 2-0)
  - Mode 3 = Client, Mode 4 = Server, Mode 5 = Broadcast
- Byte 1: Stratum (0=unspecified, 1=primary reference, 2-15=secondary)
- Byte 2: Poll interval (log₂ seconds)
- Byte 3: Precision (log₂ seconds, signed)

**Amplification detection**: NTP control messages (mode 6) with opcode 42 (`MON_GETLIST` / `monlist`) are flagged as amplification attack vectors. These can generate responses 100–200× the request size.

### BGP

BGP message header (RFC 4271), 19 bytes:
- Bytes 0..15: Marker (all 0xFF)
- Bytes 16..17: Length
- Byte 18: Type (1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE, 5=ROUTE-REFRESH)

OPEN message fields (after 19-byte header):
- Byte 0: Version (always 4)
- Bytes 1..2: My Autonomous System
- Bytes 3..4: Hold Time
- Bytes 5..8: BGP Identifier (router ID as IPv4)
- Byte 9: Optional parameters length
- Bytes 10+: Optional parameters (TLV)

### Database Protocols

| Protocol | Detection method | Key offset | Fields extracted |
|----------|-----------------|------------|-----------------|
| MySQL | Greeting: 3-byte length + sequence=0 + capability flags | Byte 5..8 (capability flags) | Server version string, auth plugin name |
| PostgreSQL | Startup magic `0x00030000` at bytes 4..7 | Bytes 8+ | User (key=`user`), database (key=`database`) |
| Redis | `*` at byte 0 + `\r\n` | RESP multi-bulk prefix | Command name (first bulk string) |
| MongoDB | OP_MSG: int32 `2013` at bytes 12..15 | Wire protocol header | Operation type, flags |

### SNMP

SNMP is BER-encoded ASN.1. Detection:
- Byte 0: `0x30` (SEQUENCE tag)
- Byte 2: `0x02` (INTEGER) + version byte
  - `0x00` = SNMPv1
  - `0x01` = SNMPv2c
  - `0x03` = SNMPv3

Community string (v1/v2c): OCTET STRING immediately after version INTEGER.

PDU type byte (next tag after community string):
- `0xA0` = GetRequest
- `0xA1` = GetNextRequest
- `0xA2` = GetResponse
- `0xA3` = SetRequest
- `0xA4` = Trap (v1)
- `0xA5` = GetBulkRequest
- `0xA7` = Trap (v2c/v3 InformRequest)

### Tunnels (re-inspection)

VXLAN, GRE, and Geneve payloads contain inner Ethernet frames. pktana **recursively calls `inspect()`** on the inner frame, so all L2–L7 dissection applies to both outer and inner packets.

**VXLAN** (RFC 7348): 8-byte header at UDP payload start:
- Byte 0: flags (bit 3 = VNI present)
- Bytes 4..6: 24-bit VNI (Virtual Network Identifier)
- Byte 7: reserved
- Bytes 8+: inner Ethernet frame

**GRE** (RFC 2784): minimal header at IP payload start:
- Bytes 0..1: flags (C=bit 15, K=bit 13, S=bit 12)
- Bytes 2..3: Protocol type (0x6558 = Transparent Ethernet Bridging)
- Optional checksum (4 bytes if C=1), key (4 bytes if K=1), sequence (4 bytes if S=1)
- Then inner Ethernet frame (if protocol == 0x6558)

**Geneve** (RFC 8926): variable-length header at UDP port 6081:
- Byte 0: version (bits 7-6) + opt_len in 4-byte units (bits 5-0)
- Byte 1: flags
- Bytes 2..3: protocol type (0x6558 = Ethernet)
- Bytes 4..6: 24-bit VNI
- Byte 7: reserved
- Bytes 8..(8 + opt_len*4): tunnel options
- Then inner Ethernet frame

---

## `one_liner()` Output Format

The `one_liner()` method on `DeepPacket` produces a single-line summary string formatted as:

```
[PROTO] src → dst  extra_detail
```

Examples by protocol:

| Protocol | Example output |
|----------|---------------|
| DNS query | `[DNS] 192.168.1.5 → 8.8.8.8  Query: A example.com` |
| DNS response | `[DNS] 8.8.8.8 → 192.168.1.5  Reply: example.com → 93.184.216.34` |
| TLS ClientHello | `[TLS] 192.168.1.5:52431 → 1.2.3.4:443  SNI: api.example.com  JA3: cd08e31494f9531f560d64c695473da9` |
| HTTP GET | `[HTTP] 192.168.1.5:52431 → 93.184.216.34:80  GET /index.html Host: example.com` |
| HTTP response | `[HTTP] 93.184.216.34:80 → 192.168.1.5:52431  200 OK  text/html` |
| DHCP Discover | `[DHCP] 0.0.0.0 → 255.255.255.255  DISCOVER  client: aa:bb:cc:dd:ee:ff` |
| ARP request | `[ARP] 192.168.1.1 → ?  Who has 192.168.1.5?` |
| ICMP echo | `[ICMP] 192.168.1.5 → 8.8.8.8  Echo Request  id=1 seq=42` |
| TCP SYN | `[TCP] 192.168.1.5:52431 → 8.8.8.8:443  SYN  seq=0` |
| SSH banner | `[SSH] 192.168.1.5:22 → 192.168.1.10:52100  SSH-2.0-OpenSSH_8.9p1` |
| NTP | `[NTP] 192.168.1.5 → 129.6.15.28  v4 Client mode` |
| BGP OPEN | `[BGP] 10.0.0.1:179 → 10.0.0.2:179  OPEN  AS=65001` |

---

## Anomaly Detection

The following anomalies are detected and added to `dp.anomalies`:

| Anomaly | Detection Logic | Risk Points |
|---------|----------------|-------------|
| `SYN+FIN` | `tcp_flags & 0x003 == 0x003` | +40 |
| `NULL scan` | `tcp_flags & 0x03F == 0x000` | +40 |
| `SYN+RST` | `tcp_flags & 0x006 == 0x006` | +35 |
| `XMAS scan` | `tcp_flags & 0x029 == 0x029` (FIN+URG+PSH) | +40 |
| `Zero-window SYN` | SYN flag set AND `tcp_window == 0` | +10 |
| `TTL=0` | `ip_ttl == Some(0)` | +10 |
| `Broadcast source MAC` | `eth_src == "ff:ff:ff:ff:ff:ff"` | +20 |
| `Malformed TCP header` | `tcp_hdr_len < 20` | +15 |
| `IP fragment` | `ip_fragment == true` | +5 |
| `Short IPv4 header` | `ip_hdr_len < 20` | +15 |
| `ARP MAC mismatch` | ARP sender MAC ≠ Ethernet src MAC | +20 |
| `ICMP redirect` | `icmp_type == 5` | +15 |
| `NTP amplification` | NTP control message + monlist opcode | +30 |
| `DGA suspected` | DNS label entropy > 3.5 bits/char | +25 |
| `Deprecated TLS` | TLS version 1.0 (`0x0301`) or 1.1 (`0x0302`) | +15 |

---

## Risk Scoring

Each packet receives a composite risk score 0–100 calculated as the **sum of all applicable anomaly points, capped at 100**.

The score is computed after the full dissection pass:

```rust
dp.risk_score = dp.anomalies.iter()
    .map(|a| anomaly_points(a))
    .sum::<u32>()
    .min(100) as u8;
```

Where `anomaly_points()` returns the per-anomaly delta from the table above.

| Score Range | Interpretation | Typical causes |
|-------------|----------------|----------------|
| 0–19 | Normal / benign | Clean traffic |
| 20–39 | Low risk | IP fragments, deprecated TLS |
| 40–59 | Medium risk | ARP mismatch + deprecated TLS |
| 60–79 | High risk | Multiple scan flags, NTP amplification |
| 80–100 | Critical | NULL+SYN+FIN scan, multiple combined anomalies |

**Example**: A packet with `SYN+FIN` (+40) and `DGA suspected` (+25) receives score 65 — High risk.

---

## Traffic Categories

Each packet is classified into an `app_category`:

| Category | Protocols |
|----------|-----------|
| Web Browsing | HTTP, HTTPS, HTTP/2, gRPC |
| Encrypted Transport | TLS (non-HTTP SNI), QUIC/HTTP3 |
| VoIP/UC | SIP, RTP |
| Database | MySQL, PostgreSQL, Redis, MongoDB |
| File Transfer | FTP, SFTP, SMB |
| Tunneling/Overlay | VXLAN, GRE, Geneve |
| Remote Access | SSH, RDP (port 3389) |
| DNS/Infrastructure | DNS, DHCP, NTP, BGP |
| Monitoring/Mgmt | SNMP, LDAP, Kerberos, Syslog, IKE |
| Generic TCP | Unrecognized TCP traffic |
| Generic UDP | Unrecognized UDP traffic |

---

## OUI Vendor Lookup

MAC address OUI (first 3 bytes) is matched against an embedded vendor table compiled from the IEEE MA-L registry. The lookup is an O(1) hash map keyed on the 3-byte prefix.

Examples:

| OUI | Vendor |
|-----|--------|
| `00:1A:2B` | Cisco Systems |
| `00:50:56` | VMware |
| `52:54:00` | QEMU/KVM (virtual) |
| `B8:27:EB` | Raspberry Pi Foundation |
| `00:0C:29` | VMware Workstation |
| `08:00:27` | Oracle VirtualBox |

---

## `hex_dump()` Function

```rust
pub fn hex_dump(data: &[u8], max_bytes: usize) -> Vec<String>
```

Produces a standard hex dump, one line per 16 bytes:

```
  0000  45 00 00 3c 1c 46 40 00  40 06 00 00 c0 a8 01 01  |E..<.F@.@.......|
  0010  08 08 08 08 cc 8e 00 50  00 00 00 00 a0 02 fa f0  |.......P........|
  0020  00 00 02 04 05 b4 04 02  08 0a 00 46 a3 8e 00 00  |...........F....|
```

Format: `  OFFSET  HEX_BYTES  |ASCII|`
- **Offset**: 4-digit hex, increments by 16 per line
- **Hex block**: space-separated bytes, split into two groups of 8 with a double space in the middle, padded to 48 characters total
- **ASCII**: printable characters (byte values 0x20–0x7E), `.` for non-printable bytes, wrapped in `|`

The `max_bytes` parameter limits how many bytes are dumped. The web UI passes 128 (first 8 lines of hex).
