# Protocol Coverage

pktana performs **layer-by-layer** protocol dissection with no external parsers. This page documents every supported protocol and what fields are extracted.

---

## Layer 2 — Data Link

### Ethernet II (IEEE 802.3)

| Field | Description |
|-------|-------------|
| Destination MAC | 6-byte hardware address |
| Source MAC | 6-byte hardware address |
| OUI vendor lookup | Manufacturer from first 3 bytes of MAC |
| EtherType | Next-layer protocol identifier |

### ARP (Address Resolution Protocol)

| Field | Description |
|-------|-------------|
| Operation | Request (1) / Reply (2) / Gratuitous |
| Sender hardware address | MAC |
| Sender protocol address | IPv4 |
| Target hardware address | MAC |
| Target protocol address | IPv4 |
| ARP MAC mismatch | Anomaly: ARP sender MAC ≠ Ethernet src MAC |

### 802.1Q VLAN / 802.1ad QinQ

| Field | Description |
|-------|-------------|
| PCP | Priority Code Point (0–7) |
| DEI | Drop Eligible Indicator |
| VLAN ID | 12-bit VLAN identifier |
| Stacked tags | QinQ (outer + inner) supported |

---

## Layer 3 — Network

### IPv4

| Field | Description |
|-------|-------------|
| Version, IHL | Header version and length |
| DSCP / ECN | QoS classification |
| Total Length | Packet size including header |
| Identification | Fragment ID |
| Flags: DF, MF | Don't Fragment, More Fragments |
| Fragment Offset | Position in fragmented datagram |
| TTL | Time-to-Live (TTL=0 flagged as anomaly) |
| Protocol | Next-layer protocol (TCP=6, UDP=17, ICMP=1, …) |
| Checksum | Header checksum |
| Source / Destination | IPv4 addresses |

### IPv6

| Field | Description |
|-------|-------------|
| Source / Destination | IPv6 addresses |
| Hop Limit | Equivalent to TTL |
| Next Header | Protocol identifier |
| Traffic Class / Flow Label | QoS fields |

---

## Layer 4 — Transport

### TCP

| Field | Description |
|-------|-------------|
| Source / Destination Port | 16-bit port numbers |
| Sequence Number | 32-bit |
| Acknowledgement Number | 32-bit |
| Header Length | Data offset in bytes |
| Flags | URG, ACK, PSH, RST, SYN, FIN (and ECE, CWR) |
| Window Size | Receive buffer size |
| Urgent Pointer | — |
| **TCP Options** | |
| MSS | Maximum Segment Size |
| Window Scale | WSCALE multiplier |
| SACK Permitted | Selective ACK capability |
| SACK Blocks | Ranges of received data |
| Timestamps | TSval/TSecr for RTT measurement |

**Anomaly detection**:
- SYN+FIN (invalid combination)
- NULL scan (no flags)
- SYN+RST (invalid combination)
- Zero-window SYN
- Malformed data offset

### UDP

| Field | Description |
|-------|-------------|
| Source / Destination Port | 16-bit port numbers |
| Length | UDP header + payload length |
| Checksum | — |

### ICMP

All 30+ type/code combinations are named. Key types:

| Type | Name |
|------|------|
| 0 | Echo Reply |
| 3 | Destination Unreachable (15 codes) |
| 5 | Redirect (flagged as anomaly) |
| 8 | Echo Request |
| 11 | Time Exceeded (TTL) |
| 12 | Parameter Problem |

Fields: type, code, identifier, sequence number, checksum.

---

## Layer 7 — Application

### TLS / SSL

Fully decodes handshake messages:

| Feature | Description |
|---------|-------------|
| TLS 1.0 / 1.1 / 1.2 / 1.3 | Version detection |
| Server Name Indication (SNI) | From ClientHello extension |
| Cipher Suites | All offered suites, with names |
| ALPN | Protocol names (`h2`, `http/1.1`, etc.) |
| JA3 Fingerprint | MD5 of `TLSVersion,Ciphers,Extensions,EllipticCurves,PointFormats` |
| GREASE filtering | RFC 8701 values excluded from JA3 |
| RFC 8996 warnings | TLS 1.0/1.1 and deprecated ciphers flagged |
| Session ID | 32-byte session identifier |

### HTTP/1.x

| Feature | Description |
|---------|-------------|
| Method | GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT |
| URI / Path | Request URI |
| Host | Host header |
| User-Agent | Browser/client identification |
| Status Code | Response codes (200, 404, 500, etc.) |
| Content-Type | Media type of response |

### HTTP/2

| Feature | Description |
|---------|-------------|
| Connection preface | `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` |
| HPACK pseudo-headers | `:method`, `:path`, `:authority`, `:status`, `content-type` |
| gRPC detection | `content-type: application/grpc` → labeled as gRPC |

### QUIC / HTTP3

| Feature | Description |
|---------|-------------|
| Long header detection | First-byte bit pattern |
| Version identification | QUIC version codes |
| Connection ID | Source/Destination connection ID |
| HTTP3 heuristic | QUIC on UDP/443 → HTTP3 |

### DNS

| Feature | Description |
|---------|-------------|
| Transaction ID | 16-bit ID for query/response matching |
| QR flag | Query (0) / Response (1) |
| Query type | A, AAAA, MX, NS, CNAME, PTR, TXT, SOA, SRV, ANY |
| Query name | Domain name |
| Response code | NOERROR, NXDOMAIN, SERVFAIL, REFUSED, etc. |
| Answers | Up to 4 answer records with IP/name |
| Shannon entropy | High-entropy names flagged as potential DGA |

### DHCP

| Feature | Description |
|---------|-------------|
| Message type | Discover, Offer, Request, Ack, Nak, Release, Inform |
| Client IP | `ciaddr` |
| Your IP | `yiaddr` (offered IP) |
| Server IP | `siaddr` |
| Options | Router, DNS servers, hostname, domain, lease time, subnet mask |

### SSH

| Feature | Description |
|---------|-------------|
| Version string | `SSH-2.0-OpenSSH_8.9p1` |
| Protocol version | SSH-1.99, SSH-2.0 |
| Server / Client identification | From banner |

### SIP / VoIP

| Feature | Description |
|---------|-------------|
| Method | INVITE, REGISTER, BYE, ACK, CANCEL, OPTIONS, PRACK, UPDATE |
| From / To | SIP URI headers |
| Call-ID | Session identifier |
| Via | Transport path |

### NTP

| Feature | Description |
|---------|-------------|
| Version | NTP version (1–4) |
| Mode | Client, Server, Broadcast, Symmetric |
| Reference timestamp | — |
| Amplification risk | `monlist` requests flagged (+30 risk points) |

### BGP

| Feature | Description |
|---------|-------------|
| Message type | OPEN, UPDATE, NOTIFICATION, KEEPALIVE |
| AS Number | From OPEN message |
| BGP version | Version field |

### SMTP

| Feature | Description |
|---------|-------------|
| Commands | EHLO, HELO, MAIL FROM, RCPT TO, DATA, QUIT, AUTH |
| Response codes | 220, 250, 354, 421, 450, 500–550, etc. |

### RDP

| Feature | Description |
|---------|-------------|
| Protocol detection | TCP/3389, TPKT/X.224 header |
| Cookie | RDP mstshash cookie (username leak) |

### Database Protocols

| Protocol | Port | Detected by | Fields |
|----------|------|-------------|--------|
| MySQL | 3306 | Greeting packet magic | Server version, auth method |
| PostgreSQL | 5432 | Startup message (196608) | User, database |
| Redis | 6379 | `*N\r\n$M\r\n` RESP | Command verb |
| MongoDB | 27017 | OP_QUERY/OP_MSG wire | Operation code |

### Infrastructure Protocols

| Protocol | Port | Fields |
|----------|------|--------|
| SNMP | 161/162 UDP | Version, community, PDU type |
| LDAP | 389 | MessageID, protocol op |
| Kerberos | 88 | Message type (AS-REQ, TGS-REQ, etc.) |
| IKE/IPsec | 500 UDP | Initiator/Responder SPI, Exchange type |
| SSDP | 1900 UDP | Method (M-SEARCH, NOTIFY), ST |
| Syslog | 514 | Facility, severity, message |

### WebSocket

| Feature | Description |
|---------|-------------|
| Upgrade detection | HTTP `Upgrade: websocket` header |
| Protocol version | `Sec-WebSocket-Version` |
| Frame detection | Opcode, mask flag |

---

## Tunnel Protocols (Re-inspection)

Tunnel protocols carry inner Ethernet frames. pktana **recursively applies the full DPI engine** to the inner frame.

| Protocol | Outer | Inner | Notes |
|----------|-------|-------|-------|
| VXLAN | UDP/4789 | Ethernet | VNI extracted |
| GRE | IP proto 47 | Ethernet | Protocol field |
| Geneve | UDP/6081 | Ethernet | VNI, options |

---

## Risk Score Contributions

| Anomaly / Protocol Feature | Score Added |
|---------------------------|-------------|
| SYN+FIN or NULL scan | +40 |
| ARP MAC mismatch | +20 |
| NTP monlist (amplification) | +30 |
| TLS 1.0/1.1 (deprecated) | +15 |
| Deprecated cipher suite | +10 |
| ICMP redirect | +15 |
| DNS DGA suspected | +20 |
| Zero-window SYN | +10 |
| TTL=0 | +10 |
| IP fragment | +5 |
| Broadcast source MAC | +10 |
| Malformed TCP header | +15 |
| Short IPv4 header | +20 |

Maximum score is capped at 100.
