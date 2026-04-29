# Changelog

All notable changes to pktana are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.3.0] — 2026-04-29

### Added

#### DPI Engine — TLS Intelligence
- **JA3 fingerprinting**: full ClientHello parse — cipher suites, extensions, elliptic curves, point formats; GREASE values filtered; raw JA3 string stored in `tls_ja3_raw`
- **ALPN extraction**: negotiated ALPN protocols (e.g. `h2`, `http/1.1`) stored in `tls_alpn`
- **Cipher suite list** stored as `Vec<u16>` in `tls_ciphers`
- TLS 1.0/1.1 deprecation warning inline (RFC 8996)

#### DPI Engine — Modern Protocols
- **QUIC / HTTP3**: long/short header decode, version decode (RFC 9000 v1, RFC 9369 v2, gQUIC, negotiation, GREASE) in `quic_version` / `quic_packet_type`
- **HTTP/2**: PRI magic detection + frame-type parsing; `http2_detected` flag
- **gRPC**: `:path` header extraction via naive HPACK literal scan; stored in `grpc_path`
- **WebSocket**: Upgrade header detection + per-frame opcode (Text/Binary/Close/Ping/Pong) + mask; `ws_upgrade` flag
- **SSH banner**: full banner string extraction, SSHv1 detection; stored in `ssh_banner`
- **SIP / VoIP**: all SIP methods (INVITE/BYE/REGISTER/OPTIONS/CANCEL/ACK/…), SIP URI, Call-ID, From, To, User-Agent; stored in `sip_method` / `sip_uri` / `sip_call_id`
- **NTP full decode**: version, mode (with name), stratum (with description), amplification risk flag (`ntp_amplification_risk`) for mode 7 monlist responses
- **BGP**: message type (OPEN/UPDATE/NOTIFICATION/KEEPALIVE), AS number from OPEN, Router ID; stored in `bgp_msg_type` / `bgp_asn`
- **IPv6**: basic header decode (src, dst, next header, hop limit); stored in `ipv6_src` / `ipv6_dst` / `ipv6_next_header` / `ipv6_hop_limit`; wired into `inspect()` via EtherType 0x86dd

#### DPI Engine — Tunnel Inner-Frame Re-Inspection
- **VXLAN** (UDP/4789): inner Ethernet + IPv4 re-inspection, inner ports and app-proto stored
- **GRE** (IP proto 47): header parse (flags, checksum, key, seq), inner Ethernet re-inspection
- **Geneve** detection
- All tunnel details stored in `tunnel_type` / `inner_ip_src` / `inner_ip_dst` / `inner_proto` / `inner_src_port` / `inner_dst_port` / `inner_app_proto`

#### DPI Engine — DNS Enhancement
- **Shannon entropy** computed on the longest DNS label; stored in `dns_label_entropy`
- `dns_query_name` stores the first question name
- Entropy threshold labels: HIGH (>3.8 bits) = possible DGA/tunneling, MEDIUM, LOW

#### DPI Engine — Risk Scoring & Classification
- `compute_risk()` method builds a **0–100 composite risk score** from: deprecated TLS, SSHv1, NTP monlist, high DNS entropy, NULL scan, zero-window SYN, broadcast source, tunneling
- `classify_app_category()` maps protocol/port to a human-readable category: Web Browsing, Encrypted Transport, VoIP / UC, Database, File Transfer, Tunneling / Overlay, Remote Access, DNS / Infrastructure, Monitoring / Mgmt, Generic TCP/UDP
- Both fields (`risk_score`, `risk_reasons`, `app_category`) automatically populated by `inspect()`

#### CLI — `pktana inspect` (print_deep_packet)
New sections added to the inspect output:
- **LAYER 3 — IPv6**: src/dst, next header with name, hop limit
- **QUIC / HTTP3**: packet type, version with RFC name
- **HTTP/2**: frame detection, gRPC `:path` in cyan
- **WEBSOCKET**: Upgrade detection
- **SSH**: banner string, SSHv1 warning in red / SSHv2 confirmation in green
- **SIP (VoIP)**: method, URI, Call-ID
- **NTP**: version, mode, stratum with description, amplification risk in red
- **BGP**: message type, AS number
- **TUNNEL**: encap type, inner src/dst IP, inner proto, inner ports, inner app proto
- **TLS FINGERPRINT**: JA3 raw string with lookup hint, ALPN list, cipher suites (first 8 as hex)
- **DNS ANALYSIS**: query name, entropy with color-coded risk label
- **CLASSIFICATION & RISK**: app category in cyan, 0-100 bar with LOW/MEDIUM/HIGH label, reasons list

#### CLI — `pktana capture` / `pktana <iface>`
- Switched from `analyze_bytes()` to full `inspect()` DPI per packet
- **Color-coded protocol column**: TLS=green, HTTP=blue, DNS=cyan, QUIC=bright-green, SSH=bright-blue, ICMP=yellow, ARP=magenta, BGP/NTP=red
- **DPI-enriched Info column**: TLS SNI+ALPN, HTTP method+path, DNS query name, SSH banner, SIP method, BGP type+ASN, QUIC version, NTP mode
- RST packets highlighted in red
- **End-of-capture summary**: protocol breakdown table + top-5 talkers with packet/byte counts

#### CLI — `pktana conn`
- **GeoIP country** for every remote IP (offline lookup, no API call)
- **Service name** for well-known ports shown in extra column
- **Color-coded TCP state**: ESTABLISHED=green, LISTEN=cyan, TIME_WAIT/CLOSE_WAIT=yellow, SYN*=bold yellow

#### CLI — `pktana stats`
- **GeoIP country name** shown for each top-10 talker

#### TUI (`pktana tui eth0`)
- `dpi_lines()` extended with all new DPI fields: IPv6, QUIC, HTTP/2, gRPC, WebSocket, SSH banner, SIP, NTP, BGP, tunnel inner frame, JA3+ALPN, DNS analysis, risk score bar, app category

### Fixed
- Removed unused `dns_decode()`/`dns_parse_name()`/`dns_name_len()`/`dns_type_str()` functions from `main.rs`
- Removed unused `TransportHeader` import from `main.rs`

---

## [0.1.0] — 2026-04-24

Initial public release.

### Added

#### Packet Capture
- Live capture on any interface using libpcap with promiscuous + immediate mode
- BPF filter support (same syntax as tcpdump)
- Packet table output: No. / Time / Bytes / Proto / Source / Dest / Info
- Shorthand `pktana <interface>` — no subcommand needed
- DNS query/reply decode in the Info column during live capture

#### Deep Packet Inspection (`pktana inspect`)
- Full layer-by-layer offline decode from a raw hex string or file
- **L2 Ethernet**: src/dst MAC, OUI vendor lookup, QinQ/802.1Q VLAN stack
- **ARP**: request/reply, sender/target MAC+IP, gratuitous ARP detection
- **L3 IPv4**: IHL, DSCP, ECN, ID, DF/MF flags, fragment offset, TTL, protocol
- **L4 TCP**: ports, seq/ack, flags, window size, urgent pointer, header length
- **TCP options**: MSS, Window Scale, SACK permitted, SACK blocks, Timestamps
- **L4 UDP**: ports, length, checksum
- **L4 ICMP**: full type/code decode (30+ messages), echo id/seq, redirect detail
- **Application layer detection**: HTTP (method/URL/status/headers), TLS (version 1.0–1.3 + SNI extraction from ClientHello), DNS (full query/answer), DHCP (message type), SMTP, SSH, RDP, MySQL, PostgreSQL, Redis, MongoDB, BGP, NTP, SNMP, IKE, VXLAN, Geneve, Syslog, SSDP
- Payload hex+ASCII dump (Wireshark-style, up to 256 bytes)
- Anomaly detection: SYN+FIN, NULL scan, SYN+RST, zero-window SYN, TTL=0, broadcast source, malformed TCP data offset, fragmented packets, short ARP/UDP/ICMP headers

#### Auto-Diagnosis Engine
- One-line packet summary for every inspection
- Rule-based findings: TCP handshake state, zero-window flow control, OS fingerprint from TTL (Linux=64/Windows=128/Cisco=255), MSS/PPPoE/tunnel detection, DSCP/QoS class labelling, DNS rcode explanation, TLS deprecation warning (RFC 8996), HTTP status classification, DHCP state machine, ARP type explanation, ICMP purpose, VLAN tagging, fragmentation notice

#### NIC Information (`pktana nic`)
- Lists all interfaces: state, MAC, MTU, speed, IP addresses
- Per-interface detail: duplex, driver, loopback/promisc flags, full RX/TX counters
- Reads entirely from sysfs/procfs — no `ip`, `ifconfig`, or `ethtool` binary needed
- Replaces: `ip link show`, `ip addr show`, `ifconfig`, `/proc/net/dev`

#### Ethtool Equivalent (`pktana ethtool`)
- Driver name, PCI bus address, firmware version, IRQ number
- Link speed, duplex, autoneg, operstate, TX queue length
- PCIe link speed and lane width
- Carrier up/down/change event counts
- RX / TX / combined queue count
- Hardware offload features (TSO, LRO, GRO, checksum offload…) ON/OFF
- Per-queue IRQ → CPU affinity (smp_affinity)
- Extended statistics (per-queue/direction counters)
- Replaces: `ethtool -i`, `ethtool -k`, `ethtool -l`, `ethtool -S`

#### Dataplane Detection (`pktana dp`)
- Detects XDP eBPF programs attached to interface (reads xdp_prog_ids)
- Detects AF_XDP zero-copy sockets (reads /proc/net/xdp)
- Detects DPDK/vfio-pci / uio_pci_generic binding
- SR-IOV VF/PF role detection and VF count
- Multi-queue RX/TX count
- Hardware offload features active
- PCI address, vendor ID, device ID, NUMA node
- Bypass mode classification: KernelStack / XDP / AF_XDP / DpdkUserspace / Hybrid
- Human-readable guidance for each mode

#### Connection Table (`pktana conn`)
- TCP and UDP sockets from /proc/net/tcp, tcp6, udp, udp6
- PID resolution via /proc/<pid>/fd symlink scanning
- Process name from /proc/<pid>/cmdline
- IPv4 + IPv6 support
- Replaces: `ss -tulnp`, `netstat -tulnp`, `lsof -i`

#### Routing Table (`pktana route`)
- IPv4 routes from /proc/net/route
- IPv6 routes from /proc/net/ipv6_route
- CIDR notation, gateway, metric, route type (default/connected/static)
- Per-interface filtering: `pktana route <iface>`
- Replaces: `ip route show`, `netstat -r`, `route -n`

#### Live Traffic Dashboard (`pktana stats`)
- Live PPS / BPS rate (1-second window)
- Cumulative packets and bytes
- Per-protocol breakdown with ASCII bar chart (TCP/UDP/ICMP/ARP/Other)
- Top-10 talkers by packet count
- Auto-trimming talkers map (capped at 5 000 unique IPs)
- BPF filter support

#### NIC Auto-Refresh (`pktana watch`)
- Reads /sys/class/net/<iface>/statistics/ on a configurable interval
- Default refresh: 2 seconds
- Replaces: `watch -n2 ip -s link show`

#### Offline Decode Utilities
- `pktana hex <HEX>` — quick one-line decode
- `pktana file <FILE>` — batch decode, one hex packet per line
- `pktana demo` — built-in sample packets
- `pktana interfaces` — list pcap capture interfaces

#### Help System
- `pktana help` — grouped command reference with color output
- `pktana help <command>` — full per-command documentation page (synopsis, description, fields, examples, replaces) for every subcommand

#### Build & Packaging
- Single-command RPM build: `make pktana`
- `release.conf` for VERSION / RELEASE / OS_TYPE (el7/el9)
- RPM spec with `Requires: libpcap >= 1.5` (auto-installs dependency)
- Supports Rocky Linux 9 / RHEL 9 / CentOS Stream 9 (el9)
- `--version` flag prints version and build metadata

### Technical
- Written in Rust (2021 edition), workspace: `pktana-core` (lib) + `pktana-cli` (binary)
- All network inspection reads sysfs/procfs directly — zero subprocess calls
- libpcap is an optional feature (`--features pcap`) for capture only
- No unsafe code in packet parsing paths

---

[Unreleased]: https://github.com/omnayak27199/pktana/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/omnayak27199/pktana/releases/tag/v0.3.0
[0.1.0]: https://github.com/omnayak27199/pktana/releases/tag/v0.1.0
