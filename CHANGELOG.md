# Changelog

All notable changes to pktana are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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

[Unreleased]: https://github.com/omnayak27199/pktana/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/omnayak27199/pktana/releases/tag/v0.1.0
