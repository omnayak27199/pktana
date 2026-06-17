# Protocols Reference

A quick-reference guide to the most important networking protocols, organized by OSI layer. Use this as a cheat sheet while capturing and analyzing packets with pktana.

---

## Layer 2 — Data Link

| Protocol | EtherType | Purpose | pktana filter |
|---------|-----------|---------|---------------|
| Ethernet II | — | Standard LAN framing | — |
| IEEE 802.1Q | 0x8100 | VLAN tagging | `vlan` |
| ARP | 0x0806 | IP → MAC address resolution | `arp` |
| RARP | 0x8035 | MAC → IP (legacy, replaced by DHCP) | `rarp` |
| PPPoE | 0x8863/8864 | PPP over Ethernet (DSL) | `pppoe` |
| LLDP | 0x88CC | Link Layer Discovery Protocol | `ether proto 0x88cc` |
| Spanning Tree (BPDU) | 0x0026 | STP loop prevention | — |

---

## Layer 3 — Network

| Protocol | IP Proto | Purpose | Default Port | pktana filter |
|---------|---------|---------|-------------|---------------|
| IPv4 | — | Internet Protocol v4 | — | `ip` |
| IPv6 | — | Internet Protocol v6 | — | `ip6` |
| ICMP | 1 | Control messages, ping, traceroute | — | `icmp` |
| ICMPv6 | 58 | IPv6 control + neighbor discovery | — | `icmp6` |
| OSPF | 89 | Link-state routing (IGP) | — | `proto ospf` |
| EIGRP | 88 | Cisco hybrid routing | — | `proto 88` |
| GRE | 47 | Generic tunnel encapsulation | — | `proto gre` |
| ESP | 50 | IPsec encryption payload | — | `proto esp` |
| AH | 51 | IPsec authentication header | — | `proto ah` |

---

## Layer 4 — Transport

| Protocol | IP Proto | Characteristics | pktana filter |
|---------|---------|----------------|---------------|
| TCP | 6 | Reliable, ordered, connection-oriented | `tcp` |
| UDP | 17 | Unreliable, connectionless, fast | `udp` |
| SCTP | 132 | Multi-stream, reliable (telecom) | `sctp` |
| DCCP | 33 | Congestion-controlled unreliable | — |

---

## Well-Known Ports

### Infrastructure Protocols

| Protocol | Port | Transport | Purpose |
|---------|------|-----------|---------|
| FTP-Data | 20 | TCP | File transfer (data channel) |
| FTP-Control | 21 | TCP | File transfer (commands) |
| SSH | 22 | TCP | Secure shell, SFTP, tunneling |
| Telnet | 23 | TCP | Remote terminal (unencrypted — avoid) |
| SMTP | 25 | TCP | Mail relay between servers |
| DNS | 53 | UDP/TCP | Name resolution |
| DHCP Server | 67 | UDP | IP address assignment |
| DHCP Client | 68 | UDP | DHCP client receive |
| TFTP | 69 | UDP | Trivial file transfer (firmware upgrades) |
| HTTP | 80 | TCP | Web traffic (unencrypted) |
| POP3 | 110 | TCP | Mail retrieval (downloads and deletes) |
| NTP | 123 | UDP | Time synchronization |
| NetBIOS | 137–139 | UDP/TCP | Windows name resolution (legacy) |
| IMAP | 143 | TCP | Mail access (leaves on server) |
| SNMP | 161/162 | UDP | Network device management/traps |
| LDAP | 389 | TCP | Directory services |
| HTTPS | 443 | TCP | Encrypted web traffic |
| SMB/CIFS | 445 | TCP | Windows file sharing |
| SMTP/TLS | 587 | TCP | Mail submission (authenticated) |
| LDAPS | 636 | TCP | LDAP over TLS |
| IMAP/TLS | 993 | TCP | IMAP over TLS |
| POP3/TLS | 995 | TCP | POP3 over TLS |
| OpenVPN | 1194 | UDP/TCP | VPN |
| MySQL | 3306 | TCP | MySQL database |
| RDP | 3389 | TCP | Windows Remote Desktop |
| PostgreSQL | 5432 | TCP | PostgreSQL database |
| Redis | 6379 | TCP | Redis in-memory data store |
| WireGuard | 51820 | UDP | Modern VPN |

### Monitoring / Logging

| Protocol | Port | Transport | Purpose |
|---------|------|-----------|---------|
| Syslog | 514 | UDP | Log collection |
| Syslog/TLS | 6514 | TCP | Encrypted log collection |
| Elasticsearch | 9200 | TCP | Search/log database |
| Kafka | 9092 | TCP | Message streaming |
| Prometheus | 9090 | TCP | Metrics collection |
| Grafana | 3000 | TCP | Metrics visualization |

---

## Application Protocols — Deep Reference

### DNS Record Types (Quick Reference)

| Type | Value | Example |
|------|-------|---------|
| A | IPv4 address | `example.com → 93.184.216.34` |
| AAAA | IPv6 address | `example.com → 2606:2800::1` |
| CNAME | Canonical name | `www.example.com → example.com` |
| MX | Mail exchanger | priority + hostname |
| TXT | Text record | SPF, DKIM, DMARC, verification |
| NS | Nameserver | delegates zone authority |
| PTR | Reverse lookup | `34.216.184.93.in-addr.arpa → example.com` |
| SOA | Start of Authority | zone serial, refresh, TTL |
| SRV | Service location | `_http._tcp.example.com 10 1 80 www.example.com` |
| CAA | Cert Authority Auth | restrict which CAs can issue certs |

### ICMP Type/Code Reference

| Type | Code | Meaning |
|------|------|---------|
| 0 | 0 | Echo Reply (ping reply) |
| 3 | 0 | Destination Network Unreachable |
| 3 | 1 | Destination Host Unreachable |
| 3 | 3 | Destination Port Unreachable |
| 3 | 4 | Fragmentation Needed (PMTUD) |
| 5 | 0 | Redirect: Network |
| 8 | 0 | Echo Request (ping) |
| 11 | 0 | TTL Exceeded (traceroute response) |
| 12 | 0 | Parameter Problem |

### TCP Flags Cheat Sheet

| Flag | Hex | Meaning |
|------|-----|---------|
| FIN | 0x01 | Finish — graceful close |
| SYN | 0x02 | Synchronize — connection start |
| RST | 0x04 | Reset — immediate abort |
| PSH | 0x08 | Push — deliver to app immediately |
| ACK | 0x10 | Acknowledge |
| URG | 0x20 | Urgent pointer valid |
| ECE | 0x40 | ECN-Echo |
| CWR | 0x80 | Congestion Window Reduced |

Common combinations:
- `SYN` — first packet of handshake
- `SYN+ACK` — server response
- `ACK` — data acknowledgment
- `FIN+ACK` — graceful close with ack
- `RST+ACK` — reset response

---

## IP Protocol Numbers

| Number | Protocol | Notes |
|--------|---------|-------|
| 1 | ICMP | Internet Control Message Protocol |
| 2 | IGMP | Multicast group management |
| 6 | TCP | Transmission Control Protocol |
| 17 | UDP | User Datagram Protocol |
| 41 | IPv6 encapsulation | IPv6-in-IPv4 tunnel |
| 47 | GRE | Generic Routing Encapsulation |
| 50 | ESP | IPsec Encrypted Payload |
| 51 | AH | IPsec Authentication Header |
| 58 | ICMPv6 | IPv6 control messages |
| 89 | OSPF | Open Shortest Path First |
| 132 | SCTP | Stream Control Transmission Protocol |

---

## BPF / pcap Filter Syntax

Used by pktana and tcpdump/Wireshark. Filters are BPF (Berkeley Packet Filter) expressions.

### Basic Filters

```
# By protocol
tcp           # all TCP traffic
udp           # all UDP traffic
icmp          # all ICMP
arp           # all ARP

# By host
host 192.168.1.1          # src or dst is this IP
src host 10.0.0.1         # source IP
dst host 8.8.8.8          # destination IP

# By network
net 192.168.0.0/24        # src or dst in this subnet
src net 10.0.0.0/8

# By port
port 80                   # src or dst port 80
src port 12345
dst port 443
portrange 8000-8999       # port range

# By MAC (Layer 2)
ether host aa:bb:cc:dd:ee:ff
ether broadcast

# By packet size
less 128                  # packets ≤ 128 bytes
greater 1400              # packets > 1400 bytes

# Ethernet type
ether proto 0x0800        # IPv4
ether proto 0x86DD        # IPv6
```

### Compound Filters

```
# Combine with and/or/not
tcp and port 443
tcp and (port 80 or port 443)
not port 22
host 10.0.0.1 and not port 22

# Specific TCP flags
tcp[tcpflags] & tcp-syn != 0              # has SYN flag
tcp[tcpflags] == tcp-syn                  # only SYN (start of handshake)
tcp[tcpflags] == (tcp-syn|tcp-ack)        # SYN+ACK

# ICMP type
icmp[icmptype] == icmp-echo               # ping requests only
icmp[icmptype] == icmp-echoreply          # ping replies

# Match HTTP GET
tcp[((tcp[12:1] & 0xf0) >> 2):4] == 0x47455420  # "GET "
```

---

## pktana Quick Reference

```bash
pktana capture --interface eth0 --count 100
pktana capture --interface eth0 --filter "tcp port 443" --count 50
pktana connections          # active TCP/UDP connections
pktana routes               # routing table
pktana nic list             # network interfaces
pktana nic stats eth0       # detailed NIC statistics
pktana dp m1                # dataplane (XDP) status
pktana flow --interface eth0 # flow capture and analysis
pktana web --port 8080      # launch Web UI
pktana mcp --port 3456      # launch MCP server for AI agents
```

---

## Summary

This reference covers the most commonly encountered protocols and their parameters. When you see an unfamiliar protocol number, EtherType, or port in pktana, come back here to identify it.

**Next:** [Modern Networking](12-modern-networking.md) — SDN, cloud networking, containers, and what comes next
