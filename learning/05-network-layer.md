# Layer 3 — The Network Layer

The Network Layer is responsible for **routing packets across multiple networks** to reach any destination on Earth (or beyond). While Layer 2 delivers frames within one LAN, Layer 3 delivers packets between LANs.

The dominant Layer 3 protocol is **IP (Internet Protocol)**.

---

## IP Addresses

Every device on the internet has an **IP address** — a logical address assigned in software (unlike MAC addresses, which are hardware-burned).

### IPv4

A 32-bit address written as four decimal octets: `192.168.1.100`

Total possible addresses: 2³² ≈ **4.3 billion** — not enough for the modern world (hence IPv6).

### IPv6

A 128-bit address written as eight groups of 4 hex digits: `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
Shortened: `2001:db8:85a3::8a2e:370:7334`

Total addresses: 2¹²⁸ ≈ 340 undecillion — effectively unlimited.

---

## Subnetting: Dividing IP Space

A **subnet** is a logical subdivision of an IP network. Subnetting lets you:
- Assign different address blocks to different departments/zones
- Control broadcast domains
- Improve security through isolation

### CIDR Notation

`192.168.1.0/24` — the `/24` means the first 24 bits are the **network portion**; the remaining 8 bits are the **host portion**.

| CIDR | Subnet Mask     | Hosts Available |
|------|----------------|----------------|
| /8   | 255.0.0.0      | 16,777,214     |
| /16  | 255.255.0.0    | 65,534         |
| /24  | 255.255.255.0  | 254            |
| /28  | 255.255.255.240| 14             |
| /30  | 255.255.255.252| 2              |
| /31  | 255.255.255.254| 2 (RFC 3021, point-to-point) |
| /32  | 255.255.255.255| 1 (single host route) |

### Private Addresses (RFC 1918)
These ranges are for use inside private networks and are **never routed** on the public internet:

| Range | CIDR | Use |
|-------|------|-----|
| 10.0.0.0–10.255.255.255 | 10.0.0.0/8 | Large enterprises |
| 172.16.0.0–172.31.255.255 | 172.16.0.0/12 | Medium |
| 192.168.0.0–192.168.255.255 | 192.168.0.0/16 | Home networks |

---

## The IPv4 Header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Key fields:
- **TTL (Time to Live)** — decremented by 1 at each router hop; packet is dropped at 0 (prevents infinite loops)
- **Protocol** — identifies the Layer 4 payload: `6` = TCP, `17` = UDP, `1` = ICMP
- **Source/Destination Address** — 32-bit IPv4 addresses

---

## Routing: How Packets Find Their Way

A **router** is a Layer 3 device. It has multiple interfaces (each on a different network) and a **routing table** that says: *"to reach network X, send the packet out interface Y, toward next-hop Z."*

### Routing Table

```
Destination       Gateway       Interface  Metric
0.0.0.0/0         10.0.0.1      eth0       100     ← default route
10.0.0.0/24       0.0.0.0       eth0       0       ← directly connected
192.168.1.0/24    10.0.0.5      eth0       10      ← static/learned route
```

### Longest Prefix Match

When multiple routes match, the router picks the **most specific** (longest prefix):
- Packet to `192.168.1.50` matches both `0.0.0.0/0` and `192.168.1.0/24`
- `/24` is longer → router uses the `192.168.1.0/24` route

### Default Route
`0.0.0.0/0` matches **everything**. If no more-specific route exists, the packet goes here (usually toward the ISP).

---

## Routing Protocols

Instead of configuring every route by hand, routers exchange routing information automatically.

### Interior Gateway Protocols (IGP) — within an organization

| Protocol | Type | Algorithm | Use Case |
|---------|------|-----------|---------|
| RIP v2  | Distance-vector | Bellman-Ford | Small, old networks |
| OSPF    | Link-state | Dijkstra SPF | Enterprise networks |
| EIGRP   | Hybrid | DUAL | Cisco networks |
| IS-IS   | Link-state | Dijkstra SPF | Service providers, data centers |

### Exterior Gateway Protocol (EGP) — between organizations

| Protocol | Use |
|---------|-----|
| BGP (Border Gateway Protocol) | The routing protocol of the Internet. Connects Autonomous Systems (ASes). Every ISP, CDN, and large enterprise uses BGP. |

---

## NAT — Network Address Translation

Private IP addresses can't be routed on the internet. **NAT** solves this by translating private addresses to a public address (usually the router's WAN IP).

**NAPT (PAT)** — the most common form: maps many private IPs + ports to one public IP + different ports.

```
Private: 192.168.1.100:5432 → NAT → Public: 203.0.113.1:40001
Private: 192.168.1.101:5433 → NAT → Public: 203.0.113.1:40002
```

Outgoing: swap private IP:port with public IP:port
Incoming: reverse the mapping, forward to original private host

---

## ICMP — Internet Control Message Protocol

ICMP is a Layer 3 utility protocol used by IP itself for error reporting and diagnostics.

Common messages:
- **Echo Request / Echo Reply** — `ping`
- **Destination Unreachable** — router can't forward packet; includes reason (port unreachable, network unreachable, fragmentation needed)
- **Time Exceeded** — TTL reached 0 (used by `traceroute`)
- **Redirect** — router tells host of a better route

---

## Fragmentation

IPv4 allows routers to **fragment** packets that are larger than the next link's MTU. The receiving host reassembles them using:
- **Identification** field (same for all fragments of one original packet)
- **Fragment Offset** field (position in original packet)
- **More Fragments (MF) flag** (0 on the last fragment)

> IPv6 does **not** allow intermediate routers to fragment. Senders must discover the path MTU and fragment themselves before sending.

---

## Try It With pktana

```bash
# View your routing table
pktana routes

# Capture and filter only ICMP (ping/traceroute)
pktana capture --interface eth0 --filter "icmp" --count 20

# See all active connections with remote IPs
pktana connections
```

In the pktana Web UI, expand any IP packet to see:
- **Version**, **TTL**, **Protocol** number
- **Source and Destination IP** with ASN/geolocation lookup
- **DSCP / ToS** (quality of service markings)
- **Fragment** flags and offset

---

## Summary

- Layer 3 routes packets between networks using **IP addresses**
- **Subnetting** (CIDR) divides IP space into manageable blocks
- **Routers** use routing tables and **longest-prefix match** to forward packets
- **NAT** lets many private hosts share a single public IP
- **ICMP** provides network diagnostics (ping, traceroute, error messages)

**Next:** [Layer 4 — Transport](06-transport-layer.md) — TCP, UDP, and reliable delivery
