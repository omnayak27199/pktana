# Layer 3 — The Network Layer

The Network Layer is responsible for **routing packets from any source to any destination across one or many networks**. While the Data Link Layer handles delivery within a single network segment, the Network Layer handles delivery between segments — across cities, countries, or the entire Internet.

Key responsibilities:
- **Logical addressing** — IP addresses identify every device uniquely across all networks
- **Packet forwarding** — moving packets hop-by-hop toward their destination
- **Routing** — determining the best path through the network
- **Encapsulation** — wrapping Transport Layer segments in IP packets with source and destination addresses
- **Fragmentation (IPv4)** — breaking large packets into smaller pieces when necessary

The dominant Network Layer protocol is **IP (Internet Protocol)** in two versions: IPv4 and IPv6.

---

## The Internet Protocol (IP)

IP is a **best-effort, connectionless** protocol. It makes no guarantees about delivery, ordering, or error correction. Each packet is treated independently — different packets between the same source and destination may take different routes through the network. Reliability, ordering, and retransmission are the job of the Transport Layer (TCP).

IP provides two things:
1. A **logical addressing scheme** — IP addresses identify devices and networks
2. A **delivery mechanism** — routers use IP addresses to forward packets toward the destination

---

## IPv4 Addressing

An IPv4 address is a **32-bit number** written as four decimal octets separated by dots: `192.168.1.100`. Each octet represents 8 bits (0–255).

Total IPv4 address space: 2³² = **4,294,967,296** (~4.3 billion) addresses. The Internet exhausted the free pool of public IPv4 addresses in 2011. NAT and IPv6 are the responses.

### Classful Addressing (Historical)

Before CIDR, IPv4 was divided into address classes based on the first octet:

| Class | First Octet | Default Mask | Hosts Per Network | Purpose |
|-------|-------------|-------------|------------------|---------|
| **A** | 1–126 | /8 | 16,777,214 | Large organisations |
| **B** | 128–191 | /16 | 65,534 | Medium organisations |
| **C** | 192–223 | /24 | 254 | Small networks |
| **D** | 224–239 | — | — | Multicast |
| **E** | 240–255 | — | — | Reserved/experimental |

Classful addressing is obsolete — it wasted enormous amounts of address space (a Class B assignment gave 65,534 addresses even to a company that needed 500). CIDR replaced it.

> 127.x.x.x is the loopback range (localhost); not a valid Class A network.

### CIDR — Classless Inter-Domain Routing

CIDR (RFC 1519) allows any prefix length, not just /8, /16, /24. The prefix length specifies how many bits are the **network portion**; the remaining bits are the **host portion**.

Notation: `192.168.1.0/24` — 24 network bits, 8 host bits.

**Subnet mask** is the CIDR prefix expressed in dotted decimal:
- /24 = `255.255.255.0` (24 ones followed by 8 zeros)
- /25 = `255.255.255.128`
- /30 = `255.255.255.252`

**Key formulas:**
- **Number of hosts** = 2^(host bits) − 2 (subtract network address and broadcast address)
- **Network address** = IP address AND subnet mask (all host bits = 0)
- **Broadcast address** = network address OR inverse mask (all host bits = 1)
- **First usable host** = network address + 1
- **Last usable host** = broadcast address − 1

### Subnetting Reference Table

| CIDR | Subnet Mask | # Hosts | Notes |
|------|-------------|---------|-------|
| /8 | 255.0.0.0 | 16,777,214 | Large Class A private |
| /16 | 255.255.0.0 | 65,534 | Large LAN / Class B private |
| /24 | 255.255.255.0 | 254 | Standard office LAN |
| /25 | 255.255.255.128 | 126 | Split a /24 in half |
| /26 | 255.255.255.192 | 62 | Quarter of a /24 |
| /27 | 255.255.255.224 | 30 | Eighth of a /24 |
| /28 | 255.255.255.240 | 14 | Small segment |
| /29 | 255.255.255.248 | 6 | Tiny segment |
| /30 | 255.255.255.252 | 2 | Point-to-point router links |
| /31 | 255.255.255.254 | 2 | P2P (no broadcast, RFC 3021) |
| /32 | 255.255.255.255 | 1 | Single host route / loopback |

### VLSM — Variable Length Subnet Masking

VLSM allows using different prefix lengths for different subnets within the same address block. Instead of dividing `192.168.10.0/24` into equal /26 subnets, you assign:
- `192.168.10.0/25` (126 hosts) — large department
- `192.168.10.128/27` (30 hosts) — small team
- `192.168.10.160/30` (2 hosts) — router-to-router link

VLSM maximises efficient use of IP address space by matching each subnet's size to actual need.

### Special IPv4 Addresses

| Range | Purpose | Notes |
|-------|---------|-------|
| `10.0.0.0/8` | Private (RFC 1918) | Largest private block |
| `172.16.0.0/12` | Private (RFC 1918) | 172.16.0.0–172.31.255.255 |
| `192.168.0.0/16` | Private (RFC 1918) | Most common home/office range |
| `127.0.0.0/8` | Loopback | 127.0.0.1 = localhost; never routes |
| `169.254.0.0/16` | Link-local (APIPA) | Self-assigned when DHCP fails |
| `0.0.0.0/0` | Default route | Matches any destination |
| `255.255.255.255` | Limited broadcast | Sent to all on local subnet |
| `224.0.0.0/4` | Multicast | D-class; group delivery |
| `100.64.0.0/10` | Shared address space | Carrier-Grade NAT (RFC 6598) |

Private addresses (RFC 1918) are **never routed on the public Internet**. Billions of devices use `192.168.x.x` behind NAT.

---

## The IPv4 Packet Header

The IPv4 header is **20 bytes minimum** (up to 60 bytes with options).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌─────────┬─────────┬───────────────────────────────────────────┐
│ Version │   IHL   │     DSCP / ToS       │   Total Length     │
├─────────┴─────────┴──────────────────────┴────────────────────┤
│          Identification          │ Flags │  Fragment Offset    │
├──────────────────────────────────┴───────┴────────────────────┤
│    TTL   │  Protocol  │            Header Checksum            │
├──────────┴────────────┴───────────────────────────────────────┤
│                       Source IP Address                       │
├───────────────────────────────────────────────────────────────┤
│                    Destination IP Address                     │
└───────────────────────────────────────────────────────────────┘
```

| Field | Bits | Purpose |
|-------|------|---------|
| **Version** | 4 | IP version number: 4 for IPv4 |
| **IHL** | 4 | Internet Header Length in 32-bit words (min 5 = 20 bytes) |
| **DSCP/TOS** | 8 | Differentiated Services Code Point — QoS markings (EF, AF, CS) |
| **Total Length** | 16 | Total size of IP packet (header + data), max 65,535 bytes |
| **Identification** | 16 | Unique ID for all fragments of the same original datagram |
| **Flags** | 3 | Bit 1: DF (Don't Fragment); Bit 2: MF (More Fragments follow) |
| **Fragment Offset** | 13 | Position of fragment in original datagram (units of 8 bytes) |
| **TTL** | 8 | Time To Live — decremented by 1 at each router hop; dropped at 0 |
| **Protocol** | 8 | Upper-layer protocol: 1=ICMP, 6=TCP, 17=UDP, 89=OSPF |
| **Header Checksum** | 16 | Checksum of IPv4 header only (not payload) |
| **Source Address** | 32 | Sender's IP address |
| **Destination Address** | 32 | Recipient's IP address |

### TTL — Time To Live

TTL prevents packets from circling indefinitely. Each router that processes the packet **decrements TTL by 1**. When TTL reaches 0, the router discards the packet and sends an ICMP "Time Exceeded" message back to the source.

Default TTL values:
| OS / Device | Default TTL |
|-------------|------------|
| Linux | 64 |
| Windows | 128 |
| Cisco IOS router | 255 |
| macOS | 64 |

`ping` and `traceroute` use TTL to probe the network. `traceroute` sends packets with TTL=1, 2, 3... — each router that drops a packet reveals its IP through the ICMP Time Exceeded reply.

---

## IPv6 Addressing

IPv6 addresses the fundamental exhaustion of IPv4. An IPv6 address is **128 bits**, written as eight groups of four hexadecimal digits separated by colons: `2001:0db8:85a3:0000:0000:8a2e:0370:7334`

Total address space: 2¹²⁸ ≈ **3.4 × 10³⁸** — approximately 50 octillion addresses per person on Earth. Practically unlimited.

### IPv6 Address Shortening Rules

1. **Remove leading zeros** in any group: `0db8` → `db8`, `0000` → `0`
2. **Replace one or more consecutive all-zero groups with `::`** (can only be used once per address to avoid ambiguity)

Examples:
- `2001:0db8:0000:0000:0000:0000:0000:0001` → `2001:db8::1`
- `fe80:0000:0000:0000:0215:5dff:fe00:1234` → `fe80::215:5dff:fe00:1234`
- Loopback: `0000:0000:0000:0000:0000:0000:0000:0001` → `::1`

### IPv6 Address Types

| Type | Prefix | Scope | Purpose |
|------|--------|-------|---------|
| **Global Unicast** | `2000::/3` | Global (Internet) | Routable on the Internet (starts with 2 or 3) |
| **Link-Local Unicast** | `FE80::/10` | Single link | Auto-configured; used for router communication; never routed |
| **Unique Local** | `FC00::/7` | Organisation | Private IPv6 equivalent of RFC 1918 |
| **Loopback** | `::1` | This host | Equivalent of 127.0.0.1 |
| **Multicast** | `FF00::/8` | Variable | Replaces broadcast; FF02::1 = all nodes, FF02::2 = all routers |
| **Anycast** | (any unicast) | Nearest node | Same address assigned to multiple nodes; routed to nearest |

IPv6 has **no broadcast**. Broadcast is replaced by specific multicast groups.

### IPv6 vs IPv4 Key Differences

| Feature | IPv4 | IPv6 |
|---------|------|------|
| Address size | 32 bits | 128 bits |
| Header size | 20–60 bytes (variable) | 40 bytes (fixed) |
| Fragmentation | Routers and hosts | Hosts only (Path MTU Discovery) |
| Broadcast | Yes | No (replaced by multicast) |
| ARP | Yes | No (NDP replaces it) |
| Auto-configuration | DHCP or manual | SLAAC (automatic) |
| Header checksum | Yes | No (removed for efficiency) |
| IPsec | Optional | Built-in (mandatory in spec) |
| NAT | Common (due to shortage) | Not needed (enough addresses) |

### Neighbour Discovery Protocol (NDP)

NDP (RFC 4861) replaces both ARP and some ICMP functions for IPv6. It uses **ICMPv6** messages and works on the local link.

| NDP Message | ICMPv6 Type | Purpose | ARP Equivalent |
|-------------|------------|---------|---------------|
| **Neighbour Solicitation (NS)** | 135 | "Who has this IPv6 address?" | ARP Request |
| **Neighbour Advertisement (NA)** | 136 | "I have it — here is my MAC" | ARP Reply |
| **Router Solicitation (RS)** | 133 | "Any routers on this link?" | — |
| **Router Advertisement (RA)** | 134 | "I am a router; here is the prefix" | — |
| **Redirect** | 137 | "Use a better first-hop router" | ICMP Redirect |

### SLAAC — Stateless Address Autoconfiguration

SLAAC (RFC 4862) allows an IPv6 host to configure its own global address without DHCP:

1. The host generates a link-local address (`FE80::/10`) from its MAC address using EUI-64, or randomly (Privacy Extensions).
2. The host sends a **Router Solicitation (RS)** to the all-routers multicast address (`FF02::2`).
3. The router replies with a **Router Advertisement (RA)** containing the network prefix (e.g., `2001:db8:1::/64`).
4. The host combines the prefix with its interface ID (MAC-derived or random) to form its global address.
5. The host performs **Duplicate Address Detection (DAD)** — sends a Neighbour Solicitation for its own address; if someone replies, the address is in use.

SLAAC is stateless — the router does not track which address each host uses. For DNS server assignment, DHCPv6 or RA with RDNSS option is needed.

---

## IP Routing

### How a Router Forwards Packets

A router is a Layer 3 device with multiple interfaces, each connected to a different network. When a packet arrives:

1. **Strip the incoming Ethernet frame** — the Data Link frame is discarded; the IP packet is extracted.
2. **Read the destination IP address** from the IP header.
3. **Look up the routing table** using **longest prefix match**.
4. **Decrement the TTL** by 1. If TTL = 0, discard and send ICMP "Time Exceeded" to source.
5. **Recalculate the IP header checksum** (TTL changed).
6. **Determine the next hop** and the outgoing interface.
7. **ARP for the next-hop MAC** if not already cached.
8. **Build a new Ethernet frame** with the router's outgoing MAC as source and the next-hop MAC as destination.
9. **Transmit the new frame** out the outgoing interface.

The IP addresses in the packet never change across hops. The MAC addresses change at every hop.

### The Routing Table

Each router maintains a routing table — a list of known networks and how to reach them.

```
Destination       Next Hop        Interface   Metric   Source
──────────────────────────────────────────────────────────────
0.0.0.0/0         10.0.0.1        Gi0/0       1        Static
10.0.0.0/24       directly conn.  Gi0/0       0        Connected
192.168.1.0/24    10.0.0.5        Gi0/0       110      OSPF
172.16.0.0/16     10.0.0.10       Gi0/1       20       EIGRP
```

Routes come from three sources:
- **Directly connected** — networks attached to the router's own interfaces (automatically added)
- **Static routes** — manually configured by an administrator
- **Dynamic routing protocols** — learned automatically from neighbouring routers (OSPF, BGP, EIGRP)

### Longest Prefix Match (LPM)

When multiple routing table entries match a destination IP, the router always selects the **most specific match** — the entry with the longest prefix (highest /number):

```
Packet destined for 192.168.1.50:
  Matches: 0.0.0.0/0      (default route, /0 prefix — matches everything)
  Matches: 192.168.0.0/16 (larger block)
  Matches: 192.168.1.0/24 (most specific — USE THIS)

Result: forward via the /24 route
```

The default route (`0.0.0.0/0`) is the **least specific** — it matches any address. If no more specific route matches, traffic uses the default route (typically toward the ISP or upstream router).

### Administrative Distance

When a router learns the same destination from multiple routing sources, **Administrative Distance (AD)** determines which source wins. Lower AD = more trusted.

| Source | Administrative Distance |
|--------|------------------------|
| Connected interface | 0 |
| Static route | 1 |
| EIGRP (summary) | 5 |
| BGP (eBGP) | 20 |
| EIGRP (internal) | 90 |
| OSPF | 110 |
| IS-IS | 115 |
| RIP v2 | 120 |
| BGP (iBGP) | 200 |

AD is a local parameter — it never appears in routing protocol messages. It only matters when the same prefix is learned from two different sources on the same router.

---

## Static Routing

Static routes are manually configured entries in the routing table. The administrator specifies exactly which network to route via which next hop.

```bash
# Cisco IOS
ip route 192.168.2.0 255.255.255.0 10.0.0.5   # via next-hop IP
ip route 192.168.2.0 255.255.255.0 Gi0/1       # via outgoing interface
ip route 0.0.0.0 0.0.0.0 10.0.0.1              # default route

# Linux
ip route add 192.168.2.0/24 via 10.0.0.5
ip route add default via 10.0.0.1
```

**Advantages:** simple, predictable, no routing protocol overhead, no CPU for route calculation.

**Disadvantages:** does not scale, no automatic failover, administrative burden on large networks.

**Floating static route:** a static route with a higher AD than a dynamic protocol. It is only used if the dynamic route disappears (failover). Example: set AD=150 on a static route behind a dynamic OSPF route (AD=110).

---

## Dynamic Routing Protocols

Dynamic routing protocols allow routers to **automatically exchange routing information** and adapt to topology changes without manual intervention.

### Interior Gateway Protocols (IGP)

Used within a single **Autonomous System (AS)** — one organisation's network.

#### RIP — Routing Information Protocol

RIP (RFC 2453) is a **distance-vector** protocol — each router knows only the distance (hop count) to each destination and the direction (which neighbour to use), without a full topology map.

- **Metric:** hop count. Maximum 15 hops. 16 = unreachable. This limits RIP to small networks.
- **Updates:** sends complete routing table to neighbours every **30 seconds** via UDP broadcast/multicast (255.255.255.255 or 224.0.0.9 for RIPv2)
- **Convergence:** slow. Can take minutes after a topology change (route poisoning, split horizon, hold-down timers help prevent routing loops but add delay)
- **Algorithm:** Bellman-Ford
- **RIPv1:** classful only, no VLSM. **RIPv2:** classless, supports VLSM and CIDR, authentication.
- **Use today:** small legacy networks, lab environments.

#### OSPF — Open Shortest Path First

OSPF (RFC 2328) is a **link-state** protocol — each router builds a complete map of the network topology and independently calculates the best path using Dijkstra's algorithm.

**How OSPF works:**
1. Routers form **neighbour adjacencies** by exchanging Hello packets (multicast 224.0.0.5)
2. Neighbours exchange **LSAs (Link State Advertisements)** describing their connected links and neighbours
3. Every router builds an identical **LSDB (Link State Database)** containing the full topology
4. Each router independently runs **Dijkstra's SPF (Shortest Path First)** algorithm to calculate the best path to every destination
5. Best paths are installed in the routing table

**OSPF areas:** large networks are divided into areas to limit LSA flooding. All areas must connect to **Area 0 (backbone area)**. Routers on area boundaries are **ABRs (Area Border Routers)**.

**OSPF metric (cost):** calculated as reference bandwidth / interface bandwidth. Default reference = 100 Mbps. A 1 Gbps interface has cost 1; a 100 Mbps interface has cost 1 (same — reference must be raised on modern networks).

**DR/BDR election:** on multi-access networks (Ethernet), OSPF elects a **Designated Router (DR)** and **Backup DR (BDR)** to reduce LSA flooding. All other routers form adjacencies only with the DR/BDR, not with each other.

**OSPF router types:**
- **Internal router** — all interfaces in one area
- **ABR (Area Border Router)** — connects two or more areas; summarises routes between areas
- **ASBR (Autonomous System Boundary Router)** — redistributes routes from outside OSPF (BGP, EIGRP, static)
- **Backbone router** — at least one interface in Area 0

**Convergence:** fast — seconds after a topology change.

#### EIGRP — Enhanced Interior Gateway Routing Protocol

EIGRP (Cisco-proprietary, though now documented in RFC 7868) is an **advanced distance-vector** protocol. It uses the **DUAL (Diffusing Update Algorithm)** to guarantee loop-free paths and fast convergence without a full topology map.

- **Metric:** composite — bandwidth and delay by default (also reliability, load, MTU optionally)
- **Updates:** partial updates sent only when topology changes (not periodic full tables)
- **Convergence:** very fast — maintains backup routes (Feasible Successors) that are instantly used if the primary fails
- **Neighbour relationships:** adjacencies via Hello packets; only neighbours receive updates
- **Use:** Cisco-only environments; still widely deployed in enterprise networks

#### IS-IS — Intermediate System to Intermediate System

IS-IS is a link-state IGP similar to OSPF but older. Originally designed for ISO's CLNS protocol and adapted for IP. Widely used by **service providers** (ISPs, carriers) and **large data centre fabrics** due to its scalability and flexibility.

### Exterior Gateway Protocols (EGP)

Used between **different Autonomous Systems** — between ISPs, between an enterprise and its ISP, between large content providers.

#### BGP — Border Gateway Protocol

BGP (RFC 4271) is the **routing protocol of the Internet**. Every ISP, CDN, content provider, and large enterprise connecting to multiple ISPs runs BGP. It is the protocol that enables the global Internet routing table (~900,000+ routes).

**BGP characteristics:**
- **Path-vector protocol** — carries the full AS path to each destination (AS_PATH attribute)
- **Uses TCP port 179** — reliable, so BGP does not need its own reliability mechanism
- **Policy-based** — routing decisions are based on operator policies, not just fastest path
- **Two types:**
  - **eBGP (external BGP)** — between different Autonomous Systems (AD = 20)
  - **iBGP (internal BGP)** — within the same AS (AD = 200)

**BGP path selection order** (when multiple paths to the same destination exist):
1. Highest **Weight** (Cisco local attribute)
2. Highest **LOCAL_PREF** (prefer exit from this AS)
3. Locally originated routes
4. Shortest **AS_PATH** (fewest hops through other ASes)
5. Lowest **Origin** (IGP < EGP < Incomplete)
6. Lowest **MED** (Multi-Exit Discriminator — prefer this entry point)
7. **eBGP over iBGP**
8. Lowest IGP metric to next-hop
9. Lowest Router ID

**Autonomous System Numbers (ASN):** 1–64511 are public (registered with IANA); 64512–65535 are private. 4-byte ASNs (32-bit) support ~4 billion ASNs total.

---

## NAT — Network Address Translation

NAT allows many devices with private RFC 1918 addresses to share a single (or small pool of) public IP address(es), extending the life of IPv4.

### NAT Types

**Static NAT (1:1):** one private IP permanently maps to one public IP. Used for servers that must be reachable from the Internet under a fixed public address.

**Dynamic NAT (pool):** a pool of public IPs is shared. As hosts initiate outbound connections, they are temporarily assigned a public IP from the pool. Less common than PAT.

**PAT — Port Address Translation (NAT Overload):** many private IPs share a single public IP, differentiated by different source port numbers. This is what virtually all home routers use. Also called NAPT or NAT Overload.

```
Private side:                 NAT Translation Table:          Public side:
192.168.1.10:52001 ────────── 192.168.1.10:52001 ↔ 203.0.113.1:40001 ──────► Internet
192.168.1.11:52002 ────────── 192.168.1.11:52002 ↔ 203.0.113.1:40002 ──────► Internet
192.168.1.12:52003 ────────── 192.168.1.12:52003 ↔ 203.0.113.1:40003 ──────► Internet
```

Outgoing packets: NAT replaces the private src IP:port with the public IP + a unique port.
Incoming packets: NAT reverses the translation to deliver the reply to the correct private host.

**NAT limitations:**
- Breaks **end-to-end connectivity** — external devices cannot initiate connections to NATted hosts (requires port forwarding rules)
- Complicates protocols that embed IP addresses in the payload (SIP, FTP active mode)
- Adds processing overhead at the router
- Makes troubleshooting harder

---

## ICMP — Internet Control Message Protocol

ICMP (RFC 792) is a Layer 3 utility protocol used by IP itself for diagnostics and error reporting. It runs directly over IP (Protocol field = 1).

### Common ICMP Messages

| Type | Code | Message | Used By |
|------|------|---------|---------|
| 0 | 0 | Echo Reply | `ping` response |
| 3 | 0 | Destination Unreachable: Network | |
| 3 | 1 | Destination Unreachable: Host | |
| 3 | 3 | Destination Unreachable: Port | Firewall or closed port |
| 3 | 4 | Fragmentation Needed, DF bit set | Path MTU Discovery |
| 5 | 0/1 | Redirect | Better route available |
| 8 | 0 | Echo Request | `ping` |
| 11 | 0 | Time Exceeded: TTL = 0 | `traceroute` |
| 11 | 1 | Time Exceeded: Fragment reassembly | |

### ping

`ping` sends ICMP Echo Requests (type 8) and expects Echo Replies (type 0). Tests basic Layer 3 reachability and measures round-trip time. If `ping` succeeds to an IP address but the hostname fails to resolve, the problem is DNS, not network connectivity.

### traceroute

`traceroute` maps the hop-by-hop path to a destination by exploiting TTL:
- Send a packet with TTL=1 → first router drops it → sends ICMP Time Exceeded → reveals router's IP
- Send with TTL=2 → second router drops → reveals its IP
- Continue until destination is reached

```bash
traceroute google.com          # Linux (UDP probes by default)
traceroute -I google.com       # Linux (ICMP mode)
tracert google.com             # Windows (ICMP)
```

### Path MTU Discovery (PMTUD)

PMTUD finds the largest packet size that can traverse the entire path without fragmentation:
1. Sender sets the **DF (Don't Fragment)** bit and sends at the largest possible size
2. If any router on the path cannot forward the packet without fragmenting, it returns ICMP type 3 code 4 ("Fragmentation Needed") with the next-hop's MTU
3. Sender reduces packet size to fit and retries

PMTUD failure (when firewalls block ICMP type 3 code 4) causes "black holes" — large packets are silently dropped, breaking applications that send large payloads while small packets work fine.

---

## IP Fragmentation

If an IPv4 packet is larger than the next link's MTU, and the DF bit is not set, the router **fragments** the packet into smaller pieces.

Each fragment is an independent IP packet with:
- Same **Identification** field — marks all fragments as belonging to the same original datagram
- **Fragment Offset** — byte position of this fragment in the original datagram (units of 8 bytes)
- **MF (More Fragments) bit** = 1 on all fragments except the last

Reassembly happens **only at the final destination**, not at intermediate routers.

**IPv6 does not allow fragmentation at routers.** Only the source host can fragment, and only after performing Path MTU Discovery.

---

## DHCP — Dynamic Host Configuration Protocol

DHCP (RFC 2131) automatically assigns IP addresses and network configuration to hosts. It runs over UDP — client uses port 68, server uses port 67.

### DORA Process

| Step | Message | Direction | Content |
|------|---------|-----------|---------|
| **D**iscover | DHCPDISCOVER | Client → Broadcast | "I need an IP address" |
| **O**ffer | DHCPOFFER | Server → Client | "Here is 192.168.1.50 for 24 hours, GW=.1, DNS=8.8.8.8" |
| **R**equest | DHCPREQUEST | Client → Broadcast | "I accept 192.168.1.50 from this server" |
| **A**cknowledge | DHCPACK | Server → Client | "Confirmed. Here is your full configuration" |

The Request is broadcast (not unicast) so other DHCP servers that also sent offers know which one was chosen.

**DHCP Lease:** the assigned IP has a time limit. The client renews at 50% of lease time (T1), or attempts other servers at 87.5% (T2), or falls back to DORA if both fail.

**DHCP Relay Agent:** DHCP uses broadcasts which routers do not forward. A relay agent (configured on the router interface facing clients with `ip helper-address <server-IP>`) converts the broadcast to a unicast and forwards it to the DHCP server, allowing one server to serve multiple subnets.

---

## Summary

- Layer 3 routes packets between networks using **logical IP addresses** (not hardware MAC addresses)
- **IPv4** is 32-bit with ~4.3B addresses; **IPv6** is 128-bit with effectively unlimited addresses
- **CIDR** notation (e.g., /24) defines network vs host portions; **VLSM** assigns different prefix lengths per subnet
- **Routers** use routing tables and **longest-prefix match** to forward packets hop-by-hop
- **Static routing** is manual and simple; **dynamic protocols** (OSPF for enterprises, BGP for the Internet) learn routes automatically
- **NAT/PAT** maps many private IPs to one public IP, conserving IPv4 space
- **ICMP** provides diagnostics (ping, traceroute) and error messages (TTL exceeded, unreachable)
- **IPv6 NDP** replaces ARP; **SLAAC** allows automatic address assignment without DHCP

**Next:** [Layer 4 — Transport](06-transport-layer.md) — TCP, UDP, and reliable delivery
