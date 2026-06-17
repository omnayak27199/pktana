# Layer 2 — The Data Link Layer

The Data Link Layer takes the raw bit stream produced by the Physical Layer and organises it into structured **frames** for local delivery. It handles communication between devices on the **same physical network segment** — devices that are directly connected, or connected through switches.

Key responsibilities:
- **Framing** — packaging data into a defined structure with a header and trailer
- **Physical addressing** — MAC addresses identify devices within a network segment
- **Error detection** — CRC checksums catch transmission errors
- **Media access control** — rules for who can transmit on a shared medium
- **Hop-to-hop delivery** — delivering frames to the next device on the path (not end-to-end)

---

## The Two Sublayers of Data Link

The IEEE (Institute of Electrical and Electronics Engineers) divides the Data Link Layer into two sublayers:

### LLC — Logical Link Control (IEEE 802.2)

The LLC sublayer is the upper portion of Layer 2. It provides a consistent interface to Layer 3 regardless of the physical technology below it:

- **Multiplexing** — identifies which Layer 3 protocol (IPv4, IPv6, ARP) is carried inside the frame, so the receiver knows how to process the payload
- **Flow control** — basic mechanism to prevent overwhelming the receiver (rarely used in modern Ethernet; TCP handles this at Layer 4)
- **Error notification** — alerts the upper layer that an error occurred (detection only; recovery is done by higher layers)

### MAC — Media Access Control

The MAC sublayer is the lower portion of Layer 2. It handles:

- **Framing** — assembles bits into frames with defined delimiters, header fields, and a trailer
- **Physical (MAC) addressing** — each frame carries a source and destination MAC address for local delivery
- **CRC / Frame Check Sequence** — a mathematical checksum appended to every frame to detect corruption in transit
- **Media access** — determines which device is allowed to transmit at any given time (CSMA/CD for wired Ethernet, CSMA/CA for Wi-Fi)

---

## The Ethernet Frame

Ethernet (IEEE 802.3) is the dominant Layer 2 protocol for wired networks. An Ethernet frame wraps an IP packet for delivery across one LAN segment.

```
┌──────────┬──────┬──────┬───────────┬──────────────────┬─────┐
│ Preamble │ Dst  │ Src  │ EtherType │    Payload       │ FCS │
│   7+1 B  │ MAC  │ MAC  │   2 B     │   46–1500 B      │ 4 B │
│          │  6 B │  6 B │           │                  │     │
└──────────┴──────┴──────┴───────────┴──────────────────┴─────┘
```

**Preamble (7 bytes):** alternating 1/0 bits (`10101010...`) that help the receiver synchronise its internal clock to the sender's bit rate.

**Start Frame Delimiter (1 byte):** `10101011` — signals the end of the preamble and the start of the actual frame content.

**Destination MAC Address (6 bytes):** the hardware address of the intended recipient on the local segment. The switch reads this to determine which port to forward the frame to.

**Source MAC Address (6 bytes):** the hardware address of the sender. The switch uses this to learn and update its MAC address table.

**EtherType (2 bytes):** identifies the Layer 3 protocol carried in the payload. Values ≥ 0x0600 indicate an EtherType. Common values:

| EtherType | Protocol |
|-----------|---------|
| 0x0800 | IPv4 |
| 0x86DD | IPv6 |
| 0x0806 | ARP |
| 0x8100 | 802.1Q VLAN tag |
| 0x8847 | MPLS unicast |
| 0x88CC | LLDP |

**Payload (46–1500 bytes):** the Layer 3 packet (IPv4 or IPv6 packet, or ARP message). If the data is shorter than 46 bytes, it is padded with zeros to reach the minimum. The maximum payload of 1500 bytes is the standard Ethernet **MTU (Maximum Transmission Unit)**.

**FCS — Frame Check Sequence (4 bytes):** a CRC-32 (Cyclic Redundancy Check) calculated over the entire frame. The receiver recalculates the CRC and compares it to the FCS field. If they do not match, the frame is silently discarded — the Data Link Layer detects the error but does not request retransmission (that is the job of TCP at Layer 4).

### Ethernet Frame Size Rules

| Frame Type | Size | Notes |
|-----------|------|-------|
| Minimum frame | 64 bytes | 6 + 6 + 2 + 46 payload + 4 FCS |
| Maximum frame | 1518 bytes | 1500 B payload + 18 B overhead |
| 802.1Q tagged | 1522 bytes | Standard + 4-byte VLAN tag |
| Jumbo frame | up to 9022 bytes | Must be configured on all devices in path |

Frames below 64 bytes are called **runts** — they indicate a collision occurred before the frame was fully transmitted. They are discarded. Frames above 1518 bytes (without jumbo support) are called **giants** and are also discarded.

---

## MAC Addresses

A **MAC (Media Access Control) address** is a 48-bit (6-byte) hardware address assigned to every network interface. It is also called the **BIA (Burned-In Address)** because it is programmed into the NIC by the manufacturer.

Written as six pairs of hexadecimal digits: `AA:BB:CC:DD:EE:FF`

```
┌────────────────────┬────────────────────┐
│  OUI  (first 3 B)  │  Device ID (3 B)   │
│  Manufacturer ID   │  Unique per device │
└────────────────────┴────────────────────┘
```

The **OUI (Organisationally Unique Identifier)** is the first 3 bytes, assigned to manufacturers by the IEEE. You can look up an OUI to identify the manufacturer of a device. For example, `00:50:56` belongs to VMware; `3C:22:FB` belongs to Apple.

The **last 3 bytes** are device-specific, assigned by the manufacturer to ensure each NIC has a globally unique address.

### MAC Address Types

| Type | Address Pattern | Meaning |
|------|----------------|---------|
| **Unicast** | Bit 0 of first byte = 0 | Destined for one specific device |
| **Multicast** | Bit 0 of first byte = 1 | Destined for a group of devices |
| **Broadcast** | `FF:FF:FF:FF:FF:FF` | Delivered to all devices on the segment |
| **IPv4 multicast** | `01:00:5E:xx:xx:xx` | Maps to IPv4 multicast group |
| **IPv6 multicast** | `33:33:xx:xx:xx:xx` | Maps to IPv6 multicast group |

The **broadcast MAC** (`FF:FF:FF:FF:FF:FF`) causes a switch to deliver the frame to every port on the VLAN. ARP requests use broadcast because the sender does not yet know the recipient's MAC address.

MAC addresses are **link-local** — they identify a device only within a single LAN segment. When a packet crosses a router, the router creates a brand new frame for the next hop with new source and destination MAC addresses. The original MAC addresses are discarded; only the IP addresses survive the hop.

### Locally Administered vs. Globally Unique

Bit 1 of the first byte indicates whether the address is globally unique (0, OUI-assigned) or locally administered (1, manually set or randomised). Modern operating systems and mobile devices use **MAC address randomisation** (locally administered, changing) to prevent tracking across Wi-Fi networks.

---

## ARP — Address Resolution Protocol

ARP (RFC 826) solves a fundamental problem: the Network Layer knows the destination IP address, but the Data Link Layer needs the destination **MAC address** to build a frame. ARP maps IP addresses to MAC addresses on the local subnet.

### ARP Operation

When Host A (`192.168.1.10`) wants to send a packet to Host B (`192.168.1.20`) on the same subnet:

1. Host A checks its **ARP cache** — if `192.168.1.20 → MAC` is already there and not expired, use it.
2. If not cached, Host A sends an **ARP Request** as an Ethernet broadcast:
   - Destination MAC: `FF:FF:FF:FF:FF:FF` (all devices on segment receive this)
   - Payload: *"Who has 192.168.1.20? Tell 192.168.1.10."*
3. Every device on the segment receives the broadcast. Only Host B (`192.168.1.20`) responds.
4. Host B sends an **ARP Reply** as a unicast back to Host A:
   - Payload: *"192.168.1.20 is at DD:EE:FF:11:22:33"*
5. Host A caches the mapping and builds the Ethernet frame.

```
Host A                                    Host B
192.168.1.10                              192.168.1.20
  │── ARP Request (Broadcast) ──────────►│  All devices receive
  │   "Who has 192.168.1.20?"            │
  │◄── ARP Reply (Unicast) ──────────────│  Only Host B replies
  │   "192.168.1.20 is at DD:EE:FF:..."  │
  │                                      │
  │ (Host A caches: 192.168.1.20 = DD:EE:FF:11:22:33, ~20 min TTL)
```

### ARP Cache

Every device maintains an ARP cache (ARP table) — a temporary mapping of IP → MAC addresses. Entries typically expire after 20 minutes of inactivity to handle changes like a NIC replacement.

```bash
arp -n              # view ARP cache (Linux)
ip neighbour show   # modern Linux equivalent
arp -a              # Windows
```

### Gratuitous ARP

A **Gratuitous ARP** is an ARP reply sent by a device **without** receiving a prior request. A device broadcasts its own IP → MAC mapping to update all neighbours' ARP caches. Used after:
- A NIC is replaced (new MAC, same IP)
- A virtual machine migrates to a new host (new MAC)
- An HSRP/VRRP failover (new active gateway, different MAC)

Gratuitous ARP is also used in **ARP spoofing attacks** — an attacker sends gratuitous ARPs with a victim's IP but their own MAC, poisoning neighbours' ARP caches and intercepting traffic (man-in-the-middle).

### Proxy ARP

A router can respond to ARP requests on behalf of hosts on another network — it answers with its own MAC address. The local host then sends packets to the router, which forwards them. Proxy ARP makes routing transparent to the host (the host does not need a default gateway configured). It is generally disabled on modern networks as it complicates troubleshooting.

---

## Switches and Frame Forwarding

A **switch** is a Layer 2 device that intelligently forwards frames only to the correct destination port, rather than flooding all ports like a hub. This eliminates collisions between ports and makes modern Ethernet efficient.

### The MAC Address Table (CAM Table)

A switch maintains a **MAC address table** (also called the CAM table — Content Addressable Memory). It maps MAC addresses to switch ports:

```
VLAN │ MAC Address         │ Port │ Age (seconds)
─────┼─────────────────────┼──────┼──────────────
  1  │ AA:BB:CC:11:22:33   │  Gi0/1 │  42
  1  │ DD:EE:FF:44:55:66   │  Gi0/7 │  11
 10  │ 11:22:33:AA:BB:CC   │  Gi0/2 │  5
```

### How a Switch Learns and Forwards

**Learning:** When a frame arrives on port Gi0/1 from source MAC `AA:BB:CC:11:22:33`, the switch records `Gi0/1 → AA:BB:CC:11:22:33` in its MAC table. This is automatic and requires no configuration.

**Forwarding (known unicast):** The switch looks up the destination MAC. If found in the table, the frame is forwarded only to that specific port. No other ports receive the frame. This is the key advantage over a hub.

**Flooding (unknown unicast):** If the destination MAC is not in the table, the switch floods the frame out all ports **except** the source port. The device with that MAC will reply, and the switch learns its port from the reply.

**Broadcasting:** Any frame with destination MAC `FF:FF:FF:FF:FF:FF` is always flooded out all ports in the VLAN except the source port.

**MAC table aging:** Entries expire after a configurable period (default 300 seconds). If a device stops transmitting, its entry ages out and is deleted. If it transmits again, the switch re-learns its port.

### Frame Forwarding Modes

| Mode | When Forwarded | CRC Check | Latency | Use |
|------|---------------|-----------|---------|-----|
| **Store-and-Forward** | After entire frame received | Yes — corrupt frames dropped | Higher | Enterprise standard |
| **Cut-Through** | After destination MAC read (14 bytes) | No — errors forwarded | Very low (~1 µs) | Low-latency data centres |
| **Fragment-Free** | After first 64 bytes received | Partial — filters runts | Medium | Compromise |

**Store-and-forward** is the standard mode in enterprise switches. It ensures no corrupted or undersized frames leave the switch.

### CAM Table Overflow Attack

An attacker floods a switch with thousands of frames with **random, spoofed source MAC addresses** (using a tool like `macof`). The CAM table has a finite size (typically 8,000–128,000 entries). When full, the switch can no longer learn new MACs and falls back to **flooding all frames to all ports** — behaving like a hub. This allows the attacker to intercept traffic not intended for them.

Mitigation: **port security** — limit the number of MAC addresses allowed per port and shut down the port if exceeded.

---

## CSMA/CD and CSMA/CA

These protocols govern how devices share a common physical medium.

### CSMA/CD — Carrier Sense Multiple Access with Collision Detection

CSMA/CD is used by **wired Ethernet on half-duplex (hub-based) networks**. It is largely historical now because full-duplex switched Ethernet eliminates collisions entirely.

The algorithm:
1. **Carrier Sense** — listen to the medium; if busy (another device is transmitting), wait.
2. **Multiple Access** — any device can attempt to transmit when the medium is idle.
3. **Transmit** — begin sending the frame.
4. **Collision Detection** — while transmitting, listen for a collision (voltage spike above normal). If detected, both transmitting devices immediately stop.
5. **Jam Signal** — send a 32-bit jam signal to ensure all devices know a collision occurred.
6. **Binary Exponential Backoff** — wait a random time before retransmitting. After each consecutive collision, the range of possible random wait times doubles (exponential backoff). After 16 attempts, discard the frame.

The minimum frame size of 64 bytes ensures a device can detect a collision before finishing transmission on a 10 Mbps Ethernet with maximum cable length.

### CSMA/CA — Carrier Sense Multiple Access with Collision Avoidance

CSMA/CA is used by **Wi-Fi (IEEE 802.11)**. You cannot detect a collision over radio while transmitting (your own signal drowns out the incoming signal), so you *avoid* them instead:

1. **Carrier Sense** — listen for other transmissions. If the medium is busy, wait.
2. **Random Backoff** — before transmitting, wait a random number of time slots (within a contention window). If the medium becomes busy during backoff, freeze the counter until it is idle again.
3. **Transmit** — send the frame.
4. **Wait for ACK** — every Wi-Fi frame must be acknowledged. If no ACK arrives within a timeout, assume a collision and increase the contention window size, then retry.

Wi-Fi also supports **RTS/CTS (Request to Send / Clear to Send)** for large frames: the sender first sends a short RTS frame; the AP (Access Point) responds with CTS, reserving the medium. This reduces the **hidden node problem** (two stations that cannot hear each other both transmitting to the AP simultaneously).

---

## VLANs — Virtual Local Area Networks

A VLAN is a **logical partition** of a physical switch. Devices assigned to VLAN 10 can only communicate directly with other devices in VLAN 10, even if they share the same physical switch hardware as devices in VLAN 20. Communication between VLANs requires a router or Layer 3 switch.

### Why VLANs Matter

**Security isolation:** separate an untrusted guest Wi-Fi network from internal servers, even on the same switches.

**Broadcast containment:** Layer 2 broadcasts (ARP, DHCP Discover) are confined to the VLAN. In a flat network with hundreds of devices, ARP storms and DHCP floods can overwhelm every device. VLANs limit the blast radius.

**Organisational flexibility:** assign ports to departments (HR, Finance, Engineering) logically. Moving a user to a different department means changing a port's VLAN in software, not physically rewiring.

**QoS segmentation:** assign VoIP traffic to a dedicated voice VLAN and apply different quality-of-service policies.

### IEEE 802.1Q VLAN Tagging

When a frame must travel between switches carrying multiple VLANs, it needs a VLAN identifier. IEEE 802.1Q inserts a **4-byte tag** into the Ethernet frame between the Source MAC and the EtherType:

```
┌─────────┬─────────┬────────────────────────────┬───────────┬─────────┬─────┐
│ Dst MAC │ Src MAC │ 0x8100 │PCP│DEI│  VID(12b) │ EtherType │ Payload │ FCS │
└─────────┴─────────┴──────────────────────────────┴───────────┴─────────┴─────┘
                     ◄────────────── 802.1Q Tag ────────────►
```

| Field | Bits | Meaning |
|-------|------|---------|
| **TPID** | 16 | Tag Protocol ID = 0x8100 (marks this as a tagged frame) |
| **PCP** | 3 | Priority Code Point — 802.1p QoS priority, 0 (lowest) to 7 (highest) |
| **DEI** | 1 | Drop Eligible Indicator — this frame may be dropped under congestion |
| **VID** | 12 | VLAN ID — 0 to 4095; usable range: 1–4094 |

### Access Ports vs. Trunk Ports

**Access port:** belongs to exactly one VLAN. Frames sent to an end device (PC, phone, printer) leave the port **untagged** — the end device has no knowledge of VLANs. The switch adds or removes the VLAN tag transparently.

**Trunk port:** carries frames from **multiple VLANs** between switches, routers, or servers. Frames are **tagged** with their VLAN ID. The receiving device reads the tag and places the frame into the correct VLAN.

The **native VLAN** on a trunk is the VLAN whose frames are sent **untagged** (default is VLAN 1). Both ends of a trunk must agree on the native VLAN. A mismatch causes frames to be placed in the wrong VLAN — a security risk called a **VLAN mismatch** (and a vector for VLAN hopping attacks).

### Inter-VLAN Routing

Devices in different VLANs cannot communicate at Layer 2. To route between VLANs, you need a Layer 3 device:

**Router-on-a-Stick:** one physical router interface connects to the switch via a trunk port. The router is configured with sub-interfaces — one per VLAN — each with an IP address as the default gateway for that VLAN. Practical for small deployments.

**Layer 3 Switch with SVIs:** a Layer 3 switch has **SVIs (Switched Virtual Interfaces)** — one per VLAN, acting as the default gateway for that VLAN. Routing happens in hardware at wire speed. This is the standard enterprise approach.

---

## Spanning Tree Protocol (STP)

Redundant switch links provide fault tolerance — if one link fails, traffic uses an alternate path. However, redundant Layer 2 paths create **loops**. Without loop prevention, broadcasts circulate indefinitely, causing:
- **Broadcast storms** — exponential traffic growth from looping broadcasts
- **MAC table instability** — the same MAC address appears on multiple ports simultaneously, constantly updating
- **Network outage** — switch CPUs max out processing looping frames; the network becomes unusable within seconds

**STP (IEEE 802.1D)** prevents loops by placing redundant ports into a **Blocking state**, maintaining exactly one active path at any time.

### How STP Works

**Step 1 — Root Bridge Election:**
All switches begin sending **BPDUs (Bridge Protocol Data Units)** out all ports every 2 seconds. The switch with the lowest **Bridge ID** (BID) is elected Root Bridge.

BID = Bridge Priority (2 bytes, default 32768) + VLAN ID + MAC address (6 bytes). A lower priority wins. If priorities tie, the lower MAC address wins. To force a switch to be root: set priority to 4096 (or use `spanning-tree vlan X root primary`).

**Step 2 — Root Port Selection:**
Every non-root switch selects one **Root Port (RP)** — the port with the lowest path cost to the Root Bridge. STP port cost is based on link speed (100 Mbps = cost 19, 1 Gbps = cost 4, 10 Gbps = cost 2).

**Step 3 — Designated Port Selection:**
On every network segment (link), one port is the **Designated Port (DP)** — the port with the best (lowest cost) path to the root on that segment. The DP is always in Forwarding state.

**Step 4 — Blocking Redundant Ports:**
Any port that is neither a Root Port nor a Designated Port becomes a **Blocked Port** (Alternate Port). It receives BPDUs but does not forward data frames. This breaks the loop.

### STP Port States

| State | Purpose | Forwards Frames | Learns MACs |
|-------|---------|----------------|-------------|
| **Blocking** | Loop prevention; receives BPDUs only | No | No |
| **Listening** | Participating in root election | No | No |
| **Learning** | Building MAC table before forwarding | No | Yes |
| **Forwarding** | Normal operation | Yes | Yes |
| **Disabled** | Administratively shut down | No | No |

Transition from Blocking to Forwarding takes **30–50 seconds** (15 sec Listening + 15 sec Learning). This is too slow for modern networks.

### RSTP — Rapid Spanning Tree Protocol (IEEE 802.1w)

RSTP was designed to eliminate STP's slow convergence. It converges in **1–2 seconds** using:
- **Proposal/Agreement handshake** between adjacent switches — instead of waiting for timers, switches negotiate state changes directly
- **Edge ports** (PortFast equivalent) — ports connected to end devices skip Listening/Learning and go directly to Forwarding
- Eliminates the Listening state entirely
- Three port roles: Root Port, Designated Port, Alternate Port (discarding)

RSTP is backward-compatible with STP. Modern switches default to RSTP.

### PortFast and BPDU Guard

**PortFast** is configured on access ports connecting to end devices (PCs, printers, phones). It causes the port to skip Listening and Learning states and go directly to Forwarding. This prevents the 30-second delay a user would experience waiting for STP to converge when their PC boots.

**PortFast must never be enabled on switch-to-switch links** — it would allow a loop to form instantly.

**BPDU Guard** protects PortFast ports. If a BPDU is received on a PortFast port (it should not be, since end devices don't send BPDUs), the port is immediately put into **err-disabled** state. This prevents a rogue switch plugged into an access port from disrupting the spanning tree.

### MSTP — Multiple Spanning Tree Protocol (IEEE 802.1s)

A network with 100 VLANs running one STP instance uses the same spanning tree for all VLANs. All traffic follows the same path, wasting redundant links. MSTP maps groups of VLANs to separate spanning tree instances, allowing different VLANs to use different paths — enabling load balancing across redundant links.

---

## Link Aggregation — EtherChannel / LACP

**Link Aggregation (IEEE 802.3ad, also called EtherChannel on Cisco, LAG or port channel generically)** combines multiple physical links between two devices into a single logical link.

Benefits:
- **Increased bandwidth** — a 4-link × 10 Gbps LAG provides 40 Gbps aggregate capacity (traffic hashed across member links)
- **Redundancy** — if one physical link fails, traffic continues on the remaining links without spanning tree reconvergence

**LACP (Link Aggregation Control Protocol)** is the IEEE 802.3ad standard protocol for negotiating and maintaining a LAG. Each end advertises its capabilities and system ID; both sides agree on which links to bundle.

Traffic distribution across member links uses a **hash** of one or more fields: source MAC, destination MAC, source IP, destination IP, or L4 ports. A single flow (same 5-tuple) always uses the same link — no per-packet reordering.

---

## Port Security

Port security limits which MAC addresses can send frames on a switch port. It protects against MAC flooding attacks and unauthorised devices connecting to the network.

**Sticky learning:** the switch dynamically learns the MAC addresses of connected devices and "sticks" them to the port — permanently storing them as allowed MACs. New devices connecting get blocked.

**Static MAC:** the administrator manually specifies the allowed MAC addresses on the port.

**Maximum MAC count:** limits how many different MACs can be learned on a port.

**Violation modes:**
| Mode | Action on Violation | Increments Counter |
|------|-------------------|------------------|
| **Protect** | Drops frames from unknown MACs silently | No |
| **Restrict** | Drops frames; increments violation counter; sends SNMP trap | Yes |
| **Shutdown** | Immediately err-disables the port; requires manual recovery | Yes |

---

## CDP and LLDP — Discovery Protocols

**CDP (Cisco Discovery Protocol)** is a Cisco-proprietary Layer 2 protocol. Cisco devices send CDP frames every 60 seconds on all interfaces, advertising:
- Device type and model
- IOS version
- Interface name
- IP address
- Capabilities (router, switch, phone)

**LLDP (Link Layer Discovery Protocol — IEEE 802.1ab)** is the open standard equivalent. It serves the same purpose as CDP but works across all vendors.

Both protocols send multicast frames that are not forwarded by switches (they stay on the local segment). Network management systems use CDP/LLDP data to automatically build topology maps. Security consideration: CDP/LLDP can reveal device models and software versions to attackers — disable on externally facing ports.

---

## Dynamic ARP Inspection (DAI)

Dynamic ARP Inspection is a switch security feature that validates ARP packets. It uses the **DHCP snooping binding table** (which records which IP address was given to which MAC on which port) to verify that ARP replies are legitimate.

If a host sends an ARP reply claiming an IP → MAC mapping that conflicts with the binding table, DAI drops the packet and can shut down the port. This prevents ARP spoofing/poisoning attacks.

---

## Summary

- The Data Link Layer organises bits into **frames** and delivers them within one network segment
- Two sublayers: **MAC** (framing, addressing, CRC, media access) and **LLC** (multiplexing, error notification)
- **Ethernet frames** carry source/destination MAC addresses, an EtherType field, payload (46–1500 B), and FCS (CRC-32)
- **MAC addresses** are 48-bit hardware addresses; the first 3 bytes identify the manufacturer (OUI)
- **ARP** maps IP addresses to MAC addresses via broadcast request and unicast reply
- **Switches** use a CAM table to forward frames only to the correct port; unknown destinations are flooded
- **VLANs** logically segment a switch; 802.1Q tagging carries VLAN IDs between switches on trunk ports
- **STP/RSTP** prevents Layer 2 loops by blocking redundant ports while keeping one active path
- **CSMA/CD** (wired Ethernet) and **CSMA/CA** (Wi-Fi) govern medium access on shared segments

**Next:** [Layer 3 — Network](05-network-layer.md) — IP addressing and how packets cross the world
