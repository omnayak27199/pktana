# Layer 2 — The Data Link Layer

The Data Link Layer is where raw bits (from Layer 1) become meaningful **frames**. It handles communication between devices on the **same physical network** — the same LAN segment.

Key responsibilities:
- **Framing** — wrapping data in a defined structure with headers and trailers
- **MAC addressing** — identifying devices on the local segment
- **Error detection** — catching transmission errors with CRC
- **Access control** — managing who gets to transmit on shared media

---

## The Ethernet Frame

Ethernet is by far the dominant Layer 2 protocol for wired LANs. An Ethernet frame looks like:

```
| Preamble (8B) | Dst MAC (6B) | Src MAC (6B) | EtherType (2B) | Payload (46–1500B) | FCS (4B) |
```

- **Preamble** — 7 bytes of alternating 1/0 bits + 1 byte start delimiter; helps the receiver sync its clock
- **Destination MAC** — the intended recipient's hardware address
- **Source MAC** — the sender's hardware address
- **EtherType** — identifies the Layer 3 protocol in the payload (`0x0800` = IPv4, `0x86DD` = IPv6, `0x0806` = ARP)
- **Payload** — the IP packet (or other Layer 3 PDU); must be 46–1500 bytes (padded if shorter)
- **FCS (Frame Check Sequence)** — a 4-byte CRC-32 checksum; if it doesn't match the frame is dropped

---

## MAC Addresses

A **MAC (Media Access Control) address** is a 48-bit (6-byte) hardware address assigned to every network interface.

Written as: `AA:BB:CC:DD:EE:FF` (hex, colon-separated) or `AA-BB-CC-DD-EE-FF`

Structure:
- **First 3 bytes** — OUI (Organizationally Unique Identifier): assigned to the manufacturer by IEEE
- **Last 3 bytes** — device-specific, assigned by the manufacturer

Special MAC addresses:
- `FF:FF:FF:FF:FF:FF` — **broadcast**: all devices on the segment receive it
- `01:xx:xx:xx:xx:xx` — **multicast**: only devices that have joined the multicast group receive it
- **Unicast** — all others: intended for one specific device

> MAC addresses are **local** — they're used for delivery within a LAN. IP addresses handle routing between LANs.

---

## Switches: How Layer 2 Devices Work

A **switch** is the central intelligence of a LAN. Unlike a hub (which blindly repeats to all ports), a switch learns which MAC addresses are on which ports and **only forwards frames to the correct port**.

### MAC Address Table (CAM Table)

A switch maintains a table mapping MAC addresses to ports:

```
Port | MAC Address         | Age
-----|--------------------|-----------
 1   | AA:BB:CC:11:22:33  | 42 sec
 2   | DD:EE:FF:44:55:66  | 11 sec
 3   | 11:22:33:AA:BB:CC  | 5 sec
```

### How a Switch Learns

1. When a frame arrives on port 1 from `AA:BB:CC:11:22:33`, the switch records: *port 1 → this MAC*
2. If the destination MAC is in the table, the frame is forwarded only to that port (**unicast forwarding**)
3. If the destination MAC is unknown, the frame is **flooded** to all ports except the source port (**unknown unicast flood**)
4. Broadcast frames are always flooded to all ports

### Aging

MAC table entries expire (typically 300 seconds) if no traffic is seen from that address. This prevents the table from filling up with stale entries.

---

## ARP — Address Resolution Protocol

IP knows the destination IP address. But to build an Ethernet frame, it needs the **destination MAC address**. ARP is how a device finds the MAC for a given IP.

**ARP Request** (broadcast): *"Who has 192.168.1.10? Tell 192.168.1.1"*
**ARP Reply** (unicast): *"192.168.1.10 is at AA:BB:CC:DD:EE:FF"*

The requester caches this mapping in its **ARP cache** (expires in ~20 min).

```bash
# View your ARP cache
arp -n
```

---

## VLANs — Virtual LANs

A **VLAN** is a logical partition of a switch. Devices on VLAN 10 can't directly communicate with devices on VLAN 20, even if they're on the same physical switch.

Benefits:
- **Isolation** — separate HR, Finance, Guest networks on one switch
- **Security** — blast radius of a broadcast storm is contained
- **Flexibility** — move a port to a different VLAN in software

**IEEE 802.1Q** (VLAN tagging) adds a 4-byte tag inside the Ethernet frame:

```
| Dst MAC | Src MAC | 0x8100 | VLAN Tag (12-bit VLAN ID) | EtherType | Payload | FCS |
```

VLAN IDs: 1–4094. VLAN 1 is the default.

**Trunk ports** carry traffic from multiple VLANs between switches. **Access ports** belong to a single VLAN and connect to end devices.

---

## Spanning Tree Protocol (STP)

Networks often have redundant links for fault tolerance. But redundancy at Layer 2 creates **loops** — frames bounce infinitely (a **broadcast storm**).

**STP (IEEE 802.1D)** prevents loops by:
1. Electing a **Root Bridge** (the switch with the lowest Bridge ID)
2. Calculating the shortest path to the Root Bridge from every switch
3. Blocking redundant ports (putting them in **Blocking state**)
4. If the active path fails, unblocking an alternate path

**RSTP (Rapid STP, 802.1w)** converges in ~1 second vs. 30–50 seconds for STP.

---

## Ethernet Frame Sizes

- **Standard frame** — up to 1518 bytes (1500 payload + 18 header)
- **Jumbo frame** — up to 9000 bytes payload (must be enabled on all devices in the path)
- **Baby giant** — slightly over 1518 bytes (can accommodate one 802.1Q tag)

The **MTU (Maximum Transmission Unit)** is the largest payload a link can carry. Mismatched MTUs cause fragmentation or drops.

---

## Other Layer 2 Technologies

| Protocol | Use Case |
|---------|---------|
| PPP | Serial WAN links (DSL, dial-up) |
| Wi-Fi (802.11) | Wireless LAN (has its own framing) |
| MPLS | Service provider backbone switching |
| ATM | Legacy telco (mostly retired) |
| Fiber Channel | Storage Area Networks (SANs) |

---

## Try It With pktana

pktana shows full Layer 2 details on every captured packet:

```bash
# Capture and see Ethernet headers
pktana capture --interface eth0 --count 10
```

In the pktana Web UI, expand a packet to see:
- **Destination MAC**, **Source MAC** (and OUI lookup)
- **EtherType** (0x0800 for IPv4, 0x86DD for IPv6)
- **VLAN tag** (if present)
- **FCS status** (valid/invalid)

```bash
# Watch for ARP traffic
pktana capture --interface eth0 --filter "arp"
```

---

## Summary

- Layer 2 frames data and delivers it within a **single network segment**
- **MAC addresses** are hardware addresses; **ARP** maps IP addresses to MACs
- **Switches** forward frames intelligently using a MAC address table
- **VLANs** logically segment a physical switch into multiple isolated networks
- **STP/RSTP** prevents Layer 2 loops in redundant topologies

**Next:** [Layer 3 — Network](05-network-layer.md) — IP addressing and how packets cross the world
