# Network Topologies

A **network topology** describes how nodes (devices) are connected to each other — both physically (how the cables run) and logically (how traffic flows). Choosing the right topology affects performance, fault tolerance, cost, and scalability.

---

## Physical vs. Logical Topology

**Physical topology** — the actual layout of cables and hardware.
**Logical topology** — how data flows through the network, which may differ from the physical layout.

Example: A network can be physically wired as a star (all cables run to a central switch) but logically operate as a bus (broadcast traffic goes to every device).

---

## Bus Topology

All devices share a single cable (the "bus"). Data sent by any device is seen by all others; only the intended recipient accepts it.

```
[A]──[B]──[C]──[D]──[E]
```

**Pros:** Simple, cheap, easy to extend.
**Cons:** One cable break kills the whole segment. Collisions when two devices transmit simultaneously. Doesn't scale past ~30 nodes.

**Used in:** Early Ethernet (10Base-2 coax), legacy industrial control networks, some IoT buses (CAN bus).

---

## Ring Topology

Each device connects to exactly two neighbors, forming a loop.

```
[A]──[B]──[C]
 │           │
[E]──[D]─────┘
```

**Pros:** Equal access (token-passing eliminates collisions). Predictable performance.
**Cons:** One break in the ring (without a redundant path) can take down the entire network. Adding/removing nodes disrupts traffic.

**Used in:** SONET/SDH (fiber backbone rings — bidirectional rings for redundancy), Token Ring (historical LAN), FDDI.

---

## Star Topology

All devices connect to a central device (switch or hub). No device talks directly to another — all traffic goes through the center.

```
     [A]
      │
[B]──[SW]──[C]
      │
     [D]
```

**Pros:** Easy to add/remove devices. One device failure doesn't affect others. Easy to troubleshoot (the central device is the single point of visibility).
**Cons:** Central device is a **single point of failure**. More cabling than bus.

**Used in:** Every modern LAN. The Ethernet + switch combination is a star topology.

---

## Tree (Hierarchical) Topology

A hierarchy of stars — switches connect to aggregation switches, which connect to a core switch.

```
           [Core]
          /       \
    [Aggr1]      [Aggr2]
    /    \        /    \
 [SW1] [SW2]  [SW3]  [SW4]
  /\    /\    /\      /\
hosts  hosts hosts   hosts
```

**Pros:** Scales to thousands of hosts. Traffic stays local at lower layers. Easy to add segments.
**Cons:** Failure at a higher-level switch isolates everything below it.

**Used in:** Enterprise campus networks, traditional data centers (3-tier: access/distribution/core).

---

## Mesh Topology

Every device has a direct connection to every other device.

**Full mesh:** N devices → N×(N-1)/2 links. For 10 devices: 45 links.

**Partial mesh:** Some (not all) direct connections. The common middle ground.

```
[A]──[B]
 │╲  ╱│
 │ ╲╱ │
 │ ╱╲ │
 │╱  ╲│
[D]──[C]
```

**Pros:** Maximum redundancy. No single point of failure. Multiple paths for load balancing.
**Cons:** Expensive (N² cabling). Complex to manage.

**Used in:** Internet backbone (ISPs have multiple BGP peerings), WAN designs, wireless mesh networks, military communications.

---

## Hybrid Topology

A combination of two or more topologies. The most common real-world networks are hybrid:

- **Star-bus**: a bus connecting multiple star segments
- **Star-ring**: rings of stars used in SONET
- **Hierarchical mesh**: data center spine-leaf (see below)

---

## Modern Data Center: Spine-Leaf

The traditional 3-tier tree doesn't scale for east-west traffic (server-to-server) in modern data centers. **Spine-leaf** (also called Clos topology) was designed for this.

```
   [Spine1]──────────[Spine2]
    /   \              /   \
[Leaf1][Leaf2]    [Leaf3][Leaf4]
  /\    /\          /\     /\
servers servers   servers servers
```

- Every **leaf** switch connects to every **spine** switch
- Servers connect only to leaf switches
- Any server can reach any other server in exactly 2 hops
- Add more spine switches for more bandwidth; add more leaf switches for more servers

**Properties:**
- **Low latency, high bandwidth** east-west traffic
- **No spanning tree** needed (ECMP routing instead)
- **Linear scalability** — add leaf pairs for capacity, add spines for bandwidth

Used by: Google, Facebook, AWS, Azure, and every modern hyperscaler.

---

## WAN Topologies

Wide Area Networks spanning cities or continents use different models:

**Hub-and-spoke:** A central "hub" site connects to multiple "spoke" sites. Spokes must route traffic through the hub to reach each other. Simple to manage, but hub is a bottleneck and single point of failure.

**Full mesh WAN:** Every site connects to every other site directly (MPLS, SD-WAN). Maximum performance; expensive.

**Partial mesh WAN:** Key sites have direct links; others go through a hub. Common trade-off.

**SD-WAN (Software-Defined WAN):** Overlays an intelligent control plane over multiple underlay links (MPLS, internet, LTE). Routes traffic based on policy and real-time path quality. Popular for remote offices.

---

## Internet Exchange Points (IXPs)

At large scale, ISPs and content providers need to exchange traffic efficiently. **Internet Exchange Points** are physical locations where many networks peer with each other over a shared switching fabric.

Major IXPs: DE-CIX (Frankfurt), AMS-IX (Amsterdam), Equinix (globally distributed).

Traffic exchanged at an IXP doesn't have to traverse an upstream ISP, reducing latency and cost.

---

## Point-to-Point vs. Multipoint

**Point-to-point:** One link between exactly two devices. Simple, dedicated bandwidth.
- Examples: leased line, fiber cross-connect between two buildings, SONET OC-N link.

**Multipoint (multi-access):** Many devices share a single network. Broadcast domains form.
- Examples: Ethernet LAN, Wi-Fi (all clients share the RF medium).

---

## Network Zones

Beyond physical topology, networks are logically divided into **zones** based on trust level:

| Zone | Description |
|------|-------------|
| Internet | Untrusted — anyone can connect |
| DMZ (Demilitarized Zone) | Semi-trusted — public-facing servers (web, mail) |
| Internal LAN | Trusted — employee workstations |
| Management network | Highly trusted — network device management |
| Guest network | Isolated — visitors, no access to internal LAN |
| OT/Industrial network | Isolated — factory floor, SCADA systems |

---

## Try It With pktana

```bash
# See how your interfaces fit the topology
pktana nic list

# View routes — see how traffic is directed (star to gateway)
pktana routes

# View active connections — see which hosts communicate
pktana connections
```

The routes output reveals your network's logical topology. A single default route (`0.0.0.0/0 via <gateway>`) is classic hub-and-spoke (your machine is a spoke, the gateway is the hub).

---

## Summary

- **Bus:** shared cable, simple, doesn't scale
- **Ring:** loop, equal access, fragile without redundancy
- **Star:** central switch, modern LAN standard
- **Tree:** hierarchy of stars, enterprise campus design
- **Mesh:** every-to-every, maximum redundancy, used in backbone/WAN
- **Spine-Leaf:** modern data center Clos topology for east-west traffic
- **Hybrid:** all real networks are combinations of the above

**Next:** [Wireless Networking](09-wireless-networking.md) — Wi-Fi, cellular, and the invisible network
