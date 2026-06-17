# Layer 1 — The Physical Layer

The Physical Layer is the foundation of all networking. It is responsible for the transmission and reception of raw, unstructured **bits** — the 0s and 1s that represent all digital data — over a physical medium. It converts digital bits into signals suitable for the medium and converts incoming signals back to bits.

The Physical Layer defines everything about the physical connection:
- The type of medium (copper cable, fiber optic, radio waves)
- The connector and cable specifications
- The signal encoding scheme (how bits become voltages or light pulses)
- The bit rate and signal timing
- The direction of data flow (simplex, half duplex, full duplex)

The Physical Layer does **not** address, frame, or correct errors. It simply puts bits on the wire.

---

## Purpose of the Physical Layer

Every network, regardless of technology, must solve the same fundamental problem: how to represent a 0 and a 1 as a physical signal and transmit that signal reliably from one device to another.

The Physical Layer answers:
- What physical medium carries the signal?
- What signal states represent a 0 and a 1?
- At what speed are bits clocked onto the medium?
- How are sender and receiver clocks synchronised?
- What does the connector look like?
- What is the maximum distance before the signal degrades?

---

## Transmission Media

Transmission media are the physical paths over which data travels. There are three main categories: copper cable, fiber optic, and wireless.

### 1. Copper Cable — Twisted Pair

Twisted-pair copper cable is the most common wired medium in office and home networks. It consists of pairs of insulated copper wires twisted around each other. The twisting provides **common-mode rejection** — electromagnetic noise hits both wires in the pair equally, and the receiving circuit subtracts one from the other, cancelling the noise.

**UTP (Unshielded Twisted Pair)** — no additional shielding; relies entirely on the twist. Inexpensive, flexible, easy to terminate.

**STP (Shielded Twisted Pair)** — an additional metallic shield around each pair or around all pairs. Used in environments with strong electromagnetic interference (near motors, industrial equipment).

| Category | Max Speed | Max Distance | Common Use |
|----------|-----------|--------------|-----------|
| Cat 5 | 100 Mbps | 100 m | Legacy Fast Ethernet |
| Cat 5e | 1 Gbps | 100 m | Home and small office networks |
| Cat 6 | 10 Gbps | 55 m | Office and data centre access |
| Cat 6a | 10 Gbps | 100 m | Data centre structured cabling |
| Cat 7 | 10 Gbps | 100 m | Fully shielded, niche enterprise |
| Cat 8 | 25–40 Gbps | 30 m | Data centre server-to-switch links |

The **100 m (328 ft) rule** applies to nearly all copper Ethernet standards. Beyond this distance, signal attenuation causes errors. A switch, repeater, or fiber link must extend the reach.

**RJ-45 Connector** is the standard 8-pin connector for twisted-pair Ethernet. Wiring follows either the **T568A** or **T568B** standard. T568B is the more common choice in North America.

A **straight-through cable** (both ends wired identically) connects unlike devices: PC to switch, switch to router. A **crossover cable** (one end T568A, other T568B) connects like devices: switch to switch, PC to PC. Modern equipment with **Auto-MDI/MDIX** detects the cable type and adjusts automatically, making crossover cables largely unnecessary.

### 2. Fiber Optic Cable

Fiber optic cable transmits data as **pulses of light** through a glass or plastic core, surrounded by cladding (lower refractive index) that keeps light inside the core by total internal reflection. Benefits over copper: no electromagnetic interference, much greater distance, much higher potential bandwidth.

**Single-Mode Fiber (SMF):**
- Core diameter: ~8–10 micrometres
- Light source: laser (infrared, 1310 nm or 1550 nm wavelength)
- Max distance: typically 10–80 km; long-haul systems reach 1000+ km with amplification
- Use: WAN links, campus backbone, metropolitan area networks

**Multi-Mode Fiber (MMF):**
- Core diameter: 50 or 62.5 micrometres
- Light source: LED or VCSEL (Vertical-Cavity Surface-Emitting Laser)
- Max distance: up to 550 m (OM3 at 10 Gbps), 400 m (OM4 at 10 Gbps)
- Use: data centre connections, intra-building backbone

The key limitation of multi-mode is **modal dispersion** — different light modes (paths) through the wider core arrive at slightly different times, spreading the pulse and limiting distance. Single-mode eliminates this by using a core narrow enough for only one mode.

**Common fiber connectors:**
| Connector | Description | Use |
|-----------|------------|-----|
| LC (Lucent Connector) | Small form factor, locking tab | Data centres (most common today) |
| SC (Subscriber Connector) | Square push-pull body | Telco, older data centres |
| ST (Straight Tip) | Bayonet-twist lock | Legacy installations |
| MPO/MTP | 12 or 24 fibres in one connector | High-density data centre cabling |

Light travels through fiber at approximately **200,000 km/s** (two-thirds the speed of light in vacuum), giving about 5 microseconds of propagation delay per kilometre.

### 3. Coaxial Cable

A coaxial cable has a central copper conductor, surrounded by a dielectric insulator, then a braided metallic shield, then an outer plastic jacket. The shield reduces interference and prevents signal leakage. Originally used for Ethernet (10Base-2 "Thinnet," 10Base-5 "Thicknet"), coax is now mainly used for:
- Cable TV distribution (CATV)
- DOCSIS broadband Internet (from street to home)
- RF and antenna connections
- Some CCTV systems

### 4. Wireless Media

Wireless media uses **radio frequency (RF)** electromagnetic waves to carry data through the air. No physical cable is required, making wireless ideal for mobile devices and locations where cabling is impractical.

| Technology | Frequency | Standard | Typical Range | Max Speed |
|-----------|-----------|---------|--------------|----------|
| Wi-Fi (802.11n) | 2.4/5 GHz | IEEE 802.11n | ~70 m indoor | 600 Mbps |
| Wi-Fi (802.11ac/Wi-Fi 5) | 5 GHz | IEEE 802.11ac | ~35 m indoor | 3.5 Gbps |
| Wi-Fi (802.11ax/Wi-Fi 6) | 2.4/5/6 GHz | IEEE 802.11ax | ~35 m indoor | 9.6 Gbps |
| Cellular (4G LTE) | 700 MHz–2.6 GHz | 3GPP | Kilometres | ~100 Mbps |
| Cellular (5G NR) | Sub-6 GHz / mmWave | 3GPP | Varies | 1–10 Gbps |
| Bluetooth | 2.4 GHz | IEEE 802.15.1 | ~10 m | ~3 Mbps |

Wireless signals are affected by **distance, obstacles (walls, floors), interference from other RF sources, and multipath fading** (reflections arriving out of phase). Higher frequencies carry more data but penetrate obstacles less effectively.

---

## Signal Encoding

Raw bits must be converted into physical signal changes. The method used is called **line encoding** or **modulation**. Different technologies use different schemes.

### Electrical Encoding (Copper)

**NRZ (Non-Return to Zero):** High voltage = bit 1, low voltage = bit 0. Simple, but long runs of the same bit cause the signal to stay constant with no transitions, making it hard for the receiver to synchronise its clock.

**Manchester Encoding:** A transition in the middle of each bit period encodes the value — transition high-to-low = 0, low-to-high = 1. Self-clocking. Used in 10BASE-T (10 Mbps Ethernet).

**4B/5B + NRZI:** Every 4 data bits are mapped to a 5-bit code chosen to guarantee at least one 0 in every code word, ensuring clock transitions. Combined with NRZI (a transition = 1, no transition = 0). Used in 100BASE-TX (Fast Ethernet).

**8B/10B:** Every 8 data bits become 10 code bits. Ensures DC balance (equal 0s and 1s) and frequent transitions for clock recovery. Used in Gigabit Ethernet (1000BASE-X), Fibre Channel.

**64B/66B:** Every 64 data bits become 66 code bits (only 3.125% overhead vs 25% for 8B/10B). Used in 10 Gbps Ethernet and beyond.

**PAM4 (Pulse Amplitude Modulation — 4 levels):** Uses four distinct voltage levels (0, 1, 2, 3) to encode **2 bits per symbol**, doubling throughput without doubling signal frequency. Used in 25GbE, 100GbE, and 400GbE.

### Optical Encoding (Fiber)

**OOK (On-Off Keying):** Light on = 1, light off = 0. Simple and used in lower-speed systems.

**PAM4:** Four light intensity levels encode 2 bits per symbol. Used in 100 Gbps and 400 Gbps optical links.

**Coherent QAM:** Combines phase and amplitude modulation with polarisation multiplexing for 100 Gbps+ long-haul fiber.

### RF Modulation (Wireless)

| Modulation | What Changes | Use |
|-----------|-------------|-----|
| AM (Amplitude Modulation) | Signal strength | AM radio |
| FM (Frequency Modulation) | Signal frequency | FM radio |
| PSK (Phase Shift Keying) | Signal phase | Wi-Fi, cellular |
| QAM (Quadrature AM) | Phase + Amplitude | Wi-Fi, cable, LTE |
| OFDM (Orthogonal Frequency Division Multiplexing) | Multiple sub-carriers | Wi-Fi 4/5/6, LTE |

Wi-Fi 6 uses **1024-QAM**, encoding 10 bits per symbol. Wi-Fi 5 used 256-QAM (8 bits). Higher QAM requires a cleaner signal — closer distance or better antenna design.

---

## Bandwidth, Throughput, Latency, and Jitter

These four terms describe the performance of a network link and are frequently confused.

### Bandwidth

Bandwidth is the **maximum data rate** a link can support, measured in bits per second (bps). It is a property of the medium and the technology:
- 1000BASE-T Ethernet has 1 Gbps bandwidth
- A 5G link might offer 1 Gbps bandwidth at a given location

Bandwidth is the size of the "pipe" — it does not tell you how fast data actually flows.

### Throughput

Throughput is the **actual measured data rate** over a link, always **less than or equal to bandwidth**. The gap is caused by:
- Protocol overhead (TCP, IP, Ethernet headers consume bandwidth)
- Retransmissions (lost packets must be resent)
- Congestion (routers drop or queue packets when overwhelmed)
- Hardware limitations (CPU, NIC, switch backplane)

If a 1 Gbps link carries 800 Mbps of application data, its throughput is 800 Mbps. The remaining 200 Mbps is consumed by overhead and unused capacity.

### Latency (Delay)

Latency is the **time for one bit (or a packet) to travel from source to destination**. It is composed of:

| Component | Cause | Typical Value |
|-----------|-------|--------------|
| **Propagation delay** | Speed of signal × distance | ~5 µs per km in fiber |
| **Transmission delay** | Packet size ÷ bandwidth | 12 µs for 1500 B at 1 Gbps |
| **Processing delay** | Router/switch CPU time | Microseconds to milliseconds |
| **Queuing delay** | Waiting in router buffer | 0 to hundreds of milliseconds |

A 10,000 km trans-Pacific fiber link has ~50 ms one-way propagation delay — irreducible by technology, set by physics.

### Jitter

Jitter is the **variation in latency** between successive packets. A packet arriving at 10 ms, then 11 ms, then 9 ms, then 15 ms has 6 ms of jitter. Low jitter is critical for real-time applications like VoIP and video conferencing — a consistent 50 ms delay is better than a jitter-filled 20–80 ms range. Jitter buffers in VoIP phones absorb jitter at the cost of added latency.

### Bandwidth-Delay Product

The bandwidth-delay product (BDP) = bandwidth × round-trip time. It represents the amount of data that can be "in flight" in the network at once.

Example: 1 Gbps link, 100 ms RTT → BDP = 1 × 10⁸ × 0.1 = 12.5 MB. TCP must buffer up to 12.5 MB of unacknowledged data to fully utilise this link. This is why TCP window scaling matters on high-speed, high-latency links.

---

## Duplex Modes

Duplex defines the **direction of data flow** between two devices on a link.

**Simplex** — data flows in one direction only. A television broadcast is simplex. Used in some sensor and monitoring devices.

**Half Duplex** — both devices can transmit, but not simultaneously. Only one device transmits at a time. If both transmit simultaneously, a **collision** occurs. Used by old hub-based Ethernet (CSMA/CD) and Wi-Fi (CSMA/CA).

**Full Duplex** — both devices transmit and receive simultaneously without collision. Achieved by using separate signal paths for each direction (separate wire pairs in Ethernet, separate wavelengths in WDM fiber). **All modern switched Ethernet runs full duplex** — each port on a switch is a separate collision domain with dedicated wire pairs.

**Duplex mismatch** occurs when one end is configured for full duplex and the other for half duplex (often because auto-negotiation fails). The half-duplex end detects "collisions" (actually the other end transmitting), causing high retransmission rates and severe performance degradation — often ~50% or less of expected throughput. Symptoms include high late-collision counters in interface statistics.

---

## Physical Network Topologies

A topology describes how devices are physically connected to each other.

**Bus Topology** — all devices connect to a single shared cable. A signal from any device travels the entire bus and reaches all others. Used in early Ethernet (10Base-2, 10Base-5). A break anywhere in the bus brings down the entire network. Collisions are inherent. Obsolete for modern LANs.

**Star Topology** — all devices connect to a central device (a switch or hub). Each device has its own dedicated cable run to the centre. A cable failure only affects that one device. The central device is a single point of failure, but switches are highly reliable. **This is the universal topology for modern Ethernet.**

**Ring Topology** — each device connects to two neighbours, forming a loop. Data travels around the ring. Used in older Token Ring (IEEE 802.5) and SONET/SDH WAN rings. Resilient to single link failure if redundant (counter-rotating) rings are used.

**Mesh Topology** — every device connects directly to every other device. Provides maximum redundancy — any single path can fail without losing connectivity. Used in WAN links between major sites (partial mesh), in data centre spine-leaf architectures, and in wireless mesh networks.

**Point-to-Point Topology** — a direct link between exactly two devices. Every WAN serial link, leased line, and fiber run between buildings is point-to-point.

**Hybrid Topology** — a combination of the above. A typical enterprise uses a star of stars (access switches connected to distribution switches connected to core switches), with mesh links between core and distribution for redundancy.

---

## Physical Layer Devices

### Hub

A hub is a Layer 1 multi-port repeater. When a signal arrives on any port, the hub **regenerates and repeats it out all other ports**. All devices share one collision domain — only one device can transmit at a time, and any two simultaneous transmissions collide. Hubs are entirely obsolete, replaced by switches in the late 1990s. Understanding hubs explains why switches were necessary.

### Repeater

A repeater regenerates a degraded signal to extend a cable run beyond its maximum distance. A repeater operating at Layer 1 does not filter, address, or interpret traffic — it copies bits. A modern equivalent is a **fiber extender** or **Ethernet extender** used to stretch a cable run beyond 100 m.

### Media Converter

A media converter converts signals between different physical media types on the same Layer 2 network — most commonly between copper (RJ-45) and fiber optic (LC or SC). Used at building or floor boundaries where fiber runs between switches but copper connects end devices.

### Transceiver (SFP / QSFP)

**SFP (Small Form-factor Pluggable)** and **QSFP (Quad SFP)** are hot-swappable modules that plug into switch or router ports and provide the physical interface. The switch port itself is media-agnostic — you insert the right transceiver for the medium:
- SFP copper (RJ-45, 1 Gbps)
- SFP LX (single-mode fiber, 10 km)
- SFP SR (multi-mode fiber, 300 m)
- QSFP28 (4 × 25G channels = 100G)
- DAC (Direct Attach Copper) — a short twinax cable with SFPs on both ends; very low cost, used between racks in the same data centre

### Network Interface Card (NIC)

A NIC (network adapter) connects a host to the network. It operates at both Layer 1 (converting frames to physical signals) and Layer 2 (it has a burned-in MAC address). Modern NICs are built into motherboards or available as PCIe expansion cards. Data centre NICs support 10/25/100/400 Gbps.

---

## Ethernet Physical Layer Standards

Ethernet names encode speed, signaling type, and medium in their names: `<speed>BASE-<medium>`.

| Standard | Speed | IEEE | Medium | Max Distance |
|---------|-------|------|--------|-------------|
| 10BASE-T | 10 Mbps | 802.3 | Cat 3 UTP | 100 m |
| 100BASE-TX | 100 Mbps | 802.3u | Cat 5 UTP | 100 m |
| 1000BASE-T | 1 Gbps | 802.3ab | Cat 5e UTP | 100 m |
| 1000BASE-SX | 1 Gbps | 802.3z | MMF | 550 m |
| 1000BASE-LX | 1 Gbps | 802.3z | SMF | 10 km |
| 10GBASE-T | 10 Gbps | 802.3an | Cat 6a UTP | 100 m |
| 10GBASE-SR | 10 Gbps | 802.3ae | MMF | 300 m |
| 10GBASE-LR | 10 Gbps | 802.3ae | SMF | 10 km |
| 25GBASE-SR | 25 Gbps | 802.3by | MMF | 100 m |
| 40GBASE-SR4 | 40 Gbps | 802.3ba | MMF (MPO) | 150 m |
| 100GBASE-LR4 | 100 Gbps | 802.3ba | SMF | 10 km |
| 400GBASE-DR4 | 400 Gbps | 802.3bs | SMF | 500 m |

In the naming scheme:
- **T** = Twisted pair copper
- **SX** = Short wavelength (multi-mode fiber)
- **LX/LR** = Long wavelength (single-mode fiber)
- **SR** = Short reach
- **Number after medium** = number of lanes (SR4 = 4 lanes × 10G = 40G)

---

## Power over Ethernet (PoE)

PoE delivers DC electrical power over the same Ethernet cable as data. The device supplying power is called a **PSE (Power Sourcing Equipment)** — typically a PoE switch or PoE injector. The device receiving power is called a **PD (Powered Device)** — a VoIP phone, wireless access point, IP camera, or IoT sensor.

PoE eliminates the need for a separate power cable and wall adapter at each endpoint, simplifying deployment, enabling centralised power management, and allowing devices to be placed anywhere within cable reach.

| IEEE Standard | Common Name | Max Power at PSE | Max Power at PD | Typical Use |
|--------------|-------------|-----------------|----------------|------------|
| 802.3af | PoE | 15.4 W | 12.95 W | IP phones |
| 802.3at | PoE+ | 30 W | 25.5 W | Wireless APs |
| 802.3bt Type 3 | PoE++ / 4PPoE | 60 W | 51 W | PTZ cameras |
| 802.3bt Type 4 | PoE++ / 4PPoE | 100 W | 71.3 W | Laptops, thin clients |

Power is delivered on the spare pairs (pins 4,5,7,8) in 10/100 Ethernet, or on the data pairs (using both pairs simultaneously) in Gigabit Ethernet. 802.3bt (Type 3/4) uses all four pairs.

**PoE budget:** a switch has a maximum total PoE wattage it can deliver to all ports. A 48-port switch might have a 740 W PoE budget. If all 48 ports are used at PoE+ (25.5 W × 48 = 1224 W needed), the switch must queue or limit power delivery.

---

## Common Physical Layer Problems and Symptoms

Understanding physical layer failures is essential for troubleshooting. Most Layer 1 issues show up as a complete absence of connectivity or as intermittent, unexplained errors.

| Problem | Symptom | Root Cause |
|---------|---------|-----------|
| No link | Link light off, interface down | Unplugged cable, broken cable, dead SFP |
| High error rate | Runts, CRC errors, input errors on interface | Damaged cable, bad connector crimp, EMI |
| Speed/duplex mismatch | ~50% throughput, late collisions | One side forced, other auto-negotiating |
| Intermittent drops | Link flapping, random ping drops | Loose connector, bent cable, marginal length |
| Short run failing | Errors even at 5 m | Wrong cable category, bad crimp, RJ-45 miswired |
| Run > 100 m failing | Errors, drops beyond a distance | Exceeded copper limit — add switch or use fiber |
| SFP not detected | Interface stays down, "SFP not supported" | Wrong SFP type, dirty connector, incompatible vendor |

---

## Summary

- The Physical Layer converts **bits to signals** (electrical, optical, radio) and transmits them over a medium
- **Twisted-pair copper** (Cat 5e through Cat 8) supports 1–40 Gbps over up to 100 m
- **Single-mode fiber** handles 10+ km; **multi-mode fiber** handles up to ~550 m in data centres
- **Line encoding** (Manchester, 4B/5B, PAM4) ensures clock synchronisation and signal integrity
- **Bandwidth** is the maximum capacity; **throughput** is actual speed; **latency** is delay; **jitter** is delay variation
- **Full duplex** (switched Ethernet) transmits and receives simultaneously — no collisions
- **PoE** delivers power over Ethernet cable (802.3af = 15.4 W, 802.3at = 30 W, 802.3bt = up to 100 W)

**Next:** [Layer 2 — Data Link](04-data-link-layer.md) — frames, MAC addresses, and how switches work
