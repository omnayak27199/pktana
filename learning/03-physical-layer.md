# Layer 1 — The Physical Layer

The Physical Layer is the foundation of all networking. It converts the abstract **bits** (0s and 1s) that computers use into actual physical signals — electrical voltages, light pulses, or radio waves — and transmits them across a medium.

No addressing, no framing, no error correction at this layer. Just raw bits on a wire (or in the air).

---

## Transmission Media

### Twisted-Pair Copper Cable (Ethernet)
The most common wired medium. Wire pairs are twisted together to reduce electromagnetic interference (EMI). Categories:

| Category | Max Speed | Max Distance | Common Use |
|----------|-----------|--------------|-----------|
| Cat 5e   | 1 Gbps    | 100 m        | Home networks |
| Cat 6    | 10 Gbps   | 55 m         | Office networks |
| Cat 6a   | 10 Gbps   | 100 m        | Data centers |
| Cat 8    | 40 Gbps   | 30 m         | Data center racks |

### Fiber Optic Cable
Transmits data as **pulses of light** through glass or plastic fibers. No electromagnetic interference, much longer distances.

- **Single-mode fiber (SMF)** — narrow core, laser light, up to 80+ km, used for long-haul WAN links
- **Multi-mode fiber (MMF)** — wider core, LED light, up to ~550 m, used for data centers

Speeds: 10 Gbps, 40 Gbps, 100 Gbps, 400 Gbps, and beyond.

### Coaxial Cable
A copper conductor surrounded by insulation and shielding. Once common for Ethernet (10Base-2/5), now mainly used for cable TV, DOCSIS (cable internet), and some RF applications.

### Wireless (Radio Frequency)
No physical cable — bits are encoded in radio waves. Covered in depth in the [Wireless Networking](09-wireless-networking.md) chapter. Key standards:
- **Wi-Fi** (IEEE 802.11): 2.4 GHz, 5 GHz, 6 GHz bands
- **Cellular**: 4G LTE, 5G NR
- **Bluetooth**: short range, personal area

---

## Signaling: How Bits Become Signals

Bits must be encoded as physical changes in the medium.

### Electrical Signaling (Copper)
- **NRZ (Non-Return to Zero)** — high voltage = 1, low voltage = 0
- **Manchester encoding** — a transition mid-bit encodes the value; avoids long runs of same level
- **PAM4** — 4-level pulse amplitude modulation; encodes 2 bits per symbol; used in modern 400G Ethernet

### Optical Signaling (Fiber)
Light on = 1, light off = 0 (simple OOK), or more complex modulation schemes for high-speed links.

### RF Signaling (Wireless)
- **Amplitude Modulation** — vary the signal strength
- **Frequency Modulation** — vary the frequency
- **Phase Modulation** — vary the phase
- **QAM (Quadrature Amplitude Modulation)** — vary both phase and amplitude; 256-QAM encodes 8 bits per symbol

---

## Bandwidth and Throughput

**Bandwidth** — the maximum capacity of a link, measured in bits per second (bps).
- 100 Mbps = Fast Ethernet
- 1 Gbps = Gigabit Ethernet
- 10/40/100 Gbps = data center links

**Throughput** — the actual data rate achieved, always ≤ bandwidth. Reduced by overhead, congestion, errors.

**Latency** — time for a bit to travel from source to destination:
- Speed of light in fiber: ~200,000 km/s (≈2/3 speed of light in vacuum)
- Transcontinental fiber link: ~40–70 ms round-trip

---

## Physical Network Devices

### Hub (obsolete)
A Layer 1 device. It simply repeats all incoming signals out all ports. Every device on the hub sees every packet — no intelligence, causes collisions at scale. Replaced by switches.

### Repeater / Extender
Amplifies or regenerates signals to extend cable length. Used when a run exceeds the maximum distance.

### Media Converter
Converts between media types, e.g., copper to fiber at the edge of a building.

### Transceiver (SFP/QSFP)
Small form-factor pluggable modules that let you insert the right optic (short-range, long-range, copper DAC) into a switch port. The switch doesn't care — you swap the transceiver for the right medium.

---

## Full Duplex vs. Half Duplex

- **Half duplex** — only one device can transmit at a time (like a walkie-talkie). Old hub-based networks. Collision risk.
- **Full duplex** — both ends can transmit simultaneously (like a phone call). Modern switched Ethernet always operates full duplex.

---

## Physical Topologies

How devices are physically wired together:

- **Bus** — all devices on a single cable (old coax Ethernet). One failure can break the whole segment.
- **Star** — all devices connect to a central switch/hub. Most common today.
- **Ring** — each device connects to two neighbors in a loop (SONET, old Token Ring).
- **Mesh** — every device connects directly to every other. Very resilient, very expensive.
- **Hybrid** — a mix (star-bus, star-ring, etc.). Common in large networks.

---

## Power over Ethernet (PoE)

PoE carries electrical power over Ethernet cable alongside data. Used to power:
- IP phones
- Wireless access points
- IP cameras
- IoT sensors

Standards: 802.3af (15.4 W), 802.3at (30 W), 802.3bt (up to 100 W).

---

## Try It With pktana

```bash
# View physical interface details: speed, duplex, MTU
pktana nic list

# Check dataplane attachment on an interface
pktana dp m1
```

The `pktana nic list` output shows each interface's speed and whether it's up. The maximum payload size (MTU, usually 1500 bytes) is a Physical/Data Link interaction — the frame must fit in one transmission unit.

---

## Summary

- The Physical Layer converts bits into signals: electrical, optical, or radio
- Cable categories (Cat6, fiber) determine speed and distance limits
- **Bandwidth** is capacity; **throughput** is actual speed; **latency** is delay
- Hubs were Layer 1 repeaters; switches (Layer 2) replaced them
- PoE delivers power and data over a single Ethernet cable

**Next:** [Layer 2 — Data Link](04-data-link-layer.md) — frames, MAC addresses, and how switches work
