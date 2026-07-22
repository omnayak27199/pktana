# Layer 1 — Physical

Layer 1 moves **bits** as energy: electricity on copper, light in fiber, or radio in the air. No “IP address” lives here — only signals, connectors, speed, and media rules.

> **Remember:** Physical = **the road**. If the road is broken, nothing above it works.

---

## Big Idea Flow

```mermaid
flowchart LR
  Bits[Bits 0/1] --> Encode[Encode to signal]
  Encode --> Medium[Cable / Fiber / Radio]
  Medium --> Decode[Decode to bits]
  Decode --> Bits2[Bits for Layer 2]
```

---

## What Layer 1 Decides

- Medium type (copper, fiber, wireless)
- Connectors and pinouts (RJ‑45, optics)
- Speed and duplex (1G/10G, full duplex)
- Signaling and encoding
- Basic link status (up/down, light levels)

It does **not** decide “which website” or “which IP.” That starts higher.

---

## Media Types (simple)

| Medium | Feel it as | Strength | Watch for |
|--------|------------|----------|-----------|
| Copper (Ethernet) | Electric pulses | Cheap, common | Length limits, interference |
| Fiber | Light pulses | Long distance, quiet | Dirty connectors, bend radius |
| Wireless | Radio waves | Mobility | Walls, interference, shared air |

Related later: [Ethernet](#protocols-reference/ethernet) frames ride on this media; [Wi‑Fi](#wireless-networking) is radio + Layer 2 rules.

---

## Link Up / Link Down

```mermaid
sequenceDiagram
  participant NIC as NIC
  participant Link as Cable/Radio
  participant Peer as Peer NIC
  NIC->>Link: Signal present?
  Link->>Peer: Energy arrives
  Peer-->>NIC: Autoneg / sync
  Note over NIC,Peer: Link = UP when both sides agree on speed/signaling
```

**Symptoms that scream Layer 1**
- No link light
- Flapping interface
- CRC / FCS errors (often bad cable/optics/duplex)
- Very short distance works, longer fails

---

## Memorable Checks

1. Is the cable plugged into the **correct** port?
2. Is the interface **admin up** and **link up**?
3. Do both sides match speed/duplex expectations?
4. For fiber: dirty connector? wrong optic type?

In pktana: NIC list/stats help spot counters climbing (errors, drops).

---

## Knowledge Check

```quiz
QUESTION: Layer 1’s PDU (what it handles) is best described as:
OPTIONS:
Frames with MAC addresses
Packets with IP addresses
Raw bits / signals
HTTP requests
ANSWER: 2
EXPLAIN: Physical layer deals with bits represented as signals on a medium.
```

```quiz
QUESTION: Which problem is most likely Layer 1?
OPTIONS:
Wrong DNS server
Broken fiber connector / no link light
Wrong TCP port on firewall
Expired TLS certificate
ANSWER: 1
EXPLAIN: No link or bad media is classic Physical-layer failure.
```

```quiz
QUESTION: Wi‑Fi radio energy is primarily a Layer 1 concern, while Wi‑Fi MAC framing is Layer:
OPTIONS:
2
4
7
Only Layer 3
ANSWER: 0
EXPLAIN: Radio is L1; 802.11 framing/addressing is Data Link (L2).
```

---

## Next

Frames and local delivery: [Layer 2 — Data Link](#data-link-layer).
