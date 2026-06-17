# Wireless Networking

Wireless networking transmits data without physical cables by encoding bits in **radio frequency (RF) signals**. From the smartphone in your pocket to the satellite link bouncing off orbit, wireless is everywhere — and increasingly the primary way humans access networks.

---

## Radio Frequency Basics

Radio waves are electromagnetic waves. Key properties:

**Frequency** — measured in Hz (cycles per second). Higher frequency = shorter wavelength = more bandwidth but shorter range and worse penetration through walls.

**Wavelength** — inversely proportional to frequency. 2.4 GHz → ~12.5 cm wavelength; 5 GHz → ~6 cm.

**Bands commonly used in networking:**

| Band | Frequency | Characteristics |
|------|-----------|----------------|
| 2.4 GHz | 2400–2483 MHz | Long range, wall penetration, crowded |
| 5 GHz | 5150–5850 MHz | Shorter range, cleaner, more channels |
| 6 GHz | 5925–7125 MHz | Wi-Fi 6E/7, very clean, short range |
| Sub-1 GHz | 800–900 MHz | Cellular, IoT — very long range |
| mmWave | 24–100 GHz | 5G mmWave — ultra-high throughput, very short range |

---

## Wi-Fi (IEEE 802.11)

Wi-Fi is the dominant wireless LAN technology. It operates in the unlicensed ISM and UNII bands.

### Wi-Fi Generations

| Generation | Standard | Max Speed | Bands | Year |
|-----------|---------|-----------|-------|------|
| Wi-Fi 4 | 802.11n | 600 Mbps | 2.4/5 GHz | 2009 |
| Wi-Fi 5 | 802.11ac | 3.5 Gbps | 5 GHz | 2013 |
| Wi-Fi 6 | 802.11ax | 9.6 Gbps | 2.4/5 GHz | 2019 |
| Wi-Fi 6E | 802.11ax | 9.6 Gbps | 2.4/5/6 GHz | 2021 |
| Wi-Fi 7 | 802.11be | 46 Gbps | 2.4/5/6 GHz | 2024 |

Max speeds are theoretical. Real throughput is significantly lower.

### OFDM and Channels

Wi-Fi uses **OFDM (Orthogonal Frequency Division Multiplexing)** — the spectrum is split into many narrow subcarriers that transmit in parallel.

**Channels** are defined slices of frequency spectrum. In 2.4 GHz, there are 14 channels (varies by country) but only 3 are non-overlapping: **1, 6, 11**. Using overlapping channels causes interference.

**Channel width:**
- 20 MHz — legacy, low interference
- 40 MHz — 802.11n, 2× throughput
- 80 MHz — 802.11ac/ax (5 GHz)
- 160 MHz — Wi-Fi 6/6E for maximum throughput

### Wi-Fi Network Components

**Access Point (AP):** the wireless base station. It connects wirelessly to clients and via Ethernet to the wired network.

**SSID (Service Set Identifier):** the network name. An AP broadcasts its SSID in **beacon frames** every 100 ms.

**BSS (Basic Service Set):** one AP + its associated clients.

**ESS (Extended Service Set):** multiple APs sharing the same SSID for seamless roaming.

### Wi-Fi Association Process

```
Client                          AP
  |─── Probe Request ──────────►|  "Any AP out there on any channel?"
  |◄── Probe Response ──────────|  "I'm here, I'm AP1 (SSID: MyWiFi)"
  |─── Authentication Request ──►|  "I want to authenticate"
  |◄── Authentication Response ──|  "OK"
  |─── Association Request ─────►|  "Associate me to your BSS"
  |◄── Association Response ─────|  "You're associated, AID=3"
  |═══════ 4-Way Handshake ══════|  (WPA2/3 key exchange)
  |═══════ Encrypted data ═══════|
```

### Wi-Fi Security

| Protocol | Status | Notes |
|---------|--------|-------|
| WEP | Broken — never use | RC4, shared key, cracked in minutes |
| WPA | Deprecated | TKIP with RC4, still vulnerable |
| WPA2-Personal | Widely used | AES-CCMP, PBKDF2 key derivation |
| WPA2-Enterprise | Enterprise standard | 802.1X/EAP, per-user credentials via RADIUS |
| WPA3-Personal | Modern | SAE (Simultaneous Authentication of Equals), forward secrecy |
| WPA3-Enterprise | Gold standard | 192-bit mode, MACsec capability |

**WPA2-Personal weakness:** the 4-way handshake can be captured and the PSK brute-forced offline. Use a strong, random passphrase.

---

## CSMA/CA — Collision Avoidance

Unlike wired Ethernet (which can detect collisions as they happen — CSMA/CD), wireless can't detect collisions because a radio transmitting can't "hear" itself receive. Wi-Fi uses **CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance)**:

1. **Listen** before transmitting (carrier sense)
2. If medium is busy, **wait** a random backoff time
3. If idle for DIFS (Distributed IFS), transmit
4. Receiver sends an **ACK**; if no ACK, retransmit (collision assumed)

This is why Wi-Fi is half-duplex — you can't transmit and receive at the same time on the same radio.

### MU-MIMO and OFDMA

**MU-MIMO (Multi-User, Multiple Input, Multiple Output):** the AP can transmit to multiple clients simultaneously using multiple antennas. Wi-Fi 5 introduced downlink MU-MIMO; Wi-Fi 6 adds uplink.

**OFDMA (Orthogonal Frequency Division Multiple Access):** Wi-Fi 6's biggest improvement. The channel is divided into small resource units (RUs) that can be allocated to different clients simultaneously — like giving each user their own lane on the highway. Dramatically improves efficiency in dense environments (stadiums, offices).

---

## Cellular Networks

Cellular networks divide geography into **cells**, each served by a base station. As you move, your device **hands off** from one cell to another.

### Generations

| Gen | Technology | Peak Speed | Latency | Key Feature |
|----|-----------|-----------|---------|------------|
| 2G | GSM/EDGE | 384 kbps | ~300 ms | Voice + SMS + basic data |
| 3G | UMTS/HSPA+ | 42 Mbps | ~50 ms | Smartphone era |
| 4G LTE | LTE-A | 300+ Mbps | ~30 ms | Broadband everywhere |
| 5G | NR (New Radio) | 20 Gbps | <1 ms | Enhanced mobile broadband, URLLC, mMTC |

### 5G Architecture

5G introduces three use-case families:
- **eMBB (enhanced Mobile Broadband)** — faster download speeds for consumers
- **URLLC (Ultra-Reliable Low-Latency Communications)** — <1 ms latency for industrial automation, autonomous vehicles
- **mMTC (massive Machine-Type Communications)** — millions of low-power IoT devices per km²

5G uses **NR** (New Radio) with sub-6 GHz for range and coverage, plus **mmWave** (24–100 GHz) for ultra-high throughput in dense urban areas.

---

## Bluetooth

Short-range wireless for personal area networks (PANs).

| Version | Max Speed | Range | Key Use |
|---------|-----------|-------|---------|
| Classic | 3 Mbps | 10 m | Audio, file transfer |
| BLE (4.0+) | 1 Mbps | 50 m | IoT, sensors, beacons |
| Bluetooth 5 | 2 Mbps | 200 m | IoT, direction finding |

Uses **frequency hopping** (79 channels, 1600 hops/sec) to avoid interference.

---

## Other Wireless Technologies

| Technology | Range | Speed | Use Case |
|-----------|-------|-------|---------|
| Zigbee (802.15.4) | 10–100 m | 250 kbps | IoT mesh (smart home, industrial) |
| Z-Wave | 30 m | 100 kbps | Home automation |
| LoRaWAN | 5–15 km | 0.3–50 kbps | Long-range IoT (agriculture, cities) |
| NB-IoT | Wide (cellular) | 200 kbps | Cellular IoT (smart meters) |
| WiMAX | 50 km | 1 Gbps | Fixed wireless broadband |
| Satellite (LEO) | Global | 100–500 Mbps | Remote broadband (Starlink, OneWeb) |

---

## Wireless Challenges

**Interference:** Competing signals in the same band (microwaves, neighboring APs, Bluetooth) degrade signal.

**Hidden node problem:** Two clients that can't hear each other both transmit to the AP simultaneously → collision. RTS/CTS handshake partially mitigates this.

**Near-far problem:** A strong nearby device drowns out a weak distant device. Power control helps.

**Multipath fading:** Signals bounce off walls and arrive at the receiver at slightly different times, interfering with each other. OFDM was specifically designed to resist multipath.

**Attenuation:** Signal strength drops with distance (inverse square law) and through obstructions (walls, floors, human bodies).

---

## Try It With pktana

```bash
# List wireless interfaces alongside wired
pktana nic list

# Capture Wi-Fi management frames (probe, beacon, auth, assoc)
# Requires monitor mode — set interface to monitor mode first:
# sudo iw dev wlan0 set type monitor
pktana capture --interface wlan0 --count 50
```

In the pktana Web UI, Wi-Fi frames show:
- Frame type (data, management, control)
- SSID (for management frames)
- BSSID and client MAC
- Signal strength (RSSI) if the driver provides it

---

## Summary

- Wi-Fi uses unlicensed RF bands; newer generations (Wi-Fi 6/6E/7) add OFDMA and MU-MIMO for dense environments
- Cellular (4G/5G) covers wide areas with licensed spectrum; 5G targets eMBB, URLLC, and mMTC
- CSMA/CA is Wi-Fi's collision avoidance mechanism; full-duplex is not possible on a single radio
- WPA3 is the current gold standard for Wi-Fi security; WEP/WPA are broken
- Wireless faces unique challenges: interference, multipath, hidden node, and attenuation

**Next:** [Network Security](10-network-security.md) — threats, defenses, and how to protect a network
