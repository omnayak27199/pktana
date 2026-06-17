# The OSI Model

The **OSI Model** (Open Systems Interconnection) is a 7-layer framework that describes how data travels from an application on one computer to an application on another. It was defined by ISO in 1984 and remains the standard mental model for networking.

---

## Why a Layered Model?

Networking is complex. By splitting the problem into **layers**, each layer solves a specific sub-problem and only talks to the layers immediately above and below it.

Benefits:
- **Modularity** — swap out Wi-Fi for Ethernet without changing TCP
- **Interoperability** — devices from different vendors work together
- **Troubleshooting** — isolate problems to a specific layer

---

## The 7 Layers

```
7  Application    ← closest to the user (HTTP, DNS, SMTP)
6  Presentation   ← encoding, encryption, compression (TLS, JPEG)
5  Session        ← managing connections (RPC, NetBIOS)
4  Transport      ← reliable/unreliable delivery (TCP, UDP)
3  Network        ← routing, logical addressing (IP, ICMP)
2  Data Link      ← frames, MAC addresses, switching (Ethernet, Wi-Fi)
1  Physical       ← raw bits over medium (cables, radio waves)
```

A helpful mnemonic (top to bottom): **All People Seem To Need Data Processing**
Bottom to top: **Please Do Not Throw Sausage Pizza Away**

---

## How Each Layer Works

### Layer 7 — Application
The layer users interact with directly. It defines **what** the application wants to do: fetch a web page, send an email, query DNS. HTTP, HTTPS, FTP, SMTP, DNS, and SSH all live here.

### Layer 6 — Presentation
Handles **format translation** — converting data between the application's internal format and a standard network format. Also handles encryption (TLS) and compression (gzip). In modern practice, this layer is often folded into the Application layer.

### Layer 5 — Session
Manages **sessions** — opening, maintaining, and closing a conversation between two applications. Handles authentication, reconnection, and dialog control. Again, in TCP/IP practice this is mostly handled by the Transport and Application layers.

### Layer 4 — Transport
Controls **how** data is delivered end-to-end:
- **TCP** — breaks data into segments, numbers them, ensures all arrive, retransmits lost ones
- **UDP** — fires packets without tracking; faster, used for video/DNS/gaming

Ports live at this layer.

### Layer 3 — Network
Handles **routing** — deciding the path packets take across multiple networks. The **IP** protocol lives here. Routers operate at Layer 3, reading IP addresses to forward packets toward their destination.

### Layer 2 — Data Link
Handles **local delivery** between directly connected devices. It wraps packets into **frames** and uses **MAC addresses** to identify devices on the same network segment. Ethernet and Wi-Fi live here. Switches operate at Layer 2.

### Layer 1 — Physical
The actual medium: voltage levels on copper cable, light pulses in fiber, radio waves in the air. This layer defines connectors, cable types, signal timing, and bit rates.

---

## Encapsulation: How Data Travels Down

When an application sends data, each layer **adds its own header** (and sometimes trailer) before passing it to the layer below. This is called **encapsulation**.

```
Application data:    [HTTP request]
+ Transport header:  [TCP header][HTTP request]
+ Network header:    [IP header][TCP header][HTTP request]
+ Data Link header:  [Ethernet header][IP header][TCP header][HTTP request][Ethernet trailer]
+ Physical:          10101010110100...  (bits on the wire)
```

On the receiving end, each layer **strips** its header and passes the rest up — **de-encapsulation**.

---

## PDU Names per Layer

Each layer has a name for the data unit it handles:

| Layer | PDU Name |
|-------|---------|
| 7–5   | Data    |
| 4     | Segment (TCP) / Datagram (UDP) |
| 3     | Packet  |
| 2     | Frame   |
| 1     | Bit     |

---

## OSI vs. TCP/IP Model

In practice, the Internet uses the **TCP/IP model** which condenses 7 layers into 4:

| TCP/IP Layer | Equivalent OSI Layers |
|-------------|----------------------|
| Application | 5, 6, 7              |
| Transport   | 4                    |
| Internet    | 3                    |
| Network Access (Link) | 1, 2       |

The OSI model is used for teaching and troubleshooting; the TCP/IP model is what's actually implemented.

---

## Real-World Example: Loading a Web Page

1. **Layer 7** — Your browser creates an HTTP GET request for `https://example.com`
2. **Layer 6** — TLS encrypts the request
3. **Layer 5** — A TCP session was already established (or is being established)
4. **Layer 4** — TCP wraps the data in a segment, assigns source/destination ports (e.g. 443)
5. **Layer 3** — IP wraps in a packet with source IP (your machine) and destination IP (example.com)
6. **Layer 2** — Ethernet wraps in a frame with your MAC and your router's MAC
7. **Layer 1** — Converted to electrical signals (or Wi-Fi radio waves) and transmitted

At the server, this process runs in reverse.

---

## Try It With pktana

pktana decodes every packet across all layers:

```bash
# Capture HTTP traffic and see the full decode
pktana capture --interface eth0 --filter "port 80" --count 5
```

In the Web UI (`pktana web`), click any captured packet to expand:
- **Ethernet** header (Layer 2) — MAC addresses
- **IP** header (Layer 3) — IP addresses, TTL
- **TCP** header (Layer 4) — ports, sequence numbers
- **HTTP** body (Layer 7) — method, headers, payload

---

## Summary

- The OSI model has 7 layers, each solving a specific networking sub-problem
- Data is **encapsulated** going down the stack, **de-encapsulated** going up
- The **TCP/IP model** (4 layers) is what the Internet actually uses
- Layers let you swap out pieces independently (change Wi-Fi to Ethernet without touching TCP)

**Next:** [Layer 1 — Physical](03-physical-layer.md) — cables, signals, and how bits travel
