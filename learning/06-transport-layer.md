# Layer 4 — The Transport Layer

The Transport Layer provides **end-to-end communication between applications** on different hosts. While IP (Layer 3) delivers packets to the right machine, the Transport Layer delivers data to the right **application** on that machine — and optionally guarantees that delivery is reliable.

The two main protocols are **TCP** (reliable) and **UDP** (fast and lightweight).

---

## Ports: Identifying Applications

An IP address identifies a machine. A **port number** (0–65535) identifies a specific application on that machine.

When you connect to a web server:
- **Destination port 443** → the web server's HTTPS listener
- **Source port ~50000** → your browser's ephemeral (temporary) port, chosen randomly

### Port Categories

| Range | Type | Examples |
|-------|------|---------|
| 0–1023 | Well-known ports | 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 443 HTTPS |
| 1024–49151 | Registered ports | 3306 MySQL, 5432 PostgreSQL, 8080 HTTP-alt |
| 49152–65535 | Dynamic/ephemeral | Source ports for client connections |

A **socket** is the combination of IP address + port: `192.168.1.10:443`. A **connection** is defined by 5 fields: protocol, source IP, source port, destination IP, destination port.

---

## TCP — Transmission Control Protocol

TCP provides **reliable, ordered, error-checked delivery** of a stream of bytes. The Internet's workhorse for everything that must not lose data: web browsing, email, file transfers, SSH.

### The TCP 3-Way Handshake

Before data flows, TCP establishes a connection:

```
Client                     Server
  |─── SYN (seq=100) ────────►|   "I want to connect, starting at seq 100"
  |◄── SYN-ACK (seq=200, ack=101) ─|   "OK, I'm at seq 200, I got your 100"
  |─── ACK (ack=201) ────────►|   "Got it, you're at 201"
  |═══════ Data flows ════════|
```

- **SYN** — synchronize sequence numbers
- **ACK** — acknowledge received data (acknowledges next expected byte)
- **SEQ** — sequence number ensures ordered reassembly

### Connection Termination (4-Way Handshake)

```
Client                     Server
  |─── FIN ──────────────────►|   "I'm done sending"
  |◄── ACK ───────────────────|   "Got it"
  |◄── FIN ───────────────────|   "I'm also done"
  |─── ACK ──────────────────►|   "Got it, connection closed"
```

### TCP Features

**Reliability** — every segment is acknowledged. Missing segments are retransmitted.

**Ordering** — sequence numbers allow reassembly in order, even if packets arrive out of order.

**Flow Control** — the **receive window** (advertised in every ACK) tells the sender: *"don't send more than N bytes before I ACK."* Prevents a fast sender from overwhelming a slow receiver.

**Congestion Control** — TCP reduces its send rate when it detects network congestion:
- **Slow Start** — begin at 1 MSS, double window each RTT until threshold
- **Congestion Avoidance** — additive increase after threshold
- **Fast Retransmit / Fast Recovery** — react to 3 duplicate ACKs (packet loss signal) without waiting for timeout

### TCP Flags (control bits)

| Flag | Meaning |
|------|---------|
| SYN | Synchronize (connection open) |
| ACK | Acknowledge |
| FIN | Finish (connection close) |
| RST | Reset (immediate close, abort) |
| PSH | Push data to application immediately |
| URG | Urgent data present |
| ECE / CWR | Explicit Congestion Notification |

### TCP States

A TCP socket moves through states: LISTEN → SYN_SENT → SYN_RECEIVED → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED

**TIME_WAIT** lasts 2× MSL (Maximum Segment Lifetime, usually 60 s) to ensure the final ACK reaches the server and delayed packets die off. You'll see many TIME_WAIT connections in `pktana connections`.

---

## UDP — User Datagram Protocol

UDP is **connectionless and unreliable**. It sends datagrams without:
- Establishing a connection first
- Guaranteeing delivery
- Guaranteeing order
- Congestion control

Why use UDP? **Speed and simplicity.** For applications that:
- Can tolerate loss (video streaming — a dropped frame is just a glitch)
- Resend on their own if needed (DNS — just retry after timeout)
- Need real-time data and old data is worse than no data (VoIP, gaming)
- Broadcast/multicast (can't do TCP with many receivers)

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Yes (3-way handshake) | No |
| Reliability | Guaranteed | Best-effort |
| Ordering | Yes | No |
| Header size | 20–60 bytes | 8 bytes |
| Speed overhead | Higher | Very low |
| Use cases | HTTP, SSH, FTP, email | DNS, VoIP, QUIC, gaming, streaming |

---

## QUIC — The New Transport Protocol

**QUIC** (Quick UDP Internet Connections) is a modern transport protocol built on top of UDP. It's the foundation of **HTTP/3**.

QUIC improvements over TCP:
- **0-RTT connection establishment** — reconnect to a known server with zero round trips
- **Built-in TLS 1.3** — encryption is mandatory, not bolt-on
- **Multiple streams** — head-of-line blocking eliminated at the transport layer
- **Connection migration** — move between Wi-Fi and cellular without reconnecting

QUIC uses UDP port **443** by default. It's now used by YouTube, Google, Cloudflare, and Facebook for a large portion of their traffic.

---

## TCP Segment Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data | Rsrvd |     Flags     |            Window             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## Common TCP Problems

**Retransmission** — a segment wasn't acknowledged in time; TCP resends it. High retransmit rates = congestion or packet loss.

**Out-of-order delivery** — packets arrive out of sequence. TCP buffers and reorders.

**Window full** — receiver's buffer is full; sender must wait (TCP Zero Window). Causes stalls.

**RST storm** — a firewall or middlebox is injecting RST packets to tear down connections.

---

## Try It With pktana

```bash
# See all TCP connections with state
pktana connections

# Capture a TCP handshake in real time
pktana capture --interface eth0 --filter "tcp" --count 20

# Filter for UDP traffic (DNS is the most common)
pktana capture --interface eth0 --filter "udp port 53" --count 10
```

In the pktana Web UI, expand a TCP packet to see:
- Source/destination ports
- Sequence and acknowledgment numbers
- TCP flags (SYN, ACK, FIN, RST)
- Window size
- Full payload (HTTP, DNS, etc.)

---

## Summary

- **Ports** identify applications on a host (0–1023 = well-known, ephemeral = client-side)
- **TCP** is reliable: 3-way handshake, ACKs, retransmission, ordering, flow/congestion control
- **UDP** is fast and stateless: no connection, no guarantees, 8-byte header
- **QUIC** (HTTP/3) is a UDP-based transport with built-in TLS and multi-stream support
- Connections are identified by 5-tuple: protocol, src IP, src port, dst IP, dst port

**Next:** [Layer 7 — Application](07-application-layer.md) — HTTP, DNS, TLS, and the protocols you use every day
