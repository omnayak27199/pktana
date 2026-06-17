# Layer 4 — The Transport Layer

The Transport Layer provides **end-to-end communication between specific applications** on two hosts. The Network Layer (IP) gets a packet to the right machine. The Transport Layer gets data to the right **application** on that machine — and, when using TCP, guarantees it arrives reliably and in order.

Key responsibilities:
- **Multiplexing and Demultiplexing** — port numbers route data to the correct application process
- **Segmentation** — large application data is broken into segments that fit inside IP packets
- **Reassembly** — segments arriving at the destination are reordered and reassembled
- **Connection management** — TCP establishes and terminates connections; UDP is connectionless
- **Reliability** — TCP provides acknowledgements, retransmission, and ordering; UDP does not
- **Flow control** — TCP prevents a fast sender from overwhelming a slow receiver
- **Congestion control** — TCP reduces send rate when the network is congested

The two dominant Transport Layer protocols are **TCP (Transmission Control Protocol)** and **UDP (User Datagram Protocol)**.

---

## Multiplexing with Port Numbers

An IP address identifies a host. A **port number** (16-bit integer: 0–65535) identifies a specific **application process** on that host. Multiple applications can communicate simultaneously over the same IP address because each uses a different port.

When a browser connects to a web server on port 443, and simultaneously your email client connects to a mail server also using a different source port — the OS uses the port numbers to deliver incoming data to the correct application.

A **socket** is the combination of an IP address and a port: `192.168.1.10:54321`.

A **connection** is uniquely identified by the **5-tuple**: `Protocol + Source IP + Source Port + Destination IP + Destination Port`. This is how one machine can handle tens of thousands of simultaneous connections.

### Port Ranges

| Range | Name | Examples |
|-------|------|---------|
| 0–1023 | **Well-known / System** | 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 443 HTTPS |
| 1024–49151 | **Registered** | 3306 MySQL, 5432 PostgreSQL, 8080 HTTP alt |
| 49152–65535 | **Dynamic / Ephemeral** | Client source ports chosen randomly per connection |

When your browser connects to a web server on port 443, your OS picks a random **ephemeral source port** (e.g., 54321) for that connection. When the server replies, it sends to `your-IP:54321`. The OS sees port 54321 and delivers the data to your browser.

### Well-Known Ports to Know

| Port | Protocol | Transport |
|------|---------|-----------|
| 20 | FTP Data | TCP |
| 21 | FTP Control | TCP |
| 22 | SSH / SFTP | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | UDP (and TCP for large responses) |
| 67/68 | DHCP Server/Client | UDP |
| 69 | TFTP | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 123 | NTP | UDP |
| 143 | IMAP | TCP |
| 161/162 | SNMP | UDP |
| 179 | BGP | TCP |
| 389 | LDAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 514 | Syslog | UDP |
| 587 | SMTP Submission | TCP |
| 993 | IMAPS | TCP |
| 995 | POP3S | TCP |
| 3389 | RDP | TCP |

---

## TCP — Transmission Control Protocol

TCP provides **reliable, ordered, error-checked delivery of a byte stream** between two applications. Every byte is numbered. Every segment must be acknowledged. Lost segments are retransmitted. Data is delivered to the application in order, even if segments arrive out of order.

Use TCP when data must not be lost: web browsing (HTTP/HTTPS), email, SSH, file transfer, database queries.

### The TCP Segment Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────────┬───────────────────────────────┐
│         Source Port           │       Destination Port        │
├───────────────────────────────┴───────────────────────────────┤
│                       Sequence Number                         │
├───────────────────────────────────────────────────────────────┤
│                    Acknowledgment Number                      │
├───────────┬──────────┬────────────────────────────────────────┤
│ Data Off. │ Reserved │  Flags  │         Window Size          │
├───────────┴──────────┴─────────┴────────────────────────────┤
│           Checksum            │         Urgent Pointer        │
└───────────────────────────────────────────────────────────────┘
  [Options — up to 40 bytes if Data Offset > 5]
```

| Field | Size | Purpose |
|-------|------|---------|
| Source Port | 16 bits | Sender's port number |
| Destination Port | 16 bits | Receiver's port number |
| Sequence Number | 32 bits | Byte offset of the first byte in this segment |
| Acknowledgment Number | 32 bits | Next byte the receiver expects (ACKs all bytes up to this − 1) |
| Data Offset | 4 bits | TCP header length in 32-bit words (min 5 = 20 bytes) |
| Flags | 9 bits | Control bits (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR) |
| Window Size | 16 bits | Receiver's available buffer space (flow control) |
| Checksum | 16 bits | Error detection over header + data + pseudo-header |
| Urgent Pointer | 16 bits | Points to urgent data (if URG flag set) |

### TCP Flags

| Flag | Purpose |
|------|---------|
| **SYN** | Synchronise — initiates a connection; carries the sender's ISN |
| **ACK** | Acknowledge — the Acknowledgment Number field is valid |
| **FIN** | Finish — sender has no more data to send; initiates graceful close |
| **RST** | Reset — immediately aborts the connection (error or unreachable port) |
| **PSH** | Push — deliver buffered data to the application immediately, don't wait to fill a buffer |
| **URG** | Urgent — urgent pointer field is valid (rarely used in modern applications) |
| **ECE** | ECN-Echo — congestion was experienced (Explicit Congestion Notification) |
| **CWR** | Congestion Window Reduced — sender already reduced transmission rate |

---

## TCP Connection Establishment — The 3-Way Handshake

Before any data is exchanged, TCP establishes a connection through a 3-way handshake. Both sides synchronise their **sequence numbers** (ISN — Initial Sequence Number).

```
Client                                   Server
  │                                          │
  │──── SYN (seq=1000) ────────────────────►│
  │     "I want to connect; my ISN is 1000"  │
  │                                          │
  │◄─── SYN-ACK (seq=2000, ack=1001) ────────│
  │     "OK; my ISN is 2000; got your 1000;  │
  │      next byte I expect from you: 1001"  │
  │                                          │
  │──── ACK (ack=2001) ────────────────────►│
  │     "Got it; next byte I expect from     │
  │      you: 2001. Connection established." │
  │                                          │
  │═══════════ Data flows ════════════════════│
```

**Step 1 — SYN:** Client sends a segment with SYN flag and a randomly chosen ISN. This randomness prevents TCP sequence prediction attacks.

**Step 2 — SYN-ACK:** Server acknowledges the client's ISN (ack = client ISN + 1) and sends its own ISN.

**Step 3 — ACK:** Client acknowledges the server's ISN (ack = server ISN + 1). Connection is now ESTABLISHED on both sides.

The handshake adds **1 RTT (Round-Trip Time)** of latency before data can flow. TLS adds another 1–2 RTTs. QUIC (HTTP/3) reduces this to 0–1 RTT.

---

## TCP Connection Termination — The 4-Way Handshake

TCP connections are full-duplex — each direction closes independently. The standard graceful close takes 4 steps:

```
Client                                   Server
  │──── FIN ─────────────────────────────►│  "I'm done sending data"
  │◄─── ACK ──────────────────────────────│  "Got it" (server may still send)
  │◄─── FIN ──────────────────────────────│  "I'm also done sending"
  │──── ACK ─────────────────────────────►│  "Got it"
  │                                        │
  [Client waits in TIME_WAIT for 2×MSL]
```

**Half-close:** between steps 2 and 3, the server can still send remaining data. The client must accept it.

**TIME_WAIT:** the active closer (client in the example) waits for 2 × MSL (Maximum Segment Lifetime, typically 30–60 seconds) before fully releasing the connection. This ensures:
1. The final ACK reaches the server (if lost, server will retransmit its FIN and the client can re-ACK)
2. Any stale packets from the old connection die off before the same port pair is reused

**RST (Reset):** an immediate, ungraceful connection abort. Sent when a port is closed (nothing listening), when a packet arrives for a dead connection, or when a firewall/middlebox terminates a connection. No TIME_WAIT on the RST side.

---

## TCP Sequence and Acknowledgment Numbers

TCP numbers every byte in the data stream. Sequence and acknowledgment numbers track exactly which bytes have been sent and received.

**Sequence Number:** the byte offset of the first byte in this segment. If the connection starts at ISN=1000 and the first segment carries 500 bytes, it has seq=1001 (ISN+1 is the first data byte).

**Acknowledgment Number:** the next byte the receiver expects. An ACK of 1501 means "I received up to byte 1500; send byte 1501 next." This implicitly acknowledges all bytes up to 1500.

**Cumulative ACK:** TCP's acknowledgment covers all data up to the ACK number. If bytes 1–1000 and 1501–2000 arrived but 1001–1500 are missing, the receiver can only ACK 1001 (the next expected byte after the gap).

---

## Reliability — Acknowledgements and Retransmission

TCP guarantees that every segment is delivered. The mechanism is **positive acknowledgement with retransmission**:

1. Sender transmits a segment and starts a **retransmission timer (RTO)**
2. Receiver sends an ACK with the next expected sequence number
3. If the sender's timer expires before the ACK arrives, the sender **retransmits** the segment

**RTO (Retransmission Timeout)** is dynamically calculated based on measured RTT:
- The sender continuously measures RTT (time from sending a segment to receiving its ACK)
- RTO is set to SRTT (smoothed RTT) plus a margin for variance: `RTO = SRTT + 4 × RTTVAR`
- RTO backs off exponentially after each timeout (doubles up to a maximum)

---

## Flow Control — The Sliding Window

Flow control prevents the sender from transmitting faster than the receiver can process.

The receiver advertises its available buffer space in the **Window field** of every ACK — this is the **receive window (rwnd)**. The sender must not have more than `rwnd` bytes outstanding (sent but not yet ACKed) at any time.

```
Bytes: 1   2   3   4   5   6   7   8   9   10
       ✓   ✓   ✓  [─────── sent, unacked ──────]  [── not sent ──]
                   ← window = 4 bytes →
                   Receiver ACKs 4 → window slides right
```

As the receiver processes data and frees buffer space, it advertises a larger window, and the sender can send more.

**TCP Zero Window:** the receiver sets window = 0, telling the sender to stop transmitting. The sender sends periodic **Zero Window Probes** (single-byte segments) to check when the receiver has free space again. A Zero Window indicates the receiver is overwhelmed — a common cause of throughput degradation.

**Window Scaling (RFC 7323):** the standard 16-bit window field caps the window at 65,535 bytes. On high-bandwidth, high-latency links (e.g., 1 Gbps over a 100 ms trans-ocean link), the bandwidth-delay product is ~12.5 MB — the window must be 12.5 MB to fully utilise the link. The Window Scale option, negotiated at handshake, multiplies the window by a power of 2 (up to 2¹⁴), allowing windows up to ~1 GB.

---

## Congestion Control

Congestion control prevents TCP senders from overwhelming the **network** (as opposed to flow control, which protects the receiver). When routers are overwhelmed, they drop packets — TCP uses packet loss as a signal to slow down.

The sender maintains a **congestion window (cwnd)**. The actual send rate is `min(cwnd, rwnd)`.

### Slow Start

After a new connection or after a timeout-triggered loss:
1. Start with `cwnd = 1 MSS` (Maximum Segment Size — typically 1460 bytes on Ethernet)
2. For each ACK received, increase cwnd by 1 MSS — this **doubles cwnd every RTT** (exponential growth)
3. Continue until cwnd reaches the **slow start threshold (ssthresh)**, then switch to Congestion Avoidance

Despite the name, slow start grows quickly (exponentially). It is "slow" only compared to sending at full speed immediately.

### Congestion Avoidance

Once cwnd ≥ ssthresh:
- Increase cwnd by 1 MSS per RTT (linear/additive growth)
- This is **AIMD — Additive Increase, Multiplicative Decrease**

### Reacting to Loss

**Timeout (RTO expires):** severe congestion indicator.
- Set ssthresh = cwnd / 2
- Reset cwnd = 1 MSS
- Restart Slow Start

**3 Duplicate ACKs (Fast Retransmit/Fast Recovery):** receiving 3 identical ACKs means one segment was lost but later ones arrived. TCP immediately retransmits the missing segment without waiting for RTO.
- Set ssthresh = cwnd / 2
- Set cwnd = ssthresh (not 1) — skip Slow Start entirely
- Enter Congestion Avoidance immediately

Fast retransmit is far more efficient than waiting for a timeout — the connection stays active and the send rate recovers quickly.

### SACK — Selective Acknowledgement

Without SACK: if segment 5 is lost but segments 6–10 arrive, TCP can only ACK up to segment 4. The sender must retransmit segments 5–10 (Go-Back-N).

With **SACK (RFC 2018):** the receiver reports which byte ranges arrived out of order:
```
ACK=<next expected>, SACK blocks: [(6–10 received)]
```
The sender only retransmits the missing segment 5. SACK dramatically improves efficiency when multiple packets are lost in a window.

SACK is negotiated at the handshake and is supported by nearly all modern implementations.

### Modern Congestion Control Algorithms

| Algorithm | OS Default | Behaviour |
|----------|-----------|----------|
| **Reno** | Baseline | Classic AIMD; halves cwnd on any loss |
| **CUBIC** | Linux (since 2.6.19) | Cubic function for cwnd growth; slower recovery after loss than Reno |
| **BBR (Bottleneck Bandwidth and RTT)** | Available on Linux/Android | Model-based; estimates actual bottleneck bandwidth; higher throughput on long-distance links; doesn't rely on loss |
| **QUIC/HTTP3** | Built into QUIC | Per-stream flow control + QUIC-level congestion control |

**BBR vs CUBIC:** CUBIC reduces send rate on packet loss, which can be caused by buffer bloat (long queues) rather than actual capacity. BBR measures actual bandwidth and RTT, achieving higher utilisation especially on satellite and trans-ocean links.

---

## TCP States

TCP connections move through a defined state machine.

| State | Description |
|-------|------------|
| **CLOSED** | No connection exists |
| **LISTEN** | Server waiting for incoming connections (passive open) |
| **SYN_SENT** | Client sent SYN; waiting for SYN-ACK |
| **SYN_RECEIVED** | Server received SYN; sent SYN-ACK; waiting for ACK |
| **ESTABLISHED** | Connection active; data can flow in both directions |
| **FIN_WAIT_1** | Active close: FIN sent; waiting for ACK |
| **FIN_WAIT_2** | FIN acknowledged; waiting for remote FIN |
| **CLOSE_WAIT** | Received FIN from remote; local application hasn't closed yet |
| **CLOSING** | Both sides sent FIN simultaneously |
| **LAST_ACK** | Passive close: FIN sent; waiting for final ACK |
| **TIME_WAIT** | Final ACK sent; waiting 2×MSL for stale packets to expire |

```bash
ss -tnp     # view TCP connections with state (Linux)
netstat -an # classic view (all platforms)
```

A server with many TIME_WAIT connections is normal — it means many short connections are being closed gracefully. Tens of thousands of TIME_WAIT connections may indicate a port exhaustion issue.

---

## TCP Performance Options

Negotiated during the 3-way handshake via TCP options:

| Option | Purpose |
|--------|---------|
| **MSS** | Maximum Segment Size — largest payload per segment (default 1460 B on Ethernet) |
| **Window Scale** | Multiplies window by 2^n to support windows larger than 65 KB |
| **SACK Permitted** | Both sides agree to use Selective Acknowledgement |
| **Timestamps** | Accurate RTT measurement; PAWS (Protection Against Wrapped Sequence numbers) |
| **TCP Fast Open (TFO)** | Allows sending data in the SYN packet for reconnections (0-RTT data) |

**MSS** is calculated to avoid fragmentation: `MSS = MTU − IP header (20 B) − TCP header (20 B) = 1460 B` for standard 1500 B Ethernet MTU.

**Nagle's Algorithm:** delays small writes, batching them into one MSS-sized segment if there is unacknowledged data in flight. Improves efficiency for bulk transfers. Disabled with the `TCP_NODELAY` socket option — required for interactive applications (SSH, databases, games) that must send small packets with minimal delay.

---

## UDP — User Datagram Protocol

UDP is **connectionless, unreliable, and stateless**. It delivers datagrams with no setup, no acknowledgement, no ordering guarantee, and no congestion control. What it offers is simplicity and speed.

### UDP Header (8 bytes)

```
┌─────────────────────┬─────────────────────┐
│    Source Port      │  Destination Port   │
├─────────────────────┼─────────────────────┤
│       Length        │      Checksum       │
└─────────────────────┴─────────────────────┘
```

Total header size: **8 bytes** (versus 20 bytes minimum for TCP). The length field covers UDP header + payload.

### When to Use UDP

UDP is not "worse than TCP" — it is the right choice when:

| Use Case | Why UDP Is Correct |
|---------|-------------------|
| **DNS** | Single request → single response; if lost, app retries in milliseconds |
| **DHCP** | Broadcast-based; no connection possible before IP assignment |
| **VoIP / Video calls** | A late packet is worse than a lost one; real-time data, not buffered |
| **Online gaming** | Player position must be current; stale data is useless |
| **Streaming video** | Occasional dropped frames are invisible; retransmission would cause jitter |
| **NTP** | Simple one-shot time query |
| **TFTP** | Simple file transfer with its own per-block ACK |
| **SNMP** | Management queries that tolerate loss |
| **QUIC (HTTP/3)** | Reliability implemented at QUIC layer, more efficiently than TCP |
| **Multicast** | Cannot establish TCP connections to thousands of receivers |

### TCP vs UDP Comparison

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | 3-way handshake | None |
| Reliability | Guaranteed delivery | Best-effort |
| Ordering | Yes (sequence numbers) | No |
| Flow control | Yes (receive window) | No |
| Congestion control | Yes (AIMD, cwnd) | No |
| Header size | 20 bytes minimum | 8 bytes |
| Setup overhead | 1 RTT | None |
| PDU name | Segment | Datagram |
| Applications | HTTP, SSH, email, DB | DNS, VoIP, streaming, QUIC |

---

## QUIC — The Modern Transport Protocol

QUIC (RFC 9000) is a transport protocol that runs over **UDP**. It is the foundation of **HTTP/3** and handles approximately 30% of Google's traffic. Created by Google, standardised by IETF.

QUIC addresses TCP's fundamental limitations in the modern web:

**Head-of-Line Blocking:** HTTP/2 over TCP multiplexes many streams over one connection. If one TCP segment is lost, all streams stall waiting for retransmission. QUIC's streams are independent — a loss in stream A does not affect stream B.

**Slow Connection Setup:** TCP + TLS 1.3 = 1 RTT each = 2 RTTs before data flows. QUIC combines transport and TLS into one handshake: **1 RTT** for new connections, **0 RTT** for reconnections to known servers.

**Ossification:** middleboxes (firewalls, NATs, load balancers) have learned to interpret and sometimes modify TCP headers. TCP cannot evolve. QUIC's entire payload is encrypted — middleboxes cannot interfere.

**Connection Migration:** TCP connections are tied to a 4-tuple (src IP, src port, dst IP, dst port). If your phone switches from Wi-Fi to cellular, the IP changes and the TCP connection breaks. QUIC uses a **64-bit Connection ID** independent of the IP/port — connections survive network transitions seamlessly.

| Feature | TCP + TLS 1.3 | QUIC (HTTP/3) |
|---------|--------------|---------------|
| Setup RTT | 2 RTT | 1 RTT |
| Reconnect RTT | 1 RTT | 0 RTT |
| Transport | TCP | UDP |
| Encryption | TLS 1.3 (separate) | TLS 1.3 (built-in) |
| Multiplexing | HOL blocking at TCP | Independent streams |
| Connection migration | No | Yes (Connection ID) |
| Middlebox interference | Possible | Minimal (encrypted) |

QUIC uses **UDP port 443** by default. Servers advertise HTTP/3 support via the `Alt-Svc: h3=":443"` HTTP response header.

---

## Common Transport Layer Problems

| Symptom | Likely Cause |
|---------|-------------|
| High retransmission rate | Packet loss on the path — bad link, congestion |
| Connection refused (RST) | No process listening on that port, or firewall rejecting |
| Connection timeout (no response) | Firewall silently dropping packets, host unreachable |
| Slow throughput on fast link | Window size too small, high latency, Nagle's algorithm |
| Many TIME_WAIT connections | Normal for high-connection-rate servers; can cause port exhaustion if extreme |
| TCP Zero Window | Receiving application too slow; receiver buffer full |
| SYN flood | DoS attack — attacker sends many SYNs without completing handshakes |

**SYN Flood mitigation — SYN Cookies:** Instead of allocating state for each half-open connection (which an attacker can exhaust), the server encodes connection state in the SYN-ACK's sequence number. No memory is allocated until the full handshake completes. If the ACK arrives and decodes correctly, the connection is legitimate.

---

## Summary

- **Port numbers** (0–65535) identify applications; connections are uniquely identified by the **5-tuple**
- **TCP** is reliable: 3-way handshake, ACKs, retransmission, sequence numbers, flow control (rwnd), congestion control (cwnd)
- The **3-way handshake** (SYN → SYN-ACK → ACK) establishes sequence numbers before data flows
- **Sliding window** flow control prevents overwhelming the receiver; **cwnd** prevents overwhelming the network
- **SACK** allows retransmitting only the missing segments instead of everything after a loss
- **UDP** is connectionless, 8-byte header, no reliability — right for DNS, VoIP, streaming, real-time data
- **QUIC** (HTTP/3) over UDP: 0–1 RTT setup, independent streams, built-in TLS, survives IP changes

**Next:** [Layer 7 — Application](07-application-layer.md) — HTTP, DNS, TLS, and the protocols you use every day
