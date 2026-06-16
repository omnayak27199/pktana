# TUI Dashboard Guide

The TUI (Terminal User Interface) is a full Wireshark-style interactive dashboard built with **ratatui** and **crossterm**. It runs entirely in the terminal — no browser needed.

> **Requires**: build with `--features tui` (and `--features pcap` for live capture).

---

## Launching

```bash
# Live capture (requires root or CAP_NET_RAW)
sudo pktana tui eth0

# Offline pcap analysis
pktana tui /path/to/capture.pcap

# Auto-detect (pass interface or pcap path)
sudo pktana tui ens3
pktana tui recording.pcap
```

---

## Layout

```
┌─────────────────────────────────────────────────────┐
│  Packet List (scrollable)                           │
│  # │ Time     │ Src         │ Dst         │ Proto │ │
│  1 │ 0.000000 │ 192.168.1.1 │ 8.8.8.8     │ DNS   │ │
│  2 │ 0.001234 │ 10.0.0.1    │ 10.0.0.2    │ TCP   │ │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│  Packet Detail (DPI layers)                         │
│  ── Ethernet ──                                     │
│    Src MAC: 00:11:22:33:44:55  (Vendor)             │
│    Dst MAC: ff:ff:ff:ff:ff:ff                        │
│  ── IPv4 ──                                         │
│    Src: 192.168.1.100   Dst: 8.8.8.8                │
│    TTL: 64   Proto: UDP   Len: 56                   │
│  ── Application: DNS ──                             │
│    Query: example.com (Type A)                      │
├─────────────────────────────────────────────────────┤
│ [S]tart [Space]Pause [F]ilter [A]nalyze [H]ex [Q]  │
└─────────────────────────────────────────────────────┘
```

The layout has three main areas:
1. **Packet List** (top) — scrollable table of captured packets
2. **Packet Detail** (middle) — full DPI breakdown of the selected packet
3. **Status / Hint Bar** (bottom) — current state, keyboard hints

---

## Keyboard Shortcuts

### Navigation

| Key | Action |
|-----|--------|
| `↑` / `k` | Move selection up |
| `↓` / `j` | Move selection down |
| `PgUp` | Scroll up one page |
| `PgDn` | Scroll down one page |
| `Home` / `g` | Jump to first packet |
| `End` / `G` | Jump to last packet |
| `Enter` | Select packet and view full detail |

### Capture Control

| Key | Action |
|-----|--------|
| `s` / `S` | Start / Stop capture |
| `Space` | Pause / Resume packet stream (buffers stop updating) |
| `c` / `C` | Clear all packets from the list |

### Display

| Key | Action |
|-----|--------|
| `f` / `F` | Open filter input — type a display filter, press Enter |
| `h` / `H` | Toggle Hex dump pane for selected packet |
| `l` / `L` | Toggle layer detail view (DPI layers decode) |
| `a` / `A` | Toggle Flow Analysis mode — shows live handshake/DORA/DNS events |
| `t` / `T` | Toggle timestamp format (relative / absolute) |
| `Esc` | Close detail pane / clear filter |

### Export

| Key | Action |
|-----|--------|
| `w` / `W` | Write capture to pcap file (prompts for filename) |
| `e` / `E` | Export filtered packets |

### Application

| Key | Action |
|-----|--------|
| `q` / `Q` | Quit pktana |
| `?` | Show keyboard shortcut reference |

---

## Display Filter

Press `f` to open the filter input at the bottom of the screen. Filters are applied immediately to the packet list (they do not re-capture).

**Filter syntax** (case-insensitive, space-separated terms are AND):

```
tcp                    # only TCP packets
dns                    # only DNS packets  
192.168.1             # src or dst contains this string
tcp 443                # TCP packets where any field contains "443"
eth0 tls               # TLS packets
```

Pipe `|` separates OR alternatives:
```
tcp|udp               # TCP or UDP
http|https|tls        # web traffic
```

---

## Flow Analysis Mode

Press `a` to toggle **Flow Analysis mode**. When active:

- A `FlowAnalyzer` is attached to the live capture stream
- Each packet is analyzed for multi-packet protocol state machines
- Status bar shows live events such as:
  - `▸ TCP Handshake COMPLETE: 192.168.1.1:45678 → 8.8.8.8:443  RTT=2.4ms`
  - `▸ TLS 1.3 Handshake: SNI=example.com  JA3=abc123...`
  - `▸ DHCP DORA: 192.168.1.50 → 192.168.1.1  Total=12.3ms`
  - `▸ DNS Query: example.com A → NOERROR 93.184.216.34  RTT=8ms`

---

## Hex Dump View

Press `h` on a selected packet to show its raw bytes:

```
0000  45 00 00 3c 1c 46 40 00  40 06 00 00 c0 a8 01 01  |E..<.F@.@.......|
0010  08 08 08 08 cc 8e 00 50  00 00 00 00 a0 02 fa f0  |.......P........|
0020  00 00 02 04 05 b4 04 02  08 0a 00 6e 44 24 00 00  |...........nD$..|
```

- **Offset** (grey): byte offset in hex
- **Hex bytes** (blue): raw byte values
- **ASCII** (green): printable characters, `.` for non-printable

---

## Color Coding

Packets in the list are color-coded by protocol:

| Color | Protocol |
|-------|----------|
| Blue | TCP |
| Cyan | UDP |
| Green | HTTP / HTTPS |
| Bright Cyan | DNS |
| Magenta | ICMP |
| Yellow | ARP |
| Red | High-risk (anomaly detected or risk score > 50) |
| White | Other / Unknown |

---

## Packet Detail Pane

When a packet is selected, the detail pane shows the full DPI layer tree:

```
── Ethernet ──────────────────────────────────────────
  Src MAC:  00:11:22:33:44:55  (Intel Corporate)
  Dst MAC:  ff:ff:ff:ff:ff:ff
  EtherType: IPv4 (0x0800)

── IPv4 ──────────────────────────────────────────────
  Version: 4     IHL: 20 bytes     TOS: 0x00
  Total Len: 60  ID: 0x1c46        TTL: 64
  Flags: DF      Frag Offset: 0
  Src: 192.168.1.1    Dst: 8.8.8.8
  Protocol: TCP (6)

── TCP ───────────────────────────────────────────────
  Src Port: 52366    Dst Port: 443
  Seq: 0             Ack: 0
  Flags: SYN         Window: 64240
  Options: MSS=1460  SACK_OK  WScale=7  Timestamps

── Application: TLS ──────────────────────────────────
  Record: Handshake (ClientHello)
  TLS Version: 1.3 (negotiated)
  SNI: example.com
  Ciphers: 32 offered
  ALPN: h2, http/1.1
  JA3: abc123def456...
```

---

## TUI in Offline Mode (PCAP)

When launched with a `.pcap` file, the TUI:
- Loads all packets immediately into the packet list
- Capture control (`s` / `Space`) is disabled
- All filtering, hex dump, and detail viewing works identically
- Press `g` / `G` to jump between first and last packet
