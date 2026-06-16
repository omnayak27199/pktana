# Web UI Guide

The Web UI is a full browser-based network analyzer. It provides a VS Code-style layout with a vertical activity bar, multi-session capture windows, live packet streaming, and deep inspection — all served by pktana's embedded pure-Rust HTTP server.

> **Requires**: build with `--features pcap,tui` (pcap for live capture).

---

## Starting the Web Server

```bash
# Start in background (default port 8080)
sudo pktana web

# Custom port, background
sudo pktana web 9000

# Stay in foreground
sudo pktana web 8080 --foreground

# Then open in browser:
# http://localhost:8080
```

When started in background mode, pktana prints:
```
pktana web server running at:
  http://localhost:8080
  http://192.168.1.100:8080

API endpoints:
  /api/nic
  /api/inspect?iface=eth0
  /api/inspect?iface=eth0&flow_analyze=true
```

---

## Layout Overview

The UI uses a **VS Code-style layout**:

```
┌──────────────────────────────────────────────────────────────────┐
│  Navbar: pktana   Network Traffic Analyzer          [Dark] [Stop]│
├────┬─────────────────────────────────────────────────────────────┤
│    │  [Packets] [Flows] [Protocols] [Hardware]  ← window tabs    │
│ A  │ ─────────────────────────────────────────────────────────── │
│ c  │  Session Strip: ● eth0  42 pkts · 18.3 KB  × | + New Window │
│ t  │ ─────────────────────────────────────────────────────────── │
│ i  │                                                             │
│ v  │         [Active Panel Content]                             │
│ i  │                                                             │
│ t  │                                                             │
│ y  │                                                             │
│    │                                                             │
│ B  │                                                             │
│ a  │                                                             │
│ r  │                                                             │
└────┴─────────────────────────────────────────────────────────────┘
```

---

## Activity Bar (Vertical Sidebar)

The left sidebar icons navigate between panels:

| Icon | Panel | Description |
|------|-------|-------------|
| Server icon | **Server Info** | System info + interface picker |
| File icon | **PCAP File** | Analyze a pcap file on the server |
| Network icon | **Connections** | Active TCP/UDP sockets |
| Terminal icon | **Terminal** | Embedded Linux terminal (xterm.js) |
| Route icon | **Routes** | System routing table |
| NIC icon | **NICs** | Network interface stats (rx/tx bytes, MAC, MTU) |
| Globe icon | **GeoIP** | IP geolocation lookup |

Session-scoped panels (Packets, Flows, Protocols, Hardware) are accessed via the **horizontal window-tabs bar** that appears when a session is open.

---

## Server Info Panel

The landing panel when the UI loads. Shows:

- **System Information**: hostname, kernel version, uptime, total RAM
- **Interface Picker**: clickable list of all network interfaces with UP/DOWN status. Click any interface to immediately open a capture window for it.
- **Active Sessions**: table of all backend capture sessions with View/Stop/Delete actions.

---

## Opening a Capture Window

1. Click any interface in the **Server Info** panel  
   — OR —  
   Click **+ New Window** in the session strip

A new per-interface capture window opens. The horizontal window-tabs bar appears with:

- **Packets** — live packet table
- **Flows** — detected network flows
- **Protocols** — traffic statistics
- **Hardware** — NIC driver/queue details

Multiple windows can be open simultaneously (one per interface). Switch between them using the session chips in the session strip.

---

## Packets Panel (Live Capture)

The main Wireshark-style packet analyzer.

### Toolbar

| Control | Description |
|---------|-------------|
| **▶ Start Capture** | Begin live capture on the active interface |
| **⏹ Stop Capture** | Stop the current capture |
| **⏸ Pause / ▶ Resume** | Freeze/unfreeze the live packet display |
| **Protocol** dropdown | Filter displayed packets by protocol |
| **Search** input | Text filter across all packet fields |
| **BPF Filter** input | Capture-time BPF filter (applied on next start) |
| **⇄** | Toggle horizontal/vertical split layout |
| **📋** | Toggle the Packet Details pane |
| **🔢** | Toggle the Hex Dump pane |

### Packet Table

Columns: `No. | Time | Source | Destination | Proto | Len | Info`

- Rows are **color-coded** by protocol (blue=TCP, cyan=UDP, green=HTTP, etc.)
- Click any row to view full DPI detail in the right pane
- High-risk packets are highlighted in red with a `[Risk: N]` badge

### Packet Details Pane

Shows the full layer-by-layer DPI decode of the selected packet:
- Each protocol layer is a collapsible section
- All fields labeled with keys and values
- Anomalies highlighted in red

### Hex Dump Pane

Shows the raw bytes of the selected packet:
- **Grey**: byte offset
- **Blue**: hex byte values  
- **Green**: ASCII representation
- First 128 bytes are shown; truncation note if packet is larger

### Protocol Filter Dropdown

| Filter | Selects |
|--------|---------|
| All Traffic | No filter |
| TCP / UDP / ICMP / ARP | Basic protocol filter |
| HTTP/HTTPS / DNS / DHCP / TLS / SSH / FTP | Application protocols |
| QUIC/HTTP3 / HTTP2 / gRPC / WebSocket / SIP / NTP / BGP / Tunnels | Advanced protocols |
| TCP Handshakes (SYN) | Only packets tagged as TCP handshake SYN |
| TLS Handshakes | Only TLS ClientHello/ServerHello packets |
| DNS Queries | Only DNS query/response packets |
| DHCP DORA | Only DHCP Discover/Offer/Request/Ack packets |

---

## Flows Panel

Shows all detected network flows for the active session:

**Columns**: Proto, Source (IP:Port), Destination (IP:Port), Category, Packets, Bytes

- Updated in real time as packets arrive
- Searchable via the search box
- Scrollable with many flows

---

## Protocols Panel (Statistics)

Real-time traffic statistics:

- **Protocol Breakdown**: packet and byte counts per protocol
- **Top Talkers**: top source IPs by byte volume, with GeoIP country codes
- **Traffic Overview**: total packets, bytes, unique flows, unique endpoints

Filter the stats with the search box at the top.

---

## Hardware Panel

Per-interface NIC details (only shown for live captures, not pcap analysis):

- **Hardware Status**: link state, speed, MAC address, MTU, IP addresses, RX/TX counters
- **Driver & Queues (Ethtool)**: kernel driver, link speed, duplex, RX/TX queue count
- **Dataplane Path**: XDP/DPDK/AF_XDP detection, bypass mode, XDP program IDs

---

## PCAP File Panel

Analyze a pcap file stored on the server:

1. Enter the server-side path to the file in the **Path to PCAP on Server** field
2. Click **Analyze Server PCAP**
3. The file is streamed into the Packets panel like a live capture

> Upload from local machine: click **Upload & Analyze** (requires file input). Note: the backend multipart upload API is not yet implemented; use server-side paths for now.

---

## Connections Panel

Live view of all active TCP/UDP connections:

- Reads `/proc/net/tcp`, `tcp6`, `udp`, `udp6`
- Resolves PID and process name for each connection
- Click **Refresh** to reload, or search with the filter input
- ESTABLISHED connections shown in green, LISTEN in normal color

---

## Routes Panel

System routing table:

- IPv4 routes from `/proc/net/route`
- IPv6 routes from `/proc/net/ipv6_route`
- **Columns**: Interface, Destination/Prefix, Gateway, Metric
- Direct routes (no gateway) shown as `Direct`
- Click **Refresh** to reload

---

## NICs Panel

Full NIC statistics for all interfaces:

- **Columns**: Interface, State, MAC, MTU, RX bytes, TX bytes
- Data from `/sys/class/net/<iface>/statistics/`
- Click interface name to open a capture window for it
- Click **Refresh** to reload

---

## GeoIP Panel

Offline IP geolocation lookup:

1. Enter an IPv4 or IPv6 address in the input field
2. Click **Lookup**
3. Results: Country Name, Country Code (ISO 3166-1), Continent

Private/RFC1918 addresses are identified as `LAN`. Works offline — no external API calls.

---

## Terminal Panel

An embedded Linux terminal powered by **xterm.js**:

- Runs real commands on the server (via `/api/terminal?cmd=`)
- Full command history (arrow up/down)
- Directory tracking (`cd` commands update the working directory)
- **Themes**: Default, Matrix Green, Monokai, Nord, Dracula, Solarized Dark, Ubuntu
- Theme persists across sessions via localStorage

**Keyboard**:
- `Enter` — execute command
- `↑` / `↓` — command history
- `Backspace` — delete last character
- `Ctrl+C` — cancel current input
- `Ctrl+L` — clear screen
- `Tab` — (not yet implemented)

**Buttons**: Clear, Reset, Theme selector

> **Security note**: The terminal executes arbitrary shell commands on the server. Only run pktana web on trusted networks.

---

## Multi-Session Management

Multiple capture sessions can be open simultaneously:

- Each **session chip** in the session strip represents one active interface window
- The **active chip** is highlighted in orange
- Each session has its own independent:
  - Packet buffer (up to 10,000 packets in memory)
  - Flow table, protocol stats, talker stats
  - Auto-scroll state, display filter, BPF filter
- Switch between sessions by clicking their chips
- Close a session with the `×` button on its chip

---

## Theme & Preferences

| Setting | How to change | Persists |
|---------|---------------|---------|
| Dark / Light theme | Click **Dark** button in sidebar | Yes (localStorage) |
| Panel layout (split direction) | **⇄** button in toolbar | Yes |
| Panel visibility | **📋** button | Yes |
| Hex pane visibility | **🔢** button | Yes |
| Terminal theme | Theme dropdown in Terminal panel | Yes |

---

## Stopping the Web Server

Click the **Stop** button in the bottom of the activity bar, or send `POST /api/stop`:

```bash
curl -X POST http://localhost:8080/api/stop
```

The server stops gracefully after 500ms.
