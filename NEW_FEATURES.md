# 🎉 pktana v0.1.0 - NEW FEATURES

## ✅ IMPLEMENTED 

### 1. **Process Tracking** ✅
- **What**: Maps network connections to process names and PIDs
- **How**: Scans `/proc` to match socket inodes to processes
- **Usage**: Automatically displayed in TUI connections table

### 2. **PCAP Export** ✅
- **What**: Save captured packets to PCAP file for Wireshark analysis
- **How**: Uses libpcap's savefile functionality
- **Usage**: Add `pcap_export: Some("capture.pcap")` to CaptureConfig
- **Status**: Infrastructure ready, CLI flag pending

### 3. **Advanced TUI Dashboard** ✅
**Features:**
- ✅ **Sortable Columns**: Press `s` to cycle through sort columns, `S` to reverse
  - Sort by: Protocol | Local Address | Remote Address | State | Process | Bytes
- ✅ **Real-time Filtering**: Press `/` to filter connections
  - Filters across: protocol, IP addresses, process names, country codes
- ✅ **Process Information**: Shows PID and process name for each connection
- ✅ **GeoIP Integration**: Displays country code for remote IPs
- ✅ **Connection State Tracking**: TCP states (ESTABLISHED, etc.)
- ✅ **Historic Connections**: Press `t` to toggle showing closed connections
- ✅ **Mouse Support**: 
  - Click to select rows
  - Scroll wheel to navigate
- ✅ **Multiple Tabs**: `Tab` to cycle through Overview → Details → Help
- ✅ **Case-Insensitive Commands**: `pktana TUI eth0` now works!

### 4. **Connection Lifecycle Management** ✅
- Tracks first seen/last seen timestamps
- Auto-cleanup of stale connections (60s timeout)
- Active vs historic connection states
- Byte and packet counters per connection

### 5. **Enhanced Statistics** ✅
- Total packets/bytes tracked
- Per-protocol breakdown
- Connection count tracking
- Traffic rate calculations

## 🎮 HOW TO USE THE NEW TUI

```bash
# Build with all features
cargo build -p pktana-cli --features pcap,tui --release

# Start the TUI (case-insensitive now!)
sudo ./target/release/pktana tui eth0
# OR
sudo ./target/release/pktana TUI eth2.100

# Keyboard Shortcuts:
# ──────────────────────────────────────── 
# s             - Cycle sort column
# S (Shift+s)   - Toggle sort direction  
# /             - Enter filter mode
# t             - Toggle historic connections
# Tab           - Switch tabs (Overview → Details → Help)
# ↑ / ↓ / j / k - Navigate connections
# q / Esc       - Quit
#
# Mouse Support:
# ──────────────────────────────────────── 
# Click row     - Select connection
# Scroll wheel  - Navigate list
```

## 📊 TUI DISPLAY

```
┌─ pktana TUI | eth0 | 12 connections | 00:05:23 ───────────────────────┐
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
┌─ Traffic Stats ───────────────┬─ Top Protocols ─────────────────────────┐
│ Total Packets: 4521           │ TCP: 3204                               │
│ Total Bytes: 12.5 MB          │ UDP: 1201                               │
│ Connections: 12               │ ICMP: 89                                │
└───────────────────────────────┴─────────────────────────────────────────┘
┌─ Connections (Sort: BytesTotal ↓) ──────────────────────────────────────┐
│ Proto │ Local Address        │ Remote Address       │ State      │ ... │
│ TCP   │ 192.168.1.10:54321   │ 142.250.80.46:443    │ ESTABLISH.. │ ... │
│ UDP   │ 192.168.1.10:54322   │ 8.8.8.8:53           │ ESTABLISH.. │ ... │
└─────────────────────────────────────────────────────────────────────────┘
┌─ Status ────────────────────────────────────────────────────────────────┐
│ / filter | s sort | t toggle historic | Tab switch tabs | q quit        │
└─────────────────────────────────────────────────────────────────────────┘
```

## 🔧 TECHNICAL DETAILS

### Process Tracking (`src/process.rs`)
- Scans `/proc/<pid>/fd/` for socket file descriptors
- Matches socket inodes from `/proc/net/{tcp,tcp6,udp,udp6}`
- Reads process name from `/proc/<pid>/comm`
- Updates every 2 seconds in TUI

### Connection Tracking
- Bidirectional flow matching (src→dst and dst→src)
- Automatic state management
- GeoIP lookup on connection creation
- Per-connection statistics

### TUI Architecture
- Event-driven with crossterm
- Ratatui for rendering
- Separate capture thread with mpsc channel
- 100ms UI refresh rate

## 📈 PERFORMANCE

- **Process map refresh**: Every 2 seconds
- **UI refresh**: 100ms (10 FPS)
- **Connection cleanup**: Every 5 seconds
- **Stale timeout**: 60 seconds idle

## 🚀 NEXT STEPS

Potential future enhancements:
- [ ] Add --pcap-export CLI flag to main capture command
- [ ] Implement connection details view (Tab → Details)
- [ ] Add graph tab for bandwidth visualization
- [ ] Export connection log to JSON
- [ ] BPF filtering in TUI
- [ ] Per-connection TCP analytics (retransmits, RTT)

## 📝 NOTES

- TUI requires root or CAP_NET_RAW capability
- PCAP export infrastructure is ready but needs CLI integration
- Process tracking works best on Linux (uses /proc)
- Case-insensitive commands now supported (TUI = tui)
