# CLI Reference

## Synopsis

```
pktana <COMMAND> [OPTIONS]
pktana <INTERFACE>          # shorthand for capture
pktana <FILE.pcap>          # shorthand for pcap
```

---

## Global Options

| Flag | Description |
|------|-------------|
| `--version`, `-V`, `version` | Print version, license, repository URL |
| `--help`, `-h`, `-?`, `help` | Print general help or per-topic help |
| `help <topic>` | Per-topic help: `capture`, `tui`, `web`, `conn`, `route`, `nic`, `inspect`, `dpi` |

---

## Capture & Recording

### `capture` / `cap`

Live packet capture with DPI. Prints colored, formatted packet summaries to stdout.

```bash
sudo pktana capture eth0
sudo pktana cap ens3 --count 100
sudo pktana eth0          # shorthand — interface name as first arg
```

**Options**:

| Flag | Default | Description |
|------|---------|-------------|
| `--count N` / `-n N` | unlimited | Stop after N packets |
| `--filter EXPR` / `-f EXPR` | none | BPF capture filter (e.g. `tcp port 80`) |
| `--write FILE` / `-w FILE` | none | Save captured packets to pcap file |
| `--no-color` | off | Disable ANSI color output |
| `--verbose` / `-v` | off | Show full DPI detail per packet |

**Output columns**: `#`, `Time`, `Src`, `Dst`, `Proto`, `Len`, `Info`

**Color coding by protocol**:

| Color | Protocols |
|-------|-----------|
| Green | HTTP, HTTPS, TLS |
| Cyan | DNS, DHCP |
| Yellow | ARP |
| Magenta | ICMP |
| Blue | TCP |
| White | UDP, other |
| Red | High-risk packets (risk score > 50) |

---

### `record` / `rec`

Record live traffic to a pcap file without printing to screen. Useful for background capture.

```bash
sudo pktana record eth0 -w /tmp/capture.pcap
sudo pktana rec eth0 -w capture.pcap --count 10000
```

Flags are the same as `capture` with `--write` mandatory.

---

## Offline Analysis

### `pcap` / `pkt`

Analyze an existing pcap file with full DPI output.

```bash
pktana pcap /var/log/capture.pcap
pktana pcap capture.pcap --filter tcp
pktana pkt /tmp/test.pcapng -v
```

| Flag | Description |
|------|-------------|
| `--filter EXPR` | Display filter (applied after parse, not BPF) |
| `--verbose` / `-v` | Full DPI detail per packet |
| `--count N` | Limit output to first N packets |
| `--stats` | Print protocol breakdown summary after analysis |

---

### `inspect`

Deep packet inspection of a single raw hex-encoded frame. Prints full layer-by-layer decode.

```bash
pktana inspect ffffffffffff001122334455080006...
```

---

### `hex`

Decode a single hex-encoded Ethernet frame from the command line.

```bash
pktana hex "ffffffffffff 001122334455 0806 0001 0800 06 04 0001 ..."
```

---

### `demo`

Run DPI on a set of built-in sample packets (DNS, HTTP, TLS, ARP, ICMP). No capture required.

```bash
pktana demo
```

---

### `file`

Decode all hex frames from a text file (one frame per line).

```bash
pktana file /tmp/frames.hex
```

---

## Network Information

### `nic`

Display NIC information from Linux sysfs. Equivalent to `ip link show` + `ip addr show` + partial `ethtool` output.

```bash
pktana nic              # all interfaces
pktana nic eth0         # specific interface
```

**Output**:
- Interface name, MAC address, MTU
- Link state (UP / DOWN / DORMANT)
- Speed (Mbps), duplex
- IP addresses (all IPv4 and IPv6)
- Driver name
- RX/TX packets, bytes, errors, drops

---

### `ethtool` / `et`

Deep NIC driver and hardware queue inspection. Reads `/sys/class/net/<iface>/queues/` and `/proc/interrupts`.

```bash
pktana ethtool eth0
pktana et ens3
```

**Output**:
- Kernel driver name
- Link speed and duplex
- Number of RX and TX queues
- IRQ-to-CPU affinity per queue
- Hardware offload capabilities (from sysfs flags)

---

### `dp` / `dataplane`

Detect which dataplane / bypass mode is active on a NIC.

```bash
pktana dp eth0
pktana dataplane ens3
```

**Detected modes**:

| Mode | Description |
|------|-------------|
| Kernel Stack | Standard kernel network stack |
| XDP (eBPF) | XDP program loaded (detected via `/sys/class/net/<iface>/xdp_bpf_progs/`) |
| AF_XDP | AF_XDP socket detected |
| DPDK Userspace | DPDK/VFIO driver binding detected |
| Hybrid | Multiple modes active simultaneously |

Also shows: XDP program IDs, AF_XDP socket count, DPDK binding status, PMD driver name.

---

### `interfaces` / `ifaces`

List all available capture interfaces.

```bash
pktana interfaces
```

Shows: name, description, whether it is a loopback, IP addresses.

---

## Connection & Routing

### `conn` / `connections`

List all active TCP and UDP connections. Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`. Resolves PIDs and process names from `/proc`.

```bash
pktana conn
pktana connections --tcp
pktana conn --udp
pktana conn --established
pktana conn --listen
```

**Filter flags**:

| Flag | Description |
|------|-------------|
| `--tcp` | Show only TCP connections |
| `--udp` | Show only UDP connections |
| `--established` / `-e` | Show only ESTABLISHED connections |
| `--listen` / `-l` | Show only LISTEN sockets |
| `--port N` | Filter by port number |
| `--process NAME` | Filter by process name |

**Output columns**: Proto, Local Address:Port, Remote Address:Port, State, PID, Process

**Sort order**: ESTABLISHED first → LISTEN → other states → sorted by protocol then port

---

### `route` / `routes` / `nexthop`

Show the system routing table. Reads `/proc/net/route` (IPv4) and `/proc/net/ipv6_route` (IPv6).

```bash
pktana route
pktana routes --iface eth0
pktana nexthop 8.8.8.8
```

**Filter flags**:

| Flag | Description |
|------|-------------|
| `--iface NAME` / `-i NAME` | Show only routes for a specific interface |
| `--ipv4` | Show only IPv4 routes |
| `--ipv6` | Show only IPv6 routes |

**Output columns**: Interface, Destination/Prefix, Gateway, Metric

---

## Live Monitoring

### `stats`

Live traffic statistics dashboard. Refreshes every second.

```bash
sudo pktana stats eth0
```

**Displays**:
- Packets per second, bytes per second
- Protocol breakdown (TCP/UDP/ICMP/ARP/DNS/TLS/…)
- Top talkers by bytes
- Unique flows count

Press `Ctrl+C` to exit.

---

### `watch`

Auto-refresh NIC statistics (RX/TX bytes, packets, errors). Replaces `watch -n1 ip -s link show eth0`.

```bash
pktana watch eth0
pktana watch eth0 --interval 2
```

| Flag | Default | Description |
|------|---------|-------------|
| `--interval N` / `-i N` | 1 | Refresh interval in seconds |

---

## GeoIP

### `geoip` / `geo`

Offline GeoIP lookup using an embedded database. No internet access needed.

```bash
pktana geoip 8.8.8.8
pktana geo 1.1.1.1
```

**Output**: IP, Country Name, Country Code (ISO 3166-1 alpha-2), Continent

Private/RFC1918 addresses return `LAN`. Unknown addresses return `Unknown`.

---

## Dashboards

### `tui`

Launch the full Wireshark-style TUI dashboard. Requires `tui` feature at build time.

```bash
sudo pktana tui eth0          # live capture
pktana tui capture.pcap       # offline pcap analysis
pktana tui                    # auto-detect: opens interface selector
```

See [TUI Guide](04-tui-guide.md) for keyboard shortcuts and detailed usage.

---

### `web`

Start the browser-based multi-window Web UI.

```bash
sudo pktana web               # default port 8080, background
sudo pktana web 9000          # custom port, background
sudo pktana web 8080 -f       # foreground (don't detach)
sudo pktana web --foreground  # same as -f
```

| Flag | Description |
|------|-------------|
| `PORT` | TCP port to listen on (default: 8080) |
| `-f` / `--foreground` / `--run-server` | Stay in foreground (don't spawn background process) |

After starting, open `http://localhost:8080` in your browser.

See [Web UI Guide](05-web-ui-guide.md) for full usage.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage error (wrong arguments) |
| 2 | Capture error (interface not found, permission denied) |
| 3 | Parse error (invalid hex, corrupt pcap) |
| 4 | I/O error |
