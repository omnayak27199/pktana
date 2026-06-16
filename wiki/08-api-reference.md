# Web API Reference

`pktana web` serves a pure-Rust HTTP/1.1 server on the configured port (default 8080). All endpoints return JSON unless noted. All responses include `Access-Control-Allow-Origin: *`.

---

## Base URL

```
http://<host>:<port>
```

Default: `http://localhost:8080`

---

## Connection Behavior

- The server is single-threaded but uses non-blocking I/O with a thread-per-connection model for SSE streams.
- Each HTTP/1.1 connection is handled by a spawned thread. Non-SSE requests are handled with `Connection: close`.
- SSE connections (`/api/inspect`) are long-lived — the thread blocks on the pcap loop until the client disconnects or the capture ends.
- There are no hard rate limits, but opening many simultaneous SSE streams may consume significant memory. One stream per browser tab is the intended usage pattern.
- No authentication is required. Run pktana on a trusted network or behind a firewall.
- The server does not support HTTPS natively. If TLS termination is needed, proxy through nginx or caddy.

---

## System Endpoints

### `GET /`

Returns the full Web UI HTML (the single-page application). The entire UI is embedded in the binary as a compile-time constant — no static files are served from disk.

**Response**: `text/html; charset=utf-8`

---

### `GET /api/server_info`

Returns basic system information read from `/proc/sys/kernel/hostname`, `/proc/version`, `/proc/uptime`, and `/proc/meminfo`.

**Response**:
```json
{
  "hostname": "my-server",
  "version": "Linux version 5.14.0-427.35.1.el9_4.x86_64 (mockbuild@...)",
  "uptime_sec": 86423.5,
  "mem_total_kb": 16384000
}
```

| Field | Type | Source |
|-------|------|--------|
| `hostname` | string | `/proc/sys/kernel/hostname` |
| `version` | string | First line of `/proc/version` |
| `uptime_sec` | float | First token of `/proc/uptime` |
| `mem_total_kb` | int | `MemTotal` from `/proc/meminfo` |

**Curl example**:
```bash
curl -s http://localhost:8080/api/server_info | jq .
```

---

### `POST /api/stop`

Stop the pktana daemon. The server sends the response and then exits after a 500ms delay (to allow the response to flush).

**Response**:
```json
{"status": "stopping daemon"}
```

**Curl example**:
```bash
curl -s -X POST http://localhost:8080/api/stop
```

---

## Interface Endpoints

### `GET /api/interfaces`

List all available network interfaces with basic info. Reads interface names from `/sys/class/net/`, addresses from `/proc/net/fib_trie` (IPv4) and `/proc/net/if_inet6` (IPv6), and link state from `/sys/class/net/<name>/operstate`.

**Response**:
```json
[
  {
    "name": "eth0",
    "description": "Intel Ethernet",
    "address": "192.168.1.100",
    "is_up": true
  },
  {
    "name": "lo",
    "description": "",
    "address": "127.0.0.1",
    "is_up": true
  }
]
```

`is_up` is `true` when `/sys/class/net/<name>/operstate` contains `up`, `unknown`, or `dormant`. It is `false` for `down` or `notpresent`.

**Curl example**:
```bash
curl -s http://localhost:8080/api/interfaces | jq '.[].name'
```

---

### `GET /api/nic`

Full NIC statistics for all interfaces, read from `/sys/class/net/<name>/statistics/` and `/sys/class/net/<name>/address`.

**Response**:
```json
[
  {
    "name": "eth0",
    "state": "up",
    "mac": "00:11:22:33:44:55",
    "mtu": 1500,
    "speed_mbps": 1000,
    "duplex": "full",
    "driver": "e1000e",
    "ip_addresses": ["192.168.1.100/24", "fe80::1/64"],
    "rx_bytes": 1234567890,
    "rx_packets": 1234567,
    "rx_errors": 0,
    "rx_dropped": 0,
    "tx_bytes": 987654321,
    "tx_packets": 987654,
    "tx_errors": 0,
    "tx_dropped": 0
  }
]
```

`speed_mbps` reads `/sys/class/net/<name>/speed` — returns -1 if the link is down or the value is unavailable. `driver` reads the symlink target of `/sys/class/net/<name>/device/driver`.

**Curl example**:
```bash
curl -s http://localhost:8080/api/nic | jq '.[] | {name, rx_bytes, tx_bytes}'
```

---

### `GET /api/nic_detail?iface=<name>`

Hardware status for a specific interface. Used by the Hardware panel.

**Query parameters**: `iface` — interface name (required)

**Response**:
```json
{
  "name": "eth0",
  "state": "up",
  "mac": "00:11:22:33:44:55",
  "mtu": 1500,
  "speed_label": "1 Gbps",
  "rx_bytes": 1234567890,
  "tx_bytes": 987654321,
  "ip_addresses": ["192.168.1.100/24"]
}
```

`speed_label` converts the raw Mbps value to a human string: `"1 Gbps"`, `"10 Gbps"`, `"100 Mbps"`, etc.

**Error** (missing parameter):
```json
{"error": "interface required"}
```

**Curl example**:
```bash
curl -s "http://localhost:8080/api/nic_detail?iface=eth0" | jq .
```

---

### `GET /api/ethtool?iface=<name>`

Ethtool-equivalent NIC driver and queue information, read from `/sys/class/net/<name>/queues/` and `/proc/interrupts`.

**Response**:
```json
{
  "driver": "e1000e",
  "speed_mbps": 1000,
  "duplex": "full",
  "rx_queues": 4,
  "tx_queues": 4
}
```

`rx_queues` counts directories matching `/sys/class/net/<name>/queues/rx-*`. `tx_queues` counts `tx-*` directories.

**Curl example**:
```bash
curl -s "http://localhost:8080/api/ethtool?iface=eth0" | jq .
```

---

### `GET /api/dp?iface=<name>`

NIC dataplane/bypass detection. Checks for XDP programs, AF_XDP sockets, and DPDK driver bindings.

**Response**:
```json
{
  "bypass_mode": "XDP (eBPF)",
  "xdp_prog_ids": "[42, 43]",
  "afxdp_sockets": 0,
  "dpdk_bound": false,
  "driver": "i40e"
}
```

Detection sources:
- XDP: presence of `/sys/class/net/<name>/xdp_bpf_progs/` directory
- AF_XDP: `/proc/net/xdp_diag` socket entries for the interface
- DPDK: driver name matching `vfio-pci`, `uio_pci_generic`, or `igb_uio`

**Curl example**:
```bash
curl -s "http://localhost:8080/api/dp?iface=eth0" | jq .
```

---

## Packet Capture (SSE)

### `GET /api/inspect?<params>`

**Server-Sent Events (SSE)** stream. Connects to a live interface or reads a pcap file and streams packet data as newline-delimited JSON events.

The response uses `Content-Type: text/event-stream` with `Cache-Control: no-cache` and keeps the connection alive until either:
- The capture is stopped (client sends `POST /api/sessions/{id}/stop`)
- The pcap file is fully read
- The client closes the connection (TCP RST detected on next write)

**Query Parameters**:

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `iface` | One of iface/read | string | Interface name for live capture (e.g. `eth0`) |
| `read` | One of iface/read | string | Server-side absolute path to pcap/pcapng file |
| `filter` | No | string | BPF capture filter (URL-encoded spaces as `+` or `%20`) |
| `flow_analyze` | No | boolean | `true` to emit flow analysis events alongside packet events |
| `session` | No | string | Session ID to associate with this capture stream |
| `export` | No | string | Server-side absolute path to save captured packets as pcap |

**BPF filter syntax** (passed directly to libpcap):
```
# Protocol filters
filter=tcp
filter=udp
filter=icmp

# Port filters
filter=tcp+port+443
filter=port+53
filter=not+port+22

# Host filters
filter=host+192.168.1.1
filter=src+host+10.0.0.1
filter=dst+net+192.168.0.0%2F24

# Combination
filter=tcp+and+%28port+80+or+port+443%29
```

**Example requests**:
```bash
# Live capture on eth0
curl -N "http://localhost:8080/api/inspect?iface=eth0"

# Live with flow analysis and BPF filter
curl -N "http://localhost:8080/api/inspect?iface=eth0&flow_analyze=true&filter=tcp+port+443"

# Offline pcap analysis
curl -N "http://localhost:8080/api/inspect?read=/tmp/capture.pcap"

# Live capture saved to pcap
curl -N "http://localhost:8080/api/inspect?iface=eth0&export=/tmp/out.pcap"
```

**SSE event stream format**:

Each event is a single line starting with `data: ` followed by a JSON object, terminated by two newlines (`\n\n`):

```
data: {JSON object}\n
\n
```

#### Packet event (every captured packet)

```
data: {"ts_sec":1718000000,"ts_usec":123456,"summary":"DNS Query: example.com","len":74,"risk":0,"category":"DNS/Infrastructure","proto":"DNS","src":"192.168.1.100","dst":"8.8.8.8","tags":"dns-query","details":"-- Ethernet --\n  Src MAC: aa:bb:cc:dd:ee:ff\n  Dst MAC: 00:11:22:33:44:55\n-- IPv4 --\n  Src: 192.168.1.100\n  Dst: 8.8.8.8\n  TTL: 64\n-- UDP --\n  Src Port: 54321\n  Dst Port: 53\n-- DNS --\n  Query: A example.com\n","hex":"  0000  45 00 00 4a ..."}

```

Full packet event field reference:

| Field | Type | Description |
|-------|------|-------------|
| `ts_sec` | int | Unix timestamp (seconds since epoch) |
| `ts_usec` | int | Sub-second microseconds (0–999999) |
| `summary` | string | One-line packet summary from `one_liner()` |
| `len` | int | Frame length in bytes (Ethernet + payload) |
| `risk` | int | Risk score 0–100 |
| `category` | string | Traffic category (e.g. `"Web Browsing"`, `"DNS/Infrastructure"`) |
| `proto` | string | Detected protocol label (e.g. `"TLS"`, `"DNS"`, `"HTTP"`, `"TCP"`) |
| `src` | string | Source IP address (or source MAC for non-IP frames) |
| `dst` | string | Destination IP address (or dest MAC) |
| `tags` | string | Comma-separated event tags for filter dropdowns |
| `details` | string | Full DPI layer decode, sections separated by `\n`, `--Layer--` headers |
| `hex` | string | Hex dump of first 128 bytes of the frame |

**`details` field format** (newlines escaped as `\n` in JSON):
```
-- Ethernet --
  Src MAC: aa:bb:cc:dd:ee:ff (Apple)
  Dst MAC: 00:11:22:33:44:55 (Cisco)
  EtherType: IPv4 (0x0800)
-- IPv4 --
  Src: 192.168.1.100
  Dst: 8.8.8.8
  TTL: 64  Proto: UDP (17)  Len: 60
-- UDP --
  Src Port: 54321  Dst Port: 53  Len: 40
-- DNS --
  Query: A example.com
  ID: 0x1234  RD=1
```

**Event tags reference**:

| Tag | When emitted |
|-----|-------------|
| `tcp-handshake` | TCP packets with SYN flag (connection establishment) |
| `tls-handshake` | TLS ClientHello or ServerHello detected |
| `dns-query` | DNS query or response packets |
| `dhcp-dora` | DHCP Discover, Offer, Request, or Ack |
| `high-risk` | `risk >= 50` |
| `anomaly` | Any anomaly detected (non-empty `dp.anomalies`) |
| `tunnel` | VXLAN, GRE, or Geneve encapsulated packet |

#### Flow analysis event

Emitted only when `flow_analyze=true`. These events appear interleaved with packet events when flow state transitions occur (TCP handshake completion, flow timeout, etc.):

```
data: {"ts_sec":1718000000,"ts_usec":456789,"flow_event":"TCP Handshake COMPLETE: 192.168.1.1:52000 → 8.8.8.8:443  RTT=2.4ms"}

```

Flow event types:
- `TCP Handshake COMPLETE: <src>:<port> → <dst>:<port>  RTT=<ms>ms`
- `TCP Flow RESET: <src>:<port> → <dst>:<port>`
- `TCP Flow FIN: <src>:<port> → <dst>:<port>  duration=<sec>s  bytes=<n>`
- `UDP Flow: <src>:<port> → <dst>:<port>  <n> packets`
- `DNS NXDOMAIN: <query-name>` (potential DGA / typosquat)

#### Error event

```
data: {"error": "Interface eth0 not found or no permission"}

```

Common error messages:

| Error message | Cause |
|---------------|-------|
| `"Interface <name> not found or no permission"` | NIC does not exist or process lacks CAP_NET_RAW |
| `"pcap file not found: <path>"` | File path invalid or unreadable |
| `"filter error: <msg>"` | BPF filter syntax error from libpcap |
| `"capture error: <msg>"` | libpcap runtime error (NIC removed, etc.) |

---

## Session Management

Sessions track the state of capture streams. Each call to `/api/inspect` can be associated with a session ID. Sessions persist their metadata (packet count, bytes) even after the SSE connection closes.

### `GET /api/sessions`

List all capture sessions.

**Response**:
```json
[
  {
    "id": "abc123",
    "interface": "eth0",
    "filter": "tcp",
    "status": "Active",
    "packet_count": 1234,
    "bytes_captured": 567890
  },
  {
    "id": "def456",
    "interface": "lo",
    "filter": "",
    "status": "Stopped",
    "packet_count": 42,
    "bytes_captured": 3010
  }
]
```

Session status values: `"Active"` (SSE stream open), `"Stopped"` (stream closed or manually stopped), `"Error"` (capture failed).

**Curl example**:
```bash
curl -s http://localhost:8080/api/sessions | jq '.[] | {id, interface, status, packet_count}'
```

---

### `POST /api/sessions/create`

Create a new capture session and return its ID. The SSE stream for this session is opened separately by calling `/api/inspect?session=<id>&iface=<name>`.

**Request body**:
```json
{"interface": "eth0", "filter": "tcp port 443"}
```

**Response**:
```json
{
  "id": "abc123",
  "interface": "eth0",
  "filter": "tcp port 443",
  "status": "Active",
  "packet_count": 0,
  "bytes_captured": 0
}
```

**Curl example**:
```bash
curl -s -X POST http://localhost:8080/api/sessions/create \
  -H "Content-Type: application/json" \
  -d '{"interface":"eth0","filter":"tcp port 443"}' | jq .
```

---

### `POST /api/sessions/{id}/stop`

Stop a running capture session. Signals the capture loop to exit, which causes the SSE stream to close.

**Response**: Updated session JSON with `"status": "Stopped"`.

**Curl example**:
```bash
curl -s -X POST http://localhost:8080/api/sessions/abc123/stop | jq .
```

---

### `DELETE /api/sessions/{id}`

Delete a session record and free its resources. If the session is still active, it is stopped first.

**Response**:
```json
{"success": true}
```

**Curl example**:
```bash
curl -s -X DELETE http://localhost:8080/api/sessions/abc123 | jq .
```

---

## Network Information Endpoints

### `GET /api/conn`

Active connections (TCP/UDP). Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`. Resolves PIDs and process names by scanning `/proc/*/fd/` symlinks for matching socket inodes.

**Response**:
```json
[
  {
    "proto": "tcp",
    "local_ip": "192.168.1.100",
    "local_port": 52366,
    "remote_ip": "8.8.8.8",
    "remote_port": 443,
    "state": "ESTABLISHED",
    "pid": 1234,
    "process": "curl"
  },
  {
    "proto": "tcp",
    "local_ip": "0.0.0.0",
    "local_port": 8080,
    "remote_ip": "0.0.0.0",
    "remote_port": 0,
    "state": "LISTEN",
    "pid": 5678,
    "process": "pktana"
  }
]
```

TCP state values decoded from `/proc/net/tcp` hex field:
`ESTABLISHED`, `SYN_SENT`, `SYN_RECV`, `FIN_WAIT1`, `FIN_WAIT2`, `TIME_WAIT`, `CLOSE`, `CLOSE_WAIT`, `LAST_ACK`, `LISTEN`, `CLOSING`

**Curl example**:
```bash
curl -s http://localhost:8080/api/conn | jq '.[] | select(.state == "ESTABLISHED")'
```

---

### `GET /api/route`

System routing table. Reads `/proc/net/route` (IPv4, hex-encoded fields) and `/proc/net/ipv6_route` (IPv6).

**Response**:
```json
[
  {
    "interface": "eth0",
    "destination": "0.0.0.0",
    "prefix_len": 0,
    "gateway": "192.168.1.1",
    "metric": 100,
    "summary": "default via 192.168.1.1 dev eth0",
    "is_default": true
  },
  {
    "interface": "eth0",
    "destination": "192.168.1.0",
    "prefix_len": 24,
    "gateway": "0.0.0.0",
    "metric": 100,
    "summary": "192.168.1.0/24 dev eth0",
    "is_default": false
  }
]
```

`is_default` is `true` when `destination == "0.0.0.0"` and `prefix_len == 0`.

**Curl example**:
```bash
curl -s http://localhost:8080/api/route | jq '.[] | select(.is_default)'
```

---

### `GET /api/geoip?ip=<addr>`

Offline GeoIP lookup using the embedded database (compiled from a public IP-to-country dataset).

**Query parameters**: `ip` — IPv4 or IPv6 address

**Response**:
```json
{
  "ip": "8.8.8.8",
  "country_name": "United States",
  "country_code": "US",
  "continent": "North America"
}
```

Special cases:
- Private/RFC1918 addresses (`10.x`, `172.16-31.x`, `192.168.x`) → `country_code: "--"`, `country_name: "Private"`
- Loopback (`127.x`) → `country_name: "Loopback"`
- Unknown addresses → `country_code: "--"`, `country_name: "Unknown"`

**Curl example**:
```bash
curl -s "http://localhost:8080/api/geoip?ip=1.1.1.1" | jq .
# Check your own public IP
curl -s "http://localhost:8080/api/geoip?ip=$(curl -s ifconfig.me)" | jq .
```

---

## Documentation Endpoints

### `GET /api/wiki`

List all available documentation pages.

**Response**:
```json
[
  {"id": "overview",      "title": "Overview"},
  {"id": "installation",  "title": "Installation"},
  {"id": "cli-reference", "title": "CLI Reference"},
  {"id": "tui-guide",     "title": "TUI Guide"},
  {"id": "web-ui-guide",  "title": "Web UI Guide"},
  {"id": "dpi-engine",    "title": "DPI Engine"},
  {"id": "flow-analyzer", "title": "Flow Analyzer"},
  {"id": "api-reference", "title": "API Reference"},
  {"id": "library-api",   "title": "Library API (Rust)"},
  {"id": "protocols",     "title": "Protocol Coverage"},
  {"id": "architecture",  "title": "Architecture"},
  {"id": "contributing",  "title": "Contributing"}
]
```

---

### `GET /api/wiki?page=<id>`

Retrieve the raw Markdown content of a documentation page. The content is embedded in the binary at compile time via `include_str!()`.

**Query parameters**: `page` — page ID from the list above (e.g. `overview`, `dpi-engine`)

Both short form (`overview`) and full form (`01-overview`) are accepted.

**Response**: `text/plain; charset=utf-8` — raw Markdown text.

**Curl examples**:
```bash
# Get the DPI engine docs
curl -s "http://localhost:8080/api/wiki?page=dpi-engine"

# Get CLI reference and count lines
curl -s "http://localhost:8080/api/wiki?page=cli-reference" | wc -l

# List all page IDs
curl -s "http://localhost:8080/api/wiki" | jq '.[].id'
```

**Error** (unknown page):
```json
{"error": "wiki page not found"}
```

---

## Terminal Endpoint

### `GET /api/terminal?cmd=<encoded_cmd>`

Execute a shell command and return its combined stdout+stderr output. Commands run in `/bin/sh -c` as the process owner (typically root when pktana is started with sudo).

**Query parameter**: `cmd` — URL-encoded shell command

**Response**:
```json
{"output": "total 48\n-rw-r--r-- 1 root root 1234 Jun 16 10:00 capture.pcap\n"}
```

If the command produces no output, `output` is an empty string. Exit codes are not reported — only the output text is returned.

**Security note**: This endpoint executes arbitrary shell commands. It is intended for local use on trusted networks only. Never expose the pktana web server on a public interface.

**Curl examples**:
```bash
# List files
curl -s "http://localhost:8080/api/terminal?cmd=ls%20-la%20%2Ftmp"

# Show interface addresses
curl -s "http://localhost:8080/api/terminal?cmd=ip%20addr%20show" | jq -r .output

# Run a tcpdump one-shot
curl -s "http://localhost:8080/api/terminal?cmd=tcpdump%20-c%205%20-n%20-i%20eth0" | jq -r .output
```

---

## PCAP Export

### `POST /api/export-filtered`

Export filtered packets to a pcap file. Currently, post-capture filtered export requires that a live capture was originally started with the `export` parameter pointing to a pcap file.

**Request body**:
```json
{
  "filename": "/tmp/filtered.pcap",
  "indices": [1, 2, 3, 5, 8]
}
```

`indices` is a 1-based array of packet sequence numbers to include in the export.

**Response** (when no pcap source is available):
```json
{
  "success": false,
  "error": "To export filtered packets: 1) Set 'Save PCAP' path before starting capture, 2) Capture live traffic, 3) Use 'Export Filtered' button"
}
```

**Response** (on success):
```json
{"success": true, "path": "/tmp/filtered.pcap", "count": 5}
```

---

## Static Assets

| Path | Content-Type | Description |
|------|-------------|-------------|
| `GET /pktana.png` | `image/png` | pktana logo (served from disk if `pktana.png` exists, else 404) |
| `GET /favicon.ico` | `image/x-icon` | Favicon (embedded 16×16 icon) |
| Anything else | `application/json` | `{"error": "Not found"}` with HTTP 404 |

---

## Error Responses

### HTTP 400 — Bad Request

Missing required query parameters:

```json
{"error": "interface required"}
{"error": "ip parameter required"}
```

### HTTP 404 — Not Found

Unknown route:

```json
{"error": "Not found"}
```

Unknown wiki page:

```json
{"error": "wiki page not found"}
```

### HTTP 500 — Internal Server Error

Returned when a system call fails unexpectedly (rare):

```json
{"error": "internal error: <details>"}
```

---

## Complete Endpoint Summary

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Web UI HTML |
| GET | `/api/server_info` | Hostname, OS version, uptime, memory |
| POST | `/api/stop` | Stop the pktana daemon |
| GET | `/api/interfaces` | List network interfaces |
| GET | `/api/nic` | NIC statistics for all interfaces |
| GET | `/api/nic_detail?iface=<n>` | Detailed stats for one interface |
| GET | `/api/ethtool?iface=<n>` | Driver and queue info |
| GET | `/api/dp?iface=<n>` | Dataplane/bypass detection |
| GET | `/api/inspect?<params>` | SSE packet capture stream |
| GET | `/api/sessions` | List capture sessions |
| POST | `/api/sessions/create` | Create a new session |
| POST | `/api/sessions/{id}/stop` | Stop a session |
| DELETE | `/api/sessions/{id}` | Delete a session |
| GET | `/api/conn` | Active TCP/UDP connections |
| GET | `/api/route` | System routing table |
| GET | `/api/geoip?ip=<addr>` | GeoIP country lookup |
| GET | `/api/wiki` | List documentation pages |
| GET | `/api/wiki?page=<id>` | Get documentation page Markdown |
| GET | `/api/terminal?cmd=<cmd>` | Execute shell command |
| POST | `/api/export-filtered` | Export filtered packets to pcap |
| GET | `/pktana.png` | Logo image |
| GET | `/favicon.ico` | Favicon |
