# pktana Wiki

**pktana** is a high-performance, zero-dependency network packet analyzer and deep inspection toolkit for Linux — written entirely in Rust.

> Replaces `tcpdump`, `wireshark`, `ethtool`, `ss`, `ip route`, and `iftop` with a single unified tool.

---

## Wiki Contents

| Page | Description |
|------|-------------|
| [Overview & Architecture](01-overview.md) | What pktana is, how it works, design goals |
| [Installation](02-installation.md) | Build from source, packages, feature flags |
| [CLI Reference](03-cli-reference.md) | Every command, flag, and shorthand |
| [TUI Dashboard](04-tui-guide.md) | Wireshark-style terminal UI guide |
| [Web UI Guide](05-web-ui-guide.md) | Browser-based multi-window capture UI |
| [DPI Engine](06-dpi-engine.md) | Deep packet inspection internals, all protocols |
| [Flow Analyzer](07-flow-analyzer.md) | Stateful flow analysis: TCP/TLS handshakes, DHCP, DNS |
| [Web API Reference](08-api-reference.md) | All REST/SSE endpoints served by `pktana web` |
| [Library API (pktana-core)](09-library-api.md) | Rust crate API for embedding pktana in your own tools |
| [Protocol Coverage](10-protocols.md) | Full protocol support matrix L2–L7 |
| [Architecture & Internals](11-architecture.md) | Module design, zero-copy pipeline, concurrency model |
| [Contributing](12-contributing.md) | Build setup, testing, adding protocols, release process |

---

## Quick Start

```bash
# Live capture on eth0
sudo pktana capture eth0

# TUI dashboard
sudo pktana tui eth0

# Browser UI on port 8080 (background)
sudo pktana web 8080

# Analyze a saved pcap file
pktana pcap /var/log/capture.pcap

# Show active connections (replaces ss -tunap)
pktana conn

# Show routing table
pktana route
```

---

## Version

Current release: **v0.5.0**  
License: Apache-2.0  
Repository: https://github.com/omnayak27199/pktana
