# pktana Packet Tracer

**Cisco Packet Tracer–style network learning lab** — build topologies visually, configure routers via IOS-style CLI, and run step-by-step ping simulations.

**Desktop app for Windows and macOS** (Electron). Part of the [pktana](https://github.com/omnayak27199/pktana) project.

## What it is

| Cisco Packet Tracer | pktana Packet Tracer |
|---|---|
| Full IOS CLI | IOS subset + visual topology editor |
| Hundreds of device models | PC, Switch, Router |
| Real-time simulation | Educational ping/DNS path + packet animation |
| Desktop (Win/Mac) | **Native Windows + macOS app** |

This is a **learning tool** — not live packet capture. For real traffic on Linux, use the main `pktana` Rust CLI.

## Quick start (desktop)

### Prerequisites

- [Node.js 20+](https://nodejs.org/) (for building from source)

### Run in development

```bash
cd packet-tracer
npm install
npm start
```

### Build installers

| Platform | Command | Output |
|---|---|---|
| **macOS** | `./scripts/build-mac.sh` or `npm run dist:mac` | `.dmg` + `.zip` in `dist/` |
| **Windows** | `scripts\build-win.bat` or `npm run dist:win` | NSIS installer + portable `.exe` in `dist/` |

> macOS `.dmg` builds must run on a Mac (or use CI `macos-latest`).  
> Windows builds run on Windows (or CI `windows-latest`).

For macOS without a local Mac, push to GitHub and download the `desktop-macos-latest` artifact from Actions.

### Browser mode (optional)

```bash
./serve.sh
# Open http://127.0.0.1:8765/
```

## Features

- **Native desktop** — Windows 10/11 and macOS, offline labs (system fonts in desktop mode)
- **Drag-and-drop canvas** — PCs, switches, routers
- **Cable tool** — connect device ports
- **Router CLI (IOS subset)** — `enable`, `conf t`, `interface g0/0`, `ip address`, `no shutdown`, `ip route`, `show run`
- **8 built-in labs** — star LAN, routing, CLI practice, troubleshooting, DNS, DHCP, blank canvas
- **Ping simulation** — IP or hostname with Layer 2/3/7 step log + animation

## Project layout

```
packet-tracer/
├── electron/
│   ├── main.js         # Electron shell + embedded static server
│   └── preload.js
├── index.html          # Learning app UI
├── css/  js/           # Simulator engine
├── package.json        # Electron + electron-builder
├── scripts/
│   ├── build-mac.sh
│   └── build-win.bat
├── serve.sh            # Optional browser dev server
└── legacy/capture-cli/ # Deprecated C++ capture tool
```

## Router CLI quick reference

```
Router> enable
Router# configure terminal
Router(config)# interface g0/0
Router(config-if)# ip address 192.168.1.1 255.255.255.0
Router(config-if)# no shutdown
Router(config-if)# exit
Router(config)# ip route 192.168.2.0 255.255.255.0 10.0.0.2
Router(config)# end
Router# show ip interface brief
Router# show running-config
```

## Roadmap

- [x] Windows + macOS desktop app
- [x] Router CLI (IOS subset)
- [x] DNS, DHCP, multi-router labs
- [ ] Custom app icon
- [ ] Traceroute and ARP table views
- [ ] Save/load topology JSON
- [ ] Linux desktop (AppImage) — later

## License

Apache-2.0 — same as the parent pktana repository.
