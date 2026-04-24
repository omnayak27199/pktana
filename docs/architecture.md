# pktana Architecture

## Vision

`pktana` is intended to grow into a Linux-native enterprise packet analysis platform with strong performance, safe parsing, and modular expansion paths.

## MVP design

The current scaffold is split into two crates.

### `pktana-core`

Responsibilities:

- raw frame decoding
- protocol parsing
- packet summary generation
- flow key construction
- flow aggregation
- future parser and capture abstractions

### `pktana-cli`

Responsibilities:

- user input handling
- batch analysis workflows
- demo mode
- rendering summaries and flow statistics

## Planned module evolution

### Capture layer

Future Linux capture modes:

- `libpcap` feature-gated MVP path
- `AF_PACKET`
- `eBPF`
- `XDP`

Current implementation details:

- `LinuxCaptureEngine::list_interfaces()` for discovery
- `LinuxCaptureEngine::capture()` for bounded live ingestion
- optional BPF filter string passed to `pcap`
- decoded frames are fed into the same parser pipeline as file/hex inputs

Deployment implication:

- current `pcap` mode is useful for fast iteration
- enterprise Linux distribution should move to native `AF_PACKET` capture for fewer runtime dependencies on CentOS/RHEL systems
- Rust/Cargo are build-time tools only and should not be required on customer machines

### Parsing layer

Current:

- Ethernet
- IPv4
- TCP
- UDP

Future:

- IPv6
- ICMP
- ARP
- DNS
- TLS
- HTTP
- VXLAN
- GRE

### Flow engine

Current:

- flow key generation from parsed IPv4/TCP/UDP packets
- packet and byte counters

Future:

- TCP stream reassembly
- timeouts
- session state
- anomaly signals

### Storage and control plane

Planned later:

- indexed flow store
- search API
- role-based access control
- distributed sensors
- central management

## Why Rust

- memory safety for hostile packet inputs
- predictable performance
- good fit for concurrent packet pipelines
- suitable for Linux systems programming
- lets us ship a single compiled binary instead of a source-runtime environment

## Distribution strategy

Recommended production distribution for CentOS:

- build release binaries in CI or a controlled Linux builder
- package as tar.gz and RPM
- install to `/usr/local/bin/pktana` or `/usr/bin/pktana`
- avoid requiring Rust, Cargo, or developer headers on customer systems

Suggested packaging pipeline:

- build `pktana` release binary on a CentOS-compatible builder
- create source tarball with binary and docs
- build RPM with `rpmbuild`
- publish RPM to internal repo or artifact storage
