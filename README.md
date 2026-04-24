# pktana

`pktana` is a Linux-first packet analyzer workspace written in Rust.

Important deployment note:

- End users on CentOS do not need Rust or Cargo installed.
- Rust/Cargo are only needed on the build machine.
- The intended deployment model is to ship a compiled `pktana` binary or RPM/tarball.
- If you build with the current optional `pcap` feature, the target machine may also need `libpcap`.
- If you want zero extra runtime dependencies for live capture, the next step is replacing the current `pcap` capture path with native Linux `AF_PACKET`.

This initial scaffold is designed as a serious MVP foundation:

- `pktana-core`: packet models, basic protocol parsing, flow tracking, and summaries
- `pktana-cli`: command-line interface for demo traffic, single-packet decoding, batch file analysis, and optional live capture

## Current MVP capabilities

- Parse raw Ethernet frames from hex
- Parse live packets through optional `pcap` support
- Decode:
  - Ethernet II
  - IPv4
  - TCP
  - UDP
- Produce human-readable packet summaries
- Build simple flow records from decoded packets
- Analyze packets from:
  - inline hex input
  - text files with one hex packet per line
  - built-in demo samples
  - Linux capture interfaces when built with the `pcap` feature

## Planned next steps

- Linux live capture with `AF_PACKET` and `libpcap`
- BPF-style filter expressions
- PCAP/PCAPNG ingestion
- DNS, TLS, and HTTP metadata extraction
- Stream reassembly
- REST API and web dashboard

## Workspace layout

```text
pktana/
├── Cargo.toml
├── README.md
├── docs/
│   └── architecture.md
└── crates/
    ├── pktana-core/
    └── pktana-cli/
```

## Build

```bash
cd pktana
cargo build
cargo run -p pktana-cli -- demo
cargo run -p pktana-cli -- hex 00112233445566778899aabb08004500002800010000400666cd0a0000010a00000201bb303900000001000000005002faf090b00000
```

## CentOS deployment

For CentOS, the recommended model is:

1. Build on a compatible Linux build machine
2. Package the compiled binary
3. Copy the package to the CentOS server
4. Install the binary into `/usr/local/bin` or package it as an RPM

That means the CentOS server only receives the final executable, not the Rust source toolchain.

### Build a release binary

```bash
cd pktana
./scripts/build-release.sh
```

### Package a tarball for transfer

```bash
cd pktana
./scripts/package-centos.sh
```

This creates a distributable archive in `dist/`.

### Build an RPM

On a CentOS/RHEL build machine with `rpm-build` installed:

```bash
cd pktana
./scripts/build-rpm.sh
```

Prerequisite on the RPM build machine:

```bash
sudo yum install -y rpm-build
```

The resulting RPM will be placed under `dist/rpmbuild/RPMS/`.

### Install on CentOS

After copying the tarball to CentOS:

```bash
tar -xzf pktana-linux-amd64.tar.gz
cd pktana-linux-amd64
sudo ./install.sh
pktana --help
```

Install from RPM:

```bash
sudo rpm -ivh pktana-0.1.0-1.el*.x86_64.rpm
pktana --help
```

## Runtime dependency model

### No Rust/Cargo on target

This is already achievable:

- build the binary once
- ship only the binary and support files
- do not compile on the target server

### No extra shared libraries on target

This depends on capture mode:

- current default parser/demo/file mode can be shipped as a normal compiled binary
- current `pcap` live-capture mode may require `libpcap` on the target
- planned native `AF_PACKET` mode is the right path for a CentOS-friendly live sniffer with no `libpcap` dependency

## Live Linux capture

Live capture is feature-gated so the project can still build in environments without `libpcap`.

Example:

```bash
cd pktana
cargo run -p pktana-cli --features pcap -- interfaces
cargo run -p pktana-cli --features pcap -- capture eth0 25 tcp
```

Typical Linux packages you may need:

```bash
sudo yum install -y libpcap libpcap-devel
```

## File mode

Create a text file with one packet hex string per line:

```text
00112233445566778899aabb08004500002800010000400666cd0a0000010a00000201bb303900000001000000005002faf090b00000
00112233445566778899aabb08004500001c00010000401166da0a00000108080808003500350008ad77
```

Then run:

```bash
cargo run -p pktana-cli -- file packets.txt
```
