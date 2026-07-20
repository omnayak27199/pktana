# Contributing

---

## Development Setup

```bash
# Clone
git clone https://github.com/omnayak27199/pktana
cd pktana

# Install Rust (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install libpcap dev headers
sudo apt install libpcap-dev      # Debian/Ubuntu
sudo dnf install libpcap-devel    # RHEL/Rocky

# Build all features
cargo build --features pcap,tui

# Run checks (same as CI)
cargo fmt --all
cargo clippy --all-targets --features pcap,tui -- -D warnings
cargo test --features pcap,tui
```

---

## Project Conventions

### Code Style

- `cargo fmt --all` before every commit
- `cargo clippy --features pcap,tui -- -D warnings` must produce zero warnings
- No `unwrap()` in library code — use `?` and `Option`/`Result` propagation
- No unsafe code except in performance-critical paths (document why)
- No external proc-macro crates without good reason

### Comments

Only add comments for non-obvious behaviour:
- Hidden constraints or kernel quirks
- Byte-order traps (IPv6 procfs byte order, etc.)
- Workarounds for specific kernel/hardware bugs

Do **not** add comments explaining what the code does — well-named identifiers do that.

### Testing

- Unit tests go in the same file as the code (`#[cfg(test)]` module)
- Integration tests for the CLI go in `tests/`
- Tests must not require root or a real network interface (mock or use `demo` samples)
- `LinuxCaptureEngine` tests that need pcap are gated with `#[cfg(feature = "pcap")]`

---

## Module Guide for Contributors

### Adding a new protocol to the DPI engine

1. Open `crates/pktana-core/src/dpi.rs`
2. Add detection in `detect_app_proto(port: u16, data: &[u8], dp: &mut DeepPacket)`:
   ```rust
   // Match by well-known port
   Some(3306) | Some(3307) => { detect_mysql(data, dp); }
   ```
3. Write a `fn detect_<proto>(data: &[u8], dp: &mut DeepPacket)` function
4. Set `dp.app_proto = Some("MyProto".to_string())`
5. Add description lines to `dp.app_detail`
6. Add anomaly checks to `dp.anomalies` if applicable
7. Add risk score contribution if the protocol has known abuse patterns
8. Add a test case with a real captured hex frame in `#[cfg(test)]`

### Adding a flow analysis state machine

1. Open `crates/pktana-core/src/flow_analyzer.rs`
2. Add a new state enum: `MyProtoState { Init, ..., Complete { ... } }`
3. Add an analysis struct: `MyProtoAnalysis { state, complete, ... }`
4. Implement `analyze(&mut self, dp: &DeepPacket, ts: Instant) -> Option<String>`
5. Add a `HashMap<FlowId, MyProtoAnalysis>` field to `FlowAnalyzer`
6. Call it in `FlowAnalyzer::analyze_packet()`
7. Add statistics to `FlowAnalyzerSummary`

### Adding a new CLI command

1. Open `crates/pktana-cli/src/main.rs`
2. Add a new match arm in `fn main()`:
   ```rust
   "mycommand" | "mc" => run_my_command(&args[2..])?,
   ```
3. Write `fn run_my_command(args: &[String]) -> Result<(), CliError>`
4. Add help text in `fn print_usage()` and `fn print_doc(topic)`

### Adding a new Web API endpoint

1. Open `crates/pktana-cli/src/web.rs`
2. Add a new `else if request.starts_with("GET /api/my_endpoint ")` branch in `handle_client()`
3. Read query parameters from the request string using the existing pattern
4. Build a JSON response string manually or using `format!()`
5. Write the response with `stream.write_all(response.as_bytes())`
6. Add the corresponding JavaScript in the `<script>` section (fetch + render)

---

## CI Pipeline

GitHub Actions runs on every push to `main` and all pull requests:

```yaml
# .github/workflows/ci.yml (abbreviated)
- cargo fmt --all -- --check
- cargo clippy --all-targets --features pcap,tui -- -D warnings
- cargo test --features pcap,tui
- cargo build --release --features pcap,tui
```

The release workflow additionally:
- Builds RPM packages for RHEL 7 and RHEL 9
- Builds DEB packages for Ubuntu 22.04 and 24.04
- Creates binary tarballs
- Uploads to GitHub Releases

---

## Release Process

Releases are tagged from `main`:

```bash
# Bump version in all Cargo.toml files
# (workspace package + both crate Cargo.toml files)
vim crates/pktana-core/Cargo.toml   # version = "0.6.0"
vim crates/pktana-cli/Cargo.toml    # version = "0.6.0"

# Update changelog / release notes
git add -A
git commit -m "release: v0.6.0"
git tag v0.6.0
git push origin main --tags
```

The CI release workflow triggers automatically on new tags matching `v*`.

---

## Crate Publishing

```bash
# Publish core first (cli depends on it)
cargo publish -p pktana-core --features pcap

# Then publish the binary
cargo publish -p pktana-cli --features pcap,tui
```

---

## Reporting Issues

File bugs and feature requests at:
**https://github.com/omnayak27199/pktana/issues**

Include:
- pktana version (`pktana --version`)
- Linux kernel version (`uname -r`)
- The command you ran
- Full output / error message
- For DPI bugs: a minimal hex capture of the offending packet
