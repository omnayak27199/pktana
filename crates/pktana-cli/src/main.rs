// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "mcp")]
mod mcp;
mod tui;
mod web;

use std::cmp::Reverse;
use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use pktana_core::{
    analyze_hex, analyze_hex_file, build_flow_table, check_drift, default_baseline_dir,
    diagnose_path, enrich_bpf_prog_ids, evaluate_packet, format_bytes, get_bond_info,
    get_bridge_info, get_bridge_port_info, get_ethtool_report, get_iommu_group, get_nic_dataplane,
    get_nic_info, get_ptp_clocks, get_security_config, hex_dump, inspect, inspect_ebpf_interface,
    list_connections, list_network_namespaces, list_nics, list_routes, list_xdp_dispatchers,
    routes_for_iface, sample_packets, scan_bpf_fs, stp_state_label, summarize_ebpf_host,
    CaptureConfig, CaptureError, IssueSeverity, LinuxCaptureEngine, NicInfo, ParseError,
    ParsedPacket,
};

// ─── error type ─────────────────────────────────────────────────────────────

#[derive(Debug)]
enum CliError {
    Parse(ParseError),
    Capture(CaptureError),
    Io(std::io::Error),
    Usage(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "{e}"),
            Self::Capture(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Usage(m) => write!(f, "{m}"),
        }
    }
}

impl From<ParseError> for CliError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}
impl From<CaptureError> for CliError {
    fn from(e: CaptureError) -> Self {
        Self::Capture(e)
    }
}
impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ─── entry point ─────────────────────────────────────────────────────────────

fn main() {
    if let Err(err) = run() {
        eprintln!("\x1b[1;31mError:\x1b[0m {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    // Make command case-insensitive
    let cmd = args[1].to_lowercase();
    match cmd.as_str() {
        // ── version ───────────────────────────────────────────────────────────
        "--version" | "-V" | "version" => {
            println!(
                "pktana {}  ({})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_DESCRIPTION")
            );
            println!("license  : Apache-2.0");
            println!("repo     : {}", env!("CARGO_PKG_REPOSITORY"));
            Ok(())
        }

        // ── packet capture ────────────────────────────────────────────────────
        "capture" | "cap" => run_capture(&args[2..]),

        // ── record live traffic to pcap file ──────────────────────────────────
        "record" | "rec" => run_record(&args[2..]),

        // ── pcap interface list ───────────────────────────────────────────────
        "interfaces" | "ifaces" => print_capture_interfaces(),

        // ── NIC detail (sysfs/procfs — no external tools) ────────────────────
        "nic" => run_nic(&args[2..]),

        // ── ip-addr-style interface address view ──────────────────────────────
        "addr" | "address" => run_addr(&args[2..]),

        // ── ethtool-equivalent deep NIC inspection ──────────────────────────────
        "ethtool" | "et" => run_ethtool(&args[2..]),

        // ── NIC dataplane / bypass / offload inspector ────────────────────────
        "dp" | "dataplane" => run_dataplane(&args[2..]),

        // ── BPF filesystem — pinned BPF objects in /sys/fs/bpf/ ─────────────
        "bpf" => run_bpf_fs(),

        // ── Unified eBPF inspector (XDP, TC, pinned, namespaces) ───────────
        "ebpf" => run_ebpf(&args[2..]),

        // ── Network namespace enumeration ─────────────────────────────────────
        "ns" | "netns" => run_netns(),

        // ── Full hardware profile (bridge/bond/PTP/IOMMU/errors) ─────────────
        "hw" | "hardware" => run_hw(&args[2..]),

        // ── deep packet inspection ────────────────────────────────────────────
        "inspect" => run_inspect(&args[2..]),

        // ── pcap file analysis ────────────────────────────────────────────────
        "pcap" | "pkt" => run_pcap_file(&args[2..]),

        // ── offline decode ────────────────────────────────────────────────────
        "demo" => run_demo(),
        "hex" => {
            if args.len() < 3 {
                return Err(CliError::Usage("usage: pktana hex <HEX>".into()));
            }
            let p = analyze_hex(&args[2])?;
            println!("{}", p.summary.pretty());
            Ok(())
        }
        "file" => {
            if args.len() < 3 {
                return Err(CliError::Usage("usage: pktana file <FILE>".into()));
            }
            let (packets, errors) = analyze_hex_file(Path::new(&args[2]))?;
            render_batch(&packets, &errors);
            Ok(())
        }

        // ── routing table / nexthop ────────────────────────────────────────────────
        "route" | "routes" | "nexthop" => run_routes(&args[2..]),

        // ── connection table (replaces ss / netstat) ──────────────────────────
        "conn" | "connections" => run_connections(&args[2..]),

        // ── live traffic stats dashboard (replaces iftop) ────────────────────
        "stats" => run_stats(&args[2..]),

        // ── NIC auto-refresh (replaces watch ip -s) ───────────────────────────
        "watch" => run_watch(&args[2..]),

        // ── TUI live dashboard ────────────────────────────────────────────────
        "tui" => {
            let arg = args.get(2).map(|s| s.as_str()).unwrap_or("eth0");
            if is_pcap_path(arg) {
                tui::inner::run_tui_pcap(arg).map_err(CliError::Io)
            } else {
                tui::inner::run_tui(arg).map_err(CliError::Io)
            }
        }

        // ── Web UI dashboard ──────────────────────────────────────────────────
        "web" => {
            let mut port = 8080;
            let mut foreground = false;
            for arg in args.iter().skip(2) {
                if arg == "-f" || arg == "--foreground" || arg == "--run-server" {
                    foreground = true;
                } else if let Ok(p) = arg.parse::<u16>() {
                    port = p;
                }
            }
            if !foreground {
                let exe = std::env::current_exe().map_err(CliError::Io)?;
                let child = std::process::Command::new(exe)
                    .arg("web")
                    .arg(port.to_string())
                    .arg("--run-server")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(CliError::Io)?;
                println!(
                    "Started pktana Web UI in background (PID: {}) on port {}",
                    child.id(),
                    port
                );
                println!();
                println!("Access the Web UI:");
                println!("  • Browser:   http://localhost:{}", port);
                println!("  • curl:      curl http://localhost:{}/api/nic", port);
                println!(
                    "  • Inspect:   curl 'http://localhost:{}/api/inspect?iface=eth0'",
                    port
                );
                println!("  • Flows:     curl 'http://localhost:{}/api/inspect?iface=eth0&flow_analyze=true'", port);
                println!();
                Ok(())
            } else {
                web::inner::run_web_server(port).map_err(CliError::Usage)
            }
        }

        // ── MCP server for AI agent integration ──────────────────────────────
        "mcp" => {
            #[cfg(feature = "mcp")]
            {
                let mut port: u16 = 3456;
                let mut host = "0.0.0.0".to_string();
                let mut stdio = false;
                let mut i = 2usize;
                while i < args.len() {
                    match args[i].as_str() {
                        "--port" | "-p" => {
                            i += 1;
                            if let Some(p) = args.get(i) {
                                port = p.parse().unwrap_or(port);
                            }
                        }
                        "--host" | "-H" => {
                            i += 1;
                            if let Some(h) = args.get(i) {
                                host = h.clone();
                            }
                        }
                        "--stdio" => stdio = true,
                        _ => {}
                    }
                    i += 1;
                }
                mcp::inner::run_mcp_server(port, &host, stdio).map_err(CliError::Usage)?;
            }
            #[cfg(not(feature = "mcp"))]
            {
                eprintln!("pktana was not built with MCP support.");
                eprintln!("Rebuild:  cargo build --release --features mcp -p pktana-cli");
            }
            Ok(())
        }

        // ── GeoIP lookup ──────────────────────────────────────────────────────
        "geoip" | "geo" => run_geoip(&args[2..]),

        "help" | "--help" | "-h" | "-?" => match args.get(2).map(|s| s.as_str()) {
            Some(topic) => print_doc(topic),
            None => {
                print_usage();
                Ok(())
            }
        },

        // ── shorthand: pktana <interface> [count] [filter] ───────────────────
        _ => {
            if is_pcap_path(&args[1]) {
                run_pcap_file(&args[1..])
            } else {
                run_capture(&args[1..])
            }
        }
    }
}

// ─── DPI-enriched display helpers ────────────────────────────────────────────

/// Derive a short protocol label from a `DeepPacket` (app-layer aware).
fn dp_proto_label(dp: &pktana_core::DeepPacket) -> String {
    if dp.quic_detected {
        return "QUIC".to_string();
    }
    if dp.http2_detected {
        return "HTTP2".to_string();
    }
    if let Some(proto) = &dp.app_proto {
        return proto.to_uppercase();
    }
    if dp.tcp_src_port.is_some() {
        return "TCP".to_string();
    }
    if dp.udp_src_port.is_some() {
        return "UDP".to_string();
    }
    if dp.icmp_type.is_some() {
        return "ICMP".to_string();
    }
    if dp.arp.is_some() {
        return "ARP".to_string();
    }
    match dp.ether_type {
        0x86dd => "IPv6".to_string(),
        _ => "?".to_string(),
    }
}

/// Wrap a pre-padded protocol label string with ANSI color codes.
fn dp_proto_color(proto: &str, padded: &str) -> String {
    match proto {
        "TLS" | "HTTPS" | "SSL" => format!("\x1b[32m{padded}\x1b[0m"),
        "HTTP" | "HTTP2" => format!("\x1b[34m{padded}\x1b[0m"),
        "DNS" => format!("\x1b[36m{padded}\x1b[0m"),
        "ICMP" => format!("\x1b[1;33m{padded}\x1b[0m"),
        "ARP" => format!("\x1b[35m{padded}\x1b[0m"),
        "QUIC" => format!("\x1b[1;32m{padded}\x1b[0m"),
        "SSH" => format!("\x1b[1;34m{padded}\x1b[0m"),
        "BGP" | "NTP" => format!("\x1b[31m{padded}\x1b[0m"),
        "SIP" | "VOIP" => format!("\x1b[35m{padded}\x1b[0m"),
        _ => padded.to_string(),
    }
}

/// Source address string from a DeepPacket: "ip:port" or IPv6 or MAC.
fn dp_src_str(dp: &pktana_core::DeepPacket) -> String {
    if let Some(src) = dp.ip_src {
        if let Some(p) = dp.tcp_src_port.or(dp.udp_src_port) {
            return format!("{src}:{p}");
        }
        return src.to_string();
    }
    if let Some(src6) = &dp.ipv6_src {
        return src6.clone();
    }
    dp.eth_src.clone()
}

/// Destination address string from a DeepPacket: "ip:port" or IPv6 or MAC.
fn dp_dst_str(dp: &pktana_core::DeepPacket) -> String {
    if let Some(dst) = dp.ip_dst {
        if let Some(p) = dp.tcp_dst_port.or(dp.udp_dst_port) {
            return format!("{dst}:{p}");
        }
        return dst.to_string();
    }
    if let Some(dst6) = &dp.ipv6_dst {
        return dst6.clone();
    }
    dp.eth_dst.clone()
}

/// Build a rich Info column string from a DeepPacket (TLS SNI, HTTP method, DNS, etc.)
fn dp_info_str(dp: &pktana_core::DeepPacket) -> String {
    let mut app_info = String::new();

    // QUIC/HTTP3
    if dp.quic_detected {
        let ver = dp
            .quic_version
            .map(|v| format!(" v0x{v:08x}"))
            .unwrap_or_default();
        app_info = format!("QUIC/HTTP3{ver}");
    }
    // App-proto specific enrichment
    else if let Some(proto) = &dp.app_proto {
        match proto.to_lowercase().as_str() {
            "tls" => {
                let mut parts: Vec<String> = Vec::new();
                for line in &dp.app_detail {
                    let l = line.trim();
                    if l.starts_with("SNI") {
                        if let Some(sni) = l.split_once(':').map(|x| x.1) {
                            parts.push(format!("sni={}", sni.trim()));
                        }
                    } else if l.starts_with("Version") {
                        if let Some(ver) = l.split_once(':').map(|x| x.1) {
                            parts.push(ver.trim().to_string());
                        }
                    }
                }
                if !dp.tls_alpn.is_empty() {
                    parts.push(format!("alpn=[{}]", dp.tls_alpn.join(",")));
                }
                let body = parts.join(" ");
                app_info = if body.is_empty() {
                    "TLS".to_string()
                } else {
                    format!("TLS {body}")
                };
            }
            "http" => {
                let mut found = false;
                for line in &dp.app_detail {
                    let l = line.trim();
                    if l.starts_with("Method") || l.starts_with("Status") {
                        if let Some(v) = l.split_once(':').map(|x| x.1) {
                            app_info = format!("HTTP {}", v.trim());
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    app_info = dp
                        .app_detail
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "HTTP".to_string());
                }
            }
            "dns" => {
                app_info = dp
                    .dns_query_name
                    .as_deref()
                    .map(|q| format!("DNS {q}"))
                    .unwrap_or_else(|| "DNS".to_string());
            }
            "ssh" => {
                app_info = dp
                    .ssh_banner
                    .as_deref()
                    .map(|b| format!("SSH {}", &b[..b.len().min(40)]))
                    .unwrap_or_else(|| "SSH".to_string());
            }
            "sip" => {
                let m = dp.sip_method.as_deref().unwrap_or("SIP");
                let u = dp.sip_uri.as_deref().unwrap_or("");
                app_info = format!("{m} {u}").trim().to_string();
            }
            "bgp" => {
                let msg = dp.bgp_msg_type.as_deref().unwrap_or("BGP");
                let asn = dp.bgp_asn.map(|a| format!(" AS{a}")).unwrap_or_default();
                app_info = format!("BGP {msg}{asn}");
            }
            "ntp" => {
                let ver = dp.ntp_version.map(|v| format!("v{v} ")).unwrap_or_default();
                let mode = dp
                    .ntp_mode
                    .map(|m| format!("mode={m} "))
                    .unwrap_or_default();
                let amp = if dp.ntp_amplification_risk {
                    "[AMPL-RISK]"
                } else {
                    ""
                };
                app_info = format!("NTP {ver}{mode}{amp}").trim().to_string();
            }
            _ => {
                app_info = dp
                    .app_detail
                    .first()
                    .cloned()
                    .unwrap_or_else(|| proto.to_uppercase());
            }
        }
    }
    // HTTP/2 without explicit app_proto
    else if dp.http2_detected {
        let grpc = dp
            .grpc_path
            .as_deref()
            .map(|p| format!(" gRPC={p}"))
            .unwrap_or_default();
        app_info = format!("HTTP/2{grpc}");
    }
    // SSH banner without app_proto set
    else if let Some(b) = &dp.ssh_banner {
        app_info = format!("SSH {}", &b[..b.len().min(40)]);
    }
    // SIP
    else if let Some(m) = &dp.sip_method {
        app_info = format!("SIP {m}");
    }
    // BGP
    else if let Some(msg) = &dp.bgp_msg_type {
        app_info = format!("BGP {msg}");
    }

    let mut l4_info = String::new();
    if let Some(flags) = &dp.tcp_flags_str {
        let svc = dp
            .tcp_dst_port
            .map(|p| {
                let s = port_service_name(p);
                if s != "?" {
                    format!(" [{s}]")
                } else {
                    String::new()
                }
            })
            .unwrap_or_default();
        let seq = dp.tcp_seq.map(|s| format!(" seq {s}")).unwrap_or_default();
        let ack = dp
            .tcp_ack
            .map(|a| {
                if a > 0 || flags.contains("ACK") {
                    format!(" ack {a}")
                } else {
                    String::new()
                }
            })
            .unwrap_or_default();
        let win = dp
            .tcp_window
            .map(|w| format!(" win {w}"))
            .unwrap_or_default();
        let len = format!(" len {}", dp.tcp_payload_len);
        l4_info = format!("{flags}{svc}{seq}{ack}{win}{len}");
    } else if let Some(p) = dp.udp_dst_port.or(dp.udp_src_port) {
        let s = port_service_name(p);
        let svc = if s != "?" {
            format!("[{s}] ")
        } else {
            String::new()
        };
        l4_info = format!("{svc}UDP len {}", dp.udp_payload_len);
    } else if let Some(t) = dp.icmp_type {
        let c = dp
            .icmp_code
            .map(|code| format!(" code {code}"))
            .unwrap_or_default();
        l4_info = format!("ICMP type {t}{c}");
    }

    if !app_info.is_empty() && !l4_info.is_empty() {
        format!("{app_info}  |  {l4_info}")
    } else if !app_info.is_empty() {
        app_info
    } else {
        l4_info
    }
}

/// Returns true when the path looks like a PCAP/PCAPNG/CAP file.
fn is_pcap_path(s: &str) -> bool {
    let l = s.to_lowercase();
    l.ends_with(".pcap") || l.ends_with(".pcapng") || l.ends_with(".cap")
}

// ─── live capture ─────────────────────────────────────────────────────────────

fn run_capture(args: &[String]) -> Result<(), CliError> {
    if args.is_empty() {
        return Err(CliError::Usage(
            "usage: pktana <INTERFACE> [COUNT] [BPF_FILTER] [--flow-analyze|-a]".into(),
        ));
    }

    // Check for flow analysis flag
    let flow_analyze = args.iter().any(|a| a == "--flow-analyze" || a == "-a");
    let args: Vec<String> = args
        .iter()
        .filter(|a| *a != "--flow-analyze" && *a != "-a")
        .cloned()
        .collect();

    let interface = &args[0];

    let (max_packets, filter) = match args.get(1) {
        None => (0, None),
        Some(second) => match second.parse::<usize>() {
            Ok(n) => {
                let f = if args.len() > 2 {
                    Some(args[2..].join(" "))
                } else {
                    None
                };
                (n, f)
            }
            Err(_) => (0, Some(args[1..].join(" "))),
        },
    };

    let count_label = if max_packets == 0 {
        "unlimited".to_string()
    } else {
        max_packets.to_string()
    };
    let filter_label = filter.as_deref().unwrap_or("none");

    if flow_analyze {
        println!(
            "Capturing on {interface}  |  mode: FLOW ANALYSIS  |  packets: {count_label}  |  filter: {filter_label}"
        );
        println!("Analyzing: TCP/TLS handshakes, DHCP DORA, DNS transactions");
    } else {
        println!(
            "Capturing on {interface}  |  packets: {count_label}  |  filter: {filter_label}  |  Ctrl+C to stop"
        );
    }
    println!();

    let sep = "─".repeat(118);
    println!(
        "\x1b[1;36m{:>5}  {:<17}  {:>7}  {:<5}  {:<26}  {:<26}  Info\x1b[0m",
        "No.", "Time", "Bytes", "Proto", "Source", "Destination"
    );
    println!("\x1b[1;36m{sep}\x1b[0m");
    let _ = std::io::stdout().flush();

    let config = CaptureConfig {
        interface: interface.clone(),
        max_packets: if max_packets == 0 {
            usize::MAX
        } else {
            max_packets
        },
        promiscuous: true,
        snapshot_len: 65_535,
        filter,
        pcap_export: None,
    };

    let mut pkt_num: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut proto_counts: HashMap<String, u64> = HashMap::new();
    let mut src_counts: HashMap<String, (u64, u64)> = HashMap::new();
    let mut analyzer = if flow_analyze {
        Some(pktana_core::FlowAnalyzer::new())
    } else {
        None
    };

    let stats = LinuxCaptureEngine::capture_streaming(&config, |pkt| {
        pkt_num += 1;
        let ts = format_timestamp(pkt.timestamp_sec, pkt.timestamp_usec);
        let bytes = pkt.data.len();
        total_bytes += bytes as u64;

        let dp = inspect(&pkt.data);

        // DLP / IDPS evaluation when engines are enabled
        let sec_cfg = get_security_config();
        if sec_cfg.dlp_enabled || sec_cfg.idps_enabled {
            let sec = evaluate_packet(
                &dp,
                pkt.timestamp_sec as u64,
                bytes as u64,
                &config.interface,
                "",
            );
            for a in &sec.alerts {
                let sev_color = match a.severity.as_str() {
                    "critical" => "\x1b[1;31m",
                    "high" => "\x1b[1;91m",
                    "medium" => "\x1b[1;33m",
                    _ => "\x1b[1;36m",
                };
                println!(
                    "      {sev_color}[{}] {}\x1b[0m {} — {} ({})",
                    a.engine.to_uppercase(),
                    a.severity.to_uppercase(),
                    a.title,
                    a.detail,
                    a.verdict
                );
            }
        }

        // Flow analysis mode
        if let Some(ref mut analyzer) = analyzer {
            let results = analyzer.analyze_packet(&dp);
            for result in results {
                println!("{:>5}  {:<17}  {}", pkt_num, ts, result);
            }

            // Print summary every 100 packets
            if pkt_num.is_multiple_of(100) && pkt_num > 0 {
                let summary = analyzer.get_summary();
                println!("\x1b[1;34m────── Summary: {} TCP ({} complete), {} TLS ({} complete), {} DHCP ({} complete) ──────\x1b[0m", 
                    summary.total_tcp_flows, summary.complete_tcp_handshakes,
                    summary.total_tls_flows, summary.complete_tls_handshakes,
                    summary.total_dhcp_flows, summary.complete_dhcp_dora);
            }
            return true;
        }

        let proto = dp_proto_label(&dp);
        let src = dp_src_str(&dp);
        let dst = dp_dst_str(&dp);
        let info = dp_info_str(&dp);

        // Accumulate end-of-capture stats
        *proto_counts.entry(proto.clone()).or_insert(0) += 1;
        let src_ip = dp
            .ip_src
            .map(|a| a.to_string())
            .or_else(|| dp.ipv6_src.clone())
            .unwrap_or_default();
        if !src_ip.is_empty() {
            let e = src_counts.entry(src_ip).or_insert((0, 0));
            e.0 += 1;
            e.1 += bytes as u64;
        }

        // Color-coded protocol column (pre-pad to width 5, then wrap with ANSI)
        let proto_padded = format!("{proto:<5}");
        let proto_col = dp_proto_color(&proto, &proto_padded);

        // RST packets highlighted
        let info_col = if dp.tcp_flags_str.as_deref() == Some("RST")
            || dp.tcp_flags_str.as_deref() == Some("RST ACK")
        {
            format!("\x1b[1;31m{info}\x1b[0m")
        } else {
            info
        };

        println!(
            "{:>5}  {:<17}  {:>7}  {}  {:<26}  {:<26}  {}",
            pkt_num,
            ts,
            bytes,
            proto_col,
            trunc(&src, 26),
            trunc(&dst, 26),
            info_col,
        );
        let _ = std::io::stdout().flush();
        true
    })?;

    println!("\x1b[1;36m{sep}\x1b[0m");
    println!(
        "{} packets captured  |  {} total",
        stats.packets_seen,
        format_bytes(total_bytes),
    );

    // ── End-of-capture summary ────────────────────────────────────────────────
    if !proto_counts.is_empty() {
        println!();
        println!("  Protocol Breakdown:");
        let total_pkts = pkt_num as f64;
        let mut protos: Vec<(&String, &u64)> = proto_counts.iter().collect();
        protos.sort_by_key(|(_, v)| Reverse(**v));
        for (name, cnt) in protos.iter().take(8) {
            let pct = **cnt as f64 / total_pkts * 100.0;
            println!("    {:<8}  {:>6} pkts  ({:5.1}%)", name, cnt, pct);
        }
    }
    if !src_counts.is_empty() {
        println!();
        println!("  Top Talkers (source IP):");
        let mut srcs: Vec<(&String, &(u64, u64))> = src_counts.iter().collect();
        srcs.sort_by_key(|(_, v)| Reverse(v.0));
        for (i, (ip, (pkts, bytes))) in srcs.iter().take(5).enumerate() {
            println!(
                "    {:>2}.  {:<24}  {:>6} pkts   {}",
                i + 1,
                ip,
                pkts,
                format_bytes(*bytes)
            );
        }
    }
    Ok(())
}

// ─── record live traffic to a .pcap file ──────────────────────────────────────
//  usage: pktana record <INTERFACE> <OUTPUT.pcap> [COUNT] [BPF_FILTER]

fn run_record(args: &[String]) -> Result<(), CliError> {
    if args.len() < 2 {
        return Err(CliError::Usage(
            "usage: pktana record <INTERFACE> <OUTPUT.pcap> [COUNT] [BPF_FILTER]".into(),
        ));
    }
    let interface = &args[0];
    let out_path = &args[1];
    if !is_pcap_path(out_path) {
        return Err(CliError::Usage(format!(
            "output file must end in .pcap / .pcapng / .cap — got '{out_path}'"
        )));
    }

    let (max_packets, filter) = match args.get(2) {
        None => (0, None),
        Some(s) => match s.parse::<usize>() {
            Ok(n) => {
                let f = if args.len() > 3 {
                    Some(args[3..].join(" "))
                } else {
                    None
                };
                (n, f)
            }
            Err(_) => (0, Some(args[2..].join(" "))),
        },
    };

    let count_label = if max_packets == 0 {
        "unlimited".to_string()
    } else {
        max_packets.to_string()
    };
    let filter_label = filter.as_deref().unwrap_or("none");

    println!(
        "Recording on {interface}  →  {out_path}  |  packets: {count_label}  |  filter: {filter_label}  |  Ctrl+C to stop"
    );
    println!();

    let sep = "─".repeat(118);
    println!(
        "\x1b[1;36m{:>5}  {:<17}  {:>7}  {:<5}  {:<26}  {:<26}  Info\x1b[0m",
        "No.", "Time", "Bytes", "Proto", "Source", "Destination"
    );
    println!("\x1b[1;36m{sep}\x1b[0m");
    let _ = std::io::stdout().flush();

    let config = CaptureConfig {
        interface: interface.clone(),
        max_packets: if max_packets == 0 {
            usize::MAX
        } else {
            max_packets
        },
        promiscuous: true,
        snapshot_len: 65_535,
        filter,
        pcap_export: Some(out_path.clone()),
    };

    let mut pkt_num: usize = 0;
    let mut total_bytes: u64 = 0;

    let stats = LinuxCaptureEngine::capture_streaming(&config, |pkt| {
        pkt_num += 1;
        let ts = format_timestamp(pkt.timestamp_sec, pkt.timestamp_usec);
        let bytes = pkt.data.len();
        total_bytes += bytes as u64;

        let dp = inspect(&pkt.data);
        let sec_cfg = get_security_config();
        if sec_cfg.dlp_enabled || sec_cfg.idps_enabled {
            let sec = evaluate_packet(
                &dp,
                pkt.timestamp_sec as u64,
                bytes as u64,
                &config.interface,
                "",
            );
            for a in &sec.alerts {
                let sev_color = match a.severity.as_str() {
                    "critical" => "\x1b[1;31m",
                    "high" => "\x1b[1;91m",
                    "medium" => "\x1b[1;33m",
                    _ => "\x1b[1;36m",
                };
                println!(
                    "      {sev_color}[{}] {}\x1b[0m {} — {} ({})",
                    a.engine.to_uppercase(),
                    a.severity.to_uppercase(),
                    a.title,
                    a.detail,
                    a.verdict
                );
            }
        }
        let proto = dp_proto_label(&dp);
        let src = dp_src_str(&dp);
        let dst = dp_dst_str(&dp);
        let info = dp_info_str(&dp);

        let proto_padded = format!("{proto:<5}");
        let proto_col = dp_proto_color(&proto, &proto_padded);

        println!(
            "{:>5}  {:<17}  {:>7}  {}  {:<26}  {:<26}  {}",
            pkt_num,
            ts,
            bytes,
            proto_col,
            trunc(&src, 26),
            trunc(&dst, 26),
            info,
        );
        let _ = std::io::stdout().flush();
        true
    })?;

    println!("\x1b[1;36m{sep}\x1b[0m");
    println!(
        "{} packets captured  |  {}  |  saved → {out_path}",
        stats.packets_seen,
        format_bytes(total_bytes),
    );
    Ok(())
}

// ─── pcap file analysis ────────────────────────────────────────────────────────

fn run_pcap_file(args: &[String]) -> Result<(), CliError> {
    let path =
        match args.first() {
            Some(p) => p.as_str(),
            None => return Err(CliError::Usage(
                "usage: pktana pcap <FILE.pcap> [BPF_FILTER]\n       (also: pktana <FILE.pcap>)"
                    .into(),
            )),
        };

    // Optional BPF filter label (informational only — offline filtering not
    // supported by this path; user can pre-filter with tcpdump -w)
    let filter_label = if args.len() > 1 { &args[1] } else { "none" };

    println!(
        "Analyzing {}  |  filter: {}  |  Ctrl+C to stop early",
        path, filter_label
    );
    println!();

    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);

    let sep = "─".repeat(130);
    println!(
        "\x1b[1;36m{:>5}  {:<22}  {:>7}  {:<7}  {:<26}  {:<26}  Info\x1b[0m",
        "No.", "Timestamp", "Bytes", "Proto", "Source", "Destination"
    );
    println!("\x1b[1;36m{sep}\x1b[0m");
    let _ = std::io::stdout().flush();

    let mut pkt_num: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut proto_counts: HashMap<String, u64> = HashMap::new();
    let mut src_counts: HashMap<String, (u64, u64)> = HashMap::new();
    let mut base_ts: Option<f64> = None;

    let stats = LinuxCaptureEngine::read_pcap_file(path, |pkt| {
        pkt_num += 1;

        // Use pcap timestamps for display
        let ts_epoch = pkt.timestamp_sec as f64 + pkt.timestamp_usec as f64 / 1_000_000.0;
        let rel_secs = match base_ts {
            None => {
                base_ts = Some(ts_epoch);
                0.0
            }
            Some(base) => ts_epoch - base,
        };
        let ts_str = format!(
            "{:>10}.{:06}",
            rel_secs as u64,
            ((rel_secs - rel_secs.floor()) * 1_000_000.0) as u64
        );

        let bytes = pkt.data.len();
        total_bytes += bytes as u64;

        let dp = inspect(&pkt.data);
        let proto = dp_proto_label(&dp);
        let src = dp_src_str(&dp);
        let dst = dp_dst_str(&dp);
        let info = dp_info_str(&dp);

        *proto_counts.entry(proto.clone()).or_insert(0) += 1;
        let src_ip = dp
            .ip_src
            .map(|a| a.to_string())
            .or_else(|| dp.ipv6_src.clone())
            .unwrap_or_default();
        if !src_ip.is_empty() {
            let e = src_counts.entry(src_ip).or_insert((0, 0));
            e.0 += 1;
            e.1 += bytes as u64;
        }

        let proto_padded = format!("{proto:<7}");
        let proto_col = dp_proto_color(&proto, &proto_padded);

        let info_col = if dp.tcp_flags_str.as_deref() == Some("RST")
            || dp.tcp_flags_str.as_deref() == Some("RST ACK")
        {
            format!("\x1b[1;31m{info}\x1b[0m")
        } else {
            info
        };

        println!(
            "{:>5}  {:<22}  {:>7}  {}  {:<26}  {:<26}  {}",
            pkt_num,
            ts_str,
            bytes,
            proto_col,
            trunc(&src, 26),
            trunc(&dst, 26),
            info_col,
        );
        let _ = std::io::stdout().flush();
        true
    })?;

    println!("\x1b[1;36m{sep}\x1b[0m");
    println!(
        "{} packets read  |  {} total  |  file: {}",
        stats.packets_seen,
        format_bytes(total_bytes),
        filename
    );

    // Summary
    if !proto_counts.is_empty() {
        println!();
        println!("  Protocol Breakdown:");
        let total_pkts = pkt_num as f64;
        let mut protos: Vec<(&String, &u64)> = proto_counts.iter().collect();
        protos.sort_by_key(|(_, v)| Reverse(**v));
        for (name, cnt) in protos.iter().take(10) {
            let pct = **cnt as f64 / total_pkts * 100.0;
            let bar = ascii_bar(pct, 30);
            println!("    {:<8}  {}  {:5.1}%  {:>6} pkts", name, bar, pct, cnt);
        }
    }
    if !src_counts.is_empty() {
        println!();
        println!("  Top Talkers (source IP):");
        let mut srcs: Vec<(&String, &(u64, u64))> = src_counts.iter().collect();
        srcs.sort_by_key(|(_, v)| Reverse(v.0));
        for (i, (ip, (pkts, bytes))) in srcs.iter().take(10).enumerate() {
            println!(
                "    {:>2}.  {:<24}  {:>6} pkts   {}",
                i + 1,
                ip,
                pkts,
                format_bytes(*bytes)
            );
        }
    }
    Ok(())
}

// ─── pcap interface list ──────────────────────────────────────────────────────

fn print_capture_interfaces() -> Result<(), CliError> {
    let ifaces = LinuxCaptureEngine::list_interfaces()?;
    if ifaces.is_empty() {
        println!("No capture interfaces found.");
        return Ok(());
    }
    println!("Capture interfaces ({}):\n", ifaces.len());
    for iface in &ifaces {
        let kind = if iface.loopback {
            "loopback"
        } else {
            "network "
        };
        let addrs = if iface.addresses.is_empty() {
            "—".to_string()
        } else {
            iface.addresses.join(", ")
        };
        println!("  {:<16}  [{}]  {}", iface.name, kind, addrs);
        if let Some(desc) = &iface.description {
            println!("                    desc: {desc}");
        }
    }
    Ok(())
}

// ─── nic info / stats ─────────────────────────────────────────────────────────

fn run_nic(args: &[String]) -> Result<(), CliError> {
    let json = args.iter().any(|a| a == "--json" || a == "-j");
    let target = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str());

    match target {
        // pktana nic  or  pktana nic list
        None | Some("list") => {
            let nics = list_nics()?;
            if json {
                let mut out = String::from("[\n");
                for (i, nic) in nics.iter().enumerate() {
                    let state = if nic.is_up() { "UP" } else { "DOWN" };
                    let ips = nic
                        .ip_addresses
                        .iter()
                        .map(|ip| format!("\"{}\"", ip))
                        .collect::<Vec<_>>()
                        .join(",");
                    out.push_str(&format!(
                        r#"  {{"name":"{}","state":"{}","mac":"{}","mtu":{},"speed_mbps":{},"ips":[{}]}}"#,
                        nic.name, state, nic.mac, nic.mtu, nic.speed_mbps.unwrap_or(0), ips
                    ));
                    if i < nics.len() - 1 {
                        out.push_str(",\n");
                    } else {
                        out.push('\n');
                    }
                }
                out.push(']');
                println!("{out}");
                return Ok(());
            }

            println!(
                "\x1b[1;36m{:<16}  {:<5}  {:<19}  {:<6}  {:<8}  IP Addresses\x1b[0m",
                "Interface", "State", "MAC", "MTU", "Speed"
            );
            println!("\x1b[1;36m{}\x1b[0m", "─".repeat(90));
            for nic in &nics {
                let state = if nic.is_up() { "UP" } else { "down" };
                let speed = nic.speed_label();
                let ips = if nic.ip_addresses.is_empty() {
                    "—".to_string()
                } else {
                    nic.ip_addresses.join(", ")
                };
                println!(
                    "{:<16}  {:<5}  {:<19}  {:<6}  {:<8}  {}",
                    nic.name, state, nic.mac, nic.mtu, speed, ips,
                );
            }
        }

        // pktana nic <interface>
        Some(name) => {
            let nic = get_nic_info(name)?;

            if json {
                let state = if nic.is_up() { "UP" } else { "DOWN" };
                let ips = nic
                    .ip_addresses
                    .iter()
                    .map(|ip| format!("\"{}\"", ip))
                    .collect::<Vec<_>>()
                    .join(",");
                let out = format!(
                    r#"{{"name":"{}","state":"{}","mac":"{}","mtu":{},"speed_mbps":{},"duplex":"{}","driver":"{}","promisc":{},"ips":[{}],"rx_bytes":{},"tx_bytes":{}}}"#,
                    nic.name,
                    state,
                    nic.mac,
                    nic.mtu,
                    nic.speed_mbps.unwrap_or(0),
                    nic.duplex.as_deref().unwrap_or("unknown"),
                    nic.driver.as_deref().unwrap_or("unknown"),
                    nic.is_promisc(),
                    ips,
                    nic.rx_bytes,
                    nic.tx_bytes
                );
                println!("{out}");
                return Ok(());
            }

            println!("Interface : {}", nic.name);
            println!("State     : {}", if nic.is_up() { "UP" } else { "down" });
            println!("MAC       : {}", nic.mac);
            println!("MTU       : {}", nic.mtu);
            println!("Speed     : {}", nic.speed_label());
            println!("Duplex    : {}", nic.duplex.as_deref().unwrap_or("?"));
            println!("Driver    : {}", nic.driver.as_deref().unwrap_or("?"));
            println!("Loopback  : {}", nic.is_loopback());
            println!("Promisc   : {}", nic.is_promisc());
            if nic.ip_addresses.is_empty() {
                println!("Addresses : —");
            } else {
                for (i, addr) in nic.ip_addresses.iter().enumerate() {
                    if i == 0 {
                        println!("Addresses : {addr}");
                    } else {
                        println!("            {addr}");
                    }
                }
            }
            println!();
            println!("  RX ─────────────────────────────");
            println!("  Bytes   : {}", format_bytes(nic.rx_bytes));
            println!("  Packets : {}", nic.rx_packets);
            println!("  Errors  : {}", nic.rx_errors);
            println!("  Dropped : {}", nic.rx_dropped);
            println!();
            println!("  TX ─────────────────────────────");
            println!("  Bytes   : {}", format_bytes(nic.tx_bytes));
            println!("  Packets : {}", nic.tx_packets);
            println!("  Errors  : {}", nic.tx_errors);
            println!("  Dropped : {}", nic.tx_dropped);
        }
    }
    Ok(())
}

// ─── ip-addr-style interface address view ────────────────────────────────────

fn run_addr(args: &[String]) -> Result<(), CliError> {
    let json = args.iter().any(|a| a == "--json" || a == "-j");
    let target = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str());

    // helper: print one NicInfo in the compact multi-line format
    fn print_nic_addr(nic: &NicInfo) {
        let state = if nic.is_up() { "UP" } else { "DOWN" };
        let speed = nic.speed_label();
        println!(
            "{}: state {}  mac {}  mtu {}  speed {}",
            nic.name, state, nic.mac, nic.mtu, speed
        );
        for ip in &nic.ip_addresses {
            println!("    inet  {ip}");
        }
        if let Some(alias) = &nic.ifalias {
            println!("    alias: {alias}");
        }
        if let Some(master) = &nic.master {
            println!("    master: {master}");
        }
        if nic.is_bridge {
            println!("    bridge-master");
        }
        if nic.is_bond {
            println!("    bond-member");
        }
        println!("    carrier changes: {}", nic.carrier_changes);
        if let Some(driver) = &nic.driver {
            println!("    driver: {driver}");
        }
    }

    // helper: serialize one NicInfo as JSON string (all fields)
    fn nic_to_json(nic: &NicInfo) -> String {
        let state = if nic.is_up() { "UP" } else { "DOWN" };
        let ips = nic
            .ip_addresses
            .iter()
            .map(|ip| format!("\"{}\"", ip))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                r#"{{"name":"{name}","state":"{state}","mac":"{mac}","mtu":{mtu},"#,
                r#""speed_label":"{speed}","duplex":"{duplex}","driver":"{driver}","#,
                r#""loopback":{loopback},"promisc":{promisc},"#,
                r#""ip_addresses":[{ips}],"#,
                r#""rx_bytes":{rxb},"rx_packets":{rxp},"rx_errors":{rxe},"rx_dropped":{rxd},"#,
                r#""tx_bytes":{txb},"tx_packets":{txp},"tx_errors":{txe},"tx_dropped":{txd},"#,
                r#""rx_crc_errors":{crc},"rx_missed_errors":{missed},"rx_frame_errors":{frame},"#,
                r#""rx_fifo_errors":{fifo},"tx_carrier_errors":{carrier_err},"collisions":{coll},"#,
                r#""carrier_changes":{cc},"master":"{master}","is_bridge":{bridge},"is_bond":{bond},"#,
                r#""ifalias":"{alias}"}}"#
            ),
            name = nic.name,
            state = state,
            mac = nic.mac,
            mtu = nic.mtu,
            speed = nic.speed_label(),
            duplex = nic.duplex.as_deref().unwrap_or(""),
            driver = nic.driver.as_deref().unwrap_or(""),
            loopback = nic.is_loopback(),
            promisc = nic.is_promisc(),
            ips = ips,
            rxb = nic.rx_bytes,
            rxp = nic.rx_packets,
            rxe = nic.rx_errors,
            rxd = nic.rx_dropped,
            txb = nic.tx_bytes,
            txp = nic.tx_packets,
            txe = nic.tx_errors,
            txd = nic.tx_dropped,
            crc = nic.rx_crc_errors,
            missed = nic.rx_missed_errors,
            frame = nic.rx_frame_errors,
            fifo = nic.rx_fifo_errors,
            carrier_err = nic.tx_carrier_errors,
            coll = nic.collisions,
            cc = nic.carrier_changes,
            master = nic.master.as_deref().unwrap_or(""),
            bridge = nic.is_bridge,
            bond = nic.is_bond,
            alias = nic.ifalias.as_deref().unwrap_or(""),
        )
    }

    match target {
        // pktana addr  — show all interfaces
        None => {
            let nics = list_nics()?;
            if json {
                let items: Vec<String> = nics.iter().map(nic_to_json).collect();
                println!("[{}]", items.join(","));
                return Ok(());
            }
            let sep = "─".repeat(60);
            for (i, nic) in nics.iter().enumerate() {
                if i > 0 {
                    println!("{sep}");
                }
                print_nic_addr(nic);
            }
        }
        // pktana addr <iface>
        Some(name) => {
            let nic = get_nic_info(name)?;
            if json {
                println!("{}", nic_to_json(&nic));
                return Ok(());
            }
            print_nic_addr(&nic);
        }
    }
    Ok(())
}

// ─── deep packet inspection ───────────────────────────────────────────────────

fn run_inspect(args: &[String]) -> Result<(), CliError> {
    // pktana inspect <HEX>
    // pktana inspect -f <FILE>
    let raw: Vec<u8> = if args.first().map(|s| s.as_str()) == Some("-f") {
        let path = args
            .get(1)
            .ok_or_else(|| CliError::Usage("usage: pktana inspect -f <FILE>".into()))?;
        let text = std::fs::read_to_string(path)?;
        let hex: String = text
            .lines()
            .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .unwrap_or("")
            .split_whitespace()
            .collect();
        decode_hex_str(&hex)?
    } else if args.is_empty() {
        return Err(CliError::Usage(
            "usage: pktana inspect <HEX_PACKET>\n       pktana inspect -f <FILE>".into(),
        ));
    } else {
        let hex: String = args.join("");
        decode_hex_str(&hex)?
    };

    let dp = inspect(&raw);
    print_deep_packet(&dp);
    Ok(())
}

fn decode_hex_str(hex: &str) -> Result<Vec<u8>, CliError> {
    let hex: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if !hex.len().is_multiple_of(2) {
        return Err(CliError::Usage("Hex string has odd length".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| CliError::Usage("Invalid hex".into()))
        })
        .collect()
}

fn print_deep_packet(dp: &pktana_core::DeepPacket) {
    let bar = "═".repeat(64);
    let thin = "─".repeat(48);

    // ANSI color codes (work on any xterm-compatible terminal)
    const BOLD: &str = "\x1b[1m";
    const CYAN: &str = "\x1b[1;36m";
    const RED: &str = "\x1b[1;31m";
    const GREEN: &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[1;33m";
    const RESET: &str = "\x1b[0m";

    // ── Packet summary + auto-diagnosis ───────────────────────────────────────
    println!();
    println!("{CYAN}{}{RESET}", "═".repeat(70));
    println!("{BOLD}  PACKET SUMMARY{RESET}  ({} bytes)", dp.frame_len);
    println!("  {}", "─".repeat(66));
    println!("{BOLD}  {}{RESET}", dp.one_liner());
    println!();
    println!("  DIAGNOSIS");
    println!("  {}", "─".repeat(66));
    for finding in dp.diagnose() {
        println!("  ▶  {finding}");
    }
    println!("{CYAN}{}{RESET}", "═".repeat(70));
    println!();

    // ── Layer 2: Ethernet ─────────────────────────────────────────────────────
    println!("{bar}");
    println!("  LAYER 2 — ETHERNET");
    println!("  {thin}");
    let src_vendor = dp
        .eth_vendor_src
        .map(|v| format!("  [{v}]"))
        .unwrap_or_default();
    let dst_vendor = dp
        .eth_vendor_dst
        .map(|v| format!("  [{v}]"))
        .unwrap_or_default();
    println!("  Dst MAC    : {}{}", dp.eth_dst, dst_vendor);
    println!("  Src MAC    : {}{}", dp.eth_src, src_vendor);

    if !dp.vlan_tags.is_empty() {
        let vlan_desc: Vec<String> = dp
            .vlan_tags
            .iter()
            .map(|t| format!("VLAN {} (PCP={} DEI={})", t.id, t.pcp, t.dei as u8))
            .collect();
        println!("  VLAN       : {}", vlan_desc.join("  →  "));
    }

    println!(
        "  EtherType  : 0x{:04x}  ({})",
        dp.ether_type, dp.ether_type_name
    );

    // ── ARP ───────────────────────────────────────────────────────────────────
    if let Some(arp) = &dp.arp {
        println!();
        println!("{bar}");
        println!("  ARP");
        println!("  {thin}");
        println!("  Operation  : {}", arp.operation);
        println!("  Sender MAC : {}", arp.sender_mac);
        println!("  Sender IP  : {}", arp.sender_ip);
        println!("  Target MAC : {}", arp.target_mac);
        println!("  Target IP  : {}", arp.target_ip);
    }

    // ── Layer 3: IPv4 ─────────────────────────────────────────────────────────
    if dp.ip_version.is_some() {
        println!();
        println!("{bar}");
        println!("  LAYER 3 — IPv4");
        println!("  {thin}");
        println!(
            "  Src IP     : {}",
            dp.ip_src
                .map(|a| a.to_string())
                .unwrap_or_else(|| "—".into())
        );
        println!(
            "  Dst IP     : {}",
            dp.ip_dst
                .map(|a| a.to_string())
                .unwrap_or_else(|| "—".into())
        );
        println!(
            "  Protocol   : {}  ({})",
            dp.ip_proto.unwrap_or(0),
            dp.ip_proto_name.unwrap_or("?")
        );
        println!(
            "  TTL        : {}    ID: 0x{:04x}    Len: {}",
            dp.ip_ttl.unwrap_or(0),
            dp.ip_id.unwrap_or(0),
            dp.ip_total_len.unwrap_or(0)
        );
        let flags_str = format!(
            "{}{}",
            if dp.ip_flag_df { "DF " } else { "" },
            if dp.ip_flag_mf { "MF " } else { "" }
        );
        let flags_str = if flags_str.is_empty() {
            "none".to_string()
        } else {
            flags_str.trim().to_string()
        };
        println!(
            "  DSCP: {}  ECN: {}  Flags: {}  Frag offset: {}",
            dp.ip_dscp.unwrap_or(0),
            dp.ip_ecn.unwrap_or(0),
            flags_str,
            dp.ip_fragment.unwrap_or(0)
        );
        println!("  Hdr length : {} bytes", dp.ip_hdr_len.unwrap_or(0));
    }

    // ── Layer 3: IPv6 (when EtherType = 0x86dd) ──────────────────────────────
    if let (Some(src6), Some(dst6)) = (&dp.ipv6_src, &dp.ipv6_dst) {
        println!();
        println!("{bar}");
        println!("  LAYER 3 — IPv6");
        println!("  {thin}");
        println!("  Src IP     : {src6}");
        println!("  Dst IP     : {dst6}");
        if let Some(nh) = dp.ipv6_next_header {
            let nh_name = match nh {
                6 => "TCP",
                17 => "UDP",
                58 => "ICMPv6",
                41 => "IPv6-in-IPv6",
                43 => "Routing",
                44 => "Fragment",
                50 => "ESP",
                51 => "AH",
                59 => "NoNextHdr",
                60 => "Destinations",
                _ => "?",
            };
            println!("  Next Hdr   : {nh}  ({nh_name})");
        }
        if let Some(hl) = dp.ipv6_hop_limit {
            println!("  Hop Limit  : {hl}");
        }
    }

    // ── Layer 4: TCP ──────────────────────────────────────────────────────────
    if dp.tcp_src_port.is_some() {
        println!();
        println!("{bar}");
        let dst_svc = dp
            .tcp_dst_port
            .map(|p| {
                let s = port_service_name(p);
                if s != "?" {
                    format!(" [{s}]")
                } else {
                    String::new()
                }
            })
            .unwrap_or_default();
        let src_svc = dp
            .tcp_src_port
            .map(|p| {
                let s = port_service_name(p);
                if s != "?" {
                    format!(" [{s}]")
                } else {
                    String::new()
                }
            })
            .unwrap_or_default();
        println!("  LAYER 4 — TCP");
        println!("  {thin}");
        println!("  Src port   : {}{}", dp.tcp_src_port.unwrap_or(0), src_svc);
        println!("  Dst port   : {}{}", dp.tcp_dst_port.unwrap_or(0), dst_svc);
        println!(
            "  Seq        : {:10}   Ack: {}",
            dp.tcp_seq.unwrap_or(0),
            dp.tcp_ack.unwrap_or(0)
        );
        println!(
            "  Window     : {}   Urgent: {}   Hdr: {} bytes",
            dp.tcp_window.unwrap_or(0),
            dp.tcp_urgent.unwrap_or(0),
            dp.tcp_hdr_len.unwrap_or(0)
        );
        println!(
            "  Flags      : {}",
            dp.tcp_flags_str.as_deref().unwrap_or("[none]")
        );

        // TCP options
        let mut opts = Vec::new();
        if let Some(mss) = dp.tcp_mss {
            opts.push(format!("MSS={mss}"));
        }
        if let Some(ws) = dp.tcp_window_scale {
            opts.push(format!("WScale={ws}"));
        }
        if dp.tcp_sack_permitted {
            opts.push("SACK_OK".into());
        }
        if let Some((tsv, tse)) = dp.tcp_timestamp {
            opts.push(format!("TS={tsv}/{tse}"));
        }
        if !dp.tcp_sack_blocks.is_empty() {
            for (l, r) in &dp.tcp_sack_blocks {
                opts.push(format!("SACK({l}-{r})"));
            }
        }
        if !opts.is_empty() {
            println!("  Options    : {}", opts.join("  "));
        }

        println!("  Payload    : {} bytes", dp.tcp_payload_len);
    }

    // ── Layer 4: UDP ──────────────────────────────────────────────────────────
    if dp.udp_src_port.is_some() {
        println!();
        println!("{bar}");
        println!("  LAYER 4 — UDP");
        println!("  {thin}");
        let dst_svc = dp
            .udp_dst_port
            .map(|p| {
                let s = port_service_name(p);
                if s != "?" {
                    format!(" [{s}]")
                } else {
                    String::new()
                }
            })
            .unwrap_or_default();
        let src_svc = dp
            .udp_src_port
            .map(|p| {
                let s = port_service_name(p);
                if s != "?" {
                    format!(" [{s}]")
                } else {
                    String::new()
                }
            })
            .unwrap_or_default();
        println!("  Src port   : {}{}", dp.udp_src_port.unwrap_or(0), src_svc);
        println!("  Dst port   : {}{}", dp.udp_dst_port.unwrap_or(0), dst_svc);
        println!(
            "  Length     : {}   Checksum: 0x{:04x}",
            dp.udp_len.unwrap_or(0),
            dp.udp_checksum.unwrap_or(0)
        );
        println!("  Payload    : {} bytes", dp.udp_payload_len);
    }

    // ── Layer 4: ICMP ─────────────────────────────────────────────────────────
    if dp.icmp_type.is_some() {
        println!();
        println!("{bar}");
        println!("  LAYER 4 — ICMP");
        println!("  {thin}");
        println!(
            "  Type/Code  : {}/{}  —  {}",
            dp.icmp_type.unwrap_or(0),
            dp.icmp_code.unwrap_or(0),
            dp.icmp_type_str.as_deref().unwrap_or("?")
        );
        println!("  Checksum   : 0x{:04x}", dp.icmp_checksum.unwrap_or(0));
        if let Some(id) = dp.icmp_id {
            println!("  ID         : {id}");
        }
        if let Some(sq) = dp.icmp_seq {
            println!("  Sequence   : {sq}");
        }
    }

    // ── Application layer ─────────────────────────────────────────────────────
    if let Some(proto) = &dp.app_proto {
        println!();
        println!("{bar}");
        println!("  APPLICATION — {}", proto.to_uppercase());
        println!("  {thin}");
        for line in &dp.app_detail {
            println!("  {line}");
        }
    }

    // ── QUIC / HTTP3 ─────────────────────────────────────────────────────────
    if dp.quic_detected {
        println!();
        println!("{bar}");
        println!("  QUIC / HTTP3");
        println!("  {thin}");
        if let Some(ptype) = dp.quic_packet_type {
            println!("  Packet Type: {ptype}");
        }
        if let Some(ver) = dp.quic_version {
            let ver_name = match ver {
                0x00000001 => "QUIC v1 (RFC 9000)",
                0x6b3343cf => "QUIC v2 (RFC 9369)",
                0x00000000 => "Version Negotiation",
                v if v >> 8 == 0x5130 => "gQUIC",
                v if v & 0x0f0f0f0f == 0x0a0a0a0a => "GREASE",
                _ => "draft / unknown",
            };
            println!("  QUIC Ver   : 0x{ver:08x}  ({ver_name})");
        }
    }

    // ── HTTP/2 & gRPC ─────────────────────────────────────────────────────────
    if dp.http2_detected {
        println!();
        println!("{bar}");
        println!(
            "  HTTP/2{}",
            if dp.quic_detected { " (over QUIC)" } else { "" }
        );
        println!("  {thin}");
        println!("  Detected   : PRI * HTTP/2.0 magic or frame parsing");
        if let Some(path) = &dp.grpc_path {
            println!("  {CYAN}gRPC Path{RESET}  : {path}");
        }
    }

    // ── WebSocket ─────────────────────────────────────────────────────────────
    if dp.ws_upgrade {
        println!();
        println!("{bar}");
        println!("  WEBSOCKET");
        println!("  {thin}");
        println!("  Upgrade    : HTTP → WebSocket (Upgrade header detected)");
    }

    // ── SSH ───────────────────────────────────────────────────────────────────
    if let Some(banner) = &dp.ssh_banner {
        println!();
        println!("{bar}");
        println!("  SSH");
        println!("  {thin}");
        println!("  Banner     : {banner}");
        if banner.starts_with("SSH-1") {
            println!("  {RED}⚠  SSHv1 detected — protocol is obsolete and insecure{RESET}");
        } else {
            println!("  {GREEN}✓  SSHv2 (or later) — modern secure version{RESET}");
        }
    }

    // ── SIP / VoIP ────────────────────────────────────────────────────────────
    if dp.sip_method.is_some() || dp.sip_uri.is_some() {
        println!();
        println!("{bar}");
        println!("  SIP  (Session Initiation Protocol / VoIP)");
        println!("  {thin}");
        if let Some(method) = &dp.sip_method {
            println!("  Method     : {method}");
        }
        if let Some(uri) = &dp.sip_uri {
            println!("  URI        : {uri}");
        }
        if let Some(call_id) = &dp.sip_call_id {
            println!("  Call-ID    : {call_id}");
        }
    }

    // ── NTP ───────────────────────────────────────────────────────────────────
    if dp.ntp_version.is_some() {
        println!();
        println!("{bar}");
        println!("  NTP  (Network Time Protocol)");
        println!("  {thin}");
        if let Some(ver) = dp.ntp_version {
            println!("  Version    : NTPv{ver}");
        }
        if let Some(mode) = dp.ntp_mode {
            let mode_name = match mode {
                1 => "Symmetric Active",
                2 => "Symmetric Passive",
                3 => "Client",
                4 => "Server",
                5 => "Broadcast",
                6 => "Control",
                7 => "Private / monlist",
                _ => "Unknown",
            };
            println!("  Mode       : {mode}  ({mode_name})");
        }
        if let Some(stratum) = dp.ntp_stratum {
            let stratum_desc = match stratum {
                0 => "unspecified / invalid",
                1 => "primary reference (GPS, radio clock)",
                2..=15 => "secondary reference (sync'd to stratum−1)",
                16 => "unsynchronized",
                _ => "reserved",
            };
            println!("  Stratum    : {stratum}  ({stratum_desc})");
        }
        if dp.ntp_amplification_risk {
            println!("  {RED}⚠  Amplification Risk : mode 7 (monlist) response — potential DDoS vector{RESET}");
        } else {
            println!("  {GREEN}✓  No amplification risk detected{RESET}");
        }
    }

    // ── BGP ───────────────────────────────────────────────────────────────────
    if let Some(msg_type) = &dp.bgp_msg_type {
        println!();
        println!("{bar}");
        println!("  BGP  (Border Gateway Protocol)");
        println!("  {thin}");
        println!("  Msg Type   : {msg_type}");
        if let Some(asn) = dp.bgp_asn {
            println!("  AS Number  : AS{asn}");
        }
    }

    // ── Tunnel — Inner Frame ───────────────────────────────────────────────────
    if let Some(ttype) = &dp.tunnel_type {
        println!();
        println!("{bar}");
        println!("  TUNNEL — {}", ttype.to_uppercase());
        println!("  {thin}");
        println!("  Encap Type : {ttype}");
        if let (Some(isrc), Some(idst)) = (dp.inner_ip_src, dp.inner_ip_dst) {
            println!("  Inner Src  : {isrc}");
            println!("  Inner Dst  : {idst}");
        }
        if let Some(proto) = dp.inner_proto {
            println!("  Inner Proto: {proto}");
        }
        if let (Some(isp), Some(idp)) = (dp.inner_src_port, dp.inner_dst_port) {
            println!("  Inner Ports: {isp} → {idp}");
        }
        if let Some(app) = &dp.inner_app_proto {
            println!("  Inner App  : {app}");
        }
    }

    // ── TLS Fingerprint (JA3) ─────────────────────────────────────────────────
    if dp.tls_ja3_raw.is_some() || !dp.tls_alpn.is_empty() || !dp.tls_ciphers.is_empty() {
        println!();
        println!("{bar}");
        println!("  TLS FINGERPRINT");
        println!("  {thin}");
        if let Some(ja3) = &dp.tls_ja3_raw {
            println!("  JA3 raw    : {ja3}");
            println!("  {CYAN}(copy JA3 raw to a threat intel lookup: MD5(raw) = JA3 hash){RESET}");
        }
        if !dp.tls_alpn.is_empty() {
            println!("  ALPN       : {}", dp.tls_alpn.join(", "));
        }
        if !dp.tls_ciphers.is_empty() {
            let cipher_strs: Vec<String> = dp
                .tls_ciphers
                .iter()
                .take(8)
                .map(|c| format!("0x{c:04x}"))
                .collect();
            let more = if dp.tls_ciphers.len() > 8 {
                format!(" … +{} more", dp.tls_ciphers.len() - 8)
            } else {
                String::new()
            };
            println!("  Ciphers    : {}{}", cipher_strs.join(" "), more);
        }
    }

    // ── DNS Analysis ──────────────────────────────────────────────────────────
    if dp.dns_query_name.is_some() || dp.dns_label_entropy.is_some() {
        println!();
        println!("{bar}");
        println!("  DNS ANALYSIS");
        println!("  {thin}");
        if let Some(qname) = &dp.dns_query_name {
            println!("  Query Name : {qname}");
        }
        if let Some(ent) = dp.dns_label_entropy {
            let (risk_label, risk_color) = if ent > 3.8 {
                ("HIGH  — possible DGA / DNS tunneling", RED)
            } else if ent > 3.0 {
                ("MEDIUM — elevated entropy, verify", YELLOW)
            } else {
                ("LOW   — likely benign", GREEN)
            };
            println!("  Entropy    : {ent:.2} bits  →  {risk_color}{risk_label}{RESET}");
        }
    }

    // ── Payload hex dump ──────────────────────────────────────────────────────
    let payload_len = dp.payload.len();
    if payload_len > 0 {
        println!();
        println!("{bar}");
        println!("  PAYLOAD ({payload_len} bytes)");
        println!("  {thin}");
        for line in hex_dump(&dp.payload, 256) {
            println!("{line}");
        }
    }

    // ── App Category & Risk Assessment ───────────────────────────────────────
    println!();
    println!("{bar}");
    println!("  CLASSIFICATION & RISK");
    println!("  {thin}");
    if let Some(cat) = &dp.app_category {
        println!("  Category   : {CYAN}{cat}{RESET}");
    } else {
        println!("  Category   : —");
    }
    {
        let score = dp.risk_score;
        let (risk_label, risk_color) = if score >= 70 {
            ("HIGH", RED)
        } else if score >= 35 {
            ("MEDIUM", YELLOW)
        } else {
            ("LOW", GREEN)
        };
        let filled = (score as usize * 30 / 100).min(30);
        let bar30 = format!(
            "{}{}",
            "\u{2588}".repeat(filled),
            "\u{2591}".repeat(30 - filled)
        );
        println!("  Risk Score : {risk_color}{bar30} {score:>3}/100  [{risk_label}]{RESET}");
        if !dp.risk_reasons.is_empty() {
            println!("  Reasons    :");
            for reason in &dp.risk_reasons {
                println!("    {RED}▶{RESET}  {reason}");
            }
        }
    }

    // ── Anomalies ─────────────────────────────────────────────────────────────
    println!();
    println!("{bar}");
    if dp.anomalies.is_empty() {
        println!("  {GREEN}✓  ANOMALIES  :  none detected{RESET}");
    } else {
        println!("  {RED}⚠  ANOMALIES ({} found):{RESET}", dp.anomalies.len());
        for a in &dp.anomalies {
            println!("  {RED}  [!]{RESET}  {a}");
        }
    }
    println!("{bar}");
    println!();
}

/// Compact port → service name for the inspect display.
fn port_service_name(port: u16) -> &'static str {
    match port {
        20 => "FTP-data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 => "DHCP-srv",
        68 => "DHCP-cli",
        69 => "TFTP",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        161 => "SNMP",
        179 => "BGP",
        389 => "LDAP",
        443 => "HTTPS",
        465 => "SMTPS",
        514 => "Syslog",
        515 => "LPD",
        587 => "SMTP-sub",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1194 => "OpenVPN",
        1433 => "MSSQL",
        1521 => "Oracle",
        1900 => "SSDP",
        2181 => "ZooKeeper",
        2375 => "Docker",
        3306 => "MySQL",
        3389 => "RDP",
        4789 => "VXLAN",
        5432 => "PostgreSQL",
        5672 => "AMQP",
        5900 => "VNC",
        6379 => "Redis",
        6443 => "K8s API",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        9042 => "Cassandra",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => "?",
    }
}

// ─── offline helpers ──────────────────────────────────────────────────────────

fn run_demo() -> Result<(), CliError> {
    let packets = sample_packets()
        .into_iter()
        .map(analyze_hex)
        .collect::<Result<Vec<_>, _>>()?;
    render_batch(&packets, &[]);
    Ok(())
}

fn render_batch(packets: &[ParsedPacket], errors: &[String]) {
    println!("Decoded packets: {}", packets.len());
    for (i, p) in packets.iter().enumerate() {
        println!("{}. {}", i + 1, p.summary.pretty());
    }
    let flows = build_flow_table(packets);
    println!();
    println!("Flow records: {}", flows.len());
    for flow in flows.records() {
        println!(
            "  {}:{} → {}:{}  proto={}  pkts={}  bytes={}",
            flow.key.source_ip,
            flow.key.source_port,
            flow.key.destination_ip,
            flow.key.destination_port,
            flow.key.protocol,
            flow.packets,
            flow.bytes,
        );
    }
    if !errors.is_empty() {
        println!();
        println!("Errors: {}", errors.len());
        for e in errors {
            println!("  {e}");
        }
    }
}

// ─── utilities ────────────────────────────────────────────────────────────────

fn format_timestamp(sec: i64, usec: i64) -> String {
    let h = (sec % 86_400) / 3_600;
    let m = (sec % 3_600) / 60;
    let s = sec % 60;
    format!("{h:02}:{m:02}:{s:02}.{usec:06}")
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}..", &s[..max.saturating_sub(2)])
    }
}

// ─── usage ────────────────────────────────────────────────────────────────────

fn print_usage() {
    const C: &str = "\x1b[1;36m"; // cyan heading
    const Y: &str = "\x1b[1;33m"; // yellow command
    const G: &str = "\x1b[1;32m"; // green
    const DIM: &str = "\x1b[2m"; // dim
    const R: &str = "\x1b[0m"; // reset

    println!(
        "{C}⚡ pktana{R} {DIM}v{v}{R} — Linux packet analyser & network inspector",
        v = env!("CARGO_PKG_VERSION")
    );
    println!("   {DIM}replaces: tcpdump, ethtool, ss, netstat, ip route, ip link, iftop{R}");
    println!();
    println!("  {DIM}Run{R} {Y}pktana help <COMMAND>{R} {DIM}for detailed documentation.{R}");
    println!();

    println!("{C}PACKET CAPTURE{R} {DIM}(requires root or CAP_NET_RAW){R}");
    println!(
        "  {G}pktana{R} {Y}<IFACE>{R}                 Live capture, unlimited (Ctrl+C to stop)"
    );
    println!("  {G}pktana{R} {Y}<IFACE> <N>{R}             Capture exactly N packets then exit");
    println!("  {G}pktana{R} {Y}<IFACE> <BPF>{R}           Unlimited capture with BPF filter");
    println!("  {G}pktana capture{R} {Y}<IFACE> ...{R}      Same as above (explicit subcommand)");
    println!("  {G}pktana record{R} {Y}<IFACE> <OUT>{R}    Live capture + save to .pcap file");
    println!("  {G}pktana interfaces{R}               List all pcap-capable interfaces");
    println!();

    println!("{C}PCAP FILE ANALYSIS{R}");
    println!(
        "  {G}pktana pcap{R} {Y}<FILE.pcap>{R}         Parse & DPI-analyse every packet in file"
    );
    println!(
        "  {G}pktana{R} {Y}<FILE.pcap>{R}              Shorthand — auto-detected by extension"
    );
    println!();

    println!("{C}DEEP PACKET INSPECTION{R} {DIM}(offline){R}");
    println!(
        "  {G}pktana inspect{R} {Y}<HEX>{R}            Full layer-by-layer decode + auto-diagnosis"
    );
    println!("  {G}pktana inspect{R} {Y}-f <FILE>{R}        Inspect first hex packet from file");
    println!("  {G}pktana hex{R} {Y}<HEX>{R}                Quick field table summary");
    println!(
        "  {G}pktana file{R} {Y}<FILE>{R}              Batch decode hex packets (one per line)"
    );
    println!("  {G}pktana demo{R}                     Decode built-in sample packets");
    println!();

    println!("{C}INTERFACE & NIC INFO{R} {DIM}(sysfs/procfs){R}");
    println!("  {G}pktana nic{R} {Y}[--json] [IFACE]{R}     List all NICs or detail for one");
    println!("  {G}pktana ethtool{R} {Y}<IFACE>{R}          Driver, link, offloads, queues, IRQ affinity");
    println!("  {G}pktana dp{R} {Y}<IFACE> [--baseline save|check]{R}  Dataplane + optional baseline drift check");
    println!("  {G}pktana ebpf{R} {Y}[IFACE|pinned|ns|dispatchers]{R}  eBPF program inventory & verification");
    println!("  {G}pktana bpf{R}                      List pinned objects in /sys/fs/bpf/");
    println!("  {G}pktana ns{R}                       Network namespaces with XDP/AF_XDP");
    println!(
        "  {G}pktana hw{R} {Y}<IFACE>{R}               Bridge/bond/PTP/IOMMU hardware profile"
    );
    println!("  {G}pktana route{R} {Y}[--json] [IFACE]{R}   Full routing table (IPv4 + IPv6)");
    println!();

    println!("{C}LIVE NETWORK MONITORING{R}");
    println!("  {G}pktana conn{R} {Y}[--json]{R}             TCP/UDP connections + PID + GeoIP");
    println!("  {G}pktana stats{R} {Y}<IFACE>{R}            Live dashboard: PPS, BPS, top talkers");
    println!(
        "  {G}pktana watch{R} {Y}<IFACE> [SECS]{R}     Auto-refresh NIC counters (default: 2s)"
    );
    println!("  {G}pktana tui{R} {Y}<IFACE | PCAP>{R}       Terminal UI dashboard — realtime packets & flows");
    println!("  {G}pktana web{R} {Y}[PORT] [-f]{R}         Web UI dashboard (starts in background, -f for foreground)");
    println!("  {G}pktana mcp{R} {Y}[--port N] [--stdio]{R}  MCP server for AI agent integration");
    println!();

    println!("{C}AI INTEGRATION{R} {DIM}(requires build --features mcp){R}");
    println!("  {G}pktana mcp{R}                       Start MCP server on port 3456 (SSE/HTTP)");
    println!("  {G}pktana mcp{R} {Y}--port 4000{R}           Custom port");
    println!("  {G}pktana mcp{R} {Y}--stdio{R}               Stdio mode for local Claude Desktop");
    println!();

    println!("{C}GEOLOCATION{R}");
    println!(
        "  {G}pktana geoip{R} {Y}<IP> ...{R}           IP-to-country lookup (offline, no API)"
    );
    println!();

    println!("{C}QUICK EXAMPLES{R}");
    println!("  {DIM}${R} pktana eth0                               {DIM}# capture everything on eth0{R}");
    println!("  {DIM}${R} pktana eth0 -a                            {DIM}# capture with flow analysis (TCP/TLS/DHCP){R}");
    println!("  {DIM}${R} pktana eth0 100 'tcp port 443'            {DIM}# 100 HTTPS packets{R}");
    println!(
        "  {DIM}${R} pktana eth0 0 'tcp port 443' -a           {DIM}# HTTPS with flow analysis{R}"
    );
    println!(
        "  {DIM}${R} pktana record eth0 capture.pcap           {DIM}# save live traffic to file{R}"
    );
    println!(
        "  {DIM}${R} pktana tui capture.pcap                   {DIM}# browse pcap file in TUI{R}"
    );
    println!("  {DIM}${R} pktana ethtool eth0                       {DIM}# driver + offloads + queues{R}");
    println!(
        "  {DIM}${R} pktana dp eth0                            {DIM}# XDP/DPDK/SR-IOV detection{R}"
    );
}

// ─── Per-command documentation ────────────────────────────────────────────────

fn print_doc(cmd: &str) -> Result<(), CliError> {
    const B: &str = "\x1b[1m";
    const C: &str = "\x1b[1;36m";
    const Y: &str = "\x1b[1;33m";
    const DIM: &str = "\x1b[2m";
    const R: &str = "\x1b[0m";

    let bar = format!("{C}{}{R}", "═".repeat(68));

    match cmd {
        // ── capture ──────────────────────────────────────────────────────────
        "capture" | "cap" | "iface" | "interfaces" | "ifaces" => {
            println!("{bar}");
            println!("{B}  pktana capture{R}  —  Live packet capture");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana <IFACE>{R}");
            println!("  {Y}pktana <IFACE> <COUNT>{R}");
            println!("  {Y}pktana <IFACE> <BPF_FILTER>{R}");
            println!("  {Y}pktana <IFACE> <COUNT> <BPF_FILTER>{R}");
            println!("  {Y}pktana <IFACE> [COUNT] [BPF_FILTER] --flow-analyze{R}");
            println!("  {Y}pktana <IFACE> [COUNT] [BPF_FILTER] -a{R}  (flow analysis short form)");
            println!("  {Y}pktana capture <IFACE> ...{R}   (explicit form of the above)");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Captures raw packets from a network interface using libpcap.");
            println!("  Runs in promiscuous mode by default — sees all frames on the wire,");
            println!("  not just those addressed to this host.");
            println!();
            println!("  Output contains one line per packet:");
            println!("  {DIM}  No.  |  Time           |  Bytes  |  Proto  |  Source  |  Dest  |  Info{R}");
            println!();
            println!(
                "  With {Y}--flow-analyze{R} or {Y}-a{R} flag, enables advanced flow analysis:"
            );
            println!("  • TCP Handshakes  — SYN → SYN-ACK → ACK tracking with RTT");
            println!("  • TLS Handshakes  — ClientHello → ServerHello → Finished");
            println!("  • DHCP DORA       — Discover → Offer → Request → Ack");
            println!("  • DNS Queries     — Query/Response matching");
            println!();
            println!("{B}ARGUMENTS{R}");
            println!("  {Y}IFACE{R}        Network interface name (eth0, ens3, bond0, etc.)");
            println!(
                "  {Y}COUNT{R}        Number of packets to capture then exit. Omit for unlimited."
            );
            println!(
                "  {Y}BPF_FILTER{R}   Berkeley Packet Filter expression (same syntax as tcpdump)."
            );
            println!("               Quotes required for multi-word filters.");
            println!("  {Y}-a, --flow-analyze{R}  Enable advanced flow analysis mode.");
            println!();
            println!("{B}BPF FILTER EXAMPLES{R}");
            println!("  tcp                          — TCP packets only");
            println!("  udp port 53                  — DNS traffic");
            println!("  host 10.0.0.1                — traffic to or from 10.0.0.1");
            println!("  src host 192.168.1.1          — packets from specific source");
            println!("  tcp port 443                 — HTTPS packets");
            println!("  not arp                      — exclude ARP");
            println!("  tcp and port 80              — HTTP packets");
            println!("  icmp                         — ping / traceroute packets");
            println!("  vlan 100 and tcp             — VLAN 100 TCP traffic");
            println!("  'host 10.1.1.1 and tcp port 8080'");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana eth0                              # all traffic, unlimited");
            println!("  pktana eth0 50                           # first 50 packets");
            println!("  pktana eth0 tcp                          # TCP only");
            println!("  pktana eth0 tcp -a                       # TCP with flow analysis");
            println!("  pktana eth0 100 udp                      # 100 UDP packets");
            println!("  pktana eth0 \"tcp port 443\"             # HTTPS, unlimited");
            println!(
                "  pktana eth0 \"tcp port 443\" -a          # HTTPS with TLS handshake tracking"
            );
            println!("  pktana eth0 200 'host 8.8.8.8'          # 200 pkts to/from 8.8.8.8");
            println!("  pktana eth0 'udp port 67' --flow-analyze  # DHCP DORA analysis");
            println!("  pktana interfaces                        # list available interfaces");
            println!();
            println!("{B}REQUIRES{R}");
            println!("  root or CAP_NET_RAW capability.");
            println!("  libpcap installed (libpcap.so.1 in ld path).");
            println!("{bar}");
        }

        // ── inspect ──────────────────────────────────────────────────────────
        "inspect" => {
            println!("{bar}");
            println!("{B}  pktana inspect{R}  —  Deep packet inspection");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana inspect <HEX_STRING>{R}");
            println!("  {Y}pktana inspect -f <FILE>{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Performs full layer-by-layer decode of a single raw packet provided");
            println!("  as a hexadecimal string.  No live capture is needed — works entirely");
            println!("  offline and requires no special permissions.");
            println!();
            println!("  Output sections (in order):");
            println!("  1. {B}PACKET SUMMARY{R}  — one-line description + auto-diagnosis");
            println!("  2. {B}LAYER 2 — ETHERNET{R}  — MAC addresses, VLAN tags, EtherType");
            println!("  3. {B}ARP{R}  — sender/target MAC+IP, operation (request/reply)");
            println!(
                "  4. {B}LAYER 3 — IPv4{R}  — IPs, TTL, DSCP, ECN, DF/MF flags, fragment offset"
            );
            println!(
                "  5. {B}LAYER 4 — TCP/UDP/ICMP{R}  — ports, flags, window, options, checksum"
            );
            println!(
                "  6. {B}APPLICATION{R}  — HTTP method/status, TLS version + SNI, DNS query/rcode,"
            );
            println!("                    DHCP message type, and 15+ other protocols");
            println!(
                "  7. {B}PAYLOAD HEX DUMP{R}  — Wireshark-style hex + ASCII (up to 256 bytes)"
            );
            println!("  8. {B}ANOMALIES{R}  — malformed headers, scan patterns, flag conflicts");
            println!();
            println!("{B}DIAGNOSIS ENGINE{R}");
            println!("  pktana analyses the decoded packet and emits human-readable findings:");
            println!("  • TCP handshake state (SYN / SYN-ACK / FIN / RST meaning)");
            println!("  • Zero window detection (receiver buffer full → flow control stall)");
            println!("  • OS fingerprint from TTL (64=Linux, 128=Windows, 255=Cisco)");
            println!("  • MSS / PPPoE / tunnel overhead detection");
            println!("  • DSCP / QoS class interpretation");
            println!("  • DNS NXDOMAIN / SERVFAIL / REFUSED explanation");
            println!("  • TLS version (warns on 1.0/1.1 deprecated per RFC 8996)");
            println!("  • HTTP status code class");
            println!("  • DHCP state machine step");
            println!("  • Gratuitous ARP / failover detection");
            println!("  • ICMP type interpretation + traceroute detection");
            println!();
            println!("{B}OPTIONS{R}");
            println!("  {Y}<HEX_STRING>{R}  Raw packet bytes as hex, spaces allowed.");
            println!("               Can be taken directly from Wireshark 'Copy as Hex'.");
            println!("  {Y}-f <FILE>{R}    Read first non-empty, non-comment line from FILE.");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  # Decode a TCP SYN packet");
            println!("  pktana inspect ffffffffffff525400123456080045000034...");
            println!();
            println!("  # Inspect a packet saved from Wireshark");
            println!("  pktana inspect -f /tmp/packet.hex");
            println!();
            println!("  # Spaces in hex are fine");
            println!("  pktana inspect \"ff ff ff ff ff ff 52 54 00 12 34 56 08 00 ...\"");
            println!("{bar}");
        }

        // ── nic ───────────────────────────────────────────────────────────────
        "nic" => {
            println!("{bar}");
            println!("{B}  pktana nic{R}  —  Network interface card information");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana nic{R}");
            println!("  {Y}pktana nic <IFACE>{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Reads interface state and statistics from the kernel sysfs and procfs");
            println!("  filesystems.  No external tools (ip, ifconfig, ethtool) are used.");
            println!();
            println!("  Without an interface argument, lists all interfaces in a table.");
            println!("  With an interface name, shows full detail for that interface.");
            println!();
            println!("{B}FIELDS (list mode){R}");
            println!("  Interface  — kernel interface name");
            println!("  State      — UP / down (operstate from /sys/class/net/.../operstate)");
            println!("  MAC        — hardware address");
            println!("  MTU        — maximum transmission unit in bytes");
            println!("  Speed      — link speed (e.g. 1G, 10G) from /sys/class/net/.../speed");
            println!("  IP Addrs   — all IPv4 and IPv6 addresses assigned");
            println!();
            println!("{B}FIELDS (detail mode){R}");
            println!("  All list-mode fields, plus:");
            println!("  Duplex     — full / half");
            println!("  Driver     — kernel module managing this NIC");
            println!("  Loopback   — is this the lo interface?");
            println!("  Promisc    — is promiscuous mode enabled?");
            println!("  RX/TX      — bytes · packets · errors · dropped since last reboot");
            println!();
            println!("{B}REPLACES{R}");
            println!("  ip link show · ip addr show · ifconfig · cat /proc/net/dev");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana nic            # list all interfaces");
            println!("  pktana nic eth0       # detail for eth0");
            println!("  pktana nic lo         # loopback interface detail");
            println!("{bar}");
        }

        // ── addr ──────────────────────────────────────────────────────────────
        "addr" | "address" => {
            println!("{bar}");
            println!("{B}  pktana addr{R}  —  Interface address view (like ip addr show)");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana addr{R}");
            println!("  {Y}pktana addr <IFACE>{R}");
            println!("  {Y}pktana addr [--json | -j]{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Shows interfaces and their assigned IP addresses in a compact multi-line");
            println!("  format similar to `ip addr show`.  No external tools are used.");
            println!();
            println!("  Without an argument, lists all interfaces.");
            println!("  With an interface name, shows that interface only.");
            println!();
            println!("{B}FIELDS{R}");
            println!("  state         — UP / DOWN");
            println!("  mac           — hardware address");
            println!("  mtu           — maximum transmission unit in bytes");
            println!("  speed         — link speed (e.g. 1G, 10G)");
            println!("  inet          — each assigned IPv4 / IPv6 address with prefix");
            println!("  alias         — ifalias label (if set)");
            println!("  master        — bridge or bond master interface (if member)");
            println!("  bridge-master — indicates this interface is a bridge");
            println!("  bond-member   — indicates this interface is a bond");
            println!("  carrier chg   — total link-up/down transitions since boot");
            println!("  driver        — kernel module managing the NIC");
            println!();
            println!("{B}FLAGS{R}");
            println!("  --json / -j   — emit full NicInfo as JSON (all counters + metadata)");
            println!();
            println!("{B}REPLACES{R}");
            println!("  ip addr show · ip addr show <iface>");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana addr             # all interfaces");
            println!("  pktana addr eth0        # single interface");
            println!("  pktana addr eth0 --json # full JSON output");
            println!("{bar}");
        }

        // ── ethtool ──────────────────────────────────────────────────────────
        "ethtool" | "et" => {
            println!("{bar}");
            println!("{B}  pktana ethtool{R}  —  Advanced NIC driver & hardware inspection");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana ethtool <IFACE>{R}");
            println!("  {Y}pktana et <IFACE>{R}      (alias)");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Shows deep driver and hardware information for one interface by reading");
            println!("  /sys/class/net/<iface>/ and /proc/interrupts.  No ethtool binary needed.");
            println!();
            println!("{B}OUTPUT SECTIONS{R}");
            println!("  {B}DRIVER INFO{R}    — driver name, PCI bus address, firmware version, IRQ number");
            println!(
                "  {B}LINK SETTINGS{R}   — speed, duplex, autoneg, operstate, TX queue length"
            );
            println!("  {B}PCIe LINK{R}       — PCIe generation and lane width (e.g. Gen3 x8)");
            println!("  {B}CARRIER EVENTS{R}  — link-up/down event counts since boot");
            println!("  {B}CHANNELS/QUEUES{R} — number of RX, TX, and combined queues");
            println!("  {B}FEATURES{R}        — hardware offload features ON/OFF (TSO, LRO, GRO, checksum…)");
            println!("  {B}IRQ AFFINITY{R}    — per-queue interrupt → CPU binding (smp_affinity)");
            println!("  {B}EXTENDED STATS{R}  — per-queue and per-direction byte/packet counters");
            println!();
            println!("{B}REPLACES{R}");
            println!("  ethtool -i · ethtool -k · ethtool -l · ethtool -S · /proc/interrupts");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana ethtool eth0      # full report for eth0");
            println!("  pktana et ens3           # same, short alias");
            println!("{bar}");
        }

        // ── dp / dataplane ───────────────────────────────────────────────────
        "dp" | "dataplane" => {
            println!("{bar}");
            println!("{B}  pktana dp{R}  —  Dataplane / packet I/O path detection");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana dp <IFACE>{R}");
            println!("  {Y}pktana dataplane <IFACE>{R}   (alias)");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Probes sysfs, /proc/net, and the vfio-pci binding path to determine");
            println!("  how packets are being processed for a given interface — whether they");
            println!("  flow through the normal Linux kernel network stack or bypass it.");
            println!();
            println!("{B}DETECTED MODES{R}");
            println!(
                "  {B}KernelStack{R}     — normal path; packets processed by kernel tcp/ip stack"
            );
            println!("  {B}XDP{R}             — eBPF XDP program attached at driver level; can drop/redirect");
            println!("                    before sk_buff allocation (faster than iptables)");
            println!("  {B}AF_XDP{R}          — zero-copy path; packets DMA'd directly to userspace rings,");
            println!("                    bypassing kernel socket layer entirely");
            println!(
                "  {B}DpdkUserspace{R}   — NIC bound to vfio-pci or uio_pci_generic; kernel sees"
            );
            println!("                    no traffic at all; pktana capture will not work");
            println!("  {B}Hybrid{R}          — XDP + AF_XDP active simultaneously");
            println!();
            println!("{B}OUTPUT SECTIONS{R}");
            println!("  Bypass Mode  — detected packet I/O path");
            println!("  XDP          — attached eBPF program IDs and mode (sysfs + ip link)");
            println!("  XDP dispatchers — libxdp multi-prog pins in /sys/fs/bpf/xdp/");
            println!("  AF_XDP       — count of zero-copy sockets (from /proc/net/xdp)");
            println!("  DPDK/PMD     — vfio/uio binding status and driver name");
            println!("  SR-IOV       — VF/PF role, VF count enabled/total");
            println!("  Queues       — RX / TX / combined queue counts");
            println!("  PCI          — address, vendor ID, device ID, NUMA node, link speed");
            println!("  HW Offloads  — features currently enabled");
            println!("  TC BPF       — clsact qdisc and TC-attached BPF program IDs");
            println!("  Guidance     — plain-English interpretation + recommendations");
            println!();
            println!("{B}RELATED{R}");
            println!("  pktana ebpf <IFACE>   — focused eBPF verification for one interface");
            println!("  pktana bpf            — pinned objects in /sys/fs/bpf/");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana dp eth0      # check if eth0 is in DPDK/XDP bypass mode");
            println!("  pktana dp ens3f0    # check SR-IOV PF with VFs");
            println!("{bar}");
        }

        "ebpf" => {
            println!("{bar}");
            println!("{B}  pktana ebpf{R}  —  eBPF program inventory and verification");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana ebpf{R}                      Host-wide eBPF summary");
            println!("  {Y}pktana ebpf <IFACE>{R}               Full eBPF check for one interface");
            println!("  {Y}pktana ebpf pinned{R}                Pinned objects in /sys/fs/bpf/");
            println!("  {Y}pktana ebpf dispatchers{R}           libxdp XDP multi-prog dispatchers");
            println!("  {Y}pktana ebpf ns{R}                    Network namespaces (XDP/AF_XDP)");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Detects XDP, TC BPF, AF_XDP, and pinned BPF objects.");
            println!("  Uses sysfs, /proc, ip link, tc, and bpftool (when available).");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana ebpf              # overview of all eBPF activity on host");
            println!("  pktana ebpf eth0         # verify XDP/TC programs on eth0");
            println!("  pktana ebpf pinned       # list Cilium/libxdp/tc pins");
            println!("{bar}");
        }

        "bpf" => {
            println!("{bar}");
            println!("{B}  pktana bpf{R}  —  BPF filesystem pinned object inventory");
            println!("{bar}");
            println!();
            println!("  Scans /sys/fs/bpf/ recursively. Categories: cilium, libxdp, tc, falco, …");
            println!("  Alias: pktana ebpf pinned");
            println!("{bar}");
        }

        "ns" | "netns" => {
            println!("{bar}");
            println!("{B}  pktana ns{R}  —  Network namespace enumeration");
            println!("{bar}");
            println!();
            println!(
                "  Groups /proc/*/ns/net by inode. Host namespace shows XDP prog IDs via sysfs."
            );
            println!("  Non-host namespaces show AF_XDP socket counts per interface.");
            println!("  Alias: pktana ebpf ns · pktana netns");
            println!("{bar}");
        }

        "hw" | "hardware" => {
            println!("{bar}");
            println!("{B}  pktana hw{R}  —  Extended hardware profile");
            println!("{bar}");
            println!();
            println!("  Bridge/bond/PTP/IOMMU, error counters, XDP dispatchers for one interface.");
            println!("  Usage: pktana hw <IFACE>");
            println!("{bar}");
        }

        // ── route ─────────────────────────────────────────────────────────────
        "route" | "routes" | "nexthop" => {
            println!("{bar}");
            println!("{B}  pktana route{R}  —  Routing table viewer");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana route [--json]{R}");
            println!("  {Y}pktana route [--json] <IFACE>{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Reads the kernel routing table directly from /proc/net/route (IPv4)");
            println!("  and /proc/net/ipv6_route (IPv6).  No 'ip' or 'route' binary needed.");
            println!();
            println!("{B}COLUMNS{R}");
            println!("  Interface   — egress interface for this route");
            println!("  Destination — network prefix (CIDR notation)");
            println!("  Prefix      — subnet mask length");
            println!("  Gateway     — nexthop IP or 'direct (connected)' for on-link routes");
            println!("  Metric      — route preference (lower wins)");
            println!("  Type        — default / connected / static/dynamic");
            println!();
            println!("{B}REPLACES{R}");
            println!("  ip route show · netstat -r · route -n");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana route          # full IPv4 + IPv6 routing table");
            println!("  pktana route eth0     # routes using eth0 as egress");
            println!("  pktana nexthop        # alias for 'route'");
            println!("{bar}");
        }

        // ── conn ──────────────────────────────────────────────────────────────
        "conn" | "connections" => {
            println!("{bar}");
            println!("{B}  pktana conn{R}  —  Active TCP / UDP connection table");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana conn [--json]{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Lists all active TCP and UDP sockets by reading:");
            println!("    /proc/net/tcp   /proc/net/tcp6   (TCP IPv4 / IPv6)");
            println!("    /proc/net/udp   /proc/net/udp6   (UDP IPv4 / IPv6)");
            println!("  PID resolution is done by scanning /proc/<pid>/fd symlinks.");
            println!("  Run as root to see connections from all processes.");
            println!();
            println!("{B}COLUMNS{R}");
            println!("  Proto    — TCP / UDP and IP version");
            println!("  Local    — local IP:port");
            println!("  Remote   — remote IP:port (— for UDP listeners)");
            println!("  State    — ESTABLISHED · LISTEN · TIME_WAIT · CLOSE_WAIT · etc.");
            println!("  PID      — process ID owning the socket");
            println!("  Process  — process name (from /proc/<pid>/cmdline)");
            println!();
            println!("{B}REPLACES{R}");
            println!("  ss -tulnp · netstat -tulnp · lsof -i");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana conn                 # show all connections");
            println!("  pktana conn | grep LISTEN   # listening sockets only");
            println!("  pktana conn | grep :443     # sockets on port 443");
            println!("{bar}");
        }

        // ── stats ─────────────────────────────────────────────────────────────
        "stats" => {
            println!("{bar}");
            println!("{B}  pktana stats{R}  —  Live traffic dashboard");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana stats <IFACE>{R}");
            println!("  {Y}pktana stats <IFACE> <BPF_FILTER>{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Captures packets in the background and renders a live dashboard that");
            println!("  refreshes every second.  Shows aggregate throughput, per-protocol");
            println!("  breakdown, and top-10 talkers by packet count.");
            println!();
            println!("{B}DASHBOARD PANELS{R}");
            println!("  Rate (last Ns)  — current PPS (packets/sec) and BPS (bytes/sec)");
            println!("  Total           — cumulative packets and bytes since start");
            println!("  Protocol Breakdown — bar chart of TCP / UDP / ICMP / ARP share");
            println!("  Top Talkers     — top-10 source IPs by packet count + bytes");
            println!();
            println!("{B}REQUIRES{R}");
            println!("  root or CAP_NET_RAW.  Press Ctrl+C to exit.");
            println!();
            println!("{B}REPLACES{R}");
            println!("  iftop · nethogs · bmon · nload");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana stats eth0              # all traffic dashboard");
            println!("  pktana stats eth0 tcp          # TCP-only dashboard");
            println!("  pktana stats eth0 'port 443'   # HTTPS traffic only");
            println!("{bar}");
        }

        // ── watch ─────────────────────────────────────────────────────────────
        "watch" => {
            println!("{bar}");
            println!("{B}  pktana watch{R}  —  Auto-refreshing NIC counter view");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana watch <IFACE>{R}");
            println!("  {Y}pktana watch <IFACE> <SECS>{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Reads /sys/class/net/<iface>/statistics/ and refreshes the display");
            println!("  every SECS seconds (default: 2).  Does not open a capture socket —");
            println!("  works without root if sysfs is readable.");
            println!();
            println!("{B}DISPLAYED FIELDS{R}");
            println!("  State · Speed · MTU · Duplex · IP addresses");
            println!("  RX: bytes · packets · errors · dropped");
            println!("  TX: bytes · packets · errors · dropped");
            println!();
            println!("{B}REPLACES{R}");
            println!("  watch -n2 ip -s link show <iface> · watch -n2 ethtool -S <iface>");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana watch eth0        # refresh every 2 seconds (default)");
            println!("  pktana watch eth0 1      # refresh every 1 second");
            println!("  pktana watch eth0 5      # refresh every 5 seconds");
            println!("{bar}");
        }

        // ── hex / file / demo ─────────────────────────────────────────────────
        "hex" => {
            println!("{bar}");
            println!("{B}  pktana hex{R}  —  Quick hex packet decoder");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana hex <HEX_STRING>{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Decodes a raw packet from a hex string and prints a single summary");
            println!("  line plus per-layer field table.  Faster and more compact than");
            println!("  'pktana inspect' — use inspect when you want the full breakdown,");
            println!("  payload dump, and auto-diagnosis.");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana hex 0800450000280001400040060000c0a80001...");
            println!("{bar}");
        }
        "file" => {
            println!("{bar}");
            println!("{B}  pktana file{R}  —  Batch hex packet decoder");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana file <FILE>{R}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Reads a text file where each line is one hex-encoded raw packet.");
            println!("  Blank lines are skipped.  Parses all packets and prints a summary");
            println!("  table plus flow statistics.");
            println!();
            println!("{B}FILE FORMAT{R}");
            println!("  One hex packet per line. Spaces within a line are ignored.");
            println!("  Lines starting with # are treated as comments.");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana file /tmp/packets.hex");
            println!("  pktana file capture.txt");
            println!("{bar}");
        }
        "demo" => {
            println!("{bar}");
            println!("{B}  pktana demo{R}  —  Built-in sample packet decoder");
            println!("{bar}");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Decodes two built-in sample packets (one TCP, one UDP/DNS) to show");
            println!("  the output format without needing an interface or hex string.");
            println!("  Useful for testing that pktana is installed and working correctly.");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana demo");
            println!("{bar}");
        }

        // ── tui ───────────────────────────────────────────────────────────────
        "tui" => {
            println!("{bar}");
            println!("{B}  pktana tui{R}  —  Terminal UI dashboard (live or pcap)");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana tui <IFACE>{R}           live capture TUI");
            println!("  {Y}pktana tui <FILE.pcap>{R}       open saved pcap file in TUI (offline)");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Opens a full-screen terminal UI dashboard.  In live mode it captures");
            println!("  from the given interface.  In pcap mode it pre-loads all packets from");
            println!("  the file and displays them statically — no capture needed, no root.");
            println!();
            println!("{B}DASHBOARD LAYOUT{R}");
            println!("  Header          — interface / PCAP filename, elapsed time, total packets");
            println!("  Bandwidth       — RX/TX throughput gauges (MB/s)  [live mode only]");
            println!("  Protocol Chart  — TCP, UDP, ICMP, ARP breakdown with percentages");
            println!("  Top Talkers     — top 10 source IPs by packet count with GeoIP country");
            println!("  Recent Packets  — table of last packets (time, size, proto, IPs)");
            println!("  Connections     — active TCP/UDP sockets with state");
            println!();
            println!("{B}CONTROLS{R}");
            println!("  q, Q, Esc       — quit");
            println!("  1–5             — switch tabs (Packets / Bandwidth / Flows / Packets / Connections)");
            println!("  j / k           — scroll packet list down / up");
            println!("  Enter           — open packet detail (layers + hex dump)");
            println!("  s / S           — sort packet list by size");
            println!();
            println!("{B}REQUIRES (live mode){R}");
            println!("  • root or CAP_NET_RAW capability");
            println!("  • pktana built with --features tui");
            println!("  • libpcap.so.1 in library path");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana tui eth0              # live dashboard on eth0");
            println!("  pktana tui ens3              # live dashboard on ens3");
            println!("  pktana tui capture.pcap      # browse a saved pcap file");
            println!();
            println!("{B}FEATURES{R}");
            println!("  • GeoIP lookup — automatically resolves top-talker IPs to countries");
            println!("  • Live update — refreshes every 100 ms");
            println!("  • Pcap mode — browse any .pcap / .pcapng / .cap file offline");
            println!("  • Protocol breakdown — see which protocols dominate traffic");
            println!("  • Connection tracking — monitor active sockets in real-time");
            println!("{bar}");
        }

        // ── web ───────────────────────────────────────────────────────────────
        "web" => {
            println!("{bar}");
            println!("{B}  pktana web{R}  —  Web UI dashboard");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana web{R}                   start on default port 8080");
            println!("  {Y}pktana web <PORT>{R}            start on custom port");
            println!("  {Y}pktana web <PORT> -f{R}         start in foreground");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Starts a local HTTP server providing a rich Web UI. Includes live");
            println!("  packet inspection, active connections, routing tables, and NIC details.");
            println!();
            println!("{B}REQUIRES{R}");
            println!("  • root or CAP_NET_RAW capability for live packet inspection");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana web                   # listen on http://0.0.0.0:8080");
            println!("{bar}");
        }

        // ── mcp ───────────────────────────────────────────────────────────────
        "mcp" => {
            println!("{bar}");
            println!("{B}  pktana mcp{R}  —  MCP server for AI agent integration");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana mcp{R}                           start on default port 3456");
            println!("  {Y}pktana mcp --port <PORT>{R}             custom port");
            println!("  {Y}pktana mcp --host <HOST> --port <N>{R}  custom bind address");
            println!(
                "  {Y}pktana mcp --stdio{R}                   stdio mode (local Claude Desktop)"
            );
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Starts an MCP (Model Context Protocol) server that exposes pktana's");
            println!("  network analysis capabilities as AI tools.  Connect Claude Desktop or");
            println!("  any MCP-compatible AI agent to inspect packets, capture traffic,");
            println!(
                "  analyse connections, routes, NIC statistics, and more via natural language."
            );
            println!();
            println!("{B}REMOTE CONNECTION (from Claude Desktop){R}");
            println!("  On the server:   pktana mcp --port 3456");
            println!("  On your laptop — edit claude_desktop_config.json:");
            println!("    Linux:   ~/.config/claude/claude_desktop_config.json");
            println!(
                "    macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json"
            );
            println!("    Windows: %APPDATA%\\Claude\\claude_desktop_config.json");
            println!();
            println!("  Add:");
            println!("    {{");
            println!("      \"mcpServers\": {{");
            println!("        \"pktana\": {{");
            println!("          \"url\": \"http://SERVER_IP:3456/mcp\"");
            println!("        }}");
            println!("      }}");
            println!("    }}");
            println!();
            println!("  Restart Claude Desktop — pktana tools appear in the tool list.");
            println!();
            println!("{B}LOCAL CONNECTION (Claude CLI){R}");
            println!("  claude mcp add pktana -- pktana mcp --stdio");
            println!("  claude mcp list");
            println!();
            println!("{B}AVAILABLE TOOLS{R}");
            println!("  inspect_packet      Deep packet inspection from hex bytes");
            println!("  capture_live        Live capture on an interface (needs root)");
            println!("  analyze_pcap_file   Analyse a .pcap file on disk");
            println!("  list_connections    Active TCP/UDP connections");
            println!("  list_routes         Kernel routing table");
            println!("  list_interfaces     Network interfaces with state/stats");
            println!("  get_nic_stats       Detailed NIC driver/queue/offload stats");
            println!("  geoip_lookup        IP-to-country lookup (offline)");
            println!("  get_server_info     Hostname, uptime, memory");
            println!("  run_flow_analysis   TCP/TLS/DHCP/DNS flow analysis (needs root)");
            println!();
            println!("{B}OPTIONS{R}");
            println!("  {Y}--port, -p <PORT>{R}   Bind port (default: 3456)");
            println!("  {Y}--host, -H <HOST>{R}   Bind address (default: 0.0.0.0)");
            println!("  {Y}--stdio{R}             Use stdio transport (local Claude Desktop)");
            println!();
            println!("{B}REQUIRES{R}");
            println!("  Built with:  cargo build --release --features mcp -p pktana-cli");
            println!("  Live capture tools need root or CAP_NET_RAW.");
            println!("{bar}");
        }

        // ── record ────────────────────────────────────────────────────────────
        "record" | "rec" => {
            println!("{bar}");
            println!("{B}  pktana record{R}  —  Record live traffic to a pcap file");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana record <IFACE> <OUT.pcap>{R}");
            println!("  {Y}pktana record <IFACE> <OUT.pcap> <COUNT>{R}");
            println!("  {Y}pktana record <IFACE> <OUT.pcap> <COUNT> <BPF_FILTER>{R}");
            println!("  {Y}pktana record <IFACE> <OUT.pcap> <BPF_FILTER>{R}");
            println!("  {Y}pktana rec ...{R}   (short alias)");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Captures live traffic from IFACE and writes every packet to OUT.pcap");
            println!("  in standard pcap format.  Packets are also displayed on screen as they");
            println!("  arrive.  The output file can be opened later with:");
            println!("    pktana pcap <OUT.pcap>        # CLI analysis");
            println!("    pktana tui <OUT.pcap>         # TUI browser");
            println!("    wireshark <OUT.pcap>          # Wireshark");
            println!();
            println!("{B}ARGUMENTS{R}");
            println!("  {Y}IFACE{R}        Network interface (eth0, ens3, ...)");
            println!("  {Y}OUT.pcap{R}     Output file — must end in .pcap / .pcapng / .cap");
            println!("  {Y}COUNT{R}        Stop after N packets (omit for unlimited)");
            println!("  {Y}BPF_FILTER{R}   BPF filter expression (same syntax as tcpdump)");
            println!();
            println!("{B}REQUIRES{R}");
            println!("  root or CAP_NET_RAW.  Press Ctrl+C to stop.");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana record eth0 out.pcap              # capture everything");
            println!("  pktana record eth0 out.pcap 1000         # stop after 1 000 packets");
            println!("  pktana record eth0 out.pcap 0 tcp        # TCP only, unlimited");
            println!("  pktana record eth0 out.pcap 500 'port 80' # 500 HTTP packets");
            println!("{bar}");
        }

        // ── pcap ──────────────────────────────────────────────────────────────
        "pcap" | "pkt" => {
            println!("{bar}");
            println!("{B}  pktana pcap{R}  —  Analyse a pcap / pcapng / cap file");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana pcap <FILE.pcap>{R}");
            println!("  {Y}pktana <FILE.pcap>{R}         shorthand — extension auto-detected");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Reads every packet from a pcap file, runs full DPI on each, and");
            println!("  prints a color-coded table (same format as live capture) with");
            println!("  pcap-relative timestamps.  Ends with a protocol breakdown and");
            println!("  top-10 talkers summary.");
            println!();
            println!("  Supported file formats: .pcap  .pcapng  .cap");
            println!("  No root required — reads file as a normal user.");
            println!();
            println!("{B}OUTPUT COLUMNS{R}");
            println!("  No.        — packet number in file (1-based)");
            println!("  Timestamp  — pcap-relative wall-clock time (HH:MM:SS.μs)");
            println!("  Bytes      — captured packet size");
            println!("  Proto      — colour-coded protocol label");
            println!("  Source     — source IP:port or MAC");
            println!("  Dest       — destination IP:port or MAC");
            println!("  Info       — DPI summary line");
            println!();
            println!("{B}END-OF-FILE SUMMARY{R}");
            println!("  Protocol Breakdown — percentage bar per protocol");
            println!("  Top Talkers        — top 10 source IPs by packet count + bytes");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana pcap capture.pcap           # analyse file");
            println!("  pktana capture.pcap                # shorthand");
            println!("  pktana tui capture.pcap            # browse in TUI instead");
            println!("{bar}");
        }

        // ── geoip ─────────────────────────────────────────────────────────────
        "geoip" | "geo" => {
            println!("{bar}");
            println!("{B}  pktana geoip{R}  —  IP-to-country geolocation lookup");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana geoip <IP> [IP2] [IP3] ...{R}");
            println!("  {Y}pktana geo <IP> [IP2] ...{R}    (short alias)");
            println!();
            println!("{B}DESCRIPTION{R}");
            println!("  Performs offline IP-to-country code and continent lookup.");
            println!("  No external API calls, no internet connection required.");
            println!("  Private/reserved IP ranges are marked as 'Private / Unknown'.");
            println!();
            println!("{B}OUTPUT COLUMNS{R}");
            println!("  IP          — IPv4 address being looked up");
            println!("  CC          — 2-letter country code (ISO 3166-1 alpha-2)");
            println!("  Continent   — 2-letter continent code (NA, EU, AS, etc.)");
            println!("  Country     — full country name (e.g., 'United States')");
            println!();
            println!("{B}PRIVATE RANGES (marked as --){R}");
            println!("  • 10.0.0.0/8  (private networks)");
            println!("  • 172.16.0.0/12  (private networks)");
            println!("  • 192.168.0.0/16  (private networks)");
            println!("  • 127.0.0.0/8  (loopback)");
            println!("  • 169.254.0.0/16  (link-local)");
            println!("  • 100.64.0.0/10  (CGNAT)");
            println!("  • Reserved ranges (0.0.0.0/8, 255.255.255.0/24, etc.)");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana geoip 8.8.8.8                        # look up Google DNS");
            println!("  pktana geoip 1.1.1.1 8.8.8.8 9.9.9.9        # multiple lookups");
            println!("  pktana geoip 192.168.1.1                    # private IP → --");
            println!("  pktana geo 77.88.8.8 185.12.50.4            # using alias");
            println!();
            println!("{B}USE CASES{R}");
            println!("  • Security — identify suspicious IPs and their origin countries");
            println!("  • Traffic analysis — see geographic distribution of network traffic");
            println!("  • Deployed in TUI dashboard — automatically resolves top talkers");
            println!("  • Scripting — batch process lists of IPs for compliance reporting");
            println!("{bar}");
        }

        // ── unknown ───────────────────────────────────────────────────────────
        other => {
            eprintln!("pktana: no documentation found for '{other}'");
            eprintln!();
            eprintln!("Available topics:");
            eprintln!(
                "  capture  record  pcap  inspect  nic  ethtool  dp  ebpf  bpf  ns  hw  route  conn  stats  watch  hex  file  demo  tui  web  geoip"
            );
            return Err(CliError::Usage(format!("unknown help topic '{other}'")));
        }
    }
    Ok(())
}

// ─── ethtool-equivalent inspector ────────────────────────────────────────────

fn run_ethtool(args: &[String]) -> Result<(), CliError> {
    let name = match args.first() {
        Some(n) => n.as_str(),
        None => return Err(CliError::Usage("usage: pktana ethtool <INTERFACE>".into())),
    };

    let r = get_ethtool_report(name)?;

    println!("pktana ethtool — {name}");
    println!("{}", "═".repeat(60));

    // ── Driver info (-i) ──────────────────────────────────────────────────────
    println!();
    println!("  DRIVER INFO");
    println!("  ───────────────────────────────────────");
    println!("    driver      : {}", r.driver.as_deref().unwrap_or("—"));
    println!("    bus-info    : {}", r.bus_info.as_deref().unwrap_or("—"));
    println!(
        "    firmware    : {}",
        r.firmware_ver.as_deref().unwrap_or("n/a")
    );
    println!(
        "    pci-rev     : {}",
        r.pci_revision.as_deref().unwrap_or("—")
    );
    println!(
        "    irq         : {}",
        r.irq.map(|n| n.to_string()).as_deref().unwrap_or("—")
    );

    // ── Link settings (-s equivalent) ─────────────────────────────────────────
    println!();
    println!("  LINK SETTINGS");
    println!("  ───────────────────────────────────────");
    let speed_str = match r.speed_mbps {
        Some(s) if s >= 1000 => format!("{}G", s / 1000),
        Some(s) => format!("{s}M"),
        None => "unknown".into(),
    };
    println!("    speed       : {speed_str}");
    println!("    duplex      : {}", r.duplex.as_deref().unwrap_or("—"));
    println!("    auto-neg    : {}", r.autoneg.as_deref().unwrap_or("—"));
    println!("    state       : {}", r.operstate);
    println!(
        "    carrier     : {}",
        match r.carrier {
            Some(1) => "UP",
            Some(0) => "DOWN",
            _ => "—",
        }
    );
    println!(
        "    tx-queue-len: {}",
        r.tx_queue_len
            .map(|n| n.to_string())
            .as_deref()
            .unwrap_or("—")
    );

    // ── PCIe link ─────────────────────────────────────────────────────────────
    if r.pcie_speed.is_some() || r.pcie_width.is_some() {
        println!();
        println!("  PCIe LINK");
        println!("  ───────────────────────────────────────");
        println!(
            "    speed       : {}",
            r.pcie_speed.as_deref().unwrap_or("—")
        );
        println!(
            "    width       : {}",
            r.pcie_width
                .map(|w| format!("x{w}"))
                .as_deref()
                .unwrap_or("—")
        );
    }

    // ── Carrier events ────────────────────────────────────────────────────────
    println!();
    println!("  CARRIER EVENTS");
    println!("  ───────────────────────────────────────");
    println!(
        "    up          : {}",
        r.carrier_up
            .map(|n| n.to_string())
            .as_deref()
            .unwrap_or("—")
    );
    println!(
        "    down        : {}",
        r.carrier_down
            .map(|n| n.to_string())
            .as_deref()
            .unwrap_or("—")
    );
    println!(
        "    changes     : {}",
        r.carrier_changes
            .map(|n| n.to_string())
            .as_deref()
            .unwrap_or("—")
    );

    // ── Channels / queues (-l) ────────────────────────────────────────────────
    println!();
    println!("  CHANNELS / QUEUES  (-l)");
    println!("  ───────────────────────────────────────");
    println!("    RX          : {}", r.rx_queues);
    println!("    TX          : {}", r.tx_queues);
    println!("    combined    : {}", r.combined_queues);

    // ── Features / offloads (-k) ──────────────────────────────────────────────
    println!();
    println!("  FEATURES / OFFLOADS  (-k)");
    println!("  ───────────────────────────────────────");
    if r.features.is_empty() {
        println!("    — not available");
    } else {
        let on: Vec<&str> = r
            .features
            .iter()
            .filter(|(_, v)| v.as_str() == "on")
            .map(|(k, _)| k.as_str())
            .collect();
        let off: Vec<&str> = r
            .features
            .iter()
            .filter(|(_, v)| v.as_str() == "off")
            .map(|(k, _)| k.as_str())
            .collect();
        println!("    ON  ({}):", on.len());
        for chunk in on.chunks(4) {
            println!("      {}", chunk.join("    "));
        }
        if !off.is_empty() {
            println!("    OFF ({}):", off.len());
            for chunk in off.chunks(4) {
                println!("      {}", chunk.join("    "));
            }
        }
    }

    // ── IRQ / CPU affinity per queue ─────────────────────────────────────────
    if !r.queue_irq_affinities.is_empty() {
        println!();
        println!("  IRQ / CPU AFFINITY  (per queue)");
        println!("  ───────────────────────────────────────");
        println!(
            "    {:<32}  {:<6}  {:<14}  CPU list",
            "Queue", "IRQ", "SMP mask"
        );
        println!("    {}", "─".repeat(70));
        for q in &r.queue_irq_affinities {
            let irq_s = if q.irq == 0 {
                "—".to_string()
            } else {
                q.irq.to_string()
            };
            println!(
                "    {:<32}  {:<6}  {:<14}  {}",
                trunc(&q.queue_name, 32),
                irq_s,
                q.cpu_mask,
                q.cpu_list
            );
        }
    }

    // ── Extended statistics (-S) ──────────────────────────────────────────────
    println!();
    println!("  EXTENDED STATISTICS  (-S)");
    println!("  ───────────────────────────────────────");
    if r.stats.is_empty() {
        println!("    — not available");
    } else {
        // Print in two columns
        let stats: Vec<(&String, &u64)> = r.stats.iter().collect();
        for pair in stats.chunks(2) {
            match pair {
                [(k1, v1), (k2, v2)] => {
                    println!("    {:<32}  {:>12}    {:<32}  {:>12}", k1, v1, k2, v2)
                }
                [(k1, v1)] => println!("    {:<32}  {:>12}", k1, v1),
                _ => {}
            }
        }
    }

    println!();
    Ok(())
}

// ─── dataplane / bypass inspector ────────────────────────────────────────────

fn run_dataplane(args: &[String]) -> Result<(), CliError> {
    let mut baseline: Option<&str> = None;
    let mut name: Option<&str> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--baseline" => {
                i += 1;
                baseline = args.get(i).map(|s| s.as_str());
            }
            other if !other.starts_with('-') => name = Some(other),
            _ => {}
        }
        i += 1;
    }
    let name = name.ok_or_else(|| {
        CliError::Usage("usage: pktana dp <INTERFACE> [--baseline save|check]".into())
    })?;

    if let Some(action) = baseline {
        let dir = default_baseline_dir();
        match action {
            "save" => {
                let snap = pktana_core::capture_snapshot(name)?;
                let path = dir.join(format!("{name}.json"));
                pktana_core::save_snapshot(&path, &snap)?;
                println!("Saved baseline for {name} → {}", path.display());
                return Ok(());
            }
            "check" => {
                let baseline_path = dir.join(format!("{name}.json"));
                if !baseline_path.exists() {
                    println!("No baseline for {name} — run: pktana dp {name} --baseline save");
                    return Ok(());
                }
                let (_, diffs) = check_drift(&dir, name)?;
                if diffs.is_empty() {
                    println!("✓ No drift on {name}");
                } else {
                    println!("DRIFT on {name} ({} field(s)):", diffs.len());
                    for d in &diffs {
                        println!("  {} : {} → {}", d.field, d.old_value, d.new_value);
                    }
                }
                return Ok(());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown --baseline action '{other}' — use save or check"
                )));
            }
        }
    }

    let dp = get_nic_dataplane(name)?;
    let ebpf = inspect_ebpf_interface(name).ok();

    println!("Dataplane Profile — {name}");
    println!("{}", "═".repeat(56));
    println!();

    // ── Bypass / PMD mode ────────────────────────────────────────────────────
    println!("  Bypass Mode    : {}", dp.bypass_mode);
    println!();

    // ── XDP ──────────────────────────────────────────────────────────────────
    let xdp_ids = ebpf
        .as_ref()
        .map(|r| r.xdp_prog_ids.clone())
        .filter(|ids| !ids.is_empty())
        .unwrap_or_else(|| dp.xdp_prog_ids.clone());
    let xdp_mode = ebpf
        .as_ref()
        .and_then(|r| r.xdp_mode.clone())
        .or_else(|| dp.xdp_mode.clone());

    if xdp_ids.is_empty() {
        println!("  XDP            : not attached");
    } else {
        let ids: Vec<String> = xdp_ids.iter().map(|id| id.to_string()).collect();
        let mode_str = xdp_mode.as_deref().unwrap_or("unknown");
        println!(
            "  XDP            : ATTACHED  (prog IDs: {}  mode: {})",
            ids.join(", "),
            mode_str
        );
        print_bpf_prog_details("    ", &xdp_ids);
    }

    // ── XDP dispatchers (libxdp multi-prog, pinned in /sys/fs/bpf/xdp/) ─────
    {
        let dispatchers = list_xdp_dispatchers();
        let mine: Vec<_> = dispatchers
            .iter()
            .filter(|d| d.iface.as_deref() == Some(name))
            .collect();
        if !mine.is_empty() {
            println!("  XDP dispatchers:");
            for d in &mine {
                let slots = d.slots.join("  ");
                println!("    dispatch-{}-{}  slots: {}", d.prog_id, d.link_id, slots);
            }
        } else if !dispatchers.is_empty() {
            // There are dispatchers but none matched this iface — show unmatched count
            let unmatched: Vec<_> = dispatchers.iter().filter(|d| d.iface.is_none()).collect();
            if !unmatched.is_empty() {
                println!(
                    "  XDP dispatchers: {} pinned in /sys/fs/bpf/xdp/ (ifindex not resolved — run as root for full correlation)",
                    unmatched.len()
                );
            }
        }
    }

    // ── AF_XDP ───────────────────────────────────────────────────────────────
    if dp.afxdp_sockets == 0 {
        println!("  AF_XDP sockets : none");
    } else {
        println!(
            "  AF_XDP sockets : {}  ← zero-copy userspace rings active",
            dp.afxdp_sockets
        );
    }

    // ── DPDK / userspace PMD ─────────────────────────────────────────────────
    if dp.dpdk_bound {
        let drv = dp.userspace_driver.as_deref().unwrap_or("unknown");
        println!("  DPDK/PMD       : BOUND  (driver: {drv})  ← kernel stack BYPASSED");
    } else {
        println!("  DPDK/PMD       : not bound");
    }

    println!();

    // ── SR-IOV ───────────────────────────────────────────────────────────────
    println!("  SR-IOV");
    if dp.is_virtual_function {
        let physfn = dp.physfn_pci.as_deref().unwrap_or("?");
        println!("    Role         : Virtual Function (VF)");
        println!("    Physical Fn  : {physfn}");
    } else if let Some(total) = dp.sriov_vfs_total {
        let enabled = dp.sriov_vfs_enabled.unwrap_or(0);
        println!("    Role         : Physical Function (PF)");
        println!("    VFs enabled  : {} / {}", enabled, total);
    } else {
        println!("    Role         : — (no SR-IOV)");
    }

    println!();

    // ── Multi-queue ───────────────────────────────────────────────────────────
    println!("  Queues");
    if dp.rx_queues == 0 && dp.tx_queues == 0 {
        println!("    RX/TX        : —");
    } else {
        println!("    RX           : {}", dp.rx_queues);
        println!("    TX           : {}", dp.tx_queues);
        println!("    Combined     : {}", dp.combined_queues);
    }

    println!();

    // ── PCI identity + link ───────────────────────────────────────────────────
    println!("  PCI");
    println!(
        "    Address      : {}",
        dp.pci_address.as_deref().unwrap_or("—")
    );
    println!(
        "    Vendor ID    : {}",
        dp.pci_vendor_id.as_deref().unwrap_or("—")
    );
    println!(
        "    Device ID    : {}",
        dp.pci_device_id.as_deref().unwrap_or("—")
    );
    println!(
        "    NUMA node    : {}",
        dp.numa_node
            .map(|n| n.to_string())
            .as_deref()
            .unwrap_or("—")
    );
    {
        let cur_speed = dp.pci_link_speed.as_deref().unwrap_or("—");
        let cur_width = dp
            .pci_link_width
            .map(|w| format!("x{w}"))
            .unwrap_or_else(|| "—".into());
        let max_speed = dp.pci_max_link_speed.as_deref().unwrap_or("—");
        let max_width = dp
            .pci_max_link_width
            .map(|w| format!("x{w}"))
            .unwrap_or_else(|| "—".into());
        println!("    Link speed   : {cur_speed} {cur_width}  (max: {max_speed} {max_width})");
    }

    println!();

    // ── Hardware offloads ─────────────────────────────────────────────────────
    println!("  Hardware Offloads (ON)");
    if dp.hw_features_on.is_empty() {
        println!("    —  (no features reported or not readable)");
    } else {
        // Group into rows of 3 for compact display
        for chunk in dp.hw_features_on.chunks(3) {
            println!("    {}", chunk.join("    "));
        }
    }

    println!();

    // ── TC / BPF ─────────────────────────────────────────────────────────────
    println!("  TC BPF");
    if let Some(ref report) = ebpf {
        if !report.tc.clsact && report.tc.prog_ids.is_empty() {
            println!("    clsact qdisc  : not detected");
        } else {
            println!(
                "    clsact qdisc  : {}",
                if report.tc.clsact {
                    "PRESENT"
                } else {
                    "unknown"
                }
            );
            if report.tc.prog_ids.is_empty() {
                println!("    BPF filters   : none resolved");
            } else {
                let dirs = if report.tc.directions.is_empty() {
                    "unknown".to_string()
                } else {
                    report.tc.directions.join(", ")
                };
                println!("    BPF filters   : {dirs}");
                let ids: Vec<String> = report.tc.prog_ids.iter().map(|id| id.to_string()).collect();
                println!("    prog IDs      : {}", ids.join(", "));
                print_bpf_prog_details("    ", &report.tc.prog_ids);
            }
        }
    } else if !dp.tc_clsact {
        println!("    clsact qdisc  : not present");
    } else {
        println!("    clsact qdisc  : PRESENT");
        if dp.tc_bpf_directions.is_empty() {
            println!("    BPF filters   : none");
        } else {
            println!("    BPF filters   : {}", dp.tc_bpf_directions.join(", "));
            if !dp.tc_bpf_prog_ids.is_empty() {
                let ids: Vec<String> = dp.tc_bpf_prog_ids.iter().map(|id| id.to_string()).collect();
                println!("    prog IDs      : {}", ids.join(", "));
                print_bpf_prog_details("    ", &dp.tc_bpf_prog_ids);
            }
        }
    }

    if let Some(ref report) = ebpf {
        let prog_pins: Vec<_> = report
            .pinned_matches
            .iter()
            .filter(|p| p.kind == "xdp" || p.kind == "tc")
            .collect();
        let map_pins: Vec<_> = report
            .pinned_matches
            .iter()
            .filter(|p| p.kind == "map")
            .collect();
        if !prog_pins.is_empty() || !map_pins.is_empty() {
            println!();
            println!(
                "  Pinned BPF     : {} program(s), {} map(s) correlated (role: {})",
                prog_pins.len(),
                map_pins.len(),
                report.iface_kind
            );
            for pin in prog_pins {
                let id = pin
                    .prog_id
                    .map(|i| format!("id {i}"))
                    .unwrap_or_else(|| "id ?".to_string());
                println!(
                    "    [{kind}] {name}  {id}",
                    kind = pin.kind,
                    name = pin.pin_name
                );
            }
            for pin in map_pins {
                println!("    [map] {}", pin.pin_name);
            }
        }
    }

    let ebpf_active = ebpf.as_ref().map(|r| r.ebpf_active()).unwrap_or_else(|| {
        !dp.xdp_prog_ids.is_empty()
            || (!dp.tc_bpf_prog_ids.is_empty() && dp.tc_clsact)
            || dp.afxdp_sockets > 0
    });
    if ebpf_active {
        println!();
        println!("  eBPF Status    : ACTIVE on this interface");
    }

    println!();

    // ── Guidance ─────────────────────────────────────────────────────────────
    println!("  Guidance");
    match dp.bypass_mode {
        pktana_core::BypassMode::KernelStack => {
            println!("    Packets are processed by the Linux kernel network stack.");
            if ebpf_active {
                println!("    TC/XDP eBPF hooks may still inspect or modify traffic in-kernel.");
            } else {
                println!("    To enable zero-copy: load an AF_XDP program or bind to DPDK.");
            }
        }
        pktana_core::BypassMode::Xdp => {
            println!("    An XDP eBPF program is intercepting packets at the driver.");
            println!("    Packets not forwarded to userspace still go through the kernel stack.");
        }
        pktana_core::BypassMode::AfXdp => {
            println!("    AF_XDP zero-copy is active — packets DMA to userspace rings,");
            println!("    bypassing the kernel socket layer.");
        }
        pktana_core::BypassMode::DpdkUserspace => {
            println!("    DPDK poll-mode driver owns this NIC — the kernel sees NO traffic.");
            println!("    pktana capture will not work on this interface.");
        }
        pktana_core::BypassMode::Hybrid => {
            println!("    XDP and AF_XDP are both active — hybrid zero-copy path.");
        }
    }

    if let Ok(diag) = diagnose_path(name) {
        if !diag.issues.is_empty() || !diag.recommendations.is_empty() {
            println!();
            println!("  Diagnostics");
            for issue in &diag.issues {
                let sev = match issue.severity {
                    IssueSeverity::Critical => "CRIT",
                    IssueSeverity::Warning => "WARN",
                    IssueSeverity::Info => "INFO",
                };
                println!("    [{sev}] {} — {}", issue.code, issue.message);
            }
            for rec in &diag.recommendations {
                println!("    → {rec}");
            }
        }
    }

    Ok(())
}

// ─── full hardware profile ────────────────────────────────────────────────────

fn run_hw(args: &[String]) -> Result<(), CliError> {
    let name = match args.first() {
        Some(n) => n.as_str(),
        None => return Err(CliError::Usage("usage: pktana hw <INTERFACE>".into())),
    };

    println!("Hardware Profile — {name}");
    println!("{}", "═".repeat(56));
    println!();

    // ── NIC basic info ────────────────────────────────────────────────────────
    if let Ok(nic) = get_nic_info(name) {
        println!("  Interface      : {}  ({})", nic.name, nic.state);
        println!("  MAC            : {}", nic.mac);
        println!("  MTU            : {}", nic.mtu);
        if let Some(alias) = &nic.ifalias {
            println!("  Alias          : {alias}");
        }

        // Layer-2 role
        if nic.is_bridge {
            println!("  L2 Role        : Bridge master");
        } else if nic.is_bond {
            println!("  L2 Role        : Bond master");
        } else if let Some(ref master) = nic.master {
            println!("  L2 Role        : Enslaved to '{master}'");
        }

        println!();

        // ── Extended error counters ───────────────────────────────────────────
        println!("  Error Counters");
        println!("    rx_crc_errors    : {}", nic.rx_crc_errors);
        println!("    rx_missed_errors : {}", nic.rx_missed_errors);
        println!("    rx_frame_errors  : {}", nic.rx_frame_errors);
        println!("    rx_fifo_errors   : {}", nic.rx_fifo_errors);
        println!("    tx_carrier_errors: {}", nic.tx_carrier_errors);
        println!("    collisions       : {}", nic.collisions);

        println!();

        // ── Link stability ────────────────────────────────────────────────────
        println!("  Link Stability");
        println!("    carrier_changes  : {}", nic.carrier_changes);
    }

    println!();

    // ── Bridge master ─────────────────────────────────────────────────────────
    if let Some(br) = get_bridge_info(name) {
        println!("  Bridge");
        println!("    Bridge ID      : {}", br.bridge_id);
        println!(
            "    STP            : {}",
            if br.stp_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "    VLAN filtering : {}",
            if br.vlan_filtering { "yes" } else { "no" }
        );
        println!("    Ageing time    : {} jiffies", br.ageing_time_jiffies);
        if br.ports.is_empty() {
            println!("    Ports          : (none)");
        } else {
            println!("    Ports          : {}", br.ports.join("  "));
        }
        println!();
    }

    // ── Bridge port ───────────────────────────────────────────────────────────
    if let Some(bp) = get_bridge_port_info(name) {
        println!("  Bridge Port");
        println!("    Bridge         : {}", bp.bridge);
        println!(
            "    STP state      : {} ({})",
            bp.stp_state,
            stp_state_label(bp.stp_state)
        );
        println!("    Port ID        : {}", bp.port_id);
        println!("    Path cost      : {}", bp.path_cost);
        println!(
            "    Hairpin        : {}",
            if bp.hairpin { "on" } else { "off" }
        );
        println!(
            "    Learning       : {}",
            if bp.learning { "on" } else { "off" }
        );
        println!();
    }

    // ── Bond master ───────────────────────────────────────────────────────────
    if let Some(bond) = get_bond_info(name) {
        println!("  Bond");
        println!("    Mode           : {}", bond.mode);
        println!(
            "    Active slave   : {}",
            bond.active_slave.as_deref().unwrap_or("—")
        );
        println!("    Slaves         : {}", bond.slaves.join("  "));
        println!("    MII monitor    : {} ms", bond.miimon);
        println!("    Link failures  : {}", bond.link_failures);
        println!();
    }

    // ── PTP hardware clocks ───────────────────────────────────────────────────
    let ptps = get_ptp_clocks(name);
    if !ptps.is_empty() {
        println!("  PTP Clocks");
        for ptp in &ptps {
            println!("    {} — {}", ptp.device, ptp.clock_name);
            println!("      max adj      : {} ppb", ptp.max_adj_ppb);
            println!("      ext ts inputs: {}", ptp.n_extts);
            println!("      period outs  : {}", ptp.n_periodic_outputs);
        }
        println!();
    }

    // ── IOMMU group ───────────────────────────────────────────────────────────
    if let Some(iommu) = get_iommu_group(name) {
        println!("  IOMMU Group    : {}", iommu.group_id);
        println!("    Members      : {}", iommu.members.join("  "));
        if iommu.members.len() > 1 {
            println!("    ⚠  Multiple devices share this IOMMU group.");
            println!("       For DPDK/VFIO passthrough all members must be bound to vfio-pci.");
        }
        println!();
    }

    // ── XDP dispatchers linked to this interface ──────────────────────────────
    let dispatchers = list_xdp_dispatchers();
    let mine: Vec<_> = dispatchers
        .iter()
        .filter(|d| d.iface.as_deref() == Some(name))
        .collect();
    if !mine.is_empty() {
        println!("  XDP Dispatchers (libxdp, /sys/fs/bpf/xdp/)");
        for d in &mine {
            println!("    dispatch-{}-{}", d.prog_id, d.link_id);
            for slot in &d.slots {
                println!("      {slot}");
            }
        }
        println!();
    }

    Ok(())
}

// ─── BPF / eBPF helpers ───────────────────────────────────────────────────────

fn print_bpf_prog_details(indent: &str, ids: &[u32]) {
    if ids.is_empty() {
        return;
    }
    let details = enrich_bpf_prog_ids(ids);
    let has_meta = details
        .iter()
        .any(|d| d.name.is_some() || d.prog_type.is_some() || d.tag.is_some());
    if !has_meta {
        return;
    }
    for d in details {
        let name = d.name.as_deref().unwrap_or("—");
        let ptype = d.prog_type.as_deref().unwrap_or("—");
        let tag = d.tag.as_deref().unwrap_or("—");
        println!(
            "{indent}prog {id}: name={name}  type={ptype}  tag={tag}",
            id = d.id
        );
    }
}

fn run_ebpf(args: &[String]) -> Result<(), CliError> {
    match args.first().map(|s| s.as_str()) {
        None => run_ebpf_summary(),
        Some("pinned") | Some("fs") => run_bpf_fs(),
        Some("ns") | Some("netns") => run_netns(),
        Some("dispatchers") | Some("xdp-dispatchers") => run_ebpf_dispatchers(),
        Some("help") | Some("--help") | Some("-h") => {
            print_doc("ebpf")?;
            Ok(())
        }
        Some(iface) => run_ebpf_iface(iface),
    }
}

fn run_ebpf_summary() -> Result<(), CliError> {
    let summary = summarize_ebpf_host();

    println!("eBPF Host Summary");
    println!("{}", "═".repeat(56));
    println!();
    println!("  Pinned objects     : {}", summary.pinned_objects);
    println!("  XDP dispatchers    : {}", summary.xdp_dispatchers);
    println!("  Network namespaces : {}", summary.network_namespaces);
    println!();

    if !summary.pinned_categories.is_empty() {
        println!("  Pinned by category:");
        let mut cats: Vec<_> = summary.pinned_categories.iter().collect();
        cats.sort_by_key(|(k, _)| k.as_str());
        for (cat, count) in cats {
            println!("    {cat:<12} {count}");
        }
        println!();
    }

    if summary.interfaces_with_xdp.is_empty() {
        println!("  XDP attachments    : none detected");
    } else {
        println!("  XDP attachments:");
        for (iface, ids) in &summary.interfaces_with_xdp {
            let id_str: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
            println!("    {iface:<16} prog_ids={}", id_str.join(","));
        }
    }
    println!();

    if summary.interfaces_with_tc_bpf.is_empty() {
        println!("  TC BPF attachments : none detected");
    } else {
        println!("  TC BPF attachments:");
        for (iface, tc) in &summary.interfaces_with_tc_bpf {
            println!(
                "    {iface:<16} directions={}  prog_ids={}",
                tc.directions.join(","),
                tc.prog_ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
    }

    println!();
    println!("  Commands:");
    println!("    pktana ebpf <IFACE>       Full eBPF check for one interface");
    println!("    pktana ebpf pinned        List /sys/fs/bpf/ pinned objects");
    println!("    pktana ebpf dispatchers   List libxdp XDP dispatchers");
    println!("    pktana ebpf ns            Network namespace XDP/AF_XDP map");
    Ok(())
}

fn run_ebpf_iface(name: &str) -> Result<(), CliError> {
    let report = inspect_ebpf_interface(name).map_err(CliError::Io)?;

    println!("eBPF Check — {name}");
    println!("{}", "═".repeat(56));
    println!();

    let all_prog_ids = report.all_prog_ids();

    println!(
        "  Status         : {}",
        if report.ebpf_active() {
            "eBPF ACTIVE"
        } else {
            "no eBPF programs detected"
        }
    );
    println!("  Interface kind : {}", report.iface_kind);
    println!();

    if report.xdp_prog_ids.is_empty() {
        println!("  XDP            : not attached (sysfs/ip/bpftool)");
    } else {
        let mode = report.xdp_mode.as_deref().unwrap_or("unknown");
        println!(
            "  XDP            : {} program(s)  mode={mode}",
            report.xdp_prog_ids.len()
        );
        print_bpf_prog_details("    ", &report.xdp_prog_ids);
    }

    let dispatchers = list_xdp_dispatchers();
    let mine: Vec<_> = dispatchers
        .iter()
        .filter(|d| d.iface.as_deref() == Some(name))
        .collect();
    if !mine.is_empty() {
        println!("  XDP dispatchers:");
        for d in &mine {
            println!(
                "    dispatch-{}-{}  slots: {}",
                d.prog_id,
                d.link_id,
                d.slots.join("  ")
            );
        }
    }

    println!();
    if !report.tc.clsact && report.tc.prog_ids.is_empty() {
        println!("  TC BPF         : not detected");
    } else if report.tc.prog_ids.is_empty() {
        println!("  TC BPF         : clsact/hooks present, no prog IDs resolved");
    } else {
        let dirs = if report.tc.directions.is_empty() {
            "unknown".to_string()
        } else {
            report.tc.directions.join(", ")
        };
        println!(
            "  TC BPF         : {} program(s) on {dirs}",
            report.tc.prog_ids.len()
        );
        print_bpf_prog_details("    ", &report.tc.prog_ids);
    }

    if !report.bpftool_attachments.is_empty() {
        println!("  bpftool net    :");
        for att in &report.bpftool_attachments {
            let id = att
                .prog_id
                .map(|i| i.to_string())
                .unwrap_or_else(|| "?".to_string());
            let mode = att.mode.as_deref().unwrap_or("");
            let name = att.prog_name.as_deref().unwrap_or("");
            println!(
                "    [{hook}] id={id} {mode} {name}",
                hook = att.hook,
                mode = if mode.is_empty() { "" } else { mode },
                name = name
            );
        }
    }

    let prog_pins: Vec<_> = report
        .pinned_matches
        .iter()
        .filter(|p| p.kind == "xdp" || p.kind == "tc")
        .collect();
    let map_pins: Vec<_> = report
        .pinned_matches
        .iter()
        .filter(|p| p.kind == "map")
        .collect();
    if !prog_pins.is_empty() || !map_pins.is_empty() {
        println!("  Pinned in /sys/fs/bpf/ (correlated by interface role):");
        for pin in &prog_pins {
            let id = pin
                .prog_id
                .map(|i| format!("id {i}"))
                .unwrap_or_else(|| "id ?".to_string());
            println!(
                "    [{kind}] {name}  {id}",
                kind = pin.kind,
                name = pin.pin_name
            );
        }
        for pin in &map_pins {
            println!("    [map] {}", pin.pin_name);
        }
    }

    if report.afxdp_sockets > 0 {
        println!("  AF_XDP         : {} socket(s)", report.afxdp_sockets);
    }

    if !all_prog_ids.is_empty() {
        println!();
        println!("  Verification:");
        println!("    bpftool net show dev {name}");
        println!("    bpftool prog show id <ID>");
    }

    Ok(())
}

fn run_ebpf_dispatchers() -> Result<(), CliError> {
    let dispatchers = list_xdp_dispatchers();

    println!("XDP Dispatchers — /sys/fs/bpf/xdp/");
    println!("{}", "═".repeat(56));
    println!();

    if dispatchers.is_empty() {
        println!("  (no libxdp dispatchers found)");
        return Ok(());
    }

    for d in &dispatchers {
        let iface = d.iface.as_deref().unwrap_or("—");
        println!("  dispatch-{}-{}  iface={iface}", d.prog_id, d.link_id);
        if !d.slots.is_empty() {
            println!("    slots: {}", d.slots.join("  "));
        }
        println!("    path : {}", d.dir);
    }
    Ok(())
}

// ─── BPF filesystem ───────────────────────────────────────────────────────────

fn run_bpf_fs() -> Result<(), CliError> {
    let objects = scan_bpf_fs();
    let dispatchers = list_xdp_dispatchers();

    println!("BPF Filesystem — /sys/fs/bpf/");
    println!("{}", "═".repeat(56));
    println!();

    if objects.is_empty() {
        println!("  (no pinned BPF objects found — /sys/fs/bpf/ is empty or not mounted)");
        println!();
        println!("  Tip: mount -t bpf bpf /sys/fs/bpf/ to enable BPF filesystem.");
        return Ok(());
    }

    let dirs: Vec<_> = objects.iter().filter(|o| o.is_dir).collect();
    let files: Vec<_> = objects.iter().filter(|o| !o.is_dir).collect();

    println!("  Pinned objects : {}", files.len());
    println!("  Directories    : {}", dirs.len());
    println!("  XDP dispatchers: {}", dispatchers.len());
    println!();

    let mut categories: HashMap<String, usize> = HashMap::new();
    for obj in &files {
        let key = obj.category.clone().unwrap_or_else(|| "other".to_string());
        *categories.entry(key).or_insert(0) += 1;
    }
    if !categories.is_empty() {
        println!("  By category:");
        let mut cats: Vec<_> = categories.iter().collect();
        cats.sort_by_key(|(k, _)| k.as_str());
        for (cat, count) in cats {
            println!("    {cat:<12} {count}");
        }
        println!();
    }

    if !files.is_empty() {
        println!("  Pinned BPF objects (programs / maps):");
        for obj in &files {
            let display = obj.path.strip_prefix("/sys/fs/bpf/").unwrap_or(&obj.path);
            let cat = obj
                .category
                .as_deref()
                .map(|c| format!("[{c}] "))
                .unwrap_or_default();
            println!("    {cat}{display}");
        }
        println!();
    }

    if !dispatchers.is_empty() {
        println!("  libxdp dispatchers:");
        for d in &dispatchers {
            let iface = d.iface.as_deref().unwrap_or("—");
            println!("    dispatch-{}-{}  iface={iface}", d.prog_id, d.link_id);
        }
        println!();
    }

    println!("  Tip: use 'bpftool prog list' or 'pktana ebpf <IFACE>' for attachment details.");
    Ok(())
}

// ─── network namespace enumeration ────────────────────────────────────────────

fn run_netns() -> Result<(), CliError> {
    let namespaces = list_network_namespaces();

    println!("Network Namespaces");
    println!("{}", "═".repeat(56));
    println!();

    if namespaces.is_empty() {
        println!("  (no namespaces found — /proc not accessible)");
        return Ok(());
    }

    println!(
        "  Found {} distinct network namespace(s)\n",
        namespaces.len()
    );

    for ns in &namespaces {
        let label = if ns.is_host {
            "HOST namespace".to_string()
        } else {
            format!("namespace  inode:{}", ns.inode)
        };
        println!("  ┌─ {label}");
        println!("  │  inode      : {}", ns.inode);

        // Show up to 5 representative processes.
        let shown_pids: Vec<String> = ns
            .pids
            .iter()
            .zip(ns.comms.iter())
            .take(5)
            .map(|(pid, comm)| format!("{pid}({comm})"))
            .collect();
        let extra = if ns.pids.len() > 5 {
            format!(" +{} more", ns.pids.len() - 5)
        } else {
            String::new()
        };
        println!("  │  processes  : {}{extra}", shown_pids.join("  "));

        // Interfaces visible in this namespace.
        if ns.interfaces.is_empty() {
            println!("  │  interfaces : (none readable)");
        } else {
            println!("  │  interfaces : {}", ns.interfaces.join("  "));
        }

        // XDP info (host namespace only via sysfs).
        if !ns.xdp_per_iface.is_empty() {
            for (iface, ids) in &ns.xdp_per_iface {
                let id_strs: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
                println!("  │  XDP        : {iface}  prog_ids={}", id_strs.join(","));
            }
        } else if ns.is_host {
            println!("  │  XDP        : no programs attached on host interfaces");
        } else {
            println!("  │  XDP        : (requires nsenter to read prog IDs)");
        }

        // AF_XDP sockets.
        if !ns.afxdp_per_iface.is_empty() {
            for (iface, cnt) in &ns.afxdp_per_iface {
                println!("  │  AF_XDP     : {iface}  sockets={cnt}");
            }
        }

        println!("  └─");
        println!();
    }

    Ok(())
}

// ─── routing table / nexthop ──────────────────────────────────────────────────

fn run_routes(args: &[String]) -> Result<(), CliError> {
    let json = args.iter().any(|a| a == "--json" || a == "-j");
    let target = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str());

    let routes = match target {
        Some(iface) => {
            let r = routes_for_iface(iface);
            if r.is_empty() {
                if !json {
                    println!("No routes found for interface '{iface}'.");
                }
                return Ok(());
            }
            r
        }
        None => {
            let r = list_routes();
            if r.is_empty() {
                if !json {
                    println!("No routes found.");
                }
                return Ok(());
            }
            r
        }
    };

    if json {
        let mut out = String::from("[\n");
        for (i, r) in routes.iter().enumerate() {
            out.push_str(&format!(
                r#"  {{"interface":"{}","destination":"{}","prefix_len":{},"gateway":"{}","metric":{},"is_default":{}}}"#,
                r.interface, r.destination, r.prefix_len, r.gateway, r.metric, r.is_default
            ));
            if i < routes.len() - 1 {
                out.push_str(",\n");
            } else {
                out.push('\n');
            }
        }
        out.push(']');
        println!("{out}");
        return Ok(());
    }

    if let Some(t) = target {
        println!("Routes for {}:\n", t);
    } else {
        println!("Routing Table (IPv4 + IPv6):\n");
    }

    println!(
        "\x1b[1;36m{:<16}  {:<24}  {:<8}  {:<26}  {:<8}  Type\x1b[0m",
        "Interface", "Destination", "Prefix", "Gateway / Nexthop", "Metric"
    );
    println!("\x1b[1;36m{}\x1b[0m", "─".repeat(100));

    for r in &routes {
        let dest_cidr = format!("{}/{}", r.destination, r.prefix_len);
        let gw_display = if r.gateway == "0.0.0.0" || r.gateway == "::" {
            "direct (connected)".to_string()
        } else {
            r.gateway.clone()
        };
        let rtype = if r.is_default {
            "default"
        } else if r.gateway == "0.0.0.0" || r.gateway == "::" {
            "connected"
        } else {
            "static/dynamic"
        };
        println!(
            "{:<16}  {:<24}  {:<8}  {:<26}  {:<8}  {}",
            r.interface,
            dest_cidr,
            format!("/{}", r.prefix_len),
            trunc(&gw_display, 26),
            r.metric,
            rtype,
        );
    }
    Ok(())
}

// ─── connection table ─────────────────────────────────────────────────────────

fn run_connections(args: &[String]) -> Result<(), CliError> {
    use pktana_core::geoip_lookup_str;

    let json = args.iter().any(|a| a == "--json" || a == "-j");
    let only_tcp = args.iter().any(|a| a == "--tcp");
    let only_udp = args.iter().any(|a| a == "--udp");
    let only_established = args.iter().any(|a| a == "--established" || a == "-e");
    let only_listen = args.iter().any(|a| a == "--listen" || a == "-l");

    let mut conns = list_connections();

    // Apply filters
    if only_tcp {
        conns.retain(|c| c.proto.starts_with("TCP"));
    }
    if only_udp {
        conns.retain(|c| c.proto.starts_with("UDP"));
    }
    if only_established {
        conns.retain(|c| c.state == "ESTABLISHED");
    }
    if only_listen {
        conns.retain(|c| c.state == "LISTEN");
    }

    if conns.is_empty() {
        if !json {
            println!("No connections found (run as root to see all processes).");
        }
        return Ok(());
    }

    if json {
        let mut out = String::from("[\n");
        for (i, c) in conns.iter().enumerate() {
            let proc = c
                .process
                .as_deref()
                .unwrap_or("")
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            out.push_str(&format!(
                r#"  {{"proto":"{}","local_ip":"{}","local_port":{},"remote_ip":"{}","remote_port":{},"state":"{}","pid":{},"process":"{}"}}"#,
                c.proto, c.local_ip, c.local_port, c.remote_ip, c.remote_port, c.state, c.pid.unwrap_or(0), proc
            ));
            if i < conns.len() - 1 {
                out.push_str(",\n");
            } else {
                out.push('\n');
            }
        }
        out.push(']');
        println!("{out}");
        return Ok(());
    }

    // Build state summary counts
    let mut state_counts: HashMap<&str, usize> = HashMap::new();
    for c in &conns {
        *state_counts.entry(c.state).or_insert(0) += 1;
    }

    println!("Active Connections ({})\n", conns.len());
    println!(
        "\x1b[1;36m{:<5}  {:<28}  {:<28}  {:<13}  {:<6}  {:<22}  Service / Country\x1b[0m",
        "Proto", "Local Address", "Remote Address", "State", "PID", "Process"
    );
    println!("\x1b[1;36m{}\x1b[0m", "─".repeat(130));
    for c in &conns {
        let local = format!("{}:{}", c.local_ip, c.local_port);
        let remote = if c.remote_port == 0 {
            "—".to_string()
        } else {
            format!("{}:{}", c.remote_ip, c.remote_port)
        };
        let pid_s = c
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());
        let proc_s = c.process.as_deref().unwrap_or("—");

        // Service name for well-known ports
        let svc = if c.remote_port != 0 {
            let s = port_service_name(c.remote_port);
            if s != "?" {
                s.to_string()
            } else {
                String::new()
            }
        } else {
            let s = port_service_name(c.local_port);
            if s != "?" {
                s.to_string()
            } else {
                String::new()
            }
        };

        // GeoIP for remote IP
        let geo = if c.remote_port != 0 {
            geoip_lookup_str(&c.remote_ip.to_string())
                .map(|g| format!("{} {}", g.country_code, g.country_name))
                .unwrap_or_else(|| "Private/LAN".to_string())
        } else {
            String::new()
        };

        let svc_geo = match (svc.is_empty(), geo.is_empty()) {
            (false, false) => format!("{svc} · {geo}"),
            (false, true) => svc,
            (true, false) => geo,
            (true, true) => "—".to_string(),
        };

        // Color-coded TCP state
        let state_padded = format!("{:<13}", c.state);
        let state_col = if c.state.contains("ESTABLISH") {
            format!("\x1b[32m{state_padded}\x1b[0m")
        } else if c.state.contains("LISTEN") {
            format!("\x1b[36m{state_padded}\x1b[0m")
        } else if c.state.contains("TIME_WAIT") || c.state.contains("CLOSE_WAIT") {
            format!("\x1b[33m{state_padded}\x1b[0m")
        } else if c.state.contains("SYN") {
            format!("\x1b[1;33m{state_padded}\x1b[0m")
        } else {
            state_padded
        };

        println!(
            "{:<5}  {:<28}  {:<28}  {}  {:<6}  {:<22}  {}",
            c.proto,
            trunc(&local, 28),
            trunc(&remote, 28),
            state_col,
            pid_s,
            trunc(proc_s, 22),
            svc_geo,
        );
    }

    // State summary footer
    if !state_counts.is_empty() {
        println!("\x1b[1;36m{}\x1b[0m", "─".repeat(130));
        let mut counts: Vec<(&str, usize)> = state_counts.into_iter().collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let parts: Vec<String> = counts.iter().map(|(s, n)| format!("{s}: {n}")).collect();
        println!("  State summary  —  {}", parts.join("  ·  "));
        println!("\x1b[2m  Filters: --tcp  --udp  --established  --listen\x1b[0m");
    }

    Ok(())
}

// ─── live stats dashboard ─────────────────────────────────────────────────────

struct LiveStats {
    interface: String,
    start: Instant,
    last_tick: Instant,
    total_pkts: u64,
    total_bytes: u64,
    win_pkts: u64,
    win_bytes: u64,
    proto: HashMap<String, (u64, u64)>, // proto  -> (pkts, bytes)
    talkers: HashMap<String, (u64, u64)>, // src_ip -> (pkts, bytes)
}

impl LiveStats {
    fn new(interface: &str) -> Self {
        let now = Instant::now();
        Self {
            interface: interface.to_string(),
            start: now,
            last_tick: now,
            total_pkts: 0,
            total_bytes: 0,
            win_pkts: 0,
            win_bytes: 0,
            proto: HashMap::new(),
            talkers: HashMap::new(),
        }
    }

    fn ingest(&mut self, src_ip: &str, proto: &str, bytes: usize) {
        let b = bytes as u64;
        self.total_pkts += 1;
        self.total_bytes += b;
        self.win_pkts += 1;
        self.win_bytes += b;
        let pe = self.proto.entry(proto.to_string()).or_insert((0, 0));
        pe.0 += 1;
        pe.1 += b;
        // cap talkers map at 5 000 unique IPs
        if self.talkers.len() < 5_000 || self.talkers.contains_key(src_ip) {
            let te = self.talkers.entry(src_ip.to_string()).or_insert((0, 0));
            te.0 += 1;
            te.1 += b;
        }
    }

    fn tick_and_render(&mut self) {
        let elapsed = self.last_tick.elapsed();
        if elapsed < Duration::from_millis(950) {
            return;
        }
        let secs = elapsed.as_secs_f64();
        let pps = self.win_pkts as f64 / secs;
        let bps = self.win_bytes as f64 / secs;
        let total_sec = self.start.elapsed().as_secs();

        // Move cursor to top instead of full clear to prevent flicker
        print!("\x1b[H");

        println!(
            "\x1b[1;36mpktana LIVE STATS — {}   [elapsed {:02}h {:02}m {:02}s]  Ctrl+C to stop\x1b[0m\x1b[K",
            self.interface,
            total_sec / 3600,
            (total_sec % 3600) / 60,
            total_sec % 60,
        );
        println!("\x1b[1;36m{}\x1b[0m\x1b[K", "═".repeat(72));
        println!("\x1b[K");
        println!(
            "  Rate (last {}s)  :  {:>8.0} pkt/s   {}/s\x1b[K",
            elapsed.as_secs().max(1),
            pps,
            format_bytes(bps as u64)
        );
        println!(
            "  Total           :  {:>8} pkts    {}\x1b[K",
            self.total_pkts,
            format_bytes(self.total_bytes)
        );
        println!("\x1b[K");

        // Protocol breakdown
        println!("  Protocol Breakdown:\x1b[K");
        let total = self.total_pkts.max(1);
        let mut protos: Vec<(&String, &(u64, u64))> = self.proto.iter().collect();
        protos.sort_by_key(|b| Reverse(b.1 .0));
        for (name, (pkts, bytes)) in protos.iter().take(6) {
            let pct = *pkts as f64 / total as f64 * 100.0;
            println!(
                "    {:6}  {}  {:5.1}%  {:>8} pkts  {}\x1b[K",
                name,
                ascii_bar(pct, 28),
                pct,
                pkts,
                format_bytes(*bytes)
            );
        }
        println!("\x1b[K");

        // Top talkers
        println!("  Top Talkers (by packets):\x1b[K");
        let mut talkers: Vec<(&String, &(u64, u64))> = self.talkers.iter().collect();
        talkers.sort_by_key(|b| Reverse(b.1 .0));
        for (i, (ip, (pkts, bytes))) in talkers.iter().take(10).enumerate() {
            use pktana_core::geoip_lookup_str;
            let country = geoip_lookup_str(ip)
                .map(|g| format!("{}  {}", g.country_code, g.country_name))
                .unwrap_or_else(|| "Private/LAN".to_string());
            println!(
                "    {:>2}.  {:<26}  {:>8} pkts   {:<12}  {}\x1b[K",
                i + 1,
                ip,
                pkts,
                format_bytes(*bytes),
                country
            );
        }

        // Clear any remaining lines below the render area
        print!("\x1b[J");
        let _ = std::io::stdout().flush();

        // reset window counters
        self.win_pkts = 0;
        self.win_bytes = 0;
        self.last_tick = Instant::now();

        // trim talkers if huge
        if self.talkers.len() > 5_000 {
            let mut v: Vec<(String, (u64, u64))> = self.talkers.drain().collect();
            v.sort_by_key(|b| Reverse(b.1 .0));
            v.truncate(1_000);
            self.talkers = v.into_iter().collect();
        }
    }
}

fn run_stats(args: &[String]) -> Result<(), CliError> {
    if args.is_empty() {
        return Err(CliError::Usage(
            "usage: pktana stats <INTERFACE> [BPF_FILTER]".into(),
        ));
    }
    let interface = &args[0];
    let filter = if args.len() > 1 {
        Some(args[1..].join(" "))
    } else {
        None
    };
    let config = CaptureConfig {
        interface: interface.clone(),
        max_packets: usize::MAX,
        promiscuous: true,
        snapshot_len: 65_535,
        filter,
        pcap_export: None,
    };
    let mut live = LiveStats::new(interface);
    // initial clear so first render starts at top
    print!("\x1b[2J");
    LinuxCaptureEngine::capture_streaming(&config, |pkt| {
        let dp = inspect(&pkt.data);
        let src = dp
            .ip_src
            .map(|a| a.to_string())
            .or_else(|| dp.ipv6_src.clone())
            .unwrap_or_else(|| dp.eth_src.clone());
        let proto = dp_proto_label(&dp);
        live.ingest(&src, &proto, pkt.data.len());
        live.tick_and_render();
        true
    })?;
    Ok(())
}

fn ascii_bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

// ─── NIC watch (auto-refresh) ─────────────────────────────────────────────────

fn run_watch(args: &[String]) -> Result<(), CliError> {
    if args.is_empty() {
        return Err(CliError::Usage(
            "usage: pktana watch <INTERFACE> [INTERVAL_SECS]".into(),
        ));
    }
    let name = &args[0];
    let interval = args.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(2);

    print!("\x1b[2J"); // clear full screen once at start
    loop {
        print!("\x1b[H"); // move cursor to top-left
        match get_nic_info(name) {
            Ok(nic) => print_nic_watch(&nic, interval),
            Err(e) => println!("Error reading {name}: {e}"),
        }
        print!("\x1b[J"); // clear anything below our new render
        let _ = std::io::stdout().flush();
        thread::sleep(Duration::from_secs(interval));
    }
}

fn print_nic_watch(nic: &NicInfo, interval: u64) {
    println!(
        "pktana watch — {}   (every {}s, Ctrl+C to stop)\x1b[K",
        nic.name, interval
    );
    println!("{}\x1b[K", "─".repeat(52));
    println!("\x1b[K");
    println!("  Interface : {}\x1b[K", nic.name);
    println!(
        "  State     : {}\x1b[K",
        if nic.is_up() { "UP" } else { "down" }
    );
    println!("  MAC       : {}\x1b[K", nic.mac);
    println!("  MTU       : {}\x1b[K", nic.mtu);
    println!(
        "  Speed     : {} / {}\x1b[K",
        nic.speed_label(),
        nic.duplex.as_deref().unwrap_or("?")
    );
    if !nic.ip_addresses.is_empty() {
        println!("  Addresses : {}\x1b[K", nic.ip_addresses.join(", "));
    }
    println!("\x1b[K");
    println!(
        "\x1b[1;36m  {:4}  {:>12}  {:>12}  {:>10}  {:>10}\x1b[0m\x1b[K",
        "", "Packets", "Bytes", "Errors", "Dropped"
    );
    println!("\x1b[1;36m  {}\x1b[0m\x1b[K", "─".repeat(55));
    println!(
        "  {:4}  {:>12}  {:>12}  {:>10}  {:>10}\x1b[K",
        "RX",
        nic.rx_packets,
        format_bytes(nic.rx_bytes),
        nic.rx_errors,
        nic.rx_dropped
    );
    println!(
        "  {:4}  {:>12}  {:>12}  {:>10}  {:>10}\x1b[K",
        "TX",
        nic.tx_packets,
        format_bytes(nic.tx_bytes),
        nic.tx_errors,
        nic.tx_dropped
    );
}

// ─── GeoIP lookup command ─────────────────────────────────────────────────────

fn run_geoip(args: &[String]) -> Result<(), CliError> {
    use pktana_core::geoip_lookup_str;

    let json = args.iter().any(|a| a == "--json" || a == "-j");
    let ips: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();

    if ips.is_empty() {
        return Err(CliError::Usage(
            "usage: pktana geoip <IP> [IP2] [IP3] ...".into(),
        ));
    }

    if json {
        let mut out = String::from("[\n");
        for (i, ip) in ips.iter().enumerate() {
            if let Some(geo) = geoip_lookup_str(ip) {
                out.push_str(&format!(
                    r#"  {{"ip":"{}","country_code":"{}","continent":"{}","country_name":"{}"}}"#,
                    ip, geo.country_code, geo.continent, geo.country_name
                ));
            } else {
                out.push_str(&format!(
                    r#"  {{"ip":"{}","country_code":null,"continent":null,"country_name":null}}"#,
                    ip
                ));
            }
            if i < ips.len() - 1 {
                out.push_str(",\n");
            } else {
                out.push('\n');
            }
        }
        out.push(']');
        println!("{out}");
        return Ok(());
    }

    println!(
        "\x1b[1;36m{:<18}  {:<4}  {:<9}  Country\x1b[0m",
        "IP", "CC", "Continent"
    );
    println!("\x1b[1;36m{}\x1b[0m", "─".repeat(55));

    for ip in ips {
        match geoip_lookup_str(ip) {
            Some(geo) => println!(
                "{:<18}  {:<4}  {:<9}  {}",
                ip, geo.country_code, geo.continent, geo.country_name
            ),
            None => println!("{:<18}  --    --         Private / Unknown", ip),
        }
    }
    Ok(())
}
