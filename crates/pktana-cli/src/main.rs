use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use pktana_core::{
    analyze_bytes,
    analyze_hex,
    analyze_hex_file,
    build_flow_table,
    format_bytes,
    get_ethtool_report,
    get_nic_dataplane,
    get_nic_info,
    hex_dump,
    inspect,
    list_connections,
    list_nics,
    list_routes,
    routes_for_iface,
    sample_packets,
    CaptureConfig,
    CaptureError,
    LinuxCaptureEngine,
    NicInfo,
    ParsedPacket,
    ParseError,
    TransportHeader,
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
            Self::Parse(e)   => write!(f, "{e}"),
            Self::Capture(e) => write!(f, "{e}"),
            Self::Io(e)      => write!(f, "io error: {e}"),
            Self::Usage(m)   => write!(f, "{m}"),
        }
    }
}

impl From<ParseError>     for CliError { fn from(e: ParseError)     -> Self { Self::Parse(e) } }
impl From<CaptureError>   for CliError { fn from(e: CaptureError)   -> Self { Self::Capture(e) } }
impl From<std::io::Error> for CliError { fn from(e: std::io::Error) -> Self { Self::Io(e) } }

// ─── entry point ─────────────────────────────────────────────────────────────

fn main() {
    if let Err(err) = run() {
        eprintln!("pktana: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        // ── version ───────────────────────────────────────────────────────────
        "--version" | "-V" | "version" => {
            println!("pktana {}  ({})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_DESCRIPTION"));
            println!("license  : Apache-2.0");
            println!("repo     : {}", env!("CARGO_PKG_REPOSITORY"));
            return Ok(());
        }

        // ── packet capture ────────────────────────────────────────────────────
        "capture" | "cap" => run_capture(&args[2..]),

        // ── pcap interface list ───────────────────────────────────────────────
        "interfaces" | "ifaces" => print_capture_interfaces(),

        // ── NIC detail (sysfs/procfs — no external tools) ────────────────────
        "nic" => run_nic(&args[2..]),

        // ── ethtool-equivalent deep NIC inspection ──────────────────────────────
        "ethtool" | "et" => run_ethtool(&args[2..]),

        // ── NIC dataplane / bypass / offload inspector ────────────────────────
        "dp" | "dataplane" => run_dataplane(&args[2..]),

        // ── deep packet inspection ────────────────────────────────────────────
        "inspect" => run_inspect(&args[2..]),

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
        "conn" | "connections" => run_connections(),

        // ── live traffic stats dashboard (replaces iftop) ────────────────────
        "stats" => run_stats(&args[2..]),

        // ── NIC auto-refresh (replaces watch ip -s) ───────────────────────────
        "watch" => run_watch(&args[2..]),

        "help" | "--help" | "-h" | "-?" => {
            match args.get(2).map(|s| s.as_str()) {
                Some(topic) => print_doc(topic),
                None        => { print_usage(); Ok(()) }
            }
        }

        // ── shorthand: pktana <interface> [count] [filter] ───────────────────
        _ => run_capture(&args[1..]),
    }
}

// ─── live capture ─────────────────────────────────────────────────────────────

fn run_capture(args: &[String]) -> Result<(), CliError> {
    if args.is_empty() {
        return Err(CliError::Usage(
            "usage: pktana <INTERFACE> [COUNT] [BPF_FILTER]".into(),
        ));
    }

    let interface = &args[0];

    let (max_packets, filter) = match args.get(1) {
        None => (0, None),
        Some(second) => match second.parse::<usize>() {
            Ok(n) => {
                let f = if args.len() > 2 { Some(args[2..].join(" ")) } else { None };
                (n, f)
            }
            Err(_) => (0, Some(args[1..].join(" "))),
        },
    };

    let count_label  = if max_packets == 0 { "unlimited".to_string() } else { max_packets.to_string() };
    let filter_label = filter.as_deref().unwrap_or("none");

    println!(
        "Capturing on {interface}  |  packets: {count_label}  |  filter: {filter_label}  |  Ctrl+C to stop"
    );
    println!();

    let sep = "─".repeat(118);
    println!(
        "{:>5}  {:<17}  {:>7}  {:<5}  {:<26}  {:<26}  {}",
        "No.", "Time", "Bytes", "Proto", "Source", "Destination", "Info"
    );
    println!("{sep}");
    let _ = std::io::stdout().flush();

    let config = CaptureConfig {
        interface: interface.clone(),
        max_packets: if max_packets == 0 { usize::MAX } else { max_packets },
        promiscuous: true,
        snapshot_len: 65_535,
        filter,
    };

    let mut pkt_num: usize = 0;
    let mut total_bytes: u64 = 0;

    let stats = LinuxCaptureEngine::capture_streaming(&config, |pkt| {
        pkt_num += 1;
        let ts    = format_timestamp(pkt.timestamp_sec, pkt.timestamp_usec);
        let bytes = pkt.data.len();
        total_bytes += bytes as u64;

        match analyze_bytes(&pkt.data) {
            Ok(parsed) => {
                let s = &parsed.summary;
                println!(
                    "{:>5}  {:<17}  {:>7}  {:<5}  {:<26}  {:<26}  {}",
                    pkt_num, ts, bytes,
                    s.proto_label(),
                    trunc(&s.src_str(), 26),
                    trunc(&s.dst_str(), 26),
                    dns_decode(&parsed).unwrap_or_else(|| s.info_str()),
                );
            }
            Err(_) => {
                println!("{:>5}  {:<17}  {:>7}  {:<5}  {}", pkt_num, ts, bytes, "?", "[parse error]");
            }
        }
        let _ = std::io::stdout().flush();
        true
    })?;

    println!("{sep}");
    println!(
        "{} packets captured  |  {} total",
        stats.packets_seen,
        format_bytes(total_bytes),
    );
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
        let kind = if iface.loopback { "loopback" } else { "network " };
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
    match args.first().map(|s| s.as_str()) {
        // pktana nic  or  pktana nic list
        None | Some("list") => {
            let nics = list_nics()?;
            println!(
                "{:<16}  {:<5}  {:<19}  {:<6}  {:<8}  {}",
                "Interface", "State", "MAC", "MTU", "Speed", "IP Addresses"
            );
            println!("{}", "─".repeat(90));
            for nic in &nics {
                let state = if nic.is_up() { "UP" } else { "down" };
                let speed = nic.speed_label();
                let ips   = if nic.ip_addresses.is_empty() {
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
                    if i == 0 { println!("Addresses : {addr}"); }
                    else       { println!("            {addr}"); }
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

// ─── deep packet inspection ───────────────────────────────────────────────────

fn run_inspect(args: &[String]) -> Result<(), CliError> {
    // pktana inspect <HEX>
    // pktana inspect -f <FILE>
    let raw: Vec<u8> = if args.first().map(|s| s.as_str()) == Some("-f") {
        let path = args.get(1).ok_or_else(|| CliError::Usage("usage: pktana inspect -f <FILE>".into()))?;
        let text = std::fs::read_to_string(path)?;
        let hex: String = text.lines()
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
    if hex.len() % 2 != 0 {
        return Err(CliError::Usage("Hex string has odd length".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16).map_err(|_| CliError::Usage("Invalid hex".into())))
        .collect()
}

fn print_deep_packet(dp: &pktana_core::DeepPacket) {
    let bar  = "═".repeat(64);
    let thin = "─".repeat(48);

    // ANSI color codes (work on any xterm-compatible terminal)
    const BOLD:  &str = "\x1b[1m";
    const CYAN:  &str = "\x1b[1;36m";
    const RED:   &str = "\x1b[1;31m";
    const GREEN: &str = "\x1b[32m";
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
    let src_vendor = dp.eth_vendor_src.map(|v| format!("  [{v}]")).unwrap_or_default();
    let dst_vendor = dp.eth_vendor_dst.map(|v| format!("  [{v}]")).unwrap_or_default();
    println!("  Dst MAC    : {}{}", dp.eth_dst, dst_vendor);
    println!("  Src MAC    : {}{}", dp.eth_src, src_vendor);

    if !dp.vlan_tags.is_empty() {
        let vlan_desc: Vec<String> = dp.vlan_tags.iter().map(|t| {
            format!("VLAN {} (PCP={} DEI={})", t.id, t.pcp, t.dei as u8)
        }).collect();
        println!("  VLAN       : {}", vlan_desc.join("  →  "));
    }

    println!("  EtherType  : 0x{:04x}  ({})", dp.ether_type, dp.ether_type_name);

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
        println!("  Src IP     : {}", dp.ip_src.map(|a| a.to_string()).unwrap_or_else(|| "—".into()));
        println!("  Dst IP     : {}", dp.ip_dst.map(|a| a.to_string()).unwrap_or_else(|| "—".into()));
        println!("  Protocol   : {}  ({})",
            dp.ip_proto.unwrap_or(0),
            dp.ip_proto_name.unwrap_or("?"));
        println!("  TTL        : {}    ID: 0x{:04x}    Len: {}",
            dp.ip_ttl.unwrap_or(0),
            dp.ip_id.unwrap_or(0),
            dp.ip_total_len.unwrap_or(0));
        let flags_str = format!("{}{}",
            if dp.ip_flag_df { "DF " } else { "" },
            if dp.ip_flag_mf { "MF " } else { "" });
        let flags_str = if flags_str.is_empty() { "none".to_string() } else { flags_str.trim().to_string() };
        println!("  DSCP: {}  ECN: {}  Flags: {}  Frag offset: {}",
            dp.ip_dscp.unwrap_or(0),
            dp.ip_ecn.unwrap_or(0),
            flags_str,
            dp.ip_fragment.unwrap_or(0));
        println!("  Hdr length : {} bytes", dp.ip_hdr_len.unwrap_or(0));
    }

    // ── Layer 4: TCP ──────────────────────────────────────────────────────────
    if dp.tcp_src_port.is_some() {
        println!();
        println!("{bar}");
        let dst_svc = dp.tcp_dst_port.map(|p| {
            let s = port_service_name(p);
            if s != "?" { format!(" [{s}]") } else { String::new() }
        }).unwrap_or_default();
        let src_svc = dp.tcp_src_port.map(|p| {
            let s = port_service_name(p);
            if s != "?" { format!(" [{s}]") } else { String::new() }
        }).unwrap_or_default();
        println!("  LAYER 4 — TCP");
        println!("  {thin}");
        println!("  Src port   : {}{}", dp.tcp_src_port.unwrap_or(0), src_svc);
        println!("  Dst port   : {}{}", dp.tcp_dst_port.unwrap_or(0), dst_svc);
        println!("  Seq        : {:10}   Ack: {}",
            dp.tcp_seq.unwrap_or(0), dp.tcp_ack.unwrap_or(0));
        println!("  Window     : {}   Urgent: {}   Hdr: {} bytes",
            dp.tcp_window.unwrap_or(0), dp.tcp_urgent.unwrap_or(0), dp.tcp_hdr_len.unwrap_or(0));
        println!("  Flags      : {}",
            dp.tcp_flags_str.as_deref().unwrap_or("[none]"));

        // TCP options
        let mut opts = Vec::new();
        if let Some(mss) = dp.tcp_mss         { opts.push(format!("MSS={mss}")); }
        if let Some(ws)  = dp.tcp_window_scale { opts.push(format!("WScale={ws}")); }
        if dp.tcp_sack_permitted               { opts.push("SACK_OK".into()); }
        if let Some((tsv, tse)) = dp.tcp_timestamp { opts.push(format!("TS={tsv}/{tse}")); }
        if !dp.tcp_sack_blocks.is_empty() {
            for (l, r) in &dp.tcp_sack_blocks { opts.push(format!("SACK({l}-{r})")); }
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
        let dst_svc = dp.udp_dst_port.map(|p| {
            let s = port_service_name(p);
            if s != "?" { format!(" [{s}]") } else { String::new() }
        }).unwrap_or_default();
        let src_svc = dp.udp_src_port.map(|p| {
            let s = port_service_name(p);
            if s != "?" { format!(" [{s}]") } else { String::new() }
        }).unwrap_or_default();
        println!("  Src port   : {}{}", dp.udp_src_port.unwrap_or(0), src_svc);
        println!("  Dst port   : {}{}", dp.udp_dst_port.unwrap_or(0), dst_svc);
        println!("  Length     : {}   Checksum: 0x{:04x}",
            dp.udp_len.unwrap_or(0), dp.udp_checksum.unwrap_or(0));
        println!("  Payload    : {} bytes", dp.udp_payload_len);
    }

    // ── Layer 4: ICMP ─────────────────────────────────────────────────────────
    if dp.icmp_type.is_some() {
        println!();
        println!("{bar}");
        println!("  LAYER 4 — ICMP");
        println!("  {thin}");
        println!("  Type/Code  : {}/{}  —  {}",
            dp.icmp_type.unwrap_or(0), dp.icmp_code.unwrap_or(0),
            dp.icmp_type_str.as_deref().unwrap_or("?"));
        println!("  Checksum   : 0x{:04x}", dp.icmp_checksum.unwrap_or(0));
        if let Some(id) = dp.icmp_id  { println!("  ID         : {id}"); }
        if let Some(sq) = dp.icmp_seq { println!("  Sequence   : {sq}"); }
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
        20=>"FTP-data", 21=>"FTP", 22=>"SSH", 23=>"Telnet", 25=>"SMTP",
        53=>"DNS", 67=>"DHCP-srv", 68=>"DHCP-cli", 69=>"TFTP",
        80=>"HTTP", 110=>"POP3", 123=>"NTP", 143=>"IMAP",
        161=>"SNMP", 179=>"BGP", 389=>"LDAP", 443=>"HTTPS",
        465=>"SMTPS", 514=>"Syslog", 515=>"LPD",
        587=>"SMTP-sub", 636=>"LDAPS", 993=>"IMAPS", 995=>"POP3S",
        1194=>"OpenVPN", 1433=>"MSSQL", 1521=>"Oracle",
        1900=>"SSDP", 2181=>"ZooKeeper", 2375=>"Docker",
        3306=>"MySQL", 3389=>"RDP", 4789=>"VXLAN",
        5432=>"PostgreSQL", 5672=>"AMQP", 5900=>"VNC",
        6379=>"Redis", 6443=>"K8s API", 8080=>"HTTP-alt",
        8443=>"HTTPS-alt", 9042=>"Cassandra", 9200=>"Elasticsearch",
        27017=>"MongoDB", _=>"?",
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
            flow.key.source_ip, flow.key.source_port,
            flow.key.destination_ip, flow.key.destination_port,
            flow.key.protocol, flow.packets, flow.bytes,
        );
    }
    if !errors.is_empty() {
        println!();
        println!("Errors: {}", errors.len());
        for e in errors { println!("  {e}"); }
    }
}

// ─── utilities ────────────────────────────────────────────────────────────────

fn format_timestamp(sec: i64, usec: i64) -> String {
    let h = (sec % 86_400) / 3_600;
    let m = (sec % 3_600) / 60;
    let s =  sec % 60;
    format!("{h:02}:{m:02}:{s:02}.{usec:06}")
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}..", &s[..max.saturating_sub(2)]) }
}

// ─── usage ────────────────────────────────────────────────────────────────────

fn print_usage() {
    const B: &str = "\x1b[1m";         // bold
    const C: &str = "\x1b[1;36m";      // cyan heading
    const Y: &str = "\x1b[33m";        // yellow command
    const R: &str = "\x1b[0m";         // reset

    println!("{B}pktana{R}  —  Linux packet analyser & network inspector");
    println!("        replaces: tcpdump  ethtool  ss  netstat  ip route  ip link  iftop");
    println!();
    println!("  {Y}pktana help <COMMAND>{R}   — show detailed documentation for any command");
    println!();

    println!("{C}PACKET CAPTURE  (requires root or CAP_NET_RAW){R}");
    println!("  {Y}pktana <IFACE>{R}                 live capture, unlimited  (Ctrl+C to stop)");
    println!("  {Y}pktana <IFACE> <N>{R}             capture exactly N packets then exit");
    println!("  {Y}pktana <IFACE> <BPF>{R}           unlimited capture with BPF filter");
    println!("  {Y}pktana <IFACE> <N> <BPF>{R}       N packets matching BPF filter");
    println!("  {Y}pktana capture <IFACE> ...{R}      same as above (explicit subcommand)");
    println!("  {Y}pktana interfaces{R}               list all pcap-capable interfaces");
    println!();

    println!("{C}DEEP PACKET INSPECTION  (offline / no capture needed){R}");
    println!("  {Y}pktana inspect <HEX>{R}            full layer-by-layer decode + auto-diagnosis");
    println!("  {Y}pktana inspect -f <FILE>{R}        inspect first hex packet from file");
    println!("  {Y}pktana hex <HEX>{R}                quick field table (shorter than inspect)");
    println!("  {Y}pktana file <FILE>{R}              decode all hex packets in file (one per line)");
    println!("  {Y}pktana demo{R}                     decode built-in sample packets");
    println!();

    println!("{C}INTERFACE & NIC INFO  (reads sysfs/procfs — no external tools){R}");
    println!("  {Y}pktana nic{R}                      list all NICs: state / MAC / IP / speed");
    println!("  {Y}pktana nic <IFACE>{R}              full NIC detail + RX/TX counters");
    println!("  {Y}pktana ethtool <IFACE>{R}          driver · link · offloads · queues · IRQ affinity");
    println!("  {Y}pktana dp <IFACE>{R}               dataplane: XDP · AF_XDP · DPDK · SR-IOV · offloads");
    println!("  {Y}pktana route{R}                    full routing table (IPv4 + IPv6)");
    println!("  {Y}pktana route <IFACE>{R}            routes and nexthops for one interface");
    println!();

    println!("{C}LIVE NETWORK MONITORING{R}");
    println!("  {Y}pktana conn{R}                     TCP/UDP connections + PID  (replaces ss / netstat)");
    println!("  {Y}pktana stats <IFACE>{R}            live dashboard: PPS · BPS · proto breakdown · top talkers");
    println!("  {Y}pktana watch <IFACE> [SECS]{R}     auto-refresh NIC counters every N seconds  (default 2)");
    println!();

    println!("{C}QUICK EXAMPLES{R}");
    println!("  pktana eth0                               # capture everything on eth0");
    println!("  pktana eth0 100 'tcp port 443'            # 100 HTTPS packets");
    println!("  pktana eth0 'host 10.0.0.1'              # traffic to/from one host");
    println!("  pktana nic eth0                           # NIC status + counters");
    println!("  pktana ethtool eth0                       # driver + offloads + queues");
    println!("  pktana dp eth0                            # XDP/DPDK/SR-IOV detection");
    println!("  pktana inspect <hex>                      # decode raw packet bytes");
    println!("  pktana stats eth0                         # live traffic dashboard");
    println!("  pktana conn                               # active connections");
    println!("  pktana route                              # routing table");
    println!();
    println!("  Run {Y}pktana help <command>{R} for detailed usage of any command.");
}

// ─── Per-command documentation ────────────────────────────────────────────────

fn print_doc(cmd: &str) -> Result<(), CliError> {
    const B:  &str = "\x1b[1m";
    const C:  &str = "\x1b[1;36m";
    const Y:  &str = "\x1b[33m";
    const DIM: &str = "\x1b[2m";
    const R:  &str = "\x1b[0m";

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
            println!("{B}ARGUMENTS{R}");
            println!("  {Y}IFACE{R}        Network interface name (eth0, ens3, bond0, etc.)");
            println!("  {Y}COUNT{R}        Number of packets to capture then exit. Omit for unlimited.");
            println!("  {Y}BPF_FILTER{R}   Berkeley Packet Filter expression (same syntax as tcpdump).");
            println!("               Quotes required for multi-word filters.");
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
            println!("  pktana eth0 100 udp                      # 100 UDP packets");
            println!("  pktana eth0 \"tcp port 443\"             # HTTPS, unlimited");
            println!("  pktana eth0 200 'host 8.8.8.8'          # 200 pkts to/from 8.8.8.8");
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
            println!("  4. {B}LAYER 3 — IPv4{R}  — IPs, TTL, DSCP, ECN, DF/MF flags, fragment offset");
            println!("  5. {B}LAYER 4 — TCP/UDP/ICMP{R}  — ports, flags, window, options, checksum");
            println!("  6. {B}APPLICATION{R}  — HTTP method/status, TLS version + SNI, DNS query/rcode,");
            println!("                    DHCP message type, and 15+ other protocols");
            println!("  7. {B}PAYLOAD HEX DUMP{R}  — Wireshark-style hex + ASCII (up to 256 bytes)");
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
            println!("  {B}LINK SETTINGS{R}   — speed, duplex, autoneg, operstate, TX queue length");
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
            println!("  {B}KernelStack{R}     — normal path; packets processed by kernel tcp/ip stack");
            println!("  {B}XDP{R}             — eBPF XDP program attached at driver level; can drop/redirect");
            println!("                    before sk_buff allocation (faster than iptables)");
            println!("  {B}AF_XDP{R}          — zero-copy path; packets DMA'd directly to userspace rings,");
            println!("                    bypassing kernel socket layer entirely");
            println!("  {B}DpdkUserspace{R}   — NIC bound to vfio-pci or uio_pci_generic; kernel sees");
            println!("                    no traffic at all; pktana capture will not work");
            println!("  {B}Hybrid{R}          — XDP + AF_XDP active simultaneously");
            println!();
            println!("{B}OUTPUT SECTIONS{R}");
            println!("  Bypass Mode  — detected packet I/O path");
            println!("  XDP          — attached eBPF program IDs");
            println!("  AF_XDP       — count of zero-copy sockets (from /proc/net/xdp)");
            println!("  DPDK/PMD     — vfio/uio binding status and driver name");
            println!("  SR-IOV       — VF/PF role, VF count enabled/total");
            println!("  Queues       — RX / TX / combined queue counts");
            println!("  PCI          — address, vendor ID, device ID, NUMA node");
            println!("  HW Offloads  — features currently enabled");
            println!("  Guidance     — plain-English interpretation + recommendations");
            println!();
            println!("{B}EXAMPLES{R}");
            println!("  pktana dp eth0      # check if eth0 is in DPDK/XDP bypass mode");
            println!("  pktana dp ens3f0    # check SR-IOV PF with VFs");
            println!("{bar}");
        }

        // ── route ─────────────────────────────────────────────────────────────
        "route" | "routes" | "nexthop" => {
            println!("{bar}");
            println!("{B}  pktana route{R}  —  Routing table viewer");
            println!("{bar}");
            println!();
            println!("{B}SYNOPSIS{R}");
            println!("  {Y}pktana route{R}");
            println!("  {Y}pktana route <IFACE>{R}");
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
            println!("  {Y}pktana conn{R}");
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

        // ── unknown ───────────────────────────────────────────────────────────
        other => {
            eprintln!("pktana: no documentation found for '{other}'");
            eprintln!();
            eprintln!("Available topics:");
            eprintln!("  capture  inspect  nic  ethtool  dp  route  conn  stats  watch  hex  file  demo");
            return Err(CliError::Usage(format!("unknown help topic '{other}'")));
        }
    }
    Ok(())
}

// ─── ethtool-equivalent inspector ────────────────────────────────────────────

fn run_ethtool(args: &[String]) -> Result<(), CliError> {
    let name = match args.first() {
        Some(n) => n.as_str(),
        None    => return Err(CliError::Usage("usage: pktana ethtool <INTERFACE>".into())),
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
    println!("    firmware    : {}", r.firmware_ver.as_deref().unwrap_or("n/a"));
    println!("    pci-rev     : {}", r.pci_revision.as_deref().unwrap_or("—"));
    println!("    irq         : {}", r.irq.map(|n| n.to_string()).as_deref().unwrap_or("—"));

    // ── Link settings (-s equivalent) ─────────────────────────────────────────
    println!();
    println!("  LINK SETTINGS");
    println!("  ───────────────────────────────────────");
    let speed_str = match r.speed_mbps {
        Some(s) if s >= 1000 => format!("{}G", s / 1000),
        Some(s)              => format!("{s}M"),
        None                 => "unknown".into(),
    };
    println!("    speed       : {speed_str}");
    println!("    duplex      : {}", r.duplex.as_deref().unwrap_or("—"));
    println!("    auto-neg    : {}", r.autoneg.as_deref().unwrap_or("—"));
    println!("    state       : {}", r.operstate);
    println!("    carrier     : {}",
        match r.carrier { Some(1) => "UP", Some(0) => "DOWN", _ => "—" });
    println!("    tx-queue-len: {}", r.tx_queue_len.map(|n| n.to_string()).as_deref().unwrap_or("—"));

    // ── PCIe link ─────────────────────────────────────────────────────────────
    if r.pcie_speed.is_some() || r.pcie_width.is_some() {
        println!();
        println!("  PCIe LINK");
        println!("  ───────────────────────────────────────");
        println!("    speed       : {}", r.pcie_speed.as_deref().unwrap_or("—"));
        println!("    width       : {}",
            r.pcie_width.map(|w| format!("x{w}")).as_deref().unwrap_or("—"));
    }

    // ── Carrier events ────────────────────────────────────────────────────────
    println!();
    println!("  CARRIER EVENTS");
    println!("  ───────────────────────────────────────");
    println!("    up          : {}", r.carrier_up.map(|n| n.to_string()).as_deref().unwrap_or("—"));
    println!("    down        : {}", r.carrier_down.map(|n| n.to_string()).as_deref().unwrap_or("—"));
    println!("    changes     : {}", r.carrier_changes.map(|n| n.to_string()).as_deref().unwrap_or("—"));

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
        let on:  Vec<&str> = r.features.iter().filter(|(_, v)| v.as_str() == "on" ).map(|(k, _)| k.as_str()).collect();
        let off: Vec<&str> = r.features.iter().filter(|(_, v)| v.as_str() == "off").map(|(k, _)| k.as_str()).collect();
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
        println!("    {:<32}  {:<6}  {:<14}  {}",
            "Queue", "IRQ", "SMP mask", "CPU list");
        println!("    {}", "─".repeat(70));
        for q in &r.queue_irq_affinities {
            let irq_s = if q.irq == 0 { "—".to_string() } else { q.irq.to_string() };
            println!("    {:<32}  {:<6}  {:<14}  {}",
                trunc(&q.queue_name, 32), irq_s, q.cpu_mask, q.cpu_list);
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
                [(k1, v1), (k2, v2)] =>
                    println!("    {:<32}  {:>12}    {:<32}  {:>12}", k1, v1, k2, v2),
                [(k1, v1)] =>
                    println!("    {:<32}  {:>12}", k1, v1),
                _ => {}
            }
        }
    }

    println!();
    Ok(())
}

// ─── dataplane / bypass inspector ────────────────────────────────────────────

fn run_dataplane(args: &[String]) -> Result<(), CliError> {
    let name = match args.first() {
        Some(n) => n.as_str(),
        None    => return Err(CliError::Usage("usage: pktana dp <INTERFACE>".into())),
    };

    let dp = get_nic_dataplane(name)?;

    println!("Dataplane Profile — {name}");
    println!("{}", "═".repeat(56));
    println!();

    // ── Bypass / PMD mode ────────────────────────────────────────────────────
    println!("  Bypass Mode    : {}", dp.bypass_mode);
    println!();

    // ── XDP ──────────────────────────────────────────────────────────────────
    if dp.xdp_prog_ids.is_empty() {
        println!("  XDP            : not attached");
    } else {
        let ids: Vec<String> = dp.xdp_prog_ids.iter().map(|id| id.to_string()).collect();
        println!("  XDP            : ATTACHED  (prog IDs: {})", ids.join(", "));
    }

    // ── AF_XDP ───────────────────────────────────────────────────────────────
    if dp.afxdp_sockets == 0 {
        println!("  AF_XDP sockets : none");
    } else {
        println!("  AF_XDP sockets : {}  ← zero-copy userspace rings active", dp.afxdp_sockets);
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

    // ── PCI identity ──────────────────────────────────────────────────────────
    println!("  PCI");
    println!("    Address      : {}", dp.pci_address.as_deref().unwrap_or("—"));
    println!("    Vendor ID    : {}", dp.pci_vendor_id.as_deref().unwrap_or("—"));
    println!("    Device ID    : {}", dp.pci_device_id.as_deref().unwrap_or("—"));
    println!("    NUMA node    : {}",
        dp.numa_node.map(|n| n.to_string()).as_deref().unwrap_or("—"));

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

    // ── Guidance ─────────────────────────────────────────────────────────────
    println!("  Guidance");
    match dp.bypass_mode {
        pktana_core::BypassMode::KernelStack => {
            println!("    Packets are processed by the Linux kernel network stack.");
            println!("    To enable zero-copy: load an AF_XDP program or bind to DPDK.");
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

    Ok(())
}

// ─── routing table / nexthop ──────────────────────────────────────────────────

fn run_routes(args: &[String]) -> Result<(), CliError> {
    let routes = match args.first() {
        Some(iface) => {
            let r = routes_for_iface(iface);
            if r.is_empty() {
                println!("No routes found for interface '{iface}'.");
                return Ok(());
            }
            println!("Routes for {iface}:\n");
            r
        }
        None => {
            let r = list_routes();
            if r.is_empty() {
                println!("No routes found.");
                return Ok(());
            }
            println!("Routing Table (IPv4 + IPv6):\n");
            r
        }
    };

    println!(
        "{:<16}  {:<24}  {:<8}  {:<26}  {:<8}  {}",
        "Interface", "Destination", "Prefix", "Gateway / Nexthop", "Metric", "Type"
    );
    println!("{}", "─".repeat(100));

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

fn run_connections() -> Result<(), CliError> {
    let conns = list_connections();
    if conns.is_empty() {
        println!("No connections found (run as root to see all processes).");
        return Ok(());
    }
    println!("Active Connections ({})\n", conns.len());
    println!(
        "{:<5}  {:<28}  {:<28}  {:<13}  {:<6}  {}",
        "Proto", "Local Address", "Remote Address", "State", "PID", "Process"
    );
    println!("{}", "─".repeat(100));
    for c in &conns {
        let local  = format!("{}:{}", c.local_ip,  c.local_port);
        let remote = if c.remote_port == 0 {
            "—".to_string()
        } else {
            format!("{}:{}", c.remote_ip, c.remote_port)
        };
        let pid_s  = c.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string());
        let proc_s = c.process.as_deref().unwrap_or("—");
        println!(
            "{:<5}  {:<28}  {:<28}  {:<13}  {:<6}  {}",
            c.proto,
            trunc(&local, 28),
            trunc(&remote, 28),
            c.state, pid_s, proc_s,
        );
    }
    Ok(())
}

// ─── live stats dashboard ─────────────────────────────────────────────────────

struct LiveStats {
    interface:   String,
    start:       Instant,
    last_tick:   Instant,
    total_pkts:  u64,
    total_bytes: u64,
    win_pkts:    u64,
    win_bytes:   u64,
    proto:       HashMap<String, (u64, u64)>,   // proto  -> (pkts, bytes)
    talkers:     HashMap<String, (u64, u64)>,   // src_ip -> (pkts, bytes)
}

impl LiveStats {
    fn new(interface: &str) -> Self {
        let now = Instant::now();
        Self {
            interface:   interface.to_string(),
            start:       now,
            last_tick:   now,
            total_pkts:  0,
            total_bytes: 0,
            win_pkts:    0,
            win_bytes:   0,
            proto:       HashMap::new(),
            talkers:     HashMap::new(),
        }
    }

    fn ingest(&mut self, src_ip: &str, proto: &str, bytes: usize) {
        let b = bytes as u64;
        self.total_pkts  += 1;
        self.total_bytes += b;
        self.win_pkts    += 1;
        self.win_bytes   += b;
        let pe = self.proto.entry(proto.to_string()).or_insert((0, 0));
        pe.0 += 1; pe.1 += b;
        // cap talkers map at 5 000 unique IPs
        if self.talkers.len() < 5_000 || self.talkers.contains_key(src_ip) {
            let te = self.talkers.entry(src_ip.to_string()).or_insert((0, 0));
            te.0 += 1; te.1 += b;
        }
    }

    fn tick_and_render(&mut self) {
        let elapsed = self.last_tick.elapsed();
        if elapsed < Duration::from_millis(950) { return; }
        let secs      = elapsed.as_secs_f64();
        let pps       = self.win_pkts  as f64 / secs;
        let bps       = self.win_bytes as f64 / secs;
        let total_sec = self.start.elapsed().as_secs();

        // clear screen, start at top
        print!("\x1b[H\x1b[J");

        println!(
            "pktana LIVE STATS — {}   [elapsed {:02}h {:02}m {:02}s]  Ctrl+C to stop",
            self.interface,
            total_sec / 3600,
            (total_sec % 3600) / 60,
            total_sec % 60,
        );
        println!("{}", "═".repeat(72));
        println!();
        println!("  Rate (last {}s)  :  {:>8.0} pkt/s   {}/s",
            elapsed.as_secs().max(1), pps, format_bytes(bps as u64));
        println!("  Total           :  {:>8} pkts    {}",
            self.total_pkts, format_bytes(self.total_bytes));
        println!();

        // Protocol breakdown
        println!("  Protocol Breakdown:");
        let total = self.total_pkts.max(1);
        let mut protos: Vec<(&String, &(u64, u64))> = self.proto.iter().collect();
        protos.sort_by(|a, b| b.1.0.cmp(&a.1.0));
        for (name, (pkts, bytes)) in protos.iter().take(6) {
            let pct = *pkts as f64 / total as f64 * 100.0;
            println!("    {:6}  {}  {:5.1}%  {:>8} pkts  {}",
                name, ascii_bar(pct, 28), pct, pkts, format_bytes(*bytes));
        }
        println!();

        // Top talkers
        println!("  Top Talkers (by packets):");
        let mut talkers: Vec<(&String, &(u64, u64))> = self.talkers.iter().collect();
        talkers.sort_by(|a, b| b.1.0.cmp(&a.1.0));
        for (i, (ip, (pkts, bytes))) in talkers.iter().take(10).enumerate() {
            println!("    {:>2}.  {:<26}  {:>8} pkts   {}",
                i + 1, ip, pkts, format_bytes(*bytes));
        }

        let _ = std::io::stdout().flush();

        // reset window counters
        self.win_pkts  = 0;
        self.win_bytes = 0;
        self.last_tick = Instant::now();

        // trim talkers if huge
        if self.talkers.len() > 5_000 {
            let mut v: Vec<(String, (u64, u64))> = self.talkers.drain().collect();
            v.sort_by(|a, b| b.1.0.cmp(&a.1.0));
            v.truncate(1_000);
            self.talkers = v.into_iter().collect();
        }
    }
}

fn run_stats(args: &[String]) -> Result<(), CliError> {
    if args.is_empty() {
        return Err(CliError::Usage("usage: pktana stats <INTERFACE> [BPF_FILTER]".into()));
    }
    let interface = &args[0];
    let filter = if args.len() > 1 { Some(args[1..].join(" ")) } else { None };
    let config = CaptureConfig {
        interface:    interface.clone(),
        max_packets:  usize::MAX,
        promiscuous:  true,
        snapshot_len: 65_535,
        filter,
    };
    let mut live = LiveStats::new(interface);
    // initial clear so first render starts at top
    print!("\x1b[2J");
    LinuxCaptureEngine::capture_streaming(&config, |pkt| {
        if let Ok(parsed) = analyze_bytes(&pkt.data) {
            let s   = &parsed.summary;
            let src = s.ipv4.as_ref()
                .map(|ip| ip.source.to_string())
                .unwrap_or_else(|| s.ethernet.source_mac());
            live.ingest(&src, s.proto_label(), pkt.data.len());
        }
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
        return Err(CliError::Usage("usage: pktana watch <INTERFACE> [INTERVAL_SECS]".into()));
    }
    let name     = &args[0];
    let interval = args.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(2);
    loop {
        print!("\x1b[H\x1b[J");
        match get_nic_info(name) {
            Ok(nic) => print_nic_watch(&nic, interval),
            Err(e)  => println!("Error reading {name}: {e}"),
        }
        let _ = std::io::stdout().flush();
        thread::sleep(Duration::from_secs(interval));
    }
}

fn print_nic_watch(nic: &NicInfo, interval: u64) {
    println!("pktana watch — {}   (every {}s, Ctrl+C to stop)", nic.name, interval);
    println!("{}", "─".repeat(52));
    println!();
    println!("  Interface : {}",  nic.name);
    println!("  State     : {}",  if nic.is_up() { "UP" } else { "down" });
    println!("  MAC       : {}",  nic.mac);
    println!("  MTU       : {}",  nic.mtu);
    println!("  Speed     : {} / {}", nic.speed_label(), nic.duplex.as_deref().unwrap_or("?"));
    if !nic.ip_addresses.is_empty() {
        println!("  Addresses : {}", nic.ip_addresses.join(", "));
    }
    println!();
    println!("  {:4}  {:>12}  {:>12}  {:>10}  {:>10}",
        "", "Packets", "Bytes", "Errors", "Dropped");
    println!("  {}", "─".repeat(55));
    println!("  {:4}  {:>12}  {:>12}  {:>10}  {:>10}",
        "RX", nic.rx_packets, format_bytes(nic.rx_bytes), nic.rx_errors, nic.rx_dropped);
    println!("  {:4}  {:>12}  {:>12}  {:>10}  {:>10}",
        "TX", nic.tx_packets, format_bytes(nic.tx_bytes), nic.tx_errors, nic.tx_dropped);
}

// ─── DNS decode ───────────────────────────────────────────────────────────────

/// Try to decode a DNS query or response from the raw packet bytes.
/// Returns Some("DNS Query: example.com A") / Some("DNS Reply: example.com A") or None.
fn dns_decode(pkt: &ParsedPacket) -> Option<String> {
    let ip = pkt.summary.ipv4.as_ref()?;
    let (src_port, dst_port) = match &pkt.summary.transport {
        Some(TransportHeader::Udp { source_port, destination_port, .. }) =>
            (*source_port, *destination_port),
        _ => return None,
    };
    if src_port != 53 && dst_port != 53 { return None; }

    // DNS payload starts after: 14 (eth) + ip_header + 8 (udp header)
    let dns_start = 14 + ip.header_length + 8;
    let data = pkt.raw.get(dns_start..)?;
    if data.len() < 12 { return None; }

    let flags    = u16::from_be_bytes([data[2], data[3]]);
    let is_resp  = (flags & 0x8000) != 0;
    let qdcount  = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 { return None; }

    let name = dns_parse_name(data, 12)?;
    if name.is_empty() { return None; }

    // QTYPE is right after the name
    let name_end = 12 + dns_name_len(data, 12);
    let qtype    = u16::from_be_bytes([
        *data.get(name_end)?,
        *data.get(name_end + 1)?,
    ]);
    let type_str = dns_type_str(qtype);
    let verb     = if is_resp { "Reply" } else { "Query" };

    // Rcode for replies
    let rcode_str = if is_resp {
        let rcode = flags & 0x000F;
        if rcode == 3 { " [NXDOMAIN]" } else { "" }
    } else { "" };

    Some(format!("DNS {verb}: {name} {type_str}{rcode_str}"))
}

fn dns_parse_name(data: &[u8], mut pos: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut hops   = 0;
    loop {
        if hops > 20 { return None; }
        let len = *data.get(pos)? as usize;
        if len == 0 { break; }
        if len & 0xC0 == 0xC0 {
            // Compression pointer
            let ptr = ((len & 0x3F) << 8) | (*data.get(pos + 1)? as usize);
            pos  = ptr;
            hops += 1;
            continue;
        }
        pos += 1;
        let label = std::str::from_utf8(data.get(pos..pos + len)?).ok()?;
        labels.push(label);
        pos += len;
    }
    Some(labels.join("."))
}

/// Number of bytes the name occupies in the DNS wire format (incl. final 0x00 or 2-byte pointer).
fn dns_name_len(data: &[u8], mut pos: usize) -> usize {
    let start = pos;
    loop {
        let len = match data.get(pos) { Some(&l) => l as usize, None => break };
        if len == 0 { pos += 1; break; }
        if len & 0xC0 == 0xC0 { pos += 2; break; }
        pos += 1 + len;
    }
    pos - start
}

fn dns_type_str(t: u16) -> &'static str {
    match t {
        1   => "A",
        2   => "NS",
        5   => "CNAME",
        6   => "SOA",
        12  => "PTR",
        15  => "MX",
        16  => "TXT",
        28  => "AAAA",
        33  => "SRV",
        255 => "ANY",
        _   => "?",
    }
}

