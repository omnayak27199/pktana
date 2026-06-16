// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

pub mod inner {
    use dashmap::DashMap;
    use pktana_core::{
        build_socket_process_map, geoip_lookup_str, get_ethtool_report, get_nic_dataplane,
        get_nic_info, hex_dump, inspect, list_connections, list_nics, list_routes, CaptureConfig,
        LinuxCaptureEngine, ProcessInfo, SocketId,
    };
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // Session Management Structures
    #[derive(Debug, Clone)]
    struct CaptureSession {
        id: String,
        interface: String,
        filter: Option<String>,
        started_at: u64,
        packet_count: usize,
        bytes_captured: usize,
        status: SessionStatus,
    }

    #[derive(Debug, Clone, PartialEq)]
    #[allow(dead_code)]
    enum SessionStatus {
        Active,
        Paused,
        Stopped,
    }

    impl SessionStatus {
        fn as_str(&self) -> &str {
            match self {
                SessionStatus::Active => "active",
                SessionStatus::Paused => "paused",
                SessionStatus::Stopped => "stopped",
            }
        }
    }

    // Global session storage - using DashMap for lock-free concurrent access
    lazy_static::lazy_static! {
        static ref SESSIONS: Arc<DashMap<String, CaptureSession>> = Arc::new(DashMap::new());
        // Global cached process map - updated by background thread every 2 seconds
        static ref PROCESS_MAP: Arc<DashMap<SocketId, ProcessInfo>> = Arc::new(DashMap::new());
    }

    // Start background thread to update process map periodically
    fn start_process_map_updater() {
        thread::spawn(|| loop {
            let new_map = build_socket_process_map();
            PROCESS_MAP.clear();
            for (k, v) in new_map {
                PROCESS_MAP.insert(k, v);
            }
            thread::sleep(Duration::from_secs(2));
        });
    }

    impl CaptureSession {
        fn new(interface: String, filter: Option<String>) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let id = format!("{}-{}", interface, now);

            Self {
                id,
                interface,
                filter,
                started_at: now,
                packet_count: 0,
                bytes_captured: 0,
                status: SessionStatus::Active,
            }
        }

        fn to_json(&self) -> String {
            format!(
                r#"{{"id":"{}","interface":"{}","filter":"{}","started_at":{},"packet_count":{},"bytes_captured":{},"status":"{}"}}"#,
                escape_json(&self.id),
                escape_json(&self.interface),
                escape_json(&self.filter.clone().unwrap_or_default()),
                self.started_at,
                self.packet_count,
                self.bytes_captured,
                self.status.as_str()
            )
        }
    }

    pub fn run_web_server(port: u16) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).map_err(|e| e.to_string())?;

        // Start background thread to update process map every 2 seconds
        start_process_map_updater();

        println!("Starting pktana Web UI on http://{}", addr);
        println!();
        println!("Access the Web UI:");
        println!("  • Browser:   http://localhost:{}", port);
        println!("  • curl:      curl http://localhost:{}", port);
        println!("  • Remote:    curl http://<your-ip>:{}", port);
        println!();
        println!("Press Ctrl+C to stop.");

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    thread::spawn(move || {
                        handle_client(&mut stream);
                    });
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
        Ok(())
    }

    fn decode_url(url: &str) -> String {
        let mut decoded = String::new();
        let mut chars = url.chars();
        while let Some(c) = chars.next() {
            if c == '%' {
                let h1 = chars.next().unwrap_or('0');
                let h2 = chars.next().unwrap_or('0');
                if let Ok(b) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                    decoded.push(b as char);
                }
            } else if c == '+' {
                decoded.push(' ');
            } else {
                decoded.push(c);
            }
        }
        decoded
    }

    fn escape_json(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 10);
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{00}'..='\u{1F}' => out.push_str(&format!("\\u{:04x}", c as u32)),
                _ => out.push(c),
            }
        }
        out
    }

    fn build_dpi_text(
        dp: &pktana_core::DeepPacket,
        proc_map: &DashMap<SocketId, ProcessInfo>,
        ts_sec: i64,
        ts_usec: i64,
    ) -> String {
        let mut lines = Vec::new();

        // Timing & Length
        let time_str = {
            let t = ts_sec % 86400;
            let h = t / 3600;
            let m = (t % 3600) / 60;
            let s = t % 60;
            format!("{:02}:{:02}:{:02}.{:06}", h, m, s, ts_usec)
        };
        lines.push(format!(
            "-- OVERVIEW\n  Time: {}\n  Frame length: {} bytes",
            time_str, dp.frame_len
        ));

        // Layer 2
        lines.push(format!(
            "-- LAYER 2: ETHERNET\n  Source MAC: {} ({})\n  Dest MAC: {} ({})\n  EtherType: 0x{:04x} ({})",
            dp.eth_src, dp.eth_vendor_src.unwrap_or("?"),
            dp.eth_dst, dp.eth_vendor_dst.unwrap_or("?"),
            dp.ether_type, dp.ether_type_name
        ));

        for vlan in &dp.vlan_tags {
            lines.push(format!(
                "  VLAN: ID={} PCP={} DEI={}",
                vlan.id, vlan.pcp, vlan.dei
            ));
        }

        if let Some(arp) = &dp.arp {
            lines.push(format!(
                "-- ARP\n  Operation: {}\n  Sender: {} ({})\n  Target: {} ({})",
                arp.operation, arp.sender_ip, arp.sender_mac, arp.target_ip, arp.target_mac
            ));
        }

        // Layer 3
        if let Some(ver) = dp.ip_version {
            if ver == 4 {
                lines.push("-- LAYER 3: IPv4".to_string());
                if let (Some(s), Some(d)) = (dp.ip_src, dp.ip_dst) {
                    lines.push(format!("  Source IP: {}", s));
                    lines.push(format!("  Dest IP: {}", d));
                }
                if let Some(ttl) = dp.ip_ttl {
                    lines.push(format!("  TTL: {}", ttl));
                }
                if let Some(p) = dp.ip_proto_name {
                    lines.push(format!("  Protocol: {} ({})", p, dp.ip_proto.unwrap_or(0)));
                }
                if let Some(id) = dp.ip_id {
                    lines.push(format!("  Identification: 0x{:04x}", id));
                }
                if let Some(hdr_len) = dp.ip_hdr_len {
                    lines.push(format!("  Header Length: {} bytes", hdr_len));
                }
                if let Some(total_len) = dp.ip_total_len {
                    lines.push(format!("  Total Length: {} bytes", total_len));
                }
                lines.push(format!(
                    "  Flags: DF={} MF={}",
                    dp.ip_flag_df, dp.ip_flag_mf
                ));
                if let Some(dscp) = dp.ip_dscp {
                    lines.push(format!("  DSCP: {} (QoS class)", dscp));
                }
                if let Some(ecn) = dp.ip_ecn {
                    lines.push(format!("  ECN: {}", ecn));
                }
                if let Some(frag) = dp.ip_fragment {
                    if frag > 0 {
                        lines.push(format!("  Fragment Offset: {}", frag));
                    }
                }
            } else if ver == 6 {
                lines.push("-- LAYER 3: IPv6".to_string());
                if let (Some(s), Some(d)) = (&dp.ipv6_src, &dp.ipv6_dst) {
                    lines.push(format!("  Source IP: {}", s));
                    lines.push(format!("  Dest IP: {}", d));
                }
                if let Some(hl) = dp.ipv6_hop_limit {
                    lines.push(format!("  Hop Limit: {}", hl));
                }
                if let Some(nh) = dp.ipv6_next_header {
                    lines.push(format!("  Next Header: {}", nh));
                }
            }
        }

        // Geography
        let mut geo_added = false;
        if let Some(dst) = dp.ip_dst {
            if let Some(geo) = pktana_core::geoip_lookup_str(&dst.to_string()) {
                if geo.country_code != "--" {
                    if !geo_added {
                        lines.push("-- GEOGRAPHY".to_string());
                        geo_added = true;
                    }
                    lines.push(format!(
                        "  Destination: {} ({}) - {}",
                        geo.country_name, geo.country_code, geo.continent
                    ));
                }
            }
        }
        if let Some(src) = dp.ip_src {
            if let Some(geo) = pktana_core::geoip_lookup_str(&src.to_string()) {
                if geo.country_code != "--" {
                    if !geo_added {
                        lines.push("-- GEOGRAPHY".to_string());
                    }
                    lines.push(format!(
                        "  Source: {} ({}) - {}",
                        geo.country_name, geo.country_code, geo.continent
                    ));
                }
            }
        }

        // Layer 4
        if let Some(sp) = dp.tcp_src_port {
            lines.push("-- LAYER 4: TCP".to_string());
            lines.push(format!("  Src Port: {}", sp));
            lines.push(format!("  Dst Port: {}", dp.tcp_dst_port.unwrap_or(0)));
            if let Some(s) = dp.tcp_seq {
                lines.push(format!("  Seq: {}", s));
            }
            if let Some(a) = dp.tcp_ack {
                lines.push(format!("  Ack: {}", a));
            }
            if let Some(f) = &dp.tcp_flags_str {
                lines.push(format!("  Flags: {}", f));
            }
            if let Some(w) = dp.tcp_window {
                lines.push(format!("  Window: {} bytes", w));
            }
            if let Some(u) = dp.tcp_urgent {
                if u > 0 {
                    lines.push(format!("  Urgent Pointer: {}", u));
                }
            }
            if let Some(m) = dp.tcp_mss {
                lines.push(format!("  MSS: {}", m));
            }
            if let Some(ws) = dp.tcp_window_scale {
                lines.push(format!("  Win Scale: x{}", ws));
            }
            if dp.tcp_sack_permitted {
                lines.push("  SACK: permitted".to_string());
            }
            if !dp.tcp_sack_blocks.is_empty() {
                for (i, (left, right)) in dp.tcp_sack_blocks.iter().enumerate() {
                    lines.push(format!("  SACK Block {}: {} - {}", i + 1, left, right));
                }
            }
            if let Some((ts_val, ts_ecr)) = dp.tcp_timestamp {
                lines.push(format!("  Timestamp: TSval={} TSecr={}", ts_val, ts_ecr));
            }
            if let Some(hdr_len) = dp.tcp_hdr_len {
                lines.push(format!("  Header len: {} bytes", hdr_len));
            }
            lines.push(format!("  Payload len: {} bytes", dp.tcp_payload_len));
        } else if let Some(sp) = dp.udp_src_port {
            lines.push("-- LAYER 4: UDP".to_string());
            lines.push(format!("  Src Port: {}", sp));
            lines.push(format!("  Dst Port: {}", dp.udp_dst_port.unwrap_or(0)));
            if let Some(l) = dp.udp_len {
                lines.push(format!("  Length: {}", l));
            }
            if let Some(cs) = dp.udp_checksum {
                lines.push(format!("  Checksum: 0x{:04x}", cs));
            }
            lines.push(format!("  Payload len: {} bytes", dp.udp_payload_len));
        } else if let Some(t) = dp.icmp_type {
            lines.push("-- LAYER 4: ICMP".to_string());
            lines.push(format!("  Type: {}", t));
            if let Some(c) = dp.icmp_code {
                lines.push(format!("  Code: {}", c));
            }
            if let Some(s) = &dp.icmp_type_str {
                lines.push(format!("  Info: {}", s));
            }
            if let Some(id) = dp.icmp_id {
                lines.push(format!("  Identifier: {}", id));
            }
            if let Some(seq) = dp.icmp_seq {
                lines.push(format!("  Sequence: {}", seq));
            }
            if let Some(cs) = dp.icmp_checksum {
                lines.push(format!("  Checksum: 0x{:04x}", cs));
            }
        }

        // Process Mapping
        if let (Some(s_ip), Some(d_ip), Some(s_port), Some(d_port)) = (
            dp.ip_src,
            dp.ip_dst,
            dp.tcp_src_port.or(dp.udp_src_port),
            dp.tcp_dst_port.or(dp.udp_dst_port),
        ) {
            let sid1 = SocketId::new(IpAddr::V4(s_ip), s_port, IpAddr::V4(d_ip), d_port);
            let sid2 = SocketId::new(IpAddr::V4(d_ip), d_port, IpAddr::V4(s_ip), s_port);
            if let Some(p) = proc_map.get(&sid1).or_else(|| proc_map.get(&sid2)) {
                lines.push("-- PROCESS / HOST".to_string());
                lines.push(format!("  Process: {} (PID {})", p.name, p.pid));
                lines.push(format!("  Cmdline: {}", p.cmdline.replace('\0', " ")));
            }
        } else if let (Some(s_ip), Some(d_ip), Some(s_port), Some(d_port)) = (
            &dp.ipv6_src,
            &dp.ipv6_dst,
            dp.tcp_src_port.or(dp.udp_src_port),
            dp.tcp_dst_port.or(dp.udp_dst_port),
        ) {
            if let (Ok(s_addr), Ok(d_addr)) = (s_ip.parse::<IpAddr>(), d_ip.parse::<IpAddr>()) {
                let sid1 = SocketId::new(s_addr, s_port, d_addr, d_port);
                let sid2 = SocketId::new(d_addr, d_port, s_addr, s_port);
                if let Some(p) = proc_map.get(&sid1).or_else(|| proc_map.get(&sid2)) {
                    lines.push("-- PROCESS / HOST".to_string());
                    lines.push(format!("  Process: {} (PID {})", p.name, p.pid));
                    lines.push(format!("  Cmdline: {}", p.cmdline.replace('\0', " ")));
                }
            }
        }

        // Layer 7
        if let Some(ap) = &dp.app_proto {
            lines.push(format!("-- APPLICATION ({})", ap));
            for d in &dp.app_detail {
                lines.push(format!("  {}", d));
            }
        }

        // QUIC
        if dp.quic_detected {
            lines.push("-- QUIC / HTTP3".to_string());
            if let Some(pt) = dp.quic_packet_type {
                lines.push(format!("  Packet Type: {}", pt));
            }
            if let Some(v) = dp.quic_version {
                lines.push(format!("  Version: 0x{:08x}", v));
            }
        }

        // HTTP/2 & gRPC
        if dp.http2_detected {
            lines.push("-- HTTP/2".to_string());
            lines.push("  Protocol: HTTP/2 detected".to_string());
            if let Some(grpc) = &dp.grpc_path {
                lines.push(format!("  gRPC Path: {}", grpc));
            }
        }

        // WebSocket
        if dp.ws_upgrade {
            lines.push("-- WEBSOCKET".to_string());
            lines.push("  WebSocket Upgrade detected".to_string());
        }

        // SSH
        if let Some(b) = &dp.ssh_banner {
            lines.push("-- SSH".to_string());
            lines.push(format!("  Banner: {}", b));
        }

        // SIP
        if let Some(m) = &dp.sip_method {
            lines.push("-- SIP / VoIP".to_string());
            lines.push(format!("  Method: {}", m));
            if let Some(u) = &dp.sip_uri {
                lines.push(format!("  URI: {}", u));
            }
            if let Some(c) = &dp.sip_call_id {
                lines.push(format!("  Call-ID: {}", c));
            }
        }

        // NTP
        if let Some(v) = dp.ntp_version {
            lines.push("-- NTP".to_string());
            lines.push(format!("  Version: NTPv{}", v));
            if let Some(m) = dp.ntp_mode {
                let mode_str = match m {
                    1 => "Symmetric Active",
                    2 => "Symmetric Passive",
                    3 => "Client",
                    4 => "Server",
                    5 => "Broadcast",
                    6 => "NTP Control",
                    7 => "Reserved",
                    _ => "Unknown",
                };
                lines.push(format!("  Mode: {} ({})", m, mode_str));
            }
            if let Some(s) = dp.ntp_stratum {
                lines.push(format!("  Stratum: {}", s));
            }
            if dp.ntp_amplification_risk {
                lines.push("  [!] AMPLIFICATION RISK: Response > 468 bytes".to_string());
            }
        }

        // BGP
        if let Some(mt) = &dp.bgp_msg_type {
            lines.push("-- BGP".to_string());
            lines.push(format!("  Msg Type: {}", mt));
            if let Some(a) = dp.bgp_asn {
                lines.push(format!("  AS Number: {}", a));
            }
        }

        // Tunnel
        if let Some(tt) = &dp.tunnel_type {
            lines.push(format!("-- TUNNEL ({})", tt));
            if let (Some(s), Some(d)) = (dp.inner_ip_src, dp.inner_ip_dst) {
                lines.push(format!("  Inner Src: {}", s));
                lines.push(format!("  Inner Dst: {}", d));
            }
            if let Some(p) = dp.inner_proto {
                lines.push(format!("  Inner Proto: {}", p));
            }
            if let (Some(sp), Some(dp2)) = (dp.inner_src_port, dp.inner_dst_port) {
                lines.push(format!("  Inner Ports: {} -> {}", sp, dp2));
            }
            if let Some(ap) = &dp.inner_app_proto {
                lines.push(format!("  Inner App: {}", ap));
            }
        }

        // TLS Fingerprint
        if dp.tls_ja3_raw.is_some() || !dp.tls_alpn.is_empty() || !dp.tls_ciphers.is_empty() {
            lines.push("-- TLS FINGERPRINT".to_string());
            if !dp.tls_alpn.is_empty() {
                lines.push(format!("  ALPN: {}", dp.tls_alpn.join(", ")));
            }
            if let Some(ja3) = &dp.tls_ja3_raw {
                lines.push(format!("  JA3 raw: {}", ja3));
                lines.push("  (MD5(JA3-raw) = JA3 fingerprint)".to_string());
            }
            if !dp.tls_ciphers.is_empty() {
                let ciphers: Vec<String> = dp
                    .tls_ciphers
                    .iter()
                    .take(10)
                    .map(|c| format!("0x{:04x}", c))
                    .collect();
                let more = if dp.tls_ciphers.len() > 10 {
                    format!(" ... +{}", dp.tls_ciphers.len() - 10)
                } else {
                    "".to_string()
                };
                lines.push(format!("  Cipher Suites: {}{}", ciphers.join(" "), more));
            }
        }

        // DNS Analysis
        if dp.dns_query_name.is_some() || dp.dns_label_entropy.is_some() {
            lines.push("-- DNS ANALYSIS".to_string());
            if let Some(qn) = &dp.dns_query_name {
                lines.push(format!("  Query: {}", qn));
            }
            if let Some(e) = dp.dns_label_entropy {
                lines.push(format!("  Entropy: {:.2}", e));
            }
        }

        // Anomalies
        if !dp.anomalies.is_empty() {
            lines.push("-- ANOMALIES".to_string());
            for a in &dp.anomalies {
                lines.push(format!("  [!] {}", a));
            }
        }

        // Classification & Risk
        if dp.risk_score > 0 || dp.app_category.is_some() {
            lines.push("-- CLASSIFICATION & RISK".to_string());
            if let Some(cat) = &dp.app_category {
                lines.push(format!("  Category: {}", cat));
            }
            if dp.risk_score > 0 {
                let label = if dp.risk_score >= 70 {
                    "HIGH"
                } else if dp.risk_score >= 35 {
                    "MEDIUM"
                } else {
                    "LOW"
                };
                let bar = "█".repeat((dp.risk_score as usize * 20) / 100)
                    + &"░".repeat(20 - (dp.risk_score as usize * 20) / 100);
                lines.push(format!(
                    "  Risk Score: {} [{}] {}",
                    dp.risk_score, bar, label
                ));
                for r in &dp.risk_reasons {
                    lines.push(format!("  • {}", r));
                }
            }
        }

        lines.join("\n")
    }

    fn handle_client(stream: &mut std::net::TcpStream) {
        let mut buffer = [0; 8192];
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);

            if request.starts_with("GET /api/interfaces ") {
                let ifaces = LinuxCaptureEngine::list_interfaces().unwrap_or_default();
                let mut json = String::from("[");
                for (i, iface) in ifaces.iter().enumerate() {
                    let desc = iface.description.as_deref().unwrap_or("");
                    let addr = iface
                        .addresses
                        .first()
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    // Check if interface is UP by reading /sys/class/net/{name}/operstate
                    let operstate_path = format!("/sys/class/net/{}/operstate", iface.name);
                    let is_up = std::fs::read_to_string(&operstate_path)
                        .map(|s| matches!(s.trim(), "up" | "unknown" | "dormant"))
                        .unwrap_or(false);
                    json.push_str(&format!(
                        r#"{{"name":"{}","description":"{}","address":"{}","is_up":{}}}"#,
                        iface.name, desc, addr, is_up
                    ));
                    if i < ifaces.len() - 1 {
                        json.push(',');
                    }
                }
                json.push(']');

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/server_info ") {
                let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let version = std::fs::read_to_string("/proc/version")
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let uptime = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
                let up_secs = uptime.split_whitespace().next().unwrap_or("0");
                let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
                let mut mem_total = "0";
                for line in meminfo.lines() {
                    if line.starts_with("MemTotal:") {
                        mem_total = line.split_whitespace().nth(1).unwrap_or("0");
                        break;
                    }
                }
                let json = format!(
                    r#"{{"hostname":"{}","version":"{}","uptime_sec":{},"mem_total_kb":{}}}"#,
                    escape_json(&hostname),
                    escape_json(&version),
                    up_secs,
                    mem_total
                );
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", json.len(), json);
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/sessions ") {
                // List all capture sessions
                let mut json = String::from("[");
                let session_list: Vec<String> = SESSIONS
                    .iter()
                    .map(|entry| entry.value().to_json())
                    .collect();
                json.push_str(&session_list.join(","));
                json.push(']');

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("POST /api/sessions/create") {
                // Create new session from POST body
                let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
                let body = &request[body_start..];

                // Parse interface and filter from JSON body
                let (interface, filter) = if body.contains("interface") {
                    // Simple JSON parsing for {"interface":"eth0","filter":"tcp"}
                    let mut iface = String::new();
                    let mut filt = None;

                    if let Some(iface_start) = body.find(r#""interface":""#) {
                        let start = iface_start + r#""interface":""#.len();
                        if let Some(end) = body[start..].find('"') {
                            iface = body[start..start + end].to_string();
                        }
                    }

                    if let Some(filter_start) = body.find(r#""filter":""#) {
                        let start = filter_start + r#""filter":""#.len();
                        if let Some(end) = body[start..].find('"') {
                            let f = body[start..start + end].to_string();
                            if !f.is_empty() {
                                filt = Some(f);
                            }
                        }
                    }

                    (iface, filt)
                } else {
                    ("any".to_string(), None)
                };

                if !interface.is_empty() {
                    let session = CaptureSession::new(interface, filter);
                    let json = session.to_json();
                    let session_id = session.id.clone();

                    SESSIONS.insert(session_id, session);

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(), json
                    );
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let json = r#"{"error":"interface required"}"#;
                    let response = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(), json
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            } else if request.starts_with("POST /api/sessions/") && request.contains("/stop") {
                // Stop a session: POST /api/sessions/{id}/stop
                let start = "POST /api/sessions/".len();
                let path = &request[start..];
                if let Some(end) = path.find("/stop") {
                    let session_id = &path[..end];

                    if let Some(mut session) = SESSIONS.get_mut(session_id) {
                        session.status = SessionStatus::Stopped;
                        let json = session.to_json();

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json.len(), json
                        );
                        let _ = stream.write_all(response.as_bytes());
                    } else {
                        let json = r#"{"error":"session not found"}"#;
                        let response = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json.len(), json
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                }
            } else if request.starts_with("DELETE /api/sessions/") {
                // Delete a session: DELETE /api/sessions/{id}
                let start = "DELETE /api/sessions/".len();
                let path = &request[start..];
                if let Some(end) = path.find(' ') {
                    let session_id = &path[..end];

                    if SESSIONS.remove(session_id).is_some() {
                        let json = r#"{"success":true}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json.len(), json
                        );
                        let _ = stream.write_all(response.as_bytes());
                    } else {
                        let json = r#"{"error":"session not found"}"#;
                        let response = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json.len(), json
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                }
            } else if request.starts_with("GET /api/terminal?cmd=") {
                let start = "GET /api/terminal?cmd=".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let cmd = decode_url(&request[start..end]);
                let output = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .output();
                let result = match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        format!("{}{}", stdout, stderr)
                    }
                    Err(e) => format!("Error executing command: {}", e),
                };
                let json = format!(r#"{{"output":"{}"}}"#, escape_json(&result));
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", json.len(), json);
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("POST /api/export-filtered") {
                // Read POST body for JSON data
                let body_start = request
                    .find("\r\n\r\n")
                    .map(|i| i + 4)
                    .unwrap_or(request.len());
                let _body = &request[body_start..];

                // For now, return a message that this requires the source PCAP
                let json = r#"{"success":false,"error":"To export filtered packets: 1) Set 'Save PCAP' path before starting capture, 2) Use BPF filter for capture-time filtering, 3) Use display filter for viewing only. Post-capture filtering will be added in a future update."}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("POST /api/stop") {
                let response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"status\":\"stopping daemon\"}";
                let _ = stream.write_all(response.as_bytes());
                std::thread::spawn(|| {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    std::process::exit(0);
                });
            } else if request.starts_with("GET /api/conn ") {
                let conns = list_connections();
                let mut json = String::from("[");
                for (i, c) in conns.iter().enumerate() {
                    let process = c
                        .process
                        .as_deref()
                        .unwrap_or("")
                        .replace("\\", "\\\\")
                        .replace("\"", "\\\"");
                    json.push_str(&format!(
                        r#"{{"proto":"{}","local_ip":"{}","local_port":{},"remote_ip":"{}","remote_port":{},"state":"{}","pid":{},"process":"{}"}}"#,
                        c.proto, c.local_ip, c.local_port, c.remote_ip, c.remote_port, c.state, c.pid.unwrap_or(0), process
                    ));
                    if i < conns.len() - 1 {
                        json.push(',');
                    }
                }
                json.push(']');
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/route ") {
                let routes = list_routes();
                let mut json = String::from("[");
                for (i, r) in routes.iter().enumerate() {
                    json.push_str(&format!(
                        r#"{{"interface":"{}","destination":"{}","prefix_len":{},"gateway":"{}","metric":{},"is_default":{}}}"#,
                        r.interface, r.destination, r.prefix_len, r.gateway, r.metric, r.is_default
                    ));
                    if i < routes.len() - 1 {
                        json.push(',');
                    }
                }
                json.push(']');
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/nic ") {
                let nics = list_nics().unwrap_or_default();
                let mut json = String::from("[");
                for (i, n) in nics.iter().enumerate() {
                    json.push_str(&format!(
                        r#"{{"name":"{}","state":"{}","mac":"{}","mtu":{},"rx_bytes":{},"tx_bytes":{}}}"#,
                        n.name, n.state, n.mac, n.mtu, n.rx_bytes, n.tx_bytes
                    ));
                    if i < nics.len() - 1 {
                        json.push(',');
                    }
                }
                json.push(']');
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/nic_detail?iface=") {
                let start = "GET /api/nic_detail?iface=".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let iface = decode_url(&request[start..end]);
                if let Ok(nic) = get_nic_info(&iface) {
                    let state = if nic.is_up() { "UP" } else { "DOWN" };
                    let mut ips = String::from("[");
                    for (i, ip) in nic.ip_addresses.iter().enumerate() {
                        ips.push_str(&format!("\"{}\"", ip));
                        if i < nic.ip_addresses.len() - 1 {
                            ips.push(',');
                        }
                    }
                    ips.push(']');
                    let json = format!(
                        r#"{{"name":"{}","state":"{}","mac":"{}","mtu":{},"rx_bytes":{},"tx_bytes":{},"rx_packets":{},"tx_packets":{},"speed":"{}","ips":{}}}"#,
                        nic.name,
                        state,
                        nic.mac,
                        nic.mtu,
                        nic.rx_bytes,
                        nic.tx_bytes,
                        nic.rx_packets,
                        nic.tx_packets,
                        nic.speed_label(),
                        ips
                    );
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", json.len(), json);
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n");
                }
            } else if request.starts_with("GET /api/dp?iface=") {
                let start = "GET /api/dp?iface=".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let iface = decode_url(&request[start..end]);
                if let Ok(dp) = get_nic_dataplane(&iface) {
                    let bypass = format!("{:?}", dp.bypass_mode);
                    let driver = dp.userspace_driver.as_deref().unwrap_or("");
                    let xdp_ids = format!("{:?}", dp.xdp_prog_ids);
                    let json = format!(
                        r#"{{"bypass_mode":"{}","afxdp_sockets":{},"dpdk_bound":{},"driver":"{}","xdp_prog_ids":"{}","rx_queues":{},"tx_queues":{}}}"#,
                        bypass,
                        dp.afxdp_sockets,
                        dp.dpdk_bound,
                        driver,
                        xdp_ids,
                        dp.rx_queues,
                        dp.tx_queues
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(), json
                    );
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n");
                }
            } else if request.starts_with("GET /api/ethtool?iface=") {
                let start = "GET /api/ethtool?iface=".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let iface = decode_url(&request[start..end]);
                if let Ok(et) = get_ethtool_report(&iface) {
                    let driver = et.driver.as_deref().unwrap_or("");
                    let speed = et.speed_mbps.unwrap_or(0);
                    let duplex = et.duplex.as_deref().unwrap_or("");
                    let json = format!(
                        r#"{{"driver":"{}","speed_mbps":{},"duplex":"{}","operstate":"{}","rx_queues":{},"tx_queues":{}}}"#,
                        driver, speed, duplex, et.operstate, et.rx_queues, et.tx_queues
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(), json
                    );
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n");
                }
            } else if request.starts_with("GET /api/geoip?ip=") {
                let start = "GET /api/geoip?ip=".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let ip = &request[start..end];
                if let Some(geo) = geoip_lookup_str(ip) {
                    let json = format!(
                        r#"{{"ip":"{}","country_code":"{}","country_name":"{}","continent":"{}"}}"#,
                        ip, geo.country_code, geo.country_name, geo.continent
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(), json
                    );
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let json = format!(
                        r#"{{"ip":"{}","country_code":"--","country_name":"Private / Unknown","continent":"--"}}"#,
                        ip
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(), json
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            } else if request.starts_with("GET /api/flow_analyze?") {
                // Advanced Flow Analysis endpoint
                use pktana_core::FlowAnalyzer;

                let start = "GET /api/flow_analyze?".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let query = &request[start..end];

                let mut iface = String::new();
                let mut filter = None;

                // Parse URL query string
                for pair in query.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        let decoded = decode_url(v);
                        if k == "iface" {
                            iface = decoded;
                        } else if k == "filter" {
                            let f = decoded.trim().to_string();
                            if !f.is_empty() {
                                filter = Some(f);
                            }
                        }
                    }
                }

                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
                if stream.write_all(response.as_bytes()).is_err() {
                    return;
                }

                let config = CaptureConfig {
                    interface: iface,
                    promiscuous: true,
                    snapshot_len: 65_535,
                    filter,
                    max_packets: usize::MAX,
                    pcap_export: None,
                };

                if let Ok(mut write_stream) = stream.try_clone() {
                    let mut analyzer = FlowAnalyzer::new();

                    let handle_pkt = move |pkt: pktana_core::CapturePacket<'_>| -> bool {
                        let dp = inspect(&pkt.data);

                        // Analyze the packet for advanced flow states
                        let flow_results = analyzer.analyze_packet(&dp);

                        // Send flow analysis results
                        for result in flow_results {
                            let msg =
                                format!(
                                "data: {{\"ts_sec\":{}, \"ts_usec\":{}, \"analysis\":\"{}\"}}\n\n",
                                pkt.timestamp_sec, pkt.timestamp_usec, escape_json(&result)
                            );
                            if write_stream.write_all(msg.as_bytes()).is_err() {
                                return false;
                            }
                        }

                        // Also send summary stats periodically
                        let summary = analyzer.get_summary();
                        let summary_msg = format!(
                            "data: {{\"type\":\"summary\", \"tcp_flows\":{}, \"tcp_complete\":{}, \"tls_flows\":{}, \"tls_complete\":{}, \"dhcp_flows\":{}, \"dhcp_complete\":{}}}\n\n",
                            summary.total_tcp_flows,
                            summary.complete_tcp_handshakes,
                            summary.total_tls_flows,
                            summary.complete_tls_handshakes,
                            summary.total_dhcp_flows,
                            summary.complete_dhcp_dora
                        );
                        let _ = write_stream.write_all(summary_msg.as_bytes());

                        true
                    };

                    // Live capture with flow analysis
                    if let Err(e) = LinuxCaptureEngine::capture_streaming(&config, handle_pkt) {
                        let msg = format!(
                            "data: {{\"error\": \"{}\"}}\n\n",
                            escape_json(&e.to_string())
                        );
                        let _ = stream.write_all(msg.as_bytes());
                    }
                }
            } else if request.starts_with("GET /api/inspect?") {
                let start = "GET /api/inspect?".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let query = &request[start..end];

                let mut iface = String::new();
                let mut filter = None;
                let mut export_file = None;
                let mut read_file = None;
                let mut flow_analyze = false;
                let mut session_id = None;

                // Parse URL query string
                for pair in query.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        let decoded = decode_url(v);
                        if k == "iface" {
                            iface = decoded;
                        } else if k == "filter" {
                            let f = decoded.trim().to_string();
                            if !f.is_empty() {
                                filter = Some(f);
                            }
                        } else if k == "export" {
                            export_file = Some(decoded.trim().to_string());
                        } else if k == "read" {
                            read_file = Some(decoded.trim().to_string());
                        } else if k == "flow_analyze" || k == "analyze" {
                            flow_analyze = decoded == "true" || decoded == "1";
                        } else if k == "session" {
                            session_id = Some(decoded.trim().to_string());
                        }
                    }
                }

                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
                if stream.write_all(response.as_bytes()).is_err() {
                    return;
                }

                // Auto-create a session if the client did not pass one, so multi-interface
                // tracking always has a record. This makes /api/sessions reflect every live capture.
                if session_id.is_none() && !iface.is_empty() {
                    let s = CaptureSession::new(iface.clone(), filter.clone());
                    let id = s.id.clone();
                    SESSIONS.insert(id.clone(), s);
                    session_id = Some(id);
                }

                let config = CaptureConfig {
                    interface: iface,
                    promiscuous: true,
                    snapshot_len: 65_535,
                    filter,
                    max_packets: usize::MAX,
                    pcap_export: export_file.filter(|s| !s.is_empty()),
                };

                if let Ok(mut write_stream) = stream.try_clone() {
                    let mut analyzer = if flow_analyze {
                        Some(pktana_core::FlowAnalyzer::new())
                    } else {
                        None
                    };

                    // Clone session_id for use in the packet handler closure
                    let session_id_for_handler = session_id.clone();

                    let handle_pkt = move |pkt: pktana_core::CapturePacket<'_>| -> bool {
                        let dp = inspect(&pkt.data);

                        // Flow analysis if enabled
                        if let Some(ref mut analyzer) = analyzer {
                            let flow_results = analyzer.analyze_packet(&dp);
                            for result in flow_results {
                                let flow_msg =
                                    format!(
                                    "data: {{\"ts_sec\":{}, \"ts_usec\":{}, \"flow_event\":\"{}\"}}

",
                                    pkt.timestamp_sec, pkt.timestamp_usec, escape_json(&result)
                                );
                                let _ = write_stream.write_all(flow_msg.as_bytes());
                            }
                        }

                        let risk = dp.risk_score;

                        let proto = if dp.quic_detected {
                            "QUIC"
                        } else if dp.http2_detected {
                            "HTTP2"
                        } else if let Some(ap) = &dp.app_proto {
                            ap.as_str()
                        } else if dp.tcp_src_port.is_some() {
                            "TCP"
                        } else if dp.udp_src_port.is_some() {
                            "UDP"
                        } else if dp.icmp_type.is_some() {
                            "ICMP"
                        } else {
                            "IP"
                        };

                        let src = dp
                            .ip_src
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| dp.eth_src.clone());
                        let dst = dp
                            .ip_dst
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| dp.eth_dst.clone());
                        let detail_text = build_dpi_text(
                            &dp,
                            &PROCESS_MAP,
                            pkt.timestamp_sec,
                            pkt.timestamp_usec,
                        );

                        // Compute filter tags for handshake / query / DORA flows
                        let mut tags: Vec<&'static str> = Vec::new();
                        if let Some(flags) = &dp.tcp_flags_str {
                            if flags.contains("SYN") {
                                tags.push("tcp-handshake");
                            }
                        }
                        let app_lc = dp
                            .app_proto
                            .as_deref()
                            .map(|s| s.to_ascii_lowercase())
                            .unwrap_or_default();
                        if app_lc == "tls"
                            && dp
                                .app_detail
                                .iter()
                                .any(|l| l.contains("Record") && l.contains("Handshake"))
                        {
                            tags.push("tls-handshake");
                        }
                        if app_lc == "dns" {
                            tags.push("dns-query");
                        }
                        if app_lc == "dhcp" {
                            tags.push("dhcp-dora");
                        }
                        let tags_str = tags.join(",");

                        // Hex dump: first 128 bytes (8 lines) for on-click display
                        let hex_text = hex_dump(&pkt.data, pkt.data.len().min(128)).join("\n");

                        let msg = format!(
                            "data: {{\"ts_sec\":{}, \"ts_usec\":{}, \"summary\":\"{}\", \"len\": {}, \"risk\": {}, \"category\": \"{}\", \"proto\": \"{}\", \"src\":\"{}\", \"dst\":\"{}\", \"tags\":\"{}\", \"details\":\"{}\", \"hex\":\"{}\"}}\n\n",
                            pkt.timestamp_sec, pkt.timestamp_usec, escape_json(&dp.one_liner()), dp.frame_len, risk, escape_json(dp.app_category.as_deref().unwrap_or("Unknown")), escape_json(proto), escape_json(&src), escape_json(&dst), tags_str, escape_json(&detail_text), escape_json(&hex_text)
                        );

                        // Update session stats if session_id is present
                        if let Some(ref sid) = session_id_for_handler {
                            if let Some(mut session) = SESSIONS.get_mut(sid) {
                                session.packet_count += 1;
                                session.bytes_captured += dp.frame_len;
                            }
                        }

                        write_stream.write_all(msg.as_bytes()).is_ok()
                    };

                    if let Some(read_path) = read_file.filter(|s| !s.is_empty()) {
                        // Read from PCAP
                        if let Err(e) = LinuxCaptureEngine::read_pcap_file(&read_path, handle_pkt) {
                            let msg = format!(
                                "data: {{\"error\": \"{}\"}}\n\n",
                                escape_json(&e.to_string())
                            );
                            let _ = stream.write_all(msg.as_bytes());
                        }
                    } else {
                        // Live capture
                        if let Err(e) = LinuxCaptureEngine::capture_streaming(&config, handle_pkt) {
                            let msg = format!(
                                "data: {{\"error\": \"{}\"}}\n\n",
                                escape_json(&e.to_string())
                            );
                            let _ = stream.write_all(msg.as_bytes());
                        }
                    }

                    // Stream ended (client disconnected, pcap finished, or filter error).
                    // Mark the session as stopped so the UI/API reflect reality.
                    if let Some(sid) = &session_id {
                        if let Some(mut s) = SESSIONS.get_mut(sid) {
                            s.status = SessionStatus::Stopped;
                        }
                    }
                }
            } else if request.starts_with("GET /api/wiki?page=") {
                let start = "GET /api/wiki?page=".len();
                let end = request[start..].find(' ').unwrap_or(request.len() - start) + start;
                let page = request[start..end].trim_end_matches(" HTTP/1.1");
                let content: Option<&str> = match page {
                    "overview" | "01-overview" => Some(WIKI_OVERVIEW),
                    "installation" | "02-installation" => Some(WIKI_INSTALLATION),
                    "cli-reference" | "03-cli-reference" => Some(WIKI_CLI_REF),
                    "tui-guide" | "04-tui-guide" => Some(WIKI_TUI),
                    "web-ui-guide" | "05-web-ui-guide" => Some(WIKI_WEBUI),
                    "dpi-engine" | "06-dpi-engine" => Some(WIKI_DPI),
                    "flow-analyzer" | "07-flow-analyzer" => Some(WIKI_FLOW),
                    "api-reference" | "08-api-reference" => Some(WIKI_API),
                    "library-api" | "09-library-api" => Some(WIKI_LIB),
                    "protocols" | "10-protocols" => Some(WIKI_PROTO),
                    "architecture" | "11-architecture" => Some(WIKI_ARCH),
                    "contributing" | "12-contributing" => Some(WIKI_CONTRIB),
                    _ => None,
                };
                if let Some(md) = content {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        md.len(), md
                    );
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"wiki page not found\"}";
                    let _ = stream.write_all(response.as_bytes());
                }
            } else if request.starts_with("GET /api/wiki ") {
                let pages = r#"[{"id":"overview","title":"Overview"},{"id":"installation","title":"Installation"},{"id":"cli-reference","title":"CLI Reference"},{"id":"tui-guide","title":"TUI Guide"},{"id":"web-ui-guide","title":"Web UI Guide"},{"id":"dpi-engine","title":"DPI Engine"},{"id":"flow-analyzer","title":"Flow Analyzer"},{"id":"api-reference","title":"API Reference"},{"id":"library-api","title":"Library API (Rust)"},{"id":"protocols","title":"Protocol Coverage"},{"id":"architecture","title":"Architecture"},{"id":"contributing","title":"Contributing"}]"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    pages.len(), pages
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /logo.png ") {
                // Serve logo.png
                if let Ok(img_data) = std::fs::read("logo.png") {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        img_data.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(&img_data);
                } else {
                    let response =
                        "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nLogo not found";
                    let _ = stream.write_all(response.as_bytes());
                }
            } else if request.starts_with("GET /pktana.png ") {
                // Serve pktana.png
                if let Ok(img_data) = std::fs::read("pktana.png") {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        img_data.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(&img_data);
                } else {
                    let response =
                        "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nImage not found";
                    let _ = stream.write_all(response.as_bytes());
                }
            } else if request.starts_with("GET / ") {
                let html = HTML_TEMPLATE;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = stream.write_all(response.as_bytes());
            } else {
                let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
            }
        }
    }

    const WIKI_OVERVIEW: &str = include_str!("../../../wiki/01-overview.md");
    const WIKI_INSTALLATION: &str = include_str!("../../../wiki/02-installation.md");
    const WIKI_CLI_REF: &str = include_str!("../../../wiki/03-cli-reference.md");
    const WIKI_TUI: &str = include_str!("../../../wiki/04-tui-guide.md");
    const WIKI_WEBUI: &str = include_str!("../../../wiki/05-web-ui-guide.md");
    const WIKI_DPI: &str = include_str!("../../../wiki/06-dpi-engine.md");
    const WIKI_FLOW: &str = include_str!("../../../wiki/07-flow-analyzer.md");
    const WIKI_API: &str = include_str!("../../../wiki/08-api-reference.md");
    const WIKI_LIB: &str = include_str!("../../../wiki/09-library-api.md");
    const WIKI_PROTO: &str = include_str!("../../../wiki/10-protocols.md");
    const WIKI_ARCH: &str = include_str!("../../../wiki/11-architecture.md");
    const WIKI_CONTRIB: &str = include_str!("../../../wiki/12-contributing.md");

    const HTML_TEMPLATE: &str = r##"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pktana Network Analyzer</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Nunito:wght@700;800;900&display=swap">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.9.0/lib/xterm-addon-web-links.js"></script>
    <style>
        :root { 
            --primary: #f97316;
            --primary-dark: #ea580c;
            --primary-light: #fed7aa;
            --primary-hover: #fb923c;
            --accent: #f97316;
            --accent-light: #ffedd5;
            --bg: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            --bg-solid: #f8fafc;
            --surface: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --success: #10b981; 
            --danger: #dc2626; 
            --warning: #f97316;
            --info: #0284c7;
            --sidebar-bg: #ffffff;
            --sidebar-hover: #f8fafc;
            --navbar-bg: #ffffff;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif; background: var(--bg-solid); color: var(--text-main); height: 100vh; display: flex; flex-direction: column; overflow: hidden; -webkit-font-smoothing: antialiased; transition: all 0.3s ease; }
        body.dark-theme { --bg: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); --bg-solid: #0f172a; --surface: #1e293b; --text-main: #f1f5f9; --text-muted: #94a3b8; --border: #334155; --navbar-bg: #1e293b; --sidebar-bg: #1e293b; --sidebar-hover: #334155; --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.3); --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4); --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.5); }
        
        .navbar { background: var(--navbar-bg); color: var(--text-main); padding: 14px 28px; display: flex; justify-content: space-between; align-items: center; box-shadow: var(--shadow); z-index: 100; border-bottom: 3px solid transparent; border-image: linear-gradient(90deg, var(--primary), var(--primary-dark)) 1; height: 70px; position: fixed; top: 0; left: 0; right: 0; backdrop-filter: blur(10px); }
        .logo { font-size: 26px; font-weight: 800; display: flex; align-items: center; letter-spacing: 0.5px; transition: transform 0.2s; font-family: 'Nunito', 'Quicksand', 'Comfortaa', 'Varela Round', 'Segoe UI Rounded', system-ui, -apple-system, sans-serif; }
        .logo:hover { transform: scale(1.02); }
        .logo span { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-weight: 800; text-transform: lowercase; }
        .nav-controls { display: flex; gap: 10px; align-items: center; }
        
        /* Landing Page Styles */
        .landing-page { position: fixed; top: 0; left: 0; width: 100%; height: 100vh; background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%); display: flex; flex-direction: column; justify-content: center; align-items: center; z-index: 9999; }
        .landing-page img { max-width: 70%; max-height: 50vh; object-fit: contain; animation: fadeInScale 0.6s ease-out; box-shadow: 0 20px 60px rgba(0,0,0,0.4); border-radius: 12px; }
        .landing-page h1 { color: white; font-size: 42px; font-weight: 700; margin: 30px 0 12px 0; text-shadow: 0 2px 8px rgba(0,0,0,0.3); animation: fadeInUp 0.8s ease-out 0.2s both; background: linear-gradient(135deg, #f97316, #ea580c); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .landing-page p { color: rgba(255,255,255,0.95); font-size: 16px; margin-bottom: 35px; animation: fadeInUp 0.8s ease-out 0.4s both; font-weight: 400; }
        .landing-btn { background: linear-gradient(135deg, #f97316, #ea580c); color: white; border: none; border-radius: 8px; padding: 14px 36px; font-size: 15px; font-weight: 600; cursor: pointer; box-shadow: 0 4px 16px rgba(0,0,0,0.2); transition: all 0.2s; animation: fadeInUp 0.8s ease-out 0.6s both; }
        .landing-btn:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.25); }
        @keyframes fadeInScale { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .landing-page.hidden { display: none; }
        
        .container { flex: 1; display: flex; flex-direction: column; width: 100%; padding: 0; overflow: hidden; }
        
        .form-input, select.form-input { padding: 10px 14px; border: 2px solid var(--border); background: var(--surface); color: var(--text-main); font-size: 13px; outline: none; border-radius: 8px; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); font-weight: 500; box-shadow: var(--shadow-sm); }
        .form-input::placeholder { color: var(--text-muted); }
        .form-input:focus, select.form-input:focus { border-color: var(--primary); box-shadow: 0 0 0 4px var(--primary-light), var(--shadow); background: white; transform: translateY(-1px); }
        select.form-input { cursor: pointer; }
        select.form-input:hover { border-color: var(--primary-hover); box-shadow: var(--shadow); }
        
        .primary-btn { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; border: none; border-radius: 8px; padding: 10px 20px; font-size: 13px; cursor: pointer; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); font-weight: 600; box-shadow: 0 4px 8px rgba(249,115,22,0.3), 0 1px 3px rgba(0,0,0,0.1); position: relative; overflow: hidden; }
        .primary-btn::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent); transition: left 0.5s; }
        .primary-btn:hover::before { left: 100%; }
        .primary-btn:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(249,115,22,0.4), 0 3px 6px rgba(0,0,0,0.15); }
        .primary-btn:active { transform: translateY(0); box-shadow: 0 2px 4px rgba(249,115,22,0.3); }
        .primary-btn.stop { background: linear-gradient(135deg, var(--danger), #b91c1c); }
        .primary-btn.stop:hover { box-shadow: 0 6px 16px rgba(220,38,38,0.4), 0 3px 6px rgba(0,0,0,0.15); }
        
        .btn { background: white; color: var(--text-main); border: 2px solid var(--border); border-radius: 8px; padding: 9px 16px; font-size: 13px; cursor: pointer; font-weight: 600; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: var(--shadow-sm); }
        .btn:hover { border-color: var(--primary); color: var(--primary); background: var(--primary-light); transform: translateY(-1px); box-shadow: var(--shadow); }
        .btn:active { transform: scale(0.98) translateY(0); }
        
        .tab-nav { background: var(--surface); border-bottom: 2px solid var(--border); padding: 0 24px; display: flex; gap: 6px; box-shadow: var(--shadow-sm); backdrop-filter: blur(10px); }
        .tab-btn { padding: 16px 22px; border: none; background: none; color: var(--text-muted); font-size: 13px; font-weight: 700; cursor: pointer; border-bottom: 3px solid transparent; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; }
        .tab-btn::after { content: ''; position: absolute; bottom: -2px; left: 50%; width: 0; height: 3px; background: linear-gradient(90deg, var(--primary), var(--primary-dark)); transition: all 0.3s; transform: translateX(-50%); }
        .tab-btn:hover { color: var(--primary); background: rgba(249, 115, 22, 0.05); }
        .tab-btn:hover::after { width: 80%; }
        .tab-btn.active { color: var(--primary); background: linear-gradient(180deg, rgba(249, 115, 22, 0.1), rgba(249, 115, 22, 0.05)); }
        .tab-btn.active::after { width: 100%; }
        
        .panel-toolbar { background: var(--surface); padding: 12px 24px; border-bottom: 2px solid var(--border); display: flex; gap: 12px; align-items: center; flex-wrap: wrap; flex-shrink: 0; box-shadow: var(--shadow-sm); }
        .toolbar-group { display: flex; gap: 10px; align-items: center; padding: 6px 14px; background: linear-gradient(135deg, #f8fafc, #f1f5f9); border-radius: 8px; border: 2px solid var(--border); transition: all 0.2s; box-shadow: var(--shadow-sm); }
        .toolbar-group:hover { border-color: var(--primary-light); box-shadow: var(--shadow); transform: translateY(-1px); }
        .toolbar-separator { width: 2px; height: 28px; background: linear-gradient(180deg, transparent, var(--border), transparent); margin: 0 8px; }
        .toolbar-label { font-size: 10px; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; margin-right: 6px; }
        
        .panel { display: none; height: 100%; flex-direction: column; overflow: hidden; }
        .panel.active { display: flex; }
        
        .wireshark-view { display: flex; flex-direction: row; flex: 1; width: 100%; gap: 18px; padding: 20px; background: var(--bg-solid); overflow: hidden; }
        .pane-left { flex: 6; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow-lg); position: relative; overflow: hidden; display: flex; flex-direction: column; transition: box-shadow 0.3s; }
        .pane-left:hover { box-shadow: var(--shadow-xl); }
        #tableContainer { flex: 1; overflow: auto; }
        .pane-right { flex: 4; display: flex; flex-direction: column; gap: 18px; min-width: 360px; min-height: 0; overflow: visible; }
        
        .section-label { font-weight: 800; color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: -8px; background: linear-gradient(90deg, var(--primary), var(--primary-dark)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .pane-detail { flex: 3; min-height: 0; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow-y: auto; padding: 18px; font-family: 'Consolas', 'Courier New', monospace; box-shadow: var(--shadow); transition: all 0.3s; }
        .pane-detail:hover { box-shadow: var(--shadow-lg); }
        .pane-hex { flex: 2; min-height: 0; background: linear-gradient(135deg, #0f172a, #1e293b); color: #e2e8f0; border: 1px solid var(--border); border-radius: 12px; overflow-y: auto; padding: 18px; font-family: 'Consolas', 'Courier New', monospace; box-shadow: var(--shadow-lg); transition: all 0.3s; }
        .pane-hex:hover { box-shadow: var(--shadow-xl); border-color: var(--primary); }
        .docs-nav-item { display:block; width:100%; text-align:left; padding:8px 16px; font-size:13px; color:var(--text-muted); background:none; border:none; cursor:pointer; border-radius:6px; margin:1px 4px; transition:all 0.2s; font-family:inherit; }
        .docs-nav-item:hover { background:var(--sidebar-hover); color:var(--text-main); }
        .docs-nav-item.active { background:linear-gradient(135deg,var(--primary),var(--primary-dark)); color:#fff; font-weight:600; }
        .md-content h1 { font-size:1.8em; font-weight:700; color:var(--text-main); margin:0 0 16px; padding-bottom:10px; border-bottom:2px solid var(--border); }
        .md-content h2 { font-size:1.3em; font-weight:700; color:var(--text-main); margin:28px 0 10px; padding-bottom:6px; border-bottom:1px solid var(--border); }
        .md-content h3 { font-size:1.1em; font-weight:600; color:var(--primary); margin:20px 0 8px; }
        .md-content h4 { font-size:1em; font-weight:600; color:var(--text-muted); margin:16px 0 6px; }
        .md-content p { margin:0 0 12px; }
        .md-content code { background:var(--accent-light,rgba(99,102,241,0.1)); color:#e879f9; padding:2px 6px; border-radius:4px; font-family:monospace; font-size:0.88em; }
        .md-content pre { background:#0f172a; border:1px solid var(--border); border-radius:8px; padding:14px 18px; overflow-x:auto; margin:12px 0; }
        .md-content pre code { background:none; color:#94a3b8; font-size:0.85em; padding:0; }
        .md-content ul, .md-content ol { margin:0 0 12px 20px; }
        .md-content li { margin:4px 0; }
        .md-content table { border-collapse:collapse; width:100%; margin:14px 0; font-size:13px; }
        .md-content th { background:var(--accent-light,rgba(99,102,241,0.08)); color:var(--text-main); font-weight:700; padding:8px 12px; border:1px solid var(--border); text-align:left; }
        .md-content td { padding:7px 12px; border:1px solid var(--border); color:var(--text-main); }
        .md-content tr:nth-child(even) td { background:rgba(148,163,184,0.04); }
        .md-content blockquote { border-left:4px solid var(--primary); padding:8px 14px; margin:12px 0; color:var(--text-muted); background:var(--accent-light,rgba(99,102,241,0.06)); border-radius:0 6px 6px 0; }
        .md-content hr { border:none; border-top:1px solid var(--border); margin:24px 0; }
        .md-content a { color:var(--primary); text-decoration:underline; }
        .md-content strong { color:var(--text-main); font-weight:700; }

        .ws-table { min-width: 100%; border-collapse: collapse; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; table-layout: auto; }
        .ws-table th { background: linear-gradient(180deg, #f8fafc, #f1f5f9); color: var(--text-main); border-bottom: 2px solid var(--primary); border-right: 1px solid var(--border); padding: 8px 10px; text-align: left; position: sticky; top: 0; z-index: 10; text-transform: uppercase; font-size: 11px; letter-spacing: 0.8px; font-weight: 700; box-shadow: var(--shadow-sm); }
        .ws-table td { border-bottom: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0; padding: 6px 10px; cursor: pointer; white-space: nowrap; transition: all 0.15s; }
        .ws-table tr:hover td { background: rgba(249, 115, 22, 0.08) !important; transform: scale(1.001); }
        .ws-table tr.selected td { background: linear-gradient(135deg, var(--primary), var(--primary-dark)) !important; color: white !important; font-weight: 600; box-shadow: inset 0 1px 3px rgba(0,0,0,0.2); }
        
        .ws-bg-tcp { background-color: #e2e8f0; color: var(--text-main); }
        .ws-bg-udp { background-color: #e0f2fe; color: var(--text-main); }
        .ws-bg-http { background-color: #dcfce7; color: var(--text-main); }
        .ws-bg-dns { background-color: #cffafe; color: var(--text-main); }
        .ws-bg-icmp { background-color: #fae8ff; color: var(--text-main); }
        .ws-bg-arp { background-color: #fef08a; color: var(--text-main); }
        .ws-bg-bad { background-color: #fee2e2; color: #991b1b; font-weight: 500; }
        .ws-bg-def { background-color: var(--surface); color: var(--text-main); }
        
        .info-cell { white-space: nowrap; }
        
        .detail-header { background: linear-gradient(135deg, var(--primary-light), #ffedd5); color: var(--primary-dark); font-weight: 800; padding: 8px 12px; margin: 14px 0 8px 0; border-radius: 6px; border-left: 4px solid var(--primary); font-size: 12px; letter-spacing: 0.8px; box-shadow: var(--shadow-sm); transition: all 0.2s; }
        .detail-header:hover { transform: translateX(2px); box-shadow: var(--shadow); }
        .detail-header:first-child { margin-top: 0; }
        .detail-row { display: flex; padding: 5px 12px; font-size: 13px; border-bottom: 1px solid #f1f5f9; transition: all 0.15s; border-radius: 4px; }
        .detail-row:hover { background: linear-gradient(90deg, transparent, rgba(249, 115, 22, 0.05), transparent); transform: translateX(3px); }
        .detail-key { color: var(--text-muted); width: 150px; flex-shrink: 0; font-weight: 700; }
        .detail-val { color: var(--text-main); word-break: break-all; font-weight: 500; }

        .scroll-toast { position: absolute; bottom: 24px; left: 50%; transform: translateX(-50%); background: linear-gradient(135deg, #1e293b, #0f172a); color: white; padding: 10px 24px; border-radius: 24px; font-size: 13px; font-weight: 700; cursor: pointer; box-shadow: var(--shadow-xl); opacity: 0.95; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); z-index: 100; border: 2px solid #334155; backdrop-filter: blur(10px); }
        .session-strip { display:flex; flex-wrap:wrap; gap:6px; padding:8px 16px; background: var(--surface); border-bottom:1px solid var(--border); align-items:center; min-height:42px; }
        .session-chip { display:inline-flex; align-items:center; gap:6px; background: rgba(249,115,22,0.08); border:1px solid rgba(249,115,22,0.25); border-radius:18px; padding:4px 10px 4px 12px; font-size:12px; font-weight:600; color:var(--text-muted); cursor:pointer; transition:all .2s; }
        .session-chip:hover { background: rgba(249,115,22,0.18); color:var(--text); }
        .session-chip.active { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color:#fff; border-color: var(--primary-dark); box-shadow: 0 2px 8px rgba(249,115,22,0.3); }
        .session-chip .chip-x { background: rgba(0,0,0,0.15); border:none; color:inherit; width:18px; height:18px; border-radius:50%; cursor:pointer; font-size:14px; line-height:1; padding:0; display:inline-flex; align-items:center; justify-content:center; }
        .session-chip .chip-x:hover { background: rgba(220,38,38,0.7); color:#fff; }
        .window-tabs { display:flex; gap:2px; padding:0 16px; background: var(--bg); border-bottom: 1px solid var(--border); }
        .win-tab { background: transparent; border: none; border-bottom: 2px solid transparent; padding: 10px 18px; cursor: pointer; font-size: 13px; font-weight: 600; color: var(--text-muted); transition: all .15s; }
        .win-tab:hover { color: var(--text); background: var(--surface); }
        .win-tab.active { color: var(--primary); border-bottom-color: var(--primary); background: var(--surface); }
        .activity-icon.hidden-session-tab { display: none; }
        .scroll-toast:hover { opacity: 1; transform: translateX(-50%) translateY(-3px) scale(1.02); background: linear-gradient(135deg, #0f172a, #000000); box-shadow: 0 8px 20px rgba(0,0,0,0.3); border-color: var(--primary); }
        
        .statusbar { background: var(--surface); border-top: 2px solid var(--border); padding: 10px 24px; font-size: 13px; font-weight: 700; color: var(--text-muted); display: flex; justify-content: space-between; flex-shrink: 0; box-shadow: 0 -2px 8px rgba(0,0,0,0.05); backdrop-filter: blur(10px); }
        
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; padding: 24px; overflow: auto; }
        .card { background: var(--surface); border: 1px solid var(--border); padding: 20px; box-shadow: var(--shadow); border-radius: 12px; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; }
        .card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--primary), var(--primary-dark)); }
        .card:hover { transform: translateY(-4px); box-shadow: var(--shadow-lg); border-color: var(--primary-light); }
        .card-title { font-weight: 700; border-bottom: 2px solid transparent; border-image: linear-gradient(90deg, var(--primary), transparent) 1; padding-bottom: 12px; margin-bottom: 16px; font-size: 15px; color: var(--text-main); letter-spacing: 0.3px; }
        .kv-list { display: flex; flex-direction: column; gap: 8px; font-size: 13px; }
        .kv-item { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px dashed var(--border); padding: 8px 0; transition: all 0.2s; }
        .kv-item:hover { padding-left: 8px; border-bottom-style: solid; border-color: var(--primary-light); }
        .kv-item strong { font-weight: 700; color: var(--text-main); }
        .kv-item span { font-weight: 600; color: var(--text-muted); }
        
        .settings-table { width: 100%; border-collapse: collapse; margin-top: 12px; background: var(--surface); font-size: 13px; border-radius: 8px; overflow: hidden; box-shadow: var(--shadow); }
        .settings-table th, .settings-table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
        .settings-table th { background: linear-gradient(180deg, #f8fafc, #f1f5f9); font-weight: 700; color: var(--text-main); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid var(--primary); }
        .settings-table tbody tr { transition: all 0.2s; }
        .settings-table tbody tr:hover td { background: linear-gradient(90deg, transparent, rgba(249, 115, 22, 0.05), transparent); transform: scale(1.001); }
        
        .badge { padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: var(--shadow-sm); transition: all 0.2s; }
        .badge:hover { transform: scale(1.05); box-shadow: var(--shadow); }
        .badge-success { background: linear-gradient(135deg, #d1fae5, #a7f3d0); color: #065f46; border: 1px solid #10b981; }
        .badge-danger { background: linear-gradient(135deg, #fee2e2, #fecaca); color: #991b1b; border: 1px solid #dc2626; }
        .badge-warning { background: linear-gradient(135deg, #fef3c7, #fde68a); color: #92400e; border: 1px solid #f59e0b; }
        .badge-info { background: linear-gradient(135deg, #dbeafe, #bfdbfe); color: #1e40af; border: 1px solid #0284c7; }
        
        /* Dark theme badge overrides for better readability */
        body.dark-theme .badge-success { background: #065f46; color: #d1fae5; }
        body.dark-theme .badge-danger { background: #991b1b; color: #fee2e2; }
        body.dark-theme .badge-warning { background: #92400e; color: #fef3c7; }
        body.dark-theme .badge-info { background: #1e40af; color: #dbeafe; }
        
        /* Dark theme: Fix font visibility on colored flow rows */
        body.dark-theme .ws-bg-tcp { background-color: #1e3a5f; color: #e2e8f0; }
        body.dark-theme .ws-bg-udp { background-color: #0c4a6e; color: #e0f2fe; }
        body.dark-theme .ws-bg-http { background-color: #14532d; color: #dcfce7; }
        body.dark-theme .ws-bg-dns { background-color: #164e63; color: #cffafe; }
        body.dark-theme .ws-bg-icmp { background-color: #581c87; color: #f3e8ff; }
        body.dark-theme .ws-bg-arp { background-color: #713f12; color: #fef08a; }
        body.dark-theme .ws-bg-bad { background-color: #7f1d1d; color: #fecaca; font-weight: 500; }
        body.dark-theme .ws-bg-def { background-color: #1e293b; color: #f1f5f9; }

        /* Dark theme: Fix button visibility (default .btn hardcodes white background) */
        body.dark-theme .btn { background: var(--surface); color: var(--text-main); border-color: var(--border); }
        body.dark-theme .btn:hover { background: var(--sidebar-hover); border-color: var(--primary); color: var(--primary); }
        body.dark-theme .btn.stop { background: linear-gradient(135deg, var(--danger), #b91c1c); color: #fff; border-color: #b91c1c; }
        body.dark-theme .form-input, body.dark-theme select.form-input, body.dark-theme input.form-input, body.dark-theme textarea.form-input { background: var(--surface); color: var(--text-main); border-color: var(--border); }
        body.dark-theme select, body.dark-theme input[type="text"], body.dark-theme input[type="search"], body.dark-theme input:not([type]), body.dark-theme textarea { background: var(--surface); color: var(--text-main); border-color: var(--border); }
        /* Table headers (light gradient hardcoded) */
        body.dark-theme .ws-table th, body.dark-theme .settings-table th { background: linear-gradient(180deg, #1e293b, #0f172a); color: var(--text-main); }
        /* Detail header (light gradient hardcoded) */
        body.dark-theme .detail-header { background: linear-gradient(135deg, #422006, #292524); color: #fdba74; }
        /* Session chip hover used --text (undefined); fall back to text-main */
        body.dark-theme .session-chip:hover, body.dark-theme .win-tab:hover { color: var(--text-main); }
        
        /* VS Code-style Vertical Sidebar */
        .vscode-layout { display: flex; height: calc(100vh - 70px); overflow: hidden; margin-top: 70px; }
        .activity-bar { width: 72px; background: var(--sidebar-bg); display: flex; flex-direction: column; align-items: center; padding: 18px 0; gap: 6px; border-right: 2px solid var(--border); flex-shrink: 0; box-shadow: var(--shadow); position: relative; backdrop-filter: blur(10px); }
        .activity-icon { width: 64px; height: 58px; display: flex; flex-direction: column; align-items: center; justify-content: center; cursor: pointer; color: var(--text-muted); font-size: 11px; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); border-left: 3px solid transparent; position: relative; border-radius: 8px; margin: 0 4px; font-weight: 600; }
        .activity-icon:hover { color: var(--primary); background: linear-gradient(135deg, var(--sidebar-hover), var(--accent-light)); transform: translateX(2px); box-shadow: var(--shadow-sm); }
        .activity-icon.active { color: white; border-left-color: var(--primary); background: linear-gradient(135deg, var(--primary), var(--primary-dark)); font-weight: 700; box-shadow: var(--shadow); }
        .activity-icon svg, .activity-icon span { pointer-events: none; }
        .icon-label { position: absolute; left: 78px; background: linear-gradient(135deg, var(--text-main), #1e293b); color: white; padding: 8px 14px; border-radius: 8px; font-size: 12px; white-space: nowrap; display: none; z-index: 1000; box-shadow: var(--shadow-lg); font-weight: 600; letter-spacing: 0.3px; animation: slideIn 0.2s ease-out; }
        .icon-label::before { content: ''; position: absolute; left: -4px; top: 50%; transform: translateY(-50%); width: 0; height: 0; border-top: 5px solid transparent; border-bottom: 5px solid transparent; border-right: 5px solid var(--text-main); }
        .activity-icon:hover .icon-label { display: block; }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        .ai-disabled { display: none !important; }
        .activity-bar-bottom { margin-top: auto; padding-top: 12px; border-top: 2px solid var(--border); width: 100%; display: flex; flex-direction: column; align-items: center; gap: 6px; }
        .theme-toggle { width: 56px; height: 44px; background: transparent; border: 2px solid var(--border); color: var(--text-muted); font-size: 11px; cursor: pointer; border-radius: 8px; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); font-weight: 700; box-shadow: var(--shadow-sm); }
        .theme-toggle:hover { background: linear-gradient(135deg, var(--sidebar-hover), var(--accent-light)); color: var(--primary); border-color: var(--primary); transform: scale(1.05); box-shadow: var(--shadow); }
        .stop-daemon-btn { width: 56px; height: 44px; background: linear-gradient(135deg, var(--danger), #b91c1c); border: none; color: white; font-size: 10px; cursor: pointer; border-radius: 8px; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); font-weight: 700; box-shadow: var(--shadow); }
        .stop-daemon-btn:hover { background: linear-gradient(135deg, #b91c1c, #991b1b); transform: scale(1.08); box-shadow: var(--shadow-lg); }
        
        .main-content { flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-solid); position: relative; }
        .main-content::before { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: radial-gradient(circle at top right, rgba(249, 115, 22, 0.03), transparent 50%), radial-gradient(circle at bottom left, rgba(249, 115, 22, 0.03), transparent 50%); pointer-events: none; z-index: 0; }
        .main-content > * { position: relative; z-index: 1; }
        
        .resizer { flex: 0 0 5px; background: var(--border); cursor: col-resize; transition: background 0.2s; z-index: 10; margin: 0 -8px; }
        .resizer:hover, .resizer.dragging { background: var(--primary); }
        .wireshark-view.vertical { flex-direction: column; }
        .wireshark-view.vertical .resizer { flex: 0 0 5px; width: 100%; cursor: row-resize; margin: -8px 0; }
        .wireshark-view.vertical .pane-left, .wireshark-view.vertical .pane-right { min-width: 100%; min-height: 100px; }
    </style>
    <script>
        // Define critical functions early so onclick handlers work
        function enterDashboard() {
            const landingPage = document.getElementById('landingPage');
            const vscodeLayout = document.getElementById('vscodeLayout');
            const mainNavbar = document.getElementById('mainNavbar');
            landingPage.style.transition = 'opacity 0.5s ease-out';
            landingPage.style.opacity = '0';
            setTimeout(() => {
                landingPage.classList.add('hidden');
                mainNavbar.style.display = 'flex';
                vscodeLayout.style.display = 'flex';
                localStorage.setItem('pktana_visited', 'true');
            }, 500);
        }

        function toggleTheme() {
            const body = document.body;
            const isDark = body.classList.toggle('dark-theme');
            const themeBtn = document.querySelector('.theme-toggle');
            if (themeBtn) themeBtn.textContent = isDark ? 'Light' : 'Dark';
            localStorage.setItem('pktana-theme', isDark ? 'dark' : 'light');
        }

        function isSessionScopedTab(tabId) {
            return tabId === 'dashboard' || tabId === 'flows' || tabId === 'stats' || tabId === 'hardware';
        }

        function switchTab(tabId) {
            // Gate interface-scoped tabs behind having an active session
            if (isSessionScopedTab(tabId) && !activeId) {
                document.getElementById('sb-status').textContent = 'Pick an interface in Server Info to open a capture window first.';
                switchTab('serverinfo');
                return;
            }
            document.querySelectorAll('.activity-icon').forEach(icon => icon.classList.remove('active'));
            const activeIcon = Array.from(document.querySelectorAll('.activity-icon')).find(icon =>
                icon.getAttribute('onclick') && icon.getAttribute('onclick').includes(tabId)
            );
            if (activeIcon) activeIcon.classList.add('active');
            document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            const tabBtn = document.querySelector(`[onclick="switchTab('${tabId}')"]`);
            if (tabBtn) tabBtn.classList.add('active');
            const panel = document.getElementById(tabId);
            if (panel) panel.classList.add('active');
            // Show session strip only for interface-scoped tabs
            const strip = document.getElementById('sessionStripGlobal');
            if (strip) strip.style.display = isSessionScopedTab(tabId) ? 'flex' : 'none';
            // When entering hardware tab, ensure data is loaded for active session's iface
            if (tabId === 'hardware' && activeId && Sessions[activeId] && !Sessions[activeId].isOffline) {
                if (typeof loadNicDetail === 'function') loadNicDetail();
                if (typeof loadEthtool === 'function') loadEthtool();
                if (typeof loadDataplane === 'function') loadDataplane();
            }
        }

        async function loadServerInfo() {
            try {
                const res = await fetch('/api/server_info');
                const data = await res.json();
                const formatBytes = (b) => { const u=['B','KB','MB','GB']; let i=0; while(b>=1024&&i<u.length-1){b/=1024;i++;} return b.toFixed(1)+' '+u[i]; };
                const formatUptime = (s) => { s=Math.floor(s); const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),sc=s%60; return (d?d+'d ':'')+(h?h+'h ':'')+(m?m+'m ':'')+sc+'s'; };
                const kvRow = (k,v) => `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #334155;"><strong>${k}:</strong><span>${v}</span></div>`;
                document.getElementById('serverContent').innerHTML =
                    kvRow('Hostname', data.hostname) +
                    kvRow('Kernel Version', data.version) +
                    kvRow('Uptime', formatUptime(parseFloat(data.uptime_sec))) +
                    kvRow('Total Memory', formatBytes(parseInt(data.mem_total_kb) * 1024));
            } catch (e) { document.getElementById('serverContent').innerHTML = 'Error loading server info'; }
        }

        async function loadInterfaces() {
            try {
                const res = await fetch('/api/interfaces');
                const ifaces = await res.json();
                let html = '';
                ifaces.forEach(iface => {
                    const statusColor = iface.is_up ? 'var(--success)' : 'var(--danger)';
                    const desc = iface.description || 'Network Interface';
                    html += `<div style="border:1px solid var(--border); border-radius:6px; padding:8px 12px; background:var(--surface); cursor:pointer; transition:all 0.2s;" 
                                  onclick="selectInterfaceForCapture('${iface.name}')" 
                                  onmouseover="this.style.borderColor='var(--primary)'" 
                                  onmouseout="this.style.borderColor='var(--border)'">
                        <div style="font-weight:700; color:var(--primary); font-size:13px;">${iface.name}</div>
                        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${desc}</div>
                        <div style="font-size:10px; margin-top:4px;"><span style="color:${statusColor}; font-weight:600;">${iface.is_up ? '●' : '○'} ${iface.is_up ? 'UP' : 'DOWN'}</span></div>
                    </div>`;
                });
                document.getElementById('serverInterfacesList').innerHTML = html;
            } catch (e) { document.getElementById('serverInterfacesList').innerHTML = 'Error loading interfaces'; }
        }

        function selectInterfaceForCapture(ifaceName) {
            // Open a per-interface capture window (creates new session)
            document.getElementById('currentIface').value = ifaceName;
            const bpf = document.getElementById('bpfFilter') ? document.getElementById('bpfFilter').value : '';
            addSession(ifaceName, bpf, false);
            switchTab('dashboard');
        }

        async function loadSessions() {
            try {
                const res = await fetch('/api/sessions');
                const sessions = await res.json();
                const list = document.getElementById('sessionsList');
                if (!sessions || sessions.length === 0) {
                    list.innerHTML = '<div style="text-align:center; padding:40px; color:var(--text-muted);"><div style="font-size:16px; margin-bottom:10px; font-weight:600;">No Active Sessions</div><div>Click "New Session" to start monitoring an interface.</div></div>';
                    return;
                }
                let html = '<table style="width:100%;border-collapse:collapse;"><tr style="background:#334155;"><th style="padding:8px;text-align:left;">ID</th><th style="padding:8px;text-align:left;">Interface</th><th style="padding:8px;text-align:left;">Status</th><th style="padding:8px;text-align:left;">Actions</th></tr>';
                sessions.forEach(s => {
                    const viewBtn = `<button class="primary-btn" style="padding:4px 12px;font-size:12px;" onclick="viewSession('${s.id}', '${s.interface}')">View</button>`;
                    const stopBtn = s.status === 'Active' ? `<button class="btn" style="padding:4px 12px;font-size:12px;" onclick="stopSession('${s.id}')">Stop</button>` : '';
                    const deleteBtn = `<button class="btn" style="padding:4px 12px;font-size:12px;background:#dc2626;color:white;border:none;" onclick="deleteSession('${s.id}')">Delete</button>`;
                    html += `<tr style="border-bottom:1px solid #334155;"><td style="padding:8px;">${s.id}</td><td style="padding:8px;">${s.interface}</td><td style="padding:8px;"><span style="color:${s.status === 'Active' ? '#10b981' : '#ef4444'};">${s.status}</span></td><td style="padding:8px;white-space:nowrap;">${viewBtn} ${stopBtn} ${deleteBtn}</td></tr>`;
                });
                html += '</table>';
                list.innerHTML = html;
            } catch (e) { console.error('Error loading sessions:', e); }
        }

        function viewSession(sessionId, ifaceName) {
            // Store the session ID globally
            window.currentSessionId = sessionId;
            
            // Set the current interface
            document.getElementById('currentIface').value = ifaceName;
            
            // Switch to packet analyzer tab
            switchTab('dashboard');
            
            // Connect to existing session stream (don't restart)
            if (typeof connectToSession === 'function') {
                connectToSession(sessionId, ifaceName);
            } else {
                // Fallback - will be overridden when full function loads
                console.log('Connecting to session:', sessionId);
            }
        }

        // Ensure these are available globally
        window.viewSession = viewSession;
        window.loadSessions = loadSessions;

        function showCreateSessionDialog() {
            const iface = prompt('Enter interface name (e.g., eth0):');
            if (!iface) return;
            fetch('/api/sessions/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface })
            }).then(res => res.json()).then(data => {
                alert('Session created: ' + data.id);
                loadSessions();
            }).catch(e => alert('Error: ' + e));
        }

        function stopSession(id) {
            fetch(`/api/sessions/${id}/stop`, { method: 'POST' })
                .then(() => loadSessions())
                .catch(e => alert('Error: ' + e));
        }

        function deleteSession(id) {
            if (confirm('Delete this session?')) {
                fetch(`/api/sessions/${id}`, { method: 'DELETE' })
                    .then(() => loadSessions())
                    .catch(e => alert('Error: ' + e));
            }
        }
    </script>
</head>
<body>
    <!-- Landing Page -->
    <div class="landing-page" id="landingPage">
        <img src="/pktana.png" alt="pktana Network Analyzer" onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22200%22 height=%22200%22%3E%3Ctext x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 dy=%22.3em%22 font-size=%2224%22 fill=%22white%22%3Epktana%3C/text%3E%3C/svg%3E'">
        <h1>Welcome to pktana</h1>
        <p>Enterprise Network Packet Analyzer & Deep Inspection Tool</p>
        <button class="landing-btn" onclick="enterDashboard()">Launch Dashboard</button>
    </div>

    <!-- Top Navbar (Fixed at top) -->
    <div class="navbar" id="mainNavbar" style="display:none;">
        <div class="logo">
            <span>pktana</span>
        </div>
        <div class="nav-controls" style="font-size:13px; color:var(--text-muted);">
            Network Traffic Analyzer
        </div>
    </div>

    <!-- VS Code Style Layout -->
    <div class="vscode-layout" id="vscodeLayout" style="display:none;">
        <!-- Vertical Activity Bar (Left Sidebar) -->
        <div class="activity-bar">
            <div class="activity-icon active" onclick="switchTab('serverinfo')" title="Server Info">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff8c42" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                    <line x1="6" y1="6" x2="6.01" y2="6"></line>
                    <line x1="6" y1="18" x2="6.01" y2="18"></line>
                </svg>
                <div class="icon-label">Server Info</div>
            </div>
            <div class="activity-icon" onclick="switchTab('pcap')" title="PCAP Analyzer">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff8c42" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="16" y1="13" x2="8" y2="13"></line>
                    <line x1="16" y1="17" x2="8" y2="17"></line>
                    <polyline points="10 9 9 9 8 9"></polyline>
                </svg>
                <div class="icon-label">PCAP File</div>
            </div>
            <div class="activity-icon" onclick="switchTab('connections')" title="Connections">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff8c42" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="18" cy="5" r="3"></circle>
                    <circle cx="6" cy="12" r="3"></circle>
                    <circle cx="18" cy="19" r="3"></circle>
                    <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
                    <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
                </svg>
                <div class="icon-label">Connections</div>
            </div>
            <div class="activity-icon" onclick="switchTab('terminal')" title="Terminal">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff8c42" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="4 17 10 11 4 5"></polyline>
                    <line x1="12" y1="19" x2="20" y2="19"></line>
                </svg>
                <div class="icon-label">Terminal</div>
            </div>
            <div class="activity-icon" onclick="switchTab('routes')" title="Routing Table">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff8c42" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="3 6 5 12 3 18"></polyline>
                    <polyline points="21 6 19 12 21 18"></polyline>
                    <line x1="8" y1="6" x2="16" y2="6"></line>
                    <line x1="8" y1="12" x2="16" y2="12"></line>
                    <line x1="8" y1="18" x2="16" y2="18"></line>
                </svg>
                <div class="icon-label">Routes</div>
            </div>
            <div class="activity-icon" onclick="switchTab('nics')" title="Network Interfaces (NIC Stats)">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff8c42" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="2" y="6" width="20" height="12" rx="2"></rect>
                    <circle cx="8" cy="12" r="1.5" fill="#ff8c42"></circle>
                    <circle cx="12" cy="12" r="1.5" fill="#ff8c42"></circle>
                    <circle cx="16" cy="12" r="1.5" fill="#ff8c42"></circle>
                </svg>
                <div class="icon-label">NICs</div>
            </div>
            <div class="activity-icon" onclick="switchTab('geoip')" title="GeoIP Lookup">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff8c42" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="2" y1="12" x2="22" y2="12"></line>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                </svg>
                <div class="icon-label">GeoIP</div>
            </div>
            <div class="activity-icon" onclick="switchTab('docs')" title="Documentation">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff8c42" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
                    <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
                </svg>
                <div class="icon-label">Docs</div>
            </div>

            <!-- Bottom Controls -->
            <div class="activity-bar-bottom">
                <button class="theme-toggle" onclick="toggleTheme()" title="Toggle Light/Dark Theme">Dark</button>
                <button class="stop-daemon-btn" onclick="stopDaemon()" title="Stop pktana Daemon">Stop</button>
            </div>
        </div>

        <!-- Main Content Area -->
        <div class="main-content">
            <!-- Per-session window strip (visible only for interface-scoped tabs) -->
            <div id="sessionStripGlobal" class="session-strip" style="display:none;"></div>
            <!-- Per-window inner tab bar (Packets/Flows/Stats/Hardware) -->
            <div id="windowTabs" class="window-tabs" style="display:none;">
                <button class="win-tab active" data-tab="dashboard" onclick="switchTab('dashboard')">📊 Packets</button>
                <button class="win-tab" data-tab="flows" onclick="switchTab('flows')">🔗 Flows</button>
                <button class="win-tab" data-tab="stats" onclick="switchTab('stats')">📈 Protocols</button>
                <button class="win-tab" data-tab="hardware" onclick="switchTab('hardware')">⚙️ Hardware</button>
            </div>
            <!-- Content Panels (no horizontal tabs) -->
    <div class="container">
        <input type="hidden" id="currentIface" value="">

        <!-- Server Info Panel -->
        <div id="serverinfo" class="panel active">
            <div class="grid-3">
                <div class="card">
                    <div class="card-title">System Information</div>
                    <div class="kv-list" id="serverContent">Loading...</div>
                </div>
                <div class="card" style="grid-column: span 2;">
                    <div class="card-title" style="font-size:13px; font-weight:600; color:var(--text-muted); margin-bottom:12px;">SELECT INTERFACE TO CAPTURE:</div>
                    <div id="serverInterfacesList" style="display:flex; flex-wrap:wrap; gap:8px; min-height:100px; max-height:240px; overflow-y:auto;">Loading interfaces...</div>
                </div>
            </div>
            
            <!-- Session Manager -->
            <div class="card" style="margin: 20px;">
                <div class="card-title">
                    Active Capture Sessions
                    <div style="float:right; display:flex; gap:10px; align-items:center;">
                        <button class="primary-btn" onclick="showCreateSessionDialog()">New Session</button>
                        <button class="btn" onclick="loadSessions()">Refresh</button>
                    </div>
                </div>
                <div id="sessionsList" style="overflow-x:auto; overflow-y:auto; min-height:200px; max-height:360px;">
                    <div style="text-align:center; padding:40px; color:var(--text-muted);">
                        <div style="font-size:16px; margin-bottom:10px; font-weight:600;">No Active Sessions</div>
                        <div>Click "New Session" to start monitoring an interface.</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- PCAP Panel -->
        <div id="pcap" class="panel">
            <div class="card" style="margin: 20px; max-width: 600px;">
                <div class="card-title">Analyze PCAP File</div>
                <div style="display:flex; flex-direction:column; gap:15px;">
                    <div>
                        <label style="font-weight:bold; font-size:13px; color:var(--text-muted);">Path to PCAP on Server:</label><br>
                        <div style="display:flex; gap:10px; margin-top:5px;">
                            <input type="text" id="pcapRead" class="form-input" placeholder="/var/log/capture.pcap" style="flex-grow:1;">
                            <button class="primary-btn" onclick="analyzePcap()">Analyze Server PCAP</button>
                        </div>
                    </div>
                    <hr style="border:0; border-top:1px dashed var(--border); margin:10px 0;">
                    <div>
                        <label style="font-weight:bold; font-size:13px; color:var(--text-muted);">Upload PCAP from Local Machine:</label><br>
                        <div style="display:flex; gap:10px; margin-top:5px;">
                            <input type="file" id="pcapUpload" class="form-input" style="flex-grow:1;" accept=".pcap,.pcapng,.cap">
                            <button class="primary-btn" onclick="uploadPcap()">Upload & Analyze</button>
                        </div>
                        <span style="font-size:11px; color:var(--text-muted);">(Upload requires backend multipart API update)</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Packet Analyzer / Dashboard -->
        <div id="dashboard" class="panel">
            <div class="panel-toolbar">
                <div class="toolbar-group">
                    <button id="btnToggle" class="primary-btn" onclick="toggleCapture()">▶ Start Capture</button>
                    <button id="btnPause" class="btn" onclick="togglePause()" style="display:none;">⏸ Pause UI</button>
                </div>
                <div class="toolbar-group">
                    <span class="toolbar-label">Protocol</span>
                    <select id="streamFilter" class="form-input" onchange="applyStreamFilter()" style="width: 180px;">
                        <option value="">All Traffic</option>
                        <optgroup label="Basic Protocols">
                            <option value="tcp">TCP</option>
                            <option value="udp">UDP</option>
                            <option value="icmp">ICMP</option>
                            <option value="arp">ARP</option>
                        </optgroup>
                        <optgroup label="Application">
                            <option value="http">HTTP/HTTPS</option>
                            <option value="dns">DNS</option>
                            <option value="dhcp">DHCP</option>
                            <option value="tls">TLS/SSL</option>
                            <option value="ssh">SSH</option>
                            <option value="ftp">FTP</option>
                        </optgroup>
                        <optgroup label="Advanced Protocols">
                            <option value="quic">QUIC/HTTP3</option>
                            <option value="http2">HTTP/2</option>
                            <option value="grpc">gRPC</option>
                            <option value="websocket">WebSocket</option>
                            <option value="sip">SIP/VoIP</option>
                            <option value="ntp">NTP</option>
                            <option value="bgp">BGP</option>
                            <option value="tunnel">Tunnels (VXLAN/GRE/Geneve)</option>
                        </optgroup>
                        <optgroup label="Flow Analysis">
                            <option value="tcp_handshake">🔄 TCP Handshakes (SYN)</option>
                            <option value="tls_handshake">🔒 TLS Handshakes</option>
                            <option value="dns_transaction">🌐 DNS Queries</option>
                            <option value="dhcp_dora">📡 DHCP DORA</option>
                        </optgroup>
                    </select>
                </div>
                <div class="toolbar-group">
                    <span class="toolbar-label">Search</span>
                    <input type="text" id="displayFilter" class="form-input" placeholder="Search packets..." onkeyup="applyDisplayFilter()" style="width: 180px;">
                </div>
                <div class="toolbar-group">
                    <span class="toolbar-label">BPF Filter</span>
                    <input type="text" id="bpfFilter" class="form-input" placeholder="e.g. tcp port 80" title="Capture-time BPF filter (applied on next start)" style="width: 160px;">
                </div>
                <div class="toolbar-separator"></div>
                <div class="toolbar-group" style="gap: 4px;">
                    <button class="btn" onclick="toggleLayoutDir()" title="Toggle Split Direction" style="padding: 8px 12px;">⇄</button>
                    <button class="btn" onclick="togglePane('paneRight')" title="Toggle Details Panel" style="padding: 8px 12px;">📋</button>
                    <button class="btn" onclick="toggleHex()" title="Toggle Hex View" style="padding: 8px 12px;">🔢</button>
                </div>
            </div>
            
            <div class="wireshark-view" id="wsView">
                <div class="pane-left" id="paneLeft" style="flex: 0 0 60%;">
                    <div id="tableContainer"><table class="ws-table">
                        <thead>
                            <tr>
                                <th style="width: 50px;">No.</th>
                                <th style="width: 90px;">Time</th>
                                <th style="width: 160px;">Source</th>
                                <th style="width: 160px;">Destination</th>
                                <th style="width: 70px;">Proto</th>
                                <th style="width: 50px;">Len</th>
                                <th>Info</th>
                            </tr>
                        </thead>
                        <tbody id="pktTableBody"></tbody>
                    </table></div>
                    <div id="resumeScrollBtn" class="scroll-toast" style="display: none;" onclick="resumeScroll()">
                        Auto-scroll paused. Click to resume.
                    </div>
                </div>
                <div class="resizer" id="dragMe"></div>
                <div class="pane-right" id="paneRight" style="flex: 1 1 0%;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <div class="section-label" style="margin-bottom:0;">Packet Details</div>
                    </div>
                    <div class="pane-detail" id="packetDetail">Select a packet to view its complete DPI decode layer by layer...</div>
                    <div id="packetHexWrapper" style="display:none; flex-direction:column; flex:2; margin-top:10px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <div class="section-label" style="margin-bottom:0;">Hex Dump</div>
                            <span id="hexByteInfo" style="font-size:11px; color:var(--text-muted); font-weight:600;"></span>
                        </div>
                        <div class="pane-hex" id="packetHex" style="flex:1; padding:14px 16px;"></div>
                    </div>
                </div>
            </div>
            <div class="statusbar">
                <span id="sb-status">Idle. Ready to capture.</span>
                <span id="sb-stats">Packets: 0 | Displayed: 0 | Bytes: 0 B</span>
            </div>
        </div>

        <!-- Flows Panel -->
        <div id="flows" class="panel">
            <div class="card" style="margin: 20px;">
                <div class="card-title">
                    Network Flows
                    <div style="float:right; display:flex; gap:10px;">
                        <input type="text" id="flowSearch" class="form-input" placeholder="Search flows..." onkeyup="filterTable('flowContent', this.value)" style="padding: 4px 8px;">
                    </div>
                </div>
                <div style="overflow-x:auto; overflow-y:auto; max-height:calc(100vh - 200px);">
                    <table class="settings-table">
                        <thead>
                            <tr><th>Proto</th><th>Source</th><th>Destination</th><th>Category</th><th>Packets</th><th>Bytes</th></tr>
                        </thead>
                        <tbody id="flowContent"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Stats Panel -->
        <div id="stats" class="panel">
            <div class="panel-toolbar">
                <input type="text" id="statsFilter" class="form-input" placeholder="Filter Statistics..." onkeyup="renderStats(this.value)" style="width: 250px;">
            </div>
            <div class="grid-3">
                <div class="card">
                    <div class="card-title">Protocol Breakdown</div>
                    <div class="kv-list" id="protoBreakdown">No data yet.</div>
                </div>
                <div class="card">
                    <div class="card-title">Top Talkers (By Bytes)</div>
                    <div class="kv-list" id="topTalkers">No data yet.</div>
                </div>
                <div class="card">
                    <div class="card-title">Traffic Overview</div>
                    <div class="kv-list" id="trafficOverview">No data yet.</div>
                </div>
            </div>
        </div>

        <!-- Hardware Panel -->
        <div id="hardware" class="panel">
            <div class="grid-3">
                <div class="card"><div class="card-title">Hardware Status</div><div class="kv-list" id="hwStatus">Select an interface above.</div></div>
                <div class="card"><div class="card-title">Driver & Queues (Ethtool)</div><div class="kv-list" id="driverStatus">Select an interface above.</div></div>
                <div class="card"><div class="card-title">Dataplane Path</div><div class="kv-list" id="dpStatus">Select an interface above.</div></div>
            </div>
        </div>

        <!-- Connections Panel -->
        <div id="connections" class="panel">
            <div class="card" style="margin: 20px;">
                <div class="card-title">
                    Active Sockets (TCP/UDP) 
                    <div style="float:right; display:flex; gap:10px;">
                        <input type="text" class="form-input" placeholder="Search..." onkeyup="filterTable('connContent', this.value)" style="padding: 4px 8px;">
                        <button class="btn" onclick="loadConnections()">Refresh</button>
                    </div>
                </div>
                <div id="connContent" style="overflow-x:auto; overflow-y:auto; max-height:calc(100vh - 260px);">Loading...</div>
            </div>
        </div>

        <!-- Routes Panel -->
        <div id="routes" class="panel">
            <div class="card" style="margin: 20px;">
                <div class="card-title">
                    System Routing Table 
                    <div style="float:right; display:flex; gap:10px;">
                        <input type="text" class="form-input" placeholder="Search..." onkeyup="filterTable('routeContent', this.value)" style="padding: 4px 8px;">
                        <button class="btn" onclick="loadRoutes()">Refresh</button>
                    </div>
                </div>
                <div id="routeContent" style="overflow-x:auto; overflow-y:auto; max-height:calc(100vh - 260px);">Loading...</div>
            </div>
        </div>

        <!-- NICs Panel -->
        <div id="nics" class="panel">
            <div class="card" style="margin: 20px;">
                <div class="card-title">
                    All Network Interfaces
                    <div style="float:right; display:flex; gap:10px;">
                        <input type="text" class="form-input" placeholder="Search..." onkeyup="filterTable('nicContent', this.value)" style="padding: 4px 8px;">
                        <button class="btn" onclick="loadNics()">Refresh</button>
                    </div>
                </div>
                <div id="nicContent" style="overflow-x:auto; overflow-y:auto; max-height:calc(100vh - 260px);">Loading...</div>
            </div>
        </div>

        <!-- GeoIP Panel -->
        <div id="geoip" class="panel">
            <div class="card" style="margin: 20px; display:flex; gap:10px; align-items:center;">
                <label>IP Lookup:</label>
                <input type="text" id="geoIpInput" class="form-input" placeholder="e.g. 8.8.8.8" style="flex-grow:1;">
                <button class="btn" onclick="loadGeoIp()">Lookup</button>
            </div>
            <div class="card" id="geoContent" style="margin: 0 20px;">Enter an IP to lookup...</div>
        </div>

        <!-- Terminal Panel -->
        <div id="terminal" class="panel">
            <div class="card" style="margin: 20px; display:flex; flex-direction:column; height: calc(100vh - 150px); background:#000; border-color:#1e293b; padding:0; box-shadow: 0 4px 20px rgba(0,0,0,0.3);">
                <div style="background: linear-gradient(135deg, #1e293b, #0f172a); color:#94a3b8; border-bottom:1px solid #334155; padding:12px 16px; margin-bottom:0; display: flex; justify-content: space-between; align-items: center;">
                    <div style="display:flex; align-items:center; gap:12px;">
                        <span style="font-weight:700; font-size:14px;">🖥️ Professional Terminal</span>
                        <span style="font-size:11px; color:#64748b;">|</span>
                        <span style="font-size:12px; color:#38bdf8;">Full Linux Terminal with xterm.js</span>
                    </div>
                    <div style="display:flex; gap:8px;">
                        <button class="btn" onclick="clearXterm()" title="Clear terminal" style="padding:4px 10px; font-size:11px;">Clear</button>
                        <button class="btn" onclick="resetXterm()" title="Reset terminal" style="padding:4px 10px; font-size:11px;">Reset</button>
                        <select id="xtermTheme" onchange="changeXtermTheme()" class="form-input" style="padding:4px 8px; font-size:11px; width:120px;">
                            <option value="default">Default</option>
                            <option value="matrix">Matrix Green</option>
                            <option value="monokai">Monokai</option>
                            <option value="nord">Nord</option>
                            <option value="dracula">Dracula</option>
                            <option value="solarized-dark">Solarized Dark</option>
                            <option value="ubuntu">Ubuntu</option>
                        </select>
                    </div>
                </div>
                <div id="xtermContainer" style="flex-grow:1; padding:10px; overflow:hidden;"></div>
                <div style="background:#0f172a; border-top:1px solid #334155; padding:6px 16px; font-size:11px; color:#64748b; display:flex; justify-content:space-between;">
                    <span>Full Linux terminal with xterm.js | Copy: <strong style="color:#94a3b8;">Ctrl+Shift+C</strong> | Paste: <strong style="color:#94a3b8;">Ctrl+Shift+V</strong></span>
                    <span id="xtermStatus">Ready</span>
                </div>
            </div>
        </div>
        <!-- Docs Panel -->
        <div id="docs" class="panel">
            <div style="display:flex; height:calc(100vh - 110px); gap:0; overflow:hidden;">
                <div id="docsNav" style="width:210px; flex-shrink:0; background:var(--surface); border-right:1px solid var(--border); overflow-y:auto; padding:8px 0;">
                    <div style="padding:10px 16px 6px; font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.08em;">Documentation</div>
                </div>
                <div id="docsContent" style="flex:1; overflow-y:auto; padding:28px 36px; font-family:inherit; line-height:1.75; color:var(--text-main);">
                    <div style="color:var(--text-muted); text-align:center; padding-top:80px;">
                        <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" style="display:block; margin:0 auto 16px; opacity:0.3;"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
                        <p style="font-size:16px;">Select a page from the sidebar to read the documentation.</p>
                    </div>
                </div>
            </div>
        </div>
        </div> <!-- Close main-content -->
    </div> <!-- Close vscode-layout -->

    <script>
        // ─── Multi-session state ─────────────────────────────────────────────
        // Each interface capture is its own session with its own buffers.
        // The active session is what the dashboard table / flows / stats show.
        const Sessions = {};
        let activeId = null;

        // Active-session mirrors (kept so legacy renderers like renderFlows /
        // renderStats / showDetail keep working unchanged).
        let eventSource = null;
        let packetCount = 0;
        let byteCount = 0;
        let isCapturing = false;
        let packetStore = [];
        let baseTs = null;
        let autoScroll = true;
        let flows = {};
        let protoStats = {};
        let talkerStats = {};
        let geoCache = {};

        // Performance optimization: batch packet updates (active session only)
        let packetBuffer = [];
        let updateTimer = null;
        let isPaused = false;
        const MAX_PACKETS_IN_MEMORY = 10000;
        const UPDATE_INTERVAL_MS = 100;

        // Legacy refs (no longer used for storage; kept so old code paths don't break)
        window.currentSessionId = null;
        window.sessionPacketStores = {};
        window.sessionFlowData = {};

        function newSessionState(id, iface, isOffline) {
            return {
                id, iface, isOffline,
                status: 'active', paused: false,
                packetStore: [], flows: {}, protoStats: {}, talkerStats: {}, geoCache: {},
                packetCount: 0, byteCount: 0, baseTs: null,
                eventSource: null, autoScroll: true
            };
        }

        function bindActive(id) {
            activeId = id;
            window.currentSessionId = id;
            const S = Sessions[id];
            if (!S) {
                packetStore = []; flows = {}; protoStats = {}; talkerStats = {}; geoCache = {};
                packetCount = 0; byteCount = 0; baseTs = null;
                eventSource = null; isCapturing = false; isPaused = false;
                return;
            }
            packetStore = S.packetStore;
            flows = S.flows;
            protoStats = S.protoStats;
            talkerStats = S.talkerStats;
            geoCache = S.geoCache;
            packetCount = S.packetCount;
            byteCount = S.byteCount;
            baseTs = S.baseTs;
            eventSource = S.eventSource;
            isCapturing = (S.status === 'active');
            isPaused = S.paused;
            autoScroll = S.autoScroll !== undefined ? S.autoScroll : true;
            packetBuffer = [];
            const ifaceEl = document.getElementById('currentIface');
            if (ifaceEl) ifaceEl.value = S.iface;
        }

        function ensureRenderTimer() {
            if (updateTimer) return;
            updateTimer = setInterval(() => {
                if (!isPaused) processPendingPackets();
            }, UPDATE_INTERVAL_MS);
        }

        async function getGeoIp(ip) {
            if (geoCache[ip]) return geoCache[ip];
            try {
                const res = await fetch(`/api/geoip?ip=${encodeURIComponent(ip)}`);
                const data = await res.json();
                const geoStr = data.country_code !== '--' && data.country_code ? `${data.country_code}` : 'LAN';
                geoCache[ip] = geoStr;
                return geoStr;
            } catch (e) {
                geoCache[ip] = 'Unknown';
                return 'Unknown';
            }
        }

        function updateStats(data) {
            if (!protoStats[data.proto]) protoStats[data.proto] = { pkts: 0, bytes: 0 };
            protoStats[data.proto].pkts++;
            protoStats[data.proto].bytes += data.len;

            if (!talkerStats[data.src]) talkerStats[data.src] = { pkts: 0, bytes: 0 };
            talkerStats[data.src].pkts++;
            talkerStats[data.src].bytes += data.len;
            if (!talkerStats[data.dst]) talkerStats[data.dst] = { pkts: 0, bytes: 0 };
            talkerStats[data.dst].pkts++;
            talkerStats[data.dst].bytes += data.len;

            let flowKey1 = `${data.proto}-${data.src}-${data.dst}`;
            let flowKey2 = `${data.proto}-${data.dst}-${data.src}`;
            let key = flows[flowKey2] ? flowKey2 : flowKey1;
            
            if (!flows[key]) {
                flows[key] = { proto: data.proto, src: data.src, dst: data.dst, category: data.category, pkts: 0, bytes: 0 };
            }
            flows[key].pkts++;
            flows[key].bytes += data.len;
        }

        setInterval(() => {
            if (isCapturing || document.getElementById('flows').classList.contains('active')) {
                renderFlows();
                const flowTerm = document.getElementById('flowSearch')?.value.toLowerCase() || '';
                if (flowTerm) filterTable('flowContent', flowTerm);
            }
            if (isCapturing || document.getElementById('stats').classList.contains('active')) {
                renderStats();
            }
        }, 2000);

        function renderFlows() {
            const tbody = document.getElementById('flowContent');
            if (!tbody) return;
            const sortedFlows = Object.values(flows).sort((a, b) => b.bytes - a.bytes).slice(0, 100);
            let html = '';
            for (let f of sortedFlows) {
                html += `<tr style="cursor:pointer;" title="Click to view packets for this flow" onclick="viewFlowDetails('${f.src}', '${f.dst}')">
                    <td><strong>${escapeHtml(f.proto)}</strong></td>
                    <td>${escapeHtml(f.src)}</td>
                    <td>${escapeHtml(f.dst)}</td>
                    <td>${escapeHtml(f.category)}</td>
                    <td>${f.pkts}</td>
                    <td>${formatBytes(f.bytes)}</td>
                    <td style="text-align:center;"></td>
                </tr>`;
            }
            tbody.innerHTML = html;
        }

        async function renderStats(filterTerm = '') {
            if (typeof filterTerm !== 'string') {
                filterTerm = document.getElementById('statsFilter')?.value.toLowerCase() || '';
            }
            
            const protoDiv = document.getElementById('protoBreakdown');
            const talkerDiv = document.getElementById('topTalkers');
            const overviewDiv = document.getElementById('trafficOverview');
            if (!protoDiv || !talkerDiv || !overviewDiv) return;

            let totalProtoBytes = Object.values(protoStats).reduce((sum, s) => sum + s.bytes, 0);
            let pHtml = '';
            const sortedProtos = Object.entries(protoStats).sort((a, b) => b[1].bytes - a[1].bytes);
            for (let [p, s] of sortedProtos) {
                if (filterTerm && !p.toLowerCase().includes(filterTerm)) continue;
                let pct = totalProtoBytes > 0 ? (s.bytes / totalProtoBytes * 100).toFixed(1) : 0;
                pHtml += `<div style="margin-bottom: 8px;">
                    <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:2px;">
                        <strong>${p}</strong>
                        <span>${formatBytes(s.bytes)} (${pct}%)</span>
                    </div>
                    <div style="width:100%; background:var(--border); border-radius:4px; height:8px; overflow:hidden;">
                        <div style="width:${pct}%; background:var(--primary); height:100%;"></div>
                    </div>
                </div>`;
            }
            protoDiv.innerHTML = pHtml || 'No data matched filter.';

            let tHtml = '';
            const sortedTalkers = Object.entries(talkerStats).sort((a, b) => b[1].bytes - a[1].bytes);
            let count = 0;
            for (let [t, s] of sortedTalkers) {
                let geo = geoCache[t];
                if (filterTerm && !t.toLowerCase().includes(filterTerm) && !(geo && geo.toLowerCase().includes(filterTerm))) continue;
                if (count >= 10) continue; // Only show top 10 matched
                
                if (!geo && !t.includes(':') && /^[0-9a-fA-F\.]+$/.test(t)) {
                    getGeoIp(t).then(g => {
                        if (document.getElementById('stats').classList.contains('active')) {
                            renderStats(filterTerm);
                        }
                    });
                    geo = '...';
                }
                const geoLabel = geo ? ` <span class="badge badge-info">${geo}</span>` : '';
                tHtml += kvRow(t + geoLabel, `${formatBytes(s.bytes)} (${s.pkts} pkts)`);
                count++;
            }
            talkerDiv.innerHTML = tHtml || 'No data matched filter.';

            overviewDiv.innerHTML = 
                kvRow("Total Packets", packetCount) +
                kvRow("Total Bytes", formatBytes(byteCount)) +
                kvRow("Unique Flows", Object.keys(flows).length) +
                kvRow("Unique Endpoints", Object.keys(talkerStats).length);
        }

        // Theme preference loading only (landing page check moved to main DOMContentLoaded)
        window.addEventListener('DOMContentLoaded', () => {
            const savedTheme = localStorage.getItem('pktana-theme');
            const body = document.body;
            const themeBtn = document.querySelector('.theme-toggle');
            
            if (savedTheme === 'dark') {
                body.classList.add('dark-theme');
                if (themeBtn) themeBtn.textContent = '☀️';
            }
        });

        function filterTable(containerId, query) {
            const terms = query.toLowerCase().split(/\s+/).filter(t => t);
            let rows = document.getElementById(containerId).getElementsByTagName('tr');
            for (let i = 0; i < rows.length; i++) {
                if (rows[i].getElementsByTagName('th').length > 0) continue; // Skip header row
                let txt = (rows[i].textContent || rows[i].innerText).toLowerCase();
                rows[i].style.display = (terms.length === 0 || rowMatchesFilter(txt, terms)) ? "" : "none";
            }
        }

        document.getElementById('tableContainer').addEventListener('scroll', function() {
            const container = this;
            const isAtBottom = container.scrollHeight - container.clientHeight <= container.scrollTop + 30;
            if (!isAtBottom && autoScroll) {
                autoScroll = false;
                if (activeId && Sessions[activeId]) Sessions[activeId].autoScroll = false;
                document.getElementById('resumeScrollBtn').style.display = 'block';
            } else if (isAtBottom && !autoScroll) {
                autoScroll = true;
                if (activeId && Sessions[activeId]) Sessions[activeId].autoScroll = true;
                document.getElementById('resumeScrollBtn').style.display = 'none';
            }
        });

        function resumeScroll() {
            autoScroll = true;
            if (activeId && Sessions[activeId]) Sessions[activeId].autoScroll = true;
            document.getElementById('resumeScrollBtn').style.display = 'none';
            const container = document.getElementById('tableContainer');
            container.scrollTop = container.scrollHeight;
        }

        function rowMatchesFilter(text, terms) {
            for (const tok of terms) {
                if (tok.includes('|')) {
                    const alts = tok.split('|').filter(a => a);
                    if (!alts.some(a => text.includes(a))) return false;
                } else if (!text.includes(tok)) {
                    return false;
                }
            }
            return true;
        }

        function getRequiredTag() {
            const sel = document.getElementById('streamFilter');
            if (!sel) return '';
            const tagMap = {
                'tcp_handshake': 'tcp-handshake',
                'tls_handshake': 'tls-handshake',
                'dns_transaction': 'dns-query',
                'dhcp_dora': 'dhcp-dora'
            };
            return tagMap[sel.value] || '';
        }

        function packetMatchesFilter(tr, terms, requiredTag) {
            if (requiredTag) {
                const tags = tr.getAttribute('data-tags') || '';
                if (!tags.split(',').includes(requiredTag)) return false;
            }
            if (terms.length === 0) return true;
            return rowMatchesFilter(tr.textContent.toLowerCase(), terms);
        }

        function getDisplayFilterTerms() {
            const el = document.getElementById('displayFilter');
            if (!el) return [];
            return el.value.toLowerCase().split(/\s+/).filter(t => t.trim() !== '');
        }

        function applyDisplayFilter() {
            const terms = getDisplayFilterTerms();
            const requiredTag = getRequiredTag();
            const rows = document.getElementById('pktTableBody').getElementsByTagName('tr');
            let visibleCount = 0;
            for (let i = 0; i < rows.length; i++) {
                const show = packetMatchesFilter(rows[i], terms, requiredTag);
                rows[i].style.display = show ? "" : "none";
                if (show) visibleCount++;
            }
            const sb = document.getElementById('sb-stats');
            if (sb) sb.textContent = `Packets: ${packetCount} | Displayed: ${visibleCount} | Bytes: ${formatBytes(byteCount)}`;
        }
        
        function applyStreamFilter() {
            const filterValue = document.getElementById('streamFilter').value;
            const displayFilterInput = document.getElementById('displayFilter');
            
            // Map non-tag filter selection to display filter text (use | for OR)
            const filterMap = {
                'tcp': 'tcp',
                'udp': 'udp',
                'http': 'http',
                'dns': 'dns',
                'dhcp': 'dhcp',
                'tls': 'tls',
                'ssh': 'ssh',
                'ftp': 'ftp',
                'icmp': 'icmp',
                'arp': 'arp',
                'quic': 'quic',
                'http2': 'http2',
                'grpc': 'grpc',
                'websocket': 'websocket',
                'sip': 'sip',
                'ntp': 'ntp',
                'bgp': 'bgp',
                'tunnel': 'vxlan|gre|geneve'
            };
            
            // Tag-based selections clear the text filter; the tag is consumed by getRequiredTag()
            const tagSelections = ['tcp_handshake','tls_handshake','dns_transaction','dhcp_dora'];
            if (tagSelections.includes(filterValue)) {
                displayFilterInput.value = '';
            } else {
                displayFilterInput.value = filterMap[filterValue] || '';
            }
            applyDisplayFilter();
        }
        
        function viewFlowDetails(src, dst) {
            document.getElementById('displayFilter').value = `${src} ${dst}`;
            switchTab('dashboard');
            applyDisplayFilter();
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function getWsClass(proto, risk) {
            if (risk > 40) return 'ws-bg-bad';
            let p = proto.toUpperCase();
            if (p.includes('TCP')) return 'ws-bg-tcp';
            if (p.includes('UDP')) return 'ws-bg-udp';
            if (p.includes('HTTP') || p.includes('TLS') || p.includes('SSL') || p.includes('QUIC') || p.includes('WEBSOCKET') || p.includes('GRPC')) return 'ws-bg-http';
            if (p.includes('DNS')) return 'ws-bg-dns';
            if (p.includes('ICMP')) return 'ws-bg-icmp';
            if (p.includes('ARP')) return 'ws-bg-arp';
            return 'ws-bg-def';
        }

        // Enhanced switchTab that loads data for each tab
        window.switchTab = function(tabId) {
            // Gate interface-scoped tabs behind having an active session
            if (typeof isSessionScopedTab === 'function' && isSessionScopedTab(tabId) && !activeId) {
                document.getElementById('sb-status').textContent = 'Pick an interface in Server Info to open a capture window first.';
                tabId = 'serverinfo';
            }
            document.querySelectorAll('.activity-icon').forEach(icon => icon.classList.remove('active'));
            const activeIcon = Array.from(document.querySelectorAll('.activity-icon')).find(icon => 
                icon.getAttribute('onclick') && icon.getAttribute('onclick').includes(tabId)
            );
            if (activeIcon) activeIcon.classList.add('active');
            document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            const tabBtn = document.querySelector(`[onclick="switchTab('${tabId}')"]`);
            if (tabBtn) tabBtn.classList.add('active');
            const panel = document.getElementById(tabId);
            if (panel) panel.classList.add('active');

            // Show session strip only for interface-scoped tabs
            const strip = document.getElementById('sessionStripGlobal');
            if (strip) strip.style.display = (typeof isSessionScopedTab === 'function' && isSessionScopedTab(tabId)) ? 'flex' : 'none';
            // Show window-tabs (inner tabs) only when on a session-scoped tab AND a window is open
            const winTabs = document.getElementById('windowTabs');
            const showWinTabs = (typeof isSessionScopedTab === 'function' && isSessionScopedTab(tabId)) && !!activeId;
            if (winTabs) winTabs.style.display = showWinTabs ? 'flex' : 'none';
            // Sync active state on inner tabs
            if (winTabs) {
                winTabs.querySelectorAll('.win-tab').forEach(b => {
                    b.classList.toggle('active', b.getAttribute('data-tab') === tabId);
                });
            }

            // Load data for each tab
            if (tabId === 'connections') loadConnections();
            if (tabId === 'routes') loadRoutes();
            if (tabId === 'nics') loadNics();
            if (tabId === 'serverinfo') { loadServerInfo(); loadInterfaces(); }
            if (tabId === 'hardware') {
                if (activeId && Sessions[activeId] && !Sessions[activeId].isOffline) {
                    if (typeof loadNicDetail === 'function') loadNicDetail();
                    if (typeof loadEthtool === 'function') loadEthtool();
                    if (typeof loadDataplane === 'function') loadDataplane();
                }
            }
            if (tabId === 'terminal') {
                if (fitAddon) setTimeout(() => fitAddon.fit(), 100);
                if (term) term.focus();
            }
            if (tabId === 'docs') {
                if (!window._wikiNavLoaded) loadWikiNav();
            }
        };

        // ─── Multi-session capture API ───────────────────────────────────────
        function startCaptureFor(iface) {
            document.getElementById('currentIface').value = iface;
            document.querySelectorAll('.analysis-tab').forEach(t => t.style.display = 'block');
            const selector = document.getElementById('interfaceSelector');
            if (selector) selector.style.display = 'none';
            const bpfFilter = document.getElementById('bpfFilter') ? document.getElementById('bpfFilter').value : '';
            switchTab('dashboard');
            addSession(iface, bpfFilter, false);
        }
        window.startCapture = startCaptureFor;
        window.connectToSession = connectToSession;
        window.startInspectWithSession = startInspectWithSession;

        function selectInterface() {
            loadNicDetail();
            loadEthtool();
            loadDataplane();
        }

        function toggleCapture() {
            // Start/Stop capture for the active per-interface window.
            if (!activeId || !Sessions[activeId]) {
                alert('No window open. Pick an interface in Server Info first.');
                return;
            }
            const S = Sessions[activeId];
            if (S.status === 'active' && S.eventSource) {
                S.paused = false; // explicit stop, not pause
                stopActiveCapture();
            } else {
                S.paused = false; // explicit start clears any paused flag
                startActiveCapture();
            }
        }

        function analyzePcap() {
            const readPath = document.getElementById('pcapRead').value;
            if (!readPath) return alert("Enter an absolute path to a PCAP file to analyze.");
            document.querySelectorAll('.analysis-tab').forEach(t => t.style.display = 'block');
            switchTab('dashboard');
            addSession('', '', true, readPath);
        }

        function uploadPcap() {
            alert("Upload functionality requires backend multipart parsing which is planned for a future update. Please use 'Analyze Server PCAP' with an absolute file path for now.");
        }

        async function exportFilteredPackets() {
            const tbody = document.getElementById('pktTableBody');
            const visibleRows = Array.from(tbody.children).filter(row => row.style.display !== 'none');
            if (visibleRows.length === 0) {
                alert('No packets to export. Capture some packets first.');
                return;
            }
            const filename = prompt('Enter PCAP filename to save on server:', '/tmp/filtered-packets.pcap');
            if (!filename) return;
            const indices = visibleRows.map(row => parseInt(row.cells[0].textContent) - 1);
            document.getElementById('sb-status').textContent = `Exporting ${indices.length} filtered packets...`;
            try {
                const response = await fetch('/api/export-filtered', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filename, indices })
                });
                const result = await response.json();
                if (result.success) {
                    document.getElementById('sb-status').textContent = `✓ Exported ${indices.length} packets to ${filename}`;
                    alert(`Successfully exported ${indices.length} packets to ${filename}`);
                } else {
                    document.getElementById('sb-status').textContent = `Export failed: ${result.error}`;
                    alert(`Export failed: ${result.error}`);
                }
            } catch (e) {
                document.getElementById('sb-status').textContent = `Export error: ${e.message}`;
                alert(`Export error: ${e.message}`);
            }
        }

        function togglePause() {
            if (!activeId || !Sessions[activeId]) return;
            const S = Sessions[activeId];
            if (S.status === 'active') {
                // Pause: freeze the render timer immediately, then stop the SSE stream
                S.paused = true;
                isPaused = true;
                stopActiveCapture();
                applyPauseButton(S);
                document.getElementById('sb-status').textContent = `[${S.iface}] Paused. ${S.packetCount} packets captured.`;
            } else {
                // Resume: unfreeze render timer, restart SSE stream
                S.paused = false;
                isPaused = false;
                startActiveCapture();
                applyPauseButton(S);
                document.getElementById('sb-status').textContent = `[${S.iface}] Resumed.`;
            }
        }

        function applyPauseButton(S) {
            const btn = document.getElementById('btnPause');
            if (!btn) return;
            if (!S) { btn.style.display = 'none'; return; }
            btn.style.display = 'inline-block';
            if (S.status === 'active') {
                btn.textContent = '⏸ Pause';
                btn.style.background = '';
            } else {
                btn.textContent = '▶ Resume';
                btn.style.background = 'var(--success)';
            }
            isPaused = !!S.paused;
        }

        function processPendingPackets() {
            if (packetBuffer.length === 0) {
                refreshChipCounts();
                return;
            }
            const tbody = document.getElementById('pktTableBody');
            const fragment = document.createDocumentFragment();
            const terms = getDisplayFilterTerms();
            const requiredTag = getRequiredTag();
            const S = Sessions[activeId];

            while (packetBuffer.length > 0) {
                const data = packetBuffer.shift();
                let ts = data.ts_sec + (data.ts_usec / 1000000.0);
                if (S && S.baseTs === null) { S.baseTs = ts; baseTs = ts; }
                const ref = (S ? S.baseTs : ts);
                const relTime = (ts - ref).toFixed(6);

                const tr = document.createElement('tr');
                tr.className = getWsClass(data.proto, data.risk);
                const riskBadge = data.risk > 0 ? `<span style="color:var(--danger);font-weight:bold;">[Risk: ${data.risk}]</span> ` : '';
                tr.innerHTML = `<td>${data.index}</td><td>${relTime}</td><td>${escapeHtml(data.src)}</td><td>${escapeHtml(data.dst)}</td><td><strong>${escapeHtml(data.proto)}</strong></td><td>${data.len}</td><td class="info-cell" title="${escapeHtml(data.summary)}">${riskBadge}${escapeHtml(data.summary)}</td>`;
                if (data.tags) tr.setAttribute('data-tags', data.tags);
                const currentIndex = data.index - 1;
                tr.onclick = function() { showDetail(currentIndex, tr); };
                if (!packetMatchesFilter(tr, terms, requiredTag)) tr.style.display = 'none';
                fragment.appendChild(tr);
            }
            tbody.appendChild(fragment);
            while (tbody.children.length > MAX_PACKETS_IN_MEMORY) tbody.removeChild(tbody.firstChild);

            if (autoScroll) {
                const container = document.getElementById('tableContainer');
                container.scrollTop = container.scrollHeight;
            }
            let visible = 0;
            for (let i = 0; i < tbody.children.length; i++) {
                if (tbody.children[i].style.display !== 'none') visible++;
            }
            document.getElementById('sb-stats').textContent = `Packets: ${packetCount} | Displayed: ${visible} | Bytes: ${formatBytes(byteCount)}`;
            refreshChipCounts();
        }

        // Open a new per-interface "window" — does NOT auto-start capture.
        // User clicks "▶ Start Capture" inside the window to begin.
        function addSession(iface, bpf = '', isOffline = false, source = null) {
            if (!isOffline && !iface) { alert('No interface selected'); return; }
            if (isOffline && !source) { alert('No PCAP file'); return; }

            // Avoid duplicate windows for the same iface
            if (!isOffline) {
                const dup = Object.values(Sessions).find(s => !s.isOffline && s.iface === iface);
                if (dup) {
                    bindActive(dup.id);
                    rebuildTableFromActive();
                    renderSessionTabs();
                    switchTab('dashboard');
                    document.getElementById('sb-status').textContent = `Window for ${iface} already open — switched to it.`;
                    return;
                }
            }

            const sessionId = `win-${Date.now()}-${Math.random().toString(36).slice(2,8)}`;
            const label = isOffline ? (source.split('/').pop() || source) : iface;
            const S = newSessionState(sessionId, label, isOffline);
            S.status = 'idle';                  // not yet capturing
            S.pending = { iface, bpf, isOffline, source };
            Sessions[sessionId] = S;

            bindActive(sessionId);
            rebuildTableFromActive();
            renderSessionTabs();

            // Pre-load per-session hardware data for live captures (so the Hardware inner tab is populated)
            if (!isOffline) {
                if (typeof loadNicDetail === 'function') loadNicDetail();
                if (typeof loadEthtool === 'function') loadEthtool();
                if (typeof loadDataplane === 'function') loadDataplane();
            }

            switchTab('dashboard');
            const btn = document.getElementById('btnToggle');
            btn.textContent = '▶ Start Capture';
            btn.classList.remove('stop');
            isCapturing = false;
            document.getElementById('btnPause').style.display = 'none';
            document.getElementById('sb-status').textContent = `Window opened for ${label}. Click ▶ Start Capture to begin.`;
        }

        // Begin capture for the currently active window
        async function startActiveCapture() {
            if (!activeId || !Sessions[activeId]) { alert('No active window. Pick an interface in Server Info.'); return; }
            const S = Sessions[activeId];
            if (S.status === 'active' && S.eventSource) return; // already running
            const p = S.pending || { iface: S.iface, bpf: '', isOffline: S.isOffline, source: S.iface };

            let backendId = S.backendId;
            if (!p.isOffline && !backendId) {
                try {
                    const res = await fetch('/api/sessions/create', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ interface: p.iface, filter: p.bpf || '' })
                    });
                    const data = await res.json();
                    backendId = data.id;
                    S.backendId = backendId;
                } catch (e) { alert('Failed to create backend session: ' + e); return; }
            }

            let url = `/api/inspect?session=${encodeURIComponent(backendId || S.id)}&`;
            url += p.isOffline ? `read=${encodeURIComponent(p.source)}` : `iface=${encodeURIComponent(p.iface)}`;
            if (p.bpf) url += `&filter=${encodeURIComponent(p.bpf)}`;
            url += `&flow_analyze=true`;

            const es = new EventSource(url);
            S.eventSource = es;
            S.status = 'active';
            es.onmessage = (event) => handleSessionMessage(S, event);
            es.onerror = () => {
                S.status = 'stopped';
                if (S.eventSource) { try { S.eventSource.close(); } catch (e) {} S.eventSource = null; }
                if (S.id === activeId) {
                    isCapturing = false;
                    const btn = document.getElementById('btnToggle');
                    btn.textContent = '▶ Start Capture';
                    btn.classList.remove('stop');
                    document.getElementById('sb-status').textContent = `[${S.iface}] capture ended. ${S.packetCount} packets.`;
                }
                renderSessionTabs();
                if (typeof loadSessions === 'function') loadSessions();
            };

            ensureRenderTimer();
            if (S.id === activeId) {
                isCapturing = true;
                const btn = document.getElementById('btnToggle');
                btn.textContent = '⏹ Stop Capture';
                btn.classList.add('stop');
                applyPauseButton(S);
                document.getElementById('sb-status').textContent = `Capturing on ${S.iface}…`;
            }
            renderSessionTabs();
            if (typeof loadSessions === 'function') loadSessions();
        }

        function handleSessionMessage(S, event) {
            let data;
            try { data = JSON.parse(event.data); } catch (e) { return; }
            if (data.error) {
                S.status = 'stopped';
                if (S.id === activeId) document.getElementById('sb-status').textContent = `[${S.iface}] Error: ${data.error}`;
                renderSessionTabs();
                return;
            }
            if (data.flow_event) {
                if (S.id === activeId && !S.paused) {
                    document.getElementById('sb-status').textContent = data.flow_event;
                }
                return;
            }

            S.packetCount++;
            S.byteCount += data.len;
            data.index = S.packetCount;
            S.packetStore.push(data);
            if (S.packetStore.length > MAX_PACKETS_IN_MEMORY) S.packetStore.shift();

            // Per-session stats
            if (!S.protoStats[data.proto]) S.protoStats[data.proto] = { pkts: 0, bytes: 0 };
            S.protoStats[data.proto].pkts++; S.protoStats[data.proto].bytes += data.len;
            if (!S.talkerStats[data.src]) S.talkerStats[data.src] = { pkts: 0, bytes: 0 };
            S.talkerStats[data.src].pkts++; S.talkerStats[data.src].bytes += data.len;
            if (!S.talkerStats[data.dst]) S.talkerStats[data.dst] = { pkts: 0, bytes: 0 };
            S.talkerStats[data.dst].pkts++; S.talkerStats[data.dst].bytes += data.len;
            const k1 = `${data.proto}-${data.src}-${data.dst}`;
            const k2 = `${data.proto}-${data.dst}-${data.src}`;
            const key = S.flows[k2] ? k2 : k1;
            if (!S.flows[key]) S.flows[key] = { proto: data.proto, src: data.src, dst: data.dst, category: data.category, pkts: 0, bytes: 0 };
            S.flows[key].pkts++;
            S.flows[key].bytes += data.len;

            if (S.id === activeId) {
                packetCount = S.packetCount;
                byteCount = S.byteCount;
                if (!S.paused) packetBuffer.push(data);
            }
        }

        function rebuildTableFromActive() {
            const tbody = document.getElementById('pktTableBody');
            tbody.innerHTML = '';
            const S = Sessions[activeId];
            if (!S) {
                document.getElementById('sb-stats').textContent = 'Packets: 0 | Displayed: 0 | Bytes: 0 B';
                document.getElementById('packetDetail').textContent = 'Select a packet to view its complete DPI decode layer by layer...';
                return;
            }
            S.baseTs = null; baseTs = null;
            const fragment = document.createDocumentFragment();
            const terms = getDisplayFilterTerms();
            const requiredTag = getRequiredTag();
            S.packetStore.forEach((data, i) => {
                const ts = data.ts_sec + (data.ts_usec / 1000000.0);
                if (S.baseTs === null) { S.baseTs = ts; baseTs = ts; }
                const relTime = (ts - S.baseTs).toFixed(6);
                const tr = document.createElement('tr');
                tr.className = getWsClass(data.proto, data.risk);
                const riskBadge = data.risk > 0 ? `<span style="color:var(--danger);font-weight:bold;">[Risk: ${data.risk}]</span> ` : '';
                tr.innerHTML = `<td>${i+1}</td><td>${relTime}</td><td>${escapeHtml(data.src)}</td><td>${escapeHtml(data.dst)}</td><td><strong>${escapeHtml(data.proto)}</strong></td><td>${data.len}</td><td class="info-cell" title="${escapeHtml(data.summary)}">${riskBadge}${escapeHtml(data.summary)}</td>`;
                if (data.tags) tr.setAttribute('data-tags', data.tags);
                const idx = i;
                tr.onclick = function() { showDetail(idx, tr); };
                if (!packetMatchesFilter(tr, terms, requiredTag)) tr.style.display = 'none';
                fragment.appendChild(tr);
            });
            tbody.appendChild(fragment);
            let visible = 0;
            for (let i = 0; i < tbody.children.length; i++) if (tbody.children[i].style.display !== 'none') visible++;
            document.getElementById('sb-stats').textContent = `Packets: ${S.packetCount} | Displayed: ${visible} | Bytes: ${formatBytes(S.byteCount)}`;
            if (typeof renderFlows === 'function') renderFlows();
            if (typeof renderStats === 'function') renderStats();
        }

        function renderSessionTabs() {
            const strips = [document.getElementById('sessionStrip'), document.getElementById('sessionStripGlobal')].filter(Boolean);
            if (strips.length === 0) return;
            const ids = Object.keys(Sessions);
            let html;
            if (ids.length === 0) {
                html = '<span style="font-size:12px;color:var(--text-muted);">No capture windows open. Click an interface in <strong>Server Info</strong> to open one.</span>'
                     + '<button class="btn" style="margin-left:auto;padding:4px 12px;font-size:12px;" onclick="switchTab(\'serverinfo\')">+ New Window</button>';
            } else {
                html = ids.map(id => {
                    const S = Sessions[id];
                    const dot = S.status === 'active'
                        ? '<span style="color:#10b981;font-size:14px;line-height:0;">●</span>'
                        : '<span style="color:#94a3b8;font-size:14px;line-height:0;">○</span>';
                    const cls = (id === activeId) ? 'session-chip active' : 'session-chip';
                    const ifaceLabel = escapeHtml(S.iface) + (S.isOffline ? ' (pcap)' : '');
                    return `<span class="${cls}" onclick="switchSession('${id}')" title="Window: ${escapeHtml(id)}">`
                         + `${dot} <strong>${ifaceLabel}</strong>`
                         + `<span data-counter style="opacity:.85;font-weight:500;">${S.packetCount} pkts · ${formatBytes(S.byteCount)}</span>`
                         + `<button class="chip-x" onclick="event.stopPropagation();closeSession('${id}')" title="Close window">×</button>`
                         + `</span>`;
                }).join('');
                html += '<button class="btn" style="margin-left:auto;padding:4px 12px;font-size:12px;" onclick="switchTab(\'serverinfo\')" title="Open another interface">+ New Window</button>';
            }
            strips.forEach(strip => { strip.innerHTML = html; });
        }

        function refreshChipCounts() {
            const strips = [document.getElementById('sessionStrip'), document.getElementById('sessionStripGlobal')].filter(Boolean);
            for (const strip of strips) {
                const chips = strip.querySelectorAll('.session-chip');
                for (const chip of chips) {
                    const m = (chip.getAttribute('onclick') || '').match(/switchSession\('([^']+)'\)/);
                    if (!m) continue;
                    const id = m[1];
                    const S = Sessions[id];
                    if (!S) continue;
                    const counter = chip.querySelector('span[data-counter]');
                    if (counter) counter.textContent = `${S.packetCount} pkts · ${formatBytes(S.byteCount)}`;
                }
            }
        }

        function switchSession(id) {
            if (!Sessions[id]) return;
            bindActive(id);
            rebuildTableFromActive();
            renderSessionTabs();
            const S = Sessions[id];
            const btn = document.getElementById('btnToggle');
            if (S.status === 'active') {
                btn.textContent = '⏹ Stop Capture';
                btn.classList.add('stop');
            } else {
                btn.textContent = '▶ Start Capture';
                btn.classList.remove('stop');
            }
            // Per-session pause/resume button
            if (S.status === 'active' || S.paused) {
                applyPauseButton(S);
            } else {
                document.getElementById('btnPause').style.display = 'none';
            }
            // Refresh per-session hardware tabs (only for live captures)
            if (!S.isOffline) {
                if (typeof loadNicDetail === 'function') loadNicDetail();
                if (typeof loadEthtool === 'function') loadEthtool();
                if (typeof loadDataplane === 'function') loadDataplane();
            }
            // Toggle Hardware inner-tab visibility for offline pcap sessions
            const hwTab = document.querySelector('#windowTabs .win-tab[data-tab="hardware"]');
            if (hwTab) hwTab.style.display = S.isOffline ? 'none' : '';
            document.getElementById('sb-status').textContent = `Active window: ${S.iface} (${S.status}) — ${S.packetCount} packets`;
        }

        function closeSession(id) {
            const S = Sessions[id];
            if (!S) return;
            if (S.eventSource) { try { S.eventSource.close(); } catch (e) {} S.eventSource = null; }
            const bid = S.backendId;
            if (bid) {
                fetch(`/api/sessions/${bid}/stop`, { method: 'POST' }).catch(() => {});
                fetch(`/api/sessions/${bid}`, { method: 'DELETE' }).catch(() => {});
            }
            delete Sessions[id];

            if (id === activeId) {
                const remaining = Object.keys(Sessions);
                if (remaining.length > 0) {
                    bindActive(remaining[0]);
                    rebuildTableFromActive();
                } else {
                    activeId = null;
                    packetStore = []; flows = {}; protoStats = {}; talkerStats = {}; geoCache = {};
                    packetCount = 0; byteCount = 0; baseTs = null;
                    eventSource = null; isCapturing = false; isPaused = false;
                    document.getElementById('pktTableBody').innerHTML = '';
                    document.getElementById('packetDetail').textContent = 'Select a packet to view its complete DPI decode layer by layer...';
                    document.getElementById('packetHex').textContent = '';
                    document.getElementById('sb-status').textContent = 'No active window';
                    document.getElementById('sb-stats').textContent = 'Packets: 0 | Displayed: 0 | Bytes: 0 B';
                    document.getElementById('btnPause').style.display = 'none';
                    const btn = document.getElementById('btnToggle');
                    btn.textContent = '▶ Start Capture';
                    btn.classList.remove('stop');
                    if (typeof renderFlows === 'function') renderFlows();
                    if (typeof renderStats === 'function') renderStats();
                    // Hide inner window-tabs when no windows remain
                    const winTabs = document.getElementById('windowTabs');
                    if (winTabs) winTabs.style.display = 'none';
                    // If user was on a session-scoped tab, route them home
                    const activePanel = document.querySelector('.panel.active');
                    if (activePanel && isSessionScopedTab(activePanel.id)) switchTab('serverinfo');
                }
            }
            renderSessionTabs();
            if (typeof loadSessions === 'function') loadSessions();
        }

        function stopActiveCapture() {
            if (!activeId) return;
            const S = Sessions[activeId];
            if (!S) return;
            if (S.eventSource) { try { S.eventSource.close(); } catch (e) {} S.eventSource = null; }
            S.status = 'stopped';
            isCapturing = false;
            const bid = S.backendId || S.id;
            fetch(`/api/sessions/${bid}/stop`, { method: 'POST' }).catch(() => {});
            renderSessionTabs();
            if (typeof loadSessions === 'function') loadSessions();
            const btn = document.getElementById('btnToggle');
            btn.textContent = '▶ Start Capture';
            btn.classList.remove('stop');
            if (S.paused) {
                applyPauseButton(S);
            } else {
                document.getElementById('btnPause').style.display = 'none';
            }
            document.getElementById('sb-status').textContent = `Stopped ${S.iface}. ${S.packetCount} packets captured.`;
        }

        // Backwards-compat shims
        function startInspect(isOffline = false, source = null) {
            const bpf = document.getElementById('bpfFilter') ? document.getElementById('bpfFilter').value : '';
            if (isOffline) {
                const path = source || document.getElementById('pcapRead').value;
                if (!path) return alert('No PCAP file provided.');
                addSession('', '', true, path);
            } else {
                const iface = source || document.getElementById('currentIface').value;
                if (!iface) return alert('Select an interface first');
                addSession(iface, bpf, false);
            }
        }
        function stopInspect() { stopActiveCapture(); }
        function startInspectWithSession(_sessionId, isOffline = false, source = null, bpf = '') {
            // Backend now auto-creates sessions; just open a new one
            if (isOffline) addSession('', bpf || '', true, source);
            else addSession(source, bpf || '', false);
        }
        function connectToSession(_sessionId, ifaceName) {
            // Open a fresh session for this interface (sessions are per-tab)
            addSession(ifaceName, '', false);
        }

        window.switchSession = switchSession;
        window.closeSession = closeSession;
        window.addSession = addSession;
        window.startInspect = startInspect;
        window.stopInspect = stopInspect;
        window.toggleCapture = toggleCapture;
        window.togglePause = togglePause;

        function escapeHtml(unsafe) {
            return (unsafe || "")
                 .replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
        }

        // Render a hex-dump string with syntax highlighting.
        // hex_dump() format: "  OOOO  HH HH HH ...  |ASCII|"
        function renderHex(hexText) {
            if (!hexText) return '<span style="color:#475569;font-style:italic;">No hex data</span>';
            return hexText.split('\n').filter(l => l.trim()).map(line => {
                // Handle truncation note line
                if (line.includes('truncated')) return '<span style="color:#64748b;font-style:italic;">' + escapeHtml(line.trim()) + '</span>';
                // Match:  optional leading spaces, 4-char offset, 2 spaces, hex block (padded to ~48), 2 spaces, |ascii|
                const m = line.match(/^ *([0-9a-fA-F]{4,8})  ([\da-fA-F ]{1,50})  \|([\x20-\x7e.]*)\|$/);
                if (m) {
                    return '<span style="color:#64748b">' + escapeHtml(m[1]) + '</span>'
                         + '  '
                         + '<span style="color:#38bdf8">' + escapeHtml(m[2]) + '</span>'
                         + '  |'
                         + '<span style="color:#4ade80">' + escapeHtml(m[3]) + '</span>'
                         + '|';
                }
                return escapeHtml(line);
            }).join('\n');
        }

        function showDetail(index, trElement) {
            autoScroll = false;
            document.getElementById('resumeScrollBtn').style.display = 'block';

            document.querySelectorAll('#pktTableBody tr').forEach(row => row.classList.remove('selected'));
            trElement.classList.add('selected');
            const pkt = packetStore[index];
            if (!pkt) return;

            // ── Packet Details pane ──
            let safeDetails = escapeHtml(pkt.details);
            let formattedDetails = safeDetails.replace(/-- ([^\n]+)/g, '<div class="detail-header">$1</div>');
            formattedDetails = formattedDetails.replace(/^  ([^:\[•]+): (.*)$/gm,
                '<div class="detail-row"><span class="detail-key">$1:</span> <span class="detail-val">$2</span></div>');
            formattedDetails = formattedDetails.replace(/^  (\[!\] .*)$/gm,
                '<div class="detail-row"><span class="detail-val" style="color:var(--danger);font-weight:600;">$1</span></div>');
            formattedDetails = formattedDetails.replace(/^  (• .*)$/gm,
                '<div class="detail-row"><span class="detail-val" style="color:var(--text-muted);">$1</span></div>');
            document.getElementById('packetDetail').innerHTML = formattedDetails;

            // ── Hex Dump pane ──
            const hexWrapper = document.getElementById('packetHexWrapper');
            const hexEl     = document.getElementById('packetHex');
            const hexInfo   = document.getElementById('hexByteInfo');
            const hexVisible = hexWrapper.style.display !== 'none';
            if (pkt.hex && pkt.hex.length > 4) {
                const totalBytes = pkt.len || 0;
                const shownBytes = Math.min(totalBytes, 128);
                if (hexInfo) hexInfo.textContent =
                    shownBytes < totalBytes
                        ? `${shownBytes} / ${totalBytes} bytes (first ${shownBytes} shown)`
                        : `${totalBytes} bytes`;
                hexEl.innerHTML = '<pre style="margin:0;font-size:11px;line-height:1.7;white-space:pre;overflow-x:auto;">'
                    + renderHex(pkt.hex) + '</pre>';
                // Auto-show hex pane only if it hasn't been explicitly hidden by the user
                if (!hexVisible) hexWrapper.style.display = 'flex';
            } else {
                if (hexInfo) hexInfo.textContent = '';
                hexEl.innerHTML = '<span style="color:#475569;font-style:italic;font-size:12px;">Hex not available for this packet</span>';
                // Don't force-show when no data
            }
        }

        function kvRow(label, value, badgeClass = "") {
            let valHtml = badgeClass ? `<span class="badge badge-${badgeClass}">${value}</span>` : `<strong>${value}</strong>`;
            return `<div class="kv-item"><span>${label}</span>${valHtml}</div>`;
        }

        async function loadNicDetail() {
            const iface = document.getElementById('currentIface').value; if (!iface) return;
            try {
                const res = await fetch(`/api/nic_detail?iface=${encodeURIComponent(iface)}`);
                const data = await res.json();
                let badge = data.state === "UP" ? "success" : "danger";
                document.getElementById('hwStatus').innerHTML = 
                    kvRow("State", data.state, badge) +
                    kvRow("MAC Address", data.mac) +
                    kvRow("MTU", data.mtu) +
                    kvRow("Speed", data.speed) +
                    kvRow("RX", `${formatBytes(data.rx_bytes)} (${data.rx_packets} pkts)`) +
                    kvRow("TX", `${formatBytes(data.tx_bytes)} (${data.tx_packets} pkts)`) +
                    kvRow("IPs", data.ips.join(', ') || "None");
            } catch (e) { document.getElementById('hwStatus').innerHTML = "Error loading hardware info."; }
        }
        
        async function loadConnections() {
            try {
                const res = await fetch('/api/conn'); const data = await res.json();
                let html = '<table class="settings-table"><thead><tr><th>Proto</th><th>Local Address</th><th>Remote Address</th><th>State</th><th>PID / Process</th></tr></thead><tbody>';
                data.forEach(c => {
                    let remote = c.remote_port === 0 ? "—" : `${c.remote_ip}:${c.remote_port}`;
                    let proc = c.pid === 0 ? "—" : `${c.process} (${c.pid})`;
                    let stateColor = c.state.includes("ESTABLISH") ? "var(--success)" : "inherit";
                    html += `<tr><td>${c.proto}</td><td>${c.local_ip}:${c.local_port}</td><td>${remote}</td><td style="color:${stateColor}; font-weight:bold;">${c.state}</td><td>${proc}</td></tr>`;
                });
                document.getElementById('connContent').innerHTML = html + '</tbody></table>';
            } catch(e) { document.getElementById('connContent').innerHTML = '<div style="padding:20px;color:var(--danger);">Error loading connections: ' + e.message + '</div>'; }
        }

        async function loadRoutes() {
            try {
                const res = await fetch('/api/route'); const data = await res.json();
                let html = '<table class="settings-table"><thead><tr><th>Interface</th><th>Destination</th><th>Gateway</th><th>Metric</th></tr></thead><tbody>';
                data.forEach(r => {
                    let dest = `${r.destination}/${r.prefix_len}`;
                    let gw = (r.gateway === "0.0.0.0" || r.gateway === "::") ? "Direct" : r.gateway;
                    html += `<tr><td>${r.interface}</td><td>${dest}</td><td>${gw}</td><td>${r.metric}</td></tr>`;
                });
                document.getElementById('routeContent').innerHTML = html + '</tbody></table>';
            } catch(e) { document.getElementById('routeContent').innerHTML = '<div style="padding:20px;color:var(--danger);">Error loading routes: ' + e.message + '</div>'; }
        }

        async function loadNics() {
            try {
                const res = await fetch('/api/nic');
                const data = await res.json();
                const fmtBytes = (b) => { const u=['B','KB','MB','GB']; let i=0; while(b>=1024&&i<u.length-1){b/=1024;i++;} return b.toFixed(1)+' '+u[i]; };
                let html = '<table class="settings-table"><thead><tr><th>Interface</th><th>State</th><th>MAC</th><th>MTU</th><th>RX</th><th>TX</th></tr></thead><tbody>';
                data.forEach(n => {
                    let stateColor = n.state === 'up' ? "var(--success)" : "var(--danger)";
                    html += `<tr>
                        <td><strong style="color:var(--primary);cursor:pointer;text-decoration:underline;" onclick="startCapture('${n.name}')">${n.name}</strong></td>
                        <td style="color:${stateColor}; font-weight:bold;">${(n.state||'?').toUpperCase()}</td>
                        <td style="font-family:monospace;">${n.mac||'—'}</td>
                        <td>${n.mtu||'—'}</td>
                        <td>${fmtBytes(n.rx_bytes||0)}</td>
                        <td>${fmtBytes(n.tx_bytes||0)}</td>
                    </tr>`;
                });
                document.getElementById('nicContent').innerHTML = html + '</tbody></table>';
            } catch(e) { document.getElementById('nicContent').innerHTML = '<div style="padding:20px;color:var(--danger);">Error loading NIC data.</div>'; }
        }

        async function loadDataplane() {
            const iface = document.getElementById('currentIface').value; if (!iface) return;
            try {
                const res = await fetch(`/api/dp?iface=${encodeURIComponent(iface)}`);
                const data = await res.json();
                document.getElementById('dpStatus').innerHTML = 
                    kvRow("Bypass Mode", data.bypass_mode, "warning") +
                    kvRow("XDP eBPF Prog", data.xdp_prog_ids === "[]" ? "None" : data.xdp_prog_ids) +
                    kvRow("AF_XDP Sockets", data.afxdp_sockets) +
                    kvRow("DPDK Bound", data.dpdk_bound ? "Yes" : "No") +
                    kvRow("PMD Driver", data.driver || '—');
            } catch (e) { document.getElementById('dpStatus').innerHTML = "Error loading dataplane info."; }
        }

        async function loadEthtool() {
            const iface = document.getElementById('currentIface').value; if (!iface) return;
            try {
                const res = await fetch(`/api/ethtool?iface=${encodeURIComponent(iface)}`);
                const data = await res.json();
                document.getElementById('driverStatus').innerHTML = 
                    kvRow("Kernel Driver", data.driver || "Unknown") +
                    kvRow("Link Speed", data.speed_mbps ? data.speed_mbps + " Mbps" : "Unknown") +
                    kvRow("Duplex", data.duplex || "Unknown") +
                    kvRow("RX Queues", data.rx_queues) +
                    kvRow("TX Queues", data.tx_queues);
            } catch (e) { document.getElementById('driverStatus').innerHTML = "Error loading driver info."; }
        }

        async function loadGeoIp() {
            const ip = document.getElementById('geoIpInput').value.trim();
            if (!ip) return;
            try {
                const res = await fetch(`/api/geoip?ip=${encodeURIComponent(ip)}`);
                if (!res.ok) throw new Error("Not found");
                const data = await res.json();
                document.getElementById('geoContent').innerHTML = 
                    `<strong>Result for ${data.ip}:</strong><br><br>` + 
                    kvRow("Country Name", data.country_name) +
                    kvRow("Country Code", data.country_code) +
                    kvRow("Continent", data.continent);
            } catch (e) { document.getElementById('geoContent').innerHTML = "Error: Lookup failed"; }
        }

        function toggleHex() {
            const hexPane = document.getElementById('packetHexWrapper');
            if (hexPane.style.display === 'none') {
                hexPane.style.display = 'flex';
            } else {
                hexPane.style.display = 'none';
            }
            if (typeof saveLayout === 'function') saveLayout();
        }

        async function stopDaemon() {
            if (!confirm("Are you sure you want to stop the pktana background daemon?")) return;
            try {
                await fetch('/api/stop', { method: 'POST' });
                alert("pktana daemon stopped. You can safely close this page.");
            } catch (e) {
                alert("Error: " + e);
            }
        }

        let term = null;
        let fitAddon = null;
        let currentCommand = '';
        let commandHistory = [];
        let historyIndex = -1;
        let currentWorkingDir = '/root/pktana'; // Track current directory
        let homeDir = '/root/pktana';

        const xtermThemes = {
            'default': {
                foreground: '#ffffff',
                background: '#000000',
                cursor: '#00ff00',
                cursorAccent: '#00ff00',
                selectionBackground: '#3a3d41',
                black: '#000000',
                red: '#cd3131',
                green: '#0dbc79',
                yellow: '#e5e510',
                blue: '#2472c8',
                magenta: '#bc3fbc',
                cyan: '#11a8cd',
                white: '#e5e5e5',
                brightBlack: '#666666',
                brightRed: '#f14c4c',
                brightGreen: '#23d18b',
                brightYellow: '#f5f543',
                brightBlue: '#3b8eea',
                brightMagenta: '#d670d6',
                brightCyan: '#29b8db',
                brightWhite: '#e5e5e5'
            },
            'matrix': {
                foreground: '#00ff00',
                background: '#000000',
                cursor: '#00ff00',
                cursorAccent: '#000000',
                selectionBackground: '#003300',
                black: '#000000',
                red: '#00ff00',
                green: '#00ff00',
                yellow: '#00ff00',
                blue: '#00ff00',
                magenta: '#00ff00',
                cyan: '#00ff00',
                white: '#00ff00'
            },
            'monokai': {
                foreground: '#f8f8f2',
                background: '#272822',
                cursor: '#f8f8f0',
                selectionBackground: '#49483e',
                black: '#272822',
                red: '#f92672',
                green: '#a6e22e',
                yellow: '#f4bf75',
                blue: '#66d9ef',
                magenta: '#ae81ff',
                cyan: '#a1efe4',
                white: '#f8f8f2'
            },
            'nord': {
                foreground: '#d8dee9',
                background: '#2e3440',
                cursor: '#d8dee9',
                selectionBackground: '#4c566a',
                black: '#3b4252',
                red: '#bf616a',
                green: '#a3be8c',
                yellow: '#ebcb8b',
                blue: '#81a1c1',
                magenta: '#b48ead',
                cyan: '#88c0d0',
                white: '#e5e9f0'
            },
            'dracula': {
                foreground: '#f8f8f2',
                background: '#282a36',
                cursor: '#f8f8f2',
                selectionBackground: '#44475a',
                black: '#000000',
                red: '#ff5555',
                green: '#50fa7b',
                yellow: '#f1fa8c',
                blue: '#bd93f9',
                magenta: '#ff79c6',
                cyan: '#8be9fd',
                white: '#bbbbbb'
            },
            'solarized-dark': {
                foreground: '#839496',
                background: '#002b36',
                cursor: '#839496',
                selectionBackground: '#073642',
                black: '#073642',
                red: '#dc322f',
                green: '#859900',
                yellow: '#b58900',
                blue: '#268bd2',
                magenta: '#d33682',
                cyan: '#2aa198',
                white: '#eee8d5'
            },
            'ubuntu': {
                foreground: '#ffffff',
                background: '#300a24',
                cursor: '#ffffff',
                selectionBackground: '#5e2750',
                black: '#2e3436',
                red: '#cc0000',
                green: '#4e9a06',
                yellow: '#c4a000',
                blue: '#3465a4',
                magenta: '#75507b',
                cyan: '#06989a',
                white: '#d3d7cf'
            }
        };

        function initXterm() {
            if (!window.Terminal) {
                console.error('xterm.js not loaded');
                return;
            }

            term = new Terminal({
                cursorBlink: true,
                cursorStyle: 'block',
                fontSize: 14,
                fontFamily: '"Cascadia Code", "Fira Code", "Courier New", monospace',
                theme: xtermThemes['default'],
                allowProposedApi: true,
                scrollback: 10000,
                convertEol: true
            });

            fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            
            const webLinksAddon = new WebLinksAddon.WebLinksAddon();
            term.loadAddon(webLinksAddon);

            term.open(document.getElementById('xtermContainer'));
            fitAddon.fit();

            // Get initial working directory from server
            fetch('/api/terminal?cmd=' + encodeURIComponent('pwd'))
                .then(res => res.json())
                .then(data => {
                    if (data.output) {
                        const pwd = data.output.trim();
                        if (pwd && pwd.startsWith('/')) {
                            currentWorkingDir = pwd;
                            homeDir = pwd;
                        }
                    }
                    displayWelcomeMessage();
                })
                .catch(err => {
                    console.error('Failed to get pwd:', err);
                    displayWelcomeMessage();
                });
        }

        function displayWelcomeMessage() {
            // Welcome message
            term.writeln('\x1b[1;32m╔═══════════════════════════════════════════════════════════════╗\x1b[0m');
            term.writeln('\x1b[1;32m║\x1b[0m  \x1b[1;36mpktana Professional Terminal\x1b[0m powered by \x1b[1;33mxterm.js\x1b[0m            \x1b[1;32m║\x1b[0m');
            term.writeln('\x1b[1;32m║\x1b[0m  Full Linux terminal experience in your browser              \x1b[1;32m║\x1b[0m');
            term.writeln('\x1b[1;32m╚═══════════════════════════════════════════════════════════════╝\x1b[0m');
            term.writeln('');
            term.writeln('Type \x1b[1;36mhelp\x1b[0m for available commands');
            term.writeln('');

            writePrompt();

            // Handle input
            term.onData(data => {
                const code = data.charCodeAt(0);

                if (code === 13) { // Enter
                    term.write('\r\n');
                    executeXtermCommand(currentCommand.trim());
                    currentCommand = '';
                } else if (code === 127) { // Backspace
                    if (currentCommand.length > 0) {
                        currentCommand = currentCommand.slice(0, -1);
                        term.write('\b \b');
                    }
                } else if (code === 27) { // Escape sequence
                    if (data === '\x1b[A') { // Arrow Up
                        if (commandHistory.length > 0 && historyIndex < commandHistory.length - 1) {
                            historyIndex++;
                            replaceCommandLine(commandHistory[commandHistory.length - 1 - historyIndex]);
                        }
                    } else if (data === '\x1b[B') { // Arrow Down
                        if (historyIndex > 0) {
                            historyIndex--;
                            replaceCommandLine(commandHistory[commandHistory.length - 1 - historyIndex]);
                        } else if (historyIndex === 0) {
                            historyIndex = -1;
                            replaceCommandLine('');
                        }
                    } else if (data === '\x1b[D') { // Arrow Left (ignore for simplicity)
                        // Do nothing
                    } else if (data === '\x1b[C') { // Arrow Right (ignore for simplicity)
                        // Do nothing
                    }
                } else if (code === 3) { // Ctrl+C
                    term.write('^C\r\n');
                    currentCommand = '';
                    writePrompt();
                } else if (code === 12) { // Ctrl+L
                    clearXterm();
                } else if (code >= 32 && code < 127) { // Printable characters
                    currentCommand += data;
                    term.write(data);
                }
            });

            // Auto-resize on window resize
            window.addEventListener('resize', () => {
                if (fitAddon) fitAddon.fit();
            });

            // Load saved theme
            const savedTheme = localStorage.getItem('pktana_xterm_theme');
            if (savedTheme && xtermThemes[savedTheme]) {
                document.getElementById('xtermTheme').value = savedTheme;
                changeXtermTheme();
            }
        }

        function writePrompt() {
            // Shorten path display
            let displayPath = currentWorkingDir;
            if (displayPath === homeDir) {
                displayPath = '~';
            } else if (displayPath.startsWith(homeDir + '/')) {
                displayPath = '~' + displayPath.substring(homeDir.length);
            } else if (displayPath.length > 30) {
                // Truncate long paths
                const parts = displayPath.split('/');
                if (parts.length > 3) {
                    displayPath = '.../' + parts.slice(-2).join('/');
                }
            }
            term.write('\x1b[1;32m➜\x1b[0m \x1b[1;36m' + displayPath + '\x1b[0m \x1b[1;90m$\x1b[0m ');
        }

        function replaceCommandLine(newCommand) {
            // Clear current line
            term.write('\r\x1b[K');
            writePrompt();
            currentCommand = newCommand;
            term.write(newCommand);
        }

        async function executeXtermCommand(cmd) {
            if (!cmd) {
                writePrompt();
                return;
            }

            // Add to history
            if (commandHistory.length === 0 || commandHistory[commandHistory.length - 1] !== cmd) {
                commandHistory.push(cmd);
                if (commandHistory.length > 100) commandHistory.shift();
            }
            historyIndex = -1;

            // Built-in commands
            if (cmd === 'clear' || cmd === 'cls') {
                term.clear();
                writePrompt();
                return;
            }

            if (cmd === 'help') {
                term.writeln('\x1b[1;33m━━━ Available Commands ━━━\x1b[0m');
                term.writeln('  \x1b[36mclear\x1b[0m              Clear terminal screen');
                term.writeln('  \x1b[36mhelp\x1b[0m               Show this help message');
                term.writeln('  \x1b[36mhistory\x1b[0m            Show command history');
                term.writeln('  \x1b[36mls\x1b[0m, \x1b[36mpwd\x1b[0m, \x1b[36mcd\x1b[0m      Basic file operations');
                term.writeln('  \x1b[36mps\x1b[0m, \x1b[36mtop\x1b[0m           Process information');
                term.writeln('  \x1b[36mifconfig\x1b[0m, \x1b[36mip\x1b[0m     Network configuration');
                term.writeln('  \x1b[36mss\x1b[0m, \x1b[36mnetstat\x1b[0m       Network connections');
                term.writeln('  \x1b[36mpktana\x1b[0m             Packet analyzer commands');
                term.writeln('  \x1b[36muname\x1b[0m, \x1b[36muptime\x1b[0m    System information');
                term.writeln('');
                term.writeln('\x1b[1;33m━━━ Keyboard Shortcuts ━━━\x1b[0m');
                term.writeln('  \x1b[32m↑/↓\x1b[0m                Navigate command history');
                term.writeln('  \x1b[32mCtrl+L\x1b[0m             Clear screen');
                term.writeln('  \x1b[32mCtrl+C\x1b[0m             Cancel current command');
                term.writeln('  \x1b[32mCtrl+Shift+C\x1b[0m       Copy selected text');
                term.writeln('  \x1b[32mCtrl+Shift+V\x1b[0m       Paste from clipboard');
                term.writeln('');
                writePrompt();
                return;
            }

            if (cmd === 'history') {
                commandHistory.forEach((histCmd, idx) => {
                    term.writeln(`  \x1b[90m${(idx + 1).toString().padStart(4)}\x1b[0m  ${histCmd}`);
                });
                term.writeln('');
                writePrompt();
                return;
            }

            // Handle cd command specially
            if (cmd.trim().startsWith('cd ') || cmd.trim() === 'cd') {
                const parts = cmd.trim().split(/\s+/);
                let targetDir = '';
                
                if (parts.length === 1 || parts[1] === '~') {
                    targetDir = homeDir;
                } else if (parts[1] === '-') {
                    // cd - not implemented yet, just go home
                    targetDir = homeDir;
                } else if (parts[1].startsWith('/')) {
                    targetDir = parts[1];
                } else if (parts[1] === '..') {
                    const pathParts = currentWorkingDir.split('/').filter(p => p);
                    pathParts.pop();
                    targetDir = '/' + pathParts.join('/');
                    if (!targetDir) targetDir = '/';
                } else if (parts[1] === '.') {
                    targetDir = currentWorkingDir;
                } else {
                    targetDir = currentWorkingDir + (currentWorkingDir.endsWith('/') ? '' : '/') + parts[1];
                }

                // Verify directory exists
                try {
                    const testCmd = `cd "${currentWorkingDir}" && cd "${parts.slice(1).join(' ') || '~'}" && pwd`;
                    const res = await fetch(`/api/terminal?cmd=${encodeURIComponent(testCmd)}`);
                    const data = await res.json();
                    
                    if (data.output && !data.output.includes('No such file or directory')) {
                        const newPath = data.output.trim();
                        if (newPath && newPath.startsWith('/')) {
                            currentWorkingDir = newPath;
                        }
                    } else {
                        term.writeln('\x1b[1;31mbash: cd: ' + (parts[1] || '~') + ': No such file or directory\x1b[0m');
                    }
                } catch (e) {
                    term.writeln('\x1b[1;31mError: ' + e.message + '\x1b[0m');
                }
                
                writePrompt();
                return;
            }

            // Handle pwd command
            if (cmd.trim() === 'pwd') {
                term.writeln(currentWorkingDir);
                writePrompt();
                return;
            }

            // Execute remote command with proper working directory
            document.getElementById('xtermStatus').textContent = 'Executing...';
            
            try {
                // Prefix command with cd to working directory
                const fullCmd = `cd "${currentWorkingDir}" && ${cmd}`;
                const res = await fetch(`/api/terminal?cmd=${encodeURIComponent(fullCmd)}`);
                const data = await res.json();
                
                const output = data.output || "";
                
                // Write output with ANSI color codes preserved
                if (output) {
                    const lines = output.split('\n');
                    // strip trailing empty element produced by final newline
                    const trimmed = (lines.length > 0 && lines[lines.length - 1] === '') ? lines.slice(0, -1) : lines;
                    trimmed.forEach(line => term.writeln(line));
                }
                
                document.getElementById('xtermStatus').textContent = 'Ready';
            } catch (e) {
                term.writeln(`\x1b[1;31mError: ${e.message}\x1b[0m`);
                document.getElementById('xtermStatus').textContent = 'Error';
            }
            
            writePrompt();
        }

        function clearXterm() {
            if (term) {
                term.clear();
                writePrompt();
            }
        }

        function resetXterm() {
            if (term) {
                term.reset();
                term.writeln('\x1b[1;32m━━━ Terminal Reset ━━━\x1b[0m');
                term.writeln('');
                writePrompt();
            }
        }

        function changeXtermTheme() {
            const themeName = document.getElementById('xtermTheme').value;
            if (term && xtermThemes[themeName]) {
                term.options.theme = xtermThemes[themeName];
                localStorage.setItem('pktana_xterm_theme', themeName);
            }
        }

        // Layout & Resizer Logic
        function saveLayout() {
            const wsView = document.getElementById('wsView');
            const leftPane = document.getElementById('paneLeft');
            const rightPane = document.getElementById('paneRight');
            const hexWrapper = document.getElementById('packetHexWrapper');
            
            localStorage.setItem('pktana_layout_dir', wsView.classList.contains('vertical') ? 'vertical' : 'horizontal');
            localStorage.setItem('pktana_pane_left_flex', leftPane.style.flex);
            localStorage.setItem('pktana_pane_right_flex', rightPane.style.flex);
            localStorage.setItem('pktana_pane_right_display', rightPane.style.display);
            localStorage.setItem('pktana_hex_display', hexWrapper.style.display);
        }

        function loadLayout() {
            const dir = localStorage.getItem('pktana_layout_dir');
            if (dir === 'vertical') document.getElementById('wsView').classList.add('vertical');
            else if (dir === 'horizontal') document.getElementById('wsView').classList.remove('vertical');

            const leftFlex = localStorage.getItem('pktana_pane_left_flex');
            if (leftFlex) document.getElementById('paneLeft').style.flex = leftFlex;
            const rightFlex = localStorage.getItem('pktana_pane_right_flex');
            if (rightFlex) document.getElementById('paneRight').style.flex = rightFlex;
            
            const rightDisplay = localStorage.getItem('pktana_pane_right_display');
            if (rightDisplay) {
                document.getElementById('paneRight').style.display = rightDisplay;
                document.getElementById('dragMe').style.display = rightDisplay === 'none' ? 'none' : 'block';
            }
            const hexDisplay = localStorage.getItem('pktana_hex_display');
            if (hexDisplay) document.getElementById('packetHexWrapper').style.display = hexDisplay;
        }

        function toggleLayoutDir() {
            const view = document.getElementById('wsView');
            view.classList.toggle('vertical');
            document.getElementById('paneLeft').style.flex = "0 0 50%";
            document.getElementById('paneRight').style.flex = "1 1 0%";
            saveLayout();
        }

        function togglePane(paneId) {
            const pane = document.getElementById(paneId);
            const resizer = document.getElementById('dragMe');
            if (pane.style.display === 'none') {
                pane.style.display = 'flex';
                resizer.style.display = 'block';
            } else {
                pane.style.display = 'none';
                resizer.style.display = 'none';
            }
            saveLayout();
        }

        document.addEventListener('DOMContentLoaded', () => {
            console.log('[DEBUG] DOMContentLoaded fired');
            
            // Check if user has visited before (skip landing page)
            if (localStorage.getItem('pktana_visited') === 'true') {
                console.log('[DEBUG] Skipping landing page');
                document.getElementById('landingPage').classList.add('hidden');
                document.getElementById('mainNavbar').style.display = 'flex';
                document.getElementById('vscodeLayout').style.display = 'flex';
            }
            
            console.log('[DEBUG] Loading layout and data...');
            loadLayout();
            
            console.log('[DEBUG] Calling loadServerInfo, type:', typeof loadServerInfo);
            loadServerInfo();
            
            console.log('[DEBUG] Calling loadInterfaces, type:', typeof loadInterfaces);
            loadInterfaces();

            // Initial session strip render (shows empty-state hint)
            if (typeof renderSessionTabs === 'function') renderSessionTabs();
            
            // Initialize xterm.js terminal
            if (window.Terminal) {
                initXterm();
            } else {
                console.error('xterm.js library failed to load');
                document.getElementById('xtermContainer').innerHTML = '<div style="color:var(--danger); padding:20px;">Failed to load terminal library. Please refresh the page.</div>';
            }
            
            const resizer = document.getElementById('dragMe');
            const leftPane = document.getElementById('paneLeft');
            const rightPane = document.getElementById('paneRight');
            const wsView = document.getElementById('wsView');
            let x = 0; let y = 0; let leftWidth = 0; let leftHeight = 0;

            const mouseMoveHandler = function(e) {
                if (wsView.classList.contains('vertical')) {
                    const dy = e.clientY - y;
                    const newHeight = ((leftHeight + dy) * 100 / wsView.getBoundingClientRect().height);
                    leftPane.style.flex = `0 0 ${newHeight}%`;
                    rightPane.style.flex = `1 1 0%`;
                } else {
                    const dx = e.clientX - x;
                    const newWidth = ((leftWidth + dx) * 100 / wsView.getBoundingClientRect().width);
                    leftPane.style.flex = `0 0 ${newWidth}%`;
                    rightPane.style.flex = `1 1 0%`;
                }
            };

            const mouseUpHandler = function() {
                resizer.classList.remove('dragging');
                document.removeEventListener('mousemove', mouseMoveHandler);
                document.removeEventListener('mouseup', mouseUpHandler);
                document.body.style.cursor = 'default';
                saveLayout();
            };

            resizer.addEventListener('mousedown', function(e) {
                x = e.clientX; y = e.clientY;
                leftWidth = leftPane.getBoundingClientRect().width;
                leftHeight = leftPane.getBoundingClientRect().height;
                resizer.classList.add('dragging');
                document.body.style.cursor = wsView.classList.contains('vertical') ? 'row-resize' : 'col-resize';
                document.addEventListener('mousemove', mouseMoveHandler);
                document.addEventListener('mouseup', mouseUpHandler);
            });
        });

        // ─── Wiki / Docs Viewer ─────────────────────────────────────────────
        const WIKI_PAGES = [
            {id:'overview',       title:'Overview'},
            {id:'installation',   title:'Installation'},
            {id:'cli-reference',  title:'CLI Reference'},
            {id:'tui-guide',      title:'TUI Guide'},
            {id:'web-ui-guide',   title:'Web UI Guide'},
            {id:'dpi-engine',     title:'DPI Engine'},
            {id:'flow-analyzer',  title:'Flow Analyzer'},
            {id:'api-reference',  title:'API Reference'},
            {id:'library-api',    title:'Library API (Rust)'},
            {id:'protocols',      title:'Protocol Coverage'},
            {id:'architecture',   title:'Architecture'},
            {id:'contributing',   title:'Contributing'},
        ];

        function loadWikiNav() {
            window._wikiNavLoaded = true;
            const nav = document.getElementById('docsNav');
            if (!nav) return;
            WIKI_PAGES.forEach(p => {
                const btn = document.createElement('button');
                btn.className = 'docs-nav-item';
                btn.textContent = p.title;
                btn.onclick = () => loadWikiPage(p.id);
                nav.appendChild(btn);
            });
            // Auto-load first page
            loadWikiPage(WIKI_PAGES[0].id);
        }

        async function loadWikiPage(id) {
            const content = document.getElementById('docsContent');
            if (!content) return;
            // Update nav active state
            document.querySelectorAll('.docs-nav-item').forEach(b => {
                b.classList.toggle('active', b.textContent === (WIKI_PAGES.find(p => p.id === id) || {}).title);
            });
            content.innerHTML = '<div style="color:var(--text-muted);padding:40px;">Loading...</div>';
            try {
                const res = await fetch('/api/wiki?page=' + encodeURIComponent(id));
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const md = await res.text();
                content.innerHTML = '<div class="md-content">' + markdownToHtml(md) + '</div>';
                content.scrollTop = 0;
            } catch(e) {
                content.innerHTML = '<div style="color:#f87171;padding:40px;">Failed to load page: ' + e.message + '</div>';
            }
        }

        function markdownToHtml(md) {
            let html = '';
            const lines = md.split('\n');
            let i = 0;
            let inCodeBlock = false;
            let codeLines = [];
            let inTable = false;
            let tableHeader = false;
            let inList = false;
            let listLines = [];
            let listOrdered = false;

            function flushList() {
                if (!inList) return;
                inList = false;
                const tag = listOrdered ? 'ol' : 'ul';
                html += '<' + tag + '>' + listLines.map(l => '<li>' + inlineFormat(l) + '</li>').join('') + '</' + tag + '>';
                listLines = [];
            }
            function flushTable() {
                if (!inTable) return;
                inTable = false;
                tableHeader = false;
            }

            while (i < lines.length) {
                const line = lines[i];

                // Code blocks
                if (line.startsWith('```')) {
                    if (!inCodeBlock) {
                        flushList();
                        flushTable();
                        inCodeBlock = true;
                        codeLines = [];
                    } else {
                        inCodeBlock = false;
                        const escaped = codeLines.map(l => escapeHtml(l)).join('\n');
                        html += '<pre><code>' + escaped + '</code></pre>';
                        codeLines = [];
                    }
                    i++; continue;
                }
                if (inCodeBlock) {
                    codeLines.push(line);
                    i++; continue;
                }

                // Headings
                if (line.startsWith('#### ')) {
                    flushList(); flushTable();
                    html += '<h4>' + inlineFormat(line.slice(5)) + '</h4>';
                    i++; continue;
                }
                if (line.startsWith('### ')) {
                    flushList(); flushTable();
                    html += '<h3>' + inlineFormat(line.slice(4)) + '</h3>';
                    i++; continue;
                }
                if (line.startsWith('## ')) {
                    flushList(); flushTable();
                    html += '<h2>' + inlineFormat(line.slice(3)) + '</h2>';
                    i++; continue;
                }
                if (line.startsWith('# ')) {
                    flushList(); flushTable();
                    html += '<h1>' + inlineFormat(line.slice(2)) + '</h1>';
                    i++; continue;
                }

                // HR
                if (/^---+$/.test(line.trim())) {
                    flushList(); flushTable();
                    html += '<hr>';
                    i++; continue;
                }

                // Blockquote
                if (line.startsWith('> ')) {
                    flushList(); flushTable();
                    html += '<blockquote>' + inlineFormat(line.slice(2)) + '</blockquote>';
                    i++; continue;
                }

                // Tables
                if (line.includes('|') && line.trim().startsWith('|')) {
                    if (!inTable) {
                        flushList();
                        html += '<table>';
                        inTable = true;
                        tableHeader = true;
                    }
                    if (/^\|[\s\-:|]+\|/.test(line)) {
                        // separator row — skip
                        tableHeader = false;
                        i++; continue;
                    }
                    const cells = line.split('|').filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
                    if (tableHeader) {
                        html += '<tr>' + cells.map(c => '<th>' + inlineFormat(c.trim()) + '</th>').join('') + '</tr>';
                    } else {
                        html += '<tr>' + cells.map(c => '<td>' + inlineFormat(c.trim()) + '</td>').join('') + '</tr>';
                    }
                    i++; continue;
                } else if (inTable) {
                    html += '</table>';
                    inTable = false;
                    tableHeader = false;
                }

                // Unordered list
                if (/^[-*] /.test(line)) {
                    if (inList && listOrdered) flushList();
                    inList = true; listOrdered = false;
                    listLines.push(line.slice(2));
                    i++; continue;
                }
                // Ordered list
                if (/^\d+\. /.test(line)) {
                    if (inList && !listOrdered) flushList();
                    inList = true; listOrdered = true;
                    listLines.push(line.replace(/^\d+\. /, ''));
                    i++; continue;
                }
                if (inList && line.startsWith('  ')) {
                    // continuation indent — append to last list item
                    listLines[listLines.length - 1] += ' ' + line.trim();
                    i++; continue;
                }
                flushList();

                // Empty line
                if (line.trim() === '') {
                    i++; continue;
                }

                // Regular paragraph
                html += '<p>' + inlineFormat(line) + '</p>';
                i++;
            }
            flushList();
            if (inTable) html += '</table>';
            return html;
        }

        function inlineFormat(text) {
            let s = escapeHtml(text);
            // Bold+italic ***text***
            s = s.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
            // Bold **text**
            s = s.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
            // Italic *text*
            s = s.replace(/\*(.*?)\*/g, '<em>$1</em>');
            // Inline code `text`
            s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
            // Links [text](url)
            s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
            return s;
        }

        function escapeHtml(str) {
            return str
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }
    </script>
</body>
</html>
"##;
}
