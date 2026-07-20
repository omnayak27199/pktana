// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

pub mod inner {
    use dashmap::DashMap;
    use pktana_core::{
        build_socket_process_map, clear_security_alerts, clear_security_engine,
        clear_security_for_interface, clear_security_for_session, evaluate_packet,
        geoip_lookup_str, get_ethtool_report, get_nic_dataplane, get_nic_info, get_security_config,
        hex_dump, inspect, inspect_ebpf_interface, list_connections, list_network_namespaces,
        list_nics, list_routes, list_security_alerts, list_security_flows,
        list_security_interfaces, list_security_rules, list_xdp_dispatchers, security_stats,
        set_security_config, CaptureConfig, LinuxCaptureEngine, ProcessInfo, SocketId,
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

    // ── WebSocket PTY Terminal ───────────────────────────────────────────

    fn sha1(input: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        let bits = (input.len() as u64) * 8;
        let mut msg = input.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bits.to_be_bytes());
        for block in msg.chunks_exact(64) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
            for (i, &wi) in w.iter().enumerate() {
                let (f, k) = if i < 20 {
                    ((b & c) | (!b & d), 0x5A827999u32)
                } else if i < 40 {
                    (b ^ c ^ d, 0x6ED9EBA1u32)
                } else if i < 60 {
                    ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32)
                } else {
                    (b ^ c ^ d, 0xCA62C1D6u32)
                };
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = t;
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }
        let mut out = [0u8; 20];
        for i in 0..5 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }

    fn b64(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for c in data.chunks(3) {
            let (aa, bb, cc) = (
                c[0] as u32,
                *c.get(1).unwrap_or(&0) as u32,
                *c.get(2).unwrap_or(&0) as u32,
            );
            let n = (aa << 16) | (bb << 8) | cc;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            if c.len() > 1 {
                out.push(T[((n >> 6) & 63) as usize] as char);
            } else {
                out.push('=');
            }
            if c.len() > 2 {
                out.push(T[(n & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    fn ws_accept_key(key: &str) -> String {
        let mut v = key.trim().as_bytes().to_vec();
        v.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        b64(&sha1(&v))
    }

    fn ws_upgrade(stream: &mut std::net::TcpStream, request: &str) -> bool {
        let key = request
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
            .and_then(|l| l.split_once(':').map(|x| x.1))
            .map(str::trim);
        let key = match key {
            Some(k) => k,
            None => return false,
        };
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            ws_accept_key(key)
        );
        stream.write_all(resp.as_bytes()).is_ok()
    }

    fn ws_write_frame(w: &mut dyn std::io::Write, opcode: u8, data: &[u8]) -> std::io::Result<()> {
        w.write_all(&[0x80 | opcode])?;
        let len = data.len();
        if len < 126 {
            w.write_all(&[len as u8])?;
        } else if len < 65536 {
            w.write_all(&[126, (len >> 8) as u8, len as u8])?;
        } else {
            w.write_all(&[127])?;
            w.write_all(&(len as u64).to_be_bytes())?;
        }
        w.write_all(data)?;
        w.flush()
    }

    fn ws_read_frame(stream: &mut std::net::TcpStream) -> Option<(u8, Vec<u8>)> {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).ok()?;
        let opcode = hdr[0] & 0x0F;
        let masked = (hdr[1] & 0x80) != 0;
        let plen = (hdr[1] & 0x7F) as usize;
        let payload_len = match plen {
            126 => {
                let mut b2 = [0u8; 2];
                stream.read_exact(&mut b2).ok()?;
                u16::from_be_bytes(b2) as usize
            }
            127 => {
                let mut b8 = [0u8; 8];
                stream.read_exact(&mut b8).ok()?;
                u64::from_be_bytes(b8) as usize
            }
            n => n,
        };
        let mask = if masked {
            let mut k = [0u8; 4];
            stream.read_exact(&mut k).ok()?;
            Some(k)
        } else {
            None
        };
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).ok()?;
        if let Some(key) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }
        Some((opcode, payload))
    }

    fn pty_resize(master: libc::c_int, cols: u16, rows: u16) {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe {
            libc::ioctl(master, libc::TIOCSWINSZ, &ws as *const _);
        }
    }

    fn handle_ws_terminal(stream: &mut std::net::TcpStream, request: &str) {
        if !ws_upgrade(stream, request) {
            return;
        }

        let (master, slave) = unsafe {
            let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            if m < 0 {
                return;
            }
            if libc::grantpt(m) != 0 {
                libc::close(m);
                return;
            }
            if libc::unlockpt(m) != 0 {
                libc::close(m);
                return;
            }
            let name_ptr = libc::ptsname(m);
            if name_ptr.is_null() {
                libc::close(m);
                return;
            }
            let s = libc::open(name_ptr, libc::O_RDWR | libc::O_NOCTTY);
            if s < 0 {
                libc::close(m);
                return;
            }
            (m, s)
        };

        pty_resize(master, 220, 50);

        let pid = unsafe { libc::fork() };

        if pid < 0 {
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            return;
        }

        if pid == 0 {
            // Child: wire PTY slave to stdio and exec bash.
            unsafe {
                libc::close(master);
                libc::setsid();
                libc::ioctl(slave, libc::TIOCSCTTY, 0i32);
                libc::dup2(slave, 0);
                libc::dup2(slave, 1);
                libc::dup2(slave, 2);
                if slave > 2 {
                    libc::close(slave);
                }
                libc::setenv(c"TERM".as_ptr(), c"xterm-256color".as_ptr(), 1);
                // Prefer login shell: zsh on macOS, bash on Linux.
                #[cfg(target_os = "macos")]
                {
                    let argv: [*const libc::c_char; 2] = [c"zsh".as_ptr(), std::ptr::null()];
                    libc::execv(c"/bin/zsh".as_ptr(), argv.as_ptr() as _);
                    let argv: [*const libc::c_char; 2] = [c"bash".as_ptr(), std::ptr::null()];
                    libc::execv(c"/bin/bash".as_ptr(), argv.as_ptr() as _);
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let argv: [*const libc::c_char; 2] = [c"bash".as_ptr(), std::ptr::null()];
                    libc::execv(c"/bin/bash".as_ptr(), argv.as_ptr() as _);
                }
                libc::_exit(1);
            }
        }

        // Parent: bridge WebSocket ↔ PTY master.
        unsafe {
            libc::close(slave);
        }

        let master_r = unsafe { libc::dup(master) };
        if master_r < 0 {
            unsafe {
                libc::kill(pid, libc::SIGHUP);
                libc::close(master);
            }
            return;
        }

        let mut ws_tx = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => {
                unsafe {
                    libc::kill(pid, libc::SIGHUP);
                    libc::close(master_r);
                    libc::close(master);
                }
                return;
            }
        };

        // Reader thread: PTY output → WebSocket frames.
        thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = unsafe {
                    libc::read(master_r, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n <= 0 {
                    break;
                }
                if ws_write_frame(&mut ws_tx, 2, &buf[..n as usize]).is_err() {
                    break;
                }
            }
            unsafe {
                libc::close(master_r);
            }
        });

        // Main loop: WebSocket frames → PTY master stdin.
        loop {
            match ws_read_frame(stream) {
                None | Some((8, _)) => break,
                Some((_, data)) if data.len() == 5 && data[0] == 0xFF => {
                    // Resize: 0xFF cols_hi cols_lo rows_hi rows_lo
                    let cols = ((data[1] as u16) << 8) | data[2] as u16;
                    let rows = ((data[3] as u16) << 8) | data[4] as u16;
                    pty_resize(master, cols, rows);
                }
                Some((_, data)) if !data.is_empty() => {
                    let mut off = 0;
                    while off < data.len() {
                        let n = unsafe {
                            libc::write(
                                master,
                                data[off..].as_ptr() as *const libc::c_void,
                                data.len() - off,
                            )
                        };
                        if n <= 0 {
                            break;
                        }
                        off += n as usize;
                    }
                }
                Some(_) => {}
            }
        }

        unsafe {
            libc::kill(pid, libc::SIGHUP);
            libc::close(master);
        }
    }

    fn handle_client(stream: &mut std::net::TcpStream) {
        let mut buffer = [0; 8192];
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);

            if request.starts_with("GET /api/security/config ") {
                let cfg = get_security_config();
                let json = serde_json::to_string(&cfg).unwrap_or_else(|_| "{}".into());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("POST /api/security/config") {
                let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
                let body = &request[body_start..];
                let prev = get_security_config();
                let mut cfg = prev.clone();
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(b) = v.get("dlp_enabled").and_then(|x| x.as_bool()) {
                        cfg.dlp_enabled = b;
                    }
                    if let Some(b) = v.get("idps_enabled").and_then(|x| x.as_bool()) {
                        cfg.idps_enabled = b;
                    }
                    if let Some(s) = v.get("dlp_action").and_then(|x| x.as_str()) {
                        cfg.dlp_action = s.to_string();
                        cfg.dlp_mode = s.to_string();
                    } else if let Some(s) = v.get("dlp_mode").and_then(|x| x.as_str()) {
                        cfg.dlp_action = s.to_string();
                        cfg.dlp_mode = s.to_string();
                    }
                    if let Some(s) = v.get("idps_action").and_then(|x| x.as_str()) {
                        cfg.idps_action = s.to_string();
                        cfg.idps_mode = s.to_string();
                    } else if let Some(s) = v.get("idps_mode").and_then(|x| x.as_str()) {
                        cfg.idps_action = s.to_string();
                        cfg.idps_mode = s.to_string();
                    }
                    if let Some(s) = v.get("redirect_target").and_then(|x| x.as_str()) {
                        cfg.redirect_target = s.to_string();
                    }
                    if let Some(ra) = v.get("rule_actions").and_then(|x| x.as_object()) {
                        cfg.rule_actions.clear();
                        for (k, val) in ra {
                            if let Some(a) = val.as_str() {
                                cfg.rule_actions.insert(k.clone(), a.to_string());
                            }
                        }
                    }
                    if let Some(rules) = v.get("policy_rules").and_then(|x| x.as_array()) {
                        cfg.policy_rules = rules
                            .iter()
                            .filter_map(|r| serde_json::from_value(r.clone()).ok())
                            .collect();
                    }
                }
                cfg.normalize();
                // When an engine is turned off, clear its logs so the UI does not keep stale alerts.
                if prev.dlp_enabled && !cfg.dlp_enabled {
                    clear_security_engine("dlp");
                }
                if prev.idps_enabled && !cfg.idps_enabled {
                    clear_security_engine("idps");
                }
                set_security_config(cfg.clone());
                let json = serde_json::to_string(&cfg).unwrap_or_else(|_| "{}".into());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/security/alerts") {
                let alerts = list_security_alerts(500);
                let json = serde_json::to_string(&alerts).unwrap_or_else(|_| "[]".into());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/security/flows") {
                let engine = if request.contains("engine=dlp") {
                    Some("dlp")
                } else if request.contains("engine=idps") {
                    Some("idps")
                } else {
                    None
                };
                let iface = request
                    .split('?')
                    .nth(1)
                    .and_then(|q| {
                        q.split('&').find_map(|pair| {
                            let (k, v) = pair.split_once('=')?;
                            if k == "iface" {
                                Some(decode_url(v))
                            } else {
                                None
                            }
                        })
                    })
                    .filter(|s| !s.is_empty());
                let flows = list_security_flows(engine, iface.as_deref(), 500);
                let json = serde_json::to_string(&flows).unwrap_or_else(|_| "[]".into());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/security/rules ") {
                let rules = list_security_rules();
                let json = serde_json::to_string(&rules).unwrap_or_else(|_| "[]".into());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/security/stats ") {
                let stats = security_stats();
                let json = serde_json::to_string(&stats).unwrap_or_else(|_| "{}".into());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/security/interfaces") {
                let ifaces = list_security_interfaces();
                let json = serde_json::to_string(&ifaces).unwrap_or_else(|_| "[]".into());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("POST /api/security/clear ") {
                clear_security_alerts();
                let json = r#"{"ok":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/interfaces ") {
                let ifaces = LinuxCaptureEngine::list_interfaces().unwrap_or_default();
                let mut json = String::from("[");
                for (i, iface) in ifaces.iter().enumerate() {
                    let desc = iface.description.as_deref().unwrap_or("");
                    let addr = iface
                        .addresses
                        .first()
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    // Linux: /sys operstate. Elsewhere (macOS): treat non-loopback as up.
                    let operstate_path = format!("/sys/class/net/{}/operstate", iface.name);
                    let is_up = std::fs::read_to_string(&operstate_path)
                        .map(|s| matches!(s.trim(), "up" | "unknown" | "dormant"))
                        .unwrap_or(!iface.loopback);
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
                let uptime_raw = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
                let up_secs = uptime_raw.split_whitespace().next().unwrap_or("0");
                let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
                let mut mem_total = 0u64;
                let mut mem_free = 0u64;
                let mut mem_avail = 0u64;
                let mut mem_buffers = 0u64;
                let mut mem_cached = 0u64;
                for line in meminfo.lines() {
                    let mut parts = line.split_whitespace();
                    match parts.next() {
                        Some("MemTotal:") => {
                            mem_total = parts.next().unwrap_or("0").parse().unwrap_or(0)
                        }
                        Some("MemFree:") => {
                            mem_free = parts.next().unwrap_or("0").parse().unwrap_or(0)
                        }
                        Some("MemAvailable:") => {
                            mem_avail = parts.next().unwrap_or("0").parse().unwrap_or(0)
                        }
                        Some("Buffers:") => {
                            mem_buffers = parts.next().unwrap_or("0").parse().unwrap_or(0)
                        }
                        Some("Cached:") => {
                            mem_cached = parts.next().unwrap_or("0").parse().unwrap_or(0)
                        }
                        _ => {}
                    }
                }
                // CPU info
                let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
                let cpu_cores = cpuinfo
                    .lines()
                    .filter(|l| l.starts_with("processor"))
                    .count();
                let cpu_model = cpuinfo
                    .lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                // Load average
                let loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
                let load_parts: Vec<&str> = loadavg.split_whitespace().collect();
                let load1 = load_parts.first().unwrap_or(&"0");
                let load5 = load_parts.get(1).unwrap_or(&"0");
                let load15 = load_parts.get(2).unwrap_or(&"0");
                // Disk usage on /
                let df_out = std::process::Command::new("df")
                    .args(["-k", "/"])
                    .output()
                    .ok();
                let (disk_total, disk_used, disk_free) = df_out
                    .and_then(|o| {
                        let s = String::from_utf8_lossy(&o.stdout).to_string();
                        s.lines().nth(1).map(|l| {
                            let p: Vec<&str> = l.split_whitespace().collect();
                            (
                                p.get(1).unwrap_or(&"0").parse::<u64>().unwrap_or(0),
                                p.get(2).unwrap_or(&"0").parse::<u64>().unwrap_or(0),
                                p.get(3).unwrap_or(&"0").parse::<u64>().unwrap_or(0),
                            )
                        })
                    })
                    .unwrap_or((0, 0, 0));
                // OS release
                let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
                let os_name = os_release
                    .lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| {
                        l.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_string()
                    })
                    .unwrap_or_default();
                let json = format!(
                    concat!(
                        r#"{{"hostname":"{}","version":"{}","uptime_sec":{},"#,
                        r#""mem_total_kb":{},"mem_free_kb":{},"mem_avail_kb":{},"mem_buffers_kb":{},"mem_cached_kb":{},"#,
                        r#""cpu_cores":{},"cpu_model":"{}","#,
                        r#""load1":{},"load5":{},"load15":{},"#,
                        r#""disk_total_kb":{},"disk_used_kb":{},"disk_free_kb":{},"#,
                        r#""os_name":"{}"}}"#
                    ),
                    escape_json(&hostname),
                    escape_json(&version),
                    up_secs,
                    mem_total,
                    mem_free,
                    mem_avail,
                    mem_buffers,
                    mem_cached,
                    cpu_cores,
                    escape_json(&cpu_model),
                    load1,
                    load5,
                    load15,
                    disk_total,
                    disk_used,
                    disk_free,
                    escape_json(&os_name)
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

                    if let Some((_, session)) = SESSIONS.remove(session_id) {
                        clear_security_for_session(session_id);
                        let iface = session.interface.clone();
                        let others_on_iface = SESSIONS
                            .iter()
                            .any(|entry| entry.value().interface == iface);
                        if !others_on_iface && !iface.is_empty() {
                            clear_security_for_interface(&iface);
                        }
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
            } else if request.starts_with("GET /api/terminal/ws ") {
                let req_str = request.to_string();
                drop(request);
                handle_ws_terminal(stream, &req_str);
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
                    let ips_json = nic
                        .ip_addresses
                        .iter()
                        .map(|ip| format!("\"{}\"", escape_json(ip)))
                        .collect::<Vec<_>>()
                        .join(",");
                    let json = format!(
                        concat!(
                            r#"{{"name":"{name}","state":"{state}","mac":"{mac}","mtu":{mtu},"#,
                            r#""speed":"{speed}","duplex":"{duplex}","driver":"{driver}","#,
                            r#""loopback":{loopback},"promisc":{promisc},"#,
                            r#""rx_bytes":{rxb},"rx_packets":{rxp},"rx_errors":{rxe},"rx_dropped":{rxd},"#,
                            r#""tx_bytes":{txb},"tx_packets":{txp},"tx_errors":{txe},"tx_dropped":{txd},"#,
                            r#""rx_crc_errors":{crc},"rx_missed_errors":{missed},"rx_frame_errors":{frame},"#,
                            r#""rx_fifo_errors":{fifo},"tx_carrier_errors":{carrier_err},"collisions":{coll},"#,
                            r#""carrier_changes":{cc},"master":"{master}","is_bridge":{bridge},"is_bond":{bond},"#,
                            r#""ifalias":"{alias}","ips":[{ips}]}}"#
                        ),
                        name = escape_json(&nic.name),
                        state = state,
                        mac = escape_json(&nic.mac),
                        mtu = nic.mtu,
                        speed = escape_json(&nic.speed_label()),
                        duplex = escape_json(nic.duplex.as_deref().unwrap_or("")),
                        driver = escape_json(nic.driver.as_deref().unwrap_or("")),
                        loopback = nic.is_loopback(),
                        promisc = nic.is_promisc(),
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
                        master = escape_json(nic.master.as_deref().unwrap_or("")),
                        bridge = nic.is_bridge,
                        bond = nic.is_bond,
                        alias = escape_json(nic.ifalias.as_deref().unwrap_or("")),
                        ips = ips_json,
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
                    let ebpf = inspect_ebpf_interface(&iface).ok();
                    let bypass = format!("{}", dp.bypass_mode);
                    let driver = dp.userspace_driver.as_deref().unwrap_or("");

                    let (xdp_prog_ids, xdp_mode_str) = if let Some(ref r) = ebpf {
                        (
                            r.xdp_prog_ids.clone(),
                            r.xdp_mode.as_deref().unwrap_or("").to_string(),
                        )
                    } else {
                        (
                            dp.xdp_prog_ids.clone(),
                            dp.xdp_mode.as_deref().unwrap_or("").to_string(),
                        )
                    };
                    let xdp_ids: Vec<String> = xdp_prog_ids.iter().map(|i| i.to_string()).collect();

                    let (tc_clsact, tc_dirs, tc_ids) = if let Some(ref r) = ebpf {
                        (
                            r.tc.clsact,
                            r.tc.directions.join(", "),
                            r.tc.prog_ids
                                .iter()
                                .map(|i| i.to_string())
                                .collect::<Vec<_>>()
                                .join(", "),
                        )
                    } else {
                        (
                            dp.tc_clsact,
                            dp.tc_bpf_directions.join(", "),
                            dp.tc_bpf_prog_ids
                                .iter()
                                .map(|i| i.to_string())
                                .collect::<Vec<_>>()
                                .join(", "),
                        )
                    };
                    let pci_link = format!(
                        "{} {}",
                        dp.pci_link_speed.as_deref().unwrap_or("—"),
                        dp.pci_link_width
                            .map(|w| format!("x{w}"))
                            .as_deref()
                            .unwrap_or("")
                    );
                    let pci_max_link = format!(
                        "{} {}",
                        dp.pci_max_link_speed.as_deref().unwrap_or("—"),
                        dp.pci_max_link_width
                            .map(|w| format!("x{w}"))
                            .as_deref()
                            .unwrap_or("")
                    );
                    // XDP dispatcher info from /sys/fs/bpf/xdp/
                    let dispatchers = list_xdp_dispatchers();
                    let mine: Vec<String> = dispatchers
                        .iter()
                        .filter(|d| d.iface.as_deref() == Some(iface.as_str()))
                        .map(|d| format!("dispatch-{}-{}", d.prog_id, d.link_id))
                        .collect();
                    let unmatched = dispatchers.iter().filter(|d| d.iface.is_none()).count();
                    let xdp_dispatchers = if !mine.is_empty() {
                        mine.join(", ")
                    } else if unmatched > 0 {
                        format!("{unmatched} pinned (run as root for iface correlation)")
                    } else {
                        String::new()
                    };
                    let sriov_role = if dp.is_virtual_function {
                        format!("VF (physfn: {})", dp.physfn_pci.as_deref().unwrap_or("?"))
                    } else if let Some(total) = dp.sriov_vfs_total {
                        format!(
                            "PF — {}/{} VFs enabled",
                            dp.sriov_vfs_enabled.unwrap_or(0),
                            total
                        )
                    } else {
                        String::new()
                    };

                    let ebpf_active = ebpf.as_ref().map(|r| r.ebpf_active()).unwrap_or(false);
                    let iface_kind = ebpf
                        .as_ref()
                        .map(|r| r.iface_kind.as_str())
                        .unwrap_or("unknown");

                    let pinned_json = ebpf
                        .as_ref()
                        .map(|r| {
                            r.pinned_matches
                                .iter()
                                .map(|p| {
                                    format!(
                                        r#"{{"name":"{}","kind":"{}","path":"{}","prog_id":{}}}"#,
                                        escape_json(&p.pin_name),
                                        escape_json(&p.kind),
                                        escape_json(&p.path),
                                        p.prog_id
                                            .map(|i| i.to_string())
                                            .unwrap_or_else(|| "null".into())
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();

                    let bpftool_json = ebpf
                        .as_ref()
                        .map(|r| {
                            r.bpftool_attachments
                                .iter()
                                .map(|a| {
                                    format!(
                                        r#"{{"hook":"{}","mode":"{}","prog_id":{},"prog_name":"{}","raw":"{}"}}"#,
                                        escape_json(&a.hook),
                                        escape_json(a.mode.as_deref().unwrap_or("")),
                                        a.prog_id
                                            .map(|i| i.to_string())
                                            .unwrap_or_else(|| "null".into()),
                                        escape_json(a.prog_name.as_deref().unwrap_or("")),
                                        escape_json(&a.raw_line)
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();

                    let dispatchers_json = dispatchers
                        .iter()
                        .filter(|d| d.iface.as_deref() == Some(iface.as_str()))
                        .map(|d| {
                            let slots = d
                                .slots
                                .iter()
                                .map(|s| format!("\"{}\"", escape_json(s)))
                                .collect::<Vec<_>>()
                                .join(",");
                            format!(
                                r#"{{"prog_id":{},"link_id":{},"dir":"{}","slots":[{}],"iface":"{}"}}"#,
                                d.prog_id,
                                d.link_id,
                                escape_json(&d.dir),
                                slots,
                                escape_json(d.iface.as_deref().unwrap_or(""))
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");

                    let ns_match = list_network_namespaces()
                        .into_iter()
                        .find(|ns| ns.interfaces.iter().any(|i| i == &iface));
                    let (ns_inode, ns_is_host, ns_label) = ns_match
                        .as_ref()
                        .map(|ns| {
                            (
                                ns.inode,
                                ns.is_host,
                                if ns.is_host {
                                    "host".to_string()
                                } else {
                                    format!("inode:{}", ns.inode)
                                },
                            )
                        })
                        .unwrap_or((0, true, String::new()));
                    let ns_xdp = ns_match
                        .as_ref()
                        .and_then(|ns| {
                            ns.xdp_per_iface
                                .iter()
                                .find(|(i, _)| i == &iface)
                                .map(|(_, ids)| {
                                    ids.iter()
                                        .map(|i| i.to_string())
                                        .collect::<Vec<_>>()
                                        .join(",")
                                })
                        })
                        .unwrap_or_default();
                    let ns_afxdp = ns_match
                        .as_ref()
                        .and_then(|ns| {
                            ns.afxdp_per_iface
                                .iter()
                                .find(|(i, _)| i == &iface)
                                .map(|(_, cnt)| *cnt)
                        })
                        .unwrap_or(0);

                    let json = format!(
                        concat!(
                            r#"{{"bypass_mode":"{bypass}","ebpf_active":{ebpf_active},"iface_kind":"{iface_kind}","#,
                            r#""xdp_prog_ids":"{xdp_ids}","xdp_mode":"{xdp_mode}","xdp_dispatchers":"{xdp_dispatchers}","#,
                            r#""xdp_dispatchers_detail":[{dispatchers_json}],"afxdp_sockets":{afxdp},"#,
                            r#""dpdk_bound":{dpdk},"driver":"{driver}","#,
                            r#""tc_clsact":{tc_clsact},"tc_bpf_directions":"{tc_dirs}","tc_bpf_prog_ids":"{tc_ids}","#,
                            r#""pinned_bpf":[{pinned_json}],"bpftool_net":[{bpftool_json}],"#,
                            r#""ns_inode":{ns_inode},"ns_is_host":{ns_is_host},"ns_label":"{ns_label}","#,
                            r#""ns_xdp_ids":"{ns_xdp}","ns_afxdp_sockets":{ns_afxdp},"#,
                            r#""rx_queues":{rx_q},"tx_queues":{tx_q},"combined_queues":{comb_q},"#,
                            r#""pci_address":"{pci_addr}","pci_vendor":"{pci_vendor}","pci_device":"{pci_dev}","#,
                            r#""pci_link":"{pci_link}","pci_max_link":"{pci_max_link}","numa_node":"{numa}","#,
                            r#""sriov":"{sriov}","hw_features_on":"{hw_on}"}}"#
                        ),
                        ebpf_active = ebpf_active,
                        iface_kind = iface_kind,
                        bypass = bypass,
                        xdp_ids = if xdp_ids.is_empty() {
                            "None".into()
                        } else {
                            xdp_ids.join(", ")
                        },
                        xdp_mode = xdp_mode_str,
                        xdp_dispatchers = xdp_dispatchers,
                        dispatchers_json = dispatchers_json,
                        afxdp = dp.afxdp_sockets,
                        dpdk = dp.dpdk_bound,
                        driver = driver,
                        tc_clsact = tc_clsact,
                        tc_dirs = tc_dirs,
                        tc_ids = tc_ids,
                        pinned_json = pinned_json,
                        bpftool_json = bpftool_json,
                        ns_inode = ns_inode,
                        ns_is_host = ns_is_host,
                        ns_label = escape_json(&ns_label),
                        ns_xdp = ns_xdp,
                        ns_afxdp = ns_afxdp,
                        rx_q = dp.rx_queues,
                        tx_q = dp.tx_queues,
                        comb_q = dp.combined_queues,
                        pci_addr = dp.pci_address.as_deref().unwrap_or("—"),
                        pci_vendor = dp.pci_vendor_id.as_deref().unwrap_or("—"),
                        pci_dev = dp.pci_device_id.as_deref().unwrap_or("—"),
                        pci_link = pci_link.trim(),
                        pci_max_link = pci_max_link.trim(),
                        numa = dp
                            .numa_node
                            .map(|n| n.to_string())
                            .as_deref()
                            .unwrap_or("—"),
                        sriov = sriov_role,
                        hw_on = dp.hw_features_on.join(", "),
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
                    let driver = escape_json(et.driver.as_deref().unwrap_or(""));
                    let fw_ver = escape_json(et.firmware_ver.as_deref().unwrap_or(""));
                    let bus_info = escape_json(et.bus_info.as_deref().unwrap_or(""));
                    let duplex = escape_json(et.duplex.as_deref().unwrap_or(""));
                    let autoneg = escape_json(et.autoneg.as_deref().unwrap_or(""));
                    let pcie_speed = escape_json(et.pcie_speed.as_deref().unwrap_or(""));
                    let pcie_width = et.pcie_width.unwrap_or(0);
                    let carrier_changes = et.carrier_changes.unwrap_or(0);
                    let carrier_up = et.carrier_up.unwrap_or(0);
                    let carrier_down = et.carrier_down.unwrap_or(0);
                    // Collect HW offload features that are "on"
                    let features_on: Vec<String> = et
                        .features
                        .iter()
                        .filter(|(_, v)| v.as_str() == "on")
                        .map(|(k, _)| escape_json(k))
                        .take(20)
                        .collect();
                    let features_json = features_on
                        .iter()
                        .map(|f| format!("\"{}\"", f))
                        .collect::<Vec<_>>()
                        .join(",");
                    // IRQ affinity: up to first 8 queues
                    let irq_json = et
                        .queue_irq_affinities
                        .iter()
                        .take(8)
                        .map(|q| {
                            format!(
                                r#"{{"q":"{}","irq":{},"cpus":"{}"}}"#,
                                escape_json(&q.queue_name),
                                q.irq,
                                escape_json(&q.cpu_list)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    let json = format!(
                        concat!(
                            r#"{{"driver":"{driver}","firmware":"{fw}","bus_info":"{bus}","#,
                            r#""speed_mbps":{speed},"duplex":"{duplex}","autoneg":"{autoneg}","operstate":"{opstate}","#,
                            r#""rx_queues":{rx_q},"tx_queues":{tx_q},"combined_queues":{comb_q},"tx_queue_len":{tql},"#,
                            r#""pcie_speed":"{pcie_speed}","pcie_width":{pcie_width},"#,
                            r#""carrier_changes":{cc},"carrier_up":{cu},"carrier_down":{cd},"#,
                            r#""features_on":[{feats}],"irq_affinities":[{irqs}]}}"#
                        ),
                        driver = driver,
                        fw = fw_ver,
                        bus = bus_info,
                        speed = et.speed_mbps.unwrap_or(0),
                        duplex = duplex,
                        autoneg = autoneg,
                        opstate = et.operstate,
                        rx_q = et.rx_queues,
                        tx_q = et.tx_queues,
                        comb_q = et.combined_queues,
                        tql = et.tx_queue_len.unwrap_or(0),
                        pcie_speed = pcie_speed,
                        pcie_width = pcie_width,
                        cc = carrier_changes,
                        cu = carrier_up,
                        cd = carrier_down,
                        feats = features_json,
                        irqs = irq_json,
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(), json
                    );
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n");
                }
            } else if request.starts_with("GET /api/hw?iface=") {
                let start = "GET /api/hw?iface=".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let iface = decode_url(&request[start..end]);
                let bridge = pktana_core::hw::get_bridge_info(&iface);
                let bridge_port = pktana_core::hw::get_bridge_port_info(&iface);
                let bond = pktana_core::hw::get_bond_info(&iface);
                let ptp = pktana_core::hw::get_ptp_clocks(&iface);
                let iommu = pktana_core::hw::get_iommu_group(&iface);
                let bridge_json = if let Some(b) = &bridge {
                    let ports_json = b
                        .ports
                        .iter()
                        .map(|p| format!("\"{}\"", escape_json(p)))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!(
                        r#"{{"bridge_id":"{}","stp":{},"vlan_filter":{},"ageing_jiffies":{},"ports":[{}]}}"#,
                        escape_json(&b.bridge_id),
                        b.stp_enabled,
                        b.vlan_filtering,
                        b.ageing_time_jiffies,
                        ports_json
                    )
                } else {
                    "null".to_string()
                };
                let bridge_port_json = if let Some(bp) = &bridge_port {
                    format!(
                        r#"{{"bridge":"{}","stp_state":{},"stp_label":"{}","port_id":"{}","path_cost":{},"hairpin":{},"learning":{}}}"#,
                        escape_json(&bp.bridge),
                        bp.stp_state,
                        escape_json(pktana_core::hw::stp_state_label(bp.stp_state)),
                        escape_json(&bp.port_id),
                        bp.path_cost,
                        bp.hairpin,
                        bp.learning
                    )
                } else {
                    "null".to_string()
                };
                let bond_json = if let Some(bo) = &bond {
                    let slaves_json = bo
                        .slaves
                        .iter()
                        .map(|s| format!("\"{}\"", escape_json(s)))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!(
                        r#"{{"mode":"{}","active_slave":"{}","slaves":[{}],"miimon":{},"link_failures":{}}}"#,
                        escape_json(&bo.mode),
                        escape_json(bo.active_slave.as_deref().unwrap_or("")),
                        slaves_json,
                        bo.miimon,
                        bo.link_failures
                    )
                } else {
                    "null".to_string()
                };
                let ptp_json = ptp.iter().map(|p| {
                    format!(r#"{{"device":"{}","clock_name":"{}","max_adj_ppb":{},"n_extts":{},"n_periodic":{}}}"#,
                        escape_json(&p.device), escape_json(&p.clock_name), p.max_adj_ppb, p.n_extts, p.n_periodic_outputs)
                }).collect::<Vec<_>>().join(",");
                let iommu_json = if let Some(ig) = &iommu {
                    let members_json = ig
                        .members
                        .iter()
                        .map(|m| format!("\"{}\"", escape_json(m)))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!(
                        r#"{{"group_id":{},"members":[{}]}}"#,
                        ig.group_id, members_json
                    )
                } else {
                    "null".to_string()
                };
                let json = format!(
                    r#"{{"bridge":{},"bridge_port":{},"bond":{},"ptp":[{}],"iommu":{}}}"#,
                    bridge_json, bridge_port_json, bond_json, ptp_json, iommu_json
                );
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", json.len(), json);
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/bpf ") {
                let objs = pktana_core::dp::scan_bpf_fs();
                let dispatchers = pktana_core::dp::list_xdp_dispatchers();
                let objs_json = objs
                    .iter()
                    .map(|o| {
                        format!(
                            r#"{{"path":"{}","is_dir":{},"category":"{}"}}"#,
                            escape_json(&o.path),
                            o.is_dir,
                            escape_json(o.category.as_deref().unwrap_or(""))
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let disp_json = dispatchers
                    .iter()
                    .map(|d| {
                        let slots_json = d
                            .slots
                            .iter()
                            .map(|s| format!("\"{}\"", escape_json(s)))
                            .collect::<Vec<_>>()
                            .join(",");
                        format!(
                            r#"{{"prog_id":{},"link_id":{},"dir":"{}","slots":[{}],"iface":"{}"}}"#,
                            d.prog_id,
                            d.link_id,
                            escape_json(&d.dir),
                            slots_json,
                            escape_json(d.iface.as_deref().unwrap_or(""))
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let json = format!(
                    r#"{{"pinned":[{}],"xdp_dispatchers":[{}]}}"#,
                    objs_json, disp_json
                );
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", json.len(), json);
                let _ = stream.write_all(response.as_bytes());
            } else if request.starts_with("GET /api/ns ") {
                let namespaces = pktana_core::dp::list_network_namespaces();
                let ns_json = namespaces.iter().map(|ns| {
                    let pids_json = ns.pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                    let comms_json = ns.comms.iter().map(|c| format!("\"{}\"", escape_json(c))).collect::<Vec<_>>().join(",");
                    let ifaces_json = ns.interfaces.iter().map(|i| format!("\"{}\"", escape_json(i))).collect::<Vec<_>>().join(",");
                    let afxdp_json = ns.afxdp_per_iface.iter().map(|(k, v)| format!("\"{}\":{}", escape_json(k), v)).collect::<Vec<_>>().join(",");
                    let xdp_json = ns.xdp_per_iface.iter().map(|(k, v)| {
                        let ids = v.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(",");
                        format!("\"{}\":[{}]", escape_json(k), ids)
                    }).collect::<Vec<_>>().join(",");
                    format!(r#"{{"inode":{},"is_host":{},"pids":[{}],"comms":[{}],"interfaces":[{}],"afxdp":{{{}}}, "xdp":{{{}}}}}"#,
                        ns.inode, ns.is_host, pids_json, comms_json, ifaces_json, afxdp_json, xdp_json)
                }).collect::<Vec<_>>().join(",");
                let json = format!(r#"[{}]"#, ns_json);
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", json.len(), json);
                let _ = stream.write_all(response.as_bytes());
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
                    let capture_iface = config.interface.clone();

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

                        let ts_sec = pkt.timestamp_sec as u64;
                        let sec_result = evaluate_packet(
                            &dp,
                            ts_sec,
                            dp.frame_len as u64,
                            &capture_iface,
                            session_id_for_handler.as_deref().unwrap_or(""),
                        );
                        let sec_alerts = sec_result.alerts.clone();
                        let sec_json =
                            serde_json::to_string(&sec_alerts).unwrap_or_else(|_| "[]".into());
                        let engines_json = serde_json::to_string(&sec_result.engines)
                            .unwrap_or_else(|_| "[]".into());

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
                        if !sec_alerts.is_empty() {
                            tags.push("security-alert");
                            if sec_alerts.iter().any(|a| a.engine == "dlp") {
                                tags.push("dlp-alert");
                            }
                            if sec_alerts.iter().any(|a| a.engine == "idps") {
                                tags.push("idps-alert");
                            }
                        }
                        if sec_result.dropped {
                            tags.push("security-drop");
                        }
                        if sec_result.verdict == "redirect" {
                            tags.push("security-redirect");
                        }
                        if sec_result.verdict == "pass" && !sec_alerts.is_empty() {
                            tags.push("security-pass");
                        }
                        if sec_result.verdict == "quarantine" {
                            tags.push("security-quarantine");
                        }
                        let tags_str = tags.join(",");

                        // Hex dump: first 128 bytes (8 lines) for on-click display
                        let hex_text = hex_dump(&pkt.data, pkt.data.len().min(128)).join("\n");

                        let msg = format!(
                            "data: {{\"ts_sec\":{}, \"ts_usec\":{}, \"summary\":\"{}\", \"len\": {}, \"risk\": {}, \"category\": \"{}\", \"proto\": \"{}\", \"src\":\"{}\", \"dst\":\"{}\", \"tags\":\"{}\", \"details\":\"{}\", \"hex\":\"{}\", \"security_alerts\":{}, \"security_verdict\":\"{}\", \"security_flow_key\":\"{}\", \"security_engines\":{}, \"security_dropped\":{}, \"security_redirect\":\"{}\"}}\n\n",
                            pkt.timestamp_sec, pkt.timestamp_usec, escape_json(&dp.one_liner()), dp.frame_len, risk, escape_json(dp.app_category.as_deref().unwrap_or("Unknown")), escape_json(proto), escape_json(&src), escape_json(&dst), tags_str, escape_json(&detail_text), escape_json(&hex_text), sec_json, escape_json(&sec_result.verdict), escape_json(&sec_result.flow_key), engines_json, sec_result.dropped, escape_json(&sec_result.redirect_target)
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

    // Wiki pages must live under this crate (`wiki/`) so `cargo publish` can
    // package them. Sync from repo-root with: scripts/sync-cli-wiki.sh
    const WIKI_OVERVIEW: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/wiki/01-overview.md"));
    const WIKI_INSTALLATION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/02-installation.md"
    ));
    const WIKI_CLI_REF: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/03-cli-reference.md"
    ));
    const WIKI_TUI: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/wiki/04-tui-guide.md"));
    const WIKI_WEBUI: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/05-web-ui-guide.md"
    ));
    const WIKI_DPI: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/06-dpi-engine.md"
    ));
    const WIKI_FLOW: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/07-flow-analyzer.md"
    ));
    const WIKI_API: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/08-api-reference.md"
    ));
    const WIKI_LIB: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/09-library-api.md"
    ));
    const WIKI_PROTO: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/wiki/10-protocols.md"));
    const WIKI_ARCH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/11-architecture.md"
    ));
    const WIKI_CONTRIB: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wiki/12-contributing.md"
    ));

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
        /* ── Design tokens — dark default ── */
        :root {
            --primary: #f97316;
            --primary-dark: #ea580c;
            --primary-light: rgba(249,115,22,0.12);
            --bg: #07111e;
            --bg-solid: #07111e;
            --surface: #0c1a2e;
            --surface2: #101e30;
            --border: #182840;
            --border-hi: #223450;
            --text-main: #c5d0e0;
            --text-muted: #445870;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #38bdf8;
            --sidebar-bg: #07111e;
            --sidebar-hover: rgba(249,115,22,0.07);
            --navbar-bg: #07111e;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.6);
            --shadow: 0 2px 8px rgba(0,0,0,0.6);
            --shadow-lg: 0 4px 16px rgba(0,0,0,0.7);
            --shadow-xl: 0 8px 32px rgba(0,0,0,0.8);
        }
        /* ── Light theme override ── */
        body.light-theme {
            --bg: #f1f5f9;
            --bg-solid: #f1f5f9;
            --surface: #ffffff;
            --surface2: #f8fafc;
            --border: #e2e8f0;
            --border-hi: #cbd5e1;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --sidebar-bg: #ffffff;
            --sidebar-hover: rgba(249,115,22,0.07);
            --navbar-bg: #ffffff;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.06);
            --shadow: 0 2px 8px rgba(0,0,0,0.08);
            --shadow-lg: 0 4px 16px rgba(0,0,0,0.1);
            --shadow-xl: 0 8px 32px rgba(0,0,0,0.12);
        }
        /* protocol row tints — light theme */
        body.light-theme .ws-bg-tcp  { background-color:#dbeafe; color:#1e40af; }
        body.light-theme .ws-bg-udp  { background-color:#dcfce7; color:#166534; }
        body.light-theme .ws-bg-http { background-color:#d1fae5; color:#065f46; }
        body.light-theme .ws-bg-dns  { background-color:#e0f2fe; color:#075985; }
        body.light-theme .ws-bg-icmp { background-color:#f3e8ff; color:#6b21a8; }
        body.light-theme .ws-bg-arp  { background-color:#fef9c3; color:#854d0e; }
        body.light-theme .ws-bg-bad  { background-color:#fee2e2; color:#991b1b; }
        body.light-theme .ws-table th { background:#f1f5f9; color:#475569; }
        body.light-theme .pane-hex   { background:#1e293b; color:#94a3b8; }

        /* ── Reset & base ── */
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background: var(--bg); color: var(--text-main); height: 100vh; display: flex; flex-direction: column; overflow: hidden; -webkit-font-smoothing: antialiased; font-size: 13px; }

        /* ── Scrollbars ── */
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(249,115,22,0.2); border-radius: 2px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(249,115,22,0.45); }

        /* ── Animations ── */
        @keyframes fadeInScale { from{opacity:0;transform:scale(0.94)} to{opacity:1;transform:scale(1)} }
        @keyframes fadeInUp    { from{opacity:0;transform:translateY(14px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin        { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes slideIn     { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }
        @keyframes livePing    { 0%{box-shadow:0 0 0 0 rgba(16,185,129,0.7)} 70%{box-shadow:0 0 0 8px rgba(16,185,129,0)} 100%{box-shadow:0 0 0 0 rgba(16,185,129,0)} }
        @keyframes toastIn     { from{opacity:0;transform:translateX(14px)} to{opacity:1;transform:translateX(0)} }
        @keyframes toastOut    { from{opacity:1;transform:translateX(0)} to{opacity:0;transform:translateX(14px)} }
        @keyframes fadeIn      { from{opacity:0} to{opacity:1} }
        @keyframes modalIn     { from{opacity:0;transform:scale(0.96)translateY(-8px)} to{opacity:1;transform:scale(1)translateY(0)} }
        @keyframes iconGlow    { 0%,100%{box-shadow:0 0 36px rgba(249,115,22,0.45),0 8px 28px rgba(0,0,0,0.5)} 50%{box-shadow:0 0 60px rgba(249,115,22,0.75),0 8px 28px rgba(0,0,0,0.5)} }
        @keyframes orbFloat    { from{transform:translate(0,0) scale(1)} to{transform:translate(28px,22px) scale(1.06)} }

        /* ── Navbar ── */
        .navbar { background: var(--navbar-bg); border-bottom: 1px solid var(--border); height: 52px; position: fixed; top: 0; left: 0; right: 0; z-index: 200; display: flex; align-items: center; justify-content: space-between; padding: 0 18px; }
        .logo { font-size: 18px; font-weight: 800; display: flex; align-items: center; gap: 8px; letter-spacing: -0.3px; font-family: 'Nunito', system-ui, sans-serif; }
        .logo span { background: linear-gradient(135deg, #f97316, #fb923c); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-weight: 900; }
        .nav-controls { display: flex; gap: 8px; align-items: center; }
        .nav-live-badge { display: none; align-items: center; gap: 6px; padding: 4px 11px; border-radius: 4px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.25); font-size: 11px; font-weight: 700; color: var(--success); }
        .nav-live-badge.on { display: flex; }
        .nav-live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--success); animation: livePing 1.4s ease-out infinite; }

        /* ── Landing ── */
        .landing-page { position: fixed; inset: 0; background: radial-gradient(ellipse at 25% 55%, #180432 0%, #080d1c 50%, #030810 100%); display: flex; flex-direction: column; justify-content: center; align-items: center; z-index: 9999; overflow: hidden; }
        .landing-bg-orb { position: absolute; border-radius: 50%; pointer-events: none; }
        .landing-bg-orb.o1 { width:560px; height:560px; top:-180px; left:-120px; background: radial-gradient(circle, rgba(249,115,22,0.11) 0%, transparent 70%); animation: orbFloat 9s ease-in-out infinite alternate; }
        .landing-bg-orb.o2 { width:440px; height:440px; bottom:-160px; right:-80px; background: radial-gradient(circle, rgba(56,189,248,0.07) 0%, transparent 70%); animation: orbFloat 12s ease-in-out infinite alternate-reverse; }
        .landing-bg-orb.o3 { width:280px; height:280px; top:40%; left:60%; background: radial-gradient(circle, rgba(168,85,247,0.05) 0%, transparent 70%); animation: orbFloat 7s ease-in-out infinite alternate; }
        .landing-inner { position: relative; z-index: 2; display: flex; flex-direction: column; align-items: center; text-align: center; padding: 0 20px; }
        .landing-icon-wrap { width:80px; height:80px; border-radius:22px; background: linear-gradient(135deg,#f97316,#ea580c); display:flex; align-items:center; justify-content:center; margin-bottom:18px; box-shadow:0 0 36px rgba(249,115,22,0.45),0 8px 28px rgba(0,0,0,0.5); animation: iconGlow 3s ease-in-out infinite, fadeInScale 0.6s ease-out; }
        .landing-brand { font-family:'Nunito',system-ui,sans-serif; font-size:52px; font-weight:900; letter-spacing:-2px; background:linear-gradient(135deg,#f97316,#fb923c,#fde68a); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; animation:fadeInUp 0.6s ease-out 0.12s both; line-height:1; margin-bottom:8px; }
        .landing-tagline { color:rgba(255,255,255,0.82); font-size:16px; font-weight:600; margin:0 0 6px; animation:fadeInUp 0.6s ease-out 0.22s both; }
        .landing-sub { color:rgba(255,255,255,0.38); font-size:12px; margin:0 0 24px; animation:fadeInUp 0.6s ease-out 0.32s both; }
        .landing-pills { display:flex; flex-wrap:wrap; gap:7px; justify-content:center; margin-bottom:34px; animation:fadeInUp 0.6s ease-out 0.42s both; }
        .landing-pills span { padding:4px 12px; border-radius:4px; font-size:11px; font-weight:600; background:rgba(255,255,255,0.05); color:rgba(255,255,255,0.55); border:1px solid rgba(255,255,255,0.09); }
        .landing-btn { background:linear-gradient(135deg,#f97316,#ea580c); color:white; border:none; border-radius:6px; padding:12px 38px; font-size:14px; font-weight:700; cursor:pointer; box-shadow:0 0 28px rgba(249,115,22,0.4),0 4px 16px rgba(0,0,0,0.35); animation:fadeInUp 0.6s ease-out 0.5s both; transition:box-shadow 0.15s, transform 0.15s; }
        .landing-btn:hover { box-shadow:0 0 48px rgba(249,115,22,0.65),0 8px 22px rgba(0,0,0,0.45); transform:translateY(-2px); }
        .landing-page.hidden { display: none; }

        /* ── Layout ── */
        .container { flex:1; display:flex; flex-direction:column; width:100%; padding:0; overflow:hidden; }
        .vscode-layout { display:flex; height:calc(100vh - 52px); overflow:hidden; margin-top:52px; }
        .ai-disabled { display:none !important; }

        /* ── Activity bar ── */
        .activity-bar { width:48px; background:var(--sidebar-bg); display:flex; flex-direction:column; align-items:center; padding:8px 0; gap:2px; border-right:1px solid var(--border); flex-shrink:0; }
        .activity-icon { width:40px; height:40px; display:flex; flex-direction:column; align-items:center; justify-content:center; cursor:pointer; color:var(--text-muted); font-size:9px; transition:color 0.12s, background 0.12s; border-left:2px solid transparent; position:relative; border-radius:4px; margin:0 3px; font-weight:600; }
        .activity-icon:hover { color:var(--text-main); background:var(--sidebar-hover); }
        .activity-icon.active { color:var(--primary); border-left-color:var(--primary); background:rgba(249,115,22,0.08); }
        .activity-icon svg, .activity-icon span { pointer-events:none; }
        .icon-label { position:absolute; left:46px; background:var(--surface2); color:var(--text-main); border:1px solid var(--border); padding:5px 10px; border-radius:4px; font-size:11px; white-space:nowrap; display:none; z-index:1000; box-shadow:var(--shadow-lg); font-weight:600; animation:slideIn 0.12s ease-out; }
        .icon-label::before { content:''; position:absolute; left:-4px; top:50%; transform:translateY(-50%); width:0; height:0; border-top:4px solid transparent; border-bottom:4px solid transparent; border-right:4px solid var(--border); }
        .activity-icon:hover .icon-label { display:block; }
        .activity-icon.hidden-session-tab { display:none; }
        .activity-bar-bottom { margin-top:auto; padding-top:8px; border-top:1px solid var(--border); width:100%; display:flex; flex-direction:column; align-items:center; gap:4px; padding-bottom:8px; }
        .theme-toggle { width:40px; height:34px; background:transparent; border:1px solid var(--border); color:var(--text-muted); font-size:10px; cursor:pointer; border-radius:4px; font-weight:700; transition:all 0.12s; }
        .theme-toggle:hover { border-color:var(--border-hi); color:var(--text-main); }
        .stop-daemon-btn { width:40px; height:34px; background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.22); color:var(--danger); font-size:9px; cursor:pointer; border-radius:4px; font-weight:700; transition:all 0.12s; }
        .stop-daemon-btn:hover { background:rgba(239,68,68,0.22); }
        .main-content { flex:1; display:flex; flex-direction:column; overflow:hidden; background:var(--bg); }

        /* ── Inputs & forms ── */
        .form-input, select.form-input { padding:6px 10px; border:1px solid var(--border); background:var(--surface); color:var(--text-main); font-size:12px; outline:none; border-radius:5px; transition:border-color 0.12s; }
        .form-input::placeholder { color:var(--text-muted); }
        .form-input:focus, select.form-input:focus { border-color:var(--primary); }
        select.form-input { cursor:pointer; }
        select, input[type="text"], input[type="search"], input:not([type]), textarea { background:var(--surface); color:var(--text-main); border-color:var(--border); }

        /* ── Buttons ── */
        .primary-btn { background:var(--primary); color:white; border:none; border-radius:5px; padding:7px 15px; font-size:12px; font-weight:600; cursor:pointer; transition:opacity 0.12s; }
        .primary-btn:hover { opacity:0.85; }
        .primary-btn:active { opacity:0.7; }
        .primary-btn.stop { background:var(--danger); }
        .btn { background:var(--surface2); color:var(--text-main); border:1px solid var(--border); border-radius:5px; padding:7px 13px; font-size:12px; font-weight:600; cursor:pointer; transition:border-color 0.12s, color 0.12s; }
        .btn:hover { border-color:var(--primary); color:var(--primary); }
        .btn.stop { background:rgba(239,68,68,0.12); color:var(--danger); border-color:rgba(239,68,68,0.25); }

        /* ── Tab nav ── */
        .tab-nav { background:var(--surface); border-bottom:1px solid var(--border); padding:0 14px; display:flex; gap:2px; }
        .tab-btn { padding:11px 17px; border:none; background:none; color:var(--text-muted); font-size:12px; font-weight:600; cursor:pointer; border-bottom:2px solid transparent; transition:color 0.12s, border-color 0.12s; }
        .tab-btn:hover { color:var(--text-main); }
        .tab-btn.active { color:var(--primary); border-bottom-color:var(--primary); }

        /* ── Toolbar ── */
        .panel-toolbar { background:var(--surface); padding:7px 14px; border-bottom:1px solid var(--border); display:flex; gap:8px; align-items:center; flex-wrap:wrap; flex-shrink:0; }
        .toolbar-group { display:flex; gap:7px; align-items:center; padding:4px 9px; background:var(--surface2); border-radius:5px; border:1px solid var(--border); }
        .toolbar-group:hover { border-color:var(--border-hi); }
        .toolbar-separator { width:1px; height:18px; background:var(--border); margin:0 4px; }
        .toolbar-label { font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.6px; margin-right:3px; }

        /* ── Panels ── */
        .panel { display:none; height:100%; flex-direction:column; overflow:hidden; }
        .panel.active { display:flex; }

        /* ── Wireshark layout ── */
        .wireshark-view { display:flex; flex-direction:row; flex:1; width:100%; gap:10px; padding:10px; background:var(--bg); overflow:hidden; }
        .pane-left { flex:6; background:var(--surface); border:1px solid var(--border); border-radius:5px; position:relative; overflow:hidden; display:flex; flex-direction:column; }
        #tableContainer { flex:1; overflow:auto; }
        .pane-right { flex:4; display:flex; flex-direction:column; gap:10px; min-width:320px; min-height:0; }
        .section-label { font-weight:700; color:var(--primary); font-size:10px; text-transform:uppercase; letter-spacing:0.8px; margin-bottom:-5px; }
        .pane-detail { flex:3; min-height:0; background:var(--surface); border:1px solid var(--border); border-radius:5px; overflow-y:auto; padding:12px; font-family:'Consolas','Courier New',monospace; font-size:12px; }
        .pane-hex { flex:2; min-height:0; background:#030b14; color:#8fa8c0; border:1px solid var(--border); border-radius:5px; overflow-y:auto; padding:12px; font-family:'Consolas','Courier New',monospace; font-size:12px; }
        .resizer { flex:0 0 4px; background:var(--border); cursor:col-resize; transition:background 0.12s; }
        .resizer:hover, .resizer.dragging { background:var(--primary); }
        .wireshark-view.vertical { flex-direction:column; }
        .wireshark-view.vertical .resizer { flex:0 0 4px; width:100%; cursor:row-resize; }
        .wireshark-view.vertical .pane-left, .wireshark-view.vertical .pane-right { min-width:100%; min-height:80px; }

        /* ── Packet table ── */
        .ws-table { min-width:100%; border-collapse:collapse; font-family:'Consolas','Courier New',monospace; font-size:12px; table-layout:auto; }
        .ws-table th { background:var(--surface2); color:var(--text-muted); border-bottom:1px solid var(--primary); border-right:1px solid var(--border); padding:6px 10px; text-align:left; position:sticky; top:0; z-index:10; text-transform:uppercase; font-size:10px; letter-spacing:0.6px; font-weight:700; }
        .ws-table td { border-bottom:1px solid var(--border); border-right:1px solid var(--border); padding:5px 10px; cursor:pointer; white-space:nowrap; }
        .ws-table tr:hover td { background:rgba(249,115,22,0.06) !important; }
        .ws-table tr.selected td { background:rgba(249,115,22,0.18) !important; color:var(--text-main) !important; font-weight:600; }
        .ws-table tr.selected:hover td { background:rgba(249,115,22,0.24) !important; }

        /* Protocol row tints — very subtle, same dark palette */
        .ws-bg-tcp  { background-color: #0a1830; }
        .ws-bg-udp  { background-color: #081a14; }
        .ws-bg-http { background-color: #091c10; }
        .ws-bg-dns  { background-color: #061528; }
        .ws-bg-icmp { background-color: #160c28; }
        .ws-bg-arp  { background-color: #1a1408; }
        .ws-bg-bad  { background-color: #1e0808; color:#fca5a5; font-weight:500; }
        .ws-bg-def  { background-color: var(--surface); }
        .info-cell { white-space:nowrap; }

        /* ── Packet detail ── */
        .detail-header { background:rgba(249,115,22,0.09); color:var(--primary); font-weight:700; padding:5px 10px; margin:10px 0 4px; border-radius:3px; border-left:3px solid var(--primary); font-size:11px; letter-spacing:0.05em; }
        .detail-header:first-child { margin-top:0; }
        .detail-row { display:flex; padding:4px 10px; font-size:12px; border-bottom:1px solid rgba(24,40,64,0.6); }
        .detail-row:hover { background:rgba(249,115,22,0.04); }
        .detail-key { color:var(--text-muted); width:140px; flex-shrink:0; font-weight:600; }
        .detail-val { color:var(--text-main); word-break:break-all; }

        /* ── Session strip ── */
        .scroll-toast { position:absolute; bottom:14px; left:50%; transform:translateX(-50%); background:var(--surface2); color:var(--text-main); padding:6px 18px; border-radius:18px; font-size:12px; font-weight:600; cursor:pointer; box-shadow:var(--shadow-lg); border:1px solid var(--border-hi); z-index:100; transition:opacity 0.12s; }
        .scroll-toast:hover { opacity:0.75; }
        .session-strip { display:flex; flex-wrap:wrap; gap:5px; padding:5px 13px; background:var(--surface); border-bottom:1px solid var(--border); align-items:center; min-height:36px; }
        .session-chip { display:inline-flex; align-items:center; gap:5px; background:var(--surface2); border:1px solid var(--border); border-radius:14px; padding:2px 8px 2px 10px; font-size:12px; font-weight:600; color:var(--text-muted); cursor:pointer; transition:all 0.12s; }
        .session-chip:hover { border-color:var(--border-hi); color:var(--text-main); }
        .session-chip.active { background:rgba(249,115,22,0.12); color:var(--primary); border-color:rgba(249,115,22,0.35); }
        .session-chip .chip-x { background:none; border:none; color:inherit; width:15px; height:15px; border-radius:50%; cursor:pointer; font-size:12px; line-height:1; padding:0; display:inline-flex; align-items:center; justify-content:center; opacity:0.55; }
        .session-chip .chip-x:hover { opacity:1; color:var(--danger); }
        .chip-live-dot { width:6px; height:6px; border-radius:50%; background:var(--success); flex-shrink:0; }
        .window-tabs { display:flex; gap:2px; padding:0 12px; background:var(--bg); border-bottom:1px solid var(--border); }
        .win-tab { background:transparent; border:none; border-bottom:2px solid transparent; padding:8px 14px; cursor:pointer; font-size:12px; font-weight:600; color:var(--text-muted); transition:all 0.12s; }
        .win-tab:hover { color:var(--text-main); }
        .win-tab.active { color:var(--primary); border-bottom-color:var(--primary); }

        /* ── Status bar ── */
        .statusbar { background:var(--surface); border-top:1px solid var(--border); padding:5px 16px; font-size:11px; font-weight:600; color:var(--text-muted); display:flex; justify-content:space-between; flex-shrink:0; }

        /* ── Cards & kv-lists ── */
        .grid-3 { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:12px; padding:14px; }
        .card { background:var(--surface); border:1px solid var(--border); padding:16px 18px; border-radius:8px; box-shadow:var(--shadow-sm); min-width:0; }
        .card:hover { border-color:var(--border-hi); box-shadow:var(--shadow); }
        .card-title { font-weight:700; border-bottom:1px solid var(--border); padding-bottom:10px; margin-bottom:12px; font-size:10px; color:var(--text-muted); letter-spacing:0.07em; text-transform:uppercase; }
        .card-title-lg { font-size:13px; font-weight:700; color:var(--text-main); letter-spacing:0; text-transform:none; border:none; padding:0; margin:0 0 4px; }
        .card-subtitle { font-size:12px; color:var(--text-muted); margin-bottom:14px; line-height:1.5; }

        /* ── Server Info layout (fixes grid overlap) ── */
        .panel-scroll { flex:1; min-height:0; overflow-y:auto; overflow-x:hidden; padding:20px 22px 24px; display:flex; flex-direction:column; gap:16px; }
        .page-header { display:flex; align-items:flex-end; justify-content:space-between; gap:16px; flex-wrap:wrap; padding-bottom:4px; }
        .page-header h2 { font-size:18px; font-weight:800; letter-spacing:-0.02em; color:var(--text-main); margin:0; }
        .page-header p { font-size:12px; color:var(--text-muted); margin:4px 0 0; max-width:520px; line-height:1.55; }
        .serverinfo-top { display:grid; grid-template-columns:minmax(0,1fr) minmax(280px,340px); gap:16px; align-items:stretch; }
        .serverinfo-stack { display:flex; flex-direction:column; gap:16px; min-width:0; }
        @media (max-width:1024px) { .serverinfo-top { grid-template-columns:1fr; } }

        .kv-list { display:flex; flex-direction:column; gap:0; font-size:12px; }
        .kv-item { display:flex; justify-content:space-between; align-items:center; gap:8px; border-bottom:1px solid rgba(24,40,64,0.6); padding:6px 0; min-width:0; }
        .kv-item:last-child { border-bottom:none; }
        .kv-item:hover { border-bottom-color:var(--border-hi); }
        .kv-item span { font-weight:600; color:var(--text-muted); font-size:11px; flex-shrink:0; white-space:nowrap; }
        .kv-item strong { font-family:'Consolas','Courier New',monospace; color:var(--text-main); text-align:right; word-break:break-word; font-size:11px; flex:1; min-width:0; overflow:hidden; }

        /* ── kv-lists (hardware overrides below) ── */
        #hardware .hw-scroll { flex:1; min-height:0; overflow-y:auto; padding:12px; display:flex; flex-direction:column; gap:10px; }
        #hardware .hw-top-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; align-items:start; }
        #hardware .hw-ethtool-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:0 24px; margin-top:4px; }
        #hardware .card { padding:10px 13px; }
        #hardware .card-title { font-size:10px; padding-bottom:6px; margin-bottom:8px; }
        #hardware .kv-list { gap:0; font-size:12px; }
        #hardware .kv-item { padding:3px 0; }
        #hardware .kv-item strong { font-size:11px; min-width:110px; }
        #hardware .kv-item span { font-size:11px; }
        #hardware .hw-section { margin:8px 0 3px; font-size:9px; letter-spacing:.1em; text-transform:uppercase; color:var(--text-muted); font-weight:700; border-top:1px solid var(--border); padding-top:5px; }
        #hardware .hw-section:first-child { border-top:none; margin-top:0; padding-top:0; }
        #hardware .hw-feat { font-size:11px; line-height:1.7; color:var(--text-muted); word-break:break-word; padding:1px 0; font-family:'Consolas','Courier New',monospace; }
        @media (max-width:900px) { #hardware .hw-top-grid { grid-template-columns:1fr 1fr; } #hardware .hw-ethtool-grid { grid-template-columns:1fr 1fr; } }
        @media (max-width:600px) { #hardware .hw-top-grid { grid-template-columns:1fr; } #hardware .hw-ethtool-grid { grid-template-columns:1fr; } }

        /* ── Settings table ── */
        .settings-table { width:100%; border-collapse:collapse; font-size:12px; }
        .settings-table th, .settings-table td { padding:7px 11px; text-align:left; border-bottom:1px solid var(--border); }
        .settings-table th { background:var(--surface2); font-weight:700; color:var(--text-muted); font-size:10px; text-transform:uppercase; letter-spacing:0.5px; border-bottom:1px solid var(--primary); }
        .settings-table tbody tr:hover td { background:rgba(249,115,22,0.04); }
        .settings-table tbody tr.selected td { background:rgba(249,115,22,0.1); }
        .settings-table tbody tr.selected:hover td { background:rgba(249,115,22,0.16); }

        /* ── Badges ── */
        .badge { padding:2px 7px; border-radius:3px; font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.4px; }
        .badge-success { background:rgba(16,185,129,0.14); color:var(--success); border:1px solid rgba(16,185,129,0.28); }
        .badge-danger  { background:rgba(239,68,68,0.14); color:var(--danger); border:1px solid rgba(239,68,68,0.28); }
        .badge-warning { background:rgba(245,158,11,0.14); color:var(--warning); border:1px solid rgba(245,158,11,0.28); }
        .badge-info    { background:rgba(56,189,248,0.14); color:var(--info); border:1px solid rgba(56,189,248,0.28); }
        .badge-critical { background:rgba(220,38,38,0.18); color:#fca5a5; border:1px solid rgba(220,38,38,0.35); }

        /* ── Feature toggles (DLP / IDPS) ── */
        .security-section { padding:18px 20px; }
        .feature-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:14px; }
        .feature-panel { position:relative; overflow:hidden; background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:14px 16px; min-width:0; }
        .feature-panel::before { content:''; position:absolute; top:0; left:0; right:0; height:3px; background:linear-gradient(90deg,var(--primary),var(--info)); opacity:0.35; }
        .feature-panel.enabled { border-color:rgba(249,115,22,0.35); background:rgba(249,115,22,0.04); }
        .feature-panel.enabled::before { opacity:1; }
        .feature-card { position:relative; overflow:hidden; }
        .feature-card::before { content:''; position:absolute; top:0; left:0; right:0; height:3px; background:linear-gradient(90deg,var(--primary),var(--info)); opacity:0.6; }
        .feature-card.enabled::before { opacity:1; }
        .feature-header { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:10px; }
        .feature-icon { width:36px; height:36px; border-radius:8px; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
        .feature-icon.dlp { background:rgba(56,189,248,0.12); color:var(--info); }
        .feature-icon.idps { background:rgba(239,68,68,0.12); color:var(--danger); }
        .feature-title { font-size:13px; font-weight:700; color:var(--text-main); letter-spacing:0; text-transform:none; margin:0; }
        .feature-desc { font-size:11px; color:var(--text-muted); line-height:1.5; margin-top:4px; }
        .feature-rules { margin-top:10px; display:flex; flex-wrap:wrap; gap:4px; }
        .rule-chip { font-size:10px; padding:2px 7px; border-radius:10px; background:var(--surface2); border:1px solid var(--border); color:var(--text-muted); font-family:'Consolas','Courier New',monospace; }
        .toggle-switch { position:relative; width:44px; height:24px; flex-shrink:0; }
        .toggle-switch input { opacity:0; width:0; height:0; }
        .toggle-slider { position:absolute; cursor:pointer; inset:0; background:var(--surface2); border:1px solid var(--border); border-radius:24px; transition:0.2s; }
        .toggle-slider::before { content:''; position:absolute; height:18px; width:18px; left:2px; bottom:2px; background:var(--text-muted); border-radius:50%; transition:0.2s; }
        .toggle-switch input:checked + .toggle-slider { background:rgba(249,115,22,0.25); border-color:var(--primary); }
        .toggle-switch input:checked + .toggle-slider::before { transform:translateX(20px); background:var(--primary); }

        /* ── Sessions card ── */
        .sessions-card { margin:0; }
        .sessions-header { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:12px; }
        .sessions-header .card-title { border:none; padding:0; margin:0; flex:1; }
        .sessions-actions { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
        .session-count-badge { font-size:11px; font-weight:700; padding:3px 10px; border-radius:12px; background:var(--surface2); border:1px solid var(--border); color:var(--text-muted); }
        .session-count-badge.live { background:rgba(16,185,129,0.12); color:var(--success); border-color:rgba(16,185,129,0.3); }
        .sessions-empty { text-align:center; padding:48px 24px; color:var(--text-muted); }
        .sessions-empty-icon { font-size:40px; margin-bottom:12px; opacity:0.5; }
        .sessions-empty-title { font-size:15px; font-weight:700; color:var(--text-main); margin-bottom:6px; }
        .sessions-empty-hint { font-size:12px; line-height:1.6; max-width:360px; margin:0 auto 16px; }
        .sessions-table-wrap { overflow-x:auto; max-height:360px; overflow-y:auto; border-radius:6px; border:1px solid var(--border); background:var(--surface2); }
        .table-actions { display:flex; gap:6px; flex-wrap:wrap; align-items:center; }
        .session-id { font-family:'Consolas','Courier New',monospace; font-size:11px; color:var(--text-muted); }
        .session-pkts { font-family:'Consolas','Courier New',monospace; font-size:11px; }

        /* ── Security panel ── */
        #security.panel.active { overflow:hidden; }
        #security .panel-scroll { gap:14px; }
        #security .page-header { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; flex-wrap:wrap; margin-bottom:2px; }
        #security .page-header h2 { margin:0 0 4px; font-size:20px; letter-spacing:-0.02em; }
        #security .page-header p { margin:0; max-width:520px; }
        .sec-status-row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
        .sec-status-pill { display:inline-flex; align-items:center; gap:6px; font-size:11px; font-weight:700; padding:5px 10px; border-radius:999px; border:1px solid var(--border); background:var(--surface2); color:var(--text-muted); }
        .sec-status-pill.on { background:rgba(16,185,129,0.1); border-color:rgba(16,185,129,0.35); color:#6ee7b7; }
        .sec-status-pill .dot { width:6px; height:6px; border-radius:50%; background:currentColor; }
        #security .sec-stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(128px,1fr)); gap:10px; padding:0; }
        .sec-stat { background:linear-gradient(180deg, var(--surface) 0%, var(--surface2) 100%); border:1px solid var(--border); border-radius:10px; padding:14px 12px; text-align:center; position:relative; overflow:hidden; }
        .sec-stat::before { content:''; position:absolute; inset:0 0 auto 0; height:2px; background:var(--border); opacity:0.9; }
        .sec-stat.dlp::before { background:linear-gradient(90deg, transparent, var(--info), transparent); }
        .sec-stat.idps::before { background:linear-gradient(90deg, transparent, var(--warning), transparent); }
        .sec-stat.critical::before { background:linear-gradient(90deg, transparent, #f87171, transparent); }
        .sec-stat.high::before { background:linear-gradient(90deg, transparent, var(--danger), transparent); }
        .sec-stat-val { font-size:24px; font-weight:800; font-family:'JetBrains Mono','Consolas','Courier New',monospace; line-height:1.15; color:var(--text-main); }
        .sec-stat-lbl { font-size:10px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.07em; margin-top:6px; font-weight:700; }
        .sec-stat.critical .sec-stat-val { color:#fca5a5; }
        .sec-stat.high .sec-stat-val { color:var(--danger); }
        .sec-stat.dlp .sec-stat-val { color:var(--info); }
        .sec-stat.idps .sec-stat-val { color:var(--warning); }
        #securityAlertsBody tr.sev-critical td { border-left:3px solid #dc2626; }
        #securityAlertsBody tr.sev-high td { border-left:3px solid var(--danger); }
        #securityAlertsBody tr.sev-medium td { border-left:3px solid var(--warning); }
        #securityAlertsBody tr.sev-low td { border-left:3px solid var(--info); }
        .sec-engine { font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; padding:2px 6px; border-radius:3px; }
        .sec-engine.dlp { background:rgba(56,189,248,0.14); color:var(--info); }
        .sec-engine.idps { background:rgba(239,68,68,0.14); color:var(--danger); }
        .security-alert-badge { display:inline-block; font-size:9px; font-weight:800; padding:1px 6px; border-radius:8px; background:rgba(220,38,38,0.2); color:#fca5a5; border:1px solid rgba(220,38,38,0.35); margin-right:4px; letter-spacing:0.04em; vertical-align:middle; }
        .verdict-badge { font-size:9px; font-weight:800; padding:2px 8px; border-radius:10px; text-transform:uppercase; letter-spacing:0.04em; }
        .verdict-monitor { background:rgba(56,189,248,0.14); color:var(--info); border:1px solid rgba(56,189,248,0.28); }
        .verdict-pass { background:rgba(16,185,129,0.14); color:var(--success); border:1px solid rgba(16,185,129,0.28); }
        .verdict-drop { background:rgba(239,68,68,0.18); color:#fca5a5; border:1px solid rgba(239,68,68,0.35); }
        .verdict-redirect { background:rgba(168,85,247,0.14); color:#c4b5fd; border:1px solid rgba(168,85,247,0.28); }
        .verdict-quarantine { background:rgba(245,158,11,0.14); color:var(--warning); border:1px solid rgba(245,158,11,0.28); }
        .sec-sub-nav { display:flex; gap:2px; flex-wrap:wrap; padding:4px; border:1px solid var(--border); border-radius:10px; background:var(--surface2); margin-bottom:6px; }
        .sec-sub-btn { background:transparent; border:none; border-radius:7px; padding:8px 12px; cursor:pointer; font-size:12px; font-weight:600; color:var(--text-muted); transition:all 0.12s; }
        .sec-sub-btn:hover { color:var(--text-main); background:rgba(255,255,255,0.03); }
        .sec-sub-btn.active { color:var(--text-main); background:var(--surface); box-shadow:0 1px 0 rgba(0,0,0,0.25); border:1px solid var(--border); }
        .sec-toolbar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:4px; padding:8px 10px; border:1px solid var(--border); border-radius:10px; background:var(--surface); }
        .sec-toolbar .hint { font-size:11px; color:var(--text-muted); margin-left:auto; }
        .sec-sub-panel { display:none; }
        .sec-sub-panel.active { display:block; }
        .sec-sub-panel .card { border-radius:10px; }
        .policy-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px; margin-bottom:14px; }
        .policy-row { display:flex; align-items:center; gap:10px; margin-top:10px; flex-wrap:wrap; }
        .policy-row label { font-size:11px; font-weight:600; color:var(--text-muted); min-width:90px; }
        .flow-row-click { cursor:pointer; }
        .flow-row-click:hover td { background:rgba(249,115,22,0.08) !important; }
        .pkt-dropped td { opacity:0.55; text-decoration:line-through; text-decoration-color:rgba(239,68,68,0.5); }
        .ws-bg-sec-drop { background-color:#1a0808 !important; }
        .security-section .feature-panel { border-radius:10px; }
        .security-section .card-title { letter-spacing:-0.01em; }

        /* ── Toast notifications ── */
        #toastContainer { position:fixed; bottom:18px; right:18px; z-index:99999; display:flex; flex-direction:column; gap:6px; pointer-events:none; }
        .toast { pointer-events:all; display:flex; align-items:center; justify-content:space-between; gap:10px; padding:9px 13px; border-radius:6px; font-size:12px; font-weight:600; box-shadow:var(--shadow-lg); animation:toastIn 0.22s ease-out; max-width:340px; }
        .toast-info    { background:#0a1626; color:var(--text-main); border-left:3px solid var(--info); }
        .toast-success { background:#051610; color:#86efac; border-left:3px solid var(--success); }
        .toast-error   { background:#160505; color:#fca5a5; border-left:3px solid var(--danger); }
        .toast-warn    { background:#160e04; color:#fde68a; border-left:3px solid var(--warning); }
        .toast-close   { background:none; border:none; color:inherit; opacity:0.5; cursor:pointer; font-size:14px; padding:0; line-height:1; flex-shrink:0; }
        .toast-close:hover { opacity:1; }

        /* ── Modal ── */
        .modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.65); z-index:99998; display:flex; align-items:center; justify-content:center; animation:fadeIn 0.12s ease; }
        .modal-box { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:22px 26px; min-width:300px; max-width:440px; box-shadow:var(--shadow-xl); animation:modalIn 0.16s ease-out; }
        .modal-title { font-size:14px; font-weight:700; color:var(--text-main); margin-bottom:7px; }
        .modal-body  { font-size:12px; color:var(--text-muted); margin-bottom:16px; line-height:1.6; }
        .modal-input-wrap { margin-bottom:16px; }
        .modal-input { width:100%; padding:7px 11px; border:1px solid var(--border); border-radius:5px; font-size:12px; background:var(--surface2); color:var(--text-main); outline:none; }
        .modal-input:focus { border-color:var(--primary); }
        .modal-footer { display:flex; gap:8px; justify-content:flex-end; }
        .modal-confirm { background:var(--primary); color:white; border:none; border-radius:5px; padding:7px 18px; font-size:12px; font-weight:700; cursor:pointer; transition:opacity 0.12s; }
        .modal-confirm:hover { opacity:0.85; }
        .modal-cancel { background:transparent; color:var(--text-muted); border:1px solid var(--border); border-radius:5px; padding:7px 14px; font-size:12px; font-weight:700; cursor:pointer; transition:all 0.12s; }
        .modal-cancel:hover { border-color:var(--border-hi); color:var(--text-main); }
        .modal-confirm.danger { background:var(--danger); }

        /* ── Icon buttons / kbd ── */
        .icon-btn { background:transparent; border:1px solid var(--border); border-radius:5px; color:var(--text-muted); cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:4px; padding:5px 8px; font-size:12px; font-weight:600; transition:all 0.12s; }
        .icon-btn:hover { border-color:var(--primary); color:var(--primary); }
        .icon-btn svg { flex-shrink:0; }
        .kbd { display:inline-block; padding:1px 4px; border:1px solid var(--border); border-bottom-width:2px; border-radius:3px; font-size:10px; font-family:monospace; color:var(--text-muted); background:var(--surface2); }

        /* ── Empty state ── */
        .empty-state { display:flex; flex-direction:column; align-items:center; justify-content:center; padding:44px 20px; color:var(--text-muted); gap:10px; }
        .empty-state-icon { width:44px; height:44px; border-radius:10px; background:rgba(249,115,22,0.07); display:flex; align-items:center; justify-content:center; }
        .empty-state-title { font-size:13px; font-weight:700; color:var(--text-main); }
        .empty-state-sub { font-size:12px; text-align:center; max-width:240px; }

        /* ── Route / NIC helpers ── */
        .default-route-badge { display:inline-block; padding:1px 5px; border-radius:2px; font-size:9px; font-weight:800; background:var(--primary); color:white; letter-spacing:0.4px; margin-right:4px; vertical-align:middle; }
        .direct-route { color:var(--text-muted); font-style:italic; }
        .nic-up   { display:inline-flex; align-items:center; gap:4px; color:var(--success); font-weight:700; font-size:11px; }
        .nic-down { display:inline-flex; align-items:center; gap:4px; color:var(--danger); font-weight:700; font-size:11px; }
        .nic-dot  { width:6px; height:6px; border-radius:50%; background:currentColor; }

        /* ── Drop zone ── */
        .drop-zone { border:1px dashed var(--border); border-radius:7px; padding:26px 20px; text-align:center; cursor:pointer; transition:all 0.12s; color:var(--text-muted); background:var(--surface); }
        .drop-zone:hover, .drop-zone.drag-over { border-color:var(--primary); color:var(--primary); }
        .drop-zone-icon { font-size:22px; margin-bottom:5px; }
        .drop-zone p { font-size:12px; font-weight:600; margin:0; }
        .drop-zone small { font-size:11px; opacity:0.55; }

        /* ── Protocol badges ── */
        .proto-badge { display:inline-block; padding:1px 5px; border-radius:3px; font-size:10px; font-weight:700; letter-spacing:0.4px; text-transform:uppercase; white-space:nowrap; }
        .proto-tcp    { background:#0a1830; color:#60a5fa; border:1px solid #182840; }
        .proto-udp    { background:#081a14; color:#34d399; border:1px solid #0f3020; }
        .proto-http, .proto-https { background:#091c10; color:#4ade80; border:1px solid #122a18; }
        .proto-http2  { background:#0a1e12; color:#86efac; border:1px solid #133020; }
        .proto-dns    { background:#061528; color:#7dd3fc; border:1px solid #0d2438; }
        .proto-tls, .proto-ssl { background:#151000; color:#fde047; border:1px solid #2c2000; }
        .proto-icmp   { background:#160c28; color:#d8b4fe; border:1px solid #280f48; }
        .proto-arp    { background:#1a1408; color:#fcd34d; border:1px solid #2a2010; }
        .proto-quic   { background:#180a12; color:#fda4af; border:1px solid #2c0f1c; }
        .proto-grpc   { background:#100820; color:#c4b5fd; border:1px solid #1e1038; }
        .proto-ssh    { background:var(--surface); color:#94a3b8; border:1px solid var(--border); }
        .proto-ftp    { background:#160e00; color:#fdba74; border:1px solid #281a00; }
        .proto-bgp    { background:#160808; color:#fca5a5; border:1px solid #280e0e; }
        .proto-ntp    { background:#081a14; color:#6ee7b7; border:1px solid #0f2e22; }
        .proto-sip    { background:#160620; color:#e879f9; border:1px solid #281038; }
        .proto-ip     { background:var(--surface); color:#64748b; border:1px solid var(--border); }

        /* ── Risk pills ── */
        .risk-badge   { display:inline-block; padding:1px 7px; border-radius:10px; font-size:10px; font-weight:700; letter-spacing:0.4px; margin-right:4px; }
        .risk-high    { background:rgba(239,68,68,0.18); color:var(--danger); border:1px solid rgba(239,68,68,0.28); }
        .risk-medium  { background:rgba(245,158,11,0.18); color:var(--warning); border:1px solid rgba(245,158,11,0.28); }
        .risk-low     { background:rgba(68,88,112,0.18); color:var(--text-muted); border:1px solid rgba(68,88,112,0.3); }

        /* ── Flow table ── */
        .flow-rank-badge { display:inline-flex; align-items:center; justify-content:center; width:15px; height:15px; border-radius:50%; font-size:9px; font-weight:900; flex-shrink:0; }
        .flow-cat-badge  { display:inline-block; padding:1px 6px; border-radius:3px; font-size:10px; font-weight:700; white-space:nowrap; }
        .flow-bytes-cell { display:flex; align-items:center; gap:5px; min-width:80px; }
        .flow-bytes-bar  { flex:1; height:3px; background:var(--border); border-radius:2px; overflow:hidden; min-width:22px; }
        .flow-bytes-fill { height:100%; border-radius:2px; }

        /* ── Progress bars ── */
        .proto-bar-wrap  { margin-bottom:7px; }
        .proto-bar-label { display:flex; justify-content:space-between; align-items:center; margin-bottom:2px; }
        .proto-bar-label strong { font-size:11px; }
        .proto-bar-label span   { font-size:11px; color:var(--text-muted); font-weight:600; }
        .proto-bar-track { width:100%; background:var(--border); border-radius:4px; height:5px; overflow:hidden; }
        .proto-bar-fill  { height:100%; border-radius:4px; transition:width 0.3s ease; background:var(--primary); }
        .proto-bar-label strong { display:flex; align-items:center; gap:6px; }
        .proto-bar-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }

        /* ── Terminal lights ── */
        .term-traffic-lights { display:flex; gap:6px; align-items:center; margin-right:9px; }
        .traffic-dot { width:11px; height:11px; border-radius:50%; cursor:pointer; transition:filter 0.12s; flex-shrink:0; }
        .traffic-dot.red    { background:#ff5f57; }
        .traffic-dot.yellow { background:#febc2e; }
        .traffic-dot.green  { background:#28c840; }
        .traffic-dot:hover  { filter:brightness(1.2); }

        /* ── Capture state ── */
        .capture-state { display:inline-flex; align-items:center; gap:5px; padding:3px 9px; border-radius:11px; font-size:11px; font-weight:700; border:1px solid; transition:all 0.12s; }
        .capture-state.idle   { background:rgba(68,88,112,0.1); color:var(--text-muted); border-color:var(--border); }
        .capture-state.live   { background:rgba(16,185,129,0.1); color:var(--success); border-color:rgba(16,185,129,0.28); animation:livePing 1.4s infinite; }
        .capture-state.paused { background:rgba(245,158,11,0.1); color:var(--warning); border-color:rgba(245,158,11,0.28); }
        .capture-dot { width:6px; height:6px; border-radius:50%; background:currentColor; }

        /* ── NIC iface card ── */
        .iface-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(168px,1fr)); gap:10px; max-height:280px; overflow-y:auto; padding:2px; }
        .iface-card { border:1px solid var(--border); border-radius:8px; padding:10px 12px; background:var(--surface2); cursor:pointer; transition:border-color 0.12s, box-shadow 0.12s, transform 0.12s; position:relative; overflow:hidden; min-width:0; }
        .iface-card::before { content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--danger); }
        .iface-card.up::before { background:var(--success); }
        .iface-card:hover { border-color:var(--primary); box-shadow:var(--shadow); transform:translateY(-1px); }
        .iface-name   { font-weight:700; color:var(--primary); font-size:13px; font-family:monospace; }
        .iface-desc   { font-size:11px; color:var(--text-muted); margin-top:2px; }
        .iface-status { font-size:10px; font-weight:700; margin-top:3px; display:flex; align-items:center; gap:4px; letter-spacing:0.4px; text-transform:uppercase; }

        /* ── Status bar pills ── */
        .sb-pill { display:inline-block; padding:1px 6px; border-radius:9px; font-size:10px; font-weight:700; margin-right:4px; }
        .sb-live { background:rgba(16,185,129,0.1); color:var(--success); border:1px solid rgba(16,185,129,0.22); }
        .sb-idle { background:rgba(68,88,112,0.1); color:var(--text-muted); border:1px solid var(--border); }

        /* ── Connection state badges ── */
        .state-badge        { display:inline-block; padding:1px 6px; border-radius:3px; font-size:10px; font-weight:700; letter-spacing:0.4px; }
        .state-established  { background:rgba(16,185,129,0.14); color:var(--success); }
        .state-listen       { background:rgba(56,189,248,0.14); color:var(--info); }
        .state-time-wait    { background:rgba(245,158,11,0.14); color:var(--warning); }
        .state-close-wait   { background:rgba(168,85,247,0.14); color:#a855f7; }
        .state-other        { background:rgba(68,88,112,0.12); color:var(--text-muted); }
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
            const isLight = body.classList.toggle('light-theme');
            const themeBtn = document.querySelector('.theme-toggle');
            if (themeBtn) themeBtn.textContent = isLight ? '🌙' : '☀️';
            localStorage.setItem('pktana-theme', isLight ? 'light' : 'dark');
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
                const d = await res.json();
                const fmtKB = (kb) => { let b=kb*1024; const u=['B','KB','MB','GB']; let i=0; while(b>=1024&&i<3){b/=1024;i++;} return b.toFixed(1)+' '+u[i]; };
                const fmtUp = (s) => { s=Math.floor(s); const dy=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),sc=s%60; return (dy?dy+'d ':'')+(h?h+'h ':'')+(m?m+'m ':'')+sc+'s'; };
                const memUsed = d.mem_total_kb - d.mem_avail_kb;
                const memPct = Math.round(memUsed / d.mem_total_kb * 100);
                const diskPct = d.disk_total_kb > 0 ? Math.round(d.disk_used_kb / d.disk_total_kb * 100) : 0;
                const bar = (pct, col='var(--primary)') => `<span style="display:inline-flex;align-items:center;gap:4px;"><span style="display:inline-block;width:72px;height:4px;background:var(--border);border-radius:3px;flex-shrink:0;"><span style="display:block;width:${pct}%;height:100%;background:${col};border-radius:3px;"></span></span><span style="font-size:10px;color:var(--text-muted);white-space:nowrap;">${pct}%</span></span>`;
                const memCol = memPct > 85 ? 'var(--danger)' : memPct > 65 ? 'var(--warning)' : 'var(--success)';
                const diskCol = diskPct > 85 ? 'var(--danger)' : diskPct > 65 ? 'var(--warning)' : 'var(--success)';
                document.getElementById('serverContent').innerHTML =
                    kvRow('Hostname', d.hostname) +
                    kvRow('OS', d.os_name || '—') +
                    kvRow('Kernel', d.version) +
                    kvRow('Uptime', fmtUp(parseFloat(d.uptime_sec))) +
                    kvRow('CPU', `${d.cpu_cores} cores — ${d.cpu_model || '—'}`) +
                    kvRow('Load Avg', `${d.load1} / ${d.load5} / ${d.load15} (1m/5m/15m)`) +
                    kvRow('Memory', `${fmtKB(memUsed)} / ${fmtKB(d.mem_total_kb)} ${bar(memPct, memCol)}`) +
                    kvRow('Mem Available', fmtKB(d.mem_avail_kb)) +
                    kvRow('Buffers + Cached', fmtKB(d.mem_buffers_kb + d.mem_cached_kb)) +
                    kvRow('Disk (/)', `${fmtKB(d.disk_used_kb)} / ${fmtKB(d.disk_total_kb)} ${bar(diskPct, diskCol)}`);
            } catch (e) { document.getElementById('serverContent').innerHTML = 'Error: ' + e.message; }
        }

        async function loadInterfaces() {
            try {
                const res = await fetch('/api/interfaces');
                const ifaces = await res.json();
                let html = '';
                ifaces.forEach(iface => {
                    const desc = iface.description || 'Network Interface';
                    const upClass = iface.is_up ? ' up' : '';
                    const statusIcon = iface.is_up ? '▲' : '▼';
                    const statusColor = iface.is_up ? 'var(--success)' : 'var(--danger)';
                    html += `<div class="iface-card${upClass}" onclick="selectInterfaceForCapture('${iface.name}')">
                        <div class="iface-name">${iface.name}</div>
                        <div class="iface-desc">${desc}</div>
                        <div class="iface-status" style="color:${statusColor};">
                            <span>${statusIcon}</span>
                            <span>${iface.is_up ? 'UP' : 'DOWN'}</span>
                            ${iface.address ? `<span style="color:var(--text-muted);font-weight:500;margin-left:4px;">${iface.address}</span>` : ''}
                        </div>
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
                const badge = document.getElementById('sessionCountBadge');
                const activeCount = (sessions || []).filter(s => s.status === 'Active').length;
                if (badge) {
                    badge.textContent = `${(sessions || []).length} session${sessions.length !== 1 ? 's' : ''}${activeCount ? ` · ${activeCount} live` : ''}`;
                    badge.classList.toggle('live', activeCount > 0);
                }
                if (!sessions || sessions.length === 0) {
                    list.innerHTML = `<div class="sessions-empty">
                        <div class="sessions-empty-icon">📡</div>
                        <div class="sessions-empty-title">No Active Sessions</div>
                        <div class="sessions-empty-hint">Start monitoring by clicking an interface above, or create a new session manually.</div>
                        <button class="primary-btn" onclick="showCreateSessionDialog()">Create Session</button>
                    </div>`;
                    return;
                }
                const fmtBytes = (b) => { if (b < 1024) return b + ' B'; if (b < 1048576) return (b/1024).toFixed(1) + ' KB'; return (b/1048576).toFixed(1) + ' MB'; };
                let html = '<table class="settings-table"><thead><tr><th>Session ID</th><th>Interface</th><th>Status</th><th>Packets</th><th>Bytes</th><th>Actions</th></tr></thead><tbody>';
                sessions.forEach(s => {
                    const isActive = s.status === 'Active';
                    const statusBadge = isActive
                        ? '<span class="badge badge-success">Active</span>'
                        : '<span class="badge badge-danger">Stopped</span>';
                    const viewBtn = `<button class="primary-btn" style="padding:4px 12px;font-size:11px;" onclick="viewSession('${s.id}', '${s.interface}')">View</button>`;
                    const stopBtn = isActive ? `<button class="btn" style="padding:4px 12px;font-size:11px;" onclick="stopSession('${s.id}')">Stop</button>` : '';
                    const deleteBtn = `<button class="btn" style="padding:4px 12px;font-size:11px;background:rgba(220,38,38,0.15);color:#fca5a5;border-color:rgba(220,38,38,0.3);" onclick="deleteSession('${s.id}')">Delete</button>`;
                    html += `<tr>
                        <td><span class="session-id">${s.id}</span></td>
                        <td><strong>${s.interface}</strong></td>
                        <td>${statusBadge}</td>
                        <td class="session-pkts">${s.packet_count || 0}</td>
                        <td class="session-pkts">${fmtBytes(s.bytes_captured || 0)}</td>
                        <td><div class="table-actions">${viewBtn}${stopBtn}${deleteBtn}</div></td>
                    </tr>`;
                });
                html += '</tbody></table>';
                list.innerHTML = html;
            } catch (e) { console.error('Error loading sessions:', e); }
        }

        let securityPollTimer = null;
        let securityConfigCache = null;

        function verdictBadge(v) {
            const cls = v === 'drop' ? 'verdict-drop' : v === 'pass' ? 'verdict-pass' : v === 'redirect' ? 'verdict-redirect' : v === 'quarantine' ? 'verdict-quarantine' : 'verdict-monitor';
            return `<span class="verdict-badge ${cls}">${escapeHtml(v || 'monitor')}</span>`;
        }

        async function loadSecurityConfig() {
            try {
                const res = await fetch('/api/security/config');
                const cfg = await res.json();
                securityConfigCache = cfg;
                const dlpToggle = document.getElementById('dlpToggle');
                const idpsToggle = document.getElementById('idpsToggle');
                if (dlpToggle) dlpToggle.checked = !!cfg.dlp_enabled;
                if (idpsToggle) idpsToggle.checked = !!cfg.idps_enabled;
                const dlpAct = document.getElementById('dlpActionSelect');
                const idpsAct = document.getElementById('idpsActionSelect');
                const redirectIn = document.getElementById('redirectTargetInput');
                if (dlpAct) dlpAct.value = cfg.dlp_action || cfg.dlp_mode || 'monitor';
                if (idpsAct) idpsAct.value = cfg.idps_action || cfg.idps_mode || 'monitor';
                if (redirectIn) redirectIn.value = cfg.redirect_target || '';
                updateSecurityVisibility(cfg);
                loadSecurityRules(cfg);
                loadPolicyRules(cfg);
            } catch (e) { console.error('Security config load failed:', e); }
        }

        function updateSecurityVisibility(cfg) {
            const enabled = cfg && (cfg.dlp_enabled || cfg.idps_enabled);
            const nav = document.getElementById('securityNavIcon');
            const preview = document.getElementById('securityPreviewCard');
            const filterGrp = document.getElementById('securityFilterGroup');
            const dlpCard = document.getElementById('dlpFeatureCard');
            const idpsCard = document.getElementById('idpsFeatureCard');
            if (nav) {
                nav.style.display = '';
                nav.style.opacity = enabled ? '1' : '0.55';
                nav.title = enabled ? 'Security (DLP / IDPS)' : 'Security — enable DLP or IDPS in Server Info';
            }
            if (preview) preview.style.display = enabled ? '' : 'none';
            // Always show security protocol filters; optgroup display toggling is unreliable in browsers
            if (filterGrp) filterGrp.style.display = '';
            if (dlpCard) dlpCard.classList.toggle('enabled', cfg && cfg.dlp_enabled);
            if (idpsCard) idpsCard.classList.toggle('enabled', cfg && cfg.idps_enabled);
            const pillDlp = document.getElementById('secPillDlp');
            const pillIdps = document.getElementById('secPillIdps');
            if (pillDlp) {
                pillDlp.classList.toggle('on', !!(cfg && cfg.dlp_enabled));
                pillDlp.innerHTML = `<span class="dot"></span>DLP ${cfg && cfg.dlp_enabled ? 'On' : 'Off'}`;
            }
            if (pillIdps) {
                pillIdps.classList.toggle('on', !!(cfg && cfg.idps_enabled));
                pillIdps.innerHTML = `<span class="dot"></span>IDPS ${cfg && cfg.idps_enabled ? 'On' : 'Off'}`;
            }
            if (enabled) {
                refreshSecurityPanel();
                if (!securityPollTimer) {
                    securityPollTimer = setInterval(() => {
                        const secPanel = document.getElementById('security');
                        const previewVisible = preview && preview.style.display !== 'none';
                        if ((secPanel && secPanel.classList.contains('active')) || previewVisible) {
                            refreshSecurityPanel();
                        }
                    }, 3000);
                }
            }
        }

        function showSecuritySub(name) {
            const map = {
                alerts: 'secSubAlerts', 'dlp-flows': 'secSubDlpFlows', 'idps-flows': 'secSubIdpsFlows',
                policy: 'secSubPolicy', interfaces: 'secSubInterfaces',
                'custom-dlp': 'secSubCustomDlp', 'custom-idps': 'secSubCustomIdps', threat: 'secSubThreat'
            };
            const btnMap = {
                alerts: 'secSubBtnAlerts', 'dlp-flows': 'secSubBtnDlpFlows', 'idps-flows': 'secSubBtnIdpsFlows',
                policy: 'secSubBtnPolicy', interfaces: 'secSubBtnInterfaces',
                'custom-dlp': 'secSubBtnCustomDlp', 'custom-idps': 'secSubBtnCustomIdps', threat: 'secSubBtnThreat'
            };
            document.querySelectorAll('.sec-sub-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.sec-sub-btn').forEach(b => b.classList.remove('active'));
            const panel = document.getElementById(map[name]);
            const btn = document.getElementById(btnMap[name]);
            if (panel) panel.classList.add('active');
            if (btn) btn.classList.add('active');
            if (name === 'dlp-flows') loadSecurityFlows('dlp');
            if (name === 'idps-flows') loadSecurityFlows('idps');
            if (name === 'policy') { loadSecurityRules(securityConfigCache); loadPolicyRules(securityConfigCache); }
            if (name === 'interfaces') loadSecurityInterfaces();
            if (name === 'custom-dlp') {
                customDlpDraft = (securityConfigCache && securityConfigCache.dlp_custom_identifiers) ? JSON.parse(JSON.stringify(securityConfigCache.dlp_custom_identifiers)) : [];
                renderCustomDlpTable();
                renderBuiltinDlpToggles(securityConfigCache);
            }
            if (name === 'custom-idps') {
                loadCustomIdpsArea(securityConfigCache);
                renderBuiltinIdpsToggles(securityConfigCache);
            }
            if (name === 'threat') loadThreatIntel();
        }

        async function refreshSecurityPanel() {
            loadSecurityStats();
            loadSecurityAlerts(true);
            loadSecurityFlows('dlp');
            loadSecurityFlows('idps');
            loadSecurityInterfaces();
        }

        async function toggleSecurityFeature(engine, enabled) {
            const body = engine === 'dlp' ? { dlp_enabled: enabled } : { idps_enabled: enabled };
            try {
                const res = await fetch('/api/security/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const cfg = await res.json();
                securityConfigCache = cfg;
                updateSecurityVisibility(cfg);
                refreshSecurityPanel();
                toast(
                    enabled
                        ? `${engine.toUpperCase()} enabled`
                        : `${engine.toUpperCase()} disabled — ${engine.toUpperCase()} logs cleared`,
                    enabled ? 'success' : 'info'
                );
                if (enabled) switchTab('security');
            } catch (e) { toast('Failed to update security config: ' + e, 'error'); }
        }

        async function setEngineAction(engine, action) {
            const body = engine === 'dlp' ? { dlp_action: action, dlp_mode: action } : { idps_action: action, idps_mode: action };
            try {
                const res = await fetch('/api/security/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
                securityConfigCache = await res.json();
                toast(`${engine.toUpperCase()} default action: ${action}`, 'success');
            } catch (e) { toast('Failed to set action: ' + e, 'error'); }
        }

        async function setRedirectTarget(target) {
            try {
                const res = await fetch('/api/security/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ redirect_target: target }) });
                securityConfigCache = await res.json();
                toast('Redirect target updated', 'info');
            } catch (e) { toast('Failed to set redirect: ' + e, 'error'); }
        }

        async function setRuleAction(ruleId, action) {
            const ra = (securityConfigCache && securityConfigCache.rule_actions) ? { ...securityConfigCache.rule_actions } : {};
            if (!action || action === 'inherit') {
                delete ra[ruleId];
            } else {
                ra[ruleId] = action;
            }
            try {
                const res = await fetch('/api/security/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rule_actions: ra }) });
                securityConfigCache = await res.json();
                toast(`Rule ${ruleId}: ${action || 'engine default'}`, 'info');
            } catch (e) { toast('Failed to set rule action: ' + e, 'error'); }
        }

        async function loadSecurityStats() {
            try {
                const res = await fetch('/api/security/stats');
                const s = await res.json();
                const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
                set('statDlp', s.dlp_alerts || 0);
                set('statIdps', s.idps_alerts || 0);
                set('statCritical', s.critical || 0);
                set('statHigh', s.high || 0);
                set('statDropped', s.dropped || 0);
                set('statRedirected', s.redirected || 0);
                set('statScanned', s.packets_scanned || 0);
            } catch (e) { /* ignore */ }
        }

        function jumpToSecurityFlow(src, dst, engine) {
            if (!activeId) {
                toast('Open a capture window first (pick an interface in Server Info)', 'warn');
                switchTab('serverinfo');
                return;
            }
            switchTab('dashboard');
            const filter = document.getElementById('displayFilter');
            const stream = document.getElementById('streamFilter');
            if (filter) {
                const parts = [];
                if (src) parts.push(src.split(':')[0]);
                if (dst) parts.push(dst.split(':')[0]);
                filter.value = parts.join(' ');
            }
            if (stream && engine) {
                stream.value = engine === 'dlp' ? 'dlp_alert' : engine === 'idps' ? 'idps_alert' : 'security_alert';
            }
            applyStreamFilter();
            applyDisplayFilter();
            document.getElementById('sb-status').textContent = `Filtered to flow ${src} → ${dst}`;
        }

        function renderSecurityFlowsTable(flows, targetId, engine) {
            const tbody = document.getElementById(targetId);
            if (!tbody) return;
            if (!flows || flows.length === 0) {
                tbody.innerHTML = `<tr><td colspan="10" style="text-align:center;padding:32px;color:var(--text-muted);">No ${engine.toUpperCase()} flows yet. Start capture with ${engine.toUpperCase()} enabled.</td></tr>`;
                return;
            }
            tbody.innerHTML = flows.map(f => {
                const srcEsc = escapeHtml(f.src).replace(/'/g, "\\'");
                const dstEsc = escapeHtml(f.dst).replace(/'/g, "\\'");
                const geo = [f.src_country, f.dst_country].filter(Boolean).join(' → ') || '—';
                return `<tr class="flow-row-click sev-${f.top_severity}" onclick="jumpToSecurityFlow('${srcEsc}','${dstEsc}','${engine}')" title="Click to filter packets for this flow">
                    <td><code style="font-size:10px">${escapeHtml(f.interface || '—')}</code></td>
                    <td><code style="font-size:10px">${escapeHtml(f.flow_key.substring(0, 20))}…</code></td>
                    <td>${escapeHtml(f.protocol)}</td>
                    <td>${escapeHtml(f.src)}</td>
                    <td>${escapeHtml(f.dst)}</td>
                    <td>${escapeHtml(geo)}</td>
                    <td>${f.alert_count}</td>
                    <td><code style="font-size:10px">${escapeHtml(f.top_rule)}</code></td>
                    <td>${verdictBadge(f.verdict)}</td>
                    <td>${formatBytes(f.bytes || 0)}</td>
                </tr>`;
            }).join('');
        }

        async function loadSecurityFlows(engine, iface) {
            try {
                let url = `/api/security/flows?engine=${engine}`;
                if (iface) url += `&iface=${encodeURIComponent(iface)}`;
                const res = await fetch(url);
                const flows = await res.json();
                renderSecurityFlowsTable(flows, engine === 'dlp' ? 'dlpFlowsBody' : 'idpsFlowsBody', engine);
            } catch (e) { console.error('Flow load failed:', e); }
        }

        function renderPolicyRulesTable(rules) {
            const tbody = document.getElementById('policyRulesBody');
            if (!tbody) return;
            if (!rules || rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="13" style="text-align:center;padding:24px;color:var(--text-muted);">No conditional policy rules. Add one to match by interface, IP, CIDR, or country.</td></tr>';
                return;
            }
            const actionOpts = ['monitor','pass','drop','redirect','quarantine'];
            const engineOpts = ['any','dlp','idps'];
            tbody.innerHTML = rules.map((r, idx) => {
                const engOpts = engineOpts.map(e => `<option value="${e}" ${r.engine === e ? 'selected' : ''}>${e}</option>`).join('');
                const actOpts = actionOpts.map(a => `<option value="${a}" ${r.action === a ? 'selected' : ''}>${a}</option>`).join('');
                return `<tr data-idx="${idx}">
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:70px" value="${escapeHtml(r.name || '')}" onchange="updatePolicyField(${idx}, 'name', this.value)"></td>
                    <td><input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="updatePolicyField(${idx}, 'enabled', this.checked)"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:50px" type="number" value="${r.priority || 0}" onchange="updatePolicyField(${idx}, 'priority', parseInt(this.value)||0)"></td>
                    <td><select class="form-input" style="font-size:10px;padding:2px 6px" onchange="updatePolicyField(${idx}, 'engine', this.value)">${engOpts}</select></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:70px" placeholder="eth0" value="${escapeHtml(r.interface || '')}" onchange="updatePolicyField(${idx}, 'interface', this.value)"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:90px" placeholder="10.0.0.0/8" value="${escapeHtml(r.src_ip || '')}" onchange="updatePolicyField(${idx}, 'src_ip', this.value)"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:90px" placeholder="8.8.8.8" value="${escapeHtml(r.dst_ip || '')}" onchange="updatePolicyField(${idx}, 'dst_ip', this.value)"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:40px" placeholder="US" value="${escapeHtml(r.src_country || '')}" onchange="updatePolicyField(${idx}, 'src_country', this.value)"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:40px" placeholder="CN" value="${escapeHtml(r.dst_country || '')}" onchange="updatePolicyField(${idx}, 'dst_country', this.value)"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:110px" placeholder="rule id" value="${escapeHtml(r.detection_rule || '')}" onchange="updatePolicyField(${idx}, 'detection_rule', this.value)"></td>
                    <td><select class="form-input" style="font-size:10px;padding:2px 6px" onchange="updatePolicyField(${idx}, 'action', this.value)">${actOpts}</select></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:80px" placeholder="redirect" value="${escapeHtml(r.redirect_target || '')}" onchange="updatePolicyField(${idx}, 'redirect_target', this.value)"></td>
                    <td><button class="btn" style="font-size:10px;padding:2px 8px" onclick="removePolicyRule(${idx})">✕</button></td>
                </tr>`;
            }).join('');
        }

        let policyRulesDraft = [];

        function loadPolicyRules(cfg) {
            policyRulesDraft = (cfg && cfg.policy_rules) ? JSON.parse(JSON.stringify(cfg.policy_rules)) : [];
            renderPolicyRulesTable(policyRulesDraft);
        }

        function updatePolicyField(idx, field, value) {
            if (!policyRulesDraft[idx]) return;
            policyRulesDraft[idx][field] = value;
        }

        function addPolicyRule() {
            policyRulesDraft.push({
                id: 'rule_' + Date.now(),
                name: 'New rule',
                enabled: true,
                priority: 50,
                engine: 'any',
                interface: '',
                src_ip: '',
                dst_ip: '',
                src_country: '',
                dst_country: '',
                detection_rule: '',
                action: 'monitor',
                redirect_target: ''
            });
            renderPolicyRulesTable(policyRulesDraft);
        }

        function removePolicyRule(idx) {
            policyRulesDraft.splice(idx, 1);
            renderPolicyRulesTable(policyRulesDraft);
        }

        async function savePolicyRules() {
            try {
                const res = await fetch('/api/security/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ policy_rules: policyRulesDraft })
                });
                securityConfigCache = await res.json();
                policyRulesDraft = securityConfigCache.policy_rules || [];
                renderPolicyRulesTable(policyRulesDraft);
                toast('Policy rules saved', 'success');
            } catch (e) { toast('Failed to save policy rules: ' + e, 'error'); }
        }

        async function loadSecurityInterfaces() {
            try {
                const res = await fetch('/api/security/interfaces');
                const ifaces = await res.json();
                const tbody = document.getElementById('securityInterfacesBody');
                if (!tbody) return;
                if (!ifaces || ifaces.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:32px;color:var(--text-muted);">No per-interface stats yet. Start capture on an interface with DLP/IDPS enabled.</td></tr>';
                    return;
                }
                tbody.innerHTML = ifaces.map(i => {
                    const s = i.stats || {};
                    return `<tr class="flow-row-click" onclick="filterSecurityByIface('${escapeHtml(i.interface).replace(/'/g, "\\'")}')" title="Click to filter DLP/IDPS flows for this interface">
                        <td><strong>${escapeHtml(i.interface)}</strong></td>
                        <td>${s.dlp_alerts || 0}</td>
                        <td>${s.idps_alerts || 0}</td>
                        <td>${i.dlp_flows || 0}</td>
                        <td>${i.idps_flows || 0}</td>
                        <td>${s.critical || 0}</td>
                        <td>${s.high || 0}</td>
                        <td>${s.dropped || 0}</td>
                        <td>${s.redirected || 0}</td>
                        <td>${s.packets_scanned || 0}</td>
                    </tr>`;
                }).join('');
            } catch (e) { console.error('Interface stats load failed:', e); }
        }

        function filterSecurityByIface(iface) {
            showSecuritySub('dlp-flows');
            loadSecurityFlows('dlp', iface);
            loadSecurityFlows('idps', iface);
            toast('Filtered flows to interface: ' + iface, 'info');
        }

        async function loadSecurityRules(cfg) {
            try {
                const res = await fetch('/api/security/rules');
                const rules = await res.json();
                const tbody = document.getElementById('securityRulesBody');
                if (!tbody) return;
                const ra = (cfg && cfg.rule_actions) ? cfg.rule_actions : {};
                tbody.innerHTML = rules.map(r => {
                    const cur = ra[r.rule_id] || 'inherit';
                    const opts = ['inherit','monitor','pass','drop','redirect','quarantine'].map(a =>
                        `<option value="${a}" ${cur === a ? 'selected' : ''}>${a === 'inherit' ? 'Engine default' : a}</option>`
                    ).join('');
                    return `<tr><td><span class="sec-engine ${r.engine}">${r.engine}</span></td><td><code style="font-size:10px">${escapeHtml(r.rule_id)}</code></td><td>${escapeHtml(r.title)}</td><td>${escapeHtml(r.severity)}</td><td><select class="form-input" style="font-size:11px;padding:4px 8px;" onchange="setRuleAction('${r.rule_id}', this.value === 'inherit' ? '' : this.value)">${opts}</select></td></tr>`;
                }).join('');
            } catch (e) { console.error('Rules load failed:', e); }
        }

        function renderSecurityAlertsTable(alerts, targetId, compact) {
            const tbody = document.getElementById(targetId);
            if (!tbody) return;
            if (!alerts || alerts.length === 0) {
                tbody.innerHTML = `<tr><td colspan="${compact ? 5 : 11}" style="text-align:center;padding:32px;color:var(--text-muted);">No security alerts yet. Start capture with DLP/IDPS enabled.</td></tr>`;
                return;
            }
            const sevBadge = (s) => {
                const cls = s === 'critical' ? 'badge-critical' : s === 'high' ? 'badge-danger' : s === 'medium' ? 'badge-warning' : 'badge-info';
                return `<span class="badge ${cls}">${s}</span>`;
            };
            const rows = alerts.slice().reverse().slice(0, compact ? 8 : 500);
            tbody.innerHTML = rows.map(a => {
                const ts = new Date(a.ts * 1000).toLocaleTimeString();
                const eng = `<span class="sec-engine ${a.engine}">${a.engine}</span>`;
                const srcEsc = escapeHtml(a.src).replace(/'/g, "\\'");
                const dstEsc = escapeHtml(a.dst).replace(/'/g, "\\'");
                if (compact) {
                    return `<tr class="sev-${a.severity} flow-row-click" onclick="jumpToSecurityFlow('${srcEsc}','${dstEsc}','${a.engine}')"><td>${ts}</td><td>${eng}</td><td>${sevBadge(a.severity)}</td><td><strong>${escapeHtml(a.title)}</strong><br><small style="color:var(--text-muted)">${escapeHtml((a.detail || '').substring(0,80))}</small></td><td>${escapeHtml(a.src)} → ${escapeHtml(a.dst)}</td></tr>`;
                }
                return `<tr class="sev-${a.severity} flow-row-click" onclick="jumpToSecurityFlow('${srcEsc}','${dstEsc}','${a.engine}')"><td>${ts}</td><td>${eng}</td><td>${sevBadge(a.severity)}</td><td>${verdictBadge(a.verdict || a.action)}</td><td><code style="font-size:10px">${escapeHtml(a.interface || '—')}</code></td><td>${escapeHtml(a.src)}${a.src_country ? ' <span class="badge badge-info">' + escapeHtml(a.src_country) + '</span>' : ''}</td><td>${escapeHtml(a.dst)}${a.dst_country ? ' <span class="badge badge-info">' + escapeHtml(a.dst_country) + '</span>' : ''}</td><td><code style="font-size:10px">${escapeHtml(a.rule_id)}</code></td><td><strong>${escapeHtml(a.title)}</strong></td><td><code style="font-size:10px">${escapeHtml(a.policy_id || '—')}</code></td></tr>`;
            }).join('');
        }

        async function loadSecurityAlerts(previewOnly) {
            try {
                const res = await fetch('/api/security/alerts');
                const alerts = await res.json();
                renderSecurityAlertsTable(alerts, 'securityAlertsBody', false);
                if (previewOnly || document.getElementById('securityPreviewList')) {
                    const preview = document.getElementById('securityPreviewList');
                    if (preview) {
                        if (!alerts || alerts.length === 0) {
                            preview.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:12px;">No alerts yet — start a capture session.</div>';
                        } else {
                            preview.innerHTML = `<table class="settings-table"><thead><tr><th>Time</th><th>Engine</th><th>Severity</th><th>Alert</th><th>Endpoints</th></tr></thead><tbody id="securityPreviewBody"></tbody></table>`;
                            renderSecurityAlertsTable(alerts, 'securityPreviewBody', true);
                        }
                    }
                }
            } catch (e) { console.error('Security alerts load failed:', e); }
        }

        async function clearSecurityAlerts() {
            if (!confirm('Clear all security alerts?')) return;
            await fetch('/api/security/clear', { method: 'POST' });
            loadSecurityStats();
            loadSecurityAlerts();
            toast('Security alerts cleared', 'info');
        }

        // ─── Custom DLP Identifiers ─────────────────────────────────────
        let customDlpDraft = [];

        function renderCustomDlpTable() {
            const tbody = document.getElementById('customDlpBody');
            if (!tbody) return;
            if (!customDlpDraft.length) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">No custom identifiers yet. Click "+ Add Identifier".</td></tr>';
                return;
            }
            const sevOpts = ['low','medium','high','critical'].map(s => `<option value="${s}">${s}</option>`).join('');
            tbody.innerHTML = customDlpDraft.map((r, i) => `
                <tr>
                    <td><input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="customDlpDraft[${i}].enabled=this.checked"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:100px" value="${escapeHtml(r.name||'')}" onchange="customDlpDraft[${i}].name=this.value" placeholder="My Rule"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:200px" value="${escapeHtml(r.pattern||'')}" onchange="customDlpDraft[${i}].pattern=this.value" placeholder="regex:pattern or keyword"></td>
                    <td><input class="form-input" style="font-size:10px;padding:2px 6px;width:80px" value="${escapeHtml(r.category||'custom')}" onchange="customDlpDraft[${i}].category=this.value"></td>
                    <td><select class="form-input" style="font-size:10px;padding:2px 6px" onchange="customDlpDraft[${i}].severity=this.value">${sevOpts.replace(`value="${r.severity}"`, `value="${r.severity}" selected`)}</select></td>
                    <td><button class="btn" style="font-size:10px;padding:2px 8px" onclick="customDlpDraft.splice(${i},1);renderCustomDlpTable()">✕</button></td>
                </tr>`).join('');
        }

        function addCustomDlpIdentifier() {
            customDlpDraft.push({ id: 'dlp_custom_' + Date.now(), name: 'New Identifier', pattern: '', category: 'custom', severity: 'high', enabled: true });
            renderCustomDlpTable();
        }

        async function saveCustomDlpIdentifiers() {
            try {
                const res = await fetch('/api/security/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ dlp_custom_identifiers: customDlpDraft }) });
                securityConfigCache = await res.json();
                toast('Custom DLP identifiers saved', 'success');
            } catch(e) { toast('Save failed: ' + e, 'error'); }
        }

        function renderBuiltinDlpToggles(cfg) {
            const el = document.getElementById('builtinDlpList');
            if (!el) return;
            fetch('/api/security/rules').then(r => r.json()).then(rules => {
                const dlpRules = rules.filter(r => r.engine === 'dlp');
                const disabled = (cfg && cfg.dlp_disabled_identifiers) || [];
                el.innerHTML = dlpRules.map(r => {
                    const on = !disabled.includes(r.rule_id);
                    const col = on ? 'var(--success)' : 'var(--text-muted)';
                    return `<label style="display:inline-flex;align-items:center;gap:5px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:4px 8px;cursor:pointer;font-size:11px;" title="${escapeHtml(r.category)} — ${escapeHtml(r.severity)}">
                        <input type="checkbox" id="dlpid_${r.rule_id}" ${on ? 'checked' : ''} style="accent-color:var(--primary);">
                        <span style="color:${col};">${escapeHtml(r.rule_id.replace('dlp_',''))}</span>
                    </label>`;
                }).join('');
            }).catch(() => { el.textContent = 'Failed to load rules.'; });
        }

        async function saveBuiltinDlpToggles() {
            const el = document.getElementById('builtinDlpList');
            if (!el) return;
            const disabled = [];
            el.querySelectorAll('input[type=checkbox]').forEach(cb => {
                if (!cb.checked) {
                    const id = cb.id.replace('dlpid_', '');
                    disabled.push(id);
                }
            });
            try {
                const res = await fetch('/api/security/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ dlp_disabled_identifiers: disabled }) });
                securityConfigCache = await res.json();
                toast('DLP identifier toggles saved', 'success');
            } catch(e) { toast('Save failed: ' + e, 'error'); }
        }

        // ─── Custom IDPS Rules ───────────────────────────────────────────
        function loadCustomIdpsArea(cfg) {
            const el = document.getElementById('customIdpsRulesArea');
            if (el && cfg && cfg.idps_custom_rules) el.value = cfg.idps_custom_rules.join('\n');
            const ja3el = document.getElementById('ja3BlocklistArea');
            if (ja3el && cfg && cfg.idps_blocked_ja3) ja3el.value = cfg.idps_blocked_ja3.join('\n');
        }

        async function saveCustomIdpsRules() {
            const el = document.getElementById('customIdpsRulesArea');
            if (!el) return;
            const lines = el.value.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
            try {
                const res = await fetch('/api/security/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ idps_custom_rules: lines }) });
                securityConfigCache = await res.json();
                toast(`${lines.length} custom IDPS rules saved`, 'success');
                document.getElementById('idpsRuleValidationMsg').textContent = `✓ ${lines.length} rules active`;
            } catch(e) { toast('Save failed: ' + e, 'error'); }
        }

        function validateCustomIdpsRules() {
            const el = document.getElementById('customIdpsRulesArea');
            const msg = document.getElementById('idpsRuleValidationMsg');
            if (!el || !msg) return;
            const lines = el.value.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
            let ok = 0, fail = 0;
            lines.forEach(line => {
                const lower = line.trim().toLowerCase();
                if (lower.startsWith('alert ') && lower.includes('sid:') && lower.includes('msg:')) ok++;
                else fail++;
            });
            msg.textContent = fail > 0 ? `⚠ ${fail} invalid rule(s), ${ok} valid` : `✓ ${ok} rule(s) valid`;
            msg.style.color = fail > 0 ? 'var(--warning)' : 'var(--success)';
        }

        async function saveJa3Blocklist() {
            const el = document.getElementById('ja3BlocklistArea');
            if (!el) return;
            const list = el.value.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#') && /^[a-f0-9]{32}$/i.test(l));
            try {
                const res = await fetch('/api/security/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ idps_blocked_ja3: list }) });
                securityConfigCache = await res.json();
                toast(`${list.length} JA3 fingerprints saved`, 'success');
            } catch(e) { toast('Save failed: ' + e, 'error'); }
        }

        function renderBuiltinIdpsToggles(cfg) {
            const el = document.getElementById('builtinIdpsList');
            if (!el) return;
            fetch('/api/security/rules').then(r => r.json()).then(rules => {
                const idpsRules = rules.filter(r => r.engine === 'idps' && r.sid > 0);
                const disabled = (cfg && cfg.idps_disabled_sids) || [];
                el.innerHTML = idpsRules.map(r => {
                    const on = !disabled.includes(r.sid);
                    const col = r.severity === 'critical' ? 'var(--danger)' : r.severity === 'high' ? 'var(--warning)' : 'var(--text-muted)';
                    return `<label style="display:inline-flex;align-items:center;gap:5px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:4px 8px;cursor:pointer;font-size:11px;" title="SID:${r.sid} — ${escapeHtml(r.severity)}">
                        <input type="checkbox" id="idpssid_${r.sid}" ${on ? 'checked' : ''} style="accent-color:var(--primary);">
                        <span style="color:${col};">${escapeHtml(r.title.substring(0,40))}</span>
                    </label>`;
                }).join('');
            }).catch(() => { el.textContent = 'Failed to load rules.'; });
        }

        async function saveBuiltinIdpsToggles() {
            const el = document.getElementById('builtinIdpsList');
            if (!el) return;
            const disabled = [];
            el.querySelectorAll('input[type=checkbox]').forEach(cb => {
                if (!cb.checked) {
                    const sid = parseInt(cb.id.replace('idpssid_',''));
                    if (!isNaN(sid)) disabled.push(sid);
                }
            });
            try {
                const res = await fetch('/api/security/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ idps_disabled_sids: disabled }) });
                securityConfigCache = await res.json();
                toast('IDPS SID toggles saved', 'success');
            } catch(e) { toast('Save failed: ' + e, 'error'); }
        }

        // ─── Threat Intelligence Overview ────────────────────────────────
        async function loadThreatIntel() {
            try {
                const res = await fetch('/api/security/alerts');
                const alerts = await res.json();
                renderThreatTimeline(alerts);
                renderSeverityBars(alerts);
                renderTopAttackers(alerts);
                renderTopRules(alerts);
                renderTopCountries(alerts);
            } catch(e) { console.error('Threat intel load failed:', e); }
        }

        function renderThreatTimeline(alerts) {
            const svg = document.getElementById('secThreatTimeline');
            if (!svg) return;
            const recent = (alerts || []).slice(-50);
            const w = svg.clientWidth || 400;
            const h = 60;
            const bw = Math.max(2, Math.floor(w / Math.max(recent.length, 1)) - 1);
            const colMap = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#64748b' };
            svg.innerHTML = recent.map((a, i) => {
                const col = colMap[a.severity] || '#64748b';
                const bh = a.severity === 'critical' ? h : a.severity === 'high' ? h*0.75 : a.severity === 'medium' ? h*0.5 : h*0.3;
                const x = i * (bw + 1);
                const y = h - bh;
                return `<rect x="${x}" y="${y}" width="${bw}" height="${bh}" fill="${col}" opacity="0.85" rx="1" title="${escapeHtml(a.title)}"/>`;
            }).join('');
        }

        function renderSeverityBars(alerts) {
            const el = document.getElementById('secSeverityBars');
            if (!el) return;
            const counts = { critical:0, high:0, medium:0, low:0, info:0 };
            (alerts||[]).forEach(a => { if (counts[a.severity] !== undefined) counts[a.severity]++; });
            const total = Object.values(counts).reduce((s,v) => s+v, 0) || 1;
            const colMap = { critical:'var(--danger)', high:'var(--warning)', medium:'#eab308', low:'var(--info)', info:'var(--text-muted)' };
            el.innerHTML = Object.entries(counts).map(([sev, cnt]) => {
                const pct = Math.round(cnt / total * 100);
                return `<div style="display:flex;align-items:center;gap:8px;font-size:11px;">
                    <span style="width:60px;text-align:right;color:${colMap[sev]};font-weight:700;text-transform:uppercase;">${sev}</span>
                    <div style="flex:1;background:var(--border);border-radius:3px;height:8px;">
                        <div style="width:${pct}%;background:${colMap[sev]};border-radius:3px;height:100%;"></div>
                    </div>
                    <span style="width:32px;color:var(--text-muted);">${cnt}</span>
                </div>`;
            }).join('');
        }

        function renderTopAttackers(alerts) {
            const tbody = document.getElementById('topAttackersBody');
            if (!tbody) return;
            const map = {};
            (alerts||[]).forEach(a => {
                const ip = a.src ? a.src.split(':')[0] : '?';
                if (!map[ip]) map[ip] = { count: 0, topRule: '' };
                map[ip].count++;
                if (!map[ip].topRule) map[ip].topRule = a.rule_id;
            });
            const sorted = Object.entries(map).sort((a,b) => b[1].count - a[1].count).slice(0,10);
            if (!sorted.length) { tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:16px;color:var(--text-muted);">No data yet.</td></tr>'; return; }
            tbody.innerHTML = sorted.map(([ip, d], i) =>
                `<tr><td style="color:var(--text-muted);">${i+1}</td><td><code style="font-size:11px;">${escapeHtml(ip)}</code></td><td><strong style="color:var(--danger);">${d.count}</strong></td><td><code style="font-size:10px;">${escapeHtml(d.topRule)}</code></td></tr>`
            ).join('');
        }

        function renderTopRules(alerts) {
            const tbody = document.getElementById('topRulesBody');
            if (!tbody) return;
            const map = {};
            (alerts||[]).forEach(a => {
                if (!map[a.rule_id]) map[a.rule_id] = { count: 0, engine: a.engine };
                map[a.rule_id].count++;
            });
            const sorted = Object.entries(map).sort((a,b) => b[1].count - a[1].count).slice(0,10);
            if (!sorted.length) { tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:16px;color:var(--text-muted);">No data yet.</td></tr>'; return; }
            tbody.innerHTML = sorted.map(([rule, d], i) =>
                `<tr><td style="color:var(--text-muted);">${i+1}</td><td><code style="font-size:10px;">${escapeHtml(rule)}</code></td><td><span class="sec-engine ${d.engine}">${d.engine}</span></td><td><strong>${d.count}</strong></td></tr>`
            ).join('');
        }

        function renderTopCountries(alerts) {
            const el = document.getElementById('topCountriesDiv');
            if (!el) return;
            const map = {};
            (alerts||[]).forEach(a => {
                if (a.src_country) { map[a.src_country] = (map[a.src_country]||0) + 1; }
            });
            const sorted = Object.entries(map).sort((a,b) => b[1]-a[1]).slice(0,8);
            if (!sorted.length) { el.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-muted);font-size:12px;">No geo data yet.</div>'; return; }
            const total = sorted.reduce((s,[,v]) => s+v, 0) || 1;
            el.innerHTML = sorted.map(([cc, cnt]) => {
                const pct = Math.round(cnt / total * 100);
                return `<div style="display:flex;align-items:center;gap:8px;font-size:11px;margin-bottom:5px;">
                    <span style="width:30px;font-weight:700;color:var(--primary);">${escapeHtml(cc)}</span>
                    <div style="flex:1;background:var(--border);border-radius:3px;height:6px;"><div style="width:${pct}%;background:var(--primary);border-radius:3px;height:100%;"></div></div>
                    <span style="width:24px;color:var(--text-muted);">${cnt}</span>
                </div>`;
            }).join('');
        }

        // ─── CSV Export ──────────────────────────────────────────────────
        async function exportSecurityCsv() {
            try {
                const res = await fetch('/api/security/alerts');
                const alerts = await res.json();
                if (!alerts || !alerts.length) { toast('No alerts to export', 'info'); return; }
                const header = ['Time','Engine','Severity','Rule','Title','Detail','Source','Destination','Protocol','Action','Interface','Country Src','Country Dst'];
                const rows = alerts.map(a => [
                    new Date(a.ts*1000).toISOString(), a.engine, a.severity, a.rule_id, a.title,
                    (a.detail||'').replace(/,/g,''), a.src, a.dst, a.protocol, a.action||'', a.interface||'', a.src_country||'', a.dst_country||''
                ].map(v => `"${String(v).replace(/"/g,'""')}"`).join(','));
                const csv = [header.join(','), ...rows].join('\n');
                const blob = new Blob([csv], { type: 'text/csv' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = 'pktana-security-alerts.csv'; a.click();
                URL.revokeObjectURL(url);
                toast(`Exported ${alerts.length} alerts as CSV`, 'success');
            } catch(e) { toast('Export failed: ' + e, 'error'); }
        }

        window.toggleSecurityFeature = toggleSecurityFeature;
        window.loadSecurityConfig = loadSecurityConfig;
        window.loadSecurityAlerts = loadSecurityAlerts;
        window.clearSecurityAlerts = clearSecurityAlerts;
        window.showSecuritySub = showSecuritySub;
        window.setEngineAction = setEngineAction;
        window.setRedirectTarget = setRedirectTarget;
        window.setRuleAction = setRuleAction;
        window.jumpToSecurityFlow = jumpToSecurityFlow;
        window.refreshSecurityPanel = refreshSecurityPanel;
        window.addPolicyRule = addPolicyRule;
        window.savePolicyRules = savePolicyRules;
        window.removePolicyRule = removePolicyRule;
        window.updatePolicyField = updatePolicyField;
        window.filterSecurityByIface = filterSecurityByIface;
        window.loadSecurityInterfaces = loadSecurityInterfaces;
        window.addCustomDlpIdentifier = addCustomDlpIdentifier;
        window.saveCustomDlpIdentifiers = saveCustomDlpIdentifiers;
        window.saveBuiltinDlpToggles = saveBuiltinDlpToggles;
        window.saveCustomIdpsRules = saveCustomIdpsRules;
        window.validateCustomIdpsRules = validateCustomIdpsRules;
        window.saveJa3Blocklist = saveJa3Blocklist;
        window.saveBuiltinIdpsToggles = saveBuiltinIdpsToggles;
        window.exportSecurityCsv = exportSecurityCsv;

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

        async function showCreateSessionDialog() {
            const iface = await modal({ title: 'New Capture Session', body: 'Enter the interface name to monitor:', confirmText: 'Create', inputPlaceholder: 'e.g. eth0, any, ens3', inputDefault: '' });
            if (!iface || !iface.trim()) return;
            try {
                const res = await fetch('/api/sessions/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interface: iface.trim() }) });
                const data = await res.json();
                toast('Session created: ' + data.id, 'success');
                loadSessions();
            } catch (e) { toast('Error creating session: ' + e, 'error'); }
        }

        function stopSession(id) {
            fetch(`/api/sessions/${id}/stop`, { method: 'POST' })
                .then(() => { toast('Session stopped', 'warn'); loadSessions(); })
                .catch(e => toast('Error: ' + e, 'error'));
        }

        async function deleteSession(id) {
            const ok = await modal({ title: 'Delete Session', body: 'Remove this session? Captured data will be lost.', confirmText: 'Delete', danger: true });
            if (!ok) return;
            fetch(`/api/sessions/${id}`, { method: 'DELETE' })
                .then(() => { toast('Session deleted', 'info'); loadSessions(); })
                .catch(e => toast('Error: ' + e, 'error'));
        }
    </script>
</head>
<body>
    <!-- Landing Page -->
    <div class="landing-page" id="landingPage">
        <div class="landing-bg-orb o1"></div>
        <div class="landing-bg-orb o2"></div>
        <div class="landing-bg-orb o3"></div>
        <div class="landing-inner">
            <div class="landing-icon-wrap">
                <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                </svg>
            </div>
            <div class="landing-brand">pktana</div>
            <div class="landing-tagline">Enterprise Network Packet Analyzer</div>
            <div class="landing-sub">Real-time Deep Packet Inspection · Layer 2–7 · GeoIP · Flow Analysis</div>
            <div class="landing-pills">
                <span>100+ Protocols</span>
                <span>TLS · QUIC · gRPC</span>
                <span>Wireshark-style UI</span>
                <span>Process Mapping</span>
                <span>XDP / DPDK</span>
                <span>BPF Filters</span>
            </div>
            <button class="landing-btn" onclick="enterDashboard()">Launch Dashboard →</button>
        </div>
    </div>

    <!-- Top Navbar (Fixed at top) -->
    <div class="navbar" id="mainNavbar" style="display:none;">
        <div class="logo" style="gap:10px;">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
            <span>pktana</span>
        </div>
        <div id="navLiveBadge" class="nav-live-badge">
            <div class="nav-live-dot"></div>
            <span>LIVE</span>
            <span id="navLivePkts" style="opacity:0.75;font-weight:500;">0 pkts</span>
        </div>
        <div class="nav-controls" style="font-size:12px; color:var(--text-muted); font-weight:500; letter-spacing:0.3px;">
            Network Packet Analyzer
        </div>
    </div>

    <!-- VS Code Style Layout -->
    <div class="vscode-layout" id="vscodeLayout" style="display:none;">
        <!-- Vertical Activity Bar (Left Sidebar) -->
        <div class="activity-bar">
            <div class="activity-icon active" onclick="switchTab('serverinfo')" title="Server Info">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                    <line x1="6" y1="6" x2="6.01" y2="6"></line>
                    <line x1="6" y1="18" x2="6.01" y2="18"></line>
                </svg>
                <div class="icon-label">Server Info</div>
            </div>
            <div class="activity-icon" onclick="switchTab('pcap')" title="PCAP Analyzer">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="16" y1="13" x2="8" y2="13"></line>
                    <line x1="16" y1="17" x2="8" y2="17"></line>
                    <polyline points="10 9 9 9 8 9"></polyline>
                </svg>
                <div class="icon-label">PCAP File</div>
            </div>
            <div class="activity-icon" onclick="switchTab('connections')" title="Connections">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="18" cy="5" r="3"></circle>
                    <circle cx="6" cy="12" r="3"></circle>
                    <circle cx="18" cy="19" r="3"></circle>
                    <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
                    <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
                </svg>
                <div class="icon-label">Connections</div>
            </div>
            <div class="activity-icon" onclick="switchTab('terminal')" title="Terminal">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="4 17 10 11 4 5"></polyline>
                    <line x1="12" y1="19" x2="20" y2="19"></line>
                </svg>
                <div class="icon-label">Terminal</div>
            </div>
            <div class="activity-icon" onclick="switchTab('routes')" title="Routing Table">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="3 6 5 12 3 18"></polyline>
                    <polyline points="21 6 19 12 21 18"></polyline>
                    <line x1="8" y1="6" x2="16" y2="6"></line>
                    <line x1="8" y1="12" x2="16" y2="12"></line>
                    <line x1="8" y1="18" x2="16" y2="18"></line>
                </svg>
                <div class="icon-label">Routes</div>
            </div>
            <div class="activity-icon" onclick="switchTab('nics')" title="Network Interfaces (NIC Stats)">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="2" y="6" width="20" height="12" rx="2"></rect>
                    <circle cx="8" cy="12" r="1.5" fill="currentColor"></circle>
                    <circle cx="12" cy="12" r="1.5" fill="currentColor"></circle>
                    <circle cx="16" cy="12" r="1.5" fill="currentColor"></circle>
                </svg>
                <div class="icon-label">NICs</div>
            </div>
            <div class="activity-icon" onclick="switchTab('geoip')" title="GeoIP Lookup">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="2" y1="12" x2="22" y2="12"></line>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                </svg>
                <div class="icon-label">GeoIP</div>
            </div>
            <div class="activity-icon" id="securityNavIcon" onclick="switchTab('security')" title="Security (DLP / IDPS)">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>
                <div class="icon-label">Security</div>
            </div>
            <!-- Bottom Controls -->
            <div class="activity-bar-bottom">
                <button class="theme-toggle" onclick="toggleTheme()" title="Toggle Light/Dark Theme">🌙</button>
                <button class="stop-daemon-btn" onclick="stopDaemon()" title="Stop pktana Daemon">Stop</button>
            </div>
        </div>

        <!-- Main Content Area -->
        <div class="main-content">
            <!-- Per-session window strip (visible only for interface-scoped tabs) -->
            <div id="sessionStripGlobal" class="session-strip" style="display:none;"></div>
            <!-- Per-window inner tab bar (Packets/Flows/Stats/Hardware) -->
            <div id="windowTabs" class="window-tabs" style="display:none;">
                <button class="win-tab active" data-tab="dashboard" onclick="switchTab('dashboard')">Packets</button>
                <button class="win-tab" data-tab="flows" onclick="switchTab('flows')">Flows</button>
                <button class="win-tab" data-tab="stats" onclick="switchTab('stats')">Protocols</button>
                <button class="win-tab" data-tab="hardware" onclick="switchTab('hardware')">Hardware</button>
            </div>
            <!-- Content Panels (no horizontal tabs) -->
    <div class="container">
        <input type="hidden" id="currentIface" value="">

        <!-- Server Info Panel -->
        <div id="serverinfo" class="panel active">
            <div class="panel-scroll">
                <div class="page-header">
                    <div>
                        <h2>Server Info</h2>
                        <p>Monitor host resources, pick a capture interface, configure security engines, and manage live sessions.</p>
                    </div>
                </div>

                <div class="serverinfo-top">
                    <div class="card">
                        <div class="card-title-lg">Select Interface to Capture</div>
                        <div class="card-subtitle">Click an interface to open a capture window. UP interfaces are highlighted in green.</div>
                        <div class="iface-grid" id="serverInterfacesList">Loading interfaces...</div>
                    </div>
                    <div class="card">
                        <div class="card-title">System Information</div>
                        <div class="kv-list" id="serverContent">Loading...</div>
                    </div>
                </div>

                <div class="card security-section" id="securityFeaturesCard">
                    <div class="card-title">Security Features</div>
                    <div class="card-subtitle">Enable DLP and IDPS engines — related alerts and filters appear automatically when active.</div>
                    <div class="feature-grid">
                        <div class="feature-panel" id="dlpFeatureCard">
                            <div class="feature-header">
                                <div style="display:flex;gap:10px;align-items:flex-start;min-width:0;">
                                    <div class="feature-icon dlp">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                    </div>
                                    <div style="min-width:0;">
                                        <div class="feature-title">Data Loss Prevention (DLP)</div>
                                        <div class="feature-desc">Detects cleartext credentials, PAN/SSN patterns, private keys, AWS keys, and sensitive HTTP payloads in live traffic.</div>
                                    </div>
                                </div>
                                <label class="toggle-switch" title="Enable DLP engine">
                                    <input type="checkbox" id="dlpToggle" onchange="toggleSecurityFeature('dlp', this.checked)">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>
                            <div class="feature-rules" id="dlpRulesList">
                                <span class="rule-chip">HTTP Basic Auth</span>
                                <span class="rule-chip">PAN (Luhn)</span>
                                <span class="rule-chip">SSN</span>
                                <span class="rule-chip">Private Keys</span>
                                <span class="rule-chip">AWS Keys</span>
                                <span class="rule-chip">Cleartext Secrets</span>
                                <span class="rule-chip">Large HTTP Body</span>
                            </div>
                            <div class="policy-row">
                                <label>Default action</label>
                                <select id="dlpActionSelect" class="form-input" onchange="setEngineAction('dlp', this.value)" style="width:140px;">
                                    <option value="monitor">Monitor</option>
                                    <option value="pass">Pass</option>
                                    <option value="drop">Drop</option>
                                    <option value="redirect">Redirect</option>
                                    <option value="quarantine">Quarantine</option>
                                </select>
                            </div>
                        </div>
                        <div class="feature-panel" id="idpsFeatureCard">
                            <div class="feature-header">
                                <div style="display:flex;gap:10px;align-items:flex-start;min-width:0;">
                                    <div class="feature-icon idps">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                                    </div>
                                    <div style="min-width:0;">
                                        <div class="feature-title">Intrusion Detection / Prevention (IDPS)</div>
                                        <div class="feature-desc">Monitors DPI risk signals, suspicious ports, telnet, NTP amplification, DNS tunneling, and large ICMP probes.</div>
                                    </div>
                                </div>
                                <label class="toggle-switch" title="Enable IDPS engine">
                                    <input type="checkbox" id="idpsToggle" onchange="toggleSecurityFeature('idps', this.checked)">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>
                            <div class="feature-rules" id="idpsRulesList">
                                <span class="rule-chip">DPI Risk Signals</span>
                                <span class="rule-chip">High Risk Score</span>
                                <span class="rule-chip">Suspicious Ports</span>
                                <span class="rule-chip">Telnet</span>
                                <span class="rule-chip">NTP Amplification</span>
                                <span class="rule-chip">DNS Tunnel</span>
                                <span class="rule-chip">Large ICMP</span>
                            </div>
                            <div class="policy-row">
                                <label>Default action</label>
                                <select id="idpsActionSelect" class="form-input" onchange="setEngineAction('idps', this.value)" style="width:140px;">
                                    <option value="monitor">Monitor</option>
                                    <option value="pass">Pass</option>
                                    <option value="drop">Drop</option>
                                    <option value="redirect">Redirect</option>
                                    <option value="quarantine">Quarantine</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="policy-row" style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border);">
                        <label>Redirect target</label>
                        <input type="text" id="redirectTargetInput" class="form-input" placeholder="e.g. 10.0.0.1:8443 or sink.internal" style="flex:1;min-width:200px;" onchange="setRedirectTarget(this.value)">
                        <span style="font-size:11px;color:var(--text-muted);">Used when action is Redirect</span>
                    </div>
                    <div class="policy-row" style="margin-top:10px;">
                        <label>Advanced</label>
                        <button class="btn" onclick="switchTab('security'); showSecuritySub('policy');">Conditional Policy Rules</button>
                        <button class="btn" onclick="switchTab('security'); showSecuritySub('interfaces');">DLP/IDPS by Interface</button>
                        <span style="font-size:11px;color:var(--text-muted);">Match actions by src/dst IP, CIDR, country, interface</span>
                    </div>
                </div>

                <div class="card sessions-card">
                    <div class="sessions-header">
                        <div class="card-title">Active Capture Sessions</div>
                        <div class="sessions-actions">
                            <span class="session-count-badge" id="sessionCountBadge">0 sessions</span>
                            <button class="primary-btn" onclick="showCreateSessionDialog()">
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;margin-right:5px;vertical-align:middle;"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                                New Session
                            </button>
                            <button class="btn" onclick="loadSessions()">Refresh</button>
                        </div>
                    </div>
                    <div id="sessionsList" class="sessions-table-wrap">
                        <div class="sessions-empty">
                            <div class="sessions-empty-icon">📡</div>
                            <div class="sessions-empty-title">No Active Sessions</div>
                            <div class="sessions-empty-hint">Start monitoring by clicking an interface above, or create a new session manually.</div>
                            <button class="primary-btn" onclick="showCreateSessionDialog()">Create Session</button>
                        </div>
                    </div>
                </div>

                <div class="card sessions-card" id="securityPreviewCard" style="display:none;">
                    <div class="sessions-header">
                        <div class="card-title">Recent Security Alerts</div>
                        <div class="sessions-actions">
                            <button class="btn" onclick="switchTab('security')">Open Security Panel</button>
                            <button class="btn" onclick="loadSecurityAlerts()">Refresh</button>
                        </div>
                    </div>
                    <div id="securityPreviewList" class="sessions-table-wrap" style="max-height:220px;border:none;background:transparent;"></div>
                </div>
            </div>
        </div>

        <!-- Security Panel (DLP / IDPS) -->
        <div id="security" class="panel">
            <div class="panel-scroll">
                <div class="page-header">
                    <div>
                        <h2>Security Center</h2>
                        <p>Live DLP content inspection and Suricata-style IDPS alerts from active capture sessions.</p>
                    </div>
                    <div class="sec-status-row">
                        <span class="sec-status-pill" id="secPillDlp"><span class="dot"></span>DLP Off</span>
                        <span class="sec-status-pill" id="secPillIdps"><span class="dot"></span>IDPS Off</span>
                    </div>
                </div>
                <div class="sec-stats" id="securityStats">
                    <div class="sec-stat dlp"><div class="sec-stat-val" id="statDlp">0</div><div class="sec-stat-lbl">DLP Alerts</div></div>
                    <div class="sec-stat idps"><div class="sec-stat-val" id="statIdps">0</div><div class="sec-stat-lbl">IDPS Alerts</div></div>
                    <div class="sec-stat critical"><div class="sec-stat-val" id="statCritical">0</div><div class="sec-stat-lbl">Critical</div></div>
                    <div class="sec-stat high"><div class="sec-stat-val" id="statHigh">0</div><div class="sec-stat-lbl">High</div></div>
                    <div class="sec-stat"><div class="sec-stat-val" id="statDropped">0</div><div class="sec-stat-lbl">Dropped</div></div>
                    <div class="sec-stat"><div class="sec-stat-val" id="statRedirected">0</div><div class="sec-stat-lbl">Redirected</div></div>
                    <div class="sec-stat"><div class="sec-stat-val" id="statScanned">0</div><div class="sec-stat-lbl">Packets Scanned</div></div>
                </div>

                <div class="sec-sub-nav">
                    <button class="sec-sub-btn active" id="secSubBtnAlerts" onclick="showSecuritySub('alerts')">Alerts</button>
                    <button class="sec-sub-btn" id="secSubBtnDlpFlows" onclick="showSecuritySub('dlp-flows')">DLP Flows</button>
                    <button class="sec-sub-btn" id="secSubBtnIdpsFlows" onclick="showSecuritySub('idps-flows')">IDPS Flows</button>
                    <button class="sec-sub-btn" id="secSubBtnPolicy" onclick="showSecuritySub('policy')">Rule Policy</button>
                    <button class="sec-sub-btn" id="secSubBtnInterfaces" onclick="showSecuritySub('interfaces')">By Interface</button>
                    <button class="sec-sub-btn" id="secSubBtnCustomDlp" onclick="showSecuritySub('custom-dlp')">Custom DLP</button>
                    <button class="sec-sub-btn" id="secSubBtnCustomIdps" onclick="showSecuritySub('custom-idps')">Custom IDPS</button>
                    <button class="sec-sub-btn" id="secSubBtnThreat" onclick="showSecuritySub('threat')">Threat Intel</button>
                </div>

                <div class="sec-toolbar">
                    <button class="btn" onclick="refreshSecurityPanel()">↺ Refresh</button>
                    <button class="btn" onclick="exportSecurityCsv()" title="Export alerts as CSV">⬇ Export CSV</button>
                    <button class="btn" onclick="clearSecurityAlerts()" style="background:rgba(220,38,38,0.15);color:#fca5a5;border-color:rgba(220,38,38,0.3);">✕ Clear All</button>
                    <span class="hint">Click any row to jump to matching packets.</span>
                </div>

                <div id="secSubAlerts" class="sec-sub-panel active">
                    <div class="card" style="padding:0;overflow:hidden;">
                        <div class="sessions-table-wrap" style="max-height:calc(100vh - 420px);border:none;border-radius:8px;">
                            <table class="settings-table">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Engine</th>
                                        <th>Severity</th>
                                        <th>Verdict</th>
                                        <th>Interface</th>
                                        <th>Source</th>
                                        <th>Destination</th>
                                        <th>Rule</th>
                                        <th>Title</th>
                                        <th>Policy</th>
                                    </tr>
                                </thead>
                                <tbody id="securityAlertsBody">
                                    <tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text-muted);">Enable DLP or IDPS and start capture to see alerts.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div id="secSubDlpFlows" class="sec-sub-panel">
                    <div class="card" style="padding:0;overflow:hidden;">
                        <div class="sessions-table-wrap" style="max-height:calc(100vh - 420px);border:none;border-radius:8px;">
                            <table class="settings-table">
                                <thead>
                                    <tr>
                                        <th>Interface</th>
                                        <th>Flow</th>
                                        <th>Proto</th>
                                        <th>Source</th>
                                        <th>Destination</th>
                                        <th>Geo</th>
                                        <th>Alerts</th>
                                        <th>Top Rule</th>
                                        <th>Verdict</th>
                                        <th>Bytes</th>
                                    </tr>
                                </thead>
                                <tbody id="dlpFlowsBody">
                                    <tr><td colspan="10" style="text-align:center;padding:32px;color:var(--text-muted);">No DLP flows yet.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div id="secSubIdpsFlows" class="sec-sub-panel">
                    <div class="card" style="padding:0;overflow:hidden;">
                        <div class="sessions-table-wrap" style="max-height:calc(100vh - 420px);border:none;border-radius:8px;">
                            <table class="settings-table">
                                <thead>
                                    <tr>
                                        <th>Interface</th>
                                        <th>Flow</th>
                                        <th>Proto</th>
                                        <th>Source</th>
                                        <th>Destination</th>
                                        <th>Geo</th>
                                        <th>Alerts</th>
                                        <th>Top Rule</th>
                                        <th>Verdict</th>
                                        <th>Bytes</th>
                                    </tr>
                                </thead>
                                <tbody id="idpsFlowsBody">
                                    <tr><td colspan="10" style="text-align:center;padding:32px;color:var(--text-muted);">No IDPS flows yet.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div id="secSubPolicy" class="sec-sub-panel">
                    <div class="card" style="margin-bottom:14px;">
                        <div class="card-title">Conditional Policy Rules</div>
                        <div class="card-subtitle">Apply monitor / pass / drop / redirect / quarantine based on interface, source/dest IP or CIDR, country code, and detection rule. Higher priority wins.</div>
                        <div style="display:flex;gap:8px;margin:12px 0;">
                            <button class="btn" onclick="addPolicyRule()">+ Add Rule</button>
                            <button class="btn btn-primary" onclick="savePolicyRules()">Save Policy Rules</button>
                        </div>
                        <div class="sessions-table-wrap" style="max-height:280px;border-radius:6px;overflow-x:auto;">
                            <table class="settings-table">
                                <thead>
                                    <tr><th>Name</th><th>On</th><th>Pri</th><th>Engine</th><th>Iface</th><th>Src IP</th><th>Dst IP</th><th>Src CC</th><th>Dst CC</th><th>Det. Rule</th><th>Action</th><th>Redirect</th><th></th></tr>
                                </thead>
                                <tbody id="policyRulesBody">
                                    <tr><td colspan="13" style="text-align:center;padding:24px;color:var(--text-muted);">Loading…</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-title">Per-Rule Actions</div>
                        <div class="card-subtitle">Override default engine action for individual detection rules when no conditional policy matches.</div>
                        <div class="sessions-table-wrap" style="max-height:360px;border-radius:6px;">
                            <table class="settings-table">
                                <thead>
                                    <tr><th>Engine</th><th>Rule</th><th>Title</th><th>Severity</th><th>Action</th></tr>
                                </thead>
                                <tbody id="securityRulesBody">
                                    <tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);">Loading rules…</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div id="secSubInterfaces" class="sec-sub-panel">
                    <div class="card" style="padding:0;overflow:hidden;">
                        <div style="padding:14px 18px;border-bottom:1px solid var(--border);">
                            <div class="card-title" style="margin:0;">DLP / IDPS by Interface</div>
                            <div class="card-subtitle" style="margin:4px 0 0;">Per-interface alert counts, flows, and enforcement stats from active capture sessions.</div>
                        </div>
                        <div class="sessions-table-wrap" style="max-height:calc(100vh - 420px);border:none;border-radius:8px;">
                            <table class="settings-table">
                                <thead>
                                    <tr>
                                        <th>Interface</th>
                                        <th>DLP Alerts</th>
                                        <th>IDPS Alerts</th>
                                        <th>DLP Flows</th>
                                        <th>IDPS Flows</th>
                                        <th>Critical</th>
                                        <th>High</th>
                                        <th>Dropped</th>
                                        <th>Redirected</th>
                                        <th>Scanned</th>
                                    </tr>
                                </thead>
                                <tbody id="securityInterfacesBody">
                                    <tr><td colspan="10" style="text-align:center;padding:32px;color:var(--text-muted);">No per-interface stats yet.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Custom DLP Identifiers -->
                <div id="secSubCustomDlp" class="sec-sub-panel">
                    <div class="card" style="margin-bottom:14px;">
                        <div class="card-title">Custom DLP Identifiers</div>
                        <div class="card-subtitle">Add custom regex or keyword patterns for DLP detection. Use <code>regex:pattern</code> prefix for regular expressions, or plain text for substring match.</div>
                        <div style="display:flex;gap:8px;margin:12px 0;flex-wrap:wrap;">
                            <button class="btn btn-primary" onclick="addCustomDlpIdentifier()">+ Add Identifier</button>
                            <button class="btn" onclick="saveCustomDlpIdentifiers()">Save All</button>
                        </div>
                        <div class="sessions-table-wrap" style="max-height:300px;border-radius:6px;">
                            <table class="settings-table">
                                <thead>
                                    <tr><th>On</th><th>Name</th><th>Pattern</th><th>Category</th><th>Severity</th><th></th></tr>
                                </thead>
                                <tbody id="customDlpBody">
                                    <tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">No custom identifiers yet.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-title">Built-in DLP Identifier Status</div>
                        <div class="card-subtitle">Enable or disable built-in DLP detection rules individually.</div>
                        <div id="builtinDlpList" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;">Loading…</div>
                        <div style="margin-top:12px;display:flex;gap:8px;">
                            <button class="btn" onclick="saveBuiltinDlpToggles()">Save Toggles</button>
                        </div>
                    </div>
                </div>

                <!-- Custom IDPS Rules -->
                <div id="secSubCustomIdps" class="sec-sub-panel">
                    <div class="card" style="margin-bottom:14px;">
                        <div class="card-title">Custom Suricata-style Rules</div>
                        <div class="card-subtitle">Write custom IDS rules in Suricata format. Example: <code style="font-size:10px;">alert tcp any any -> any 80 (msg:"Test"; content:"evil"; sid:9000001;)</code></div>
                        <textarea id="customIdpsRulesArea" class="form-input" style="width:100%;min-height:180px;font-family:monospace;font-size:11px;resize:vertical;margin:10px 0;" placeholder="# One rule per line&#10;alert tcp any any -> any 80 (msg:&quot;ET WEB Custom&quot;; content:&quot;payload&quot;; nocase; sid:9000001;)"></textarea>
                        <div style="display:flex;gap:8px;flex-wrap:wrap;">
                            <button class="btn btn-primary" onclick="saveCustomIdpsRules()">Save Rules</button>
                            <button class="btn" onclick="validateCustomIdpsRules()">Validate Syntax</button>
                            <span id="idpsRuleValidationMsg" style="font-size:11px;align-self:center;color:var(--text-muted);"></span>
                        </div>
                    </div>
                    <div class="card" style="margin-bottom:14px;">
                        <div class="card-title">JA3 TLS Fingerprint Blocklist</div>
                        <div class="card-subtitle">Add MD5 JA3 fingerprints to block/alert on (one per line). These are matched against incoming TLS ClientHello fingerprints.</div>
                        <textarea id="ja3BlocklistArea" class="form-input" style="width:100%;min-height:100px;font-family:monospace;font-size:11px;resize:vertical;margin:10px 0;" placeholder="# One MD5 JA3 fingerprint per line&#10;e7d705a3286e19ea42f587b6d71c4c82"></textarea>
                        <button class="btn btn-primary" onclick="saveJa3Blocklist()">Save JA3 Blocklist</button>
                    </div>
                    <div class="card">
                        <div class="card-title">Built-in IDPS Rule Status</div>
                        <div class="card-subtitle">Enable or disable built-in IDPS signatures by SID. Disabled rules will not fire alerts.</div>
                        <div id="builtinIdpsList" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;max-height:220px;overflow-y:auto;">Loading…</div>
                        <div style="margin-top:12px;"><button class="btn" onclick="saveBuiltinIdpsToggles()">Save Toggles</button></div>
                    </div>
                </div>

                <!-- Threat Intelligence Overview -->
                <div id="secSubThreat" class="sec-sub-panel">
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;margin-bottom:14px;">
                        <div class="card">
                            <div class="card-title">Alert Timeline (Last 50)</div>
                            <svg id="secThreatTimeline" width="100%" height="60" style="display:block;"></svg>
                            <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">Each bar = one alert. Red=critical, orange=high, yellow=medium, blue=info.</div>
                        </div>
                        <div class="card">
                            <div class="card-title">Severity Breakdown</div>
                            <div id="secSeverityBars" style="display:flex;flex-direction:column;gap:6px;margin-top:8px;"></div>
                        </div>
                    </div>
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;">
                        <div class="card">
                            <div class="card-title">Top Attackers (by Alert Count)</div>
                            <table class="settings-table" style="margin-top:6px;">
                                <thead><tr><th>#</th><th>Source IP</th><th>Alerts</th><th>Top Rule</th></tr></thead>
                                <tbody id="topAttackersBody"><tr><td colspan="4" style="text-align:center;padding:16px;color:var(--text-muted);">No data yet.</td></tr></tbody>
                            </table>
                        </div>
                        <div class="card">
                            <div class="card-title">Top Rules Hit</div>
                            <table class="settings-table" style="margin-top:6px;">
                                <thead><tr><th>#</th><th>Rule</th><th>Engine</th><th>Hits</th></tr></thead>
                                <tbody id="topRulesBody"><tr><td colspan="4" style="text-align:center;padding:16px;color:var(--text-muted);">No data yet.</td></tr></tbody>
                            </table>
                        </div>
                        <div class="card">
                            <div class="card-title">Top Source Countries</div>
                            <div id="topCountriesDiv" style="margin-top:6px;">
                                <div style="text-align:center;padding:16px;color:var(--text-muted);font-size:12px;">No geo data yet.</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- PCAP Panel -->
        <div id="pcap" class="panel">
            <div class="panel-scroll">
                <div class="page-header">
                    <div>
                        <h2>PCAP Analyzer</h2>
                        <p>Analyze packet captures from the server filesystem or upload a file from your browser.</p>
                    </div>
                </div>
                <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px;">
                    <div class="card">
                        <div class="card-title">Analyze PCAP on Server</div>
                        <div class="card-subtitle">Provide an absolute path to a PCAP file on the server filesystem.</div>
                        <div style="display:flex; gap:10px;">
                            <input type="text" id="pcapRead" class="form-input" placeholder="/var/log/capture.pcap" style="flex-grow:1;">
                            <button class="primary-btn" onclick="analyzePcap()">
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;margin-right:5px;vertical-align:middle;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Analyze
                            </button>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-title">Upload PCAP from Browser</div>
                        <div class="drop-zone" id="pcapDropZone" onclick="document.getElementById('pcapUpload').click()" ondragover="event.preventDefault();this.classList.add('drag-over')" ondragleave="this.classList.remove('drag-over')" ondrop="event.preventDefault();this.classList.remove('drag-over');document.getElementById('pcapUpload').files=event.dataTransfer.files;uploadPcap()">
                            <div class="drop-zone-icon">
                                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                            </div>
                            <p>Drop .pcap / .pcapng here</p>
                            <small>or click to browse</small>
                        </div>
                        <input type="file" id="pcapUpload" style="display:none;" accept=".pcap,.pcapng,.cap" onchange="uploadPcap()">
                        <div style="font-size:11px; color:var(--text-muted); margin-top:8px; text-align:center;">Upload requires backend multipart API (planned)</div>
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
                        <optgroup label="Security (DLP / IDPS)" id="securityFilterGroup">
                            <option value="security_alert">🛡 All Security Alerts</option>
                            <option value="dlp_alert">🔒 DLP Hits Only</option>
                            <option value="idps_alert">⚠ IDPS Hits Only</option>
                            <option value="security_drop">🚫 Dropped (Drop action)</option>
                            <option value="security_pass">✓ Passed Through</option>
                            <option value="security_redirect">↪ Redirected</option>
                            <option value="security_quarantine">⛔ Quarantined</option>
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
                    <button class="icon-btn" onclick="toggleLayoutDir()" title="Toggle Split Direction (Alt+L)">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="18" rx="1"/><rect x="14" y="3" width="7" height="18" rx="1"/></svg>
                    </button>
                    <button class="icon-btn" onclick="togglePane('paneRight')" title="Toggle Details Panel (Alt+D)">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="15" y1="3" x2="15" y2="21"/></svg>
                    </button>
                    <button class="icon-btn" onclick="toggleHex()" title="Toggle Hex View (Alt+H)">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h2v12H4zm6-1 4 7-4 7m8-13v12"/></svg>
                    </button>
                </div>
                <div class="toolbar-group" style="gap: 4px;">
                    <button class="icon-btn" onclick="clearPackets()" title="Clear packets (Alt+C)" id="btnClear">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6m4-6v6"/><path d="M9 6V4h6v2"/></svg>
                        Clear
                    </button>
                    <button class="icon-btn" onclick="exportPacketsCsv()" title="Export as CSV (Alt+E)">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        CSV
                    </button>
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
                        <tbody id="pktTableBody">
                            <tr id="emptyPacketState"><td colspan="7">
                                <div class="empty-state">
                                    <div class="empty-state-icon">
                                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                                    </div>
                                    <div class="empty-state-title">No packets captured yet</div>
                                    <div class="empty-state-sub">Select an interface in <strong>Server Info</strong>, then click <strong>▶ Start Capture</strong></div>
                                    <span class="kbd">Space</span><span style="font-size:11px;color:var(--text-muted);"> to start / pause</span>
                                </div>
                            </td></tr>
                        </tbody>
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
                <div style="display:flex;gap:20px;align-items:center;">
                    <span id="sb-rate" style="color:var(--primary);font-weight:700;min-width:80px;text-align:right;"></span>
                    <span id="sb-stats">Packets: 0 | Displayed: 0 | Bytes: 0 B</span>
                </div>
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
            <div class="panel-scroll">
                <div class="grid-3" style="padding:0;">
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
        </div>

        <!-- Hardware Panel -->
        <div id="hardware" class="panel">
            <div class="hw-scroll">
                <div class="hw-top-grid">
                    <div class="card"><div class="card-title">Interface Config</div><div class="kv-list" id="ifaceConfig">Select an interface above.</div></div>
                    <div class="card"><div class="card-title">Hardware Status</div><div class="kv-list" id="hwStatus">Select an interface above.</div></div>
                    <div class="card"><div class="card-title">Dataplane Path</div><div class="kv-list" id="dpStatus">Select an interface above.</div></div>
                </div>
                <div class="hw-top-grid">
                    <div class="card"><div class="card-title">Pinned BPF <span id="hwPinnedCount" style="font-weight:normal;color:var(--text-muted);"></span></div><div class="kv-list" id="hwPinnedBpf" style="max-height:180px;overflow:auto;">—</div></div>
                    <div class="card"><div class="card-title">XDP Dispatchers <span id="hwDispCount" style="font-weight:normal;color:var(--text-muted);"></span></div><div class="kv-list" id="hwDispatchers" style="max-height:180px;overflow:auto;">—</div></div>
                    <div class="card"><div class="card-title">Network Namespace</div><div class="kv-list" id="hwNetNs">—</div></div>
                </div>
                <div class="card">
                    <div class="card-title">Ethtool Report</div>
                    <div id="ethtoolDetail" class="hw-ethtool-grid">Select an interface above.</div>
                </div>
            </div>
        </div>

        <!-- Connections Panel -->
        <div id="connections" class="panel">
            <div class="panel-scroll">
                <div class="card">
                    <div class="sessions-header">
                        <div class="card-title">Active Sockets (TCP/UDP)</div>
                        <div class="sessions-actions">
                            <input type="text" class="form-input" placeholder="Search..." onkeyup="filterTable('connContent', this.value)" style="padding:4px 8px;">
                            <button class="btn" onclick="loadConnections()">Refresh</button>
                        </div>
                    </div>
                    <div id="connContent" class="sessions-table-wrap" style="max-height:calc(100vh - 220px);">Loading...</div>
                </div>
            </div>
        </div>

        <!-- Routes Panel -->
        <div id="routes" class="panel">
            <div class="panel-scroll">
                <div class="card">
                    <div class="sessions-header">
                        <div class="card-title">System Routing Table</div>
                        <div class="sessions-actions">
                            <input type="text" class="form-input" placeholder="Search..." onkeyup="filterTable('routeContent', this.value)" style="padding:4px 8px;">
                            <button class="btn" onclick="loadRoutes()">Refresh</button>
                        </div>
                    </div>
                    <div id="routeContent" class="sessions-table-wrap" style="max-height:calc(100vh - 220px);">Loading...</div>
                </div>
            </div>
        </div>

        <!-- NICs Panel -->
        <div id="nics" class="panel">
            <div class="panel-scroll">
                <div class="card">
                    <div class="sessions-header">
                        <div class="card-title">All Network Interfaces</div>
                        <div class="sessions-actions">
                            <input type="text" class="form-input" placeholder="Search..." onkeyup="filterTable('nicContent', this.value)" style="padding:4px 8px;">
                            <button class="btn" onclick="loadNics()">Refresh</button>
                        </div>
                    </div>
                    <div id="nicContent" class="sessions-table-wrap" style="max-height:calc(100vh - 220px);">Loading...</div>
                </div>
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
                <div style="background: linear-gradient(135deg, #1e293b, #0f172a); color:#94a3b8; border-bottom:1px solid #334155; padding:10px 16px; margin-bottom:0; display: flex; justify-content: space-between; align-items: center;">
                    <div style="display:flex; align-items:center; gap:0;">
                        <div class="term-traffic-lights">
                            <div class="traffic-dot red"    title="Close" onclick="switchTab('serverinfo')"></div>
                            <div class="traffic-dot yellow" title="Clear"  onclick="clearXterm()"></div>
                            <div class="traffic-dot green"  title="Reset"  onclick="resetXterm()"></div>
                        </div>
                        <span style="font-weight:700; font-size:13px; color:#e2e8f0; margin-right:10px;">bash</span>
                        <span style="font-size:11px; color:#475569; margin-right:10px;">—</span>
                        <span style="font-size:11px; color:#38bdf8;">pktana terminal</span>
                    </div>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <button class="btn" onclick="connectTerminalWs()" title="Reconnect" style="padding:3px 10px; font-size:11px; background:transparent; color:#38bdf8; border-color:#334155;">↺ Reconnect</button>
                        <select id="xtermTheme" onchange="changeXtermTheme()" class="form-input" style="padding:3px 8px; font-size:11px; width:130px; background:#0f172a; color:#94a3b8; border-color:#334155;">
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

        let lastRateCheck = { time: 0, count: 0 };
        setInterval(() => {
            const rateEl = document.getElementById('sb-rate');
            if (!rateEl) return;
            if (!isCapturing || !activeId || !Sessions[activeId]) { rateEl.textContent = ''; return; }
            const now = Date.now();
            const S = Sessions[activeId];
            if (lastRateCheck.time > 0) {
                const elapsed = (now - lastRateCheck.time) / 1000;
                const pktDelta = S.packetCount - lastRateCheck.count;
                if (elapsed > 0) rateEl.textContent = Math.round(pktDelta / elapsed) + ' pkt/s';
            }
            lastRateCheck = { time: now, count: S.packetCount };
            const navPkts = document.getElementById('navLivePkts');
            if (navPkts && S) navPkts.textContent = S.packetCount.toLocaleString() + ' pkts';
        }, 1000);

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
                eventSource: null, autoScroll: true,
                streamFilter: ''
            };
        }

        function bindActive(id) {
            // Save the outgoing session's protocol filter before switching
            if (activeId && Sessions[activeId] && activeId !== id) {
                const outFilter = document.getElementById('streamFilter');
                if (outFilter) Sessions[activeId].streamFilter = outFilter.value;
            }
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
            // Restore incoming session's protocol filter
            const filterEl = document.getElementById('streamFilter');
            if (filterEl) filterEl.value = S.streamFilter || '';
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

        function flowAccentColor(proto) {
            const p = (proto || '').toLowerCase();
            if (['tls','ssl','https'].some(x => p.includes(x))) return '#3b82f6';
            if (p.includes('quic'))   return '#6366f1';
            if (p.includes('ssh'))    return '#6366f1';
            if (['http','grpc','websocket'].some(x => p.includes(x))) return '#22c55e';
            if (p.includes('dns'))    return '#06b6d4';
            if (['icmp','arp','bgp','igmp','ospf'].some(x => p.includes(x))) return '#a855f7';
            if (['sip','rtp','rtsp'].some(x => p.includes(x))) return '#f97316';
            if (p === 'tcp')  return '#3b82f6';
            if (p === 'udp')  return '#10b981';
            return '#6b7280';
        }
        function flowRowBg(proto) {
            const p = (proto || '').toLowerCase();
            if (['tls','ssl','https','quic'].some(x => p.includes(x))) return 'rgba(59,130,246,0.06)';
            if (p.includes('ssh'))    return 'rgba(99,102,241,0.06)';
            if (['http','grpc','websocket'].some(x => p.includes(x))) return 'rgba(34,197,94,0.06)';
            if (p.includes('dns'))    return 'rgba(6,182,212,0.06)';
            if (['icmp','arp','bgp'].some(x => p.includes(x))) return 'rgba(168,85,247,0.06)';
            if (['sip','rtp'].some(x => p.includes(x)))  return 'rgba(249,115,22,0.06)';
            if (p === 'tcp') return 'rgba(59,130,246,0.03)';
            if (p === 'udp') return 'rgba(16,185,129,0.03)';
            return 'transparent';
        }
        function catBadgeStyle(cat) {
            const c = (cat || '').toLowerCase();
            if (c.includes('encrypt') || c.includes('tls') || c.includes('secure'))
                return 'background:rgba(59,130,246,0.12);color:#2563eb;border:1px solid rgba(59,130,246,0.3)';
            if (c.includes('web') || c.includes('http'))
                return 'background:rgba(34,197,94,0.12);color:#15803d;border:1px solid rgba(34,197,94,0.3)';
            if (c.includes('dns') || c.includes('resolv'))
                return 'background:rgba(6,182,212,0.12);color:#0e7490;border:1px solid rgba(6,182,212,0.3)';
            if (c.includes('tunnel') || c.includes('vpn'))
                return 'background:rgba(168,85,247,0.12);color:#7e22ce;border:1px solid rgba(168,85,247,0.3)';
            if (c.includes('voip') || c.includes('sip') || c.includes('rtp'))
                return 'background:rgba(249,115,22,0.12);color:#c2410c;border:1px solid rgba(249,115,22,0.3)';
            return 'background:rgba(107,114,128,0.1);color:var(--text-muted);border:1px solid var(--border)';
        }

        function renderFlows() {
            const tbody = document.getElementById('flowContent');
            if (!tbody) return;
            const sortedFlows = Object.values(flows).sort((a, b) => b.bytes - a.bytes).slice(0, 100);
            const maxBytes = sortedFlows.length > 0 ? sortedFlows[0].bytes : 1;
            const RANK_COLORS = ['#f59e0b', '#94a3b8', '#b45309'];
            let html = '';
            for (let i = 0; i < sortedFlows.length; i++) {
                const f = sortedFlows[i];
                const fpk = f.proto.toLowerCase().replace(/[^a-z0-9]/g,'');
                const accent  = flowAccentColor(f.proto);
                const rowBg   = flowRowBg(f.proto);
                const bytesPct = Math.max(3, Math.round(f.bytes / maxBytes * 100));
                const rankBadge = i < 3
                    ? `<span class="flow-rank-badge" style="background:${RANK_COLORS[i]};color:#fff;">${i+1}</span>`
                    : '';
                const catSty = catBadgeStyle(f.category);
                html += `<tr style="cursor:pointer;background:${rowBg};" title="Click to filter packets for this flow" onclick="viewFlowDetails('${f.src}', '${f.dst}')">
                    <td style="border-left:3px solid ${accent};padding-left:8px;">
                        <div style="display:flex;align-items:center;gap:5px;">${rankBadge}<span class="proto-badge proto-${fpk}">${escapeHtml(f.proto)}</span></div>
                    </td>
                    <td style="font-family:monospace;font-size:12px;">${escapeHtml(f.src)}</td>
                    <td style="font-family:monospace;font-size:12px;">${escapeHtml(f.dst)}</td>
                    <td><span class="flow-cat-badge" style="${catSty}">${escapeHtml(f.category || 'Unknown')}</span></td>
                    <td style="text-align:right;font-variant-numeric:tabular-nums;">${f.pkts}</td>
                    <td>
                        <div class="flow-bytes-cell">
                            <span style="white-space:nowrap;font-variant-numeric:tabular-nums;">${formatBytes(f.bytes)}</span>
                            <div class="flow-bytes-bar"><div class="flow-bytes-fill" style="width:${bytesPct}%;background:linear-gradient(90deg,${accent},${accent}99);"></div></div>
                        </div>
                    </td>
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
                const pk = p.toLowerCase().replace(/[^a-z0-9]/g,'');
                const col = protoColor(p);
                pHtml += `<div class="proto-bar-wrap">
                    <div class="proto-bar-label">
                        <strong><span class="proto-bar-dot" style="background:${col};"></span>${p}</strong>
                        <span>${formatBytes(s.bytes)} &nbsp;${pct}%</span>
                    </div>
                    <div class="proto-bar-track">
                        <div class="proto-bar-fill" style="width:${pct}%;background:${col};"></div>
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
            
            if (savedTheme === 'light') {
                body.classList.add('light-theme');
                if (themeBtn) themeBtn.textContent = '🌙';
            } else {
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
                'dhcp_dora': 'dhcp-dora',
                'security_alert': 'security-alert',
                'dlp_alert': 'dlp-alert',
                'idps_alert': 'idps-alert',
                'security_drop': 'security-drop',
                'security_pass': 'security-pass',
                'security_redirect': 'security-redirect',
                'security_quarantine': 'security-quarantine'
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
            const tagSelections = [
                'tcp_handshake','tls_handshake','dns_transaction','dhcp_dora',
                'security_alert','dlp_alert','idps_alert',
                'security_drop','security_pass','security_redirect','security_quarantine'
            ];
            if (tagSelections.includes(filterValue)) {
                displayFilterInput.value = '';
            } else {
                displayFilterInput.value = filterMap[filterValue] || '';
            }
            applyDisplayFilter();
            if (filterValue.startsWith('security_') || filterValue.endsWith('_alert')) {
                const cfg = securityConfigCache;
                const secOn = cfg && (cfg.dlp_enabled || cfg.idps_enabled);
                if (!secOn) {
                    toast('Enable DLP or IDPS in Server Info for security filters to match packets', 'warn');
                }
            }
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

        const PROTO_COLORS = {
            tcp:'#3b82f6', udp:'#10b981', http:'#22c55e', https:'#22c55e',
            http2:'#4ade80', dns:'#38bdf8', tls:'#eab308', ssl:'#eab308',
            icmp:'#a855f7', arp:'#f59e0b', quic:'#ec4899', grpc:'#8b5cf6',
            ssh:'#94a3b8', ftp:'#fb923c', bgp:'#f87171', ntp:'#34d399',
            sip:'#e879f9', ip:'#64748b', default:'#f97316'
        };
        function protoColor(proto) {
            const k = (proto || '').toLowerCase().replace(/[^a-z0-9]/g,'');
            for (const [key, col] of Object.entries(PROTO_COLORS)) {
                if (k.includes(key)) return col;
            }
            return PROTO_COLORS.default;
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
            if (tabId === 'serverinfo') { loadServerInfo(); loadInterfaces(); loadSessions(); loadSecurityConfig(); }
            if (tabId === 'dashboard' && typeof loadSecurityConfig === 'function') loadSecurityConfig();
            if (tabId === 'security') { loadSecurityConfig(); refreshSecurityPanel(); showSecuritySub('alerts'); }
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
                toast('No packets to export. Capture some first.', 'warn');
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
                const pb = document.getElementById('btnPause');
                if (pb) { pb.style.display = 'inline-block'; pb.textContent = '⏸ Pause'; pb.style.background = ''; }
                document.getElementById('sb-status').textContent = `[${S.iface}] Resuming…`;
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
            const emptyRow = document.getElementById('emptyPacketState');
            if (emptyRow) emptyRow.remove();
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
                if (data.security_dropped || data.security_verdict === 'drop') {
                    tr.classList.add('pkt-dropped', 'ws-bg-sec-drop');
                }
                const riskBadge = data.risk >= 70 ? `<span class="risk-badge risk-high">HIGH ${data.risk}</span>` : data.risk >= 35 ? `<span class="risk-badge risk-medium">MED ${data.risk}</span>` : data.risk > 0 ? `<span class="risk-badge risk-low">LOW ${data.risk}</span>` : '';
                const secBadge = (data.security_alerts && data.security_alerts.length > 0)
                    ? data.security_alerts.map(a => `<span class="security-alert-badge" title="${escapeHtml(a.title)}">${a.engine.toUpperCase()}</span>`).join('')
                    : '';
                const vBadge = (data.security_verdict && data.security_alerts && data.security_alerts.length > 0)
                    ? verdictBadge(data.security_verdict) : '';
                const protoKey = escapeHtml(data.proto).toLowerCase().replace(/[^a-z0-9]/g,'');
                tr.innerHTML = `<td>${data.index}</td><td>${relTime}</td><td>${escapeHtml(data.src)}</td><td>${escapeHtml(data.dst)}</td><td><span class="proto-badge proto-${protoKey}">${escapeHtml(data.proto)}</span></td><td>${data.len}</td><td class="info-cell" title="${escapeHtml(data.summary)}">${vBadge}${secBadge}${riskBadge}${escapeHtml(data.summary)}</td>`;
                if (data.tags) tr.setAttribute('data-tags', data.tags);
                (function(p, row) { row.onclick = function() { showDetail(p, row); }; })(data, tr);
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
                const nb = document.getElementById('navLiveBadge');
                if (nb) nb.classList.add('on');
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

            if (data.security_alerts && data.security_alerts.length > 0) {
                S.securityAlertCount = (S.securityAlertCount || 0) + data.security_alerts.length;
            }

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
            if (!S || S.packetStore.length === 0) {
                tbody.innerHTML = '<tr id="emptyPacketState"><td colspan="7" style="text-align:center;padding:48px 20px;color:var(--text-muted);"><div style="font-size:32px;margin-bottom:12px;">📡</div><div style="font-weight:700;font-size:15px;margin-bottom:6px;">No packets captured yet</div><div style="font-size:13px;">Click <strong>▶ Start Capture</strong> to begin</div></td></tr>';
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
                if (data.security_dropped || data.security_verdict === 'drop') {
                    tr.classList.add('pkt-dropped', 'ws-bg-sec-drop');
                }
                const riskBadge = data.risk >= 70 ? `<span class="risk-badge risk-high">HIGH ${data.risk}</span>` : data.risk >= 35 ? `<span class="risk-badge risk-medium">MED ${data.risk}</span>` : data.risk > 0 ? `<span class="risk-badge risk-low">LOW ${data.risk}</span>` : '';
                const secBadge = (data.security_alerts && data.security_alerts.length > 0)
                    ? data.security_alerts.map(a => `<span class="security-alert-badge" title="${escapeHtml(a.title)}">${a.engine.toUpperCase()}</span>`).join('')
                    : '';
                const vBadge = (data.security_verdict && data.security_alerts && data.security_alerts.length > 0)
                    ? verdictBadge(data.security_verdict) : '';
                const protoKey2 = escapeHtml(data.proto).toLowerCase().replace(/[^a-z0-9]/g,'');
                tr.innerHTML = `<td>${i+1}</td><td>${relTime}</td><td>${escapeHtml(data.src)}</td><td>${escapeHtml(data.dst)}</td><td><span class="proto-badge proto-${protoKey2}">${escapeHtml(data.proto)}</span></td><td>${data.len}</td><td class="info-cell" title="${escapeHtml(data.summary)}">${vBadge}${secBadge}${riskBadge}${escapeHtml(data.summary)}</td>`;
                if (data.tags) tr.setAttribute('data-tags', data.tags);
                (function(p, row) { row.onclick = function() { showDetail(p, row); }; })(data, tr);
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
                        ? '<span class="chip-live-dot"></span>'
                        : '<span style="width:7px;height:7px;border-radius:50%;background:#94a3b8;display:inline-block;flex-shrink:0;"></span>';
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
            applyStreamFilter();
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
                    const nb2 = document.getElementById('navLiveBadge');
                    if (nb2) nb2.classList.remove('on');
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
            if (typeof refreshSecurityPanel === 'function') refreshSecurityPanel();
        }

        function stopActiveCapture() {
            if (!activeId) return;
            const S = Sessions[activeId];
            if (!S) return;
            if (S.eventSource) { try { S.eventSource.close(); } catch (e) {} S.eventSource = null; }
            S.status = 'stopped';
            isCapturing = false;
            const nb = document.getElementById('navLiveBadge');
            if (nb) nb.classList.remove('on');
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

        function showDetail(pkt, trElement) {
            autoScroll = false;
            if (isCapturing) document.getElementById('resumeScrollBtn').style.display = 'block';

            document.querySelectorAll('#pktTableBody tr').forEach(row => row.classList.remove('selected'));
            trElement.classList.add('selected');
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
            if (pkt.security_alerts && pkt.security_alerts.length > 0) {
                formattedDetails = '<div class="detail-header" style="color:var(--danger);">Security Engine Verdict</div>'
                    + `<div class="detail-row"><span class="detail-key">Verdict:</span> <span class="detail-val">${verdictBadge(pkt.security_verdict || 'monitor')}</span></div>`
                    + (pkt.security_flow_key ? `<div class="detail-row"><span class="detail-key">Flow:</span> <span class="detail-val">${escapeHtml(pkt.security_flow_key)}</span></div>` : '')
                    + (pkt.security_redirect ? `<div class="detail-row"><span class="detail-key">Redirect:</span> <span class="detail-val">${escapeHtml(pkt.security_redirect)}</span></div>` : '')
                    + '<div class="detail-header" style="color:var(--danger);margin-top:8px;">Security Alerts</div>'
                    + pkt.security_alerts.map(a =>
                        `<div class="detail-row"><span class="detail-key">${escapeHtml(a.engine.toUpperCase())} [${escapeHtml(a.severity)}]:</span> <span class="detail-val" style="color:var(--danger);font-weight:600;">${escapeHtml(a.title)}</span><br><span class="detail-val" style="color:var(--text-muted);font-size:11px;">${escapeHtml(a.detail)} — action: ${escapeHtml(a.action || a.verdict || 'monitor')}</span></div>`
                    ).join('') + formattedDetails;
            }
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
                // Hex pane is only shown via the toggle button — never auto-show on row click
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
                const badge = data.state === "UP" ? "success" : "danger";

                // ── Card 1: Interface Config (identity + IPs + roles) ───────
                let cfg = '';
                cfg += hwSection('Identity');
                cfg += kvRow("State", data.state, badge);
                cfg += kvRow("MAC Address", data.mac);
                cfg += kvRow("MTU", data.mtu);
                cfg += kvRow("Speed", data.speed || "—");
                cfg += kvRow("Duplex", data.duplex || "—");
                cfg += kvRow("Driver", data.driver || "—");
                if (data.loopback) cfg += kvRow("Type", "Loopback");
                if (data.promisc)  cfg += kvRow("Promiscuous", "Yes");
                if (data.master)   cfg += kvRow("Master", data.master);
                if (data.is_bridge) cfg += kvRow("Role", "Bridge master");
                if (data.is_bond)   cfg += kvRow("Role", "Bond member");
                if (data.ifalias)   cfg += kvRow("Alias", data.ifalias);

                cfg += hwSection('IP Addresses');
                const ips = data.ips || [];
                cfg += ips.length > 0
                    ? ips.map(ip => kvRow("addr", ip)).join('')
                    : kvRow("addr", "—");

                document.getElementById('ifaceConfig').innerHTML = cfg;

                // ── Card 2: Hardware Status (traffic + error counters) ──────
                let hw = '';
                hw += hwSection('Traffic');
                hw += kvRow("RX", `${formatBytes(data.rx_bytes)} (${data.rx_packets} pkts)`);
                hw += kvRow("TX", `${formatBytes(data.tx_bytes)} (${data.tx_packets} pkts)`);
                hw += kvRow("RX Errors / Dropped", `${data.rx_errors} / ${data.rx_dropped}`);
                hw += kvRow("TX Errors / Dropped", `${data.tx_errors} / ${data.tx_dropped}`);

                const hasErrors = (data.rx_crc_errors + data.rx_missed_errors +
                                   data.rx_frame_errors + data.rx_fifo_errors +
                                   data.tx_carrier_errors + data.collisions) > 0;
                if (hasErrors) {
                    hw += hwSection('Error Counters');
                    hw += kvRow("CRC Errors",      data.rx_crc_errors);
                    hw += kvRow("Missed",           data.rx_missed_errors);
                    hw += kvRow("Frame Errors",     data.rx_frame_errors);
                    hw += kvRow("FIFO Errors",      data.rx_fifo_errors);
                    hw += kvRow("TX Carrier Errors",data.tx_carrier_errors);
                    hw += kvRow("Collisions",       data.collisions);
                }

                hw += hwSection('Carrier');
                hw += kvRow("Carrier Changes", data.carrier_changes);

                document.getElementById('hwStatus').innerHTML = hw;
            } catch (e) {
                const msg = "Error: " + e.message;
                document.getElementById('ifaceConfig').innerHTML = msg;
                document.getElementById('hwStatus').innerHTML = msg;
            }
        }
        
        async function loadConnections() {
            try {
                const res = await fetch('/api/conn'); const data = await res.json();
                let html = '<table class="settings-table"><thead><tr><th>Proto</th><th>Local Address</th><th>Remote Address</th><th>State</th><th>PID / Process</th></tr></thead><tbody>';
                data.forEach(c => {
                    let remote = c.remote_port === 0 ? "—" : `${c.remote_ip}:${c.remote_port}`;
                    let proc = c.pid === 0 ? "—" : `${c.process} (${c.pid})`;
                    let stateClass = c.state.includes("ESTABLISH") ? "state-established" : c.state.includes("LISTEN") ? "state-listen" : c.state.includes("TIME_WAIT") ? "state-time-wait" : c.state.includes("CLOSE_WAIT") ? "state-close-wait" : "state-other";
                    const cprotoKey = (c.proto || '').toLowerCase().replace(/[^a-z0-9]/g,'');
                    html += `<tr><td><span class="proto-badge proto-${cprotoKey}">${c.proto}</span></td><td>${c.local_ip}:${c.local_port}</td><td>${remote}</td><td><span class="state-badge ${stateClass}">${c.state}</span></td><td>${proc}</td></tr>`;
                });
                document.getElementById('connContent').innerHTML = html + '</tbody></table>';
            } catch(e) { document.getElementById('connContent').innerHTML = '<div style="padding:20px;color:var(--danger);">Error loading connections: ' + e.message + '</div>'; }
        }

        async function loadRoutes() {
            try {
                const res = await fetch('/api/route'); const data = await res.json();
                let html = '<table class="settings-table"><thead><tr><th>Interface</th><th>Destination / Prefix</th><th>Gateway</th><th>Metric</th></tr></thead><tbody>';
                data.sort((a,b) => (b.is_default?1:0)-(a.is_default?1:0)).forEach(r => {
                    let dest = `${r.destination}/${r.prefix_len}`;
                    let gw = (r.gateway === "0.0.0.0" || r.gateway === "::") ? '<span class="direct-route">Direct</span>' : r.gateway;
                    let defBadge = r.is_default ? '<span class="default-route-badge">DEFAULT</span>' : '';
                    html += `<tr style="${r.is_default ? 'font-weight:600;' : ''}"><td>${r.interface}</td><td>${defBadge}${dest}</td><td>${gw}</td><td>${r.metric}</td></tr>`;
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
                    const isUp = (n.state||'').toLowerCase() === 'up';
                    const stateEl = isUp
                        ? `<span class="nic-up"><span class="nic-dot"></span>UP</span>`
                        : `<span class="nic-down"><span class="nic-dot"></span>DOWN</span>`;
                    html += `<tr>
                        <td><strong style="color:var(--primary);cursor:pointer;" onclick="selectInterfaceForCapture('${n.name}')" title="Click to open capture window">${n.name}</strong></td>
                        <td>${stateEl}</td>
                        <td style="font-family:monospace;font-size:12px;">${n.mac||'—'}</td>
                        <td>${n.mtu||'—'}</td>
                        <td>${fmtBytes(n.rx_bytes||0)}</td>
                        <td>${fmtBytes(n.tx_bytes||0)}</td>
                    </tr>`;
                });
                document.getElementById('nicContent').innerHTML = html + '</tbody></table>';
            } catch(e) { document.getElementById('nicContent').innerHTML = '<div style="padding:20px;color:var(--danger);">Error loading NIC data.</div>'; }
        }

        const dpSection = (title) =>
            `<div style="margin:14px 0 4px;font-size:0.75rem;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;font-weight:600;border-top:1px solid #334155;padding-top:8px;">${title}</div>`;

        // Compact section header for hardware panel cards
        const hwSection = (title) => `<div class="hw-section">${title}</div>`;

        async function loadDataplane() {
            const iface = document.getElementById('currentIface').value; if (!iface) return;
            try {
                const res = await fetch(`/api/dp?iface=${encodeURIComponent(iface)}`);
                const data = await res.json();

                let html = '';

                // ── eBPF summary ──────────────────────────────────────────
                html += dpSection('eBPF Status');
                html += kvRow('Active', data.ebpf_active ? 'Yes' : 'No');
                html += kvRow('Interface Kind', data.iface_kind || '—');

                // ── XDP ───────────────────────────────────────────────────
                html += dpSection('XDP / eBPF');
                const xdpIds = data.xdp_prog_ids && data.xdp_prog_ids !== 'None' ? data.xdp_prog_ids : '—';
                html += kvRow('XDP Prog IDs', xdpIds);
                html += kvRow('XDP Mode', data.xdp_mode || '—');
                if (data.xdp_dispatchers) {
                    html += kvRow('libxdp Dispatchers', data.xdp_dispatchers);
                }
                html += kvRow('AF_XDP Sockets', data.afxdp_sockets > 0 ? data.afxdp_sockets : '—');

                // ── TC BPF ─────────────────────────────────────────────────
                html += dpSection('TC BPF');
                html += kvRow('clsact qdisc', data.tc_clsact ? 'Present' : 'Not detected');
                if (data.tc_clsact || (data.tc_bpf_prog_ids && data.tc_bpf_prog_ids.length)) {
                    html += kvRow('BPF Directions', data.tc_bpf_directions || '—');
                    html += kvRow('BPF Prog IDs', data.tc_bpf_prog_ids || '—');
                }

                // ── bpftool net ────────────────────────────────────────────
                if (data.bpftool_net && data.bpftool_net.length) {
                    html += dpSection('bpftool net');
                    data.bpftool_net.forEach(a => {
                        const id = a.prog_id != null ? a.prog_id : '?';
                        html += kvRow(a.hook || 'attach', `id ${id} ${a.mode || ''} ${a.prog_name || ''}`.trim());
                    });
                }

                // ── Userspace Dataplane ────────────────────────────────────
                html += dpSection('Userspace Dataplane');
                html += kvRow('Bypass Mode', data.bypass_mode);
                html += kvRow('DPDK Bound', data.dpdk_bound ? 'Yes' : 'No');
                if (data.driver) html += kvRow('PMD Driver', data.driver);

                // ── Queues ─────────────────────────────────────────────────
                html += dpSection('Queues');
                html += kvRow('RX / TX / Combined', `${data.rx_queues} / ${data.tx_queues} / ${data.combined_queues}`);

                // ── PCIe ───────────────────────────────────────────────────
                html += dpSection('PCIe');
                html += kvRow('PCI Address', data.pci_address || '—');
                if (data.pci_vendor && data.pci_vendor !== '—')
                    html += kvRow('Vendor / Device', `${data.pci_vendor} / ${data.pci_device}`);
                if (data.pci_link && data.pci_link !== '—')
                    html += kvRow('Link Speed', data.pci_link);
                if (data.pci_max_link && data.pci_max_link !== '—')
                    html += kvRow('Max Link Speed', data.pci_max_link);
                html += kvRow('NUMA Node', data.numa_node || '—');

                // ── SR-IOV ─────────────────────────────────────────────────
                if (data.sriov && data.sriov !== '') {
                    html += dpSection('SR-IOV');
                    html += kvRow('SR-IOV Role', data.sriov);
                }

                // ── HW Offloads ────────────────────────────────────────────
                if (data.hw_features_on) {
                    html += dpSection('HW Offload Features');
                    html += kvRow('Enabled', data.hw_features_on || '—');
                }

                document.getElementById('dpStatus').innerHTML = html;

                // ── Per-interface Pinned BPF ───────────────────────────────
                const pins = data.pinned_bpf || [];
                document.getElementById('hwPinnedCount').textContent = pins.length ? `(${pins.length})` : '';
                if (!pins.length) {
                    document.getElementById('hwPinnedBpf').innerHTML = '<span style="color:var(--text-muted);font-style:italic;">No correlated pinned objects</span>';
                } else {
                    let pinHtml = '';
                    pins.forEach(p => {
                        const id = p.prog_id != null ? `id ${p.prog_id}` : 'id ?';
                        pinHtml += kvRow(`[${p.kind}] ${p.name}`, id);
                    });
                    document.getElementById('hwPinnedBpf').innerHTML = pinHtml;
                }

                // ── Per-interface XDP Dispatchers ──────────────────────────
                const disps = data.xdp_dispatchers_detail || [];
                document.getElementById('hwDispCount').textContent = disps.length ? `(${disps.length})` : '';
                if (!disps.length) {
                    document.getElementById('hwDispatchers').innerHTML = '<span style="color:var(--text-muted);font-style:italic;">None for this interface</span>';
                } else {
                    let dispHtml = '';
                    disps.forEach(d => {
                        dispHtml += hwSection(`dispatch-${d.prog_id}-${d.link_id}`);
                        dispHtml += kvRow('Slots', (d.slots || []).join(', ') || '—');
                        dispHtml += kvRow('Path', d.dir || '—');
                    });
                    document.getElementById('hwDispatchers').innerHTML = dispHtml;
                }

                // ── Network namespace for this interface ───────────────────
                let nsHtml = '';
                if (data.ns_label) {
                    nsHtml += kvRow('Namespace', data.ns_is_host ? 'Host' : data.ns_label);
                    if (data.ns_inode) nsHtml += kvRow('Inode', data.ns_inode);
                    if (data.ns_xdp_ids) nsHtml += kvRow('XDP in NS', data.ns_xdp_ids);
                    if (data.ns_afxdp_sockets > 0) nsHtml += kvRow('AF_XDP in NS', data.ns_afxdp_sockets);
                } else {
                    nsHtml = '<span style="color:var(--text-muted);font-style:italic;">Namespace not resolved</span>';
                }
                document.getElementById('hwNetNs').innerHTML = nsHtml;
            } catch (e) {
                document.getElementById('dpStatus').innerHTML = 'Error loading dataplane info: ' + e.message;
                document.getElementById('hwPinnedBpf').innerHTML = '—';
                document.getElementById('hwDispatchers').innerHTML = '—';
                document.getElementById('hwNetNs').innerHTML = '—';
            }
        }

        async function loadEthtool() {
            const iface = document.getElementById('currentIface').value; if (!iface) return;
            try {
                const res = await fetch(`/api/ethtool?iface=${encodeURIComponent(iface)}`);
                const data = await res.json();

                // ── Full ethtool report ─────────────────────────────────────
                const col = (content) =>
                    `<div style="min-width:0;">${content}</div>`;

                let c1 = '', c2 = '', c3 = '';

                // Column 1 — Driver & Link
                c1 += hwSection('Driver');
                c1 += kvRow('Kernel Driver', data.driver || '—');
                if (data.firmware) c1 += kvRow('Firmware', data.firmware);
                if (data.bus_info) c1 += kvRow('Bus Info', data.bus_info);
                c1 += hwSection('Link');
                c1 += kvRow('Operstate', data.operstate || '—');
                c1 += kvRow('Speed', data.speed_mbps ? data.speed_mbps + ' Mbps' : '—');
                c1 += kvRow('Duplex', data.duplex || '—');
                c1 += kvRow('Auto-Negotiate', data.autoneg || '—');

                // Column 2 — Queues, PCIe, Carrier
                c2 += hwSection('Queues');
                c2 += kvRow('RX / TX / Combined', `${data.rx_queues} / ${data.tx_queues} / ${data.combined_queues}`);
                if (data.tx_queue_len > 0) c2 += kvRow('TX Queue Length', data.tx_queue_len);
                if (data.pcie_speed) {
                    c2 += hwSection('PCIe');
                    c2 += kvRow('Speed / Width', data.pcie_speed + (data.pcie_width ? ` x${data.pcie_width}` : ''));
                }
                c2 += hwSection('Carrier');
                c2 += kvRow('Changes', data.carrier_changes);
                c2 += kvRow('Up / Down Events', `${data.carrier_up} / ${data.carrier_down}`);

                // Column 3 — HW Offloads & IRQ Affinities
                if (data.features_on && data.features_on.length > 0) {
                    c3 += hwSection('HW Offload Features');
                    c3 += `<div class="hw-feat">${data.features_on.join(' · ')}</div>`;
                }
                if (data.irq_affinities && data.irq_affinities.length > 0) {
                    c3 += hwSection('IRQ Affinities');
                    data.irq_affinities.forEach(q => {
                        c3 += kvRow(q.q, `IRQ ${q.irq}  · CPUs: ${q.cpus || '—'}`);
                    });
                }

                document.getElementById('ethtoolDetail').innerHTML =
                    col(c1) + col(c2) + col(c3 || '<span style="color:#475569;font-style:italic;font-size:0.82rem;">No HW offload or IRQ data.</span>');
            } catch (e) {
                document.getElementById('ethtoolDetail').innerHTML = 'Error loading ethtool report: ' + e.message;
            }
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

        function clearPackets() {
            if (!activeId || !Sessions[activeId]) return;
            const S = Sessions[activeId];
            S.packetStore = []; S.packetCount = 0; S.byteCount = 0; S.baseTs = null;
            S.flows = {}; S.protoStats = {}; S.talkerStats = {};
            packetStore = S.packetStore; flows = S.flows;
            protoStats = S.protoStats; talkerStats = S.talkerStats;
            packetCount = 0; byteCount = 0; baseTs = null; packetBuffer = [];
            lastRateCheck = { time: 0, count: 0 };
            document.getElementById('pktTableBody').innerHTML = '<tr id="emptyPacketState"><td colspan="7" style="text-align:center;padding:48px 20px;color:var(--text-muted);"><div style="font-size:32px;margin-bottom:12px;">📡</div><div style="font-weight:700;font-size:15px;margin-bottom:6px;">Cleared</div><div style="font-size:13px;">Click <strong>▶ Start Capture</strong> to capture new packets</div></td></tr>';
            document.getElementById('packetDetail').textContent = 'Select a packet to view its complete DPI decode layer by layer...';
            document.getElementById('packetHex').innerHTML = '';
            document.getElementById('packetHexWrapper').style.display = 'none';
            document.getElementById('sb-stats').textContent = 'Packets: 0 | Displayed: 0 | Bytes: 0 B';
            document.getElementById('sb-rate').textContent = '';
            renderFlows(); renderStats();
        }
        window.clearPackets = clearPackets;

        function exportPacketsCsv() {
            const tbody = document.getElementById('pktTableBody');
            const visibleRows = Array.from(tbody.children).filter(r => r.style.display !== 'none');
            if (visibleRows.length === 0) {
                alert('No packets to export. Capture some packets first.');
                return;
            }
            const headers = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'];
            const rows = visibleRows.map(tr => {
                return Array.from(tr.cells).map(td => {
                    const v = td.textContent.replace(/"/g, '""');
                    return '"' + v + '"';
                }).join(',');
            });
            const csv = [headers.join(','), ...rows].join('\r\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = 'pktana-capture.csv';
            document.body.appendChild(a); a.click();
            document.body.removeChild(a); URL.revokeObjectURL(url);
            toast(`Exported ${visibleRows.length} packets as CSV`, 'success');
            document.getElementById('sb-status').textContent = `Exported ${visibleRows.length} packets as CSV.`;
        }
        window.exportPacketsCsv = exportPacketsCsv;

        // ── Toast & Modal system ─────────────────────────────────────────────
        function toast(msg, type = 'info', duration = 3500) {
            const container = document.getElementById('toastContainer');
            if (!container) return;
            const t = document.createElement('div');
            t.className = `toast toast-${type}`;
            const icons = { success:'✓', error:'✕', warn:'!', info:'ℹ' };
            t.innerHTML = `<span style="display:flex;align-items:center;gap:8px;"><strong style="opacity:0.8">${icons[type]||'ℹ'}</strong>${msg}</span><button class="toast-close" onclick="this.parentElement.remove()">×</button>`;
            container.appendChild(t);
            setTimeout(() => { t.style.animation = 'toastOut 0.3s ease forwards'; setTimeout(() => t.remove(), 300); }, duration);
        }

        function modal({ title = 'Confirm', body = '', confirmText = 'OK', cancelText = 'Cancel', danger = false, inputPlaceholder = null, inputDefault = '' } = {}) {
            return new Promise(resolve => {
                const overlay = document.createElement('div');
                overlay.className = 'modal-overlay';
                overlay.innerHTML = `<div class="modal-box">
                    <div class="modal-title">${title}</div>
                    <div class="modal-body">${body}</div>
                    ${inputPlaceholder !== null ? `<div class="modal-input-wrap"><input class="modal-input" type="text" placeholder="${inputPlaceholder}" value="${inputDefault}" /></div>` : ''}
                    <div class="modal-footer">
                        <button class="modal-cancel">${cancelText}</button>
                        <button class="modal-confirm${danger ? ' danger' : ''}">${confirmText}</button>
                    </div>
                </div>`;
                const close = (val) => { overlay.remove(); resolve(val); };
                overlay.querySelector('.modal-cancel').onclick = () => close(null);
                overlay.querySelector('.modal-confirm').onclick = () => {
                    const inp = overlay.querySelector('.modal-input');
                    close(inp ? inp.value : true);
                };
                overlay.addEventListener('keydown', e => { if (e.key === 'Escape') close(null); if (e.key === 'Enter' && !overlay.querySelector('.modal-input')) close(true); });
                document.body.appendChild(overlay);
                const inp = overlay.querySelector('.modal-input');
                if (inp) { inp.focus(); inp.select(); } else overlay.querySelector('.modal-confirm').focus();
            });
        }

        async function stopDaemon() {
            const ok = await modal({ title: 'Stop pktana Daemon', body: 'This will terminate the background daemon and close all active captures. Are you sure?', confirmText: 'Stop Daemon', cancelText: 'Cancel', danger: true });
            if (!ok) return;
            try {
                await fetch('/api/stop', { method: 'POST' });
                toast('pktana daemon stopped. You can safely close this page.', 'success', 6000);
            } catch (e) {
                toast('Error stopping daemon: ' + e, 'error');
            }
        }

        let term = null;
        let fitAddon = null;
        let termWs = null;
        let termReconnectAttempts = 0;
        const TERM_MAX_RECONNECTS = 5;

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
                document.getElementById('xtermContainer').innerHTML =
                    '<div style="color:var(--danger);padding:20px;">Failed to load terminal library. Refresh the page.</div>';
                return;
            }

            term = new Terminal({
                cursorBlink: true,
                cursorStyle: 'block',
                fontSize: 14,
                fontFamily: '"Cascadia Code","Fira Code","Courier New",monospace',
                theme: xtermThemes['default'],
                allowProposedApi: true,
                scrollback: 10000,
                convertEol: false,
            });

            fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            const webLinksAddon = new WebLinksAddon.WebLinksAddon();
            term.loadAddon(webLinksAddon);

            term.open(document.getElementById('xtermContainer'));
            fitAddon.fit();

            // Register input/resize handlers once; they close over termWs.
            term.onData((data) => {
                if (termWs && termWs.readyState === WebSocket.OPEN) {
                    termWs.send(new TextEncoder().encode(data));
                }
            });
            term.onResize((sz) => { sendTermResize(sz.cols, sz.rows); });

            window.addEventListener('resize', () => { if (fitAddon) fitAddon.fit(); });

            const saved = localStorage.getItem('pktana_xterm_theme');
            if (saved && xtermThemes[saved]) {
                document.getElementById('xtermTheme').value = saved;
                term.options.theme = xtermThemes[saved];
            }

            connectTerminalWs();
        }

        function connectTerminalWs() {
            if (termWs) { try { termWs.close(1000); } catch(_) {} termWs = null; }
            const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            termWs = new WebSocket(`${proto}//${location.host}/api/terminal/ws`);
            termWs.binaryType = 'arraybuffer';
            document.getElementById('xtermStatus').textContent = 'Connecting…';

            termWs.onopen = () => {
                document.getElementById('xtermStatus').textContent = 'Connected';
                sendTermResize(term.cols, term.rows);
            };
            termWs.onmessage = (ev) => {
                term.write(ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : ev.data);
            };
            termWs.onerror = () => {
                document.getElementById('xtermStatus').textContent = 'Error';
            };
            termWs.onclose = () => {
                document.getElementById('xtermStatus').textContent = 'Reconnecting…';
                term.writeln('\r\n\x1b[1;33m[connection closed – reconnecting in 3 s…]\x1b[0m');
                setTimeout(connectTerminalWs, 3000);
            };
        }

        function sendTermResize(cols, rows) {
            if (!termWs || termWs.readyState !== WebSocket.OPEN) return;
            const b = new Uint8Array(5);
            b[0] = 0xFF; b[1] = cols >> 8; b[2] = cols & 0xFF; b[3] = rows >> 8; b[4] = rows & 0xFF;
            termWs.send(b.buffer);
        }

        function clearXterm() {
            if (term) term.clear();
        }

        function resetXterm() {
            if (term) term.reset();
            connectTerminalWs();
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
            // Hex dump always starts hidden; only shown via the toggle button
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
            if (typeof loadSecurityConfig === 'function') loadSecurityConfig();
            if (typeof loadSessions === 'function') loadSessions();

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

        // ── Keyboard shortcuts ───────────────────────────────────────────────
        document.addEventListener('keydown', e => {
            const tag = document.activeElement ? document.activeElement.tagName : '';
            if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
            if (e.altKey) {
                if (e.key === 'l' || e.key === 'L') { e.preventDefault(); toggleLayoutDir(); }
                if (e.key === 'd' || e.key === 'D') { e.preventDefault(); togglePane('paneRight'); }
                if (e.key === 'h' || e.key === 'H') { e.preventDefault(); toggleHex(); }
                if (e.key === 'c' || e.key === 'C') { e.preventDefault(); clearPackets(); }
                if (e.key === 'e' || e.key === 'E') { e.preventDefault(); exportPacketsCsv(); }
            }
            if (e.key === ' ' && !e.altKey && !e.ctrlKey && !e.metaKey) {
                const panel = document.getElementById('dashboard');
                if (panel && panel.classList.contains('active')) { e.preventDefault(); isCapturing ? togglePause() : toggleCapture(); }
            }
            if (e.key === 'Escape') {
                const df = document.getElementById('displayFilter');
                if (df && df.value) { df.value = ''; applyDisplayFilter(); }
            }
        });

        // Ctrl+F focuses the search box
        document.addEventListener('keydown', e => {
            if (e.ctrlKey && e.key === 'f') {
                const panel = document.getElementById('dashboard');
                if (panel && panel.classList.contains('active')) {
                    e.preventDefault();
                    const df = document.getElementById('displayFilter');
                    if (df) { df.focus(); df.select(); }
                }
            }
        });

    </script>
    <div id="toastContainer"></div>
</body>
</html>
"##;
}
