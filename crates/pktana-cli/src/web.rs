// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

pub mod inner {
    use pktana_core::{
        build_socket_process_map, geoip_lookup_str, get_ethtool_report, get_nic_dataplane,
        get_nic_info, inspect, list_connections, list_nics, list_routes, CaptureConfig,
        LinuxCaptureEngine, ProcessInfo, SocketId,
    };
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener};
    use std::thread;
    use std::time::{Duration, Instant};

    pub fn run_web_server(port: u16) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).map_err(|e| e.to_string())?;

        println!("Starting pktana Web UI on http://{}", addr);
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
        proc_map: &HashMap<SocketId, ProcessInfo>,
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
                lines.push(format!(
                    "  Flags: DF={} MF={}",
                    dp.ip_flag_df, dp.ip_flag_mf
                ));
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
            if let Some(m) = dp.tcp_mss {
                lines.push(format!("  MSS: {}", m));
            }
            if let Some(ws) = dp.tcp_window_scale {
                lines.push(format!("  Win Scale: x{}", ws));
            }
            lines.push(format!("  Payload len: {} bytes", dp.tcp_payload_len));
        } else if let Some(sp) = dp.udp_src_port {
            lines.push("-- LAYER 4: UDP".to_string());
            lines.push(format!("  Src Port: {}", sp));
            lines.push(format!("  Dst Port: {}", dp.udp_dst_port.unwrap_or(0)));
            if let Some(l) = dp.udp_len {
                lines.push(format!("  Length: {}", l));
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
                lines.push(format!("  Mode: {}", m));
            }
            if let Some(s) = dp.ntp_stratum {
                lines.push(format!("  Stratum: {}", s));
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
                lines.push(format!("  JA3-raw: {}", ja3));
            }
            if !dp.tls_ciphers.is_empty() {
                let ciphers: Vec<String> = dp
                    .tls_ciphers
                    .iter()
                    .take(5)
                    .map(|c| format!("0x{:04x}", c))
                    .collect();
                let more = if dp.tls_ciphers.len() > 5 {
                    format!(" ... +{}", dp.tls_ciphers.len() - 5)
                } else {
                    "".to_string()
                };
                lines.push(format!("  Ciphers: {}{}", ciphers.join(" "), more));
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
        let mut buffer = [0; 1024];
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);

            if request.starts_with("GET /api/interfaces ") {
                let ifaces = LinuxCaptureEngine::list_interfaces().unwrap_or_default();
                let mut json = String::from("[");
                for (i, iface) in ifaces.iter().enumerate() {
                    let desc = iface.description.as_deref().unwrap_or("");
                    json.push_str(&format!(
                        r#"{{"name":"{}","description":"{}"}}"#,
                        iface.name, desc
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
            } else if request.starts_with("GET /api/inspect?") {
                let start = "GET /api/inspect?".len();
                let end = request[start..].find(' ').unwrap_or(0) + start;
                let query = &request[start..end];

                let mut iface = String::new();
                let mut filter = None;
                let mut export_file = None;
                let mut read_file = None;

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
                    pcap_export: export_file.filter(|s| !s.is_empty()),
                };

                if let Ok(mut write_stream) = stream.try_clone() {
                    let mut last_proc_update = Instant::now();
                    let mut proc_map = build_socket_process_map();

                    let handle_pkt = move |pkt: pktana_core::CapturePacket<'_>| -> bool {
                        if last_proc_update.elapsed() > Duration::from_secs(2) {
                            proc_map = build_socket_process_map();
                            last_proc_update = Instant::now();
                        }

                        let dp = inspect(&pkt.data);
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
                        let detail_text =
                            build_dpi_text(&dp, &proc_map, pkt.timestamp_sec, pkt.timestamp_usec);
                        let hex_lines = pktana_core::hex_dump(&pkt.data, 512).join("\n");

                        let msg = format!(
                            "data: {{\"ts_sec\":{}, \"ts_usec\":{}, \"summary\":\"{}\", \"len\": {}, \"risk\": {}, \"category\": \"{}\", \"proto\": \"{}\", \"src\":\"{}\", \"dst\":\"{}\", \"details\":\"{}\", \"hex\":\"{}\"}}\n\n",
                            pkt.timestamp_sec, pkt.timestamp_usec, escape_json(&dp.one_liner()), dp.frame_len, risk, escape_json(dp.app_category.as_deref().unwrap_or("Unknown")), escape_json(proto), escape_json(&src), escape_json(&dst), escape_json(&detail_text), escape_json(&hex_lines)
                        );

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

    const HTML_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pktana Enterprise Dashboard</title>
    <style>
        :root { 
            --primary: #0284c7; /* Sky-600 */
            --primary-dark: #0369a1; /* Sky-700 */
            --primary-light: #f0f9ff; /* Sky-50 */
            --bg: #f8fafc;
            --surface: #ffffff;
            --text-main: #1e293b;
            --text-muted: #475569;
            --border: #cbd5e1;
            --success: #16a34a; 
            --danger: #dc2626; 
            --info: #0ea5e9;
        }
        * { box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: var(--bg); color: var(--text-main); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
        
        .navbar { background: linear-gradient(135deg, #1e293b, #0f172a); border-bottom: 2px solid var(--primary); color: white; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); z-index: 100; }
        .logo { font-size: 20px; font-weight: 800; display: flex; align-items: center; gap: 8px; letter-spacing: -0.5px; text-shadow: 0 1px 2px rgba(0,0,0,0.2); }
        .nav-controls { display: flex; gap: 8px; align-items: center; }
        
        .container { flex: 1; display: flex; flex-direction: column; width: 100%; padding: 0; overflow: hidden; }
        
        .form-input { padding: 8px 12px; border: 1px solid rgba(255,255,255,0.3); background: rgba(255,255,255,0.1); color: white; font-size: 13px; outline: none; border-radius: 6px; transition: all 0.2s; }
        .form-input::placeholder { color: rgba(255,255,255,0.7); }
        .form-input:focus { background: white; color: #0f172a; border-color: white; box-shadow: 0 0 0 3px rgba(255,255,255,0.3); }
        .panel .form-input { background: white; color: var(--text-main); border: 1px solid var(--border); }
        .panel .form-input::placeholder { color: var(--text-muted); }
        .panel .form-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-light); }
        
        .primary-btn { background: white; color: var(--primary); border: none; border-radius: 6px; padding: 8px 16px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 700; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .primary-btn:hover { background: var(--primary-light); transform: translateY(-1px); }
        .primary-btn.stop { background: #fee2e2; color: #dc2626; }
        .primary-btn.stop:hover { background: #fecaca; }
        
        .btn { background: rgba(255,255,255,0.15); color: white; border: 1px solid rgba(255,255,255,0.3); border-radius: 6px; padding: 8px 16px; font-size: 13px; cursor: pointer; font-weight: 500; transition: all 0.2s; }
        .btn:hover { background: rgba(255,255,255,0.25); }
        .panel .btn { background: var(--surface); color: var(--text-main); border: 1px solid var(--border); }
        .panel .btn:hover { border-color: var(--primary); color: var(--primary); background: var(--primary-light); }
        
        .tab-nav { background: var(--surface); border-bottom: 2px solid var(--border); padding: 0 16px; display: flex; gap: 16px; }
        .tab-btn { padding: 14px 4px; border: none; background: none; color: var(--text-muted); font-size: 14px; font-weight: 600; cursor: pointer; border-bottom: 3px solid transparent; transition: all 0.2s; }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }
        
        .panel { display: none; height: 100%; flex-direction: column; overflow: hidden; }
        .panel.active { display: flex; }
        
        .wireshark-view { display: flex; flex-direction: row; flex: 1; width: 100%; gap: 16px; padding: 16px; background: var(--bg); overflow: hidden; }
        .pane-left { flex: 6; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); position: relative; overflow: hidden; display: flex; flex-direction: column; }
        #tableContainer { flex: 1; overflow: auto; }
        .pane-right { flex: 4; display: flex; flex-direction: column; gap: 16px; min-width: 340px; overflow: hidden; }
        
        .section-label { font-weight: 700; color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: -8px; }
        .pane-detail { flex: 3; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow-y: auto; padding: 16px; font-family: 'Consolas', 'Courier New', monospace; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .pane-hex { flex: 2; background: #0f172a; color: #e2e8f0; border: 1px solid var(--border); border-radius: 8px; overflow-y: auto; padding: 16px; font-family: 'Consolas', 'Courier New', monospace; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        
        .ws-table { min-width: 100%; border-collapse: collapse; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; table-layout: auto; }
        .ws-table th { background: #f1f5f9; color: var(--text-main); border-bottom: 1px solid var(--border); border-right: 1px solid var(--border); padding: 6px 8px; text-align: left; position: sticky; top: 0; z-index: 10; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; font-weight: 700; box-shadow: 0 1px 0 var(--border); }
        .ws-table td { border-bottom: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0; padding: 4px 8px; cursor: default; white-space: nowrap; }
        .ws-table tr:hover td { filter: brightness(0.95); }
        .ws-table tr.selected td { background-color: var(--primary) !important; color: white !important; font-weight: 500; }
        
        .ws-bg-tcp { background-color: #e2e8f0; color: var(--text-main); }
        .ws-bg-udp { background-color: #e0f2fe; color: var(--text-main); }
        .ws-bg-http { background-color: #dcfce7; color: var(--text-main); }
        .ws-bg-dns { background-color: #cffafe; color: var(--text-main); }
        .ws-bg-icmp { background-color: #fae8ff; color: var(--text-main); }
        .ws-bg-arp { background-color: #fef08a; color: var(--text-main); }
        .ws-bg-bad { background-color: #fee2e2; color: #991b1b; font-weight: 500; }
        .ws-bg-def { background-color: var(--surface); color: var(--text-main); }
        
        .info-cell { white-space: nowrap; }
        
        .detail-header { background: var(--primary-light); color: var(--primary-dark); font-weight: 700; padding: 6px 10px; margin: 12px 0 6px 0; border-radius: 4px; border-left: 4px solid var(--primary); font-size: 12px; letter-spacing: 0.5px; }
        .detail-header:first-child { margin-top: 0; }
        .detail-row { display: flex; padding: 3px 10px; font-size: 13px; border-bottom: 1px solid #f1f5f9; }
        .detail-row:hover { background: #f8fafc; }
        .detail-key { color: var(--text-muted); width: 140px; flex-shrink: 0; font-weight: 600; }
        .detail-val { color: var(--text-main); word-break: break-all; }

        .scroll-toast { position: absolute; bottom: 20px; left: 50%; transform: translateX(-50%); background: #1e293b; color: white; padding: 8px 20px; border-radius: 20px; font-size: 13px; font-weight: 600; cursor: pointer; box-shadow: 0 4px 12px rgba(0,0,0,0.15); opacity: 0.95; transition: opacity 0.2s, transform 0.2s; z-index: 100; border: 1px solid #334155; }
        .scroll-toast:hover { opacity: 1; transform: translateX(-50%) translateY(-2px); background: #0f172a; }
        
        .statusbar { background: var(--surface); border-top: 1px solid var(--border); padding: 8px 20px; font-size: 13px; font-weight: 600; color: var(--text-muted); display: flex; justify-content: space-between; flex-shrink: 0; }
        
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; padding: 20px; overflow: auto; }
        .card { background: var(--surface); border: 1px solid var(--border); padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-radius: 6px; }
        .card-title { font-weight: 600; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 12px; font-size: 14px; color: var(--primary); }
        .kv-list { display: flex; flex-direction: column; gap: 8px; font-size: 13px; }
        .kv-item { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px dashed var(--border); padding-bottom: 4px; }
        
        .settings-table { width: 100%; border-collapse: collapse; margin-top: 10px; background: var(--surface); }
        .settings-table th, .settings-table td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }
        .settings-table th { background-color: var(--bg); font-weight: 600; color: var(--text-muted); }
        .settings-table tbody tr:hover td { background-color: var(--primary-light); }
        
        .badge { padding: 2px 6px; border-radius: 12px; font-size: 11px; font-weight: 600; }
        .badge-success { background: #dcfce7; color: #166534; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-warning { background: #fef9c3; color: #854d0e; }
        
        .panel-toolbar { background: var(--surface); padding: 8px 16px; border-bottom: 1px solid var(--border); display: flex; gap: 10px; align-items: center; flex-wrap: wrap; flex-shrink: 0; }
        .resizer { flex: 0 0 5px; background: var(--border); cursor: col-resize; transition: background 0.2s; z-index: 10; margin: 0 -8px; }
        .resizer:hover, .resizer.dragging { background: var(--primary); }
        .wireshark-view.vertical { flex-direction: column; }
        .wireshark-view.vertical .resizer { flex: 0 0 5px; width: 100%; cursor: row-resize; margin: -8px 0; }
        .wireshark-view.vertical .pane-left, .wireshark-view.vertical .pane-right { min-width: 100%; min-height: 100px; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">pktana</div>
        <div class="nav-controls">
            <button class="btn" style="background:#dc2626; color:white; border-color:#991b1b;" title="Stop pktana Daemon" onclick="stopDaemon()">Stop Daemon</button>
        </div>
    </div>

    <div class="tab-nav">
        <button class="tab-btn active" onclick="switchTab('serverinfo')">Server Info</button>
        <button class="tab-btn" onclick="switchTab('terminal')">Terminal</button>
        <button class="tab-btn" onclick="switchTab('pcap')">PCAP Analyzer</button>
        <button class="tab-btn analysis-tab" style="display:none;" onclick="switchTab('dashboard')">Packet Analyzer</button>
        <button class="tab-btn analysis-tab" style="display:none;" onclick="switchTab('flows')">Flows</button>
        <button class="tab-btn analysis-tab" style="display:none;" onclick="switchTab('stats')">Statistics</button>
        <button class="tab-btn analysis-tab" style="display:none;" onclick="switchTab('hardware')">Hardware & Interface</button>
        <button class="tab-btn" onclick="switchTab('connections')">Connections</button>
        <button class="tab-btn" onclick="switchTab('routes')">Routing Table</button>
        <button class="tab-btn" onclick="switchTab('nics')">All NICs</button>
        <button class="tab-btn" onclick="switchTab('geoip')">Tools (GeoIP)</button>
    </div>

    <div class="container">
        <input type="hidden" id="currentIface" value="">

        <!-- Server Info Panel -->
        <div id="serverinfo" class="panel active">
            <div class="grid-3">
                <div class="card">
                    <div class="card-title">System Information 
                        <div style="float:right; display:flex; gap:10px;">
                            <button class="btn" onclick="loadServerInfo()">Refresh</button>
                        </div>
                    </div>
                    <div class="kv-list" id="serverContent">Loading...</div>
                </div>
                <div class="card" style="grid-column: span 2;">
                    <div class="card-title">Network Interfaces</div>
                    <div id="serverInterfacesList" style="overflow-x:auto;">Loading interfaces...</div>
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
                <button id="btnToggle" class="primary-btn stop" onclick="toggleCapture()">Stop Capture</button>
                <input type="text" id="bpfFilter" class="form-input" placeholder="BPF Filter (Capture)" style="width: 160px;">
                <input type="text" id="displayFilter" class="form-input" placeholder="Display Filter..." onkeyup="applyDisplayFilter()" style="width: 180px; background: white; color: #0f172a;">
                <span style="color:var(--border);">|</span>
                <button class="btn" onclick="toggleLayoutDir()" title="Toggle Horizontal/Vertical Split">↔/↕ Split</button>
                <button class="btn" onclick="togglePane('paneRight')" title="Show/Hide Details">👁 Details</button>
                <button class="btn" onclick="toggleHex()" title="Show/Hide Hex Dump">👁 Hex</button>
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
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:-8px;">
                        <div class="section-label" style="margin-bottom:0;">Packet Details</div>
                    </div>
                    <div class="pane-detail" id="packetDetail">Select a packet to view its complete DPI decode layer by layer...</div>
                    <div id="packetHexWrapper" style="display:none; flex-direction:column; flex:2;">
                        <div class="section-label">Hex Dump</div>
                        <div class="pane-hex" id="packetHex" style="flex:1;">0000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................</div>
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
                <div style="overflow-x:auto;">
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
                <div id="connContent" style="overflow-x:auto;">Loading...</div>
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
                <div id="routeContent" style="overflow-x:auto;">Loading...</div>
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
                <div id="nicContent" style="overflow-x:auto;">Loading...</div>
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
            <div class="card" style="margin: 20px; display:flex; flex-direction:column; height: calc(100vh - 150px); background:#0f172a; border-color:#1e293b; padding:0;">
                <div class="card-title" style="color:#94a3b8; border-bottom:1px solid #1e293b; padding:16px 16px 8px 16px; margin-bottom:0;">Server Terminal Access</div>
                <div id="termContainer" style="flex-grow:1; overflow-y:auto; font-family:monospace; font-size:13px; display:flex; flex-direction:column; cursor:text; padding:16px;" onclick="document.getElementById('termInput').focus()">
                    <pre id="termOutput" style="margin:0; white-space:pre-wrap; color:#e2e8f0; font-family:monospace; font-size:13px;"></pre>
                    <div style="display:flex; align-items:center; margin-top:4px;">
                        <span style="color:#38bdf8; margin-right:8px;">$</span>
                        <input type="text" id="termInput" style="flex-grow:1; background:transparent; border:none; color:#e2e8f0; font-family:monospace; font-size:13px; outline:none;" autocomplete="off" spellcheck="false" autofocus onkeydown="handleTermKey(event)">
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        let eventSource = null; let packetCount = 0; let byteCount = 0;
        let isCapturing = false;
        let packetStore = [];
        let baseTs = null;
        let autoScroll = true;
        let flows = {};
        let protoStats = {};
        let talkerStats = {};
        let geoCache = {};

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
                html += `<tr style="cursor:pointer;" title="Click to view packet analysis for this flow" onclick="viewFlowDetails('${f.src}', '${f.dst}')"><td><strong>${escapeHtml(f.proto)}</strong></td><td>${escapeHtml(f.src)}</td><td>${escapeHtml(f.dst)}</td><td>${escapeHtml(f.category)}</td><td>${f.pkts}</td><td>${formatBytes(f.bytes)}</td></tr>`;
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

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelector(`[onclick="switchTab('${tabId}')"]`).classList.add('active');
            document.getElementById(tabId).classList.add('active');

            if (tabId === 'connections') loadConnections();
            if (tabId === 'routes') loadRoutes();
            if (tabId === 'nics') loadNics();
            if (tabId === 'serverinfo') { loadServerInfo(); loadInterfaces(); }
            if (tabId === 'hardware') {
                const iface = document.getElementById('currentIface').value;
                if (iface) selectInterface();
                else document.getElementById('hwStatus').innerHTML = "No interface selected for capture yet.";
            }
            if (tabId === 'terminal') document.getElementById('termInput').focus();
        }

        function filterTable(containerId, query) {
            let filter = query.toLowerCase();
            let rows = document.getElementById(containerId).getElementsByTagName('tr');
            for (let i = 0; i < rows.length; i++) {
                if (rows[i].getElementsByTagName('th').length > 0) continue; // Skip header row
                let txt = rows[i].textContent || rows[i].innerText;
                rows[i].style.display = txt.toLowerCase().indexOf(filter) > -1 ? "" : "none";
            }
        }

        document.getElementById('tableContainer').addEventListener('scroll', function() {
            const container = this;
            const isAtBottom = container.scrollHeight - container.clientHeight <= container.scrollTop + 30;
            if (!isAtBottom && autoScroll) {
                autoScroll = false;
                document.getElementById('resumeScrollBtn').style.display = 'block';
            } else if (isAtBottom && !autoScroll) {
                autoScroll = true;
                document.getElementById('resumeScrollBtn').style.display = 'none';
            }
        });

        function resumeScroll() {
            autoScroll = true;
            document.getElementById('resumeScrollBtn').style.display = 'none';
            const container = document.getElementById('tableContainer');
            container.scrollTop = container.scrollHeight;
        }

        function applyDisplayFilter() {
            const terms = document.getElementById('displayFilter').value.toLowerCase().split(' ').filter(t => t.trim() !== '');
            const rows = document.getElementById('pktTableBody').getElementsByTagName('tr');
            for (let i = 0; i < rows.length; i++) {
                const text = rows[i].textContent.toLowerCase();
                let show = true;
                for (let t of terms) {
                    if (!text.includes(t)) {
                        show = false;
                        break;
                    }
                }
                rows[i].style.display = show ? "" : "none";
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

        function getWsClass(proto, risk) {
            if (risk > 40) return 'ws-bg-bad';
            let p = proto.toUpperCase();
            if (p.includes('TCP')) return 'ws-bg-tcp';
            if (p.includes('UDP')) return 'ws-bg-udp';
            if (p.includes('HTTP') || p.includes('TLS') || p.includes('SSL')) return 'ws-bg-http';
            if (p.includes('DNS')) return 'ws-bg-dns';
            if (p.includes('ICMP')) return 'ws-bg-icmp';
            if (p.includes('ARP')) return 'ws-bg-arp';
            if (p.includes('QUIC')) return 'ws-bg-http';
            return 'ws-bg-def';
        }

        async function loadInterfaces() { 
            try { 
                const res = await fetch('/api/interfaces'); 
                const ifaces = await res.json(); 
                
                let html = '<table class="settings-table"><thead><tr><th>Interface</th><th>Description</th><th>Action</th></tr></thead><tbody>';
                ifaces.forEach(i => { 
                    html += `<tr>
                        <td><strong>${i.name}</strong></td>
                        <td>${i.description || 'Virtual / Unknown'}</td>
                        <td><button class="primary-btn" onclick="startCaptureFor('${i.name}')">Start Capture</button></td>
                    </tr>`;
                });
                html += '</tbody></table>';
                document.getElementById('serverInterfacesList').innerHTML = html;
            } catch (err) { 
                document.getElementById('serverInterfacesList').textContent = "Failed to load interfaces. Is the server running?"; 
            } 
        }

        function startCaptureFor(iface) {
            document.getElementById('currentIface').value = iface;
            document.querySelectorAll('.analysis-tab').forEach(t => t.style.display = 'block');
            switchTab('dashboard');
            startInspect(false, iface);
        }
        
        function selectInterface() {
            loadNicDetail();
            loadEthtool();
            loadDataplane();
        }
        
        function toggleCapture() {
            if (isCapturing) stopInspect(); else startInspect(false, document.getElementById('currentIface').value);
        }
        
        function analyzePcap() {
            const readPath = document.getElementById('pcapRead').value;
            if (!readPath) return alert("Enter an absolute path to a PCAP file to analyze.");
            document.querySelectorAll('.analysis-tab').forEach(t => t.style.display = 'block');
            switchTab('dashboard');
            startInspect(true, readPath);
        }

        function uploadPcap() {
            alert("Upload functionality requires backend multipart parsing which is planned for a future update. Please use 'Analyze Server PCAP' with an absolute file path for now.");
        }

        function startInspect(isOffline = false, source = null) { 
            const bpf = document.getElementById('bpfFilter') ? document.getElementById('bpfFilter').value : ''; 
            let iface = '';
            let readPath = '';
            
            if (isOffline) {
                readPath = source || document.getElementById('pcapRead').value;
                if (!readPath) return alert("No PCAP file provided.");
            } else {
                iface = source || document.getElementById('currentIface').value;
                if (!iface) return alert("Select an interface first");
            }
            
            packetCount = 0; byteCount = 0; baseTs = null;
            autoScroll = true; document.getElementById('resumeScrollBtn').style.display = 'none';
            packetStore = [];
            flows = {}; protoStats = {}; talkerStats = {}; geoCache = {};
            document.getElementById('pktTableBody').innerHTML = '';
            document.getElementById('packetDetail').textContent = isOffline ? `Analyzing offline PCAP ${readPath}...` : `Starting live capture on ${iface}...`;
            document.getElementById('packetHex').textContent = '';
            
            const btn = document.getElementById('btnToggle');
            btn.textContent = "Stop Capture";
            btn.classList.add("stop");
            isCapturing = true;
            
            document.getElementById('sb-status').textContent = isOffline ? `Reading ${readPath}...` : `Capturing from ${iface}...`;
            
            if (eventSource) eventSource.close(); 
            let url = `/api/inspect?`;
            if (isOffline) {
                url += `read=${encodeURIComponent(readPath)}`;
            } else {
                url += `iface=${encodeURIComponent(iface)}`;
            }
            if (bpf) url += `&filter=${encodeURIComponent(bpf)}`; 
            
            eventSource = new EventSource(url); 
            eventSource.onmessage = function(event) { 
                const data = JSON.parse(event.data); 
                if (data.error) {
                    alert("Capture Error: " + data.error);
                    stopInspect();
                    return;
                }
                packetCount++; 
                byteCount += data.len;
                packetStore.push(data);
                updateStats(data);
                
                let ts = data.ts_sec + (data.ts_usec / 1000000.0);
                if (baseTs === null) baseTs = ts;
                let relTime = (ts - baseTs).toFixed(6);
                
                let tr = document.createElement('tr');
                tr.className = getWsClass(data.proto, data.risk);
                
                let riskBadge = data.risk > 0 ? `<span style="color:var(--danger);font-weight:bold;">[Risk: ${data.risk}]</span> ` : '';
                tr.innerHTML = `<td>${packetCount}</td><td>${relTime}</td><td>${escapeHtml(data.src)}</td><td>${escapeHtml(data.dst)}</td><td><strong>${escapeHtml(data.proto)}</strong></td><td>${data.len}</td><td class="info-cell" title="${escapeHtml(data.summary)}">${riskBadge}${escapeHtml(data.summary)}</td>`;
                
                let currentIndex = packetCount - 1;
                tr.onclick = function() { showDetail(currentIndex, tr); };
                
                const term = document.getElementById('displayFilter').value.toLowerCase();
                if (term && !tr.textContent.toLowerCase().includes(term)) {
                    tr.style.display = "none";
                }
                
                const container = document.getElementById('tableContainer');
                const isScrolledToBottom = container.scrollHeight - container.clientHeight <= container.scrollTop + 50;

                const tbody = document.getElementById('pktTableBody');
                tbody.appendChild(tr);
                
                if (autoScroll) {
                    container.scrollTop = container.scrollHeight;
                }
                
                document.getElementById('sb-stats').textContent = `Packets: ${packetCount} | Displayed: ${tbody.children.length} | Bytes: ${formatBytes(byteCount)}`;
            }; 
            eventSource.onerror = function() { stopInspect(); }; 
        }
        
        function stopInspect() { 
            if (eventSource) { eventSource.close(); eventSource = null; } 
            const btn = document.getElementById('btnToggle');
            btn.textContent = "Start";
            btn.classList.remove("stop");
            isCapturing = false;
            
            document.getElementById('sb-status').textContent = `Capture Stopped.`;
        }

        function escapeHtml(unsafe) {
            return (unsafe || "")
                 .replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
        }

        function showDetail(index, trElement) {
            autoScroll = false;
            document.getElementById('resumeScrollBtn').style.display = 'block';

            document.querySelectorAll('#pktTableBody tr').forEach(row => row.classList.remove('selected'));
            trElement.classList.add('selected');
            const pkt = packetStore[index];
            if (!pkt) return;
            
            let safeDetails = escapeHtml(pkt.details);
            let formattedDetails = safeDetails.replace(/-- ([^\n]+)/g, '<div class="detail-header">$1</div>');
            formattedDetails = formattedDetails.replace(/^  ([^:\[•]+): (.*)$/gm, '<div class="detail-row"><span class="detail-key">$1:</span> <span class="detail-val">$2</span></div>');
            formattedDetails = formattedDetails.replace(/^  (\[!\] .*)$/gm, '<div class="detail-row"><span class="detail-val" style="color:var(--danger); font-weight:600;">$1</span></div>');
            formattedDetails = formattedDetails.replace(/^  (• .*)$/gm, '<div class="detail-row"><span class="detail-val" style="color:var(--text-muted);">$1</span></div>');
            
            document.getElementById('packetDetail').innerHTML = formattedDetails;
            document.getElementById('packetHex').textContent = pkt.hex;
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
            const res = await fetch('/api/conn'); const data = await res.json();
            let html = '<table class="settings-table"><tr><th>Proto</th><th>Local Address</th><th>Remote Address</th><th>State</th><th>PID / Process</th></tr>';
            data.forEach(c => {
                let remote = c.remote_port === 0 ? "—" : `${c.remote_ip}:${c.remote_port}`;
                let proc = c.pid === 0 ? "—" : `${c.process} (${c.pid})`;
                let stateColor = c.state.includes("ESTABLISH") ? "green" : "inherit";
                html += `<tr><td>${c.proto}</td><td>${c.local_ip}:${c.local_port}</td><td>${remote}</td><td style="color:${stateColor}; font-weight:bold;">${c.state}</td><td>${proc}</td></tr>`;
            });
            document.getElementById('connContent').innerHTML = html + '</table>';
        }

        async function loadRoutes() {
            const res = await fetch('/api/route'); const data = await res.json();
            let html = '<table class="settings-table"><tr><th>Interface</th><th>Destination</th><th>Gateway</th><th>Metric</th></tr>';
            data.forEach(r => {
                let dest = `${r.destination}/${r.prefix_len}`;
                let gw = (r.gateway === "0.0.0.0" || r.gateway === "::") ? "Direct" : r.gateway;
                html += `<tr><td>${r.interface}</td><td>${dest}</td><td>${gw}</td><td>${r.metric}</td></tr>`;
            });
            document.getElementById('routeContent').innerHTML = html + '</table>';
        }

        async function loadNics() {
            const res = await fetch('/api/nic'); const data = await res.json();
            let html = '<table class="settings-table"><tr><th>Interface</th><th>State</th><th>MAC</th><th>MTU</th><th>RX</th><th>TX</th></tr>';
            data.forEach(n => {
                let stateColor = n.state.toLowerCase() === "up" ? "green" : "red";
                html += `<tr><td><strong>${n.name}</strong></td><td style="color:${stateColor}; font-weight:bold;">${n.state}</td><td>${n.mac}</td><td>${n.mtu}</td><td>${formatBytes(n.rx_bytes)}</td><td>${formatBytes(n.tx_bytes)}</td></tr>`;
            });
            document.getElementById('nicContent').innerHTML = html + '</table>';
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

        async function loadServerInfo() {
            try {
                const res = await fetch(`/api/server_info`);
                const data = await res.json();
                document.getElementById('serverContent').innerHTML = 
                    kvRow("Hostname", data.hostname) +
                    kvRow("Kernel Version", data.version) +
                    kvRow("Uptime", formatBytes(parseFloat(data.uptime_sec) * 1024).replace('B','s').replace('KB','mins').replace('MB','hours')) +
                    kvRow("Total Memory", formatBytes(parseFloat(data.mem_total_kb) * 1024));
            } catch (e) { document.getElementById('serverContent').innerHTML = "Error: Could not load server info."; }
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

        let termHistory = [];
        let termHistoryIndex = -1;

        function handleTermKey(event) {
            const input = document.getElementById('termInput');
            if (event.key === 'Enter') {
                runTerminalCommand();
            } else if (event.key === 'ArrowUp') {
                if (termHistoryIndex > 0) {
                    termHistoryIndex--;
                    input.value = termHistory[termHistoryIndex];
                }
                event.preventDefault();
            } else if (event.key === 'ArrowDown') {
                if (termHistoryIndex < termHistory.length - 1) {
                    termHistoryIndex++;
                    input.value = termHistory[termHistoryIndex];
                } else {
                    termHistoryIndex = termHistory.length;
                    input.value = '';
                }
                event.preventDefault();
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
            loadLayout();
            loadServerInfo();
            loadInterfaces();
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

        async function runTerminalCommand() {
            const input = document.getElementById('termInput');
            const out = document.getElementById('termOutput');
            const container = document.getElementById('termContainer');
            const cmd = input.value.trim();
            
            if (cmd) {
                termHistory.push(cmd);
            }
            termHistoryIndex = termHistory.length;
            
            out.innerHTML += `<span style="color:#38bdf8;">$ ${escapeHtml(cmd)}</span>\n`;
            input.value = '';
            container.scrollTop = container.scrollHeight;
            
            if (!cmd) return;
            
            try {
                const res = await fetch(`/api/terminal?cmd=${encodeURIComponent(cmd)}`);
                const data = await res.json();
                out.innerHTML += escapeHtml(data.output) || "";
                if (data.output && !data.output.endsWith('\n')) {
                    out.innerHTML += '\n';
                }
            } catch (e) {
                out.innerHTML += `Error: ${e.message}\n`;
            }
            container.scrollTop = container.scrollHeight;
        }
    </script>
</body>
</html>
"#;
}
