//! Deep Packet Inspection engine.
//! Parses every byte of a raw frame: Ethernet → VLAN → ARP/IPv4 → TCP/UDP/ICMP → Application.
//! All parsing is pure Rust — no libpcap, no external tools.

use std::net::Ipv4Addr;

// ─── Public result type ───────────────────────────────────────────────────────

/// Full layer-by-layer analysis of one raw packet.
#[derive(Debug, Clone)]
pub struct DeepPacket {
    pub frame_len: usize,

    // ── Layer 2: Ethernet ────────────────────────────────────────────────────
    pub eth_src: String,
    pub eth_dst: String,
    pub eth_vendor_src: Option<&'static str>,
    pub eth_vendor_dst: Option<&'static str>,
    /// 802.1Q / QinQ VLAN stack (outermost first).
    pub vlan_tags: Vec<VlanTag>,
    pub ether_type: u16,
    pub ether_type_name: &'static str,

    // ── Layer 2: ARP (when EtherType = 0x0806) ───────────────────────────────
    pub arp: Option<ArpDetail>,

    // ── Layer 3: IPv4 ────────────────────────────────────────────────────────
    pub ip_version: Option<u8>,
    pub ip_src: Option<Ipv4Addr>,
    pub ip_dst: Option<Ipv4Addr>,
    pub ip_hdr_len: Option<usize>,
    pub ip_total_len: Option<u16>,
    pub ip_id: Option<u16>,
    pub ip_ttl: Option<u8>,
    pub ip_proto: Option<u8>,
    pub ip_proto_name: Option<&'static str>,
    pub ip_dscp: Option<u8>,
    pub ip_ecn: Option<u8>,
    pub ip_flag_df: bool,
    pub ip_flag_mf: bool,
    pub ip_fragment: Option<u16>, // fragment offset × 8

    // ── Layer 4: TCP ─────────────────────────────────────────────────────────
    pub tcp_src_port: Option<u16>,
    pub tcp_dst_port: Option<u16>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_flags: Option<u16>,
    pub tcp_flags_str: Option<String>,
    pub tcp_window: Option<u16>,
    pub tcp_urgent: Option<u16>,
    pub tcp_hdr_len: Option<usize>,
    pub tcp_payload_len: usize,
    // TCP options
    pub tcp_mss: Option<u16>,
    pub tcp_window_scale: Option<u8>,
    pub tcp_sack_permitted: bool,
    pub tcp_sack_blocks: Vec<(u32, u32)>,
    pub tcp_timestamp: Option<(u32, u32)>,

    // ── Layer 4: UDP ─────────────────────────────────────────────────────────
    pub udp_src_port: Option<u16>,
    pub udp_dst_port: Option<u16>,
    pub udp_len: Option<u16>,
    pub udp_checksum: Option<u16>,
    pub udp_payload_len: usize,

    // ── Layer 4: ICMP ────────────────────────────────────────────────────────
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub icmp_type_str: Option<String>,
    pub icmp_id: Option<u16>,
    pub icmp_seq: Option<u16>,
    pub icmp_checksum: Option<u16>,

    // ── Layer 7: Application ─────────────────────────────────────────────────
    pub app_proto: Option<String>,
    pub app_detail: Vec<String>,

    // ── Raw payload ──────────────────────────────────────────────────────────
    /// Application-layer payload bytes (last layer's payload).
    pub payload: Vec<u8>,

    // ── Anomalies ─────────────────────────────────────────────────────────────
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VlanTag {
    pub id: u16,
    pub pcp: u8,
    pub dei: bool,
}

#[derive(Debug, Clone)]
pub struct ArpDetail {
    pub operation: &'static str, // "Request" / "Reply" / "?"
    pub sender_mac: String,
    pub sender_ip: Ipv4Addr,
    pub target_mac: String,
    pub target_ip: Ipv4Addr,
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/// Inspect raw packet bytes and return a `DeepPacket` with every decoded field.
pub fn inspect(raw: &[u8]) -> DeepPacket {
    let mut dp = DeepPacket::empty(raw.len());
    let mut anomalies: Vec<String> = Vec::new();

    if raw.len() < 14 {
        anomalies.push("Frame too short for Ethernet header".into());
        dp.anomalies = anomalies;
        return dp;
    }

    // ── Ethernet ─────────────────────────────────────────────────────────────
    let mut src_mac = [0u8; 6];
    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&raw[0..6]);
    src_mac.copy_from_slice(&raw[6..12]);
    dp.eth_dst = fmt_mac(&dst_mac);
    dp.eth_src = fmt_mac(&src_mac);
    dp.eth_vendor_dst = oui_vendor(&dst_mac);
    dp.eth_vendor_src = oui_vendor(&src_mac);

    if dst_mac == [0xff; 6] { /* broadcast — fine */ }
    if src_mac == [0xff; 6] {
        anomalies.push("Source MAC is broadcast (invalid)".into());
    }

    // ── VLAN tags (QinQ) ─────────────────────────────────────────────────────
    let mut offset = 12usize;
    loop {
        if offset + 4 > raw.len() {
            break;
        }
        let et = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        if et != 0x8100 && et != 0x88a8 {
            break;
        }
        let tci = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        dp.vlan_tags.push(VlanTag {
            id: tci & 0x0fff,
            pcp: (tci >> 13) as u8,
            dei: (tci >> 12) & 1 == 1,
        });
        offset += 4;
    }

    if offset + 2 > raw.len() {
        anomalies.push("Frame truncated after VLAN tags".into());
        dp.anomalies = anomalies;
        return dp;
    }

    let ether_type = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
    dp.ether_type = ether_type;
    dp.ether_type_name = ether_type_name(ether_type);
    offset += 2;

    let l3 = &raw[offset..];

    match ether_type {
        0x0806 => {
            // ARP
            dp.arp = parse_arp(l3, &mut anomalies);
        }
        0x0800 => {
            // IPv4
            parse_ipv4(l3, raw, &mut dp, &mut anomalies);
        }
        0x86dd => { /* IPv6 — not yet decoded */ }
        _ => {}
    }

    if dp.frame_len < 60 && ether_type != 0x8100 {
        // Ethernet minimum is 64 bytes (60 + 4 CRC), pad frames < 60 bytes
        // are normal for short packets on loopback/veth — not an anomaly.
    }

    dp.anomalies = anomalies;
    dp
}

// ─── ARP ─────────────────────────────────────────────────────────────────────

fn parse_arp(data: &[u8], anomalies: &mut Vec<String>) -> Option<ArpDetail> {
    if data.len() < 28 {
        anomalies.push("ARP packet too short".into());
        return None;
    }
    let op = u16::from_be_bytes([data[6], data[7]]);
    let op_str = match op {
        1 => "Request",
        2 => "Reply",
        _ => "?",
    };
    let sender_mac_b: [u8; 6] = data[8..14].try_into().ok()?;
    let sender_ip = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
    let target_mac_b: [u8; 6] = data[18..24].try_into().ok()?;
    let target_ip = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

    Some(ArpDetail {
        operation: op_str,
        sender_mac: fmt_mac(&sender_mac_b),
        sender_ip,
        target_mac: fmt_mac(&target_mac_b),
        target_ip,
    })
}

// ─── IPv4 ────────────────────────────────────────────────────────────────────

fn parse_ipv4(data: &[u8], _raw: &[u8], dp: &mut DeepPacket, anomalies: &mut Vec<String>) {
    if data.len() < 20 {
        anomalies.push("IPv4 header truncated".into());
        return;
    }
    let version = data[0] >> 4;
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    dp.ip_version = Some(version);
    dp.ip_hdr_len = Some(ihl);

    if version != 4 {
        anomalies.push(format!("Unexpected IP version: {version}"));
    }
    if ihl < 20 {
        anomalies.push("IPv4 IHL < 20 (malformed)".into());
        return;
    }
    if data.len() < ihl {
        anomalies.push("IPv4 header longer than frame".into());
        return;
    }

    let dscp_ecn = data[1];
    dp.ip_dscp = Some(dscp_ecn >> 2);
    dp.ip_ecn = Some(dscp_ecn & 0x03);
    dp.ip_total_len = Some(u16::from_be_bytes([data[2], data[3]]));
    dp.ip_id = Some(u16::from_be_bytes([data[4], data[5]]));

    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    dp.ip_flag_df = (flags_frag >> 14) & 1 == 1;
    dp.ip_flag_mf = (flags_frag >> 13) & 1 == 1;
    let frag_offset = (flags_frag & 0x1fff) * 8;
    if frag_offset > 0 || dp.ip_flag_mf {
        dp.ip_fragment = Some(frag_offset);
        anomalies.push(format!(
            "Fragmented packet (offset={frag_offset}, MF={})",
            dp.ip_flag_mf
        ));
    }

    dp.ip_ttl = Some(data[8]);
    dp.ip_proto = Some(data[9]);
    dp.ip_proto_name = Some(ip_proto_name(data[9]));
    dp.ip_src = Some(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    dp.ip_dst = Some(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

    if data[8] == 0 {
        anomalies.push("TTL=0 (invalid)".into());
    }
    if data[8] == 1 {
        anomalies.push("TTL=1 (will expire on next hop)".into());
    }

    // Check source IP sanity
    let src = dp.ip_src.unwrap();
    if src.is_unspecified() {
        anomalies.push("Source IP is 0.0.0.0".into());
    }
    if src.is_broadcast() {
        anomalies.push("Source IP is broadcast (spoofed?)".into());
    }

    let transport = &data[ihl..];

    match data[9] {
        6 => parse_tcp(transport, dp, anomalies),
        17 => parse_udp(transport, dp, anomalies),
        1 => parse_icmp(transport, dp, anomalies),
        proto => {
            dp.payload = transport.to_vec();
            let _ = proto;
        }
    }
}

// ─── TCP ─────────────────────────────────────────────────────────────────────

fn parse_tcp(data: &[u8], dp: &mut DeepPacket, anomalies: &mut Vec<String>) {
    if data.len() < 20 {
        anomalies.push("TCP header truncated".into());
        return;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let hdr_len = ((data[12] >> 4) as usize) * 4;
    let flags = u16::from_be_bytes([data[12] & 0x01, data[13]]);
    let window = u16::from_be_bytes([data[14], data[15]]);
    let urgent = u16::from_be_bytes([data[18], data[19]]);

    dp.tcp_src_port = Some(src_port);
    dp.tcp_dst_port = Some(dst_port);
    dp.tcp_seq = Some(seq);
    dp.tcp_ack = Some(ack);
    dp.tcp_flags = Some(flags);
    dp.tcp_flags_str = Some(decode_tcp_flags(flags));
    dp.tcp_window = Some(window);
    dp.tcp_urgent = Some(urgent);
    dp.tcp_hdr_len = Some(hdr_len);

    // Flag anomalies
    let syn = flags & 0x0002 != 0;
    let ack_f = flags & 0x0010 != 0;
    let fin = flags & 0x0001 != 0;
    let rst = flags & 0x0004 != 0;
    let psh = flags & 0x0008 != 0;
    if syn && fin {
        anomalies.push("TCP SYN+FIN set simultaneously (scan/malformed)".into());
    }
    if syn && rst {
        anomalies.push("TCP SYN+RST set simultaneously (malformed)".into());
    }
    if !syn && !ack_f && !fin && !rst && !psh {
        anomalies.push("TCP no flags set (NULL scan)".into());
    }
    if syn && psh {
        anomalies.push("TCP SYN+PSH unusual".into());
    }
    if window == 0 && syn {
        anomalies.push("TCP SYN with zero window (malformed)".into());
    }

    if hdr_len < 20 {
        anomalies.push("TCP data offset < 20 (malformed)".into());
        return;
    }
    if data.len() < hdr_len {
        anomalies.push("TCP header longer than segment".into());
        return;
    }

    // TCP options
    if hdr_len > 20 {
        parse_tcp_options(&data[20..hdr_len], dp, anomalies);
    }

    let payload = &data[hdr_len..];
    dp.tcp_payload_len = payload.len();
    dp.payload = payload.to_vec();

    // Application layer detection
    detect_app_tcp(src_port, dst_port, payload, dp);
}

fn parse_tcp_options(opts: &[u8], dp: &mut DeepPacket, anomalies: &mut Vec<String>) {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break, // End of options
            1 => {
                i += 1;
                continue;
            } // NOP
            2 => {
                // MSS
                if i + 4 > opts.len() {
                    break;
                }
                dp.tcp_mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                i += 4;
            }
            3 => {
                // Window scale
                if i + 3 > opts.len() {
                    break;
                }
                dp.tcp_window_scale = Some(opts[i + 2]);
                i += 3;
            }
            4 => {
                // SACK permitted
                dp.tcp_sack_permitted = true;
                i += 2;
            }
            5 => {
                // SACK blocks
                if i + 1 >= opts.len() {
                    break;
                }
                let len = opts[i + 1] as usize;
                if i + len > opts.len() {
                    break;
                }
                let mut j = i + 2;
                while j + 8 <= i + len {
                    let left = u32::from_be_bytes([opts[j], opts[j + 1], opts[j + 2], opts[j + 3]]);
                    let right =
                        u32::from_be_bytes([opts[j + 4], opts[j + 5], opts[j + 6], opts[j + 7]]);
                    dp.tcp_sack_blocks.push((left, right));
                    j += 8;
                }
                i += len;
            }
            8 => {
                // Timestamps
                if i + 10 > opts.len() {
                    break;
                }
                let tsval =
                    u32::from_be_bytes([opts[i + 2], opts[i + 3], opts[i + 4], opts[i + 5]]);
                let tsecr =
                    u32::from_be_bytes([opts[i + 6], opts[i + 7], opts[i + 8], opts[i + 9]]);
                dp.tcp_timestamp = Some((tsval, tsecr));
                i += 10;
            }
            _ => {
                if i + 1 >= opts.len() {
                    break;
                }
                let len = opts[i + 1] as usize;
                if len < 2 {
                    anomalies.push(format!(
                        "TCP option kind={} has length<2 (malformed)",
                        opts[i]
                    ));
                    break;
                }
                i += len;
            }
        }
    }
}

// ─── UDP ─────────────────────────────────────────────────────────────────────

fn parse_udp(data: &[u8], dp: &mut DeepPacket, anomalies: &mut Vec<String>) {
    if data.len() < 8 {
        anomalies.push("UDP header truncated".into());
        return;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let udp_len = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    dp.udp_src_port = Some(src_port);
    dp.udp_dst_port = Some(dst_port);
    dp.udp_len = Some(udp_len);
    dp.udp_checksum = Some(checksum);

    if udp_len < 8 {
        anomalies.push("UDP length < 8 (malformed)".into());
    }

    let payload = &data[8..];
    dp.udp_payload_len = payload.len();
    dp.payload = payload.to_vec();

    detect_app_udp(src_port, dst_port, payload, dp);
}

// ─── ICMP ────────────────────────────────────────────────────────────────────

fn parse_icmp(data: &[u8], dp: &mut DeepPacket, anomalies: &mut Vec<String>) {
    if data.len() < 8 {
        anomalies.push("ICMP header truncated".into());
        return;
    }
    let icmp_type = data[0];
    let icmp_code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    dp.icmp_type = Some(icmp_type);
    dp.icmp_code = Some(icmp_code);
    dp.icmp_checksum = Some(checksum);
    dp.icmp_type_str = Some(icmp_describe(icmp_type, icmp_code));

    // Echo request/reply carry id + seq
    if icmp_type == 0 || icmp_type == 8 {
        dp.icmp_id = Some(u16::from_be_bytes([data[4], data[5]]));
        dp.icmp_seq = Some(u16::from_be_bytes([data[6], data[7]]));
    }
    dp.payload = data[8..].to_vec();
}

// ─── Application layer detection ─────────────────────────────────────────────

fn detect_app_tcp(src: u16, dst: u16, payload: &[u8], dp: &mut DeepPacket) {
    // Check the higher port number — that is typically the server/service side
    match dst.max(src) {
        80 | 8080 | 8000 => {
            detect_http(payload, dp);
        }
        443 | 8443 => detect_tls(payload, dp),
        22 => {
            dp.app_proto = Some("SSH".into());
        }
        25 | 587 | 465 => detect_smtp(payload, dp),
        110 | 995 => {
            dp.app_proto = Some("POP3".into());
        }
        143 | 993 => {
            dp.app_proto = Some("IMAP".into());
        }
        21 => {
            dp.app_proto = Some("FTP Control".into());
        }
        23 => {
            dp.app_proto = Some("Telnet".into());
        }
        3306 => {
            dp.app_proto = Some("MySQL".into());
        }
        5432 => {
            dp.app_proto = Some("PostgreSQL".into());
        }
        6379 => {
            dp.app_proto = Some("Redis".into());
        }
        27017 => {
            dp.app_proto = Some("MongoDB".into());
        }
        3389 => {
            dp.app_proto = Some("RDP".into());
        }
        179 => {
            dp.app_proto = Some("BGP".into());
        }
        _ => {
            // Heuristic fallback: try HTTP/TLS regardless of non-standard port
            if payload.len() >= 4 {
                if !detect_http(payload, dp) {
                    detect_tls(payload, dp);
                }
            }
        }
    }
}

fn detect_app_udp(src: u16, dst: u16, payload: &[u8], dp: &mut DeepPacket) {
    match dst.max(src) {
        53 => detect_dns(payload, dp),
        67 | 68 => detect_dhcp(payload, dp),
        123 => {
            dp.app_proto = Some("NTP".into());
        }
        161 | 162 => {
            dp.app_proto = Some("SNMP".into());
        }
        500 | 4500 => {
            dp.app_proto = Some("IKE/IPsec".into());
        }
        514 => {
            dp.app_proto = Some("Syslog".into());
        }
        1900 => {
            dp.app_proto = Some("SSDP".into());
        }
        5353 => detect_dns(payload, dp), // mDNS
        4789 => {
            dp.app_proto = Some("VXLAN".into());
        }
        6081 => {
            dp.app_proto = Some("Geneve".into());
        }
        _ => {}
    }
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

fn detect_http(payload: &[u8], dp: &mut DeepPacket) -> bool {
    let Ok(text) = std::str::from_utf8(&payload[..payload.len().min(512)]) else {
        return false;
    };
    // Request: "GET / HTTP/1.1"
    let methods = [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    ];
    for m in &methods {
        if text.starts_with(m) {
            dp.app_proto = Some("HTTP".into());
            let first_line = text.lines().next().unwrap_or("").trim();
            dp.app_detail.push(format!("Request  : {first_line}"));
            // Extract Host header
            for line in text.lines().skip(1) {
                if line.to_lowercase().starts_with("host:") {
                    dp.app_detail
                        .push(format!("Host     : {}", line[5..].trim()));
                }
                if line.to_lowercase().starts_with("user-agent:") {
                    dp.app_detail
                        .push(format!("UserAgent: {}", line[11..].trim()));
                }
                if line.to_lowercase().starts_with("content-type:") {
                    dp.app_detail
                        .push(format!("Content  : {}", line[13..].trim()));
                }
                if line.is_empty() {
                    break;
                }
            }
            return true;
        }
    }
    // Response: "HTTP/1.1 200 OK"
    if text.starts_with("HTTP/") {
        dp.app_proto = Some("HTTP".into());
        let first_line = text.lines().next().unwrap_or("").trim();
        dp.app_detail.push(format!("Response : {first_line}"));
        for line in text.lines().skip(1) {
            if line.to_lowercase().starts_with("content-type:") {
                dp.app_detail
                    .push(format!("Content  : {}", line[13..].trim()));
            }
            if line.to_lowercase().starts_with("server:") {
                dp.app_detail
                    .push(format!("Server   : {}", line[7..].trim()));
            }
            if line.is_empty() {
                break;
            }
        }
        return true;
    }
    false
}

// ── TLS ───────────────────────────────────────────────────────────────────────

fn detect_tls(payload: &[u8], dp: &mut DeepPacket) {
    if payload.len() < 5 {
        return;
    }
    // TLS record: content_type(1) version(2) length(2)
    let content_type = payload[0];
    let ver_major = payload[1];
    let ver_minor = payload[2];
    if ver_major != 3 || ver_minor > 4 {
        return;
    }

    let tls_ver = match (ver_major, ver_minor) {
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => "TLS ?",
    };
    let record_type = match content_type {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        _ => return,
    };
    dp.app_proto = Some("TLS/SSL".into());
    dp.app_detail.push(format!("Version  : {tls_ver}"));
    dp.app_detail.push(format!("Record   : {record_type}"));

    // Try to extract SNI from ClientHello (handshake type 1)
    if content_type == 22 && payload.len() > 9 && payload[5] == 1 {
        if let Some(sni) = extract_sni(payload) {
            dp.app_detail.push(format!("SNI      : {sni}"));
        }
    }
}

fn extract_sni(payload: &[u8]) -> Option<String> {
    // Skip: TLS record header (5) + HandshakeType (1) + length (3) + version (2) + random (32)
    // = 43 bytes, then session_id_len (1) byte
    let mut pos = 43;
    if payload.len() <= pos {
        return None;
    }
    let sid_len = payload[pos] as usize;
    pos += 1 + sid_len;
    if payload.len() <= pos + 2 {
        return None;
    }
    let cipher_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if payload.len() <= pos {
        return None;
    }
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;
    if payload.len() <= pos + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(payload.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0 && pos + ext_data_len <= ext_end {
            // SNI extension: list_len(2) type(1) name_len(2) name
            if ext_data_len >= 5 {
                let name_len = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
                let name_start = pos + 5;
                if name_start + name_len <= payload.len() {
                    return std::str::from_utf8(&payload[name_start..name_start + name_len])
                        .ok()
                        .map(|s| s.to_string());
                }
            }
        }
        pos += ext_data_len;
    }
    None
}

// ── DNS ───────────────────────────────────────────────────────────────────────

fn detect_dns(payload: &[u8], dp: &mut DeepPacket) {
    if payload.len() < 12 {
        return;
    }
    dp.app_proto = Some("DNS".into());
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_resp = (flags & 0x8000) != 0;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let rcode = flags & 0x000f;
    let opcode = (flags >> 11) & 0x000f;
    let rd = (flags & 0x0100) != 0;
    let ra = (flags & 0x0080) != 0;
    let aa = (flags & 0x0400) != 0;
    let txid = u16::from_be_bytes([payload[0], payload[1]]);

    dp.app_detail.push(format!("TxID     : 0x{txid:04x}"));
    dp.app_detail.push(format!(
        "Type     : {}  OpCode={}",
        if is_resp { "Response" } else { "Query" },
        opcode
    ));
    dp.app_detail.push(format!(
        "Flags    : RD={} RA={} AA={}",
        rd as u8, ra as u8, aa as u8
    ));
    if is_resp {
        dp.app_detail
            .push(format!("RCode    : {}", dns_rcode(rcode)));
        dp.app_detail.push(format!("Answers  : {ancount}"));
    }

    // Decode question section
    if qdcount > 0 {
        if let Some((name, end)) = dns_parse_name(payload, 12) {
            if end + 4 <= payload.len() {
                let qtype = u16::from_be_bytes([payload[end], payload[end + 1]]);
                let qclass = u16::from_be_bytes([payload[end + 2], payload[end + 3]]);
                dp.app_detail.push(format!(
                    "Question : {} {} CLASS={}",
                    name,
                    dns_type(qtype),
                    qclass
                ));
            } else {
                dp.app_detail.push(format!("Question : {name}"));
            }
        }
    }
}

fn dns_rcode(code: u16) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "?",
    }
}

fn dns_type(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "?",
    }
}

fn dns_parse_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut hops = 0u8;
    loop {
        if hops > 20 || pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            pos = ptr;
            hops += 1;
            continue;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&data[pos..pos + len]).ok()?.to_string());
        pos += len;
    }
    Some((labels.join("."), pos))
}

// ── DHCP ──────────────────────────────────────────────────────────────────────

fn detect_dhcp(payload: &[u8], dp: &mut DeepPacket) {
    if payload.len() < 236 {
        return;
    }
    let msg_type = payload[0];
    let op = match msg_type {
        1 => "BOOTREQUEST",
        2 => "BOOTREPLY",
        _ => "?",
    };
    dp.app_proto = Some("DHCP".into());
    dp.app_detail.push(format!("Op       : {op}"));
    // Client IP
    let ciaddr = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    if !ciaddr.is_unspecified() {
        dp.app_detail.push(format!("ClientIP : {ciaddr}"));
    }
    if !yiaddr.is_unspecified() {
        dp.app_detail.push(format!("YourIP   : {yiaddr}"));
    }
    // Client MAC
    let mac: [u8; 6] = payload[28..34].try_into().unwrap_or([0; 6]);
    dp.app_detail.push(format!("ClientMAC: {}", fmt_mac(&mac)));
    // Magic cookie check
    if payload.len() >= 240 && &payload[236..240] == b"\x63\x82\x53\x63" {
        // Parse DHCP message type option (option 53)
        let opts = &payload[240..];
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                255 => break,
                0 => {
                    i += 1;
                    continue;
                }
                53 if i + 2 < opts.len() => {
                    let dhcp_type = match opts[i + 2] {
                        1 => "DISCOVER",
                        2 => "OFFER",
                        3 => "REQUEST",
                        4 => "DECLINE",
                        5 => "ACK",
                        6 => "NAK",
                        7 => "RELEASE",
                        8 => "INFORM",
                        _ => "?",
                    };
                    dp.app_detail.push(format!("MsgType  : {dhcp_type}"));
                    i += 3;
                    continue;
                }
                _ => {
                    if i + 1 >= opts.len() {
                        break;
                    }
                    i += 2 + opts[i + 1] as usize;
                    continue;
                }
            }
        }
    }
}

// ── SMTP ──────────────────────────────────────────────────────────────────────

fn detect_smtp(payload: &[u8], dp: &mut DeepPacket) {
    dp.app_proto = Some("SMTP".into());
    if let Ok(text) = std::str::from_utf8(&payload[..payload.len().min(256)]) {
        let first = text.lines().next().unwrap_or("").trim();
        if !first.is_empty() {
            dp.app_detail.push(format!("Banner   : {first}"));
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn decode_tcp_flags(flags: u16) -> String {
    let mut parts = Vec::new();
    if flags & 0x0002 != 0 {
        parts.push("SYN");
    }
    if flags & 0x0010 != 0 {
        parts.push("ACK");
    }
    if flags & 0x0001 != 0 {
        parts.push("FIN");
    }
    if flags & 0x0004 != 0 {
        parts.push("RST");
    }
    if flags & 0x0008 != 0 {
        parts.push("PSH");
    }
    if flags & 0x0020 != 0 {
        parts.push("URG");
    }
    if flags & 0x0040 != 0 {
        parts.push("ECE");
    }
    if flags & 0x0080 != 0 {
        parts.push("CWR");
    }
    if parts.is_empty() {
        "[none]".into()
    } else {
        parts.join("|")
    }
}

fn icmp_describe(t: u8, code: u8) -> String {
    match t {
        0 => format!("Echo Reply (id/seq via fields)"),
        3 => format!(
            "Dest Unreachable — {}",
            match code {
                0 => "Net",
                1 => "Host",
                2 => "Protocol",
                3 => "Port",
                4 => "Fragmentation needed",
                5 => "Source route failed",
                9 => "Net admin prohibited",
                10 => "Host admin prohibited",
                13 => "Comm admin prohibited",
                _ => "?",
            }
        ),
        4 => "Source Quench (deprecated)".into(),
        5 => format!(
            "Redirect — {}",
            match code {
                0 => "Net",
                1 => "Host",
                2 => "Net+TOS",
                3 => "Host+TOS",
                _ => "?",
            }
        ),
        8 => "Echo Request".into(),
        9 => "Router Advertisement".into(),
        10 => "Router Solicitation".into(),
        11 => format!(
            "Time Exceeded — {}",
            match code {
                0 => "TTL in transit",
                1 => "Fragment reassembly",
                _ => "?",
            }
        ),
        12 => "Parameter Problem".into(),
        13 => "Timestamp Request".into(),
        14 => "Timestamp Reply".into(),
        30 => "Traceroute".into(),
        _ => format!("Type {t} Code {code}"),
    }
}

pub fn fmt_mac(b: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

fn ether_type_name(et: u16) -> &'static str {
    match et {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "VLAN (802.1Q)",
        0x88a8 => "QinQ (802.1ad)",
        0x8847 => "MPLS Unicast",
        0x8848 => "MPLS Multicast",
        0x0842 => "Wake-on-LAN",
        0x88cc => "LLDP",
        0x88e5 => "MACsec",
        0x9000 => "Loopback",
        _ => "Unknown",
    }
}

fn ip_proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "Unknown",
    }
}

/// Very rough OUI lookup (top vendors only).
fn oui_vendor(mac: &[u8; 6]) -> Option<&'static str> {
    let oui = ((mac[0] as u32) << 16) | ((mac[1] as u32) << 8) | (mac[2] as u32);
    match oui {
        0x000c29 | 0x000569 | 0x001c14 | 0x005056 => Some("VMware"),
        0x525400 => Some("QEMU/KVM"),
        0x001a2b => Some("Dell"),
        0x0025b3 => Some("Dell"),
        0x3c970e => Some("Dell"),
        0xf8bc12 => Some("Dell"),
        0x00163e => Some("Xen"),
        0x020000..=0x02ffff => Some("Locally administered"),
        _ if mac[0] & 0x01 == 1 => Some("Multicast"),
        _ => None,
    }
}

// ─── Analysis methods: one-liner summary + rule-based diagnosis ───────────────

impl DeepPacket {
    /// One-line packet description: `[PROTO FLAGS] src → dst [SERVICE]  TTL=N  (N bytes)`.
    pub fn one_liner(&self) -> String {
        let proto = if self.tcp_src_port.is_some() {
            "TCP"
        } else if self.udp_src_port.is_some() {
            "UDP"
        } else if self.icmp_type.is_some() {
            "ICMP"
        } else if self.arp.is_some() {
            "ARP"
        } else {
            "ETH"
        };

        if let Some(arp) = &self.arp {
            return format!(
                "[ARP {}]  {} ({}) → {}",
                arp.operation, arp.sender_ip, arp.sender_mac, arp.target_ip
            );
        }

        let flags_s = self
            .tcp_flags_str
            .as_deref()
            .filter(|s| *s != "[none]")
            .map(|s| format!(" {s}"))
            .unwrap_or_default();

        let src = match (self.ip_src, self.tcp_src_port.or(self.udp_src_port)) {
            (Some(ip), Some(p)) => format!("{ip}:{p}"),
            (Some(ip), None) => ip.to_string(),
            _ => self.eth_src.clone(),
        };

        let dst_port = self.tcp_dst_port.or(self.udp_dst_port);
        let dst = match (self.ip_dst, dst_port) {
            (Some(ip), Some(p)) => format!("{ip}:{p}"),
            (Some(ip), None) => ip.to_string(),
            _ => self.eth_dst.clone(),
        };

        let svc = dst_port
            .and_then(quick_svc)
            .map(|s| format!(" [{s}]"))
            .unwrap_or_default();

        let ttl_s = self
            .ip_ttl
            .map(|t| format!("  TTL={t}"))
            .unwrap_or_default();
        let win_s = if self.tcp_window == Some(0) {
            "  [ZERO-WIN]"
        } else {
            ""
        };
        let icmp_s = self
            .icmp_type_str
            .as_deref()
            .map(|s| format!("  {s}"))
            .unwrap_or_default();
        let vlan_s = if self.vlan_tags.is_empty() {
            String::new()
        } else {
            let ids: Vec<_> = self.vlan_tags.iter().map(|t| t.id.to_string()).collect();
            format!("  VLAN={}", ids.join("→"))
        };

        format!(
            "[{proto}{flags_s}]  {src} → {dst}{svc}{ttl_s}{vlan_s}{icmp_s}{win_s}  ({} bytes)",
            self.frame_len
        )
    }

    /// Rule-based diagnostic findings — human-readable interpretation of the packet.
    pub fn diagnose(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.diagnose_tcp(&mut out);
        self.diagnose_ip(&mut out);
        self.diagnose_icmp(&mut out);
        self.diagnose_arp(&mut out);
        self.diagnose_app(&mut out);
        self.diagnose_misc(&mut out);
        if out.is_empty() {
            out.push("No specific diagnosis available for this packet type.".into());
        }
        out
    }

    fn diagnose_tcp(&self, out: &mut Vec<String>) {
        let Some(flags) = self.tcp_flags else { return };
        let syn = flags & 0x0002 != 0;
        let ack = flags & 0x0010 != 0;
        let fin = flags & 0x0001 != 0;
        let rst = flags & 0x0004 != 0;
        let psh = flags & 0x0008 != 0;

        if syn && !ack {
            out.push("TCP SYN — connection request (3-way handshake step 1/3)".into());
            if self.tcp_mss.is_none() {
                out.push(
                    "No MSS option in SYN — unusual; may cause fragmentation on this path".into(),
                );
            }
        } else if syn && ack {
            out.push("TCP SYN-ACK — server accepted connection (handshake step 2/3)".into());
        } else if fin && ack && !rst {
            out.push("TCP FIN-ACK — graceful connection teardown initiated".into());
        } else if rst {
            out.push("TCP RST — connection abruptly reset".into());
            if self.tcp_payload_len == 0 && !syn {
                out.push("RST with no payload — connection refused or firewall rule hit".into());
            }
        } else if psh && ack {
            out.push(format!(
                "TCP data push — {} bytes of application payload",
                self.tcp_payload_len
            ));
        } else if ack && !psh && !fin && !syn {
            out.push("TCP ACK — bare acknowledgement (no data)".into());
        }

        if let Some(win) = self.tcp_window {
            if win == 0 && !rst {
                out.push("Zero receive window — receiver buffer full; sender must pause (TCP flow control)".into());
            }
        }

        if let Some(mss) = self.tcp_mss {
            if mss < 536 {
                out.push(format!(
                    "Very small MSS={mss} — path likely has a tunnel or strict MTU constraint"
                ));
            } else if mss == 1452 {
                out.push("MSS=1452 — PPPoE path (8-byte overhead reducing standard 1460)".into());
            } else if mss == 1460 {
                out.push("MSS=1460 — standard Ethernet path (no encapsulation overhead)".into());
            }
        }

        if let Some((0, _)) = self.tcp_timestamp {
            out.push("TCP timestamp=0 — connection just started or host recently booted".into());
        }
    }

    fn diagnose_ip(&self, out: &mut Vec<String>) {
        let Some(ttl) = self.ip_ttl else { return };
        match ttl {
            64 => out.push("TTL=64 — source OS: Linux / macOS / Android (default)".into()),
            128 => out.push("TTL=128 — source OS: Windows (default)".into()),
            255 => out.push("TTL=255 — source: network device / Cisco IOS / HP ProCurve".into()),
            _ => {}
        }
        if self.ip_flag_df {
            out.push("DF bit set — sender using Path MTU Discovery (PMTUD)".into());
        }
        if let Some(dscp) = self.ip_dscp {
            if dscp > 0 {
                let label = match dscp {
                    8 => "CS1 — background/scavenger",
                    16 => "CS2 — OAM",
                    18 => "AF21 — assured forwarding",
                    24 => "CS3 — call signalling",
                    32 => "CS4 — broadcast video",
                    34 => "AF41 — real-time interactive",
                    40 => "CS5 — telephony",
                    46 => "EF — expedited forwarding (VoIP/low-latency)",
                    48 => "CS6 — network control",
                    56 => "CS7 — highest priority",
                    _ => "custom QoS class",
                };
                out.push(format!("DSCP={dscp} — QoS marking: {label}"));
            }
        }
    }

    fn diagnose_icmp(&self, out: &mut Vec<String>) {
        let Some(t) = self.icmp_type else { return };
        match t {
            8  => out.push(format!("Ping request — id={} seq={}",
                self.icmp_id.unwrap_or(0), self.icmp_seq.unwrap_or(0))),
            0  => out.push(format!("Ping reply — id={} seq={} (match pair to measure RTT)",
                self.icmp_id.unwrap_or(0), self.icmp_seq.unwrap_or(0))),
            3  => out.push("Destination unreachable — check firewall rules, route table, or that target port is listening".into()),
            4  => out.push("Source Quench (deprecated, RFC 6633) — ignore".into()),
            5  => out.push("ICMP Redirect — router instructing sender to use a different next-hop".into()),
            11 => out.push("TTL Exceeded — traceroute probe or routing loop detected".into()),
            _ => {}
        }
    }

    fn diagnose_arp(&self, out: &mut Vec<String>) {
        let Some(arp) = &self.arp else { return };
        match arp.operation {
            "Request" => out.push(format!(
                "ARP who-has {}? — broadcast from {} ({})",
                arp.target_ip, arp.sender_ip, arp.sender_mac
            )),
            "Reply" => out.push(format!(
                "ARP reply: {} is at {} — L2 neighbor cache updated",
                arp.sender_ip, arp.sender_mac
            )),
            _ => {}
        }
        if arp.sender_ip == arp.target_ip {
            out.push(format!("Gratuitous ARP — {} announcing its own MAC; normal after failover / IP conflict detection",
                arp.sender_ip));
        }
    }

    fn diagnose_app(&self, out: &mut Vec<String>) {
        let Some(proto) = &self.app_proto else { return };
        let detail_val = |key: &str| -> Option<String> {
            self.app_detail
                .iter()
                .find(|l| l.trim_start().starts_with(key))
                .and_then(|l| l.splitn(2, ':').nth(1))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        match proto.as_str() {
            "DNS" => {
                let type_line = detail_val("Type").unwrap_or_default();
                let is_resp   = type_line.contains("Response");
                if let Some(q) = detail_val("Question") {
                    if is_resp {
                        let rcode = detail_val("RCode").unwrap_or_else(|| "NOERROR".into());
                        out.push(format!("DNS response: {q}  →  {rcode}"));
                        match rcode.as_str() {
                            "NXDOMAIN" => out.push("NXDOMAIN — domain not found; check spelling or DNS server config".into()),
                            "SERVFAIL" => out.push("SERVFAIL — authoritative server error; possible DNS misconfiguration".into()),
                            "REFUSED"  => out.push("REFUSED — server rejected query; check client ACLs".into()),
                            _ => {}
                        }
                    } else {
                        out.push(format!("DNS query: {q}"));
                    }
                }
            }
            "TLS/SSL" => {
                let ver = detail_val("Version").unwrap_or_else(|| "TLS ?".into());
                let rec = detail_val("Record").unwrap_or_default();
                if let Some(sni) = detail_val("SNI") {
                    out.push(format!("TLS ClientHello → connecting to: {sni}  ({ver})"));
                    out.push("SNI sent in plaintext — hostname visible before encryption starts".into());
                } else if rec == "ApplicationData" {
                    out.push(format!("{ver} encrypted data — payload not readable without session keys"));
                } else if !rec.is_empty() {
                    out.push(format!("{ver} — {rec}"));
                }
                if ver.contains("1.0") || ver.contains("1.1") {
                    out.push(format!("{ver} is deprecated (RFC 8996) — upgrade to TLS 1.2+"));
                }
            }
            "HTTP" => {
                if let Some(req) = detail_val("Request") {
                    out.push(format!("HTTP request: {req}"));
                    out.push("Cleartext HTTP — all data visible on wire; consider HTTPS".into());
                } else if let Some(resp) = detail_val("Response") {
                    let code: u16 = resp.split_whitespace().nth(1)
                        .and_then(|s| s.parse().ok()).unwrap_or(0);
                    let class = match code {
                        200..=299 => "✓ Success",
                        301 | 302 | 307 | 308 => "→ Redirect",
                        400 => "✗ Bad Request",
                        401 => "✗ Unauthorized — credentials required",
                        403 => "✗ Forbidden — access denied",
                        404 => "✗ Not Found",
                        429 => "✗ Rate Limited",
                        500 => "✗ Internal Server Error",
                        502 => "✗ Bad Gateway",
                        503 => "✗ Service Unavailable",
                        _   => "",
                    };
                    if class.is_empty() {
                        out.push(format!("HTTP response: {resp}"));
                    } else {
                        out.push(format!("HTTP response: {resp}  [{class}]"));
                    }
                }
            }
            "DHCP" => {
                let mt = detail_val("MsgType").unwrap_or_else(|| "?".into());
                out.push(format!("DHCP {mt}"));
                match mt.as_str() {
                    "DISCOVER" => out.push("Client broadcasting to find DHCP server (no IP yet)".into()),
                    "OFFER"    => {
                        let ip = detail_val("YourIP").unwrap_or_else(|| "?".into());
                        out.push(format!("Server offering IP: {ip}"));
                    }
                    "REQUEST"  => out.push("Client requesting or renewing a specific lease".into()),
                    "ACK"      => out.push("Lease confirmed — client may now use the IP address".into()),
                    "NAK"      => out.push("Lease rejected — IP unavailable or wrong subnet".into()),
                    "RELEASE"  => out.push("Client releasing IP address back to pool".into()),
                    _ => {}
                }
            }
            "NTP"    => out.push("NTP clock sync — large response (>400B) may indicate amplification abuse".into()),
            "SNMP"   => out.push("SNMP management — ensure SNMPv3 auth; avoid community string exposure".into()),
            "BGP"    => out.push("BGP peering — protect with TCP-MD5 or TTL-security (GTSM)".into()),
            "VXLAN"  => out.push("VXLAN tunnel — inner L2 frame encapsulated; re-inspect inner payload for real traffic".into()),
            "SSH"    => out.push("SSH — encrypted; many SYNs with RSTs on port 22 suggest brute-force scanning".into()),
            other    => out.push(format!("Application: {other}")),
        }
    }

    fn diagnose_misc(&self, out: &mut Vec<String>) {
        if !self.vlan_tags.is_empty() {
            let ids: Vec<_> = self.vlan_tags.iter().map(|t| t.id.to_string()).collect();
            out.push(format!("VLAN-tagged frame: {}", ids.join(" → ")));
        }
        if self.ip_flag_mf || self.ip_fragment.unwrap_or(0) > 0 {
            out.push(
                "Fragmented IP — full decode only possible after all fragments are reassembled"
                    .into(),
            );
        }
        if let Some(vendor) = self.eth_vendor_src {
            out.push(format!("Source NIC vendor: {vendor}"));
        }
    }
}

fn quick_svc(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 => "DHCP",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        179 => "BGP",
        443 => "HTTPS",
        465 => "SMTPS",
        514 => "Syslog",
        587 => "SMTP",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PgSQL",
        6379 => "Redis",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => return None,
    })
}

// ─── Display helper (hex+ASCII dump) ─────────────────────────────────────────

/// Format raw bytes as Wireshark-style hex+ASCII dump.
pub fn hex_dump(data: &[u8], max_bytes: usize) -> Vec<String> {
    let data = &data[..data.len().min(max_bytes)];
    let mut lines = Vec::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        // Pad to 16 columns
        let mut hex_padded = hex.join(" ");
        while hex_padded.len() < 48 {
            hex_padded.push(' ');
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        lines.push(format!("  {offset:04x}  {hex_padded}  |{ascii}|"));
    }
    if data.len() == max_bytes {
        lines.push(format!("  ... (truncated at {max_bytes} bytes)"));
    }
    lines
}

// ─── Empty constructor ────────────────────────────────────────────────────────

impl DeepPacket {
    fn empty(frame_len: usize) -> Self {
        DeepPacket {
            frame_len,
            eth_src: String::new(),
            eth_dst: String::new(),
            eth_vendor_src: None,
            eth_vendor_dst: None,
            vlan_tags: Vec::new(),
            ether_type: 0,
            ether_type_name: "",
            arp: None,
            ip_version: None,
            ip_src: None,
            ip_dst: None,
            ip_hdr_len: None,
            ip_total_len: None,
            ip_id: None,
            ip_ttl: None,
            ip_proto: None,
            ip_proto_name: None,
            ip_dscp: None,
            ip_ecn: None,
            ip_flag_df: false,
            ip_flag_mf: false,
            ip_fragment: None,
            tcp_src_port: None,
            tcp_dst_port: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            tcp_flags_str: None,
            tcp_window: None,
            tcp_urgent: None,
            tcp_hdr_len: None,
            tcp_payload_len: 0,
            tcp_mss: None,
            tcp_window_scale: None,
            tcp_sack_permitted: false,
            tcp_sack_blocks: Vec::new(),
            tcp_timestamp: None,
            udp_src_port: None,
            udp_dst_port: None,
            udp_len: None,
            udp_checksum: None,
            udp_payload_len: 0,
            icmp_type: None,
            icmp_code: None,
            icmp_type_str: None,
            icmp_id: None,
            icmp_seq: None,
            icmp_checksum: None,
            app_proto: None,
            app_detail: Vec::new(),
            payload: Vec::new(),
            anomalies: Vec::new(),
        }
    }
}
