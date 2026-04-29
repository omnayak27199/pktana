// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

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

    // ── TLS enhanced (JA3, ALPN, cipher suites) ──────────────────────────────
    /// Raw TLS cipher suite values (from ClientHello),  GREASE filtered.
    pub tls_ciphers: Vec<u16>,
    /// Negotiated / offered ALPN protocols (e.g. ["h2", "http/1.1"]).
    pub tls_alpn: Vec<String>,
    /// JA3 fingerprint input string:  "TLSVer,Ciphers,Extensions,Curves,PointFmts".
    /// MD5(tls_ja3_raw) == JA3 fingerprint used by security tools.
    pub tls_ja3_raw: Option<String>,

    // ── QUIC / HTTP3 ─────────────────────────────────────────────────────────
    pub quic_detected: bool,
    pub quic_version: Option<u32>,
    pub quic_packet_type: Option<&'static str>,

    // ── HTTP/2 & gRPC ────────────────────────────────────────────────────────
    pub http2_detected: bool,
    /// gRPC :path header value (if observed inside clear HTTP/2).
    pub grpc_path: Option<String>,

    // ── WebSocket ────────────────────────────────────────────────────────────
    pub ws_upgrade: bool,

    // ── Tunnel inner-frame ───────────────────────────────────────────────────
    /// Encapsulation type: "VXLAN", "GRE", "Geneve", …
    pub tunnel_type: Option<String>,
    pub inner_ip_src: Option<std::net::Ipv4Addr>,
    pub inner_ip_dst: Option<std::net::Ipv4Addr>,
    pub inner_proto: Option<&'static str>,
    pub inner_src_port: Option<u16>,
    pub inner_dst_port: Option<u16>,
    pub inner_app_proto: Option<String>,

    // ── SSH ──────────────────────────────────────────────────────────────────
    pub ssh_banner: Option<String>,

    // ── SIP / VoIP ───────────────────────────────────────────────────────────
    pub sip_method: Option<String>,
    pub sip_uri: Option<String>,
    pub sip_call_id: Option<String>,

    // ── NTP ──────────────────────────────────────────────────────────────────
    pub ntp_version: Option<u8>,
    pub ntp_mode: Option<u8>,
    pub ntp_stratum: Option<u8>,
    /// True when response > 468 bytes — potential amplification abuse.
    pub ntp_amplification_risk: bool,

    // ── BGP ──────────────────────────────────────────────────────────────────
    pub bgp_msg_type: Option<String>,
    pub bgp_asn: Option<u16>,

    // ── IPv6 ─────────────────────────────────────────────────────────────────
    pub ipv6_src: Option<String>,
    pub ipv6_dst: Option<String>,
    pub ipv6_next_header: Option<u8>,
    pub ipv6_hop_limit: Option<u8>,

    // ── DNS enhanced ─────────────────────────────────────────────────────────
    /// Shannon entropy of the queried label (high = possible DGA / tunneling).
    pub dns_label_entropy: Option<f32>,
    pub dns_query_name: Option<String>,

    // ── Risk / classification ─────────────────────────────────────────────────
    /// Composite 0-100 risk score  (0 = benign, 100 = high risk).
    pub risk_score: u8,
    pub risk_reasons: Vec<String>,
    /// High-level traffic category: "WebBrowsing", "Streaming", "VoIP", "Tunnel", …
    pub app_category: Option<String>,
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
        0x86dd => {
            // IPv6 — basic header decode
            parse_ipv6(l3, &mut dp, &mut anomalies);
        }
        _ => {}
    }

    if dp.frame_len < 60 && ether_type != 0x8100 {
        // short frame — normal on loopback/veth
    }

    dp.anomalies = anomalies;
    // Post-processing: risk score + app category
    dp.compute_risk();
    dp.classify_app_category();
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
        47 => parse_gre(transport, dp, anomalies),
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
    if payload.is_empty() {
        return;
    }

    // Port-agnostic heuristics first (content sniffing)
    // HTTP/2 PRI magic
    if detect_http2(payload, dp) {
        return;
    }
    // WebSocket upgrade
    if detect_websocket(payload, dp) {
        return;
    }
    // SSH banner
    if payload.starts_with(b"SSH-") {
        detect_ssh_banner(payload, dp);
        return;
    }
    // BGP (16 × 0xFF marker)
    if payload.starts_with(&[0xff; 16]) {
        detect_bgp(payload, dp);
        return;
    }
    // SIP (well-known method words or SIP/ response)
    if payload.starts_with(b"INVITE")
        || payload.starts_with(b"SIP/")
        || payload.starts_with(b"REGISTER")
        || payload.starts_with(b"OPTIONS")
        || payload.starts_with(b"BYE ")
        || payload.starts_with(b"ACK ")
    {
        detect_sip(payload, dp);
        return;
    }

    // Port-based dispatch (check both src and dst)
    match dst.max(src) {
        80 | 8080 | 8000 => {
            detect_http(payload, dp);
        }
        443 | 8443 => detect_tls(payload, dp),
        22 => detect_ssh_banner(payload, dp),
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
        179 => detect_bgp(payload, dp),
        389 | 636 => {
            dp.app_proto = Some("LDAP".into());
        }
        88 => {
            dp.app_proto = Some("Kerberos".into());
        }
        5060 | 5061 => detect_sip(payload, dp),
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
        _ => {
            // Heuristic fallback: try HTTP then TLS regardless of non-standard port
            if !detect_http(payload, dp) {
                detect_tls(payload, dp);
            }
        }
    }
}

fn detect_app_udp(src: u16, dst: u16, payload: &[u8], dp: &mut DeepPacket) {
    match dst.max(src) {
        53 => detect_dns(payload, dp),
        67 | 68 => detect_dhcp(payload, dp),
        123 => detect_ntp_full(payload, dp),
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
        5060 | 5061 => detect_sip(payload, dp),
        4789 => {
            dp.app_proto = Some("VXLAN".into());
            inspect_vxlan_inner(payload, dp);
        }
        6081 => {
            dp.app_proto = Some("Geneve".into());
        }
        // QUIC runs on UDP 443 (HTTP3) and occasionally 80
        443 | 80 => {
            detect_quic(payload, dp);
            if !dp.quic_detected {
                detect_dns(payload, dp);
            } // fallback for DoH-over-UDP
        }
        _ => {
            // QUIC heuristic: check long-header bit pattern regardless of port
            detect_quic(payload, dp);
        }
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

    // ClientHello (handshake type 1) — extract SNI, ALPN, ciphers, JA3
    if content_type == 22 && payload.len() > 9 && payload[5] == 1 {
        if let Some(sni) = extract_sni(payload) {
            dp.app_detail.push(format!("SNI      : {sni}"));
        }
        // Full ClientHello parsing for JA3 + ALPN + ciphers
        parse_tls_client_hello(payload, dp);
    }
    // TLS 1.0/1.1 deprecation warning
    if ver_minor <= 2 {
        dp.app_detail.push(format!(
            "⚠ {tls_ver} is deprecated (RFC 8996) — upgrade to TLS 1.2+"
        ));
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
            dp.dns_query_name = Some(name.clone());
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
            // Shannon entropy of the longest label for DGA/tunnel detection
            let longest = name.split('.').max_by_key(|l| l.len()).unwrap_or("");
            if longest.len() >= 10 {
                let entropy = shannon_entropy(longest);
                dp.dns_label_entropy = Some(entropy);
                if entropy > 3.5 {
                    dp.app_detail.push(format!(
                        "⚠ DNS label entropy={entropy:.2} (high — possible DGA/tunneling)"
                    ));
                }
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

// ── SSH ───────────────────────────────────────────────────────────────────────

fn detect_ssh_banner(payload: &[u8], dp: &mut DeepPacket) {
    // SSH identification string: "SSH-2.0-OpenSSH_8.4\r\n" or "SSH-1.99-..."
    if let Ok(text) = std::str::from_utf8(&payload[..payload.len().min(256)]) {
        if text.starts_with("SSH-") {
            dp.app_proto = Some("SSH".into());
            let banner = text.lines().next().unwrap_or("").trim();
            dp.ssh_banner = Some(banner.to_string());
            dp.app_detail.push(format!("Banner   : {banner}"));
            // Software version hint
            if let Some(sw) = banner.splitn(3, '-').nth(2) {
                dp.app_detail.push(format!("Software : {sw}"));
            }
            // Flag SSH-1.x (insecure)
            if text.starts_with("SSH-1.") {
                dp.app_detail
                    .push("⚠ SSHv1 is deprecated and cryptographically broken".to_string());
            }
        }
    }
}

// ── SIP / VoIP ────────────────────────────────────────────────────────────────

fn detect_sip(payload: &[u8], dp: &mut DeepPacket) {
    let Ok(text) = std::str::from_utf8(&payload[..payload.len().min(512)]) else {
        return;
    };

    // SIP request line: "INVITE sip:bob@example.com SIP/2.0"
    // SIP response:     "SIP/2.0 200 OK"
    let first_line = text.lines().next().unwrap_or("").trim();
    if first_line.starts_with("SIP/2.0") {
        // Response
        dp.app_proto = Some("SIP".into());
        dp.app_detail.push(format!("Response : {first_line}"));
    } else {
        let methods = [
            "INVITE",
            "ACK",
            "BYE",
            "CANCEL",
            "REGISTER",
            "OPTIONS",
            "PRACK",
            "SUBSCRIBE",
            "NOTIFY",
            "PUBLISH",
            "INFO",
            "REFER",
            "MESSAGE",
            "UPDATE",
        ];
        let method = methods.iter().find(|&&m| first_line.starts_with(m));
        if let Some(&m) = method {
            dp.app_proto = Some("SIP".into());
            dp.sip_method = Some(m.to_string());
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                dp.sip_uri = Some(parts[1].to_string());
                dp.app_detail.push(format!("Method   : {m}"));
                dp.app_detail.push(format!("URI      : {}", parts[1]));
            }
        } else {
            return;
        }
    }
    // Extract key headers
    for line in text.lines().skip(1) {
        let lower = line.to_lowercase();
        if lower.starts_with("call-id:") || lower.starts_with("i:") {
            let val = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
            dp.sip_call_id = Some(val.to_string());
            dp.app_detail.push(format!("Call-ID  : {val}"));
        } else if lower.starts_with("from:") || lower.starts_with("f:") {
            let val = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
            dp.app_detail.push(format!("From     : {val}"));
        } else if lower.starts_with("to:") || lower.starts_with("t:") {
            let val = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
            dp.app_detail.push(format!("To       : {val}"));
        } else if lower.starts_with("user-agent:") {
            let val = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
            dp.app_detail.push(format!("UA       : {val}"));
        }
        if line.trim().is_empty() {
            break;
        }
    }
}

// ── NTP ───────────────────────────────────────────────────────────────────────

fn detect_ntp_full(payload: &[u8], dp: &mut DeepPacket) {
    if payload.len() < 48 {
        return;
    }
    let byte0 = payload[0];
    let li = (byte0 >> 6) & 0x03;
    let version = (byte0 >> 3) & 0x07;
    let mode = byte0 & 0x07;
    let stratum = payload[1];
    let poll = payload[2] as i8;
    let precision = payload[3] as i8;

    dp.app_proto = Some("NTP".into());
    dp.ntp_version = Some(version);
    dp.ntp_mode = Some(mode);
    dp.ntp_stratum = Some(stratum);

    let mode_str = match mode {
        0 => "Reserved",
        1 => "Symmetric Active",
        2 => "Symmetric Passive",
        3 => "Client",
        4 => "Server",
        5 => "Broadcast",
        6 => "Control",
        7 => "Private (monlist?)",
        _ => "?",
    };
    let stratum_str = match stratum {
        0 => "Unspecified/KoD",
        1 => "Primary (GPS / atomic clock)",
        2..=15 => "Secondary",
        16..=255 => "Unsynchronized",
    };
    let li_str = match li {
        0 => "No warning",
        1 => "Last minute 61s",
        2 => "Last minute 59s",
        _ => "Clock unsynchronized",
    };

    dp.app_detail.push(format!("Version  : NTPv{version}"));
    dp.app_detail
        .push(format!("Mode     : {mode} ({mode_str})"));
    dp.app_detail
        .push(format!("Stratum  : {stratum} — {stratum_str}"));
    dp.app_detail.push(format!("LI       : {li} — {li_str}"));
    dp.app_detail.push(format!("Poll     : 2^{poll} s"));
    dp.app_detail.push(format!("Precision: 2^{precision} s"));

    // Mode 7 (private/monlist) over UDP is the classic NTP amplification vector
    if mode == 7 && payload.len() > 468 {
        dp.ntp_amplification_risk = true;
        dp.app_detail
            .push("⚠ Mode 7 response > 468B — NTP amplification attack risk".to_string());
    }
    if mode == 6 && payload.len() > 100 {
        dp.app_detail
            .push("⚠ NTP control mode — verify source is authorised".to_string());
    }
}

// ── BGP ───────────────────────────────────────────────────────────────────────

fn detect_bgp(payload: &[u8], dp: &mut DeepPacket) {
    // BGP messages start with 16-byte 0xFF marker
    if payload.len() < 19 {
        return;
    }
    if payload[..16] != [0xff; 16] {
        return;
    }

    let length = u16::from_be_bytes([payload[16], payload[17]]);
    let msg_type = payload[18];
    let type_str = match msg_type {
        1 => "OPEN",
        2 => "UPDATE",
        3 => "NOTIFICATION",
        4 => "KEEPALIVE",
        5 => "ROUTE-REFRESH",
        _ => "Unknown",
    };
    dp.app_proto = Some("BGP".into());
    dp.bgp_msg_type = Some(type_str.to_string());
    dp.app_detail
        .push(format!("MsgType  : {type_str}  (len={length})"));

    // OPEN message carries BGP version + AS number
    if msg_type == 1 && payload.len() >= 29 {
        let bgp_ver = payload[19];
        let my_asn = u16::from_be_bytes([payload[20], payload[21]]);
        let hold_time = u16::from_be_bytes([payload[22], payload[23]]);
        dp.bgp_asn = Some(my_asn);
        dp.app_detail.push(format!("BGP Ver  : {bgp_ver}"));
        dp.app_detail.push(format!("My ASN   : {my_asn}"));
        dp.app_detail.push(format!("Hold Time: {hold_time}s"));
        let router_id = std::net::Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);
        dp.app_detail.push(format!("Router ID: {router_id}"));
    }
    if msg_type == 3 && payload.len() >= 22 {
        let error = payload[19];
        let sub = payload[20];
        let err_str = match error {
            1 => "Message Header Error",
            2 => "OPEN Message Error",
            3 => "UPDATE Message Error",
            4 => "Hold Timer Expired",
            5 => "FSM Error",
            6 => "Cease",
            _ => "Unknown",
        };
        dp.app_detail
            .push(format!("Error    : {err_str}  (sub={sub})"));
    }
}

// ── QUIC / HTTP3 ─────────────────────────────────────────────────────────────

fn detect_quic(payload: &[u8], dp: &mut DeepPacket) {
    if payload.len() < 5 {
        return;
    }
    let first = payload[0];

    // QUIC long header: first byte bit7=1, bit6=1 (0xC0 mask = 0xC0)
    if first & 0xC0 == 0xC0 {
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let pkt_type = match (first >> 4) & 0x03 {
            0 => "Initial",
            1 => "0-RTT",
            2 => "Handshake",
            3 => "Retry",
            _ => "Long",
        };
        // Common QUIC versions
        let ver_str = match version {
            0x00000001 => "QUIC v1 (RFC 9000)",
            0xff00001d..=0xff00002b => "QUIC draft",
            0x6b3343cf => "QUIC v2",
            0x51303530 | 0x51303433 | 0x51303436 => "gQUIC (Google)",
            0x00000000 => "Version Negotiation",
            _ => "QUIC (unknown ver)",
        };
        dp.quic_detected = true;
        dp.quic_version = Some(version);
        dp.quic_packet_type = Some(pkt_type);
        dp.app_proto = Some("QUIC/HTTP3".into());
        dp.app_detail.push(format!("QUIC     : {ver_str}"));
        dp.app_detail.push(format!("PktType  : {pkt_type}"));
        dp.app_detail.push(format!("Version  : 0x{version:08x}"));
        if version == 0x00000000 {
            dp.app_detail
                .push("Version Negotiation — client offering multiple QUIC versions".to_string());
        }
    } else if first & 0x80 == 0 {
        // Short header — encrypted, can still identify as QUIC
        dp.quic_detected = true;
        dp.quic_packet_type = Some("Short/1-RTT");
        dp.app_proto = Some("QUIC/HTTP3".into());
        dp.app_detail
            .push("QUIC short header (1-RTT encrypted)".to_string());
    }
}

// ── HTTP/2 ────────────────────────────────────────────────────────────────────

fn detect_http2(payload: &[u8], dp: &mut DeepPacket) -> bool {
    // HTTP/2 client preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
    const H2_MAGIC: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if payload.len() >= H2_MAGIC.len() && &payload[..H2_MAGIC.len()] == H2_MAGIC {
        dp.app_proto = Some("HTTP/2".into());
        dp.http2_detected = true;
        dp.app_detail
            .push("HTTP/2 client connection preface".to_string());
        // Parse SETTINGS frame that follows
        let rest = &payload[H2_MAGIC.len()..];
        parse_h2_frames(rest, dp);
        return true;
    }
    // HTTP/2 frames without preface (continuation)
    if payload.len() >= 9 {
        let frame_type = payload[3];
        let stream_id = u32::from_be_bytes([payload[5] & 0x7f, payload[6], payload[7], payload[8]]);
        if matches!(frame_type, 0..=9) && stream_id <= 0x7fff_ffff {
            let len = u32::from_be_bytes([0, payload[0], payload[1], payload[2]]);
            if len as usize <= payload.len().saturating_sub(9) {
                dp.http2_detected = true;
                dp.app_proto = Some("HTTP/2".into());
                parse_h2_frames(payload, dp);
                return true;
            }
        }
    }
    false
}

fn parse_h2_frames(data: &[u8], dp: &mut DeepPacket) {
    const FRAME_NAMES: &[&str] = &[
        "DATA",
        "HEADERS",
        "PRIORITY",
        "RST_STREAM",
        "SETTINGS",
        "PUSH_PROMISE",
        "PING",
        "GOAWAY",
        "WINDOW_UPDATE",
        "CONTINUATION",
    ];
    let mut pos = 0;
    let mut frame_count = 0;
    while pos + 9 <= data.len() && frame_count < 8 {
        let length = u32::from_be_bytes([0, data[pos], data[pos + 1], data[pos + 2]]) as usize;
        let frame_type = data[pos + 3];
        let flags = data[pos + 4];
        let stream_id = u32::from_be_bytes([
            data[pos + 5] & 0x7f,
            data[pos + 6],
            data[pos + 7],
            data[pos + 8],
        ]);
        let name = FRAME_NAMES
            .get(frame_type as usize)
            .copied()
            .unwrap_or("UNKNOWN");
        dp.app_detail.push(format!(
            "H2 Frame : {name}  len={length}  flags=0x{flags:02x}  stream={stream_id}"
        ));

        // HEADERS frame: look for :path and content-type (basic HPACK literal detection)
        if frame_type == 1 {
            let payload_start = pos + 9;
            let payload_end = (payload_start + length).min(data.len());
            let hdr_bytes = &data[payload_start..payload_end];
            if let Some(path) = hpack_find_literal(hdr_bytes, b":path") {
                dp.app_detail.push(format!("H2 Path  : {path}"));
                // gRPC detection: content-type = application/grpc
                if path.starts_with('/') && path.contains('.') {
                    dp.grpc_path = Some(path.clone());
                }
            }
            if let Some(ct) = hpack_find_literal(hdr_bytes, b"content-type") {
                dp.app_detail.push(format!("H2 CT    : {ct}"));
                if ct.contains("grpc") {
                    dp.grpc_path
                        .get_or_insert_with(|| "gRPC (unknown path)".to_string());
                    dp.app_proto = Some("gRPC".into());
                }
            }
        }
        frame_count += 1;
        pos += 9 + length;
    }
}

/// Very simple HPACK literal header value finder (no huffman, indexed-only skip).
fn hpack_find_literal(data: &[u8], key: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    // Look for key as substring then extract following value
    let key_str = std::str::from_utf8(key).ok()?;
    let lower = text.to_lowercase();
    let pos = lower.find(key_str)?;
    let after = &text[pos + key_str.len()..];
    // Value follows as length-prefixed bytes; try to grab printable chars
    let value: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_alphanumeric() && *c != '/')
        .take_while(|c| c.is_ascii_graphic())
        .collect();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

// ── WebSocket ────────────────────────────────────────────────────────────────

fn detect_websocket(payload: &[u8], dp: &mut DeepPacket) -> bool {
    let Ok(text) = std::str::from_utf8(&payload[..payload.len().min(512)]) else {
        return false;
    };
    let lower = text.to_lowercase();
    if lower.contains("upgrade: websocket") || lower.contains("connection: upgrade") {
        dp.ws_upgrade = true;
        dp.app_proto = Some("WebSocket".into());
        dp.app_detail.push("WebSocket upgrade request".to_string());
        for line in text.lines() {
            let ll = line.to_lowercase();
            if ll.starts_with("sec-websocket-key:") {
                let key = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
                dp.app_detail.push(format!("WS Key   : {key}"));
            }
            if ll.starts_with("sec-websocket-version:") {
                let ver = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
                dp.app_detail.push(format!("WS Ver   : {ver}"));
            }
            if ll.starts_with("sec-websocket-extensions:") {
                let ext = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
                dp.app_detail.push(format!("WS Ext   : {ext}"));
            }
        }
        return true;
    }
    // WebSocket frame (binary): first byte = opcode
    if !payload.is_empty() && dp.ws_upgrade {
        let opcode = payload[0] & 0x0f;
        let masked = (payload[1] & 0x80) != 0;
        let op_str = match opcode {
            0 => "Continuation",
            1 => "Text",
            2 => "Binary",
            8 => "Close",
            9 => "Ping",
            10 => "Pong",
            _ => "?",
        };
        dp.app_detail
            .push(format!("WS Frame : opcode={op_str}  masked={masked}"));
    }
    false
}

// ── TLS enhanced — ALPN + cipher suites + JA3 raw ───────────────────────────

/// Parse a full TLS ClientHello and extract cipher suites, ALPN, supported groups,
/// point formats — then build the raw JA3 input string.
fn parse_tls_client_hello(payload: &[u8], dp: &mut DeepPacket) {
    // Layout: TLS record(5) + HandshakeType(1) + HS length(3) = 9
    // Then: ClientHello version(2) + random(32) = 43 from start
    if payload.len() < 43 {
        return;
    }

    // Record-layer version (for JA3 SSLVersion field)
    let rec_ver = u16::from_be_bytes([payload[1], payload[2]]);
    // ClientHello version (bytes 9-10 after TLS record header)
    let hello_ver = u16::from_be_bytes([payload[9], payload[10]]);

    let mut pos: usize = 43;

    // Session ID
    if pos >= payload.len() {
        return;
    }
    let sid_len = payload[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > payload.len() {
        return;
    }

    // Cipher suites
    let cs_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > payload.len() {
        return;
    }
    let mut ciphers: Vec<u16> = Vec::new();
    let mut i = 0;
    while i + 1 < cs_len {
        let cs = u16::from_be_bytes([payload[pos + i], payload[pos + i + 1]]);
        if !is_grease(cs) {
            ciphers.push(cs);
        }
        i += 2;
    }
    pos += cs_len;

    // Compression methods
    if pos >= payload.len() {
        return;
    }
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > payload.len() {
        return;
    }
    let ext_total = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(payload.len());

    let mut ext_types: Vec<u16> = Vec::new();
    let mut curves: Vec<u16> = Vec::new();
    let mut pf: Vec<u8> = Vec::new();
    let mut alpn_list: Vec<String> = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        let ext_data = if pos + ext_len <= payload.len() {
            &payload[pos..pos + ext_len]
        } else {
            break;
        };

        if !is_grease(ext_type) {
            ext_types.push(ext_type);
        }

        match ext_type {
            0x0000 => { /* SNI — already extracted */ }
            0x000a if ext_data.len() >= 2 => {
                // Supported groups (elliptic curves)
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut j = 2usize;
                while j + 1 < list_len + 2 && j + 1 < ext_data.len() {
                    let g = u16::from_be_bytes([ext_data[j], ext_data[j + 1]]);
                    if !is_grease(g) {
                        curves.push(g);
                    }
                    j += 2;
                }
            }
            0x000b if !ext_data.is_empty() => {
                // EC point formats
                let pf_len = ext_data[0] as usize;
                for k in 0..pf_len.min(ext_data.len() - 1) {
                    pf.push(ext_data[1 + k]);
                }
            }
            0x0010 if ext_data.len() >= 2 => {
                // ALPN
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut j = 2usize;
                while j < list_len + 2 && j < ext_data.len() {
                    if j >= ext_data.len() {
                        break;
                    }
                    let proto_len = ext_data[j] as usize;
                    j += 1;
                    if j + proto_len <= ext_data.len() {
                        if let Ok(s) = std::str::from_utf8(&ext_data[j..j + proto_len]) {
                            alpn_list.push(s.to_string());
                        }
                    }
                    j += proto_len;
                }
            }
            _ => {}
        }
        pos += ext_len;
    }

    // Store parsed data
    dp.tls_ciphers = ciphers.clone();
    dp.tls_alpn = alpn_list.clone();

    if !alpn_list.is_empty() {
        dp.app_detail
            .push(format!("ALPN     : {}", alpn_list.join(", ")));
        // If ALPN includes h2, tag HTTP/2 over TLS
        if alpn_list.iter().any(|a| a == "h2") {
            dp.http2_detected = true;
            dp.app_detail
                .push("ALPN→h2  : HTTP/2 negotiated over TLS".to_string());
        }
        if alpn_list.iter().any(|a| a.contains("grpc")) {
            dp.app_detail
                .push("ALPN→gRPC: gRPC transport negotiated".to_string());
        }
    }
    if !ciphers.is_empty() {
        let cs_str: Vec<String> = ciphers
            .iter()
            .take(5)
            .map(|c| format!("0x{c:04x}"))
            .collect();
        let suffix = if ciphers.len() > 5 {
            format!("…+{}", ciphers.len() - 5)
        } else {
            String::new()
        };
        dp.app_detail
            .push(format!("Ciphers  : {}{suffix}", cs_str.join(" ")));
    }
    if !curves.is_empty() {
        let cur_str: Vec<String> = curves.iter().map(|c| named_group(*c)).collect();
        dp.app_detail
            .push(format!("Curves   : {}", cur_str.join(", ")));
    }

    // Build JA3 raw string: "TLSVersion,Ciphers,Extensions,Curves,PointFormats"
    //  JA3 uses the ClientHello version (hello_ver) not record version
    let _ = rec_ver;
    let ja3_ciphers = ciphers
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ja3_exts = ext_types
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ja3_curves = curves
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ja3_pf = pf
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ja3_raw = format!("{hello_ver},{ja3_ciphers},{ja3_exts},{ja3_curves},{ja3_pf}");
    dp.tls_ja3_raw = Some(ja3_raw.clone());
    dp.app_detail.push(format!("JA3-raw  : {ja3_raw}"));
    dp.app_detail
        .push("(MD5 of JA3-raw = JA3 fingerprint used by security tools)".to_string());
}

fn is_grease(val: u16) -> bool {
    // GREASE values: 0x0a0a, 0x1a1a, … 0xfafa
    let lo = val & 0x00ff;
    let hi = val >> 8;
    lo == hi && lo & 0x0f == 0x0a
}

fn named_group(g: u16) -> String {
    match g {
        23 => "secp256r1".into(),
        24 => "secp384r1".into(),
        25 => "secp521r1".into(),
        29 => "x25519".into(),
        30 => "x448".into(),
        256 => "ffdhe2048".into(),
        257 => "ffdhe3072".into(),
        _ => format!("0x{g:04x}"),
    }
}

// ── IPv6 ─────────────────────────────────────────────────────────────────────

fn parse_ipv6(data: &[u8], dp: &mut DeepPacket, anomalies: &mut Vec<String>) {
    if data.len() < 40 {
        anomalies.push("IPv6 header truncated".into());
        return;
    }
    dp.ip_version = Some(6);
    let next_header = data[6];
    let hop_limit = data[7];
    let src = fmt_ipv6(&data[8..24]);
    let dst = fmt_ipv6(&data[24..40]);

    dp.ipv6_src = Some(src.clone());
    dp.ipv6_dst = Some(dst.clone());
    dp.ipv6_next_header = Some(next_header);
    dp.ipv6_hop_limit = Some(hop_limit);

    dp.ip_ttl = Some(hop_limit);
    dp.ip_proto_name = Some(ip_proto_name(next_header));
    if hop_limit == 0 {
        anomalies.push("IPv6 Hop Limit=0 (invalid)".into());
    }

    let payload = &data[40..];
    match next_header {
        6 => parse_tcp(payload, dp, anomalies),
        17 => parse_udp(payload, dp, anomalies),
        58 => parse_icmp(payload, dp, anomalies), // ICMPv6
        _ => {
            dp.payload = payload.to_vec();
        }
    }
}

fn fmt_ipv6(b: &[u8]) -> String {
    let groups: Vec<String> = b
        .chunks(2)
        .map(|g| format!("{:02x}{:02x}", g[0], g[1]))
        .collect();
    groups.join(":")
}

// ── Tunnel inner frame re-inspection (VXLAN, GRE, Geneve) ───────────────────

fn inspect_vxlan_inner(payload: &[u8], dp: &mut DeepPacket) {
    // VXLAN: 8-byte header (flags + VNI), then inner Ethernet frame (≥14 bytes)
    if payload.len() < 22 {
        return;
    }
    let vni = ((payload[4] as u32) << 16) | ((payload[5] as u32) << 8) | payload[6] as u32;
    dp.tunnel_type = Some(format!("VXLAN VNI={vni}"));
    dp.app_detail.push(format!("VXLAN VNI: {vni}"));
    let inner = &payload[8..];
    decode_inner_ethernet(inner, dp);
}

fn inspect_gre_inner(payload: &[u8], gre_proto: u16, dp: &mut DeepPacket) {
    if payload.is_empty() {
        return;
    }
    dp.tunnel_type = Some("GRE".to_string());
    dp.app_detail.push(format!("GRE Proto: 0x{gre_proto:04x}"));
    match gre_proto {
        0x0800 => {
            // Inner IPv4
            let mut inner_dp = DeepPacket::empty(payload.len());
            let mut anoms = Vec::new();
            parse_ipv4(payload, payload, &mut inner_dp, &mut anoms);
            harvest_inner(&inner_dp, dp);
        }
        0x86dd => {
            let mut inner_dp = DeepPacket::empty(payload.len());
            let mut anoms = Vec::new();
            parse_ipv6(payload, &mut inner_dp, &mut anoms);
            harvest_inner(&inner_dp, dp);
        }
        _ => {}
    }
}

fn decode_inner_ethernet(inner: &[u8], dp: &mut DeepPacket) {
    if inner.len() < 14 {
        return;
    }
    let et = u16::from_be_bytes([inner[12], inner[13]]);
    let l3 = &inner[14..];
    let mut inner_dp = DeepPacket::empty(inner.len());
    let mut anoms = Vec::new();
    match et {
        0x0800 => parse_ipv4(l3, l3, &mut inner_dp, &mut anoms),
        0x86dd => parse_ipv6(l3, &mut inner_dp, &mut anoms),
        _ => {}
    }
    harvest_inner(&inner_dp, dp);
}

fn harvest_inner(inner: &DeepPacket, dp: &mut DeepPacket) {
    dp.inner_ip_src = inner.ip_src;
    dp.inner_ip_dst = inner.ip_dst;
    dp.inner_proto = inner.ip_proto_name;
    dp.inner_src_port = inner.tcp_src_port.or(inner.udp_src_port);
    dp.inner_dst_port = inner.tcp_dst_port.or(inner.udp_dst_port);
    dp.inner_app_proto = inner.app_proto.clone();
    if let Some(src) = inner.ip_src {
        dp.app_detail.push(format!("Inner Src: {src}"));
    }
    if let Some(dst) = inner.ip_dst {
        dp.app_detail.push(format!("Inner Dst: {dst}"));
    }
    if let Some(p) = inner.app_proto.as_deref() {
        dp.app_detail.push(format!("Inner App: {p}"));
    }
    if let Some(p) = &inner.ip_proto_name {
        dp.app_detail.push(format!("Inner Proto: {p}"));
    }
}

// ── GRE header parsing ───────────────────────────────────────────────────────

fn parse_gre(data: &[u8], dp: &mut DeepPacket, anomalies: &mut Vec<String>) {
    if data.len() < 4 {
        anomalies.push("GRE header truncated".into());
        return;
    }
    let flags = u16::from_be_bytes([data[0], data[1]]);
    let proto = u16::from_be_bytes([data[2], data[3]]);
    let has_checksum = (flags >> 15) & 1 == 1;
    let has_key = (flags >> 13) & 1 == 1;
    let has_seq = (flags >> 12) & 1 == 1;
    let mut offset = 4usize;
    if has_checksum {
        offset += 4;
    }
    if has_key {
        offset += 4;
    }
    if has_seq {
        offset += 4;
    }
    dp.app_proto = Some("GRE".into());
    if offset <= data.len() {
        inspect_gre_inner(&data[offset..], proto, dp);
    }
}

// ── DNS label entropy (tunneling / DGA heuristic) ────────────────────────────

/// Shannon entropy of a string. High entropy (>3.5) suggests encoding or DGA.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

// ── Risk scorer ───────────────────────────────────────────────────────────────

impl DeepPacket {
    /// Compute a 0-100 risk score based on observed anomalies and protocol signals.
    pub fn compute_risk(&mut self) {
        let mut score: i32 = 0;
        let mut reasons: Vec<String> = Vec::new();

        // Anomaly-based score
        score += (self.anomalies.len() as i32) * 10;

        // TCP flag attacks
        if let Some(flags) = self.tcp_flags {
            if flags & 0x003 == 0x003 {
                score += 30;
                reasons.push("SYN+FIN (port scan / malformed)".into());
            }
            if flags & 0x006 == 0x006 {
                score += 30;
                reasons.push("SYN+RST (malformed)".into());
            }
            if flags == 0 {
                score += 25;
                reasons.push("NULL scan (no flags)".into());
            }
        }

        // Old/deprecated protocol versions
        if let Some(ref proto) = self.app_proto {
            if proto == "TLS/SSL" || proto == "TLS" {
                for d in &self.app_detail {
                    if d.contains("TLS 1.0") || d.contains("TLS 1.1") {
                        score += 20;
                        reasons.push("Deprecated TLS version".into());
                        break;
                    }
                }
            }
            if proto == "Telnet" {
                score += 40;
                reasons.push("Telnet — cleartext remote access".into());
            }
            if proto == "FTP Control" {
                score += 15;
                reasons.push("FTP — cleartext credentials".into());
            }
            if proto == "SNMP" {
                score += 10;
                reasons.push("SNMP — verify SNMPv3 auth".into());
            }
        }

        // Cleartext HTTP carrying sensitive-looking paths
        if self.app_proto.as_deref() == Some("HTTP") {
            score += 10;
            reasons.push("Cleartext HTTP".into());
            for d in &self.app_detail {
                let dl = d.to_lowercase();
                if dl.contains("password")
                    || dl.contains("passwd")
                    || dl.contains("token")
                    || dl.contains("secret")
                {
                    score += 20;
                    reasons.push("HTTP with credential-like keyword in path/header".into());
                    break;
                }
            }
        }

        // NTP amplification
        if self.ntp_amplification_risk {
            score += 35;
            reasons.push("NTP amplification attack pattern".into());
        }

        // DNS tunneling heuristic
        if let Some(entropy) = self.dns_label_entropy {
            if entropy > 3.8 {
                score += 25;
                reasons.push(format!(
                    "DNS label entropy={entropy:.2} — possible tunneling/DGA"
                ));
            } else if entropy > 3.3 {
                score += 10;
                reasons.push(format!(
                    "DNS label entropy={entropy:.2} — slightly elevated"
                ));
            }
        }

        // SSH version 1
        if let Some(ref b) = self.ssh_banner {
            if b.starts_with("SSH-1.") {
                score += 35;
                reasons.push("SSHv1 — cryptographically broken".into());
            }
        }

        // BGP anomaly
        if self.bgp_msg_type.as_deref() == Some("NOTIFICATION") {
            score += 15;
            reasons.push("BGP NOTIFICATION — session may be flapping".into());
        }

        // IP TTL anomalies
        if self.ip_ttl == Some(0) {
            score += 30;
            reasons.push("IP TTL=0".into());
        }
        if self.ip_ttl == Some(1) {
            score += 5;
            reasons.push("IP TTL=1 (expires on next hop)".into());
        }

        // Fragment
        if self.ip_fragment.is_some() {
            score += 5;
            reasons.push("Fragmented IP packet".into());
        }

        // QUIC (not inherently risky, but mark for visibility)
        if self.quic_detected {
            // QUIC itself is fine, but note for visibility
        }

        // Source IP anomalies from anomalies list
        for a in &self.anomalies {
            if a.contains("broadcast")
                || a.contains("unspecified")
                || a.contains("malformed")
                || a.contains("scan")
            {
                score += 10;
                reasons.push(a.clone());
            }
        }

        self.risk_score = score.clamp(0, 100) as u8;
        self.risk_reasons = reasons;
    }

    /// App category classification based on detected protocol.
    pub fn classify_app_category(&mut self) {
        self.app_category = Some(match self.app_proto.as_deref().unwrap_or("") {
            "HTTP" | "HTTPS" | "TLS/SSL" | "HTTP/2" => "Web Browsing".into(),
            "QUIC/HTTP3" => "Web Browsing (QUIC)".into(),
            "gRPC" => "RPC / Microservices".into(),
            "DNS" => "DNS".into(),
            "DHCP" => "Network Infrastructure".into(),
            "NTP" => "Time Synchronization".into(),
            "SSH" => "Remote Access".into(),
            "Telnet" => "Remote Access (Insecure)".into(),
            "FTP Control" => "File Transfer".into(),
            "SMTP" | "IMAP" | "POP3" | "SMTPS" | "IMAPS" | "POP3S" => "Email".into(),
            "SIP" => "VoIP / UC".into(),
            "SNMP" => "Network Management".into(),
            "BGP" | "OSPF" | "RIP" => "Routing Protocol".into(),
            "VXLAN" | "GRE" | "Geneve" => "Overlay Tunnel".into(),
            "SSDP" => "Service Discovery".into(),
            "IKE/IPsec" => "VPN / Encrypted Tunnel".into(),
            "MySQL" | "PostgreSQL" | "Redis" | "MongoDB" => "Database".into(),
            "RDP" => "Remote Desktop".into(),
            "WebSocket" => "Real-time / WebSocket".into(),
            "LDAP" | "Kerberos" => "Directory / Auth".into(),
            _ => {
                // Port-based category fallback
                let port = self.tcp_dst_port.or(self.udp_dst_port).unwrap_or(0);
                match port {
                    80 | 443 | 8080 | 8443 => "Web Browsing",
                    25 | 465 | 587 => "Email",
                    22 => "Remote Access",
                    3306 | 5432 | 6379 | 27017 => "Database",
                    1935 | 8554 => "Streaming",
                    5060 | 5061 | 16384..=32767 => "VoIP / UC",
                    _ => "Unknown",
                }
                .into()
            }
        });
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
        0 => "Echo Reply (id/seq via fields)".to_string(),
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
                .and_then(|l| l.split_once(':').map(|x| x.1))
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
            "NTP" => {
                let mode = self.ntp_mode.unwrap_or(0);
                let stratum = self.ntp_stratum.unwrap_or(0);
                out.push(format!("NTP mode={mode}  stratum={stratum}"));
                if self.ntp_amplification_risk {
                    out.push("⚠ NTP amplification risk — mode 7 or oversized monlist response".into());
                }
            }
            "SNMP"   => out.push("SNMP management — ensure SNMPv3 auth+encrypt; avoid SNMPv1/v2 community strings on internet".into()),
            "BGP"    => {
                out.push("BGP peering — protect with TCP-MD5 or TTL-security (GTSM)".into());
                if let Some(asn) = self.bgp_asn { out.push(format!("BGP AS: {asn}")); }
            }
            "VXLAN"  => {
                if let Some(ref tn) = self.tunnel_type { out.push(format!("Tunnel: {tn}")); }
                if let (Some(s), Some(d)) = (self.inner_ip_src, self.inner_ip_dst) {
                    out.push(format!("Inner flow: {s} → {d}"));
                }
                if let Some(ref ap) = self.inner_app_proto { out.push(format!("Inner app: {ap}")); }
            }
            "GRE"    => {
                if let Some(ref tn) = self.tunnel_type { out.push(format!("GRE tunnel: {tn}")); }
                if let (Some(s), Some(d)) = (self.inner_ip_src, self.inner_ip_dst) {
                    out.push(format!("Inner flow: {s} → {d}"));
                }
            }
            "SSH" => {
                if let Some(ref b) = self.ssh_banner {
                    out.push(format!("SSH server: {b}"));
                    if b.starts_with("SSH-1.") {
                        out.push("⚠ SSHv1 is deprecated — cryptographically broken, upgrade to OpenSSH".into());
                    }
                } else {
                    out.push("SSH — encrypted session; brute-force attempts appear as many SYN+RST on port 22".into());
                }
            }
            "SIP" => {
                if let Some(ref m) = self.sip_method { out.push(format!("SIP {m} request")); }
                if let Some(ref cid) = self.sip_call_id { out.push(format!("Call-ID: {cid}")); }
                if let Some(ref uri) = self.sip_uri { out.push(format!("URI: {uri}")); }
            }
            "QUIC/HTTP3" => {
                if let Some(ver) = self.quic_version {
                    out.push(format!("QUIC encrypted transport (ver=0x{ver:08x}) — content not readable without keys"));
                }
                if let Some(pt) = self.quic_packet_type { out.push(format!("Packet type: {pt}")); }
            }
            "HTTP/2" | "gRPC" => {
                if let Some(ref path) = self.grpc_path {
                    out.push(format!("gRPC method: {path}"));
                } else {
                    out.push("HTTP/2 frame stream — binary multiplexed over single TCP connection".into());
                }
                if !self.tls_alpn.is_empty() {
                    out.push(format!("ALPN negotiated: {}", self.tls_alpn.join(", ")));
                }
            }
            "WebSocket" => {
                out.push("WebSocket — full-duplex real-time channel over HTTP upgrade".into());
            }
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
        // IPv6 summary
        if let (Some(ref s), Some(ref d)) = (&self.ipv6_src, &self.ipv6_dst) {
            out.push(format!("IPv6: {s} → {d}"));
            if let Some(hl) = self.ipv6_hop_limit {
                out.push(format!("IPv6 Hop Limit: {hl}"));
            }
        }
        // Tunnel inner summary
        if let Some(ref tn) = self.tunnel_type {
            out.push(format!("Tunnel encapsulation: {tn}"));
            if let (Some(s), Some(d)) = (self.inner_ip_src, self.inner_ip_dst) {
                out.push(format!("  Inner: {s} → {d}"));
            }
        }
        // JA3 fingerprint
        if let Some(ref ja3) = self.tls_ja3_raw {
            out.push(format!("TLS JA3-raw (MD5 = JA3): {ja3}"));
        }
        // Risk score
        if self.risk_score > 0 {
            out.push(format!("⚠ Risk score: {}/100", self.risk_score));
            for r in &self.risk_reasons {
                out.push(format!("  • {r}"));
            }
        }
        // App category
        if let Some(ref cat) = self.app_category {
            out.push(format!("Category: {cat}"));
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
            tls_ciphers: Vec::new(),
            tls_alpn: Vec::new(),
            tls_ja3_raw: None,
            quic_detected: false,
            quic_version: None,
            quic_packet_type: None,
            http2_detected: false,
            grpc_path: None,
            ws_upgrade: false,
            tunnel_type: None,
            inner_ip_src: None,
            inner_ip_dst: None,
            inner_proto: None,
            inner_src_port: None,
            inner_dst_port: None,
            inner_app_proto: None,
            ssh_banner: None,
            sip_method: None,
            sip_uri: None,
            sip_call_id: None,
            ntp_version: None,
            ntp_mode: None,
            ntp_stratum: None,
            ntp_amplification_risk: false,
            bgp_msg_type: None,
            bgp_asn: None,
            ipv6_src: None,
            ipv6_dst: None,
            ipv6_next_header: None,
            ipv6_hop_limit: None,
            dns_label_entropy: None,
            dns_query_name: None,
            risk_score: 0,
            risk_reasons: Vec::new(),
            app_category: None,
        }
    }
}
