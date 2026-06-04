// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Advanced Flow Analysis Engine
//!
//! Tracks protocol state across multiple packets to analyze:
//! - TCP handshakes (SYN/SYN-ACK/ACK)
//! - TLS handshakes (ClientHello/ServerHello/Certificate/Finished)
//! - DHCP DORA flows (Discover/Offer/Request/Acknowledge)
//! - DNS query/response matching
//! - HTTP request/response pairing
//! - And more protocol-specific analysis

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::dpi::DeepPacket;

// ─── Flow State Types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowId {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl FlowId {
    pub fn from_packet(dp: &DeepPacket) -> Option<Self> {
        let (src_ip, dst_ip) = (dp.ip_src?, dp.ip_dst?);

        if let (Some(src_port), Some(dst_port)) = (dp.tcp_src_port, dp.tcp_dst_port) {
            return Some(FlowId {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol: Protocol::Tcp,
            });
        }

        if let (Some(src_port), Some(dst_port)) = (dp.udp_src_port, dp.udp_dst_port) {
            return Some(FlowId {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol: Protocol::Udp,
            });
        }

        None
    }

    /// Create a reversed flow ID (for matching bidirectional flows)
    pub fn reverse(&self) -> Self {
        FlowId {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

// ─── TCP Handshake Analysis ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum TcpHandshakeState {
    Init,
    SynSent {
        seq: u32,
        timestamp: Instant,
    },
    SynAckReceived {
        syn_seq: u32,
        syn_ack_seq: u32,
        timestamp: Instant,
    },
    Established {
        timestamp: Instant,
        rtt_ms: f64,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct TcpHandshakeAnalysis {
    pub state: TcpHandshakeState,
    pub complete: bool,
    pub syn_retransmits: u32,
    pub flags_observed: Vec<String>,
}

impl Default for TcpHandshakeAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpHandshakeAnalysis {
    pub fn new() -> Self {
        Self {
            state: TcpHandshakeState::Init,
            complete: false,
            syn_retransmits: 0,
            flags_observed: Vec::new(),
        }
    }

    pub fn analyze(&mut self, dp: &DeepPacket, timestamp: Instant) -> Option<String> {
        let flags = dp.tcp_flags_str.as_ref()?;
        self.flags_observed.push(flags.clone());

        match &self.state {
            TcpHandshakeState::Init if flags.contains("SYN") && !flags.contains("ACK") => {
                let seq = dp.tcp_seq?;
                self.state = TcpHandshakeState::SynSent { seq, timestamp };
                return Some("TCP handshake started: SYN sent".to_string());
            }
            TcpHandshakeState::SynSent {
                seq,
                timestamp: _syn_time,
            } => {
                if flags.contains("SYN") && !flags.contains("ACK") {
                    // SYN retransmit
                    self.syn_retransmits += 1;
                    return Some(format!("SYN retransmit #{}", self.syn_retransmits));
                }
                if flags.contains("SYN") && flags.contains("ACK") {
                    let ack_seq = dp.tcp_ack?;
                    if ack_seq == seq + 1 {
                        let syn_ack_seq = dp.tcp_seq?;
                        self.state = TcpHandshakeState::SynAckReceived {
                            syn_seq: *seq,
                            syn_ack_seq,
                            timestamp,
                        };
                        return Some("TCP handshake: SYN-ACK received".to_string());
                    } else {
                        self.state = TcpHandshakeState::Failed {
                            reason: format!(
                                "Invalid ACK number: expected {}, got {}",
                                seq + 1,
                                ack_seq
                            ),
                        };
                        return Some("TCP handshake FAILED: Invalid ACK".to_string());
                    }
                }
            }
            TcpHandshakeState::SynAckReceived {
                syn_seq: _,
                syn_ack_seq,
                timestamp: syn_ack_time,
            } if flags.contains("ACK") && !flags.contains("SYN") => {
                let ack_seq = dp.tcp_ack?;
                if ack_seq == syn_ack_seq + 1 {
                    let rtt_ms =
                        timestamp.duration_since(*syn_ack_time).as_micros() as f64 / 1000.0;
                    self.state = TcpHandshakeState::Established { timestamp, rtt_ms };
                    self.complete = true;
                    return Some(format!("TCP handshake COMPLETE (RTT: {:.2}ms)", rtt_ms));
                } else {
                    self.state = TcpHandshakeState::Failed {
                        reason: format!(
                            "Invalid final ACK: expected {}, got {}",
                            syn_ack_seq + 1,
                            ack_seq
                        ),
                    };
                    return Some("TCP handshake FAILED: Invalid final ACK".to_string());
                }
            }
            _ => {}
        }

        None
    }
}

// ─── TLS Handshake Analysis ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum TlsHandshakeState {
    Init,
    ClientHelloSent {
        timestamp: Instant,
        sni: Option<String>,
    },
    ServerHelloReceived {
        timestamp: Instant,
        version: String,
    },
    CertificateReceived {
        timestamp: Instant,
    },
    Finished {
        timestamp: Instant,
        rtt_ms: f64,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct TlsHandshakeAnalysis {
    pub state: TlsHandshakeState,
    pub complete: bool,
    pub cipher_suites: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub version: Option<String>,
}

impl Default for TlsHandshakeAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsHandshakeAnalysis {
    pub fn new() -> Self {
        Self {
            state: TlsHandshakeState::Init,
            complete: false,
            cipher_suites: Vec::new(),
            sni: None,
            alpn: Vec::new(),
            version: None,
        }
    }

    pub fn analyze(&mut self, dp: &DeepPacket, timestamp: Instant) -> Option<String> {
        // Check if this is a TLS packet
        let app_proto = dp.app_proto.as_ref()?;
        if !app_proto.to_lowercase().contains("tls") && !app_proto.to_lowercase().contains("ssl") {
            return None;
        }

        // Extract TLS information
        let details = &dp.app_detail;

        match &self.state {
            TlsHandshakeState::Init => {
                // Look for ClientHello indicators
                for detail in details {
                    if detail.contains("ClientHello") || detail.contains("Client Hello") {
                        // Extract SNI if available
                        let sni = details
                            .iter()
                            .find(|d| d.starts_with("SNI"))
                            .and_then(|d| d.split_once(':'))
                            .map(|(_, v)| v.trim().to_string());

                        self.sni = sni.clone();
                        self.cipher_suites = dp.tls_ciphers.clone();
                        self.alpn = dp.tls_alpn.clone();

                        self.state = TlsHandshakeState::ClientHelloSent { timestamp, sni };
                        return Some(format!(
                            "TLS handshake started: ClientHello{}",
                            self.sni
                                .as_ref()
                                .map(|s| format!(" (SNI: {})", s))
                                .unwrap_or_default()
                        ));
                    }
                }
            }
            TlsHandshakeState::ClientHelloSent {
                timestamp: _start, ..
            } => {
                for detail in details {
                    if detail.contains("ServerHello") || detail.contains("Server Hello") {
                        let version = details
                            .iter()
                            .find(|d| d.starts_with("Version"))
                            .and_then(|d| d.split_once(':'))
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_else(|| "Unknown".to_string());

                        self.version = Some(version.clone());
                        self.state = TlsHandshakeState::ServerHelloReceived {
                            timestamp,
                            version: version.clone(),
                        };
                        return Some(format!("TLS handshake: ServerHello received ({})", version));
                    }

                    if detail.contains("Certificate") {
                        self.state = TlsHandshakeState::CertificateReceived { timestamp };
                        return Some("TLS handshake: Server Certificate received".to_string());
                    }
                }
            }
            TlsHandshakeState::ServerHelloReceived {
                timestamp: start, ..
            }
            | TlsHandshakeState::CertificateReceived { timestamp: start } => {
                for detail in details {
                    if detail.contains("Finished") || detail.contains("Change Cipher Spec") {
                        let rtt_ms = timestamp.duration_since(*start).as_micros() as f64 / 1000.0;
                        self.state = TlsHandshakeState::Finished { timestamp, rtt_ms };
                        self.complete = true;
                        return Some(format!("TLS handshake COMPLETE (RTT: {:.2}ms)", rtt_ms));
                    }
                }
            }
            _ => {}
        }

        None
    }
}

// ─── DHCP DORA Flow Analysis ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DhcpDoraState {
    Init,
    DiscoverSent {
        timestamp: Instant,
        xid: Option<u32>,
    },
    OfferReceived {
        timestamp: Instant,
        offered_ip: Option<Ipv4Addr>,
    },
    RequestSent {
        timestamp: Instant,
    },
    AckReceived {
        timestamp: Instant,
        assigned_ip: Option<Ipv4Addr>,
        total_ms: f64,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct DhcpDoraAnalysis {
    pub state: DhcpDoraState,
    pub complete: bool,
    pub offered_ip: Option<Ipv4Addr>,
    pub assigned_ip: Option<Ipv4Addr>,
    pub server_ip: Option<Ipv4Addr>,
    pub lease_time: Option<u32>,
}

impl Default for DhcpDoraAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpDoraAnalysis {
    pub fn new() -> Self {
        Self {
            state: DhcpDoraState::Init,
            complete: false,
            offered_ip: None,
            assigned_ip: None,
            server_ip: None,
            lease_time: None,
        }
    }

    pub fn analyze(&mut self, dp: &DeepPacket, timestamp: Instant) -> Option<String> {
        // Check if this is a DHCP packet (UDP port 67 or 68)
        if dp.udp_src_port != Some(67)
            && dp.udp_src_port != Some(68)
            && dp.udp_dst_port != Some(67)
            && dp.udp_dst_port != Some(68)
        {
            return None;
        }

        // Parse DHCP message type from app_detail
        let details = &dp.app_detail;

        match &self.state {
            DhcpDoraState::Init => {
                for detail in details {
                    if detail.contains("DHCP Discover") || detail.contains("DHCPDiscover") {
                        self.state = DhcpDoraState::DiscoverSent {
                            timestamp,
                            xid: None,
                        };
                        return Some(
                            "DHCP DORA: Discover sent (client searching for DHCP server)"
                                .to_string(),
                        );
                    }
                }
            }
            DhcpDoraState::DiscoverSent {
                timestamp: _start, ..
            } => {
                for detail in details {
                    if detail.contains("DHCP Offer") || detail.contains("DHCPOffer") {
                        // Try to extract offered IP
                        let offered_ip = details
                            .iter()
                            .find(|d| d.contains("Your IP") || d.contains("Offered IP"))
                            .and_then(|d| {
                                let parts: Vec<&str> = d.split(':').collect();
                                if parts.len() > 1 {
                                    parts[1].trim().parse::<Ipv4Addr>().ok()
                                } else {
                                    None
                                }
                            });

                        self.offered_ip = offered_ip;
                        self.state = DhcpDoraState::OfferReceived {
                            timestamp,
                            offered_ip,
                        };
                        return Some(format!(
                            "DHCP DORA: Offer received{}",
                            offered_ip
                                .map(|ip| format!(" (IP: {})", ip))
                                .unwrap_or_default()
                        ));
                    }
                }
            }
            DhcpDoraState::OfferReceived { .. } => {
                for detail in details {
                    if detail.contains("DHCP Request") || detail.contains("DHCPRequest") {
                        self.state = DhcpDoraState::RequestSent { timestamp };
                        return Some(
                            "DHCP DORA: Request sent (client accepting offer)".to_string(),
                        );
                    }
                }
            }
            DhcpDoraState::RequestSent {
                timestamp: _req_time,
            } => {
                for detail in details {
                    if detail.contains("DHCP Ack")
                        || detail.contains("DHCPAck")
                        || detail.contains("DHCPACK")
                    {
                        // Try to extract assigned IP
                        let assigned_ip = details
                            .iter()
                            .find(|d| d.contains("Your IP") || d.contains("Assigned IP"))
                            .and_then(|d| {
                                let parts: Vec<&str> = d.split(':').collect();
                                if parts.len() > 1 {
                                    parts[1].trim().parse::<Ipv4Addr>().ok()
                                } else {
                                    None
                                }
                            });

                        let total_ms = if let DhcpDoraState::DiscoverSent {
                            timestamp: start, ..
                        } = self.state
                        {
                            timestamp.duration_since(start).as_micros() as f64 / 1000.0
                        } else {
                            0.0
                        };

                        self.assigned_ip = assigned_ip.or(self.offered_ip);
                        self.state = DhcpDoraState::AckReceived {
                            timestamp,
                            assigned_ip: self.assigned_ip,
                            total_ms,
                        };
                        self.complete = true;

                        return Some(format!(
                            "DHCP DORA COMPLETE: Ack received{} (Total: {:.2}ms)",
                            self.assigned_ip
                                .map(|ip| format!(" (IP: {})", ip))
                                .unwrap_or_default(),
                            total_ms
                        ));
                    }

                    if detail.contains("DHCP Nak")
                        || detail.contains("DHCPNak")
                        || detail.contains("DHCPNAK")
                    {
                        self.state = DhcpDoraState::Failed {
                            reason: "Server sent NAK (negative acknowledgment)".to_string(),
                        };
                        return Some("DHCP DORA FAILED: NAK received from server".to_string());
                    }
                }
            }
            _ => {}
        }

        None
    }
}

// ─── DNS Query/Response Analysis ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsTransactionAnalysis {
    pub query_name: Option<String>,
    pub query_time: Option<Instant>,
    pub response_time: Option<Instant>,
    pub rtt_ms: Option<f64>,
    pub response_ips: Vec<Ipv4Addr>,
    pub complete: bool,
}

impl Default for DnsTransactionAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTransactionAnalysis {
    pub fn new() -> Self {
        Self {
            query_name: None,
            query_time: None,
            response_time: None,
            rtt_ms: None,
            response_ips: Vec::new(),
            complete: false,
        }
    }

    pub fn analyze(&mut self, dp: &DeepPacket, timestamp: Instant) -> Option<String> {
        // Check if this is a DNS packet (UDP port 53)
        if dp.udp_src_port != Some(53) && dp.udp_dst_port != Some(53) {
            return None;
        }

        let app_proto = dp.app_proto.as_ref()?;
        if !app_proto.to_lowercase().contains("dns") {
            return None;
        }

        if dp.udp_dst_port == Some(53) {
            // This is a query
            self.query_name = dp.dns_query_name.clone();
            self.query_time = Some(timestamp);
            return Some(format!(
                "DNS Query: {}",
                self.query_name.as_deref().unwrap_or("unknown")
            ));
        } else if dp.udp_src_port == Some(53) && self.query_time.is_some() {
            // This is a response
            self.response_time = Some(timestamp);
            if let Some(query_time) = self.query_time {
                self.rtt_ms =
                    Some(timestamp.duration_since(query_time).as_micros() as f64 / 1000.0);
            }

            // Try to extract response IPs from app_detail
            for detail in &dp.app_detail {
                if let Ok(ip) = detail.trim().parse::<Ipv4Addr>() {
                    self.response_ips.push(ip);
                }
            }

            self.complete = true;
            return Some(format!(
                "DNS Response: {} (RTT: {:.2}ms, {} answers)",
                self.query_name.as_deref().unwrap_or("unknown"),
                self.rtt_ms.unwrap_or(0.0),
                self.response_ips.len()
            ));
        }

        None
    }
}

// ─── Flow Analyzer (Main Engine) ─────────────────────────────────────────────

pub struct FlowAnalyzer {
    tcp_flows: HashMap<FlowId, TcpHandshakeAnalysis>,
    tls_flows: HashMap<FlowId, TlsHandshakeAnalysis>,
    dhcp_flows: HashMap<Ipv4Addr, DhcpDoraAnalysis>, // keyed by client MAC/IP
    dns_flows: HashMap<u16, DnsTransactionAnalysis>, // keyed by DNS transaction ID
    #[allow(dead_code)]
    flow_timeout: Duration,
}

impl Default for FlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowAnalyzer {
    pub fn new() -> Self {
        Self {
            tcp_flows: HashMap::new(),
            tls_flows: HashMap::new(),
            dhcp_flows: HashMap::new(),
            dns_flows: HashMap::new(),
            flow_timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    pub fn analyze_packet(&mut self, dp: &DeepPacket) -> Vec<String> {
        let mut results = Vec::new();
        let timestamp = Instant::now();

        // TCP handshake analysis
        if let Some(flow_id) = FlowId::from_packet(dp) {
            if flow_id.protocol == Protocol::Tcp && dp.tcp_flags_str.is_some() {
                let analysis = self.tcp_flows.entry(flow_id.clone()).or_default();

                if let Some(result) = analysis.analyze(dp, timestamp) {
                    results.push(format!("[TCP] {}", result));
                }
            }

            // TLS handshake analysis
            if dp
                .app_proto
                .as_ref()
                .map(|p| p.to_lowercase().contains("tls"))
                .unwrap_or(false)
            {
                let analysis = self.tls_flows.entry(flow_id.clone()).or_default();

                if let Some(result) = analysis.analyze(dp, timestamp) {
                    results.push(format!("[TLS] {}", result));
                }
            }
        }

        // DHCP DORA analysis
        if dp.udp_src_port == Some(67)
            || dp.udp_src_port == Some(68)
            || dp.udp_dst_port == Some(67)
            || dp.udp_dst_port == Some(68)
        {
            // Use client IP as key (or 0.0.0.0 for initial discover)
            let client_ip = dp.ip_src.unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
            let analysis = self.dhcp_flows.entry(client_ip).or_default();

            if let Some(result) = analysis.analyze(dp, timestamp) {
                results.push(format!("[DHCP] {}", result));
            }
        }

        // DNS query/response analysis
        if dp.udp_src_port == Some(53) || dp.udp_dst_port == Some(53) {
            // Use a dummy transaction ID (would need to parse DNS header for real ID)
            let tx_id = 0_u16;
            let analysis = self.dns_flows.entry(tx_id).or_default();

            if let Some(result) = analysis.analyze(dp, timestamp) {
                results.push(format!("[DNS] {}", result));
            }
        }

        results
    }

    /// Get all TCP handshake states
    pub fn get_tcp_handshakes(&self) -> Vec<(&FlowId, &TcpHandshakeAnalysis)> {
        self.tcp_flows.iter().collect()
    }

    /// Get all TLS handshake states
    pub fn get_tls_handshakes(&self) -> Vec<(&FlowId, &TlsHandshakeAnalysis)> {
        self.tls_flows.iter().collect()
    }

    /// Get all DHCP DORA flows
    pub fn get_dhcp_flows(&self) -> Vec<(&Ipv4Addr, &DhcpDoraAnalysis)> {
        self.dhcp_flows.iter().collect()
    }

    /// Get statistics summary
    pub fn get_summary(&self) -> FlowAnalyzerSummary {
        FlowAnalyzerSummary {
            total_tcp_flows: self.tcp_flows.len(),
            complete_tcp_handshakes: self.tcp_flows.values().filter(|a| a.complete).count(),
            total_tls_flows: self.tls_flows.len(),
            complete_tls_handshakes: self.tls_flows.values().filter(|a| a.complete).count(),
            total_dhcp_flows: self.dhcp_flows.len(),
            complete_dhcp_dora: self.dhcp_flows.values().filter(|a| a.complete).count(),
        }
    }

    /// Clean up old flows
    pub fn cleanup_old_flows(&mut self) {
        // Note: Would need to track timestamps to actually clean up
        // For now, just provide the API
    }
}

#[derive(Debug, Clone)]
pub struct FlowAnalyzerSummary {
    pub total_tcp_flows: usize,
    pub complete_tcp_handshakes: usize,
    pub total_tls_flows: usize,
    pub complete_tls_handshakes: usize,
    pub total_dhcp_flows: usize,
    pub complete_dhcp_dora: usize,
}
