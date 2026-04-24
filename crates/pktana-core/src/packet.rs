use std::fmt;
use std::net::Ipv4Addr;

/// Human-readable byte size: "1.23 GB", "512.00 KB", "42 B", etc.
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.2} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Vlan,
    Other(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            0x8100 | 0x88a8 => Self::Vlan,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "IPv4"),
            Self::Arp => write!(f, "ARP"),
            Self::Ipv6 => write!(f, "IPv6"),
            Self::Vlan => write!(f, "VLAN"),
            Self::Other(value) => write!(f, "0x{value:04x}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: EtherType,
}

impl EthernetFrame {
    pub fn source_mac(&self) -> String {
        format_mac(&self.source)
    }

    pub fn destination_mac(&self) -> String {
        format_mac(&self.destination)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Other(value) => write!(f, "IP({value})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: IpProtocol,
    pub ttl: u8,
    pub header_length: usize,
    pub total_length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportHeader {
    Tcp {
        source_port: u16,
        destination_port: u16,
        sequence_number: u32,
        acknowledgement_number: u32,
        data_offset: usize,
        flags: u16,
        /// TCP receive window (bytes). 0 = receiver buffer full (flow control pause).
        window_size: u16,
    },
    Udp {
        source_port: u16,
        destination_port: u16,
        length: u16,
    },
    Icmp {
        icmp_type: u8,
        code: u8,
    },
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSummary {
    pub ethernet: EthernetFrame,
    pub ipv4: Option<Ipv4Header>,
    pub transport: Option<TransportHeader>,
    pub payload_len: usize,
    pub frame_len: usize,
}

impl PacketSummary {
    pub fn pretty(&self) -> String {
        let mut line = format!(
            "{} -> {} | eth={} | len={}",
            self.ethernet.source_mac(),
            self.ethernet.destination_mac(),
            self.ethernet.ether_type,
            self.frame_len
        );

        if let Some(ip) = &self.ipv4 {
            line.push_str(&format!(
                " | ip={} -> {} | proto={} | ttl={}",
                ip.source, ip.destination, ip.protocol, ip.ttl
            ));
        }

        if let Some(transport) = &self.transport {
            match transport {
                TransportHeader::Tcp {
                    source_port,
                    destination_port,
                    flags,
                    window_size,
                    ..
                } => {
                    line.push_str(&format!(
                        " | tcp={} -> {} | flags=0x{flags:03x} | win={window_size}",
                        source_port, destination_port
                    ));
                }
                TransportHeader::Udp {
                    source_port,
                    destination_port,
                    length,
                } => {
                    line.push_str(&format!(
                        " | udp={} -> {} | udp_len={}",
                        source_port, destination_port, length
                    ));
                }
                TransportHeader::Icmp { icmp_type, code } => {
                    line.push_str(&format!(" | icmp type={icmp_type} code={code}"));
                }
                TransportHeader::Unsupported => {
                    line.push_str(" | transport=unsupported");
                }
            }
        }

        line.push_str(&format!(" | payload={}", self.payload_len));
        line
    }

    /// One-word protocol label for the table Proto column.
    pub fn proto_label(&self) -> &'static str {
        match &self.transport {
            Some(TransportHeader::Tcp { .. }) => "TCP",
            Some(TransportHeader::Udp { .. }) => "UDP",
            Some(TransportHeader::Icmp { .. }) => "ICMP",
            _ => match self.ethernet.ether_type {
                EtherType::Arp  => "ARP",
                EtherType::Ipv6 => "IPv6",
                EtherType::Vlan => "VLAN",
                _ => "Other",
            },
        }
    }

    /// Source string: "ip:port" for TCP/UDP, "ip" for others, MAC if no IP.
    pub fn src_str(&self) -> String {
        if let Some(ip) = &self.ipv4 {
            match &self.transport {
                Some(TransportHeader::Tcp { source_port, .. }) => {
                    format!("{}:{}", ip.source, source_port)
                }
                Some(TransportHeader::Udp { source_port, .. }) => {
                    format!("{}:{}", ip.source, source_port)
                }
                _ => ip.source.to_string(),
            }
        } else {
            self.ethernet.source_mac()
        }
    }

    /// Destination string: "ip:port" for TCP/UDP, "ip" for others, MAC if no IP.
    pub fn dst_str(&self) -> String {
        if let Some(ip) = &self.ipv4 {
            match &self.transport {
                Some(TransportHeader::Tcp { destination_port, .. }) => {
                    format!("{}:{}", ip.destination, destination_port)
                }
                Some(TransportHeader::Udp { destination_port, .. }) => {
                    format!("{}:{}", ip.destination, destination_port)
                }
                _ => ip.destination.to_string(),
            }
        } else {
            self.ethernet.destination_mac()
        }
    }

    /// Human-readable Info column: flag names, service names, ICMP descriptions.
    pub fn info_str(&self) -> String {
        match &self.transport {
            Some(TransportHeader::Tcp { source_port, destination_port, flags, window_size, .. }) => {
                let flagstr = tcp_flags_str(*flags);
                let svc = port_service(*destination_port)
                    .or_else(|| port_service(*source_port))
                    .map(|s| format!(" [{s}]"))
                    .unwrap_or_default();
                let win_warn = if *window_size == 0 { " [ZERO-WIN]" } else { "" };
                format!("{flagstr}{svc}{win_warn}")
            }
            Some(TransportHeader::Udp { source_port, destination_port, .. }) => {
                port_service(*destination_port)
                    .or_else(|| port_service(*source_port))
                    .unwrap_or("UDP")
                    .to_string()
            }
            Some(TransportHeader::Icmp { icmp_type, code }) => icmp_info(*icmp_type, *code),
            _ => match self.ethernet.ether_type {
                EtherType::Arp  => "ARP".to_string(),
                EtherType::Ipv6 => "IPv6".to_string(),
                EtherType::Vlan => "VLAN".to_string(),
                EtherType::Other(v) => format!("EtherType 0x{v:04x}"),
                EtherType::Ipv4 => "IPv4".to_string(),
            },
        }
    }
}

/// Decode TCP flags word into human-readable flag names (e.g. "SYN-ACK").
/// The flags u16 is stored as [payload[12] & 0x1f, payload[13]] big-endian,
/// so the standard 6 control bits live in the low byte.
pub fn tcp_flags_str(flags: u16) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & 0x0002 != 0 { parts.push("SYN"); }
    if flags & 0x0010 != 0 { parts.push("ACK"); }
    if flags & 0x0001 != 0 { parts.push("FIN"); }
    if flags & 0x0004 != 0 { parts.push("RST"); }
    if flags & 0x0008 != 0 { parts.push("PSH"); }
    if flags & 0x0020 != 0 { parts.push("URG"); }
    if parts.is_empty() { "[no flags]".to_string() } else { parts.join("-") }
}

fn port_service(port: u16) -> Option<&'static str> {
    match port {
        22   => Some("SSH"),
        23   => Some("Telnet"),
        25   => Some("SMTP"),
        53   => Some("DNS"),
        67 | 68 => Some("DHCP"),
        80   => Some("HTTP"),
        110  => Some("POP3"),
        123  => Some("NTP"),
        143  => Some("IMAP"),
        179  => Some("BGP"),
        443  => Some("HTTPS"),
        514  => Some("Syslog"),
        587  => Some("SMTP"),
        636  => Some("LDAPS"),
        993  => Some("IMAPS"),
        995  => Some("POP3S"),
        1194 => Some("OpenVPN"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5432 => Some("PostgreSQL"),
        6379 => Some("Redis"),
        8080 => Some("HTTP-Alt"),
        8443 => Some("HTTPS-Alt"),
        9200 => Some("Elasticsearch"),
        27017 => Some("MongoDB"),
        _    => None,
    }
}

fn icmp_info(icmp_type: u8, code: u8) -> String {
    match icmp_type {
        0  => "Echo Reply".to_string(),
        3  => match code {
            0 => "Dest Unreachable: Net".to_string(),
            1 => "Dest Unreachable: Host".to_string(),
            2 => "Dest Unreachable: Protocol".to_string(),
            3 => "Dest Unreachable: Port".to_string(),
            _ => format!("Dest Unreachable (code {code})"),
        },
        8  => "Echo Request".to_string(),
        11 => match code {
            0 => "TTL Exceeded in Transit".to_string(),
            1 => "Fragment Reassembly Timeout".to_string(),
            _ => format!("Time Exceeded (code {code})"),
        },
        _  => format!("ICMP Type {icmp_type} Code {code}"),
    }
}

fn format_mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

