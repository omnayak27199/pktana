use std::fmt;
use std::fs;
use std::path::Path;

use crate::flow::FlowTable;
use crate::packet::{
    EtherType, EthernetFrame, IpProtocol, Ipv4Header, PacketSummary, TransportHeader,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub raw: Vec<u8>,
    pub summary: PacketSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InvalidHex(String),
    Truncated(&'static str),
    Unsupported(&'static str),
    Io(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex(msg) => write!(f, "invalid hex: {msg}"),
            Self::Truncated(layer) => write!(f, "truncated {layer} header"),
            Self::Unsupported(msg) => write!(f, "unsupported packet: {msg}"),
            Self::Io(msg) => write!(f, "io error: {msg}"),
        }
    }
}

pub fn analyze_hex(input: &str) -> Result<ParsedPacket, ParseError> {
    let bytes = decode_hex(input)?;
    analyze_bytes(&bytes)
}

pub fn analyze_bytes(bytes: &[u8]) -> Result<ParsedPacket, ParseError> {
    parse_ethernet_frame(&bytes)
}

pub fn analyze_many_hex_lines(input: &str) -> (Vec<ParsedPacket>, Vec<String>) {
    let mut packets = Vec::new();
    let mut errors = Vec::new();

    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match analyze_hex(trimmed) {
            Ok(packet) => packets.push(packet),
            Err(err) => errors.push(format!("line {}: {}", index + 1, err)),
        }
    }

    (packets, errors)
}

pub fn analyze_hex_file(path: &Path) -> Result<(Vec<ParsedPacket>, Vec<String>), ParseError> {
    let content = fs::read_to_string(path).map_err(|err| ParseError::Io(err.to_string()))?;
    Ok(analyze_many_hex_lines(&content))
}

pub fn sample_packets() -> Vec<&'static str> {
    vec![
        "00112233445566778899aabb08004500002800010000400666cd0a0000010a00000201bb303900000001000000005002faf090b00000",
        "00112233445566778899aabb08004500001c00010000401160c30a00000108080808003500350008ad77",
    ]
}

pub fn build_flow_table(packets: &[ParsedPacket]) -> FlowTable {
    let mut table = FlowTable::default();
    for packet in packets {
        table.ingest(&packet.summary);
    }
    table
}

fn parse_ethernet_frame(bytes: &[u8]) -> Result<ParsedPacket, ParseError> {
    if bytes.len() < 14 {
        return Err(ParseError::Truncated("ethernet"));
    }

    let mut destination = [0_u8; 6];
    let mut source = [0_u8; 6];
    destination.copy_from_slice(&bytes[0..6]);
    source.copy_from_slice(&bytes[6..12]);

    let ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
    let ethernet = EthernetFrame {
        destination,
        source,
        ether_type: EtherType::from(ether_type),
    };

    let payload = &bytes[14..];
    let (ipv4, transport, payload_len) = match ethernet.ether_type {
        EtherType::Ipv4 => parse_ipv4(payload)?,
        EtherType::Arp | EtherType::Ipv6 | EtherType::Vlan | EtherType::Other(_) => {
            (None, None, payload.len())
        }
    };

    Ok(ParsedPacket {
        raw: bytes.to_vec(),
        summary: PacketSummary {
            ethernet,
            ipv4,
            transport,
            payload_len,
            frame_len: bytes.len(),
        },
    })
}

fn parse_ipv4(
    payload: &[u8],
) -> Result<(Option<Ipv4Header>, Option<TransportHeader>, usize), ParseError> {
    if payload.len() < 20 {
        return Err(ParseError::Truncated("ipv4"));
    }

    let version = payload[0] >> 4;
    if version != 4 {
        return Err(ParseError::Unsupported("non-ipv4 payload in ipv4 parser"));
    }

    let ihl = (payload[0] & 0x0f) as usize * 4;
    if payload.len() < ihl {
        return Err(ParseError::Truncated("ipv4 options"));
    }

    let total_length = u16::from_be_bytes([payload[2], payload[3]]);
    let ttl = payload[8];
    let protocol = IpProtocol::from(payload[9]);
    let source = std::net::Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let destination = std::net::Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

    let header = Ipv4Header {
        source,
        destination,
        protocol,
        ttl,
        header_length: ihl,
        total_length,
    };

    let ip_payload = &payload[ihl..];
    let (transport, payload_len) = match protocol {
        IpProtocol::Tcp => parse_tcp(ip_payload)?,
        IpProtocol::Udp => parse_udp(ip_payload)?,
        IpProtocol::Icmp => parse_icmp(ip_payload)?,
        _ => (Some(TransportHeader::Unsupported), ip_payload.len()),
    };

    Ok((Some(header), transport, payload_len))
}

fn parse_tcp(payload: &[u8]) -> Result<(Option<TransportHeader>, usize), ParseError> {
    if payload.len() < 20 {
        return Err(ParseError::Truncated("tcp"));
    }

    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let sequence_number = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let acknowledgement_number =
        u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let data_offset = ((payload[12] >> 4) as usize) * 4;
    if payload.len() < data_offset {
        return Err(ParseError::Truncated("tcp options"));
    }
    let flags = u16::from_be_bytes([payload[12] & 0x1f, payload[13]]);
    let window_size = u16::from_be_bytes([payload[14], payload[15]]);
    let payload_len = payload.len().saturating_sub(data_offset);

    Ok((
        Some(TransportHeader::Tcp {
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            data_offset,
            flags,
            window_size,
        }),
        payload_len,
    ))
}

fn parse_udp(payload: &[u8]) -> Result<(Option<TransportHeader>, usize), ParseError> {
    if payload.len() < 8 {
        return Err(ParseError::Truncated("udp"));
    }

    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u16::from_be_bytes([payload[4], payload[5]]);
    let payload_len = payload.len().saturating_sub(8);

    Ok((
        Some(TransportHeader::Udp {
            source_port,
            destination_port,
            length,
        }),
        payload_len,
    ))
}

fn parse_icmp(payload: &[u8]) -> Result<(Option<TransportHeader>, usize), ParseError> {
    if payload.len() < 4 {
        return Err(ParseError::Truncated("icmp"));
    }
    let icmp_type = payload[0];
    let code = payload[1];
    let payload_len = payload.len().saturating_sub(4);
    Ok((Some(TransportHeader::Icmp { icmp_type, code }), payload_len))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ParseError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err(ParseError::InvalidHex("odd-length hex string".to_string()));
    }

    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    let chars: Vec<char> = cleaned.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let pair = [chars[index], chars[index + 1]];
        let text: String = pair.iter().collect();
        let byte = u8::from_str_radix(&text, 16)
            .map_err(|_| ParseError::InvalidHex(format!("bad byte `{text}`")))?;
        bytes.push(byte);
        index += 2;
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_demo_packets() {
        for sample in sample_packets() {
            let parsed = analyze_hex(sample).expect("sample packet should parse");
            assert!(parsed.summary.frame_len > 14);
        }
    }

    #[test]
    fn builds_flows() {
        let packets = sample_packets()
            .into_iter()
            .map(|hex| analyze_hex(hex).expect("packet should parse"))
            .collect::<Vec<_>>();
        let flows = build_flow_table(&packets);
        assert!(!flows.is_empty());
    }
}
