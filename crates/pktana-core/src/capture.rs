use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub interface: String,
    pub max_packets: usize,
    pub promiscuous: bool,
    pub snapshot_len: i32,
    pub filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            max_packets: 10,
            promiscuous: true,
            snapshot_len: 65_535,
            filter: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSummary {
    pub name: String,
    pub description: Option<String>,
    pub loopback: bool,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePacket {
    pub timestamp_sec: i64,
    pub timestamp_usec: i64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStats {
    pub packets_seen: usize,
    pub bytes_seen: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    Unsupported(&'static str),
    Interface(String),
    Open(String),
    Filter(String),
    Read(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(msg) => write!(f, "{msg}"),
            Self::Interface(msg) => write!(f, "interface error: {msg}"),
            Self::Open(msg) => write!(f, "capture open error: {msg}"),
            Self::Filter(msg) => write!(f, "capture filter error: {msg}"),
            Self::Read(msg) => write!(f, "capture read error: {msg}"),
        }
    }
}

pub struct LinuxCaptureEngine;

impl LinuxCaptureEngine {
    pub fn list_interfaces() -> Result<Vec<InterfaceSummary>, CaptureError> {
        list_interfaces_impl()
    }

    pub fn capture(
        config: &CaptureConfig,
    ) -> Result<(Vec<CapturePacket>, CaptureStats), CaptureError> {
        capture_impl(config)
    }

    /// Stream packets one-by-one, calling `on_packet` for each.
    /// Return `false` from the closure to stop early.
    pub fn capture_streaming<F>(
        config: &CaptureConfig,
        on_packet: F,
    ) -> Result<CaptureStats, CaptureError>
    where
        F: FnMut(CapturePacket) -> bool,
    {
        capture_streaming_impl(config, on_packet)
    }
}

#[cfg(feature = "pcap")]
fn list_interfaces_impl() -> Result<Vec<InterfaceSummary>, CaptureError> {
    let devices = pcap::Device::list().map_err(|err| CaptureError::Interface(err.to_string()))?;
    Ok(devices
        .into_iter()
        .map(|device| {
            let addresses = device
                .addresses
                .iter()
                .map(|a| a.addr.to_string())
                .collect();
            InterfaceSummary {
                name: device.name,
                description: device.desc,
                loopback: device.flags.is_loopback(),
                addresses,
            }
        })
        .collect())
}

#[cfg(not(feature = "pcap"))]
fn list_interfaces_impl() -> Result<Vec<InterfaceSummary>, CaptureError> {
    Err(CaptureError::Unsupported(
        "pcap support is not enabled; rebuild with `--features pcap`",
    ))
}

#[cfg(feature = "pcap")]
fn capture_streaming_impl<F>(
    config: &CaptureConfig,
    mut on_packet: F,
) -> Result<CaptureStats, CaptureError>
where
    F: FnMut(CapturePacket) -> bool,
{
    let inactive = pcap::Capture::from_device(config.interface.as_str())
        .map_err(|err| CaptureError::Interface(err.to_string()))?;

    let mut capture = inactive
        .promisc(config.promiscuous)
        .snaplen(config.snapshot_len)
        .timeout(1_000)
        .immediate_mode(true)
        .open()
        .map_err(|err| CaptureError::Open(err.to_string()))?;

    if let Some(filter) = &config.filter {
        capture
            .filter(filter, true)
            .map_err(|err| CaptureError::Filter(err.to_string()))?;
    }

    let mut stats = CaptureStats {
        packets_seen: 0,
        bytes_seen: 0,
    };

    loop {
        if stats.packets_seen >= config.max_packets {
            break;
        }
        match capture.next_packet() {
            Ok(packet) => {
                let data = packet.data.to_vec();
                stats.packets_seen += 1;
                stats.bytes_seen += data.len();
                let cp = CapturePacket {
                    timestamp_sec: packet.header.ts.tv_sec,
                    timestamp_usec: packet.header.ts.tv_usec,
                    data,
                };
                if !on_packet(cp) {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => return Err(CaptureError::Read(err.to_string())),
        }
    }

    Ok(stats)
}

#[cfg(not(feature = "pcap"))]
fn capture_streaming_impl<F>(
    _config: &CaptureConfig,
    _on_packet: F,
) -> Result<CaptureStats, CaptureError>
where
    F: FnMut(CapturePacket) -> bool,
{
    Err(CaptureError::Unsupported(
        "live capture is not enabled; rebuild with `--features pcap`",
    ))
}

#[cfg(feature = "pcap")]
fn capture_impl(
    config: &CaptureConfig,
) -> Result<(Vec<CapturePacket>, CaptureStats), CaptureError> {
    let inactive = pcap::Capture::from_device(config.interface.as_str())
        .map_err(|err| CaptureError::Interface(err.to_string()))?;

    let mut capture = inactive
        .promisc(config.promiscuous)
        .snaplen(config.snapshot_len)
        .timeout(1_000)
        .immediate_mode(true)
        .open()
        .map_err(|err| CaptureError::Open(err.to_string()))?;

    if let Some(filter) = &config.filter {
        capture
            .filter(filter, true)
            .map_err(|err| CaptureError::Filter(err.to_string()))?;
    }

    let mut packets = Vec::with_capacity(config.max_packets);
    let mut stats = CaptureStats {
        packets_seen: 0,
        bytes_seen: 0,
    };

    while packets.len() < config.max_packets {
        match capture.next_packet() {
            Ok(packet) => {
                let packet_data = packet.data.to_vec();
                stats.packets_seen += 1;
                stats.bytes_seen += packet_data.len();
                packets.push(CapturePacket {
                    timestamp_sec: packet.header.ts.tv_sec,
                    timestamp_usec: packet.header.ts.tv_usec,
                    data: packet_data,
                });
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => return Err(CaptureError::Read(err.to_string())),
        }
    }

    Ok((packets, stats))
}

#[cfg(not(feature = "pcap"))]
fn capture_impl(
    _config: &CaptureConfig,
) -> Result<(Vec<CapturePacket>, CaptureStats), CaptureError> {
    Err(CaptureError::Unsupported(
        "live capture is not enabled; rebuild with `--features pcap`",
    ))
}
