pub mod capture;
pub mod connections;
pub mod dpi;
pub mod ethtool;
pub mod flow;
pub mod nic;
pub mod packet;
pub mod parser;
pub mod routes;

pub use capture::{CaptureConfig, CaptureError, CapturePacket, CaptureStats, InterfaceSummary, LinuxCaptureEngine};
pub use dpi::{inspect, hex_dump, DeepPacket, ArpDetail, VlanTag};
pub use connections::{list_connections, Connection};
pub use ethtool::{get_ethtool_report, EthtoolReport, QueueIrq};
pub use flow::{FlowKey, FlowRecord, FlowTable};
pub use nic::{get_nic_info, get_nic_dataplane, list_nics, BypassMode, NicDataplane, NicInfo};
pub use packet::format_bytes;
pub use packet::{tcp_flags_str, EtherType, EthernetFrame, IpProtocol, Ipv4Header, PacketSummary, TransportHeader};
pub use routes::{list_routes, routes_for_iface, RouteEntry};
pub use parser::{
    analyze_bytes,
    analyze_hex,
    analyze_hex_file,
    analyze_many_hex_lines,
    build_flow_table,
    sample_packets,
    ParseError,
    ParsedPacket,
};
