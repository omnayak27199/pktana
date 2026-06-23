// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

pub mod buffer_pool;
pub mod capture;
pub mod connections;
pub mod dp;
pub mod dpi;
pub mod ethtool;
pub mod flow;
pub mod flow_analyzer;
pub mod geoip;
pub mod hw;
pub mod nic;
pub mod packet;
pub mod parser;
pub mod process;
pub mod routes;

pub use buffer_pool::{BufferPool, PacketBuffer};
pub use capture::{
    CaptureConfig, CaptureError, CapturePacket, CaptureStats, InterfaceSummary, LinuxCaptureEngine,
};
pub use connections::{list_connections, Connection};
pub use dp::{
    detect_tc_bpf, list_network_namespaces, list_xdp_dispatchers, scan_bpf_fs, BpfPinnedObject,
    NetNamespace, TcBpfInfo, XdpDispatcher,
};
pub use dpi::{hex_dump, inspect, ArpDetail, DeepPacket, VlanTag};
pub use ethtool::{get_ethtool_report, EthtoolReport, QueueIrq};
pub use flow::{FlowKey, FlowRecord, FlowTable};
pub use flow_analyzer::{
    DhcpDoraAnalysis, DhcpDoraState, DnsTransactionAnalysis, FlowAnalyzer, FlowAnalyzerSummary,
    FlowId, Protocol, TcpHandshakeAnalysis, TcpHandshakeState, TlsHandshakeAnalysis,
    TlsHandshakeState,
};
pub use geoip::{lookup as geoip_lookup, lookup_str as geoip_lookup_str, GeoInfo};
pub use hw::{
    get_bond_info, get_bridge_info, get_bridge_port_info, get_iommu_group, get_ptp_clocks,
    stp_state_label, BondInfo, BridgeInfo, BridgePortInfo, IommuGroup, PtpClock,
};
pub use nic::{get_nic_dataplane, get_nic_info, list_nics, BypassMode, NicDataplane, NicInfo};
pub use packet::format_bytes;
pub use packet::{
    tcp_flags_str, EtherType, EthernetFrame, IpProtocol, Ipv4Header, PacketSummary, TransportHeader,
};
pub use parser::{
    analyze_bytes, analyze_hex, analyze_hex_file, analyze_many_hex_lines, build_flow_table,
    sample_packets, ParseError, ParsedPacket,
};
pub use process::{build_socket_process_map, lookup_process, ProcessInfo, SocketId};
pub use routes::{list_routes, routes_for_iface, RouteEntry};
