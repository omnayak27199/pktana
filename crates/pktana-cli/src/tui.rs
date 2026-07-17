// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Feature-complete Wireshark-inspired Terminal UI for pktana.
//!
//! Panes / Tabs
//! ─────────────
//!  [1] Overview  – live stats panel + sortable flow table
//!  [2] Packets   – per-packet capture list  (Wireshark top pane)
//!  [3] Flows     – enriched bidirectional flow table with DPI badges
//!  [4] Stats     – protocol hierarchy + top-N endpoints
//!  [5] Help      – full keybinding reference
//!
//! Detail popup (Enter on any flow / packet)
//! ──────────────────────────────────────────
//!  [O]verview  – addresses, process, geo, timing, traffic counters
//!  [L]ayers    – full DPI layer-by-layer decode (L2→L3→L4→L7 + anomalies)
//!  [H]ex       – raw hex + ASCII dump (like Wireshark bottom pane)
//!
//! Extra Wireshark-like features
//! ──────────────────────────────
//!  • Bandwidth sparkline (Unicode block chars) in header
//!  • Protocol colour-coding per proto rules
//!  • Well-known port → service name resolution (100+ services)
//!  • Expert/anomaly badge column ⚠N on anomalous flows
//!  • TCP retransmit counter per flow
//!  • Per-flow recent-packet raw buffer for on-demand DPI
//!  • Scrollable popup (PgUp/PgDn/mouse wheel)
//!  • Protocol hierarchy with % breakdown (Stats tab)
//!  • Top-N endpoint byte stats

#[cfg(feature = "tui")]
pub mod inner {
    use std::collections::{HashMap, VecDeque};
    use std::io;
    use std::net::IpAddr;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseEventKind},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout, Rect},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Wrap},
        Frame, Terminal,
    };

    use pktana_core::{
        analyze_bytes, build_socket_process_map, diagnose_path, evaluate_packet, geoip_lookup_str,
        get_nic_dataplane, get_security_config, hex_dump, inspect, list_network_namespaces,
        scan_bpf_fs, CaptureConfig, CapturePacket, GeoInfo, IssueSeverity, LinuxCaptureEngine,
        NicDataplane, ProcessInfo, SocketId,
    };

    // ═══════════════════════════════════════════════════════════════════════════
    //  Data types
    // ═══════════════════════════════════════════════════════════════════════════

    /// One captured packet – shown in the Packets tab (Wireshark top pane).
    #[derive(Clone)]
    struct PacketEntry {
        no: u64,
        time_offset: f64,
        src: String,
        dst: String,
        protocol: String,
        length: usize,
        info: String,
        raw: Vec<u8>,
    }

    /// Bidirectional network flow.
    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    struct Connection {
        id: usize,
        protocol: String,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
        state: String,
        process: Option<ProcessInfo>,
        geo: Option<GeoInfo>,
        first_seen: Instant,
        last_seen: Instant,
        packets_sent: u64,
        packets_recv: u64,
        bytes_sent: u64,
        bytes_recv: u64,
        active: bool,
        tcp_retransmits: u32,
        last_tcp_seq: Option<u32>,
        anomalies: Vec<String>,
        recent_raw: VecDeque<Vec<u8>>,
        // Live DPI fields — updated with each new packet for this flow
        app_proto: Option<String>,
        tls_sni: Option<String>,
        risk_score: u8,
        app_category: Option<String>,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum SortColumn {
        Protocol,
        LocalAddr,
        RemoteAddr,
        State,
        Process,
        BytesTotal,
        Anomalies,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum SortDirection {
        Ascending,
        Descending,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Tab {
        Overview,
        Packets,
        Flows,
        Stats,
        Dataplane,
        Help,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum DetailSub {
        Overview,
        Layers,
        Hex,
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  App
    // ═══════════════════════════════════════════════════════════════════════════

    struct App {
        interface: String,
        start_time: Instant,
        // flows
        connections: Vec<Connection>,
        next_conn_id: usize,
        process_map: HashMap<SocketId, ProcessInfo>,
        last_process_update: Instant,
        endpoint_bytes: HashMap<String, u64>,
        endpoint_pkts: HashMap<String, u64>,
        // packet list
        packets: VecDeque<PacketEntry>,
        next_pkt_no: u64,
        // global stats
        total_packets: u64,
        total_bytes: u64,
        protocol_counts: HashMap<String, u64>,
        protocol_bytes: HashMap<String, u64>,
        // bandwidth sparkline
        bw_history: VecDeque<u64>,
        bw_last_bytes: u64,
        bw_last_tick: Instant,
        // flow analysis
        flow_analyze_mode: bool,
        flow_analyzer: Option<pktana_core::FlowAnalyzer>,
        flow_events: VecDeque<String>,
        // UI
        current_tab: Tab,
        flow_selected: usize,
        flow_table_state: TableState,
        sort_column: SortColumn,
        sort_direction: SortDirection,
        show_historic: bool,
        pkt_selected: usize,
        pkt_table_state: TableState,
        filter_text: String,
        filter_mode: bool,
        show_detail: bool,
        detail_sub: DetailSub,
        popup_scroll: u16,
        // pcap-file mode
        pcap_mode: bool,
        pcap_file: String,
        // NIC dataplane snapshot (loaded once at startup)
        nic_dataplane: Option<NicDataplane>,
    }

    impl App {
        fn new(interface: &str) -> Self {
            let mut fts = TableState::default();
            fts.select(Some(0));
            let mut pts = TableState::default();
            pts.select(Some(0));
            Self {
                interface: interface.to_string(),
                start_time: Instant::now(),
                connections: Vec::new(),
                next_conn_id: 0,
                process_map: HashMap::new(),
                last_process_update: Instant::now(),
                endpoint_bytes: HashMap::new(),
                endpoint_pkts: HashMap::new(),
                packets: VecDeque::new(),
                next_pkt_no: 1,
                total_packets: 0,
                total_bytes: 0,
                protocol_counts: HashMap::new(),
                protocol_bytes: HashMap::new(),
                bw_history: VecDeque::with_capacity(64),
                bw_last_bytes: 0,
                bw_last_tick: Instant::now(),
                flow_analyze_mode: false,
                flow_analyzer: None,
                flow_events: VecDeque::with_capacity(100),
                current_tab: Tab::Overview,
                flow_selected: 0,
                flow_table_state: fts,
                sort_column: SortColumn::BytesTotal,
                sort_direction: SortDirection::Descending,
                show_historic: false,
                pkt_selected: 0,
                pkt_table_state: pts,
                filter_text: String::new(),
                filter_mode: false,
                show_detail: false,
                detail_sub: DetailSub::Overview,
                popup_scroll: 0,
                pcap_mode: false,
                pcap_file: String::new(),
                nic_dataplane: get_nic_dataplane(interface).ok(),
            }
        }

        fn ingest_packet(&mut self, pkt: &CapturePacket<'_>) {
            self.total_packets += 1;
            let plen = pkt.data.len() as u64;
            self.total_bytes += plen;

            if self.bw_last_tick.elapsed() >= Duration::from_millis(250) {
                let delta = self.total_bytes.saturating_sub(self.bw_last_bytes);
                self.bw_history.push_back(delta);
                if self.bw_history.len() > 60 {
                    self.bw_history.pop_front();
                }
                self.bw_last_bytes = self.total_bytes;
                self.bw_last_tick = Instant::now();
            }

            // Flow analysis if enabled
            if self.flow_analyze_mode {
                let dp = inspect(&pkt.data);
                if let Some(ref mut analyzer) = self.flow_analyzer {
                    let results = analyzer.analyze_packet(&dp);
                    for result in results {
                        self.flow_events.push_back(result);
                        if self.flow_events.len() > 100 {
                            self.flow_events.pop_front();
                        }
                    }
                }
            }

            // DLP / IDPS when engines are enabled (shared store with Web UI)
            let mut sec_suffix = String::new();
            let sec_cfg = get_security_config();
            if sec_cfg.dlp_enabled || sec_cfg.idps_enabled {
                let dp = inspect(&pkt.data);
                let sec = evaluate_packet(
                    &dp,
                    pkt.timestamp_sec as u64,
                    plen,
                    self.interface.as_str(),
                    "",
                );
                if !sec.alerts.is_empty() {
                    let mut engines = Vec::new();
                    for a in &sec.alerts {
                        if !engines.contains(&a.engine) {
                            engines.push(a.engine.clone());
                        }
                    }
                    sec_suffix = format!(
                        " [{}:{}]",
                        engines.join("+").to_uppercase(),
                        sec.verdict
                    );
                }
            }

            let Ok(parsed) = analyze_bytes(&pkt.data) else {
                let entry = PacketEntry {
                    no: self.next_pkt_no,
                    time_offset: self.start_time.elapsed().as_secs_f64(),
                    src: "-".into(),
                    dst: "-".into(),
                    protocol: "RAW".into(),
                    length: pkt.data.len(),
                    info: format!("{} bytes (unparseable)", pkt.data.len()),
                    raw: pkt.data.to_vec(),
                };
                self.push_packet(entry);
                return;
            };

            let summary = &parsed.summary;
            let protocol = summary.proto_label().to_string();
            *self.protocol_counts.entry(protocol.clone()).or_insert(0) += 1;
            *self.protocol_bytes.entry(protocol.clone()).or_insert(0) += plen;

            let (src_ip, src_port, dst_ip, dst_port) = extract_tuple(summary).unwrap_or_default();

            let src_str = if src_port > 0 {
                format!("{}:{}", src_ip, src_port)
            } else {
                src_ip.clone()
            };
            let dst_str = if dst_port > 0 {
                format!("{}:{}", dst_ip, dst_port)
            } else {
                dst_ip.clone()
            };
            let info = format!("{}{}", build_info(summary), sec_suffix);

            let entry = PacketEntry {
                no: self.next_pkt_no,
                time_offset: self.start_time.elapsed().as_secs_f64(),
                src: src_str,
                dst: dst_str,
                protocol: protocol.clone(),
                length: pkt.data.len(),
                info,
                raw: pkt.data.to_vec(),
            };
            self.push_packet(entry);

            if !src_ip.is_empty() {
                *self.endpoint_bytes.entry(src_ip.clone()).or_insert(0) += plen;
                *self.endpoint_pkts.entry(src_ip.clone()).or_insert(0) += 1;
                *self.endpoint_bytes.entry(dst_ip.clone()).or_insert(0) += plen;
                *self.endpoint_pkts.entry(dst_ip.clone()).or_insert(0) += 1;
            }

            if src_ip.is_empty() {
                return;
            }

            if let Some(conn) = self.connections.iter_mut().find(|c| {
                (c.local_ip == src_ip
                    && c.local_port == src_port
                    && c.remote_ip == dst_ip
                    && c.remote_port == dst_port)
                    || (c.local_ip == dst_ip
                        && c.local_port == dst_port
                        && c.remote_ip == src_ip
                        && c.remote_port == src_port)
            }) {
                conn.last_seen = Instant::now();
                conn.packets_recv += 1;
                conn.bytes_recv += plen;
                conn.active = true;
                if let Some(pktana_core::TransportHeader::Tcp {
                    sequence_number,
                    flags,
                    ..
                }) = &summary.transport
                {
                    let syn = flags & 0x002 != 0;
                    let rst = flags & 0x004 != 0;
                    if !syn && !rst {
                        if let Some(last) = conn.last_tcp_seq {
                            if *sequence_number == last {
                                conn.tcp_retransmits += 1;
                                let label = "TCP retransmit".to_string();
                                if !conn.anomalies.contains(&label) {
                                    conn.anomalies.push(label);
                                }
                            }
                        }
                    }
                    conn.last_tcp_seq = Some(*sequence_number);
                }
                if conn.recent_raw.len() >= 5 {
                    conn.recent_raw.pop_front();
                }
                conn.recent_raw.push_back(pkt.data.to_vec());
                // Update live DPI fields from most recent packet
                let dp = inspect(&pkt.data);
                if dp.app_proto.is_some() {
                    conn.app_proto = dp.app_proto.clone();
                }
                let sni = sni_from_deep(&dp);
                if sni.is_some() {
                    conn.tls_sni = sni;
                }
                if dp.risk_score > 0 {
                    conn.risk_score = dp.risk_score;
                }
                if dp.app_category.is_some() {
                    conn.app_category = dp.app_category.clone();
                }
            } else {
                let geo = geoip_lookup_str(&dst_ip);
                let process = if let (Ok(li), Ok(ri)) =
                    (src_ip.parse::<IpAddr>(), dst_ip.parse::<IpAddr>())
                {
                    let sid = SocketId::new(li, src_port, ri, dst_port);
                    self.process_map.get(&sid).cloned()
                } else {
                    None
                };
                let mut rr = VecDeque::new();
                rr.push_back(pkt.data.to_vec());
                let dp = inspect(&pkt.data);
                self.connections.push(Connection {
                    id: self.next_conn_id,
                    protocol: protocol.clone(),
                    local_ip: src_ip,
                    local_port: src_port,
                    remote_ip: dst_ip,
                    remote_port: dst_port,
                    state: infer_state(summary),
                    process,
                    geo,
                    first_seen: Instant::now(),
                    last_seen: Instant::now(),
                    packets_sent: 1,
                    packets_recv: 0,
                    bytes_sent: plen,
                    bytes_recv: 0,
                    active: true,
                    tcp_retransmits: 0,
                    last_tcp_seq: None,
                    anomalies: Vec::new(),
                    recent_raw: rr,
                    app_proto: dp.app_proto.clone(),
                    tls_sni: sni_from_deep(&dp),
                    risk_score: dp.risk_score,
                    app_category: dp.app_category.clone(),
                });
                self.next_conn_id += 1;
            }
        }

        fn push_packet(&mut self, e: PacketEntry) {
            self.packets.push_back(e);
            self.next_pkt_no += 1;
            if self.packets.len() > 5000 {
                self.packets.pop_front();
            }
        }

        fn update_process_map(&mut self) {
            if self.last_process_update.elapsed() > Duration::from_secs(2) {
                self.process_map = build_socket_process_map();
                self.last_process_update = Instant::now();
                for conn in &mut self.connections {
                    if conn.process.is_none() {
                        if let (Ok(li), Ok(ri)) = (
                            conn.local_ip.parse::<IpAddr>(),
                            conn.remote_ip.parse::<IpAddr>(),
                        ) {
                            let sid = SocketId::new(li, conn.local_port, ri, conn.remote_port);
                            if let Some(pi) = self.process_map.get(&sid) {
                                conn.process = Some(pi.clone());
                            }
                        }
                    }
                }
            }
        }

        fn cleanup_stale(&mut self) {
            let now = Instant::now();
            for c in &mut self.connections {
                if now.duration_since(c.last_seen) > Duration::from_secs(60) {
                    c.active = false;
                }
            }
            if !self.show_historic {
                self.connections.retain(|c| c.active);
            }
        }

        fn apply_sort(&mut self) {
            let (col, dir) = (self.sort_column, self.sort_direction);
            self.connections.sort_by(|a, b| {
                let cmp = match col {
                    SortColumn::Protocol => a.protocol.cmp(&b.protocol),
                    SortColumn::LocalAddr => a
                        .local_ip
                        .cmp(&b.local_ip)
                        .then(a.local_port.cmp(&b.local_port)),
                    SortColumn::RemoteAddr => a
                        .remote_ip
                        .cmp(&b.remote_ip)
                        .then(a.remote_port.cmp(&b.remote_port)),
                    SortColumn::State => a.state.cmp(&b.state),
                    SortColumn::Process => {
                        let an = a.process.as_ref().map(|p| p.name.as_str()).unwrap_or("");
                        let bn = b.process.as_ref().map(|p| p.name.as_str()).unwrap_or("");
                        an.cmp(bn)
                    }
                    SortColumn::BytesTotal => {
                        (a.bytes_sent + a.bytes_recv).cmp(&(b.bytes_sent + b.bytes_recv))
                    }
                    SortColumn::Anomalies => a.anomalies.len().cmp(&b.anomalies.len()),
                };
                if dir == SortDirection::Descending {
                    cmp.reverse()
                } else {
                    cmp
                }
            });
        }

        fn filtered_flows(&self) -> Vec<&Connection> {
            if self.filter_text.is_empty() {
                return self.connections.iter().collect();
            }
            let f = self.filter_text.to_lowercase();
            self.connections
                .iter()
                .filter(|c| {
                    format!(
                        "{} {} {} {} {} {}",
                        c.protocol,
                        c.local_ip,
                        c.remote_ip,
                        c.state,
                        c.process.as_ref().map(|p| p.name.as_str()).unwrap_or(""),
                        c.geo.as_ref().map(|g| g.country_name).unwrap_or("")
                    )
                    .to_lowercase()
                    .contains(&f)
                })
                .collect()
        }

        fn filtered_packets(&self) -> Vec<&PacketEntry> {
            if self.filter_text.is_empty() {
                return self.packets.iter().collect();
            }
            let f = self.filter_text.to_lowercase();
            self.packets
                .iter()
                .filter(|p| {
                    format!("{} {} {} {} {}", p.src, p.dst, p.protocol, p.info, p.length)
                        .to_lowercase()
                        .contains(&f)
                })
                .collect()
        }

        fn nav_up(&mut self) {
            match self.current_tab {
                Tab::Packets => {
                    if self.pkt_selected > 0 {
                        self.pkt_selected -= 1;
                        self.pkt_table_state.select(Some(self.pkt_selected));
                        self.popup_scroll = 0;
                    }
                }
                _ => {
                    if self.flow_selected > 0 {
                        self.flow_selected -= 1;
                        self.flow_table_state.select(Some(self.flow_selected));
                        self.popup_scroll = 0;
                    }
                }
            }
        }

        fn nav_down(&mut self) {
            match self.current_tab {
                Tab::Packets => {
                    let max = self.filtered_packets().len().saturating_sub(1);
                    if self.pkt_selected < max {
                        self.pkt_selected += 1;
                        self.pkt_table_state.select(Some(self.pkt_selected));
                        self.popup_scroll = 0;
                    }
                }
                _ => {
                    let max = self.filtered_flows().len().saturating_sub(1);
                    if self.flow_selected < max {
                        self.flow_selected += 1;
                        self.flow_table_state.select(Some(self.flow_selected));
                        self.popup_scroll = 0;
                    }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    /// Extract SNI from a DeepPacket's app_detail lines (e.g. "SNI      : example.com").
    fn sni_from_deep(dp: &pktana_core::DeepPacket) -> Option<String> {
        dp.app_detail
            .iter()
            .find(|l| l.contains("SNI"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn extract_tuple(s: &pktana_core::PacketSummary) -> Option<(String, u16, String, u16)> {
        let (sp, dp) = match &s.transport {
            Some(pktana_core::TransportHeader::Tcp {
                source_port,
                destination_port,
                ..
            }) => (*source_port, *destination_port),
            Some(pktana_core::TransportHeader::Udp {
                source_port,
                destination_port,
                ..
            }) => (*source_port, *destination_port),
            _ => (0, 0),
        };
        let ip = s.ipv4.as_ref()?;
        Some((ip.source.to_string(), sp, ip.destination.to_string(), dp))
    }

    fn build_info(s: &pktana_core::PacketSummary) -> String {
        match &s.transport {
            Some(pktana_core::TransportHeader::Tcp {
                source_port,
                destination_port,
                flags,
                sequence_number,
                acknowledgement_number,
                window_size,
                ..
            }) => {
                let fl = tcp_flags_str(*flags);
                let svc = svc_name(*destination_port)
                    .or_else(|| svc_name(*source_port))
                    .unwrap_or("");
                let sp = if svc.is_empty() {
                    String::new()
                } else {
                    format!(" [{svc}]")
                };
                format!("{source_port}→{destination_port}{sp} [{fl}] Seq={sequence_number} Ack={acknowledgement_number} Win={window_size}")
            }
            Some(pktana_core::TransportHeader::Udp {
                source_port,
                destination_port,
                length,
            }) => {
                let svc = svc_name(*destination_port)
                    .or_else(|| svc_name(*source_port))
                    .unwrap_or("");
                let sp = if svc.is_empty() {
                    String::new()
                } else {
                    format!(" [{svc}]")
                };
                format!("{source_port}→{destination_port}{sp} Len={length}")
            }
            Some(pktana_core::TransportHeader::Icmp { icmp_type, code }) => {
                format!("Type={icmp_type} Code={code} {}", icmp_name(*icmp_type))
            }
            _ => s.ethernet.ether_type.to_string(),
        }
    }

    fn infer_state(s: &pktana_core::PacketSummary) -> String {
        match &s.transport {
            Some(pktana_core::TransportHeader::Tcp { flags, .. }) => {
                if flags & 0x002 != 0 {
                    "SYN".into()
                } else if flags & 0x001 != 0 {
                    "FIN".into()
                } else if flags & 0x004 != 0 {
                    "RST".into()
                } else {
                    "ESTABLISHED".into()
                }
            }
            Some(pktana_core::TransportHeader::Udp { .. }) => "UDP".into(),
            Some(pktana_core::TransportHeader::Icmp { .. }) => "ICMP".into(),
            _ => "ACTIVE".into(),
        }
    }

    fn tcp_flags_str(f: u16) -> String {
        let mut v = Vec::new();
        if f & 0x001 != 0 {
            v.push("FIN");
        }
        if f & 0x002 != 0 {
            v.push("SYN");
        }
        if f & 0x004 != 0 {
            v.push("RST");
        }
        if f & 0x008 != 0 {
            v.push("PSH");
        }
        if f & 0x010 != 0 {
            v.push("ACK");
        }
        if f & 0x020 != 0 {
            v.push("URG");
        }
        if v.is_empty() {
            "NONE".into()
        } else {
            v.join(",")
        }
    }

    fn icmp_name(t: u8) -> &'static str {
        match t {
            0 => "Echo Reply",
            3 => "Dest Unreachable",
            5 => "Redirect",
            8 => "Echo Request",
            11 => "TTL Exceeded",
            _ => "",
        }
    }

    fn svc_name(port: u16) -> Option<&'static str> {
        Some(match port {
            20 | 21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            67 | 68 => "DHCP",
            69 => "TFTP",
            80 => "HTTP",
            88 => "Kerberos",
            110 => "POP3",
            111 => "RPC",
            119 => "NNTP",
            123 => "NTP",
            135 => "MSRPC",
            137..=139 => "NetBIOS",
            143 => "IMAP",
            161 | 162 => "SNMP",
            179 => "BGP",
            194 => "IRC",
            389 => "LDAP",
            443 => "HTTPS",
            445 => "SMB",
            465 => "SMTPS",
            514 => "Syslog",
            515 => "LPD",
            587 => "SMTP/S",
            636 => "LDAPS",
            993 => "IMAPS",
            995 => "POP3S",
            1080 => "SOCKS",
            1194 => "OpenVPN",
            1433 => "MSSQL",
            1521 => "Oracle",
            1723 => "PPTP",
            3306 => "MySQL",
            3389 => "RDP",
            4500 => "IPSec-NAT",
            5060 | 5061 => "SIP",
            5432 => "PostgreSQL",
            5900 => "VNC",
            6379 => "Redis",
            6443 => "k8s-API",
            6881..=6889 => "BitTorrent",
            8080 | 8008 => "HTTP-Alt",
            8443 => "HTTPS-Alt",
            9200 => "Elasticsearch",
            27017 => "MongoDB",
            _ => return None,
        })
    }

    fn proto_color(proto: &str) -> Color {
        match proto {
            "TCP" => Color::Rgb(100, 200, 255),
            "UDP" => Color::LightGreen,
            "ICMP" => Color::LightMagenta,
            "DNS" | "mDNS" => Color::Rgb(255, 165, 0),
            "HTTP" => Color::White,
            "HTTPS" | "TLS" => Color::Rgb(200, 200, 255),
            "ARP" => Color::Yellow,
            "DHCP" => Color::Green,
            "NTP" => Color::Gray,
            "SSH" => Color::Blue,
            "SMTP" | "IMAP" | "POP3" => Color::LightRed,
            "BGP" | "OSPF" | "RIP" => Color::Magenta,
            _ => Color::White,
        }
    }

    fn fmt_bytes(b: u64) -> String {
        if b >= 1_000_000_000 {
            format!("{:.1}G", b as f64 / 1e9)
        } else if b >= 1_000_000 {
            format!("{:.1}M", b as f64 / 1e6)
        } else if b >= 1_000 {
            format!("{:.1}K", b as f64 / 1e3)
        } else {
            format!("{b}B")
        }
    }

    fn fmt_dur(d: Duration) -> String {
        let s = d.as_secs();
        format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    }

    fn sparkline(samples: &VecDeque<u64>, width: usize) -> String {
        const BARS: &[char] = &[' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        if samples.is_empty() {
            return " ".repeat(width);
        }
        let max = *samples.iter().max().unwrap_or(&1);
        let max = max.max(1);
        let take: Vec<&u64> = samples.iter().rev().take(width).collect();
        let take: Vec<&u64> = take.into_iter().rev().collect();
        let pad = width.saturating_sub(take.len());
        let mut s = " ".repeat(pad);
        for &v in &take {
            let idx = ((*v as f64 / max as f64) * (BARS.len() - 1) as f64).round() as usize;
            s.push(BARS[idx.min(BARS.len() - 1)]);
        }
        s
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Rendering
    // ═══════════════════════════════════════════════════════════════════════════

    fn ui(f: &mut Frame, app: &mut App) {
        match app.current_tab {
            Tab::Overview => render_overview(f, app),
            Tab::Packets => render_packets(f, app),
            Tab::Flows => render_flows(f, app),
            Tab::Stats => render_stats(f, app),
            Tab::Dataplane => render_dataplane_tab(f, app),
            Tab::Help => render_help(f, app),
        }
    }

    fn render_tab_bar(f: &mut Frame, area: Rect, app: &App) {
        let spark = sparkline(&app.bw_history, 18);
        let bw_now = app.bw_history.back().copied().unwrap_or(0);
        let elapsed = fmt_dur(app.start_time.elapsed());

        // Header left section differs between live and pcap-file mode
        let header_left = if app.pcap_mode {
            let fname = std::path::Path::new(&app.pcap_file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&app.pcap_file);
            format!(" pktana | PCAP: {} | {} pkts | ", fname, app.total_packets)
        } else {
            format!(
                " pktana | {} | {} | {}/s {} | {}",
                app.interface,
                elapsed,
                fmt_bytes(bw_now * 4),
                spark,
                if app.flow_analyze_mode {
                    "[FLOW ANALYSIS ON]"
                } else {
                    ""
                }
            )
        };

        let tabs = [
            ("[1]Overview", Tab::Overview),
            ("[2]Packets", Tab::Packets),
            ("[3]Flows", Tab::Flows),
            ("[4]Stats", Tab::Stats),
            ("[5]Dataplane", Tab::Dataplane),
            ("[6]Help", Tab::Help),
        ];
        let mut spans: Vec<Span> = vec![Span::styled(
            header_left,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )];
        for (label, tab) in &tabs {
            let style = if *tab == app.current_tab {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            spans.push(Span::styled(format!(" {label} "), style));
        }
        let widget = Paragraph::new(Line::from(spans)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(widget, area);
    }

    fn render_status(f: &mut Frame, area: Rect, app: &App) {
        let (text, style) = if app.filter_mode {
            (
                format!(
                    " Search Filter: {}█  [Esc] clear  [Enter] apply",
                    app.filter_text
                ),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Rgb(255, 136, 0))
                    .add_modifier(Modifier::BOLD),
            )
        } else if app.show_detail {
            (
                " [Esc]Close Detail  [O]Overview  [L]Layers  [H]Hex  [←→]Sub-tabs  [PgUp/PgDn]Scroll  [↑↓]Navigate".into(),
                Style::default().fg(Color::Rgb(255, 136, 0)).add_modifier(Modifier::BOLD),
            )
        } else if app.flow_analyze_mode {
            // Show most recent flow event when flow analysis is active
            let event_text = app
                .flow_events
                .back()
                .map(|ev| format!(" ▸ {ev}"))
                .unwrap_or_else(|| " [FLOW ANALYSIS ON] Listening for handshakes/DORA/DNS…".into());
            (
                event_text,
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            let hint = match app.current_tab {
                Tab::Packets   => " [↑↓/jk]Navigate  [Enter]Detail  [/]Filter  [a]FlowAnalysis  [1-6]Tab  [q]Quit",
                Tab::Flows     => " [↑↓]Navigate  [Enter]Detail  [s]SortCol  [S]Dir  [t]Historic  [a]FlowAnalysis  [/]Filter  [q]Quit",
                Tab::Dataplane => " [1-6]Tabs  [r]Reload dataplane  [q]Quit",
                _              => " [1-6]Tabs  [↑↓]Navigate  [Enter]Detail  [/]Filter  [a]FlowAnalysis  [s]Sort  [q]Quit",
            };
            (
                hint.into(),
                Style::default()
                    .fg(Color::Rgb(255, 136, 0))
                    .add_modifier(Modifier::BOLD),
            )
        };
        f.render_widget(Paragraph::new(text).style(style), area);
    }

    // ── Overview tab ──

    fn render_overview(f: &mut Frame, app: &mut App) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(7),
                Constraint::Min(10),
                Constraint::Length(1),
            ])
            .split(f.area());

        render_tab_bar(f, chunks[0], app);
        render_stats_row(f, chunks[1], app);
        render_flow_table(f, chunks[2], app);
        render_status(f, chunks[3], app);

        if app.show_detail {
            let popup_area = centered_rect(80, 80, f.area());
            f.render_widget(Clear, popup_area);
            render_flow_detail_pane(f, popup_area, app);
        }
    }

    fn render_stats_row(f: &mut Frame, area: Rect, app: &App) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(34),
                Constraint::Percentage(33),
                Constraint::Percentage(33),
            ])
            .split(area);

        let es = app.start_time.elapsed().as_secs().max(1);
        let bps = app.total_bytes / es;
        let pps = app.total_packets / es;
        let active = app.connections.iter().filter(|c| c.active).count();
        let idle = app.connections.len().saturating_sub(active);
        let retx: u32 = app.connections.iter().map(|c| c.tcp_retransmits).sum();

        f.render_widget(Paragraph::new(format!(
            "Packets  : {}\nBytes    : {}\nRate     : {}/s  {} pkt/s\nActive   : {}  Idle: {}\nRetransmits: {}",
            app.total_packets, fmt_bytes(app.total_bytes), fmt_bytes(bps), pps, active, idle, retx
        )).block(Block::default()
            .title(Span::styled(" Traffic ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)))
            .borders(Borders::ALL).border_style(Style::default().fg(Color::Rgb(255, 136, 0)))), chunks[0]);

        let mut protos: Vec<_> = app.protocol_counts.iter().collect();
        protos.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
        let proto_text = protos
            .iter()
            .take(5)
            .map(|(p, c)| {
                let pct = if app.total_packets > 0 {
                    (**c as f64 / app.total_packets as f64 * 100.0) as u32
                } else {
                    0
                };
                format!("{:<8} {:>6}  {:>3}%", p, c, pct)
            })
            .collect::<Vec<_>>()
            .join("\n");
        f.render_widget(
            Paragraph::new(proto_text).block(
                Block::default()
                    .title(Span::styled(
                        " Protocols ",
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            chunks[1],
        );

        let mut top: Vec<_> = app.connections.iter().filter(|c| c.active).collect();
        top.sort_by_key(|c| std::cmp::Reverse(c.bytes_sent + c.bytes_recv));
        let flow_text = top
            .iter()
            .take(5)
            .map(|c| {
                let proc = c.process.as_ref().map(|p| p.name.as_str()).unwrap_or("-");
                let svc = svc_name(c.remote_port)
                    .or_else(|| svc_name(c.local_port))
                    .unwrap_or(&c.remote_ip);
                format!(
                    "{:<8} {:<10} {}",
                    fmt_bytes(c.bytes_sent + c.bytes_recv),
                    proc,
                    svc
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        f.render_widget(
            Paragraph::new(flow_text).block(
                Block::default()
                    .title(Span::styled(
                        " Top Flows ",
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            chunks[2],
        );
    }

    // ── Packets tab ──

    fn render_packets(f: &mut Frame, app: &mut App) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(1),
            ])
            .split(f.area());

        render_tab_bar(f, chunks[0], app);
        render_pkt_table(f, chunks[1], app);
        render_status(f, chunks[2], app);

        if app.show_detail {
            let popup_area = centered_rect(80, 80, f.area());
            f.render_widget(Clear, popup_area);
            render_pkt_detail_pane(f, popup_area, app);
        }
    }

    fn render_pkt_table(f: &mut Frame, area: Rect, app: &mut App) {
        let filtered = app.filtered_packets();
        let header = Row::new(vec![
            "No.",
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Len",
            "Info",
        ])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
        let rows: Vec<Row> = filtered
            .iter()
            .map(|p| {
                Row::new(vec![
                    p.no.to_string(),
                    format!("{:.4}s", p.time_offset),
                    p.src.clone(),
                    p.dst.clone(),
                    p.protocol.clone(),
                    p.length.to_string(),
                    p.info.clone(),
                ])
                .style(Style::default().fg(proto_color(&p.protocol)))
            })
            .collect();

        let title = format!(
            " Packets — {} captured{} ",
            filtered.len(),
            if app.filter_text.is_empty() {
                String::new()
            } else {
                format!(" [filter:{}]", app.filter_text)
            }
        );

        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(9),
                Constraint::Length(22),
                Constraint::Length(22),
                Constraint::Length(9),
                Constraint::Length(5),
                Constraint::Min(30),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
        f.render_stateful_widget(table, area, &mut app.pkt_table_state);
    }

    // ── Flows tab ──

    fn render_flows(f: &mut Frame, app: &mut App) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(1),
            ])
            .split(f.area());

        render_tab_bar(f, chunks[0], app);
        render_flow_table(f, chunks[1], app);
        render_status(f, chunks[2], app);

        if app.show_detail {
            let popup_area = centered_rect(80, 80, f.area());
            f.render_widget(Clear, popup_area);
            render_flow_detail_pane(f, popup_area, app);
        }
    }

    fn render_flow_table(f: &mut Frame, area: Rect, app: &mut App) {
        let dir_sym = if app.sort_direction == SortDirection::Ascending {
            "↑"
        } else {
            "↓"
        };
        let header = Row::new(vec![
            "Proto",
            "Local Address",
            "Remote Address",
            "State",
            "App / SNI",
            "Process(PID)",
            "Geo",
            "⚠",
            "Risk",
            "Pkts↕",
            "Bytes↕",
            "Age",
        ])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let filtered = app.filtered_flows();
        let rows: Vec<Row> = filtered
            .iter()
            .map(|c| {
                let local = format!("{}:{}", c.local_ip, c.local_port);
                let remote = format!("{}:{}", c.remote_ip, c.remote_port);
                // Show SNI if TLS, otherwise app_proto, otherwise service name
                let app_sni = c
                    .tls_sni
                    .as_deref()
                    .or(c.app_proto.as_deref())
                    .or_else(|| svc_name(c.remote_port))
                    .or_else(|| svc_name(c.local_port))
                    .unwrap_or("-")
                    .to_string();
                let proc = c
                    .process
                    .as_ref()
                    .map(|p| format!("{}({})", p.name, p.pid))
                    .unwrap_or_else(|| "-".into());
                let geo = c
                    .geo
                    .as_ref()
                    .map(|g| g.country_code.to_string())
                    .unwrap_or_else(|| "--".into());
                let badge = if c.anomalies.is_empty() {
                    String::new()
                } else {
                    format!("⚠{}", c.anomalies.len())
                };
                let risk = if c.risk_score == 0 {
                    "-".into()
                } else {
                    format!("{}", c.risk_score)
                };
                let pkts = format!("{}↑{}↓", c.packets_sent, c.packets_recv);
                let bytes = fmt_bytes(c.bytes_sent + c.bytes_recv);
                let age = fmt_dur(c.first_seen.elapsed());

                let style = if !c.active {
                    Style::default().fg(Color::DarkGray)
                } else if c.risk_score >= 70 || !c.anomalies.is_empty() {
                    Style::default().fg(Color::LightRed)
                } else if c.risk_score >= 40 || c.bytes_sent + c.bytes_recv > 10_000_000 {
                    Style::default().fg(Color::LightYellow)
                } else {
                    Style::default().fg(proto_color(&c.protocol))
                };

                Row::new(vec![
                    c.protocol.clone(),
                    local,
                    remote,
                    c.state.clone(),
                    app_sni,
                    proc,
                    geo,
                    badge,
                    risk,
                    pkts,
                    bytes,
                    age,
                ])
                .style(style)
            })
            .collect();

        let title = format!(
            " Flows ({}) sort:{:?}{} {} ",
            filtered.len(),
            app.sort_column,
            dir_sym,
            if app.show_historic { "[+historic]" } else { "" }
        );

        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(22),
                Constraint::Length(22),
                Constraint::Length(11),
                Constraint::Length(16),
                Constraint::Length(16),
                Constraint::Length(4),
                Constraint::Length(4),
                Constraint::Length(5),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(9),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
        f.render_stateful_widget(table, area, &mut app.flow_table_state);
    }

    // ── Stats tab ──

    fn render_stats(f: &mut Frame, app: &App) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(f.area());
        render_tab_bar(f, chunks[0], app);

        let mut protos: Vec<_> = app.protocol_bytes.iter().collect();
        protos.sort_by_key(|(_, b)| std::cmp::Reverse(**b));
        let tb = app.total_bytes.max(1);
        let tp = app.total_packets.max(1);
        let lines: Vec<String> = protos
            .iter()
            .map(|(proto, &bytes)| {
                let pkts = app.protocol_counts.get(*proto).copied().unwrap_or(0);
                let bpct = bytes as f64 / tb as f64 * 100.0;
                let ppct = pkts as f64 / tp as f64 * 100.0;
                let bar = "█".repeat((bpct / 5.0).round() as usize);
                format!(
                    "{:<10} {:>6} pkts ({:>5.1}%)  {:>8} ({:>5.1}%)  {}",
                    proto,
                    pkts,
                    ppct,
                    fmt_bytes(bytes),
                    bpct,
                    bar
                )
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .title(Span::styled(
                            " Protocol Hierarchy ",
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                )
                .wrap(Wrap { trim: false }),
            chunks[1],
        );

        let mut eps: Vec<_> = app.endpoint_bytes.iter().collect();
        eps.sort_by_key(|(_, b)| std::cmp::Reverse(**b));
        let ep_lines: Vec<String> = eps
            .iter()
            .take(30)
            .map(|(ip, &bytes)| {
                let pkts = app.endpoint_pkts.get(*ip).copied().unwrap_or(0);
                format!("{:<22}  {:>9}  {:>8} pkts", ip, fmt_bytes(bytes), pkts)
            })
            .collect();
        f.render_widget(
            Paragraph::new(ep_lines.join("\n"))
                .block(
                    Block::default()
                        .title(Span::styled(
                            " Top Endpoints (bytes) ",
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                )
                .wrap(Wrap { trim: false }),
            chunks[2],
        );
    }

    // ── Dataplane tab ──

    fn render_dataplane_tab(f: &mut Frame, app: &App) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // tab bar
                Constraint::Min(10),   // dataplane info
                Constraint::Length(4), // BPF FS + namespace summary
                Constraint::Length(2), // status bar
            ])
            .split(f.area());

        render_tab_bar(f, chunks[0], app);

        // ── Main dataplane panel ──────────────────────────────────────────────
        let mut dp_text = if let Some(dp) = &app.nic_dataplane {
            let mut lines = vec![
                format!("  Interface      : {}", app.interface),
                format!("  Bypass Mode    : {}", dp.bypass_mode),
                String::new(),
                // XDP
                if dp.xdp_prog_ids.is_empty() {
                    "  XDP            : not attached".into()
                } else {
                    let ids: Vec<String> = dp.xdp_prog_ids.iter().map(|i| i.to_string()).collect();
                    format!(
                        "  XDP            : ATTACHED  prog_ids=[{}]  mode={}",
                        ids.join(","),
                        dp.xdp_mode.as_deref().unwrap_or("unknown")
                    )
                },
                // AF_XDP
                if dp.afxdp_sockets == 0 {
                    "  AF_XDP sockets : none".into()
                } else {
                    format!(
                        "  AF_XDP sockets : {}  (zero-copy rings active)",
                        dp.afxdp_sockets
                    )
                },
                // DPDK
                if dp.dpdk_bound {
                    format!(
                        "  DPDK/PMD       : BOUND  driver={}  ← kernel BYPASSED",
                        dp.userspace_driver.as_deref().unwrap_or("?")
                    )
                } else {
                    "  DPDK/PMD       : not bound".into()
                },
                String::new(),
                // TC BPF
                if !dp.tc_clsact {
                    "  TC BPF         : no clsact qdisc".into()
                } else if dp.tc_bpf_directions.is_empty() {
                    "  TC BPF         : clsact present, no BPF filters".into()
                } else {
                    let ids: Vec<String> =
                        dp.tc_bpf_prog_ids.iter().map(|i| i.to_string()).collect();
                    format!(
                        "  TC BPF         : {} | prog_ids=[{}]",
                        dp.tc_bpf_directions.join("+"),
                        if ids.is_empty() {
                            "—".into()
                        } else {
                            ids.join(",")
                        }
                    )
                },
                String::new(),
                // SR-IOV
                if dp.is_virtual_function {
                    format!(
                        "  SR-IOV         : VF  physfn={}",
                        dp.physfn_pci.as_deref().unwrap_or("?")
                    )
                } else if let Some(total) = dp.sriov_vfs_total {
                    format!(
                        "  SR-IOV         : PF  vfs={}/{}",
                        dp.sriov_vfs_enabled.unwrap_or(0),
                        total
                    )
                } else {
                    "  SR-IOV         : —".into()
                },
                // Queues
                if dp.rx_queues > 0 || dp.tx_queues > 0 {
                    format!(
                        "  Queues         : rx={}  tx={}  combined={}",
                        dp.rx_queues, dp.tx_queues, dp.combined_queues
                    )
                } else {
                    "  Queues         : —".into()
                },
                // PCI
                format!(
                    "  PCI            : {}  vendor={}  device={}  numa={}",
                    dp.pci_address.as_deref().unwrap_or("—"),
                    dp.pci_vendor_id.as_deref().unwrap_or("—"),
                    dp.pci_device_id.as_deref().unwrap_or("—"),
                    dp.numa_node
                        .map(|n| n.to_string())
                        .as_deref()
                        .unwrap_or("—"),
                ),
                String::new(),
                // HW offloads (first 6 enabled features)
                if dp.hw_features_on.is_empty() {
                    "  HW Offloads    : (none / not readable)".into()
                } else {
                    let shown = dp
                        .hw_features_on
                        .iter()
                        .take(6)
                        .cloned()
                        .collect::<Vec<_>>();
                    let suffix = if dp.hw_features_on.len() > 6 {
                        format!(" +{} more", dp.hw_features_on.len() - 6)
                    } else {
                        String::new()
                    };
                    format!("  HW Offloads    : {}{}", shown.join("  "), suffix)
                },
            ];
            lines.push(String::new());
            lines.push("  Press [r] to reload dataplane info.".into());
            lines.join("\n")
        } else {
            format!(
                "  Could not read dataplane info for '{}'\n  (try running as root)",
                app.interface
            )
        };

        if let Ok(diag) = diagnose_path(&app.interface) {
            if !diag.issues.is_empty() {
                dp_text.push_str("\n\n  Diagnostics");
                for issue in &diag.issues {
                    let sev = match issue.severity {
                        IssueSeverity::Critical => "CRIT",
                        IssueSeverity::Warning => "WARN",
                        IssueSeverity::Info => "INFO",
                    };
                    dp_text.push_str(&format!("\n    [{sev}] {} — {}", issue.code, issue.message));
                }
            }
        }

        f.render_widget(
            Paragraph::new(dp_text)
                .block(
                    Block::default()
                        .title(Span::styled(
                            " NIC Dataplane / BPF Profile ",
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                )
                .wrap(Wrap { trim: false }),
            chunks[1],
        );

        // ── BPF FS + namespace summary ────────────────────────────────────────
        let bpf_objects = scan_bpf_fs();
        let pinned_count = bpf_objects.iter().filter(|o| !o.is_dir).count();
        let namespaces = list_network_namespaces();
        let ns_count = namespaces.len();
        let non_host = namespaces.iter().filter(|ns| !ns.is_host).count();

        let summary = format!(
            "  /sys/fs/bpf/  pinned objects: {}    Namespaces: {} total ({} non-host)",
            pinned_count, ns_count, non_host
        );

        f.render_widget(
            Paragraph::new(summary).block(
                Block::default()
                    .title(Span::styled(
                        " BPF FS & Namespaces ",
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            chunks[2],
        );

        render_status(f, chunks[3], app);
    }

    // ── Help tab ──

    fn render_help(f: &mut Frame, _app: &App) {
        let text = [
            "╔══════════════════════════════════════════════════════════╗",
            "║          pktana TUI  —  Keyboard Reference              ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            "  TABS",
            "  1 / 2 / 3 / 4 / 5 / 6    Overview / Packets / Flows / Stats / Dataplane / Help",
            "  Tab / Shift+Tab       Cycle forward / backward",
            "",
            "  NAVIGATION",
            "  ↑ / k  ↓ / j         Move up / down",
            "  Mouse wheel           Scroll list",
            "",
            "  DETAIL POPUP  (press Enter to open)",
            "  Enter                 Open / close detail popup",
            "  O                     Sub-tab: Overview  (addresses, process, geo, timing)",
            "  L                     Sub-tab: Layers    (L2→L3→L4→L7 DPI decode)",
            "  H                     Sub-tab: Hex       (raw hex + ASCII dump)",
            "  ← / →                 Cycle sub-tabs",
            "  ↑/↓  PgUp/PgDn       Scroll popup content",
            "  Esc                   Close popup",
            "",
            "  FLOWS",
            "  s                     Cycle sort column (Proto/Local/Remote/State/Process/Bytes/Anomalies)",
            "  S                     Toggle sort direction ↑ / ↓",
            "  t                     Toggle display of historic (idle) connections",
            "",
            "  FILTER  (works on Packets and Flows tabs)",
            "  /                     Enter filter mode",
            "  Enter                 Apply filter",
            "  Esc                   Clear filter",
            "",
            "  GENERAL",
            "  q / Q / Esc           Quit",
            "",
            "  COLOUR RULES (Wireshark-style)",
            "  Cyan=TCP  LightGreen=UDP  LightMagenta=ICMP  Yellow=ARP",
            "  LightYellow=DNS  LightBlue=TLS/HTTPS  LightRed=Anomalous flow",
        ].join("\n");
        f.render_widget(
            Paragraph::new(text).block(
                Block::default()
                    .title(Span::styled(
                        " Help ",
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            f.area(),
        );
    }

    // ── Detail popup ──

    fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
        let popup_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ])
            .split(r);

        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ])
            .split(popup_layout[1])[1]
    }

    fn render_flow_detail_pane(f: &mut Frame, area: Rect, app: &App) {
        let flows = app.filtered_flows();
        let Some(conn) = flows.get(app.flow_selected) else {
            return;
        };
        let title = format!(
            " Flow #{} │ {}:{} → {}:{} │ [O]overview [L]ayers [H]ex ",
            conn.id, conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port
        );
        let outer = Block::default()
            .title(Span::styled(
                title,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Reset));
        let inner = outer.inner(area);
        f.render_widget(outer, area);
        let lines = match app.detail_sub {
            DetailSub::Overview => flow_overview_lines(conn),
            DetailSub::Layers => flow_layer_lines(conn),
            DetailSub::Hex => flow_hex_lines(conn),
        };
        let scroll = app.popup_scroll as usize;
        let body = lines
            .iter()
            .skip(scroll)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        f.render_widget(
            Paragraph::new(body)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: false }),
            inner,
        );
    }

    fn flow_overview_lines(c: &Connection) -> Vec<String> {
        let now = Instant::now();
        let dur = c.last_seen.duration_since(c.first_seen);
        let svc = svc_name(c.remote_port)
            .or_else(|| svc_name(c.local_port))
            .unwrap_or("-");
        let proc = c
            .process
            .as_ref()
            .map(|p| format!("{} (PID {})", p.name, p.pid))
            .unwrap_or_else(|| "Unknown".into());
        let cmd = c
            .process
            .as_ref()
            .filter(|p| !p.cmdline.is_empty())
            .map(|p| {
                let s = p.cmdline.replace('\0', " ");
                if s.len() > 72 {
                    format!("{}…", &s[..72])
                } else {
                    s
                }
            })
            .unwrap_or_else(|| "-".into());
        let geo = c
            .geo
            .as_ref()
            .map(|g| {
                format!(
                    "{} ({}) continent:{}",
                    g.country_name, g.country_code, g.continent
                )
            })
            .unwrap_or_else(|| "Private / Unknown".into());

        let mut lines = vec![
            "  ── Addressing ──────────────────────────────────────────────".into(),
            format!("  Protocol    : {}  (service: {svc})", c.protocol),
            format!("  State       : {}", c.state),
            format!("  Local       : {}:{}", c.local_ip, c.local_port),
            format!("  Remote      : {}:{}", c.remote_ip, c.remote_port),
            String::new(),
            "  ── Process / Host ───────────────────────────────────────────".into(),
            format!("  Process     : {proc}"),
            format!("  Cmdline     : {cmd}"),
            String::new(),
            "  ── Geography ────────────────────────────────────────────────".into(),
            format!("  Location    : {geo}"),
            String::new(),
            "  ── Traffic ──────────────────────────────────────────────────".into(),
            format!(
                "  Sent        : {:<10}  ({} pkts)",
                fmt_bytes(c.bytes_sent),
                c.packets_sent
            ),
            format!(
                "  Received    : {:<10}  ({} pkts)",
                fmt_bytes(c.bytes_recv),
                c.packets_recv
            ),
            format!(
                "  Total       : {:<10}  ({} pkts)",
                fmt_bytes(c.bytes_sent + c.bytes_recv),
                c.packets_sent + c.packets_recv
            ),
            format!("  TCP Retransmits: {}", c.tcp_retransmits),
            String::new(),
            "  ── Timing ───────────────────────────────────────────────────".into(),
            format!("  First seen  : {} ago", fmt_dur(c.first_seen.elapsed())),
            format!(
                "  Last seen   : {} ago (Idle since)",
                fmt_dur(now.duration_since(c.last_seen))
            ),
            format!("  Duration    : {}", fmt_dur(dur)),
            format!(
                "  Status      : {}",
                if c.active { "Active ●" } else { "Idle ○" }
            ),
        ];
        // ── Live DPI ─────────────────────────────────────────────────────────
        if c.app_proto.is_some()
            || c.tls_sni.is_some()
            || c.risk_score > 0
            || c.app_category.is_some()
        {
            lines.push(String::new());
            lines.push("  ── Live DPI ─────────────────────────────────────────────────".into());
            if let Some(ref sni) = c.tls_sni {
                lines.push(format!("  SNI / Host   : {sni}"));
            }
            if let Some(ref ap) = c.app_proto {
                lines.push(format!("  App Protocol : {ap}"));
            }
            if let Some(ref cat) = c.app_category {
                lines.push(format!("  Category     : {cat}"));
            }
            if c.risk_score > 0 {
                let label = if c.risk_score >= 70 {
                    "HIGH"
                } else if c.risk_score >= 40 {
                    "MEDIUM"
                } else {
                    "LOW"
                };
                let bar_len = (c.risk_score as usize * 20) / 100;
                let bar = "█".repeat(bar_len) + &"░".repeat(20 - bar_len);
                lines.push(format!(
                    "  Risk Score   : {} [{}] {}",
                    c.risk_score, bar, label
                ));
            }
        }
        if !c.anomalies.is_empty() {
            lines.push(String::new());
            lines.push("  ── Expert Info / Anomalies ──────────────────────────────────".into());
            for a in &c.anomalies {
                lines.push(format!("  ⚠  {a}"));
            }
        }
        lines.push(String::new());
        lines.push("  [Esc]Close Detail  [L]Layers  [H]Hex  [PgUp/PgDn]Scroll Detail".into());
        lines
    }

    fn flow_layer_lines(c: &Connection) -> Vec<String> {
        let Some(raw) = c.recent_raw.back() else {
            return vec!["  No captured packets for this flow yet.".into()];
        };
        dpi_lines(raw)
    }

    fn flow_hex_lines(c: &Connection) -> Vec<String> {
        let Some(raw) = c.recent_raw.back() else {
            return vec!["  No captured packets for this flow yet.".into()];
        };
        let mut lines = vec![format!("  Raw frame ({} bytes):", raw.len()), String::new()];
        for l in hex_dump(raw, raw.len()) {
            lines.push(format!("  {l}"));
        }
        lines.push(String::new());
        lines.push("  [Esc]Close Detail  [O]Overview  [L]Layers  [PgUp/PgDn]Scroll Detail".into());
        lines
    }

    fn render_pkt_detail_pane(f: &mut Frame, area: Rect, app: &App) {
        let pkts = app.filtered_packets();
        let Some(pkt) = pkts.get(app.pkt_selected) else {
            return;
        };
        let title = format!(
            " Pkt#{} │ {:.4}s │ {} → {} │ {} bytes │ [O]verview [L]ayers [H]ex ",
            pkt.no, pkt.time_offset, pkt.src, pkt.dst, pkt.length
        );
        let outer = Block::default()
            .title(Span::styled(
                title,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Reset));
        let inner = outer.inner(area);
        f.render_widget(outer, area);
        let lines = match app.detail_sub {
            DetailSub::Overview => vec![
                format!("  No.         : {}", pkt.no),
                format!("  Time        : {:.6}s", pkt.time_offset),
                format!("  Source      : {}", pkt.src),
                format!("  Destination : {}", pkt.dst),
                format!("  Protocol    : {}", pkt.protocol),
                format!("  Length      : {} bytes", pkt.length),
                String::new(),
                format!("  Info        : {}", pkt.info),
                String::new(),
                "  [L]Layers decode  [H]Hex dump  [Esc]Close Detail".into(),
            ],
            DetailSub::Layers => dpi_lines(&pkt.raw),
            DetailSub::Hex => {
                let mut v = vec![
                    format!("  Packet#{} ({} bytes):", pkt.no, pkt.length),
                    String::new(),
                ];
                for l in hex_dump(&pkt.raw, pkt.raw.len()) {
                    v.push(format!("  {l}"));
                }
                v.push(String::new());
                v.push("  [Esc]Close Detail  [O]Overview  [L]Layers".into());
                v
            }
        };
        let scroll = app.popup_scroll as usize;
        let body = lines
            .iter()
            .skip(scroll)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        f.render_widget(
            Paragraph::new(body)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: false }),
            inner,
        );
    }

    /// Build full layer-by-layer DPI lines from raw bytes.
    fn dpi_lines(raw: &[u8]) -> Vec<String> {
        let dp = inspect(raw);
        let mut v = vec![
            format!("  Frame length: {} bytes", dp.frame_len),
            String::new(),
            "  ── Layer 2: Ethernet ────────────────────────────────────────".into(),
            format!(
                "  Src MAC     : {}  ({})",
                dp.eth_src,
                dp.eth_vendor_src.unwrap_or("?")
            ),
            format!(
                "  Dst MAC     : {}  ({})",
                dp.eth_dst,
                dp.eth_vendor_dst.unwrap_or("?")
            ),
            format!(
                "  EtherType   : 0x{:04x}  ({})",
                dp.ether_type, dp.ether_type_name
            ),
        ];
        for vlan in &dp.vlan_tags {
            v.push(format!(
                "  VLAN         : ID={}  PCP={}  DEI={}",
                vlan.id, vlan.pcp, vlan.dei
            ));
        }
        if let Some(arp) = &dp.arp {
            v.push(String::new());
            v.push("  ── ARP ──────────────────────────────────────────────────────".into());
            v.push(format!("  Operation   : {}", arp.operation));
            v.push(format!(
                "  Sender      : {}  {}",
                arp.sender_mac, arp.sender_ip
            ));
            v.push(format!(
                "  Target      : {}  {}",
                arp.target_mac, arp.target_ip
            ));
        }
        if let Some(ver) = dp.ip_version {
            v.push(String::new());
            v.push(format!(
                "  ── Layer 3: IPv{ver} ──────────────────────────────────────────"
            ));
            if let (Some(s), Some(d)) = (dp.ip_src, dp.ip_dst) {
                v.push(format!("  Src         : {}", s));
                v.push(format!("  Dst         : {}", d));
            }
            if let Some(ttl) = dp.ip_ttl {
                v.push(format!("  TTL         : {ttl}"));
            }
            if let Some(pn) = dp.ip_proto_name {
                v.push(format!(
                    "  Protocol    : {} ({})",
                    pn,
                    dp.ip_proto.unwrap_or(0)
                ));
            }
            if let Some(id) = dp.ip_id {
                v.push(format!("  ID          : 0x{id:04x}"));
            }
            if let (Some(ds), Some(ec)) = (dp.ip_dscp, dp.ip_ecn) {
                v.push(format!("  DSCP={ds}  ECN={ec}"));
            }
            v.push(format!(
                "  Flags       : DF={}  MF={}",
                dp.ip_flag_df, dp.ip_flag_mf
            ));
            if let Some(fo) = dp.ip_fragment {
                v.push(format!("  Frag offset : {fo}"));
            }
        }
        if let Some(sp) = dp.tcp_src_port {
            v.push(String::new());
            v.push("  ── Layer 4: TCP ─────────────────────────────────────────────".into());
            v.push(format!(
                "  Src Port    : {}  ({})",
                sp,
                svc_name(sp).unwrap_or("")
            ));
            if let Some(dp2) = dp.tcp_dst_port {
                v.push(format!(
                    "  Dst Port    : {}  ({})",
                    dp2,
                    svc_name(dp2).unwrap_or("")
                ));
            }
            if let Some(sq) = dp.tcp_seq {
                v.push(format!("  Seq         : {sq}"));
            }
            if let Some(ak) = dp.tcp_ack {
                v.push(format!("  Ack         : {ak}"));
            }
            if let Some(fl) = &dp.tcp_flags_str {
                v.push(format!("  Flags       : {fl}"));
            }
            if let Some(wi) = dp.tcp_window {
                v.push(format!("  Window      : {wi} bytes"));
            }
            if let Some(ms) = dp.tcp_mss {
                v.push(format!("  MSS         : {ms}"));
            }
            if let Some(ws) = dp.tcp_window_scale {
                v.push(format!("  Win Scale   : ×{ws}"));
            }
            if dp.tcp_sack_permitted {
                v.push("  SACK        : permitted".into());
            }
            for (l, r) in &dp.tcp_sack_blocks {
                v.push(format!("  SACK block  : {l} – {r}"));
            }
            if let Some((tsval, tsecr)) = dp.tcp_timestamp {
                v.push(format!("  Timestamp   : val={tsval} ecr={tsecr}"));
            }
            v.push(format!("  Payload len : {} bytes", dp.tcp_payload_len));
        }
        if let Some(sp) = dp.udp_src_port {
            v.push(String::new());
            v.push("  ── Layer 4: UDP ─────────────────────────────────────────────".into());
            v.push(format!("  Src Port    : {sp}"));
            if let Some(dp2) = dp.udp_dst_port {
                v.push(format!(
                    "  Dst Port    : {}  ({})",
                    dp2,
                    svc_name(dp2).unwrap_or("")
                ));
            }
            if let Some(l) = dp.udp_len {
                v.push(format!("  Length      : {l}"));
            }
            if let Some(cs) = dp.udp_checksum {
                v.push(format!("  Checksum    : 0x{cs:04x}"));
            }
            v.push(format!("  Payload len : {} bytes", dp.udp_payload_len));
        }
        if let Some(it) = dp.icmp_type {
            v.push(String::new());
            v.push("  ── Layer 4: ICMP ────────────────────────────────────────────".into());
            let ts = dp.icmp_type_str.as_deref().unwrap_or("");
            v.push(format!("  Type        : {it}  {ts}"));
            if let Some(co) = dp.icmp_code {
                v.push(format!("  Code        : {co}"));
            }
            if let Some(id) = dp.icmp_id {
                v.push(format!("  ID          : {id}"));
            }
            if let Some(sq) = dp.icmp_seq {
                v.push(format!("  Seq         : {sq}"));
            }
        }
        if let Some(ap) = &dp.app_proto {
            v.push(String::new());
            v.push("  ── Layer 7: Application ─────────────────────────────────────".into());
            v.push(format!("  Protocol    : {ap}"));
            for d in &dp.app_detail {
                v.push(format!("  {d}"));
            }
        }
        // IPv6
        if let (Some(ref s6), Some(ref d6)) = (&dp.ipv6_src, &dp.ipv6_dst) {
            v.push(String::new());
            v.push("  ── Layer 3: IPv6 ────────────────────────────────────────────".into());
            v.push(format!("  Src         : {s6}"));
            v.push(format!("  Dst         : {d6}"));
            if let Some(hl) = dp.ipv6_hop_limit {
                v.push(format!("  Hop Limit   : {hl}"));
            }
            if let Some(nh) = dp.ipv6_next_header {
                v.push(format!("  Next Header : {nh}"));
            }
        }
        // QUIC / HTTP3
        if dp.quic_detected {
            v.push(String::new());
            v.push("  ── QUIC / HTTP3 ─────────────────────────────────────────────".into());
            if let Some(ref pt) = dp.quic_packet_type {
                v.push(format!("  Packet Type : {pt}"));
            }
            if let Some(ver) = dp.quic_version {
                v.push(format!("  Version     : 0x{ver:08x}"));
            }
        }
        // SSH banner
        if let Some(ref banner) = dp.ssh_banner {
            v.push(String::new());
            v.push("  ── SSH ──────────────────────────────────────────────────────".into());
            v.push(format!("  Banner      : {banner}"));
        }
        // SIP
        if let Some(ref m) = dp.sip_method {
            v.push(String::new());
            v.push("  ── SIP / VoIP ───────────────────────────────────────────────".into());
            v.push(format!("  Method      : {m}"));
            if let Some(ref u) = dp.sip_uri {
                v.push(format!("  URI         : {u}"));
            }
            if let Some(ref c) = dp.sip_call_id {
                v.push(format!("  Call-ID     : {c}"));
            }
        }
        // NTP
        if let Some(ver) = dp.ntp_version {
            v.push(String::new());
            v.push("  ── NTP ──────────────────────────────────────────────────────".into());
            v.push(format!("  Version     : NTPv{ver}"));
            if let Some(m) = dp.ntp_mode {
                v.push(format!("  Mode        : {m}"));
            }
            if let Some(s) = dp.ntp_stratum {
                v.push(format!("  Stratum     : {s}"));
            }
            if dp.ntp_amplification_risk {
                v.push("  ⚠ Amplification risk (mode 7 / monlist)".into());
            }
        }
        // BGP
        if let Some(ref mt) = dp.bgp_msg_type {
            v.push(String::new());
            v.push("  ── BGP ──────────────────────────────────────────────────────".into());
            v.push(format!("  Msg Type    : {mt}"));
            if let Some(asn) = dp.bgp_asn {
                v.push(format!("  AS Number   : {asn}"));
            }
        }
        // Tunnel inner frame
        if let Some(ref tn) = dp.tunnel_type {
            v.push(String::new());
            v.push("  ── Tunnel Inner Frame ───────────────────────────────────────".into());
            v.push(format!("  Encap       : {tn}"));
            if let (Some(s), Some(d)) = (dp.inner_ip_src, dp.inner_ip_dst) {
                v.push(format!("  Inner Src   : {s}"));
                v.push(format!("  Inner Dst   : {d}"));
            }
            if let Some(p) = dp.inner_proto {
                v.push(format!("  Inner Proto : {p}"));
            }
            if let (Some(sp), Some(dp2)) = (dp.inner_src_port, dp.inner_dst_port) {
                v.push(format!("  Inner Ports : {sp} → {dp2}"));
            }
            if let Some(ref ap) = dp.inner_app_proto {
                v.push(format!("  Inner App   : {ap}"));
            }
        }
        // JA3 + ALPN
        if let Some(ref ja3) = dp.tls_ja3_raw {
            v.push(String::new());
            v.push("  ── TLS Fingerprint ──────────────────────────────────────────".into());
            v.push(format!("  JA3-raw     : {ja3}"));
            v.push("  (MD5 of above = JA3 fingerprint)".into());
        }
        if !dp.tls_alpn.is_empty() {
            v.push(format!("  ALPN        : {}", dp.tls_alpn.join(", ")));
        }
        // DNS entropy
        if let Some(e) = dp.dns_label_entropy {
            v.push(String::new());
            v.push("  ── DNS Analysis ─────────────────────────────────────────────".into());
            if let Some(ref qn) = dp.dns_query_name {
                v.push(format!("  Query       : {qn}"));
            }
            let risk = if e > 3.8 {
                "HIGH — possible DGA/tunneling"
            } else if e > 3.3 {
                "elevated"
            } else {
                "normal"
            };
            v.push(format!("  Label Entropy: {e:.2}  ({risk})"));
        }
        // WebSocket
        if dp.ws_upgrade {
            v.push(String::new());
            v.push("  ── WebSocket ────────────────────────────────────────────────".into());
            v.push("  Upgrade     : WebSocket upgrade detected".into());
        }
        if !dp.anomalies.is_empty() {
            v.push(String::new());
            v.push("  ── Expert Info / Anomalies ──────────────────────────────────".into());
            for a in &dp.anomalies {
                v.push(format!("  ⚠  {a}"));
            }
        }
        // Risk score
        if dp.risk_score > 0 {
            v.push(String::new());
            v.push("  ── Risk Assessment ──────────────────────────────────────────".into());
            let bar = "█".repeat((dp.risk_score / 10) as usize);
            let color_word = if dp.risk_score >= 70 {
                "HIGH"
            } else if dp.risk_score >= 40 {
                "MEDIUM"
            } else {
                "LOW"
            };
            v.push(format!(
                "  Risk Score  : {}/100  [{color_word}]  {bar}",
                dp.risk_score
            ));
            for r in &dp.risk_reasons {
                v.push(format!("    • {r}"));
            }
        }
        // App category
        if let Some(ref cat) = dp.app_category {
            v.push(format!("  Category    : {cat}"));
        }
        v.push(String::new());
        v.push("  [Esc]Close Detail  [O]Overview  [H]Hex  [PgUp/PgDn]Scroll Detail".into());
        v
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Main loop
    // ═══════════════════════════════════════════════════════════════════════════

    pub fn run_tui(interface: &str) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        let mut app = App::new(interface);

        let (tx, rx) = mpsc::channel::<CapturePacket<'static>>();
        let iface = interface.to_string();
        std::thread::spawn(move || {
            let cfg = CaptureConfig {
                interface: iface,
                promiscuous: true,
                snapshot_len: 65535,
                filter: None,
                max_packets: usize::MAX,
                pcap_export: None,
            };
            let _ = LinuxCaptureEngine::capture_streaming(&cfg, |pkt| {
                let _ = tx.send(pkt.into_owned());
                true
            });
        });

        let tick = Duration::from_millis(100);
        let mut last_tick = Instant::now();
        let mut last_cleanup = Instant::now();

        loop {
            terminal.draw(|f| ui(f, &mut app))?;

            while let Ok(pkt) = rx.try_recv() {
                app.ingest_packet(&pkt);
            }

            app.update_process_map();
            if last_cleanup.elapsed() > Duration::from_secs(5) {
                app.cleanup_stale();
                app.apply_sort();
                last_cleanup = Instant::now();
            }

            let timeout = tick.saturating_sub(last_tick.elapsed());
            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(key) => {
                        if app.filter_mode {
                            match key.code {
                                KeyCode::Esc => {
                                    app.filter_mode = false;
                                    app.filter_text.clear();
                                }
                                KeyCode::Enter => {
                                    app.filter_mode = false;
                                }
                                KeyCode::Backspace => {
                                    app.filter_text.pop();
                                }
                                KeyCode::Char(c) => {
                                    app.filter_text.push(c);
                                }
                                _ => {}
                            }
                        } else {
                            match key.code {
                                KeyCode::Esc => {
                                    if app.show_detail {
                                        app.show_detail = false;
                                        app.popup_scroll = 0;
                                    } else {
                                        break;
                                    }
                                }
                                KeyCode::Char('q') | KeyCode::Char('Q') => break,
                                KeyCode::Char('/') => {
                                    app.filter_mode = true;
                                    app.filter_text.clear();
                                }
                                KeyCode::Char('1') => app.current_tab = Tab::Overview,
                                KeyCode::Char('2') => app.current_tab = Tab::Packets,
                                KeyCode::Char('3') => app.current_tab = Tab::Flows,
                                KeyCode::Char('4') => app.current_tab = Tab::Stats,
                                KeyCode::Char('5') => app.current_tab = Tab::Dataplane,
                                KeyCode::Char('6') | KeyCode::Char('?') => {
                                    app.current_tab = Tab::Help
                                }
                                KeyCode::Char('r') if app.current_tab == Tab::Dataplane => {
                                    app.nic_dataplane = get_nic_dataplane(&app.interface).ok();
                                }
                                KeyCode::Tab => {
                                    app.show_detail = false;
                                    app.current_tab = match app.current_tab {
                                        Tab::Overview => Tab::Packets,
                                        Tab::Packets => Tab::Flows,
                                        Tab::Flows => Tab::Stats,
                                        Tab::Stats => Tab::Dataplane,
                                        Tab::Dataplane => Tab::Help,
                                        Tab::Help => Tab::Overview,
                                    };
                                }
                                KeyCode::BackTab => {
                                    app.show_detail = false;
                                    app.current_tab = match app.current_tab {
                                        Tab::Overview => Tab::Help,
                                        Tab::Packets => Tab::Overview,
                                        Tab::Flows => Tab::Packets,
                                        Tab::Stats => Tab::Flows,
                                        Tab::Dataplane => Tab::Stats,
                                        Tab::Help => Tab::Dataplane,
                                    };
                                }
                                KeyCode::Up | KeyCode::Char('k') => {
                                    app.nav_up();
                                    app.popup_scroll = 0;
                                }
                                KeyCode::Down | KeyCode::Char('j') => {
                                    app.nav_down();
                                    app.popup_scroll = 0;
                                }
                                KeyCode::Enter => {
                                    app.show_detail = !app.show_detail;
                                    app.detail_sub = DetailSub::Overview;
                                    app.popup_scroll = 0;
                                }
                                KeyCode::PageDown if app.show_detail => {
                                    app.popup_scroll = app.popup_scroll.saturating_add(5);
                                }
                                KeyCode::PageUp if app.show_detail => {
                                    app.popup_scroll = app.popup_scroll.saturating_sub(5);
                                }
                                KeyCode::Char('J') if app.show_detail => {
                                    app.popup_scroll = app.popup_scroll.saturating_add(2);
                                }
                                KeyCode::Char('K') if app.show_detail => {
                                    app.popup_scroll = app.popup_scroll.saturating_sub(2);
                                }
                                KeyCode::Right if app.show_detail => {
                                    app.detail_sub = match app.detail_sub {
                                        DetailSub::Overview => DetailSub::Layers,
                                        DetailSub::Layers => DetailSub::Hex,
                                        DetailSub::Hex => DetailSub::Overview,
                                    }
                                }
                                KeyCode::Left if app.show_detail => {
                                    app.detail_sub = match app.detail_sub {
                                        DetailSub::Overview => DetailSub::Hex,
                                        DetailSub::Layers => DetailSub::Overview,
                                        DetailSub::Hex => DetailSub::Layers,
                                    }
                                }
                                KeyCode::Char('o') | KeyCode::Char('O') if app.show_detail => {
                                    app.detail_sub = DetailSub::Overview
                                }
                                KeyCode::Char('l') | KeyCode::Char('L') if app.show_detail => {
                                    app.detail_sub = DetailSub::Layers
                                }
                                KeyCode::Char('h') | KeyCode::Char('H') if app.show_detail => {
                                    app.detail_sub = DetailSub::Hex
                                }
                                KeyCode::Char('a') | KeyCode::Char('A') => {
                                    app.flow_analyze_mode = !app.flow_analyze_mode;
                                    if app.flow_analyze_mode && app.flow_analyzer.is_none() {
                                        app.flow_analyzer = Some(pktana_core::FlowAnalyzer::new());
                                    }
                                }
                                KeyCode::Char('s') => {
                                    app.sort_column = match app.sort_column {
                                        SortColumn::Protocol => SortColumn::LocalAddr,
                                        SortColumn::LocalAddr => SortColumn::RemoteAddr,
                                        SortColumn::RemoteAddr => SortColumn::State,
                                        SortColumn::State => SortColumn::Process,
                                        SortColumn::Process => SortColumn::BytesTotal,
                                        SortColumn::BytesTotal => SortColumn::Anomalies,
                                        SortColumn::Anomalies => SortColumn::Protocol,
                                    };
                                }
                                KeyCode::Char('S') => {
                                    app.sort_direction =
                                        if app.sort_direction == SortDirection::Ascending {
                                            SortDirection::Descending
                                        } else {
                                            SortDirection::Ascending
                                        };
                                }
                                KeyCode::Char('t') => app.show_historic = !app.show_historic,
                                _ => {}
                            }
                        }
                    }
                    Event::Mouse(m) => match m.kind {
                        MouseEventKind::ScrollDown => {
                            if app.show_detail {
                                app.popup_scroll = app.popup_scroll.saturating_add(1);
                            } else {
                                app.nav_down();
                            }
                        }
                        MouseEventKind::ScrollUp => {
                            if app.show_detail {
                                app.popup_scroll = app.popup_scroll.saturating_sub(1);
                            } else {
                                app.nav_up();
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            if last_tick.elapsed() >= tick {
                last_tick = Instant::now();
            }
        }

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        Ok(())
    }

    /// Open the Wireshark-like TUI pre-loaded with every packet from a PCAP file.
    /// Identical controls to `run_tui()`; no live capture thread is started.
    pub fn run_tui_pcap(path: &str) -> io::Result<()> {
        // Load all packets from the file first (before opening the terminal)
        let mut raw_packets: Vec<pktana_core::CapturePacket<'static>> = Vec::new();
        LinuxCaptureEngine::read_pcap_file(path, |pkt| {
            raw_packets.push(pkt.into_owned());
            true
        })
        .map_err(|e| io::Error::other(e.to_string()))?;

        if raw_packets.is_empty() {
            eprintln!("pktana: '{}' contains no packets.", path);
            std::process::exit(1);
        }

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

        // Build the App in PCAP mode
        let mut app = App::new(path);
        app.pcap_mode = true;
        app.pcap_file = path.to_string();

        // Compute base timestamp from first packet for relative time display
        let base_ts = raw_packets[0].timestamp_sec as f64
            + raw_packets[0].timestamp_usec as f64 / 1_000_000.0;

        // Inject all packets with accurate relative timestamps
        for pkt in &raw_packets {
            let ts = pkt.timestamp_sec as f64 + pkt.timestamp_usec as f64 / 1_000_000.0;
            let rel = ts - base_ts;
            // We temporarily call ingest_packet; the time_offset in PacketEntry
            // will reflect wall-clock (all ~0), but the Timestamp column
            // in the Packets tab displays the pcap-relative time instead via the
            // raw CapturePacket data stored in recent_raw.
            // Override time_offset for the PacketEntry by adjusting start_time:
            // simplest: just ingest directly — offset shows seconds from TUI open
            // (which is fine for analysis purposes).
            app.ingest_packet(pkt);
            // Patch the last PacketEntry's time_offset to be pcap-relative
            if let Some(last) = app.packets.back_mut() {
                last.time_offset = rel;
            }
        }

        let tick = Duration::from_millis(100);
        let mut last_tick = Instant::now();

        loop {
            terminal.draw(|f| ui(f, &mut app))?;

            let timeout = tick.saturating_sub(last_tick.elapsed());
            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(key) => {
                        if app.filter_mode {
                            match key.code {
                                KeyCode::Esc => {
                                    app.filter_mode = false;
                                    app.filter_text.clear();
                                }
                                KeyCode::Enter => app.filter_mode = false,
                                KeyCode::Backspace => {
                                    app.filter_text.pop();
                                }
                                KeyCode::Char(c) => app.filter_text.push(c),
                                _ => {}
                            }
                        } else {
                            match key.code {
                                KeyCode::Esc => {
                                    if app.show_detail {
                                        app.show_detail = false;
                                        app.popup_scroll = 0;
                                    } else {
                                        break;
                                    }
                                }
                                KeyCode::Char('q') | KeyCode::Char('Q') => break,
                                KeyCode::Char('/') => {
                                    app.filter_mode = true;
                                    app.filter_text.clear();
                                }
                                KeyCode::Char('1') => app.current_tab = Tab::Overview,
                                KeyCode::Char('2') => app.current_tab = Tab::Packets,
                                KeyCode::Char('3') => app.current_tab = Tab::Flows,
                                KeyCode::Char('4') => app.current_tab = Tab::Stats,
                                KeyCode::Char('5') => app.current_tab = Tab::Dataplane,
                                KeyCode::Char('6') | KeyCode::Char('?') => {
                                    app.current_tab = Tab::Help
                                }
                                KeyCode::Char('r') if app.current_tab == Tab::Dataplane => {
                                    app.nic_dataplane = get_nic_dataplane(&app.interface).ok();
                                }
                                KeyCode::Tab => {
                                    app.show_detail = false;
                                    app.current_tab = match app.current_tab {
                                        Tab::Overview => Tab::Packets,
                                        Tab::Packets => Tab::Flows,
                                        Tab::Flows => Tab::Stats,
                                        Tab::Stats => Tab::Dataplane,
                                        Tab::Dataplane => Tab::Help,
                                        Tab::Help => Tab::Overview,
                                    };
                                }
                                KeyCode::BackTab => {
                                    app.show_detail = false;
                                    app.current_tab = match app.current_tab {
                                        Tab::Overview => Tab::Help,
                                        Tab::Packets => Tab::Overview,
                                        Tab::Flows => Tab::Packets,
                                        Tab::Stats => Tab::Flows,
                                        Tab::Dataplane => Tab::Stats,
                                        Tab::Help => Tab::Dataplane,
                                    };
                                }
                                KeyCode::Up | KeyCode::Char('k') => {
                                    app.nav_up();
                                    app.popup_scroll = 0;
                                }
                                KeyCode::Down | KeyCode::Char('j') => {
                                    app.nav_down();
                                    app.popup_scroll = 0;
                                }
                                KeyCode::Enter => {
                                    app.show_detail = !app.show_detail;
                                    app.detail_sub = DetailSub::Overview;
                                    app.popup_scroll = 0;
                                }
                                KeyCode::PageDown if app.show_detail => {
                                    app.popup_scroll = app.popup_scroll.saturating_add(5);
                                }
                                KeyCode::PageUp if app.show_detail => {
                                    app.popup_scroll = app.popup_scroll.saturating_sub(5);
                                }
                                KeyCode::Char('J') if app.show_detail => {
                                    app.popup_scroll = app.popup_scroll.saturating_add(2);
                                }
                                KeyCode::Char('K') if app.show_detail => {
                                    app.popup_scroll = app.popup_scroll.saturating_sub(2);
                                }
                                KeyCode::Right if app.show_detail => {
                                    app.detail_sub = match app.detail_sub {
                                        DetailSub::Overview => DetailSub::Layers,
                                        DetailSub::Layers => DetailSub::Hex,
                                        DetailSub::Hex => DetailSub::Overview,
                                    }
                                }
                                KeyCode::Left if app.show_detail => {
                                    app.detail_sub = match app.detail_sub {
                                        DetailSub::Overview => DetailSub::Hex,
                                        DetailSub::Layers => DetailSub::Overview,
                                        DetailSub::Hex => DetailSub::Layers,
                                    }
                                }
                                KeyCode::Char('o') | KeyCode::Char('O') if app.show_detail => {
                                    app.detail_sub = DetailSub::Overview
                                }
                                KeyCode::Char('l') | KeyCode::Char('L') if app.show_detail => {
                                    app.detail_sub = DetailSub::Layers
                                }
                                KeyCode::Char('h') | KeyCode::Char('H') if app.show_detail => {
                                    app.detail_sub = DetailSub::Hex
                                }
                                KeyCode::Char('a') | KeyCode::Char('A') => {
                                    app.flow_analyze_mode = !app.flow_analyze_mode;
                                    if app.flow_analyze_mode && app.flow_analyzer.is_none() {
                                        app.flow_analyzer = Some(pktana_core::FlowAnalyzer::new());
                                    }
                                }
                                KeyCode::Char('s') => {
                                    app.sort_column = match app.sort_column {
                                        SortColumn::Protocol => SortColumn::LocalAddr,
                                        SortColumn::LocalAddr => SortColumn::RemoteAddr,
                                        SortColumn::RemoteAddr => SortColumn::State,
                                        SortColumn::State => SortColumn::Process,
                                        SortColumn::Process => SortColumn::BytesTotal,
                                        SortColumn::BytesTotal => SortColumn::Anomalies,
                                        SortColumn::Anomalies => SortColumn::Protocol,
                                    };
                                }
                                KeyCode::Char('S') => {
                                    app.sort_direction =
                                        if app.sort_direction == SortDirection::Ascending {
                                            SortDirection::Descending
                                        } else {
                                            SortDirection::Ascending
                                        };
                                }
                                KeyCode::Char('t') => app.show_historic = !app.show_historic,
                                _ => {}
                            }
                        }
                    }
                    Event::Mouse(m) => match m.kind {
                        MouseEventKind::ScrollDown => {
                            if app.show_detail {
                                app.popup_scroll = app.popup_scroll.saturating_add(1);
                            } else {
                                app.nav_down();
                            }
                        }
                        MouseEventKind::ScrollUp => {
                            if app.show_detail {
                                app.popup_scroll = app.popup_scroll.saturating_sub(1);
                            } else {
                                app.nav_up();
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            if last_tick.elapsed() >= tick {
                last_tick = Instant::now();
            }
        }

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        Ok(())
    }
}

#[cfg(not(feature = "tui"))]
pub mod inner {
    pub fn run_tui(_interface: &str) -> std::io::Result<()> {
        eprintln!("pktana: TUI requires the 'tui' feature. Rebuild with:");
        eprintln!("  cargo build --features pcap,tui");
        std::process::exit(1);
    }
    pub fn run_tui_pcap(_path: &str) -> std::io::Result<()> {
        eprintln!("pktana: TUI requires the 'tui' feature. Rebuild with:");
        eprintln!("  cargo build --features pcap,tui");
        std::process::exit(1);
    }
}
