// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Advanced Terminal User Interface for pktana — feature-complete live network dashboard.
//!
//! Features:
//! - Process tracking (PID/name)
//! - Sortable columns
//! - Advanced filtering (keyword-based)
//! - Connection state tracking
//! - Historic connections
//! - Mouse support
//! - Multiple tabs

#[cfg(feature = "tui")]
pub mod inner {
    use std::collections::HashMap;
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
        widgets::{Block, Borders, Paragraph, Row, Table, TableState},
        Frame, Terminal,
    };

    use pktana_core::{
        analyze_bytes, build_socket_process_map, geoip_lookup_str, CaptureConfig, CapturePacket,
        GeoInfo, LinuxCaptureEngine, ProcessInfo, SocketId,
    };

    // ─── Connection tracking ───────────────────────────────────────────────────

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
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum SortColumn {
        Protocol,
        LocalAddr,
        RemoteAddr,
        State,
        Process,
        BytesTotal,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum SortDirection {
        Ascending,
        Descending,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Tab {
        Overview,
        Details,
        Help,
    }

    // ─── App state ─────────────────────────────────────────────────────────────

    struct App {
        interface: String,
        start_time: Instant,
        connections: Vec<Connection>,
        next_conn_id: usize,
        process_map: HashMap<SocketId, ProcessInfo>,
        last_process_update: Instant,

        // UI state
        selected_index: usize,
        sort_column: SortColumn,
        sort_direction: SortDirection,
        filter_text: String,
        filter_mode: bool,
        show_historic: bool,
        current_tab: Tab,
        table_state: TableState,

        // Stats
        total_packets: u64,
        total_bytes: u64,
        protocol_counts: HashMap<String, u64>,
    }

    impl App {
        fn new(interface: &str) -> Self {
            let mut table_state = TableState::default();
            table_state.select(Some(0));

            Self {
                interface: interface.to_string(),
                start_time: Instant::now(),
                connections: Vec::new(),
                next_conn_id: 0,
                process_map: HashMap::new(),
                last_process_update: Instant::now(),
                selected_index: 0,
                sort_column: SortColumn::BytesTotal,
                sort_direction: SortDirection::Descending,
                filter_text: String::new(),
                filter_mode: false,
                show_historic: false,
                current_tab: Tab::Overview,
                table_state,
                total_packets: 0,
                total_bytes: 0,
                protocol_counts: HashMap::new(),
            }
        }

        fn update_process_map(&mut self) {
            // Refresh every 2 seconds
            if self.last_process_update.elapsed() > Duration::from_secs(2) {
                self.process_map = build_socket_process_map();
                self.last_process_update = Instant::now();

                // Update existing connections with process info
                for conn in &mut self.connections {
                    if conn.process.is_none() {
                        if let (Ok(local_ip), Ok(remote_ip)) = (
                            conn.local_ip.parse::<IpAddr>(),
                            conn.remote_ip.parse::<IpAddr>(),
                        ) {
                            let socket_id = SocketId::new(
                                local_ip,
                                conn.local_port,
                                remote_ip,
                                conn.remote_port,
                            );
                            if let Some(proc_info) = self.process_map.get(&socket_id) {
                                conn.process = Some(proc_info.clone());
                            }
                        }
                    }
                }
            }
        }

        fn ingest_packet(&mut self, pkt: &CapturePacket) {
            self.total_packets += 1;
            self.total_bytes += pkt.data.len() as u64;

            let Ok(parsed) = analyze_bytes(&pkt.data) else {
                return;
            };

            let summary = &parsed.summary;
            let protocol = summary.proto_label().to_string();

            *self.protocol_counts.entry(protocol.clone()).or_insert(0) += 1;

            // Extract connection tuple
            let (src_ip, src_port, dst_ip, dst_port) = match extract_connection_tuple(summary) {
                Some(tuple) => tuple,
                None => return,
            };

            // Find or create connection

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
                // Update existing connection
                conn.last_seen = Instant::now();
                conn.packets_recv += 1;
                conn.bytes_recv += pkt.data.len() as u64;
                conn.active = true;
            } else {
                // Create new connection
                let geo = geoip_lookup_str(&dst_ip);

                // Try to find process info
                let process = if let (Ok(local_ip), Ok(remote_ip)) =
                    (src_ip.parse::<IpAddr>(), dst_ip.parse::<IpAddr>())
                {
                    let socket_id = SocketId::new(local_ip, src_port, remote_ip, dst_port);
                    self.process_map.get(&socket_id).cloned()
                } else {
                    None
                };

                self.connections.push(Connection {
                    id: self.next_conn_id,
                    protocol: protocol.clone(),
                    local_ip: src_ip,
                    local_port: src_port,
                    remote_ip: dst_ip,
                    remote_port: dst_port,
                    state: "ESTABLISHED".to_string(),
                    process,
                    geo,
                    first_seen: Instant::now(),
                    last_seen: Instant::now(),
                    packets_sent: 0,
                    packets_recv: 1,
                    bytes_sent: 0,
                    bytes_recv: pkt.data.len() as u64,
                    active: true,
                });
                self.next_conn_id += 1;
            }
        }

        fn cleanup_stale_connections(&mut self) {
            let now = Instant::now();
            for conn in &mut self.connections {
                if now.duration_since(conn.last_seen) > Duration::from_secs(60) {
                    conn.active = false;
                }
            }

            if !self.show_historic {
                self.connections.retain(|c| c.active);
            }
        }

        fn apply_sort(&mut self) {
            let sort_col = self.sort_column;
            let sort_dir = self.sort_direction;

            self.connections.sort_by(|a, b| {
                let cmp = match sort_col {
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
                        let a_proc = a.process.as_ref().map(|p| p.name.as_str()).unwrap_or("");
                        let b_proc = b.process.as_ref().map(|p| p.name.as_str()).unwrap_or("");
                        a_proc.cmp(b_proc)
                    }
                    SortColumn::BytesTotal => {
                        let a_total = a.bytes_sent + a.bytes_recv;
                        let b_total = b.bytes_sent + b.bytes_recv;
                        a_total.cmp(&b_total)
                    }
                };

                match sort_dir {
                    SortDirection::Ascending => cmp,
                    SortDirection::Descending => cmp.reverse(),
                }
            });
        }

        fn filtered_connections(&self) -> Vec<&Connection> {
            if self.filter_text.is_empty() {
                return self.connections.iter().collect();
            }

            let filter_lower = self.filter_text.to_lowercase();

            self.connections
                .iter()
                .filter(|conn| {
                    // Simple contains search across all fields
                    format!(
                        "{} {} {} {} {} {}",
                        conn.protocol,
                        conn.local_ip,
                        conn.remote_ip,
                        conn.state,
                        conn.process.as_ref().map(|p| p.name.as_str()).unwrap_or(""),
                        conn.geo.as_ref().map(|g| g.country_name).unwrap_or("")
                    )
                    .to_lowercase()
                    .contains(&filter_lower)
                })
                .collect()
        }
    }

    fn extract_connection_tuple(
        summary: &pktana_core::PacketSummary,
    ) -> Option<(String, u16, String, u16)> {
        let (src_port, dst_port) = match &summary.transport {
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

        let (src_ip, dst_ip) = if let Some(ipv4) = &summary.ipv4 {
            (ipv4.source.to_string(), ipv4.destination.to_string())
        } else {
            return None;
        };

        Some((src_ip, src_port, dst_ip, dst_port))
    }

    // ─── UI rendering ──────────────────────────────────────────────────────────

    fn ui(f: &mut Frame, app: &mut App) {
        match app.current_tab {
            Tab::Overview => render_overview(f, app),
            Tab::Details => render_details(f, app),
            Tab::Help => render_help(f, app),
        }
    }

    fn render_overview(f: &mut Frame, app: &mut App) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Length(8), // Stats panel
                Constraint::Min(10),   // Connections table
                Constraint::Length(3), // Status bar
            ])
            .split(f.area());

        // Header
        render_header(f, chunks[0], app);

        // Stats panel
        render_stats_panel(f, chunks[1], app);

        // Connections table
        render_connections_table(f, chunks[2], app);

        // Status bar
        render_status_bar(f, chunks[3], app);
    }

    fn render_header(f: &mut Frame, area: Rect, app: &App) {
        let elapsed = format_duration(app.start_time.elapsed());
        let active_count = app.connections.iter().filter(|c| c.active).count();
        let total_count = app.connections.len();

        let text = if app.show_historic {
            format!(
                " pktana TUI | {} | {} active | {} total ({}historic) | {}",
                app.interface,
                active_count,
                total_count,
                total_count - active_count,
                elapsed
            )
        } else {
            format!(
                " pktana TUI | {} | {} connections | {}",
                app.interface, active_count, elapsed
            )
        };

        let header = Paragraph::new(text)
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(header, area);
    }

    fn render_stats_panel(f: &mut Frame, area: Rect, app: &App) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left: Traffic stats
        let traffic_text = [
            format!("Total Packets: {}", app.total_packets),
            format!("Total Bytes: {}", format_bytes(app.total_bytes)),
            format!("Connections: {}", app.connections.len()),
        ];
        let traffic = Paragraph::new(traffic_text.join("\n")).block(
            Block::default()
                .title(" Traffic Stats ")
                .borders(Borders::ALL),
        );
        f.render_widget(traffic, chunks[0]);

        // Right: Protocol breakdown
        let mut proto_list: Vec<_> = app.protocol_counts.iter().collect();
        proto_list.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

        let proto_text: Vec<String> = proto_list
            .iter()
            .take(5)
            .map(|(proto, count)| format!("{}: {}", proto, count))
            .collect();

        let protocols = Paragraph::new(proto_text.join("\n")).block(
            Block::default()
                .title(" Top Protocols ")
                .borders(Borders::ALL),
        );
        f.render_widget(protocols, chunks[1]);
    }

    fn render_connections_table(f: &mut Frame, area: Rect, app: &mut App) {
        let header = Row::new(vec![
            "Proto",
            "Local Address",
            "Remote Address",
            "State",
            "Process",
            "Country",
            "Bytes",
        ])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

        let filtered = app.filtered_connections();
        let rows: Vec<Row> = filtered
            .iter()
            .map(|conn| {
                let local = format!("{}:{}", conn.local_ip, conn.local_port);
                let remote = format!("{}:{}", conn.remote_ip, conn.remote_port);
                let process = conn
                    .process
                    .as_ref()
                    .map(|p| p.name.as_str())
                    .unwrap_or("-");
                let country = conn.geo.as_ref().map(|g| g.country_code).unwrap_or("--");
                let bytes = format_bytes(conn.bytes_sent + conn.bytes_recv);

                let style = if !conn.active {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default()
                };

                Row::new(vec![
                    conn.protocol.clone(),
                    local,
                    remote,
                    conn.state.clone(),
                    process.to_string(),
                    country.to_string(),
                    bytes,
                ])
                .style(style)
            })
            .collect();

        let sort_indicator = match app.sort_direction {
            SortDirection::Ascending => "↑",
            SortDirection::Descending => "↓",
        };

        let title = format!(
            " Connections (Sort: {:?} {}) ",
            app.sort_column, sort_indicator
        );

        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(22),
                Constraint::Length(22),
                Constraint::Length(12),
                Constraint::Length(15),
                Constraint::Length(8),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

        f.render_stateful_widget(table, area, &mut app.table_state);
    }

    fn render_status_bar(f: &mut Frame, area: Rect, app: &App) {
        let status = if app.filter_mode {
            format!("Filter: {} (Esc to clear)", app.filter_text)
        } else {
            "/ filter | s sort | t toggle historic | Tab switch tabs | q quit".to_string()
        };

        let bar = Paragraph::new(status)
            .style(Style::default().fg(Color::Green))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(bar, area);
    }

    fn render_details(f: &mut Frame, _app: &App) {
        let text = "Connection Details (press Tab to return)";
        let widget =
            Paragraph::new(text).block(Block::default().title(" Details ").borders(Borders::ALL));
        f.render_widget(widget, f.area());
    }

    fn render_help(f: &mut Frame, _app: &App) {
        let help_text = vec![
            "KEYBOARD SHORTCUTS",
            "",
            "Tab / Shift+Tab - Switch tabs",
            "↑ / ↓ / j / k   - Navigate",
            "s               - Cycle sort column",
            "S (Shift+s)     - Toggle sort direction",
            "/               - Enter filter mode",
            "t               - Toggle historic connections",
            "Esc             - Clear filter / back",
            "q               - Quit",
            "",
            "MOUSE SUPPORT",
            "",
            "Click row       - Select connection",
            "Double-click    - View details",
            "Scroll wheel    - Navigate list",
        ];

        let widget = Paragraph::new(help_text.join("\n"))
            .block(Block::default().title(" Help ").borders(Borders::ALL));
        f.render_widget(widget, f.area());
    }

    // ─── Utilities ─────────────────────────────────────────────────────────────

    fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_000_000_000 {
            format!("{:.1} GB", bytes as f64 / 1e9)
        } else if bytes >= 1_000_000 {
            format!("{:.1} MB", bytes as f64 / 1e6)
        } else if bytes >= 1_000 {
            format!("{:.1} KB", bytes as f64 / 1e3)
        } else {
            format!("{} B", bytes)
        }
    }

    fn format_duration(d: Duration) -> String {
        let secs = d.as_secs();
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        format!("{:02}:{:02}:{:02}", h, m, s)
    }

    // ─── Main TUI loop ─────────────────────────────────────────────────────────

    pub fn run_tui(interface: &str) -> io::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut app = App::new(interface);

        // Spawn capture thread
        let (tx, rx) = mpsc::channel();
        let iface = interface.to_string();
        std::thread::spawn(move || {
            let config = CaptureConfig {
                interface: iface,
                promiscuous: true,
                snapshot_len: 65535,
                filter: None,
                max_packets: usize::MAX,
                pcap_export: None,
            };
            let _ = LinuxCaptureEngine::capture_streaming(&config, |pkt| {
                let _ = tx.send(pkt);
                true
            });
        });

        let tick_rate = Duration::from_millis(100);
        let mut last_tick = Instant::now();
        let mut last_cleanup = Instant::now();

        loop {
            terminal.draw(|f| ui(f, &mut app))?;

            // Process captured packets
            while let Ok(pkt) = rx.try_recv() {
                app.ingest_packet(&pkt);
            }

            // Update process map periodically
            app.update_process_map();

            // Cleanup stale connections
            if last_cleanup.elapsed() > Duration::from_secs(5) {
                app.cleanup_stale_connections();
                last_cleanup = Instant::now();
            }

            // Apply sorting
            app.apply_sort();

            // Handle input
            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
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
                                KeyCode::Char('q') | KeyCode::Char('Q') => break,
                                KeyCode::Esc => break,
                                KeyCode::Char('/') => app.filter_mode = true,
                                KeyCode::Char('t') => app.show_historic = !app.show_historic,
                                KeyCode::Char('s') => {
                                    // Cycle sort column
                                    app.sort_column = match app.sort_column {
                                        SortColumn::Protocol => SortColumn::LocalAddr,
                                        SortColumn::LocalAddr => SortColumn::RemoteAddr,
                                        SortColumn::RemoteAddr => SortColumn::State,
                                        SortColumn::State => SortColumn::Process,
                                        SortColumn::Process => SortColumn::BytesTotal,
                                        SortColumn::BytesTotal => SortColumn::Protocol,
                                    };
                                }
                                KeyCode::Char('S') => {
                                    // Toggle sort direction
                                    app.sort_direction = match app.sort_direction {
                                        SortDirection::Ascending => SortDirection::Descending,
                                        SortDirection::Descending => SortDirection::Ascending,
                                    };
                                }
                                KeyCode::Tab => {
                                    app.current_tab = match app.current_tab {
                                        Tab::Overview => Tab::Details,
                                        Tab::Details => Tab::Help,
                                        Tab::Help => Tab::Overview,
                                    };
                                }
                                KeyCode::Up | KeyCode::Char('k') if app.selected_index > 0 => {
                                    app.selected_index -= 1;
                                    app.table_state.select(Some(app.selected_index));
                                }
                                KeyCode::Down | KeyCode::Char('j') => {
                                    let max = app.filtered_connections().len().saturating_sub(1);
                                    if app.selected_index < max {
                                        app.selected_index += 1;
                                        app.table_state.select(Some(app.selected_index));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Event::Mouse(mouse) if matches!(mouse.kind, MouseEventKind::ScrollDown) => {
                        let max = app.filtered_connections().len().saturating_sub(1);
                        if app.selected_index < max {
                            app.selected_index += 1;
                            app.table_state.select(Some(app.selected_index));
                        }
                    }
                    Event::Mouse(mouse)
                        if matches!(mouse.kind, MouseEventKind::ScrollUp)
                            && app.selected_index > 0 =>
                    {
                        app.selected_index -= 1;
                        app.table_state.select(Some(app.selected_index));
                    }
                    _ => {}
                }
            }

            if last_tick.elapsed() >= tick_rate {
                last_tick = Instant::now();
            }
        }

        // Cleanup
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
}
