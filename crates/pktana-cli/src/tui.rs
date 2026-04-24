// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Terminal User Interface for pktana — live network dashboard.
//!
//! Activated with: `pktana tui <interface>`
//!
//! Layout:
//!   ┌─ Header ─────────────────────────────────────────────────────────────┐
//!   │ pktana live dashboard  iface=eth0  elapsed=00:01:23  pkts=4521       │
//!   ├─ Bandwidth ──────────────┬─ Protocol Breakdown ──────────────────────┤
//!   │ RX: 12.3 MB/s ▓▓▓▓▓▓░░░ │  TCP  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓░  68%              │
//!   │ TX:  4.1 MB/s ▓▓░░░░░░░ │  UDP  ▓▓▓▓░░░░░░░░░░░  22%              │
//!   ├─ Top Talkers ────────────┴───────────────────────────────────────────┤
//!   │  1. 8.8.8.8        US  United States   12 321 pkts   4.2 MB         │
//!   │  2. 185.12.50.4    DE  Germany          3 210 pkts   1.1 MB         │
//!   ├─ Recent Packets ─────────────────────────────────────────────────────┤
//!   │  No.  Time              Bytes   Proto  Source           Destination  │
//!   │    1  13:21:04.123456    1 500  TCP    192.168.1.5      8.8.8.8      │
//!   ├─ Connections ────────────────────────────────────────────────────────┤
//!   │  Proto  Local                  Remote                 State          │
//!   └──────────────────────────────────────────────────────────────────────┘

#[cfg(feature = "tui")]
pub mod inner {
    use std::collections::HashMap;
    use std::io;
    use std::time::{Duration, Instant};

    use crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout, Rect},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Row, Table},
        Frame, Terminal,
    };

    use pktana_core::{
        geoip_lookup_str, list_connections, CaptureConfig, CapturePacket, GeoInfo,
        LinuxCaptureEngine,
    };

    // ─── State ─────────────────────────────────────────────────────────────────

    struct App {
        interface: String,
        start: Instant,
        last_tick: Instant,
        total_pkts: u64,
        total_bytes: u64,
        tick_pkts: u64,
        tick_bytes: u64,
        bw_rx_bps: f64,
        proto_counts: HashMap<String, (u64, u64)>,
        talkers: HashMap<String, (u64, u64, Option<GeoInfo>)>,
        recent: Vec<PacketRow>,
        log: Vec<String>,
    }

    #[derive(Clone)]
    struct PacketRow {
        num: u64,
        time: String,
        bytes: usize,
        proto: String,
        src: String,
        dst: String,
    }

    impl App {
        fn new(interface: &str) -> Self {
            let now = Instant::now();
            Self {
                interface: interface.to_string(),
                start: now,
                last_tick: now,
                total_pkts: 0,
                total_bytes: 0,
                tick_pkts: 0,
                tick_bytes: 0,
                bw_rx_bps: 0.0,
                proto_counts: HashMap::new(),
                talkers: HashMap::new(),
                recent: Vec::new(),
                log: Vec::new(),
            }
        }

        fn ingest(&mut self, pkt: &CapturePacket) {
            use pktana_core::analyze_bytes;
            self.total_pkts += 1;
            self.total_bytes += pkt.data.len();
            self.tick_pkts += 1;
            self.tick_bytes += pkt.data.len() as u64;

            let (proto, src, dst) = if let Ok(parsed) = analyze_bytes(&pkt.data) {
                let s = &parsed.summary;
                (s.proto_label().to_string(), s.src_str(), s.dst_str())
            } else {
                ("?".into(), "?".into(), "?".into())
            };

            let e = self.proto_counts.entry(proto.clone()).or_insert((0, 0));
            e.0 += 1;
            e.1 += pkt.data.len() as u64;

            if self.talkers.len() < 2_000 || self.talkers.contains_key(&src) {
                let t = self
                    .talkers
                    .entry(src.clone())
                    .or_insert_with(|| (0, 0, geoip_lookup_str(&src)));
                t.0 += 1;
                t.1 += pkt.data.len() as u64;
            }

            let row = PacketRow {
                num: self.total_pkts,
                time: format_ts(pkt.timestamp_sec, pkt.timestamp_usec),
                bytes: pkt.data.len(),
                proto,
                src,
                dst,
            };
            self.recent.push(row);
            if self.recent.len() > 200 {
                self.recent.remove(0);
            }
        }

        fn tick(&mut self) {
            let elapsed = self.last_tick.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                self.bw_rx_bps = self.tick_bytes as f64 * 8.0 / elapsed;
            }
            self.tick_pkts = 0;
            self.tick_bytes = 0;
            self.last_tick = Instant::now();
        }
    }

    fn format_ts(sec: i64, usec: i64) -> String {
        let t = sec % 86400;
        let h = t / 3600;
        let m = (t % 3600) / 60;
        let s = t % 60;
        format!("{h:02}:{m:02}:{s:02}.{usec:06}")
    }

    fn fmt_bytes(b: u64) -> String {
        if b >= 1_000_000_000 {
            format!("{:.1} GB", b as f64 / 1e9)
        } else if b >= 1_000_000 {
            format!("{:.1} MB", b as f64 / 1e6)
        } else if b >= 1_000 {
            format!("{:.1} KB", b as f64 / 1e3)
        } else {
            format!("{b} B")
        }
    }

    fn fmt_bps(bps: f64) -> String {
        if bps >= 1e9 {
            format!("{:.1} Gbps", bps / 1e9)
        } else if bps >= 1e6 {
            format!("{:.1} Mbps", bps / 1e6)
        } else if bps >= 1e3 {
            format!("{:.1} Kbps", bps / 1e3)
        } else {
            format!("{:.0} bps", bps)
        }
    }

    fn elapsed_str(start: Instant) -> String {
        let s = start.elapsed().as_secs();
        let h = s / 3600;
        let m = (s % 3600) / 60;
        let sec = s % 60;
        format!("{h:02}:{m:02}:{sec:02}")
    }

    // ─── UI rendering ──────────────────────────────────────────────────────────

    fn ui(f: &mut Frame, app: &App) {
        let area = f.area();

        // Outer vertical split: header | body
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);

        // Header
        draw_header(f, outer[0], app);

        // Body: top-half | packet list | connections
        let body = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(10), // stats
                Constraint::Min(8),     // recent packets
                Constraint::Length(8),  // connections
            ])
            .split(outer[1]);

        // Stats row: bandwidth | proto breakdown | top talkers
        let stats_row = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Percentage(30),
                Constraint::Percentage(40),
            ])
            .split(body[0]);

        draw_bandwidth(f, stats_row[0], app);
        draw_proto(f, stats_row[1], app);
        draw_talkers(f, stats_row[2], app);
        draw_packets(f, body[1], app);
        draw_connections(f, body[2]);
    }

    fn draw_header(f: &mut Frame, area: Rect, app: &App) {
        let text = Line::from(vec![
            Span::styled(
                " pktana ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("live dashboard  "),
            Span::styled(
                format!("iface={}", app.interface),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(format!(
                "  elapsed={}  pkts={}  total={}  [q] quit",
                elapsed_str(app.start),
                app.total_pkts,
                fmt_bytes(app.total_bytes),
            )),
        ]);
        let p = Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(p, area);
    }

    fn draw_bandwidth(f: &mut Frame, area: Rect, app: &App) {
        let bps = app.bw_rx_bps;
        let ratio = (bps / 1e9_f64).min(1.0); // normalize to 1 Gbps
        let label = format!(" RX  {}  ", fmt_bps(bps));
        let g = Gauge::default()
            .block(
                Block::default()
                    .title(" Bandwidth ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(ratio)
            .label(label);
        f.render_widget(g, area);
    }

    fn draw_proto(f: &mut Frame, area: Rect, app: &App) {
        let total = app.total_pkts.max(1);
        let mut protos: Vec<(&String, &(u64, u64))> = app.proto_counts.iter().collect();
        protos.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));

        let items: Vec<ListItem> = protos
            .iter()
            .take(6)
            .map(|(name, (pkts, bytes))| {
                let pct = *pkts as f64 / total as f64 * 100.0;
                let bar_len = (pct / 5.0) as usize; // max 20 chars at 100%
                let bar = "▓".repeat(bar_len) + &"░".repeat(20usize.saturating_sub(bar_len));
                ListItem::new(format!(
                    "{:<6} {} {:4.1}%  {}",
                    name,
                    &bar[..bar.len().min(20)],
                    pct,
                    fmt_bytes(*bytes)
                ))
            })
            .collect();

        let list = List::new(items).block(
            Block::default()
                .title(" Protocol Breakdown ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(list, area);
    }

    fn draw_talkers(f: &mut Frame, area: Rect, app: &App) {
        let mut talkers: Vec<(&String, &(u64, u64, Option<GeoInfo>))> =
            app.talkers.iter().collect();
        talkers.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));

        let header = Row::new(vec!["#", "IP", "CC", "Country", "Pkts", "Data"]).style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        );

        let rows: Vec<Row> = talkers
            .iter()
            .take(8)
            .enumerate()
            .map(|(i, (ip, (pkts, bytes, geo)))| {
                let (cc, country) = if let Some(g) = geo {
                    (g.country_code, g.country_name)
                } else {
                    ("--", "Unknown")
                };
                Row::new(vec![
                    format!("{}", i + 1),
                    (*ip).clone(),
                    cc.to_string(),
                    country.to_string(),
                    pkts.to_string(),
                    fmt_bytes(*bytes),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(3),
            Constraint::Length(17),
            Constraint::Length(4),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Length(9),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .title(" Top Talkers (GeoIP) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .row_highlight_style(Style::default().fg(Color::Yellow));
        f.render_widget(table, area);
    }

    fn draw_packets(f: &mut Frame, area: Rect, app: &App) {
        let header = Row::new(vec![
            "No.",
            "Time",
            "Bytes",
            "Proto",
            "Source",
            "Destination",
        ])
        .style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        );

        let recent: Vec<&PacketRow> = app.recent.iter().rev().take(50).collect();
        let rows: Vec<Row> = recent
            .iter()
            .map(|r| {
                Row::new(vec![
                    r.num.to_string(),
                    r.time.clone(),
                    r.bytes.to_string(),
                    r.proto.clone(),
                    r.src.clone(),
                    r.dst.clone(),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(26),
            Constraint::Length(26),
        ];
        let table = Table::new(rows, widths).header(header).block(
            Block::default()
                .title(" Recent Packets ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(table, area);
    }

    fn draw_connections(f: &mut Frame, area: Rect) {
        let conns = list_connections().unwrap_or_default();
        let header = Row::new(vec!["Proto", "Local", "Remote", "State", "PID", "Process"]).style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        );

        let rows: Vec<Row> = conns
            .iter()
            .take(5)
            .map(|c| {
                let local = format!("{}:{}", c.local_ip, c.local_port);
                let remote = if c.remote_port == 0 {
                    "—".to_string()
                } else {
                    format!("{}:{}", c.remote_ip, c.remote_port)
                };
                let pid = if c.pid == 0 {
                    "—".to_string()
                } else {
                    c.pid.to_string()
                };
                Row::new(vec![
                    c.proto.clone(),
                    local,
                    remote,
                    c.state.clone(),
                    pid,
                    c.process.clone(),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(6),
            Constraint::Length(22),
            Constraint::Length(22),
            Constraint::Length(13),
            Constraint::Length(7),
            Constraint::Min(10),
        ];
        let table = Table::new(rows, widths).header(header).block(
            Block::default()
                .title(" Active Connections ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(table, area);
    }

    // ─── Entry point ───────────────────────────────────────────────────────────

    pub fn run_tui(interface: &str) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut app = App::new(interface);

        // Spawn capture thread
        let iface = interface.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<CapturePacket>();

        std::thread::spawn(move || {
            let config = CaptureConfig {
                interface: iface,
                promiscuous: true,
                snapshot_len: 65535,
                timeout_ms: 500,
                filter: None,
                max_packets: usize::MAX,
            };
            let _result = LinuxCaptureEngine::stream(&config, |pkt| {
                let _ = tx.send(pkt);
                true
            });
        });

        let tick_rate = Duration::from_millis(500);
        let mut last_tick = Instant::now();

        loop {
            terminal.draw(|f| ui(f, &app))?;

            // Drain packets from capture thread
            while let Ok(pkt) = rx.try_recv() {
                app.ingest(&pkt);
            }

            // Handle keyboard input
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_default();

            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                        break;
                    }
                }
            }

            if last_tick.elapsed() >= tick_rate {
                app.tick();
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
}
