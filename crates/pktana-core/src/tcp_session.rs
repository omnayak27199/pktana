// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! TCP Stream Reassembly and Session State Tracking
//!
//! Implements RFC 793 state machine, bidirectional stream reassembly with
//! out-of-order buffering, retransmission detection, and gap tracking.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::Ipv4Addr;

use crate::dpi::DeepPacket;

// ── TCP Flag Constants ────────────────────────────────────────────────────────

const TCP_FIN: u16 = 0x0001;
const TCP_SYN: u16 = 0x0002;
const TCP_RST: u16 = 0x0004;
const TCP_ACK: u16 = 0x0010;

// ── RFC 793 State Machine ─────────────────────────────────────────────────────

/// Full RFC 793 TCP connection states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpState {
    /// SYN observed, awaiting SYN-ACK
    SynSent,
    /// SYN-ACK observed, awaiting final ACK
    SynReceived,
    /// Three-way handshake complete — data transfer phase
    Established,
    /// Local side sent FIN, awaiting ACK or peer FIN
    FinWait1,
    /// FIN ACK'd, awaiting peer's FIN
    FinWait2,
    /// Peer's FIN received — local side can still send
    CloseWait,
    /// Both sides sent FIN simultaneously
    Closing,
    /// Sent FIN, waiting for final ACK from peer
    LastAck,
    /// Waiting 2×MSL before recycling the 5-tuple
    TimeWait,
    /// Connection closed cleanly
    Closed,
    /// RST received — connection aborted immediately
    Reset,
    /// Observed mid-stream (no SYN captured)
    MidStream,
}

impl TcpState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed | Self::TimeWait | Self::Reset)
    }

    pub fn is_data_phase(&self) -> bool {
        matches!(
            self,
            Self::Established
                | Self::FinWait1
                | Self::FinWait2
                | Self::CloseWait
                | Self::Closing
                | Self::LastAck
                | Self::MidStream
        )
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RCVD",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::Closed => "CLOSED",
            Self::Reset => "RESET",
            Self::MidStream => "MID_STREAM",
        };
        write!(f, "{s}")
    }
}

// ── Session Key ───────────────────────────────────────────────────────────────

/// Symmetric 5-tuple key for bidirectional session lookup.
/// Canonical form ensures the same key regardless of packet direction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpSessionKey {
    pub a_ip: Ipv4Addr,
    pub b_ip: Ipv4Addr,
    pub a_port: u16,
    pub b_port: u16,
}

impl TcpSessionKey {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Self {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            Self {
                a_ip: src_ip,
                b_ip: dst_ip,
                a_port: src_port,
                b_port: dst_port,
            }
        } else {
            Self {
                a_ip: dst_ip,
                b_ip: src_ip,
                a_port: dst_port,
                b_port: src_port,
            }
        }
    }
}

impl fmt::Display for TcpSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} <-> {}:{}",
            self.a_ip, self.a_port, self.b_ip, self.b_port
        )
    }
}

// ── Sequence Number Arithmetic (RFC 1982) ─────────────────────────────────────

/// True when `a` comes before `b` in sequence number space (handles wrap-around).
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

// ── Stream Reassembly Buffer ──────────────────────────────────────────────────

/// One directional stream: tracks sequence space and buffers out-of-order data.
#[derive(Debug, Clone, Default)]
pub struct TcpStreamBuffer {
    /// Initial sequence number (ISN) — set on SYN.
    pub isn: Option<u32>,
    /// Next expected sequence number from this sender.
    pub next_seq: u32,
    /// Out-of-order segments buffered until the gap is filled.
    /// Key = sequence number of the first byte in the segment.
    pub ooo_segments: BTreeMap<u32, Vec<u8>>,
    /// Total application bytes successfully reassembled in order.
    pub bytes_reassembled: u64,
    /// Retransmitted segments (fully within already-received range).
    pub retransmits: u32,
    /// Out-of-order arrivals (sequence gap ahead of next_seq).
    pub ooo_count: u32,
    /// Distinct gaps observed in the sequence space.
    pub gaps: u32,
    /// Sequence number at which FIN was received (FIN consumes 1 byte).
    pub fin_seq: Option<u32>,
    /// Most recently advertised receive window.
    pub window_size: u16,
    /// Window scale factor (from TCP options, if negotiated).
    pub window_scale: u8,
}

impl TcpStreamBuffer {
    /// Record the ISN from the SYN packet.
    pub fn set_isn(&mut self, isn: u32) {
        self.isn = Some(isn);
        // SYN occupies one sequence number
        self.next_seq = isn.wrapping_add(1);
    }

    /// Ingest one segment. Returns any newly in-order application bytes.
    ///
    /// `seq`    — sequence number of the first byte in `data`
    /// `data`   — application-layer payload bytes (may be empty for pure ACKs)
    /// `flags`  — TCP flags word
    /// `win`    — advertised receive window
    pub fn ingest(&mut self, seq: u32, data: &[u8], flags: u16, win: u16) -> Vec<u8> {
        self.window_size = win;

        let data_len = data.len() as u32;

        // FIN occupies one sequence number after data
        if (flags & TCP_FIN) != 0 {
            self.fin_seq = Some(seq.wrapping_add(data_len));
        }

        if data.is_empty() {
            return Vec::new();
        }

        let seg_end = seq.wrapping_add(data_len);

        // Fully retransmitted: entire segment already acknowledged
        if seq_le(seg_end, self.next_seq) {
            if self.isn.is_some() {
                self.retransmits += 1;
            }
            return Vec::new();
        }

        let mut out = Vec::new();

        if seq == self.next_seq {
            // In-order delivery
            out.extend_from_slice(data);
            self.bytes_reassembled += data_len as u64;
            self.next_seq = seg_end;

            // Drain any now-consecutive OOO segments
            loop {
                let next = self.next_seq;
                if let Some(ooo_data) = self.ooo_segments.remove(&next) {
                    let ooo_end = next.wrapping_add(ooo_data.len() as u32);
                    out.extend_from_slice(&ooo_data);
                    self.bytes_reassembled += ooo_data.len() as u64;
                    self.next_seq = ooo_end;
                } else {
                    break;
                }
            }
        } else if seq_lt(self.next_seq, seq) {
            // Future segment — gap between next_seq and seq
            self.ooo_count += 1;
            if !self.ooo_segments.contains_key(&seq) {
                self.gaps += 1;
                self.ooo_segments
                    .entry(seq)
                    .or_insert_with(|| data.to_vec());
            }
        } else {
            // Partial overlap: seq < next_seq < seg_end
            let already = self.next_seq.wrapping_sub(seq) as usize;
            if already < data.len() {
                let fresh = &data[already..];
                out.extend_from_slice(fresh);
                self.bytes_reassembled += fresh.len() as u64;
                self.next_seq = self.next_seq.wrapping_add(fresh.len() as u32);
            } else {
                self.retransmits += 1;
            }
        }

        out
    }

    /// Effective window size in bytes (applies window scale if negotiated).
    pub fn effective_window(&self) -> u32 {
        (self.window_size as u32) << self.window_scale
    }
}

// ── Session Events ────────────────────────────────────────────────────────────

/// Notable event produced while processing a packet.
#[derive(Debug, Clone)]
pub enum TcpSessionEvent {
    StateChange {
        old: TcpState,
        new: TcpState,
    },
    HandshakeComplete {
        rtt_us: u64,
    },
    DataReassembled {
        from_client: bool,
        bytes: usize,
    },
    Retransmit {
        from_client: bool,
        seq: u32,
    },
    OutOfOrder {
        from_client: bool,
        seq: u32,
        expected: u32,
    },
    GapDetected {
        from_client: bool,
        at_seq: u32,
    },
    Reset {
        from_client: bool,
    },
    ZeroWindow {
        from_client: bool,
    },
    WindowScaleNegotiated {
        client_scale: u8,
        server_scale: u8,
    },
}

// ── TCP Session ───────────────────────────────────────────────────────────────

/// Bidirectional TCP session: state machine + two-direction stream reassembly.
#[derive(Debug, Clone)]
pub struct TcpSession {
    pub key: TcpSessionKey,
    pub state: TcpState,

    /// IP and port of the initiating side (sent the SYN)
    pub client_ip: Ipv4Addr,
    pub client_port: u16,
    pub server_ip: Ipv4Addr,
    pub server_port: u16,

    /// Stream going client → server
    pub client_to_server: TcpStreamBuffer,
    /// Stream going server → client
    pub server_to_client: TcpStreamBuffer,

    /// RTT measured SYN → final handshake ACK (microseconds)
    pub handshake_rtt_us: Option<u64>,

    // Timestamps in microseconds since epoch (from pcap or live capture)
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub established_us: Option<u64>,
    pub closed_us: Option<u64>,

    /// SYN or SYN-ACK retransmits during handshake
    pub syn_retransmits: u32,
    /// Total packets processed (both directions)
    pub packets_seen: u64,

    /// Window scale factors negotiated during handshake
    pub client_window_scale: u8,
    pub server_window_scale: u8,

    /// Bounded event log (most recent 64 events)
    pub events: Vec<TcpSessionEvent>,
}

impl TcpSession {
    fn new(
        key: TcpSessionKey,
        client_ip: Ipv4Addr,
        client_port: u16,
        server_ip: Ipv4Addr,
        server_port: u16,
        first_ts: u64,
    ) -> Self {
        Self {
            key,
            state: TcpState::SynSent,
            client_ip,
            client_port,
            server_ip,
            server_port,
            client_to_server: TcpStreamBuffer::default(),
            server_to_client: TcpStreamBuffer::default(),
            handshake_rtt_us: None,
            first_seen_us: first_ts,
            last_seen_us: first_ts,
            established_us: None,
            closed_us: None,
            syn_retransmits: 0,
            packets_seen: 0,
            client_window_scale: 0,
            server_window_scale: 0,
            events: Vec::new(),
        }
    }

    fn push_event(&mut self, ev: TcpSessionEvent) {
        if self.events.len() < 64 {
            self.events.push(ev);
        }
    }

    fn transition(&mut self, new: TcpState) {
        if self.state != new {
            let old = self.state.clone();
            self.push_event(TcpSessionEvent::StateChange {
                old: old.clone(),
                new: new.clone(),
            });
            self.state = new;
        }
    }

    #[inline]
    fn is_from_client(&self, src_ip: Ipv4Addr, src_port: u16) -> bool {
        src_ip == self.client_ip && src_port == self.client_port
    }

    /// Process one TCP segment. Updates state machine and feeds the reassembly buffer.
    ///
    /// Returns any application bytes freshly reassembled in each direction.
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        &mut self,
        src_ip: Ipv4Addr,
        src_port: u16,
        seq: u32,
        _ack: u32,
        flags: u16,
        window_size: u16,
        window_scale: Option<u8>,
        payload: &[u8],
        timestamp_us: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        self.packets_seen += 1;
        self.last_seen_us = timestamp_us;

        let from_client = self.is_from_client(src_ip, src_port);

        // RST overrides everything
        if (flags & TCP_RST) != 0 {
            self.push_event(TcpSessionEvent::Reset { from_client });
            if self.closed_us.is_none() {
                self.closed_us = Some(timestamp_us);
            }
            self.transition(TcpState::Reset);
            return (Vec::new(), Vec::new());
        }

        // Zero-window warning
        if window_size == 0 && (flags & TCP_SYN) == 0 {
            self.push_event(TcpSessionEvent::ZeroWindow { from_client });
        }

        // Apply window scale if just negotiated (SYN/SYN-ACK options)
        if let Some(scale) = window_scale {
            if (flags & TCP_SYN) != 0 {
                if from_client {
                    self.client_window_scale = scale;
                    self.client_to_server.window_scale = scale;
                } else {
                    self.server_window_scale = scale;
                    self.server_to_client.window_scale = scale;
                }
                if self.client_window_scale > 0 && self.server_window_scale > 0 {
                    self.push_event(TcpSessionEvent::WindowScaleNegotiated {
                        client_scale: self.client_window_scale,
                        server_scale: self.server_window_scale,
                    });
                }
            }
        }

        self.drive_state_machine(from_client, seq, flags, timestamp_us);

        // Reassemble payload during data phase or mid-stream
        let mut c2s = Vec::new();
        let mut s2c = Vec::new();

        if self.state.is_data_phase() && !payload.is_empty() {
            let win = window_size;
            if from_client {
                let before_ooo = self.client_to_server.ooo_count;
                let before_gaps = self.client_to_server.gaps;
                let before_retx = self.client_to_server.retransmits;
                c2s = self.client_to_server.ingest(seq, payload, flags, win);
                if self.client_to_server.ooo_count > before_ooo {
                    self.push_event(TcpSessionEvent::OutOfOrder {
                        from_client: true,
                        seq,
                        expected: self.client_to_server.next_seq,
                    });
                }
                if self.client_to_server.gaps > before_gaps {
                    self.push_event(TcpSessionEvent::GapDetected {
                        from_client: true,
                        at_seq: seq,
                    });
                }
                if self.client_to_server.retransmits > before_retx {
                    self.push_event(TcpSessionEvent::Retransmit {
                        from_client: true,
                        seq,
                    });
                }
                if !c2s.is_empty() {
                    self.push_event(TcpSessionEvent::DataReassembled {
                        from_client: true,
                        bytes: c2s.len(),
                    });
                }
            } else {
                let before_ooo = self.server_to_client.ooo_count;
                let before_gaps = self.server_to_client.gaps;
                let before_retx = self.server_to_client.retransmits;
                s2c = self.server_to_client.ingest(seq, payload, flags, win);
                if self.server_to_client.ooo_count > before_ooo {
                    self.push_event(TcpSessionEvent::OutOfOrder {
                        from_client: false,
                        seq,
                        expected: self.server_to_client.next_seq,
                    });
                }
                if self.server_to_client.gaps > before_gaps {
                    self.push_event(TcpSessionEvent::GapDetected {
                        from_client: false,
                        at_seq: seq,
                    });
                }
                if self.server_to_client.retransmits > before_retx {
                    self.push_event(TcpSessionEvent::Retransmit {
                        from_client: false,
                        seq,
                    });
                }
                if !s2c.is_empty() {
                    self.push_event(TcpSessionEvent::DataReassembled {
                        from_client: false,
                        bytes: s2c.len(),
                    });
                }
            }
        }

        (c2s, s2c)
    }

    fn drive_state_machine(&mut self, from_client: bool, seq: u32, flags: u16, ts: u64) {
        let syn = (flags & TCP_SYN) != 0;
        let ack = (flags & TCP_ACK) != 0;
        let fin = (flags & TCP_FIN) != 0;

        match self.state.clone() {
            TcpState::SynSent => {
                if from_client && syn && !ack {
                    // SYN retransmit
                    self.syn_retransmits += 1;
                    self.push_event(TcpSessionEvent::Retransmit {
                        from_client: true,
                        seq,
                    });
                } else if !from_client && syn && ack {
                    // SYN-ACK from server
                    self.server_to_client.set_isn(seq);
                    self.transition(TcpState::SynReceived);
                }
            }
            TcpState::SynReceived => {
                if !from_client && syn && ack {
                    // SYN-ACK retransmit
                    self.syn_retransmits += 1;
                    self.push_event(TcpSessionEvent::Retransmit {
                        from_client: false,
                        seq,
                    });
                } else if from_client && ack && !syn {
                    // Final handshake ACK
                    let rtt_us = ts.saturating_sub(self.first_seen_us);
                    self.handshake_rtt_us = Some(rtt_us);
                    self.established_us = Some(ts);
                    self.push_event(TcpSessionEvent::HandshakeComplete { rtt_us });
                    self.transition(TcpState::Established);
                    // Client's initial seq is already set; update next_seq past the SYN
                    if self.client_to_server.isn.is_some() {
                        // already set
                    }
                }
            }
            TcpState::Established => {
                if fin && from_client {
                    self.transition(TcpState::FinWait1);
                } else if fin && !from_client {
                    self.transition(TcpState::CloseWait);
                }
            }
            TcpState::FinWait1 => {
                if !from_client {
                    if fin && ack {
                        // Simultaneous FIN+ACK
                        self.transition(TcpState::TimeWait);
                        self.closed_us = Some(ts);
                    } else if ack && !fin {
                        self.transition(TcpState::FinWait2);
                    } else if fin && !ack {
                        self.transition(TcpState::Closing);
                    }
                }
            }
            TcpState::FinWait2 => {
                if !from_client && fin {
                    self.transition(TcpState::TimeWait);
                    self.closed_us = Some(ts);
                }
            }
            TcpState::CloseWait => {
                if !from_client && fin {
                    self.transition(TcpState::LastAck);
                }
            }
            TcpState::Closing => {
                if ack {
                    self.transition(TcpState::TimeWait);
                    self.closed_us = Some(ts);
                }
            }
            TcpState::LastAck => {
                if from_client && ack {
                    self.transition(TcpState::Closed);
                    self.closed_us = Some(ts);
                }
            }
            TcpState::MidStream if fin => {
                if from_client {
                    self.transition(TcpState::FinWait1);
                } else {
                    self.transition(TcpState::CloseWait);
                }
            }
            _ => {}
        }
    }

    // ── Summary accessors ─────────────────────────────────────────────────────

    pub fn total_bytes(&self) -> u64 {
        self.client_to_server.bytes_reassembled + self.server_to_client.bytes_reassembled
    }

    pub fn total_retransmits(&self) -> u32 {
        self.syn_retransmits + self.client_to_server.retransmits + self.server_to_client.retransmits
    }

    pub fn total_ooo(&self) -> u32 {
        self.client_to_server.ooo_count + self.server_to_client.ooo_count
    }

    pub fn total_gaps(&self) -> u32 {
        self.client_to_server.gaps + self.server_to_client.gaps
    }

    pub fn duration_us(&self) -> Option<u64> {
        self.closed_us
            .map(|end| end.saturating_sub(self.first_seen_us))
    }
}

// ── Session Table ─────────────────────────────────────────────────────────────

/// Tracks all active TCP sessions and archives completed ones.
pub struct TcpSessionTable {
    /// Active sessions indexed by symmetric 5-tuple key
    pub active: HashMap<TcpSessionKey, TcpSession>,
    /// Sessions that reached a terminal state (bounded ring)
    pub completed: Vec<TcpSession>,
    max_completed: usize,
    /// Lifetime session counter
    pub total_seen: u64,
}

impl Default for TcpSessionTable {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl TcpSessionTable {
    pub fn new(max_completed: usize) -> Self {
        Self {
            active: HashMap::new(),
            completed: Vec::new(),
            max_completed,
            total_seen: 0,
        }
    }

    /// Ingest a `DeepPacket` (from `pktana_core::inspect()`).
    ///
    /// `timestamp_us` — microseconds since epoch (from pcap header or live capture).
    ///
    /// Returns the session key touched, if any.
    pub fn process(&mut self, dp: &DeepPacket, timestamp_us: u64) -> Option<TcpSessionKey> {
        let src_ip = dp.ip_src?;
        let dst_ip = dp.ip_dst?;
        let src_port = dp.tcp_src_port?;
        let dst_port = dp.tcp_dst_port?;
        let seq = dp.tcp_seq?;
        let ack = dp.tcp_ack.unwrap_or(0);
        let flags = dp.tcp_flags?;
        let window_size = dp.tcp_window.unwrap_or(0);
        let window_scale = dp.tcp_window_scale;

        let key = TcpSessionKey::new(src_ip, dst_ip, src_port, dst_port);

        // Create session on SYN; accept mid-stream packets if session already exists
        if !self.active.contains_key(&key) {
            if (flags & TCP_SYN) != 0 && (flags & TCP_ACK) == 0 {
                // New SYN from client
                let mut session = TcpSession::new(
                    key.clone(),
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    timestamp_us,
                );
                session.client_to_server.set_isn(seq);
                self.active.insert(key.clone(), session);
                self.total_seen += 1;
            } else {
                // Mid-stream: capture started after handshake
                let (client_ip, client_port, server_ip, server_port) =
                    if (src_ip, src_port) <= (dst_ip, dst_port) {
                        (src_ip, src_port, dst_ip, dst_port)
                    } else {
                        (dst_ip, dst_port, src_ip, src_port)
                    };
                let mut session = TcpSession::new(
                    key.clone(),
                    client_ip,
                    client_port,
                    server_ip,
                    server_port,
                    timestamp_us,
                );
                session.state = TcpState::MidStream;
                session.client_to_server.next_seq = seq;
                self.active.insert(key.clone(), session);
                self.total_seen += 1;
            }
        }

        if let Some(session) = self.active.get_mut(&key) {
            session.process(
                src_ip,
                src_port,
                seq,
                ack,
                flags,
                window_size,
                window_scale,
                &dp.payload,
                timestamp_us,
            );

            if session.state.is_terminal() {
                let done = self.active.remove(&key).unwrap();
                if self.completed.len() < self.max_completed {
                    self.completed.push(done);
                }
            }
        }

        Some(key)
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Iterate over all sessions (active + completed).
    pub fn all_sessions(&self) -> impl Iterator<Item = &TcpSession> {
        self.active.values().chain(self.completed.iter())
    }

    /// Summary statistics across all sessions.
    pub fn summary(&self) -> TcpSessionSummary {
        let mut s = TcpSessionSummary {
            active: self.active.len() as u64,
            completed: self.completed.len() as u64,
            total_seen: self.total_seen,
            ..Default::default()
        };

        for sess in self.all_sessions() {
            s.total_bytes += sess.total_bytes();
            s.total_retransmits += sess.total_retransmits() as u64;
            s.total_ooo += sess.total_ooo() as u64;
            s.total_gaps += sess.total_gaps() as u64;
            s.total_packets += sess.packets_seen;
            if let Some(rtt) = sess.handshake_rtt_us {
                s.rtt_samples += 1;
                s.rtt_sum_us += rtt;
            }
            match sess.state {
                TcpState::Established => s.state_established += 1,
                TcpState::Reset => s.state_reset += 1,
                TcpState::TimeWait | TcpState::Closed => s.state_closed += 1,
                TcpState::SynSent | TcpState::SynReceived => s.state_handshake += 1,
                _ => {}
            }
        }

        s
    }
}

// ── Summary ───────────────────────────────────────────────────────────────────

/// Aggregate statistics across all sessions in a `TcpSessionTable`.
#[derive(Debug, Clone, Default)]
pub struct TcpSessionSummary {
    pub active: u64,
    pub completed: u64,
    pub total_seen: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_retransmits: u64,
    pub total_ooo: u64,
    pub total_gaps: u64,
    /// Sessions currently in ESTABLISHED state
    pub state_established: u64,
    pub state_handshake: u64,
    pub state_reset: u64,
    pub state_closed: u64,
    pub rtt_samples: u64,
    pub rtt_sum_us: u64,
}

impl TcpSessionSummary {
    pub fn avg_rtt_ms(&self) -> Option<f64> {
        if self.rtt_samples == 0 {
            return None;
        }
        Some((self.rtt_sum_us as f64 / self.rtt_samples as f64) / 1000.0)
    }
}
