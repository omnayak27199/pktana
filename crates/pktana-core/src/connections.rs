// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Active network connection listing from /proc/net/tcp, tcp6, udp, udp6.
//! No external tools (ss, netstat) required.
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct Connection {
    pub proto: &'static str,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: &'static str,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

/// List all active TCP and UDP connections (IPv4 + IPv6).
/// Attempts to resolve PIDs and process names via /proc/$pid/fd.
pub fn list_connections() -> Vec<Connection> {
    let pid_map = build_pid_map();
    let mut conns = Vec::new();

    let sources: &[(&'static str, &str, bool)] = &[
        ("TCP", "/proc/net/tcp", false),
        ("TCP6", "/proc/net/tcp6", true),
        ("UDP", "/proc/net/udp", false),
        ("UDP6", "/proc/net/udp6", true),
    ];

    for &(proto, path, is_ipv6) in sources {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(c) = parse_line(line, proto, is_ipv6, &pid_map) {
                conns.push(c);
            }
        }
    }

    conns
}

// ─── internal ────────────────────────────────────────────────────────────────

fn parse_line(
    line: &str,
    proto: &'static str,
    is_ipv6: bool,
    pid_map: &HashMap<u64, (u32, String)>,
) -> Option<Connection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let parse: fn(&str) -> Option<(String, u16)> = if is_ipv6 {
        parse_ipv6_addr
    } else {
        parse_ipv4_addr
    };

    let (local_ip, local_port) = parse(parts[1])?;
    let (remote_ip, remote_port) = parse(parts[2])?;

    let state_code = u8::from_str_radix(parts[3], 16).unwrap_or(0);
    let state = tcp_state(state_code, proto);

    let inode: u64 = parts[9].parse().unwrap_or(0);
    let (pid, process) = pid_map
        .get(&inode)
        .map(|(p, n)| (Some(*p), Some(n.clone())))
        .unwrap_or((None, None));

    Some(Connection {
        proto,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        state,
        pid,
        process,
    })
}

/// Parse "AABBCCDD:PPPP" (hex IPv4 LE:port) into (ip_string, port).
fn parse_ipv4_addr(s: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let n = u32::from_str_radix(ip_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    // The kernel writes host-byte-order (LE on x86); to_le_bytes recovers original.
    Some((Ipv4Addr::from(n.to_le_bytes()).to_string(), port))
}

/// Parse "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP" (32 hex chars IPv6 LE words:port).
fn parse_ipv6_addr(s: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if ip_hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in ip_hex.as_bytes().chunks(8).enumerate() {
        let word_str = std::str::from_utf8(chunk).ok()?;
        let word = u32::from_str_radix(word_str, 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    Some((Ipv6Addr::from(bytes).to_string(), port))
}

fn tcp_state(code: u8, proto: &'static str) -> &'static str {
    if proto.starts_with("UDP") {
        return match code {
            7 => "CLOSE",
            _ => "-",
        };
    }
    match code {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        _ => "?",
    }
}

/// Build inode → (pid, process_name) map by scanning /proc/$pid/fd symlinks.
fn build_pid_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let Ok(pid) = fname.to_string_lossy().parse::<u32>() else {
            continue;
        };

        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let Ok(fd_dir) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fd_dir.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                if let Some(inode_str) =
                    t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        map.insert(inode, (pid, comm.clone()));
                    }
                }
            }
        }
    }

    map
}
