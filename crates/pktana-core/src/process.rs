// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Process information tracking for network connections.
//! Maps network sockets to process IDs and names.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
}

/// Socket identifier (IP:port pair)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SocketId {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

impl SocketId {
    pub fn new(local_ip: IpAddr, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        }
    }
}

/// Build a map of socket -> process info by scanning /proc
pub fn build_socket_process_map() -> HashMap<SocketId, ProcessInfo> {
    let mut map = HashMap::new();

    // Scan all PIDs in /proc
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        // Get process name and cmdline
        let name = read_process_name(pid).unwrap_or_else(|| format!("pid-{}", pid));
        let cmdline = read_process_cmdline(pid).unwrap_or_default();

        let proc_info = ProcessInfo { pid, name, cmdline };

        // Scan fd directory for socket file descriptors
        let fd_dir = path.join("fd");
        if let Ok(fds) = fs::read_dir(&fd_dir) {
            for fd_entry in fds.flatten() {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    if let Some(link_str) = link.to_str() {
                        // Socket links look like: socket:[12345] or anon_inode:[12345]
                        if link_str.starts_with("socket:[") {
                            if let Some(inode_str) = link_str
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    // Match inode to socket from /proc/net/tcp, tcp6, udp, udp6
                                    if let Some(socket_id) = find_socket_by_inode(inode) {
                                        map.insert(socket_id, proc_info.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    map
}

/// Read process name from /proc/<pid>/comm
fn read_process_name(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Read process command line from /proc/<pid>/cmdline
fn read_process_cmdline(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|s| {
            s.replace('\0', " ")
                .trim()
                .to_string()
                .chars()
                .take(200)
                .collect()
        })
}

/// Find socket by inode in /proc/net/{tcp,tcp6,udp,udp6}
fn find_socket_by_inode(inode: u64) -> Option<SocketId> {
    // Try TCP first
    if let Some(socket) = parse_net_file("/proc/net/tcp", inode, false) {
        return Some(socket);
    }
    if let Some(socket) = parse_net_file("/proc/net/tcp6", inode, true) {
        return Some(socket);
    }
    // Then UDP
    if let Some(socket) = parse_net_file("/proc/net/udp", inode, false) {
        return Some(socket);
    }
    if let Some(socket) = parse_net_file("/proc/net/udp6", inode, true) {
        return Some(socket);
    }
    None
}

/// Parse /proc/net/tcp or /proc/net/udp file to find socket by inode
fn parse_net_file(path: &str, target_inode: u64, is_ipv6: bool) -> Option<SocketId> {
    let content = fs::read_to_string(path).ok()?;

    for line in content.lines().skip(1) {
        // Skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        // Field 9 is inode
        if let Ok(inode) = fields[9].parse::<u64>() {
            if inode == target_inode {
                // Parse local and remote addresses
                let local = parse_socket_addr(fields[1], is_ipv6)?;
                let remote = parse_socket_addr(fields[2], is_ipv6)?;

                return Some(SocketId {
                    local_ip: local.0,
                    local_port: local.1,
                    remote_ip: remote.0,
                    remote_port: remote.1,
                });
            }
        }
    }

    None
}

/// Parse socket address from hex format "0100007F:0050" (127.0.0.1:80)
fn parse_socket_addr(addr_str: &str, is_ipv6: bool) -> Option<(IpAddr, u16)> {
    let parts: Vec<&str> = addr_str.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip_hex = parts[0];
    let port_hex = parts[1];

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if is_ipv6 {
        // IPv6: 32 hex chars (128 bits) in little-endian byte order
        if ip_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = u8::from_str_radix(&ip_hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        // Reverse for little-endian
        bytes.reverse();
        Some((IpAddr::from(bytes), port))
    } else {
        // IPv4: 8 hex chars (32 bits) in little-endian byte order
        if ip_hex.len() != 8 {
            return None;
        }
        let num = u32::from_str_radix(ip_hex, 16).ok()?;
        let bytes = num.to_le_bytes();
        Some((
            IpAddr::from(std::net::Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )),
            port,
        ))
    }
}

/// Lookup process info for a connection
pub fn lookup_process(
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
) -> Option<ProcessInfo> {
    let map = build_socket_process_map();
    let socket_id = SocketId::new(local_ip, local_port, remote_ip, remote_port);
    map.get(&socket_id).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_addr() {
        // 127.0.0.1:80 in hex is 0100007F:0050
        let result = parse_socket_addr("0100007F:0050", false);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_build_process_map() {
        let map = build_socket_process_map();
        // Should return a map (may be empty if no connections)
        println!("Found {} socket->process mappings", map.len());
    }
}
