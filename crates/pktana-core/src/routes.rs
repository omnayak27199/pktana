// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Routing table reader — pure /proc/net/route + /proc/net/ipv6_route.
//! No external commands (ip route, netstat -r) required.
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

/// One entry from the kernel routing table.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Network interface this route goes out of.
    pub interface: String,
    /// Destination network (e.g. "10.0.0.0").
    pub destination: String,
    /// Prefix length (e.g. 24 for /24, 0 for default route).
    pub prefix_len: u8,
    /// Next-hop gateway ("0.0.0.0" / "::" means directly connected).
    pub gateway: String,
    /// Route metric / distance.
    pub metric: u32,
    /// "connected" | "via <gateway>" | "default via <gateway>"
    pub summary: String,
    /// true = default route (0.0.0.0/0 or ::/0).
    pub is_default: bool,
}

/// Read all IPv4 and IPv6 routes for every interface.
pub fn list_routes() -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    routes.extend(read_ipv4_routes());
    routes.extend(read_ipv6_routes());
    // Sort: default routes last, then by interface name, then prefix length descending.
    routes.sort_by(|a, b| {
        a.is_default
            .cmp(&b.is_default)
            .then(a.interface.cmp(&b.interface))
            .then(b.prefix_len.cmp(&a.prefix_len))
    });
    routes
}

/// Read routes that go out of the named interface only.
pub fn routes_for_iface(name: &str) -> Vec<RouteEntry> {
    list_routes()
        .into_iter()
        .filter(|r| r.interface == name)
        .collect()
}

// ─── IPv4 ────────────────────────────────────────────────────────────────────
// /proc/net/route columns (hex, host-byte-order):
// Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
fn read_ipv4_routes() -> Vec<RouteEntry> {
    let Ok(content) = fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };

    let mut routes = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 11 {
            continue;
        }

        let iface = cols[0].to_string();
        let dest_n = u32::from_str_radix(cols[1], 16).unwrap_or(0);
        let gw_n = u32::from_str_radix(cols[2], 16).unwrap_or(0);
        let mask_n = u32::from_str_radix(cols[7], 16).unwrap_or(0);
        let metric = u32::from_str_radix(cols[6], 16).unwrap_or(0);

        let dest_ip = Ipv4Addr::from(dest_n.to_le_bytes());
        let gw_ip = Ipv4Addr::from(gw_n.to_le_bytes());
        let prefix = mask_to_prefix_v4(mask_n);
        let is_def = dest_n == 0 && mask_n == 0;
        let gw_str = gw_ip.to_string();
        let gw_zero = gw_n == 0;

        let summary = if is_def {
            format!("default via {gw_str}")
        } else if gw_zero {
            "directly connected".to_string()
        } else {
            format!("via {gw_str}")
        };

        routes.push(RouteEntry {
            interface: iface,
            destination: dest_ip.to_string(),
            prefix_len: prefix,
            gateway: gw_str,
            metric,
            summary,
            is_default: is_def,
        });
    }
    routes
}

// ─── IPv6 ────────────────────────────────────────────────────────────────────
// /proc/net/ipv6_route columns (hex):
// dest/plen src/plen nexthop metric refcnt use flags iface
fn read_ipv6_routes() -> Vec<RouteEntry> {
    let Ok(content) = fs::read_to_string("/proc/net/ipv6_route") else {
        return Vec::new();
    };

    let mut routes = Vec::new();
    for line in content.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }

        let dest_hex = cols[0];
        let plen: u8 = u8::from_str_radix(cols[1], 16).unwrap_or(0);
        let gw_hex = cols[4];
        let metric = u32::from_str_radix(cols[5], 16).unwrap_or(0);
        let iface = cols[9].to_string();

        // Skip local / loopback-only routes produced by the kernel
        let flags_raw = u32::from_str_radix(cols[8], 16).unwrap_or(0);
        // RTF_LOCAL = 0x80000000
        if flags_raw & 0x80000000 != 0 {
            continue;
        }

        let dest_ip = parse_ipv6_hex(dest_hex);
        let gw_ip = parse_ipv6_hex(gw_hex);
        let is_def = plen == 0 && dest_hex == "00000000000000000000000000000000";
        let gw_zero = gw_hex == "00000000000000000000000000000000";
        let gw_str = gw_ip.to_string();

        let summary = if is_def {
            format!("default via {gw_str}")
        } else if gw_zero {
            "directly connected".to_string()
        } else {
            format!("via {gw_str}")
        };

        routes.push(RouteEntry {
            interface: iface,
            destination: dest_ip.to_string(),
            prefix_len: plen,
            gateway: gw_str,
            metric,
            summary,
            is_default: is_def,
        });
    }
    routes
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn mask_to_prefix_v4(mask: u32) -> u8 {
    mask.count_ones() as u8
}

fn parse_ipv6_hex(s: &str) -> Ipv6Addr {
    if s.len() != 32 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if let Ok(b) = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("00"), 16) {
            bytes[i] = b;
        }
    }
    Ipv6Addr::from(bytes)
}
