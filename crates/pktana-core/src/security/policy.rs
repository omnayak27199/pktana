// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use super::types::SecurityPolicyRule;

#[derive(Copy, Clone)]
pub(crate) struct PolicyMatchCtx<'a> {
    pub iface: &'a str,
    pub rule_id: &'a str,
    pub src_ip: &'a str,
    pub dst_ip: &'a str,
    pub src_country: &'a str,
    pub dst_country: &'a str,
}

pub(crate) fn policy_matches(
    rule: &SecurityPolicyRule,
    engine: &str,
    ctx: &PolicyMatchCtx<'_>,
) -> bool {
    if !rule.enabled {
        return false;
    }
    if rule.engine != "any" && rule.engine != engine {
        return false;
    }
    if !rule.interface.is_empty() && rule.interface != ctx.iface {
        return false;
    }
    if !ip_matches(&rule.src_ip, ctx.src_ip) {
        return false;
    }
    if !ip_matches(&rule.dst_ip, ctx.dst_ip) {
        return false;
    }
    if !country_matches(&rule.src_country, ctx.src_country) {
        return false;
    }
    if !country_matches(&rule.dst_country, ctx.dst_country) {
        return false;
    }
    rule.detection_rule.is_empty() || rule.detection_rule == ctx.rule_id
}

fn country_matches(spec: &str, country: &str) -> bool {
    spec.is_empty() || spec.eq_ignore_ascii_case(country)
}

fn ip_matches(spec: &str, ip: &str) -> bool {
    if spec.is_empty() {
        return true;
    }
    let Some(addr) = ip.parse::<Ipv4Addr>().ok() else {
        return false;
    };
    if spec.contains('/') {
        ip_in_cidr(addr, spec)
    } else if let Ok(want) = spec.parse::<Ipv4Addr>() {
        addr == want
    } else {
        false
    }
}

pub(crate) fn ip_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}
