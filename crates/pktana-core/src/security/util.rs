// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use crate::dpi::DeepPacket;
use crate::geoip::lookup;

pub fn endpoint(dp: &DeepPacket, src: bool) -> String {
    if src {
        if let Some(ip) = dp.ip_src {
            let port = dp.tcp_src_port.or(dp.udp_src_port);
            return match port {
                Some(p) => format!("{ip}:{p}"),
                None => ip.to_string(),
            };
        }
        return dp.eth_src.clone();
    }
    if let Some(ip) = dp.ip_dst {
        let port = dp.tcp_dst_port.or(dp.udp_dst_port);
        return match port {
            Some(p) => format!("{ip}:{p}"),
            None => ip.to_string(),
        };
    }
    dp.eth_dst.clone()
}

pub fn ip_host(endpoint: &str) -> String {
    endpoint.split(':').next().unwrap_or(endpoint).to_string()
}

pub fn endpoint_country(dp: &DeepPacket, src: bool) -> String {
    let ip = if src { dp.ip_src } else { dp.ip_dst };
    ip.and_then(|i| lookup(std::net::IpAddr::V4(i)))
        .map(|g| g.country_code.to_string())
        .unwrap_or_default()
}

pub fn proto_label(dp: &DeepPacket) -> String {
    dp.app_proto.clone().unwrap_or_else(|| {
        dp.ip_proto_name
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".into())
    })
}

pub fn make_flow_key(proto: &str, src: &str, dst: &str) -> String {
    format!("{proto}|{src}|{dst}")
}

pub fn payload_snippet(dp: &DeepPacket) -> String {
    if !dp.app_detail.is_empty() {
        return dp.app_detail.join("\n");
    }
    String::from_utf8_lossy(&dp.payload).into_owned()
}
