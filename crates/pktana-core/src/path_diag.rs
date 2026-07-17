// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! End-to-end network path diagnostics for one interface.

use std::io;
use std::path::Path;

use crate::connections::list_connections;
use crate::dp::{find_pinned_bpf_for_iface, inspect_ebpf_interface, list_xdp_dispatchers};
use crate::nic::{get_nic_dataplane, get_nic_info, BypassMode};
use crate::routes::{list_routes, RouteEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone)]
pub struct PathIssue {
    pub severity: IssueSeverity,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PathDiagnostic {
    pub iface: String,
    pub nic_up: bool,
    pub carrier_ok: bool,
    pub issues: Vec<PathIssue>,
    pub recommendations: Vec<String>,
    pub bypass_mode: String,
    pub ebpf_active: bool,
    pub capture_possible: bool,
    pub route_count: usize,
    pub default_route_iface: Option<String>,
    pub listener_count: usize,
    pub established_count: usize,
    pub pinned_bpf_count: usize,
    pub xdp_dispatcher_count: usize,
}

pub fn diagnose_path(iface: &str) -> io::Result<PathDiagnostic> {
    if !Path::new(&format!("/sys/class/net/{iface}")).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface '{iface}' not found"),
        ));
    }

    let nic = get_nic_info(iface)?;
    let dp = get_nic_dataplane(iface)?;
    let ebpf = inspect_ebpf_interface(iface).ok();

    let nic_up = nic.is_up();
    let carrier_ok = nic.state == "up" || nic.state == "unknown";
    let ebpf_active = ebpf.as_ref().is_some_and(|r| r.ebpf_active());
    let pinned_bpf_count = ebpf
        .as_ref()
        .map(|r| r.pinned_matches.len())
        .unwrap_or_else(|| find_pinned_bpf_for_iface(iface).len());

    let xdp_dispatcher_count = list_xdp_dispatchers()
        .iter()
        .filter(|d| d.iface.as_deref() == Some(iface))
        .count();

    let all_routes = list_routes();
    let routes: Vec<&RouteEntry> = all_routes.iter().filter(|r| r.interface == iface).collect();
    let (listener_count, established_count) = socket_counts();

    let mut issues = Vec::new();
    let mut recommendations = Vec::new();

    if !nic_up {
        issues.push(PathIssue {
            severity: IssueSeverity::Critical,
            code: "iface_down".into(),
            message: format!("Interface {iface} is administratively DOWN"),
        });
        recommendations.push(format!("Bring interface up: ip link set {iface} up"));
    }

    if dp.dpdk_bound {
        issues.push(PathIssue {
            severity: IssueSeverity::Critical,
            code: "dpdk_bound".into(),
            message: format!(
                "NIC bound to userspace driver ({}) — kernel capture will see no traffic",
                dp.userspace_driver.as_deref().unwrap_or("unknown")
            ),
        });
        recommendations
            .push("Use DPDK-aware capture or unbind from vfio/uio to inspect kernel path".into());
    }

    if matches!(dp.bypass_mode, BypassMode::Xdp | BypassMode::Hybrid) {
        issues.push(PathIssue {
            severity: IssueSeverity::Info,
            code: "xdp_active".into(),
            message: "XDP eBPF program attached — some packets may bypass normal stack".into(),
        });
    }

    if ebpf_active && dp.xdp_prog_ids.is_empty() && pinned_bpf_count > 0 {
        issues.push(PathIssue {
            severity: IssueSeverity::Warning,
            code: "pinned_only".into(),
            message: format!(
                "{pinned_bpf_count} pinned BPF object(s) correlate with this interface but no XDP/TC IDs resolved via sysfs"
            ),
        });
        recommendations.push(format!("Verify with: bpftool net show dev {iface}"));
    }

    if routes.is_empty() && !nic.is_loopback() {
        issues.push(PathIssue {
            severity: IssueSeverity::Warning,
            code: "no_routes".into(),
            message: format!("No routes egress via {iface}"),
        });
    }

    if nic.rx_dropped > 0 || nic.tx_dropped > 0 {
        issues.push(PathIssue {
            severity: IssueSeverity::Warning,
            code: "drops".into(),
            message: format!(
                "Interface drops: rx_dropped={} tx_dropped={}",
                nic.rx_dropped, nic.tx_dropped
            ),
        });
    }

    let capture_possible = nic_up && !dp.dpdk_bound;
    let default_route_iface = list_routes()
        .into_iter()
        .find(|r| r.is_default)
        .map(|r| r.interface);

    Ok(PathDiagnostic {
        iface: iface.to_string(),
        nic_up,
        carrier_ok,
        issues,
        recommendations,
        bypass_mode: format!("{}", dp.bypass_mode),
        ebpf_active,
        capture_possible,
        route_count: routes.len(),
        default_route_iface,
        listener_count,
        established_count,
        pinned_bpf_count,
        xdp_dispatcher_count,
    })
}

fn socket_counts() -> (usize, usize) {
    let conns = list_connections();
    let listeners = conns.iter().filter(|c| c.state == "LISTEN").count();
    let established = conns.iter().filter(|c| c.state == "ESTABLISHED").count();
    (listeners, established)
}
