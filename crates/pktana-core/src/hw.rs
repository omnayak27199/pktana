// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

/// Extended hardware profile for a network interface.
/// Reads bridge, bonding, PTP, and IOMMU info from /sys/.
use std::fs;
use std::path::Path;

// ─── Bridge ───────────────────────────────────────────────────────────────────

/// Bridge configuration read from /sys/class/net/<ifc>/bridge/.
#[derive(Debug, Clone)]
pub struct BridgeInfo {
    /// Bridge ID in 802.1D format, e.g. "8000.0cc47a786ffa".
    pub bridge_id: String,
    /// STP state: 0=disabled, 1=enabled.
    pub stp_enabled: bool,
    /// Whether VLAN filtering is active.
    pub vlan_filtering: bool,
    /// MAC ageing time in jiffies (divide by 100 for seconds on most kernels).
    pub ageing_time_jiffies: u32,
    /// Port interface names currently enslaved to this bridge.
    pub ports: Vec<String>,
}

/// Read bridge info for an interface that IS a bridge master.
/// Returns None if /sys/class/net/<ifc>/bridge/ does not exist.
pub fn get_bridge_info(iface: &str) -> Option<BridgeInfo> {
    let bridge_dir = format!("/sys/class/net/{iface}/bridge");
    if !Path::new(&bridge_dir).exists() {
        return None;
    }

    let read = |file: &str| -> String {
        fs::read_to_string(format!("{bridge_dir}/{file}"))
            .unwrap_or_default()
            .trim()
            .to_string()
    };

    let bridge_id = read("bridge_id");
    let stp_enabled = read("stp_state") == "1";
    let vlan_filtering = read("vlan_filtering") == "1";
    let ageing_time_jiffies = read("ageing_time").parse().unwrap_or(0);

    // Enumerate port interfaces: each /sys/class/net/<port>/brport/bridge
    // symlink points to this bridge. Simpler: look for ifaces whose master == iface.
    let ports = read_bridge_ports(iface);

    Some(BridgeInfo {
        bridge_id,
        stp_enabled,
        vlan_filtering,
        ageing_time_jiffies,
        ports,
    })
}

/// Bridge-port state for an interface that is enslaved to a bridge.
#[derive(Debug, Clone)]
pub struct BridgePortInfo {
    /// Name of the bridge this port belongs to.
    pub bridge: String,
    /// STP port state: 0=disabled, 1=listening, 2=learning, 3=forwarding, 4=blocking.
    pub stp_state: u8,
    /// Port ID in hex, e.g. "0x8001".
    pub port_id: String,
    /// Path cost for STP.
    pub path_cost: u32,
    /// Whether hairpin mode is on (needed for proxies/reflectors).
    pub hairpin: bool,
    /// Whether learning is enabled.
    pub learning: bool,
}

/// Read bridge-port info for an interface enslaved to a bridge.
pub fn get_bridge_port_info(iface: &str) -> Option<BridgePortInfo> {
    let brport_dir = format!("/sys/class/net/{iface}/brport");
    if !Path::new(&brport_dir).exists() {
        return None;
    }

    let read = |file: &str| -> String {
        fs::read_to_string(format!("{brport_dir}/{file}"))
            .unwrap_or_default()
            .trim()
            .to_string()
    };

    // Resolve the bridge name via the "bridge" symlink inside brport/.
    let bridge = fs::read_link(format!("{brport_dir}/bridge"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_default();

    let stp_state = read("state").parse().unwrap_or(0);
    let port_id = read("port_id");
    let path_cost = read("path_cost").parse().unwrap_or(0);
    let hairpin = read("hairpin_mode") == "1";
    let learning = read("learning") == "1";

    Some(BridgePortInfo {
        bridge,
        stp_state,
        port_id,
        path_cost,
        hairpin,
        learning,
    })
}

// ─── Bonding ──────────────────────────────────────────────────────────────────

/// Bond master info read from /sys/class/net/<ifc>/bonding/.
#[derive(Debug, Clone)]
pub struct BondInfo {
    /// Active-backup, 802.3ad, balance-rr, etc.
    pub mode: String,
    /// Currently active slave interface name (active-backup only).
    pub active_slave: Option<String>,
    /// All slave interface names.
    pub slaves: Vec<String>,
    /// MII monitoring interval in ms (0 = disabled).
    pub miimon: u32,
    /// Link failure count across all slaves.
    pub link_failures: u32,
}

/// Read bond info for an interface that IS a bond master.
pub fn get_bond_info(iface: &str) -> Option<BondInfo> {
    let bond_dir = format!("/sys/class/net/{iface}/bonding");
    if !Path::new(&bond_dir).exists() {
        return None;
    }

    let read = |file: &str| -> String {
        fs::read_to_string(format!("{bond_dir}/{file}"))
            .unwrap_or_default()
            .trim()
            .to_string()
    };

    let mode = read("mode");
    let active_slave = {
        let s = read("active_slave");
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    };
    let slaves: Vec<String> = read("slaves")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let miimon = read("miimon").parse().unwrap_or(0);

    // Sum link_failures across all slave interfaces.
    let link_failures: u32 = slaves
        .iter()
        .map(|slave| {
            fs::read_to_string(format!(
                "/sys/class/net/{slave}/bonding_slave/link_failure_count"
            ))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
        })
        .sum();

    Some(BondInfo {
        mode,
        active_slave,
        slaves,
        miimon,
        link_failures,
    })
}

// ─── PTP hardware clocks ─────────────────────────────────────────────────────

/// One PTP hardware clock associated with a network interface.
#[derive(Debug, Clone)]
pub struct PtpClock {
    /// PTP device name, e.g. "ptp0".
    pub device: String,
    /// Clock name reported by the driver, e.g. "ICE-1588".
    pub clock_name: String,
    /// Maximum frequency adjustment in ppb.
    pub max_adj_ppb: i64,
    /// Number of external timestamp inputs.
    pub n_extts: u32,
    /// Number of programmable periodic outputs.
    pub n_periodic_outputs: u32,
}

/// Find PTP clocks associated with a NIC via
/// /sys/class/net/<iface>/device/ptp/ptp*/
pub fn get_ptp_clocks(iface: &str) -> Vec<PtpClock> {
    let ptp_dir = format!("/sys/class/net/{iface}/device/ptp");
    let Ok(entries) = fs::read_dir(&ptp_dir) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let device = entry.file_name().to_string_lossy().to_string();
            if !device.starts_with("ptp") {
                return None;
            }
            let path = format!("/sys/class/ptp/{device}");
            let read = |f: &str| -> String {
                fs::read_to_string(format!("{path}/{f}"))
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            Some(PtpClock {
                device: device.clone(),
                clock_name: read("clock_name"),
                max_adj_ppb: read("max_adjustment").parse().unwrap_or(0),
                n_extts: read("n_external_timestamps").parse().unwrap_or(0),
                n_periodic_outputs: read("n_periodic_outputs").parse().unwrap_or(0),
            })
        })
        .collect()
}

// ─── IOMMU group ─────────────────────────────────────────────────────────────

/// IOMMU group membership for a PCI device — critical for SR-IOV and DPDK/VFIO.
#[derive(Debug, Clone)]
pub struct IommuGroup {
    /// Group number, e.g. 14.
    pub group_id: u32,
    /// PCI addresses of all devices sharing this IOMMU group.
    pub members: Vec<String>,
}

/// Read IOMMU group for the PCI device backing `iface`.
pub fn get_iommu_group(iface: &str) -> Option<IommuGroup> {
    // Resolve PCI address from the device symlink.
    let pci_addr = fs::read_link(format!("/sys/class/net/{iface}/device"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))?;

    // /sys/bus/pci/devices/<addr>/iommu_group -> symlink to /sys/kernel/iommu_groups/N
    let group_link = format!("/sys/bus/pci/devices/{pci_addr}/iommu_group");
    let group_path = fs::read_link(&group_link).ok()?;
    let group_id: u32 = group_path.file_name()?.to_string_lossy().parse().ok()?;

    // List all devices in the group.
    let devices_dir = format!("/sys/kernel/iommu_groups/{group_id}/devices");
    let members: Vec<String> = fs::read_dir(&devices_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    Some(IommuGroup { group_id, members })
}

// ─── helper ───────────────────────────────────────────────────────────────────

fn read_bridge_ports(bridge: &str) -> Vec<String> {
    let Ok(net_dir) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    net_dir
        .flatten()
        .filter_map(|entry| {
            let iface = entry.file_name().to_string_lossy().to_string();
            // A port has a "master" symlink that resolves to the bridge name.
            let master = fs::read_link(format!("/sys/class/net/{iface}/master"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))?;
            if master == bridge {
                Some(iface)
            } else {
                None
            }
        })
        .collect()
}

/// STP state number → human label.
pub fn stp_state_label(state: u8) -> &'static str {
    match state {
        0 => "disabled",
        1 => "listening",
        2 => "learning",
        3 => "forwarding",
        4 => "blocking",
        _ => "unknown",
    }
}
