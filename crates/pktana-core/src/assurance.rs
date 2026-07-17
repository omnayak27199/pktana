// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Dataplane assurance: baseline snapshots and drift detection for eBPF/XDP/TC state.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::dp::inspect_ebpf_interface;
use crate::nic::get_nic_dataplane;

const SNAPSHOT_VERSION: u32 = 1;

/// Point-in-time dataplane state for one interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataplaneSnapshot {
    pub version: u32,
    pub captured_at: u64,
    pub hostname: String,
    pub iface: String,
    pub bypass_mode: String,
    pub xdp_prog_ids: Vec<u32>,
    pub xdp_mode: Option<String>,
    pub tc_prog_ids: Vec<u32>,
    pub tc_clsact: bool,
    pub tc_directions: Vec<String>,
    pub pinned_paths: Vec<String>,
    pub ebpf_active: bool,
    pub iface_kind: String,
    pub dpdk_bound: bool,
}

/// One detected change between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDiff {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Capture current dataplane state for one interface.
pub fn capture_snapshot(iface: &str) -> io::Result<DataplaneSnapshot> {
    let dp = get_nic_dataplane(iface)?;
    let ebpf = inspect_ebpf_interface(iface).ok();

    let (
        xdp_prog_ids,
        xdp_mode,
        tc_prog_ids,
        tc_clsact,
        tc_directions,
        pinned_paths,
        ebpf_active,
        iface_kind,
    ) = if let Some(ref r) = ebpf {
        (
            r.xdp_prog_ids.clone(),
            r.xdp_mode.clone(),
            r.tc.prog_ids.clone(),
            r.tc.clsact,
            r.tc.directions.clone(),
            r.pinned_matches.iter().map(|p| p.path.clone()).collect(),
            r.ebpf_active(),
            r.iface_kind.clone(),
        )
    } else {
        (
            dp.xdp_prog_ids.clone(),
            dp.xdp_mode.clone(),
            dp.tc_bpf_prog_ids.clone(),
            dp.tc_clsact,
            dp.tc_bpf_directions.clone(),
            Vec::new(),
            !dp.xdp_prog_ids.is_empty() || dp.tc_clsact,
            String::new(),
        )
    };

    Ok(DataplaneSnapshot {
        version: SNAPSHOT_VERSION,
        captured_at: unix_now(),
        hostname: read_hostname(),
        iface: iface.to_string(),
        bypass_mode: format!("{}", dp.bypass_mode),
        xdp_prog_ids,
        xdp_mode,
        tc_prog_ids,
        tc_clsact,
        tc_directions,
        pinned_paths,
        ebpf_active,
        iface_kind,
        dpdk_bound: dp.dpdk_bound,
    })
}

/// Capture snapshots for every interface under /sys/class/net.
pub fn capture_host_snapshots() -> Vec<DataplaneSnapshot> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut snaps = Vec::new();
    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().to_string();
        if let Ok(s) = capture_snapshot(&iface) {
            snaps.push(s);
        }
    }
    snaps.sort_by(|a, b| a.iface.cmp(&b.iface));
    snaps
}

/// Save one snapshot to a JSON file.
pub fn save_snapshot(path: &Path, snap: &DataplaneSnapshot) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(snap)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(path, json)
}

/// Load a snapshot from JSON.
pub fn load_snapshot(path: &Path) -> io::Result<DataplaneSnapshot> {
    let content = fs::read_to_string(path)?;
    serde_json::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Load all `*.json` snapshots from a baseline directory keyed by interface name.
pub fn load_baseline_dir(dir: &Path) -> io::Result<HashMap<String, DataplaneSnapshot>> {
    let mut map = HashMap::new();
    if !dir.exists() {
        return Ok(map);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(snap) = load_snapshot(&path) {
            map.insert(snap.iface.clone(), snap);
        }
    }
    Ok(map)
}

/// Save host-wide baseline (one file per interface).
pub fn save_baseline_dir(dir: &Path) -> io::Result<usize> {
    let snaps = capture_host_snapshots();
    for snap in &snaps {
        let path = dir.join(format!("{}.json", snap.iface));
        save_snapshot(&path, snap)?;
    }
    Ok(snaps.len())
}

/// Compare two snapshots and return human-readable diffs.
pub fn diff_snapshots(old: &DataplaneSnapshot, new: &DataplaneSnapshot) -> Vec<SnapshotDiff> {
    let mut diffs = Vec::new();

    macro_rules! diff_field {
        ($field:expr, $old:expr, $new:expr) => {
            if $old != $new {
                diffs.push(SnapshotDiff {
                    field: $field.to_string(),
                    old_value: $old.to_string(),
                    new_value: $new.to_string(),
                });
            }
        };
    }

    diff_field!("bypass_mode", old.bypass_mode, new.bypass_mode);
    diff_field!("ebpf_active", old.ebpf_active, new.ebpf_active);
    diff_field!("dpdk_bound", old.dpdk_bound, new.dpdk_bound);
    diff_field!(
        "xdp_prog_ids",
        fmt_ids(&old.xdp_prog_ids),
        fmt_ids(&new.xdp_prog_ids)
    );
    diff_field!(
        "xdp_mode",
        old.xdp_mode.as_deref().unwrap_or("—"),
        new.xdp_mode.as_deref().unwrap_or("—")
    );
    diff_field!("tc_clsact", old.tc_clsact, new.tc_clsact);
    diff_field!(
        "tc_prog_ids",
        fmt_ids(&old.tc_prog_ids),
        fmt_ids(&new.tc_prog_ids)
    );
    diff_field!(
        "tc_directions",
        old.tc_directions.join(","),
        new.tc_directions.join(",")
    );
    diff_field!(
        "pinned_paths",
        old.pinned_paths.join(";"),
        new.pinned_paths.join(";")
    );

    diffs
}

/// Check one interface against its baseline file; returns current snapshot + diffs.
pub fn check_drift(
    baseline_dir: &Path,
    iface: &str,
) -> io::Result<(DataplaneSnapshot, Vec<SnapshotDiff>)> {
    let baseline_path = baseline_dir.join(format!("{iface}.json"));
    let current = capture_snapshot(iface)?;
    if !baseline_path.exists() {
        return Ok((current, Vec::new()));
    }
    let baseline = load_snapshot(&baseline_path)?;
    Ok((current.clone(), diff_snapshots(&baseline, &current)))
}

/// Default baseline storage path.
pub fn default_baseline_dir() -> PathBuf {
    PathBuf::from("/var/lib/pktana/baselines")
}

fn fmt_ids(ids: &[u32]) -> String {
    if ids.is_empty() {
        "none".to_string()
    } else {
        ids.iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_detects_xdp_change() {
        let old = DataplaneSnapshot {
            version: 1,
            captured_at: 0,
            hostname: "h".into(),
            iface: "eth0".into(),
            bypass_mode: "Kernel stack (no bypass)".into(),
            xdp_prog_ids: vec![42],
            xdp_mode: Some("native".into()),
            tc_prog_ids: vec![],
            tc_clsact: false,
            tc_directions: vec![],
            pinned_paths: vec![],
            ebpf_active: true,
            iface_kind: "phy".into(),
            dpdk_bound: false,
        };
        let mut new = old.clone();
        new.xdp_prog_ids = vec![99];
        let diffs = diff_snapshots(&old, &new);
        assert!(diffs.iter().any(|d| d.field == "xdp_prog_ids"));
    }
}
