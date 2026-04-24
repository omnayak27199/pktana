//! ethtool-equivalent information gathered purely from sysfs / procfs.
//! Covers: driver info, extended statistics, features/offloads,
//!         channel / queue info, link settings, PCIe link status,
//!         carrier-change events, IRQ assignments and permanent MAC.
use std::collections::BTreeMap;
use std::fs;

// ─── public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EthtoolReport {
    pub name:          String,

    // driver info (-i)
    pub driver:        Option<String>,
    pub driver_path:   Option<String>,
    pub firmware_ver:  Option<String>,
    pub bus_info:      Option<String>,
    pub pci_revision:  Option<String>,
    pub irq:           Option<u32>,

    // link settings (-s equivalent)
    pub speed_mbps:    Option<u32>,
    pub duplex:        Option<String>,
    pub autoneg:       Option<String>,
    pub link_mode:     Option<u32>,
    pub operstate:     String,
    pub carrier:       Option<u8>,
    pub tx_queue_len:  Option<u32>,

    // PCIe link
    pub pcie_speed:    Option<String>,
    pub pcie_width:    Option<u32>,

    // carrier history
    pub carrier_up:    Option<u64>,
    pub carrier_down:  Option<u64>,
    pub carrier_changes: Option<u64>,

    // channels / queues (-l equivalent)
    pub rx_queues:     usize,
    pub tx_queues:     usize,
    pub combined_queues: usize,

    // features/offloads (-k equivalent)  feature → "on" | "off" | "n/a" | "fixed"
    pub features:      BTreeMap<String, String>,

    // extended statistics (-S equivalent)
    pub stats:         BTreeMap<String, u64>,

    // IRQ-to-CPU affinity per queue
    pub queue_irq_affinities: Vec<QueueIrq>,
}

#[derive(Debug, Clone)]
pub struct QueueIrq {
    pub queue_name: String,
    pub irq:        u32,
    pub cpu_mask:   String,
    pub cpu_list:   String,
}

// ─── public function ──────────────────────────────────────────────────────────

/// Collect everything ethtool would show for one interface, from sysfs alone.
pub fn get_ethtool_report(name: &str) -> std::io::Result<EthtoolReport> {
    let base   = format!("/sys/class/net/{name}");
    let devdir = format!("{base}/device");

    // ── driver ───────────────────────────────────────────────────────────────
    let driver_link  = fs::read_link(format!("{devdir}/driver")).ok();
    let driver       = driver_link.as_ref()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
    let driver_path  = driver_link.map(|p| p.to_string_lossy().to_string());

    // PCI bus info: the device symlink in /sys/class/net/<ifc>/device resolves
    // to /sys/bus/pci/devices/<addr>, whose last component is the PCI address.
    let bus_info = fs::read_link(&devdir)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));

    // Firmware: check common sysfs paths
    let firmware_ver = fs::read_to_string(format!("{devdir}/firmware_version"))
        .or_else(|_| fs::read_to_string(format!("{devdir}/firmware_revision")))
        .or_else(|_| fs::read_to_string(format!("{devdir}/../firmware_version")))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let pci_revision = fs::read_to_string(format!("{devdir}/revision"))
        .ok().map(|s| s.trim().to_string());

    let irq = fs::read_to_string(format!("{devdir}/irq"))
        .ok().and_then(|s| s.trim().parse::<u32>().ok());

    // ── link settings ────────────────────────────────────────────────────────
    let speed_mbps = read_u32(&base, "speed").and_then(|v| if v == 0 { None } else { Some(v) });
    let duplex     = sysfs_str(&base, "duplex");
    let autoneg    = sysfs_str(&base, "autoneg");
    let link_mode  = read_u32(&base, "link_mode");
    let operstate  = sysfs_str(&base, "operstate").unwrap_or_else(|| "unknown".into());
    let carrier    = sysfs_str(&base, "carrier").and_then(|s| s.parse::<u8>().ok());
    let tx_queue_len = read_u32(&base, "tx_queue_len");

    // PCIe link
    let pcie_speed = sysfs_str(&devdir, "current_link_speed");
    let pcie_width = sysfs_str(&devdir, "current_link_width")
        .and_then(|s| s.parse::<u32>().ok());

    // ── carrier events ───────────────────────────────────────────────────────
    let carrier_up      = read_u64(&base, "carrier_up_count");
    let carrier_down    = read_u64(&base, "carrier_down_count");
    let carrier_changes = read_u64(&base, "carrier_changes");

    // ── channels / queues ─────────────────────────────────────────────────────
    let (rx_queues, tx_queues, combined_queues) = count_queues(&base);

    // ── features / offloads ──────────────────────────────────────────────────
    let features = read_features(&base);

    // ── extended statistics ──────────────────────────────────────────────────
    let stats = read_statistics(&base);

    // ── per-queue IRQ affinities ──────────────────────────────────────────────
    let queue_irq_affinities = read_queue_irqs(name, &base);

    Ok(EthtoolReport {
        name: name.to_string(),
        driver, driver_path, firmware_ver, bus_info,
        pci_revision, irq,
        speed_mbps, duplex, autoneg, link_mode, operstate,
        carrier, tx_queue_len,
        pcie_speed, pcie_width,
        carrier_up, carrier_down, carrier_changes,
        rx_queues, tx_queues, combined_queues,
        features, stats,
        queue_irq_affinities,
    })
}

// ─── internal helpers ─────────────────────────────────────────────────────────

fn sysfs_str(base: &str, file: &str) -> Option<String> {
    fs::read_to_string(format!("{base}/{file}"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_u32(base: &str, file: &str) -> Option<u32> {
    sysfs_str(base, file)?.parse::<i64>().ok()
        .filter(|&v| v >= 0)
        .map(|v| v as u32)
}

fn read_u64(base: &str, file: &str) -> Option<u64> {
    sysfs_str(base, file)?.parse().ok()
}

/// `/sys/class/net/<ifc>/queues/rx-N` and `tx-N` directories.
fn count_queues(base: &str) -> (usize, usize, usize) {
    let Ok(entries) = fs::read_dir(format!("{base}/queues")) else {
        return (0, 0, 0);
    };
    let mut rx = 0usize;
    let mut tx = 0usize;
    for e in entries.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with("rx-") { rx += 1; }
        if n.starts_with("tx-") { tx += 1; }
    }
    (rx, tx, rx.min(tx))
}

/// `/sys/class/net/<ifc>/features` — each line: `<feature> <state>`
fn read_features(base: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Ok(content) = fs::read_to_string(format!("{base}/features")) else {
        return map;
    };
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(feat), Some(state)) = (parts.next(), parts.next()) {
            map.insert(feat.to_string(), state.to_string());
        }
    }
    map
}

/// `/sys/class/net/<ifc>/statistics/<counter>` — one value per file.
fn read_statistics(base: &str) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    let Ok(entries) = fs::read_dir(format!("{base}/statistics")) else {
        return map;
    };
    for entry in entries.flatten() {
        let key = entry.file_name().to_string_lossy().to_string();
        if let Ok(val) = fs::read_to_string(entry.path()) {
            if let Ok(n) = val.trim().parse::<u64>() {
                map.insert(key, n);
            }
        }
    }
    map
}

/// Read per-queue IRQ numbers from `/sys/class/net/<ifc>/queues/rx-N/rps_cpus`
/// and correlate them with `/proc/irq/N/smp_affinity` + `/proc/irq/N/node`.
/// Queue IRQ numbers come from `/sys/class/net/<ifc>/queues/rx-N` — but getting
/// the *IRQ number* for a queue requires reading `/proc/interrupts` and matching
/// the interface name.
fn read_queue_irqs(name: &str, base: &str) -> Vec<QueueIrq> {
    // Build map: irq_num → (cpu_mask, cpu_list) from /proc/irq/
    let mut irq_info: std::collections::HashMap<u32, (String, String)> =
        std::collections::HashMap::new();

    // Parse /proc/interrupts to extract per-queue IRQs for this interface.
    // Format: " IRQ_NUM:  count  ...  driver  <name>-<queue>"
    let Ok(content) = fs::read_to_string("/proc/interrupts") else {
        return Vec::new();
    };

    let mut result = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim_start();
        // Split off the IRQ number (ends with ':')
        let Some(colon) = trimmed.find(':') else { continue };
        let irq_str = trimmed[..colon].trim();
        let Ok(irq_num) = irq_str.parse::<u32>() else { continue };
        let rest = &trimmed[colon + 1..];

        // Look for the interface name in the description (last field)
        let parts: Vec<&str> = rest.split_whitespace().collect();
        let Some(desc) = parts.last() else { continue };
        if !desc.contains(name) { continue };

        // Determine queue name from the description suffix (e.g. "eth0-rx-0")
        let queue_name = desc.to_string();

        // Read affinity mask from /proc/irq/<N>/smp_affinity
        let cpu_mask = fs::read_to_string(format!("/proc/irq/{irq_num}/smp_affinity"))
            .unwrap_or_default()
            .trim()
            .to_string();

        // Read affinity list from /proc/irq/<N>/smp_affinity_list
        let cpu_list = fs::read_to_string(format!("/proc/irq/{irq_num}/smp_affinity_list"))
            .unwrap_or_default()
            .trim()
            .to_string();

        if !irq_info.contains_key(&irq_num) {
            irq_info.insert(irq_num, (cpu_mask.clone(), cpu_list.clone()));
        }

        result.push(QueueIrq {
            queue_name,
            irq: irq_num,
            cpu_mask,
            cpu_list,
        });
    }

    // Also read RPS (Receive Packet Steering) config per RX queue
    if let Ok(entries) = fs::read_dir(format!("{base}/queues")) {
        for entry in entries.flatten() {
            let qname = entry.file_name().to_string_lossy().to_string();
            if !qname.starts_with("rx-") { continue; }
            let rps = fs::read_to_string(entry.path().join("rps_cpus"))
                .unwrap_or_default();
            let rps = rps.trim();
            if rps != "0" && !rps.is_empty() {
                result.push(QueueIrq {
                    queue_name: format!("{name}/{qname} (RPS)"),
                    irq:        0,
                    cpu_mask:   rps.to_string(),
                    cpu_list:   "RPS".to_string(),
                });
            }
        }
    }

    result
}
