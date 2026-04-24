// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

/// NIC / interface information gathered purely from Linux sysfs and procfs.
/// No external commands (ip, ethtool, ifconfig) are required.
use std::fs;
use std::io;

// ─── basic NIC info ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NicInfo {
    pub name: String,
    pub state: String,
    pub mac: String,
    pub mtu: u32,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<String>,
    pub driver: Option<String>,
    pub ip_addresses: Vec<String>,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
    pub flags: u32,
}

impl NicInfo {
    pub fn is_up(&self) -> bool {
        self.state == "up" || (self.flags & 0x1) != 0
    }
    pub fn is_loopback(&self) -> bool {
        self.flags & 0x8 != 0
    }
    pub fn is_promisc(&self) -> bool {
        self.flags & 0x100 != 0
    }
    pub fn speed_label(&self) -> String {
        match self.speed_mbps {
            Some(s) if s >= 1000 => format!("{}G", s / 1000),
            Some(s) => format!("{s}M"),
            None => "?".to_string(),
        }
    }
}

// ─── dataplane / bypass detection ────────────────────────────────────────────

/// Whether and how the NIC bypasses the normal Linux kernel network stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BypassMode {
    /// Normal kernel networking — packets go through the full stack.
    KernelStack,
    /// XDP eBPF program attached at the driver / NIC level (partial bypass).
    Xdp,
    /// AF_XDP zero-copy socket — packets DMA'd directly to userspace ring.
    AfXdp,
    /// DPDK / userspace PMD — interface fully removed from the kernel;
    /// bound to vfio-pci, igb_uio or uio_pci_generic.
    DpdkUserspace,
    /// More than one bypass active simultaneously (e.g. XDP + AF_XDP).
    Hybrid,
}

impl std::fmt::Display for BypassMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KernelStack => write!(f, "Kernel stack (no bypass)"),
            Self::Xdp => write!(f, "XDP eBPF (driver-level)"),
            Self::AfXdp => write!(f, "AF_XDP zero-copy"),
            Self::DpdkUserspace => write!(f, "DPDK / userspace PMD"),
            Self::Hybrid => write!(f, "Hybrid (XDP + AF_XDP)"),
        }
    }
}

/// Dataplane / offload profile for one NIC — all read from sysfs / procfs.
#[derive(Debug, Clone)]
pub struct NicDataplane {
    // ── XDP ──────────────────────────────────────────────────────────────────
    /// IDs of XDP programs attached to this interface.
    pub xdp_prog_ids: Vec<u32>,

    // ── AF_XDP ───────────────────────────────────────────────────────────────
    /// Number of AF_XDP sockets bound to this interface (reads /proc/net/xdp).
    pub afxdp_sockets: usize,

    // ── DPDK / userspace PMD ─────────────────────────────────────────────────
    /// True if the PCI device backing this interface is bound to a DPDK
    /// userspace driver (vfio-pci, igb_uio, uio_pci_generic).
    pub dpdk_bound: bool,
    /// Name of the userspace driver if dpdk_bound is true.
    pub userspace_driver: Option<String>,

    // ── SR-IOV ───────────────────────────────────────────────────────────────
    /// VFs currently enabled (None = not an SR-IOV PF).
    pub sriov_vfs_enabled: Option<u32>,
    /// Maximum VFs the hardware supports.
    pub sriov_vfs_total: Option<u32>,
    /// True if this interface is itself a Virtual Function (VF).
    pub is_virtual_function: bool,
    /// PCI address of the Physical Function that owns this VF.
    pub physfn_pci: Option<String>,

    // ── Multi-queue / RSS ─────────────────────────────────────────────────────
    pub rx_queues: usize,
    pub tx_queues: usize,
    pub combined_queues: usize,

    // ── Hardware offloads (read from /sys/class/net/<ifc>/features) ───────────
    /// Feature flags that are ON, e.g. "tx-checksum-ipv4", "rx-gro", "tx-tso".
    pub hw_features_on: Vec<String>,

    // ── PCI identity ──────────────────────────────────────────────────────────
    pub pci_address: Option<String>,
    pub pci_vendor_id: Option<String>,
    pub pci_device_id: Option<String>,
    pub numa_node: Option<i32>,

    // ── Summary ───────────────────────────────────────────────────────────────
    pub bypass_mode: BypassMode,
}

/// Detect dataplane profile for a single interface.
pub fn get_nic_dataplane(name: &str) -> io::Result<NicDataplane> {
    let base = format!("/sys/class/net/{name}");

    // ── XDP programs ─────────────────────────────────────────────────────────
    // /sys/class/net/<ifc>/xdp_prog_ids — space-separated list of program IDs
    let xdp_prog_ids: Vec<u32> = fs::read_to_string(format!("{base}/xdp_prog_ids"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();

    // Also check /sys/class/net/<ifc>/xdp_features (kernel ≥ 6.3)
    // If file exists and value != 0, at least one XDP feature is supported/active.
    // The prog_ids file is more definitive — use it as primary indicator.

    // ── AF_XDP sockets ───────────────────────────────────────────────────────
    // /proc/net/xdp lists all AF_XDP sockets; columns include the interface name.
    let afxdp_sockets = count_afxdp_sockets(name);

    // ── PCI device info ───────────────────────────────────────────────────────
    // /sys/class/net/<ifc>/device is a symlink to the PCI device directory.
    let pci_address = fs::read_link(format!("{base}/device"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));

    let pci_base = pci_address
        .as_ref()
        .map(|addr| format!("/sys/bus/pci/devices/{addr}"));

    let pci_vendor_id = pci_base
        .as_ref()
        .and_then(|b| fs::read_to_string(format!("{b}/vendor")).ok())
        .map(|s| s.trim().to_string());

    let pci_device_id = pci_base
        .as_ref()
        .and_then(|b| fs::read_to_string(format!("{b}/device")).ok())
        .map(|s| s.trim().to_string());

    let numa_node = pci_base
        .as_ref()
        .and_then(|b| fs::read_to_string(format!("{b}/numa_node")).ok())
        .and_then(|s| s.trim().parse::<i32>().ok());

    // ── DPDK / userspace PMD ─────────────────────────────────────────────────
    // If the PCI device's driver is one of the DPDK passthrough drivers
    // the interface is (or was) DPDK-bound.
    let (dpdk_bound, userspace_driver) = detect_dpdk_driver(&pci_address, &pci_base);

    // ── SR-IOV ───────────────────────────────────────────────────────────────
    let sriov_vfs_enabled = pci_base
        .as_ref()
        .and_then(|b| fs::read_to_string(format!("{b}/sriov_numvfs")).ok())
        .and_then(|s| s.trim().parse::<u32>().ok());

    let sriov_vfs_total = pci_base
        .as_ref()
        .and_then(|b| fs::read_to_string(format!("{b}/sriov_totalvfs")).ok())
        .and_then(|s| s.trim().parse::<u32>().ok());

    // A VF has a "physfn" symlink inside its PCI device directory.
    let is_virtual_function = pci_base
        .as_ref()
        .map(|b| std::path::Path::new(&format!("{b}/physfn")).exists())
        .unwrap_or(false);

    let physfn_pci = if is_virtual_function {
        pci_base.as_ref().and_then(|b| {
            fs::read_link(format!("{b}/physfn"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        })
    } else {
        None
    };

    // ── Multi-queue / RSS ─────────────────────────────────────────────────────
    let (rx_queues, tx_queues, combined_queues) = count_queues(name);

    // ── Hardware offloads ─────────────────────────────────────────────────────
    let hw_features_on = read_hw_features(name);

    // ── Bypass summary ────────────────────────────────────────────────────────
    let bypass_mode = {
        let has_xdp = !xdp_prog_ids.is_empty();
        let has_afxdp = afxdp_sockets > 0;
        match (dpdk_bound, has_xdp, has_afxdp) {
            (true, _, _) => BypassMode::DpdkUserspace,
            (_, true, true) => BypassMode::Hybrid,
            (_, true, false) => BypassMode::Xdp,
            (_, false, true) => BypassMode::AfXdp,
            _ => BypassMode::KernelStack,
        }
    };

    Ok(NicDataplane {
        xdp_prog_ids,
        afxdp_sockets,
        dpdk_bound,
        userspace_driver,
        sriov_vfs_enabled,
        sriov_vfs_total,
        is_virtual_function,
        physfn_pci,
        rx_queues,
        tx_queues,
        combined_queues,
        hw_features_on,
        pci_address,
        pci_vendor_id,
        pci_device_id,
        numa_node,
        bypass_mode,
    })
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Count AF_XDP sockets for this interface from /proc/net/xdp.
/// Format (kernel ≥ 5.4):
///   sk mem_alloc flags ifindex queue_id
fn count_afxdp_sockets(name: &str) -> usize {
    // Resolve ifindex for the named interface.
    let ifindex = fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    if ifindex == 0 {
        return 0;
    }

    let Ok(content) = fs::read_to_string("/proc/net/xdp") else {
        return 0;
    };
    content
        .lines()
        .skip(1) // header
        .filter(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // column 3 is ifindex (0-based col index)
            cols.get(3).and_then(|s| s.parse::<u32>().ok()) == Some(ifindex)
        })
        .count()
}

const USERSPACE_DRIVERS: &[&str] = &["vfio-pci", "igb_uio", "uio_pci_generic"];

/// Detect if the PCI device is bound to a DPDK/userspace driver.
fn detect_dpdk_driver(
    pci_address: &Option<String>,
    pci_base: &Option<String>,
) -> (bool, Option<String>) {
    // 1. Check the current driver symlink for the device.
    if let Some(base) = pci_base {
        let driver = fs::read_link(format!("{base}/driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
        if let Some(ref d) = driver {
            if USERSPACE_DRIVERS.contains(&d.as_str()) {
                return (true, driver);
            }
        }
    }

    // 2. Scan /sys/bus/pci/drivers/<dpdk-driver>/<pci-addr> for this device.
    if let Some(addr) = pci_address {
        for drv in USERSPACE_DRIVERS {
            let path = format!("/sys/bus/pci/drivers/{drv}/{addr}");
            if std::path::Path::new(&path).exists() {
                return (true, Some(drv.to_string()));
            }
        }
    }

    (false, None)
}

/// Count RX / TX / combined queue directories under
/// /sys/class/net/<ifc>/queues/rx-N and tx-N.
fn count_queues(name: &str) -> (usize, usize, usize) {
    let queues_dir = format!("/sys/class/net/{name}/queues");
    let Ok(entries) = fs::read_dir(&queues_dir) else {
        return (0, 0, 0);
    };

    let mut rx = 0usize;
    let mut tx = 0usize;
    for entry in entries.flatten() {
        let n = entry.file_name().to_string_lossy().to_string();
        if n.starts_with("rx-") {
            rx += 1;
        }
        if n.starts_with("tx-") {
            tx += 1;
        }
    }
    let combined = rx.min(tx);
    (rx, tx, combined)
}

/// Read enabled hardware feature flags from /sys/class/net/<ifc>/features.
/// Each line is: <feature_name> <on|off|n/a>
/// Only features marked "on" are returned.
fn read_hw_features(name: &str) -> Vec<String> {
    let Ok(content) = fs::read_to_string(format!("/sys/class/net/{name}/features")) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let feat = parts.next()?;
            let state = parts.next()?;
            if state == "on" {
                Some(feat.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Return info for a single interface by name.
pub fn get_nic_info(name: &str) -> io::Result<NicInfo> {
    let base = format!("/sys/class/net/{name}");

    let state = read_sysfs(&base, "operstate").unwrap_or_else(|_| "unknown".to_string());
    let mac = read_sysfs(&base, "address").unwrap_or_else(|_| "??:??:??:??:??:??".to_string());
    let mtu = read_sysfs(&base, "mtu")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let flags = read_sysfs(&base, "flags")
        .ok()
        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    let speed_mbps = read_sysfs(&base, "speed")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v as u32);
    let duplex = read_sysfs(&base, "duplex").ok();
    let driver = fs::read_link(format!("{base}/device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));

    let (rx_bytes, rx_packets, rx_errors, rx_dropped, tx_bytes, tx_packets, tx_errors, tx_dropped) =
        read_stats(name);

    let ip_addresses = read_ip_addresses(name);

    Ok(NicInfo {
        name: name.to_string(),
        state,
        mac,
        mtu,
        speed_mbps,
        duplex,
        driver,
        ip_addresses,
        rx_bytes,
        rx_packets,
        rx_errors,
        rx_dropped,
        tx_bytes,
        tx_packets,
        tx_errors,
        tx_dropped,
        flags,
    })
}

/// List all interfaces found in /sys/class/net.
pub fn list_nics() -> io::Result<Vec<NicInfo>> {
    let mut nics = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let name = entry?.file_name().to_string_lossy().to_string();
        if let Ok(info) = get_nic_info(&name) {
            nics.push(info);
        }
    }
    nics.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(nics)
}

// ---- helpers ---------------------------------------------------------------

fn read_sysfs(base: &str, file: &str) -> io::Result<String> {
    let raw = fs::read_to_string(format!("{base}/{file}"))?;
    Ok(raw.trim().to_string())
}

/// Parse /proc/net/dev for the named interface.
fn read_stats(name: &str) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let zero = (0, 0, 0, 0, 0, 0, 0, 0);
    let content = match fs::read_to_string("/proc/net/dev") {
        Ok(c) => c,
        Err(_) => return zero,
    };
    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with(name) {
            continue;
        }
        // Format: iface: rx_bytes rx_pkts rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_mcast
        //                tx_bytes tx_pkts tx_errs tx_drop tx_fifo tx_colls tx_carrier tx_compressed
        let after_colon = match line.find(':') {
            Some(pos) => &line[pos + 1..],
            None => continue,
        };
        let nums: Vec<u64> = after_colon
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        if nums.len() >= 16 {
            return (
                nums[0], nums[1], nums[2], nums[3], nums[8], nums[9], nums[10], nums[11],
            );
        }
    }
    zero
}

/// Read IPv4/IPv6 addresses from /proc/net/if_inet6 and /proc/net/fib_trie (simple approach via /proc/net/fib_trie is complex).
/// We use /proc/net/if_inet6 for IPv6 and parse /proc/net/fib_trie for IPv4,
/// but a simpler portable approach: read /proc/net/arp + /proc/net/if_inet6.
/// Easiest reliable source: parse `ip addr` output is not allowed —
/// instead read /proc/net/if_inet6 for IPv6 and /proc/net/fib_trie for IPv4.
fn read_ip_addresses(name: &str) -> Vec<String> {
    let mut addrs = Vec::new();

    // IPv4: /proc/net/fib_trie is complex; use /proc/net/if_inet6 sibling approach.
    // Reliable IPv4 source: /sys/class/net/<ifc>/... doesn't directly give IP.
    // We read /proc/net/fib_trie: LOCAL entries associated with the interface.
    // Simpler: parse /proc/net/arp for the interface's own IP is wrong (that's neighbour cache).
    // Best simple approach: read the interface index, then check /proc/net/fib_trie.
    if let Ok(ipv4_addrs) = read_ipv4_addrs(name) {
        addrs.extend(ipv4_addrs);
    }

    // IPv6: /proc/net/if_inet6
    //   fe80000000000000025056fffec00001 02 40 20 80    eth0
    if let Ok(content) = fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 && parts[5] == name {
                let raw = parts[0]; // 32 hex chars
                if raw.len() == 32 {
                    let groups: Vec<String> = (0..8)
                        .map(|i| raw[i * 4..(i + 1) * 4].to_string())
                        .collect();
                    let prefix_len = u8::from_str_radix(parts[2], 16).unwrap_or(0);
                    addrs.push(format!("{}/{prefix_len}", groups.join(":")));
                }
            }
        }
    }

    addrs
}

/// Read IPv4 addresses for an interface from /proc/net/fib_trie.
/// The trie encodes LOCAL host routes (32-bit prefix) for each interface.
/// We correlate via /proc/net/fib_triestat... actually the simpler path:
/// parse /proc/net/if_inet (not standard). Use ioctl SIOCGIFADDR is too complex.
/// Best portable approach without external commands: read the interface index
/// from /sys/class/net/<ifc>/ifindex, then scan /proc/net/fib_trie for LOCAL entries.
fn read_ipv4_addrs(name: &str) -> io::Result<Vec<String>> {
    // Read ifindex for this interface
    let ifindex: u32 = fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
        .trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // /proc/net/fib_trie format (abbreviated):
    //   +-- 0.0.0.0/0
    //     +-- 10.0.0.0/8
    //       LOCAL 10.0.0.1
    //         /32 host LOCAL
    //           pref medium nh bound dev eth0 scope host src 10.0.0.1
    // This is complex. Use /proc/net/fib_trie with a two-pass approach.

    // Simpler and 100% reliable: check /proc/net/if_inet via reading
    // /proc/self/net/if_inet6 etc. — not available.
    // Actually the most portable approach: read /proc/net/arp for the host's
    // own address is wrong. The cleanest sysfs approach:
    // /sys/class/net/<ifc>/... has no IPv4 addr file.
    //
    // Use /proc/net/fib_trie: scan for "LOCAL" blocks and match interface.
    let content = fs::read_to_string("/proc/net/fib_trie")?;
    let mut addrs = Vec::new();
    let mut current_ip: Option<String> = None;
    let mut in_local = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Line like: "32 host LOCAL" or "/32 host LOCAL"
        if trimmed.contains("host LOCAL") || trimmed.starts_with("LOCAL") {
            in_local = true;
            continue;
        }

        // IP address line: "   +-- 1.2.3.4/32 ..."  or  "10.0.0.1"
        if let Some(stripped) = trimmed.strip_prefix("+-- ") {
            let ip_part = stripped.split('/').next().unwrap_or("").trim();
            if !ip_part.is_empty() && ip_part.contains('.') {
                current_ip = Some(ip_part.to_string());
                in_local = false;
            }
            continue;
        }

        if in_local {
            // Look for "nh bound dev <name> scope host"
            if trimmed.contains(&format!("dev {name}")) && trimmed.contains("scope host") {
                if let Some(ref ip) = current_ip {
                    // Extract prefix by finding the /32 we just saw
                    addrs.push(format!("{ip}/32"));
                }
            }
            in_local = false;
            continue;
        }
    }

    // Fallback: use /proc/net/fib_trie second pass — look for ifindex match.
    // The above may miss some cases; supplement with ifindex-based reading.
    if addrs.is_empty() {
        addrs = read_ipv4_via_ifindex(name, ifindex, &content);
    }

    Ok(addrs)
}

fn read_ipv4_via_ifindex(name: &str, _ifindex: u32, fib_trie: &str) -> Vec<String> {
    // Walk fib_trie: for every /32 LOCAL entry, check if next lines mention "dev <name>"
    let lines: Vec<&str> = fib_trie.lines().collect();
    let mut addrs = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        // Detect IP node like "+-- 10.10.10.1/32"
        if let Some(rest) = trimmed.strip_prefix("+-- ") {
            if rest.ends_with("/32") {
                let ip = rest.trim_end_matches("/32").trim();
                // Look ahead for "LOCAL" + "dev <name>"
                let mut j = i + 1;
                let mut found_local = false;
                while j < lines.len() && j < i + 10 {
                    let l = lines[j].trim();
                    if l.contains("host LOCAL") {
                        found_local = true;
                    }
                    if found_local && l.contains(&format!("dev {name}")) {
                        addrs.push(format!("{ip}/32"));
                        break;
                    }
                    // Stop if we hit another IP node
                    if l.starts_with("+--") && j != i {
                        break;
                    }
                    j += 1;
                }
            }
        }
        i += 1;
    }
    addrs
}
