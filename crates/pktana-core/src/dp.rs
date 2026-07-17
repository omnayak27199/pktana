// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

/// Extended dataplane detection: BPF filesystem objects and network namespaces.
/// Primary sources: /sys/fs/bpf/, /sys/class/net/, /proc/*/ns/net.
/// Optional enrichment via `ip link`, `tc`, and `bpftool` when available.
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ─── BPF filesystem ───────────────────────────────────────────────────────────

/// A pinned BPF object discovered in the BPF filesystem (/sys/fs/bpf/).
///
/// When a BPF program or map is pinned, the kernel creates a file entry here.
/// Presence means some tool (iproute2/tc, Cilium, Falco, bpftool …) pinned
/// the object so it survives its owning process exiting.
#[derive(Debug, Clone)]
pub struct BpfPinnedObject {
    /// Full absolute path of the pinned entry.
    pub path: String,
    /// True for directories (namespace/group of pins), false for actual objects.
    pub is_dir: bool,
    /// Heuristic owner/category inferred from the pin path (e.g. cilium, xdp, tc).
    pub category: Option<String>,
}

/// Metadata for a BPF program resolved via bpftool (when installed).
#[derive(Debug, Clone, Default)]
pub struct BpfProgInfo {
    pub id: u32,
    pub name: Option<String>,
    pub prog_type: Option<String>,
    pub tag: Option<String>,
    pub loaded_at: Option<String>,
}

/// Walk /sys/fs/bpf/ recursively and return every entry found.
///
/// Returns an empty Vec when the BPF filesystem is not mounted or not readable.
pub fn scan_bpf_fs() -> Vec<BpfPinnedObject> {
    let mut objects = Vec::new();
    walk_bpf_dir(Path::new("/sys/fs/bpf"), &mut objects);
    objects
}

fn walk_bpf_dir(dir: &Path, out: &mut Vec<BpfPinnedObject>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Use symlink_metadata so we don't follow symlinks and loop.
        let is_dir = fs::symlink_metadata(&path)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        let path_str = path.to_string_lossy().to_string();
        out.push(BpfPinnedObject {
            category: classify_bpf_pin(&path_str),
            path: path_str,
            is_dir,
        });
        if is_dir {
            walk_bpf_dir(&path, out);
        }
    }
}

// ─── Network namespaces ───────────────────────────────────────────────────────

/// One distinct Linux network namespace, identified by the inode of its
/// /proc/<pid>/ns/net symlink target (e.g. "net:[4026531992]").
#[derive(Debug, Clone)]
pub struct NetNamespace {
    /// Kernel inode that uniquely identifies this namespace.
    pub inode: u64,
    /// True when this is the host (initial) network namespace.
    pub is_host: bool,
    /// PIDs whose primary network namespace is this one.
    pub pids: Vec<u32>,
    /// Process names (comm strings) for each PID, same order as `pids`.
    pub comms: Vec<String>,
    /// Network interface names visible inside this namespace
    /// (read from /proc/<pid>/net/dev for the first associated PID).
    pub interfaces: Vec<String>,
    /// AF_XDP socket counts per interface in this namespace
    /// (read from /proc/<pid>/net/xdp).  Tuple: (iface_name, socket_count).
    pub afxdp_per_iface: Vec<(String, usize)>,
    /// XDP program IDs per interface.  Populated only for the host namespace
    /// (via /sys/class/net/<ifc>/xdp_prog_ids); empty for other namespaces
    /// because reading them would require setns().
    pub xdp_per_iface: Vec<(String, Vec<u32>)>,
}

/// Enumerate all distinct network namespaces visible from this process.
///
/// Scans /proc/*/ns/net, groups PIDs by namespace inode, then reads
/// /proc/<pid>/net/dev and /proc/<pid>/net/xdp for each unique namespace.
pub fn list_network_namespaces() -> Vec<NetNamespace> {
    let host_inode = host_netns_inode();
    let mut map: HashMap<u64, NetNamespace> = HashMap::new();

    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let pid_str = fname.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let Ok(target) = fs::read_link(format!("/proc/{pid}/ns/net")) else {
            continue; // process may have already exited
        };
        let inode = parse_ns_inode(&target.to_string_lossy());
        if inode == 0 {
            continue;
        }

        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let ns = map.entry(inode).or_insert_with(|| NetNamespace {
            inode,
            is_host: Some(inode) == host_inode,
            pids: Vec::new(),
            comms: Vec::new(),
            interfaces: Vec::new(),
            afxdp_per_iface: Vec::new(),
            xdp_per_iface: Vec::new(),
        });
        ns.pids.push(pid);
        ns.comms.push(comm);
    }

    // Enrich each namespace with interface + XDP info via its first PID.
    for ns in map.values_mut() {
        let Some(&pid) = ns.pids.first() else {
            continue;
        };
        ns.interfaces = read_ns_interfaces(pid);
        ns.afxdp_per_iface = read_ns_afxdp(pid, &ns.interfaces);
        if ns.is_host {
            ns.xdp_per_iface = read_host_xdp(&ns.interfaces);
        }
    }

    let mut result: Vec<NetNamespace> = map.into_values().collect();
    // Host namespace first, then sort by inode ascending.
    result.sort_by(|a, b| b.is_host.cmp(&a.is_host).then(a.inode.cmp(&b.inode)));
    result
}

// ─── XDP dispatcher (libxdp multi-prog) ──────────────────────────────────────

/// One libxdp XDP multi-prog dispatcher pinned in /sys/fs/bpf/xdp/.
///
/// libxdp pins dispatchers as:
///   /sys/fs/bpf/xdp/dispatch-{prog_id}-{link_id}/
///     prog0-prog   ← pinned BPF program (sub-program slot 0)
///     prog0-link   ← pinned BPF link
///     prog1-prog / prog1-link   (if a second sub-prog is loaded)
///     …
///
/// The prog_id in the directory name is the *dispatcher* program ID —
/// the same value that appears in /sys/class/net/<iface>/xdp_prog_ids when
/// the dispatcher is attached to that interface.
#[derive(Debug, Clone)]
pub struct XdpDispatcher {
    /// Dispatcher BPF program ID (first number in the directory name).
    pub prog_id: u32,
    /// BPF link ID (second number in the directory name).
    pub link_id: u32,
    /// Full path of the dispatcher directory.
    pub dir: String,
    /// Sub-program slot names pinned inside (e.g. "prog0-prog", "prog0-link").
    pub slots: Vec<String>,
    /// Interface name this dispatcher is attached to, if determinable.
    pub iface: Option<String>,
}

/// Scan /sys/fs/bpf/xdp/ for libxdp dispatcher directories and return
/// one entry per dispatcher found.
///
/// Optionally correlates each dispatcher to an interface name by matching
/// its prog_id against /sys/class/net/<iface>/xdp_prog_ids.
pub fn list_xdp_dispatchers() -> Vec<XdpDispatcher> {
    let xdp_dir = Path::new("/sys/fs/bpf/xdp");
    if !xdp_dir.exists() {
        return Vec::new();
    }

    // Build a reverse map: prog_id -> interface name from all host interfaces.
    let prog_id_to_iface = build_prog_id_to_iface_map();

    let Ok(entries) = fs::read_dir(xdp_dir) else {
        return Vec::new();
    };

    let mut dispatchers = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name().to_string_lossy().to_string();
        // Match "dispatch-{prog_id}-{link_id}"
        let Some((prog_id, link_id)) = parse_dispatcher_name(&fname) else {
            continue;
        };
        let dir = entry.path().to_string_lossy().to_string();

        // List slot files inside the dispatcher directory.
        let slots: Vec<String> = fs::read_dir(entry.path())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        let iface = prog_id_to_iface.get(&prog_id).cloned();

        dispatchers.push(XdpDispatcher {
            prog_id,
            link_id,
            dir,
            slots,
            iface,
        });
    }

    dispatchers.sort_by_key(|d| d.prog_id);
    dispatchers
}

/// Parse "dispatch-{prog_id}-{link_id}" → (prog_id, link_id).
fn parse_dispatcher_name(name: &str) -> Option<(u32, u32)> {
    let rest = name.strip_prefix("dispatch-")?;
    let mut parts = rest.splitn(2, '-');
    let prog_id: u32 = parts.next()?.parse().ok()?;
    let link_id: u32 = parts.next()?.parse().ok()?;
    Some((prog_id, link_id))
}

/// Build a map from XDP prog_id → interface name by scanning all
/// /sys/class/net/<iface>/xdp_prog_ids files.
fn build_prog_id_to_iface_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let Ok(net_dir) = fs::read_dir("/sys/class/net") else {
        return map;
    };
    for entry in net_dir.flatten() {
        let iface = entry.file_name().to_string_lossy().to_string();
        let path = format!("/sys/class/net/{iface}/xdp_prog_ids");
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for id in content
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok())
        {
            map.insert(id, iface.clone());
        }
    }
    map
}

// ─── TC BPF detection ─────────────────────────────────────────────────────────

/// TC BPF attachment info for one interface.
#[derive(Debug, Clone, Default)]
pub struct TcBpfInfo {
    /// True when a clsact qdisc is present (prerequisite for TC BPF hooks).
    pub clsact: bool,
    /// Directions that have BPF filters: "ingress" and/or "egress".
    pub directions: Vec<String>,
    /// BPF program IDs attached via TC (parsed from `tc filter show` output).
    pub prog_ids: Vec<u32>,
}

/// Detect TC BPF programs on `iface` by running `tc qdisc/filter show`.
///
/// Falls back gracefully when `tc` is not installed or not accessible.
pub fn detect_tc_bpf(iface: &str) -> TcBpfInfo {
    let Some(tc) = find_bin(&["/sbin/tc", "/usr/sbin/tc", "/bin/tc", "/usr/bin/tc"]) else {
        return detect_tc_bpf_sysfs(iface);
    };

    let qdisc_out = run_cmd(&tc, &["qdisc", "show", "dev", iface]);
    let clsact = qdisc_out.contains("clsact") || detect_tc_bpf_sysfs(iface).clsact;
    if !clsact {
        return TcBpfInfo {
            clsact: false,
            ..Default::default()
        };
    }

    let mut directions = Vec::new();
    let mut prog_ids = Vec::new();

    for dir in &["ingress", "egress"] {
        let filter_out = run_cmd(&tc, &["filter", "show", "dev", iface, dir]);
        if tc_filter_has_bpf(&filter_out) {
            directions.push(dir.to_string());
            for id in parse_tc_bpf_ids(&filter_out) {
                push_unique(&mut prog_ids, id);
            }
        }
    }

    if prog_ids.is_empty() {
        let all_filters = run_cmd(&tc, &["filter", "show", "dev", iface]);
        if tc_filter_has_bpf(&all_filters) {
            for id in parse_tc_bpf_ids(&all_filters) {
                push_unique(&mut prog_ids, id);
            }
            if directions.is_empty() && !prog_ids.is_empty() {
                directions.push("unknown".to_string());
            }
        }
    }

    TcBpfInfo {
        clsact,
        directions,
        prog_ids,
    }
}

/// Read XDP program IDs and attachment mode from `ip link show` output.
pub fn parse_xdp_link_output(text: &str) -> (Vec<u32>, Option<String>) {
    let mut ids = Vec::new();
    let mut mode: Option<String> = None;
    for token in text.split_whitespace() {
        for (prefix, mode_name) in &[
            ("xdp/id:", "generic"),
            ("xdpdrv/id:", "native"),
            ("xdpoffload/id:", "offload"),
            ("xdplink/id:", "xdplink"),
        ] {
            if let Some(id_str) = token.strip_prefix(prefix) {
                if let Ok(id) = id_str.trim_end_matches(',').parse::<u32>() {
                    push_unique(&mut ids, id);
                    mode = Some(mode_name.to_string());
                }
            }
        }
    }
    (ids, mode)
}

/// Query XDP program IDs and mode for an interface via `ip link show`.
pub fn xdp_from_ip_link(iface: &str) -> (Vec<u32>, Option<String>) {
    let Some(ip) = find_bin(&["/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"]) else {
        return (Vec::new(), None);
    };
    let out = run_cmd(&ip, &["link", "show", iface]);
    parse_xdp_link_output(&out)
}

/// Read XDP program IDs from sysfs.
pub fn read_xdp_prog_ids_sysfs(iface: &str) -> Vec<u32> {
    fs::read_to_string(format!("/sys/class/net/{iface}/xdp_prog_ids"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Combined XDP detection: sysfs IDs + ip-link mode/IDs merged without losing mode.
pub fn detect_xdp_attachment(iface: &str) -> (Vec<u32>, Option<String>) {
    let sysfs_ids = read_xdp_prog_ids_sysfs(iface);
    let (link_ids, link_mode) = xdp_from_ip_link(iface);

    let mut prog_ids = if !sysfs_ids.is_empty() {
        sysfs_ids
    } else {
        link_ids.clone()
    };
    for id in link_ids {
        push_unique(&mut prog_ids, id);
    }
    (prog_ids, link_mode)
}

/// Resolve BPF program metadata via `bpftool prog show id <N>` when available.
pub fn enrich_bpf_prog_ids(ids: &[u32]) -> Vec<BpfProgInfo> {
    let Some(bpftool) = find_bin(&[
        "/sbin/bpftool",
        "/usr/sbin/bpftool",
        "/bin/bpftool",
        "/usr/bin/bpftool",
    ]) else {
        return ids
            .iter()
            .map(|&id| BpfProgInfo {
                id,
                ..Default::default()
            })
            .collect();
    };

    ids.iter()
        .map(|&id| {
            let out = run_cmd(&bpftool, &["prog", "show", "id", &id.to_string()]);
            parse_bpftool_prog_show(id, &out)
        })
        .collect()
}

/// Host-wide eBPF summary for CLI / API overview.
#[derive(Debug, Clone, Default)]
pub struct EbpfHostSummary {
    pub pinned_objects: usize,
    pub pinned_categories: HashMap<String, usize>,
    pub xdp_dispatchers: usize,
    pub interfaces_with_xdp: Vec<(String, Vec<u32>)>,
    pub interfaces_with_tc_bpf: Vec<(String, TcBpfInfo)>,
    pub network_namespaces: usize,
}

/// Build a host-wide eBPF inventory summary.
pub fn summarize_ebpf_host() -> EbpfHostSummary {
    let pinned = scan_bpf_fs();
    let mut pinned_categories: HashMap<String, usize> = HashMap::new();
    for obj in &pinned {
        if obj.is_dir {
            continue;
        }
        let key = obj.category.clone().unwrap_or_else(|| "other".to_string());
        *pinned_categories.entry(key).or_insert(0) += 1;
    }

    let dispatchers = list_xdp_dispatchers();
    let namespaces = list_network_namespaces();

    let mut interfaces_with_xdp = Vec::new();
    let mut interfaces_with_tc_bpf = Vec::new();
    if let Ok(net_dir) = fs::read_dir("/sys/class/net") {
        for entry in net_dir.flatten() {
            let iface = entry.file_name().to_string_lossy().to_string();
            let (xdp_ids, _) = detect_xdp_attachment(&iface);
            if !xdp_ids.is_empty() {
                interfaces_with_xdp.push((iface.clone(), xdp_ids));
            }
            let tc = detect_tc_bpf(&iface);
            if tc.clsact && !tc.prog_ids.is_empty() {
                interfaces_with_tc_bpf.push((iface, tc));
            }
        }
    }

    EbpfHostSummary {
        pinned_objects: pinned.iter().filter(|o| !o.is_dir).count(),
        pinned_categories,
        xdp_dispatchers: dispatchers.len(),
        interfaces_with_xdp,
        interfaces_with_tc_bpf,
        network_namespaces: namespaces.len(),
    }
}

/// One BPF program attachment reported by `bpftool net show`.
#[derive(Debug, Clone)]
pub struct BpfNetAttachment {
    pub hook: String,
    pub mode: Option<String>,
    pub prog_id: Option<u32>,
    pub prog_name: Option<String>,
    pub raw_line: String,
}

/// A pinned BPF object correlated with an interface.
#[derive(Debug, Clone)]
pub struct PinnedBpfMatch {
    pub path: String,
    pub pin_name: String,
    pub kind: String,
    pub prog_id: Option<u32>,
}

/// Full eBPF inspection report for one network interface.
#[derive(Debug, Clone)]
pub struct EbpfInterfaceReport {
    pub iface: String,
    pub iface_kind: String,
    pub xdp_prog_ids: Vec<u32>,
    pub xdp_mode: Option<String>,
    pub tc: TcBpfInfo,
    pub bpftool_attachments: Vec<BpfNetAttachment>,
    pub pinned_matches: Vec<PinnedBpfMatch>,
    pub afxdp_sockets: usize,
}

impl EbpfInterfaceReport {
    pub fn ebpf_active(&self) -> bool {
        !self.xdp_prog_ids.is_empty()
            || (self.tc.clsact && !self.tc.prog_ids.is_empty())
            || self.afxdp_sockets > 0
            || !self.bpftool_attachments.is_empty()
            || self
                .pinned_matches
                .iter()
                .any(|p| p.kind == "xdp" || p.kind == "tc")
    }

    pub fn all_prog_ids(&self) -> Vec<u32> {
        let mut ids = self.xdp_prog_ids.clone();
        for id in &self.tc.prog_ids {
            push_unique(&mut ids, *id);
        }
        for att in &self.bpftool_attachments {
            if let Some(id) = att.prog_id {
                push_unique(&mut ids, id);
            }
        }
        for pin in &self.pinned_matches {
            if let Some(id) = pin.prog_id {
                if pin.kind == "xdp" || pin.kind == "tc" {
                    push_unique(&mut ids, id);
                }
            }
        }
        ids
    }
}

/// Classify interface for pinned-object correlation (phy vs veth).
pub fn iface_bpf_link_kind(iface: &str) -> &'static str {
    if iface.starts_with("veth") {
        return "veth";
    }
    if iface == "lo" {
        return "loopback";
    }
    // veth peers expose ../peer_ifindex; physical NICs do not.
    if Path::new(&format!("/sys/class/net/{iface}/peer_ifindex")).exists() {
        return "veth";
    }
    "phy"
}

/// Find pinned BPF objects in /sys/fs/bpf/ likely used by `iface`.
pub fn find_pinned_bpf_for_iface(iface: &str) -> Vec<PinnedBpfMatch> {
    let link_kind = iface_bpf_link_kind(iface);
    if link_kind == "loopback" {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for obj in scan_bpf_fs() {
        if obj.is_dir {
            continue;
        }
        let pin_name = Path::new(&obj.path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !pin_matches_iface(&pin_name, iface, link_kind) {
            continue;
        }
        let kind = classify_pin_kind(&pin_name);
        let prog_id = if kind == "xdp" || kind == "tc" {
            prog_id_from_pinned_path(&obj.path)
        } else {
            None
        };
        matches.push(PinnedBpfMatch {
            path: obj.path.clone(),
            pin_name,
            kind: kind.to_string(),
            prog_id,
        });
    }

    matches.sort_by(|a, b| a.pin_name.cmp(&b.pin_name));
    matches
}

/// Query `bpftool net show dev <iface>` for kernel-reported attachments.
pub fn detect_bpftool_net(iface: &str) -> Vec<BpfNetAttachment> {
    let Some(bpftool) = find_bin(&[
        "/sbin/bpftool",
        "/usr/sbin/bpftool",
        "/bin/bpftool",
        "/usr/bin/bpftool",
    ]) else {
        return Vec::new();
    };
    let out = run_cmd(&bpftool, &["net", "show", "dev", iface]);
    parse_bpftool_net_output(iface, &out)
}

/// Comprehensive eBPF inspection for one interface.
pub fn inspect_ebpf_interface(iface: &str) -> std::io::Result<EbpfInterfaceReport> {
    let base = format!("/sys/class/net/{iface}");
    if !Path::new(&base).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface '{iface}' not found"),
        ));
    }

    let (mut xdp_prog_ids, xdp_mode) = detect_xdp_attachment(iface);
    let tc = detect_tc_bpf(iface);
    let bpftool_attachments = detect_bpftool_net(iface);
    let pinned_matches = find_pinned_bpf_for_iface(iface);

    for att in &bpftool_attachments {
        if let Some(id) = att.prog_id {
            if att.hook.starts_with("xdp") {
                push_unique(&mut xdp_prog_ids, id);
            }
        }
    }

    let mut tc = tc;
    for att in &bpftool_attachments {
        if att.hook.starts_with("tc") {
            if let Some(id) = att.prog_id {
                push_unique(&mut tc.prog_ids, id);
            }
            if att.hook.contains("ingress") && !tc.directions.contains(&"ingress".to_string()) {
                tc.directions.push("ingress".to_string());
            }
            if att.hook.contains("egress") && !tc.directions.contains(&"egress".to_string()) {
                tc.directions.push("egress".to_string());
            }
            tc.clsact = true;
        }
    }

    for pin in &pinned_matches {
        if pin.kind == "xdp" {
            if let Some(id) = pin.prog_id {
                push_unique(&mut xdp_prog_ids, id);
            }
        } else if pin.kind == "tc" {
            if let Some(id) = pin.prog_id {
                push_unique(&mut tc.prog_ids, id);
            }
            tc.clsact = true;
            if !tc.directions.contains(&"ingress".to_string()) {
                tc.directions.push("ingress".to_string());
            }
        }
    }

    let afxdp_sockets = count_afxdp_for_iface(iface);

    Ok(EbpfInterfaceReport {
        iface: iface.to_string(),
        iface_kind: iface_bpf_link_kind(iface).to_string(),
        xdp_prog_ids,
        xdp_mode,
        tc,
        bpftool_attachments,
        pinned_matches,
        afxdp_sockets,
    })
}

fn count_afxdp_for_iface(name: &str) -> usize {
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
        .skip(1)
        .filter(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            cols.get(3).and_then(|s| s.parse::<u32>().ok()) == Some(ifindex)
        })
        .count()
}

fn pin_matches_iface(pin_name: &str, iface: &str, link_kind: &str) -> bool {
    let lower = pin_name.to_lowercase();
    let iface_lower = iface.to_lowercase();

    // Exact interface name embedded in the pin path/name.
    if lower.contains(&iface_lower) {
        return true;
    }

    // Generic link-role tokens used by many custom eBPF dataplane loaders
    // (physical NIC vs veth/container paths).
    let role_tokens = link_role_tokens(link_kind);
    if role_tokens.iter().any(|token| lower.contains(token)) {
        return !pin_conflicts_with_link_kind(&lower, link_kind);
    }

    false
}

fn link_role_tokens(link_kind: &str) -> &'static [&'static str] {
    match link_kind {
        "veth" => &["veth", "virt", "container", "pod"],
        "phy" => &["phy", "phys", "physical", "nic", "netdev", "int"],
        _ => &[],
    }
}

fn pin_conflicts_with_link_kind(lower: &str, link_kind: &str) -> bool {
    match link_kind {
        "phy" => lower.contains("veth"),
        "veth" => {
            (lower.contains("phy") || lower.contains("physical") || lower.contains("netdev"))
                && !lower.contains("veth")
        }
        _ => false,
    }
}

fn classify_pin_kind(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    if lower.contains("xdp") {
        "xdp"
    } else if lower.contains("tc") || lower.contains("cls") || lower.contains("ingress") {
        "tc"
    } else if lower.contains("map") {
        "map"
    } else {
        "other"
    }
}

fn prog_id_from_pinned_path(path: &str) -> Option<u32> {
    let bpftool = find_bin(&[
        "/sbin/bpftool",
        "/usr/sbin/bpftool",
        "/bin/bpftool",
        "/usr/bin/bpftool",
    ])?;
    let out = run_cmd(&bpftool, &["prog", "show", "pinned", path]);
    out.lines().next().and_then(|line| {
        line.split(':')
            .next()
            .and_then(|id| id.trim().parse::<u32>().ok())
    })
}

/// Parse `bpftool net show` output for one interface.
pub fn parse_bpftool_net_output(iface: &str, output: &str) -> Vec<BpfNetAttachment> {
    let mut section = String::new();
    let mut attachments = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.ends_with(':') && !trimmed.contains('(') {
            section = trimmed.trim_end_matches(':').to_string();
            continue;
        }
        if !line_contains_iface(trimmed, iface) {
            continue;
        }

        let hook = if section.is_empty() {
            "unknown".to_string()
        } else {
            section.clone()
        };

        let lower = trimmed.to_lowercase();
        let mode = if lower.contains(" driver") || lower.contains("xdpdrv") {
            Some("native".to_string())
        } else if lower.contains(" generic") || lower.contains("xdpgeneric") {
            Some("generic".to_string())
        } else if lower.contains(" offload") || lower.contains("xdpoffload") {
            Some("offload".to_string())
        } else {
            None
        };

        let prog_id = extract_id_from_bpftool_line(trimmed);
        let prog_name = extract_name_from_bpftool_line(trimmed);

        attachments.push(BpfNetAttachment {
            hook,
            mode,
            prog_id,
            prog_name,
            raw_line: trimmed.to_string(),
        });
    }

    attachments
}

fn line_contains_iface(line: &str, iface: &str) -> bool {
    line.starts_with(iface)
        || line.contains(&format!("{iface}("))
        || line.contains(&format!("dev {iface}"))
}

fn extract_id_from_bpftool_line(line: &str) -> Option<u32> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "id" {
            if let Some(id_str) = parts.get(i + 1) {
                let clean: String = id_str.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(id) = clean.parse::<u32>() {
                    return Some(id);
                }
            }
        }
    }
    None
}

fn extract_name_from_bpftool_line(line: &str) -> Option<String> {
    if let Some(idx) = line.find(" name ") {
        let rest = &line[idx + 6..];
        let name = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches(':');
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    // tc lines often have "progname id N" without "name" keyword
    for (i, part) in line.split_whitespace().enumerate() {
        if part == "id" && i > 0 {
            let candidate = line.split_whitespace().nth(i - 1)?;
            if !candidate.chars().all(|c| c.is_ascii_digit()) && candidate != "clsact/ingress" {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn parse_ns_inode(link: &str) -> u64 {
    link.strip_prefix("net:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn host_netns_inode() -> Option<u64> {
    fs::read_link("/proc/self/ns/net")
        .ok()
        .map(|t| parse_ns_inode(&t.to_string_lossy()))
        .filter(|&i| i != 0)
}

fn read_ns_interfaces(pid: u32) -> Vec<String> {
    let Ok(content) = fs::read_to_string(format!("/proc/{pid}/net/dev")) else {
        return Vec::new();
    };
    content
        .lines()
        .skip(2) // two header lines
        .filter_map(|line| {
            let name = line.trim().split(':').next()?.trim().to_string();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        })
        .collect()
}

/// Count AF_XDP sockets per interface from /proc/<pid>/net/xdp.
/// Format: sk  mem_alloc  flags  ifindex  queue_id
fn read_ns_afxdp(pid: u32, ifaces: &[String]) -> Vec<(String, usize)> {
    let Ok(content) = fs::read_to_string(format!("/proc/{pid}/net/xdp")) else {
        return Vec::new();
    };

    // Build ifindex → name map from sysfs (works for host-ns ifaces).
    let mut idx_to_name: HashMap<u32, String> = HashMap::new();
    for iface in ifaces {
        if let Ok(s) = fs::read_to_string(format!("/sys/class/net/{iface}/ifindex")) {
            if let Ok(idx) = s.trim().parse::<u32>() {
                idx_to_name.insert(idx, iface.clone());
            }
        }
    }

    let mut counts: HashMap<u32, usize> = HashMap::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = cols.get(3).and_then(|s| s.parse::<u32>().ok()) {
            *counts.entry(idx).or_insert(0) += 1;
        }
    }

    counts
        .into_iter()
        .filter(|(_, cnt)| *cnt > 0)
        .map(|(idx, cnt)| {
            let name = idx_to_name
                .get(&idx)
                .cloned()
                .unwrap_or_else(|| format!("ifidx:{idx}"));
            (name, cnt)
        })
        .collect()
}

fn read_host_xdp(ifaces: &[String]) -> Vec<(String, Vec<u32>)> {
    ifaces
        .iter()
        .filter_map(|iface| {
            let (ids, _) = detect_xdp_attachment(iface);
            if ids.is_empty() {
                None
            } else {
                Some((iface.clone(), ids))
            }
        })
        .collect()
}

fn find_bin(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|s| s.to_string())
}

fn run_cmd(bin: &str, args: &[&str]) -> String {
    std::process::Command::new(bin)
        .args(args)
        .output()
        .ok()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.trim().is_empty() {
                String::from_utf8_lossy(&o.stderr).to_string()
            } else {
                stdout.to_string()
            }
        })
        .unwrap_or_default()
}

fn push_unique(list: &mut Vec<u32>, id: u32) {
    if !list.contains(&id) {
        list.push(id);
    }
}

fn tc_filter_has_bpf(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("bpf")
        || lower.contains("ebpf")
        || lower.contains("object pinned")
        || lower.contains("bpf_direct")
}

fn detect_tc_bpf_sysfs(iface: &str) -> TcBpfInfo {
    let clsact_path = format!("/sys/class/net/{iface}/qdisc");
    let clsact = fs::read_to_string(&clsact_path)
        .map(|s| s.contains("clsact"))
        .unwrap_or(false);
    TcBpfInfo {
        clsact,
        ..Default::default()
    }
}

fn classify_bpf_pin(path: &str) -> Option<String> {
    let rel = path.strip_prefix("/sys/fs/bpf/").unwrap_or(path);
    let category = if rel.starts_with("cilium") {
        "cilium"
    } else if rel.starts_with("xdp") {
        "libxdp"
    } else if rel.starts_with("tc") {
        "tc"
    } else if rel.starts_with("falco") {
        "falco"
    } else if rel.starts_with("calico") {
        "calico"
    } else if rel.contains("kube") {
        "kubernetes"
    } else if rel.starts_with("ip") || rel.starts_with("iptables") {
        "iptables"
    } else if rel.contains("bpf") || rel.contains("_xdp_") || rel.contains("_tc_") {
        "pinned-bpf"
    } else {
        return None;
    };
    Some(category.to_string())
}

fn parse_bpftool_prog_show(id: u32, output: &str) -> BpfProgInfo {
    let mut info = BpfProgInfo {
        id,
        ..Default::default()
    };
    if output.trim().is_empty() {
        return info;
    }

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("name ") {
            info.name = Some(trimmed.trim_start_matches("name ").trim().to_string());
        } else if trimmed.starts_with("type ") {
            info.prog_type = Some(trimmed.trim_start_matches("type ").trim().to_string());
        } else if trimmed.starts_with("tag ") {
            info.tag = Some(trimmed.trim_start_matches("tag ").trim().to_string());
        } else if trimmed.starts_with("loaded_at ") {
            info.loaded_at = Some(trimmed.trim_start_matches("loaded_at ").trim().to_string());
        } else if info.name.is_none() {
            // bpftool one-liner: "42: type xdp  name foo  tag abc  ..."
            if let Some(name_part) = trimmed.split("name ").nth(1) {
                info.name = Some(
                    name_part
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string(),
                );
            }
            if let Some(type_part) = trimmed.split("type ").nth(1) {
                info.prog_type = Some(
                    type_part
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string(),
                );
            }
            if let Some(tag_part) = trimmed.split("tag ").nth(1) {
                info.tag = Some(tag_part.split_whitespace().next().unwrap_or("").to_string());
            }
        }
    }
    info
}

/// Parse BPF prog IDs from `tc filter show` output on lines that reference BPF.
pub fn parse_tc_bpf_ids(output: &str) -> Vec<u32> {
    let mut ids = Vec::new();
    for line in output.lines() {
        if !tc_filter_has_bpf(line) {
            continue;
        }
        let lower = line.to_lowercase();
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, &part) in parts.iter().enumerate() {
            let part_lower = part.to_lowercase();
            if part_lower == "id" {
                if let Some(id_str) = parts.get(i + 1) {
                    let clean: String = id_str.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(id) = clean.parse::<u32>() {
                        // Prefer IDs on bpf-specific lines; skip obvious handle/chain IDs.
                        let prev = parts.get(i.saturating_sub(1)).copied().unwrap_or("");
                        if prev.eq_ignore_ascii_case("bpf")
                            || prev.eq_ignore_ascii_case("ebpf")
                            || lower.contains("prog")
                        {
                            push_unique(&mut ids, id);
                        }
                    }
                }
            } else if part_lower == "bpf"
                && i + 2 < parts.len()
                && parts[i + 1].eq_ignore_ascii_case("id")
            {
                if let Ok(id) = parts[i + 2]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u32>()
                {
                    push_unique(&mut ids, id);
                }
            }
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dispatcher_name_valid() {
        assert_eq!(parse_dispatcher_name("dispatch-42-7"), Some((42, 7)));
        assert_eq!(parse_dispatcher_name("dispatch-1-2"), Some((1, 2)));
    }

    #[test]
    fn parse_dispatcher_name_invalid() {
        assert_eq!(parse_dispatcher_name("not-dispatch"), None);
        assert_eq!(parse_dispatcher_name("dispatch-bad"), None);
    }

    #[test]
    fn parse_xdp_link_output_native_and_generic() {
        let text = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpdrv/id:21 xdplink/id:99";
        let (ids, mode) = parse_xdp_link_output(text);
        assert!(ids.contains(&21));
        assert!(ids.contains(&99));
        assert_eq!(mode.as_deref(), Some("xdplink"));
    }

    #[test]
    fn parse_xdp_link_output_offload() {
        let text = "3: ens1: <BROADCAST> mtu 1500 xdpoffload/id:5";
        let (ids, mode) = parse_xdp_link_output(text);
        assert_eq!(ids, vec![5]);
        assert_eq!(mode.as_deref(), Some("offload"));
    }

    #[test]
    fn parse_tc_bpf_ids_from_filter_lines() {
        let out = "filter protocol all pref 49152 bpf chain 0 \
                   handle 0x1 bpf id 42 tag abcdef01 direct-action not_in_hw \
                   id 999";
        let ids = parse_tc_bpf_ids(out);
        assert!(ids.contains(&42));
        assert!(!ids.contains(&999));
    }

    #[test]
    fn parse_tc_bpf_ids_skips_non_bpf_lines() {
        let out = "filter parent 1: protocol ip pref 1 u32 chain 0 handle 0x1 id 77";
        assert!(parse_tc_bpf_ids(out).is_empty());
    }

    #[test]
    fn pin_matches_iface_by_link_role() {
        assert!(pin_matches_iface("bpf_xdp_rx_phy_v4", "m1", "phy"));
        assert!(pin_matches_iface("epp_map_phy", "m1", "phy"));
        assert!(pin_matches_iface("bpf_tc_rx_veth_v4", "veth0", "veth"));
        assert!(!pin_matches_iface("bpf_xdp_rx_veth_v4", "m1", "phy"));
        assert!(pin_matches_iface("bpf_xdp_eth0", "eth0", "phy"));
    }

    #[test]
    fn classify_bpf_pin_paths() {
        assert_eq!(
            classify_bpf_pin("/sys/fs/bpf/cilium/devices"),
            Some("cilium".to_string())
        );
        assert_eq!(
            classify_bpf_pin("/sys/fs/bpf/xdp/dispatch-1-2"),
            Some("libxdp".to_string())
        );
        assert_eq!(
            classify_bpf_pin("/sys/fs/bpf/bpf_xdp_rx_phy_v4"),
            Some("pinned-bpf".to_string())
        );
        assert_eq!(classify_bpf_pin("/sys/fs/bpf/random"), None);
    }

    #[test]
    fn parse_bpftool_prog_show_one_liner() {
        let out = "42: type xdp  name cil_from_eth0  tag abcdef12  gpl loaded_at 2024-01-01";
        let info = parse_bpftool_prog_show(42, out);
        assert_eq!(info.id, 42);
        assert_eq!(info.name.as_deref(), Some("cil_from_eth0"));
        assert_eq!(info.prog_type.as_deref(), Some("xdp"));
        assert_eq!(info.tag.as_deref(), Some("abcdef12"));
    }
}
