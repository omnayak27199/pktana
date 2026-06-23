// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

/// Extended dataplane detection: BPF filesystem objects and network namespaces.
/// Reads purely from /sys/fs/bpf/ and /proc/*/ns/net — no external commands.
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
        out.push(BpfPinnedObject {
            path: path.to_string_lossy().to_string(),
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
        return TcBpfInfo::default();
    };

    // Check for clsact qdisc — required for TC BPF ingress/egress hooks.
    let qdisc_out = run_cmd(&tc, &["qdisc", "show", "dev", iface]);
    let clsact = qdisc_out.contains("clsact");
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
        if filter_out.contains("bpf") || filter_out.contains("ebpf") {
            directions.push(dir.to_string());
            // Parse BPF prog IDs from lines like: "... bpf id 42 tag ..."
            for id in parse_tc_bpf_ids(&filter_out) {
                if !prog_ids.contains(&id) {
                    prog_ids.push(id);
                }
            }
        }
    }

    TcBpfInfo {
        clsact,
        directions,
        prog_ids,
    }
}

// ─── private helpers ──────────────────────────────────────────────────────────

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
            let ids: Vec<u32> = fs::read_to_string(format!("/sys/class/net/{iface}/xdp_prog_ids"))
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
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
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Parse BPF prog IDs from `tc filter show` output.
/// Looks for tokens: "id <N>" where N is a decimal number.
fn parse_tc_bpf_ids(output: &str) -> Vec<u32> {
    let mut ids = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, &part) in parts.iter().enumerate() {
            if part == "id" {
                if let Some(id_str) = parts.get(i + 1) {
                    // Strip trailing punctuation like ')' or ','
                    let clean: String = id_str.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(id) = clean.parse::<u32>() {
                        ids.push(id);
                    }
                }
            }
        }
    }
    ids
}
