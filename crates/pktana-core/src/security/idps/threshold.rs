// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Tracks per-source connection attempts for scan/brute-force heuristics.
struct FlowTracker {
    dst_ports: HashMap<String, Vec<u16>>,
    ssh_attempts: HashMap<String, u32>,
}

impl FlowTracker {
    fn new() -> Self {
        Self {
            dst_ports: HashMap::new(),
            ssh_attempts: HashMap::new(),
        }
    }
}

static TRACKER: OnceLock<Mutex<FlowTracker>> = OnceLock::new();

fn tracker() -> &'static Mutex<FlowTracker> {
    TRACKER.get_or_init(|| Mutex::new(FlowTracker::new()))
}

pub enum BehavioralHit {
    PortScan { unique_ports: usize },
    SshBrute { attempts: u32 },
}

pub fn track_and_detect(
    src: &str,
    dst_port: Option<u16>,
    is_ssh_syn: bool,
) -> Option<BehavioralHit> {
    let Ok(mut t) = tracker().lock() else {
        return None;
    };
    if let Some(port) = dst_port {
        let ports = t.dst_ports.entry(src.to_string()).or_default();
        if !ports.contains(&port) {
            ports.push(port);
        }
        if ports.len() >= 15 {
            return Some(BehavioralHit::PortScan {
                unique_ports: ports.len(),
            });
        }
    }
    if is_ssh_syn {
        let attempts = t.ssh_attempts.entry(src.to_string()).or_insert(0);
        *attempts += 1;
        if *attempts >= 20 {
            return Some(BehavioralHit::SshBrute {
                attempts: *attempts,
            });
        }
    }
    None
}
