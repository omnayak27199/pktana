// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Suricata-style Intrusion Detection/Prevention engine.
//!
//! Signature-based detection with a subset of Snort/Suricata rule syntax,
//! built-in ET-style rules, JA3 fingerprint blocking, and heuristic analysis.

mod catalog;
mod dpi_bridge;
mod heuristics;
mod scanner;
mod signatures;
mod threshold;

pub use catalog::idps_rule_catalog;
pub use scanner::scan;

/// Re-export for backward-compatible public API.
pub fn scan_idps(
    dp: &crate::dpi::DeepPacket,
    ts: u64,
    cfg: &super::config::SecurityConfig,
) -> Vec<super::types::SecurityAlert> {
    scan(dp, ts, cfg)
}
