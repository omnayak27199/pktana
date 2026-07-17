// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Sophos-style Data Loss Prevention engine.
//!
//! Content inspection across cleartext protocols with categorized data identifiers
//! (PCI, PII, HIPAA, credentials, financial) and custom regex patterns.

mod catalog;
mod identifiers;
mod protocols;
mod scanner;

pub use catalog::dlp_rule_catalog;
pub use scanner::scan;

/// Re-export for backward-compatible public API.
pub fn scan_dlp(
    dp: &crate::dpi::DeepPacket,
    ts: u64,
    cfg: &super::config::SecurityConfig,
) -> Vec<super::types::SecurityAlert> {
    scan(dp, ts, cfg)
}
