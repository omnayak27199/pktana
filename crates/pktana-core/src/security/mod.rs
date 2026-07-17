// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Data Loss Prevention (DLP) and Intrusion Detection/Prevention (IDPS) engines
//! built on top of the DPI `DeepPacket` inspector.
//!
//! Architecture:
//! - `dlp/` — Sophos-style content inspection with categorized data identifiers
//! - `idps/` — Suricata-style signature matching, heuristics, and behavioral analysis

mod alert;
mod config;
mod dlp;
mod engine;
mod idps;
mod policy;
mod store;
mod types;
mod util;

pub use config::{DlpCustomIdentifier, SecurityConfig};
pub use dlp::{dlp_rule_catalog, scan_dlp};
pub use engine::{analyze_packet, evaluate_packet};
pub use idps::{idps_rule_catalog, scan_idps};
pub use store::{
    clear_security_alerts, clear_security_engine, clear_security_for_interface,
    clear_security_for_session, get_security_config, list_security_alerts, list_security_flows,
    list_security_interfaces, security_stats, set_security_config,
};
pub use types::{
    AlertSeverity, InterfaceSecurityStats, PacketSecurityResult, SecurityAction, SecurityAlert,
    SecurityEngine, SecurityFlow, SecurityPolicyRule, SecurityRuleDef, SecurityStats,
};

pub fn list_security_rules() -> Vec<SecurityRuleDef> {
    let mut rules = dlp_rule_catalog();
    rules.extend(idps_rule_catalog());
    rules
}

#[cfg(test)]
mod tests;
