// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityEngine {
    Dlp,
    Idps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityAction {
    Monitor,
    Pass,
    Drop,
    Redirect,
    Quarantine,
}

impl SecurityAction {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "pass" => Self::Pass,
            "drop" => Self::Drop,
            "redirect" => Self::Redirect,
            "quarantine" => Self::Quarantine,
            _ => Self::Monitor,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monitor => "monitor",
            Self::Pass => "pass",
            Self::Drop => "drop",
            Self::Redirect => "redirect",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicyRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
    /// `any`, `dlp`, or `idps`
    pub engine: String,
    /// Empty = all interfaces
    pub interface: String,
    /// Source IP or CIDR (empty = any)
    pub src_ip: String,
    /// Destination IP or CIDR (empty = any)
    pub dst_ip: String,
    /// ISO country code for source (empty = any)
    pub src_country: String,
    /// ISO country code for destination (empty = any)
    pub dst_country: String,
    /// Detection rule id (empty = any matched rule)
    pub detection_rule: String,
    pub action: String,
    pub redirect_target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSecurityStats {
    pub interface: String,
    pub stats: SecurityStats,
    pub dlp_flows: u64,
    pub idps_flows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRuleDef {
    pub rule_id: String,
    pub engine: String,
    pub title: String,
    pub severity: String,
    pub default_action: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub sid: u32,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub ts: u64,
    pub engine: String,
    pub severity: String,
    pub rule_id: String,
    pub title: String,
    pub detail: String,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub risk_score: u8,
    pub action: String,
    pub flow_key: String,
    pub verdict: String,
    pub interface: String,
    pub src_country: String,
    pub dst_country: String,
    pub policy_id: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub sid: u32,
    /// Capture session that produced this alert (empty = legacy / unknown).
    #[serde(default)]
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFlow {
    pub flow_key: String,
    pub engine: String,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub alert_count: u64,
    pub packet_count: u64,
    pub bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub top_rule: String,
    pub top_severity: String,
    pub verdict: String,
    pub rules: Vec<String>,
    pub interface: String,
    pub src_country: String,
    pub dst_country: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityStats {
    pub dlp_alerts: u64,
    pub idps_alerts: u64,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub packets_scanned: u64,
    pub dlp_flows: u64,
    pub idps_flows: u64,
    pub dropped: u64,
    pub passed: u64,
    pub redirected: u64,
    pub quarantined: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSecurityResult {
    pub alerts: Vec<SecurityAlert>,
    pub verdict: String,
    pub flow_key: String,
    pub engines: Vec<String>,
    pub dropped: bool,
    pub redirect_target: String,
    pub interface: String,
}

pub(crate) struct FlowAgg {
    pub engine: String,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub interface: String,
    pub session_id: String,
    pub src_country: String,
    pub dst_country: String,
    pub alert_count: u64,
    pub packet_count: u64,
    pub bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub top_rule: String,
    pub top_severity: String,
    pub verdict: String,
    pub rules: Vec<String>,
}

pub fn action_rank(a: SecurityAction) -> u8 {
    match a {
        SecurityAction::Pass => 0,
        SecurityAction::Monitor => 1,
        SecurityAction::Redirect => 2,
        SecurityAction::Quarantine => 3,
        SecurityAction::Drop => 4,
    }
}

pub fn verdict_rank(v: &str) -> u8 {
    action_rank(SecurityAction::parse(v))
}

pub fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}
