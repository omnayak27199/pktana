// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::config::SecurityConfig;
use super::types::{
    severity_rank, verdict_rank, FlowAgg, InterfaceSecurityStats, SecurityAction, SecurityAlert,
    SecurityFlow, SecurityStats,
};

struct AlertStore {
    alerts: Vec<SecurityAlert>,
    flows: HashMap<String, FlowAgg>,
    iface_stats: HashMap<String, SecurityStats>,
    stats: SecurityStats,
    max: usize,
}

impl AlertStore {
    fn new(max: usize) -> Self {
        Self {
            alerts: Vec::new(),
            flows: HashMap::new(),
            iface_stats: HashMap::new(),
            stats: SecurityStats::default(),
            max,
        }
    }

    fn push_alert(&mut self, alert: SecurityAlert) {
        Self::count_alert(&mut self.stats, alert.interface.as_str(), &alert);
        if !alert.interface.is_empty() {
            let iface_stats = self.iface_stats.entry(alert.interface.clone()).or_default();
            Self::count_alert_iface(iface_stats, &alert);
        }
        self.alerts.push(alert.clone());
        if self.alerts.len() > self.max {
            let drop = self.alerts.len() - self.max;
            self.alerts.drain(0..drop);
            self.rebuild_stats_from_store();
        }
    }

    fn count_alert(stats: &mut SecurityStats, iface: &str, alert: &SecurityAlert) {
        match alert.severity.as_str() {
            "critical" => stats.critical += 1,
            "high" => stats.high += 1,
            "medium" => stats.medium += 1,
            _ => {}
        }
        if alert.engine == "dlp" {
            stats.dlp_alerts += 1;
        } else {
            stats.idps_alerts += 1;
        }
        if !iface.is_empty() {
            // iface_stats updated via caller when needed
        }
    }

    fn count_alert_iface(iface_stats: &mut SecurityStats, alert: &SecurityAlert) {
        if alert.engine == "dlp" {
            iface_stats.dlp_alerts += 1;
        } else {
            iface_stats.idps_alerts += 1;
        }
        match alert.severity.as_str() {
            "critical" => iface_stats.critical += 1,
            "high" => iface_stats.high += 1,
            "medium" => iface_stats.medium += 1,
            _ => {}
        }
    }

    fn touch_iface_stats(&mut self, iface: &str, verdict: SecurityAction, has_alerts: bool) {
        let stats = self.iface_stats.entry(iface.to_string()).or_default();
        stats.packets_scanned += 1;
        match verdict {
            SecurityAction::Drop => stats.dropped += 1,
            SecurityAction::Redirect => stats.redirected += 1,
            SecurityAction::Quarantine => stats.quarantined += 1,
            SecurityAction::Pass if has_alerts => stats.passed += 1,
            _ => {}
        }
    }

    fn touch_flow(&mut self, key: &str, alert: &SecurityAlert, bytes: u64) {
        let entry = self
            .flows
            .entry(key.to_string())
            .or_insert_with(|| FlowAgg {
                engine: alert.engine.clone(),
                protocol: alert.protocol.clone(),
                src: alert.src.clone(),
                dst: alert.dst.clone(),
                interface: alert.interface.clone(),
                session_id: alert.session_id.clone(),
                src_country: alert.src_country.clone(),
                dst_country: alert.dst_country.clone(),
                alert_count: 0,
                packet_count: 0,
                bytes: 0,
                first_ts: alert.ts,
                last_ts: alert.ts,
                top_rule: alert.rule_id.clone(),
                top_severity: alert.severity.clone(),
                verdict: alert.verdict.clone(),
                rules: Vec::new(),
            });
        entry.alert_count += 1;
        entry.packet_count += 1;
        entry.bytes += bytes;
        entry.last_ts = alert.ts;
        if alert.ts < entry.first_ts {
            entry.first_ts = alert.ts;
        }
        if !entry.rules.contains(&alert.rule_id) {
            entry.rules.push(alert.rule_id.clone());
        }
        if severity_rank(&alert.severity) >= severity_rank(&entry.top_severity) {
            entry.top_severity = alert.severity.clone();
            entry.top_rule = alert.rule_id.clone();
        }
        if verdict_rank(&alert.verdict) >= verdict_rank(&entry.verdict) {
            entry.verdict = alert.verdict.clone();
        }
    }

    fn recount_flow_stats(&mut self) {
        self.stats.dlp_flows = self.flows.values().filter(|f| f.engine == "dlp").count() as u64;
        self.stats.idps_flows = self.flows.values().filter(|f| f.engine == "idps").count() as u64;
    }

    fn rebuild_stats_from_store(&mut self) {
        self.stats = SecurityStats::default();
        self.iface_stats.clear();

        for alert in &self.alerts {
            Self::count_alert(&mut self.stats, alert.interface.as_str(), alert);
            if !alert.interface.is_empty() {
                let iface_stats = self.iface_stats.entry(alert.interface.clone()).or_default();
                Self::count_alert_iface(iface_stats, alert);
            }
        }

        for flow in self.flows.values() {
            self.stats.packets_scanned += flow.packet_count;
            let verdict = SecurityAction::parse(&flow.verdict);
            match verdict {
                SecurityAction::Drop => self.stats.dropped += flow.packet_count,
                SecurityAction::Redirect => self.stats.redirected += flow.packet_count,
                SecurityAction::Quarantine => self.stats.quarantined += flow.packet_count,
                SecurityAction::Pass if flow.alert_count > 0 => {
                    self.stats.passed += flow.packet_count
                }
                _ => {}
            }
            if !flow.interface.is_empty() {
                let iface_stats = self.iface_stats.entry(flow.interface.clone()).or_default();
                iface_stats.packets_scanned += flow.packet_count;
                match verdict {
                    SecurityAction::Drop => iface_stats.dropped += flow.packet_count,
                    SecurityAction::Redirect => iface_stats.redirected += flow.packet_count,
                    SecurityAction::Quarantine => iface_stats.quarantined += flow.packet_count,
                    SecurityAction::Pass if flow.alert_count > 0 => {
                        iface_stats.passed += flow.packet_count
                    }
                    _ => {}
                }
            }
        }

        self.recount_flow_stats();
    }
}

static STORE: OnceLock<Mutex<AlertStore>> = OnceLock::new();
static CONFIG: OnceLock<Mutex<SecurityConfig>> = OnceLock::new();

fn store() -> &'static Mutex<AlertStore> {
    STORE.get_or_init(|| Mutex::new(AlertStore::new(5000)))
}

fn config_lock() -> &'static Mutex<SecurityConfig> {
    CONFIG.get_or_init(|| Mutex::new(SecurityConfig::default()))
}

pub fn get_security_config() -> SecurityConfig {
    config_lock().lock().map(|c| c.clone()).unwrap_or_default()
}

pub fn set_security_config(mut cfg: SecurityConfig) {
    cfg.normalize();
    if let Ok(mut c) = config_lock().lock() {
        *c = cfg;
    }
}

pub fn clear_security_alerts() {
    if let Ok(mut s) = store().lock() {
        s.alerts.clear();
        s.flows.clear();
        s.iface_stats.clear();
        s.stats = SecurityStats::default();
    }
}

/// Remove DLP/IDPS alerts, flows, and stats for a closed capture session.
pub fn clear_security_for_session(session_id: &str) {
    if session_id.is_empty() {
        return;
    }
    if let Ok(mut s) = store().lock() {
        s.alerts.retain(|a| a.session_id != session_id);
        s.flows.retain(|_, flow| flow.session_id != session_id);
        s.rebuild_stats_from_store();
    }
}

/// Remove security data tied to an interface (used when no session id is available).
pub fn clear_security_for_interface(iface: &str) {
    if iface.is_empty() {
        return;
    }
    if let Ok(mut s) = store().lock() {
        s.alerts.retain(|a| a.interface != iface);
        s.flows.retain(|_, flow| flow.interface != iface);
        s.iface_stats.remove(iface);
        s.rebuild_stats_from_store();
    }
}

/// Clear alerts, flows, and related stats for one engine (`dlp` or `idps`).
/// Used when the user disables that engine so stale logs do not remain visible.
pub fn clear_security_engine(engine: &str) {
    let engine = engine.to_ascii_lowercase();
    if engine != "dlp" && engine != "idps" {
        return;
    }
    if let Ok(mut s) = store().lock() {
        s.alerts.retain(|a| a.engine != engine);
        s.flows.retain(|_, flow| flow.engine != engine);
        s.rebuild_stats_from_store();
    }
}

pub fn list_security_alerts(limit: usize) -> Vec<SecurityAlert> {
    store()
        .lock()
        .ok()
        .map(|s| {
            let start = s.alerts.len().saturating_sub(limit);
            s.alerts[start..].to_vec()
        })
        .unwrap_or_default()
}

pub fn list_security_flows(
    engine: Option<&str>,
    iface: Option<&str>,
    limit: usize,
) -> Vec<SecurityFlow> {
    store()
        .lock()
        .ok()
        .map(|s| {
            let mut flows: Vec<SecurityFlow> = s
                .flows
                .iter()
                .filter(|(_, f)| engine.is_none_or(|e| f.engine == e))
                .filter(|(_, f)| iface.is_none_or(|i| f.interface == i))
                .map(|(k, f)| SecurityFlow {
                    flow_key: k.clone(),
                    engine: f.engine.clone(),
                    protocol: f.protocol.clone(),
                    src: f.src.clone(),
                    dst: f.dst.clone(),
                    alert_count: f.alert_count,
                    packet_count: f.packet_count,
                    bytes: f.bytes,
                    first_ts: f.first_ts,
                    last_ts: f.last_ts,
                    top_rule: f.top_rule.clone(),
                    top_severity: f.top_severity.clone(),
                    verdict: f.verdict.clone(),
                    rules: f.rules.clone(),
                    interface: f.interface.clone(),
                    src_country: f.src_country.clone(),
                    dst_country: f.dst_country.clone(),
                })
                .collect();
            flows.sort_by_key(|b| std::cmp::Reverse(b.last_ts));
            flows.truncate(limit);
            flows
        })
        .unwrap_or_default()
}

pub fn list_security_interfaces() -> Vec<InterfaceSecurityStats> {
    store()
        .lock()
        .ok()
        .map(|s| {
            let mut out: Vec<InterfaceSecurityStats> = s
                .iface_stats
                .iter()
                .map(|(iface, stats)| {
                    let dlp_flows = s
                        .flows
                        .values()
                        .filter(|f| f.interface == *iface && f.engine == "dlp")
                        .count() as u64;
                    let idps_flows = s
                        .flows
                        .values()
                        .filter(|f| f.interface == *iface && f.engine == "idps")
                        .count() as u64;
                    InterfaceSecurityStats {
                        interface: iface.clone(),
                        stats: stats.clone(),
                        dlp_flows,
                        idps_flows,
                    }
                })
                .collect();
            out.sort_by(|a, b| a.interface.cmp(&b.interface));
            out
        })
        .unwrap_or_default()
}

pub fn security_stats() -> SecurityStats {
    store()
        .lock()
        .ok()
        .map(|s| s.stats.clone())
        .unwrap_or_default()
}

pub(crate) fn record_evaluation(
    alerts: &[SecurityAlert],
    verdict: SecurityAction,
    iface: &str,
    session_id: &str,
    bytes: u64,
    flow_key: &str,
) {
    if let Ok(mut s) = store().lock() {
        s.stats.packets_scanned += 1;
        match verdict {
            SecurityAction::Drop => s.stats.dropped += 1,
            SecurityAction::Redirect => s.stats.redirected += 1,
            SecurityAction::Quarantine => s.stats.quarantined += 1,
            SecurityAction::Pass if !alerts.is_empty() => s.stats.passed += 1,
            _ => {}
        }
        if !iface.is_empty() {
            s.touch_iface_stats(iface, verdict, !alerts.is_empty());
        }
        for alert in alerts {
            s.push_alert(alert.clone());
            let store_key = if session_id.is_empty() {
                format!("{}:{}", alert.engine, flow_key)
            } else {
                format!("{}:{}:{}", session_id, alert.engine, flow_key)
            };
            s.touch_flow(&store_key, alert, bytes);
        }
        s.recount_flow_stats();
    }
}
