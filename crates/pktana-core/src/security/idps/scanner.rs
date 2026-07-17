// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use crate::dpi::DeepPacket;

use super::super::alert::AlertCtx;
use super::super::config::SecurityConfig;
use super::super::types::{AlertSeverity, SecurityAlert, SecurityEngine};
use super::super::util::{endpoint, proto_label};
use super::dpi_bridge::scan_dpi_risks;
use super::heuristics::scan_heuristics;
use super::signatures::{load_rules, match_signatures, threshold_allows};
use super::threshold::{track_and_detect, BehavioralHit};

pub fn scan(dp: &DeepPacket, ts: u64, cfg: &SecurityConfig) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();
    let src = endpoint(dp, true);
    let dst = endpoint(dp, false);
    let protocol = proto_label(dp);
    let action = cfg.idps_action.clone();
    let ctx = AlertCtx {
        ts,
        engine: SecurityEngine::Idps,
        src: &src,
        dst: &dst,
        protocol: &protocol,
        risk_score: dp.risk_score,
        action: &action,
    };

    alerts.extend(scan_dpi_risks(&ctx, dp));
    alerts.extend(scan_heuristics(&ctx, dp, cfg));

    let rules = load_rules(cfg);
    for hit in match_signatures(dp, &rules, cfg) {
        if !threshold_allows(hit.sid, &src, ts, cfg) {
            continue;
        }
        alerts.push(ctx.alert_full(
            hit.severity,
            &hit.rule_id,
            &hit.msg,
            hit.detail,
            &protocol,
            &hit.category,
            hit.sid,
        ));
    }

    let is_ssh_syn = dp.tcp_flags == Some(0x02) && dp.tcp_dst_port == Some(22);
    if let Some(behavior) = track_and_detect(&src, dp.tcp_dst_port, is_ssh_syn) {
        match behavior {
            BehavioralHit::PortScan { unique_ports } => {
                if cfg.idps_sid_enabled(2000009) {
                    alerts.push(ctx.alert_full(
                        AlertSeverity::High,
                        "idps_port_scan",
                        "TCP port scan pattern",
                        format!("{unique_ports} unique destination ports from {src}"),
                        &protocol,
                        "attempted-recon",
                        2000009,
                    ));
                }
            }
            BehavioralHit::SshBrute { attempts } => {
                if cfg.idps_sid_enabled(2000010) {
                    alerts.push(ctx.alert_full(
                        AlertSeverity::High,
                        "idps_ssh_brute",
                        "SSH brute-force indicator",
                        format!("{attempts} SSH SYN attempts from {src}"),
                        &protocol,
                        "attempted-admin",
                        2000010,
                    ));
                }
            }
        }
    }

    alerts.dedup_by(|a, b| a.rule_id == b.rule_id && a.src == b.src && a.dst == b.dst);
    alerts
}
