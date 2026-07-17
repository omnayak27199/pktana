// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use crate::dpi::DeepPacket;

use super::dlp;
use super::idps;
use super::policy::PolicyMatchCtx;
use super::store::{get_security_config, record_evaluation};
use super::types::{
    action_rank, PacketSecurityResult, SecurityAction, SecurityAlert, SecurityEngine,
};
use super::util::{endpoint, endpoint_country, ip_host, make_flow_key, proto_label};

pub fn analyze_packet(dp: &DeepPacket, ts: u64) -> Vec<SecurityAlert> {
    evaluate_packet(dp, ts, dp.frame_len as u64, "", "").alerts
}

pub fn evaluate_packet(
    dp: &DeepPacket,
    ts: u64,
    bytes: u64,
    iface: &str,
    session_id: &str,
) -> PacketSecurityResult {
    let cfg = get_security_config();
    let src = endpoint(dp, true);
    let dst = endpoint(dp, false);
    let src_ip = ip_host(&src);
    let dst_ip = ip_host(&dst);
    let src_country = endpoint_country(dp, true);
    let dst_country = endpoint_country(dp, false);
    let protocol = proto_label(dp);
    let flow_key = make_flow_key(&protocol, &src, &dst);

    let mut raw_alerts = Vec::new();
    if cfg.dlp_enabled {
        raw_alerts.extend(dlp::scan(dp, ts, &cfg));
    }
    if cfg.idps_enabled {
        raw_alerts.extend(idps::scan(dp, ts, &cfg));
    }

    let mut engines = Vec::new();
    let mut strongest = SecurityAction::Pass;
    let mut alerts = Vec::new();
    let mut redirect_target = String::new();
    let policy_ctx = PolicyMatchCtx {
        iface,
        rule_id: "",
        src_ip: &src_ip,
        dst_ip: &dst_ip,
        src_country: &src_country,
        dst_country: &dst_country,
    };

    for mut alert in raw_alerts {
        let engine = if alert.engine == "dlp" {
            SecurityEngine::Dlp
        } else {
            SecurityEngine::Idps
        };
        if !engines.contains(&alert.engine) {
            engines.push(alert.engine.clone());
        }
        let mut match_ctx = policy_ctx;
        match_ctx.rule_id = &alert.rule_id;
        let (action, rule_redirect, policy_id) = cfg.resolve_action(engine, &match_ctx);
        alert.action = action.as_str().into();
        alert.flow_key = flow_key.clone();
        alert.verdict = action.as_str().into();
        alert.interface = iface.to_string();
        alert.session_id = session_id.to_string();
        alert.src_country = src_country.clone();
        alert.dst_country = dst_country.clone();
        alert.policy_id = policy_id;
        if action_rank(action) > action_rank(strongest) {
            strongest = action;
            redirect_target = if action == SecurityAction::Redirect {
                if rule_redirect.is_empty() {
                    cfg.redirect_target.clone()
                } else {
                    rule_redirect
                }
            } else {
                String::new()
            };
        }
        alerts.push(alert);
    }

    let verdict = if alerts.is_empty() {
        SecurityAction::Pass
    } else {
        strongest
    };

    if redirect_target.is_empty() && verdict == SecurityAction::Redirect {
        redirect_target = cfg.redirect_target.clone();
    }

    record_evaluation(&alerts, verdict, iface, session_id, bytes, &flow_key);

    PacketSecurityResult {
        alerts,
        verdict: verdict.as_str().into(),
        flow_key,
        engines,
        dropped: verdict == SecurityAction::Drop,
        redirect_target,
        interface: iface.to_string(),
    }
}
