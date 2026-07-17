// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use crate::dpi::DeepPacket;

use super::super::alert::AlertCtx;
use super::super::config::SecurityConfig;
use super::super::types::{AlertSeverity, SecurityAlert, SecurityEngine};
use super::super::util::{endpoint, payload_snippet, proto_label};
use super::identifiers::{contains_email_exfil, scan_builtin, scan_custom};
use super::protocols::protocol_alerts;

pub fn scan(dp: &DeepPacket, ts: u64, cfg: &SecurityConfig) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();
    let src = endpoint(dp, true);
    let dst = endpoint(dp, false);
    let protocol = proto_label(dp);
    let action = cfg.dlp_action.clone();
    let payload = payload_snippet(dp);
    let app_proto = dp.app_proto.as_deref();
    let ctx = AlertCtx {
        ts,
        engine: SecurityEngine::Dlp,
        src: &src,
        dst: &dst,
        protocol: &protocol,
        risk_score: dp.risk_score,
        action: &action,
    };

    alerts.extend(protocol_alerts(&ctx, app_proto, &payload));

    for m in scan_builtin(&payload) {
        if !cfg.dlp_identifier_enabled(m.id) {
            continue;
        }
        alerts.push(severity_for(&ctx, m.id, m.category, m.detail));
    }

    for m in scan_custom(&payload, &cfg.dlp_custom_identifiers) {
        if !cfg.dlp_identifier_enabled("dlp_custom") {
            continue;
        }
        alerts.push(ctx.alert_full(
            AlertSeverity::High,
            "dlp_custom",
            "Custom data identifier match",
            m.detail,
            &protocol,
            m.category,
            0,
        ));
    }

    if contains_email_exfil(&payload, app_proto) && cfg.dlp_identifier_enabled("dlp_email_bulk") {
        alerts.push(ctx.alert(
            AlertSeverity::Medium,
            "dlp_email_bulk",
            "Bulk email addresses in cleartext transfer",
            "Possible email/data exfiltration",
        ));
    }

    if dp.frame_len > 9000
        && app_proto == Some("HTTP")
        && cfg.dlp_identifier_enabled("dlp_large_http")
    {
        alerts.push(ctx.alert(
            AlertSeverity::Medium,
            "dlp_large_http",
            "Large cleartext HTTP payload",
            format!("Frame size {} bytes", dp.frame_len),
        ));
    }

    alerts.dedup_by(|a, b| {
        a.rule_id == b.rule_id && a.src == b.src && a.dst == b.dst && a.detail == b.detail
    });
    alerts
}

fn severity_for(ctx: &AlertCtx<'_>, id: &str, category: &str, detail: String) -> SecurityAlert {
    let sev = match id {
        "dlp_pan_detected" | "dlp_ssn_detected" | "dlp_iban_detected" | "dlp_private_key"
        | "dlp_cloud_api_key" | "dlp_medical_record" => AlertSeverity::Critical,
        "dlp_passport_detected" | "dlp_sensitive_file" | "dlp_custom" => AlertSeverity::High,
        _ => AlertSeverity::Medium,
    };
    let title = match id {
        "dlp_pan_detected" => "Payment card number pattern in cleartext payload",
        "dlp_ssn_detected" => "Social Security Number pattern in payload",
        "dlp_iban_detected" => "IBAN financial identifier detected",
        "dlp_passport_detected" => "Passport number pattern detected",
        "dlp_phone_bulk" => "Bulk phone numbers in transfer",
        "dlp_private_key" => "Private key material in network traffic",
        "dlp_cloud_api_key" => "Cloud API key pattern detected",
        "dlp_sensitive_file" => "Sensitive file type in transfer",
        "dlp_medical_record" => "Medical record number pattern",
        _ => "DLP content match",
    };
    ctx.alert_full(sev, id, title, detail, ctx.protocol, category, 0)
}
