// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use crate::dpi::DeepPacket;

use super::super::alert::AlertCtx;
use super::super::types::{AlertSeverity, SecurityAlert};

pub fn scan_dpi_risks(ctx: &AlertCtx<'_>, dp: &DeepPacket) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();
    for reason in &dp.risk_reasons {
        let sev = if reason.contains("scan") || reason.contains("malformed") {
            AlertSeverity::High
        } else if reason.contains("amplification") || reason.contains("SSHv1") {
            AlertSeverity::Critical
        } else {
            AlertSeverity::Medium
        };
        alerts.push(ctx.alert_full(
            sev,
            "idps_dpi_risk",
            "DPI risk signal",
            reason.as_str(),
            ctx.protocol,
            "anomaly",
            2000001,
        ));
    }

    if dp.risk_score >= 70 {
        alerts.push(ctx.alert_full(
            AlertSeverity::High,
            "idps_high_risk_score",
            "High composite risk score",
            format!("Risk score {}/100", dp.risk_score),
            ctx.protocol,
            "anomaly",
            2000002,
        ));
    }
    alerts
}
