// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use super::super::super::alert::AlertCtx;
use super::super::super::types::{AlertSeverity, SecurityAlert};

pub fn scan_smtp(ctx: &AlertCtx<'_>, payload: &str) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();
    let lower = payload.to_ascii_lowercase();
    if lower.contains("auth plain")
        || lower.contains("auth login")
        || lower.contains("password")
        || lower.contains("passwd")
    {
        alerts.push(ctx.alert(
            AlertSeverity::High,
            "dlp_smtp_cleartext",
            "SMTP cleartext authentication or credentials",
            "AUTH or credential keyword in SMTP session",
        ));
    }
    alerts
}
