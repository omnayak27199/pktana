// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use super::super::super::alert::AlertCtx;
use super::super::super::types::{AlertSeverity, SecurityAlert};

pub fn scan_http(ctx: &AlertCtx<'_>, payload: &str) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();
    for line in payload.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("authorization: basic") {
            alerts.push(ctx.alert(
                AlertSeverity::Critical,
                "dlp_http_basic_auth",
                "Cleartext HTTP Basic credentials",
                line,
            ));
        }
        if lower.contains("authorization: bearer") {
            alerts.push(ctx.alert(
                AlertSeverity::Critical,
                "dlp_http_bearer_token",
                "Bearer/OAuth token in cleartext HTTP",
                truncate_line(line),
            ));
        }
        if lower.contains("password=")
            || lower.contains("passwd=")
            || lower.contains("api_key=")
            || lower.contains("secret=")
            || lower.contains("token=")
        {
            alerts.push(ctx.alert(
                AlertSeverity::High,
                "dlp_http_cleartext_secret",
                "Credential-like parameter in cleartext HTTP",
                truncate_line(line),
            ));
        }
        if (lower.contains("set-cookie:") || lower.contains("cookie:"))
            && (lower.contains("session") || lower.contains("auth") || lower.contains("token"))
        {
            alerts.push(ctx.alert(
                AlertSeverity::High,
                "dlp_http_cookie_session",
                "Session cookie in cleartext HTTP",
                truncate_line(line),
            ));
        }
    }
    alerts
}

fn truncate_line(line: &str) -> String {
    if line.len() > 120 {
        format!("{}…", &line[..120])
    } else {
        line.to_string()
    }
}
