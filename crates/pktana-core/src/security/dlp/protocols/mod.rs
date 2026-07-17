// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

mod ftp;
mod http;
mod smtp;

pub use ftp::scan_ftp;
pub use http::scan_http;
pub use smtp::scan_smtp;

use super::super::alert::AlertCtx;
use super::super::types::{AlertSeverity, SecurityAlert};

pub fn protocol_alerts(
    ctx: &AlertCtx<'_>,
    app_proto: Option<&str>,
    payload: &str,
) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();
    match app_proto {
        Some("HTTP") => alerts.extend(scan_http(ctx, payload)),
        Some("SMTP") => alerts.extend(scan_smtp(ctx, payload)),
        Some("FTP Control") => alerts.extend(scan_ftp(ctx)),
        Some("Telnet") => alerts.push(ctx.alert(
            AlertSeverity::Critical,
            "dlp_telnet_cleartext",
            "Telnet cleartext remote access",
            "Legacy insecure remote shell — data visible on wire",
        )),
        _ => {}
    }
    alerts
}
