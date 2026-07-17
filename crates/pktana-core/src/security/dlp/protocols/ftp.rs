// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use super::super::super::alert::AlertCtx;
use super::super::super::types::{AlertSeverity, SecurityAlert};

pub fn scan_ftp(ctx: &AlertCtx<'_>) -> Vec<SecurityAlert> {
    vec![ctx.alert(
        AlertSeverity::High,
        "dlp_ftp_cleartext",
        "FTP cleartext file transfer",
        "Unencrypted file transfer channel",
    )]
}
