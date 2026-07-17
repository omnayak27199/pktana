// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use super::types::{AlertSeverity, SecurityAlert, SecurityEngine};

pub(crate) struct AlertCtx<'a> {
    pub ts: u64,
    pub engine: SecurityEngine,
    pub src: &'a str,
    pub dst: &'a str,
    pub protocol: &'a str,
    pub risk_score: u8,
    pub action: &'a str,
}

impl AlertCtx<'_> {
    pub fn alert(
        &self,
        severity: AlertSeverity,
        rule_id: &str,
        title: &str,
        detail: impl Into<String>,
    ) -> SecurityAlert {
        self.alert_full(severity, rule_id, title, detail, self.protocol, "", 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn alert_full(
        &self,
        severity: AlertSeverity,
        rule_id: &str,
        title: &str,
        detail: impl Into<String>,
        protocol: &str,
        category: &str,
        sid: u32,
    ) -> SecurityAlert {
        SecurityAlert {
            ts: self.ts,
            engine: match self.engine {
                SecurityEngine::Dlp => "dlp".into(),
                SecurityEngine::Idps => "idps".into(),
            },
            severity: severity.as_str().into(),
            rule_id: rule_id.into(),
            title: title.into(),
            detail: detail.into(),
            src: self.src.to_string(),
            dst: self.dst.to_string(),
            protocol: protocol.to_string(),
            risk_score: self.risk_score,
            action: self.action.to_string(),
            flow_key: String::new(),
            verdict: self.action.to_string(),
            interface: String::new(),
            src_country: String::new(),
            dst_country: String::new(),
            policy_id: String::new(),
            category: category.into(),
            sid,
            session_id: String::new(),
        }
    }
}
