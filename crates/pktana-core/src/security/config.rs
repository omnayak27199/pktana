// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::policy::{policy_matches, PolicyMatchCtx};
use super::types::{SecurityAction, SecurityEngine, SecurityPolicyRule};

/// Sophos-style custom data identifier (regex pattern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpCustomIdentifier {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub category: String,
    pub severity: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub dlp_enabled: bool,
    pub idps_enabled: bool,
    /// Legacy alias kept for API compatibility.
    pub dlp_mode: String,
    pub idps_mode: String,
    pub dlp_action: String,
    pub idps_action: String,
    pub redirect_target: String,
    pub rule_actions: HashMap<String, String>,
    pub policy_rules: Vec<SecurityPolicyRule>,
    /// Disable built-in DLP identifiers by id (empty = all enabled).
    #[serde(default)]
    pub dlp_disabled_identifiers: Vec<String>,
    /// User-defined Sophos-style content identifiers.
    #[serde(default)]
    pub dlp_custom_identifiers: Vec<DlpCustomIdentifier>,
    /// Disable IDPS signature rules by Suricata sid (empty = all enabled).
    #[serde(default)]
    pub idps_disabled_sids: Vec<u32>,
    /// Additional Suricata-format signature rules (one rule per line).
    #[serde(default)]
    pub idps_custom_rules: Vec<String>,
    /// JA3 fingerprints to block/monitor (MD5 hex, lowercase).
    #[serde(default)]
    pub idps_blocked_ja3: Vec<String>,
    /// Per-signature threshold: sid -> count within window before alert.
    #[serde(default)]
    pub idps_threshold_count: HashMap<u32, u32>,
    /// Threshold window in seconds (default 60).
    #[serde(default = "default_threshold_window")]
    pub idps_threshold_window_secs: u64,
}

fn default_threshold_window() -> u64 {
    60
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            dlp_enabled: false,
            idps_enabled: false,
            dlp_mode: "monitor".into(),
            idps_mode: "monitor".into(),
            dlp_action: "monitor".into(),
            idps_action: "monitor".into(),
            redirect_target: String::new(),
            rule_actions: HashMap::new(),
            policy_rules: Vec::new(),
            dlp_disabled_identifiers: Vec::new(),
            dlp_custom_identifiers: Vec::new(),
            idps_disabled_sids: Vec::new(),
            idps_custom_rules: Vec::new(),
            idps_blocked_ja3: Vec::new(),
            idps_threshold_count: HashMap::new(),
            idps_threshold_window_secs: 60,
        }
    }
}

impl SecurityConfig {
    pub fn normalize(&mut self) {
        if self.dlp_action == "monitor" && self.dlp_mode != "monitor" {
            self.dlp_action = self.dlp_mode.clone();
        }
        if self.idps_action == "monitor" && self.idps_mode != "monitor" {
            self.idps_action = self.idps_mode.clone();
        }
        self.dlp_mode = self.dlp_action.clone();
        self.idps_mode = self.idps_action.clone();
    }

    pub fn action_for(&self, engine: SecurityEngine, rule_id: &str) -> SecurityAction {
        if let Some(a) = self.rule_actions.get(rule_id) {
            return SecurityAction::parse(a);
        }
        match engine {
            SecurityEngine::Dlp => SecurityAction::parse(&self.dlp_action),
            SecurityEngine::Idps => SecurityAction::parse(&self.idps_action),
        }
    }

    pub(crate) fn resolve_action(
        &self,
        engine: SecurityEngine,
        ctx: &PolicyMatchCtx<'_>,
    ) -> (SecurityAction, String, String) {
        let engine_str = match engine {
            SecurityEngine::Dlp => "dlp",
            SecurityEngine::Idps => "idps",
        };
        let mut matched: Vec<&SecurityPolicyRule> = self
            .policy_rules
            .iter()
            .filter(|r| policy_matches(r, engine_str, ctx))
            .collect();
        matched.sort_by_key(|r| std::cmp::Reverse(r.priority));
        if let Some(rule) = matched.first() {
            let action = SecurityAction::parse(&rule.action);
            let redirect = if action == SecurityAction::Redirect {
                if rule.redirect_target.is_empty() {
                    self.redirect_target.clone()
                } else {
                    rule.redirect_target.clone()
                }
            } else {
                String::new()
            };
            return (action, redirect, rule.id.clone());
        }
        (
            self.action_for(engine, ctx.rule_id),
            String::new(),
            String::new(),
        )
    }

    pub fn dlp_identifier_enabled(&self, id: &str) -> bool {
        !self.dlp_disabled_identifiers.iter().any(|d| d == id)
    }

    pub fn idps_sid_enabled(&self, sid: u32) -> bool {
        !self.idps_disabled_sids.contains(&sid)
    }
}
