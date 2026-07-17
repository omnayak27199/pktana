// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use super::super::types::SecurityRuleDef;

pub fn idps_rule_catalog() -> Vec<SecurityRuleDef> {
    let mut rules = vec![
        sig_rule(
            2000001,
            "idps_dpi_risk",
            "DPI risk signal",
            "medium",
            "anomaly",
        ),
        sig_rule(
            2000002,
            "idps_high_risk_score",
            "High composite risk score",
            "high",
            "anomaly",
        ),
        sig_rule(
            2000003,
            "idps_suspicious_port",
            "Connection to suspicious port",
            "high",
            "policy-violation",
        ),
        sig_rule(
            2000004,
            "idps_telnet",
            "Telnet cleartext session",
            "critical",
            "policy-violation",
        ),
        sig_rule(
            2000005,
            "idps_ntp_amp",
            "NTP amplification pattern",
            "critical",
            "attempted-dos",
        ),
        sig_rule(
            2000006,
            "idps_dns_tunnel",
            "DNS tunneling indicator",
            "high",
            "policy-violation",
        ),
        sig_rule(
            2000007,
            "idps_icmp_large",
            "Large ICMP echo probe",
            "medium",
            "attempted-recon",
        ),
        sig_rule(
            2000008,
            "idps_ja3_block",
            "Blocked JA3 TLS fingerprint",
            "high",
            "policy-violation",
        ),
        sig_rule(
            2000009,
            "idps_port_scan",
            "TCP port scan pattern",
            "high",
            "attempted-recon",
        ),
        sig_rule(
            2000010,
            "idps_ssh_brute",
            "SSH brute-force indicator",
            "high",
            "attempted-admin",
        ),
        sig_rule(
            2000011,
            "idps_ssh_syn",
            "SSH connection attempt",
            "medium",
            "misc-activity",
        ),
        sig_rule(
            2000012,
            "idps_scan_ua",
            "Security scanning tool user-agent",
            "high",
            "attempted-recon",
        ),
        sig_rule(
            2000013,
            "idps_http_method_probe",
            "Unusual HTTP method probe (TRACE/DEBUG)",
            "medium",
            "attempted-recon",
        ),
        sig_rule(
            2000014,
            "idps_smtp_bulk",
            "SMTP bulk mail relay attempt",
            "high",
            "policy-violation",
        ),
        sig_rule(
            2000015,
            "idps_rdp_syn",
            "RDP connection attempt",
            "medium",
            "policy-violation",
        ),
        sig_rule(
            2000016,
            "idps_dns_high_entropy",
            "High-entropy DNS label (exfiltration)",
            "high",
            "policy-violation",
        ),
    ];
    rules.extend(super::signatures::builtin_catalog());
    rules
}

fn sig_rule(sid: u32, id: &str, title: &str, severity: &str, category: &str) -> SecurityRuleDef {
    SecurityRuleDef {
        rule_id: id.into(),
        engine: "idps".into(),
        title: title.into(),
        severity: severity.into(),
        default_action: "monitor".into(),
        category: category.into(),
        sid,
        description: String::new(),
    }
}
