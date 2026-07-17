// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use crate::dpi::DeepPacket;

use super::super::alert::AlertCtx;
use super::super::config::SecurityConfig;
use super::super::types::{AlertSeverity, SecurityAlert};

const SUSPICIOUS_PORTS: &[u16] = &[
    23, 2323, 1337, 31337, 4444, 5555, 6666, 3389, 5900, 1433, 3306,
];

pub fn scan_heuristics(
    ctx: &AlertCtx<'_>,
    dp: &DeepPacket,
    cfg: &SecurityConfig,
) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();

    if let Some(port) = dp.tcp_dst_port.or(dp.udp_dst_port) {
        if SUSPICIOUS_PORTS.contains(&port) {
            alerts.push(ctx.alert_full(
                AlertSeverity::High,
                "idps_suspicious_port",
                "Connection to suspicious port",
                format!("Destination port {port}"),
                ctx.protocol,
                "policy-violation",
                2000003,
            ));
        }
    }

    if dp.app_proto.as_deref() == Some("Telnet") {
        alerts.push(ctx.alert_full(
            AlertSeverity::Critical,
            "idps_telnet",
            "Telnet cleartext remote access",
            "Legacy insecure remote shell protocol",
            ctx.protocol,
            "policy-violation",
            2000004,
        ));
    }

    if dp.ntp_amplification_risk {
        alerts.push(ctx.alert_full(
            AlertSeverity::Critical,
            "idps_ntp_amp",
            "NTP amplification attack pattern",
            "Oversized NTP response",
            ctx.protocol,
            "attempted-dos",
            2000005,
        ));
    }

    if let Some(name) = &dp.dns_query_name {
        if name.len() > 60 || name.matches('.').count() > 10 {
            alerts.push(ctx.alert_full(
                AlertSeverity::High,
                "idps_dns_tunnel",
                "Suspicious DNS query length",
                name.clone(),
                "DNS",
                "policy-violation",
                2000006,
            ));
        }
    }

    if dp.icmp_type == Some(8) && dp.frame_len > 512 {
        alerts.push(ctx.alert_full(
            AlertSeverity::Medium,
            "idps_icmp_large",
            "Large ICMP echo",
            format!("ICMP type 8, {} bytes", dp.frame_len),
            "ICMP",
            "attempted-recon",
            2000007,
        ));
    }

    if let Some(ja3_raw) = &dp.tls_ja3_raw {
        let fp = md5_hex(ja3_raw.as_bytes());
        if cfg
            .idps_blocked_ja3
            .iter()
            .any(|b| b.eq_ignore_ascii_case(&fp))
        {
            alerts.push(ctx.alert_full(
                AlertSeverity::High,
                "idps_ja3_block",
                "Blocked JA3 TLS fingerprint",
                format!("JA3={fp}"),
                "TLS",
                "policy-violation",
                2000008,
            ));
        }
    }

    if dp.tcp_flags == Some(0x02) && dp.tcp_dst_port == Some(22) {
        alerts.push(ctx.alert_full(
            AlertSeverity::Medium,
            "idps_ssh_syn",
            "SSH connection attempt",
            format!("SYN to port 22 from {}", ctx.src),
            ctx.protocol,
            "misc-activity",
            2000011,
        ));
    }

    // Suspicious HTTP scanning tool user-agents
    let payload_str = String::from_utf8_lossy(&dp.payload);
    let app_str = dp.app_detail.join("\n");
    let combined = format!("{payload_str}\n{app_str}");
    for line in combined.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("user-agent:") {
            for tool in &[
                "nikto",
                "sqlmap",
                "nmap",
                "masscan",
                "dirbuster",
                "gobuster",
                "hydra",
                "metasploit",
                "acunetix",
                "burpsuite",
                "nessus",
                "openvas",
                "w3af",
                "zap",
            ] {
                if lower.contains(tool) {
                    if cfg.idps_sid_enabled(2000012) {
                        alerts.push(ctx.alert_full(
                            AlertSeverity::High,
                            "idps_scan_ua",
                            "Security scanning tool user-agent detected",
                            line.to_string(),
                            "HTTP",
                            "attempted-recon",
                            2000012,
                        ));
                    }
                    break;
                }
            }
        }
    }

    // HTTP method probing (TRACE/DEBUG/TRACK methods)
    if dp.app_proto.as_deref() == Some("HTTP") {
        for line in combined.lines().take(3) {
            let upper = line.to_ascii_uppercase();
            for method in &["TRACE ", "DEBUG ", "TRACK ", "PROPFIND ", "PROPPATCH "] {
                if upper.starts_with(method) {
                    if cfg.idps_sid_enabled(2000013) {
                        alerts.push(ctx.alert_full(
                            AlertSeverity::Medium,
                            "idps_http_method_probe",
                            "Unusual HTTP method probe",
                            line.to_string(),
                            "HTTP",
                            "attempted-recon",
                            2000013,
                        ));
                    }
                    break;
                }
            }
        }
    }

    // SMTP open-relay attempt
    if dp.app_proto.as_deref() == Some("SMTP") && combined.contains("RCPT TO:") {
        let rcpt_count = combined.matches("RCPT TO:").count();
        if rcpt_count >= 10 && cfg.idps_sid_enabled(2000014) {
            alerts.push(ctx.alert_full(
                AlertSeverity::High,
                "idps_smtp_bulk",
                "SMTP bulk mail relay attempt",
                format!("{rcpt_count} RCPT TO recipients"),
                "SMTP",
                "policy-violation",
                2000014,
            ));
        }
    }

    // RDP connection attempt (SYN to port 3389)
    if dp.tcp_flags == Some(0x02) && dp.tcp_dst_port == Some(3389) && cfg.idps_sid_enabled(2000015)
    {
        alerts.push(ctx.alert_full(
            AlertSeverity::Medium,
            "idps_rdp_syn",
            "RDP connection attempt",
            format!("SYN to port 3389 from {}", ctx.src),
            ctx.protocol,
            "policy-violation",
            2000015,
        ));
    }

    // High-entropy DNS label (possible base64/data exfil via DNS)
    if let Some(entropy) = dp.dns_label_entropy {
        if entropy > 4.2 && cfg.idps_sid_enabled(2000016) {
            alerts.push(ctx.alert_full(
                AlertSeverity::High,
                "idps_dns_high_entropy",
                "High-entropy DNS label — possible exfiltration",
                format!("Label entropy {entropy:.2}"),
                "DNS",
                "policy-violation",
                2000016,
            ));
        }
    }

    alerts
}

fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}
