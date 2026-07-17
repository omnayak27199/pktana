// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::dpi::DeepPacket;

use super::super::config::SecurityConfig;
use super::super::types::AlertSeverity;

#[derive(Debug, Clone)]
pub struct SignatureRule {
    pub sid: u32,
    pub rule_id: String,
    pub msg: String,
    pub protocol: String,
    pub dst_port: Option<u16>,
    pub content: Vec<u8>,
    pub nocase: bool,
    pub severity: AlertSeverity,
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct SignatureHit {
    pub sid: u32,
    pub rule_id: String,
    pub msg: String,
    pub detail: String,
    pub severity: AlertSeverity,
    pub category: String,
}

pub fn load_rules(cfg: &SecurityConfig) -> Vec<SignatureRule> {
    let mut rules = builtin_rules();
    for line in &cfg.idps_custom_rules {
        if let Some(rule) = parse_rule_line(line) {
            rules.push(rule);
        }
    }
    rules
}

pub fn match_signatures(
    dp: &DeepPacket,
    rules: &[SignatureRule],
    cfg: &SecurityConfig,
) -> Vec<SignatureHit> {
    let payload = if !dp.payload.is_empty() {
        dp.payload.clone()
    } else {
        dp.app_detail.join("\n").into_bytes()
    };
    let payload_str = String::from_utf8_lossy(&payload);
    let proto = dp.ip_proto_name.unwrap_or("unknown").to_ascii_lowercase();
    let dst_port = dp.tcp_dst_port.or(dp.udp_dst_port);

    let mut hits = Vec::new();
    for rule in rules {
        if !cfg.idps_sid_enabled(rule.sid) {
            continue;
        }
        if !protocol_matches(&rule.protocol, &proto) {
            continue;
        }
        if let Some(want) = rule.dst_port {
            if dst_port != Some(want) {
                continue;
            }
        }
        if rule.content.is_empty() {
            continue;
        }
        let matched = if rule.nocase {
            payload_str
                .to_ascii_lowercase()
                .contains(&String::from_utf8_lossy(&rule.content).to_ascii_lowercase())
        } else {
            payload
                .windows(rule.content.len())
                .any(|w| w == rule.content.as_slice())
                || payload_str.contains(String::from_utf8_lossy(&rule.content).as_ref())
        };
        if matched {
            hits.push(SignatureHit {
                sid: rule.sid,
                rule_id: rule.rule_id.clone(),
                msg: rule.msg.clone(),
                detail: rule.msg.clone(),
                severity: rule.severity,
                category: rule.category.clone(),
            });
        }
    }
    hits
}

pub fn builtin_catalog() -> Vec<super::super::types::SecurityRuleDef> {
    builtin_rules()
        .into_iter()
        .map(|r| super::super::types::SecurityRuleDef {
            rule_id: r.rule_id,
            engine: "idps".into(),
            title: r.msg,
            severity: r.severity.as_str().into(),
            default_action: "monitor".into(),
            category: r.category,
            sid: r.sid,
            description: String::new(),
        })
        .collect()
}

fn builtin_rules() -> Vec<SignatureRule> {
    vec![
        sig(
            2100001,
            "idps_sig_shellcode_nop",
            "ET EXPLOIT Possible NOP sled",
            "tcp",
            None,
            b"\x90\x90\x90",
            false,
            AlertSeverity::High,
            "attempted-admin",
        ),
        sig(
            2100002,
            "idps_sig_sqli_union",
            "ET WEB_SERVER SQL Injection UNION SELECT",
            "tcp",
            Some(80),
            b"UNION SELECT",
            true,
            AlertSeverity::High,
            "web-application-attack",
        ),
        sig(
            2100003,
            "idps_sig_xss_script",
            "ET WEB_CLIENT XSS script tag",
            "tcp",
            None,
            b"<script",
            true,
            AlertSeverity::Medium,
            "web-application-attack",
        ),
        sig(
            2100004,
            "idps_sig_cmd_injection",
            "ET WEB_SERVER Command injection",
            "tcp",
            None,
            b"; /bin/sh",
            false,
            AlertSeverity::Critical,
            "attempted-admin",
        ),
        sig(
            2100005,
            "idps_sig_ldap_injection",
            "ET WEB_SERVER LDAP injection",
            "tcp",
            None,
            b")(|(password=",
            true,
            AlertSeverity::High,
            "web-application-attack",
        ),
        sig(
            2100006,
            "idps_sig_reverse_shell",
            "ET EXPLOIT Possible reverse shell",
            "tcp",
            None,
            b"/bin/bash -i",
            false,
            AlertSeverity::Critical,
            "attempted-admin",
        ),
        sig(
            2100007,
            "idps_sig_mirai",
            "ET MALWARE Mirai botnet string",
            "tcp",
            None,
            b"/bin/busybox",
            false,
            AlertSeverity::Critical,
            "trojan-activity",
        ),
        sig(
            2100008,
            "idps_sig_cryptominer",
            "ET POLICY Cryptominer pool connection",
            "tcp",
            Some(3333),
            b"mining.subscribe",
            true,
            AlertSeverity::High,
            "policy-violation",
        ),
        sig(
            2100009,
            "idps_sig_ftp_bounce",
            "ET POLICY FTP bounce attempt",
            "tcp",
            Some(21),
            b"PORT 127,0,0,1",
            true,
            AlertSeverity::High,
            "policy-violation",
        ),
        sig(
            2100010,
            "idps_sig_smb_eternal",
            "ET EXPLOIT EternalBlue SMB signature",
            "tcp",
            Some(445),
            b"\x00\x00\x00\x00\x18\x53\x00",
            false,
            AlertSeverity::Critical,
            "attempted-admin",
        ),
        sig(
            2100011,
            "idps_sig_log4shell",
            "ET EXPLOIT Apache Log4j JNDI Injection CVE-2021-44228",
            "tcp",
            None,
            b"${jndi:",
            false,
            AlertSeverity::Critical,
            "attempted-admin",
        ),
        sig(
            2100012,
            "idps_sig_log4shell_obf",
            "ET EXPLOIT Log4j Obfuscated JNDI Injection variant",
            "tcp",
            None,
            b"${${::-j}ndi",
            false,
            AlertSeverity::Critical,
            "attempted-admin",
        ),
        sig(
            2100013,
            "idps_sig_spring4shell",
            "ET EXPLOIT Spring4Shell RCE CVE-2022-22965",
            "tcp",
            Some(80),
            b"class.module.classLoader",
            false,
            AlertSeverity::Critical,
            "attempted-admin",
        ),
        sig(
            2100014,
            "idps_sig_xxe",
            "ET WEB_SERVER XML External Entity Injection",
            "tcp",
            None,
            b"<!ENTITY",
            true,
            AlertSeverity::High,
            "web-application-attack",
        ),
        sig(
            2100015,
            "idps_sig_ssrf_aws",
            "ET ATTACK SSRF targeting AWS metadata endpoint",
            "tcp",
            None,
            b"169.254.169.254",
            false,
            AlertSeverity::Critical,
            "attempted-admin",
        ),
        sig(
            2100016,
            "idps_sig_path_traversal",
            "ET WEB_SERVER Directory traversal attack",
            "tcp",
            None,
            b"../../../etc/passwd",
            false,
            AlertSeverity::High,
            "web-application-attack",
        ),
        sig(
            2100017,
            "idps_sig_crlf",
            "ET WEB_SERVER HTTP Response Splitting CRLF",
            "tcp",
            None,
            b"\r\nContent-Type:",
            false,
            AlertSeverity::High,
            "web-application-attack",
        ),
        sig(
            2100018,
            "idps_sig_php_rfi",
            "ET WEB_SERVER PHP Remote File Inclusion",
            "tcp",
            Some(80),
            b"include($_GET[",
            false,
            AlertSeverity::Critical,
            "web-application-attack",
        ),
        sig(
            2100019,
            "idps_sig_java_deser",
            "ET EXPLOIT Java deserialization magic bytes",
            "tcp",
            None,
            b"\xac\xed\x00\x05",
            false,
            AlertSeverity::High,
            "attempted-admin",
        ),
        sig(
            2100020,
            "idps_sig_heartbleed",
            "ET EXPLOIT OpenSSL HeartBleed probe",
            "tcp",
            Some(443),
            b"\x18\x03\x02",
            false,
            AlertSeverity::Critical,
            "attempted-admin",
        ),
        sig(
            2100021,
            "idps_sig_dns_rebind",
            "ET ATTACK DNS rebinding attempt",
            "udp",
            Some(53),
            b"rebind",
            true,
            AlertSeverity::High,
            "attempted-admin",
        ),
        sig(
            2100022,
            "idps_sig_host_inject",
            "ET WEB_SERVER HTTP Host header injection",
            "tcp",
            Some(80),
            b"Host: localhost",
            true,
            AlertSeverity::High,
            "web-application-attack",
        ),
        sig(
            2100023,
            "idps_sig_ransom_note",
            "ET MALWARE Ransomware activity indicator",
            "tcp",
            None,
            b"YOUR FILES HAVE BEEN ENCRYPTED",
            true,
            AlertSeverity::Critical,
            "trojan-activity",
        ),
        sig(
            2100024,
            "idps_sig_ssti",
            "ET WEB_SERVER Server-Side Template Injection",
            "tcp",
            Some(80),
            b"{{7*7}}",
            false,
            AlertSeverity::High,
            "web-application-attack",
        ),
        sig(
            2100025,
            "idps_sig_sqli_sleep",
            "ET WEB_SERVER SQL Injection time-based blind",
            "tcp",
            Some(80),
            b"SLEEP(5)",
            true,
            AlertSeverity::High,
            "web-application-attack",
        ),
        sig(
            2100026,
            "idps_sig_webshell",
            "ET WEBSHELL Generic webshell indicator",
            "tcp",
            Some(80),
            b"cmd=",
            false,
            AlertSeverity::High,
            "web-application-attack",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn sig(
    sid: u32,
    rule_id: &str,
    msg: &str,
    protocol: &str,
    dst_port: Option<u16>,
    content: &[u8],
    nocase: bool,
    severity: AlertSeverity,
    category: &str,
) -> SignatureRule {
    SignatureRule {
        sid,
        rule_id: rule_id.into(),
        msg: msg.into(),
        protocol: protocol.into(),
        dst_port,
        content: content.to_vec(),
        nocase,
        severity,
        category: category.into(),
    }
}

fn protocol_matches(rule_proto: &str, actual: &str) -> bool {
    rule_proto == "ip" || rule_proto == actual
}

pub fn parse_rule_line(line: &str) -> Option<SignatureRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    if !lower.starts_with("alert ") {
        return None;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 7 {
        return None;
    }
    let protocol = parts[1].to_ascii_lowercase();
    let dst_port = parse_port_spec(parts[5]);
    let options = line.split('(').nth(1)?.trim_end_matches(')');
    let mut sid = 0u32;
    let mut msg = String::new();
    let mut content = Vec::new();
    let mut nocase = false;
    for opt in options.split(';') {
        let opt = opt.trim();
        if let Some(v) = opt.strip_prefix("sid:") {
            sid = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = opt.strip_prefix("msg:") {
            msg = v.trim().trim_matches('"').to_string();
        } else if let Some(v) = opt.strip_prefix("content:") {
            content = parse_content(v.trim().trim_matches('"'));
        } else if opt == "nocase" {
            nocase = true;
        }
    }
    if sid == 0 {
        return None;
    }
    Some(SignatureRule {
        sid,
        rule_id: format!("idps_sig_{sid}"),
        msg: if msg.is_empty() {
            format!("Custom signature sid:{sid}")
        } else {
            msg
        },
        protocol,
        dst_port,
        content,
        nocase,
        severity: AlertSeverity::High,
        category: "custom".into(),
    })
}

fn parse_port_spec(spec: &str) -> Option<u16> {
    if spec == "any" {
        return None;
    }
    spec.parse().ok()
}

fn parse_content(raw: &str) -> Vec<u8> {
    if raw.contains('|') {
        let mut out = Vec::new();
        let mut hex = false;
        for part in raw.split('|') {
            if hex {
                let digits: String = part.chars().filter(|c| !c.is_whitespace()).collect();
                for chunk in digits.as_bytes().chunks(2) {
                    if chunk.len() == 2 {
                        if let Ok(b) =
                            u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("00"), 16)
                        {
                            out.push(b);
                        }
                    }
                }
                hex = false;
            } else {
                out.extend(part.as_bytes());
                hex = true;
            }
        }
        out
    } else {
        raw.as_bytes().to_vec()
    }
}

type ThresholdMap = HashMap<(u32, String), Vec<u64>>;

static THRESHOLD: OnceLock<Mutex<ThresholdMap>> = OnceLock::new();

pub fn threshold_allows(sid: u32, src: &str, ts: u64, cfg: &SecurityConfig) -> bool {
    let threshold = cfg.idps_threshold_count.get(&sid).copied().unwrap_or(1);
    if threshold <= 1 {
        return true;
    }
    let window = cfg.idps_threshold_window_secs;
    let key = (sid, src.to_string());
    let lock = THRESHOLD.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut map) = lock.lock() else {
        return true;
    };
    let entry = map.entry(key).or_default();
    entry.retain(|t| ts.saturating_sub(*t) <= window);
    entry.push(ts);
    entry.len() as u32 >= threshold
}
