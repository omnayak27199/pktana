// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use crate::dpi::inspect;

use super::*;

#[test]
fn dlp_detects_http_basic() {
    let cfg = SecurityConfig {
        dlp_enabled: true,
        ..Default::default()
    };
    let mut dp = inspect(&[]);
    dp.frame_len = 100;
    dp.app_proto = Some("HTTP".into());
    dp.app_detail
        .push("Authorization: Basic dXNlcjpwYXNzd29yZA==".into());
    dp.ip_src = Some("10.0.0.1".parse().unwrap());
    dp.ip_dst = Some("8.8.8.8".parse().unwrap());
    let alerts = scan_dlp(&dp, 0, &cfg);
    assert!(alerts.iter().any(|a| a.rule_id == "dlp_http_basic_auth"));
}

#[test]
fn dlp_detects_pan() {
    let cfg = SecurityConfig {
        dlp_enabled: true,
        ..Default::default()
    };
    let mut dp = inspect(&[]);
    dp.frame_len = 100;
    dp.app_proto = Some("HTTP".into());
    dp.app_detail.push("card=4111111111111111".into());
    let alerts = scan_dlp(&dp, 0, &cfg);
    assert!(alerts.iter().any(|a| a.rule_id == "dlp_pan_detected"));
}

#[test]
fn idps_flags_high_risk() {
    let cfg = SecurityConfig {
        idps_enabled: true,
        ..Default::default()
    };
    let mut dp = inspect(&[]);
    dp.frame_len = 64;
    dp.risk_score = 85;
    dp.risk_reasons.push("test".into());
    let alerts = scan_idps(&dp, 0, &cfg);
    assert!(alerts.iter().any(|a| a.rule_id == "idps_high_risk_score"));
}

#[test]
fn idps_signature_sqli() {
    let cfg = SecurityConfig {
        idps_enabled: true,
        ..Default::default()
    };
    let mut dp = inspect(&[]);
    dp.frame_len = 200;
    dp.ip_proto_name = Some("tcp");
    dp.tcp_dst_port = Some(80);
    dp.payload = b"GET /?q=1 UNION SELECT password FROM users".to_vec();
    let alerts = scan_idps(&dp, 0, &cfg);
    assert!(alerts.iter().any(|a| a.rule_id == "idps_sig_sqli_union"));
}

#[test]
fn drop_action_sets_verdict() {
    clear_security_alerts();
    set_security_config(SecurityConfig {
        dlp_enabled: true,
        dlp_action: "drop".into(),
        ..Default::default()
    });
    let mut dp = inspect(&[]);
    dp.frame_len = 100;
    dp.app_proto = Some("HTTP".into());
    dp.app_detail
        .push("Authorization: Basic dXNlcjpwYXNzd29yZA==".into());
    dp.ip_src = Some("10.0.0.1".parse().unwrap());
    dp.ip_dst = Some("8.8.8.8".parse().unwrap());
    let result = evaluate_packet(&dp, 1, 100, "eth0", "sess-1");
    assert_eq!(result.verdict, "drop");
    assert!(result.dropped);
    let flows = list_security_flows(Some("dlp"), None, 10);
    assert!(!flows.is_empty());
    assert_eq!(flows[0].interface, "eth0");
}

#[test]
fn policy_rule_overrides_default_action() {
    clear_security_alerts();
    set_security_config(SecurityConfig {
        dlp_enabled: true,
        dlp_action: "monitor".into(),
        policy_rules: vec![SecurityPolicyRule {
            id: "p1".into(),
            name: "Drop external".into(),
            enabled: true,
            priority: 100,
            engine: "dlp".into(),
            interface: String::new(),
            src_ip: String::new(),
            dst_ip: "8.8.8.8".into(),
            src_country: String::new(),
            dst_country: String::new(),
            detection_rule: String::new(),
            action: "drop".into(),
            redirect_target: String::new(),
        }],
        ..Default::default()
    });
    let mut dp = inspect(&[]);
    dp.frame_len = 100;
    dp.app_proto = Some("HTTP".into());
    dp.app_detail
        .push("Authorization: Basic dXNlcjpwYXNzd29yZA==".into());
    dp.ip_src = Some("10.0.0.1".parse().unwrap());
    dp.ip_dst = Some("8.8.8.8".parse().unwrap());
    let result = evaluate_packet(&dp, 2, 100, "eth0", "sess-2");
    assert_eq!(result.verdict, "drop");
    let alerts = list_security_alerts(10);
    assert!(alerts.iter().any(|a| a.policy_id == "p1"));
}

#[test]
fn clear_session_removes_alerts_and_flows() {
    clear_security_alerts();
    set_security_config(SecurityConfig {
        dlp_enabled: true,
        ..Default::default()
    });
    let mut dp = inspect(&[]);
    dp.frame_len = 100;
    dp.app_proto = Some("HTTP".into());
    dp.app_detail
        .push("Authorization: Basic dXNlcjpwYXNzd29yZA==".into());
    dp.ip_src = Some("10.0.0.1".parse().unwrap());
    dp.ip_dst = Some("8.8.8.8".parse().unwrap());
    evaluate_packet(&dp, 1, 100, "eth0", "sess-close");
    assert!(!list_security_alerts(10).is_empty());
    assert!(!list_security_flows(Some("dlp"), None, 10).is_empty());

    clear_security_for_session("sess-close");
    assert!(list_security_alerts(10).is_empty());
    assert!(list_security_flows(Some("dlp"), None, 10).is_empty());
}

#[test]
fn clear_engine_removes_only_that_engine() {
    clear_security_alerts();
    set_security_config(SecurityConfig {
        dlp_enabled: true,
        idps_enabled: true,
        ..Default::default()
    });
    let mut dp = inspect(&[]);
    dp.frame_len = 100;
    dp.app_proto = Some("HTTP".into());
    dp.app_detail
        .push("Authorization: Basic dXNlcjpwYXNzd29yZA==".into());
    dp.ip_src = Some("10.0.0.1".parse().unwrap());
    dp.ip_dst = Some("8.8.8.8".parse().unwrap());
    dp.risk_score = 90;
    dp.risk_reasons.push("test".into());
    evaluate_packet(&dp, 1, 100, "eth0", "s1");
    assert!(list_security_alerts(50)
        .iter()
        .any(|a| a.engine == "dlp"));
    assert!(list_security_alerts(50)
        .iter()
        .any(|a| a.engine == "idps"));

    clear_security_engine("dlp");
    assert!(!list_security_alerts(50)
        .iter()
        .any(|a| a.engine == "dlp"));
    assert!(list_security_alerts(50)
        .iter()
        .any(|a| a.engine == "idps"));
    assert!(list_security_flows(Some("dlp"), None, 10).is_empty());
}

#[test]
fn custom_dlp_identifier() {
    let cfg = SecurityConfig {
        dlp_enabled: true,
        dlp_custom_identifiers: vec![DlpCustomIdentifier {
            id: "proj_alpha".into(),
            name: "Project Alpha code".into(),
            pattern: "PROJ-ALPHA-".into(),
            category: "custom".into(),
            severity: "high".into(),
            enabled: true,
        }],
        ..Default::default()
    };
    let mut dp = inspect(&[]);
    dp.frame_len = 64;
    dp.app_detail.push("secret=PROJ-ALPHA-998877".into());
    let alerts = scan_dlp(&dp, 0, &cfg);
    assert!(alerts.iter().any(|a| a.rule_id == "dlp_custom"));
}

#[test]
fn custom_suricata_rule() {
    let cfg = SecurityConfig {
        idps_enabled: true,
        idps_custom_rules: vec![
            r#"alert tcp any any -> any any (msg:"Custom test rule"; content:"EVILPAYLOAD"; sid:9999001; rev:1;)"#
                .into(),
        ],
        ..Default::default()
    };
    let mut dp = inspect(&[]);
    dp.frame_len = 64;
    dp.ip_proto_name = Some("tcp");
    dp.payload = b"EVILPAYLOAD detected".to_vec();
    let alerts = scan_idps(&dp, 0, &cfg);
    assert!(alerts.iter().any(|a| a.sid == 9999001));
}
