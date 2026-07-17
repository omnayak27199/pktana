// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use super::super::types::SecurityRuleDef;

pub fn dlp_rule_catalog() -> Vec<SecurityRuleDef> {
    vec![
        rule(
            "dlp_http_basic_auth",
            "Cleartext HTTP Basic credentials",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_http_bearer_token",
            "Bearer/OAuth token in cleartext HTTP",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_http_cleartext_secret",
            "Credential-like HTTP parameter",
            "high",
            "credentials",
        ),
        rule(
            "dlp_http_cookie_session",
            "Session cookie in cleartext HTTP",
            "high",
            "credentials",
        ),
        rule(
            "dlp_pan_detected",
            "Payment card number (PAN/PCI)",
            "critical",
            "pci",
        ),
        rule(
            "dlp_ssn_detected",
            "US Social Security Number",
            "critical",
            "pii",
        ),
        rule(
            "dlp_iban_detected",
            "International Bank Account Number",
            "critical",
            "financial",
        ),
        rule(
            "dlp_passport_detected",
            "Passport number pattern",
            "high",
            "pii",
        ),
        rule(
            "dlp_phone_bulk",
            "Bulk phone numbers in transfer",
            "medium",
            "pii",
        ),
        rule("dlp_email_bulk", "Bulk email exfiltration", "medium", "pii"),
        rule(
            "dlp_private_key",
            "Private key material in traffic",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_cloud_api_key",
            "Cloud API key leak",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_ftp_cleartext",
            "FTP cleartext transfer",
            "high",
            "protocol",
        ),
        rule(
            "dlp_smtp_cleartext",
            "SMTP cleartext credentials/content",
            "high",
            "protocol",
        ),
        rule(
            "dlp_telnet_cleartext",
            "Telnet cleartext session",
            "critical",
            "protocol",
        ),
        rule(
            "dlp_large_http",
            "Large cleartext HTTP body",
            "medium",
            "exfiltration",
        ),
        rule(
            "dlp_sensitive_file",
            "Sensitive file type in transfer",
            "high",
            "content",
        ),
        rule(
            "dlp_medical_record",
            "Medical record number pattern",
            "critical",
            "hipaa",
        ),
        rule(
            "dlp_custom",
            "Custom data identifier match",
            "high",
            "custom",
        ),
        rule(
            "dlp_github_token",
            "GitHub personal access token in traffic",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_slack_token",
            "Slack API token in plaintext transfer",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_jwt_token",
            "JWT/Bearer token in cleartext traffic",
            "high",
            "credentials",
        ),
        rule(
            "dlp_stripe_key",
            "Stripe API key in plaintext",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_db_connection",
            "Database connection string with credentials",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_npm_token",
            "NPM publish token in cleartext",
            "critical",
            "credentials",
        ),
        rule(
            "dlp_api_key_param",
            "API key in cleartext URL parameter",
            "high",
            "credentials",
        ),
        rule(
            "dlp_national_id",
            "National/government ID pattern",
            "high",
            "pii",
        ),
        rule(
            "dlp_google_token",
            "Google OAuth/API token in traffic",
            "critical",
            "credentials",
        ),
    ]
}

fn rule(id: &str, title: &str, severity: &str, category: &str) -> SecurityRuleDef {
    SecurityRuleDef {
        rule_id: id.into(),
        engine: "dlp".into(),
        title: title.into(),
        severity: severity.into(),
        default_action: "monitor".into(),
        category: category.into(),
        sid: 0,
        description: String::new(),
    }
}
