// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use super::super::config::DlpCustomIdentifier;

pub struct IdentifierMatch {
    pub id: &'static str,
    pub category: &'static str,
    pub detail: String,
}

pub fn scan_builtin(payload: &str) -> Vec<IdentifierMatch> {
    let mut out = Vec::new();
    if contains_credit_card(payload) {
        out.push(id_match(
            "dlp_pan_detected",
            "pci",
            "Possible PAN/PCI data exposure",
        ));
    }
    if contains_ssn(payload) {
        out.push(id_match("dlp_ssn_detected", "pii", "Possible SSN exposure"));
    }
    if contains_iban(payload) {
        out.push(id_match(
            "dlp_iban_detected",
            "financial",
            "IBAN pattern detected",
        ));
    }
    if contains_passport(payload) {
        out.push(id_match(
            "dlp_passport_detected",
            "pii",
            "Passport number pattern",
        ));
    }
    if contains_medical_record(payload) {
        out.push(id_match(
            "dlp_medical_record",
            "hipaa",
            "Medical record number pattern",
        ));
    }
    if count_phone_numbers(payload) >= 5 {
        out.push(id_match(
            "dlp_phone_bulk",
            "pii",
            format!("{} phone number patterns", count_phone_numbers(payload)),
        ));
    }
    if payload.contains("BEGIN RSA PRIVATE KEY")
        || payload.contains("BEGIN OPENSSH PRIVATE KEY")
        || payload.contains("BEGIN EC PRIVATE KEY")
        || payload.contains("BEGIN PGP PRIVATE KEY BLOCK")
    {
        out.push(id_match(
            "dlp_private_key",
            "credentials",
            "Private key block detected",
        ));
    }
    if looks_like_aws_key(payload) || looks_like_azure_key(payload) || looks_like_gcp_key(payload) {
        out.push(id_match(
            "dlp_cloud_api_key",
            "credentials",
            "Cloud provider API key pattern",
        ));
    }
    if let Some(kind) = detect_sensitive_file(payload.as_bytes()) {
        out.push(id_match(
            "dlp_sensitive_file",
            "content",
            format!("Sensitive file signature: {kind}"),
        ));
    }
    if looks_like_github_token(payload) {
        out.push(id_match(
            "dlp_github_token",
            "credentials",
            "GitHub personal access token detected",
        ));
    }
    if looks_like_slack_token(payload) {
        out.push(id_match(
            "dlp_slack_token",
            "credentials",
            "Slack API token detected",
        ));
    }
    if contains_jwt(payload) {
        out.push(id_match(
            "dlp_jwt_token",
            "credentials",
            "JWT token in plaintext transfer",
        ));
    }
    if looks_like_stripe_key(payload) {
        out.push(id_match(
            "dlp_stripe_key",
            "credentials",
            "Stripe API key detected",
        ));
    }
    if contains_db_connection_string(payload) {
        out.push(id_match(
            "dlp_db_connection",
            "credentials",
            "Database connection string with embedded credentials",
        ));
    }
    if looks_like_npm_token(payload) {
        out.push(id_match(
            "dlp_npm_token",
            "credentials",
            "NPM publish token detected",
        ));
    }
    if contains_api_key_param(payload) {
        out.push(id_match(
            "dlp_api_key_param",
            "credentials",
            "API key in cleartext URL parameter",
        ));
    }
    if contains_national_id(payload) {
        out.push(id_match(
            "dlp_national_id",
            "pii",
            "Government/national ID pattern detected",
        ));
    }
    if looks_like_google_token(payload) {
        out.push(id_match(
            "dlp_google_token",
            "credentials",
            "Google OAuth/service account token detected",
        ));
    }
    out
}

pub fn scan_custom(payload: &str, rules: &[DlpCustomIdentifier]) -> Vec<IdentifierMatch> {
    let mut out = Vec::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        if simple_pattern_match(payload, &rule.pattern) {
            out.push(IdentifierMatch {
                id: "dlp_custom",
                category: "custom",
                detail: format!("{} ({})", rule.name, rule.id),
            });
        }
    }
    out
}

fn id_match(
    id: &'static str,
    category: &'static str,
    detail: impl Into<String>,
) -> IdentifierMatch {
    IdentifierMatch {
        id,
        category,
        detail: detail.into(),
    }
}

fn simple_pattern_match(haystack: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if let Some(re) = pattern.strip_prefix("regex:") {
        return regex_match(haystack, re);
    }
    haystack.contains(pattern)
}

fn regex_match(haystack: &str, pattern: &str) -> bool {
    regex::Regex::new(pattern)
        .ok()
        .is_some_and(|re| re.is_match(haystack))
}

pub fn contains_credit_card(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 13 {
        return false;
    }
    for i in 0..=digits.len().saturating_sub(13) {
        for len in [13usize, 16, 19] {
            if i + len <= digits.len() {
                let slice = &digits[i..i + len];
                if luhn_valid(slice.as_bytes()) {
                    return true;
                }
            }
        }
    }
    false
}

fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        if !d.is_ascii_digit() {
            return false;
        }
        let mut n = (d - b'0') as u32;
        if alt {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alt = !alt;
    }
    sum.is_multiple_of(10) && !digits.iter().all(|&d| d == digits[0])
}

pub fn contains_ssn(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(10) {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3] == b'-'
            && bytes[i + 4].is_ascii_digit()
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6] == b'-'
            && bytes[i + 7].is_ascii_digit()
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
        {
            let area = (bytes[i] - b'0') as u16 * 100
                + (bytes[i + 1] - b'0') as u16 * 10
                + (bytes[i + 2] - b'0') as u16;
            if area != 0 && area != 666 && !(900..=999).contains(&area) {
                return true;
            }
        }
    }
    false
}

fn contains_iban(s: &str) -> bool {
    let upper = s.to_uppercase();
    for word in upper.split_whitespace() {
        let clean: String = word.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        if clean.len() >= 15
            && clean.len() <= 34
            && clean.len() >= 4
            && clean[..2].chars().all(|c| c.is_ascii_alphabetic())
            && clean[2..4].chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

fn contains_passport(s: &str) -> bool {
    regex_match(
        s,
        r"(?i)\b(passport|travel document)[:\s#-]*[A-Z0-9]{6,12}\b",
    )
}

fn contains_medical_record(s: &str) -> bool {
    regex_match(
        s,
        r"(?i)\b(MRN|medical record|patient id)[:\s#-]*[A-Z0-9-]{6,20}\b",
    )
}

fn count_phone_numbers(s: &str) -> usize {
    regex::Regex::new(r"\b\+?[0-9]{1,3}[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b")
        .ok()
        .map(|re| re.find_iter(s).count())
        .unwrap_or(0)
}

fn looks_like_aws_key(s: &str) -> bool {
    s.contains("AKIA") || s.contains("aws_secret_access_key") || regex_match(s, r"AKIA[0-9A-Z]{16}")
}

fn looks_like_azure_key(s: &str) -> bool {
    regex_match(s, r"(?i)DefaultEndpointsProtocol=https;AccountName=")
        || s.contains("azure_storage_connection_string")
}

fn looks_like_gcp_key(s: &str) -> bool {
    regex_match(s, r#""type"\s*:\s*"service_account""#) || s.contains("private_key_id")
}

fn detect_sensitive_file(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"%PDF") {
        return Some("PDF");
    }
    if data.starts_with(b"PK\x03\x04") {
        return Some("ZIP/Office archive");
    }
    if data.starts_with(b"\x89PNG") {
        return Some("PNG image");
    }
    if data.starts_with(b"\xFF\xD8\xFF") {
        return Some("JPEG image");
    }
    if data.len() >= 4 && &data[0..4] == b"\xD0\xCF\x11\xE0" {
        return Some("MS Office legacy");
    }
    None
}

pub fn contains_email_exfil(s: &str, app_proto: Option<&str>) -> bool {
    if app_proto != Some("HTTP") && app_proto != Some("SMTP") {
        return false;
    }
    s.matches('@').count() >= 3
}

fn looks_like_github_token(s: &str) -> bool {
    regex_match(s, r"\bghp_[A-Za-z0-9]{36}\b")
        || regex_match(s, r"\bgho_[A-Za-z0-9]{36}\b")
        || regex_match(s, r"\bghb_[A-Za-z0-9]{36}\b")
        || regex_match(s, r"\bghs_[A-Za-z0-9]{36}\b")
        || regex_match(s, r"\bghr_[A-Za-z0-9]{36}\b")
}

fn looks_like_slack_token(s: &str) -> bool {
    regex_match(s, r"\bxox[bpars]-[0-9A-Za-z-]{10,}\b")
}

fn contains_jwt(s: &str) -> bool {
    // JWT: eyXXX.eyXXX.XXX (base64url encoded header.payload.signature)
    regex_match(
        s,
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    )
}

fn looks_like_stripe_key(s: &str) -> bool {
    regex_match(s, r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{20,}\b")
}

fn contains_db_connection_string(s: &str) -> bool {
    regex_match(
        s,
        r"(?i)(postgres|postgresql|mysql|mongodb|mssql|redis|mongodb\+srv)://[^:]+:[^@]+@",
    ) || (s.contains("password=")
        && (s.contains("host=") || s.contains("server=") || s.contains("Server=")))
}

fn looks_like_npm_token(s: &str) -> bool {
    regex_match(s, r"\bnpm_[A-Za-z0-9]{36}\b")
}

fn contains_api_key_param(s: &str) -> bool {
    regex_match(
        s,
        r"(?i)[?&](api_key|apikey|access_token|auth_token|secret_key|client_secret|app_secret)=[A-Za-z0-9_\-]{16,}",
    )
}

fn contains_national_id(s: &str) -> bool {
    // Indian Aadhaar: 12-digit with optional spaces (pattern: [2-9]xxx xxxx xxxx)
    regex_match(s, r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")
        || regex_match(
            s,
            r"(?i)\b(national.?id|nid|voter.?id|aadhar|aadhaar)[:\s#-]*[A-Z0-9]{8,16}\b",
        )
}

fn looks_like_google_token(s: &str) -> bool {
    // Google OAuth2 access tokens start with ya29.
    regex_match(s, r"\bya29\.[A-Za-z0-9_\-]{60,}\b")
        || regex_match(s, r#""type"\s*:\s*"service_account""#)
        || s.contains("AIza") // Google API keys
}
