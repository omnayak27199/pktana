// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use super::super::super::alert::AlertCtx;
use super::super::super::types::{AlertSeverity, SecurityAlert};

/// Known LLM/AI API provider SNI hostnames and display names.
const AI_SNI_PROVIDERS: &[(&str, &str)] = &[
    ("api.openai.com", "OpenAI"),
    ("api.anthropic.com", "Anthropic"),
    ("generativelanguage.googleapis.com", "Google Gemini"),
    ("api.cohere.ai", "Cohere"),
    ("api.cohere.com", "Cohere"),
    ("api-inference.huggingface.co", "HuggingFace"),
    ("api.mistral.ai", "Mistral"),
    ("api.together.ai", "Together AI"),
    ("api.groq.com", "Groq"),
    ("api.perplexity.ai", "Perplexity"),
    ("api.deepseek.com", "DeepSeek"),
    ("api.replicate.com", "Replicate"),
    ("api.ai21.com", "AI21 Labs"),
    ("api.fireworks.ai", "Fireworks AI"),
    ("api.cerebras.ai", "Cerebras"),
    ("openai.azure.com", "Azure OpenAI"),
    ("inference.ai.azure.com", "Azure AI"),
    ("bedrock-runtime.amazonaws.com", "AWS Bedrock"),
    ("api.lepton.ai", "Lepton AI"),
];

/// Common LLM REST API endpoint path fragments and their human labels.
const AI_ENDPOINTS: &[(&str, &str)] = &[
    ("/v1/chat/completions", "Chat completion"),
    ("/v1/completions", "Text completion"),
    ("/v1/embeddings", "Embeddings"),
    ("/v1/images/generations", "Image generation"),
    ("/v1/messages", "Anthropic messages"),
    ("/v1beta/models", "Gemini models"),
    ("/api/generate", "Ollama generate"),
    ("/api/chat", "Ollama chat"),
    ("/v1/chat", "Mistral chat"),
    ("/v1/generate", "Cohere generate"),
    ("/openai/deployments", "Azure OpenAI deployment"),
];

/// Scan packet payload for LLM/AI traffic patterns.
///
/// Works in two modes:
/// - TLS: `payload` contains `app_detail` lines including `"SNI      : <host>"` —
///   provider is identified even without decrypting the session.
/// - Cleartext HTTP/HTTP2: inspects headers and JSON body for API keys, endpoints,
///   and SSE streaming responses.
pub fn scan_ai_traffic(ctx: &AlertCtx<'_>, payload: &str) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();

    // ── SNI-based detection (TLS encrypted traffic) ───────────────────────────
    if let Some(provider) = detect_ai_sni(payload) {
        alerts.push(ctx.alert_full(
            AlertSeverity::Medium,
            "dlp_shadow_ai",
            "AI/LLM service traffic detected",
            format!("TLS connection to {provider} API (SNI match)"),
            ctx.protocol,
            "shadow_ai",
            0,
        ));
    }

    // ── HTTP cleartext header inspection ─────────────────────────────────────
    let mut sni_already_flagged = !alerts.is_empty();
    for line in payload.lines() {
        let lower = line.to_ascii_lowercase();

        // x-api-key: <key>  — used by Anthropic, Cohere, Mistral, etc.
        if let Some(val) = lower.strip_prefix("x-api-key:") {
            let raw = &line[10..];
            if looks_like_ai_key(val.trim()) {
                alerts.push(ctx.alert_full(
                    AlertSeverity::Critical,
                    "dlp_ai_api_key",
                    "AI provider API key in cleartext traffic",
                    format!("x-api-key: {}", truncate(raw, 40)),
                    ctx.protocol,
                    "credentials",
                    0,
                ));
            }
        }

        // Authorization: Bearer <key>  — used by OpenAI, HuggingFace, etc.
        if let Some(val) = lower.strip_prefix("authorization: bearer ") {
            let raw = &line[22..];
            if looks_like_ai_key(val.trim()) {
                alerts.push(ctx.alert_full(
                    AlertSeverity::Critical,
                    "dlp_ai_api_key",
                    "AI provider bearer token in cleartext HTTP",
                    format!("Bearer: {}", truncate(raw, 40)),
                    ctx.protocol,
                    "credentials",
                    0,
                ));
            }
        }

        // AI API endpoint path in HTTP request line (only for unencrypted traffic)
        if !sni_already_flagged {
            if let Some(ep_name) = detect_ai_endpoint(&lower) {
                alerts.push(ctx.alert_full(
                    AlertSeverity::High,
                    "dlp_ai_endpoint",
                    "AI API endpoint call in cleartext traffic",
                    format!("{ep_name}: {}", truncate(line, 80)),
                    ctx.protocol,
                    "shadow_ai",
                    0,
                ));
                sni_already_flagged = true; // one endpoint alert per packet is enough
            }
        }

        // SSE streaming response — strong indicator of an active LLM session
        if lower.contains("content-type: text/event-stream") {
            alerts.push(ctx.alert_full(
                AlertSeverity::Low,
                "dlp_ai_stream",
                "AI streaming (SSE) response detected",
                "Server-Sent Events stream — likely active LLM token output",
                ctx.protocol,
                "shadow_ai",
                0,
            ));
        }

        // Anthropic SDK-specific headers (present in cleartext proxied traffic)
        if lower.starts_with("anthropic-version:") || lower.starts_with("anthropic-beta:") {
            alerts.push(ctx.alert_full(
                AlertSeverity::Medium,
                "dlp_shadow_ai",
                "Anthropic SDK header in cleartext traffic",
                truncate(line, 80),
                ctx.protocol,
                "shadow_ai",
                0,
            ));
        }

        // OpenAI org/project headers
        if lower.starts_with("openai-organization:") || lower.starts_with("openai-project:") {
            alerts.push(ctx.alert_full(
                AlertSeverity::Medium,
                "dlp_shadow_ai",
                "OpenAI organization header in cleartext traffic",
                truncate(line, 80),
                ctx.protocol,
                "shadow_ai",
                0,
            ));
        }
    }

    // ── JSON body: model name extraction (cleartext HTTP to local AI servers) ─
    if let Some(model) = extract_model_name(payload) {
        alerts.push(ctx.alert_full(
            AlertSeverity::Low,
            "dlp_ai_model",
            "AI model name in cleartext request payload",
            format!("model: {model}"),
            ctx.protocol,
            "shadow_ai",
            0,
        ));
    }

    alerts.dedup_by(|a, b| a.rule_id == b.rule_id && a.detail == b.detail);
    alerts
}

/// Check TLS `app_detail` lines for an AI provider SNI hostname.
/// Lines are formatted by the DPI engine as `"SNI      : <host>"`.
fn detect_ai_sni(payload: &str) -> Option<&'static str> {
    for line in payload.lines() {
        let trimmed = line.trim_start();
        if !trimmed.to_ascii_lowercase().starts_with("sni") {
            continue;
        }
        let host = trimmed
            .split_once(':')
            .map(|x| x.1)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        for (domain, provider) in AI_SNI_PROVIDERS {
            if host == *domain || host.ends_with(&format!(".{domain}")) {
                return Some(provider);
            }
        }
    }
    None
}

fn detect_ai_endpoint(lower_line: &str) -> Option<&'static str> {
    for (path, name) in AI_ENDPOINTS {
        if lower_line.contains(path) {
            return Some(name);
        }
    }
    None
}

/// Returns true if the token looks like a known AI provider API key.
pub fn looks_like_ai_key(s: &str) -> bool {
    let s = s.trim();
    // OpenAI new project key: sk-proj-...
    if s.starts_with("sk-proj-") && s.len() > 40 {
        return true;
    }
    // OpenAI legacy key: sk-<48 alphanumeric>
    if s.starts_with("sk-")
        && !s.starts_with("sk-ant-")
        && !s.starts_with("sk-proj-")
        && s.len() >= 48
        && s[3..].chars().take(48).all(|c| c.is_ascii_alphanumeric())
    {
        return true;
    }
    // Anthropic: sk-ant-api03-...
    if s.starts_with("sk-ant-") && s.len() > 40 {
        return true;
    }
    // HuggingFace: hf_...
    if s.starts_with("hf_") && s.len() > 30 {
        return true;
    }
    false
}

/// Extract the value of a `"model"` JSON key from a payload (best-effort, no full parse).
fn extract_model_name(payload: &str) -> Option<String> {
    let pos = payload.find("\"model\"")?;
    let after = &payload[pos + 7..];
    let colon = after.find(':')?;
    let val = after[colon + 1..].trim_start();
    let val = val.strip_prefix('"')?;
    let end = val.find('"')?;
    let model = &val[..end];
    if model.len() > 2 && model.len() < 80 {
        Some(model.to_string())
    } else {
        None
    }
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.len() > max {
        format!("{}…", &s[..max])
    } else {
        s.to_string()
    }
}
