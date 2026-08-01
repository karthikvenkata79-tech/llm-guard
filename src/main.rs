//! llm-guard (single-file edition)
//!
//! A guardrail proxy for LLM apps. It sits between your app and the real LLM:
//!
//!   client  ->  llm-guard (scan + log)  ->  real LLM API  ->  client
//!
//! - Prompt injection  -> BLOCKED (403)
//! - Secrets / PII      -> REDACTED, then forwarded
//! - The model's reply  -> also scanned/redacted on the way out
//!
//! Everything lives in this one file. Run it with `cargo run`.

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::{Lazy, OnceCell};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ============================================================================
// CONFIG  — settings, read from environment variables with sensible defaults.
// ============================================================================

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: String,
    pub upstream_url: String,
    pub block_on_detect: bool,
    pub scan_response: bool,
    pub rules_file: Option<String>,
    /// LLM10: max requests per client per 60s (0 = disabled).
    pub rate_limit: u32,
    /// LLM07: if the reply contains this string, treat it as a system-prompt leak.
    pub system_prompt_canary: Option<String>,
    /// Semantic layer: URL of the embedder service (unset = layer off).
    pub embedder: Option<String>,
}

impl Config {
    fn from_env() -> Self {
        Config {
            listen_addr: std::env::var("GUARD_LISTEN")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            upstream_url: std::env::var("GUARD_UPSTREAM")
                .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string()),
            block_on_detect: std::env::var("GUARD_BLOCK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            scan_response: std::env::var("GUARD_SCAN_RESPONSE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            rules_file: std::env::var("GUARD_RULES_FILE").ok(),
            rate_limit: std::env::var("GUARD_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            system_prompt_canary: std::env::var("GUARD_SYSTEM_PROMPT_CANARY")
                .ok()
                .filter(|s| !s.is_empty()),
            embedder: std::env::var("GUARD_EMBEDDER").ok().filter(|s| !s.is_empty()),
        }
    }
}

// ============================================================================
// SCANNER — the detection rules, plus scan() (detect) and redact() (clean).
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: String, // "prompt_injection" | "secret" | "pii"
    pub rule: String,
    pub severity: Severity,
    pub snippet: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low = 0,
    Medium = 1,
    High = 2,
}

struct Rule {
    category: &'static str,
    name: &'static str,
    severity: Severity,
    re: Regex,
}

/// The built-in rules, used when no rules file is provided.
static DEFAULT_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        // ---- Prompt injection ----
        Rule {
            category: "prompt_injection",
            name: "ignore_previous_instructions",
            severity: Severity::High,
            re: Regex::new(
                r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|context|rules)",
            )
            .unwrap(),
        },
        Rule {
            category: "prompt_injection",
            name: "disregard_instructions",
            severity: Severity::High,
            re: Regex::new(
                r"(?i)(disregard|forget|override)\s+(all\s+)?(your\s+)?(previous\s+|prior\s+|the\s+)?(instructions|rules|system\s+prompt)",
            )
            .unwrap(),
        },
        Rule {
            category: "prompt_injection",
            name: "reveal_system_prompt",
            severity: Severity::High,
            re: Regex::new(
                r"(?i)(reveal|show|print|repeat|display|output)\s+(me\s+)?(your\s+)?(the\s+)?(system\s+prompt|initial\s+instructions|your\s+instructions)",
            )
            .unwrap(),
        },
        Rule {
            category: "prompt_injection",
            name: "role_override",
            severity: Severity::Medium,
            re: Regex::new(
                r"(?i)(you\s+are\s+now|from\s+now\s+on\s+you|pretend\s+to\s+be|act\s+as\s+(if\s+you\s+are\s+)?)\b",
            )
            .unwrap(),
        },
        Rule {
            category: "prompt_injection",
            name: "jailbreak_dan",
            severity: Severity::Medium,
            re: Regex::new(r"(?i)\b(DAN|do\s+anything\s+now|developer\s+mode|jailbreak)\b").unwrap(),
        },
        Rule {
            category: "prompt_injection",
            name: "repeat_words_above",
            severity: Severity::High,
            re: Regex::new(
                r"(?i)(repeat|print|output|show|tell\s+me)\s+(the\s+)?(words|text|everything|content|instructions|prompt)\s+(above|before)",
            )
            .unwrap(),
        },
        // ---- Secrets ----
        Rule {
            category: "secret",
            name: "openai_api_key",
            severity: Severity::High,
            re: Regex::new(r"sk-[A-Za-z0-9_-]{20,}").unwrap(),
        },
        Rule {
            category: "secret",
            name: "aws_access_key_id",
            severity: Severity::High,
            re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        },
        Rule {
            category: "secret",
            name: "bearer_token",
            severity: Severity::Medium,
            re: Regex::new(r"(?i)bearer\s+[A-Za-z0-9._-]{16,}").unwrap(),
        },
        // ---- PII ----
        Rule {
            category: "pii",
            name: "email_address",
            severity: Severity::Low,
            re: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
        },
        Rule {
            category: "pii",
            name: "phone_number",
            severity: Severity::Medium,
            re: Regex::new(
                r"\b(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
            )
            .unwrap(),
        },
        Rule {
            category: "pii",
            name: "us_ssn",
            severity: Severity::Medium,
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        },
        Rule {
            category: "pii",
            name: "credit_card_like",
            severity: Severity::Medium,
            re: Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap(),
        },
    ]
});

// The rules currently in effect: file-loaded rules if provided, else defaults.
static ACTIVE_RULES: OnceCell<Vec<Rule>> = OnceCell::new();

/// The rules scan() and redact() actually use.
fn rules() -> &'static [Rule] {
    ACTIVE_RULES
        .get()
        .map(|v| v.as_slice())
        .unwrap_or_else(|| DEFAULT_RULES.as_slice())
}

/// One rule as written in a JSON rules file.
#[derive(Deserialize)]
struct RuleSpec {
    category: String,
    name: String,
    severity: String,
    pattern: String,
}

#[derive(Deserialize)]
struct RulesFile {
    rules: Vec<RuleSpec>,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Load rules from a JSON file. Each pattern is compiled here, so a typo in
/// the file is reported at startup instead of being silently ignored.
fn load_rules(path: &str) -> anyhow::Result<Vec<Rule>> {
    let text = std::fs::read_to_string(path)?;
    let parsed: RulesFile = serde_json::from_str(&text)?;
    let mut out = Vec::new();
    for spec in parsed.rules {
        let re = Regex::new(&spec.pattern)
            .map_err(|e| anyhow::anyhow!("bad regex in rule '{}': {e}", spec.name))?;
        out.push(Rule {
            category: Box::leak(spec.category.into_boxed_str()),
            name: Box::leak(spec.name.into_boxed_str()),
            severity: parse_severity(&spec.severity),
            re,
        });
    }
    Ok(out)
}

/// Detect: run every rule against the text and return all matches. Reads only.
pub fn scan(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in rules() {
        if let Some(m) = rule.re.find(text) {
            findings.push(Finding {
                category: rule.category.to_string(),
                rule: rule.name.to_string(),
                severity: rule.severity,
                snippet: safe_snippet(rule.category, m.as_str()),
            });
        }
    }
    findings
}

/// Only secrets and PII get cleaned — never injection (that gets blocked).
fn is_redactable(category: &str) -> bool {
    category == "secret" || category == "pii"
}

/// Clean: replace every secret/PII match with `[REDACTED:<rule>]`.
/// Returns the cleaned text and a record of what was removed.
pub fn redact(text: &str) -> (String, Vec<Finding>) {
    let mut out = text.to_string();
    let mut redactions = Vec::new();

    for rule in rules() {
        if !is_redactable(rule.category) {
            continue;
        }
        let matches: Vec<Finding> = rule
            .re
            .find_iter(&out)
            .map(|m| Finding {
                category: rule.category.to_string(),
                rule: rule.name.to_string(),
                severity: rule.severity,
                snippet: safe_snippet(rule.category, m.as_str()),
            })
            .collect();

        if !matches.is_empty() {
            redactions.extend(matches);
            let replacement = format!("[REDACTED:{}]", rule.name);
            out = rule.re.replace_all(&out, replacement.as_str()).to_string();
        }
    }
    (out, redactions)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let taken: String = s.chars().take(max).collect();
        format!("{taken}…")
    }
}

/// Build a log-safe snippet. For secrets and PII we must NOT log the real value
/// (that would leak into the audit log the very thing we redact), so we record
/// only its length. Injection/unsafe-output text is safe and useful to keep.
fn safe_snippet(category: &str, matched: &str) -> String {
    if category == "secret" || category == "pii" {
        format!("[{} chars hidden]", matched.chars().count())
    } else {
        truncate(matched, 60)
    }
}

// ---- Normalization: undo common evasion tricks before scanning ----

/// A base64-looking run of characters (used to spot hidden encoded instructions).
static B64_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{16,}={0,2}").unwrap());

/// Map "leetspeak" digits/symbols back to letters: "1gn0re" -> "ignore".
fn deleet(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '@' => 'a',
            '$' => 's',
            other => other,
        })
        .collect()
}

/// Map a few common look-alike (homoglyph) characters to plain ASCII.
fn map_homoglyphs(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'а' => 'a',
            'е' => 'e',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'х' => 'x',
            'у' => 'y',
            'і' => 'i',
            other => other,
        })
        .collect()
}

/// Re-join words spelled out letter-by-letter: "i g n o r e" -> "ignore".
/// (The separators . - _ * are treated as spaces first.)
fn collapse_spaced_letters(text: &str) -> String {
    let spaced: String = text
        .chars()
        .map(|c| if matches!(c, '.' | '-' | '_' | '*') { ' ' } else { c })
        .collect();
    let mut out = String::new();
    let mut buf = String::new();
    for token in spaced.split_whitespace() {
        if token.chars().count() == 1 {
            buf.push_str(token);
        } else {
            if !buf.is_empty() {
                out.push_str(&buf);
                out.push(' ');
                buf.clear();
            }
            out.push_str(token);
            out.push(' ');
        }
    }
    if !buf.is_empty() {
        out.push_str(&buf);
    }
    out.trim().to_string()
}

/// Decode any base64-looking fragments and return the decoded text.
fn decode_base64_fragments(text: &str) -> String {
    let mut out = String::new();
    for m in B64_RE.find_iter(text) {
        if let Ok(bytes) = general_purpose::STANDARD.decode(m.as_str()) {
            if let Ok(s) = String::from_utf8(bytes) {
                out.push_str(&s);
                out.push(' ');
            }
        }
    }
    out
}

/// Build a combined text with several "cleaned up" views of the input, so
/// evasions (spaced letters, leetspeak, homoglyphs, base64) still get caught.
/// Used for the injection/block decision — not for redaction of the real body.
fn augment_for_scanning(text: &str) -> String {
    let homoglyph_free = map_homoglyphs(text);
    let despaced = collapse_spaced_letters(&homoglyph_free);
    let mut combined = String::new();
    combined.push_str(text);
    combined.push('\n');
    combined.push_str(&homoglyph_free);
    combined.push('\n');
    combined.push_str(&despaced);
    combined.push('\n');
    combined.push_str(&deleet(&despaced));
    combined.push('\n');
    combined.push_str(&decode_base64_fragments(text));
    combined
}

// ============================================================================
// PROXY  — the per-request handler: scan -> block or redact -> forward -> reply
// ============================================================================

// ---- Detection layers (run cheap -> expensive, with early exit) ----

/// Deny-list layer (cheap): exact known-bad phrases. Returns the matched phrase.
const DENY_LIST: &[&str] = &[
    "ignore all previous instructions",
    "disregard previous instructions",
    "you are now in developer mode",
    "do anything now",
];

fn deny_list_hit(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    DENY_LIST.iter().copied().find(|p| lower.contains(p))
}

/// Semantic layer (expensive): ask the embedder service whether this text MEANS
/// the same as a known attack. Returns Some(true/false), or None if the layer
/// is off or the service is unreachable (fail-open so the guard keeps working).
async fn semantic_is_attack(state: &AppState, text: &str) -> Option<bool> {
    let url = state.config.embedder.as_ref()?;
    let resp = state
        .client
        .post(url)
        .json(&json!({ "text": text }))
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .ok()?;
    let body: Value = resp.json().await.ok()?;
    body.get("is_attack").and_then(|v| v.as_bool())
}

async fn handle(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let start = Instant::now();

    // LLM10 (Unbounded Consumption): rate-limit each client before any work.
    if !allow_request(&state, client_key(&headers)) {
        tracing::warn!(target: "audit", "request RATE LIMITED (429)");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "rate limit exceeded" })),
        )
            .into_response();
    }

    let body_str = String::from_utf8_lossy(&body).to_string();

    let scan_target = extract_prompt_text(&body_str).unwrap_or_else(|| body_str.clone());
    let findings = scan(&augment_for_scanning(&scan_target));

    // Layer: deny-list (cheap). Early exit — if it hits, block now, skip the rest.
    if let Some(phrase) = deny_list_hit(&scan_target) {
        tracing::warn!(target: "audit", phrase = phrase, "request BLOCKED (deny-list)");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "request blocked by llm-guard", "layer": "deny_list" })),
        )
            .into_response();
    }

    // Decision 1: block high-severity prompt injection.
    let injection_block = state.config.block_on_detect
        && findings
            .iter()
            .any(|f| f.category == "prompt_injection" && f.severity == Severity::High);

    if injection_block {
        tracing::warn!(
            target: "audit",
            elapsed_ms = start.elapsed().as_millis() as u64,
            findings = %serde_json::to_string(&findings).unwrap_or_default(),
            "request BLOCKED (prompt injection)"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "request blocked by llm-guard", "findings": findings })),
        )
            .into_response();
    }

    // Layer: semantic (expensive). Only wakes if the cheap layers found nothing —
    // this is the early-exit / "sleep mode" routing: no point paying for it
    // when regex/deny-list already cleared or caught the message.
    if findings.is_empty() && state.config.block_on_detect {
        if let Some(true) = semantic_is_attack(&state, &scan_target).await {
            tracing::warn!(target: "audit", "request BLOCKED (semantic layer)");
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "request blocked by llm-guard", "layer": "semantic" })),
            )
                .into_response();
        }
    }

    // Decision 2: redact secrets/PII, then forward the cleaned request.
    let (clean_body, redactions) = redact_body(&body_str);

    tracing::info!(
        target: "audit",
        blocked = false,
        redaction_count = redactions.len(),
        redactions = %serde_json::to_string(&redactions).unwrap_or_default(),
        other_findings = %serde_json::to_string(&findings).unwrap_or_default(),
        request_bytes = body.len(),
        "request scanned"
    );

    // If the app asked for a streaming reply, pass the reply straight through
    // word-by-word. Note: response-side redaction is skipped in this mode
    // (you'd have to buffer the whole reply to scan it, which defeats streaming).
    // Request-side protection (blocking + prompt redaction) above still applies.
    if wants_stream(&clean_body) {
        tracing::info!(target: "audit", streaming = true, "request forwarded (streaming)");
        return match forward_stream(&state, &headers, clean_body).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!(error = %e, "upstream stream failed");
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "error": format!("upstream error: {e}") })),
                )
                    .into_response()
            }
        };
    }

    match forward(&state, &headers, clean_body).await {
        Ok((status, upstream_bytes)) => {
            let (out_bytes, out_redactions) = if state.config.scan_response {
                redact_response_body(&upstream_bytes, state.config.system_prompt_canary.as_deref())
            } else {
                (upstream_bytes, Vec::new())
            };

            tracing::info!(
                target: "audit",
                elapsed_ms = start.elapsed().as_millis() as u64,
                response_redaction_count = out_redactions.len(),
                response_redactions = %serde_json::to_string(&out_redactions).unwrap_or_default(),
                "request forwarded"
            );

            build_response(status, out_bytes)
        }
        Err(e) => {
            tracing::error!(error = %e, "upstream request failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("upstream error: {e}") })),
            )
                .into_response()
        }
    }
}

/// Pull all `messages[].content` strings out of an OpenAI-style body.
fn extract_prompt_text(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let messages = v.get("messages")?.as_array()?;
    let mut out = String::new();
    for m in messages {
        if let Some(content) = m.get("content").and_then(|c| c.as_str()) {
            out.push_str(content);
            out.push('\n');
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Redact secrets/PII inside the request body (each message's content).
fn redact_body(body: &str) -> (Vec<u8>, Vec<Finding>) {
    if let Ok(mut v) = serde_json::from_str::<Value>(body) {
        if let Some(messages) = v.get_mut("messages").and_then(|m| m.as_array_mut()) {
            let mut all = Vec::new();
            for msg in messages.iter_mut() {
                let cleaned = msg
                    .get("content")
                    .and_then(|c| c.as_str())
                    .map(redact);
                if let Some((clean, reds)) = cleaned {
                    all.extend(reds);
                    msg["content"] = Value::String(clean);
                }
            }
            let bytes = serde_json::to_vec(&v).unwrap_or_else(|_| body.as_bytes().to_vec());
            return (bytes, all);
        }
    }
    let (clean, reds) = redact(body);
    (clean.into_bytes(), reds)
}

/// Clean the model's response: redact secrets/PII (LLM02), neutralize unsafe
/// output (LLM05), and catch a leaked system-prompt canary (LLM07).
fn redact_response_body(body: &[u8], canary: Option<&str>) -> (Vec<u8>, Vec<Finding>) {
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => return (body.to_vec(), Vec::new()),
    };

    if let Ok(mut v) = serde_json::from_str::<Value>(text) {
        if let Some(choices) = v.get_mut("choices").and_then(|c| c.as_array_mut()) {
            let mut all = Vec::new();
            for choice in choices.iter_mut() {
                let cleaned = choice
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str())
                    .map(|content| clean_reply_content(content, canary));
                if let Some((clean, reds)) = cleaned {
                    all.extend(reds);
                    if let Some(msg) = choice.get_mut("message") {
                        msg["content"] = Value::String(clean);
                    }
                }
            }
            let bytes = serde_json::to_vec(&v).unwrap_or_else(|_| body.to_vec());
            return (bytes, all);
        }
    }
    (body.to_vec(), Vec::new())
}

/// Run all reply-side checks on one message's content.
fn clean_reply_content(content: &str, canary: Option<&str>) -> (String, Vec<Finding>) {
    // LLM02: secrets / PII
    let (mut text, mut findings) = redact(content);
    // LLM05: unsafe output (scripts, iframes, javascript: URIs)
    let (validated, unsafe_findings) = validate_output(&text);
    text = validated;
    findings.extend(unsafe_findings);
    // LLM07: system-prompt leak (operator-provided canary)
    if let Some(c) = canary {
        if !c.is_empty() && text.contains(c) {
            findings.push(Finding {
                category: "system_prompt_leak".to_string(),
                rule: "canary_in_output".to_string(),
                severity: Severity::High,
                snippet: "[system-prompt canary detected]".to_string(),
            });
            text = text.replace(c, "[REDACTED:system_prompt_leak]");
        }
    }
    (text, findings)
}

/// LLM05 patterns: content that is dangerous if a UI renders the reply as HTML.
static UNSAFE_OUTPUT_RULES: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        ("script_tag", Regex::new(r"(?is)<script.*?</script>").unwrap()),
        ("iframe_tag", Regex::new(r"(?i)<iframe[^>]*>").unwrap()),
        ("js_uri", Regex::new(r"(?i)javascript:").unwrap()),
    ]
});

/// LLM05: neutralize dangerous HTML/JS in the model's reply.
fn validate_output(text: &str) -> (String, Vec<Finding>) {
    let mut out = text.to_string();
    let mut findings = Vec::new();
    for (name, re) in UNSAFE_OUTPUT_RULES.iter() {
        let hits: Vec<Finding> = re
            .find_iter(&out)
            .map(|m| Finding {
                category: "unsafe_output".to_string(),
                rule: name.to_string(),
                severity: Severity::High,
                snippet: truncate(m.as_str(), 60),
            })
            .collect();
        if !hits.is_empty() {
            findings.extend(hits);
            out = re
                .replace_all(&out, format!("[REMOVED:{name}]").as_str())
                .to_string();
        }
    }
    (out, findings)
}

// ---- LLM10: rate limiting ----

/// Identify the client (by API key or X-Client-Id header), hashed so we never
/// store the raw credential.
fn client_key(headers: &HeaderMap) -> u64 {
    let raw = headers
        .get("authorization")
        .or_else(|| headers.get("x-client-id"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous");
    let mut h = DefaultHasher::new();
    raw.hash(&mut h);
    h.finish()
}

/// Fixed 60-second window rate limit. Returns true if the request is allowed.
fn allow_request(state: &AppState, key: u64) -> bool {
    let limit = state.config.rate_limit;
    if limit == 0 {
        return true; // disabled
    }
    // Recover the guard even if a previous holder panicked (no crash).
    let mut map = state.rate.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();

    // Bound memory (DoS defense): if the map grows large, drop expired windows.
    const RATE_MAP_CAP: usize = 10_000;
    if map.len() > RATE_MAP_CAP {
        map.retain(|_, (start, _)| now.duration_since(*start).as_secs() < 60);
    }

    let entry = map.entry(key).or_insert((now, 0));
    if now.duration_since(entry.0).as_secs() >= 60 {
        entry.0 = now;
        entry.1 = 0;
    }
    entry.1 += 1;
    entry.1 <= limit
}

fn build_response(status: u16, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "response build error").into_response()
        })
}

/// Does the request ask for a streaming (word-by-word) reply?
fn wants_stream(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("stream").and_then(|s| s.as_bool()))
        .unwrap_or(false)
}

/// Forward the request and stream the reply straight back, chunk by chunk,
/// as the LLM produces it. (No response redaction here — see the note in handle.)
async fn forward_stream(
    state: &AppState,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> anyhow::Result<Response> {
    let mut req = state.client.post(&state.config.upstream_url).body(body);
    for name in ["authorization", "content-type"] {
        if let Some(val) = headers.get(name) {
            if let Ok(s) = val.to_str() {
                req = req.header(name, s);
            }
        }
    }

    let upstream = req.send().await?;
    let status = upstream.status().as_u16();

    // Turn the upstream reply into a live stream of bytes and hand it to the
    // client as an axum streaming body — pieces flow out as they flow in.
    let stream = upstream.bytes_stream();
    let response = Response::builder()
        .status(status)
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(response)
}

/// Forward the cleaned request to the upstream LLM; return status + raw bytes.
async fn forward(
    state: &AppState,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut req = state.client.post(&state.config.upstream_url).body(body);
    for name in ["authorization", "content-type"] {
        if let Some(val) = headers.get(name) {
            if let Ok(s) = val.to_str() {
                req = req.header(name, s);
            }
        }
    }
    let upstream = req.send().await?;
    let status = upstream.status().as_u16();
    let resp_body = upstream.bytes().await?;
    Ok((status, resp_body.to_vec()))
}

// ============================================================================
// MAIN  — logging, shared state, routes, start the server.
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub client: reqwest::Client,
    /// LLM10: per-client request counters (key -> (window_start, count)).
    pub rate: Arc<Mutex<HashMap<u64, (Instant, u32)>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Config::from_env();
    tracing::info!(?config, "starting llm-guard");

    // Choose the active rule set: from the configured file, or the built-in defaults.
    match config.rules_file.as_deref() {
        Some(path) => match load_rules(path) {
            Ok(loaded) => {
                tracing::info!(count = loaded.len(), path, "loaded rules from file");
                let _ = ACTIVE_RULES.set(loaded);
            }
            Err(e) => {
                tracing::warn!(error = %e, path, "could not load rules file — using built-in defaults");
            }
        },
        None => {
            tracing::info!(count = DEFAULT_RULES.len(), "using built-in default rules");
        }
    }

    let state = AppState {
        config: Arc::new(config.clone()),
        client: reqwest::Client::new(),
        rate: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/chat/completions", post(handle))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("llm-guard listening on http://{}", config.listen_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_list_blocks_known_phrase() {
        assert!(deny_list_hit("please do anything now").is_some());
        assert!(deny_list_hit("what is the weather today").is_none());
    }

    #[test]
    fn regex_layer_detects_injection() {
        let f = scan(&augment_for_scanning("ignore all previous instructions"));
        assert!(f.iter().any(|x| x.category == "prompt_injection"));
    }

    #[test]
    fn regex_layer_detects_secret() {
        let f = scan("my key is sk-abcdef0123456789ABCDEFGH");
        assert!(f.iter().any(|x| x.category == "secret"));
    }

    #[test]
    fn logs_never_contain_raw_secret() {
        let s = safe_snippet("secret", "sk-supersecretvalue");
        assert!(!s.contains("supersecretvalue"));
    }
}
