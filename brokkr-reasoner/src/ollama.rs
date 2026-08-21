//! The real model backend (Phase 12): an [`OllamaBackend`] that talks to a self-hosted
//! `llama3.2:3b` via ollama's `/api/generate`, reached **through BIFRÖST's mTLS transport** (I-6).
//!
//! **The model call passes through BIFRÖST.** This backend formats an ollama HTTP request and hands
//! the bytes to [`brokkr_bifrost::MtlsTransport::round_trip`]; it opens no socket of its own. That
//! is the one path from MÍMIR to the network, and it goes through the crossing.
//!
//! **No new dependency, no `unsafe`.** The HTTP request and the JSON are built and parsed by hand
//! (a single POST to one endpoint; a short, single-response body), so no HTTP or JSON crate is
//! pulled in. The TLS lives in `brokkr-crypto`, reached via BIFRÖST.
//!
//! **The proposal is untrusted.** Whatever the model returns is wrapped as a `BackendProposal`
//! (an [`Action`] + the model's raw text as rationale). SINDRI decides whether it may act; a
//! response that does not name a declared tool becomes an `unknown` action the gate denies.

use brokkr_bifrost::MtlsTransport;
use brokkr_core::gate::Action;
use brokkr_core::ids::ToolId;
use brokkr_core::intent::IntentScope;

use crate::backend::{BackendError, BackendProposal, ModelBackend};

/// The default system instruction: ask the model for a strict, parseable coding proposal. Kept
/// deliberately blunt because a small (3B) model follows format instructions weakly.
pub const DEFAULT_SYSTEM: &str = "You are a tool-dispatching agent. You do NOT write code, bash, or \
markdown. You output ONLY these two lines and nothing else:\nTOOL: write_file\nPATH: <absolute \
path>\nReplace <absolute path> with the path in the user's request. No commentary, no backticks, \
no code fences, no extra lines.\nExample output:\nTOOL: write_file\nPATH: /tmp/example.txt";

/// A real ollama backend, reached through BIFRÖST's mTLS transport.
pub struct OllamaBackend {
    transport: MtlsTransport,
    model: String,
    system: String,
    /// The HTTP `Host` header value the gateway expects (e.g. `"localhost"`).
    host_header: String,
}

impl OllamaBackend {
    /// Construct with the default system prompt.
    pub fn new(
        transport: MtlsTransport,
        model: impl Into<String>,
        host_header: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            model: model.into(),
            system: DEFAULT_SYSTEM.to_string(),
            host_header: host_header.into(),
        }
    }

    /// Override the system prompt.
    #[must_use]
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = system.into();
        self
    }

    fn request_bytes(&self, payload: &str) -> Vec<u8> {
        // `temperature:0` makes a small model as deterministic and instruction-obedient as it gets.
        let body = format!(
            "{{\"model\":\"{}\",\"system\":\"{}\",\"prompt\":\"{}\",\"stream\":false,\
\"options\":{{\"temperature\":0}}}}",
            json_escape(&self.model),
            json_escape(&self.system),
            json_escape(payload),
        );
        let req = format!(
            "POST /api/generate HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.host_header,
            body.len(),
            body,
        );
        req.into_bytes()
    }
}

impl ModelBackend for OllamaBackend {
    fn propose(
        &self,
        payload: &str,
        _scope: &IntentScope,
    ) -> Result<BackendProposal, BackendError> {
        let request = self.request_bytes(payload);
        let response = self
            .transport
            .round_trip(&request)
            .map_err(|e| BackendError {
                detail: e.to_string(),
            })?;
        let raw = String::from_utf8_lossy(&response);

        // An ollama error object surfaces as a backend error.
        if let Some(err) = json_string_field(&raw, "error") {
            return Err(BackendError {
                detail: format!("ollama error: {err}"),
            });
        }

        let text = json_string_field(&raw, "response").ok_or_else(|| BackendError {
            detail: "ollama response missing a `response` field".to_string(),
        })?;

        // The model's text is the (untrusted) rationale; the parsed intent is the action.
        let action = parse_action(&text);
        Ok(BackendProposal {
            action,
            rationale: text,
        })
    }
}

/// Escape a string for embedding in a JSON string literal (the request side).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Extract the decoded value of a JSON string field named `field` from `text` — searching the
/// whole HTTP response (headers, chunk markers, and body). Robust for a short, single-response
/// body where the field's value is contiguous (ollama with `stream:false`). Returns `None` if the
/// field is absent or is not a string.
fn json_string_field(text: &str, field: &str) -> Option<String> {
    let key = format!("\"{field}\"");
    let key_at = text.find(&key)?;
    let after_key = key_at + key.len();
    let rest = text.get(after_key..)?;

    // Skip to and past the ':' , then to the opening quote of the value.
    let colon = rest.find(':')?;
    let after_colon = rest.get(colon + 1..)?;
    let mut chars = after_colon.char_indices().peekable();
    // Skip whitespace up to the opening quote.
    let mut value_start = None;
    for (i, c) in chars.by_ref() {
        if c == '"' {
            value_start = Some(i + 1);
            break;
        }
        if !c.is_whitespace() {
            // A non-string value (number/true/null) — not what we want.
            return None;
        }
    }
    let body = after_colon.get(value_start?..)?;

    // Walk the value, decoding escapes, until an unescaped closing quote.
    let mut out = String::new();
    let mut it = body.chars();
    while let Some(c) = it.next() {
        match c {
            '"' => return Some(out),
            '\\' => {
                let Some(e) = it.next() else { return Some(out) };
                match e {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{08}'),
                    'f' => out.push('\u{0c}'),
                    'u' => {
                        // Best-effort \uXXXX: take 4 hex digits; on failure, drop the escape.
                        let hex: String = it.by_ref().take(4).collect();
                        if let Ok(cp) = u32::from_str_radix(&hex, 16)
                            && let Some(ch) = char::from_u32(cp)
                        {
                            out.push(ch);
                        }
                    }
                    other => out.push(other),
                }
            }
            c => out.push(c),
        }
    }
    // Unterminated string — return what we have rather than fail.
    Some(out)
}

/// Parse the model's text into an [`Action`].
///
/// The **strict** form is two lines — `TOOL: <tool>` and `PATH: <path>` (case-insensitive key).
/// Because a small model often answers in prose or a shell command instead, a **lenient** fallback
/// then recognizes the one Phase-12 verb (`write_file`) anywhere in the text and the first
/// absolute-path token (`/…`). An unrecognized response yields an `unknown` tool, which SINDRI
/// denies (fail-closed): the model proposes; the spine disposes.
fn parse_action(text: &str) -> Action {
    let mut tool: Option<String> = None;
    let mut path: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = strip_prefix_ci(t, "TOOL:") {
            tool = Some(clean_value(rest));
        } else if let Some(rest) = strip_prefix_ci(t, "PATH:") {
            path = Some(clean_value(rest));
        }
    }

    // Lenient fallback for a chatty model (Phase 12, single tool).
    if tool.as_deref().unwrap_or("").is_empty() && mentions_word(text, "write_file") {
        tool = Some("write_file".to_string());
    }
    if path.as_deref().unwrap_or("").is_empty() {
        path = first_abs_path(text);
    }

    let tool_id = tool
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    // The path is the action detail; if the model gave none, fall back to a truncated echo so the
    // proposal is still concrete (the gate will judge it).
    let detail = path.filter(|s| !s.is_empty()).unwrap_or_else(|| {
        text.lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_string()
    });
    Action {
        tool: ToolId::new(tool_id),
        detail,
    }
}

/// Whether `word` appears in `text` as a whitespace-delimited token (ignoring surrounding
/// punctuation), so `write_file` matches in `write_file /tmp/x` and `` `write_file` `` alike.
fn mentions_word(text: &str, word: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || c == '`' || c == '(' || c == ')')
        .any(|tok| tok.trim_matches(|c| c == '"' || c == '\'' || c == ':') == word)
}

/// The first whitespace-delimited token that looks like an absolute path (`/…`), with surrounding
/// quotes/backticks stripped.
fn first_abs_path(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|tok| tok.trim_matches(|c| c == '"' || c == '\'' || c == '`'))
        .find(|tok| tok.starts_with('/') && tok.len() > 1)
        .map(|s| s.to_string())
}

/// Case-insensitive prefix strip: returns the remainder after `prefix` if `s` starts with it.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        s.get(prefix.len()..)
    } else {
        None
    }
}

/// Trim a parsed value and strip surrounding quotes or backticks a chatty model might add.
fn clean_value(s: &str) -> String {
    let t = s.trim();
    let t = t.trim_matches(|c| c == '"' || c == '`' || c == '\'');
    t.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_response_field_from_a_full_http_response() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 60\r\n\r\n\
{\"model\":\"llama3.2:3b\",\"response\":\"TOOL: write_file\\nPATH: /tmp/x.txt\",\"done\":true}";
        assert_eq!(
            json_string_field(raw, "response").as_deref(),
            Some("TOOL: write_file\nPATH: /tmp/x.txt")
        );
    }

    #[test]
    fn missing_field_is_none_and_error_field_is_detected() {
        assert!(json_string_field("{\"done\":true}", "response").is_none());
        let err = "HTTP/1.1 404\r\n\r\n{\"error\":\"model not found\"}";
        assert_eq!(
            json_string_field(err, "error").as_deref(),
            Some("model not found")
        );
    }

    #[test]
    fn decodes_common_escapes() {
        let raw = "{\"response\":\"line1\\nline2 \\\"quoted\\\" end\"}";
        assert_eq!(
            json_string_field(raw, "response").as_deref(),
            Some("line1\nline2 \"quoted\" end")
        );
    }

    #[test]
    fn parses_tool_and_path_lines() {
        let a = parse_action("TOOL: write_file\nPATH: /tmp/brokkr.txt");
        assert_eq!(a.tool.as_str(), "write_file");
        assert_eq!(a.detail, "/tmp/brokkr.txt");
    }

    #[test]
    fn parse_is_case_insensitive_and_strips_quotes() {
        let a = parse_action("tool: `write_file`\npath: \"/tmp/y.txt\"");
        assert_eq!(a.tool.as_str(), "write_file");
        assert_eq!(a.detail, "/tmp/y.txt");
    }

    #[test]
    fn unparseable_response_yields_unknown_tool_gate_will_deny() {
        let a = parse_action("I think you should write a file somewhere nice.");
        assert_eq!(a.tool.as_str(), "unknown");
        assert!(!a.detail.is_empty(), "detail echoes the model text");
    }

    #[test]
    fn lenient_parse_recovers_a_shell_style_response() {
        // The exact shape llama3.2:3b produced before the lenient fallback.
        let a = parse_action("#!/bin/bash\nwrite_file /tmp/brokkr-phase12-test.txt 'hello world'");
        assert_eq!(a.tool.as_str(), "write_file");
        assert_eq!(a.detail, "/tmp/brokkr-phase12-test.txt");
    }

    #[test]
    fn strict_form_still_wins_over_lenient() {
        let a =
            parse_action("TOOL: write_file\nPATH: /tmp/strict.txt\n(write_file /other/path too)");
        assert_eq!(a.tool.as_str(), "write_file");
        assert_eq!(a.detail, "/tmp/strict.txt");
    }

    #[test]
    fn json_escape_roundtrips_through_the_extractor() {
        let payload = "path is \"C:\\tmp\" and\na newline";
        let escaped = json_escape(payload);
        let doc = format!("{{\"response\":\"{escaped}\"}}");
        assert_eq!(
            json_string_field(&doc, "response").as_deref(),
            Some(payload)
        );
    }
}
