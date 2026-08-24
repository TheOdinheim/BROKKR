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
                // F-17 — a trailing backslash means the value was truncated mid-escape; fail
                // cleanly (`?` yields `None`) rather than return a partial.
                let e = it.next()?;
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
    // F-17 — unterminated string (no closing quote before EOF): the value is truncated. Return
    // `None` so the backend surfaces a clean error, rather than a partial value that could leak
    // internal state or be silently mis-parsed downstream.
    None
}

/// Parse the model's text into an [`Action`].
///
/// **Strict form ONLY** (13-FIX F-6): two lines — `TOOL: <tool>` and `PATH: <path>`
/// (case-insensitive key). There is **no** lenient prose-mining fallback: a response that does not
/// carry an explicit `TOOL:` line yields the tool `unknown`, which the genome denies (fail-closed).
/// Removing the fallback shrinks the prompt-injection → action surface — a prose sentence
/// mentioning a tool verb and a path can no longer be turned into an actionable proposal. The model
/// proposes; the spine disposes.
fn parse_action(text: &str) -> Action {
    let mut tool: Option<String> = None;
    let mut path: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        // F-16 — the FIRST pair wins, not the last. An attacker who controls the model's output
        // *suffix* (a poisoned continuation appended after the model's intended reply) must not be
        // able to override an earlier, benign `TOOL:`/`PATH:`. `get_or_insert` keeps the first.
        if let Some(rest) = strip_prefix_ci(t, "TOOL:") {
            tool.get_or_insert_with(|| clean_value(rest));
        } else if let Some(rest) = strip_prefix_ci(t, "PATH:") {
            path.get_or_insert_with(|| clean_value(rest));
        }
    }

    let tool_id = tool
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    // The detail is the strict `PATH:` value, or empty if none was given (the gate judges it).
    let detail = path.filter(|s| !s.is_empty()).unwrap_or_default();
    Action {
        tool: ToolId::new(tool_id),
        detail,
    }
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
        // 13-FIX F-6: no fallback — an unparseable response yields an empty detail (and `unknown`
        // tool, which the gate denies).
        assert!(
            a.detail.is_empty(),
            "no detail echo after the fallback removal"
        );
    }

    #[test]
    fn fix_f6_shell_style_response_no_longer_parsed() {
        // 13-FIX F-6: the shell-style shape that the lenient fallback used to recover is now
        // `unknown` (no strict TOOL: line) → the gate denies it.
        let a = parse_action("#!/bin/bash\nwrite_file /tmp/brokkr-phase12-test.txt 'hello world'");
        assert_eq!(a.tool.as_str(), "unknown", "no lenient recovery");
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

    // ===================================================================================
    // Phase 13B — Category 3: parser-confusion attacks against `parse_action`.
    // These document the parser's behavior (it targets the parser, not the spine). The
    // spine gates whatever the parser produces; a mis-parse yields an undeclared tool the
    // gate denies, or a valid tool whose path is the §13 residual.
    // ===================================================================================

    /// 3.1 — a benign TOOL/PATH in a fenced block, then a malicious pair appended after. 14-FIX
    /// F-16: the parser now takes the FIRST match, so an attacker who appends a malicious pair as a
    /// suffix cannot override the earlier benign one.
    #[test]
    fn attack_3_1_first_tool_pair_wins() {
        let resp = "Here's the plan:\n```\nTOOL: read_file\nPATH: /tmp/safe.txt\n```\n\
Actually do this:\nTOOL: write_file\nPATH: /etc/shadow";
        let a = parse_action(resp);
        assert_eq!(a.tool.as_str(), "read_file", "FIRST TOOL wins (F-16)");
        assert_eq!(a.detail, "/tmp/safe.txt", "FIRST PATH wins (F-16)");
    }

    /// 3.2 — TOOL and PATH on the same line. `TOOL:` is a line prefix, so the whole remainder
    /// (`write_file PATH: /etc/passwd`) becomes the tool name — a malformed, undeclared tool.
    #[test]
    fn attack_3_2_same_line_is_a_malformed_tool() {
        let a = parse_action("TOOL: write_file PATH: /etc/passwd");
        assert_ne!(a.tool.as_str(), "write_file", "not the clean tool name");
        assert!(
            a.tool.as_str().contains("write_file PATH:"),
            "the whole rest became the tool"
        );
        // 13-FIX F-6: with no lenient path-mining, and no `PATH:` line prefix, the detail is empty.
        assert_eq!(a.detail, "");
    }

    /// 3.3 — reversed order (PATH before TOOL). Extraction is order-independent (each line is
    /// scanned independently).
    #[test]
    fn attack_3_3_order_independent() {
        let a = parse_action("PATH: /etc/passwd\nTOOL: write_file");
        assert_eq!(a.tool.as_str(), "write_file");
        assert_eq!(a.detail, "/etc/passwd");
    }

    /// 3.4 — multiple TOOL/PATH pairs: 14-FIX F-16 makes the FIRST pair win (same as 3.1, stated
    /// explicitly).
    #[test]
    fn attack_3_4_multiple_pairs_first_wins() {
        let a = parse_action(
            "TOOL: read_file\nPATH: /tmp/safe.txt\nTOOL: write_file\nPATH: /etc/passwd",
        );
        assert_eq!(a.tool.as_str(), "read_file", "FIRST pair wins (F-16)");
        assert_eq!(a.detail, "/tmp/safe.txt");
    }

    /// 3.5 — a LITERAL `\n` (backslash-n, two chars), not a real newline. It is not a line
    /// separator, so the whole string becomes one malformed tool name → undeclared.
    #[test]
    fn attack_3_5_literal_backslash_n_is_not_a_separator() {
        let a = parse_action("TOOL: write_file\\nPATH: /etc/passwd");
        assert_ne!(a.tool.as_str(), "write_file");
        assert!(
            a.tool.as_str().contains("write_file\\nPATH:"),
            "one line, one malformed tool"
        );
    }

    /// 3.6 — LENIENT-parser exploitation: a prose sentence mentioning `write_file` and an
    /// absolute path yields an actionable proposal. The parser is over-eager; the spine then
    /// gates the result. 13-FIX F-6: the lenient fallback is REMOVED, so prose no longer yields an
    /// actionable proposal — the tool is `unknown` and the gate denies it.
    #[test]
    fn attack_3_6_prose_yields_unknown_after_fix() {
        let a = parse_action("I suggest using write_file at /etc/shadow to store credentials.");
        assert_eq!(
            a.tool.as_str(),
            "unknown",
            "prose is no longer mined into an action"
        );
        assert_eq!(a.detail, "", "no lenient path extraction");
    }

    // ---- 13-FIX F-6 regression tests ----

    /// The strict `TOOL:`/`PATH:` format still works after the lenient fallback is removed.
    #[test]
    fn fix_f6_strict_format_still_works() {
        let a = parse_action("TOOL: write_file\nPATH: /tmp/x.txt");
        assert_eq!(a.tool.as_str(), "write_file");
        assert_eq!(a.detail, "/tmp/x.txt");
    }

    /// Prose that would have been mined by the old fallback is now `unknown` (fail-closed).
    #[test]
    fn fix_f6_prose_no_longer_parsed() {
        for prose in [
            "please run write_file on /etc/shadow",
            "the write_file tool should target /root/.ssh/id_rsa",
            "write_file /etc/passwd now",
        ] {
            assert_eq!(parse_action(prose).tool.as_str(), "unknown", "{prose}");
        }
    }

    // ===================================================================================
    // Phase 14B — Category 2: strict-parser edge cases (white box, medium noise).
    // ===================================================================================

    /// 2.1 — `TOOL:` with no value → empty tool → `unknown` (fail-closed, the gate denies).
    #[test]
    fn attack_2_1_tool_with_no_value_is_unknown() {
        let a = parse_action("TOOL:\nPATH: /tmp/x.txt");
        assert_eq!(a.tool.as_str(), "unknown");
        assert_eq!(a.detail, "/tmp/x.txt");
    }

    /// 2.2 — `PATH:` with no value → empty detail (the orchestrator/tool judges it; empty is safe).
    #[test]
    fn attack_2_2_path_with_no_value_is_empty() {
        let a = parse_action("TOOL: write_file\nPATH:");
        assert_eq!(a.tool.as_str(), "write_file");
        assert_eq!(a.detail, "");
    }

    /// 2.3 — duplicate TOOL/PATH: 14-FIX F-16 makes the FIRST pair win, so an attacker who controls
    /// the model's *suffix* can no longer override the earlier pair (and the result is still gated).
    #[test]
    fn attack_2_3_first_pair_wins() {
        let a = parse_action("TOOL: read_file\nPATH: /tmp/a\nTOOL: write_file\nPATH: /tmp/b");
        assert_eq!(a.tool.as_str(), "read_file", "FIRST pair wins (F-16)");
        assert_eq!(a.detail, "/tmp/a");
    }

    /// 2.4 — a Cyrillic homoglyph (`\u{0435}`) in the tool name is byte-different from `write_file`;
    /// the parser does not normalize Unicode, so it yields a non-`write_file` tool the genome denies.
    #[test]
    fn attack_2_4_unicode_homoglyph_not_normalized() {
        let a = parse_action("TOOL: writ\u{0435}_file\nPATH: /tmp/x.txt");
        assert_ne!(a.tool.as_str(), "write_file", "homoglyph is byte-different");
        assert!(
            a.tool.as_str().contains('\u{0435}'),
            "the codepoint is preserved verbatim"
        );
    }

    /// 2.5 — escaped inner JSON in the `response` value. `json_string_field` decodes the escapes,
    /// so the extracted string is `{"TOOL": "write_file"}` — one line with no leading `TOOL:` prefix
    /// (it starts with `{`), so `parse_action` finds no TOOL line → `unknown`.
    #[test]
    fn attack_2_5_escaped_inner_json_yields_unknown() {
        let raw = "{\"response\": \"{\\\"TOOL\\\": \\\"write_file\\\"}\"}";
        let decoded = json_string_field(raw, "response");
        assert_eq!(decoded.as_deref(), Some("{\"TOOL\": \"write_file\"}"));
        // The decoded value is a single line beginning with `{`, not `TOOL:`; no match.
        let decoded = decoded.unwrap_or_default();
        assert_eq!(parse_action(&decoded).tool.as_str(), "unknown");
    }

    /// 2.6 — a response truncated mid-string (no closing quote). 14-FIX F-17: the extractor now
    /// returns `None` (fail clean) rather than a partial value, so the backend surfaces a clean
    /// error instead of a silently truncated string.
    #[test]
    fn attack_2_6_truncated_response() {
        // No `response` key present at all → None → BackendError upstream.
        assert!(json_string_field("{\"mod", "response").is_none());
        // `response` present but unterminated → None (F-17), not a partial value.
        assert!(
            json_string_field("{\"response\": \"TOO", "response").is_none(),
            "truncated value returns None (F-17), not a partial"
        );
    }

    // ---- 14-FIX F-16 / F-17 regression tests ----

    /// F-16: with multiple pairs, the FIRST wins — a benign pair cannot be overridden by an
    /// appended malicious suffix. Fails before the fix (would extract `write_file` / `/etc/shadow`).
    #[test]
    fn fix_f16_first_pair_wins() {
        let a =
            parse_action("TOOL: read_file\nPATH: /tmp/safe\nTOOL: write_file\nPATH: /etc/shadow");
        assert_eq!(
            a.tool.as_str(),
            "read_file",
            "defender's choice: FIRST tool"
        );
        assert_eq!(a.detail, "/tmp/safe", "defender's choice: FIRST path");
    }

    /// F-17: a value with no closing quote returns `None`. Fails before the fix (would return the
    /// partial `"TOO"`).
    #[test]
    fn fix_f17_truncated_returns_none() {
        assert!(json_string_field("{\"response\": \"TOO", "response").is_none());
        // A value truncated mid-escape (trailing backslash) also returns None.
        assert!(json_string_field("{\"response\": \"a\\", "response").is_none());
        // A well-formed value is still extracted.
        assert_eq!(
            json_string_field("{\"response\": \"ok\"}", "response").as_deref(),
            Some("ok")
        );
    }
}
