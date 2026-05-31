//! Secret redaction (`observability::redaction`) — Req 32.6, 46.7.
//!
//! The system must **never** emit a secret value into a log line — not the API
//! password, a store token, the Vault secret, nor the encrypted `d`/token proxy
//! material that travels in request URLs (Req 32.6, 46.7). [`Redactor`] is the
//! single scrubbing primitive both the [`RedactionLayer`] `tracing` layer (so
//! *every* emitted log record is scrubbed centrally, not per-call-site) and any
//! ad-hoc string-logging call site share.
//!
//! It performs two complementary kinds of scrubbing on a rendered log string:
//!
//! 1. **Known-key scrubbing** — values of well-known sensitive query parameters
//!    and header names (`api_password`, `metrics_password`, `d`, `token`,
//!    `password`, `authorization`, …) are replaced wherever they appear in a
//!    URL/query-string or `Header: value` shape. This catches secrets the code
//!    never explicitly registered (e.g. an end user's encrypted `d` param that
//!    is unique per request).
//! 2. **Registered-value scrubbing** — exact secret values handed to
//!    [`Redactor::register_secret`] at startup (the configured API password,
//!    metrics password, Vault secret, store tokens) are replaced wherever they
//!    appear verbatim, even in free-form text such as an error message.
//!
//! Both replace the secret with the fixed [`REDACTED`] marker, so the property
//! *"the emitted output never contains the secret verbatim"* (Property 34,
//! task 12.3) holds for any log record.

use std::sync::Arc;

use arc_swap::ArcSwap;

/// The marker substituted for any scrubbed secret.
pub const REDACTED: &str = "[REDACTED]";

/// Query-parameter keys (case-insensitive) whose values are always secrets.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "api_password",
    "metrics_password",
    "password",
    "token",
    "access_token",
    "refresh_token",
    "vault_secret",
    // mediaflow-style encrypted proxy-link parameters (Req 14): the encrypted
    // `d` blob and stremthru token are per-link secrets.
    "d",
    "t",
];

/// Header names (case-insensitive) whose values are always secrets.
const SENSITIVE_HEADER_KEYS: &[&str] = &[
    "authorization",
    "x-api-password",
    "x-metrics-password",
    "x-stremthru-authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// The single secret-scrubbing primitive (Req 32.6, 46.7).
///
/// Cheap to clone (an [`Arc`] bump); clones share the same registered-secret
/// set, which is updated atomically so the `tracing` layer never blocks a
/// logging thread.
#[derive(Clone)]
pub struct Redactor {
    /// Exact secret values registered at startup, scrubbed verbatim anywhere.
    /// Hot-swapped via [`ArcSwap`] so registration never locks the log path.
    secrets: Arc<ArcSwap<Vec<String>>>,
}

impl Redactor {
    /// Build an empty redactor (only key-based scrubbing until secrets are
    /// registered).
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(ArcSwap::from_pointee(Vec::new())),
        }
    }

    /// Register an exact secret value to be scrubbed verbatim wherever it later
    /// appears in a log line (Req 32.6, 46.7).
    ///
    /// Empty values are ignored (an unset/empty secret is not sensitive and a
    /// blanket empty-string match would corrupt every line).
    pub fn register_secret(&self, secret: impl Into<String>) {
        let secret = secret.into();
        if secret.is_empty() {
            return;
        }
        let current = self.secrets.load();
        if current.iter().any(|s| s == &secret) {
            return;
        }
        let mut next = Vec::with_capacity(current.len() + 1);
        next.extend(current.iter().cloned());
        next.push(secret);
        self.secrets.store(Arc::new(next));
    }

    /// Scrub every known secret from `input`, returning the redacted string.
    ///
    /// Applies registered-value scrubbing first (so a registered secret is
    /// removed even when it travels under an unexpected key), then key-based
    /// query and header scrubbing.
    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_string();

        // 1. Registered exact secret values — verbatim, anywhere.
        for secret in self.secrets.load().iter() {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }

        // 2. Sensitive query parameters: `key=value` until the next delimiter.
        out = redact_query_params(&out);

        // 3. Sensitive header values: `Header-Name: value` until end of line.
        out = redact_header_values(&out);

        out
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

/// Replace the value of any sensitive query parameter (`key=value`) with the
/// redaction marker, preserving the key and the surrounding text.
///
/// A query-parameter value runs until the next `&`, whitespace, `"`, `'`, or
/// `#` (so a trailing fragment, a quoted log field, or the next param is left
/// intact).
fn redact_query_params(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        // Try to match a `key=` for one of the sensitive keys at position `i`,
        // but only at a parameter boundary (start, `?`, `&`) so we don't match
        // a key that is a suffix of a larger word (e.g. `grandtoken`).
        let at_boundary = i == 0 || matches!(bytes[i - 1], b'?' | b'&');
        if at_boundary {
            if let Some((key_len, _matched)) = match_sensitive_query_key(&input[i..]) {
                // Copy `key=`.
                out.push_str(&input[i..i + key_len]);
                i += key_len;
                // Skip + redact the value up to the next delimiter.
                let value_start = i;
                while i < bytes.len()
                    && !matches!(
                        bytes[i],
                        b'&' | b' ' | b'\t' | b'"' | b'\'' | b'#' | b'\n' | b'\r'
                    )
                {
                    i += 1;
                }
                if i > value_start {
                    out.push_str(REDACTED);
                }
                continue;
            }
        }
        // Default: copy one byte (UTF-8 safe — we only branch on ASCII bytes).
        let ch_start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
        out.push_str(&input[ch_start..i]);
    }

    out
}

/// If `s` begins with one of the sensitive query keys followed by `=`, return
/// `(len_of_key_plus_equals, key)`.
fn match_sensitive_query_key(s: &str) -> Option<(usize, &'static str)> {
    for &key in SENSITIVE_QUERY_KEYS {
        let klen = key.len();
        if s.len() > klen && s.as_bytes()[klen] == b'=' && s[..klen].eq_ignore_ascii_case(key) {
            return Some((klen + 1, key));
        }
    }
    None
}

/// Replace the value of any sensitive header (`Header-Name: value`) with the
/// redaction marker, preserving the header name. The value runs to end of line.
fn redact_header_values(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut first = true;
    for line in input.split_inclusive('\n') {
        if !first {
            // `split_inclusive` keeps the `\n` on the previous chunk, so no
            // separator handling is needed here.
        }
        first = false;
        out.push_str(&redact_header_line(line));
    }
    out
}

/// Redact a single (possibly newline-terminated) chunk if it is a sensitive
/// `Header-Name: value` line.
fn redact_header_line(line: &str) -> String {
    // Find the first colon; the header name is everything before it.
    if let Some(colon) = line.find(':') {
        let name = line[..colon].trim();
        if SENSITIVE_HEADER_KEYS
            .iter()
            .any(|k| name.eq_ignore_ascii_case(k))
        {
            // Preserve trailing newline (if any) so multi-line text is intact.
            let (body, eol) = match line.strip_suffix("\r\n") {
                Some(b) => (b, "\r\n"),
                None => match line.strip_suffix('\n') {
                    Some(b) => (b, "\n"),
                    None => (line, ""),
                },
            };
            // Keep `Header-Name:` plus one leading space, redact the value.
            let header_prefix = &body[..colon + 1];
            return format!("{header_prefix} {REDACTED}{eol}");
        }
    }
    line.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_query_params_only() {
        let r = Redactor::new();
        let line = "GET /proxy/stream?d=ENCRYPTEDBLOB&api_password=hunter2&x=keepme HTTP/1.1";
        let out = r.redact(line);
        assert!(!out.contains("ENCRYPTEDBLOB"));
        assert!(!out.contains("hunter2"));
        assert!(
            out.contains("x=keepme"),
            "non-secret param must survive: {out}"
        );
        assert!(out.contains("d=[REDACTED]"));
        assert!(out.contains("api_password=[REDACTED]"));
    }

    #[test]
    fn does_not_match_key_suffix() {
        let r = Redactor::new();
        // `grandtoken` ends with `token` but is not the `token` param.
        let line = "/x?grandtoken=keepme&token=secret";
        let out = r.redact(line);
        assert!(
            out.contains("grandtoken=keepme"),
            "suffix must not match: {out}"
        );
        assert!(out.contains("token=[REDACTED]"));
        assert!(!out.contains("token=secret"));
    }

    #[test]
    fn redacts_registered_secret_anywhere() {
        let r = Redactor::new();
        r.register_secret("super-secret-token");
        let out = r.redact("Authorization: Bearer super-secret-token failed");
        assert!(!out.contains("super-secret-token"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn empty_registered_secret_is_ignored() {
        let r = Redactor::new();
        r.register_secret("");
        // Must not turn every character into a marker.
        assert_eq!(r.redact("hello world"), "hello world");
    }

    #[test]
    fn redacts_sensitive_header_value() {
        let r = Redactor::new();
        let line = "X-StremThru-Authorization: Basic YWxpY2U6d29uZGVybGFuZA==";
        let out = r.redact(line);
        assert!(!out.contains("YWxpY2U6d29uZGVybGFuZA=="));
        assert!(out.contains("X-StremThru-Authorization: [REDACTED]"));
    }

    #[test]
    fn multiline_redacts_only_sensitive_header_lines() {
        let r = Redactor::new();
        let line = "Host: example.com\nAuthorization: Bearer abc123\nAccept: */*\n";
        let out = r.redact(line);
        assert!(out.contains("Host: example.com"));
        assert!(out.contains("Accept: */*"));
        assert!(!out.contains("abc123"));
        assert!(out.contains("Authorization: [REDACTED]"));
    }

    #[test]
    fn unicode_text_is_preserved() {
        let r = Redactor::new();
        let line = "café ☕ /x?token=secret ünïcödé";
        let out = r.redact(line);
        assert!(out.contains("café ☕"));
        assert!(out.contains("ünïcödé"));
        assert!(!out.contains("token=secret"));
    }
}
