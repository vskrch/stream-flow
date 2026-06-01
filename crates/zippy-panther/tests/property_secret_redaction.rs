//! Property-based test for secret redaction in logs
//! (`observability::Redactor` — task 12.1, exercised by task 12.3).
//!
//! Feature: ZippyPanther, Property 34
//!
//! **Property 34: Secret redaction in logs**
//!
//! *For any* log record whose fields or formatted message contain a known
//! secret value (API password, store token, Vault secret, encrypted `d`/token),
//! the emitted log output does not contain that secret value verbatim.
//!
//! **Validates: Requirements 32.6, 46.7**
//!
//! Requirement 32.6: "WHEN logging a request that carries a secret in its URL
//! or headers, THE Stream_Flow_System SHALL redact the secret value in the
//! emitted log."
//!
//! Requirement 46.7: "THE Stream_Flow_System SHALL never log secret values, API
//! passwords, store tokens, or Vault_Secret contents in plaintext."
//!
//! ## Unit under test
//!
//! [`Redactor`] (design: Components → Observability → "Redactor … the single
//! secret-scrubbing primitive") is the one scrubbing primitive shared by the
//! `tracing` redaction layer and every ad-hoc string-logging call site. It
//! performs two complementary kinds of scrubbing, and Property 34 has a facet
//! for each:
//!
//! * **Registered-value scrubbing** — an exact secret value handed to
//!   `register_secret` at startup (the configured API password, metrics
//!   password, Vault secret, store tokens) is replaced with the fixed
//!   `[REDACTED]` marker *wherever it appears verbatim*, even in free-form
//!   text such as an error message.
//! * **Known-key scrubbing** — values of well-known sensitive query parameters
//!   (`api_password`, `token`, `d`, `t`, …) and header names (`authorization`,
//!   `x-stremthru-authorization`, `cookie`, …) are scrubbed wherever they
//!   appear in a URL/query-string or `Header: value` shape, catching secrets
//!   the code never explicitly registered (e.g. an end user's per-request
//!   encrypted `d` blob).
//!
//! ## How the invariant is exercised
//!
//! The generators lean on **disjoint alphabets** so the property is tested
//! cleanly without `prop_assume` rejection churn:
//!
//! * A **secret value** is drawn from lowercase letters + digits (`[a-z0-9]+`,
//!   always non-empty — an empty secret is ignored by the `Redactor` by
//!   design). This alphabet is disjoint from both the surrounding "scaffold"
//!   text (uppercase letters + spaces) and the uppercase-only `[REDACTED]`
//!   marker, so a generated secret can never appear in the scaffold by accident
//!   nor be reintroduced inside the marker after substitution.
//! * Sensitive **values** for the key-based facets always contain at least one
//!   digit, while the surviving scaffold (uppercase key/header name + marker)
//!   contains no digits — so `!out.contains(value)` is a sound check that the
//!   value was actually scrubbed rather than coincidentally absent.
//!
//! Each property registers/embeds the secret, redacts, and asserts the secret
//! value is gone verbatim while the non-secret surrounding text survives.

use proptest::prelude::*;
use zippy_panther::observability::{Redactor, REDACTED};

/// Sensitive query-parameter keys (mirrors the production `SENSITIVE_QUERY_KEYS`
/// set). Their values must always be scrubbed regardless of registration.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "api_password",
    "metrics_password",
    "password",
    "token",
    "access_token",
    "refresh_token",
    "vault_secret",
    "d",
    "t",
];

/// Sensitive header names (mirrors the production `SENSITIVE_HEADER_KEYS` set).
const SENSITIVE_HEADER_KEYS: &[&str] = &[
    "authorization",
    "x-api-password",
    "x-metrics-password",
    "x-stremthru-authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// A non-empty secret value: lowercase letters + digits. Disjoint from the
/// uppercase/space scaffold and the uppercase `[REDACTED]` marker.
fn arb_secret() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,32}".prop_map(|s| s)
}

/// Arbitrary "surrounding" log text: uppercase letters + spaces, possibly
/// empty. Contains no `=`, `:`, `&`, `?`, quote, `#`, or newline, so it never
/// triggers key-based scrubbing and survives redaction verbatim; and being
/// uppercase/space it can never contain a lowercase/digit secret as a
/// substring.
fn arb_scaffold() -> impl Strategy<Value = String> {
    "[A-Z ]{0,40}".prop_map(|s| s)
}

/// A sensitive value carrying at least one digit (digit-led), drawn from
/// lowercase + digits so it contains no query/header delimiter and is fully
/// scrubbed. The guaranteed digit makes `!out.contains(value)` sound because
/// the surviving scaffold/marker are digit-free.
fn arb_sensitive_value() -> impl Strategy<Value = String> {
    "[0-9][a-z0-9]{0,31}".prop_map(|s| s)
}

/// Flip the case of each ASCII letter in `s` according to the bits of `seed`
/// (non-letters such as `_` and `-` are preserved), to exercise the
/// case-insensitive key/header matching.
fn randomize_casing(s: &str, mut seed: u64) -> String {
    s.chars()
        .map(|c| {
            let upper = seed & 1 == 1;
            seed >>= 1;
            if c.is_ascii_alphabetic() {
                if upper {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect()
}

/// One of the sensitive query keys under arbitrary casing.
fn arb_query_key() -> impl Strategy<Value = String> {
    (0..SENSITIVE_QUERY_KEYS.len(), any::<u64>())
        .prop_map(|(idx, seed)| randomize_casing(SENSITIVE_QUERY_KEYS[idx], seed))
}

/// One of the sensitive header names under arbitrary casing.
fn arb_header_key() -> impl Strategy<Value = String> {
    (0..SENSITIVE_HEADER_KEYS.len(), any::<u64>())
        .prop_map(|(idx, seed)| randomize_casing(SENSITIVE_HEADER_KEYS[idx], seed))
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 34 — a **registered** secret value is
    /// scrubbed wherever it appears verbatim in a log line, while the
    /// surrounding non-secret text survives.
    ///
    /// **Validates: Requirements 32.6, 46.7**
    #[test]
    fn registered_secret_never_appears_verbatim(
        secret in arb_secret(),
        prefix in arb_scaffold(),
        suffix in arb_scaffold(),
    ) {
        let redactor = Redactor::new();
        redactor.register_secret(secret.clone());

        // A log line that embeds the registered secret in arbitrary text.
        let line = format!("{prefix}{secret}{suffix}");
        let out = redactor.redact(&line);

        // The whole property: the secret value is never emitted verbatim.
        prop_assert!(
            !out.contains(secret.as_str()),
            "registered secret {:?} leaked into redacted output {:?}",
            secret, out,
        );
        // It was replaced by the redaction marker.
        prop_assert!(
            out.contains(REDACTED),
            "redacted output {:?} is missing the {:?} marker",
            out, REDACTED,
        );
        // Non-secret surrounding text is preserved (redaction is surgical).
        prop_assert!(
            out.contains(prefix.as_str()) && out.contains(suffix.as_str()),
            "non-secret text was lost: prefix={:?} suffix={:?} out={:?}",
            prefix, suffix, out,
        );
    }

    /// Feature: ZippyPanther, Property 34 — the value of a sensitive **query
    /// parameter** is scrubbed even when the secret was never registered (e.g.
    /// an end user's per-request encrypted `d`/token blob).
    ///
    /// **Validates: Requirements 32.6, 46.7**
    #[test]
    fn sensitive_query_param_value_is_scrubbed(
        key in arb_query_key(),
        value in arb_sensitive_value(),
        prefix in arb_scaffold(),
    ) {
        let redactor = Redactor::new();

        // `?` puts the key at a parameter boundary; the value runs to the end
        // of the line, so it is scrubbed in full.
        let line = format!("{prefix}?{key}={value}");
        let out = redactor.redact(&line);

        // The secret value is gone verbatim.
        prop_assert!(
            !out.contains(value.as_str()),
            "query value {:?} (key {:?}) leaked into redacted output {:?}",
            value, key, out,
        );
        // The key is preserved and its value replaced by the marker.
        let expected = format!("{key}={REDACTED}");
        prop_assert!(
            out.contains(expected.as_str()),
            "expected {:?} in redacted output {:?}",
            expected, out,
        );
    }

    /// Feature: ZippyPanther, Property 34 — the value of a sensitive **header**
    /// is scrubbed while the header name is preserved.
    ///
    /// **Validates: Requirements 32.6, 46.7**
    #[test]
    fn sensitive_header_value_is_scrubbed(
        name in arb_header_key(),
        value in arb_sensitive_value(),
    ) {
        let redactor = Redactor::new();

        // A `Header-Name: value` line; the value runs to end of line.
        let line = format!("{name}: {value}");
        let out = redactor.redact(&line);

        // The secret value is gone verbatim.
        prop_assert!(
            !out.contains(value.as_str()),
            "header value {:?} (header {:?}) leaked into redacted output {:?}",
            value, name, out,
        );
        // The header name survives and its value is replaced by the marker.
        let expected = format!("{name}: {REDACTED}");
        prop_assert!(
            out.contains(expected.as_str()),
            "expected {:?} in redacted output {:?}",
            expected, out,
        );
    }
}
