//! `Server_Path_Prefix` normalization + validation (Req 31.4, 31.5).
//!
//! The `Server_Path_Prefix` is prepended to every generated URL when the system
//! runs behind a reverse proxy. A raw operator-supplied value is run through
//! [`normalize_path_prefix`] at config load time (see `config::Config::load`),
//! which guarantees the canonical shape required by Req 31.4:
//!
//! * a **leading** `/`,
//! * **no trailing** `/`,
//! * **collapsed** repeated internal slashes,
//!
//! and rejects (Req 31.5) any value containing **whitespace**, **control**
//! characters, or **URL-delimiter** characters, naming the offending value.
//!
//! Two boundary cases are treated as "no prefix" and normalize to the empty
//! string: the empty input (the documented default — the prefix is "not
//! provided") and an input consisting solely of slashes (e.g. `"/"`, `"//"`),
//! which carries no path segment. The empty string composes cleanly when a
//! prefix is later joined onto a route.
//!
//! ## What counts as a "URL delimiter"
//!
//! The reserved characters of RFC 3986 — the *gen-delims* and *sub-delims* —
//! are exactly the URL delimiters. The path separator `/` is intentionally
//! excluded (it is the segment separator this normalizer operates on); every
//! other reserved character is rejected.

/// Reason a configured `Server_Path_Prefix` was rejected at load (Req 31.5).
///
/// The error names the offending `value` together with the first disallowed
/// character and its byte offset, so the operator can locate the problem.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathPrefixError {
    /// The prefix contained a character that is not permitted in a URL path
    /// prefix (whitespace, a control character, or a URL delimiter).
    #[error("value `{value}` contains a forbidden {kind} character {ch:?} at byte offset {index}")]
    ForbiddenChar {
        /// The full offending prefix value (Req 31.5: "report the offending value").
        value: String,
        /// A human label for the rejected character class.
        kind: &'static str,
        /// The first offending character.
        ch: char,
        /// Byte offset of `ch` within `value`.
        index: usize,
    },
}

/// `true` when `ch` is an RFC 3986 reserved character (a URL delimiter), with
/// the path separator `/` deliberately excluded.
fn is_url_delimiter(ch: char) -> bool {
    matches!(
        ch,
        // gen-delims (minus '/').
        ':' | '?' | '#' | '[' | ']' | '@'
        // sub-delims.
        | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
    )
}

/// Reject the first whitespace / control / URL-delimiter character (Req 31.5).
fn validate_chars(input: &str) -> Result<(), PathPrefixError> {
    for (index, ch) in input.char_indices() {
        // `is_whitespace` is checked before `is_control` so a tab/newline is
        // reported as whitespace; both are rejected regardless of order.
        let kind = if ch.is_whitespace() {
            "whitespace"
        } else if ch.is_control() {
            "control"
        } else if is_url_delimiter(ch) {
            "URL delimiter"
        } else {
            continue;
        };
        return Err(PathPrefixError::ForbiddenChar {
            value: input.to_string(),
            kind,
            ch,
            index,
        });
    }
    Ok(())
}

/// Collapse repeated slashes, drop leading/trailing slashes, and re-emit each
/// segment behind a single `/`. Assumes `input` already passed [`validate_chars`].
fn normalize_validated(input: &str) -> String {
    // Splitting on '/' and discarding empty fragments collapses repeated
    // slashes and strips any leading/trailing slash in one pass.
    let segments: Vec<&str> = input.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        // Empty input, or an input made only of slashes ("/", "//", …): there
        // is no path segment, so this is "no prefix".
        return String::new();
    }
    let mut out = String::with_capacity(input.len() + 1);
    for segment in segments {
        out.push('/');
        out.push_str(segment);
    }
    out
}

/// Validate then normalize a `Server_Path_Prefix` (Req 31.4, 31.5).
///
/// Returns the canonical prefix (leading `/`, no trailing `/`, no repeated
/// internal slashes), the empty string when no path segment is present, or a
/// [`PathPrefixError`] naming the offending value when it contains a
/// whitespace, control, or URL-delimiter character.
///
/// The function is **idempotent**: feeding an already-normalized value back
/// through it yields the same value.
pub fn normalize_path_prefix(input: &str) -> Result<String, PathPrefixError> {
    // Validation precedes normalization so a rejected character is reported
    // against the operator's original value rather than a partially rewritten
    // one (Req 31.5).
    validate_chars(input)?;
    Ok(normalize_validated(input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ConfigLoadError, LoadOptions};
    use std::collections::HashMap;

    // ---- Req 31.4: normalization (leading '/', no trailing '/', collapse) ----

    #[test]
    fn adds_leading_slash_to_a_bare_segment() {
        assert_eq!(normalize_path_prefix("api").unwrap(), "/api");
    }

    #[test]
    fn strips_trailing_slash() {
        assert_eq!(normalize_path_prefix("/api/").unwrap(), "/api");
        assert_eq!(normalize_path_prefix("api/").unwrap(), "/api");
    }

    #[test]
    fn collapses_repeated_internal_slashes() {
        assert_eq!(normalize_path_prefix("//api//v1//").unwrap(), "/api/v1");
        assert_eq!(normalize_path_prefix("/api///v1").unwrap(), "/api/v1");
    }

    #[test]
    fn already_canonical_value_is_unchanged() {
        assert_eq!(normalize_path_prefix("/api/v1").unwrap(), "/api/v1");
    }

    #[test]
    fn empty_input_maps_to_no_prefix() {
        assert_eq!(normalize_path_prefix("").unwrap(), "");
    }

    #[test]
    fn slash_only_inputs_map_to_no_prefix() {
        assert_eq!(normalize_path_prefix("/").unwrap(), "");
        assert_eq!(normalize_path_prefix("//").unwrap(), "");
        assert_eq!(normalize_path_prefix("///").unwrap(), "");
    }

    #[test]
    fn normalized_value_starts_with_slash_and_has_no_trailing_slash() {
        let out = normalize_path_prefix("///deep//nested//path///").unwrap();
        assert!(out.starts_with('/'));
        assert!(!out.ends_with('/'));
        assert!(!out.contains("//"));
        assert_eq!(out, "/deep/nested/path");
    }

    // ---- idempotence ----

    #[test]
    fn normalization_is_idempotent() {
        for input in [
            "",
            "/",
            "api",
            "/api",
            "/api/",
            "//api//v1//",
            "/a/b/c",
            "deep/nested/path/",
        ] {
            let once = normalize_path_prefix(input).unwrap();
            let twice = normalize_path_prefix(&once).unwrap();
            assert_eq!(once, twice, "normalizing {input:?} was not idempotent");
        }
    }

    // ---- Req 31.5: reject whitespace / control / URL-delimiter characters ----

    #[test]
    fn rejects_space() {
        let err = normalize_path_prefix("/api v1").unwrap_err();
        match err {
            PathPrefixError::ForbiddenChar { kind, ch, .. } => {
                assert_eq!(kind, "whitespace");
                assert_eq!(ch, ' ');
            }
        }
    }

    #[test]
    fn rejects_tab_and_newline() {
        assert!(matches!(
            normalize_path_prefix("/api\tv1").unwrap_err(),
            PathPrefixError::ForbiddenChar {
                kind: "whitespace",
                ..
            }
        ));
        assert!(matches!(
            normalize_path_prefix("/api\nv1").unwrap_err(),
            PathPrefixError::ForbiddenChar {
                kind: "whitespace",
                ..
            }
        ));
    }

    #[test]
    fn rejects_control_character() {
        let err = normalize_path_prefix("/api\u{0007}v1").unwrap_err();
        assert!(matches!(
            err,
            PathPrefixError::ForbiddenChar {
                kind: "control",
                ..
            }
        ));
    }

    #[test]
    fn rejects_url_delimiters() {
        for bad in [
            "/api?x", "/api#x", "/a[b]", "/a@b", "/a:b", "/a!b", "/a$b", "/a&b", "/a'b", "/a(b)",
            "/a*b", "/a+b", "/a,b", "/a;b", "/a=b",
        ] {
            let err = normalize_path_prefix(bad).unwrap_err();
            assert!(
                matches!(
                    err,
                    PathPrefixError::ForbiddenChar {
                        kind: "URL delimiter",
                        ..
                    }
                ),
                "expected {bad:?} to be rejected as a URL delimiter, got {err:?}"
            );
        }
    }

    #[test]
    fn error_names_the_offending_value() {
        let err = normalize_path_prefix("/bad value").unwrap_err();
        // The Display must surface the offending value so the operator can find it.
        assert!(
            err.to_string().contains("/bad value"),
            "error message should name the offending value, got: {err}"
        );
    }

    #[test]
    fn path_separator_slash_is_not_treated_as_a_delimiter() {
        // '/' must be allowed (it is the segment separator we normalize on).
        assert_eq!(normalize_path_prefix("/a/b").unwrap(), "/a/b");
    }

    // ---- load-time wiring (Req 31.4, 31.5 via Config::load) ----

    fn env_with_api_password() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("APP__AUTH__API_PASSWORD".to_string(), "secret".to_string());
        env
    }

    #[test]
    fn load_normalizes_path_prefix() {
        let mut env = env_with_api_password();
        env.insert(
            "APP__SERVER__PATH_PREFIX".to_string(),
            "//api//v1//".to_string(),
        );
        let config = Config::load(&LoadOptions::new().with_env(env)).expect("valid prefix loads");
        assert_eq!(config.server.path_prefix, "/api/v1");
    }

    #[test]
    fn load_rejects_invalid_path_prefix_naming_the_value() {
        let mut env = env_with_api_password();
        env.insert(
            "APP__SERVER__PATH_PREFIX".to_string(),
            "/bad prefix".to_string(),
        );
        let err = Config::load(&LoadOptions::new().with_env(env))
            .expect_err("invalid prefix must abort load");
        match err {
            ConfigLoadError::InvalidPathPrefix(inner) => {
                assert!(
                    inner.to_string().contains("/bad prefix"),
                    "load error should name the offending value, got: {inner}"
                );
            }
            other => panic!("expected InvalidPathPrefix, got {other:?}"),
        }
    }

    #[test]
    fn load_leaves_default_empty_prefix_empty() {
        let config = Config::load(&LoadOptions::new().with_env(env_with_api_password()))
            .expect("default prefix loads");
        assert_eq!(config.server.path_prefix, "");
    }
}
