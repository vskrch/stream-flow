//! Property-based test for `Server_Path_Prefix` normalization (task 3.4).
//!
//! Feature: stream-flow, Property 33
//!
//! **Property 33: Server path prefix normalization is idempotent**
//!
//! *For any* input string accepted as a path prefix, the normalized result
//! starts with `/`, does not end with `/`, contains no repeated internal
//! slashes, and normalizing an already-normalized prefix is the identity.
//!
//! **Validates: Requirements 31.4**
//!
//! Requirement 31.4: "WHEN the Server_Path_Prefix is provided, THE
//! Stream_Flow_System SHALL normalize it to start with `/`, not end with `/`,
//! and collapse repeated internal slashes."
//!
//! This property exercises [`stream_flow::config::normalize_path_prefix`] across
//! the full input space — operator-plausible prefixes (segments separated by
//! runs of slashes, with optional leading/trailing slashes) as well as fully
//! arbitrary and adversarial strings — and asserts the two invariants the
//! requirement hinges on:
//!
//! * **Canonical shape (Req 31.4):** whenever normalization *succeeds*, the
//!   result is either the empty string (the documented "no prefix" form, used
//!   for empty / slash-only inputs that carry no path segment) or a value that
//!   starts with `/`, does not end with `/`, and contains no repeated internal
//!   slashes.
//! * **Idempotence (Property 33):** feeding an already-normalized prefix back
//!   through the normalizer yields exactly the same value — and, since the
//!   canonical output only contains characters that already passed validation,
//!   re-normalization always *succeeds*.
//!
//! The operation is also **total**: for arbitrary / adversarial input it
//! returns either an `Ok(canonical)` or a typed [`PathPrefixError`] without ever
//! panicking (proptest fails the property on any panic). Inputs containing a
//! forbidden character are rejected (Req 31.5) and exercise the totality arm;
//! the idempotence claim is over the values the normalizer *accepts*.

use proptest::prelude::*;
use stream_flow::config::{normalize_path_prefix, PathPrefixError};

/// `true` when `out` has the canonical path-prefix shape required by Req 31.4:
/// the empty "no prefix" form, or a leading `/`, no trailing `/`, and no
/// repeated internal slashes.
fn is_canonical(out: &str) -> bool {
    out.is_empty() || (out.starts_with('/') && !out.ends_with('/') && !out.contains("//"))
}

/// Generates operator-plausible path-prefix inputs: 0..=4 path segments built
/// from clearly-allowed characters (alphanumerics plus the unreserved RFC 3986
/// marks that are neither whitespace, control, nor URL delimiters), joined and
/// optionally wrapped by runs of 0..=3 slashes. This drives the *success* path
/// — collapsing repeats, trimming edges, and inserting a leading slash — with
/// high probability so the canonical-shape and idempotence invariants get real
/// coverage rather than only the rejection arm.
fn valid_prefix_input() -> impl Strategy<Value = String> {
    // Allowed segment characters: a path-safe subset that always passes
    // `validate_chars` (no whitespace / control / URL-delimiter characters).
    let segment = "[a-zA-Z0-9._~-]{1,8}";
    let slash_run = "/{0,3}";
    let leading = "/{0,3}";

    (
        leading,
        proptest::collection::vec((segment, slash_run), 0..=4),
    )
        .prop_map(|(lead, parts)| {
            let mut s = lead;
            for (seg, slashes) in parts {
                s.push_str(&seg);
                s.push_str(&slashes);
            }
            s
        })
}

/// Generates the full adversarial space: empty, slash-only, whitespace /
/// control / URL-delimiter laden, multi-byte unicode, plus fully arbitrary
/// strings. Models "any input string" so the property covers both the
/// acceptance and rejection arms and proves totality (Req 31.4 / 31.5).
fn any_prefix_input() -> impl Strategy<Value = String> {
    prop_oneof![
        5 => valid_prefix_input(),
        1 => Just(String::new()),
        1 => Just("/".to_string()),
        1 => Just("///".to_string()),
        1 => Just("  /a b/ ".to_string()),
        1 => Just("/a\u{0}/b\t/c".to_string()),
        1 => Just("/a?x/#y/[z]".to_string()),
        1 => Just("/路径//段//".to_string()),
        2 => ".{0,48}",
        2 => any::<String>(),
    ]
}

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 33 — server path prefix normalization is
    /// idempotent. **Validates: Requirements 31.4**
    #[test]
    fn path_prefix_normalization_is_idempotent(input in any_prefix_input()) {
        // -- Total: returns Ok or a typed error, never panics (Req 31.4/31.5).
        match normalize_path_prefix(&input) {
            Ok(once) => {
                // -- Canonical shape (Req 31.4): leading `/` (or empty), no
                //    trailing `/`, no repeated internal slashes.
                prop_assert!(
                    is_canonical(&once),
                    "normalized {:?} -> {:?} is not in canonical shape",
                    input,
                    once,
                );

                // -- Idempotence (Property 33): re-normalizing an already
                //    normalized prefix succeeds and is the identity.
                let twice = normalize_path_prefix(&once)
                    .expect("re-normalizing a canonical prefix must succeed");
                prop_assert_eq!(
                    &twice,
                    &once,
                    "normalization was not idempotent for {:?}: {:?} -> {:?}",
                    input,
                    once,
                    twice,
                );
            }
            Err(PathPrefixError::ForbiddenChar { value, .. }) => {
                // Rejection arm (Req 31.5): the error names the offending value
                // verbatim. The idempotence claim is over accepted inputs, so
                // there is nothing further to assert here beyond totality.
                prop_assert_eq!(&value, &input);
            }
        }
    }
}
