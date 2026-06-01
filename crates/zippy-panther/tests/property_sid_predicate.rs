//! Property-based test for the `sid` acceptance/ignore predicate
//! (task 24.7, Property 23).
//!
//! Feature: stream-flow, Property 23
//!
//! **Property 23: sid acceptance/ignore predicate**
//!
//! *For any* `sid` string, it is retained when it matches
//! `tt<digits>[:season:episode]` (regex `tt\d+(?::\d+:\d+)?`) and silently
//! ignored (returns `None`) — never rejected — otherwise.
//!
//! **Validates: Requirements 17.13**
//!
//! Requirement 17.13: a `sid` query parameter is accepted when it matches
//! `tt\d+(?::\d+:\d+)?` and ignored (treated as absent, returning `None`) when
//! malformed, so that a request carrying a malformed `sid` is still processed
//! rather than rejected.
//!
//! The implementation under test is the public predicate
//! [`stream_flow::store::endpoints::validate_sid`].
//!
//! ## How the invariant is exercised
//!
//! 1. **Acceptance (well-formed shape):** every `tt` + digits string, with or
//!    without a `:season:episode` suffix, is retained verbatim — the function
//!    returns `Some(input)`.
//! 2. **Ignore-not-reject (malformed shape):** arbitrary and near-miss strings
//!    that do not match the shape return `None`; the function never errors or
//!    panics (totality), so the surrounding request keeps flowing.
//! 3. **Oracle agreement:** for arbitrary and near-miss inputs the result is
//!    compared against an independent oracle that re-derives the Req 17.13
//!    contract with a deliberately different implementation strategy.

use proptest::prelude::*;
use stream_flow::store::endpoints::validate_sid;

// ---------------------------------------------------------------------------
// Independent oracle
// ---------------------------------------------------------------------------
//
// This oracle re-derives the Req 17.13 contract WITHOUT reusing the source's
// algorithm. The source uses `str::strip_prefix("tt")` followed by
// `splitn(3, ':')` with an explicit "season requires episode" branch. The
// oracle instead checks `starts_with`, slices the literal 2-byte `tt` prefix,
// and uses an unbounded `split(':')` collected into a `Vec`, accepting only the
// 1-segment (id only) and 3-segment (id:season:episode) shapes. Different code,
// same contract.

/// True iff `s` is a non-empty run of ASCII digits.
fn is_ascii_digits_nonempty(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// True iff `s` (already trimmed) matches `tt\d+(?::\d+:\d+)?` as a full match.
fn oracle_is_well_formed(s: &str) -> bool {
    if !s.starts_with("tt") {
        return false;
    }
    // "tt" is two ASCII bytes, so byte index 2 is a valid char boundary.
    let rest = &s[2..];
    let segments: Vec<&str> = rest.split(':').collect();
    match segments.len() {
        // tt<digits>
        1 => is_ascii_digits_nonempty(segments[0]),
        // tt<digits>:<digits>:<digits>
        3 => segments.iter().all(|seg| is_ascii_digits_nonempty(seg)),
        // one colon (season without episode) or 3+ colons -> not the shape
        _ => false,
    }
}

/// Independent reference for `validate_sid(Some(raw))`: the contract trims the
/// input first, then retains the trimmed value when it matches the shape,
/// otherwise ignores it (`None`).
fn oracle_validate_sid(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if oracle_is_well_formed(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// Well-formed `sid` values (no surrounding whitespace), so the trimmed value
/// equals the input and acceptance must return `Some(input)` verbatim.
fn arb_well_formed_sid() -> impl Strategy<Value = String> {
    prop_oneof![
        // tt + digits (IMDb id only)
        "tt[0-9]{1,9}",
        // tt + digits + :season:episode
        "tt[0-9]{1,9}:[0-9]{1,5}:[0-9]{1,5}",
    ]
}

/// Arbitrary strings — overwhelmingly malformed, exercising the ignore branch
/// and totality across the full input space (unicode, control chars, empty).
fn arb_arbitrary_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // any unicode, any char class
        "\\PC{0,48}",
        ".*",
        Just(String::new()),
        Just("   ".to_string()),
        Just("tt".to_string()),
        Just("imdb:tt123".to_string()),
        Just("123456".to_string()),
    ]
}

/// Near-miss strings that crowd the predicate boundary: missing `tt`, missing
/// episode, non-digit parts, extra colons, and well-formed values wrapped in
/// whitespace (to exercise the trim semantics).
fn arb_near_miss_sid() -> impl Strategy<Value = String> {
    prop_oneof![
        // tt + digits then junk / trailing parts
        "tt[0-9]{0,6}[:a-z ]{0,4}[0-9]{0,4}",
        // season present, episode possibly missing/empty
        "tt[0-9]{1,6}:[0-9]{0,4}",
        // two colons but possibly empty / non-digit parts
        "tt[0-9]{0,4}:[0-9a-z]{0,4}:[0-9a-z]{0,4}",
        // three+ colons (too many parts)
        "tt[0-9]{1,4}:[0-9]{1,4}:[0-9]{1,4}:[0-9]{1,4}",
        // missing or partial "tt" prefix
        "t?[0-9]{1,6}(:[0-9]{1,4}:[0-9]{1,4})?",
        // well-formed wrapped in surrounding whitespace (trim is applied)
        " {0,3}tt[0-9]{1,6}(:[0-9]{1,4}:[0-9]{1,4})? {0,3}",
    ]
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 23 — well-formed sids are retained verbatim.
    /// **Validates: Requirements 17.13**
    ///
    /// Any `tt<digits>[:season:episode]` value (no surrounding whitespace) is
    /// accepted and returned unchanged.
    #[test]
    fn well_formed_sid_is_retained(sid in arb_well_formed_sid()) {
        // Sanity: the generator really produces the well-formed shape.
        prop_assert!(
            oracle_is_well_formed(&sid),
            "generator produced a non-well-formed sid {:?}",
            sid,
        );

        // Acceptance: retained verbatim (Req 17.13).
        prop_assert_eq!(
            validate_sid(Some(&sid)),
            Some(sid.clone()),
            "well-formed sid {:?} must be retained as Some(input)",
            sid,
        );
    }

    /// Feature: stream-flow, Property 23 — arbitrary sids are ignored, never rejected.
    /// **Validates: Requirements 17.13**
    ///
    /// For any string the function is total (never panics) and its result
    /// agrees with the independent oracle: malformed shapes yield `None`
    /// (ignored, not rejected), well-formed shapes yield the trimmed value.
    #[test]
    fn arbitrary_sid_matches_oracle(raw in arb_arbitrary_string()) {
        let got = validate_sid(Some(&raw));
        let expected = oracle_validate_sid(&raw);
        prop_assert_eq!(
            &got,
            &expected,
            "validate_sid({:?}) = {:?}, oracle expected {:?}",
            raw,
            got,
            expected,
        );

        // Ignore-not-reject: when the shape does not match, the result is None
        // (the request would still be processed with the sid treated as absent).
        if !oracle_is_well_formed(raw.trim()) {
            prop_assert_eq!(
                validate_sid(Some(&raw)),
                None,
                "malformed sid {:?} must be ignored (None), not rejected",
                raw,
            );
        }
    }

    /// Feature: stream-flow, Property 23 — boundary near-misses match the oracle.
    /// **Validates: Requirements 17.13**
    ///
    /// Strings that crowd the acceptance boundary (missing prefix, missing
    /// episode, non-digit parts, extra colons, whitespace-wrapped values)
    /// agree with the independent oracle for both the accept and ignore cases.
    #[test]
    fn near_miss_sid_matches_oracle(raw in arb_near_miss_sid()) {
        let got = validate_sid(Some(&raw));
        let expected = oracle_validate_sid(&raw);
        prop_assert_eq!(
            &got,
            &expected,
            "validate_sid({:?}) = {:?}, oracle expected {:?}",
            raw,
            got,
            expected,
        );

        // Whatever the verdict, an accepted sid is always the well-formed,
        // trimmed shape — never an arbitrary or whitespace-padded string.
        if let Some(ref accepted) = got {
            prop_assert!(
                oracle_is_well_formed(accepted),
                "accepted sid {:?} is not well-formed",
                accepted,
            );
            prop_assert_eq!(
                accepted.trim(),
                accepted.as_str(),
                "accepted sid {:?} must not carry surrounding whitespace",
                accepted,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Totality of the absent case (example-based)
// ---------------------------------------------------------------------------

/// `validate_sid(None)` is ignored (returns `None`) rather than panicking or
/// rejecting — the absent-sid contract (Req 17.13).
#[test]
fn absent_sid_returns_none() {
    assert_eq!(validate_sid(None), None);
}
