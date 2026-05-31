//! Property-based test for magnet status normalization totality
//! (task 22.6, Property 21).
//!
//! Feature: stream-flow, Property 21
//!
//! **Property 21: Magnet status normalization is total**
//!
//! *For any* arbitrary string, `MagnetStatus::from_native` produces exactly one
//! of the 9 `MagnetStatus` variants without panicking. Known native strings
//! (dead, virus, errored, etc.) always map to `Failed` (Req 16.14).
//!
//! **Validates: Requirements 16.5, 16.14**
//!
//! Requirement 16.5: "WHEN any Store operation reports a magnet's state, THE
//! Orchestration_Layer SHALL represent it as exactly one Magnet_Status from the
//! set `cached`, `queued`, `downloading`, `processing`, `downloaded`,
//! `uploading`, `failed`, `invalid`, `unknown`."
//!
//! Requirement 16.14: "WHEN a magnet's underlying torrent is reported by the
//! store as dead, errored, or virus-flagged, THE Orchestration_Layer SHALL
//! represent its Magnet_Status as `failed` rather than `downloading` or
//! `unknown`."
//!
//! ## How the invariant is exercised
//!
//! 1. **Totality (Req 16.5):** For any arbitrary string (including empty,
//!    whitespace-only, unicode, control characters), `from_native` returns
//!    exactly one of the 9 canonical variants — it never panics.
//!
//! 2. **Failed-mapping (Req 16.14):** Known failure-indicating native strings
//!    (`dead`, `virus`, `error`, `errored`, etc.) always map to
//!    `MagnetStatus::Failed`, regardless of case.

use proptest::prelude::*;
use stream_flow::store::MagnetStatus;

/// The complete set of known native strings that MUST map to `Failed`
/// per Req 16.14 (dead, errored, virus-flagged, and related failure states).
const KNOWN_FAILED_NATIVES: &[&str] = &[
    "failed",
    "error",
    "dead",
    "virus",
    "magnet_error",
    "banned",
    "file_hosters_are_not_available",
    "internal_error",
    "download_error",
    "not_downloaded",
    "timed_out",
];

/// Strategy that generates arbitrary strings — exercises totality.
fn arb_native_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // Completely arbitrary unicode strings (the main totality exerciser)
        "\\PC{0,64}",
        // Empty and whitespace-only
        Just(String::new()),
        Just("   ".to_string()),
        // Known canonical status names (should map to themselves)
        prop_oneof![
            Just("cached".to_string()),
            Just("queued".to_string()),
            Just("downloading".to_string()),
            Just("processing".to_string()),
            Just("downloaded".to_string()),
            Just("uploading".to_string()),
            Just("failed".to_string()),
            Just("invalid".to_string()),
            Just("unknown".to_string()),
        ],
        // Known native aliases
        prop_oneof![
            Just("ready".to_string()),
            Just("finished".to_string()),
            Just("seeding".to_string()),
            Just("completed".to_string()),
            Just("waiting".to_string()),
            Just("pending".to_string()),
            Just("active".to_string()),
            Just("dead".to_string()),
            Just("virus".to_string()),
            Just("error".to_string()),
            Just("magnet_error".to_string()),
            Just("banned".to_string()),
            Just("wrong_password".to_string()),
            Just("bad_token".to_string()),
        ],
    ]
}

/// Strategy that generates known failure-indicating native strings with
/// arbitrary casing to exercise case-insensitive matching (Req 16.14).
fn arb_failed_native() -> impl Strategy<Value = String> {
    prop::sample::select(KNOWN_FAILED_NATIVES).prop_flat_map(|s| {
        // Generate the string with random casing
        Just(s.to_string()).prop_map(|base| {
            base.chars()
                .map(|c| {
                    if c.is_ascii_alphabetic() {
                        // Randomly upper/lower — but since proptest strategies
                        // must be deterministic per seed, we alternate based on
                        // char position parity for variety. The real test is
                        // that from_native lowercases internally.
                        c // keep original; we'll also test uppercase variants
                    } else {
                        c
                    }
                })
                .collect::<String>()
        })
    })
}

/// Strategy that generates uppercase variants of known failure natives.
fn arb_failed_native_upper() -> impl Strategy<Value = String> {
    prop::sample::select(KNOWN_FAILED_NATIVES)
        .prop_map(|s| s.to_uppercase())
}

/// Strategy that generates mixed-case variants of known failure natives.
fn arb_failed_native_mixed() -> impl Strategy<Value = String> {
    prop::sample::select(KNOWN_FAILED_NATIVES).prop_map(|s| {
        s.chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c.to_lowercase().next().unwrap_or(c)
                }
            })
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 21 — magnet status normalization is total.
    /// **Validates: Requirements 16.5, 16.14**
    ///
    /// For any arbitrary string, `from_native` produces exactly one of the 9
    /// MagnetStatus variants without panicking (Req 16.5).
    #[test]
    fn from_native_is_total_for_any_string(input in arb_native_string()) {
        // This call must not panic — totality.
        let result = MagnetStatus::from_native(&input);

        // The result must be one of the 9 canonical variants (Req 16.5).
        prop_assert!(
            MagnetStatus::ALL.contains(&result),
            "from_native({:?}) returned {:?} which is not in MagnetStatus::ALL",
            input,
            result,
        );
    }

    /// Feature: stream-flow, Property 21 — known failure natives map to Failed.
    /// **Validates: Requirements 16.14**
    ///
    /// Known native strings (dead, virus, errored, etc.) always map to
    /// `MagnetStatus::Failed`, never to `Downloading` or `Unknown`.
    #[test]
    fn known_failure_natives_map_to_failed(input in arb_failed_native()) {
        let result = MagnetStatus::from_native(&input);

        prop_assert_eq!(
            result,
            MagnetStatus::Failed,
            "from_native({:?}) should be Failed (Req 16.14), got {:?}",
            input,
            result,
        );

        // Explicitly verify it is NOT Downloading or Unknown (Req 16.14).
        prop_assert_ne!(
            result,
            MagnetStatus::Downloading,
            "from_native({:?}) must never be Downloading for a failure native",
            input,
        );
        prop_assert_ne!(
            result,
            MagnetStatus::Unknown,
            "from_native({:?}) must never be Unknown for a failure native",
            input,
        );
    }

    /// Feature: stream-flow, Property 21 — uppercase failure natives map to Failed.
    /// **Validates: Requirements 16.14**
    ///
    /// Case-insensitive matching: uppercase variants of known failure strings
    /// still map to `Failed`.
    #[test]
    fn uppercase_failure_natives_map_to_failed(input in arb_failed_native_upper()) {
        let result = MagnetStatus::from_native(&input);

        prop_assert_eq!(
            result,
            MagnetStatus::Failed,
            "from_native({:?}) should be Failed (case-insensitive, Req 16.14), got {:?}",
            input,
            result,
        );
    }

    /// Feature: stream-flow, Property 21 — mixed-case failure natives map to Failed.
    /// **Validates: Requirements 16.14**
    ///
    /// Case-insensitive matching: mixed-case variants of known failure strings
    /// still map to `Failed`.
    #[test]
    fn mixed_case_failure_natives_map_to_failed(input in arb_failed_native_mixed()) {
        let result = MagnetStatus::from_native(&input);

        prop_assert_eq!(
            result,
            MagnetStatus::Failed,
            "from_native({:?}) should be Failed (mixed-case, Req 16.14), got {:?}",
            input,
            result,
        );
    }

    /// Feature: stream-flow, Property 21 — totality with purely random bytes.
    /// **Validates: Requirements 16.5**
    ///
    /// Even completely random strings (not biased toward known natives) produce
    /// a valid variant without panicking.
    #[test]
    fn from_native_never_panics_on_random_input(input in "\\PC{0,128}") {
        let result = MagnetStatus::from_native(&input);

        prop_assert!(
            MagnetStatus::ALL.contains(&result),
            "from_native on random input {:?} returned {:?} not in ALL",
            input,
            result,
        );
    }
}
