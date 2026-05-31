//! Property-based test for HLS pre-buffer variant selection (task 18.6).
//!
//! Feature: stream-flow, Property 16
//!
//! **Property 16: Prebuffer variant selection**
//!
//! *For any* set of HLS variant bandwidths and a configured ceiling, the
//! selected pre-buffer variant is the highest-bandwidth variant not exceeding
//! the ceiling, or the lowest-bandwidth variant when all exceed the ceiling.
//!
//! **Validates: Requirements 7.2**
//!
//! Requirement 7.2: *WHEN selecting a variant to pre-buffer for an HLS master
//! manifest, THE Streaming_Proxy_Engine SHALL select the variant whose
//! advertised `BANDWIDTH` is the highest that does not exceed the configured
//! pre-buffer bandwidth ceiling, and SHALL select the lowest-bandwidth variant
//! when all variants exceed the ceiling.*
//!
//! The test drives an *arbitrary* non-empty list of HLS variants (each with a
//! bandwidth and an I-frame/normal flag) plus an arbitrary bandwidth ceiling
//! through [`stream_flow::prebuffer::select_prebuffer_variant`] and checks the
//! result against an independent, specification-level oracle:
//!
//! * **Candidate pool:** real playback variants are preferred — I-frame
//!   trick-play variants (`#EXT-X-I-FRAME-STREAM-INF`) are excluded from
//!   selection whenever at least one normal variant exists, and only become
//!   candidates when the master advertises *only* I-frame variants.
//! * **At/under the ceiling (Req 7.2 clause 1):** when some candidate's
//!   bandwidth is `<=` the ceiling, the selection is the *highest* such
//!   bandwidth, with ties broken toward the first occurrence (determinism).
//! * **All exceed the ceiling (Req 7.2 clause 2):** when every candidate
//!   exceeds the ceiling, the selection is the *lowest* candidate bandwidth,
//!   again first-on-ties.
//!
//! Every generated variant carries a unique `uri` keyed by its index so the
//! exact variant chosen — including the first-occurrence tie-break — can be
//! asserted, not merely its bandwidth.

use m3u8_rs::VariantStream;
use proptest::prelude::*;
use stream_flow::prebuffer::select_prebuffer_variant;

/// A generator spec for a single variant: whether it is an I-frame-only
/// trick-play variant, and its advertised `BANDWIDTH`.
#[derive(Debug, Clone, Copy)]
struct VariantSpec {
    is_i_frame: bool,
    bandwidth: u64,
}

/// Build the `m3u8_rs::VariantStream` list the function under test consumes,
/// assigning each variant a unique `uri` (`v{index}.m3u8`) so the precise
/// selection can be identified even when bandwidths tie.
fn build_variants(specs: &[VariantSpec]) -> Vec<VariantStream> {
    specs
        .iter()
        .enumerate()
        .map(|(i, spec)| VariantStream {
            is_i_frame: spec.is_i_frame,
            uri: format!("v{i}.m3u8"),
            bandwidth: spec.bandwidth,
            ..VariantStream::default()
        })
        .collect()
}

/// Independent, specification-level oracle for Req 7.2. Returns the index of
/// the variant that *should* be selected, or `None` for an empty list.
///
/// Written in spec terms (filter → max-under-ceiling-else-min) rather than as
/// the one-pass scan the implementation uses, so it is a genuine cross-check.
fn expected_index(specs: &[VariantSpec], ceiling: u64) -> Option<usize> {
    if specs.is_empty() {
        return None;
    }

    // Candidate pool: prefer real playback variants; fall back to I-frame
    // variants only when there is no normal variant at all.
    let has_playable = specs.iter().any(|s| !s.is_i_frame);
    let candidates: Vec<usize> = specs
        .iter()
        .enumerate()
        .filter(|(_, s)| !has_playable || !s.is_i_frame)
        .map(|(i, _)| i)
        .collect();

    // Clause 1: some candidate is at/under the ceiling → highest such
    // bandwidth, first occurrence on ties.
    let under: Vec<usize> = candidates
        .iter()
        .copied()
        .filter(|&i| specs[i].bandwidth <= ceiling)
        .collect();
    if !under.is_empty() {
        let max_bw = under.iter().map(|&i| specs[i].bandwidth).max().unwrap();
        return under.into_iter().find(|&i| specs[i].bandwidth == max_bw);
    }

    // Clause 2: every candidate exceeds the ceiling → lowest candidate
    // bandwidth, first occurrence on ties.
    let min_bw = candidates.iter().map(|&i| specs[i].bandwidth).min().unwrap();
    candidates.into_iter().find(|&i| specs[i].bandwidth == min_bw)
}

/// A single variant spec. Bandwidths are biased toward a small shared set (to
/// force ties and boundary hits against the ceiling) plus a wide spread, and
/// the `0` / `u64::MAX` extremes are included. I-frame variants are the
/// minority so most generated masters exercise the normal-variant path.
fn variant_spec() -> impl Strategy<Value = VariantSpec> {
    let bandwidth = prop_oneof![
        3 => prop_oneof![
            Just(0u64),
            Just(500_000u64),
            Just(1_000_000u64),
            Just(2_000_000u64),
            Just(5_000_000u64),
        ],
        4 => 0u64..=20_000_000u64,
        1 => Just(u64::MAX),
    ];
    let is_i_frame = prop_oneof![3 => Just(false), 1 => Just(true)];
    (is_i_frame, bandwidth).prop_map(|(is_i_frame, bandwidth)| VariantSpec {
        is_i_frame,
        bandwidth,
    })
}

/// A bandwidth ceiling biased to coincide with the common variant bandwidths
/// (so the boundary `bandwidth == ceiling` is exercised), plus a wide spread
/// and the extremes.
fn ceiling_strategy() -> impl Strategy<Value = u64> {
    prop_oneof![
        3 => prop_oneof![
            Just(0u64),
            Just(500_000u64),
            Just(1_000_000u64),
            Just(2_000_000u64),
            Just(5_000_000u64),
        ],
        4 => 0u64..=20_000_000u64,
        1 => Just(u64::MAX),
    ]
}

proptest! {
    // 512 cases comfortably exceeds the 100-iteration floor for a property task.
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Feature: stream-flow, Property 16 — Prebuffer variant selection.
    /// **Validates: Requirements 7.2**
    #[test]
    fn prebuffer_variant_selection_matches_req_7_2(
        specs in proptest::collection::vec(variant_spec(), 1..=8),
        ceiling in ceiling_strategy(),
    ) {
        let variants = build_variants(&specs);
        let selected = select_prebuffer_variant(&variants, ceiling);

        // A non-empty master always yields a selection (Req 7.2 always picks
        // *something* so playback can start).
        let selected = selected.expect("a non-empty master must select a variant");

        // Recover the chosen index from its unique uri.
        let chosen = variants
            .iter()
            .position(|v| v.uri == selected.uri)
            .expect("selected variant must be one of the inputs");

        // -- Exact selection (incl. first-occurrence tie-break / determinism).
        let want = expected_index(&specs, ceiling)
            .expect("oracle must also select for a non-empty master");
        prop_assert_eq!(
            chosen,
            want,
            "selected index {} != expected {}\nspecs: {:?}\nceiling: {}",
            chosen,
            want,
            specs,
            ceiling
        );

        // -- Independent high-level invariants (re-derived from the spec). ---
        let has_playable = specs.iter().any(|s| !s.is_i_frame);

        // The selection is always drawn from the candidate pool: a normal
        // variant whenever any exists, else an I-frame variant.
        if has_playable {
            prop_assert!(
                !selected.is_i_frame,
                "an I-frame variant must not be chosen while a normal variant exists\nspecs: {:?}",
                specs
            );
        }

        let candidate_bws: Vec<u64> = specs
            .iter()
            .filter(|s| !has_playable || !s.is_i_frame)
            .map(|s| s.bandwidth)
            .collect();
        let min_candidate = *candidate_bws.iter().min().unwrap();
        let any_under = candidate_bws.iter().any(|&bw| bw <= ceiling);

        if any_under {
            // Clause 1: chosen is the highest candidate bandwidth not exceeding
            // the ceiling — it fits, and nothing else fits with more bandwidth.
            prop_assert!(
                selected.bandwidth <= ceiling,
                "selected bandwidth {} must not exceed the ceiling {} when something fits\nspecs: {:?}",
                selected.bandwidth,
                ceiling,
                specs
            );
            let max_under = candidate_bws
                .iter()
                .copied()
                .filter(|&bw| bw <= ceiling)
                .max()
                .unwrap();
            prop_assert_eq!(
                selected.bandwidth,
                max_under,
                "selected must be the highest candidate bandwidth at/under the ceiling\nspecs: {:?}\nceiling: {}",
                specs,
                ceiling
            );
        } else {
            // Clause 2: every candidate exceeds the ceiling → the lowest
            // candidate bandwidth is chosen.
            prop_assert!(
                selected.bandwidth > ceiling,
                "when all candidates exceed the ceiling the selection must too\nspecs: {:?}\nceiling: {}",
                specs,
                ceiling
            );
            prop_assert_eq!(
                selected.bandwidth,
                min_candidate,
                "selected must be the lowest candidate bandwidth when all exceed the ceiling\nspecs: {:?}\nceiling: {}",
                specs,
                ceiling
            );
        }
    }
}
