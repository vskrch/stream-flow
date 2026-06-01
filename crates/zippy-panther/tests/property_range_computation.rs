//! Property-based test for generic byte-range computation (task 13.4).
//!
//! Feature: stream-flow, Property 1
//!
//! **Property 1: Generic range computation correctness and 416**
//!
//! *For any* resource size `S` and any `RangeSpec` (full, `from-offset`,
//! inclusive, or suffix), the computed response metadata is correct: a
//! satisfiable range produces `206` with `Content-Range: bytes start-end/S`
//! where `0 ≤ start ≤ end < S`, an open-ended `bytes=N-` spans `N..S-1`, a
//! suffix `bytes=-N` spans `max(0,S-N)..S-1`, and any range whose start is
//! `≥ S` produces `416` with `Content-Range: bytes */S`.
//!
//! **Validates: Requirements 5.2, 5.5, 19.2, 37.15, 37.16**
//!
//! Requirement 5.2 / 19.2: a satisfiable range is served as `206 Partial
//! Content` with a `Content-Range` header. Requirement 5.5: an unsatisfiable
//! range is a `416 Range Not Satisfiable`. Requirement 37.15: an open-ended
//! range (`bytes=N-`) spans from the requested offset to the last byte.
//! Requirement 37.16: a suffix range (`bytes=-N`) returns the final `N` bytes.
//!
//! This property exercises the pure range arithmetic of
//! [`stream_flow::proxy::RangeSpec::resolve`] and
//! [`stream_flow::proxy::compute_response_metadata`] against an **independent
//! oracle** that re-derives the expected outcome straight from the requirement
//! text (open-ended → `N..=S-1`; suffix → `max(0,S-N)..=S-1`; closed → clamp
//! the end to `S-1`; `start ≥ S`, zero-length suffix, or any range on an empty
//! resource → `416`). Generators bias offsets toward the `start == S` /
//! `start > S` boundaries (and total sizes toward `0`/`1`/small) so the
//! satisfiable↔unsatisfiable frontier — and the `416` arm — get real coverage
//! across a spread of resource sizes up to `u32::MAX`.

use proptest::prelude::*;
use stream_flow::proxy::{compute_response_metadata, RangeSpec, ResolvedRange};

/// The requirement-level expected outcome of resolving a `RangeSpec` against a
/// known total size, derived independently of the implementation under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    /// `RangeSpec::Full` → `200 OK`, whole body.
    Full,
    /// A satisfiable partial range → `206` with `Content-Range: bytes
    /// start-end/total`. `start`/`end` are inclusive absolute offsets.
    Partial { start: u64, end: u64 },
    /// An unsatisfiable range → `416` with `Content-Range: bytes */total`.
    Unsatisfiable,
}

/// Independent oracle: re-derive the expected outcome from the requirement
/// semantics, deliberately *not* sharing code with the implementation.
///
/// * Open-ended `bytes=N-` → `N..=S-1` when `N < S` (Req 37.15).
/// * Suffix `bytes=-N` → `max(0,S-N)..=S-1` when `N > 0` and `S > 0` (Req 37.16).
/// * Closed `bytes=N-M` → `N..=min(M,S-1)` when `N < S` (Req 5.2).
/// * `start ≥ S`, a zero-length suffix, or any range on an empty resource is
///   unsatisfiable (Req 5.5).
fn oracle(spec: &RangeSpec, total: u64) -> Expected {
    match *spec {
        RangeSpec::Full => Expected::Full,
        RangeSpec::FromOffset(start) => {
            if start >= total {
                Expected::Unsatisfiable
            } else {
                Expected::Partial {
                    start,
                    end: total - 1,
                }
            }
        }
        RangeSpec::Inclusive(start, end) => {
            if start >= total {
                Expected::Unsatisfiable
            } else {
                // RFC 7233: a last-byte-pos beyond the resource clamps to S-1.
                Expected::Partial {
                    start,
                    end: end.min(total - 1),
                }
            }
        }
        RangeSpec::Suffix(n) => {
            if n == 0 || total == 0 {
                Expected::Unsatisfiable
            } else {
                // max(0, S-N) expressed as a saturating subtraction.
                Expected::Partial {
                    start: total.saturating_sub(n),
                    end: total - 1,
                }
            }
        }
    }
}

/// Total resource sizes, biased toward the small/boundary sizes (`0`, `1`,
/// kilobyte-scale) where the satisfiable↔unsatisfiable frontier is dense, while
/// still reaching multi-gigabyte sizes up to `u32::MAX`.
fn total_strategy() -> impl Strategy<Value = u64> {
    prop_oneof![
        2 => Just(0u64),
        2 => Just(1u64),
        6 => 0u64..=4096,
        3 => 0u64..=10_000_000,
        2 => 0u64..=u64::from(u32::MAX),
    ]
}

/// Byte offsets relative to `total`, biased so the `start == total` and
/// `start > total` boundaries (the `416` frontier) are hit frequently rather
/// than vanishingly rarely as `total` grows.
fn offset_for_total(total: u64) -> impl Strategy<Value = u64> {
    let last = total.saturating_sub(1);
    let beyond_hi = total.saturating_add(16);
    prop_oneof![
        4 => 0u64..=last,          // interior (< total when total > 0)
        1 => Just(0u64),
        1 => Just(last),
        1 => Just(total),          // exactly at the size boundary
        1 => total..=beyond_hi,    // at or beyond the size boundary
    ]
}

/// Generate a `RangeSpec` whose offsets are drawn relative to `total`, covering
/// all four spec shapes. Inclusive ranges keep `start ≤ end` (the only form the
/// parser yields) and let `end` run past `S-1` to exercise end-clamping.
fn spec_for_total(total: u64) -> impl Strategy<Value = RangeSpec> {
    prop_oneof![
        1 => Just(RangeSpec::Full),
        3 => offset_for_total(total).prop_map(RangeSpec::FromOffset),
        3 => offset_for_total(total)
            .prop_flat_map(move |start| {
                let hi = start.saturating_add(total).saturating_add(16);
                (Just(start), start..=hi)
            })
            .prop_map(|(start, end)| RangeSpec::Inclusive(start, end)),
        3 => offset_for_total(total).prop_map(RangeSpec::Suffix),
    ]
}

/// `(total, spec)` pairs with the spec's offsets generated relative to the
/// total, so every total size gets coverage across its own boundaries.
fn total_and_spec() -> impl Strategy<Value = (u64, RangeSpec)> {
    total_strategy()
        .prop_flat_map(|total| spec_for_total(total).prop_map(move |spec| (total, spec)))
}

proptest! {
    // 256 cases > the 100-iteration floor required for a property task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 1 — generic range computation correctness
    /// and 416. **Validates: Requirements 5.2, 5.5, 19.2, 37.15, 37.16**
    #[test]
    fn range_computation_matches_oracle((total, spec) in total_and_spec()) {
        let expected = oracle(&spec, total);

        // `resolve` and `compute_response_metadata` must agree with each other
        // and with the independent oracle.
        let resolved = spec.resolve(total);
        let meta = compute_response_metadata(&spec, Some(total), false);

        match expected {
            // -- Full body: 200, no Content-Range, Content-Length = S --------
            Expected::Full => {
                prop_assert_eq!(
                    resolved,
                    Ok(None),
                    "Full spec must resolve to the whole body for total {}",
                    total
                );
                let meta = meta.expect("Full spec is always satisfiable");
                prop_assert_eq!(meta.status.as_u16(), 200);
                prop_assert_eq!(&meta.content_range, &None);
                prop_assert_eq!(meta.content_length, Some(total));
                prop_assert_eq!(meta.range, None);
                prop_assert!(meta.accept_ranges, "size is known, so Accept-Ranges holds");
            }

            // -- Satisfiable partial range: 206 + Content-Range (Req 5.2/19.2,
            //    37.15, 37.16) ----------------------------------------------
            Expected::Partial { start, end } => {
                let want = ResolvedRange { start, end, total };

                // Structural invariant from Property 1: 0 <= start <= end < S.
                prop_assert!(start <= end, "start {} must not exceed end {}", start, end);
                prop_assert!(end < total, "end {} must be < total {}", end, total);

                prop_assert_eq!(
                    resolved,
                    Ok(Some(want)),
                    "resolve mismatch for {:?} against total {}",
                    spec,
                    total
                );

                let meta = meta.expect("a satisfiable range yields metadata, not 416");
                prop_assert_eq!(meta.status.as_u16(), 206);
                prop_assert_eq!(meta.range, Some(want));

                // Content-Range: bytes start-end/S (Req 5.2, 19.2).
                let want_cr = format!("bytes {}-{}/{}", start, end, total);
                prop_assert_eq!(
                    meta.content_range.as_deref(),
                    Some(want_cr.as_str()),
                    "Content-Range mismatch for {:?} against total {}",
                    spec,
                    total
                );
                prop_assert_eq!(want.content_range(), want_cr);

                // Content-Length is the (inclusive) range length.
                prop_assert_eq!(meta.content_length, Some(end - start + 1));
                prop_assert_eq!(want.length(), end - start + 1);

                // Shape-specific guarantees straight from the requirements.
                match spec {
                    // Open-ended bytes=N- spans N..=S-1 (Req 37.15).
                    RangeSpec::FromOffset(n) => {
                        prop_assert_eq!(start, n, "open-ended start must be the offset");
                        prop_assert_eq!(end, total - 1, "open-ended end must be the last byte");
                    }
                    // Suffix bytes=-N spans max(0,S-N)..=S-1 (Req 37.16).
                    RangeSpec::Suffix(n) => {
                        prop_assert_eq!(
                            start,
                            total.saturating_sub(n),
                            "suffix start must be max(0, S-N)"
                        );
                        prop_assert_eq!(end, total - 1, "suffix end must be the last byte");
                    }
                    _ => {}
                }
            }

            // -- Unsatisfiable: 416 + Content-Range bytes */S (Req 5.5) ------
            Expected::Unsatisfiable => {
                let unsat = resolved
                    .expect_err("oracle says unsatisfiable; resolve must return Err");
                prop_assert_eq!(unsat.total, total);

                let meta_err = meta
                    .expect_err("oracle says unsatisfiable; metadata must be the 416 error");
                prop_assert_eq!(meta_err.total, total);

                // Content-Range: bytes */S (Req 5.5).
                let want_cr = format!("bytes */{}", total);
                prop_assert_eq!(
                    unsat.content_range(),
                    want_cr.clone(),
                    "unsatisfiable Content-Range mismatch for {:?} against total {}",
                    spec,
                    total
                );
                prop_assert_eq!(meta_err.content_range(), want_cr);

                // Maps onto the canonical 416 taxonomy.
                prop_assert_eq!(meta_err.to_app_error().http_status().as_u16(), 416);
            }
        }
    }
}
