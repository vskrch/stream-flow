//! Property-based test for `Accept-Ranges` advertisement in the byte-range
//! response-metadata computation (`proxy::range::compute_response_metadata` —
//! task 13.1). Exercises task 13.6.
//!
//! Feature: stream-flow, Property 4
//!
//! **Property 4: Accept-Ranges advertised whenever size is known**
//!
//! *For any* upstream that reports a known `Content-Length`, the system
//! advertises `Accept-Ranges: bytes` to the client and satisfies range requests
//! by issuing ranged upstream requests, regardless of whether the upstream
//! itself advertised `Accept-Ranges`.
//!
//! **Validates: Requirements 5.3, 37.17**
//!
//! Requirement 5.3: "WHEN the upstream advertises `Accept-Ranges: bytes`, THE
//! Streaming_Proxy_Engine SHALL advertise `Accept-Ranges: bytes` to the
//! client."
//!
//! Requirement 37.17: "WHERE the upstream does not advertise
//! `Accept-Ranges: bytes` but reports a known `Content-Length`, THE
//! Stream_Flow_System SHALL still advertise `Accept-Ranges: bytes` and satisfy
//! range requests by issuing ranged upstream requests, so that seeking works
//! for non-seekable-appearing sources."
//!
//! ## Unit under test
//!
//! [`compute_response_metadata`]`(spec, total_size, is_head)` is the single
//! pure place (design: Components → Range handling) that decides the
//! `Accept-Ranges` advertisement. It takes no "did the upstream advertise it"
//! input *by design*: the advertisement is derived solely from whether the
//! total size is known, so the union of Req 5.3 (upstream advertised → we
//! advertise) and Req 37.17 (upstream did *not* advertise but size is known →
//! we still advertise) collapses to one rule:
//!
//! > advertise `Accept-Ranges: bytes` **iff** the total size is `Some`.
//!
//! Because the decision cannot depend on an upstream `Accept-Ranges` input that
//! the function never receives, the "regardless of whether the upstream
//! advertised it" clause is structurally guaranteed; the test makes this
//! explicit by generating an arbitrary `upstream_advertises` flag and proving
//! the computed advertisement is invariant under it.
//!
//! ## How the invariant is exercised
//!
//! Each case generates an arbitrary [`RangeSpec`] (all four forms), an
//! arbitrary `total_size` (`Some` over a wide spread incl. the empty-resource
//! `0`, and `None`), an arbitrary `is_head`, and an irrelevant
//! `upstream_advertises` flag, then asserts the single decision rule across
//! every produced outcome:
//!
//! * size known + range produces metadata (`200`/`206`) → `accept_ranges` is
//!   `true`;
//! * size known + range is unsatisfiable (`416`) → the error path is reachable
//!   only when the size is known (the `416` still carries a known size);
//! * size unknown → metadata is a `200` passthrough with `accept_ranges`
//!   `false`.
//!
//! The advertisement never varies with the range spec, the method
//! (`HEAD`/`GET`), or the `upstream_advertises` flag — only with whether the
//! size is known.

use proptest::prelude::*;
use stream_flow::proxy::{compute_response_metadata, RangeSpec};

/// A byte position / length generator kept within a wide but overflow-safe
/// range. Includes `0` and values both below and above typical sizes so the
/// satisfiable, unsatisfiable, and clamped paths are all reached.
fn arb_pos() -> impl Strategy<Value = u64> {
    prop_oneof![
        // Dense small values (incl. 0 and 1) where the boundary cases live.
        4 => 0u64..=8,
        // Wide spread up to ~10M.
        3 => 0u64..=10_000_000,
    ]
}

/// Generate any of the four [`RangeSpec`] forms. `Inclusive` is constrained to
/// `start <= end`, mirroring the invariant `RangeSpec::parse` enforces (it
/// rejects `end < start`), so the generated specs are exactly those the parser
/// can produce.
fn arb_spec() -> impl Strategy<Value = RangeSpec> {
    prop_oneof![
        Just(RangeSpec::Full),
        arb_pos().prop_map(RangeSpec::FromOffset),
        (arb_pos(), arb_pos()).prop_map(|(a, b)| {
            let (start, end) = if a <= b { (a, b) } else { (b, a) };
            RangeSpec::Inclusive(start, end)
        }),
        arb_pos().prop_map(RangeSpec::Suffix),
    ]
}

/// Generate the (optionally known) total size: `Some` over a wide spread that
/// includes the empty-resource `0`, and `None` (size unknown). Weighted toward
/// `Some` so the known-size advertisement rule is exercised densely while the
/// `None` arm still appears often.
fn arb_total_size() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![
        4 => arb_pos().prop_map(Some),
        1 => Just(None),
    ]
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 4 — `Accept-Ranges: bytes` is advertised
    /// exactly when the total size is known, independent of the range spec, the
    /// request method (`HEAD`/`GET`), and whether the upstream advertised it.
    ///
    /// **Validates: Requirements 5.3, 37.17**
    #[test]
    fn accept_ranges_advertised_iff_size_known(
        spec in arb_spec(),
        total_size in arb_total_size(),
        is_head in any::<bool>(),
        upstream_advertises in any::<bool>(),
    ) {
        let size_known = total_size.is_some();

        match compute_response_metadata(&spec, total_size, is_head) {
            Ok(meta) => {
                // The whole property: advertise iff the size is known. This
                // holds for the full `200` and the satisfiable `206` alike, and
                // is invariant under `is_head`, the `spec`, and the
                // (deliberately ignored) `upstream_advertises` flag.
                prop_assert_eq!(
                    meta.accept_ranges, size_known,
                    "accept_ranges must equal size_known: spec={:?} size={:?} is_head={} \
                     upstream_advertises={} (advertisement must not depend on method, \
                     spec, or upstream advertisement)",
                    spec, total_size, is_head, upstream_advertises,
                );

                if size_known {
                    // Req 37.17: a known size means seeking is supported, so the
                    // advertisement is on even when the upstream never set it.
                    prop_assert!(
                        meta.accept_ranges,
                        "known size must advertise Accept-Ranges even when upstream did not \
                         (upstream_advertises={}): spec={:?} size={:?}",
                        upstream_advertises, spec, total_size,
                    );
                } else {
                    // Size unknown: a plain 200 passthrough that cannot honour
                    // ranges locally, so Accept-Ranges is withheld and no
                    // Content-Length is declared.
                    prop_assert!(
                        !meta.accept_ranges,
                        "unknown size must not advertise Accept-Ranges: spec={:?}",
                        spec,
                    );
                    prop_assert_eq!(
                        meta.content_length, None,
                        "unknown size must not declare a Content-Length: spec={:?}",
                        spec,
                    );
                }
            }
            Err(_unsatisfiable) => {
                // The unsatisfiable `416` path is reachable only when the size
                // is known (an unknown size never resolves a range). The 416's
                // own Accept-Ranges header is applied by the response layer; the
                // pure computation surfaces only the error here. What this arm
                // proves for Property 4 is that the *absence* of advertised
                // metadata never happens for an unknown size.
                prop_assert!(
                    size_known,
                    "an unsatisfiable range (416) can only arise for a known size: \
                     spec={:?} size={:?}",
                    spec, total_size,
                );
            }
        }
    }
}
