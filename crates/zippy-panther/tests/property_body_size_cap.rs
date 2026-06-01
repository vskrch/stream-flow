//! Property-based test for the body-size caps (`security::check_request_body_size`,
//! `security::check_response_body_size`, and the async `security::read_to_cap`
//! buffered-stream reader — task 12.2). Exercises task 12.5.
//!
//! Feature: ZippyPanther, Property 45
//!
//! **Property 45: Body-size cap boundary**
//!
//! *For any* request or buffered upstream body size, the read is accepted when
//! the size is at most the configured cap and rejected (payload-too-large /
//! abort-with-error) when it exceeds the cap.
//!
//! **Validates: Requirements 46.4, 46.5**
//!
//! Requirement 46.4: "WHEN an incoming request body exceeds the configured
//! maximum request body size, THE Stream_Flow_System SHALL reject the request
//! with a payload-too-large error."
//!
//! Requirement 46.5: "WHEN an upstream response body exceeds the configured
//! maximum response body size for buffered reads, THE Stream_Flow_System SHALL
//! abort the read and return an error."
//!
//! ## Units under test
//!
//! The body-size gate (design: Components → Security / SSRF → "body caps") is
//! three pure/total entry points, all tested directly against the real
//! [`SecurityConfig`] cap fields (no mocks):
//!
//! * [`check_request_body_size`]`(size, cfg)` — the inbound-request gate
//!   (Req 46.4).
//! * [`check_response_body_size`]`(size, cfg)` — the buffered-upstream gate
//!   for an already-known body length (Req 46.5).
//! * [`read_to_cap`]`(stream, cap)` — the streaming buffered reader that must
//!   accumulate an upstream body and **abort the moment** the running total
//!   would exceed the cap, returning a typed error and dropping the stream so
//!   no further chunks are polled (Req 46.5).
//!
//! ## How the boundary invariant is exercised
//!
//! Each of the three properties generates arbitrary `(size, cap)` pairs that
//! are *concentrated around the boundary* (`cap-2 … cap+2`) on top of a wide
//! random spread, and asserts the single decision rule:
//!
//! > the body is accepted **iff** `size <= cap`.
//!
//! The exactly-at-cap case is accepted and the first byte over is rejected.
//! For the streaming reader, an arbitrary sequence of chunks is fed through a
//! poll-counting stream and, on the reject side, the test additionally proves
//! the abort is *eager*: the number of chunks pulled equals the index of the
//! first chunk whose arrival pushes the running total over the cap (the rest
//! are never consumed). Every rejection is the canonical
//! [`ErrorCategory::PayloadTooLarge`] (HTTP `413`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use futures::StreamExt;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use zippy_panther::config::SecurityConfig;
use zippy_panther::errors::ErrorCategory;
use zippy_panther::security::{check_request_body_size, check_response_body_size, read_to_cap};

/// Arbitrary cap value, kept small so the wide random `size` spread stays cheap
/// while still covering "zero cap" and large caps.
fn arb_cap() -> impl Strategy<Value = usize> {
    0usize..=1_048_576
}

/// Generate a `(size, cap)` pair whose `size` is concentrated around the cap
/// boundary (`cap-2 … cap+2`) and also spread over a wide random range. This
/// guarantees the exactly-at-cap and first-over-cap cases are hit densely,
/// which is where the accept/reject decision flips.
fn arb_size_and_cap() -> impl Strategy<Value = (usize, usize)> {
    arb_cap().prop_flat_map(|cap| {
        let near = prop_oneof![
            // Dense coverage right around the boundary.
            5 => prop_oneof![
                Just(cap.saturating_sub(2)),
                Just(cap.saturating_sub(1)),
                Just(cap),
                Just(cap.saturating_add(1)),
                Just(cap.saturating_add(2)),
            ],
            // Wide random spread including 0 and well past the cap.
            3 => 0usize..=cap.saturating_mul(2).saturating_add(8),
        ];
        near.prop_map(move |size| (size, cap))
    })
}

/// Generate a chunk sequence plus a cap that is concentrated around the
/// stream's total size — so `read_to_cap` is repeatedly driven right across its
/// accept/abort boundary. Chunks are small (incl. empty chunks) and the
/// sequence may be empty.
fn arb_chunks_and_cap() -> impl Strategy<Value = (Vec<Vec<u8>>, usize)> {
    prop_vec(prop_vec(any::<u8>(), 0..=8), 0..=12).prop_flat_map(|chunks| {
        let total: usize = chunks.iter().map(Vec::len).sum();
        let cap = prop_oneof![
            5 => prop_oneof![
                Just(total.saturating_sub(2)),
                Just(total.saturating_sub(1)),
                Just(total),
                Just(total.saturating_add(1)),
                Just(total.saturating_add(2)),
            ],
            3 => 0usize..=total.saturating_add(4),
        ];
        cap.prop_map(move |cap| (chunks.clone(), cap))
    })
}

/// Build a per-case current-thread Tokio runtime for the async streaming arm.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime must build")
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 45 — request body-size cap boundary
    /// (Req 46.4). The inbound request is accepted iff `size <= cap`, and an
    /// over-cap body is the canonical `PayloadTooLarge` (HTTP 413).
    ///
    /// **Validates: Requirements 46.4**
    #[test]
    fn request_body_cap_boundary((size, cap) in arb_size_and_cap()) {
        let cfg = SecurityConfig {
            max_request_body_bytes: cap,
            ..SecurityConfig::default()
        };

        let result = check_request_body_size(size, &cfg);
        let accept = size <= cap;

        // The whole property: accept exactly when at-or-under the cap.
        prop_assert_eq!(
            result.is_ok(), accept,
            "request body of {} bytes vs cap {}: expected accept={}",
            size, cap, accept,
        );

        if let Err(err) = result {
            // Over-cap rejection is the canonical payload-too-large taxonomy.
            prop_assert!(size > cap, "only an over-cap body may be rejected");
            prop_assert_eq!(err.category, ErrorCategory::PayloadTooLarge);
            prop_assert_eq!(err.http_status().as_u16(), 413);
        }
    }

    /// Feature: ZippyPanther, Property 45 — buffered response body-size cap
    /// boundary for an already-known length (Req 46.5). Accepted iff
    /// `size <= cap`; over-cap is `PayloadTooLarge` (HTTP 413).
    ///
    /// **Validates: Requirements 46.5**
    #[test]
    fn response_body_cap_boundary((size, cap) in arb_size_and_cap()) {
        let cfg = SecurityConfig {
            max_response_body_bytes: cap,
            ..SecurityConfig::default()
        };

        let result = check_response_body_size(size, &cfg);
        let accept = size <= cap;

        prop_assert_eq!(
            result.is_ok(), accept,
            "response body of {} bytes vs cap {}: expected accept={}",
            size, cap, accept,
        );

        if let Err(err) = result {
            prop_assert!(size > cap, "only an over-cap body may be rejected");
            prop_assert_eq!(err.category, ErrorCategory::PayloadTooLarge);
            prop_assert_eq!(err.http_status().as_u16(), 413);
        }
    }
}

proptest! {
    // 128 cases (>= 100 required). Each case drives the async reader on a
    // per-case current-thread runtime, so the count is kept modest.
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Feature: ZippyPanther, Property 45 — streaming buffered-read cap boundary
    /// and eager abort (Req 46.5). `read_to_cap` accepts the body iff the total
    /// size is `<= cap`; otherwise it aborts the read with `PayloadTooLarge`
    /// the moment the running total first exceeds the cap, without consuming
    /// any chunk beyond the overflow point.
    ///
    /// **Validates: Requirements 46.5**
    #[test]
    fn read_to_cap_boundary_and_eager_abort((chunks, cap) in arb_chunks_and_cap()) {
        let rt = runtime();
        let outcome: Result<(), TestCaseError> = rt.block_on(async {
            let total: usize = chunks.iter().map(Vec::len).sum();
            let accept = total <= cap;

            // Expected number of chunks pulled before the reader returns. The
            // implementation checks `running + chunk.len() > cap` *after*
            // pulling each chunk, so the overflow chunk is pulled (counted) but
            // not buffered. When the body fits, every chunk is pulled. This
            // single walk yields the expected poll count for both arms.
            let mut running = 0usize;
            let mut expected_polls = 0usize;
            for chunk in &chunks {
                expected_polls += 1;
                if running.saturating_add(chunk.len()) > cap {
                    break; // overflow chunk: pulled, then the read aborts.
                }
                running += chunk.len();
            }

            // A poll-counting stream: the closure runs once per chunk actually
            // pulled, so the counter measures exactly how far the reader read.
            let polled = Arc::new(AtomicUsize::new(0));
            let counter = polled.clone();
            let items = chunks.clone();
            let stream = futures::stream::iter(items).map(move |chunk| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok::<Bytes, std::io::Error>(Bytes::from(chunk))
            });

            let result = read_to_cap(stream, cap).await;

            // -- The boundary decision: accept iff total <= cap --------------
            prop_assert_eq!(
                result.is_ok(), accept,
                "stream total {} bytes vs cap {}: expected accept={}",
                total, cap, accept,
            );

            // -- The reader pulls exactly as far as the rule requires --------
            // On accept: every chunk (and no more). On reject: up to and
            // including the first overflow chunk, never the rest.
            prop_assert_eq!(
                polled.load(Ordering::SeqCst), expected_polls,
                "reader must pull exactly {} chunk(s) (total {}, cap {})",
                expected_polls, total, cap,
            );

            match result {
                Ok(body) => {
                    // The fully buffered body equals the concatenated input.
                    let expected: Vec<u8> = chunks.concat();
                    prop_assert_eq!(body, expected, "buffered body must equal the source bytes");
                }
                Err(err) => {
                    prop_assert!(total > cap, "only an over-cap stream may be rejected");
                    prop_assert_eq!(err.category, ErrorCategory::PayloadTooLarge);
                    prop_assert_eq!(err.http_status().as_u16(), 413);
                    // Eager abort is already proven by the exact poll-count
                    // equality above (the reader stops at the first overflow
                    // chunk); the running total at that point must exceed cap.
                    prop_assert!(
                        expected_polls >= 1,
                        "an over-cap stream must have pulled at least one chunk",
                    );
                }
            }

            Ok(())
        });
        outcome?;
    }
}
