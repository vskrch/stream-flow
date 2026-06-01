//! Property-based test for the adaptive + jitter buffer's sizing and bounded
//! peak-memory invariants (`proxy::buffer::AdaptiveJitterBuffer` — task 13.2).
//! Exercises task 13.7.
//!
//! Feature: ZippyPanther, Property 5
//!
//! **Property 5: Adaptive buffer sizing**
//!
//! *For any* delivered byte offset `o`, the active buffer size equals the
//! configured initial size while `o < initial_window` (default 2 MiB) and
//! equals the configured steady-state size thereafter; the buffer's peak
//! memory is bounded by the larger configured size regardless of total stream
//! length.
//!
//! **Validates: Requirements 37.3, 5.7, 35.1**
//!
//! Requirement 37.3: the read/refill chunk size is the larger *initial* size
//! while the delivered playback offset is below the *initial window* (so
//! playback starts smoothly) and the smaller *steady* size for the remainder.
//!
//! Requirement 5.7 / 35.1: the streaming relay holds at most one bounded
//! buffer in memory — peak memory is independent of the total stream size, so
//! arbitrarily long streams fit the 512 MB-VPS constraint.
//!
//! ## Unit under test
//!
//! [`AdaptiveJitterBuffer`] (design: Components → Adaptive + jitter buffer) is
//! the bounded ring between the upstream reader ([`push`](AdaptiveJitterBuffer::push))
//! and the client writer ([`pull`](AdaptiveJitterBuffer::pull)). Its capacity
//! is `max(initial_size, steady_size)` and its refill decision is driven by the
//! delivered (drained) offset. Both properties below run against the real type
//! with no mocks.
//!
//! ## How the invariants are exercised
//!
//! * `adaptive_sizing_and_bounded_memory_under_arbitrary_io` drives an
//!   arbitrary interleaving of `push`/`pull` operations over arbitrary
//!   `(initial_size, steady_size, initial_window)` triples and asserts, **at
//!   every step**, the two invariants: (a) `active_size()` equals the initial
//!   size iff the delivered offset is below the window and the steady size
//!   otherwise, and (b) the buffered byte count never exceeds the capacity
//!   (`max(initial, steady)`) no matter how many bytes have flowed through. The
//!   chunk sizes are deliberately allowed to exceed the capacity so the
//!   backpressure/bounding path is hit, and the long random op sequences drive
//!   the delivered offset across the window boundary in both regimes.
//!
//! * `active_size_matches_window_boundary_for_any_offset` covers the "for any
//!   delivered byte offset `o`" clause exhaustively at the decision boundary by
//!   probing [`size_at`](AdaptiveJitterBuffer::size_at) with arbitrary offsets
//!   plus the exact boundary values (`window-1`, `window`, `window+1`, `0`,
//!   `u64::MAX`) — including offsets that no finite stream could reach.

use bytes::Bytes;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use zippy_panther::proxy::AdaptiveJitterBuffer;

/// One step of the reader/writer interleaving: the reader pushes a chunk of
/// `n` bytes, or the writer pulls up to `n` bytes.
#[derive(Debug, Clone)]
enum Op {
    Push(usize),
    Pull(usize),
}

/// Arbitrary push/pull op. Chunk sizes range up to `4096` so a single push can
/// exceed small capacities — exercising the backpressure (remainder) path that
/// enforces the peak-memory bound.
fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0usize..=4096).prop_map(Op::Push),
        (0usize..=4096).prop_map(Op::Pull),
    ]
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 5 — adaptive sizing + bounded peak memory
    /// under an arbitrary reader/writer interleaving (Req 37.3, 5.7, 35.1).
    ///
    /// At every step of an arbitrary push/pull sequence over arbitrary sizes
    /// and windows:
    ///   * the active refill size is the initial size while the delivered
    ///     offset is below the window and the steady size at/after it, and
    ///   * the buffered byte count never exceeds the capacity
    ///     (`max(initial, steady)`), regardless of how many bytes are streamed.
    ///
    /// **Validates: Requirements 37.3, 5.7, 35.1**
    #[test]
    fn adaptive_sizing_and_bounded_memory_under_arbitrary_io(
        initial_size in 1usize..=4096,
        steady_size in 1usize..=4096,
        initial_window in 0u64..=16_384,
        ops in prop_vec(arb_op(), 1..=200),
    ) {
        let capacity = initial_size.max(steady_size);
        let mut buf = AdaptiveJitterBuffer::new(initial_size, steady_size, initial_window);

        // Capacity is the larger configured size and never changes (Req 35.1, 5.7).
        prop_assert_eq!(
            buf.capacity(), capacity,
            "capacity must be max(initial {}, steady {})",
            initial_size, steady_size,
        );

        // Invariants must hold on the fresh (empty, offset-0) buffer too.
        check_invariants(&buf, initial_size, steady_size, initial_window, capacity)?;

        // The most bytes ever simultaneously buffered — must stay <= capacity.
        let mut peak = buf.buffered();
        // Total bytes streamed through, to prove the bound is independent of it.
        let mut total_pushed: u64 = 0;

        for op in ops {
            match op {
                Op::Push(n) => {
                    let free_before = buf.free_space();
                    let buffered_before = buf.buffered();
                    let delivered_before = buf.delivered_offset();

                    let remainder = buf.push(Bytes::from(vec![0u8; n]));

                    // push accepts exactly what fits; the rest is handed back.
                    let accepted = n - remainder.len();
                    prop_assert_eq!(
                        accepted, n.min(free_before),
                        "push must accept min(chunk {}, free {})",
                        n, free_before,
                    );
                    prop_assert_eq!(
                        buf.buffered(), buffered_before + accepted,
                        "buffered must grow by exactly the accepted bytes",
                    );
                    // push never advances the delivered (playback) offset.
                    prop_assert_eq!(
                        buf.delivered_offset(), delivered_before,
                        "push must not change the delivered offset",
                    );
                    total_pushed += accepted as u64;
                }
                Op::Pull(n) => {
                    let buffered_before = buf.buffered();
                    let delivered_before = buf.delivered_offset();

                    let got = buf.pull(n);

                    // pull yields min(request, buffered), FIFO.
                    prop_assert_eq!(
                        got.len(), n.min(buffered_before),
                        "pull must yield min(request {}, buffered {})",
                        n, buffered_before,
                    );
                    prop_assert_eq!(
                        buf.buffered(), buffered_before - got.len(),
                        "buffered must shrink by exactly the pulled bytes",
                    );
                    // Draining advances the playback offset by the bytes pulled.
                    prop_assert_eq!(
                        buf.delivered_offset(), delivered_before + got.len() as u64,
                        "delivered offset must advance by the pulled bytes",
                    );
                }
            }

            peak = peak.max(buf.buffered());
            check_invariants(&buf, initial_size, steady_size, initial_window, capacity)?;
        }

        // Peak memory is bounded by the larger configured size no matter how
        // many bytes flowed through (Req 5.7, 35.1).
        prop_assert!(
            peak <= capacity,
            "peak buffered {} exceeded capacity {} (after streaming {} bytes)",
            peak, capacity, total_pushed,
        );
    }

    /// Feature: ZippyPanther, Property 5 — the "for any delivered byte offset
    /// `o`" sizing decision, probed exhaustively at the window boundary
    /// (Req 37.3).
    ///
    /// `size_at(o)` is the initial size iff `o < initial_window` and the steady
    /// size otherwise, for arbitrary offsets and the exact boundary values —
    /// including offsets no finite stream could reach.
    ///
    /// **Validates: Requirements 37.3**
    #[test]
    fn active_size_matches_window_boundary_for_any_offset(
        initial_size in 1usize..=4096,
        steady_size in 1usize..=4096,
        initial_window in 0u64..=u64::MAX,
        random_offsets in prop_vec(any::<u64>(), 0..=8),
    ) {
        let buf = AdaptiveJitterBuffer::new(initial_size, steady_size, initial_window);

        // Arbitrary offsets plus the exact decision boundary values.
        let mut offsets = random_offsets;
        offsets.extend_from_slice(&[
            0,
            initial_window.saturating_sub(2),
            initial_window.saturating_sub(1),
            initial_window,
            initial_window.saturating_add(1),
            initial_window.saturating_add(2),
            u64::MAX,
        ]);

        for o in offsets {
            let expected = if o < initial_window { initial_size } else { steady_size };
            prop_assert_eq!(
                buf.size_at(o), expected,
                "size_at({}) must be {} (window {}, initial {}, steady {})",
                o, expected, initial_window, initial_size, steady_size,
            );
        }
    }
}

/// Assert the two Property-5 invariants for the buffer's *current* state:
///   1. the active refill size matches the window decision for the current
///      delivered offset, and is consistent with `size_at`, and
///   2. the buffered/free accounting stays within the capacity bound and the
///      refill quota can never push past capacity.
fn check_invariants(
    buf: &AdaptiveJitterBuffer,
    initial_size: usize,
    steady_size: usize,
    initial_window: u64,
    capacity: usize,
) -> Result<(), TestCaseError> {
    let offset = buf.delivered_offset();

    // -- Adaptive sizing (Req 37.3) -----------------------------------------
    let expected_size = if offset < initial_window {
        initial_size
    } else {
        steady_size
    };
    prop_assert_eq!(
        buf.active_size(),
        expected_size,
        "active_size at offset {} (window {}) must be {}",
        offset,
        initial_window,
        expected_size,
    );
    prop_assert_eq!(
        buf.active_size(),
        buf.size_at(offset),
        "active_size must equal size_at(delivered_offset)",
    );

    // -- Bounded peak memory (Req 5.7, 35.1) --------------------------------
    prop_assert!(
        buf.buffered() <= capacity,
        "buffered {} exceeded capacity {} at offset {}",
        buf.buffered(),
        capacity,
        offset,
    );
    prop_assert_eq!(
        buf.free_space(),
        capacity - buf.buffered(),
        "free_space must equal capacity - buffered",
    );

    // A refill is the active size capped by free space, so applying it can
    // never push the buffer past capacity (the bounding guarantee).
    prop_assert_eq!(
        buf.refill_quota(),
        buf.active_size().min(buf.free_space()),
        "refill_quota must be active_size capped by free_space",
    );
    prop_assert!(
        buf.buffered() + buf.refill_quota() <= capacity,
        "buffered {} + refill_quota {} must stay within capacity {}",
        buf.buffered(),
        buf.refill_quota(),
        capacity,
    );

    Ok(())
}
