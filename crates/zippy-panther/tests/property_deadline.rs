//! Property-based test for deadline bounding of external operations (task 6.8).
//!
//! Feature: stream-flow, Property 53
//!
//! **Property 53: Deadline bounding of external operations**
//!
//! *For any* configured deadline `d` and any simulated operation completion
//! time `t` (measured on a fake clock), `with_deadline(d, op)` resolves with
//! the operation's result when `t ≤ d` and resolves with a timeout `AppError`
//! when `t > d`, and in all cases the wrapper resolves no later than `d` (no
//! single slow upstream can block past the deadline). As a companion invariant
//! of the same Pattern-10 budget (Req 35.4): a clamped backoff delay never
//! exceeds the deadline's `remaining()` budget.
//!
//! **Validates: Requirements 50.9, 35.4**
//!
//! The unit under test is [`stream_flow::resilience::deadline`]:
//! [`with_deadline`](stream_flow::resilience::with_deadline), the
//! [`Deadline`](stream_flow::resilience::Deadline) type, and its
//! `remaining()` / `clamp_backoff()` budget helpers.
//!
//! ## Deterministic fake clock under synchronous proptest cases
//!
//! `Deadline` is anchored on a [`tokio::time::Instant`], so under a *paused*
//! Tokio runtime the deadline timer and the simulated op's `sleep(t)` share a
//! single deterministic fake clock — no real wall-clock sleeping occurs.
//! Because `proptest` cases are synchronous, each case is driven on its own
//! per-case current-thread runtime built with `start_paused(true)`. With the
//! runtime paused and otherwise idle, Tokio auto-advances time to the next
//! pending timer, so the op's `sleep(t)` and the deadline at `d` race purely
//! on the mock timeline: whichever instant is earlier fires first, exactly as
//! `t` vs `d` dictates. This makes every case both fast and fully
//! deterministic.

use std::time::Duration;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use stream_flow::errors::ErrorCategory;
use stream_flow::resilience::{with_deadline, Deadline};
use tokio::time::Instant;

/// Bounded small durations (milliseconds) for both the deadline `d` and the
/// simulated op completion time `t`. The range deliberately includes `0`
/// (an already-due deadline / an instantly-ready op) and spans values on both
/// sides of one another so the `t < d`, `t == d`, and `t > d` regimes are all
/// exercised across cases.
fn arb_millis() -> impl Strategy<Value = u64> {
    0u64..=5_000
}

/// A per-case current-thread runtime with a **paused** clock and timers
/// enabled — the deterministic fake clock the whole property relies on.
fn paused_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("paused current-thread tokio runtime must build")
}

proptest! {
    // 256 cases (>= 100 required for a property task). Every case runs on the
    // fake clock, so this stays fast despite simulating multi-second timeouts.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 53 — deadline bounding of external
    /// operations. **Validates: Requirements 50.9, 35.4**
    ///
    /// For generated `d` (deadline) and `t` (op completion time), drive a
    /// `with_deadline(Deadline::after(d), sleep(t) -> Ok(token))` on the fake
    /// clock and assert the full contract:
    ///   * `t <= d` ⇒ resolves with the op's own `Ok(token)`,
    ///   * `t  > d` ⇒ resolves with a deadline-exceeded `AppError`
    ///     (`UpstreamUnavailable` + `deadline_exceeded` ⇒ `504`),
    ///   * in every case the wrapper resolves **no later than** `d`, and in
    ///     fact at exactly `min(t, d)` on the mock timeline.
    #[test]
    fn with_deadline_bounds_op_by_deadline(
        d_ms in arb_millis(),
        t_ms in arb_millis(),
        token in any::<u64>(),
    ) {
        let d = Duration::from_millis(d_ms);
        let t = Duration::from_millis(t_ms);

        let rt = paused_runtime();
        let result: Result<(), TestCaseError> = rt.block_on(async move {
            let deadline = Deadline::after(d);
            let started = Instant::now();

            let outcome = with_deadline(deadline, async move {
                tokio::time::sleep(t).await;
                Ok::<u64, stream_flow::errors::AppError>(token)
            })
            .await;

            // On the fake clock with nothing else to do, time advances to
            // whichever timer fires first: the op (at `t`) or the deadline
            // (at `d`). So the wrapper resolves at exactly `min(t, d)`.
            let waited = started.elapsed();
            let expected_wait = t.min(d);
            prop_assert_eq!(
                waited, expected_wait,
                "wrapper resolved at {:?}; on the fake clock it must \
                 resolve at exactly min(t, d) = {:?}",
                waited, expected_wait,
            );

            // Core "never later than d" invariant: no single slow op can block
            // past the deadline (Req 50.9).
            prop_assert!(
                waited <= d,
                "wrapper resolved at {:?}, later than the deadline {:?}",
                waited, d,
            );

            if t <= d {
                // t <= d ⇒ the op's own Ok value is propagated unchanged.
                match outcome {
                    Ok(v) => prop_assert_eq!(
                        v, token,
                        "t <= d must propagate the op's own Ok value",
                    ),
                    Err(e) => prop_assert!(
                        false,
                        "t ({:?}) <= d ({:?}) must resolve with the op result, got error: {:?}",
                        t, d, e,
                    ),
                }
            } else {
                // t > d ⇒ a deadline-exceeded AppError, distinct from a generic
                // upstream failure: UpstreamUnavailable + deadline_exceeded ⇒ 504.
                match outcome {
                    Ok(v) => prop_assert!(
                        false,
                        "t ({:?}) > d ({:?}) must time out, but resolved Ok({})",
                        t, d, v,
                    ),
                    Err(e) => {
                        prop_assert_eq!(
                            e.category, ErrorCategory::UpstreamUnavailable,
                            "a deadline elapse maps to UpstreamUnavailable",
                        );
                        prop_assert!(
                            e.deadline_exceeded,
                            "the timeout error must carry the deadline_exceeded marker",
                        );
                        prop_assert_eq!(
                            e.http_status(),
                            actix_web::http::StatusCode::GATEWAY_TIMEOUT,
                            "deadline_exceeded ⇒ 504 Gateway Timeout",
                        );
                    }
                }
            }

            Ok(())
        });
        result?;
    }

    /// Feature: stream-flow, Property 53 — companion budget invariant
    /// (Pattern 10 ↔ Pattern 2): a clamped backoff delay never exceeds the
    /// deadline's `remaining()` budget, for **any** proposed delay and at any
    /// point along the deadline's lifetime. **Validates: Requirements 35.4, 50.9**
    ///
    /// `clamp_backoff(delay)` must equal `min(delay, remaining())` and so can
    /// never overrun the budget — the guarantee the retry composition relies on
    /// so no backoff sleep sleeps past the deadline.
    #[test]
    fn clamp_backoff_never_exceeds_remaining(
        d_ms in arb_millis(),
        delay_ms in arb_millis(),
        advance_ms in arb_millis(),
    ) {
        let d = Duration::from_millis(d_ms);
        let delay = Duration::from_millis(delay_ms);
        let advance = Duration::from_millis(advance_ms);

        let rt = paused_runtime();
        let result: Result<(), TestCaseError> = rt.block_on(async move {
            let deadline = Deadline::after(d);

            // Advance the fake clock to an arbitrary point in the deadline's
            // life (possibly past it, where remaining saturates to zero).
            tokio::time::advance(advance).await;

            let remaining = deadline.remaining();
            let clamped = deadline.clamp_backoff(delay);

            // The clamp can never exceed the remaining budget — the property's
            // load-bearing invariant (no backoff sleeps past the deadline).
            prop_assert!(
                clamped <= remaining,
                "clamp_backoff({:?}) = {:?} must not exceed remaining {:?}",
                delay, clamped, remaining,
            );
            // And it is exactly min(delay, remaining()).
            prop_assert_eq!(
                clamped,
                delay.min(remaining),
                "clamp_backoff must be min(delay, remaining())",
            );

            // remaining() saturates at zero and never goes negative.
            let expected_remaining = d.saturating_sub(advance);
            prop_assert_eq!(
                remaining, expected_remaining,
                "remaining must be the saturating d - advance on the fake clock",
            );

            Ok(())
        });
        result?;
    }
}
