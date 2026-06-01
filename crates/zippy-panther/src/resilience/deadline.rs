//! Request-scoped deadlines & timeout budgets (`resilience::deadline`) —
//! Req 50.9, 35.4.
//!
//! A [`Deadline`] is the **outermost** bound of the resilience stack (design:
//! Resilience → Pattern 10 "Timeout Budgets & Deadline Propagation"): nothing
//! runs past it. A request-scoped deadline is created once
//! ([`Deadline::after`], e.g. the 2 s Stremio start budget) and threaded
//! through resolution → store calls → link-gen → fallback so the whole
//! control-plane path stays inside the budget and **never hangs** (Req 50.9).
//!
//! [`with_deadline`] wraps an external operation so it resolves with the op's
//! result when the op finishes within the budget, and otherwise resolves —
//! **never later than the deadline** — with a deadline-exceeded
//! [`AppError`](crate::errors::AppError) built via
//! [`AppError::into_deadline_exceeded`](crate::errors::AppError::into_deadline_exceeded)
//! (`UpstreamUnavailable` + `deadline_exceeded` ⇒ `504`, so the elapse is
//! observable and distinct from a generic upstream failure — Req 50.14).
//!
//! ## Clock choice (testability)
//!
//! [`Deadline`] is anchored on a [`tokio::time::Instant`], **not** a
//! [`std::time::Instant`]. This is deliberate: under a paused test runtime
//! (`#[tokio::test(start_paused = true)]` / [`tokio::time::pause`] +
//! [`tokio::time::advance`]) the tokio clock is a deterministic "fake clock",
//! so [`Deadline::remaining`] and [`with_deadline`]'s timeout fire on the same
//! mock timeline — the unit tests below need no real sleeping.
//!
//! ## Streaming vs control-plane (critical — design Pattern 10)
//!
//! Only **control-plane** calls (link resolution, store metadata, manifest
//! fetches, id-map, …) carry a finite total deadline. **Streaming bodies** must
//! have **no** total deadline (a long movie legitimately streams for hours) —
//! they are protected by stall-detection → reconnect-with-resume, not a
//! wall-clock cap. [`TimeoutBudget::total`] is `Some` for control-plane and
//! `None` for stream bodies; [`TimeoutBudget::deadline`] yields a [`Deadline`]
//! only for the former.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use crate::errors::AppError;

/// The coherent per-call **timeout hierarchy** for a control-plane operation
/// (design: Pattern 10).
///
/// The per-phase timeouts (`connect`/`tls`/`headers`/`body_read_idle`) come
/// from `ProxyConfig` (Req 35.4) and bound each upstream call so a single dead
/// socket fails fast well inside the budget. `total` is the overall deadline:
/// `Some(_)` for control-plane paths (which must complete or fail fast) and
/// `None` for streaming bodies (which must never be killed by a wall-clock cap
/// — Req 37.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeoutBudget {
    /// TCP connect timeout (e.g. `2s`).
    pub connect: Duration,
    /// TLS handshake timeout (e.g. `2s`).
    pub tls: Duration,
    /// Time-to-headers / response-start timeout (e.g. `3s`).
    pub headers: Duration,
    /// Max gap between body chunks (control-plane reads only).
    pub body_read_idle: Duration,
    /// Overall deadline: `Some` for control-plane, `None` for stream bodies.
    pub total: Option<Duration>,
}

impl TimeoutBudget {
    /// A control-plane budget with a finite `total` deadline (design's example
    /// phase values: connect/tls `2s`, headers `3s`).
    pub fn control_plane(total: Duration) -> Self {
        Self {
            connect: Duration::from_secs(2),
            tls: Duration::from_secs(2),
            headers: Duration::from_secs(3),
            body_read_idle: Duration::from_secs(10),
            total: Some(total),
        }
    }

    /// A streaming-body budget: per-phase timeouts still apply, but there is
    /// **no** total deadline (`total: None`) so a long media relay is never
    /// killed by a wall-clock cap (Req 37.5).
    pub fn streaming() -> Self {
        Self {
            connect: Duration::from_secs(2),
            tls: Duration::from_secs(2),
            headers: Duration::from_secs(3),
            body_read_idle: Duration::from_secs(30),
            total: None,
        }
    }

    /// The request-scoped [`Deadline`] for this budget: `Some` iff a finite
    /// `total` is configured (i.e. a control-plane path). Streaming bodies
    /// yield `None` and are therefore never deadline-bounded.
    pub fn deadline(&self) -> Option<Deadline> {
        self.total.map(Deadline::after)
    }
}

/// A request-scoped deadline: a single point in time past which nothing should
/// run (design: Pattern 10).
///
/// Anchored on a [`tokio::time::Instant`] so it shares the runtime clock with
/// [`with_deadline`]'s timeout (and is deterministic under a paused test
/// runtime). `Copy`, so it threads cheaply through a request's call graph.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    /// A deadline `d` from now (e.g. `Deadline::after(start_budget)` with the
    /// default 2 s Stremio start budget — Req 37.1).
    pub fn after(d: Duration) -> Self {
        Self {
            at: Instant::now() + d,
        }
    }

    /// A deadline anchored at an explicit instant (e.g. to derive a child
    /// deadline that can only ever be earlier than a parent's).
    pub fn at(at: Instant) -> Self {
        Self { at }
    }

    /// The instant this deadline elapses.
    pub fn instant(&self) -> Instant {
        self.at
    }

    /// Time left until the deadline, saturating to [`Duration::ZERO`] once
    /// elapsed (never negative).
    pub fn remaining(&self) -> Duration {
        self.at.saturating_duration_since(Instant::now())
    }

    /// Whether the deadline has elapsed (`remaining() == 0`).
    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }

    /// Clamp a proposed backoff `delay` so a sleep can **never exceed**
    /// [`remaining`](Self::remaining): `min(delay, remaining())`.
    ///
    /// Used by the retry composition (`with_retry`, task 6.2) so that no
    /// backoff sleep overruns the request budget (design: Pattern 2 ↔ Pattern
    /// 10 — "no backoff sleep may exceed `remaining()`").
    pub fn clamp_backoff(&self, delay: Duration) -> Duration {
        delay.min(self.remaining())
    }

    /// Whether a full backoff `delay` fits strictly inside the remaining
    /// budget (`delay < remaining()`).
    ///
    /// Mirrors the retry-loop guard `if deadline.remaining() <= delay { fail
    /// fast }`: a backoff is permitted only when it would complete before the
    /// deadline, otherwise the caller fails fast with a deadline-exceeded
    /// error rather than sleeping past the budget.
    pub fn permits_backoff(&self, delay: Duration) -> bool {
        delay < self.remaining()
    }

    /// Sleep for a backoff `delay` clamped to the remaining budget, so the
    /// sleep is guaranteed to return no later than the deadline.
    pub async fn sleep_backoff(&self, delay: Duration) {
        tokio::time::sleep(self.clamp_backoff(delay)).await;
    }
}

/// Bound an external operation by `deadline` (design: Pattern 10; Req 50.9,
/// 35.4).
///
/// Resolves with `op`'s result when `op` completes at or before the deadline;
/// otherwise resolves — **never later than the deadline** — with a
/// deadline-exceeded [`AppError`] (`UpstreamUnavailable` + `deadline_exceeded`
/// ⇒ `504`, via
/// [`into_deadline_exceeded`](crate::errors::AppError::into_deadline_exceeded)).
/// A genuine error returned by `op` within the budget is propagated unchanged
/// — only the timeout is mapped.
///
/// Implemented with [`tokio::time::timeout_at`] anchored on the deadline's
/// instant, so the wall-clock guarantee holds exactly at `deadline.instant()`.
pub async fn with_deadline<T, F>(deadline: Deadline, op: F) -> Result<T, AppError>
where
    F: Future<Output = Result<T, AppError>>,
{
    match tokio::time::timeout_at(deadline.instant(), op).await {
        // `op` finished within the budget — propagate its own Result verbatim.
        Ok(result) => result,
        // The deadline elapsed first — map to the canonical deadline error.
        Err(_elapsed) => Err(deadline_exceeded_error()),
    }
}

/// Convenience wrapper: bound `op` by a fresh `Deadline::after(dur)`.
///
/// Equivalent to `with_deadline(Deadline::after(dur), op)`; handy where the
/// caller has a duration rather than a pre-threaded request deadline.
pub async fn with_timeout<T, F>(dur: Duration, op: F) -> Result<T, AppError>
where
    F: Future<Output = Result<T, AppError>>,
{
    with_deadline(Deadline::after(dur), op).await
}

/// The canonical error for an elapsed control-plane deadline (Req 50.9,
/// 35.4): an `UpstreamUnavailable` carrying the `deadline_exceeded` marker
/// (⇒ `504`), built via
/// [`into_deadline_exceeded`](crate::errors::AppError::into_deadline_exceeded).
fn deadline_exceeded_error() -> AppError {
    AppError::upstream_unavailable("operation exceeded its deadline").into_deadline_exceeded()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use actix_web::http::StatusCode;

    // All timing tests run on a *paused* runtime: the tokio clock is a
    // deterministic fake clock, auto-advancing to the next timer when the
    // runtime is otherwise idle, so nothing sleeps in real time.

    // -- with_deadline: completes within budget ----------------------------

    /// `t <= d`: an op that finishes before the deadline resolves with its own
    /// `Ok` value (Req 50.9).
    #[tokio::test(start_paused = true)]
    async fn resolves_with_op_result_when_op_completes_before_deadline() {
        let deadline = Deadline::after(Duration::from_secs(2));
        let result = with_deadline(deadline, async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok::<u32, AppError>(42)
        })
        .await;
        assert_eq!(result.unwrap(), 42);
    }

    /// An op that finishes within budget but returns its own `Err` has that
    /// error propagated **unchanged** — only a timeout is remapped, never a
    /// genuine in-budget failure.
    #[tokio::test(start_paused = true)]
    async fn propagates_op_error_unchanged_when_within_budget() {
        let deadline = Deadline::after(Duration::from_secs(2));
        let result: Result<(), AppError> = with_deadline(deadline, async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Err(AppError::not_found("genuine miss"))
        })
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.category, ErrorCategory::NotFound);
        assert!(
            !err.deadline_exceeded,
            "in-budget error must not be remapped"
        );
    }

    /// An op ready immediately resolves immediately, even with budget to spare.
    #[tokio::test(start_paused = true)]
    async fn resolves_immediately_when_op_is_ready() {
        let deadline = Deadline::after(Duration::from_secs(5));
        let result = with_deadline(deadline, async { Ok::<_, AppError>("done") }).await;
        assert_eq!(result.unwrap(), "done");
    }

    // -- with_deadline: exceeds budget -------------------------------------

    /// `t > d`: an op that would take longer than the deadline resolves with a
    /// deadline-exceeded `AppError` — `UpstreamUnavailable` + `deadline_exceeded`
    /// ⇒ `504` (Req 50.9, 35.4).
    #[tokio::test(start_paused = true)]
    async fn returns_deadline_exceeded_error_when_op_exceeds_deadline() {
        let deadline = Deadline::after(Duration::from_secs(1));
        let result: Result<u32, AppError> = with_deadline(deadline, async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(7)
        })
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(
            err.deadline_exceeded,
            "must carry the deadline_exceeded marker"
        );
        assert_eq!(err.http_status(), StatusCode::GATEWAY_TIMEOUT);
    }

    /// Never resolves later than `d`: a 10 s op under a 1 s deadline returns at
    /// the deadline (≈1 s on the fake clock), not at the op's completion.
    #[tokio::test(start_paused = true)]
    async fn never_resolves_later_than_the_deadline() {
        let started = Instant::now();
        let deadline = Deadline::after(Duration::from_secs(1));
        let result: Result<(), AppError> = with_deadline(deadline, async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        })
        .await;
        let waited = started.elapsed();
        assert!(result.is_err());
        // Resolved at the deadline (1s), well before the op's 10s completion.
        assert!(
            waited >= Duration::from_secs(1) && waited < Duration::from_secs(2),
            "resolved after {waited:?}; expected ~1s (the deadline), not the op's 10s",
        );
    }

    /// An already-expired deadline fails fast with the deadline error rather
    /// than running the (not-immediately-ready) op.
    #[tokio::test(start_paused = true)]
    async fn already_expired_deadline_fails_fast() {
        let deadline = Deadline::after(Duration::ZERO);
        // Advance past the deadline so it is firmly elapsed.
        tokio::time::advance(Duration::from_millis(10)).await;
        assert!(deadline.expired());

        let result: Result<(), AppError> = with_deadline(deadline, async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        })
        .await;
        assert!(result.unwrap_err().deadline_exceeded);
    }

    // -- remaining() / expired() under the fake clock ----------------------

    /// `remaining()` shrinks as the clock advances and saturates at zero (never
    /// goes negative); `expired()` flips exactly when the budget is spent.
    #[tokio::test(start_paused = true)]
    async fn remaining_shrinks_with_advance_and_saturates_at_zero() {
        let deadline = Deadline::after(Duration::from_secs(10));
        assert_eq!(deadline.remaining(), Duration::from_secs(10));
        assert!(!deadline.expired());

        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(deadline.remaining(), Duration::from_secs(6));
        assert!(!deadline.expired());

        // Advance past the deadline — remaining saturates at zero.
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(deadline.remaining(), Duration::ZERO);
        assert!(deadline.expired());
    }

    // -- backoff-never-exceeds-remaining helper ----------------------------

    /// A clamped backoff sleep **never exceeds** `remaining()`: a delay longer
    /// than the budget is clamped down, a shorter one is unchanged.
    #[tokio::test(start_paused = true)]
    async fn clamp_backoff_never_exceeds_remaining() {
        let deadline = Deadline::after(Duration::from_secs(2));

        // Delay longer than remaining → clamped to remaining.
        assert_eq!(
            deadline.clamp_backoff(Duration::from_secs(10)),
            Duration::from_secs(2),
        );
        // Delay shorter than remaining → unchanged.
        assert_eq!(
            deadline.clamp_backoff(Duration::from_millis(500)),
            Duration::from_millis(500),
        );

        // After time passes, the clamp tracks the smaller remaining budget.
        tokio::time::advance(Duration::from_millis(1500)).await;
        let clamped = deadline.clamp_backoff(Duration::from_secs(10));
        assert!(
            clamped <= deadline.remaining() && clamped == Duration::from_millis(500),
            "clamp {clamped:?} must not exceed remaining {:?}",
            deadline.remaining(),
        );
    }

    /// `permits_backoff` is true iff the full delay fits strictly inside the
    /// remaining budget — the guard the retry loop uses to decide fail-fast vs
    /// sleep-then-retry.
    #[tokio::test(start_paused = true)]
    async fn permits_backoff_reflects_remaining_budget() {
        let deadline = Deadline::after(Duration::from_secs(1));
        assert!(deadline.permits_backoff(Duration::from_millis(500)));
        assert!(!deadline.permits_backoff(Duration::from_secs(1)));
        assert!(!deadline.permits_backoff(Duration::from_secs(5)));

        // Once expired, no backoff is permitted.
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(deadline.expired());
        assert!(!deadline.permits_backoff(Duration::ZERO));
    }

    /// A clamped backoff sleep returns no later than the deadline (≤ the
    /// remaining budget), on the fake clock.
    #[tokio::test(start_paused = true)]
    async fn sleep_backoff_returns_within_remaining() {
        let started = Instant::now();
        let deadline = Deadline::after(Duration::from_secs(1));
        // Ask for a 10s backoff; it must be clamped to the 1s budget.
        deadline.sleep_backoff(Duration::from_secs(10)).await;
        let waited = started.elapsed();
        assert!(
            waited <= Duration::from_secs(1),
            "sleep waited {waited:?}; must not exceed the 1s budget",
        );
    }

    // -- TimeoutBudget -----------------------------------------------------

    /// A control-plane budget yields a finite deadline; a streaming budget
    /// never does (streams must not be wall-clock capped — Req 37.5).
    #[tokio::test(start_paused = true)]
    async fn timeout_budget_deadline_is_some_only_for_control_plane() {
        let control = TimeoutBudget::control_plane(Duration::from_secs(2));
        assert_eq!(control.total, Some(Duration::from_secs(2)));
        let deadline = control.deadline().expect("control-plane has a deadline");
        assert!(deadline.remaining() <= Duration::from_secs(2));

        let streaming = TimeoutBudget::streaming();
        assert_eq!(streaming.total, None);
        assert!(
            streaming.deadline().is_none(),
            "streaming bodies must not carry a total deadline",
        );
    }

    // -- with_timeout convenience ------------------------------------------

    /// `with_timeout(dur, op)` behaves like `with_deadline(Deadline::after(dur), op)`.
    #[tokio::test(start_paused = true)]
    async fn with_timeout_bounds_like_with_deadline() {
        // Completes in time.
        let ok = with_timeout(Duration::from_secs(2), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok::<_, AppError>(1)
        })
        .await;
        assert_eq!(ok.unwrap(), 1);

        // Exceeds the timeout.
        let timed_out: Result<u32, AppError> = with_timeout(Duration::from_millis(100), async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(1)
        })
        .await;
        assert!(timed_out.unwrap_err().deadline_exceeded);
    }
}
