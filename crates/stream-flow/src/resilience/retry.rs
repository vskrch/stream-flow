//! Unified retry policy (`resilience::retry`) — Req 50.1, 35.4.
//!
//! A single [`RetryPolicy`] governs **control-plane / API-style** outbound
//! calls (store ops, link-gen, integration fetches, id-map lookups). It uses
//! **exponential backoff with full jitter** and a capped attempt count, and it
//! retries **only** errors classified as transient (design: Resilience →
//! Pattern 2 "Unified Retry Policy"; Components → `RetryPolicy`).
//!
//! Classification is the single source of truth in
//! [`ErrorCategory::is_retryable`](crate::errors::ErrorCategory::is_retryable):
//! transient = `UpstreamUnavailable` (503/504, connection reset, timeout),
//! `HosterUnavailable` (502), `TooManyRequests` (429); permanent = every
//! 4xx-style category (other than the timeout/rate-limit cases folded into the
//! transient categories above) plus the catch-all `Unknown`. Permanent errors
//! are returned immediately with **zero** retries; a transient error is
//! retried at most `max_attempts − 1` times.
//!
//! The backoff RNG is **seedable** so unit tests and the property test
//! (task 6.6 / Property 50) are deterministic: [`RetryPolicy::backoff`] is
//! generic over any [`rand::Rng`], [`RetryPolicy::run_seeded`] drives the loop
//! from a fixed `u64` seed, and [`RetryPolicy::run`] uses an OS-seeded
//! [`StdRng`] in production.
//!
//! ## Scope of this task (6.1)
//!
//! This module implements the **classification + full-jitter backoff + a
//! standalone retry-run loop**. The full
//! `with_retry(policy, breaker, deadline, op)` composition that wires the
//! retry loop together with the `CircuitBreaker` (task 6.2) and `Deadline`
//! (task 6.3) lands with those tasks; the `run` loop here is the retry half of
//! that composition and is the single place the backoff schedule is applied.

use std::future::Future;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::errors::AppError;

/// Whether an error should be retried (design: Components → `RetryPolicy`).
///
/// Derived solely from the error's
/// [`ErrorCategory`](crate::errors::ErrorCategory) via
/// [`ErrorCategory::is_retryable`](crate::errors::ErrorCategory::is_retryable),
/// so classification is **deterministic**: the same error always yields the
/// same decision (Req 50.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryability {
    /// A transient failure (connection reset/timeout, `502/503/504`, `429`)
    /// that a retry can plausibly clear.
    Transient,
    /// A permanent failure (4xx-style, account cap, `Unknown`) that a bare
    /// retry cannot clear — return it immediately.
    Permanent,
}

/// Exponential-backoff-with-full-jitter retry policy (Req 50.1, 35.4).
///
/// Field shape follows the design's Pattern 2 "Unified Retry Policy":
/// `max_attempts` (total tries, **including** the first), `base_delay` (the
/// first backoff term), `max_delay` (the cap applied to the exponential term),
/// and `multiplier` (the exponential factor, e.g. `2.0`).
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts, **including** the first try (e.g. `3` ⇒ at
    /// most two retries). Should be `>= 1`.
    pub max_attempts: u32,
    /// The first backoff term (e.g. `100ms`).
    pub base_delay: Duration,
    /// Cap on the (pre-jitter) exponential term (e.g. `5s`). Also bounds the
    /// `retry_after` honored value.
    pub max_delay: Duration,
    /// Exponential factor applied per attempt (e.g. `2.0`).
    pub multiplier: f64,
}

impl Default for RetryPolicy {
    /// The design's example policy: 3 attempts, 100ms base, 5s cap, ×2.
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// Construct an explicit policy.
    pub fn new(max_attempts: u32, base_delay: Duration, max_delay: Duration, multiplier: f64) -> Self {
        Self {
            max_attempts,
            base_delay,
            max_delay,
            multiplier,
        }
    }

    /// Classify an error as [`Transient`](Retryability::Transient) or
    /// [`Permanent`](Retryability::Permanent) (Req 50.1).
    ///
    /// Delegates to the canonical
    /// [`ErrorCategory::is_retryable`](crate::errors::ErrorCategory::is_retryable),
    /// so it is deterministic and consistent with every other call site.
    pub fn classify(err: &AppError) -> Retryability {
        if err.category.is_retryable() {
            Retryability::Transient
        } else {
            Retryability::Permanent
        }
    }

    /// The **un-jittered upper bound** of the backoff band for `attempt`:
    /// `min(max_delay, base_delay · multiplierᵃᵗᵗᵉᵐᵖᵗ)`.
    ///
    /// Computed in `f64` seconds so a large `attempt` (where
    /// `multiplierᵃᵗᵗᵉᵐᵖᵗ` overflows) saturates to `max_delay` instead of
    /// panicking in [`Duration::mul_f64`]. This is the cap that every jittered
    /// delay stays at or below.
    pub fn capped_delay(&self, attempt: u32) -> Duration {
        let base_secs = self.base_delay.as_secs_f64();
        let max_secs = self.max_delay.as_secs_f64();
        // `multiplier.powi(attempt)` may be `+inf` for a large attempt; the
        // subsequent `.min(max_secs)` then collapses it back to the cap, and
        // the `is_finite` guard catches any residual non-finite product.
        let factor = self.multiplier.powi(attempt as i32);
        let exp_secs = base_secs * factor;
        let capped_secs = exp_secs.min(max_secs);
        let capped_secs = if capped_secs.is_finite() {
            capped_secs.max(0.0)
        } else {
            max_secs
        };
        Duration::from_secs_f64(capped_secs)
    }

    /// Full-jitter backoff for `attempt`:
    /// `random_between(0, min(max_delay, base_delay · multiplierᵃᵗᵗᵉᵐᵖᵗ))`
    /// (design: Pattern 2).
    ///
    /// The result lies in the band `[0, capped]` and never exceeds
    /// `max_delay`. Generic over [`Rng`] so the schedule is **deterministic**
    /// for a seeded RNG (unit tests / Property 50).
    pub fn backoff(&self, attempt: u32, rng: &mut impl Rng) -> Duration {
        let capped = self.capped_delay(attempt);
        // `random::<f64>()` ∈ [0, 1) ⇒ jittered delay ∈ [0, capped).
        capped.mul_f64(rng.random::<f64>())
    }

    /// The delay to wait before the retry following `attempt`, honoring
    /// `retry_after` when present (Req 50.1).
    ///
    /// When the error carries a `retry_after` hint (e.g. a `429`'s
    /// `Retry-After`), the policy waits that long, **clamped to `max_delay`**,
    /// instead of the jittered value (design: Pattern 2 — "when the error
    /// carries `retry_after`, the policy waits at least that long (clamped to
    /// `max_delay`) instead of the jittered value"). Otherwise it uses the
    /// full-jitter [`backoff`](Self::backoff).
    pub fn delay_for(&self, attempt: u32, err: &AppError, rng: &mut impl Rng) -> Duration {
        match err.retry_after {
            Some(retry_after) => retry_after.min(self.max_delay),
            None => self.backoff(attempt, rng),
        }
    }

    /// Run an idempotent async `op`, retrying **only** transient errors up to
    /// `max_attempts` total tries with full-jitter backoff (Req 50.1).
    ///
    /// Production entry point: seeds an [`StdRng`] from the OS. Use
    /// [`run_seeded`](Self::run_seeded) for a deterministic schedule in tests.
    pub async fn run<T, F, Fut>(&self, op: F) -> Result<T, AppError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, AppError>>,
    {
        let mut rng = StdRng::from_os_rng();
        self.run_with_rng(&mut rng, op).await
    }

    /// Like [`run`](Self::run) but with a fixed `seed` for a **deterministic**
    /// backoff schedule (tests / property tests).
    pub async fn run_seeded<T, F, Fut>(&self, seed: u64, op: F) -> Result<T, AppError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, AppError>>,
    {
        let mut rng = StdRng::seed_from_u64(seed);
        self.run_with_rng(&mut rng, op).await
    }

    /// The retry loop itself, driven by a caller-provided RNG.
    ///
    /// Calls `op`; on a **transient** error and while more attempts remain,
    /// sleeps for [`delay_for`](Self::delay_for) and retries. A **permanent**
    /// error (or the last attempt) is returned immediately — so a permanent
    /// error performs zero retries and a transient one is retried at most
    /// `max_attempts − 1` times.
    pub async fn run_with_rng<T, F, Fut, R>(&self, rng: &mut R, op: F) -> Result<T, AppError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, AppError>>,
        R: Rng,
    {
        let mut attempt: u32 = 0;
        loop {
            match op().await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    let more_attempts_remain = attempt + 1 < self.max_attempts;
                    if more_attempts_remain && Self::classify(&err) == Retryability::Transient {
                        let delay = self.delay_for(attempt, &err, rng);
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fast policy (no real sleeping) for exercising the run loop:
    /// `max_attempts` tries, zero backoff.
    fn fast_policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy::new(max_attempts, Duration::ZERO, Duration::ZERO, 2.0)
    }

    /// One representative `AppError` per category, for classification tests.
    fn sample_for(category: ErrorCategory) -> AppError {
        AppError::new(category, "sample")
    }

    const ALL_CATEGORIES: [ErrorCategory; 14] = [
        ErrorCategory::InvalidStoreName,
        ErrorCategory::Unauthorized,
        ErrorCategory::Forbidden,
        ErrorCategory::PaymentRequired,
        ErrorCategory::NotFound,
        ErrorCategory::StoreLimitExceeded,
        ErrorCategory::InfringingContent,
        ErrorCategory::HosterUnavailable,
        ErrorCategory::TooManyRequests,
        ErrorCategory::UpstreamUnavailable,
        ErrorCategory::BadRequest,
        ErrorCategory::PayloadTooLarge,
        ErrorCategory::RangeNotSatisfiable,
        ErrorCategory::Unknown,
    ];

    // -- Classification -----------------------------------------------------

    /// The transient set is exactly {502 (`HosterUnavailable`), 503/504 +
    /// reset/timeout (`UpstreamUnavailable`), 429 (`TooManyRequests`)}; every
    /// other category (the permanent 4xx-style ones, account caps, `Unknown`)
    /// is `Permanent` (Req 50.1).
    #[test]
    fn classify_partitions_transient_vs_permanent() {
        let transient = [
            ErrorCategory::UpstreamUnavailable,
            ErrorCategory::HosterUnavailable,
            ErrorCategory::TooManyRequests,
        ];
        for category in ALL_CATEGORIES {
            let expected = if transient.contains(&category) {
                Retryability::Transient
            } else {
                Retryability::Permanent
            };
            assert_eq!(
                RetryPolicy::classify(&sample_for(category)),
                expected,
                "category {category:?} classified incorrectly",
            );
        }
    }

    /// "connection reset / timeout / 502 / 503 / 504" are all transient — in
    /// the canonical taxonomy resets/timeouts/503/504 fold into
    /// `UpstreamUnavailable` and 502 into `HosterUnavailable`.
    #[test]
    fn transient_network_failures_classify_as_transient() {
        assert_eq!(
            RetryPolicy::classify(&AppError::upstream_unavailable("connection reset")),
            Retryability::Transient,
        );
        assert_eq!(
            RetryPolicy::classify(
                &AppError::upstream_unavailable("read timed out").into_deadline_exceeded()
            ),
            Retryability::Transient,
        );
        assert_eq!(
            RetryPolicy::classify(&AppError::hoster_unavailable("502 bad gateway")),
            Retryability::Transient,
        );
    }

    /// "4xx other than 408/429" must not be retried.
    #[test]
    fn permanent_4xx_classify_as_permanent() {
        for err in [
            AppError::bad_request("400"),
            AppError::unauthorized("401"),
            AppError::payment_required("402"),
            AppError::forbidden("403"),
            AppError::not_found("404"),
            AppError::range_not_satisfiable("416"),
            // account cap (429-status but routes to fallback, not retry)
            AppError::store_limit_exceeded("429-cap"),
        ] {
            assert_eq!(
                RetryPolicy::classify(&err),
                Retryability::Permanent,
                "{:?} must be permanent",
                err.category,
            );
        }
    }

    /// Classification is deterministic: the same error yields the same
    /// decision every time (Req 50.1).
    #[test]
    fn classify_is_deterministic() {
        for category in ALL_CATEGORIES {
            let err = sample_for(category);
            let first = RetryPolicy::classify(&err);
            for _ in 0..5 {
                assert_eq!(RetryPolicy::classify(&err), first);
            }
        }
    }

    // -- Backoff band + cap -------------------------------------------------

    /// Every jittered delay lies in the full-jitter band `[0, capped]` and
    /// never exceeds `max_delay`, across many attempts and seeds.
    #[test]
    fn backoff_is_within_full_jitter_band_and_capped() {
        let policy = RetryPolicy::new(
            8,
            Duration::from_millis(100),
            Duration::from_secs(5),
            2.0,
        );
        for seed in 0..32u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            for attempt in 0..8u32 {
                let capped = policy.capped_delay(attempt);
                let delay = policy.backoff(attempt, &mut rng);
                assert!(delay <= capped, "attempt {attempt}: {delay:?} > cap {capped:?}");
                assert!(
                    delay <= policy.max_delay,
                    "attempt {attempt}: {delay:?} exceeds max_delay {:?}",
                    policy.max_delay,
                );
            }
        }
    }

    /// The exponential term is capped at `max_delay`: once
    /// `base·multiplierⁿ >= max_delay`, the cap is exactly `max_delay`.
    #[test]
    fn capped_delay_saturates_at_max_delay() {
        let policy = RetryPolicy::new(
            64,
            Duration::from_millis(100),
            Duration::from_secs(5),
            2.0,
        );
        // 100ms·2⁶ = 6.4s > 5s ⇒ capped at 5s.
        assert_eq!(policy.capped_delay(6), Duration::from_secs(5));
        // A huge attempt must saturate (not overflow/panic).
        assert_eq!(policy.capped_delay(1000), Duration::from_secs(5));
        assert!(policy.backoff(1000, &mut StdRng::seed_from_u64(1)) <= Duration::from_secs(5));
    }

    /// Early (un-capped) attempts grow as `base·multiplierⁿ`.
    #[test]
    fn capped_delay_follows_exponential_before_cap() {
        let policy = RetryPolicy::new(
            10,
            Duration::from_millis(100),
            Duration::from_secs(60),
            2.0,
        );
        assert_eq!(policy.capped_delay(0), Duration::from_millis(100));
        assert_eq!(policy.capped_delay(1), Duration::from_millis(200));
        assert_eq!(policy.capped_delay(2), Duration::from_millis(400));
        assert_eq!(policy.capped_delay(3), Duration::from_millis(800));
    }

    /// The seeded RNG makes the schedule reproducible (determinism for the
    /// property test / unit tests).
    #[test]
    fn backoff_is_deterministic_for_a_fixed_seed() {
        let policy = RetryPolicy::default();
        let mut a = StdRng::seed_from_u64(42);
        let mut b = StdRng::seed_from_u64(42);
        for attempt in 0..6u32 {
            assert_eq!(policy.backoff(attempt, &mut a), policy.backoff(attempt, &mut b));
        }
    }

    // -- retry_after honoring ----------------------------------------------

    /// When `retry_after` is present the delay is exactly that hint, clamped to
    /// `max_delay`, independent of the RNG (Req 50.1).
    #[test]
    fn delay_for_honors_retry_after_clamped_to_max_delay() {
        let policy = RetryPolicy::new(5, Duration::from_millis(100), Duration::from_secs(5), 2.0);

        // Within the cap: honored verbatim.
        let within =
            AppError::too_many_requests("rate limited").with_retry_after(Duration::from_secs(3));
        let mut rng = StdRng::seed_from_u64(7);
        assert_eq!(policy.delay_for(0, &within, &mut rng), Duration::from_secs(3));

        // Above the cap: clamped to max_delay.
        let above =
            AppError::too_many_requests("rate limited").with_retry_after(Duration::from_secs(30));
        assert_eq!(policy.delay_for(0, &above, &mut rng), policy.max_delay);

        // No hint: falls back to the jittered backoff (within band).
        let no_hint = AppError::upstream_unavailable("reset");
        let delay = policy.delay_for(2, &no_hint, &mut rng);
        assert!(delay <= policy.capped_delay(2));
    }

    // -- run loop -----------------------------------------------------------

    /// A permanent error performs **zero** retries: `op` is invoked exactly
    /// once (Req 50.1).
    #[tokio::test]
    async fn permanent_error_performs_zero_retries() {
        let policy = fast_policy(5);
        let calls = AtomicUsize::new(0);
        let result: Result<(), AppError> = policy
            .run_seeded(1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(AppError::not_found("permanent")) }
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1, "permanent error must not retry");
    }

    /// A persistently transient error is retried at most `max_attempts − 1`
    /// times ⇒ `op` is invoked exactly `max_attempts` times (Req 50.1).
    #[tokio::test]
    async fn transient_error_is_retried_up_to_max_attempts_minus_one() {
        let policy = fast_policy(3);
        let calls = AtomicUsize::new(0);
        let result: Result<(), AppError> = policy
            .run_seeded(1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(AppError::upstream_unavailable("always transient")) }
            })
            .await;
        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "3 attempts total = the first try + (max_attempts - 1) retries",
        );
    }

    /// A transient error that later succeeds stops retrying as soon as it
    /// succeeds and returns the value.
    #[tokio::test]
    async fn transient_then_success_returns_ok_and_stops_early() {
        let policy = fast_policy(5);
        let calls = AtomicUsize::new(0);
        let result: Result<&str, AppError> = policy
            .run_seeded(1, || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(AppError::hoster_unavailable("flaky"))
                    } else {
                        Ok("ok")
                    }
                }
            })
            .await;
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 3, "2 failures + 1 success");
    }

    /// `max_attempts == 1` ⇒ no retries even for a transient error.
    #[tokio::test]
    async fn single_attempt_policy_never_retries() {
        let policy = fast_policy(1);
        let calls = AtomicUsize::new(0);
        let result: Result<(), AppError> = policy
            .run_seeded(1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(AppError::upstream_unavailable("transient")) }
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A first-try success never invokes the op a second time.
    #[tokio::test]
    async fn immediate_success_returns_without_retry() {
        let policy = fast_policy(5);
        let calls = AtomicUsize::new(0);
        let result: Result<u32, AppError> = policy
            .run_seeded(1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Ok(7) }
            })
            .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
