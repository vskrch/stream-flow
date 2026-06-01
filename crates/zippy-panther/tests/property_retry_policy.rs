//! Property-based test for the unified retry policy (task 6.6).
//!
//! Feature: stream-flow, Property 50
//!
//! **Property 50: Retry-policy classification and bounded jittered backoff**
//!
//! *For any* error sample, [`RetryPolicy::classify`] returns `Transient` for
//! connection resets, timeouts, and `502/503/504`, and `Permanent` for any
//! `4xx` other than `408`/`429`; classification is deterministic (the same
//! error always yields the same decision). *For any* policy config and attempt
//! index, the computed full-jitter backoff lies in the band `[0, capped]` and
//! never exceeds `max_delay`, where `capped = min(max_delay,
//! base·multiplierᵃᵗᵗᵉᵐᵖᵗ)`; the capped delay saturates at `max_delay`; and a
//! `retry_after` hint is honored, clamped to `max_delay`.
//!
//! **Validates: Requirements 50.1, 35.4**
//!
//! These properties pin the resilience contract that every control-plane
//! outbound call relies on (design: Resilience → Pattern 2 "Unified Retry
//! Policy"; Property 50). The backoff is exercised with a **seeded** [`StdRng`]
//! so the schedule is deterministic, and arbitrary policies (bounded fields),
//! attempt indices, and error categories are generated to cover the full input
//! space.
//!
//! The implementation under test uses **full jitter** — the design's canonical
//! jitter band collapses to `[0, capped]` (design: Pattern 2; `retry.rs`
//! [`RetryPolicy::backoff`] = `random_between(0, capped)`), which is what this
//! property asserts.

use std::time::Duration;

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use stream_flow::errors::{AppError, ErrorCategory};
use stream_flow::resilience::{RetryPolicy, Retryability};

/// The full category space (mirrors the canonical taxonomy) so classification
/// is checked over every variant (Req 50.1).
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

/// Generates every [`ErrorCategory`] variant with equal weight.
fn any_category() -> impl Strategy<Value = ErrorCategory> {
    (0usize..ALL_CATEGORIES.len()).prop_map(|i| ALL_CATEGORIES[i])
}

/// The transient set: exactly the categories a bare retry can plausibly clear —
/// `502` (`HosterUnavailable`), `503/504` + connection-reset/timeout
/// (`UpstreamUnavailable`), and `429` (`TooManyRequests`). Every other category
/// is permanent (Req 50.1). Mirrored independently from the implementation so
/// the property pins the contract.
fn expected_retryability(category: ErrorCategory) -> Retryability {
    match category {
        ErrorCategory::UpstreamUnavailable
        | ErrorCategory::HosterUnavailable
        | ErrorCategory::TooManyRequests => Retryability::Transient,
        _ => Retryability::Permanent,
    }
}

/// Generates an arbitrary, bounded [`RetryPolicy`]:
/// * `max_attempts ∈ [1, 20]` (≥ 1 total try),
/// * `base_delay ∈ [1ms, 5000ms]` (strictly positive so the exponential term
///   is well-defined for every attempt),
/// * `max_delay ∈ [0ms, 20000ms]` (independent of `base` — may be below it,
///   which simply pins the cap at `max_delay`),
/// * `multiplier ∈ [1.0, 4.0]` (a non-shrinking exponential factor).
fn any_policy() -> impl Strategy<Value = RetryPolicy> {
    (1u32..=20, 1u64..=5_000, 0u64..=20_000, 1.0f64..=4.0).prop_map(
        |(max_attempts, base_ms, max_ms, multiplier)| {
            RetryPolicy::new(
                max_attempts,
                Duration::from_millis(base_ms),
                Duration::from_millis(max_ms),
                multiplier,
            )
        },
    )
}

/// The mathematical full-jitter cap, recomputed independently in `f64` seconds:
/// `min(max_delay, base·multiplierᵃᵗᵗᵉᵐᵖᵗ)`, with non-finite products (a huge
/// attempt overflowing `multiplierᵃᵗᵗᵉᵐᵖᵗ` to `+inf`) saturating to
/// `max_delay`. This mirrors the contract `capped_delay` must satisfy without
/// reusing its code path.
fn expected_capped_secs(policy: &RetryPolicy, attempt: u32) -> f64 {
    let base_secs = policy.base_delay.as_secs_f64();
    let max_secs = policy.max_delay.as_secs_f64();
    let factor = policy.multiplier.powi(attempt as i32);
    let exp_secs = base_secs * factor;
    let capped = exp_secs.min(max_secs);
    if capped.is_finite() {
        capped.max(0.0)
    } else {
        max_secs
    }
}

/// Absolute tolerance (1µs) for `f64`-seconds comparisons: both the
/// implementation and the mirror route the same `f64` through
/// `Duration::from_secs_f64` (nanosecond resolution), so the only divergence is
/// sub-nanosecond rounding, comfortably within 1µs.
const TOL_SECS: f64 = 1e-6;

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 50 — classification is deterministic and
    /// partitions the transient categories (`UpstreamUnavailable`,
    /// `HosterUnavailable`, `TooManyRequests`) from every permanent one.
    /// **Validates: Requirements 50.1, 35.4**
    #[test]
    fn classify_is_deterministic_and_partitions_transient_vs_permanent(
        category in any_category(),
        message in ".{0,64}",
    ) {
        let err = AppError::new(category, message);

        // Partition: classification matches the independently-mirrored set.
        let expected = expected_retryability(category);
        prop_assert_eq!(
            RetryPolicy::classify(&err),
            expected,
            "category {:?} classified incorrectly",
            category,
        );

        // Determinism: the same error yields the same decision every time.
        let first = RetryPolicy::classify(&err);
        for _ in 0..8 {
            prop_assert_eq!(RetryPolicy::classify(&err), first);
        }
    }

    /// Feature: stream-flow, Property 50 — every full-jitter backoff lies in
    /// the band `[0, capped]` and never exceeds `max_delay`, for any policy,
    /// attempt, and seed. **Validates: Requirements 50.1, 35.4**
    #[test]
    fn backoff_lies_in_band_and_never_exceeds_max_delay(
        policy in any_policy(),
        attempt in 0u32..=64,
        seed in any::<u64>(),
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let capped = policy.capped_delay(attempt);
        let delay = policy.backoff(attempt, &mut rng);

        // Lower bound: a `Duration` is always ≥ 0 (the band's floor).
        // Upper bound: never exceeds the cap, and the cap never exceeds
        // `max_delay`.
        prop_assert!(
            delay <= capped,
            "attempt {}: backoff {:?} exceeds cap {:?}",
            attempt, delay, capped,
        );
        prop_assert!(
            delay <= policy.max_delay,
            "attempt {}: backoff {:?} exceeds max_delay {:?}",
            attempt, delay, policy.max_delay,
        );
        prop_assert!(
            capped <= policy.max_delay,
            "attempt {}: cap {:?} exceeds max_delay {:?}",
            attempt, capped, policy.max_delay,
        );
    }

    /// Feature: stream-flow, Property 50 — the capped delay equals
    /// `min(max_delay, base·multiplierᵃᵗᵗᵉᵐᵖᵗ)` for any attempt.
    /// **Validates: Requirements 50.1, 35.4**
    #[test]
    fn capped_delay_equals_min_of_exponential_and_max(
        policy in any_policy(),
        attempt in 0u32..=64,
    ) {
        let capped_secs = policy.capped_delay(attempt).as_secs_f64();
        let expected = expected_capped_secs(&policy, attempt);
        prop_assert!(
            (capped_secs - expected).abs() <= TOL_SECS,
            "attempt {}: capped {}s != min(max, base*mult^n) {}s",
            attempt, capped_secs, expected,
        );
        // The cap is always within `max_delay`.
        prop_assert!(capped_secs <= policy.max_delay.as_secs_f64() + TOL_SECS);
    }

    /// Feature: stream-flow, Property 50 — once the exponential term reaches or
    /// overflows `max_delay`, the cap saturates at exactly `max_delay` (no
    /// overflow/panic). A `multiplier > 1` plus a huge attempt drives
    /// `multiplierᵃᵗᵗᵉᵐᵖᵗ → +inf`, so the cap must collapse to `max_delay`.
    /// **Validates: Requirements 50.1, 35.4**
    #[test]
    fn capped_delay_saturates_at_max_delay_for_large_attempts(
        base_ms in 1u64..=5_000,
        max_ms in 0u64..=20_000,
        multiplier in 1.5f64..=4.0,
        attempt in 200u32..=4_000,
    ) {
        let policy = RetryPolicy::new(
            64,
            Duration::from_millis(base_ms),
            Duration::from_millis(max_ms),
            multiplier,
        );
        let capped = policy.capped_delay(attempt);
        // Saturates to exactly `max_delay` (within float tolerance) and never
        // panics on the overflowing exponential term.
        prop_assert!(
            (capped.as_secs_f64() - policy.max_delay.as_secs_f64()).abs() <= TOL_SECS,
            "attempt {}: cap {:?} did not saturate to max_delay {:?}",
            attempt, capped, policy.max_delay,
        );
        // A jittered draw at a saturating attempt is still inside the band.
        let mut rng = StdRng::seed_from_u64(attempt as u64);
        prop_assert!(policy.backoff(attempt, &mut rng) <= policy.max_delay);
    }

    /// Feature: stream-flow, Property 50 — when an error carries a `retry_after`
    /// hint, `delay_for` waits exactly that long clamped to `max_delay`,
    /// independent of the RNG; without a hint it falls back to the in-band
    /// jittered backoff. **Validates: Requirements 50.1, 35.4**
    #[test]
    fn delay_for_honors_retry_after_clamped_to_max_delay(
        policy in any_policy(),
        attempt in 0u32..=64,
        retry_after_ms in 0u64..=120_000,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let retry_after = Duration::from_millis(retry_after_ms);
        let err = AppError::too_many_requests("rate limited").with_retry_after(retry_after);

        // Honored, clamped to `max_delay`.
        let expected = retry_after.min(policy.max_delay);
        let mut rng_a = StdRng::seed_from_u64(seed_a);
        let mut rng_b = StdRng::seed_from_u64(seed_b);
        let delay_a = policy.delay_for(attempt, &err, &mut rng_a);
        let delay_b = policy.delay_for(attempt, &err, &mut rng_b);

        prop_assert_eq!(delay_a, expected, "retry_after must be honored, clamped to max_delay");
        // Independent of the RNG: two different seeds give the same value.
        prop_assert_eq!(delay_a, delay_b, "retry_after delay must not depend on the RNG");
        prop_assert!(delay_a <= policy.max_delay, "clamped delay must not exceed max_delay");

        // Without a hint: falls back to the in-band jittered backoff.
        let no_hint = AppError::upstream_unavailable("connection reset");
        let mut rng_c = StdRng::seed_from_u64(seed_a);
        let fallback = policy.delay_for(attempt, &no_hint, &mut rng_c);
        prop_assert!(
            fallback <= policy.capped_delay(attempt),
            "fallback backoff {:?} exceeds cap {:?}",
            fallback, policy.capped_delay(attempt),
        );
    }

    /// Feature: stream-flow, Property 50 — the seeded RNG makes the backoff
    /// schedule reproducible: identical seeds produce identical delays for the
    /// same attempt. **Validates: Requirements 50.1, 35.4**
    #[test]
    fn backoff_is_deterministic_for_a_fixed_seed(
        policy in any_policy(),
        attempt in 0u32..=64,
        seed in any::<u64>(),
    ) {
        let mut rng_a = StdRng::seed_from_u64(seed);
        let mut rng_b = StdRng::seed_from_u64(seed);
        prop_assert_eq!(
            policy.backoff(attempt, &mut rng_a),
            policy.backoff(attempt, &mut rng_b),
            "same seed + attempt must yield the same backoff",
        );
    }
}
