//! Property-based test for the supervisor's crash-loop guard (task 7.5).
//!
//! Feature: ZippyPanther, Property 55
//!
//! **Property 55: Supervisor crash-loop guard caps restarts within a window**
//!
//! *For any* sequence of task-crash timestamps (on a fake clock) and any
//! `RestartPolicy { max_restarts, window }`, the number of restarts the
//! supervisor performs within every sliding window of length `window` never
//! exceeds `max_restarts`; once the cap is reached the task is parked in a
//! `Failed` state and is not restarted again until the window has rolled
//! forward, and a task that is still running is never restarted.
//!
//! **Validates: Requirements 50.7, 50.12**
//!
//! The component under test is the pure, deterministic
//! [`zippy_panther::supervisor::CrashLoopGuard`] (design: Resilience → Pattern 5
//! "Self-Healing & Supervision"). It is the single place the supervisor decides
//! whether a just-exited task is restarted (with backoff) or parked, so pinning
//! its window invariant pins Property 55. Because [`CrashLoopGuard::on_exit`]
//! takes an explicit `now_ms`, the "fake clock" is just the generated timestamp
//! stream — no async runtime is required.
//!
//! ## What the generators cover
//!
//! * An arbitrary [`RestartPolicy`] over the two guard-relevant fields:
//!   `max_restarts ∈ [0, 8]` (including the degenerate `0`, which parks every
//!   exit) and `window ∈ [1ms, 10s]`. The backoff-schedule fields are fixed to
//!   small constants — they do not affect the window invariant.
//! * An arbitrary **non-decreasing** stream of exit timestamps, built by
//!   accumulating 1..=64 inter-exit gaps drawn from `[0ms, 6s]`. A monotonic
//!   timeline mirrors the monitor loop, whose timestamps come from
//!   `Instant::elapsed()`; gaps that are sometimes smaller than `window`
//!   (clustered crashes → trip the cap) and sometimes larger (→ self-heal) make
//!   the invariant non-trivial. Repeated/zero-gap timestamps exercise several
//!   exits at the very same instant.
//!
//! ## The invariants asserted
//!
//! * **Live cap (Req 50.12):** [`CrashLoopGuard::restarts_in_window`] never
//!   exceeds `max_restarts` at any step.
//! * **Park ⇒ window full (Req 50.7):** every [`RestartDecision::Park`] happens
//!   exactly when `max_restarts` restarts already sit inside the trailing
//!   window — the guard parks only at the cap, never early.
//! * **Index agreement:** every authorized [`RestartDecision::Restart`] reports
//!   an `in_window_index` strictly below `max_restarts` and equal to the count
//!   of restarts already in the window (so it drives the right backoff term).
//! * **Window invariant (Property 55 core):** computed independently from the
//!   recorded authorized restarts, no trailing window of length `window` ever
//!   held more than `max_restarts` of them.
//! * **Self-heal (Req 50.7/50.12):** after the cap is tripped the guard stays
//!   parked everywhere inside the window, then authorizes restarts again once
//!   the window has fully rolled forward — it is not permanently latched.
//!
//! The "a task that is still running is never restarted" clause is structural:
//! `on_exit` is invoked only on an *actual* exit, so a still-running task never
//! reaches the guard. That path is covered by the supervisor's own
//! live-monitor-loop tests; this property pins the guard's window contract.

use std::time::Duration;

use proptest::prelude::*;
use zippy_panther::supervisor::{CrashLoopGuard, RestartDecision, RestartPolicy};

/// An arbitrary policy over the two crash-loop-guard fields. `max_restarts`
/// includes the degenerate `0` (every exit parks); the backoff-schedule fields
/// are fixed small constants since they are irrelevant to the window invariant.
fn arb_policy() -> impl Strategy<Value = RestartPolicy> {
    (0u32..=8, 1u64..=10_000).prop_map(|(max_restarts, window_ms)| RestartPolicy {
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(50),
        multiplier: 2.0,
        max_restarts,
        window: Duration::from_millis(window_ms),
    })
}

/// Same as [`arb_policy`] but with `max_restarts ∈ [1, 8]`, used by the
/// self-heal property where authorizing at least one restart is meaningful.
fn arb_policy_nonzero() -> impl Strategy<Value = RestartPolicy> {
    (1u32..=8, 1u64..=10_000).prop_map(|(max_restarts, window_ms)| RestartPolicy {
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(50),
        multiplier: 2.0,
        max_restarts,
        window: Duration::from_millis(window_ms),
    })
}

/// A non-decreasing "fake clock" stream of exit timestamps: 1..=64 inter-exit
/// gaps in `[0ms, 6s]` accumulated into a monotonic timeline (zero gaps yield
/// several exits at the same instant).
fn arb_exit_times() -> impl Strategy<Value = Vec<u64>> {
    proptest::collection::vec(0u64..=6_000, 1..=64).prop_map(|gaps| {
        let mut t = 0u64;
        let mut out = Vec::with_capacity(gaps.len());
        for g in gaps {
            t = t.saturating_add(g);
            out.push(t);
        }
        out
    })
}

/// The largest number of restarts inside any trailing window of length
/// `window_ms`, computed independently from the guard.
///
/// The guard's window is half-open `(end − window_ms, end]` (a restart exactly
/// `window_ms` old is pruned). The maximum population of any fixed-length
/// window over a non-decreasing point set is attained at a window whose right
/// edge sits on a point, so it suffices to evaluate the window ending at each
/// authorized restart. Because the timestamps are non-decreasing, the restarts
/// inside `(end − window_ms, end]` form a contiguous suffix of the prefix up to
/// `end`, counted here by walking back while `ts > lo`.
fn max_count_in_any_window(restarts: &[u64], window_ms: u64) -> usize {
    let mut max = 0usize;
    for (i, &end) in restarts.iter().enumerate() {
        let lo = end.saturating_sub(window_ms);
        let count = restarts[..=i]
            .iter()
            .rev()
            .take_while(|&&ts| ts > lo)
            .count();
        max = max.max(count);
    }
    max
}

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 55 — for any exit-timestamp stream and any
    /// `{ max_restarts, window }` policy, the guard never authorizes more than
    /// `max_restarts` restarts in any trailing window, parks exactly at the cap,
    /// and reports a consistent in-window index for every authorized restart.
    /// **Validates: Requirements 50.7, 50.12**
    #[test]
    fn crash_loop_guard_caps_restarts_within_window(
        policy in arb_policy(),
        exits in arb_exit_times(),
    ) {
        let max = policy.max_restarts;
        let window_ms = policy.window.as_millis() as u64;
        let mut guard = CrashLoopGuard::new(policy);

        let mut authorized: Vec<u64> = Vec::new();
        for &now in &exits {
            let decision = guard.on_exit(now);

            // Live cap: the in-window count never exceeds max_restarts.
            prop_assert!(
                guard.restarts_in_window() as u32 <= max,
                "live restarts_in_window {} exceeded max_restarts {} at t={}",
                guard.restarts_in_window(), max, now,
            );

            match decision {
                RestartDecision::Restart { in_window_index, .. } => {
                    // The reported index is below the cap and equals the count
                    // of restarts already in the window (it just got pushed).
                    prop_assert!(
                        in_window_index < max,
                        "authorized restart reported in_window_index {} >= max_restarts {}",
                        in_window_index, max,
                    );
                    prop_assert_eq!(
                        in_window_index as usize + 1,
                        guard.restarts_in_window(),
                        "in_window_index must be the pre-push window population",
                    );
                    authorized.push(now);
                }
                RestartDecision::Park => {
                    // The guard parks only at the cap: the window is exactly
                    // full (for max_restarts == 0 this is the empty window).
                    prop_assert_eq!(
                        guard.restarts_in_window() as u32,
                        max,
                        "park at t={} must mean the window holds exactly max_restarts",
                        now,
                    );
                }
            }
        }

        // Core Property 55 invariant: no trailing window of length `window`
        // ever held more than max_restarts authorized restarts.
        let observed_max = max_count_in_any_window(&authorized, window_ms);
        prop_assert!(
            observed_max as u32 <= max,
            "a window of {}ms held {} authorized restarts (> max_restarts {})",
            window_ms, observed_max, max,
        );
    }

    /// Feature: ZippyPanther, Property 55 — once the cap is tripped the guard
    /// stays parked everywhere inside the window, then self-heals (authorizes a
    /// restart again) the moment the window has fully rolled forward; it is not
    /// permanently latched. **Validates: Requirements 50.7, 50.12**
    #[test]
    fn crash_loop_guard_self_heals_after_window_rolls_forward(
        policy in arb_policy_nonzero(),
        base in 0u64..=1_000_000,
    ) {
        let max = policy.max_restarts;
        let window_ms = policy.window.as_millis() as u64;
        let mut guard = CrashLoopGuard::new(policy);

        // Fill the window: max_restarts rapid exits at the same instant are all
        // authorized.
        for i in 0..max {
            prop_assert!(
                matches!(guard.on_exit(base), RestartDecision::Restart { .. }),
                "restart {} of {} at the cap-filling instant must be authorized",
                i + 1, max,
            );
        }

        // The next exit at the same instant trips the cap and parks.
        prop_assert_eq!(
            guard.on_exit(base),
            RestartDecision::Park,
            "the (max_restarts + 1)-th rapid exit must park",
        );

        // Still parked anywhere strictly inside the window: at the last instant
        // before the oldest restart ages out, the window is still full.
        let still_inside = base.saturating_add(window_ms - 1);
        prop_assert_eq!(
            guard.on_exit(still_inside),
            RestartDecision::Park,
            "must remain parked while the window has not yet rolled forward",
        );

        // Self-heal: once the window has fully rolled forward (the oldest
        // restart is exactly `window` old ⇒ pruned), a restart is authorized
        // again.
        let after = base.saturating_add(window_ms);
        prop_assert!(
            matches!(guard.on_exit(after), RestartDecision::Restart { .. }),
            "the guard must authorize a restart once the window has rolled forward",
        );
    }
}
