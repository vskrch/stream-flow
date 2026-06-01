//! Property-based test for supervised background-task restart with backoff
//! (task 7.4).
//!
//! Feature: stream-flow, Property 52
//!
//! **Property 52: Supervised task restart with backoff**
//!
//! *For any* sequence of background-task outcomes (`panic`, early `exit`, or
//! `run-forever`), the supervisor restarts the task after each panic or early
//! exit using delays drawn from the configured backoff schedule (never
//! exceeding `max_backoff`), records a restart event for each restart, and
//! never restarts a task that is still running; a task that only ever
//! runs-forever is never restarted.
//!
//! **Validates: Requirements 50.7, 50.12**
//!
//! The unit under test is the background-task supervisor (design: Resilience →
//! Pattern 5 "Self-Healing & Supervision"; Components → Background-task
//! supervision). Property 52 has two halves and this file exercises both:
//!
//! * **The pure backoff schedule** ([`RestartPolicy::backoff`] and the
//!   restart-decisions [`CrashLoopGuard::on_exit`] hands out) is driven over
//!   arbitrary policies and restart indices. The schedule must be the capped
//!   exponential `min(max_backoff, base · multiplierⁱⁿᵈᵉˣ)` — monotonic before
//!   the cap, saturating at `max_backoff`, and **never exceeding**
//!   `max_backoff` for any index, however large.
//! * **The live monitor loop** ([`spawn_supervised`]) is exercised on a
//!   per-case **current-thread paused runtime** (`start_paused = true`) so the
//!   backoff sleeps are virtual time and the whole restart sequence resolves
//!   deterministically with no real sleeping. A task that always panics / always
//!   exits early is restarted using exactly the configured schedule, recording
//!   one [`RestartEvent`] per restart; a task that runs forever is never
//!   restarted.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use stream_flow::supervisor::{
    spawn_supervised, CrashLoopGuard, ExitReason, RestartDecision, RestartPolicy, ShutdownSignal,
    TaskStatus,
};

/// Absolute tolerance (1µs) for `f64`-seconds comparisons: both the
/// implementation and this mirror route the same `f64` through
/// `Duration::from_secs_f64` (nanosecond resolution), so the only divergence is
/// sub-nanosecond rounding, comfortably within 1µs.
const TOL_SECS: f64 = 1e-6;

/// The capped-exponential backoff term recomputed independently in `f64`
/// seconds: `min(max_backoff, base · multiplierⁱⁿᵈᵉˣ)`, with a non-finite
/// product (a huge index overflowing `multiplierⁱⁿᵈᵉˣ` to `+inf`) saturating to
/// `max_backoff`. Mirrors the contract [`RestartPolicy::backoff`] must satisfy
/// without reusing its code path.
fn expected_backoff_secs(policy: &RestartPolicy, index: u32) -> f64 {
    let base_secs = policy.base_backoff.as_secs_f64();
    let max_secs = policy.max_backoff.as_secs_f64();
    let factor = policy.multiplier.powi(index as i32);
    let exp_secs = base_secs * factor;
    let capped = exp_secs.min(max_secs);
    if capped.is_finite() {
        capped.max(0.0)
    } else {
        max_secs
    }
}

/// An arbitrary, bounded [`RestartPolicy`] for the **pure schedule** properties:
/// * `base_backoff ∈ [1ms, 5000ms]` (strictly positive so the exponential term
///   is well-defined for every index),
/// * `max_backoff ∈ [0ms, 20000ms]` (independent of `base` — may be below it,
///   which simply pins the cap at `max_backoff`),
/// * `multiplier ∈ [1.0, 4.0]` (a non-shrinking exponential factor, so the
///   pre-cap schedule is monotonic),
/// * `max_restarts ∈ [1, 8]` and `window = 600s` (a window far larger than any
///   restart burst, so the crash-loop guard's in-window index advances by one
///   per restart with no pruning — isolating Property 52's *schedule* from
///   Property 55's *window cap*).
fn any_policy() -> impl Strategy<Value = RestartPolicy> {
    (1u64..=5_000, 0u64..=20_000, 1.0f64..=4.0, 1u32..=8).prop_map(
        |(base_ms, max_ms, multiplier, max_restarts)| RestartPolicy {
            base_backoff: Duration::from_millis(base_ms),
            max_backoff: Duration::from_millis(max_ms),
            multiplier,
            max_restarts,
            window: Duration::from_secs(600),
        },
    )
}

/// An arbitrary [`RestartPolicy`] for the **live monitor loop** properties.
/// Bounds are kept small (`max_restarts ∈ [1, 6]`) so each paused-runtime case
/// runs a bounded restart burst; the `600s` window again guarantees no pruning
/// during the burst so the recorded backoffs equal `backoff(0..max_restarts)`.
fn any_live_policy() -> impl Strategy<Value = RestartPolicy> {
    (1u64..=50, 1u64..=200, 1.0f64..=3.0, 1u32..=6).prop_map(
        |(base_ms, max_ms, multiplier, max_restarts)| RestartPolicy {
            base_backoff: Duration::from_millis(base_ms),
            max_backoff: Duration::from_millis(max_ms),
            multiplier,
            max_restarts,
            window: Duration::from_secs(600),
        },
    )
}

/// A per-case current-thread runtime with virtual (paused) time, so the
/// supervisor's backoff sleeps resolve deterministically by auto-advancing the
/// clock instead of sleeping for real (mirrors the in-module supervisor tests'
/// `#[tokio::test(start_paused = true)]`).
fn paused_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("current-thread paused tokio runtime must build")
}

/// Let spawned tasks make progress under the paused runtime.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 52 — the pure backoff schedule is the
    /// capped exponential `min(max_backoff, base·multiplierⁱⁿᵈᵉˣ)`: it equals
    /// the formula, is monotonic non-decreasing, and **never exceeds**
    /// `max_backoff` for any index. **Validates: Requirements 50.7, 50.12**
    #[test]
    fn backoff_is_capped_monotonic_and_matches_formula(
        policy in any_policy(),
        index in 0u32..=64,
    ) {
        let backoff = policy.backoff(index);

        // -- Never exceeds the cap, for any index ----------------------------
        prop_assert!(
            backoff <= policy.max_backoff,
            "backoff({}) = {:?} exceeded max_backoff {:?}",
            index, backoff, policy.max_backoff,
        );

        // -- Equals min(max_backoff, base·multiplierⁱⁿᵈᵉˣ) -------------------
        let expected = expected_backoff_secs(&policy, index);
        prop_assert!(
            (backoff.as_secs_f64() - expected).abs() <= TOL_SECS,
            "backoff({}) = {}s != min(max, base·mult^index) = {}s",
            index, backoff.as_secs_f64(), expected,
        );

        // -- Monotonic non-decreasing in the index --------------------------
        // multiplier >= 1 ⇒ the pre-cap term is non-decreasing, and capping
        // with a constant preserves that ordering.
        let next = policy.backoff(index + 1);
        prop_assert!(
            backoff <= next,
            "schedule not monotonic: backoff({}) = {:?} > backoff({}) = {:?}",
            index, backoff, index + 1, next,
        );
    }

    /// Feature: stream-flow, Property 52 — for a large index the schedule
    /// saturates to exactly `max_backoff` (never overflowing/panicking on the
    /// runaway `multiplierⁱⁿᵈᵉˣ` term). A `multiplier > 1` plus a huge index
    /// drives `multiplierⁱⁿᵈᵉˣ → +inf`, so the term must collapse to the cap.
    /// **Validates: Requirements 50.7, 50.12**
    #[test]
    fn backoff_saturates_at_max_backoff_for_large_indices(
        base_ms in 1u64..=5_000,
        max_ms in 0u64..=20_000,
        multiplier in 1.5f64..=4.0,
        index in 200u32..=4_000,
    ) {
        let policy = RestartPolicy {
            base_backoff: Duration::from_millis(base_ms),
            max_backoff: Duration::from_millis(max_ms),
            multiplier,
            max_restarts: 8,
            window: Duration::from_secs(600),
        };
        let backoff = policy.backoff(index);
        prop_assert!(
            (backoff.as_secs_f64() - policy.max_backoff.as_secs_f64()).abs() <= TOL_SECS,
            "backoff({}) = {:?} did not saturate to max_backoff {:?}",
            index, backoff, policy.max_backoff,
        );
        prop_assert!(backoff <= policy.max_backoff);
    }

    /// Feature: stream-flow, Property 52 — the crash-loop guard hands out the
    /// configured schedule: while restarts remain inside the window each
    /// `on_exit` authorizes a `Restart` whose backoff is exactly
    /// `policy.backoff(in_window_index)` (always `<= max_backoff`) with the
    /// in-window index advancing by one per restart. (The window cap itself is
    /// Property 55; here `window` is large so the schedule is isolated.)
    /// **Validates: Requirements 50.7, 50.12**
    #[test]
    fn crash_loop_guard_restart_backoff_follows_schedule(
        policy in any_policy(),
    ) {
        let max_restarts = policy.max_restarts;
        let mut guard = CrashLoopGuard::new(policy.clone());

        // Tightly-spaced exits (1ms apart) all fall inside the 600s window, so
        // none are pruned and the in-window index simply counts restarts.
        for i in 0..max_restarts {
            let decision = guard.on_exit(i as u64);
            match decision {
                RestartDecision::Restart { backoff, in_window_index } => {
                    prop_assert_eq!(
                        in_window_index, i,
                        "in-window index must advance by one per restart",
                    );
                    prop_assert_eq!(
                        backoff,
                        policy.backoff(i),
                        "guard backoff must equal the configured schedule at index {}",
                        i,
                    );
                    prop_assert!(
                        backoff <= policy.max_backoff,
                        "guard backoff {:?} exceeded max_backoff {:?}",
                        backoff, policy.max_backoff,
                    );
                }
                RestartDecision::Park => {
                    prop_assert!(false, "must not park before reaching max_restarts (i={})", i);
                }
            }
        }

        // The next exit, still inside the window, trips the cap and parks.
        prop_assert_eq!(
            guard.on_exit(max_restarts as u64),
            RestartDecision::Park,
            "the exit past max_restarts must park rather than restart",
        );
    }

    /// Feature: stream-flow, Property 52 — a supervised task that always panics
    /// or always exits early is restarted using exactly the configured backoff
    /// schedule, recording one restart event per restart (each `<= max_backoff`)
    /// with the matching exit reason, until the crash-loop cap parks it
    /// `Failed`. **Validates: Requirements 50.7, 50.12**
    #[test]
    fn supervised_task_restarts_on_exit_with_backoff_schedule_and_records_events(
        policy in any_live_policy(),
        panic_mode in any::<bool>(),
    ) {
        let rt = paused_runtime();
        let result: Result<(), TestCaseError> = rt.block_on(async move {
            let max_restarts = policy.max_restarts;
            let runs = Arc::new(AtomicU32::new(0));
            let signal = ShutdownSignal::new();
            let r = runs.clone();

            let mut handle = spawn_supervised("prop-task", policy.clone(), signal.token(), move || {
                let r = r.clone();
                async move {
                    r.fetch_add(1, Ordering::SeqCst);
                    if panic_mode {
                        panic!("simulated background-task panic");
                    }
                    // else: clean but unexpected early exit of a long-lived task.
                }
            });

            // The monitor loop runs the task, restarts up to `max_restarts`
            // times, then parks `Failed` — virtual time means the backoff
            // sleeps cost nothing.
            handle.wait().await;

            // -- Restarted after each exit, capped by the crash-loop guard ----
            prop_assert_eq!(
                runs.load(Ordering::SeqCst),
                max_restarts + 1,
                "initial run + max_restarts restarts must have executed",
            );
            prop_assert_eq!(
                handle.restart_count(),
                max_restarts,
                "restart_count must equal max_restarts",
            );
            prop_assert_eq!(
                handle.status(),
                TaskStatus::Failed,
                "task must be parked Failed once the crash-loop cap is hit",
            );

            // -- One event per restart, each drawn from the backoff schedule --
            let events = handle.events();
            prop_assert_eq!(
                events.len(),
                max_restarts as usize,
                "exactly one restart event recorded per restart",
            );
            for (i, event) in events.iter().enumerate() {
                prop_assert_eq!(
                    event.backoff,
                    policy.backoff(i as u32),
                    "event {} backoff must follow the configured schedule",
                    i,
                );
                prop_assert!(
                    event.backoff <= policy.max_backoff,
                    "event {} backoff {:?} exceeded max_backoff {:?}",
                    i, event.backoff, policy.max_backoff,
                );
                prop_assert_eq!(
                    event.restart_count,
                    (i as u32) + 1,
                    "restart_count must be 1-based and contiguous",
                );
                if panic_mode {
                    prop_assert!(
                        matches!(event.reason, ExitReason::Panicked(_)),
                        "a panicking task's exit reason must be Panicked, got {:?}",
                        event.reason,
                    );
                } else {
                    prop_assert!(
                        matches!(event.reason, ExitReason::Completed),
                        "an early-exiting task's reason must be Completed, got {:?}",
                        event.reason,
                    );
                }
            }

            drop(signal);
            Ok(())
        });
        result?;
    }

    /// Feature: stream-flow, Property 52 — a task that only ever runs forever
    /// is never restarted: advancing the fake clock far past every backoff
    /// window leaves `restart_count == 0` and the task `Running`, with its body
    /// having entered exactly once. **Validates: Requirements 50.7, 50.12**
    #[test]
    fn still_running_task_is_never_restarted(
        policy in any_live_policy(),
        advance_secs in 1u64..=7_200,
    ) {
        let rt = paused_runtime();
        let result: Result<(), TestCaseError> = rt.block_on(async move {
            let started = Arc::new(AtomicU32::new(0));
            let signal = ShutdownSignal::new();
            let s = started.clone();

            let handle = spawn_supervised("prop-forever", policy, signal.token(), move || {
                let s = s.clone();
                async move {
                    s.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await; // never completes
                }
            });

            settle().await;
            // Advance the fake clock far beyond any backoff window.
            tokio::time::advance(Duration::from_secs(advance_secs)).await;
            settle().await;

            prop_assert_eq!(
                started.load(Ordering::SeqCst),
                1,
                "a run-forever task body must enter exactly once",
            );
            prop_assert_eq!(
                handle.restart_count(),
                0,
                "a still-running task must never be restarted",
            );
            prop_assert_eq!(
                handle.status(),
                TaskStatus::Running,
                "a still-running task must remain Running",
            );

            handle.abort();
            drop(signal);
            Ok(())
        });
        result?;
    }
}
