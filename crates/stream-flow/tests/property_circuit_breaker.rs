//! Property-based test for the circuit breaker (task 6.7).
//!
//! Feature: stream-flow, Property 51
//!
//! **Property 51: Circuit-breaker state-machine invariants and breaker-aware
//! selection**
//!
//! *For any* sequence of `{success, failure, advance-clock}` operations applied
//! to a [`CircuitBreaker`], every prefix satisfies: the breaker opens after
//! exactly `failure_threshold` consecutive trip-eligible failures; while `Open`
//! and before `cooldown` elapses, `acquire` short-circuits **without** invoking
//! the operation; after `cooldown` the next call runs as a single `HalfOpen`
//! probe; a `HalfOpen` success returns to `Closed` and resets the failure
//! counter while a `HalfOpen` (trip-eligible) failure returns to `Open` and
//! restarts the cooldown; only trip-eligible categories count toward opening;
//! and the breaker never panics over any sequence. *For any* configured store
//! order and per-store breaker states, breaker-aware selection
//! ([`select_available`]) returns the first store (in configured order) whose
//! breaker is not `Open`, or a typed `UpstreamUnavailable` error when all are
//! `Open`.
//!
//! **Validates: Requirements 50.2, 50.3, 50.4**
//!
//! The unit under test is [`stream_flow::resilience::breaker`]: the
//! [`CircuitBreaker`] state machine (driven on a [`ManualClock`] so the
//! `Open → HalfOpen` cooldown transition is deterministic) and the
//! [`select_available`] breaker-aware selector (design: Resilience → Pattern 1
//! "Circuit Breakers"; Components → `CircuitBreaker` / `StoreBreakerSet`).
//!
//! ## How the invariants are exercised
//!
//! The state-machine clauses are verified with a **reference model**: a tiny,
//! independent reimplementation of the breaker's transition rules. Each case
//! generates an arbitrary `(failure_threshold, cooldown)` plus a random
//! sequence of operations — `Call(success | eligible-failure |
//! non-eligible-failure)` and `Advance(clock)` — and drives **both** the real
//! breaker and the model through the same sequence on a shared fake clock. After
//! every operation the property asserts the observed
//! [`state`](CircuitBreaker::state) agrees with the model, that admission
//! (run vs. short-circuit) agrees, and that a short-circuit carries the
//! `circuit_open` marker and never "runs the op" (the op is gated entirely by
//! `acquire`). Agreement over every prefix of every sequence pins each named
//! transition at once, and reaching the end without a panic discharges the
//! "never panics over any sequence" clause.
//!
//! The selection clause is a separate property over an arbitrary ordered vector
//! of per-store breaker states.

use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use stream_flow::errors::{AppError, ErrorCategory};
use stream_flow::resilience::breaker::{
    BreakerConfig, BreakerKey, BreakerState, CircuitBreaker, ManualClock,
};
use stream_flow::resilience::select_available;

// ---------------------------------------------------------------------------
// Trip-eligibility mirror (design: Pattern 1 classification)
// ---------------------------------------------------------------------------

/// Mirrors the breaker's trip-eligibility rule **independently** of the
/// implementation so the property pins the contract rather than re-deriving it:
/// only `UpstreamUnavailable` / `HosterUnavailable` count toward opening; every
/// other category (client/semantic, plus the account-cap `StoreLimitExceeded`
/// and rate-limit `TooManyRequests` the per-store cooldown owns) does not.
fn is_eligible(category: ErrorCategory) -> bool {
    matches!(
        category,
        ErrorCategory::UpstreamUnavailable | ErrorCategory::HosterUnavailable
    )
}

// ---------------------------------------------------------------------------
// Operation alphabet
// ---------------------------------------------------------------------------

/// The outcome a `Call` resolves to once it is admitted.
#[derive(Clone, Copy, Debug)]
enum Outcome {
    /// A successful call.
    Success,
    /// A failed call carrying the given category (eligible or not).
    Failure(ErrorCategory),
}

/// One step in a generated operation sequence.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// Attempt a guarded call resolving to `Outcome` (one `acquire` then,
    /// **iff** admitted, one recorded outcome — so at most one permit is ever
    /// in flight at an operation boundary).
    Call(Outcome),
    /// Advance the shared fake clock by `ms` milliseconds.
    Advance(u64),
}

/// The eligible categories (each opens the breaker) and a spread of
/// non-eligible ones (none of which ever count toward opening).
const ELIGIBLE: [ErrorCategory; 2] = [
    ErrorCategory::UpstreamUnavailable,
    ErrorCategory::HosterUnavailable,
];
const NON_ELIGIBLE: [ErrorCategory; 6] = [
    ErrorCategory::NotFound,
    ErrorCategory::Unauthorized,
    ErrorCategory::Forbidden,
    ErrorCategory::TooManyRequests,
    ErrorCategory::StoreLimitExceeded,
    ErrorCategory::BadRequest,
];

fn arb_outcome() -> impl Strategy<Value = Outcome> {
    prop_oneof![
        2 => Just(Outcome::Success),
        3 => (0usize..ELIGIBLE.len()).prop_map(|i| Outcome::Failure(ELIGIBLE[i])),
        2 => (0usize..NON_ELIGIBLE.len()).prop_map(|i| Outcome::Failure(NON_ELIGIBLE[i])),
    ]
}

/// `Call` is weighted above `Advance` so sequences exercise the failure-driven
/// transitions densely, while advances still regularly elapse the cooldown.
fn arb_op(max_advance_ms: u64) -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => arb_outcome().prop_map(Op::Call),
        1 => (0u64..=max_advance_ms).prop_map(Op::Advance),
    ]
}

/// Build the [`AppError`] a generated `Outcome::Failure(category)` records.
fn error_for(category: ErrorCategory) -> AppError {
    AppError::new(category, "property step")
}

// ---------------------------------------------------------------------------
// Reference model — an independent mirror of the breaker transition rules
// ---------------------------------------------------------------------------

/// A faithful, minimal reimplementation of the breaker state machine the
/// property checks the real [`CircuitBreaker`] against. It tracks the same
/// fields and applies the same rules as `resilience::breaker`, but is written
/// independently so divergence is a real discrepancy, not a tautology.
struct Model {
    state: BreakerState,
    consecutive_failures: u32,
    opened_at_ms: u64,
    now_ms: u64,
    threshold: u32,
    cooldown_ms: u64,
}

impl Model {
    fn new(threshold: u32, cooldown_ms: u64) -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            opened_at_ms: 0,
            now_ms: 0,
            threshold: threshold.max(1),
            cooldown_ms,
        }
    }

    fn advance(&mut self, ms: u64) {
        self.now_ms = self.now_ms.saturating_add(ms);
    }

    /// Mirror of `CircuitBreaker::acquire`. Returns `(admitted, is_probe)` and
    /// performs the lazy `Open → HalfOpen` transition exactly as the source
    /// does. Because each `Call` resolves its permit before the next operation,
    /// no probe slot is ever held across operations, so a `HalfOpen` acquire
    /// always claims the single probe slot here.
    fn acquire(&mut self) -> (bool, bool) {
        match self.state {
            BreakerState::Closed => (true, false),
            BreakerState::HalfOpen => (true, true),
            BreakerState::Open => {
                let elapsed = self.now_ms.saturating_sub(self.opened_at_ms);
                if elapsed >= self.cooldown_ms {
                    self.state = BreakerState::HalfOpen;
                    (true, true)
                } else {
                    (false, false)
                }
            }
        }
    }

    /// Mirror of `CircuitBreaker::on_success`.
    fn on_success(&mut self, was_probe: bool) {
        if was_probe {
            self.state = BreakerState::Closed;
        }
        self.consecutive_failures = 0;
    }

    /// Mirror of `CircuitBreaker::on_failure`.
    fn on_failure(&mut self, was_probe: bool, eligible: bool) {
        if was_probe {
            if eligible {
                self.state = BreakerState::Open;
                self.opened_at_ms = self.now_ms;
            } else {
                self.state = BreakerState::Closed;
                self.consecutive_failures = 0;
            }
            return;
        }
        if eligible && self.state == BreakerState::Closed {
            self.consecutive_failures += 1;
            if self.consecutive_failures >= self.threshold {
                self.state = BreakerState::Open;
                self.opened_at_ms = self.now_ms;
            }
        }
        // Non-eligible closed failures are ignored (neither counted nor reset).
    }
}

// ---------------------------------------------------------------------------
// Selection helpers
// ---------------------------------------------------------------------------

fn arb_breaker_state() -> impl Strategy<Value = BreakerState> {
    prop_oneof![
        Just(BreakerState::Closed),
        Just(BreakerState::Open),
        Just(BreakerState::HalfOpen),
    ]
}

/// Construct a store breaker already driven into `state`, labelled by `name`,
/// over a fresh [`ManualClock`] (kept alive inside the breaker's `Arc`).
fn breaker_in_state(name: String, state: BreakerState) -> CircuitBreaker {
    let clock = Arc::new(ManualClock::new());
    let breaker = CircuitBreaker::with_clock(
        BreakerKey::Store(name),
        BreakerConfig::new(1, Duration::from_secs(10)),
        clock.clone(),
    );
    match state {
        BreakerState::Closed => {}
        BreakerState::Open => {
            let permit = breaker.acquire().expect("closed breaker admits");
            breaker.on_failure(permit, &AppError::upstream_unavailable("trip"));
        }
        BreakerState::HalfOpen => {
            let permit = breaker.acquire().expect("closed breaker admits");
            breaker.on_failure(permit, &AppError::upstream_unavailable("trip"));
            clock.advance(Duration::from_secs(10)); // elapse cooldown
                                                    // Admitting (then dropping) a probe transitions Open → HalfOpen and
                                                    // releases the slot; the observed state stays HalfOpen.
            let _probe = breaker
                .acquire()
                .expect("cooldown elapsed → probe admitted");
        }
    }
    assert_eq!(
        breaker.state(),
        state,
        "breaker must be in the requested state"
    );
    breaker
}

proptest! {
    // 256 cases (>= 100 required for a property task). Every case runs on a
    // ManualClock with pure in-memory transitions, so a generous count stays
    // fast while broadly exploring operation interleavings.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 51 — the real breaker's observed state,
    /// admission decision, and short-circuit behavior agree with an
    /// independent reference model after **every** operation of **any**
    /// generated sequence, and the breaker never panics. This single
    /// equivalence pins all the state-machine clauses at once: opening after
    /// exactly `failure_threshold` consecutive eligible failures, `Open`
    /// short-circuiting without invoking the op, the post-cooldown single
    /// `HalfOpen` probe, probe success→`Closed`(reset) / eligible-failure→
    /// `Open`(cooldown restart), and only-eligible-categories-count.
    /// **Validates: Requirements 50.2, 50.3, 50.4**
    #[test]
    fn state_machine_matches_reference_model_over_any_sequence(
        threshold in 1u32..=6,
        cooldown_ms in 1u64..=200,
        ops in proptest::collection::vec(arb_op(300), 1..=80),
    ) {
        let clock = Arc::new(ManualClock::new());
        let breaker = CircuitBreaker::with_clock(
            BreakerKey::Store("realdebrid".into()),
            BreakerConfig::new(threshold, Duration::from_millis(cooldown_ms)),
            clock.clone(),
        );
        let mut model = Model::new(threshold, cooldown_ms);

        // Sanity: both start Closed.
        prop_assert_eq!(breaker.state(), BreakerState::Closed);
        prop_assert_eq!(model.state, BreakerState::Closed);

        for op in ops {
            match op {
                Op::Advance(ms) => {
                    clock.advance(Duration::from_millis(ms));
                    model.advance(ms);
                    // Advancing the clock alone never mutates the stored state
                    // (the Open → HalfOpen transition is lazy, in `acquire`).
                }
                Op::Call(outcome) => {
                    // The model decides admission first (it also performs the
                    // lazy Open → HalfOpen transition), then the real breaker.
                    let (admitted_model, is_probe_model) = model.acquire();
                    let permit = breaker.acquire();

                    prop_assert_eq!(
                        permit.is_ok(), admitted_model,
                        "admission must agree with the model (state {:?})",
                        model.state,
                    );

                    match permit {
                        Ok(permit) => {
                            // Admitted ⇒ the guarded op "runs"; record outcome.
                            match outcome {
                                Outcome::Success => {
                                    model.on_success(is_probe_model);
                                    breaker.on_success(permit);
                                }
                                Outcome::Failure(category) => {
                                    let eligible = is_eligible(category);
                                    model.on_failure(is_probe_model, eligible);
                                    breaker.on_failure(permit, &error_for(category));
                                }
                            }
                        }
                        Err(err) => {
                            // Short-circuit ⇒ the op is NOT invoked (it is gated
                            // entirely by `acquire`) and the error carries the
                            // circuit-open marker (Req 50.2). A store breaker
                            // surfaces UpstreamUnavailable.
                            prop_assert!(
                                err.circuit_open,
                                "a short-circuit must carry the circuit_open marker",
                            );
                            prop_assert_eq!(
                                err.category, ErrorCategory::UpstreamUnavailable,
                                "a store breaker short-circuit is UpstreamUnavailable",
                            );
                        }
                    }
                }
            }

            // The load-bearing invariant: observed state matches the model
            // after every prefix, and is always a valid variant (never panics).
            prop_assert_eq!(
                breaker.state(), model.state,
                "observed state diverged from the reference model",
            );
        }
    }

    /// Feature: stream-flow, Property 51 — opening is **exact**: from `Closed`,
    /// `n` consecutive trip-eligible failures leave the breaker `Closed` for
    /// every `n < failure_threshold` and flip it to `Open` at exactly
    /// `n == failure_threshold`; interleaved non-eligible failures never count
    /// (they are ignored), so they do not bring the open forward.
    /// **Validates: Requirements 50.2**
    #[test]
    fn opens_after_exactly_failure_threshold_eligible_failures(
        threshold in 1u32..=8,
        // A noise category applied just before the eligible run: either an
        // eligible one (which DOES count) or a non-eligible one (ignored).
        noise_eligible in any::<bool>(),
        noise_count in 0u32..=4,
    ) {
        let clock = Arc::new(ManualClock::new());
        let breaker = CircuitBreaker::with_clock(
            BreakerKey::Store("torbox".into()),
            // Long cooldown so no Open → HalfOpen transition interferes.
            BreakerConfig::new(threshold, Duration::from_secs(3600)),
            clock,
        );

        // Apply `noise_count` non-eligible failures: these are ignored and must
        // not move the breaker toward opening, whatever their number.
        if !noise_eligible {
            for _ in 0..noise_count {
                let permit = breaker.acquire().expect("closed admits");
                breaker.on_failure(permit, &AppError::not_found("ignored"));
            }
            prop_assert_eq!(
                breaker.state(), BreakerState::Closed,
                "non-eligible failures must never open the breaker",
            );
        }

        // Now drive eligible failures one at a time; the breaker must stay
        // Closed until exactly the threshold-th failure flips it to Open.
        for n in 1..=threshold {
            prop_assert_eq!(
                breaker.state(), BreakerState::Closed,
                "must still be Closed before the {}th eligible failure", n,
            );
            let permit = breaker.acquire().expect("closed admits");
            breaker.on_failure(permit, &AppError::upstream_unavailable("trip"));
            let expected = if n < threshold {
                BreakerState::Closed
            } else {
                BreakerState::Open
            };
            prop_assert_eq!(
                breaker.state(), expected,
                "after {} of {} eligible failures the state is wrong", n, threshold,
            );
        }
    }

    /// Feature: stream-flow, Property 51 (selection clause) — for any configured
    /// order of per-store breaker states, [`select_available`] returns the
    /// **first** store whose breaker is not `Open` (an `Open` breaker is removed
    /// from rotation; a `HalfOpen` breaker, admitting a recovery probe, stays in
    /// rotation), or a typed `UpstreamUnavailable` + `circuit_open` error when
    /// every breaker is `Open` (or the set is empty).
    /// **Validates: Requirements 50.3, 50.4**
    #[test]
    fn breaker_aware_selection_picks_first_non_open_or_errors(
        states in proptest::collection::vec(arb_breaker_state(), 0..=6),
    ) {
        let breakers: Vec<CircuitBreaker> = states
            .iter()
            .enumerate()
            .map(|(i, &state)| breaker_in_state(format!("store-{i}"), state))
            .collect();

        // Independently compute the expected winner: the first non-Open index.
        let expected_index = states.iter().position(|&s| s != BreakerState::Open);

        match (select_available(&breakers), expected_index) {
            (Ok(chosen), Some(i)) => {
                prop_assert_eq!(
                    chosen.key().label(), format!("store-{i}"),
                    "selection must return the first non-Open store in order",
                );
            }
            (Err(err), None) => {
                // All Open (or empty) ⇒ the whole set is unavailable.
                prop_assert_eq!(
                    err.category, ErrorCategory::UpstreamUnavailable,
                    "all-open selection must surface UpstreamUnavailable",
                );
                prop_assert!(
                    err.circuit_open,
                    "all-open selection error must carry the circuit_open marker",
                );
            }
            (Ok(chosen), None) => prop_assert!(
                false,
                "selection returned {:?} but every breaker was Open",
                chosen.key().label(),
            ),
            (Err(_), Some(i)) => prop_assert!(
                false,
                "selection errored but store-{} was selectable", i,
            ),
        }
    }
}
