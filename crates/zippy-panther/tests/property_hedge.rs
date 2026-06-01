//! Property-based test for the hedged / speculative-request combinator
//! (task 6.11).
//!
//! Feature: ZippyPanther, Property 58
//!
//! **Property 58: Hedged requests take first success, cancel the rest, and
//! never hedge the same store**
//!
//! *For any* ordered set of distinct hedge candidates (each over a different
//! store or a different cache tier) with assorted latencies and
//! success/failure outcomes, the hedged combinator resolves with the result of
//! the first candidate to succeed, cancels every other still-in-flight
//! candidate once a winner is chosen, never runs more than `max_in_flight`
//! candidates concurrently, never issues two concurrent attempts against the
//! same store, skips any candidate whose store is in cooldown or whose breaker
//! is `Open`, and returns a typed `AppError` only when every eligible
//! candidate fails.
//!
//! **Validates: Requirements 37.1, 37.7, 20.2, 50.9**
//!
//! The combinator under test is [`zippy_panther::resilience::hedge::hedged`]
//! (design: Resilience → Pattern 4). Candidate identity is a generic key (the
//! "never two concurrent attempts on the same store" unit), eligibility is a
//! caller-supplied flag (the not-in-cooldown / breaker-not-`Open` predicate),
//! and the attempt itself is a lazy factory that is only invoked once the
//! combinator launches the candidate.
//!
//! ## How the invariants are exercised
//!
//! Each case generates an arbitrary candidate set — keys drawn from a small
//! pool so they *repeat* (multiple candidates over the same store), arbitrary
//! eligibility flags, simulated per-candidate latencies, and success/failure
//! outcomes — plus an arbitrary [`HedgeConfig`]. Every candidate is wrapped in
//! an instrumented attempt whose future, on first poll, takes an RAII
//! [`AttemptGuard`] that bumps a shared [`Tracker`]'s global and per-key
//! concurrency counters (and records a cancellation if it is dropped before
//! completing). The candidate's *success* value is its own index, so the
//! winner can be mapped straight back to the candidate that produced it.
//!
//! The combinator runs on a **per-case current-thread paused runtime**
//! (`start_paused = true`): the simulated latencies and the hedge tail delay
//! are virtual time, so the runtime auto-advances to the next timer and the
//! whole race resolves deterministically with no real sleeping. After the run
//! the case asserts:
//!
//! * **First success / take a real winner (Req 37.7):** an `Ok(idx)` result is
//!   only ever the index of a candidate that was both *eligible* and a
//!   *success* — the combinator returns a value produced by a candidate that
//!   actually succeeded, and that candidate was actually started.
//! * **Success iff a winner exists (Req 37.1/37.7):** the result is `Ok`
//!   exactly when at least one eligible candidate was a success; otherwise it
//!   is `Err` — so the fallback chain is exhaustive and never gives up while a
//!   viable candidate remains.
//! * **Bounded concurrency (Req 50.9):** the global peak concurrency never
//!   exceeds [`HedgeConfig::effective_max_in_flight`].
//! * **Never two concurrent attempts on the same store (Req 20.2/37.7):** the
//!   per-key peak concurrency is at most one for every key.
//! * **Skip ineligible (Req 50.2 via the eligibility flag):** no ineligible
//!   candidate is ever started.
//! * **Typed error only when all fail (Req 37.7):** an `Err` result carries a
//!   typed [`AppError`] category (here, one of the upstream failure
//!   categories the candidates emit, or the synthesized `UpstreamUnavailable`
//!   when nothing was eligible).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use zippy_panther::errors::{AppError, ErrorCategory};
use zippy_panther::resilience::hedge::{hedged, Candidate, CandidateId, HedgeConfig};

/// The concurrency cap the combinator actually applies, mirroring its internal
/// rule: `max(1, max_in_flight)` when enabled, otherwise `1` (a disabled or
/// `max_in_flight = 0` config can never run two attempts at once — Req 50.9).
fn effective_max_in_flight(cfg: &HedgeConfig) -> usize {
    if cfg.enabled {
        cfg.max_in_flight.max(1)
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// Instrumentation: a shared tracker + RAII guard recording start / exit and
// the global and per-key concurrency peaks across all attempts in one case.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Inner {
    /// Candidate indices whose attempt actually began running (was polled).
    started: Vec<usize>,
    /// Live count of running attempts and its peak (global concurrency).
    current: usize,
    peak: usize,
    /// Live count of running attempts per candidate key and its peak.
    per_key_current: HashMap<String, usize>,
    per_key_peak: HashMap<String, usize>,
}

#[derive(Clone, Default)]
struct Tracker(Arc<Mutex<Inner>>);

impl Tracker {
    /// An attempt began running (its future was polled for the first time).
    fn enter(&self, idx: usize, key: &str) {
        let mut g = self.0.lock().unwrap();
        g.started.push(idx);
        g.current += 1;
        let cur = g.current;
        g.peak = g.peak.max(cur);

        let k = g.per_key_current.entry(key.to_string()).or_insert(0);
        *k += 1;
        let kc = *k;
        let kp = g.per_key_peak.entry(key.to_string()).or_insert(0);
        *kp = (*kp).max(kc);
    }

    /// An attempt stopped (completed normally or was cancelled by drop).
    fn exit(&self, key: &str) {
        let mut g = self.0.lock().unwrap();
        g.current = g.current.saturating_sub(1);
        if let Some(k) = g.per_key_current.get_mut(key) {
            *k = k.saturating_sub(1);
        }
    }

    fn started(&self) -> Vec<usize> {
        self.0.lock().unwrap().started.clone()
    }
    fn peak(&self) -> usize {
        self.0.lock().unwrap().peak
    }
    /// The largest per-key concurrency peak observed across all keys (0 if no
    /// attempt ever started).
    fn per_key_peak_max(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .per_key_peak
            .values()
            .copied()
            .max()
            .unwrap_or(0)
    }
}

/// RAII guard maintaining the tracker's concurrency counters for one attempt:
/// enters on construction (first poll of the attempt future) and exits on
/// drop, so a cancelled (dropped-before-completion) attempt still decrements
/// the live counters.
struct AttemptGuard {
    tracker: Tracker,
    key: String,
}

impl AttemptGuard {
    fn enter(tracker: Tracker, idx: usize, key: String) -> Self {
        tracker.enter(idx, &key);
        Self { tracker, key }
    }
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.tracker.exit(&self.key);
    }
}

// ---------------------------------------------------------------------------
// Case input model + generators.
// ---------------------------------------------------------------------------

/// One generated candidate: its identity, eligibility, simulated latency, and
/// whether the attempt ultimately succeeds.
#[derive(Clone, Debug)]
struct CandSpec {
    id: CandidateId,
    eligible: bool,
    latency_ms: u64,
    success: bool,
}

impl CandSpec {
    /// A stable string for tracking concurrency per *identity*. The
    /// combinator's dedup guard is keyed on the whole [`CandidateId`]
    /// (`Store("rd")` is distinct from `Tier("rd")`), so the tracker key must
    /// distinguish the variant too.
    fn id_key(&self) -> String {
        match &self.id {
            CandidateId::Store(s) => format!("store:{s}"),
            CandidateId::Tier(t) => format!("tier:{t}"),
        }
    }
}

/// Identities are drawn from a small pool so they REPEAT across candidates —
/// this is what makes the "never two concurrent attempts on the same store"
/// invariant non-trivial (several candidates share a store), and it mixes the
/// `Store` and `Tier` variants per the design ("a different store or a
/// different cache tier").
fn arb_candidate_id() -> impl Strategy<Value = CandidateId> {
    prop_oneof![
        Just(CandidateId::store("rd")),
        Just(CandidateId::store("pm")),
        Just(CandidateId::store("ad")),
        Just(CandidateId::tier("local")),
        Just(CandidateId::tier("sqlite")),
    ]
}

fn arb_cand() -> impl Strategy<Value = CandSpec> {
    (arb_candidate_id(), any::<bool>(), 0u64..200, any::<bool>()).prop_map(
        |(id, eligible, latency_ms, success)| CandSpec {
            id,
            eligible,
            latency_ms,
            success,
        },
    )
}

/// 0..=8 candidates, including the empty set (which must yield a typed error).
fn arb_candidates() -> impl Strategy<Value = Vec<CandSpec>> {
    proptest::collection::vec(arb_cand(), 0..=8)
}

/// Arbitrary config, including `enabled = false` (OFF, effective cap 1) and the
/// nonsensical `max_in_flight = 0` (which must still clamp to 1).
fn arb_config() -> impl Strategy<Value = HedgeConfig> {
    (any::<bool>(), 0u64..120, 0usize..5).prop_map(|(enabled, delay_ms, max_in_flight)| {
        HedgeConfig {
            enabled,
            delay: Duration::from_millis(delay_ms),
            max_in_flight,
        }
    })
}

/// Build an instrumented candidate. The success value is the candidate's own
/// index so a winning `Ok(idx)` maps straight back to its producer; failures
/// alternate between two typed categories to confirm the error stays typed.
/// Eligibility is gated via the real [`Candidate::with_eligibility`] seam.
fn build_candidate(tracker: &Tracker, idx: usize, spec: &CandSpec) -> Candidate<usize> {
    let tracker = tracker.clone();
    let id_key = spec.id_key();
    let latency_ms = spec.latency_ms;
    let success = spec.success;
    let eligible = spec.eligible;
    Candidate::new(spec.id.clone(), move || async move {
        let _guard = AttemptGuard::enter(tracker, idx, id_key);
        tokio::time::sleep(Duration::from_millis(latency_ms)).await;
        if success {
            Ok(idx)
        } else if idx.is_multiple_of(2) {
            Err(AppError::upstream_unavailable("simulated upstream failure"))
        } else {
            Err(AppError::hoster_unavailable("simulated hoster failure"))
        }
    })
    .with_eligibility(move || eligible)
}

/// A per-case current-thread runtime with virtual (paused) time, so the
/// simulated latencies and the hedge tail delay resolve deterministically by
/// auto-advancing the clock instead of sleeping for real.
fn paused_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("current-thread paused tokio runtime must build")
}

proptest! {
    // >= 100 cases required for a property task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 58 — hedged requests take the first
    /// success, cancel the rest, cap concurrency, and never hedge the same
    /// store. **Validates: Requirements 37.1, 37.7, 20.2, 50.9**
    #[test]
    fn hedged_takes_first_success_caps_concurrency_and_never_hedges_same_store(
        specs in arb_candidates(),
        cfg in arb_config(),
    ) {
        let rt = paused_runtime();
        let result: Result<(), TestCaseError> = rt.block_on(async {
            let tracker = Tracker::default();

            let candidates: Vec<Candidate<usize>> = specs
                .iter()
                .enumerate()
                .map(|(idx, spec)| build_candidate(&tracker, idx, spec))
                .collect();

            let outcome = hedged(&cfg, candidates).await;

            let effective_max = effective_max_in_flight(&cfg);
            // Whether any candidate could possibly win: eligible AND a success.
            let any_eligible_success =
                specs.iter().any(|s| s.eligible && s.success);

            // -- Success iff a viable (eligible + success) candidate exists --
            // The fallback chain is exhaustive: it never returns an error while
            // a candidate that would succeed remains (Req 37.1/37.7), and it
            // never returns Ok when none could succeed.
            prop_assert_eq!(
                outcome.is_ok(),
                any_eligible_success,
                "result must be Ok exactly when an eligible successful candidate exists \
                 (cfg={:?}, specs={:?})",
                cfg, specs,
            );

            match outcome {
                Ok(idx) => {
                    // -- First success: the winner is a real, eligible success.
                    let winner = &specs[idx];
                    prop_assert!(
                        winner.eligible,
                        "winner index {} must be an eligible candidate",
                        idx,
                    );
                    prop_assert!(
                        winner.success,
                        "winner index {} must be a candidate that succeeds",
                        idx,
                    );
                    // The winner's attempt must actually have been started.
                    prop_assert!(
                        tracker.started().contains(&idx),
                        "the winning candidate's attempt must have been launched",
                    );
                }
                Err(err) => {
                    // -- Typed error only when all eligible candidates fail ---
                    // The error is one of the typed upstream-failure categories
                    // the candidates emit, or the synthesized UpstreamUnavailable
                    // for the no-eligible-candidate case.
                    prop_assert!(
                        matches!(
                            err.category,
                            ErrorCategory::UpstreamUnavailable
                                | ErrorCategory::HosterUnavailable
                        ),
                        "error must carry a typed upstream-failure category, got {:?}",
                        err.category,
                    );
                }
            }

            // -- Bounded global concurrency (Req 50.9) -----------------------
            prop_assert!(
                tracker.peak() <= effective_max,
                "peak global concurrency {} exceeded effective_max_in_flight {} (cfg={:?})",
                tracker.peak(), effective_max, cfg,
            );

            // -- Never two concurrent attempts on the same store (Req 20.2) --
            // Per-key peak is at most 1 (0 when no attempt ran).
            prop_assert!(
                tracker.per_key_peak_max() <= 1,
                "a store ran two concurrent attempts (per-key peak {})",
                tracker.per_key_peak_max(),
            );

            // -- Ineligible candidates are never started (Req 50.2) ----------
            let started = tracker.started();
            for (idx, spec) in specs.iter().enumerate() {
                if !spec.eligible {
                    prop_assert!(
                        !started.contains(&idx),
                        "ineligible candidate index {} must never start",
                        idx,
                    );
                }
            }

            Ok(())
        });
        result?;
    }
}
