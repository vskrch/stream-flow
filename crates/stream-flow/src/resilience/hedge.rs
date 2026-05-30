//! Hedged / speculative requests (`resilience::hedge`) — Req 37.1, 37.7, 20.2, 50.9.
//!
//! For **latency-critical, idempotent** reads the system can issue a *hedged*
//! (speculative) request: start the primary candidate, and if it has not
//! responded within a tail-latency [`delay`](HedgeConfig::delay), start the
//! next candidate **in parallel**, take the first success, and cancel the
//! rest. This trims p99 latency toward the 2 s Stremio start budget (Req 37.1)
//! without waiting for a hard failure (design: Resilience → Pattern 4 "Hedged
//! / Speculative Requests").
//!
//! ## What this combinator guarantees (design: Pattern 4; Property 58)
//!
//! For any ordered set of candidates with assorted latencies / outcomes,
//! [`hedged`]:
//!
//! * resolves with the result of the **first candidate to succeed**, and
//! * **cancels** every other still-in-flight candidate once a winner is chosen
//!   (Req 37.7), and
//! * never runs more than [`max_in_flight`](HedgeConfig::max_in_flight)
//!   candidates concurrently (Req 50.9), and
//! * never issues two concurrent attempts against the **same candidate key**
//!   (e.g. the same debrid store — Req 20.2/37.7: two concurrent
//!   `GenerateLink` calls to one account waste a charged call and risk account
//!   flags), and
//! * **skips** any candidate flagged ineligible (store in cooldown or breaker
//!   `Open` — Req 50.2 via the caller-supplied eligibility flag), and
//! * returns a typed [`AppError`] **only when every eligible candidate fails**.
//!
//! ## Decoupling (task 6.5 note)
//!
//! Pattern 4 is developed in parallel with the [`CircuitBreaker`]
//! (`resilience::breaker`, task 6.2). To avoid a hard dependency on it, the
//! combinator does **not** import `BreakerKey` or the breaker at all:
//!
//! * Candidate **identity** is a generic [`String`] key the caller supplies
//!   (a `StoreName`, a cache-tier id, …). It is the unit of the
//!   "never two concurrent attempts on the same candidate" guard.
//! * Candidate **eligibility** ("not in cooldown / breaker not `Open`") is a
//!   plain `bool` the caller computes (e.g.
//!   `!breaker.is_open(key) && !store.in_cooldown(key)`) when it builds the
//!   [`Candidate`]. The combinator simply skips ineligible candidates.
//!
//! When the breaker lands, callers wire it in at the call site; this module
//! needs no change.
//!
//! ## Default OFF
//!
//! Hedging is **disabled by default** ([`HedgeConfig::default`]). While
//! disabled the combinator still works as the existing on-failure fallback
//! chain — it just never runs more than **one** attempt concurrently
//! (`effective_max_in_flight() == 1`), so it can never amplify load against a
//! debrid account. Enabling it and setting `max_in_flight > 1` turns the
//! purely-on-failure fallback into a tail-latency-triggered hedge.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};

use crate::errors::AppError;

/// Configuration for the [`hedged`] combinator (design: Pattern 4).
///
/// Conservative, debrid-safe defaults: **OFF**, a 300 ms tail delay, and a cap
/// of 2 simultaneous attempts when enabled.
#[derive(Clone, Debug)]
pub struct HedgeConfig {
    /// Config-gated master switch. **Default `false`** (OFF): while disabled
    /// the combinator runs at most one attempt at a time
    /// ([`effective_max_in_flight`](Self::effective_max_in_flight) clamps to
    /// `1`), behaving as the plain on-failure fallback chain.
    pub enabled: bool,
    /// Tail-latency delay: with no result yet, the next candidate is launched
    /// after this much time (e.g. `300ms`). Only consulted when hedging can
    /// actually add concurrency (enabled, under the cap, a launchable
    /// candidate remains).
    pub delay: Duration,
    /// Hard cap on simultaneous hedged attempts (e.g. `2`). Bounds the load
    /// the feature can ever add. Effective only when [`enabled`](Self::enabled)
    /// — see [`effective_max_in_flight`](Self::effective_max_in_flight).
    pub max_in_flight: usize,
}

impl Default for HedgeConfig {
    /// **OFF** by default (Req 37.1/20.2 debrid-safety): `enabled = false`,
    /// `delay = 300ms`, `max_in_flight = 2`. Because `enabled` is `false`, the
    /// *effective* concurrency cap is `1` — only one attempt ever runs until an
    /// operator opts in.
    fn default() -> Self {
        Self {
            enabled: false,
            delay: Duration::from_millis(300),
            max_in_flight: 2,
        }
    }
}

impl HedgeConfig {
    /// The concurrency cap actually applied by [`hedged`].
    ///
    /// `max(1, max_in_flight)` when [`enabled`](Self::enabled), else `1`. So a
    /// disabled config — or a nonsensical `max_in_flight == 0` — can never run
    /// two attempts at once (Req 50.9, debrid-rate-limit safety).
    pub fn effective_max_in_flight(&self) -> usize {
        if self.enabled {
            self.max_in_flight.max(1)
        } else {
            1
        }
    }
}

/// A future producing one attempt's typed result.
type BoxAttempt<T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send>>;

/// A lazily-constructed attempt: the work is **not** started until the
/// combinator decides to launch the candidate, so a candidate that never wins
/// the tail-delay race never even allocates its future (and never touches the
/// upstream).
type AttemptFactory<T> = Box<dyn FnOnce() -> BoxAttempt<T> + Send>;

/// One distinct hedge candidate: a different store, or a different cache tier
/// (design: Pattern 4 — "Hedge across DISTINCT candidates only").
///
/// Carries everything the combinator needs without depending on the breaker:
/// a generic identity [`key`](Candidate::key) (the "never two concurrent
/// attempts on the same candidate" unit), an
/// [`eligible`](Candidate::eligible) flag (the caller's
/// not-in-cooldown / breaker-not-`Open` predicate), and a lazy attempt
/// factory.
pub struct Candidate<T> {
    /// Identity of the underlying resource (e.g. a `StoreName` or a cache-tier
    /// id). Two candidates sharing a key are never run concurrently.
    key: String,
    /// `true` when the candidate may be attempted. `false` means the caller's
    /// predicate rejected it (store in cooldown or breaker `Open`); the
    /// combinator skips it entirely (Req 50.2).
    eligible: bool,
    /// Builds the attempt future on demand, the moment the candidate is
    /// launched.
    make_attempt: AttemptFactory<T>,
}

impl<T> Candidate<T> {
    /// Build a candidate from its `key`, an `eligible` flag, and an async
    /// attempt factory.
    ///
    /// `make_attempt` is a [`FnOnce`] returning the attempt future; it is
    /// invoked **only if and when** the combinator launches this candidate, so
    /// no upstream work happens for a candidate that never gets its turn.
    pub fn new<F, Fut>(key: impl Into<String>, eligible: bool, make_attempt: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, AppError>> + Send + 'static,
    {
        Self {
            key: key.into(),
            eligible,
            make_attempt: Box::new(move || Box::pin(make_attempt())),
        }
    }

    /// This candidate's identity key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Whether this candidate is currently eligible to be attempted.
    pub fn is_eligible(&self) -> bool {
        self.eligible
    }
}

/// The set of attempts currently running, each tagged with its candidate key
/// so a completion can release that key for (sequential) reuse.
type InFlight<T> = FuturesUnordered<Pin<Box<dyn Future<Output = (String, Result<T, AppError>)> + Send>>>;

/// Race speculative attempts across `candidates`, returning the first success
/// and cancelling the rest (design: Resilience → Pattern 4; Req 37.1, 37.7,
/// 20.2, 50.9).
///
/// Behaviour (see the module docs for the full contract):
/// 1. ineligible candidates (cooldown / breaker `Open`) are skipped up front;
/// 2. the first eligible candidate (the primary) is launched immediately;
/// 3. while enabled and under [`HedgeConfig::effective_max_in_flight`], each
///    [`HedgeConfig::delay`] with no success launches the next distinct-key
///    candidate in parallel;
/// 4. a failed attempt is replaced **immediately** (no extra delay) by the
///    next distinct-key candidate, preserving the fallback-chain behaviour;
/// 5. the first `Ok` wins — the function returns it and drops every other
///    in-flight attempt, cancelling them;
/// 6. two candidates that share a key never run concurrently — the second
///    waits until the first frees the key;
/// 7. if every eligible candidate fails, the most recent typed [`AppError`] is
///    returned; if there were no eligible candidates at all, a typed
///    `UpstreamUnavailable` error is returned.
///
/// Cancellation is by drop: the winning return value drops the
/// [`FuturesUnordered`] holding the losing attempts, so their futures stop
/// being polled and run their destructors. Callers therefore get
/// cancel-on-drop semantics for free as long as the attempt futures are
/// drop-safe (they should be — they wrap an [`OutboundClient`] request).
pub async fn hedged<T>(cfg: &HedgeConfig, candidates: Vec<Candidate<T>>) -> Result<T, AppError>
where
    T: Send + 'static,
{
    let effective_max = cfg.effective_max_in_flight();

    // 1. Skip ineligible candidates entirely (Req 50.2) — they are never
    //    launched and never counted toward concurrency.
    let mut pending: VecDeque<Candidate<T>> = candidates.into_iter().filter(|c| c.eligible).collect();

    let mut in_flight: InFlight<T> = FuturesUnordered::new();
    let mut in_flight_keys: HashSet<String> = HashSet::new();
    // The most recent failure — returned if (and only if) every eligible
    // candidate fails (Req 37.7 typed error).
    let mut last_err: Option<AppError> = None;

    loop {
        // Nothing running: launch the next launchable candidate, or finish.
        if in_flight.is_empty() && !launch_one(&mut pending, &mut in_flight, &mut in_flight_keys, effective_max) {
            // No eligible candidate launched anything: every eligible
            // candidate has already failed (return its error), or there were
            // none at all (synthesize a typed error).
            return Err(last_err.unwrap_or_else(|| {
                AppError::upstream_unavailable("no eligible hedge candidates")
            }));
        }

        // May we add a *speculative* parallel attempt right now? Only when
        // enabled, under the cap, and a distinct-key candidate is waiting.
        let can_hedge = cfg.enabled
            && in_flight.len() < effective_max
            && has_launchable_pending(&pending, &in_flight_keys);

        if can_hedge {
            // Take whichever happens first: an attempt resolving, or the tail
            // delay elapsing (which fires off the next candidate in parallel).
            tokio::select! {
                done = in_flight.next() => {
                    if let ControlFlow::Win(value) =
                        on_complete(done, &mut in_flight_keys, &mut last_err,
                                    &mut pending, &mut in_flight, effective_max)
                    {
                        return Ok(value);
                    }
                }
                _ = tokio::time::sleep(cfg.delay) => {
                    // Tail latency exceeded with no result: hedge the next one.
                    launch_one(&mut pending, &mut in_flight, &mut in_flight_keys, effective_max);
                }
            }
        } else {
            // At the cap (or hedging disabled / nothing more to launch): just
            // wait for the next attempt to resolve.
            let done = in_flight.next().await;
            if let ControlFlow::Win(value) =
                on_complete(done, &mut in_flight_keys, &mut last_err,
                            &mut pending, &mut in_flight, effective_max)
            {
                return Ok(value);
            }
        }
    }
}

/// Outcome of folding one completed attempt back into the loop state.
enum ControlFlow<T> {
    /// A candidate succeeded — `hedged` should return this value (and drop the
    /// rest, cancelling them).
    Win(T),
    /// No winner yet; keep racing.
    Continue,
}

/// Handle one resolved attempt: on success, signal a [`ControlFlow::Win`]; on
/// failure, free the candidate's key, record the error, and **immediately**
/// relaunch the next launchable candidate (so a failure does not wait out the
/// tail delay — it behaves as the fallback chain).
fn on_complete<T>(
    done: Option<(String, Result<T, AppError>)>,
    in_flight_keys: &mut HashSet<String>,
    last_err: &mut Option<AppError>,
    pending: &mut VecDeque<Candidate<T>>,
    in_flight: &mut InFlight<T>,
    effective_max: usize,
) -> ControlFlow<T>
where
    T: Send + 'static,
{
    match done {
        Some((key, Ok(value))) => {
            // First success wins. `in_flight` is dropped when `hedged`
            // returns, cancelling every other still-running attempt.
            let _ = key;
            ControlFlow::Win(value)
        }
        Some((key, Err(err))) => {
            in_flight_keys.remove(&key);
            *last_err = Some(err);
            // Replace the failed attempt right away (no extra delay).
            launch_one(pending, in_flight, in_flight_keys, effective_max);
            ControlFlow::Continue
        }
        // `in_flight` was empty — only reachable transiently; nothing to do.
        None => ControlFlow::Continue,
    }
}

/// Is there a pending candidate we could launch right now — i.e. one whose key
/// is **not** already in flight? Used to decide whether a tail-delay timer
/// would have anything to launch (avoids arming a pointless timer / busy spin).
fn has_launchable_pending<T>(pending: &VecDeque<Candidate<T>>, in_flight_keys: &HashSet<String>) -> bool {
    pending.iter().any(|c| !in_flight_keys.contains(&c.key))
}

/// Launch the first pending candidate whose key is not already in flight,
/// provided we are under `effective_max`.
///
/// Returns `true` if a candidate was launched. The "key not already in flight"
/// rule is what enforces **never two concurrent attempts on the same store**
/// (Req 20.2/37.7): a same-key candidate is left in the queue until the
/// in-flight attempt for that key completes and frees it.
fn launch_one<T>(
    pending: &mut VecDeque<Candidate<T>>,
    in_flight: &mut InFlight<T>,
    in_flight_keys: &mut HashSet<String>,
    effective_max: usize,
) -> bool
where
    T: Send + 'static,
{
    if in_flight.len() >= effective_max {
        return false;
    }
    let Some(idx) = pending.iter().position(|c| !in_flight_keys.contains(&c.key)) else {
        return false;
    };
    let candidate = pending.remove(idx).expect("index from position() is valid");
    let key = candidate.key;
    let make_attempt = candidate.make_attempt;
    in_flight_keys.insert(key.clone());
    in_flight.push(Box::pin(async move {
        let result = make_attempt().await;
        (key, result)
    }));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // -- Test instrumentation ------------------------------------------------

    /// Records, across all attempts, the launch order, cancellations, and the
    /// global / per-key concurrency peaks — so the tests can assert the
    /// combinator's invariants directly.
    #[derive(Default)]
    struct Inner {
        started: Vec<String>,
        cancelled: Vec<String>,
        current: usize,
        peak: usize,
        per_key_current: HashMap<String, usize>,
        per_key_peak: HashMap<String, usize>,
    }

    #[derive(Clone, Default)]
    struct Tracker(Arc<Mutex<Inner>>);

    impl Tracker {
        /// An attempt began running (its future was polled for the first time).
        fn enter(&self, key: &str) {
            let mut g = self.0.lock().unwrap();
            g.started.push(key.to_string());
            g.current += 1;
            let cur = g.current;
            g.peak = g.peak.max(cur);
            let k = g.per_key_current.entry(key.to_string()).or_insert(0);
            *k += 1;
            let kc = *k;
            let kp = g.per_key_peak.entry(key.to_string()).or_insert(0);
            *kp = (*kp).max(kc);
        }

        /// An attempt stopped (completed or was cancelled by drop).
        fn exit(&self, key: &str, completed: bool) {
            let mut g = self.0.lock().unwrap();
            g.current = g.current.saturating_sub(1);
            if let Some(k) = g.per_key_current.get_mut(key) {
                *k = k.saturating_sub(1);
            }
            if !completed {
                g.cancelled.push(key.to_string());
            }
        }

        fn started(&self) -> Vec<String> {
            self.0.lock().unwrap().started.clone()
        }
        fn cancelled(&self) -> Vec<String> {
            self.0.lock().unwrap().cancelled.clone()
        }
        fn peak(&self) -> usize {
            self.0.lock().unwrap().peak
        }
        fn per_key_peak_max(&self) -> usize {
            self.0.lock().unwrap().per_key_peak.values().copied().max().unwrap_or(0)
        }
    }

    /// RAII guard that maintains the tracker's concurrency counters and records
    /// a cancellation when dropped before the attempt completed.
    struct AttemptGuard {
        tracker: Tracker,
        key: String,
        completed: bool,
    }

    impl AttemptGuard {
        fn enter(tracker: Tracker, key: String) -> Self {
            tracker.enter(&key);
            Self { tracker, key, completed: false }
        }
    }

    impl Drop for AttemptGuard {
        fn drop(&mut self) {
            self.tracker.exit(&self.key, self.completed);
        }
    }

    /// Build an instrumented candidate: identity `key`, eligibility flag, a
    /// simulated `latency_ms`, and a final `outcome`.
    fn cand(
        tracker: &Tracker,
        key: &str,
        eligible: bool,
        latency_ms: u64,
        outcome: Result<u32, AppError>,
    ) -> Candidate<u32> {
        let tracker = tracker.clone();
        let key_owned = key.to_string();
        Candidate::new(key, eligible, move || async move {
            let mut guard = AttemptGuard::enter(tracker, key_owned);
            tokio::time::sleep(Duration::from_millis(latency_ms)).await;
            guard.completed = true;
            outcome
        })
    }

    fn ok(v: u32) -> Result<u32, AppError> {
        Ok(v)
    }
    fn fail(msg: &str) -> Result<u32, AppError> {
        Err(AppError::upstream_unavailable(msg))
    }

    fn on() -> HedgeConfig {
        HedgeConfig { enabled: true, delay: Duration::from_millis(50), max_in_flight: 2 }
    }

    // -- effective cap -------------------------------------------------------

    /// The default config is OFF, so the effective concurrency cap is 1.
    #[test]
    fn default_config_is_off_and_effective_cap_is_one() {
        let cfg = HedgeConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.effective_max_in_flight(), 1);
    }

    /// `enabled` gates the cap; a disabled config or `max_in_flight == 0` can
    /// never run two attempts at once.
    #[test]
    fn effective_cap_clamps_to_one_when_disabled_or_zero() {
        assert_eq!(
            HedgeConfig { enabled: false, delay: Duration::ZERO, max_in_flight: 5 }
                .effective_max_in_flight(),
            1,
        );
        assert_eq!(
            HedgeConfig { enabled: true, delay: Duration::ZERO, max_in_flight: 0 }
                .effective_max_in_flight(),
            1,
        );
        assert_eq!(
            HedgeConfig { enabled: true, delay: Duration::ZERO, max_in_flight: 3 }
                .effective_max_in_flight(),
            3,
        );
    }

    // -- first success wins / cancel the rest --------------------------------

    /// Among concurrent attempts, the **first to succeed** wins and its value
    /// is returned (Req 37.7).
    #[tokio::test(start_paused = true)]
    async fn first_success_wins() {
        let t = Tracker::default();
        // Primary is slow; the hedge (fired after the 50ms delay) is fast and
        // succeeds first.
        let candidates = vec![
            cand(&t, "rd", true, 1000, ok(1)),
            cand(&t, "pm", true, 10, ok(2)),
        ];
        let result = hedged(&on(), candidates).await;
        assert_eq!(result.unwrap(), 2, "the first candidate to SUCCEED wins");
    }

    /// Once a winner is chosen, every other still-in-flight attempt is
    /// cancelled (dropped before completing) — Req 37.7.
    #[tokio::test(start_paused = true)]
    async fn winner_cancels_the_rest() {
        let t = Tracker::default();
        // Both launch (primary slow → 50ms delay fires → hedge launched), then
        // the fast hedge wins and the slow primary is cancelled.
        let candidates = vec![
            cand(&t, "rd", true, 5_000, ok(1)),
            cand(&t, "pm", true, 10, ok(2)),
        ];
        let result = hedged(&on(), candidates).await;
        assert_eq!(result.unwrap(), 2);
        assert_eq!(t.started(), vec!["rd", "pm"], "both attempts were launched");
        assert_eq!(t.cancelled(), vec!["rd"], "the losing primary was cancelled");
    }

    /// A fast primary returns before the tail delay, so the hedge is **never
    /// launched** (speculation only pays off on tail latency) — Req 37.1.
    #[tokio::test(start_paused = true)]
    async fn fast_primary_never_launches_a_hedge() {
        let t = Tracker::default();
        let candidates = vec![
            cand(&t, "rd", true, 5, ok(7)), // resolves well before the 50ms delay
            cand(&t, "pm", true, 5, ok(8)),
        ];
        let result = hedged(&on(), candidates).await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(t.started(), vec!["rd"], "the hedge candidate must not start");
    }

    // -- max_in_flight bound -------------------------------------------------

    /// No more than `effective_max_in_flight` attempts ever run concurrently
    /// (Req 50.9).
    #[tokio::test(start_paused = true)]
    async fn never_exceeds_max_in_flight() {
        let t = Tracker::default();
        let cfg = HedgeConfig { enabled: true, delay: Duration::from_millis(20), max_in_flight: 2 };
        // Five slow distinct candidates that all eventually fail except the
        // last; the combinator keeps launching but must cap concurrency at 2.
        let candidates = vec![
            cand(&t, "a", true, 1000, fail("a")),
            cand(&t, "b", true, 1000, fail("b")),
            cand(&t, "c", true, 1000, fail("c")),
            cand(&t, "d", true, 1000, fail("d")),
            cand(&t, "e", true, 30, ok(42)),
        ];
        let result = hedged(&cfg, candidates).await;
        assert_eq!(result.unwrap(), 42);
        assert!(t.peak() <= 2, "peak concurrency {} exceeded max_in_flight 2", t.peak());
    }

    // -- never two concurrent attempts on the same store ---------------------

    /// Candidates that share a key (same store) are never run concurrently;
    /// they fall back sequentially (Req 20.2, 37.7).
    #[tokio::test(start_paused = true)]
    async fn never_two_concurrent_attempts_on_same_store() {
        let t = Tracker::default();
        let cfg = HedgeConfig { enabled: true, delay: Duration::from_millis(10), max_in_flight: 3 };
        // Three candidates, ALL the same store "rd": the first two fail, the
        // third succeeds. Even with max_in_flight = 3 they must run one at a
        // time because they share a key.
        let candidates = vec![
            cand(&t, "rd", true, 100, fail("rd-1")),
            cand(&t, "rd", true, 100, fail("rd-2")),
            cand(&t, "rd", true, 100, ok(99)),
        ];
        let result = hedged(&cfg, candidates).await;
        assert_eq!(result.unwrap(), 99);
        assert_eq!(t.per_key_peak_max(), 1, "the same store must never run two attempts at once");
        assert_eq!(t.peak(), 1, "with one shared key, global concurrency stays at 1");
    }

    /// With a mix of stores, distinct stores hedge in parallel but the shared
    /// store still never doubles up.
    #[tokio::test(start_paused = true)]
    async fn distinct_stores_hedge_but_shared_key_does_not_double() {
        let t = Tracker::default();
        let cfg = HedgeConfig { enabled: true, delay: Duration::from_millis(10), max_in_flight: 3 };
        let candidates = vec![
            cand(&t, "rd", true, 1000, fail("rd-1")),
            cand(&t, "rd", true, 1000, fail("rd-2")), // same store as primary
            cand(&t, "pm", true, 1000, ok(5)),
        ];
        let result = hedged(&cfg, candidates).await;
        assert_eq!(result.unwrap(), 5);
        assert_eq!(t.per_key_peak_max(), 1, "no store ever runs two concurrent attempts");
    }

    // -- skip cooldown / open-breaker candidates -----------------------------

    /// Ineligible candidates (cooldown / breaker `Open`) are skipped: their
    /// attempt is never started (Req 50.2).
    #[tokio::test(start_paused = true)]
    async fn skips_ineligible_candidates() {
        let t = Tracker::default();
        let candidates = vec![
            cand(&t, "rd", false, 5, ok(1)), // in cooldown / breaker open → skip
            cand(&t, "pm", true, 5, ok(2)),
        ];
        let result = hedged(&on(), candidates).await;
        assert_eq!(result.unwrap(), 2);
        assert!(!t.started().contains(&"rd".to_string()), "ineligible candidate must not start");
        assert_eq!(t.started(), vec!["pm"]);
    }

    /// When every candidate is ineligible, the combinator returns a typed
    /// error without launching anything.
    #[tokio::test(start_paused = true)]
    async fn all_ineligible_returns_typed_error_without_launching() {
        let t = Tracker::default();
        let candidates = vec![
            cand(&t, "rd", false, 5, ok(1)),
            cand(&t, "pm", false, 5, ok(2)),
        ];
        let err = hedged(&on(), candidates).await.unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::UpstreamUnavailable);
        assert!(t.started().is_empty(), "no ineligible candidate may start");
    }

    /// An empty candidate list yields a typed error.
    #[tokio::test(start_paused = true)]
    async fn empty_candidates_returns_typed_error() {
        let err = hedged::<u32>(&on(), vec![]).await.unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::UpstreamUnavailable);
    }

    // -- typed error only when all fail --------------------------------------

    /// When every eligible candidate fails, a typed [`AppError`] is returned
    /// (the most recent failure) — Req 37.7.
    #[tokio::test(start_paused = true)]
    async fn typed_error_when_all_fail() {
        let t = Tracker::default();
        let candidates = vec![
            cand(&t, "rd", true, 20, fail("rd down")),
            cand(&t, "pm", true, 20, Err(AppError::hoster_unavailable("pm down"))),
        ];
        let err = hedged(&on(), candidates).await.unwrap_err();
        // The taxonomy is preserved (typed, not a panic / generic).
        assert!(matches!(
            err.category,
            crate::errors::ErrorCategory::UpstreamUnavailable | crate::errors::ErrorCategory::HosterUnavailable
        ));
    }

    /// A failing primary falls back to the next candidate, which succeeds.
    #[tokio::test(start_paused = true)]
    async fn failing_primary_falls_back_to_success() {
        let t = Tracker::default();
        let candidates = vec![
            cand(&t, "rd", true, 10, fail("rd down")),
            cand(&t, "pm", true, 10, ok(3)),
        ];
        let result = hedged(&on(), candidates).await;
        assert_eq!(result.unwrap(), 3);
    }

    // -- default OFF behaviour -----------------------------------------------

    /// With the default (OFF) config, candidates run **sequentially** as the
    /// plain fallback chain — never two at once — Req 37.1/20.2 default-OFF.
    #[tokio::test(start_paused = true)]
    async fn default_off_runs_sequentially() {
        let t = Tracker::default();
        let candidates = vec![
            cand(&t, "rd", true, 1000, fail("rd down")),
            cand(&t, "pm", true, 10, ok(2)),
        ];
        let result = hedged(&HedgeConfig::default(), candidates).await;
        assert_eq!(result.unwrap(), 2, "falls back to the second candidate on failure");
        assert_eq!(t.peak(), 1, "OFF must never run two attempts concurrently");
        // The fallback only starts after the primary has finished (failed).
        assert_eq!(t.started(), vec!["rd", "pm"]);
    }

    /// With the default (OFF) config and a successful primary, the second
    /// candidate is never started — no speculation while disabled.
    #[tokio::test(start_paused = true)]
    async fn default_off_does_not_speculate_on_success() {
        let t = Tracker::default();
        let candidates = vec![
            cand(&t, "rd", true, 1000, ok(1)),
            cand(&t, "pm", true, 10, ok(2)),
        ];
        let result = hedged(&HedgeConfig::default(), candidates).await;
        assert_eq!(result.unwrap(), 1);
        assert_eq!(t.started(), vec!["rd"], "no hedge while disabled");
        assert_eq!(t.peak(), 1);
    }

    // -- single candidate ----------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn single_candidate_success() {
        let t = Tracker::default();
        let candidates = vec![cand(&t, "rd", true, 5, ok(11))];
        assert_eq!(hedged(&on(), candidates).await.unwrap(), 11);
    }

    #[tokio::test(start_paused = true)]
    async fn single_candidate_failure_is_typed() {
        let t = Tracker::default();
        let candidates = vec![cand(&t, "rd", true, 5, fail("only store down"))];
        let err = hedged(&on(), candidates).await.unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::UpstreamUnavailable);
    }
}
