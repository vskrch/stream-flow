//! Hedged / speculative requests (`resilience::hedge`) — Req 37.1, 37.7, 20.2, 50.9.
//!
//! For **latency-critical, idempotent** reads the system can issue a *hedged*
//! (speculative) request: start the primary candidate, and if it has not
//! responded within a tail-latency [`delay`](HedgeConfig::delay), start the
//! next candidate in parallel, take the **first success**, and cancel the rest.
//! This trims p99 latency toward the 2 s Stremio start budget (Req 37.1)
//! without waiting for a hard failure (design: Resilience → Pattern 4 "Hedged /
//! Speculative Requests").
//!
//! ## Where hedging is allowed
//!
//! * `CheckMagnet` across **cache tiers** (in-memory `Local_Cache` → SQLite
//!   `magnet_cache` → live store) — the faster tier usually wins and the live
//!   call is only paid on a miss/lag.
//! * `GenerateLink` across **distinct configured stores** (the existing
//!   fallback chain), turned from purely-on-failure into tail-latency-triggered
//!   when [`HedgeConfig::enabled`] (Req 37.7, 20.2).
//!
//! ## Hard guardrails (debrid-rate-limit safety)
//!
//! * **Never hedge against the *same* store.** Two concurrent `GenerateLink`
//!   calls to one debrid account waste a charged call and risk account flags,
//!   so [`hedged`] never issues two **concurrent** attempts that share a
//!   [`CandidateId`] (Req 20.2). Hedging is only ever across *different*
//!   stores or across *cache tiers*.
//! * A candidate whose store is **in cooldown** or whose **breaker is `Open`**
//!   is skipped (never hedged to). Eligibility is expressed by a per-candidate
//!   predicate ([`Candidate::with_eligibility`]) so this combinator integrates
//!   cleanly with both the [`CircuitBreaker`](crate::resilience::breaker)
//!   (use [`Candidate::guarded_by`]) and the per-store cooldown (a closure over
//!   the store's cooldown clock) without taking a hard dependency on either.
//! * Bounded by [`max_in_flight`](HedgeConfig::max_in_flight): never more than
//!   that many candidates run concurrently, so the feature can never amplify
//!   load unboundedly.
//! * **Disabled by default** ([`HedgeConfig::default`] → `enabled = false`).
//!   When disabled the combinator degrades to the plain sequential
//!   fallback chain (one attempt at a time, next on failure) so it is always
//!   debrid-safe unless an operator opts in.
//!
//! ## Outcome
//!
//! The combinator resolves with the value of the **first candidate to
//! succeed**, dropping (cancelling) every other still-in-flight candidate. If
//! every eligible candidate fails it returns the **last** (most-recent) typed
//! [`AppError`]; if no candidate was ever eligible it returns a typed
//! `UpstreamUnavailable`. It never panics and never returns an untyped error
//! (Req 50.9).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};

use crate::errors::AppError;
use crate::resilience::breaker::{BreakerState, CircuitBreaker};

/// Tail-latency hedging configuration (design: Pattern 4 `HedgeConfig`).
///
/// **Default OFF** — `enabled = false` — so the conservative, debrid-safe
/// sequential fallback is used unless an operator explicitly opts in.
#[derive(Clone, Debug)]
pub struct HedgeConfig {
    /// Master switch. Config-gated; **default OFF** (Req 20.2 safety).
    pub enabled: bool,
    /// Tail-latency delay: fire the next candidate after this long with no
    /// result (e.g. `300ms`).
    pub delay: Duration,
    /// Cap on simultaneous hedged attempts (e.g. `2`). Clamped to `>= 1`
    /// internally so the combinator always makes progress.
    pub max_in_flight: usize,
}

impl Default for HedgeConfig {
    /// Disabled, `300ms` tail delay, at most `2` in flight — the design's
    /// example, but **off** until opted in.
    fn default() -> Self {
        Self {
            enabled: false,
            delay: Duration::from_millis(300),
            max_in_flight: 2,
        }
    }
}

impl HedgeConfig {
    /// An **enabled** policy with the given tail `delay` and `max_in_flight`
    /// (opt-in; mostly for tests and explicit operator configuration).
    pub fn enabled(delay: Duration, max_in_flight: usize) -> Self {
        Self {
            enabled: true,
            delay,
            max_in_flight,
        }
    }

    /// A **disabled** policy: plain sequential fallback, no speculative
    /// parallelism (the safe default).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

/// Identifies a hedge candidate for the **never-hedge-the-same-store**
/// guardrail (Req 20.2).
///
/// Two candidates that share a `CandidateId` are never run **concurrently**;
/// hedging is only ever across distinct stores or distinct cache tiers. The
/// `Store` variant carries the store identifier as a [`String`] (it migrates to
/// the `StoreName` newtype when the store module lands); `Tier` labels a
/// cache tier (e.g. `"local"`, `"sqlite"`, `"live"`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CandidateId {
    /// A debrid store, by store identifier — the dedup key for Req 20.2.
    Store(String),
    /// A cache tier, by label.
    Tier(String),
}

impl CandidateId {
    /// A `Store` candidate id.
    pub fn store(name: impl Into<String>) -> Self {
        CandidateId::Store(name.into())
    }

    /// A cache-`Tier` candidate id.
    pub fn tier(label: impl Into<String>) -> Self {
        CandidateId::Tier(label.into())
    }

    /// A human-readable label for messages/metrics.
    pub fn label(&self) -> &str {
        match self {
            CandidateId::Store(s) => s,
            CandidateId::Tier(t) => t,
        }
    }
}

/// The boxed future a candidate's operation produces.
type OpFuture<T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send>>;
/// The boxed, single-shot factory that *starts* a candidate's operation. It is
/// only invoked when (and if) the candidate is actually launched, so a skipped
/// candidate's operation is **never started** (Req 20.2 — no wasted call).
type OpFn<T> = Box<dyn FnOnce() -> OpFuture<T> + Send>;
/// The eligibility predicate, evaluated at launch time.
type EligibleFn = Box<dyn Fn() -> bool + Send>;

/// One distinct hedge candidate (design: Pattern 4 `Candidate<T>`).
///
/// Built from an identity ([`CandidateId`]) and a single-shot async operation,
/// with an optional eligibility predicate that gates whether the candidate may
/// be launched (used to skip `Open` breakers / cooled-down stores).
pub struct Candidate<T> {
    id: CandidateId,
    eligible: EligibleFn,
    op: OpFn<T>,
}

impl<T> Candidate<T> {
    /// Build a candidate identified by `id` whose operation is started by
    /// calling `op`. The candidate is eligible by default; attach
    /// [`with_eligibility`](Self::with_eligibility) or
    /// [`guarded_by`](Self::guarded_by) to gate it.
    ///
    /// `op` is a [`FnOnce`] so a charged debrid call is constructed **lazily**
    /// — it is only invoked if the candidate is actually launched.
    pub fn new<F, Fut>(id: CandidateId, op: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, AppError>> + Send + 'static,
    {
        Self {
            id,
            eligible: Box::new(|| true),
            op: Box::new(move || Box::pin(op())),
        }
    }

    /// The candidate's dedup identity.
    pub fn id(&self) -> &CandidateId {
        &self.id
    }

    /// Gate this candidate on an arbitrary predicate, evaluated at launch time.
    ///
    /// Returning `false` skips the candidate entirely (its operation is never
    /// started). This is the integration seam for the per-store cooldown
    /// ("store in cooldown" → predicate returns `false`) and for any other
    /// eligibility rule, so the combinator never takes a hard dependency on a
    /// concrete cooldown type.
    pub fn with_eligibility<E>(mut self, eligible: E) -> Self
    where
        E: Fn() -> bool + Send + 'static,
    {
        self.eligible = Box::new(eligible);
        self
    }

    /// Gate this candidate on a [`CircuitBreaker`]: eligible **iff** the
    /// breaker is not [`Open`](BreakerState::Open) (Req 50.2 — a candidate
    /// whose breaker is open is never hedged to).
    ///
    /// Coded defensively against the breaker's public API
    /// ([`state`](CircuitBreaker::state)) so it composes with the breaker
    /// authored in task 6.2 without reaching into its internals. Compose with
    /// a cooldown via [`with_eligibility`](Self::with_eligibility) when both
    /// gates apply.
    pub fn guarded_by(self, breaker: CircuitBreaker) -> Self {
        self.with_eligibility(move || breaker.state() != BreakerState::Open)
    }

    /// Is this candidate currently eligible to launch?
    fn is_eligible(&self) -> bool {
        (self.eligible)()
    }
}

/// The future kept in the in-flight set: yields the finishing candidate's id
/// alongside its result so the dedup set can be updated.
type RunningFuture<T> = Pin<Box<dyn Future<Output = (CandidateId, Result<T, AppError>)> + Send>>;

/// Run `candidates` as a hedged/speculative request (design: Pattern 4
/// `hedged`).
///
/// Behavior:
/// 1. Launch the first eligible candidate.
/// 2. **When enabled**, each [`cfg.delay`](HedgeConfig::delay) with no result,
///    launch the next eligible candidate — up to
///    [`cfg.max_in_flight`](HedgeConfig::max_in_flight) concurrently. A
///    candidate that **fails** immediately triggers the next launch regardless
///    of the timer (the fallback chain). **When disabled**, no timer fires and
///    at most one candidate runs at a time (pure sequential fallback).
/// 3. The first `Ok` wins; the function returns and the remaining in-flight
///    candidate futures are dropped — i.e. **cancelled** (Req 37.1).
/// 4. If every eligible candidate fails, the **last** typed [`AppError`] is
///    returned; if none was eligible, a typed `UpstreamUnavailable` is
///    returned (Req 50.9).
///
/// Guardrails: never launches a candidate whose id is already in flight
/// (Req 20.2), never exceeds `max_in_flight` concurrent attempts, and never
/// starts the operation of a skipped/ineligible candidate.
pub async fn hedged<T>(cfg: &HedgeConfig, candidates: Vec<Candidate<T>>) -> Result<T, AppError>
where
    T: Send + 'static,
{
    if candidates.is_empty() {
        return Err(AppError::upstream_unavailable(
            "hedged: no candidates provided",
        ));
    }

    // Effective bounds: when disabled we degrade to a strictly sequential
    // fallback (at most one in flight, no speculative timer). The `.max(1)`
    // guards against a misconfigured `max_in_flight = 0` deadlocking the run.
    let eff_max = if cfg.enabled {
        cfg.max_in_flight.max(1)
    } else {
        1
    };
    let use_timer = cfg.enabled;

    let mut pending: VecDeque<Candidate<T>> = candidates.into();
    let mut in_flight: Vec<CandidateId> = Vec::new();
    let mut running: FuturesUnordered<RunningFuture<T>> = FuturesUnordered::new();
    let mut last_err: Option<AppError> = None;

    loop {
        // Ensure progress: if nothing is in flight, try to launch a candidate.
        // If none can be launched (all skipped/ineligible/exhausted), we are
        // done — surface the last error (or a typed "no eligible" error).
        if running.is_empty() && !launch_one(&mut pending, &mut in_flight, &mut running, eff_max) {
            return Err(last_err.unwrap_or_else(|| {
                AppError::upstream_unavailable("hedged: no eligible candidate")
            }));
        }

        // Arm the speculative timer only when enabled, there is room for
        // another concurrent attempt, and a launchable candidate remains.
        let timer_armed =
            use_timer && running.len() < eff_max && has_launchable(&pending, &in_flight);

        // Wait for the next event. Decisions that mutate `running` are taken
        // *after* the select resolves so its borrow of `running` is released.
        let step = tokio::select! {
            Some(done) = running.next() => Step::Completed(done),
            _ = tokio::time::sleep(cfg.delay), if timer_armed => Step::Timer,
        };

        match step {
            Step::Completed((id, result)) => {
                remove_in_flight(&mut in_flight, &id);
                match result {
                    // First success wins; returning drops `running`, cancelling
                    // every other still-in-flight candidate (Req 37.1).
                    Ok(value) => return Ok(value),
                    // On failure, immediately try the next candidate (fallback).
                    Err(err) => {
                        last_err = Some(err);
                        launch_one(&mut pending, &mut in_flight, &mut running, eff_max);
                    }
                }
            }
            // Tail-latency elapsed with no result: fire the next candidate.
            Step::Timer => {
                launch_one(&mut pending, &mut in_flight, &mut running, eff_max);
            }
        }
    }
}

/// One iteration's resolved event.
enum Step<T> {
    /// A candidate finished (with its id so the in-flight set can be updated).
    Completed((CandidateId, Result<T, AppError>)),
    /// The speculative tail-latency timer elapsed.
    Timer,
}

/// Launch the next launchable candidate, returning whether one was launched.
///
/// A candidate is launchable iff it is **eligible** and its id is **not
/// already in flight**. Ineligible candidates are dropped permanently (their
/// operation is never started); a candidate whose id is currently in flight is
/// left in the queue (deferred) so it can run later — sequentially — once the
/// in-flight attempt on that store completes, upholding the
/// never-two-concurrent-attempts-per-store guardrail (Req 20.2). Respects the
/// `max` concurrency bound (Req 50.9).
fn launch_one<T>(
    pending: &mut VecDeque<Candidate<T>>,
    in_flight: &mut Vec<CandidateId>,
    running: &mut FuturesUnordered<RunningFuture<T>>,
    max: usize,
) -> bool
where
    T: Send + 'static,
{
    if running.len() >= max {
        return false;
    }

    let mut i = 0;
    while i < pending.len() {
        if !pending[i].is_eligible() {
            // Skip ineligible candidates permanently (e.g. Open breaker /
            // store in cooldown) — never start their operation.
            pending.remove(i);
            continue; // VecDeque shifted left; re-examine index `i`.
        }
        if in_flight.contains(&pending[i].id) {
            // Same-store attempt already running — defer to avoid a concurrent
            // duplicate (Req 20.2); examine the next candidate.
            i += 1;
            continue;
        }

        // Launchable: start it and record the in-flight id.
        let cand = pending.remove(i).expect("index in bounds");
        let id = cand.id.clone();
        in_flight.push(id.clone());
        let fut = (cand.op)();
        running.push(Box::pin(async move { (id, fut.await) }));
        return true;
    }

    false
}

/// Whether any pending candidate could be launched *right now* (eligible and
/// not a concurrent duplicate of an in-flight attempt). Used to decide whether
/// arming the speculative timer can make progress.
fn has_launchable<T>(pending: &VecDeque<Candidate<T>>, in_flight: &[CandidateId]) -> bool {
    pending
        .iter()
        .any(|c| c.is_eligible() && !in_flight.contains(&c.id))
}

/// Remove `id` from the in-flight set once its attempt has resolved.
fn remove_in_flight(in_flight: &mut Vec<CandidateId>, id: &CandidateId) {
    if let Some(pos) = in_flight.iter().position(|x| x == id) {
        in_flight.swap_remove(pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resilience::breaker::{BreakerConfig, BreakerKey};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    // -- Concurrency / lifecycle tracker -----------------------------------

    /// Records, for the candidate operations launched during a hedged run:
    /// peak global concurrency, peak per-store concurrency, and which
    /// candidates started, completed, or were cancelled (dropped before
    /// completion). Shared across candidates via [`Arc`].
    #[derive(Default)]
    struct Tracker {
        concurrent: AtomicUsize,
        peak: AtomicUsize,
        per_store: Mutex<HashMap<String, usize>>,
        per_store_peak: Mutex<HashMap<String, usize>>,
        started: Mutex<Vec<String>>,
        completed: Mutex<Vec<String>>,
        cancelled: Mutex<Vec<String>>,
    }

    impl Tracker {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn enter(&self, label: &str, store: &str) {
            let now = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            self.started.lock().unwrap().push(label.to_string());

            let mut per = self.per_store.lock().unwrap();
            let c = per.entry(store.to_string()).or_insert(0);
            *c += 1;
            let c = *c;
            drop(per);
            let mut peak = self.per_store_peak.lock().unwrap();
            let p = peak.entry(store.to_string()).or_insert(0);
            if c > *p {
                *p = c;
            }
        }

        fn leave(&self, store: &str) {
            self.concurrent.fetch_sub(1, Ordering::SeqCst);
            let mut per = self.per_store.lock().unwrap();
            if let Some(c) = per.get_mut(store) {
                *c = c.saturating_sub(1);
            }
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }

        fn per_store_peak(&self, store: &str) -> usize {
            *self.per_store_peak.lock().unwrap().get(store).unwrap_or(&0)
        }

        fn started(&self) -> Vec<String> {
            self.started.lock().unwrap().clone()
        }

        fn completed(&self) -> Vec<String> {
            self.completed.lock().unwrap().clone()
        }

        fn cancelled(&self) -> Vec<String> {
            self.cancelled.lock().unwrap().clone()
        }
    }

    /// RAII guard for a running candidate operation. Constructing it records
    /// "started" and bumps concurrency; dropping it decrements concurrency and,
    /// unless [`complete`](ActiveGuard::complete) was called, records the
    /// candidate as **cancelled** (its future was dropped mid-flight).
    struct ActiveGuard {
        tracker: Arc<Tracker>,
        label: String,
        store: String,
        completed: bool,
    }

    impl ActiveGuard {
        fn enter(tracker: &Arc<Tracker>, label: &str, store: &str) -> Self {
            tracker.enter(label, store);
            Self {
                tracker: tracker.clone(),
                label: label.to_string(),
                store: store.to_string(),
                completed: false,
            }
        }

        fn complete(&mut self) {
            self.completed = true;
            self.tracker.completed.lock().unwrap().push(self.label.clone());
        }
    }

    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.tracker.leave(&self.store);
            if !self.completed {
                self.tracker.cancelled.lock().unwrap().push(self.label.clone());
            }
        }
    }

    fn store_name(id: &CandidateId) -> String {
        id.label().to_string()
    }

    /// Build a candidate that, when launched, sleeps `latency` then resolves to
    /// `outcome`, tracking its lifecycle in `tracker`.
    fn tracked(
        tracker: &Arc<Tracker>,
        id: CandidateId,
        latency: Duration,
        outcome: Result<&'static str, AppError>,
    ) -> Candidate<&'static str> {
        let tracker = tracker.clone();
        let label = id.label().to_string();
        let store = store_name(&id);
        Candidate::new(id, move || async move {
            let mut guard = ActiveGuard::enter(&tracker, &label, &store);
            tokio::time::sleep(latency).await;
            guard.complete();
            outcome
        })
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    // -- default OFF --------------------------------------------------------

    /// The default configuration is **disabled** (Req 20.2 — opt-in only).
    #[test]
    fn default_config_is_off() {
        let cfg = HedgeConfig::default();
        assert!(!cfg.enabled, "hedging must be OFF by default");
        assert_eq!(cfg.max_in_flight, 2);
    }

    /// When disabled, the combinator runs **at most one** candidate at a time:
    /// even though the primary is slow and a later candidate is fast, no
    /// speculative parallelism occurs — the primary alone wins.
    #[tokio::test(start_paused = true)]
    async fn disabled_is_sequential_no_speculation() {
        let t = Tracker::new();
        let cfg = HedgeConfig::disabled();
        let result = hedged(
            &cfg,
            vec![
                tracked(&t, CandidateId::store("primary"), ms(1000), Ok("primary")),
                tracked(&t, CandidateId::store("secondary"), ms(10), Ok("secondary")),
            ],
        )
        .await;

        assert_eq!(result.unwrap(), "primary");
        assert_eq!(t.peak(), 1, "disabled must never run two at once");
        // The fast secondary was never launched because the primary succeeded.
        assert_eq!(t.started(), vec!["primary"]);
    }

    /// When disabled, a failing primary still falls back to the next candidate
    /// sequentially (the existing fallback chain), one at a time.
    #[tokio::test(start_paused = true)]
    async fn disabled_falls_back_sequentially_on_failure() {
        let t = Tracker::new();
        let cfg = HedgeConfig::disabled();
        let result = hedged(
            &cfg,
            vec![
                tracked(
                    &t,
                    CandidateId::store("primary"),
                    ms(50),
                    Err(AppError::upstream_unavailable("primary down")),
                ),
                tracked(&t, CandidateId::store("secondary"), ms(50), Ok("secondary")),
            ],
        )
        .await;

        assert_eq!(result.unwrap(), "secondary");
        assert_eq!(t.peak(), 1, "fallback runs strictly sequentially");
        assert_eq!(t.started(), vec!["primary", "secondary"]);
    }

    // -- first success wins, cancels the rest ------------------------------

    /// With hedging enabled, a slow primary triggers a speculative second
    /// candidate after `delay`; the faster candidate's success wins and the
    /// still-in-flight primary is cancelled (Req 37.1).
    #[tokio::test(start_paused = true)]
    async fn first_success_wins_and_cancels_the_rest() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(300), 2);
        let result = hedged(
            &cfg,
            vec![
                tracked(&t, CandidateId::store("slow"), ms(5000), Ok("slow")),
                tracked(&t, CandidateId::store("fast"), ms(100), Ok("fast")),
            ],
        )
        .await;

        assert_eq!(result.unwrap(), "fast", "first success wins");
        // Both were launched (the slow one fired, then the fast hedge at +300ms).
        let mut started = t.started();
        started.sort();
        assert_eq!(started, vec!["fast", "slow"]);
        // The fast one completed; the slow one was cancelled when fast won.
        assert_eq!(t.completed(), vec!["fast"]);
        assert_eq!(t.cancelled(), vec!["slow"]);
    }

    /// A primary that responds **before** the tail-latency delay wins outright
    /// and no hedge is ever fired (the common, debrid-safe fast path).
    #[tokio::test(start_paused = true)]
    async fn fast_primary_never_fires_a_hedge() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(300), 3);
        let result = hedged(
            &cfg,
            vec![
                tracked(&t, CandidateId::store("primary"), ms(50), Ok("primary")),
                tracked(&t, CandidateId::store("backup1"), ms(50), Ok("backup1")),
                tracked(&t, CandidateId::store("backup2"), ms(50), Ok("backup2")),
            ],
        )
        .await;

        assert_eq!(result.unwrap(), "primary");
        assert_eq!(t.started(), vec!["primary"], "no speculative hedge fired");
    }

    // -- max_in_flight bound -----------------------------------------------

    /// Concurrency never exceeds `max_in_flight`, even with many slow
    /// candidates and a short tail delay (Req 50.9).
    #[tokio::test(start_paused = true)]
    async fn never_exceeds_max_in_flight() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(50), 2);
        // Five candidates, all slow and all failing, so the run keeps launching
        // up to the bound until everything is exhausted.
        let candidates: Vec<_> = (0..5)
            .map(|i| {
                tracked(
                    &t,
                    CandidateId::store(format!("s{i}")),
                    ms(1000),
                    Err(AppError::upstream_unavailable("down")),
                )
            })
            .collect();

        let result = hedged(&cfg, candidates).await;
        assert!(result.is_err(), "all candidates fail");
        assert!(t.peak() <= 2, "peak concurrency {} exceeded max 2", t.peak());
        assert!(t.peak() >= 2, "hedging should reach the bound, got {}", t.peak());
    }

    // -- never two concurrent attempts on the same store -------------------

    /// Two candidates that share a store id are never run concurrently: the
    /// second is deferred until the first completes, then runs sequentially
    /// (Req 20.2 — never waste a charged duplicate call against one account).
    #[tokio::test(start_paused = true)]
    async fn never_two_concurrent_attempts_on_the_same_store() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(100), 2);
        let result = hedged(
            &cfg,
            vec![
                tracked(
                    &t,
                    CandidateId::store("realdebrid"),
                    ms(1000),
                    Err(AppError::upstream_unavailable("first attempt failed")),
                ),
                tracked(&t, CandidateId::store("realdebrid"), ms(100), Ok("second")),
            ],
        )
        .await;

        assert_eq!(result.unwrap(), "second");
        assert_eq!(
            t.per_store_peak("realdebrid"),
            1,
            "the same store must never have two concurrent attempts",
        );
        assert_eq!(t.peak(), 1, "deduped same-store candidates run sequentially");
        // Both attempts ran, but one after the other.
        assert_eq!(t.started(), vec!["realdebrid", "realdebrid"]);
    }

    /// Distinct stores *are* allowed to run concurrently (the whole point of
    /// hedging) — the same-store guardrail must not over-constrain.
    #[tokio::test(start_paused = true)]
    async fn distinct_stores_may_run_concurrently() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(100), 2);
        let result = hedged(
            &cfg,
            vec![
                tracked(&t, CandidateId::store("alpha"), ms(5000), Ok("alpha")),
                tracked(&t, CandidateId::store("beta"), ms(5000), Ok("beta")),
            ],
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(t.peak(), 2, "distinct stores hedge concurrently");
    }

    // -- skip cooldown / open-breaker candidates ---------------------------

    /// A candidate gated ineligible (e.g. store in cooldown) is skipped
    /// entirely — its operation is never started — and an eligible candidate
    /// serves the request (Req 20.2 guardrail).
    #[tokio::test(start_paused = true)]
    async fn skips_ineligible_cooldown_candidate() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(100), 2);
        let result = hedged(
            &cfg,
            vec![
                tracked(&t, CandidateId::store("cooling"), ms(50), Ok("cooling"))
                    .with_eligibility(|| false), // store in cooldown
                tracked(&t, CandidateId::store("healthy"), ms(50), Ok("healthy")),
            ],
        )
        .await;

        assert_eq!(result.unwrap(), "healthy");
        assert_eq!(
            t.started(),
            vec!["healthy"],
            "the cooled-down candidate's operation must never start",
        );
    }

    /// A candidate whose [`CircuitBreaker`] is `Open` is skipped via
    /// [`Candidate::guarded_by`] (Req 50.2) and a healthy store serves the
    /// request.
    #[tokio::test(start_paused = true)]
    async fn skips_open_breaker_candidate() {
        let t = Tracker::new();

        // Force a store breaker Open: one trip-eligible failure at threshold 1.
        let breaker = CircuitBreaker::new(
            BreakerKey::Store("tripped".into()),
            BreakerConfig::new(1, Duration::from_secs(60)),
        );
        let permit = breaker.acquire().expect("closed admits");
        breaker.on_failure(permit, &AppError::upstream_unavailable("boom"));
        assert_eq!(breaker.state(), BreakerState::Open);

        let cfg = HedgeConfig::enabled(ms(100), 2);
        let result = hedged(
            &cfg,
            vec![
                tracked(&t, CandidateId::store("tripped"), ms(50), Ok("tripped"))
                    .guarded_by(breaker.clone()),
                tracked(&t, CandidateId::store("healthy"), ms(50), Ok("healthy")),
            ],
        )
        .await;

        assert_eq!(result.unwrap(), "healthy");
        assert_eq!(t.started(), vec!["healthy"], "open-breaker candidate skipped");
    }

    // -- typed error only when all fail ------------------------------------

    /// When every eligible candidate fails, the combinator returns the **last**
    /// (most-recent) typed [`AppError`] — never an untyped error (Req 50.9).
    #[tokio::test(start_paused = true)]
    async fn returns_last_typed_error_when_all_fail() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(50), 1); // sequential so order is deterministic
        let result = hedged(
            &cfg,
            vec![
                tracked(
                    &t,
                    CandidateId::store("first"),
                    ms(10),
                    Err(AppError::hoster_unavailable("first")),
                ),
                tracked(
                    &t,
                    CandidateId::store("second"),
                    ms(10),
                    Err(AppError::not_found("second")),
                ),
            ],
        )
        .await;

        let err = result.expect_err("all candidates failed");
        assert_eq!(err.category, crate::errors::ErrorCategory::NotFound);
        assert_eq!(err.message, "second", "the last error is surfaced");
    }

    /// When **no** candidate is eligible, a typed `UpstreamUnavailable` is
    /// returned and no operation is ever started.
    #[tokio::test(start_paused = true)]
    async fn returns_typed_error_when_no_candidate_eligible() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(50), 2);
        let result = hedged(
            &cfg,
            vec![
                tracked(&t, CandidateId::store("a"), ms(50), Ok("a")).with_eligibility(|| false),
                tracked(&t, CandidateId::store("b"), ms(50), Ok("b")).with_eligibility(|| false),
            ],
        )
        .await;

        let err = result.expect_err("no eligible candidate");
        assert_eq!(err.category, crate::errors::ErrorCategory::UpstreamUnavailable);
        assert!(t.started().is_empty(), "no operation started");
    }

    /// An empty candidate list yields a typed error rather than a panic.
    #[tokio::test(start_paused = true)]
    async fn empty_candidate_list_returns_typed_error() {
        let cfg = HedgeConfig::enabled(ms(50), 2);
        let result: Result<&str, AppError> = hedged(&cfg, Vec::new()).await;
        let err = result.expect_err("no candidates");
        assert_eq!(err.category, crate::errors::ErrorCategory::UpstreamUnavailable);
    }

    /// A mid-list failure hands off to a later success across distinct stores
    /// (the hedged fallback chain), returning the successful value.
    #[tokio::test(start_paused = true)]
    async fn failure_then_later_success_returns_ok() {
        let t = Tracker::new();
        let cfg = HedgeConfig::enabled(ms(300), 2);
        let result = hedged(
            &cfg,
            vec![
                tracked(
                    &t,
                    CandidateId::store("primary"),
                    ms(20),
                    Err(AppError::upstream_unavailable("primary failed fast")),
                ),
                tracked(&t, CandidateId::store("backup"), ms(50), Ok("backup")),
            ],
        )
        .await;

        assert_eq!(result.unwrap(), "backup");
    }
}
