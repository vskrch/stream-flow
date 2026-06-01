//! Circuit breaker (`resilience::breaker`) — Req 50.2, 50.3, 50.4.
//!
//! A [`CircuitBreaker`] is a per-dependency state machine that short-circuits a
//! failing upstream **before** any work is done, so a down dependency is not
//! hammered and a worker is never pinned on a known-bad origin (design:
//! Resilience → Pattern 1 "Circuit Breakers"; Components → `CircuitBreaker`).
//! One breaker is attached to every distinct upstream dependency — each debrid
//! store, each extractor host, each integration source, the Acestream engine,
//! Telegram, and Redis — keyed by [`BreakerKey`] and shared across worker tasks
//! (the `DashMap<BreakerKey, Arc<CircuitBreaker>>` on `AppState` lands with the
//! modules that call upstreams).
//!
//! ## State machine (Req 50.2, 50.4)
//!
//! ```text
//!         consecutive trip-eligible failures == failure_threshold
//!   Closed ───────────────────────────────────────────────► Open
//!     ▲  ▲                                                    │
//!     │  │ success / non-trip-eligible outcome resets count   │ cooldown elapsed
//!     │  └────────────────────────────────────────────────┐  ▼
//!     │ probe succeeds                                     HalfOpen
//!     └──────────────────────────────────────────────────────┤
//!                          probe fails (trip-eligible) → Open  │ (restart cooldown)
//! ```
//!
//! * **Closed** — calls run normally. Each **trip-eligible** failure increments
//!   a consecutive-failure counter; the breaker opens the instant the count
//!   reaches `failure_threshold`. A success **or** a non-trip-eligible outcome
//!   resets / leaves the counter so it never opens spuriously.
//! * **Open** — [`acquire`](CircuitBreaker::acquire) short-circuits with a
//!   `circuit_open` [`AppError`] **without invoking the operation** (Req 50.2).
//!   Store breakers thereby drive multi-store fallback (Req 50.3, 37.7).
//! * **HalfOpen** — after `cooldown` elapses, the next [`acquire`] admits a
//!   single trial probe (`half_open_max_probes`, default `1`); further acquires
//!   are rejected until the probe resolves. A probe **success** closes the
//!   breaker and resets the counter; a probe **failure** reopens it and
//!   restarts the cooldown (Req 50.4).
//!
//! ## What counts as a tripping failure (design: Pattern 1 classification)
//!
//! Only failures that indicate the **dependency itself** is unhealthy count
//! toward opening: [`UpstreamUnavailable`](ErrorCategory::UpstreamUnavailable)
//! and [`HosterUnavailable`](ErrorCategory::HosterUnavailable) (which fold in
//! connection resets, transport errors, timeouts, and `502/503/504`).
//! Client/semantic outcomes (`Unauthorized`, `Forbidden`, `InfringingContent`,
//! `BadRequest`, `NotFound`, `RangeNotSatisfiable`, `InvalidStoreName`,
//! `PaymentRequired`, `PayloadTooLarge`) are **not** counted — a bad token must
//! not open the breaker for everyone. `StoreLimitExceeded` and
//! `TooManyRequests` are also **not** counted: they are account/rate signals
//! handled by the per-store cooldown, not breaker health (design: reconciliation
//! with the per-store cooldown). Trip-eligibility is therefore **narrower** than
//! retryability ([`is_retryable`](ErrorCategory::is_retryable) includes
//! `TooManyRequests`; trip-eligibility does not).
//!
//! ## Adapters
//!
//! [`guarded`] wraps an async op in `acquire → run → record outcome` without
//! changing the op's signature. [`with_retry`] composes the
//! [`RetryPolicy`](crate::resilience::retry::RetryPolicy) (task 6.1) **inside**
//! the breaker: every attempt goes through [`guarded`], and a mid-retry breaker
//! trip short-circuits the remaining attempts so retries can never outlive a
//! tripped breaker (design: Pattern 2 "Composition with the circuit breaker and
//! deadline").
//!
//! ### Deadline composition (task 6.3)
//!
//! Following the design's full signature
//! `with_retry(policy, breaker, deadline, op)`, the request-scoped
//! [`Deadline`](crate::resilience::deadline::Deadline) is the **outermost**
//! bound: before each backoff sleep the loop checks the remaining budget and,
//! if the proposed backoff would not complete inside it, fails fast with a
//! deadline-exceeded [`AppError`] (via
//! [`into_deadline_exceeded`](crate::errors::AppError::into_deadline_exceeded))
//! rather than sleeping past the budget. Thus a retry storm can never overrun
//! the request deadline **or** a tripped breaker (design: Pattern 2 ↔ Pattern
//! 10).

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::errors::{AppError, ErrorCategory};
use crate::resilience::deadline::Deadline;
use crate::resilience::retry::RetryPolicy;

// ---------------------------------------------------------------------------
// Clock abstraction
// ---------------------------------------------------------------------------

/// A monotonic millisecond clock, abstracted so the breaker's `cooldown`
/// transitions (`Open → HalfOpen`) are **deterministically testable** with a
/// [`ManualClock`] (design: Components → `CircuitBreaker` holds a `clock`).
pub trait Clock: Send + Sync {
    /// Monotonic "now", in milliseconds, from an arbitrary fixed epoch.
    fn now_millis(&self) -> u64;
}

/// The production clock: monotonic milliseconds since the breaker was created,
/// derived from [`Instant`].
pub struct SystemClock {
    base: Instant,
}

impl SystemClock {
    /// Anchor the clock at "now".
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }
}

/// A manually-advanced clock for deterministic tests of the `cooldown`
/// transition. Shared via [`Arc`] so a test holds the handle and the breaker
/// reads through the same instance.
pub struct ManualClock {
    now_ms: AtomicU64,
}

impl ManualClock {
    /// Start at `t = 0`.
    pub fn new() -> Self {
        Self {
            now_ms: AtomicU64::new(0),
        }
    }

    /// Advance the clock by `delta`.
    pub fn advance(&self, delta: Duration) {
        self.now_ms
            .fetch_add(delta.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now_millis(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Keys, states, config
// ---------------------------------------------------------------------------

/// Identifies the upstream dependency a breaker guards (design: Pattern 1
/// `BreakerKey`).
///
/// The canonical design types `Store(StoreName)`; the `StoreName` newtype lands
/// with the store module, so the store variant carries the store identifier as
/// a [`String`] here and migrates to `StoreName` later.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum BreakerKey {
    /// A debrid store, by store identifier (Req 16.9, 50.3).
    Store(String),
    /// An extractor host, by case-insensitive host name (Req 12.1).
    ExtractorHost(String),
    /// An integration source (`anilist|github|mdblist|tmdb|trakt|tvdb|letterboxd`).
    Integration(String),
    /// The Acestream engine.
    Acestream,
    /// Telegram (MTProto).
    Telegram,
    /// The Redis connection manager.
    Redis,
}

impl BreakerKey {
    /// A human-readable label for the dependency, used in the tripped-error
    /// message and metrics/log lines.
    pub fn label(&self) -> String {
        match self {
            BreakerKey::Store(s) => s.clone(),
            BreakerKey::ExtractorHost(h) => h.clone(),
            BreakerKey::Integration(i) => i.clone(),
            BreakerKey::Acestream => "acestream".to_string(),
            BreakerKey::Telegram => "telegram".to_string(),
            BreakerKey::Redis => "redis".to_string(),
        }
    }
}

/// The three circuit-breaker states (design: Pattern 1 `BreakerState`).
///
/// `serde::Serialize` is derived so the breaker state can be embedded directly
/// in the health model's [`ComponentHealth`](crate::health::ComponentHealth)
/// component breakdown (design: Health Model & Probes — `breaker:
/// Option<BreakerState>`); it serializes as `"closed"` / `"open"` /
/// `"half_open"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    /// Calls run normally; trip-eligible failures accumulate toward opening.
    Closed,
    /// Calls are short-circuited; the cooldown is counting down.
    Open,
    /// A single trial probe is admitted to test recovery.
    HalfOpen,
}

/// Circuit-breaker tuning (design: Components → `CircuitBreaker`, simplified
/// view `{ failure_threshold, cooldown }`).
///
/// The simplified fields map onto the canonical Pattern 1 config as
/// `failure_threshold ≡ consecutive_failures` and `cooldown ≡ open_timeout`.
/// `half_open_max_probes` is retained (default `1`) to enforce the "single
/// probe" rule; the rolling-failure-rate triggers
/// (`failure_rate_threshold`/`minimum_throughput`/`rolling_window`) are
/// additional optional triggers that are not part of this task.
#[derive(Clone, Debug)]
pub struct BreakerConfig {
    /// Consecutive trip-eligible failures that open the breaker (Req 50.2).
    pub failure_threshold: u32,
    /// How long the breaker stays `Open` before admitting a `HalfOpen` probe
    /// (Req 50.2, 50.4).
    pub cooldown: Duration,
    /// Concurrent trial probes admitted in `HalfOpen` (default `1`).
    pub half_open_max_probes: u32,
}

impl Default for BreakerConfig {
    /// The design's example breaker: open after 5 consecutive failures, 15s
    /// cooldown, a single half-open probe.
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown: Duration::from_secs(15),
            half_open_max_probes: 1,
        }
    }
}

impl BreakerConfig {
    /// Construct from the simplified `{ failure_threshold, cooldown }` view; a
    /// single half-open probe is used.
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cooldown,
            half_open_max_probes: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Permit
// ---------------------------------------------------------------------------

/// A token returned by [`CircuitBreaker::acquire`] that must be handed back to
/// [`on_success`](CircuitBreaker::on_success) or
/// [`on_failure`](CircuitBreaker::on_failure) to record the call's outcome.
///
/// For a `HalfOpen` **probe** permit the token also owns the probe slot: if it
/// is dropped without an outcome being recorded (e.g. the guarded op panicked
/// and unwound), [`Drop`] releases the slot so the breaker can admit a fresh
/// probe rather than wedging in `HalfOpen` forever (self-healing — Req 50).
#[must_use = "a breaker permit must be passed to on_success/on_failure to record the outcome"]
pub struct BreakerPermit {
    /// `Some` only for a probe permit whose slot has not yet been released.
    probe_guard: Option<Arc<Shared>>,
}

impl BreakerPermit {
    /// A permit issued while `Closed` (no probe slot held).
    fn closed() -> Self {
        Self { probe_guard: None }
    }

    /// A probe permit issued while `HalfOpen`, owning a probe slot in `shared`.
    fn probe(shared: Arc<Shared>) -> Self {
        Self {
            probe_guard: Some(shared),
        }
    }

    /// Was this a `HalfOpen` trial probe?
    fn is_probe(&self) -> bool {
        self.probe_guard.is_some()
    }
}

impl std::fmt::Debug for BreakerPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakerPermit")
            .field("is_probe", &self.is_probe())
            .finish()
    }
}

impl Drop for BreakerPermit {
    fn drop(&mut self) {
        // Outcome never recorded for a probe → release the slot so a future
        // acquire can re-probe instead of the breaker hanging in HalfOpen.
        if let Some(shared) = self.probe_guard.take() {
            let mut inner = shared.lock();
            inner.half_open_in_flight = inner.half_open_in_flight.saturating_sub(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Breaker
// ---------------------------------------------------------------------------

/// Mutable breaker state, guarded by a [`Mutex`]. Mutated only under the lock
/// by short, panic-free critical sections (no user code runs while held).
#[derive(Debug)]
struct Inner {
    state: BreakerState,
    consecutive_failures: u32,
    /// `clock.now_millis()` at the last `→ Open` transition.
    opened_at_millis: u64,
    /// Probe slots currently in flight while `HalfOpen`.
    half_open_in_flight: u32,
}

/// The breaker's shared state — held by the [`CircuitBreaker`] and by any
/// outstanding probe [`BreakerPermit`] so the slot can be released on drop.
struct Shared {
    key: BreakerKey,
    config: BreakerConfig,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

impl Shared {
    /// Lock `inner`, recovering from a poisoned mutex so a breaker method can
    /// never itself panic (Req 50 robustness — "never panics over any op
    /// sequence").
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A per-dependency circuit breaker (Req 50.2, 50.3, 50.4).
///
/// Cheap to clone — clones share the same underlying state.
#[derive(Clone)]
pub struct CircuitBreaker {
    shared: Arc<Shared>,
}

impl CircuitBreaker {
    /// Build a breaker for `key` with `config`, using the real
    /// [`SystemClock`].
    pub fn new(key: BreakerKey, config: BreakerConfig) -> Self {
        Self::with_clock(key, config, Arc::new(SystemClock::new()))
    }

    /// Build a breaker with an injected [`Clock`] (deterministic-cooldown
    /// tests use a [`ManualClock`]).
    pub fn with_clock(key: BreakerKey, config: BreakerConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            shared: Arc::new(Shared {
                key,
                config,
                clock,
                inner: Mutex::new(Inner {
                    state: BreakerState::Closed,
                    consecutive_failures: 0,
                    opened_at_millis: 0,
                    half_open_in_flight: 0,
                }),
            }),
        }
    }

    /// The dependency this breaker guards.
    pub fn key(&self) -> &BreakerKey {
        &self.shared.key
    }

    /// The current observed state (for metrics — Req 50.14 — and breaker-aware
    /// store selection — Req 50.3).
    ///
    /// This is the raw stored state; the lazy `Open → HalfOpen` transition
    /// happens inside [`acquire`](Self::acquire) when a probe is admitted.
    pub fn state(&self) -> BreakerState {
        self.shared.lock().state
    }

    /// Whether trip-eligible failures of category `err` count toward opening
    /// the breaker (design: Pattern 1 classification).
    ///
    /// Only [`UpstreamUnavailable`](ErrorCategory::UpstreamUnavailable) and
    /// [`HosterUnavailable`](ErrorCategory::HosterUnavailable) are eligible —
    /// these subsume connection resets, transport errors, timeouts, and
    /// `502/503/504`. Everything else (client/semantic categories, plus the
    /// account-cap `StoreLimitExceeded` and rate-limit `TooManyRequests`, which
    /// the per-store cooldown owns) is **not** eligible.
    pub fn is_trip_eligible(err: &AppError) -> bool {
        matches!(
            err.category,
            ErrorCategory::UpstreamUnavailable | ErrorCategory::HosterUnavailable
        )
    }

    /// Decide admission **before** doing work (design: Pattern 1 `acquire`).
    ///
    /// * `Closed` → a closed permit.
    /// * `Open` and the cooldown has elapsed → transition to `HalfOpen` and try
    ///   to claim the single probe slot.
    /// * `Open` and still cooling down → short-circuit with the tripped error,
    ///   **without** invoking the operation (Req 50.2).
    /// * `HalfOpen` → claim a probe slot if one is free, else short-circuit
    ///   (enforces the single-probe rule).
    pub fn acquire(&self) -> Result<BreakerPermit, AppError> {
        let mut inner = self.shared.lock();
        match inner.state {
            BreakerState::Closed => Ok(BreakerPermit::closed()),
            BreakerState::HalfOpen => self.try_claim_probe(&mut inner),
            BreakerState::Open => {
                let elapsed = self
                    .shared
                    .clock
                    .now_millis()
                    .saturating_sub(inner.opened_at_millis);
                if elapsed >= self.shared.config.cooldown.as_millis() as u64 {
                    inner.state = BreakerState::HalfOpen;
                    inner.half_open_in_flight = 0;
                    self.try_claim_probe(&mut inner)
                } else {
                    Err(self.tripped_error())
                }
            }
        }
    }

    /// Claim a `HalfOpen` probe slot if one is free; otherwise short-circuit.
    fn try_claim_probe(&self, inner: &mut Inner) -> Result<BreakerPermit, AppError> {
        if inner.half_open_in_flight < self.shared.config.half_open_max_probes {
            inner.half_open_in_flight += 1;
            Ok(BreakerPermit::probe(self.shared.clone()))
        } else {
            Err(self.tripped_error())
        }
    }

    /// Record a **successful** call (design: Pattern 1 `on_success`).
    ///
    /// A probe success closes the breaker and resets the counter; a closed
    /// success simply resets the consecutive-failure counter.
    pub fn on_success(&self, mut permit: BreakerPermit) {
        let was_probe = permit.is_probe();
        // Consume the probe slot here so `Drop` does not double-release it.
        let _ = permit.probe_guard.take();

        let mut inner = self.shared.lock();
        if was_probe {
            inner.state = BreakerState::Closed;
            inner.half_open_in_flight = 0;
        }
        inner.consecutive_failures = 0;
    }

    /// Record a **failed** call (design: Pattern 1 `on_failure`).
    ///
    /// Only [`trip-eligible`](Self::is_trip_eligible) failures move the state
    /// machine:
    /// * Closed + eligible → increment the counter; open at `failure_threshold`.
    /// * Closed + non-eligible → ignored (the counter is neither incremented
    ///   nor reset — the dependency is reachable, just rejecting this request).
    /// * Probe + eligible → reopen and restart the cooldown.
    /// * Probe + non-eligible → the dependency responded, so treat the probe as
    ///   healthy and close the breaker.
    pub fn on_failure(&self, mut permit: BreakerPermit, err: &AppError) {
        let was_probe = permit.is_probe();
        let _ = permit.probe_guard.take();
        let eligible = Self::is_trip_eligible(err);

        let mut inner = self.shared.lock();
        if was_probe {
            inner.half_open_in_flight = 0;
            if eligible {
                inner.state = BreakerState::Open;
                inner.opened_at_millis = self.shared.clock.now_millis();
            } else {
                // Probe reached a responsive dependency → recover.
                inner.state = BreakerState::Closed;
                inner.consecutive_failures = 0;
            }
            return;
        }

        // Closed-context outcome.
        if eligible && inner.state == BreakerState::Closed {
            inner.consecutive_failures += 1;
            if inner.consecutive_failures >= self.shared.config.failure_threshold {
                inner.state = BreakerState::Open;
                inner.opened_at_millis = self.shared.clock.now_millis();
            }
        }
        // Non-eligible closed failures are ignored (not counted — design).
    }

    /// The error returned when the breaker short-circuits a call (Req 50.2).
    ///
    /// A store breaker surfaces an
    /// [`UpstreamUnavailable`](ErrorCategory::UpstreamUnavailable) identifying
    /// the store (Req 16.9); an extractor host surfaces a
    /// [`HosterUnavailable`](ErrorCategory::HosterUnavailable); integration /
    /// Acestream / Telegram / Redis surface `UpstreamUnavailable`. Every
    /// tripped error carries the [`circuit_open`](AppError::circuit_open) marker
    /// for metrics/logs (it does not change the client HTTP status).
    fn tripped_error(&self) -> AppError {
        let label = self.shared.key.label();
        let message = format!("circuit open for {label}");
        let err = match &self.shared.key {
            BreakerKey::Store(name) => AppError::upstream_unavailable_for(name.clone(), message),
            BreakerKey::ExtractorHost(_) => AppError::hoster_unavailable(message),
            _ => AppError::upstream_unavailable(message),
        };
        err.with_circuit_open()
    }
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

/// Wrap an async `op` in the breaker's `acquire → run → record outcome` cycle
/// without changing the op's signature (design: Pattern 1 `guarded`).
///
/// If the breaker is `Open` (and still cooling down) or its `HalfOpen` probe
/// slot is taken, this returns the tripped error **without** calling `op`
/// (Req 50.2). Otherwise `op` runs and its `Ok`/`Err` is recorded so the state
/// machine advances.
pub async fn guarded<T, F, Fut>(breaker: &CircuitBreaker, op: F) -> Result<T, AppError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let permit = breaker.acquire()?;
    match op().await {
        Ok(value) => {
            breaker.on_success(permit);
            Ok(value)
        }
        Err(err) => {
            breaker.on_failure(permit, &err);
            Err(err)
        }
    }
}

/// Breaker-aware selection over an ordered set of interchangeable dependencies
/// (design: Pattern 1 — `StoreBreakerSet`; Req 50.3).
///
/// Given the breakers for a set of interchangeable dependencies **in the
/// configured order** (e.g. the per-store breakers behind a
/// `StoreFallbackChain`), this returns the first dependency still in rotation —
/// the first whose breaker is **not** [`Open`](BreakerState::Open). An `Open`
/// breaker removes its dependency from rotation so resolution falls through to
/// the next configured candidate (Req 50.3, 37.7). When **every** breaker is
/// `Open` the whole set is unavailable and a typed
/// [`UpstreamUnavailable`](ErrorCategory::UpstreamUnavailable) error carrying
/// the [`circuit_open`](AppError::circuit_open) marker is returned (Req 50.3);
/// the same error is returned for an empty set (no candidate to route to).
///
/// A [`HalfOpen`](BreakerState::HalfOpen) breaker is deliberately **not**
/// excluded: it is admitting a recovery probe and is therefore back in
/// rotation, so a recovered dependency resumes serving automatically (Req
/// 50.4). This is the breaker-aware refinement of `StoreFallbackChain`; the
/// cooldown reconciliation (Property 54) layers on top of it.
pub fn select_available(breakers: &[CircuitBreaker]) -> Result<&CircuitBreaker, AppError> {
    breakers
        .iter()
        .find(|breaker| breaker.state() != BreakerState::Open)
        .ok_or_else(|| {
            AppError::upstream_unavailable("all dependencies unavailable (all circuits open)")
                .with_circuit_open()
        })
}

/// Compose the [`RetryPolicy`] **inside** the [`CircuitBreaker`], bounded by a
/// request-scoped [`Deadline`]: production entry point seeded from the OS RNG
/// (design: Pattern 2 `with_retry`).
///
/// The `deadline` is the outermost bound (design: Pattern 10): a backoff sleep
/// is only taken when it would complete inside the remaining budget, otherwise
/// the call fails fast with a deadline-exceeded error. Pass a `Deadline` far in
/// the future (e.g. `Deadline::after(Duration::MAX)`) when only retry+breaker
/// composition is wanted.
pub async fn with_retry<T, F, Fut>(
    policy: &RetryPolicy,
    breaker: &CircuitBreaker,
    deadline: Deadline,
    op: F,
) -> Result<T, AppError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let mut rng = StdRng::from_os_rng();
    with_retry_with_rng(policy, breaker, deadline, &mut rng, op).await
}

/// Like [`with_retry`] but with a fixed `seed` for a **deterministic** backoff
/// schedule (tests / property tests).
pub async fn with_retry_seeded<T, F, Fut>(
    policy: &RetryPolicy,
    breaker: &CircuitBreaker,
    deadline: Deadline,
    seed: u64,
    op: F,
) -> Result<T, AppError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let mut rng = StdRng::seed_from_u64(seed);
    with_retry_with_rng(policy, breaker, deadline, &mut rng, op).await
}

/// The retry-over-breaker loop, driven by a caller-provided RNG and bounded by
/// `deadline`.
///
/// Each attempt runs through [`guarded`], so a tripped breaker short-circuits
/// without calling `op`. The loop retries only when **all** hold: attempts
/// remain, the error is [`retryable`](ErrorCategory::is_retryable), and it is
/// **not** a breaker short-circuit ([`circuit_open`](AppError::circuit_open)).
/// The last condition is what makes a mid-retry breaker trip stop the remaining
/// attempts instead of spinning through cheap short-circuits (design: Pattern 2
/// "a mid-retry breaker trip short-circuits the remaining attempts").
///
/// Before sleeping for the chosen backoff, the loop consults `deadline`: if the
/// backoff would not complete strictly inside the remaining budget
/// ([`permits_backoff`](crate::resilience::deadline::Deadline::permits_backoff)
/// is false), it returns the error remapped via
/// [`into_deadline_exceeded`](AppError::into_deadline_exceeded) instead of
/// sleeping past the deadline — so no backoff sleep ever exceeds `remaining()`
/// (design: Pattern 2 ↔ Pattern 10).
pub async fn with_retry_with_rng<T, F, Fut, R>(
    policy: &RetryPolicy,
    breaker: &CircuitBreaker,
    deadline: Deadline,
    rng: &mut R,
    op: F,
) -> Result<T, AppError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
    R: Rng,
{
    let mut attempt: u32 = 0;
    loop {
        match guarded(breaker, &op).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                let more_attempts_remain = attempt + 1 < policy.max_attempts;
                let retryable = err.category.is_retryable() && !err.circuit_open;
                if more_attempts_remain && retryable {
                    let delay = policy.delay_for(attempt, &err, rng);
                    // Deadline is the outermost bound (design: Pattern 10): a
                    // backoff sleep may never overrun the request budget. If
                    // the chosen delay would not complete inside the remaining
                    // budget, fail fast with a deadline-exceeded error rather
                    // than sleeping past the deadline.
                    if !deadline.permits_backoff(delay) {
                        return Err(err.into_deadline_exceeded());
                    }
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                } else {
                    return Err(err);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -- Builders -----------------------------------------------------------

    /// A store breaker over a [`ManualClock`], returning both so tests can
    /// advance the cooldown deterministically.
    fn store_breaker(threshold: u32, cooldown: Duration) -> (CircuitBreaker, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new());
        let breaker = CircuitBreaker::with_clock(
            BreakerKey::Store("realdebrid".into()),
            BreakerConfig::new(threshold, cooldown),
            clock.clone(),
        );
        (breaker, clock)
    }

    fn eligible() -> AppError {
        AppError::upstream_unavailable("connection reset")
    }

    fn hoster_eligible() -> AppError {
        AppError::hoster_unavailable("502 bad gateway")
    }

    /// Drive one closed-state trip-eligible failure through the breaker.
    fn fail_eligible(breaker: &CircuitBreaker) {
        let permit = breaker.acquire().expect("closed breaker admits");
        breaker.on_failure(permit, &eligible());
    }

    /// Drive one closed-state success through the breaker.
    fn succeed(breaker: &CircuitBreaker) {
        let permit = breaker.acquire().expect("closed breaker admits");
        breaker.on_success(permit);
    }

    // -- Trip-eligibility classification ------------------------------------

    /// Only `UpstreamUnavailable`/`HosterUnavailable` are trip-eligible; the
    /// account-cap and rate-limit 429s and every client/semantic category are
    /// not (design: Pattern 1 classification).
    #[test]
    fn trip_eligibility_matches_health_categories_only() {
        assert!(CircuitBreaker::is_trip_eligible(
            &AppError::upstream_unavailable("x")
        ));
        assert!(CircuitBreaker::is_trip_eligible(
            &AppError::hoster_unavailable("x")
        ));
        // Timeouts fold into UpstreamUnavailable and remain eligible.
        assert!(CircuitBreaker::is_trip_eligible(
            &AppError::upstream_unavailable("slow").into_deadline_exceeded()
        ));

        for err in [
            AppError::too_many_requests("rate"),
            AppError::store_limit_exceeded("cap"),
            AppError::unauthorized("401"),
            AppError::forbidden("403"),
            AppError::payment_required("402"),
            AppError::not_found("404"),
            AppError::bad_request("400"),
            AppError::range_not_satisfiable("416"),
            AppError::infringing_content("451"),
            AppError::invalid_store_name("?"),
            AppError::payload_too_large("413"),
            AppError::unknown("500"),
        ] {
            assert!(
                !CircuitBreaker::is_trip_eligible(&err),
                "{:?} must not be trip-eligible",
                err.category,
            );
        }
    }

    // -- Opening ------------------------------------------------------------

    /// Opens after **exactly** `failure_threshold` consecutive trip-eligible
    /// failures — not before, and the threshold-th failure flips the state
    /// (Req 50.2).
    #[test]
    fn opens_after_exactly_failure_threshold_consecutive_eligible_failures() {
        let (breaker, _clock) = store_breaker(3, Duration::from_secs(10));
        assert_eq!(breaker.state(), BreakerState::Closed);

        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Closed, "1 < 3");
        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Closed, "2 < 3");
        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open, "exactly 3 opens");
    }

    /// A success before the threshold resets the consecutive counter, so a
    /// fresh run of `failure_threshold` is required to open (Req 50.2).
    #[test]
    fn success_resets_the_consecutive_failure_counter() {
        let (breaker, _clock) = store_breaker(3, Duration::from_secs(10));

        fail_eligible(&breaker);
        fail_eligible(&breaker);
        succeed(&breaker); // reset
        fail_eligible(&breaker);
        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Closed, "2 after reset < 3");
        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    /// Non-trip-eligible failures never open the breaker, however many occur —
    /// `TooManyRequests`/`StoreLimitExceeded` and client/semantic outcomes are
    /// not counted (design: Pattern 1 classification).
    #[test]
    fn only_trip_eligible_categories_count_toward_opening() {
        let (breaker, _clock) = store_breaker(2, Duration::from_secs(10));
        for err in [
            AppError::not_found("404"),
            AppError::unauthorized("401"),
            AppError::forbidden("403"),
            AppError::bad_request("400"),
            AppError::too_many_requests("429"),
            AppError::store_limit_exceeded("cap"),
            AppError::too_many_requests("429"),
            AppError::not_found("404"),
        ] {
            let permit = breaker.acquire().expect("closed admits");
            breaker.on_failure(permit, &err);
            assert_eq!(
                breaker.state(),
                BreakerState::Closed,
                "{:?} must not trip the breaker",
                err.category,
            );
        }
    }

    /// A non-eligible failure interleaved with eligible ones is *ignored* — it
    /// neither increments nor resets the counter — so the eligible failures are
    /// still counted as consecutive (resilience4j-style "ignored" semantics;
    /// design: "not counted").
    #[test]
    fn non_eligible_failure_is_ignored_not_a_reset() {
        let (breaker, _clock) = store_breaker(3, Duration::from_secs(10));
        fail_eligible(&breaker); // 1
        fail_eligible(&breaker); // 2

        let permit = breaker.acquire().expect("closed admits");
        breaker.on_failure(permit, &AppError::not_found("ignored")); // ignored, still 2
        assert_eq!(breaker.state(), BreakerState::Closed);

        fail_eligible(&breaker); // 3 → open
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    // -- Open short-circuit -------------------------------------------------

    /// While `Open` (before cooldown), `guarded` short-circuits with a
    /// `circuit_open` error and **never invokes the operation** (Req 50.2).
    #[tokio::test]
    async fn open_breaker_short_circuits_without_invoking_op() {
        let (breaker, _clock) = store_breaker(1, Duration::from_secs(10));
        fail_eligible(&breaker); // threshold 1 → open immediately
        assert_eq!(breaker.state(), BreakerState::Open);

        let calls = AtomicUsize::new(0);
        let result: Result<(), AppError> = guarded(&breaker, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        })
        .await;

        let err = result.expect_err("open breaker must short-circuit");
        assert!(err.circuit_open, "tripped error carries circuit_open");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "op must NOT be invoked while Open"
        );
    }

    /// `acquire` itself short-circuits while `Open` (the low-level contract
    /// behind `guarded`).
    #[test]
    fn acquire_errors_while_open_before_cooldown() {
        let (breaker, clock) = store_breaker(1, Duration::from_secs(10));
        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open);

        assert!(breaker.acquire().is_err(), "open before cooldown rejects");
        clock.advance(Duration::from_secs(5)); // still < cooldown
        assert!(breaker.acquire().is_err());
    }

    // -- Half-open ----------------------------------------------------------

    /// After the cooldown elapses, only a **single** probe is admitted; a
    /// concurrent acquire while the probe is in flight is rejected (Req 50.4).
    #[test]
    fn half_open_admits_only_a_single_probe() {
        let (breaker, clock) = store_breaker(1, Duration::from_secs(10));
        fail_eligible(&breaker);
        clock.advance(Duration::from_secs(10)); // cooldown elapsed

        let probe = breaker
            .acquire()
            .expect("cooldown elapsed → one probe admitted");
        assert!(probe.is_probe());
        assert_eq!(breaker.state(), BreakerState::HalfOpen);

        // A second probe while the first is in flight is rejected.
        assert!(
            breaker.acquire().is_err(),
            "HalfOpen admits at most half_open_max_probes (1)"
        );

        // Resolve the probe so it is not leaked.
        breaker.on_success(probe);
    }

    /// A probe **success** closes the breaker and resets the counter (Req 50.4).
    #[test]
    fn half_open_probe_success_closes_and_resets() {
        let (breaker, clock) = store_breaker(3, Duration::from_secs(10));
        for _ in 0..3 {
            fail_eligible(&breaker);
        }
        assert_eq!(breaker.state(), BreakerState::Open);

        clock.advance(Duration::from_secs(10));
        let probe = breaker.acquire().expect("probe admitted");
        breaker.on_success(probe);
        assert_eq!(breaker.state(), BreakerState::Closed);

        // Counter was reset: it takes a fresh `threshold` failures to reopen.
        fail_eligible(&breaker);
        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Closed, "2 < 3 after reset");
        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    /// A probe **failure** reopens the breaker and **restarts** the cooldown
    /// (Req 50.4).
    #[test]
    fn half_open_probe_failure_reopens_and_restarts_cooldown() {
        let (breaker, clock) = store_breaker(1, Duration::from_secs(10));
        fail_eligible(&breaker);
        clock.advance(Duration::from_secs(10));

        let probe = breaker.acquire().expect("probe admitted");
        breaker.on_failure(probe, &eligible());
        assert_eq!(breaker.state(), BreakerState::Open, "probe failure reopens");

        // Cooldown restarted from the reopen instant: a partial wait still rejects.
        clock.advance(Duration::from_secs(9));
        assert!(
            breaker.acquire().is_err(),
            "cooldown restarted, not yet elapsed"
        );

        // Once the full restarted cooldown elapses, a fresh probe is admitted.
        clock.advance(Duration::from_secs(1));
        let probe2 = breaker.acquire().expect("restarted cooldown elapsed");
        assert!(probe2.is_probe());
        breaker.on_success(probe2);
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    /// A probe that reaches a responsive (non-trip-eligible) error recovers the
    /// breaker rather than reopening it — the dependency is alive.
    #[test]
    fn half_open_probe_non_eligible_error_closes() {
        let (breaker, clock) = store_breaker(1, Duration::from_secs(10));
        fail_eligible(&breaker);
        clock.advance(Duration::from_secs(10));

        let probe = breaker.acquire().expect("probe admitted");
        breaker.on_failure(probe, &AppError::not_found("404 from a live host"));
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    /// Dropping a probe permit without recording an outcome releases the slot,
    /// so the breaker can admit a fresh probe instead of wedging in `HalfOpen`
    /// (self-healing).
    #[test]
    fn dropped_probe_permit_releases_the_slot() {
        let (breaker, clock) = store_breaker(1, Duration::from_secs(10));
        fail_eligible(&breaker);
        clock.advance(Duration::from_secs(10));

        {
            let _probe = breaker.acquire().expect("probe admitted");
            // dropped here without on_success/on_failure
        }
        // Slot released → a new probe can be admitted even though we are still
        // HalfOpen (cooldown already elapsed).
        let probe = breaker.acquire().expect("slot released, re-probe admitted");
        assert!(probe.is_probe());
        breaker.on_success(probe);
    }

    // -- tripped_error mapping ----------------------------------------------

    /// The tripped error maps to the right category per key: store →
    /// `UpstreamUnavailable` (identifying the store), extractor host →
    /// `HosterUnavailable`; both carry `circuit_open` (Req 16.9, 50.2).
    #[test]
    fn tripped_error_category_depends_on_breaker_key() {
        let clock = Arc::new(ManualClock::new());
        let store = CircuitBreaker::with_clock(
            BreakerKey::Store("torbox".into()),
            BreakerConfig::new(1, Duration::from_secs(10)),
            clock.clone(),
        );
        store.on_failure(store.acquire().unwrap(), &eligible());
        let store_err = store.acquire().expect_err("open");
        assert_eq!(store_err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(store_err.store.as_deref(), Some("torbox"));
        assert!(store_err.circuit_open);

        let host = CircuitBreaker::with_clock(
            BreakerKey::ExtractorHost("example.com".into()),
            BreakerConfig::new(1, Duration::from_secs(10)),
            clock,
        );
        host.on_failure(host.acquire().unwrap(), &hoster_eligible());
        let host_err = host.acquire().expect_err("open");
        assert_eq!(host_err.category, ErrorCategory::HosterUnavailable);
        assert!(host_err.circuit_open);
    }

    // -- breaker-aware selection (select_available) -------------------------

    /// Build a store breaker already driven into a given state, returning it
    /// alongside its clock so further transitions can be staged.
    fn breaker_in_state(name: &str, state: BreakerState) -> (CircuitBreaker, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new());
        let breaker = CircuitBreaker::with_clock(
            BreakerKey::Store(name.into()),
            BreakerConfig::new(1, Duration::from_secs(10)),
            clock.clone(),
        );
        match state {
            BreakerState::Closed => {}
            BreakerState::Open => {
                breaker.on_failure(breaker.acquire().unwrap(), &eligible());
            }
            BreakerState::HalfOpen => {
                breaker.on_failure(breaker.acquire().unwrap(), &eligible());
                clock.advance(Duration::from_secs(10)); // cooldown elapsed
                                                        // Admitting a probe transitions Open → HalfOpen; dropping the
                                                        // probe releases the slot but leaves the observed state HalfOpen.
                let _probe = breaker.acquire().expect("probe admitted");
            }
        }
        assert_eq!(breaker.state(), state);
        (breaker, clock)
    }

    /// Selection returns the **first** non-`Open` breaker in configured order;
    /// an `Open` breaker is skipped (removed from rotation) (Req 50.3).
    #[test]
    fn select_available_returns_first_non_open_in_order() {
        let (a, _ca) = breaker_in_state("rd", BreakerState::Open);
        let (b, _cb) = breaker_in_state("ad", BreakerState::Closed);
        let (c, _cc) = breaker_in_state("pm", BreakerState::Closed);

        let set = [a, b, c];
        let chosen = select_available(&set).expect("a healthy store exists");
        assert_eq!(
            chosen.key().label(),
            "ad",
            "skip Open rd, pick first healthy ad"
        );
    }

    /// A `HalfOpen` breaker is in rotation (it admits a recovery probe), so
    /// selection may return it ahead of a later `Closed` store (Req 50.4).
    #[test]
    fn select_available_admits_half_open() {
        let (a, _ca) = breaker_in_state("rd", BreakerState::Open);
        let (b, _cb) = breaker_in_state("ad", BreakerState::HalfOpen);
        let (c, _cc) = breaker_in_state("pm", BreakerState::Closed);

        let set = [a, b, c];
        let chosen = select_available(&set).expect("half-open is selectable");
        assert_eq!(chosen.key().label(), "ad", "HalfOpen is in rotation");
    }

    /// When every breaker is `Open` the whole set is unavailable: a typed
    /// `UpstreamUnavailable` + `circuit_open` error is returned (Req 50.3).
    #[test]
    fn select_available_errors_when_all_open() {
        let (a, _ca) = breaker_in_state("rd", BreakerState::Open);
        let (b, _cb) = breaker_in_state("ad", BreakerState::Open);

        let set = [a, b];
        let err = match select_available(&set) {
            Ok(_) => panic!("all open → must be unavailable"),
            Err(e) => e,
        };
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.circuit_open);
    }

    /// An empty set has no candidate to route to and surfaces the same typed
    /// unavailable error.
    #[test]
    fn select_available_errors_on_empty_set() {
        let err = match select_available(&[]) {
            Ok(_) => panic!("no candidates → must be unavailable"),
            Err(e) => e,
        };
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.circuit_open);
    }

    // -- guarded ------------------------------------------------------------

    /// A successful guarded call resets the breaker; the value is passed
    /// through.
    #[tokio::test]
    async fn guarded_success_passes_value_and_keeps_closed() {
        let (breaker, _clock) = store_breaker(2, Duration::from_secs(10));
        fail_eligible(&breaker); // count = 1

        let value: u32 = guarded(&breaker, || async { Ok(7) }).await.unwrap();
        assert_eq!(value, 7);
        assert_eq!(breaker.state(), BreakerState::Closed);

        // The success reset the counter, so a single new failure does not open.
        fail_eligible(&breaker);
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    // -- with_retry composition ---------------------------------------------

    /// Zero-delay policy so the loop does not actually sleep in tests.
    fn fast_policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy::new(max_attempts, Duration::ZERO, Duration::ZERO, 2.0)
    }

    /// A deadline far enough in the future that it never bounds these
    /// composition tests (which exercise retry/breaker behavior, not the
    /// deadline). Deadline-bounding has its own dedicated tests below.
    fn far_deadline() -> Deadline {
        Deadline::after(Duration::from_secs(3600))
    }

    /// A transient error is retried through the breaker and eventually
    /// succeeds; the breaker stays closed (high threshold).
    #[tokio::test]
    async fn with_retry_retries_transient_then_succeeds() {
        let (breaker, _clock) = store_breaker(100, Duration::from_secs(10));
        let policy = fast_policy(5);
        let calls = AtomicUsize::new(0);

        let result: Result<&str, AppError> =
            with_retry_seeded(&policy, &breaker, far_deadline(), 1, || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(eligible())
                    } else {
                        Ok("ok")
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), "ok");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "2 transient failures + 1 success"
        );
    }

    /// A permanent error performs zero retries through `with_retry`.
    #[tokio::test]
    async fn with_retry_does_not_retry_permanent_errors() {
        let (breaker, _clock) = store_breaker(100, Duration::from_secs(10));
        let policy = fast_policy(5);
        let calls = AtomicUsize::new(0);

        let result: Result<(), AppError> =
            with_retry_seeded(&policy, &breaker, far_deadline(), 1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(AppError::not_found("permanent")) }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A breaker that is already `Open` short-circuits `with_retry` immediately:
    /// the op is never called and the retry loop does not spin (Req 50.2).
    #[tokio::test]
    async fn with_retry_short_circuits_on_open_breaker() {
        let (breaker, _clock) = store_breaker(1, Duration::from_secs(10));
        fail_eligible(&breaker); // open
        assert_eq!(breaker.state(), BreakerState::Open);

        let policy = fast_policy(5);
        let calls = AtomicUsize::new(0);
        let result: Result<(), AppError> =
            with_retry_seeded(&policy, &breaker, far_deadline(), 1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            })
            .await;

        let err = result.expect_err("open breaker short-circuits");
        assert!(err.circuit_open);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "op never called");
    }

    /// When the breaker trips **mid-retry**, the remaining attempts are
    /// short-circuited: the op runs exactly until the breaker opens, then
    /// `with_retry` returns the circuit-open error instead of spinning the
    /// remaining attempts (design: Pattern 2 composition).
    #[tokio::test]
    async fn with_retry_stops_when_breaker_trips_midway() {
        // threshold 2, but the policy would otherwise allow 5 attempts.
        let (breaker, _clock) = store_breaker(2, Duration::from_secs(10));
        let policy = fast_policy(5);
        let calls = AtomicUsize::new(0);

        let result: Result<(), AppError> =
            with_retry_seeded(&policy, &breaker, far_deadline(), 1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(eligible()) }
            })
            .await;

        let err = result.expect_err("all attempts fail");
        assert!(err.circuit_open, "final error is the breaker short-circuit");
        // Attempt 1 & 2 invoke the op (2nd opens the breaker); attempt 3 is a
        // short-circuit that never calls the op → exactly 2 invocations.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    // -- with_retry deadline bounding (task 6.3 integration) ----------------

    /// A backoff that would not complete inside the remaining deadline fails
    /// fast with a deadline-exceeded error instead of sleeping past the budget:
    /// the op is tried once, the breaker stays closed (transient, sub-threshold),
    /// and the loop returns the remapped error rather than retrying (design:
    /// Pattern 2 ↔ Pattern 10; Req 50.9, 35.4).
    #[tokio::test(start_paused = true)]
    async fn with_retry_fails_fast_when_backoff_exceeds_remaining_deadline() {
        // High threshold so the breaker never trips — isolate the deadline path.
        let (breaker, _clock) = store_breaker(100, Duration::from_secs(60));
        // Backoff is a fixed 5s (base == max, zero jitter band width at cap).
        let policy = RetryPolicy::new(5, Duration::from_secs(5), Duration::from_secs(5), 2.0);
        // Only 1s of budget — far less than the 5s backoff.
        let deadline = Deadline::after(Duration::from_secs(1));
        let calls = AtomicUsize::new(0);

        let result: Result<(), AppError> =
            with_retry_seeded(&policy, &breaker, deadline, 1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(eligible()) }
            })
            .await;

        let err = result.expect_err("budget too small for a retry");
        assert!(err.deadline_exceeded, "must remap to deadline-exceeded");
        assert_eq!(
            err.category,
            ErrorCategory::UpstreamUnavailable,
            "deadline-exceeded surfaces as UpstreamUnavailable",
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "op tried once, then fails fast instead of sleeping past the deadline",
        );
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    /// When the budget comfortably exceeds the backoff, the loop retries
    /// normally and a later success is returned — the deadline does not
    /// interfere when there is room to sleep.
    #[tokio::test(start_paused = true)]
    async fn with_retry_retries_within_a_generous_deadline() {
        let (breaker, _clock) = store_breaker(100, Duration::from_secs(60));
        // 100ms backoff, well inside the 10s budget.
        let policy = RetryPolicy::new(
            5,
            Duration::from_millis(100),
            Duration::from_millis(100),
            2.0,
        );
        let deadline = Deadline::after(Duration::from_secs(10));
        let calls = AtomicUsize::new(0);

        let result: Result<&str, AppError> =
            with_retry_seeded(&policy, &breaker, deadline, 1, || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(eligible())
                    } else {
                        Ok("ok")
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), "ok");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "2 retries within budget + success"
        );
    }

    /// An already-expired deadline permits no backoff at all: the first
    /// transient failure fails fast (single op invocation) rather than retrying.
    #[tokio::test(start_paused = true)]
    async fn with_retry_fails_fast_on_expired_deadline() {
        let (breaker, _clock) = store_breaker(100, Duration::from_secs(60));
        let policy = fast_policy(5); // zero-delay backoff
        let deadline = Deadline::after(Duration::from_millis(10));
        // Advance past the deadline so it is firmly expired.
        tokio::time::advance(Duration::from_millis(50)).await;
        assert!(deadline.expired());
        let calls = AtomicUsize::new(0);

        let result: Result<(), AppError> =
            with_retry_seeded(&policy, &breaker, deadline, 1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(eligible()) }
            })
            .await;

        assert!(result.expect_err("expired").deadline_exceeded);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no retry past an expired deadline"
        );
    }

    // -- Robustness ---------------------------------------------------------

    /// The breaker never panics over any sequence of operations: random
    /// acquires resolved as success / eligible failure / non-eligible failure /
    /// dropped, interleaved with random clock advances, always leave the state
    /// machine in a valid state (Req 50 — "never panics over any op sequence").
    #[test]
    fn never_panics_over_any_op_sequence() {
        let categories = [
            ErrorCategory::UpstreamUnavailable, // eligible
            ErrorCategory::HosterUnavailable,   // eligible
            ErrorCategory::NotFound,            // ignored
            ErrorCategory::TooManyRequests,     // ignored
            ErrorCategory::Unauthorized,        // ignored
        ];

        for start in 0..64u64 {
            let (breaker, clock) = store_breaker(3, Duration::from_millis(50));
            // Deterministic LCG so the sequence is reproducible per `start`.
            let mut seed = start.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            let mut next = || {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (seed >> 33) as u32
            };

            let mut held: Vec<BreakerPermit> = Vec::new();
            for _ in 0..200 {
                match next() % 5 {
                    0 => clock.advance(Duration::from_millis((next() % 80) as u64)),
                    1 => {
                        if let Ok(permit) = breaker.acquire() {
                            held.push(permit);
                        }
                    }
                    2 => {
                        if let Some(permit) = held.pop() {
                            breaker.on_success(permit);
                        }
                    }
                    3 => {
                        if let Some(permit) = held.pop() {
                            let cat = categories[(next() as usize) % categories.len()];
                            breaker.on_failure(permit, &AppError::new(cat, "seq"));
                        }
                    }
                    _ => {
                        held.pop(); // drop a permit without recording an outcome
                    }
                }
                // The observed state is always one of the three variants.
                assert!(matches!(
                    breaker.state(),
                    BreakerState::Closed | BreakerState::Open | BreakerState::HalfOpen
                ));
            }
        }
    }
}
