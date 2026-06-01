//! Degradation Guard (`http::degradation`) — Req 44.1, 44.3, 44.4, 44.5, 44.6.
//!
//! An actix middleware plus a shared, cheaply-clonable [`LoadController`] that
//! sheds load gracefully under pressure rather than letting the process crash
//! or wedge (design: Components → Degradation Guard). The guard is driven by:
//!
//! * **atomic connection counters** — `active_connections` (every in-flight
//!   request) and `active_streams` (the protected byte-delivery class), and
//! * a **sampled RSS gauge** — process resident-set size read periodically via
//!   [`sysinfo`] (cheap, *not* per-request — design: Technology Choices →
//!   "Process RSS sampling").
//!
//! ## What the basic guard does (this task, 11.3)
//!
//! When the `active_connections` count crosses the configured **connection
//! high-water mark** (or RSS crosses the **memory high-water mark**) the shared
//! [`LoadState`] flips to [`LoadState::Degraded`] and the middleware rejects
//! **new non-streaming** requests with `503 Service Unavailable` + `Retry-After`
//! (Req 44.1), while **active streams continue uninterrupted** and new
//! *streaming* requests are still admitted (Req 44.3 — the protected class).
//! Health/observability endpoints (`/health`, `/metrics`) are always admitted
//! so the load balancer can still observe the degraded state.
//!
//! The flip is **reversible with hysteresis**: the guard only returns to
//! [`LoadState::Normal`] once the connection count falls back below the
//! (strictly lower) **low-water mark**, so the system cannot oscillate between
//! admitting and rejecting on every connection open/close (Req 44.4). Each
//! `Normal ⇄ Degraded` transition emits a structured `tracing` log and bumps a
//! transition metric counter (Req 44.5).
//!
//! The current [`LoadState`] is the very enum the health module already
//! exposes (`crate::health::LoadState`); the composite [`HealthProbes`] reports
//! it through `/health` via [`HealthProbes::load_state`], so the load state is
//! surfaced to orchestrators with no duplication (Req 44.6). This module
//! deliberately **reuses** that enum rather than defining its own.
//!
//! ## What lands later (task 29)
//!
//! This is the **basic** guard: a single `Normal ⇄ Degraded` flip protecting
//! active streams. The full ordered **L1–L5 graceful-degradation ladder** with
//! per-level hysteresis (stop warmup → shrink prebuffer/evict segment cache →
//! shed non-streaming → shed new stream starts → shed idle streams) extends
//! *this* `http::degradation` module in task 29 (design: Resilience → Pattern
//! 8). The counters and RSS gauge defined here are the load signals that ladder
//! consumes.
//!
//! [`HealthProbes`]: crate::health::HealthProbes
//! [`HealthProbes::load_state`]: crate::health::HealthProbes::load_state

use std::future::{ready, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use actix_web::body::{BodySize, BoxBody, EitherBody, MessageBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::web::Bytes;
use actix_web::{Error, ResponseError};
use futures::future::LocalBoxFuture;

use crate::config::DegradationConfig;
use crate::errors::AppError;
use crate::health::LoadState;

/// `Retry-After` advertised on a shed `503` so a well-behaved client backs off
/// before retrying (design: Pattern 8 L3 "503 + Retry-After").
const RETRY_AFTER_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Request classification
// ---------------------------------------------------------------------------

/// How the guard treats an inbound request under load (design: Pattern 8 —
/// active streams are the highest priority; health must always answer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestClass {
    /// A streaming byte-delivery request (HLS/DASH segments, generic ranged
    /// proxy, Telegram/Acestream, SSE). The **protected class**: never shed by
    /// the basic guard, so active and newly-starting streams keep flowing
    /// (Req 44.3). New-stream-start shedding is L4 in task 29.
    Stream,
    /// Health / observability endpoints (`/health`, `/metrics`). Always
    /// admitted so the load balancer can still observe the degraded state and
    /// scrape metrics while shedding (otherwise readiness could never recover).
    Exempt,
    /// A normal non-streaming API request. Shed with `503` while the guard is
    /// in [`LoadState::Degraded`] (Req 44.1).
    Sheddable,
}

/// Classify an inbound request path into a [`RequestClass`].
///
/// Streaming byte-delivery paths from **both** API surfaces (the
/// `mediaflow-proxy-light` `/proxy/*` stream/segment endpoints and the
/// `stremthru` `/v0/proxy` content proxy + Xtream `get.php`) are the protected
/// [`RequestClass::Stream`]; `/health` and `/metrics` are
/// [`RequestClass::Exempt`]; everything else is [`RequestClass::Sheddable`].
///
/// Matching is prefix-based on the raw request path. A configured
/// `Server_Path_Prefix` is not stripped here; deployments behind a prefix wire
/// the prefix-aware classifier when the ladder integrates with the router
/// (task 29). The default (empty-prefix) deployment classifies exactly.
pub fn classify_path(path: &str) -> RequestClass {
    // Health & observability must always respond, even while shedding.
    if path == "/health" || path.starts_with("/health/") || path == "/metrics" {
        return RequestClass::Exempt;
    }

    // Streaming byte-delivery endpoints (highest priority, never shed here).
    const STREAM_PREFIXES: &[&str] = &[
        "/proxy/stream",    // mediaflow generic ranged stream (Req 5)
        "/proxy/hls",       // HLS manifests + segments (Req 1)
        "/proxy/mpd",       // DASH→HLS segments (Req 2, 3)
        "/proxy/segment",   // pre-buffered segment delivery (Req 7)
        "/proxy/telegram",  // Telegram MTProto media (Req 11)
        "/proxy/acestream", // Acestream P2P (Req 10)
        "/get.php",         // Xtream stream URLs (Req 9)
        "/v0/proxy",        // stremthru content proxy / byte serving (Req 36.2)
        "/v0/events",       // SSE long-lived stream (Req 36.2)
    ];
    if STREAM_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return RequestClass::Stream;
    }

    RequestClass::Sheddable
}

// ---------------------------------------------------------------------------
// Thresholds + pure decision logic
// ---------------------------------------------------------------------------

/// The high/low-water marks driving the basic guard's `Normal ⇄ Degraded`
/// flip, projected from [`DegradationConfig`] into `u64` for the atomic gauges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadThresholds {
    /// Whether the guard is active at all. When `false` the state is pinned to
    /// [`LoadState::Normal`] and nothing is shed.
    pub enabled: bool,
    /// `active_connections` at/above which the guard enters
    /// [`LoadState::Degraded`] (Req 44.1).
    pub conn_high_water: u64,
    /// `active_connections` strictly below which the guard may return to
    /// [`LoadState::Normal`] — the hysteresis floor (Req 44.4).
    pub conn_low_water: u64,
    /// Process RSS (bytes) at/above which the guard enters
    /// [`LoadState::Degraded`] (Req 44.2). The full memory-reclamation ladder
    /// (evict segment cache + shrink prebuffer) lands in task 29.
    pub memory_high_water_bytes: u64,
}

impl LoadThresholds {
    /// Project the operator-facing [`DegradationConfig`] into the guard's
    /// internal `u64` marks.
    pub fn from_config(cfg: &DegradationConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            conn_high_water: cfg.conn_high_water as u64,
            conn_low_water: cfg.conn_low_water as u64,
            memory_high_water_bytes: cfg.memory_high_water_bytes,
        }
    }
}

/// Pure, hysteresis-aware load-state transition (Req 44.1, 44.4).
///
/// Given the **previous** state and the current connection / RSS signals,
/// compute the next [`LoadState`]:
///
/// * **enter `Degraded`** (from `Normal`) when *either* signal is at/above its
///   high-water mark (`conns ≥ conn_high_water` or `rss ≥ memory_high_water`);
/// * **return to `Normal`** (from `Degraded`) only once the connection count is
///   strictly below the (lower) `conn_low_water` **and** RSS is below the
///   memory high-water mark — the hysteresis gap that prevents flapping.
///
/// When the guard is disabled the state is always [`LoadState::Normal`].
///
/// Splitting this out as a pure function makes it exhaustively testable offline
/// and is the single source of truth the property test (task 11.5, Property 46)
/// drives directly with generated inputs.
pub fn next_load_state(
    prev: LoadState,
    active_connections: u64,
    rss_bytes: u64,
    thresholds: &LoadThresholds,
) -> LoadState {
    if !thresholds.enabled {
        return LoadState::Normal;
    }

    let over_high = active_connections >= thresholds.conn_high_water
        || rss_bytes >= thresholds.memory_high_water_bytes;
    // Hysteresis: relax only once *both* signals are back under their floors.
    // Connections use the strictly-lower low-water mark; memory uses its high
    // mark (the basic guard has one memory mark — a separate memory floor is
    // part of the L1–L5 ladder in task 29).
    let under_low = active_connections < thresholds.conn_low_water
        && rss_bytes < thresholds.memory_high_water_bytes;

    match prev {
        LoadState::Normal => {
            if over_high {
                LoadState::Degraded
            } else {
                LoadState::Normal
            }
        }
        LoadState::Degraded => {
            if under_low {
                LoadState::Normal
            } else {
                LoadState::Degraded
            }
        }
    }
}

/// Pure admission decision for a *new* request (Req 44.1, 44.3): a request is
/// shed **iff** the guard is enabled, the request is [`RequestClass::Sheddable`]
/// (a non-streaming, non-exempt API call), and the current state sheds traffic
/// ([`LoadState::Degraded`]). Streams and exempt endpoints are never shed.
pub fn shed_new_request(state: LoadState, class: RequestClass, enabled: bool) -> bool {
    enabled && class == RequestClass::Sheddable && state.sheds_traffic()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DegradationLevel {
    L0Normal = 0,
    L1StopWarmup = 1,
    L2ShrinkCaches = 2,
    L3ShedNonStreaming = 3,
    L4ShedNewStreams = 4,
    L5Emergency = 5,
}

impl DegradationLevel {
    pub fn protects_active_streams(self) -> bool {
        self < DegradationLevel::L5Emergency
    }

    fn from_index(index: usize) -> Self {
        match index {
            0 => DegradationLevel::L0Normal,
            1 => DegradationLevel::L1StopWarmup,
            2 => DegradationLevel::L2ShrinkCaches,
            3 => DegradationLevel::L3ShedNonStreaming,
            4 => DegradationLevel::L4ShedNewStreams,
            _ => DegradationLevel::L5Emergency,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DegradationLadder {
    /// Rising thresholds for L1..L5.
    pub on_thresholds: [u64; 5],
    /// Falling thresholds for L1..L5. Each value must be below the matching
    /// `on_thresholds` value to create a hysteresis gap.
    pub off_thresholds: [u64; 5],
    /// Seconds the signal must remain below the lower threshold before relaxing.
    pub cooldown_hold_secs: u64,
}

impl Default for DegradationLadder {
    fn default() -> Self {
        Self {
            on_thresholds: [70, 80, 90, 95, 99],
            off_thresholds: [60, 70, 80, 90, 95],
            cooldown_hold_secs: 30,
        }
    }
}

impl DegradationLadder {
    pub fn next_level(
        &self,
        current: DegradationLevel,
        pressure: u64,
        below_off_since_secs: Option<u64>,
    ) -> DegradationLevel {
        let mut target = DegradationLevel::L0Normal;
        for (idx, threshold) in self.on_thresholds.iter().enumerate() {
            if pressure >= *threshold {
                target = DegradationLevel::from_index(idx + 1);
            }
        }
        if target > current {
            return DegradationLevel::from_index((current as usize + 1).min(target as usize));
        }
        if target == current {
            return current;
        }
        let idx = current as usize;
        if idx == 0 {
            return current;
        }
        let off = self.off_thresholds[idx - 1];
        let hold_satisfied = below_off_since_secs
            .map(|secs| secs >= self.cooldown_hold_secs)
            .unwrap_or(false);
        if pressure < off && hold_satisfied {
            DegradationLevel::from_index(idx - 1)
        } else {
            current
        }
    }

    pub fn action(level: DegradationLevel) -> &'static str {
        match level {
            DegradationLevel::L0Normal => "normal",
            DegradationLevel::L1StopWarmup => "stop_warmup",
            DegradationLevel::L2ShrinkCaches => "shrink_prebuffer_and_evict_segment_cache",
            DegradationLevel::L3ShedNonStreaming => "shed_non_streaming",
            DegradationLevel::L4ShedNewStreams => "shed_new_stream_starts",
            DegradationLevel::L5Emergency => "shed_idle_or_excess_streams",
        }
    }
}

// ---------------------------------------------------------------------------
// LoadController — shared atomic state
// ---------------------------------------------------------------------------

/// `LoadState::Normal` encoded for the atomic state cell.
const STATE_NORMAL: u8 = 0;
/// `LoadState::Degraded` encoded for the atomic state cell.
const STATE_DEGRADED: u8 = 1;

fn load_state_to_u8(state: LoadState) -> u8 {
    match state {
        LoadState::Normal => STATE_NORMAL,
        LoadState::Degraded => STATE_DEGRADED,
    }
}

fn load_state_from_u8(value: u8) -> LoadState {
    match value {
        STATE_NORMAL => LoadState::Normal,
        _ => LoadState::Degraded,
    }
}

/// The owned shared state behind a [`LoadController`].
struct ControllerInner {
    thresholds: LoadThresholds,
    /// Every in-flight request currently admitted by the guard.
    active_connections: AtomicU64,
    /// The protected byte-delivery subset of `active_connections` (Req 44.3).
    active_streams: AtomicU64,
    /// Last sampled process RSS in bytes (Req 44.2). `0` until the first sample.
    rss_bytes: AtomicU64,
    /// Current [`LoadState`], encoded (see [`load_state_to_u8`]).
    state: AtomicU8,
    /// Count of `Normal → Degraded` transitions (Req 44.5 metric).
    degraded_entries: AtomicU64,
    /// Count of `Degraded → Normal` transitions (Req 44.5 metric).
    degraded_exits: AtomicU64,
    /// Count of requests shed with `503` while degraded (Req 44.1 metric).
    shed_total: AtomicU64,
}

impl ControllerInner {
    /// Recompute the load state from the current signals, applying hysteresis,
    /// and atomically commit any transition exactly once (Req 44.4, 44.5).
    ///
    /// Uses a compare-exchange so that under concurrency only the single thread
    /// that actually flips the state records the transition log + metric, and a
    /// lost race simply re-reads the fresh state. Returns the committed state.
    fn evaluate(&self) -> LoadState {
        loop {
            let conns = self.active_connections.load(Ordering::SeqCst);
            let rss = self.rss_bytes.load(Ordering::SeqCst);
            let prev_u8 = self.state.load(Ordering::SeqCst);
            let prev = load_state_from_u8(prev_u8);
            let next = next_load_state(prev, conns, rss, &self.thresholds);

            if next == prev {
                return prev;
            }

            match self.state.compare_exchange(
                prev_u8,
                load_state_to_u8(next),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.record_transition(next, conns, rss);
                    return next;
                }
                // Another thread moved the state between our read and CAS;
                // retry with fresh signals (self-heals — evaluate runs on every
                // admit/release/sample).
                Err(_) => continue,
            }
        }
    }

    /// Emit the structured log + bump the transition metric for a committed
    /// state change (Req 44.5).
    fn record_transition(&self, next: LoadState, conns: u64, rss: u64) {
        match next {
            LoadState::Degraded => {
                self.degraded_entries.fetch_add(1, Ordering::SeqCst);
                tracing::warn!(
                    active_connections = conns,
                    rss_bytes = rss,
                    conn_high_water = self.thresholds.conn_high_water,
                    memory_high_water_bytes = self.thresholds.memory_high_water_bytes,
                    "degradation guard entered Degraded: shedding new non-streaming requests \
                     while active streams continue"
                );
            }
            LoadState::Normal => {
                self.degraded_exits.fetch_add(1, Ordering::SeqCst);
                tracing::info!(
                    active_connections = conns,
                    rss_bytes = rss,
                    conn_low_water = self.thresholds.conn_low_water,
                    "degradation guard returned to Normal: accepting new requests"
                );
            }
        }
    }
}

/// The shared load controller: holds the atomic connection counters, the
/// sampled RSS gauge, and the current [`LoadState`]. Cheap to clone (one
/// [`Arc`] bump) — every clone shares the same state, so all actix workers and
/// the RSS sampler task observe one consistent view (mirrors how `AppState`
/// shares dependencies across workers).
#[derive(Clone)]
pub struct LoadController {
    inner: Arc<ControllerInner>,
}

impl LoadController {
    /// Build a controller from explicit [`LoadThresholds`].
    pub fn new(thresholds: LoadThresholds) -> Self {
        Self {
            inner: Arc::new(ControllerInner {
                thresholds,
                active_connections: AtomicU64::new(0),
                active_streams: AtomicU64::new(0),
                rss_bytes: AtomicU64::new(0),
                state: AtomicU8::new(STATE_NORMAL),
                degraded_entries: AtomicU64::new(0),
                degraded_exits: AtomicU64::new(0),
                shed_total: AtomicU64::new(0),
            }),
        }
    }

    /// Build a controller from the operator-facing [`DegradationConfig`].
    pub fn from_config(cfg: &DegradationConfig) -> Self {
        Self::new(LoadThresholds::from_config(cfg))
    }

    /// The configured thresholds.
    pub fn thresholds(&self) -> LoadThresholds {
        self.inner.thresholds
    }

    /// Whether the guard is enabled.
    pub fn enabled(&self) -> bool {
        self.inner.thresholds.enabled
    }

    /// The current load state — the value reported through `/health` via
    /// [`HealthProbes::load_state`](crate::health::HealthProbes::load_state)
    /// (Req 44.6). Cheap atomic read.
    pub fn load_state(&self) -> LoadState {
        load_state_from_u8(self.inner.state.load(Ordering::SeqCst))
    }

    /// Current count of in-flight admitted requests.
    pub fn active_connections(&self) -> u64 {
        self.inner.active_connections.load(Ordering::SeqCst)
    }

    /// Current count of active protected streams (Req 44.3).
    pub fn active_streams(&self) -> u64 {
        self.inner.active_streams.load(Ordering::SeqCst)
    }

    /// Last sampled process RSS in bytes (`0` until the first sample).
    pub fn rss_bytes(&self) -> u64 {
        self.inner.rss_bytes.load(Ordering::SeqCst)
    }

    /// Number of `Normal → Degraded` transitions so far (Req 44.5 metric).
    pub fn degraded_entries(&self) -> u64 {
        self.inner.degraded_entries.load(Ordering::SeqCst)
    }

    /// Number of `Degraded → Normal` transitions so far (Req 44.5 metric).
    pub fn degraded_exits(&self) -> u64 {
        self.inner.degraded_exits.load(Ordering::SeqCst)
    }

    /// Number of requests shed with `503` while degraded (Req 44.1 metric).
    pub fn shed_total(&self) -> u64 {
        self.inner.shed_total.load(Ordering::SeqCst)
    }

    /// Update the sampled RSS gauge and re-evaluate the load state (Req 44.2).
    /// Called by the periodic [`RssSampler`] task; exposed for deterministic
    /// tests that inject a memory figure.
    pub fn set_rss_bytes(&self, bytes: u64) -> LoadState {
        self.inner.rss_bytes.store(bytes, Ordering::SeqCst);
        self.inner.evaluate()
    }

    /// Decide whether a *new* request of the given class should be shed under
    /// the current load (Req 44.1, 44.3). See [`shed_new_request`].
    pub fn should_shed(&self, class: RequestClass) -> bool {
        shed_new_request(self.load_state(), class, self.inner.thresholds.enabled)
    }

    /// Admit a request: increment the connection counter (and the stream
    /// counter for the protected class), re-evaluate the load state, and return
    /// a [`ConnectionGuard`] that releases the count when dropped. The guard's
    /// lifetime is tied to the response body so a streaming connection is
    /// counted for its full delivery duration (Req 44.3).
    pub fn admit(&self, class: RequestClass) -> ConnectionGuard {
        self.inner.active_connections.fetch_add(1, Ordering::SeqCst);
        let is_stream = class == RequestClass::Stream;
        if is_stream {
            self.inner.active_streams.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.evaluate();
        ConnectionGuard {
            inner: self.inner.clone(),
            is_stream,
        }
    }

    /// Record that a request was shed with `503` (Req 44.1 metric).
    fn record_shed(&self) {
        self.inner.shed_total.fetch_add(1, Ordering::SeqCst);
    }
}

/// A RAII guard representing one admitted in-flight connection. Releasing it
/// (on drop) decrements the connection counters and re-evaluates the load
/// state, which is how the guard reverses out of [`LoadState::Degraded`] once
/// enough connections finish (Req 44.4).
pub struct ConnectionGuard {
    inner: Arc<ControllerInner>,
    is_stream: bool,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.inner.active_connections.fetch_sub(1, Ordering::SeqCst);
        if self.is_stream {
            self.inner.active_streams.fetch_sub(1, Ordering::SeqCst);
        }
        self.inner.evaluate();
    }
}

// ---------------------------------------------------------------------------
// RSS sampler — cheap, periodic process resident-set-size gauge
// ---------------------------------------------------------------------------

/// Samples the current process's resident-set size (RSS) periodically and feeds
/// it into a [`LoadController`] (Req 44.2). The sampling is **periodic, not
/// per-request** so it stays lightweight (design: Technology Choices → "Process
/// RSS sampling … sampled (not per-request) to stay lightweight").
///
/// The reader is abstracted behind [`RssReader`] so the sampling loop is
/// testable without spawning a real process probe; the production reader is
/// [`SysinfoRssReader`] (backed by [`sysinfo`]).
pub struct RssSampler<R: RssReader> {
    controller: LoadController,
    reader: R,
    interval: Duration,
}

/// Abstracts the source of the process RSS figure so the sampler can be tested
/// deterministically (a fake reader) and so a `/proc/self/statm` fast-path can
/// replace the [`sysinfo`] reader later without touching the loop.
pub trait RssReader: Send + 'static {
    /// Read the current process RSS in bytes. Returns `None` when the figure is
    /// momentarily unavailable (the sampler then keeps the previous gauge).
    fn read_rss_bytes(&mut self) -> Option<u64>;
}

impl<R: RssReader> RssSampler<R> {
    /// Build a sampler over an explicit reader and sampling interval.
    pub fn new(controller: LoadController, reader: R, interval: Duration) -> Self {
        Self {
            controller,
            reader,
            interval,
        }
    }

    /// Take one sample now, updating the controller's RSS gauge and
    /// re-evaluating the load state. Returns the sampled bytes when available.
    pub fn sample_once(&mut self) -> Option<u64> {
        let bytes = self.reader.read_rss_bytes()?;
        self.controller.set_rss_bytes(bytes);
        Some(bytes)
    }

    /// Run the periodic sampling loop forever (intended to be spawned as a
    /// supervised background task in the binary's startup wiring). Each tick
    /// reads RSS and updates the gauge; a momentarily-unavailable reading is
    /// skipped, keeping the last good value.
    pub async fn run(mut self) {
        let mut ticker = tokio::time::interval(self.interval);
        // Skip the immediate first tick's "catch-up" behaviour so a stall does
        // not produce a burst of samples.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            self.sample_once();
        }
    }
}

/// The production [`RssReader`]: reads this process's RSS via [`sysinfo`],
/// refreshing only the current PID's memory on each sample to stay cheap
/// (Req 44.2). `sysinfo` reports process memory in **bytes** (0.30+), matching
/// the [`DegradationConfig::memory_high_water_bytes`] unit directly.
pub struct SysinfoRssReader {
    system: sysinfo::System,
    pid: Option<sysinfo::Pid>,
}

impl SysinfoRssReader {
    /// Build a reader bound to the current process. Returns `None` when the
    /// current PID cannot be determined (the caller then omits RSS-based
    /// shedding and relies on the connection counter alone).
    pub fn new() -> Option<Self> {
        let pid = sysinfo::get_current_pid().ok()?;
        Some(Self {
            system: sysinfo::System::new(),
            pid: Some(pid),
        })
    }
}

impl RssReader for SysinfoRssReader {
    fn read_rss_bytes(&mut self) -> Option<u64> {
        let pid = self.pid?;
        // Refresh only the current process (cheap), then read its RSS.
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        self.system.process(pid).map(|proc_| proc_.memory())
    }
}

// ---------------------------------------------------------------------------
// Actix middleware
// ---------------------------------------------------------------------------

/// The Degradation Guard actix middleware (Req 44.1, 44.3).
///
/// Install with `App::wrap(...)` / `Scope::wrap(...)`. On each request it:
///
/// 1. classifies the path ([`classify_path`]);
/// 2. if the request is sheddable **and** the guard is degraded, short-circuits
///    with `503 Service Unavailable` + `Retry-After` *without* admitting it
///    (Req 44.1) — active streams and exempt endpoints are never shed (Req
///    44.3);
/// 3. otherwise admits the request (incrementing the counters via
///    [`LoadController::admit`]) and ties the returned [`ConnectionGuard`] to
///    the response body so a streaming connection stays counted for its whole
///    delivery duration (Req 44.3).
///
/// Built from a shared [`LoadController`] so every worker shares one set of
/// counters and one [`LoadState`].
#[derive(Clone)]
pub struct DegradationGuard {
    controller: LoadController,
}

impl DegradationGuard {
    /// Build the middleware over a shared [`LoadController`].
    pub fn new(controller: LoadController) -> Self {
        Self { controller }
    }
}

impl<S, B> Transform<S, ServiceRequest> for DegradationGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<GuardedBody<B>, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = DegradationGuardService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DegradationGuardService {
            service: Rc::new(service),
            controller: self.controller.clone(),
        }))
    }
}

/// The instantiated guard service produced by [`DegradationGuard`].
pub struct DegradationGuardService<S> {
    service: Rc<S>,
    controller: LoadController,
}

impl<S, B> Service<ServiceRequest> for DegradationGuardService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<GuardedBody<B>, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let class = classify_path(req.path());

        // Shed a new sheddable request while degraded — *before* admitting it,
        // so a rejected request never counts toward the load (Req 44.1). The
        // `503` carries the canonical error envelope + a `Retry-After` hint.
        if self.controller.should_shed(class) {
            self.controller.record_shed();
            let err = AppError::upstream_unavailable(
                "service temporarily overloaded; new requests are shed while active \
                 streams are protected",
            )
            .with_retry_after(Duration::from_secs(RETRY_AFTER_SECS));
            let resp = req
                .into_response(err.error_response())
                .map_into_right_body();
            return Box::pin(async move { Ok(resp) });
        }

        // Admit the request; the guard rides along on the response body so a
        // streaming connection is counted for its entire delivery (Req 44.3).
        let guard = self.controller.admit(class);
        let fut = self.service.call(req);
        Box::pin(async move {
            let resp = fut.await?;
            Ok(resp.map_body(move |_, body| {
                EitherBody::left(GuardedBody {
                    body,
                    _guard: guard,
                })
            }))
        })
    }
}

/// A response body wrapper that holds the request's [`ConnectionGuard`] until
/// the body is fully delivered (or dropped on client disconnect), so the
/// connection counter reflects the true in-flight duration of streaming
/// responses (Req 44.3). It is otherwise a transparent pass-through to the
/// inner body.
pub struct GuardedBody<B> {
    body: B,
    _guard: ConnectionGuard,
}

impl<B: MessageBody> MessageBody for GuardedBody<B> {
    type Error = B::Error;

    fn size(&self) -> BodySize {
        self.body.size()
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        // Safe projection: we never move `body` out, and `_guard` is `Unpin`.
        let this = unsafe { self.get_unchecked_mut() };
        let body = unsafe { Pin::new_unchecked(&mut this.body) };
        body.poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Thresholds with a clear hysteresis gap (high=10, low=5) and a memory
    /// high-water mark, used by most tests.
    fn test_thresholds() -> LoadThresholds {
        LoadThresholds {
            enabled: true,
            conn_high_water: 10,
            conn_low_water: 5,
            memory_high_water_bytes: 1_000_000,
        }
    }

    // -- classify_path (Req 44.3) -------------------------------------------

    #[test]
    fn classify_streaming_paths_as_protected() {
        for path in [
            "/proxy/stream",
            "/proxy/hls/master.m3u8",
            "/proxy/mpd/manifest",
            "/proxy/segment/abc",
            "/proxy/telegram/123",
            "/proxy/acestream/xyz",
            "/get.php",
            "/v0/proxy",
            "/v0/events",
        ] {
            assert_eq!(
                classify_path(path),
                RequestClass::Stream,
                "{path} should be a protected stream"
            );
        }
    }

    #[test]
    fn classify_health_and_metrics_as_exempt() {
        assert_eq!(classify_path("/health"), RequestClass::Exempt);
        assert_eq!(classify_path("/health/ready"), RequestClass::Exempt);
        assert_eq!(classify_path("/metrics"), RequestClass::Exempt);
    }

    #[test]
    fn classify_other_api_paths_as_sheddable() {
        for path in [
            "/v0/store/magnets/check",
            "/v0/store/link/generate",
            "/generate_url",
            "/extractor/video",
            "/stremio/manifest.json",
            "/player_api.php",
        ] {
            assert_eq!(
                classify_path(path),
                RequestClass::Sheddable,
                "{path} should be sheddable"
            );
        }
    }

    #[test]
    fn ladder_engages_one_level_at_a_time_and_relaxes_in_reverse() {
        let ladder = DegradationLadder {
            on_thresholds: [10, 20, 30, 40, 50],
            off_thresholds: [5, 15, 25, 35, 45],
            cooldown_hold_secs: 10,
        };
        let l1 = ladder.next_level(DegradationLevel::L0Normal, 55, None);
        assert_eq!(l1, DegradationLevel::L1StopWarmup);
        let l2 = ladder.next_level(l1, 55, None);
        assert_eq!(l2, DegradationLevel::L2ShrinkCaches);
        assert_eq!(
            ladder.next_level(l2, 14, Some(9)),
            DegradationLevel::L2ShrinkCaches
        );
        assert_eq!(
            ladder.next_level(l2, 14, Some(10)),
            DegradationLevel::L1StopWarmup
        );
    }

    #[test]
    fn ladder_protects_active_streams_until_l5() {
        assert!(DegradationLevel::L4ShedNewStreams.protects_active_streams());
        assert!(!DegradationLevel::L5Emergency.protects_active_streams());
        assert_eq!(
            DegradationLadder::action(DegradationLevel::L2ShrinkCaches),
            "shrink_prebuffer_and_evict_segment_cache"
        );
    }

    // -- next_load_state hysteresis (Req 44.1, 44.4) ------------------------

    #[test]
    fn enters_degraded_at_conn_high_water() {
        let t = test_thresholds();
        // Just below high-water: stays Normal.
        assert_eq!(
            next_load_state(LoadState::Normal, 9, 0, &t),
            LoadState::Normal
        );
        // At high-water: enters Degraded.
        assert_eq!(
            next_load_state(LoadState::Normal, 10, 0, &t),
            LoadState::Degraded
        );
        // Above high-water: Degraded.
        assert_eq!(
            next_load_state(LoadState::Normal, 50, 0, &t),
            LoadState::Degraded
        );
    }

    #[test]
    fn enters_degraded_at_memory_high_water() {
        let t = test_thresholds();
        // Connections fine, but RSS over the memory mark → Degraded (Req 44.2).
        assert_eq!(
            next_load_state(LoadState::Normal, 0, 1_000_000, &t),
            LoadState::Degraded
        );
        assert_eq!(
            next_load_state(LoadState::Normal, 0, 999_999, &t),
            LoadState::Normal
        );
    }

    #[test]
    fn stays_degraded_within_hysteresis_gap() {
        let t = test_thresholds();
        // Between low (5) and high (10): a Degraded guard must NOT relax yet —
        // this is exactly the gap that prevents flapping (Req 44.4).
        for conns in [9, 8, 7, 6, 5] {
            assert_eq!(
                next_load_state(LoadState::Degraded, conns, 0, &t),
                LoadState::Degraded,
                "conns={conns} is within the hysteresis gap; must stay Degraded"
            );
        }
    }

    #[test]
    fn returns_to_normal_below_low_water() {
        let t = test_thresholds();
        // Strictly below low-water (5) AND RSS clear → relax to Normal.
        assert_eq!(
            next_load_state(LoadState::Degraded, 4, 0, &t),
            LoadState::Normal
        );
        assert_eq!(
            next_load_state(LoadState::Degraded, 0, 0, &t),
            LoadState::Normal
        );
    }

    #[test]
    fn does_not_relax_while_memory_still_high() {
        let t = test_thresholds();
        // Connections cleared but RSS still over the mark → stay Degraded.
        assert_eq!(
            next_load_state(LoadState::Degraded, 0, 1_000_000, &t),
            LoadState::Degraded
        );
    }

    #[test]
    fn disabled_guard_is_always_normal() {
        let mut t = test_thresholds();
        t.enabled = false;
        assert_eq!(
            next_load_state(LoadState::Normal, 10_000, u64::MAX, &t),
            LoadState::Normal
        );
        assert_eq!(
            next_load_state(LoadState::Degraded, 10_000, u64::MAX, &t),
            LoadState::Normal
        );
    }

    // -- shed_new_request (Req 44.1, 44.3) ----------------------------------

    #[test]
    fn sheds_only_sheddable_requests_while_degraded() {
        assert!(shed_new_request(
            LoadState::Degraded,
            RequestClass::Sheddable,
            true
        ));
        // Protected + exempt classes are never shed (Req 44.3).
        assert!(!shed_new_request(
            LoadState::Degraded,
            RequestClass::Stream,
            true
        ));
        assert!(!shed_new_request(
            LoadState::Degraded,
            RequestClass::Exempt,
            true
        ));
    }

    #[test]
    fn sheds_nothing_while_normal_or_disabled() {
        assert!(!shed_new_request(
            LoadState::Normal,
            RequestClass::Sheddable,
            true
        ));
        // Disabled guard never sheds even while (impossibly) marked degraded.
        assert!(!shed_new_request(
            LoadState::Degraded,
            RequestClass::Sheddable,
            false
        ));
    }

    // -- LoadController admit/release + transition accounting ----------------

    #[test]
    fn admit_release_flips_state_with_hysteresis_and_counts_transitions() {
        let ctrl = LoadController::new(test_thresholds());
        assert_eq!(ctrl.load_state(), LoadState::Normal);

        // Admit up to just below high-water: still Normal.
        let mut guards: Vec<ConnectionGuard> = (0..9)
            .map(|_| ctrl.admit(RequestClass::Sheddable))
            .collect();
        assert_eq!(ctrl.active_connections(), 9);
        assert_eq!(ctrl.load_state(), LoadState::Normal);

        // The 10th admit crosses the high-water mark → Degraded (one entry).
        guards.push(ctrl.admit(RequestClass::Sheddable));
        assert_eq!(ctrl.active_connections(), 10);
        assert_eq!(ctrl.load_state(), LoadState::Degraded);
        assert_eq!(ctrl.degraded_entries(), 1);

        // Drop down into the hysteresis gap (to 6 connections): stays Degraded.
        guards.truncate(6);
        assert_eq!(ctrl.active_connections(), 6);
        assert_eq!(
            ctrl.load_state(),
            LoadState::Degraded,
            "within gap stays degraded"
        );
        assert_eq!(ctrl.degraded_exits(), 0);

        // Drop below low-water (to 4): relaxes back to Normal (one exit).
        guards.truncate(4);
        assert_eq!(ctrl.active_connections(), 4);
        assert_eq!(ctrl.load_state(), LoadState::Normal);
        assert_eq!(ctrl.degraded_exits(), 1);

        // Releasing the rest leaves us Normal with no spurious transitions.
        drop(guards);
        assert_eq!(ctrl.active_connections(), 0);
        assert_eq!(ctrl.load_state(), LoadState::Normal);
        assert_eq!(ctrl.degraded_entries(), 1);
        assert_eq!(ctrl.degraded_exits(), 1);
    }

    #[test]
    fn streams_increment_the_protected_counter() {
        let ctrl = LoadController::new(test_thresholds());
        let s = ctrl.admit(RequestClass::Stream);
        let a = ctrl.admit(RequestClass::Sheddable);
        assert_eq!(ctrl.active_connections(), 2);
        assert_eq!(
            ctrl.active_streams(),
            1,
            "only the stream counts as protected"
        );
        drop(s);
        assert_eq!(ctrl.active_streams(), 0);
        drop(a);
        assert_eq!(ctrl.active_connections(), 0);
    }

    #[test]
    fn should_shed_reflects_live_state() {
        let ctrl = LoadController::new(test_thresholds());
        // Normal: nothing shed.
        assert!(!ctrl.should_shed(RequestClass::Sheddable));

        let _guards: Vec<_> = (0..10)
            .map(|_| ctrl.admit(RequestClass::Sheddable))
            .collect();
        assert_eq!(ctrl.load_state(), LoadState::Degraded);
        // Degraded: sheddable shed, protected/exempt not (Req 44.1, 44.3).
        assert!(ctrl.should_shed(RequestClass::Sheddable));
        assert!(!ctrl.should_shed(RequestClass::Stream));
        assert!(!ctrl.should_shed(RequestClass::Exempt));
    }

    #[test]
    fn rss_gauge_drives_state_via_set_rss_bytes() {
        let ctrl = LoadController::new(test_thresholds());
        assert_eq!(ctrl.set_rss_bytes(1_500_000), LoadState::Degraded);
        assert_eq!(ctrl.rss_bytes(), 1_500_000);
        assert_eq!(ctrl.degraded_entries(), 1);

        // Dropping RSS below the mark (with no connections) relaxes to Normal.
        assert_eq!(ctrl.set_rss_bytes(10), LoadState::Normal);
        assert_eq!(ctrl.degraded_exits(), 1);
    }

    #[test]
    fn from_config_projects_thresholds() {
        let cfg = DegradationConfig::default();
        let ctrl = LoadController::from_config(&cfg);
        let t = ctrl.thresholds();
        assert_eq!(t.enabled, cfg.enabled);
        assert_eq!(t.conn_high_water, cfg.conn_high_water as u64);
        assert_eq!(t.conn_low_water, cfg.conn_low_water as u64);
        assert_eq!(t.memory_high_water_bytes, cfg.memory_high_water_bytes);
    }

    // -- RSS sampler with a fake reader (Req 44.2) --------------------------

    struct FakeRssReader {
        readings: std::cell::RefCell<Vec<Option<u64>>>,
    }

    impl FakeRssReader {
        fn new(readings: Vec<Option<u64>>) -> Self {
            Self {
                readings: std::cell::RefCell::new(readings),
            }
        }
    }

    impl RssReader for FakeRssReader {
        fn read_rss_bytes(&mut self) -> Option<u64> {
            let mut r = self.readings.borrow_mut();
            if r.is_empty() {
                None
            } else {
                r.remove(0)
            }
        }
    }

    #[test]
    fn sampler_updates_gauge_and_skips_unavailable_readings() {
        let ctrl = LoadController::new(test_thresholds());
        let reader = FakeRssReader::new(vec![Some(2_000_000), None, Some(5)]);
        let mut sampler = RssSampler::new(ctrl.clone(), reader, Duration::from_secs(1));

        // First sample: over the mark → Degraded, gauge updated.
        assert_eq!(sampler.sample_once(), Some(2_000_000));
        assert_eq!(ctrl.rss_bytes(), 2_000_000);
        assert_eq!(ctrl.load_state(), LoadState::Degraded);

        // Unavailable reading: keeps the previous gauge, no change.
        assert_eq!(sampler.sample_once(), None);
        assert_eq!(ctrl.rss_bytes(), 2_000_000);
        assert_eq!(ctrl.load_state(), LoadState::Degraded);

        // Recovered low reading: relaxes to Normal.
        assert_eq!(sampler.sample_once(), Some(5));
        assert_eq!(ctrl.rss_bytes(), 5);
        assert_eq!(ctrl.load_state(), LoadState::Normal);
    }

    #[test]
    fn sysinfo_reader_reads_a_plausible_rss_for_this_process() {
        // The production reader should produce a non-zero RSS for the running
        // test process (sysinfo reports bytes in 0.30+, so this is well above
        // any kilobyte-era confusion).
        if let Some(mut reader) = SysinfoRssReader::new() {
            // First refresh may need a warm-up on some platforms; sample twice.
            let _ = reader.read_rss_bytes();
            if let Some(rss) = reader.read_rss_bytes() {
                assert!(rss > 0, "current-process RSS should be > 0 bytes");
            }
        }
    }

    // -- /health exposure (Req 44.6) ----------------------------------------

    #[test]
    fn load_state_surfaces_through_health_probes() {
        use crate::health::{HealthInputs, HealthProbes, StoreBreaker};

        // A HealthProbes impl backed by the controller is exactly how the
        // composite probe surfaces the guard's load state via `/health`.
        struct ProbesFromController(LoadController);
        impl HealthProbes for ProbesFromController {
            fn sqlite_reachable(&self) -> bool {
                true
            }
            fn load_state(&self) -> LoadState {
                self.0.load_state()
            }
            fn store_breakers(&self) -> Vec<StoreBreaker> {
                Vec::new()
            }
        }

        let ctrl = LoadController::new(test_thresholds());
        let probes = ProbesFromController(ctrl.clone());

        // Normal: the load component is Up and readiness is ready.
        assert_eq!(probes.load_state(), LoadState::Normal);

        // Drive the controller to Degraded, then build the health snapshot the
        // way the registry does, and confirm `/health` reflects the degraded
        // load (readiness sheds traffic — Req 44.3, 44.6).
        let _guards: Vec<_> = (0..10)
            .map(|_| ctrl.admit(RequestClass::Sheddable))
            .collect();
        assert_eq!(probes.load_state(), LoadState::Degraded);

        let inputs = HealthInputs {
            migrations_applied: true,
            config_valid: true,
            sqlite_reachable: true,
            startup_probes_done: true,
            liveness_fresh: true,
            load: probes.load_state(),
            stores: vec![],
            extra: vec![],
        };
        assert!(inputs.load.sheds_traffic());
        assert!(
            !inputs.readiness_ready(),
            "degraded load → not ready (Req 44.3)"
        );
        let load_component = inputs
            .components()
            .into_iter()
            .find(|c| c.name == "load")
            .expect("load component present");
        assert_eq!(load_component.detail.as_deref(), Some("degraded"));
    }
}

#[cfg(test)]
mod middleware_tests {
    //! Actix integration tests for the [`DegradationGuard`] middleware
    //! (Req 44.1, 44.3): a sheddable request is `503`'d while degraded, active
    //! streams and exempt endpoints keep flowing, and the flip is reversible.
    use super::*;
    use actix_web::{test, web, App, HttpResponse};

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().body("ok")
    }

    #[actix_web::test]
    async fn sheddable_request_gets_503_while_degraded() {
        // Pin the guard into Degraded via RSS so the state is set before the
        // request, deterministically.
        let degraded_thresholds = LoadThresholds {
            enabled: true,
            conn_high_water: 1,
            conn_low_water: 1,
            memory_high_water_bytes: 100,
        };
        let ctrl = LoadController::new(degraded_thresholds);
        ctrl.set_rss_bytes(1_000);
        assert_eq!(ctrl.load_state(), LoadState::Degraded);

        let app = test::init_service(
            App::new()
                .wrap(DegradationGuard::new(ctrl.clone()))
                .route("/v0/store/check", web::get().to(ok)),
        )
        .await;

        let req = test::TestRequest::get().uri("/v0/store/check").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            503,
            "sheddable request shed with 503"
        );
        assert!(
            resp.headers().contains_key("retry-after"),
            "shed 503 carries Retry-After"
        );
        // The shed request was rejected before admission → not counted, and the
        // shed metric incremented.
        assert_eq!(ctrl.active_connections(), 0);
        assert_eq!(ctrl.shed_total(), 1);
    }

    #[actix_web::test]
    async fn streaming_request_is_served_while_degraded() {
        let degraded_thresholds = LoadThresholds {
            enabled: true,
            conn_high_water: 1,
            conn_low_water: 1,
            memory_high_water_bytes: 100,
        };
        let ctrl = LoadController::new(degraded_thresholds);
        ctrl.set_rss_bytes(1_000);
        assert_eq!(ctrl.load_state(), LoadState::Degraded);

        let app = test::init_service(
            App::new()
                .wrap(DegradationGuard::new(ctrl.clone()))
                .route("/proxy/stream", web::get().to(ok)),
        )
        .await;

        // A protected stream is served normally even while degraded (Req 44.3).
        let req = test::TestRequest::get().uri("/proxy/stream").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
        let body = test::read_body(resp).await;
        assert_eq!(&body[..], b"ok");
    }

    #[actix_web::test]
    async fn exempt_health_is_served_while_degraded() {
        let degraded_thresholds = LoadThresholds {
            enabled: true,
            conn_high_water: 1,
            conn_low_water: 1,
            memory_high_water_bytes: 100,
        };
        let ctrl = LoadController::new(degraded_thresholds);
        ctrl.set_rss_bytes(1_000);
        assert_eq!(ctrl.load_state(), LoadState::Degraded);

        let app = test::init_service(
            App::new()
                .wrap(DegradationGuard::new(ctrl.clone()))
                .route("/health", web::get().to(ok)),
        )
        .await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "health always answers (Req 44.6)"
        );
    }

    #[actix_web::test]
    async fn admitted_request_releases_connection_after_response() {
        // With the guard Normal, a sheddable request is admitted, served, and
        // its connection released once the response body is consumed — so the
        // counter returns to zero (the basis of reversibility, Req 44.4).
        let ctrl = LoadController::new(LoadThresholds {
            enabled: true,
            conn_high_water: 100,
            conn_low_water: 50,
            memory_high_water_bytes: u64::MAX,
        });
        let app = test::init_service(
            App::new()
                .wrap(DegradationGuard::new(ctrl.clone()))
                .route("/v0/store/check", web::get().to(ok)),
        )
        .await;

        let req = test::TestRequest::get().uri("/v0/store/check").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
        // Consume the body so the GuardedBody (and its ConnectionGuard) drops.
        let _ = test::read_body(resp).await;
        assert_eq!(
            ctrl.active_connections(),
            0,
            "connection released after delivery"
        );
    }

    #[actix_web::test]
    async fn disabled_guard_admits_everything() {
        let ctrl = LoadController::new(LoadThresholds {
            enabled: false,
            conn_high_water: 1,
            conn_low_water: 1,
            memory_high_water_bytes: 1,
        });
        ctrl.set_rss_bytes(u64::MAX); // would degrade if enabled
        assert_eq!(
            ctrl.load_state(),
            LoadState::Normal,
            "disabled → always Normal"
        );

        let app = test::init_service(
            App::new()
                .wrap(DegradationGuard::new(ctrl.clone()))
                .route("/v0/store/check", web::get().to(ok)),
        )
        .await;

        let req = test::TestRequest::get().uri("/v0/store/check").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "disabled guard sheds nothing");
    }
}
