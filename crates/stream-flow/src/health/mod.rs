//! Health model & probes (`health`) — Req 50.10, 50.13, 32.4, 44.6, 29.2.
//!
//! The single `/health` endpoint expresses the three orchestration-standard
//! probe semantics (Kubernetes/Docker/Compose), distinguishing **liveness**
//! from **readiness** and adding a **startup** probe; a `?probe=` query
//! parameter selects the view and the component breakdown is always available
//! for humans/dashboards (design: Resilience → Pattern 6 "Health Model &
//! Probes"; Components → Health, readiness & liveness).
//!
//! ## Probe semantics (design: Pattern 6 table)
//!
//! | Probe | Healthy iff | Drives |
//! |---|---|---|
//! | **Liveness** | the async runtime is responsive — a watchdog heartbeat is fresh (no event-loop deadlock) | orchestrator **restarts** the container |
//! | **Readiness** | migrations applied (Req 29.2), config valid, SQLite reachable, load not degraded-to-not-ready (Req 44.1/44.6), **and** not all configured store breakers `Open` (Req 50.3) | orchestrator **routes traffic away** without killing the instance |
//! | **Startup** | migrations complete (Req 29.2) **and** one-time detection done (FFmpeg encoder probe, Req 6.7/49.5) | hold traffic until boot completes |
//!
//! Readiness intentionally **degrades to not-ready** (rather than down) under
//! overload or a total store outage so the load balancer sheds traffic to
//! healthier replicas while active streams on this replica keep flowing
//! (Req 44.3, 50.11). **Liveness stays green during overload** (the process is
//! healthy, just busy) so the orchestrator does *not* kill an instance that is
//! merely under load — a critical distinction that prevents restart storms.
//!
//! ## Decoupling
//!
//! The readiness/liveness/startup predicates are pure functions over a
//! fully-gathered, plain-data [`HealthInputs`] snapshot, so they are exhaustively
//! unit/property-testable offline (the property test is task 7.6). The live
//! [`HealthRegistry`] gathers that snapshot from abstracted signal sources (the
//! [`HealthProbes`] trait for SQLite reachability, load state, and store-breaker
//! enumeration) plus its own boot/heartbeat flags, so it wires to concrete
//! components (persistence, the Degradation Guard, the breaker registry) later
//! **without** tight coupling.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, HttpResponse};

use crate::resilience::breaker::{BreakerState, Clock, SystemClock};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Which probe view `/health?probe=` selects (design: Pattern 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    /// Is the process alive / the runtime responsive? (orchestrator restarts on failure)
    Liveness,
    /// Should this instance receive traffic? (orchestrator routes away on failure)
    Readiness,
    /// Has boot completed? (hold traffic until complete)
    Startup,
}

impl ProbeKind {
    /// Parse the `?probe=` query value; unrecognized/empty values yield `None`
    /// (the caller then renders the overall human/dashboard view).
    pub fn parse(value: &str) -> Option<ProbeKind> {
        match value {
            "liveness" => Some(ProbeKind::Liveness),
            "readiness" => Some(ProbeKind::Readiness),
            "startup" => Some(ProbeKind::Startup),
            _ => None,
        }
    }
}

/// Overall service health (design: Pattern 6 `HealthReport.status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Fully healthy and ready.
    Ok,
    /// Ready, but at least one non-critical component is degraded or down
    /// (e.g. Redis fell back to local, or one of several store breakers is open).
    Degraded,
    /// Should not receive traffic right now — overload or a total store outage
    /// (readiness degrades to not-ready, Req 44.3, 50.11), or a core readiness
    /// signal (migrations/config/SQLite) is unmet.
    NotReady,
    /// Still booting — migrations and/or one-time startup probes incomplete.
    Starting,
}

/// Current load state exposed via the health endpoint (Req 44.6).
///
/// The full L1–L5 degradation ladder lands in task 29; here the guard reports
/// the coarse `Normal | Degraded` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadState {
    /// Below the high-water marks; accepting new requests normally.
    Normal,
    /// Above a high-water mark; shedding new non-streaming requests (Req 44.1).
    Degraded,
}

impl LoadState {
    /// Whether this load state sheds new traffic, and therefore degrades
    /// readiness to not-ready (Req 44.1, 44.3).
    pub fn sheds_traffic(self) -> bool {
        matches!(self, LoadState::Degraded)
    }
}

/// Per-component health in the breakdown (design: Pattern 6 `ComponentState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    /// Healthy.
    Up,
    /// Working but impaired (e.g. breaker half-open, or serving from fallback).
    Degraded,
    /// Unavailable.
    Down,
    /// Not yet determined.
    Unknown,
}

impl ComponentState {
    /// Map a circuit-breaker state to a component state: `Closed → Up`,
    /// `HalfOpen → Degraded`, `Open → Down`.
    pub fn from_breaker(state: BreakerState) -> ComponentState {
        match state {
            BreakerState::Closed => ComponentState::Up,
            BreakerState::HalfOpen => ComponentState::Degraded,
            BreakerState::Open => ComponentState::Down,
        }
    }
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// One component's health line in the breakdown (design: Pattern 6).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ComponentHealth {
    /// Stable identifier, e.g. `"store:realdebrid"`, `"redis"`, `"sqlite"`, `"load"`.
    pub name: String,
    /// The component's coarse state.
    pub state: ComponentState,
    /// The dependency's breaker state, for breaker-backed components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaker: Option<BreakerState>,
    /// Optional human-readable detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ComponentHealth {
    /// Build a component line.
    pub fn new(
        name: impl Into<String>,
        state: ComponentState,
        breaker: Option<BreakerState>,
        detail: Option<String>,
    ) -> Self {
        Self { name: name.into(), state, breaker, detail }
    }
}

/// The serialized health response body (design: Pattern 6 `HealthReport`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct HealthReport {
    /// Overall service health.
    pub status: HealthStatus,
    /// Current load state (Req 44.6).
    pub load: LoadState,
    /// Per-component breakdown (always present for humans/dashboards).
    pub components: Vec<ComponentHealth>,
}

/// The outcome of a single probe evaluation: whether the probe is healthy
/// (drives the HTTP status — `200` vs `503`) plus the full report body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// `true` → the probe passes (`200 OK`); `false` → it fails (`503`).
    pub healthy: bool,
    /// The full health report rendered alongside the probe result.
    pub report: HealthReport,
}

// ---------------------------------------------------------------------------
// Inputs (plain data) + pure predicates
// ---------------------------------------------------------------------------

/// A single store's breaker state, named for the component breakdown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreBreaker {
    /// Store identifier (e.g. `"realdebrid"`).
    pub name: String,
    /// The store breaker's current state.
    pub state: BreakerState,
}

impl StoreBreaker {
    /// Convenience constructor.
    pub fn new(name: impl Into<String>, state: BreakerState) -> Self {
        Self { name: name.into(), state }
    }
}

/// A fully-gathered, plain-data snapshot of every readiness/liveness/startup
/// input. The probe predicates below are **pure** over this value, so they are
/// exhaustively testable offline (property test: task 7.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthInputs {
    /// All pending migrations have been applied (Req 29.2).
    pub migrations_applied: bool,
    /// Configuration validated successfully at load.
    pub config_valid: bool,
    /// SQLite is currently reachable.
    pub sqlite_reachable: bool,
    /// One-time startup detection (e.g. FFmpeg encoder probe) has completed
    /// (Req 6.7/49.5).
    pub startup_probes_done: bool,
    /// The liveness watchdog heartbeat is fresh (runtime responsive).
    pub liveness_fresh: bool,
    /// Current load state (Req 44.6).
    pub load: LoadState,
    /// Configured store breakers (empty when no store is configured).
    pub stores: Vec<StoreBreaker>,
    /// Extra component lines (redis, integrations, …) for the breakdown only;
    /// they do not affect the readiness predicate.
    pub extra: Vec<ComponentHealth>,
}

impl HealthInputs {
    /// Whether **every** configured store breaker is `Open` — i.e. no store can
    /// resolve a stream right now (Req 50.3). Vacuously `false` when no store is
    /// configured, so a store-less deployment is never marked not-ready on this
    /// account.
    pub fn all_stores_open(&self) -> bool {
        !self.stores.is_empty()
            && self.stores.iter().all(|s| s.state == BreakerState::Open)
    }

    /// Readiness predicate (Req 50.10): ready **iff** migrations applied,
    /// config valid, SQLite reachable, load not degraded-to-not-ready, **and**
    /// not all store breakers are `Open`.
    pub fn readiness_ready(&self) -> bool {
        self.migrations_applied
            && self.config_valid
            && self.sqlite_reachable
            && !self.load.sheds_traffic()
            && !self.all_stores_open()
    }

    /// Liveness predicate (Req 50.10): alive **iff** the watchdog heartbeat is
    /// fresh. Deliberately **independent** of load and readiness, so an instance
    /// that is merely busy (overloaded / shedding) is not killed.
    pub fn liveness_alive(&self) -> bool {
        self.liveness_fresh
    }

    /// Startup predicate (Req 29.2, 6.7): complete **iff** migrations are
    /// applied **and** one-time startup probes have finished.
    pub fn startup_complete(&self) -> bool {
        self.migrations_applied && self.startup_probes_done
    }

    /// Overall status for the human/dashboard view: `Starting` until boot
    /// completes, then `NotReady` if readiness is not met, then `Degraded` if a
    /// non-critical component is impaired, else `Ok`.
    pub fn status(&self) -> HealthStatus {
        if !self.startup_complete() {
            HealthStatus::Starting
        } else if !self.readiness_ready() {
            HealthStatus::NotReady
        } else if self.any_component_impaired() {
            HealthStatus::Degraded
        } else {
            HealthStatus::Ok
        }
    }

    /// Whether any component in the breakdown is degraded or down (used to
    /// distinguish `Ok` from `Degraded` once the instance is ready).
    fn any_component_impaired(&self) -> bool {
        let store_impaired = self
            .stores
            .iter()
            .any(|s| s.state != BreakerState::Closed);
        let extra_impaired = self
            .extra
            .iter()
            .any(|c| matches!(c.state, ComponentState::Degraded | ComponentState::Down));
        store_impaired || extra_impaired
    }

    /// Build the always-present component breakdown: SQLite, load, every
    /// configured store breaker, then any extra components.
    pub fn components(&self) -> Vec<ComponentHealth> {
        let mut out = Vec::with_capacity(2 + self.stores.len() + self.extra.len());

        out.push(ComponentHealth::new(
            "sqlite",
            if self.sqlite_reachable { ComponentState::Up } else { ComponentState::Down },
            None,
            None,
        ));
        out.push(ComponentHealth::new(
            "load",
            if self.load.sheds_traffic() { ComponentState::Degraded } else { ComponentState::Up },
            None,
            Some(match self.load {
                LoadState::Normal => "normal".to_string(),
                LoadState::Degraded => "degraded".to_string(),
            }),
        ));

        for store in &self.stores {
            out.push(ComponentHealth::new(
                format!("store:{}", store.name),
                ComponentState::from_breaker(store.state),
                Some(store.state),
                None,
            ));
        }

        out.extend(self.extra.iter().cloned());
        out
    }

    /// The full report body.
    pub fn report(&self) -> HealthReport {
        HealthReport { status: self.status(), load: self.load, components: self.components() }
    }

    /// Evaluate a single probe view, returning whether it is healthy plus the
    /// full report body.
    pub fn probe(&self, kind: ProbeKind) -> ProbeOutcome {
        let healthy = match kind {
            ProbeKind::Liveness => self.liveness_alive(),
            ProbeKind::Readiness => self.readiness_ready(),
            ProbeKind::Startup => self.startup_complete(),
        };
        ProbeOutcome { healthy, report: self.report() }
    }
}

// ---------------------------------------------------------------------------
// Abstracted signal sources
// ---------------------------------------------------------------------------

/// The abstracted live-signal sources the [`HealthRegistry`] reads on each
/// evaluation. Implemented later by the concrete components (persistence pool,
/// Degradation Guard, breaker registry) so the registry stays decoupled.
pub trait HealthProbes: Send + Sync {
    /// Is SQLite currently reachable? (cheap, e.g. a cached last-probe result).
    fn sqlite_reachable(&self) -> bool;
    /// Current load state from the Degradation Guard (Req 44.6).
    fn load_state(&self) -> LoadState;
    /// Configured store breakers and their states (Req 50.3).
    fn store_breakers(&self) -> Vec<StoreBreaker>;
    /// Extra component lines for the breakdown (redis, integrations, …). These
    /// are informational and do not affect readiness.
    fn extra_components(&self) -> Vec<ComponentHealth> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// HealthRegistry
// ---------------------------------------------------------------------------

/// The live health registry: holds boot flags and a liveness heartbeat, reads
/// abstracted live signals via [`HealthProbes`], and produces a [`HealthReport`]
/// / [`ProbeOutcome`] on demand. Cheap to clone — clones share the same state.
#[derive(Clone)]
pub struct HealthRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    migrations_applied: AtomicBool,
    config_valid: AtomicBool,
    startup_probes_done: AtomicBool,
    /// `clock.now_millis()` at the last liveness heartbeat.
    last_heartbeat_millis: AtomicU64,
    /// How stale the heartbeat may get before liveness fails.
    liveness_bound_millis: u64,
    clock: Arc<dyn Clock>,
    probes: Arc<dyn HealthProbes>,
}

impl HealthRegistry {
    /// Build a registry over the real [`SystemClock`]. Starts with the
    /// heartbeat fresh, config assumed valid, and migrations/startup-probes
    /// pending (so the instance reports `Starting` until boot marks them done).
    pub fn new(probes: Arc<dyn HealthProbes>, liveness_bound: Duration) -> Self {
        Self::with_clock(probes, liveness_bound, Arc::new(SystemClock::new()))
    }

    /// Build a registry with an injected [`Clock`] (deterministic
    /// heartbeat-freshness tests use a `ManualClock`).
    pub fn with_clock(
        probes: Arc<dyn HealthProbes>,
        liveness_bound: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let now = clock.now_millis();
        Self {
            inner: Arc::new(RegistryInner {
                migrations_applied: AtomicBool::new(false),
                config_valid: AtomicBool::new(true),
                startup_probes_done: AtomicBool::new(false),
                last_heartbeat_millis: AtomicU64::new(now),
                liveness_bound_millis: liveness_bound.as_millis() as u64,
                clock,
                probes,
            }),
        }
    }

    /// Mark migrations as applied (called once the startup migrator finishes,
    /// Req 29.2).
    pub fn set_migrations_applied(&self, applied: bool) {
        self.inner.migrations_applied.store(applied, Ordering::SeqCst);
    }

    /// Mark configuration validity (Req 31.7); defaults to `true`.
    pub fn set_config_valid(&self, valid: bool) {
        self.inner.config_valid.store(valid, Ordering::SeqCst);
    }

    /// Mark one-time startup detection (FFmpeg encoder probe, Req 6.7/49.5) as
    /// done.
    pub fn set_startup_probes_done(&self, done: bool) {
        self.inner.startup_probes_done.store(done, Ordering::SeqCst);
    }

    /// Record a liveness heartbeat — called by the runtime watchdog task; the
    /// heartbeat going stale is exactly what trips the liveness probe.
    pub fn heartbeat(&self) {
        self.inner
            .last_heartbeat_millis
            .store(self.inner.clock.now_millis(), Ordering::SeqCst);
    }

    /// Whether the heartbeat is fresh (within `liveness_bound`).
    pub fn liveness_fresh(&self) -> bool {
        let now = self.inner.clock.now_millis();
        let last = self.inner.last_heartbeat_millis.load(Ordering::SeqCst);
        now.saturating_sub(last) <= self.inner.liveness_bound_millis
    }

    /// Gather a plain-data [`HealthInputs`] snapshot from the boot flags,
    /// heartbeat, and abstracted live signals.
    pub fn snapshot(&self) -> HealthInputs {
        HealthInputs {
            migrations_applied: self.inner.migrations_applied.load(Ordering::SeqCst),
            config_valid: self.inner.config_valid.load(Ordering::SeqCst),
            sqlite_reachable: self.inner.probes.sqlite_reachable(),
            startup_probes_done: self.inner.startup_probes_done.load(Ordering::SeqCst),
            liveness_fresh: self.liveness_fresh(),
            load: self.inner.probes.load_state(),
            stores: self.inner.probes.store_breakers(),
            extra: self.inner.probes.extra_components(),
        }
    }

    /// The full report body (overall human/dashboard view).
    pub fn report(&self) -> HealthReport {
        self.snapshot().report()
    }

    /// Evaluate a single probe view.
    pub fn probe(&self, kind: ProbeKind) -> ProbeOutcome {
        self.snapshot().probe(kind)
    }
}

// ---------------------------------------------------------------------------
// HTTP views — `/health?probe=liveness|readiness|startup`
// ---------------------------------------------------------------------------

/// Query string for the health endpoint: `?probe=liveness|readiness|startup`.
#[derive(Debug, serde::Deserialize)]
pub struct ProbeQuery {
    /// The probe view to render; absent/unknown → overall human view.
    pub probe: Option<String>,
}

/// Render a probe outcome as an HTTP response: `200 OK` when healthy, `503
/// Service Unavailable` when not, both carrying the JSON [`HealthReport`].
fn probe_response(outcome: ProbeOutcome) -> HttpResponse {
    if outcome.healthy {
        HttpResponse::Ok().json(outcome.report)
    } else {
        HttpResponse::ServiceUnavailable().json(outcome.report)
    }
}

/// Render the overall human/dashboard view: `200 OK` for `Ok`/`Degraded`,
/// `503` for `NotReady`/`Starting` (Req 32.4 overall service health).
fn overall_response(report: HealthReport) -> HttpResponse {
    match report.status {
        HealthStatus::Ok | HealthStatus::Degraded => HttpResponse::Ok().json(report),
        HealthStatus::NotReady | HealthStatus::Starting => {
            HttpResponse::ServiceUnavailable().json(report)
        }
    }
}

/// The `/health` handler. Selects a probe view from `?probe=` and renders the
/// appropriate status code + JSON body (design: Pattern 6 `/health?probe=`).
///
/// Wired into the dual-surface router with `AppState` in task 11.2; here it
/// reads the shared [`HealthRegistry`] from actix app data.
pub async fn health_endpoint(
    query: web::Query<ProbeQuery>,
    registry: web::Data<HealthRegistry>,
) -> HttpResponse {
    match query.probe.as_deref().and_then(ProbeKind::parse) {
        Some(kind) => probe_response(registry.probe(kind)),
        None => overall_response(registry.report()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resilience::breaker::ManualClock;

    // -- Input builders -----------------------------------------------------

    /// A fully-healthy, ready, booted instance with one closed store breaker.
    fn healthy_inputs() -> HealthInputs {
        HealthInputs {
            migrations_applied: true,
            config_valid: true,
            sqlite_reachable: true,
            startup_probes_done: true,
            liveness_fresh: true,
            load: LoadState::Normal,
            stores: vec![StoreBreaker::new("realdebrid", BreakerState::Closed)],
            extra: vec![],
        }
    }

    // -- Readiness ----------------------------------------------------------

    #[test]
    fn ready_when_all_signals_healthy() {
        assert!(healthy_inputs().readiness_ready());
        assert_eq!(healthy_inputs().status(), HealthStatus::Ok);
    }

    #[test]
    fn not_ready_when_migrations_not_applied() {
        let mut i = healthy_inputs();
        i.migrations_applied = false;
        assert!(!i.readiness_ready());
    }

    #[test]
    fn not_ready_when_config_invalid() {
        let mut i = healthy_inputs();
        i.config_valid = false;
        assert!(!i.readiness_ready());
    }

    #[test]
    fn not_ready_when_sqlite_unreachable() {
        let mut i = healthy_inputs();
        i.sqlite_reachable = false;
        assert!(!i.readiness_ready());
    }

    #[test]
    fn not_ready_when_load_degraded_to_not_ready() {
        let mut i = healthy_inputs();
        i.load = LoadState::Degraded;
        assert!(!i.readiness_ready());
        assert_eq!(i.status(), HealthStatus::NotReady);
    }

    #[test]
    fn not_ready_when_all_store_breakers_open() {
        let mut i = healthy_inputs();
        i.stores = vec![
            StoreBreaker::new("realdebrid", BreakerState::Open),
            StoreBreaker::new("alldebrid", BreakerState::Open),
        ];
        assert!(i.all_stores_open());
        assert!(!i.readiness_ready());
    }

    #[test]
    fn ready_when_some_but_not_all_store_breakers_open() {
        let mut i = healthy_inputs();
        i.stores = vec![
            StoreBreaker::new("realdebrid", BreakerState::Open),
            StoreBreaker::new("alldebrid", BreakerState::Closed),
        ];
        assert!(!i.all_stores_open());
        assert!(i.readiness_ready());
        // ready but impaired → Degraded, not Ok.
        assert_eq!(i.status(), HealthStatus::Degraded);
    }

    #[test]
    fn ready_when_no_stores_configured() {
        let mut i = healthy_inputs();
        i.stores = vec![];
        assert!(!i.all_stores_open(), "vacuously not all-open with zero stores");
        assert!(i.readiness_ready());
    }

    // -- Liveness independence ----------------------------------------------

    #[test]
    fn liveness_alive_while_heartbeat_fresh_independent_of_readiness() {
        // Overloaded + all stores open + config invalid + sqlite down: NOT ready,
        // yet liveness stays alive because the heartbeat is fresh (no deadlock).
        let i = HealthInputs {
            migrations_applied: false,
            config_valid: false,
            sqlite_reachable: false,
            startup_probes_done: false,
            liveness_fresh: true,
            load: LoadState::Degraded,
            stores: vec![StoreBreaker::new("realdebrid", BreakerState::Open)],
            extra: vec![],
        };
        assert!(!i.readiness_ready(), "not ready under overload/outage");
        assert!(i.liveness_alive(), "liveness independent of readiness/load");
    }

    #[test]
    fn liveness_dead_when_heartbeat_stale() {
        let mut i = healthy_inputs();
        i.liveness_fresh = false;
        assert!(!i.liveness_alive());
        // ...even though everything else is healthy and ready.
        assert!(i.readiness_ready());
    }

    // -- Startup ------------------------------------------------------------

    #[test]
    fn startup_gates_on_migrations_and_one_time_probes() {
        let mut i = healthy_inputs();

        i.migrations_applied = false;
        i.startup_probes_done = false;
        assert!(!i.startup_complete());
        assert_eq!(i.status(), HealthStatus::Starting);

        i.migrations_applied = true;
        i.startup_probes_done = false;
        assert!(!i.startup_complete(), "migrations done but probes pending");

        i.migrations_applied = false;
        i.startup_probes_done = true;
        assert!(!i.startup_complete(), "probes done but migrations pending");

        i.migrations_applied = true;
        i.startup_probes_done = true;
        assert!(i.startup_complete());
    }

    // -- Component breakdown ------------------------------------------------

    #[test]
    fn component_breakdown_reports_sqlite_load_and_stores() {
        let mut i = healthy_inputs();
        i.load = LoadState::Degraded;
        i.stores = vec![
            StoreBreaker::new("realdebrid", BreakerState::Open),
            StoreBreaker::new("alldebrid", BreakerState::HalfOpen),
        ];
        i.extra = vec![ComponentHealth::new("redis", ComponentState::Down, None, None)];

        let components = i.components();
        let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"sqlite"));
        assert!(names.contains(&"load"));
        assert!(names.contains(&"store:realdebrid"));
        assert!(names.contains(&"store:alldebrid"));
        assert!(names.contains(&"redis"));

        let rd = components.iter().find(|c| c.name == "store:realdebrid").unwrap();
        assert_eq!(rd.state, ComponentState::Down);
        assert_eq!(rd.breaker, Some(BreakerState::Open));

        let ad = components.iter().find(|c| c.name == "store:alldebrid").unwrap();
        assert_eq!(ad.state, ComponentState::Degraded);
        assert_eq!(ad.breaker, Some(BreakerState::HalfOpen));

        let load = components.iter().find(|c| c.name == "load").unwrap();
        assert_eq!(load.state, ComponentState::Degraded);
    }

    // -- Registry / heartbeat freshness -------------------------------------

    struct FakeProbes {
        sqlite: bool,
        load: LoadState,
        stores: Vec<StoreBreaker>,
    }

    impl HealthProbes for FakeProbes {
        fn sqlite_reachable(&self) -> bool {
            self.sqlite
        }
        fn load_state(&self) -> LoadState {
            self.load
        }
        fn store_breakers(&self) -> Vec<StoreBreaker> {
            self.stores.clone()
        }
    }

    fn registry_with(
        probes: FakeProbes,
        bound: Duration,
    ) -> (HealthRegistry, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new());
        let reg = HealthRegistry::with_clock(Arc::new(probes), bound, clock.clone());
        (reg, clock)
    }

    #[test]
    fn registry_starts_in_starting_state_until_boot_marked() {
        let (reg, _clock) = registry_with(
            FakeProbes {
                sqlite: true,
                load: LoadState::Normal,
                stores: vec![StoreBreaker::new("rd", BreakerState::Closed)],
            },
            Duration::from_secs(10),
        );
        // Fresh registry: migrations + startup probes pending → Starting.
        assert_eq!(reg.report().status, HealthStatus::Starting);
        assert!(!reg.probe(ProbeKind::Startup).healthy);
        assert!(!reg.probe(ProbeKind::Readiness).healthy);
        // ...but liveness is already green (heartbeat seeded fresh at creation).
        assert!(reg.probe(ProbeKind::Liveness).healthy);

        reg.set_migrations_applied(true);
        reg.set_startup_probes_done(true);
        assert!(reg.probe(ProbeKind::Startup).healthy);
        assert!(reg.probe(ProbeKind::Readiness).healthy);
        assert_eq!(reg.report().status, HealthStatus::Ok);
    }

    #[test]
    fn registry_liveness_goes_stale_then_refreshes_on_heartbeat() {
        let (reg, clock) = registry_with(
            FakeProbes {
                sqlite: true,
                load: LoadState::Normal,
                stores: vec![],
            },
            Duration::from_secs(5),
        );
        reg.set_migrations_applied(true);
        reg.set_startup_probes_done(true);

        assert!(reg.liveness_fresh(), "fresh at t=0");

        clock.advance(Duration::from_secs(5));
        assert!(reg.liveness_fresh(), "exactly at the bound is still fresh");

        clock.advance(Duration::from_millis(1));
        assert!(!reg.liveness_fresh(), "past the bound is stale (runtime wedged)");
        assert!(!reg.probe(ProbeKind::Liveness).healthy);
        // Readiness is unaffected by a stale liveness heartbeat.
        assert!(reg.probe(ProbeKind::Readiness).healthy);

        // The watchdog beats again → liveness recovers automatically.
        reg.heartbeat();
        assert!(reg.liveness_fresh());
        assert!(reg.probe(ProbeKind::Liveness).healthy);
    }

    #[test]
    fn registry_readiness_tracks_live_load_and_store_signals() {
        let (reg, _clock) = registry_with(
            FakeProbes {
                sqlite: true,
                load: LoadState::Degraded,
                stores: vec![StoreBreaker::new("rd", BreakerState::Closed)],
            },
            Duration::from_secs(10),
        );
        reg.set_migrations_applied(true);
        reg.set_startup_probes_done(true);
        // Live load signal is Degraded → not ready.
        assert!(!reg.probe(ProbeKind::Readiness).healthy);
        assert_eq!(reg.report().status, HealthStatus::NotReady);
    }

    // -- HTTP views ---------------------------------------------------------

    use actix_web::{test as actix_test, web, App};

    fn http_registry(probes: FakeProbes, booted: bool) -> HealthRegistry {
        let reg = HealthRegistry::new(Arc::new(probes), Duration::from_secs(10));
        if booted {
            reg.set_migrations_applied(true);
            reg.set_startup_probes_done(true);
        }
        reg
    }

    #[actix_web::test]
    async fn http_readiness_503_when_not_ready_200_when_ready() {
        // Not ready: all stores open.
        let reg = http_registry(
            FakeProbes {
                sqlite: true,
                load: LoadState::Normal,
                stores: vec![StoreBreaker::new("rd", BreakerState::Open)],
            },
            true,
        );
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(reg))
                .route("/health", web::get().to(health_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get().uri("/health?probe=readiness").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 503);

        // Liveness stays 200 even though readiness is 503.
        let req = actix_test::TestRequest::get().uri("/health?probe=liveness").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[actix_web::test]
    async fn http_ready_instance_returns_200_and_report_body() {
        let reg = http_registry(
            FakeProbes {
                sqlite: true,
                load: LoadState::Normal,
                stores: vec![StoreBreaker::new("rd", BreakerState::Closed)],
            },
            true,
        );
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(reg))
                .route("/health", web::get().to(health_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get().uri("/health?probe=readiness").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);

        // Default human view carries the report JSON with the load field (Req 44.6).
        let req = actix_test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = actix_test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["load"], "normal");
        assert!(body["components"].is_array());
    }

    #[actix_web::test]
    async fn http_startup_503_before_boot_completes() {
        let reg = http_registry(
            FakeProbes {
                sqlite: true,
                load: LoadState::Normal,
                stores: vec![],
            },
            false, // not booted: migrations + probes pending
        );
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(reg))
                .route("/health", web::get().to(health_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get().uri("/health?probe=startup").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 503);
    }
}
