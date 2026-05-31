//! Application state (`app`) — Req 49.6.
//!
//! [`AppState`] is the single container of process-wide shared dependencies
//! threaded into every request handler. It is constructed once at boot (by the
//! binary) or per test (by the integration harness) and handed to
//! [`build_app`](crate::build_app), which registers it as actix
//! [`web::Data`](actix_web::web::Data) so handlers reach it uniformly (design:
//! Workspace and Crate Layout → `app.rs`: "AppState, server bootstrap").
//!
//! ## Why an `Arc` newtype
//!
//! actix clones the application factory once per worker thread, so `AppState`
//! must be cheap to clone and share the *same* underlying dependencies across
//! every worker (the breaker registry, config, health registry, cache, pools,
//! … all live behind one `Arc`). Wrapping the inner data in an [`Arc`] makes a
//! clone a pointer bump rather than a deep copy, and guarantees every worker
//! observes one shared set of dependencies — exactly what the breaker `DashMap`
//! and `FailoverCache` reattach loop require (design: Circuit Breakers "live in
//! a `DashMap<BreakerKey, Arc<CircuitBreaker>>` on `AppState` so they are shared
//! across all worker tasks").
//!
//! ## Scope of this task (11.2)
//!
//! This is the router-skeleton `AppState`: it carries the validated
//! [`Config`] and the [`HealthRegistry`] (task 7.3) that backs the shared
//! `/health` route — the health module is explicitly wired into the router
//! "once `AppState` threads the shared registry in task 11.2". The registry's
//! live signals come from a skeleton [`HealthProbes`] until the concrete
//! persistence / degradation / breaker components replace it in their own
//! tasks. The remaining shared dependencies (breaker registry, cache,
//! persistence pool, egress `OutboundClient`, degradation `LoadState`, …) are
//! added to [`AppStateInner`] as those modules are wired into the router in
//! later tasks — without changing the `build_app(state)` signature the binary
//! and tests already depend on.

use std::sync::Arc;
use std::time::Duration;

use crate::cache::{CacheBackend, FailoverCache, FailoverConfig, LocalCache, RedisCache};
use crate::config::Config;
use crate::content_proxy::ConnectionRegistry;
use crate::egress::{HttpIpReflector, OutboundClient};
use crate::health::{ComponentHealth, HealthProbes, HealthRegistry, LoadState, StoreBreaker};
use crate::http::degradation::LoadController;
use crate::observability::Metrics;
use crate::resilience::breaker::{BreakerConfig, BreakerKey, CircuitBreaker};
use crate::sse::SseRegistry;

/// Default liveness-heartbeat staleness bound for the skeleton registry.
///
/// The runtime watchdog (added with the supervisor wiring) beats well inside
/// this window; until then the heartbeat seeded at construction keeps liveness
/// green so a freshly built instance reports "alive".
const DEFAULT_LIVENESS_BOUND: Duration = Duration::from_secs(30);

/// The process-wide shared-dependency container threaded into every handler.
///
/// Cheap to clone (a single [`Arc`] bump); every clone shares the same
/// underlying dependencies, so all actix workers observe one consistent state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

/// The owned shared dependencies behind [`AppState`]'s [`Arc`].
///
/// Fields are added here (not to [`AppState`]) as later tasks wire their
/// subsystems in, keeping [`AppState`] a stable, clonable handle.
struct AppStateInner {
    /// The validated root configuration (Req 31).
    config: Config,
    /// The health registry backing `/health?probe=` (Req 50.10, task 7.3).
    health: HealthRegistry,
    /// The Prometheus metrics registry backing `/metrics` and recording
    /// counters/latencies for proxied requests, store ops, cache hit/miss,
    /// upstream failures, and every self-healing action (Req 32.5, 50.14,
    /// task 12.1).
    metrics: Metrics,
    /// The single outbound seam (Req 51.1): the only approved way any handler
    /// obtains an HTTP client for an upstream call, and the source of the
    /// tunnel-observed Egress_IP backing `/proxy/ip` (Req 51.11, task 14.2).
    egress: Arc<OutboundClient>,
    /// Shared cache backend. Redis is wrapped by `FailoverCache`; when Redis is
    /// absent or down, callers still use the local tier.
    cache: Arc<dyn CacheBackend>,
    /// Shared degradation/load controller used by middleware and health probes.
    load: LoadController,
    /// Per-user active content-proxy connection counters.
    content_connections: Arc<ConnectionRegistry>,
    /// The SSE registry backing `/v0/events` (Req 41.1, task 28.4).
    sse: SseRegistry,
}

impl AppState {
    /// Build the shared state from a loaded [`Config`].
    ///
    /// Called once at boot by the binary and once per test by the integration
    /// harness, so both construct handlers over the *identical* dependency set
    /// (Req 49.6). The health registry is created over a skeleton
    /// [`HealthProbes`]; concrete probe sources are injected by later tasks via
    /// [`AppState::with_health`].
    pub fn new(config: Config) -> Self {
        let load = LoadController::from_config(&config.degradation);
        let health = HealthRegistry::new(
            Arc::new(RuntimeHealthProbes { load: load.clone() }),
            DEFAULT_LIVENESS_BOUND,
        );
        // A skeleton instance has no pending migrations and no one-time startup
        // probes, so it is "booted" the moment it is built: mark boot complete
        // so the shared `/health` overall view reports `Ok` (`200`) rather than
        // `Starting` (`503`). The binary's real startup sequence drives these
        // flags off the actual migrator + probe results via the registry
        // setters in later tasks (it constructs its own registry through
        // [`AppState::with_health`]).
        health.set_migrations_applied(true);
        health.set_startup_probes_done(true);
        Self::from_parts(config, health, None, load)
    }

    /// Build the shared state from a loaded [`Config`] and an already-wired
    /// [`HealthRegistry`].
    ///
    /// The binary uses this once the real probe sources (persistence pool,
    /// Degradation Guard, breaker registry) exist, so the registry reflects
    /// live signals instead of the skeleton defaults.
    pub fn with_health(config: Config, health: HealthRegistry) -> Self {
        let load = LoadController::from_config(&config.degradation);
        Self::from_parts(config, health, None, load)
    }

    /// Build the shared state from a loaded [`Config`], an already-wired
    /// [`HealthRegistry`], and an explicit egress [`OutboundClient`].
    ///
    /// The binary uses this once the egress resolver's refresh loop is spawned
    /// under the task supervisor, so the live, leak-verified Egress_IP backs
    /// `/proxy/ip` (Req 51.11). Tests use it to inject an `OutboundClient` with
    /// a seeded resolver.
    pub fn with_health_and_egress(
        config: Config,
        health: HealthRegistry,
        egress: Arc<OutboundClient>,
    ) -> Self {
        let load = LoadController::from_config(&config.degradation);
        Self::from_parts(config, health, Some(egress), load)
    }

    fn from_parts(
        config: Config,
        health: HealthRegistry,
        egress: Option<Arc<OutboundClient>>,
        load: LoadController,
    ) -> Self {
        let egress = egress.unwrap_or_else(|| Arc::new(build_egress(&config)));
        let cache = build_cache_backend(&config);
        Self {
            inner: Arc::new(AppStateInner {
                config,
                health,
                metrics: Metrics::new(),
                egress,
                cache,
                load,
                content_connections: Arc::new(ConnectionRegistry::new()),
                sse: SseRegistry::new(),
            }),
        }
    }

    /// Borrow the shared configuration.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// Borrow the shared health registry (registered as `web::Data` so the
    /// `/health` handler can read it).
    pub fn health(&self) -> &HealthRegistry {
        &self.inner.health
    }

    /// Borrow the shared metrics registry (registered as `web::Data` so the
    /// `/metrics` handler renders it and every call site records into it,
    /// Req 32.5, 50.14).
    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    /// Borrow the shared egress [`OutboundClient`] — the single outbound seam
    /// (Req 51.1) and the source of the tunnel-observed Egress_IP for
    /// `/proxy/ip` (Req 51.11). Cheap: returns a reference behind the state
    /// `Arc`; clone the returned `Arc` when an owned handle is needed.
    pub fn egress(&self) -> &Arc<OutboundClient> {
        &self.inner.egress
    }

    /// Return the shared cache backend for the rate limiter (Req 40.5). When
    /// Redis is configured this is a Redis+local failover backend; otherwise it
    /// is local-only.
    pub fn rate_limit_cache(&self) -> Option<Arc<dyn crate::cache::CacheBackend>> {
        Some(Arc::clone(&self.inner.cache))
    }

    /// Borrow the shared cache backend.
    pub fn cache(&self) -> &Arc<dyn CacheBackend> {
        &self.inner.cache
    }

    /// Borrow the shared degradation/load controller.
    pub fn load_controller(&self) -> &LoadController {
        &self.inner.load
    }

    /// Borrow the content-proxy connection registry.
    pub fn content_connections(&self) -> &Arc<ConnectionRegistry> {
        &self.inner.content_connections
    }

    /// Borrow the shared SSE registry backing `/v0/events` (Req 41.1).
    pub fn sse(&self) -> &SseRegistry {
        &self.inner.sse
    }
}

/// Build the egress [`OutboundClient`] from the loaded [`Config`] for the
/// infallible [`AppState`] constructors (Req 51.1).
///
/// Production wires the egress resolver's refresh loop under the supervisor and
/// constructs the client via [`AppState::with_health_and_egress`]; this helper
/// backs the default / skeleton path. A misconfigured egress (e.g. proxy mode
/// without a `tunnel_url`) is logged and falls back to a **disabled,
/// fail-closed** client rather than aborting state construction — under the
/// fail-closed default that client refuses every dial and exposes no Egress_IP,
/// so it never leaks the host's real IP (Req 51.8).
fn build_egress(config: &Config) -> OutboundClient {
    let reflector = match HttpIpReflector::from_config(&config.egress) {
        Ok(reflector) => Arc::new(reflector),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "egress IP-reflector misconfigured; falling back to a disabled fail-closed egress",
            );
            return disabled_fail_closed_egress();
        }
    };
    match OutboundClient::from_config(&config.egress, reflector) {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "egress OutboundClient misconfigured; falling back to a disabled fail-closed egress",
            );
            disabled_fail_closed_egress()
        }
    }
}

/// A disabled, fail-closed [`OutboundClient`] used as the safe fallback when
/// the configured egress cannot be built (Req 51.8). It has no tunnel, so it
/// refuses every dial and reports no Egress_IP.
fn disabled_fail_closed_egress() -> OutboundClient {
    let cfg = crate::config::EgressConfig {
        tunnel_mode: crate::config::EgressTunnelMode::Disabled,
        policy: crate::config::EgressPolicy::FailClosed,
        ..crate::config::EgressConfig::default()
    };
    // A disabled-mode reflector never performs I/O; from_config cannot fail.
    let reflector = Arc::new(
        HttpIpReflector::from_config(&cfg).expect("disabled-mode reflector always builds"),
    );
    OutboundClient::from_config(&cfg, reflector)
        .expect("disabled-mode OutboundClient always builds")
}

fn build_cache_backend(config: &Config) -> Arc<dyn CacheBackend> {
    let namespace = config.cache.namespace.clone();
    let local = LocalCache::new(namespace.clone());
    match config
        .cache
        .redis_url
        .as_deref()
        .filter(|url| !url.trim().is_empty())
    {
        Some(url) => match RedisCache::from_url(url, namespace) {
            Ok(redis) => {
                let breaker = CircuitBreaker::new(
                    BreakerKey::Integration("redis-cache".to_string()),
                    BreakerConfig::new(5, Duration::from_secs(30)),
                );
                Arc::new(FailoverCache::with_redis(
                    local,
                    redis,
                    breaker,
                    FailoverConfig::default(),
                ))
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "redis cache misconfigured; using local cache only"
                );
                Arc::new(FailoverCache::local_only(local))
            }
        },
        None => Arc::new(FailoverCache::local_only(local)),
    }
}

/// A skeleton [`HealthProbes`] used until the concrete signal sources are
/// wired in: SQLite is reported reachable, load is `Normal`, and no store
/// breakers are configured. With no stores, readiness is never failed on the
/// "all store breakers open" account (the health module treats zero stores as
/// vacuously not-all-open).
struct SkeletonHealthProbes;

impl HealthProbes for SkeletonHealthProbes {
    fn sqlite_reachable(&self) -> bool {
        true
    }

    fn load_state(&self) -> LoadState {
        LoadState::Normal
    }

    fn store_breakers(&self) -> Vec<StoreBreaker> {
        Vec::new()
    }

    fn extra_components(&self) -> Vec<ComponentHealth> {
        Vec::new()
    }
}

struct RuntimeHealthProbes {
    load: LoadController,
}

impl HealthProbes for RuntimeHealthProbes {
    fn sqlite_reachable(&self) -> bool {
        true
    }

    fn load_state(&self) -> LoadState {
        self.load.load_state()
    }

    fn store_breakers(&self) -> Vec<StoreBreaker> {
        Vec::new()
    }

    fn extra_components(&self) -> Vec<ComponentHealth> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::ProbeKind;

    #[test]
    fn clone_shares_the_same_inner_dependencies() {
        let state = AppState::new(Config::default());
        let clone = state.clone();
        // Both handles point at the one shared `AppStateInner` (a clone is an
        // `Arc` bump, not a deep copy) — the property every actix worker relies
        // on for a single shared breaker registry / cache / pool.
        assert!(Arc::ptr_eq(&state.inner, &clone.inner));
    }

    #[test]
    fn exposes_the_loaded_config() {
        let state = AppState::new(Config::default());
        // The default server bind is loopback:8080 (config defaults, Req 31.2).
        assert_eq!(state.config().server.port, 8080);
    }

    #[test]
    fn skeleton_registry_is_live_at_construction() {
        let state = AppState::new(Config::default());
        // Liveness is green at construction (heartbeat seeded fresh), so the
        // shared `/health?probe=liveness` route answers healthy immediately.
        assert!(state.health().probe(ProbeKind::Liveness).healthy);
    }
}
