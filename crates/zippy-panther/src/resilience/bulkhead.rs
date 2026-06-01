//! Bulkhead isolation (`resilience::bulkhead`) — Req 35.3, 20.3, 50.9.
//!
//! Each upstream dependency gets its **own bounded concurrency pool** (a
//! [`tokio::sync::Semaphore`]) so that one slow or failing upstream cannot
//! exhaust global worker capacity or starve healthy dependencies (design:
//! Resilience → Pattern 3 "Bulkhead Isolation"). This generalizes the per-host
//! semaphore and per-store active-stream tracking into one uniform
//! [`BulkheadRegistry`].
//!
//! ## Guarantees
//!
//! * **Bounded concurrency.** A pool's live (in-flight) permit count never
//!   exceeds its configured maximum — acquiring caps concurrency at
//!   `max_permits` (Req 35.3).
//! * **Isolation.** Saturating one dependency's pool never prevents acquiring a
//!   permit from a *different*, unsaturated pool: [`Bulkhead::acquire`] is
//!   non-blocking, so a full pool fails fast with an [`AppError`] instead of
//!   parking the caller and tying up a worker (Req 50.9). One slow/failing
//!   upstream therefore cannot block another.
//! * **RAII release.** Capacity is represented by an
//!   [`OwnedSemaphorePermit`]; dropping the permit (normally, on early return,
//!   or on panic) returns the slot to the pool — mirroring the `ConnGuard`
//!   pattern (Req 19.5).
//! * **Shared per-store bound (Req 20.3).** The per-store bulkhead's
//!   `max_permits` **is** the per-store max-concurrent-streams value: acquiring
//!   a streaming permit and acquiring the store bulkhead permit are the same
//!   operation, so active-stream accounting and isolation share one bound.
//!
//! ## Scope of this task (6.4)
//!
//! This module implements the [`Bulkhead`] pool, its own [`BulkheadKey`]
//! identifier enum (kept independent of `breaker::BreakerKey`, which is
//! authored concurrently in task 6.2 — the two are reconciled later), and the
//! [`BulkheadRegistry`]. The full outbound composition
//! (deadline → bulkhead → breaker → retry) is wired by the later resilience
//! composition task; this module is the *bulkhead* layer of that stack.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::errors::AppError;

/// Identifies the dependency a [`Bulkhead`] guards (design: Resilience →
/// Pattern 3; mirrors the dependencies covered by `BreakerKey`).
///
/// Defined locally rather than reusing `breaker::BreakerKey` so this task does
/// not depend on the concurrently-authored breaker module; the two key enums
/// are reconciled in a later pass.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BulkheadKey {
    /// A debrid store, identified by its (lower-cased) `StoreName` string
    /// (Req 20.3 — also bounds active streams per store).
    Store(String),
    /// An origin/extractor host, identified by its (lower-cased) host name
    /// (Req 35.3 — per-origin in-flight cap).
    Host(String),
    /// A list-sync / metadata integration source
    /// (`anilist|github|mdblist|tmdb|trakt|tvdb|letterboxd`).
    Integration(String),
    /// The Acestream engine.
    Acestream,
    /// Telegram (MTProto).
    Telegram,
}

impl std::fmt::Display for BulkheadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BulkheadKey::Store(name) => write!(f, "store:{name}"),
            BulkheadKey::Host(host) => write!(f, "host:{host}"),
            BulkheadKey::Integration(name) => write!(f, "integration:{name}"),
            BulkheadKey::Acestream => f.write_str("acestream"),
            BulkheadKey::Telegram => f.write_str("telegram"),
        }
    }
}

impl BulkheadKey {
    /// The store name when this key is a [`Store`](BulkheadKey::Store), so a
    /// saturation error can identify the originating store (Req 16.9).
    fn store_name(&self) -> Option<&str> {
        match self {
            BulkheadKey::Store(name) => Some(name.as_str()),
            _ => None,
        }
    }
}

/// A bounded concurrency pool for a single dependency (design: Resilience →
/// Pattern 3).
///
/// Holds an `Arc<Semaphore>` so cheap [`Clone`]s share the *same* pool: the
/// [`BulkheadRegistry`] hands out clones rather than holding a `DashMap` guard
/// across an `await`, which would risk a deadlock. A permit is acquired before
/// admitting work and released (RAII) when the returned
/// [`OwnedSemaphorePermit`] is dropped.
#[derive(Clone)]
pub struct Bulkhead {
    sem: Arc<Semaphore>,
    max_permits: usize,
    key: BulkheadKey,
}

impl Bulkhead {
    /// Create a pool admitting at most `max_permits` concurrent operations for
    /// the dependency identified by `key`.
    pub fn new(key: BulkheadKey, max_permits: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(max_permits)),
            max_permits,
            key,
        }
    }

    /// The dependency this pool guards.
    pub fn key(&self) -> &BulkheadKey {
        &self.key
    }

    /// The configured maximum concurrent permits (the pool's hard bound).
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }

    /// Permits currently available to be acquired.
    pub fn available_permits(&self) -> usize {
        self.sem.available_permits()
    }

    /// Permits currently held (in-flight). Equals `max_permits −
    /// available_permits` and, by construction, **never exceeds**
    /// `max_permits` (Req 35.3).
    pub fn in_flight(&self) -> usize {
        self.max_permits - self.available_permits()
    }

    /// Acquire one RAII permit, capping concurrency at `max_permits`
    /// (Req 35.3).
    ///
    /// **Non-blocking**: if the pool is saturated this returns an
    /// [`AppError`] immediately rather than waiting, which is what makes
    /// isolation hold — a full pool fails fast and never parks the caller, so
    /// one saturated dependency cannot block work on another (Req 50.9). The
    /// error is an `UpstreamUnavailable` identifying the dependency (and the
    /// store, for [`Store`](BulkheadKey::Store) pools, per Req 16.9).
    ///
    /// Dropping the returned [`OwnedSemaphorePermit`] releases the slot
    /// (RAII), including on early return or panic.
    ///
    /// `async` to match the outbound composition seam
    /// (deadline → bulkhead → breaker → retry) even though the current body
    /// never yields.
    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, AppError> {
        match Arc::clone(&self.sem).try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(TryAcquireError::NoPermits) | Err(TryAcquireError::Closed) => {
                Err(self.busy_error())
            }
        }
    }

    /// The fail-fast error returned when the pool is saturated.
    fn busy_error(&self) -> AppError {
        let err = AppError::upstream_unavailable(format!(
            "bulkhead at capacity for {} ({} concurrent)",
            self.key, self.max_permits
        ));
        match self.key.store_name() {
            Some(store) => err.with_store(store),
            None => err,
        }
    }
}

/// Per-category defaults used by [`BulkheadRegistry`] for the pools whose bound
/// is not a per-key config value (host/integration defaults and the singleton
/// acestream/telegram pools).
///
/// Per-store pools are **not** configured here: their bound is the per-store
/// max-concurrent-streams value supplied at the call site (Req 20.3).
#[derive(Clone, Debug)]
pub struct BulkheadConfig {
    /// Default per-origin-host in-flight cap (Req 35.3).
    pub default_host_permits: usize,
    /// Default per-integration concurrency (isolates list-sync workers).
    pub default_integration_permits: usize,
    /// Concurrency for the Acestream engine pool.
    pub acestream_permits: usize,
    /// Concurrency for the Telegram (MTProto) pool.
    pub telegram_permits: usize,
}

impl Default for BulkheadConfig {
    fn default() -> Self {
        Self {
            default_host_permits: 8,
            default_integration_permits: 4,
            acestream_permits: 4,
            telegram_permits: 4,
        }
    }
}

/// The registry of per-dependency bulkhead pools shared across all worker
/// tasks (design: Resilience → Pattern 3).
///
/// Per-store/per-host/per-integration pools are created lazily on first use
/// and then shared; the acestream and telegram pools are singletons created at
/// construction from [`BulkheadConfig`]. Lookups return a cheap [`Bulkhead`]
/// clone (sharing the underlying `Arc<Semaphore>`) so no `DashMap` guard is
/// ever held across an `await`.
pub struct BulkheadRegistry {
    per_store: DashMap<String, Bulkhead>,
    per_host: DashMap<String, Bulkhead>,
    per_integration: DashMap<String, Bulkhead>,
    acestream: Bulkhead,
    telegram: Bulkhead,
    cfg: BulkheadConfig,
}

impl BulkheadRegistry {
    /// Build a registry from `cfg`, eagerly creating the singleton acestream
    /// and telegram pools.
    pub fn new(cfg: BulkheadConfig) -> Self {
        Self {
            per_store: DashMap::new(),
            per_host: DashMap::new(),
            per_integration: DashMap::new(),
            acestream: Bulkhead::new(BulkheadKey::Acestream, cfg.acestream_permits),
            telegram: Bulkhead::new(BulkheadKey::Telegram, cfg.telegram_permits),
            cfg,
        }
    }

    /// The per-store pool, created on first use with `max_concurrent_streams`
    /// as its bound (Req 20.3).
    ///
    /// The per-store bulkhead's `max_permits` **is** the per-store
    /// max-concurrent-streams config value: acquiring a streaming permit and
    /// acquiring the store bulkhead permit are the same operation. The pool is
    /// created once per store — the first call fixes its bound; later calls
    /// return the existing pool regardless of the `max_concurrent_streams`
    /// argument.
    pub fn store(&self, name: &str, max_concurrent_streams: usize) -> Bulkhead {
        let key = name.to_ascii_lowercase();
        self.per_store
            .entry(key.clone())
            .or_insert_with(|| Bulkhead::new(BulkheadKey::Store(key), max_concurrent_streams))
            .clone()
    }

    /// The per-origin-host pool, created on first use. Defaults to
    /// [`BulkheadConfig::default_host_permits`] when `max_permits` is `None`
    /// (Req 35.3). Host names are matched case-insensitively.
    pub fn host(&self, host: &str, max_permits: Option<usize>) -> Bulkhead {
        let key = host.to_ascii_lowercase();
        let permits = max_permits.unwrap_or(self.cfg.default_host_permits);
        self.per_host
            .entry(key.clone())
            .or_insert_with(|| Bulkhead::new(BulkheadKey::Host(key), permits))
            .clone()
    }

    /// The per-integration pool, created on first use. Defaults to
    /// [`BulkheadConfig::default_integration_permits`] when `max_permits` is
    /// `None`.
    pub fn integration(&self, name: &str, max_permits: Option<usize>) -> Bulkhead {
        let key = name.to_ascii_lowercase();
        let permits = max_permits.unwrap_or(self.cfg.default_integration_permits);
        self.per_integration
            .entry(key.clone())
            .or_insert_with(|| Bulkhead::new(BulkheadKey::Integration(key), permits))
            .clone()
    }

    /// The singleton Acestream-engine pool.
    pub fn acestream(&self) -> Bulkhead {
        self.acestream.clone()
    }

    /// The singleton Telegram (MTProto) pool.
    pub fn telegram(&self) -> Bulkhead {
        self.telegram.clone()
    }
}

impl Default for BulkheadRegistry {
    fn default() -> Self {
        Self::new(BulkheadConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Bulkhead: bounded concurrency (Req 35.3) ---------------------------

    /// Acquiring up to `max_permits` succeeds; the live (in-flight) count
    /// tracks the held permits and never exceeds the configured maximum.
    #[tokio::test]
    async fn live_permit_count_never_exceeds_max() {
        let bh = Bulkhead::new(BulkheadKey::Host("cdn.example".into()), 3);
        assert_eq!(bh.max_permits(), 3);
        assert_eq!(bh.in_flight(), 0);
        assert_eq!(bh.available_permits(), 3);

        let mut held = Vec::new();
        for expected_in_flight in 1..=3 {
            let permit = bh.acquire().await.expect("within capacity");
            held.push(permit);
            assert_eq!(bh.in_flight(), expected_in_flight);
            assert!(bh.in_flight() <= bh.max_permits(), "must never exceed max");
        }
        assert_eq!(bh.available_permits(), 0);

        // The pool is now saturated: the next acquire fails fast (no block),
        // and the live count is still pinned at the max — never above it.
        let err = bh
            .acquire()
            .await
            .expect_err("saturated pool must fail fast");
        assert_eq!(
            err.category,
            crate::errors::ErrorCategory::UpstreamUnavailable
        );
        assert_eq!(bh.in_flight(), 3);
        assert!(bh.in_flight() <= bh.max_permits());
    }

    /// A repeated acquire/release cycle keeps the live count within `[0, max]`
    /// for every observed step (deterministic interleaving).
    #[tokio::test]
    async fn interleaved_acquire_release_stays_within_bound() {
        let bh = Bulkhead::new(BulkheadKey::Store("realdebrid".into()), 2);
        for _ in 0..50 {
            let a = bh.acquire().await.expect("permit a");
            assert!(bh.in_flight() <= 2);
            let b = bh.acquire().await.expect("permit b");
            assert_eq!(bh.in_flight(), 2);
            assert!(bh.acquire().await.is_err(), "third over a 2-permit pool");
            drop(a);
            assert_eq!(bh.in_flight(), 1);
            drop(b);
            assert_eq!(bh.in_flight(), 0);
        }
    }

    // -- Bulkhead: isolation (Req 50.9) -------------------------------------

    /// Saturating one pool never prevents acquiring from a different,
    /// unsaturated pool — and the saturated pool fails *fast* (non-blocking),
    /// so one slow/failing upstream cannot block another.
    #[tokio::test]
    async fn saturating_one_pool_never_blocks_another() {
        let busy = Bulkhead::new(BulkheadKey::Store("torbox".into()), 1);
        let healthy = Bulkhead::new(BulkheadKey::Store("realdebrid".into()), 1);

        // Saturate `busy`.
        let _held = busy.acquire().await.expect("first permit");
        assert!(busy.acquire().await.is_err(), "busy pool is saturated");

        // The healthy pool is unaffected and still admits a permit. Bound the
        // call with a timeout to prove `acquire` does not block on the
        // saturated neighbour.
        let acquired = tokio::time::timeout(std::time::Duration::from_secs(1), healthy.acquire())
            .await
            .expect("acquire must not block")
            .expect("healthy pool has capacity");
        assert_eq!(healthy.in_flight(), 1);
        drop(acquired);
    }

    /// A saturated store pool's error identifies the originating store
    /// (Req 16.9) and is a 503-family `UpstreamUnavailable`.
    #[tokio::test]
    async fn saturation_error_identifies_store() {
        let bh = Bulkhead::new(BulkheadKey::Store("premiumize".into()), 1);
        let _held = bh.acquire().await.unwrap();
        let err = bh.acquire().await.unwrap_err();
        assert_eq!(
            err.category,
            crate::errors::ErrorCategory::UpstreamUnavailable
        );
        assert_eq!(err.store.as_deref(), Some("premiumize"));
    }

    // -- Bulkhead: RAII release ---------------------------------------------

    /// Dropping a permit returns capacity to the pool (RAII), making a slot
    /// available for a subsequent acquire.
    #[tokio::test]
    async fn dropping_permit_releases_capacity() {
        let bh = Bulkhead::new(BulkheadKey::Acestream, 1);
        let permit = bh.acquire().await.expect("first");
        assert_eq!(bh.available_permits(), 0);
        assert!(bh.acquire().await.is_err(), "saturated before release");

        drop(permit); // RAII release
        assert_eq!(bh.available_permits(), 1);
        let _reacquired = bh.acquire().await.expect("capacity restored after drop");
        assert_eq!(bh.in_flight(), 1);
    }

    /// A permit dropped at the end of a scope (early return path) releases
    /// capacity just like an explicit drop.
    #[tokio::test]
    async fn scoped_permit_releases_at_scope_end() {
        let bh = Bulkhead::new(BulkheadKey::Telegram, 2);
        {
            let _a = bh.acquire().await.unwrap();
            let _b = bh.acquire().await.unwrap();
            assert_eq!(bh.in_flight(), 2);
        } // both permits dropped here
        assert_eq!(bh.in_flight(), 0);
        assert_eq!(bh.available_permits(), 2);
    }

    // -- Registry: per-store bound == max-concurrent-streams (Req 20.3) -----

    /// The per-store bulkhead's permit count **is** the configured per-store
    /// max-concurrent-streams: acquiring the store permit caps active streams
    /// at exactly that bound.
    #[tokio::test]
    async fn per_store_bulkhead_permit_equals_max_concurrent_streams() {
        let registry = BulkheadRegistry::default();
        let max_concurrent_streams = 3;

        let store = registry.store("RealDebrid", max_concurrent_streams);
        assert_eq!(store.max_permits(), max_concurrent_streams);

        // Acquire exactly the configured number of streaming permits.
        let mut streams = Vec::new();
        for _ in 0..max_concurrent_streams {
            streams.push(store.acquire().await.expect("within stream cap"));
        }
        // The next stream would exceed the per-store max → refused (Req 20.3).
        assert!(
            store.acquire().await.is_err(),
            "must not initiate a stream beyond max-concurrent-streams",
        );
        assert_eq!(store.in_flight(), max_concurrent_streams);
    }

    /// The registry shares one pool per store key: a second lookup returns the
    /// same underlying semaphore (so the bound is global per store), and the
    /// key is matched case-insensitively.
    #[tokio::test]
    async fn registry_shares_one_pool_per_store_key() {
        let registry = BulkheadRegistry::default();
        let a = registry.store("RealDebrid", 1);
        let _held = a.acquire().await.expect("permit on first handle");

        // Same store (different casing) → same pool, already saturated.
        let b = registry.store("realdebrid", 1);
        assert_eq!(b.available_permits(), 0, "shares the same semaphore");
        assert!(b.acquire().await.is_err(), "second handle sees saturation");
    }

    /// The first lookup fixes a store pool's bound; later lookups return the
    /// existing pool regardless of the max argument passed.
    #[tokio::test]
    async fn registry_store_bound_is_fixed_on_first_use() {
        let registry = BulkheadRegistry::default();
        let first = registry.store("torbox", 2);
        assert_eq!(first.max_permits(), 2);
        let second = registry.store("torbox", 99);
        assert_eq!(second.max_permits(), 2, "bound fixed by first creation");
    }

    // -- Registry: cross-dependency isolation -------------------------------

    /// Distinct dependency categories have independent pools: saturating a
    /// store pool does not affect a host, integration, acestream, or telegram
    /// pool.
    #[tokio::test]
    async fn registry_pools_are_isolated_across_dependencies() {
        let registry = BulkheadRegistry::new(BulkheadConfig {
            default_host_permits: 1,
            default_integration_permits: 1,
            acestream_permits: 1,
            telegram_permits: 1,
        });

        // Saturate the store pool.
        let store = registry.store("alldebrid", 1);
        let _s = store.acquire().await.unwrap();
        assert!(store.acquire().await.is_err());

        // Every other dependency pool still admits a permit.
        let _h = registry
            .host("cdn.example.com", None)
            .acquire()
            .await
            .expect("host free");
        let _i = registry
            .integration("trakt", None)
            .acquire()
            .await
            .expect("integration free");
        let _a = registry
            .acestream()
            .acquire()
            .await
            .expect("acestream free");
        let _t = registry.telegram().acquire().await.expect("telegram free");
    }

    /// The acestream/telegram singletons returned by repeated lookups share
    /// the same underlying pool.
    #[tokio::test]
    async fn registry_singleton_pools_are_shared() {
        let registry = BulkheadRegistry::new(BulkheadConfig {
            acestream_permits: 1,
            ..BulkheadConfig::default()
        });
        let _held = registry
            .acestream()
            .acquire()
            .await
            .expect("first acestream permit");
        // A fresh handle to the same singleton sees the saturation.
        assert!(registry.acestream().acquire().await.is_err());
    }

    /// A zero-permit pool admits nothing (degenerate bound).
    #[tokio::test]
    async fn zero_permit_pool_admits_nothing() {
        let bh = Bulkhead::new(BulkheadKey::Host("blocked".into()), 0);
        assert_eq!(bh.max_permits(), 0);
        assert!(bh.acquire().await.is_err());
        assert_eq!(bh.in_flight(), 0);
    }

    /// `BulkheadKey` renders a stable, dependency-identifying label (used in
    /// saturation error messages / metrics).
    #[test]
    fn bulkhead_key_display_is_stable() {
        assert_eq!(
            BulkheadKey::Store("realdebrid".into()).to_string(),
            "store:realdebrid"
        );
        assert_eq!(BulkheadKey::Host("cdn".into()).to_string(), "host:cdn");
        assert_eq!(
            BulkheadKey::Integration("trakt".into()).to_string(),
            "integration:trakt"
        );
        assert_eq!(BulkheadKey::Acestream.to_string(), "acestream");
        assert_eq!(BulkheadKey::Telegram.to_string(), "telegram");
    }
}
