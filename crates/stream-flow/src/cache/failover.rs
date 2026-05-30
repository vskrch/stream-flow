//! [`FailoverCache`] — Redis breaker + local fallback (Req 30.2, 30.5, 50.5).
//!
//! Wraps an **optional** Redis backend over the **always-present**
//! [`LocalCache`] so callers never branch on which storage is active (design:
//! Components -> Cache backend (FailoverCache)). The optional Redis handle is
//! held in an [`ArcSwapOption`] so it can be hot-swapped without a lock on the
//! cache hot path:
//!
//! * **Steady state (Redis configured & healthy).** `get`/`set`/`del` run
//!   against Redis through a [`CircuitBreaker`] guard (Req 50.2). `set` is
//!   write-through: the value is written to the local tier *first* so the local
//!   cache always holds a recent copy to fall back to.
//! * **Redis blip (Req 30.5, 50.5).** The instant a Redis call returns a typed
//!   error, the Redis handle is dropped (`ArcSwapOption::swap(None)`), the
//!   failure is recorded in the structured log, and the request is served from
//!   the local tier. The breaker also records the failure. **The request never
//!   fails** — a Redis outage is invisible to the caller.
//! * **Detached state.** While the handle is `None`, `get`/`set`/`del` skip
//!   Redis entirely and serve from local with no per-request Redis dial — so a
//!   sustained outage costs nothing and in-flight requests are never blocked.
//! * **Recovery (Req 50.5).** A supervised reattach loop periodically probes
//!   the dropped backend (through the same breaker, so its cooldown/half-open
//!   semantics drive the probe cadence). On the first successful probe the
//!   handle is swapped back in (`ArcSwapOption::store(Some(..))`) and normal
//!   Redis use resumes — **without a restart and without dropping in-flight
//!   requests** (Req 50.5).
//!
//! ## Why `ArcSwapOption`
//!
//! Reads of the active backend are lock-free ([`ArcSwapOption::load`]), so the
//! failover decision adds no contention to the streaming hot path. Swapping the
//! handle in/out is atomic, so a request that loaded the old handle finishes
//! against it (or fails over to local) while a concurrent swap installs the new
//! one — no request is ever interrupted by the swap (design: "in-flight
//! requests never fail").
//!
//! ## Testing without a live Redis
//!
//! [`FailoverCache`] is generic over the Redis backend type
//! (`FailoverCache<R = RedisCache>`), so the `ArcSwapOption<RedisCache>` of the
//! design is the production default while the unit tests substitute a
//! controllable in-memory [`CacheBackend`] that can be toggled to error on
//! demand. That exercises the failover **and** reattach paths deterministically
//! with no Redis container (design: Testing Strategy — "otherwise the local
//! fallback path is asserted").

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::task::JoinHandle;

use crate::errors::AppError;
use crate::resilience::breaker::{guarded, BreakerConfig, BreakerKey, CircuitBreaker};

use super::{CacheBackend, LocalCache, RedisCache};

/// Tuning for the [`FailoverCache`] reattach loop (design: Components -> Cache
/// backend (FailoverCache) — `reattach: TaskHandle`).
#[derive(Clone, Debug)]
pub struct FailoverConfig {
    /// How often the supervised reattach loop probes a dropped Redis backend
    /// for recovery (Req 50.5).
    pub probe_interval: Duration,
    /// The sentinel logical key used by the recovery probe. A successful `get`
    /// of this key (returning `Ok(_)`, hit or miss) proves Redis is reachable
    /// again; the value is never read, so any unused key works.
    pub probe_key: String,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(5),
            probe_key: "__stream_flow_failover_probe__".to_string(),
        }
    }
}

/// State shared between the [`FailoverCache`] handle and its supervised
/// reattach task. Held behind an [`Arc`] so the background loop can run
/// independently of (and outlive a clone of) the owning handle without a
/// reference cycle.
struct Shared<R: CacheBackend> {
    /// The always-present in-process tier and the durable fallback copy.
    local: LocalCache,
    /// The hot-swappable Redis handle: `Some` while attached, `None` after a
    /// failover until the reattach loop restores it (design: `ArcSwapOption`).
    redis: ArcSwapOption<R>,
    /// The persistent Redis backend the reattach loop re-probes and re-installs.
    /// `None` when no Redis was configured (local-only mode — Req 30.2).
    candidate: Option<Arc<R>>,
    /// Guards every Redis call (Req 50.2); its cooldown/half-open semantics also
    /// pace the recovery probe.
    breaker: CircuitBreaker,
    /// Reattach loop tuning.
    config: FailoverConfig,
    /// `true` while a reattach loop is live, so only one runs at a time.
    reattach_running: AtomicBool,
}

impl<R: CacheBackend + 'static> Shared<R> {
    /// Probe the dropped backend once and, on success, swap it back in.
    ///
    /// The probe runs through the breaker ([`guarded`]) so the breaker's
    /// cooldown gates how often a real probe is issued; a probe success also
    /// closes the breaker, so normal Redis use resumes cleanly. Returns `true`
    /// once Redis is reattached (or was never detached / not configured).
    async fn probe_and_reattach(self: &Arc<Self>) -> bool {
        // Already attached (or a concurrent probe won the race) → done.
        if self.redis.load().is_some() {
            return true;
        }
        let Some(candidate) = self.candidate.clone() else {
            // Local-only: nothing to reattach.
            return false;
        };
        let probe_key = self.config.probe_key.as_str();
        match guarded(&self.breaker, || candidate.get(probe_key)).await {
            Ok(_) => {
                // Re-install the recovered backend. A request that already
                // loaded `None` finishes against local; the next load sees the
                // restored handle — no in-flight request is interrupted.
                self.redis.store(Some(candidate));
                tracing::info!(
                    namespace = %self.local.namespace(),
                    "redis cache backend reattached after recovery",
                );
                true
            }
            Err(_) => false,
        }
    }

    /// The supervised reattach loop (Req 50.5): probe on the configured
    /// interval until Redis recovers, then exit and release the run flag.
    async fn reattach_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.config.probe_interval).await;
            if self.probe_and_reattach().await {
                break;
            }
        }
        self.reattach_running.store(false, Ordering::Release);
    }
}

/// Optional Redis backend over an always-present [`LocalCache`], with a circuit
/// breaker guarding Redis and a supervised reattach loop (Req 30.2, 30.5,
/// 50.5).
///
/// Generic over the Redis backend type so production uses
/// `FailoverCache<RedisCache>` (the design's `ArcSwapOption<RedisCache>`) while
/// tests substitute a controllable [`CacheBackend`]. Construct it with
/// [`FailoverCache::with_redis`] when a Redis URL is configured, or
/// [`FailoverCache::local_only`] when it is not (Req 30.2).
pub struct FailoverCache<R: CacheBackend = RedisCache> {
    shared: Arc<Shared<R>>,
    /// Handle to the supervised reattach task, aborted on drop so the loop does
    /// not outlive the cache (design: `reattach: TaskHandle`).
    reattach: Mutex<Option<JoinHandle<()>>>,
}

impl FailoverCache<RedisCache> {
    /// Build a **local-only** cache: no Redis is configured, so every operation
    /// is served by the local tier (Req 30.2 — "no Redis URL → Local_Cache").
    pub fn local_only(local: LocalCache) -> Self {
        Self::from_parts(local, None, default_redis_breaker(), FailoverConfig::default())
    }
}

impl<R: CacheBackend + 'static> FailoverCache<R> {
    /// Build a failover cache over a configured Redis backend (Req 30.2). The
    /// backend starts **attached**; on any Redis error it is dropped and the
    /// supervised reattach loop restores it on recovery (Req 30.5, 50.5).
    ///
    /// `local` and `redis` should share the same configured namespace so a
    /// logical key maps to the same physical key in both tiers (Req 30.3).
    pub fn with_redis(
        local: LocalCache,
        redis: R,
        breaker: CircuitBreaker,
        config: FailoverConfig,
    ) -> Self {
        Self::from_parts(local, Some(Arc::new(redis)), breaker, config)
    }

    /// Shared constructor: `candidate == Some` means Redis is configured and the
    /// handle starts attached; `None` is local-only.
    fn from_parts(
        local: LocalCache,
        candidate: Option<Arc<R>>,
        breaker: CircuitBreaker,
        config: FailoverConfig,
    ) -> Self {
        let redis = match &candidate {
            Some(c) => ArcSwapOption::new(Some(Arc::clone(c))),
            None => ArcSwapOption::empty(),
        };
        Self {
            shared: Arc::new(Shared {
                local,
                redis,
                candidate,
                breaker,
                config,
                reattach_running: AtomicBool::new(false),
            }),
            reattach: Mutex::new(None),
        }
    }

    /// Is the Redis tier currently attached (healthy)? `false` while failed over
    /// to local or in local-only mode. Exposed for tests / health reporting.
    pub fn redis_attached(&self) -> bool {
        self.shared.redis.load().is_some()
    }

    /// Run a single recovery probe and reattach on success (Req 50.5).
    ///
    /// Drives one iteration of the reattach loop deterministically (used by the
    /// production loop and directly by tests). Returns `true` once Redis is
    /// reattached, `false` if it is still unreachable.
    pub async fn attempt_reattach(&self) -> bool {
        self.shared.probe_and_reattach().await
    }

    /// React to a Redis call failing or being short-circuited by the breaker.
    ///
    /// A genuine failure detaches the Redis handle (so subsequent requests skip
    /// Redis and serve from local immediately — Req 30.5), logs the failure
    /// once (Req 30.5), and starts the supervised reattach loop (Req 50.5). A
    /// breaker short-circuit (`circuit_open`) means we have already failed over,
    /// so there is nothing new to do.
    fn on_redis_error(&self, err: &AppError) {
        if err.circuit_open {
            return;
        }
        // Only the swap that actually drops a live handle logs, so a burst of
        // concurrent failures yields a single failover log line.
        if self.shared.redis.swap(None).is_some() {
            tracing::warn!(
                namespace = %self.shared.local.namespace(),
                error = %err,
                "redis cache unreachable; serving from local cache and scheduling reattach",
            );
        }
        self.ensure_reattach_running();
    }

    /// Start the supervised reattach loop if one is not already running and a
    /// Redis backend was configured. Idempotent under concurrency via the
    /// `reattach_running` flag.
    fn ensure_reattach_running(&self) {
        if self.shared.candidate.is_none() {
            return; // local-only: nothing to reattach
        }
        // Claim the single run slot.
        if self
            .shared
            .reattach_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return; // a loop is already running
        }
        // Spawn only when a Tokio runtime is available; otherwise leave the flag
        // claimed-then-released so `attempt_reattach` can still drive recovery.
        match tokio::runtime::Handle::try_current() {
            Ok(_) => {
                let shared = Arc::clone(&self.shared);
                let handle = tokio::spawn(shared.reattach_loop());
                if let Ok(mut slot) = self.reattach.lock() {
                    if let Some(old) = slot.replace(handle) {
                        old.abort();
                    }
                }
            }
            Err(_) => {
                self.shared.reattach_running.store(false, Ordering::Release);
            }
        }
    }
}

#[async_trait]
impl<R: CacheBackend + 'static> CacheBackend for FailoverCache<R> {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, AppError> {
        // Lock-free read of the active backend (design: ArcSwapOption).
        if let Some(redis) = self.shared.redis.load_full() {
            match guarded(&self.shared.breaker, || redis.get(key)).await {
                Ok(value) => return Ok(value),
                Err(err) => self.on_redis_error(&err),
            }
        }
        // Detached, local-only, or Redis errored → serve from local. Never fails
        // the request on a Redis blip (Req 30.5, 50.5).
        self.shared.local.get(key).await
    }

    async fn set(&self, key: &str, val: Bytes, ttl: Duration) -> Result<(), AppError> {
        // Write-through to local first so the local tier always holds a recent
        // copy to fall back to during a Redis outage (Req 30.5).
        self.shared.local.set(key, val.clone(), ttl).await?;
        if let Some(redis) = self.shared.redis.load_full() {
            if let Err(err) = guarded(&self.shared.breaker, || redis.set(key, val.clone(), ttl)).await
            {
                self.on_redis_error(&err);
            }
        }
        // The local write succeeded, so the set is durable regardless of Redis.
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<(), AppError> {
        self.shared.local.del(key).await?;
        if let Some(redis) = self.shared.redis.load_full() {
            if let Err(err) = guarded(&self.shared.breaker, || redis.del(key)).await {
                self.on_redis_error(&err);
            }
        }
        Ok(())
    }

    fn namespace(&self) -> &str {
        self.shared.local.namespace()
    }
}

impl<R: CacheBackend> Drop for FailoverCache<R> {
    fn drop(&mut self) {
        // Stop the supervised reattach loop so it does not outlive the cache.
        if let Ok(mut slot) = self.reattach.lock() {
            if let Some(handle) = slot.take() {
                handle.abort();
            }
        }
    }
}

/// The default Redis circuit breaker (`BreakerKey::Redis`) used when a caller
/// does not supply one (design: Components -> Cache backend — `breaker` guards
/// Redis calls, Req 50.2).
fn default_redis_breaker() -> CircuitBreaker {
    CircuitBreaker::new(BreakerKey::Redis, BreakerConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use crate::errors::ErrorCategory;

    // -- A controllable in-memory backend standing in for Redis -------------
    //
    // Toggling `fail` to `true` makes every operation return a typed
    // `UpstreamUnavailable` error, exactly as an unreachable Redis would
    // (Req 50.5), so the failover and reattach paths are exercised
    // deterministically with no Redis container.
    #[derive(Clone)]
    struct ToggleBackend {
        store: Arc<Mutex<HashMap<String, Bytes>>>,
        fail: Arc<AtomicBool>,
        namespace: String,
        get_calls: Arc<AtomicUsize>,
    }

    impl ToggleBackend {
        fn new(namespace: &str) -> Self {
            Self {
                store: Arc::new(Mutex::new(HashMap::new())),
                fail: Arc::new(AtomicBool::new(false)),
                namespace: namespace.to_string(),
                get_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_failing(&self, failing: bool) {
            self.fail.store(failing, Ordering::SeqCst);
        }

        fn is_failing(&self) -> bool {
            self.fail.load(Ordering::SeqCst)
        }

        fn err(&self) -> AppError {
            AppError::upstream_unavailable("redis unreachable (test)")
        }

        fn contains(&self, physical_key: &str) -> bool {
            self.store.lock().unwrap().contains_key(physical_key)
        }
    }

    #[async_trait]
    impl CacheBackend for ToggleBackend {
        async fn get(&self, key: &str) -> Result<Option<Bytes>, AppError> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            if self.is_failing() {
                return Err(self.err());
            }
            let physical = super::super::namespaced_key(&self.namespace, key);
            Ok(self.store.lock().unwrap().get(&physical).cloned())
        }

        async fn set(&self, key: &str, val: Bytes, _ttl: Duration) -> Result<(), AppError> {
            if self.is_failing() {
                return Err(self.err());
            }
            let physical = super::super::namespaced_key(&self.namespace, key);
            self.store.lock().unwrap().insert(physical, val);
            Ok(())
        }

        async fn del(&self, key: &str) -> Result<(), AppError> {
            if self.is_failing() {
                return Err(self.err());
            }
            let physical = super::super::namespaced_key(&self.namespace, key);
            self.store.lock().unwrap().remove(&physical);
            Ok(())
        }

        fn namespace(&self) -> &str {
            &self.namespace
        }
    }

    /// A breaker with a high threshold so it stays `Closed` throughout a test
    /// (the failover logic detaches on the first error regardless of the
    /// breaker, and a `Closed` breaker lets the recovery probe actually call
    /// the backend). A long probe interval keeps the auto-spawned background
    /// loop idle so tests can drive `attempt_reattach` deterministically.
    fn test_cache(ns: &str) -> (FailoverCache<ToggleBackend>, ToggleBackend) {
        let backend = ToggleBackend::new(ns);
        let breaker = CircuitBreaker::new(BreakerKey::Redis, BreakerConfig::new(1000, Duration::from_millis(1)));
        let config = FailoverConfig {
            probe_interval: Duration::from_secs(3600),
            probe_key: "__probe__".to_string(),
        };
        let cache = FailoverCache::with_redis(LocalCache::new(ns), backend.clone(), breaker, config);
        (cache, backend)
    }

    // -- Steady state -------------------------------------------------------

    /// With Redis healthy, a value set through the failover cache is readable
    /// and lands in the Redis tier (Req 30.2, 30.6).
    #[tokio::test]
    async fn healthy_redis_round_trip() {
        let (cache, backend) = test_cache("sf");
        cache
            .set("k", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(cache.get("k").await.unwrap(), Some(Bytes::from_static(b"v")));
        assert!(cache.redis_attached());
        // Write-through reached Redis under the shared namespace (Req 30.3).
        assert!(backend.contains("sf:k"));
    }

    // -- Req 30.5 / 50.5: Redis error transparently serves from local -------

    /// When Redis errors, the request is served from the local tier (which was
    /// warmed by the write-through `set`) instead of failing, and the Redis
    /// handle is detached so subsequent requests skip Redis (Req 30.5, 50.5).
    #[tokio::test]
    async fn redis_error_transparently_serves_from_local() {
        let (cache, backend) = test_cache("sf");

        // Warm both tiers while Redis is healthy.
        cache
            .set("k", Bytes::from_static(b"local-copy"), Duration::from_secs(60))
            .await
            .unwrap();
        assert!(cache.redis_attached());

        // Redis goes down mid-flight.
        backend.set_failing(true);

        // The get does not fail — it transparently falls back to local.
        let got = cache.get("k").await.unwrap();
        assert_eq!(got, Some(Bytes::from_static(b"local-copy")));

        // The handle was dropped, so we have failed over to local (Req 30.5).
        assert!(!cache.redis_attached());

        // While detached, further reads skip Redis entirely (no new Redis call).
        let calls_before = backend.get_calls.load(Ordering::SeqCst);
        let _ = cache.get("k").await.unwrap();
        assert_eq!(
            backend.get_calls.load(Ordering::SeqCst),
            calls_before,
            "a detached Redis must not be dialed on every request",
        );
    }

    /// A `set` issued while Redis is down still succeeds (served by the local
    /// tier) and is later readable — the outage never fails a write (Req 50.5).
    #[tokio::test]
    async fn set_during_outage_succeeds_via_local() {
        let (cache, backend) = test_cache("sf");
        backend.set_failing(true);

        // First op detaches Redis but still succeeds via local.
        cache
            .set("k", Bytes::from_static(b"written-while-down"), Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!cache.redis_attached());

        assert_eq!(
            cache.get("k").await.unwrap(),
            Some(Bytes::from_static(b"written-while-down")),
        );
    }

    /// The error surfaced by the stand-in backend is the typed
    /// `UpstreamUnavailable` an unreachable Redis produces — never a panic —
    /// confirming the failover reacts to the same category `RedisCache` emits.
    #[tokio::test]
    async fn redis_failure_is_typed_not_panic() {
        let (_cache, backend) = test_cache("sf");
        backend.set_failing(true);
        let err = backend.get("anything").await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    // -- Req 50.5: reattach restores Redis ----------------------------------

    /// After a failover, once Redis recovers the supervised probe reattaches it
    /// and normal Redis use resumes without a restart (Req 50.5).
    #[tokio::test]
    async fn reattach_restores_redis_on_recovery() {
        let (cache, backend) = test_cache("sf");

        // Fail over.
        backend.set_failing(true);
        let _ = cache.get("k").await.unwrap();
        assert!(!cache.redis_attached());

        // Recovery probe while still down does not reattach.
        assert!(!cache.attempt_reattach().await);
        assert!(!cache.redis_attached());

        // Redis recovers; the next probe reattaches it.
        backend.set_failing(false);
        assert!(cache.attempt_reattach().await);
        assert!(cache.redis_attached());

        // Normal Redis use resumes: a write reaches the Redis tier again.
        cache
            .set("after", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();
        assert!(backend.contains("sf:after"));
    }

    /// The supervised background loop reattaches automatically (without anyone
    /// calling `attempt_reattach`) once Redis recovers (Req 50.5).
    #[tokio::test]
    async fn background_loop_reattaches_automatically() {
        let backend = ToggleBackend::new("sf");
        let breaker = CircuitBreaker::new(BreakerKey::Redis, BreakerConfig::new(1000, Duration::from_millis(1)));
        let config = FailoverConfig {
            probe_interval: Duration::from_millis(20),
            probe_key: "__probe__".to_string(),
        };
        let cache =
            FailoverCache::with_redis(LocalCache::new("sf"), backend.clone(), breaker, config);

        // Trigger a failover; this also spawns the supervised reattach loop.
        backend.set_failing(true);
        let _ = cache.get("k").await.unwrap();
        assert!(!cache.redis_attached());

        // Redis recovers; the background loop should reattach on its own.
        backend.set_failing(false);

        let mut reattached = false;
        for _ in 0..100 {
            if cache.redis_attached() {
                reattached = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(reattached, "supervised loop must reattach Redis automatically");
    }

    // -- Req 50.5: in-flight requests never fail due to a Redis blip --------

    /// Under concurrent load, toggling Redis down and back up never produces a
    /// failed request: every get/set returns `Ok` because the local tier
    /// absorbs the blip (Req 50.5 — "without dropping in-flight requests").
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_flight_requests_never_fail_during_a_blip() {
        let (cache, backend) = test_cache("sf");
        let cache = Arc::new(cache);

        // Seed a value so reads have something to fall back to.
        cache
            .set("seed", Bytes::from_static(b"seed"), Duration::from_secs(60))
            .await
            .unwrap();

        let mut workers = Vec::new();
        for w in 0..8 {
            let cache = Arc::clone(&cache);
            workers.push(tokio::spawn(async move {
                for i in 0..50 {
                    let key = format!("w{w}-{i}");
                    // Each op must succeed regardless of Redis state.
                    cache
                        .set(&key, Bytes::from_static(b"x"), Duration::from_secs(60))
                        .await
                        .expect("set never fails on a Redis blip");
                    cache.get(&key).await.expect("get never fails on a Redis blip");
                    cache.get("seed").await.expect("get never fails on a Redis blip");
                }
            }));
        }

        // Flap Redis up and down while the workers run.
        let flapper = {
            let backend = backend.clone();
            tokio::spawn(async move {
                for _ in 0..10 {
                    backend.set_failing(true);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    backend.set_failing(false);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
        };

        for worker in workers {
            worker.await.expect("worker task must not panic");
        }
        flapper.await.expect("flapper task must not panic");
    }

    // -- Req 30.2: local-only mode (no Redis configured) --------------------

    /// With no Redis configured, the cache is purely local: round trips work,
    /// the Redis tier is never attached, and a reattach is a no-op (Req 30.2).
    #[tokio::test]
    async fn local_only_mode_uses_local_tier() {
        let cache = FailoverCache::local_only(LocalCache::new("sf"));
        assert!(!cache.redis_attached());

        cache
            .set("k", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(cache.get("k").await.unwrap(), Some(Bytes::from_static(b"v")));

        // Nothing to reattach.
        assert!(!cache.attempt_reattach().await);
        assert!(!cache.redis_attached());
        assert_eq!(cache.namespace(), "sf");
    }

    /// `del` removes from the local tier and is not an error during an outage.
    #[tokio::test]
    async fn del_works_through_failover() {
        let (cache, backend) = test_cache("sf");
        cache
            .set("k", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();

        // Delete while Redis is down: still succeeds via local.
        backend.set_failing(true);
        cache.del("k").await.unwrap();
        assert_eq!(cache.get("k").await.unwrap(), None);
    }
}
