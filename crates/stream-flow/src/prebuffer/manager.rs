//! Prefetcher registry with LRU + idle eviction (`prebuffer::manager`) —
//! Req 7.5, 7.6.
//!
//! The [`PrefetcherManager`] owns the set of active per-playlist
//! [`Prefetcher`]s and enforces the two bounding rules (design: Components →
//! Pre-Buffering):
//!
//! * **LRU bound (Req 7.6):** while the number of active prefetchers exceeds the
//!   configured `prebuffer_cache_size`, the least-recently-used prefetchers are
//!   evicted down to that size. Every access (get-or-create / touch) updates the
//!   recency order, so the prefetcher the client is actively using is never the
//!   one evicted.
//! * **Idle eviction (Req 7.5):** a prefetcher that receives no request for the
//!   configured inactivity timeout is evicted and its resources released. This
//!   is driven by [`reap_idle`](PrefetcherManager::reap_idle), which the
//!   leaked-resource [`Reaper`](crate::supervisor::reaper) calls on its
//!   interval — the manager exposes a [`Reapable`] adapter so it plugs straight
//!   into the existing reaper seam.
//!
//! Recency and idle-time are measured against an injectable [`Clock`] so both
//! rules are unit-testable on a deterministic fake clock with no real sleeping.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::supervisor::reaper::Reapable;

use super::prefetcher::Prefetcher;

/// A monotonic millisecond clock the manager reads for recency + idle timing.
///
/// Abstracted so tests can drive eviction deterministically with a fake clock
/// (the production clock reads [`std::time::Instant`] relative to a fixed
/// epoch).
pub trait Clock: Send + Sync {
    /// Milliseconds elapsed since some fixed, process-stable epoch. Must be
    /// monotonic non-decreasing.
    fn now_ms(&self) -> u64;
}

/// The default monotonic clock, anchored at the first read of a process-wide
/// [`std::time::Instant`].
pub struct MonotonicClock {
    epoch: std::time::Instant,
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }
}

/// One registry slot: the prefetcher plus the last-access timestamp + a
/// monotonic recency tick used for LRU ordering.
struct Entry {
    prefetcher: Arc<Prefetcher>,
    /// Last access time in clock-ms (drives idle eviction — Req 7.5).
    last_access_ms: u64,
    /// Monotonic recency tick (drives LRU ordering — Req 7.6). A larger tick is
    /// more-recently used; distinct per access so ties never collide.
    recency: u64,
}

/// Owns and bounds the active per-playlist prefetchers (Req 7.5, 7.6).
///
/// Cloneable (`Arc`-backed) so the read path (get-or-create on each media
/// playlist request) and the reaper (idle sweep) share one registry.
#[derive(Clone)]
pub struct PrefetcherManager {
    inner: Arc<Inner>,
}

struct Inner {
    /// Keyed by a caller-chosen prefetcher key (e.g. the resolved
    /// playlist+variant URL). Guarded by a `Mutex`; prefetchers themselves do
    /// their I/O outside the lock.
    entries: Mutex<HashMap<String, Entry>>,
    /// Maximum number of active prefetchers before LRU eviction (Req 7.6).
    max_prefetchers: usize,
    /// Inactivity timeout after which an idle prefetcher is evicted (Req 7.5).
    idle_timeout_ms: u64,
    /// Source of recency ticks + idle timestamps.
    clock: Arc<dyn Clock>,
    /// Monotonic recency counter (each access bumps it).
    recency: AtomicU64,
}

impl PrefetcherManager {
    /// Build a manager bounding the active prefetchers to `max_prefetchers`
    /// (Req 7.6) and evicting any idle longer than `idle_timeout` (Req 7.5),
    /// timed by the default monotonic clock.
    pub fn new(max_prefetchers: usize, idle_timeout: Duration) -> Self {
        Self::with_clock(
            max_prefetchers,
            idle_timeout,
            Arc::new(MonotonicClock::default()),
        )
    }

    /// Build a manager with an injected [`Clock`] (for deterministic tests).
    pub fn with_clock(
        max_prefetchers: usize,
        idle_timeout: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                entries: Mutex::new(HashMap::new()),
                max_prefetchers,
                idle_timeout_ms: idle_timeout.as_millis() as u64,
                clock,
                recency: AtomicU64::new(0),
            }),
        }
    }

    /// Look up the prefetcher for `key`, marking it most-recently-used; returns
    /// `None` when there is no such prefetcher (it was never created or has been
    /// evicted). Touching is what keeps an actively-used prefetcher from being
    /// reaped (Req 7.5) or LRU-evicted (Req 7.6).
    pub fn get(&self, key: &str) -> Option<Arc<Prefetcher>> {
        let mut entries = self.inner.entries.lock().unwrap();
        let now = self.inner.clock.now_ms();
        let recency = self.inner.recency.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = entries.get_mut(key)?;
        entry.last_access_ms = now;
        entry.recency = recency;
        Some(entry.prefetcher.clone())
    }

    /// Register `prefetcher` under `key` as most-recently-used, then enforce the
    /// LRU bound (Req 7.6). Returns the stored handle. If `key` already exists it
    /// is replaced (and marked most-recently-used).
    pub fn insert(&self, key: impl Into<String>, prefetcher: Arc<Prefetcher>) -> Arc<Prefetcher> {
        let key = key.into();
        {
            let mut entries = self.inner.entries.lock().unwrap();
            let now = self.inner.clock.now_ms();
            let recency = self.inner.recency.fetch_add(1, Ordering::Relaxed) + 1;
            entries.insert(
                key,
                Entry {
                    prefetcher: prefetcher.clone(),
                    last_access_ms: now,
                    recency,
                },
            );
        }
        // Enforce the LRU bound after admitting the new prefetcher (Req 7.6).
        self.evict_lru_over_capacity();
        prefetcher
    }

    /// Get the existing prefetcher for `key` (marking it most-recently-used), or
    /// build one with `make`, insert it, and return it — the read-path entry
    /// point invoked on each media-playlist request.
    pub fn get_or_create<F>(&self, key: &str, make: F) -> Arc<Prefetcher>
    where
        F: FnOnce() -> Prefetcher,
    {
        if let Some(existing) = self.get(key) {
            return existing;
        }
        self.insert(key, Arc::new(make()))
    }

    /// The number of active prefetchers.
    pub fn len(&self) -> usize {
        self.inner.entries.lock().unwrap().len()
    }

    /// Whether there are no active prefetchers.
    pub fn is_empty(&self) -> bool {
        self.inner.entries.lock().unwrap().is_empty()
    }

    /// Whether a prefetcher for `key` is currently registered (without touching
    /// recency).
    pub fn contains(&self, key: &str) -> bool {
        self.inner.entries.lock().unwrap().contains_key(key)
    }

    /// Evict every prefetcher idle for at least the inactivity timeout, returning
    /// the number evicted (Req 7.5). Called by the reaper on its interval.
    pub fn reap_idle(&self) -> usize {
        // A zero/disabled timeout means "never idle-evict".
        if self.inner.idle_timeout_ms == 0 {
            return 0;
        }
        let now = self.inner.clock.now_ms();
        let timeout = self.inner.idle_timeout_ms;
        let mut entries = self.inner.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|_, e| now.saturating_sub(e.last_access_ms) < timeout);
        before - entries.len()
    }

    /// A [`Reapable`] adapter so this manager can be registered with the
    /// leaked-resource [`Reaper`](crate::supervisor::reaper) under the
    /// `"prefetcher"` kind (Req 7.5, 50.12).
    pub fn as_reapable(&self) -> Arc<dyn Reapable> {
        Arc::new(PrefetcherReaper {
            manager: self.clone(),
        })
    }

    /// Evict least-recently-used prefetchers until at most `max_prefetchers`
    /// remain (Req 7.6). A `max_prefetchers` of 0 means "unbounded" (no LRU
    /// eviction).
    fn evict_lru_over_capacity(&self) {
        let cap = self.inner.max_prefetchers;
        if cap == 0 {
            return;
        }
        let mut entries = self.inner.entries.lock().unwrap();
        if entries.len() <= cap {
            return;
        }
        // Order keys by recency ascending (least-recently-used first) and drop
        // the overflow.
        let mut by_recency: Vec<(u64, String)> = entries
            .iter()
            .map(|(k, e)| (e.recency, k.clone()))
            .collect();
        by_recency.sort_unstable_by_key(|(recency, _)| *recency);
        let overflow = entries.len() - cap;
        for (_, key) in by_recency.into_iter().take(overflow) {
            entries.remove(&key);
        }
    }
}

/// The [`Reapable`] wrapper returned by
/// [`PrefetcherManager::as_reapable`]: each reaper sweep evicts idle prefetchers
/// (Req 7.5).
struct PrefetcherReaper {
    manager: PrefetcherManager,
}

impl Reapable for PrefetcherReaper {
    fn kind(&self) -> &'static str {
        "prefetcher"
    }

    fn reap(&self) -> usize {
        self.manager.reap_idle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::egress::OutboundClient;
    use crate::prebuffer::cache::SegmentCache;
    use url::Url;

    /// A manually-advanced fake clock for deterministic eviction tests.
    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn advance(&self, by: Duration) {
            self.0.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
        }
    }

    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn outbound() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    /// Build a throwaway prefetcher (its identity is all these tests need).
    fn make_prefetcher(n: usize) -> Prefetcher {
        let base = Url::parse(&format!("https://cdn.example/p{n}/media.m3u8")).unwrap();
        Prefetcher::new(outbound(), SegmentCache::new(Duration::from_secs(300)), base, 3)
    }

    fn manager(max: usize, idle: Duration, clock: FakeClock) -> PrefetcherManager {
        PrefetcherManager::with_clock(max, idle, Arc::new(clock))
    }

    // -- get_or_create reuses the same prefetcher ----------------------------

    #[test]
    fn get_or_create_reuses_existing_prefetcher() {
        let mgr = manager(10, Duration::from_secs(60), FakeClock::default());
        let a = mgr.get_or_create("k", || make_prefetcher(1));
        let b = mgr.get_or_create("k", || make_prefetcher(2));
        assert!(Arc::ptr_eq(&a, &b), "the same key returns the same prefetcher");
        assert_eq!(mgr.len(), 1);
    }

    // -- Req 7.6: LRU eviction down to the configured size -------------------

    #[test]
    fn evicts_lru_down_to_configured_size() {
        let clock = FakeClock::default();
        let mgr = manager(3, Duration::from_secs(3600), clock.clone());

        // Insert 3 prefetchers (k0 oldest .. k2 newest), spacing accesses in
        // time so recency is unambiguous.
        for i in 0..3 {
            mgr.insert(format!("k{i}"), Arc::new(make_prefetcher(i)));
            clock.advance(Duration::from_secs(1));
        }
        assert_eq!(mgr.len(), 3);

        // Touch k0 so it becomes most-recently-used; k1 is now the LRU.
        clock.advance(Duration::from_secs(1));
        assert!(mgr.get("k0").is_some());

        // Insert a 4th → over capacity → exactly one eviction down to 3.
        clock.advance(Duration::from_secs(1));
        mgr.insert("k3", Arc::new(make_prefetcher(3)));
        assert_eq!(mgr.len(), 3, "LRU-evict down to the configured size (Req 7.6)");

        // k1 (the least-recently-used) was evicted; the rest remain.
        assert!(!mgr.contains("k1"), "the LRU prefetcher is evicted");
        assert!(mgr.contains("k0") && mgr.contains("k2") && mgr.contains("k3"));
    }

    #[test]
    fn bulk_overflow_evicts_down_to_size_in_one_insert() {
        let clock = FakeClock::default();
        let mgr = manager(2, Duration::from_secs(3600), clock.clone());
        for i in 0..5 {
            mgr.insert(format!("k{i}"), Arc::new(make_prefetcher(i)));
            clock.advance(Duration::from_millis(10));
        }
        // Never exceeds the cap; the two most-recent survive.
        assert_eq!(mgr.len(), 2);
        assert!(mgr.contains("k3") && mgr.contains("k4"));
    }

    #[test]
    fn zero_max_means_unbounded() {
        let mgr = manager(0, Duration::from_secs(3600), FakeClock::default());
        for i in 0..50 {
            mgr.insert(format!("k{i}"), Arc::new(make_prefetcher(i)));
        }
        assert_eq!(mgr.len(), 50, "max=0 disables LRU eviction");
    }

    // -- Req 7.5: idle prefetchers evicted after the inactivity timeout ------

    #[test]
    fn reaps_idle_prefetchers_after_inactivity_timeout() {
        let clock = FakeClock::default();
        let mgr = manager(100, Duration::from_secs(30), clock.clone());

        mgr.insert("idle", Arc::new(make_prefetcher(1)));
        mgr.insert("active", Arc::new(make_prefetcher(2)));

        // 20s later (under the 30s timeout): nothing reaped.
        clock.advance(Duration::from_secs(20));
        assert_eq!(mgr.reap_idle(), 0);
        assert_eq!(mgr.len(), 2);

        // Touch "active" to keep it fresh, then advance past the timeout for
        // "idle".
        assert!(mgr.get("active").is_some());
        clock.advance(Duration::from_secs(15)); // idle: 35s, active: 15s

        assert_eq!(mgr.reap_idle(), 1, "the idle prefetcher is evicted (Req 7.5)");
        assert!(!mgr.contains("idle"));
        assert!(mgr.contains("active"), "the recently-used prefetcher survives");
    }

    #[test]
    fn reap_at_exactly_the_timeout_evicts() {
        let clock = FakeClock::default();
        let mgr = manager(100, Duration::from_secs(30), clock.clone());
        mgr.insert("k", Arc::new(make_prefetcher(1)));

        // Just under the timeout → still alive.
        clock.advance(Duration::from_secs(30) - Duration::from_millis(1));
        assert_eq!(mgr.reap_idle(), 0);
        assert!(mgr.contains("k"));

        // Idle has now reached the configured timeout → evicted (Req 7.5:
        // "no requests for the configured inactivity timeout").
        clock.advance(Duration::from_millis(1));
        assert_eq!(mgr.reap_idle(), 1);
        assert!(!mgr.contains("k"));
    }

    #[test]
    fn zero_idle_timeout_never_reaps() {
        let clock = FakeClock::default();
        let mgr = manager(100, Duration::from_secs(0), clock.clone());
        mgr.insert("k", Arc::new(make_prefetcher(1)));
        clock.advance(Duration::from_secs(3600));
        assert_eq!(mgr.reap_idle(), 0, "a zero idle timeout disables idle eviction");
        assert!(mgr.contains("k"));
    }

    // -- Reapable adapter plugs into the reaper seam (Req 7.5, 50.12) --------

    #[test]
    fn as_reapable_evicts_idle_via_the_reaper_seam() {
        let clock = FakeClock::default();
        let mgr = manager(100, Duration::from_secs(30), clock.clone());
        mgr.insert("idle", Arc::new(make_prefetcher(1)));

        let reapable = mgr.as_reapable();
        assert_eq!(reapable.kind(), "prefetcher");

        clock.advance(Duration::from_secs(31));
        assert_eq!(reapable.reap(), 1, "the reaper seam evicts the idle prefetcher");
        assert!(mgr.is_empty());
    }
}
