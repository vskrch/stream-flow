//! Property-based test for the warmup-pool size bound and LRU eviction
//! (task 29.5).
//!
//! Feature: ZippyPanther, Property 43
//!
//! **Property 43: Warmup pool bounds**
//!
//! *For any* sequence of `record_access` / `upsert_link` / `get` operations
//! over a key universe strictly larger than the configured `pool_size`, the
//! warmup pool never holds more entries than `pool_size` (LRU eviction bound,
//! Req 45.5), the evicted entry is always the least-recently-used (Req 45.3),
//! and per-store refresh-rate enforcement holds for any interleaving of
//! `can_refresh_store` / `record_refresh` calls (Req 45.7).
//!
//! **Validates: Requirements 45.3, 45.5, 45.7**
//!
//! ## How the property is exercised
//!
//! Each case generates:
//!
//! * `cap ∈ [1, 8]` — the pool size.
//! * `extra ∈ [1, 4]` — additional keys beyond the cap, so eviction pressure is
//!   guaranteed.
//! * `ops ∈ 1..=60` — a sequence of:
//!     * `Upsert(key_idx)` — calls `upsert_link`, the primary insertion path.
//!     * `Access(key_idx)` — calls `record_access`, touches recency.
//!     * `Get(key_idx)` — calls `get`, touches recency.
//!
//! After each operation the invariants are checked against an independent
//! textbook LRU oracle identical to the one in Property 17.
//!
//! The per-store refresh-rate sub-property generates a separate sequence of
//! `can_refresh_store` / `record_refresh` calls against a rate limit of 2 per
//! 60-second window and asserts the in-window count never exceeds the limit.

use std::collections::{HashMap, HashSet};

use proptest::prelude::*;

use zippy_panther::config::WarmupConfig;
use zippy_panther::warmup::{StoreCost, WarmupKey, WarmupPool};

// ---------------------------------------------------------------------------
// LRU oracle (independent textbook implementation)
// ---------------------------------------------------------------------------

/// An independent LRU oracle: `order` is sorted least-recently-used at the
/// front, most-recently-used at the back. Only tracks key indices.
struct LruOracle {
    order: Vec<usize>,
    linked: HashSet<usize>,
    cap: usize,
}

impl LruOracle {
    fn new(cap: usize) -> Self {
        Self {
            order: Vec::new(),
            linked: HashSet::new(),
            cap,
        }
    }

    /// Move `key` to the back (most-recently-used) if present; absent keys are
    /// a no-op (mirrors `WarmupPool::get` returning `None`).
    fn touch(&mut self, key: usize) {
        if let Some(pos) = self.order.iter().position(|&k| k == key) {
            self.order.remove(pos);
            self.order.push(key);
        }
    }

    /// Record an access as most-recently-used without creating a warmed link.
    fn access(&mut self, key: usize) {
        self.admit(key, false);
    }

    /// Admit/update `key` with a warmed link as most-recently-used, then evict
    /// LRU entries until at most `cap` remain (Req 45.5).
    fn upsert(&mut self, key: usize) {
        self.admit(key, true);
    }

    fn admit(&mut self, key: usize, has_link: bool) {
        if let Some(pos) = self.order.iter().position(|&k| k == key) {
            self.order.remove(pos);
        }
        if has_link {
            self.linked.insert(key);
        }
        self.order.push(key);
        while self.order.len() > self.cap {
            let evicted = self.order.remove(0);
            self.linked.remove(&evicted);
        }
    }

    fn get(&mut self, key: usize) {
        if self.linked.contains(&key) {
            self.touch(key);
        }
    }

    fn contains(&self, key: usize) -> bool {
        self.order.contains(&key)
    }

    fn len(&self) -> usize {
        self.order.len()
    }
}

// ---------------------------------------------------------------------------
// Operation type
// ---------------------------------------------------------------------------

/// One operation in the generated sequence over the key universe.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// `upsert_link` — primary insertion path; creates/refreshes a warm link.
    Upsert(usize),
    /// `record_access` — marks the key as recently accessed (read-path).
    Access(usize),
    /// `get` — touch-on-hit; miss is a no-op.
    Get(usize),
}

// ---------------------------------------------------------------------------
// Strategy
// ---------------------------------------------------------------------------

/// Generate a `(cap, universe_size, ops)` triple such that `universe_size >
/// cap` (guaranteed eviction pressure) and `ops` is a bounded sequence over
/// that universe.
fn case_strategy() -> impl Strategy<Value = (usize, usize, Vec<Op>)> {
    (1usize..=8, 1usize..=4).prop_flat_map(|(cap, extra)| {
        let universe = cap + extra;
        let op = (0..3usize, 0..universe).prop_map(|(kind, key)| match kind {
            0 => Op::Upsert(key),
            1 => Op::Access(key),
            _ => Op::Get(key),
        });
        (Just(cap), Just(universe), prop::collection::vec(op, 1..=60))
    })
}

/// Generate a sequence of (is_refresh, elapsed_secs) pairs for the per-store
/// rate-limit sub-property: 1..=40 events, `elapsed ∈ [0, 120]` seconds.
fn rate_case_strategy() -> impl Strategy<Value = Vec<(bool, u64)>> {
    prop::collection::vec((any::<bool>(), 0u64..=120), 1..=40)
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 43 (pool-size bound and LRU eviction) —
    /// for any interleaving of `upsert_link` / `record_access` / `get` over a
    /// key universe strictly larger than `pool_size`, the pool never holds more
    /// than `pool_size` entries, and the surviving entries are exactly the
    /// most-recently-used ones (LRU eviction, Req 45.5, 45.3).
    ///
    /// **Validates: Requirements 45.3, 45.5**
    #[test]
    fn warmup_pool_lru_bound_holds_over_arbitrary_access_sequences(
        (cap, universe, ops) in case_strategy(),
    ) {
        let cfg = WarmupConfig {
            enabled: true,
            pool_size: cap,
            popularity_threshold: 1, // promote immediately so Access also inserts
            min_refresh_interval_secs: 0,
            link_validity_secs: 10_000,
            allow_costly_stores: true,
            per_store_max_refresh_per_minute: 1_000,
        };
        let mut pool = WarmupPool::new(cfg);
        let mut oracle = LruOracle::new(cap);

        let key = |idx: usize| WarmupKey::new("rd", format!("k{idx}"));

        for op in &ops {
            match *op {
                Op::Upsert(idx) => {
                    pool.upsert_link(key(idx), format!("https://cdn/k{idx}"), 1, None);
                    oracle.upsert(idx);
                }
                Op::Access(idx) => {
                    // record_access with count >= threshold will mark it; because
                    // threshold = 1 and the pool is enabled, this behaves like an
                    // insert when the entry already reached the threshold.
                    pool.record_access(key(idx), StoreCost::Free, 1);
                    // Only counts as an oracle insert when the pool actually
                    // admits the entry (i.e. record_access touched it). The pool
                    // may not insert if count < threshold, but threshold=1 here
                    // so the first access always inserts.
                    oracle.access(idx);
                }
                Op::Get(idx) => {
                    pool.get(&key(idx), 1); // touch on hit, miss is no-op
                    oracle.get(idx);
                }
            }

            // Bound invariant (Req 45.5): pool never grows past pool_size.
            prop_assert!(
                pool.len() <= cap,
                "pool.len()={} exceeded pool_size={} after {:?}",
                pool.len(), cap, op,
            );
            // The live count matches the oracle at every step.
            prop_assert_eq!(
                pool.len(),
                oracle.len(),
                "pool.len()={} != oracle.len()={} after {:?}",
                pool.len(), oracle.len(), op,
            );
        }

        // LRU survivors (Req 45.3): the surviving set equals the oracle's set.
        for idx in 0..universe {
            let in_pool = pool.contains(&key(idx));
            let in_oracle = oracle.contains(idx);

            prop_assert_eq!(
                in_pool,
                in_oracle,
                "LRU survivor mismatch for k{} (pool.len={})",
                idx,
                pool.len(),
            );
        }
    }

    /// Feature: ZippyPanther, Property 43 (per-store refresh rate) —
    /// for any sequence of `can_refresh_store` / `record_refresh` calls against
    /// a rate limit of 2 per 60-second window, the number of in-window recorded
    /// refreshes never exceeds the limit, and `can_refresh_store` returns `false`
    /// once the limit is reached until the window rolls forward.
    ///
    /// **Validates: Requirements 45.7**
    #[test]
    fn warmup_pool_per_store_refresh_rate_never_exceeds_limit(
        events in rate_case_strategy(),
    ) {
        const LIMIT: u32 = 2;
        let cfg = WarmupConfig {
            enabled: true,
            pool_size: 100,
            popularity_threshold: 1,
            min_refresh_interval_secs: 0,
            link_validity_secs: 10_000,
            allow_costly_stores: true,
            per_store_max_refresh_per_minute: LIMIT,
        };
        let mut pool = WarmupPool::new(cfg);

        // Independent oracle: map from store -> VecDeque of recorded timestamps.
        let mut oracle_refreshes: HashMap<String, Vec<u64>> = HashMap::new();
        let mut now: u64 = 0;

        for (is_refresh, elapsed) in &events {
            now = now.saturating_add(*elapsed);

            let store = "rd";
            let oracle_bucket = oracle_refreshes.entry(store.to_string()).or_default();

            // Expire stale entries (older than 60s).
            oracle_bucket.retain(|&ts| now.saturating_sub(ts) < 60);

            let oracle_can = (oracle_bucket.len() as u32) < LIMIT;
            let pool_can = pool.can_refresh_store(store, now);

            // Oracle and pool must agree on whether a refresh is allowed.
            prop_assert_eq!(
                pool_can, oracle_can,
                "can_refresh_store disagreed at t={}: pool={}, oracle={} (in-window count={})",
                now, pool_can, oracle_can, oracle_bucket.len(),
            );

            if *is_refresh && pool_can {
                pool.record_refresh(store, now);
                oracle_bucket.push(now);
            }

            // After recording, in-window count must not exceed the limit.
            oracle_bucket.retain(|&ts| now.saturating_sub(ts) < 60);
            prop_assert!(
                (oracle_bucket.len() as u32) <= LIMIT,
                "oracle in-window count {} exceeded limit {LIMIT} at t={now}",
                oracle_bucket.len(),
            );
        }
    }
}
