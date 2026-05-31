//! Property-based test for the prefetcher LRU bound (task 18.7).
//!
//! Feature: stream-flow, Property 17
//!
//! **Property 17: Prefetcher LRU bound**
//!
//! *For any* sequence of playlist accesses, after eviction the number of active
//! prefetchers never exceeds the configured prebuffer cache size, and the
//! evicted prefetchers are exactly the least-recently-used ones.
//!
//! **Validates: Requirements 7.6** (and relates to 7.5)
//!
//! The unit under test is the prefetcher registry
//! [`stream_flow::prebuffer::PrefetcherManager`] (design: Components →
//! Pre-Buffering; `src/prebuffer/manager.rs`). Requirement 7.6 states: *while
//! the number of active prefetchers exceeds the configured prebuffer cache
//! size, the least-recently-used prefetchers are evicted down to the configured
//! size.* So for any interleaving of **inserts** (register/replace a
//! per-playlist prefetcher, the read-path admission) and **touches** (look up
//! an existing prefetcher, marking it most-recently-used), two invariants must
//! hold:
//!
//! * **Bound:** after every operation `len() <= prebuffer_cache_size`.
//! * **LRU survivors:** the set of surviving prefetchers is exactly the
//!   most-recently-used ones — equivalently, the evicted ones are exactly the
//!   least-recently-used.
//!
//! Both are checked against an independent textbook LRU oracle driven by the
//! same operation sequence. Recency in the manager is ordered by an internal
//! monotonic access counter (not the wall clock), so a single-threaded
//! operation sequence makes the recency order unambiguous; the idle-eviction
//! timeout is set far in the future and never triggered, isolating the LRU
//! bound (Req 7.6) from idle eviction (Req 7.5).

use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use url::Url;

use stream_flow::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
use stream_flow::egress::{HttpIpReflector, OutboundClient};
use stream_flow::prebuffer::{Prefetcher, PrefetcherManager, SegmentCache};

/// A throwaway egress client. Pre-buffering never dials upstream in this test —
/// the manager stores prefetchers by identity and the LRU bound is purely about
/// registry bookkeeping — so a disabled, fail-open egress with the production
/// HTTP IP reflector (which performs no network I/O at construction) is all the
/// `Prefetcher` constructor needs.
fn outbound() -> Arc<OutboundClient> {
    let cfg = EgressConfig {
        tunnel_mode: EgressTunnelMode::Disabled,
        policy: EgressPolicy::FailOpen,
        ..EgressConfig::default()
    };
    let reflector = Arc::new(HttpIpReflector::from_config(&cfg).expect("reflector builds"));
    Arc::new(OutboundClient::from_config(&cfg, reflector).expect("outbound client builds"))
}

/// Build a throwaway prefetcher for key index `n`; only its identity matters to
/// the registry's LRU accounting.
fn make_prefetcher(client: &Arc<OutboundClient>, cache: &SegmentCache, n: usize) -> Prefetcher {
    let base = Url::parse(&format!("https://cdn.example/p{n}/media.m3u8")).unwrap();
    Prefetcher::new(client.clone(), cache.clone(), base, 3)
}

/// One operation in a generated access sequence over a small key universe.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// Register (or replace) the prefetcher for the key — read-path admission,
    /// marks it most-recently-used and then enforces the LRU bound (Req 7.6).
    Insert(usize),
    /// Look up the prefetcher for the key — marks an existing one
    /// most-recently-used; a miss is a no-op.
    Touch(usize),
}

/// An independent textbook LRU oracle: `order` holds live keys with the
/// least-recently-used at the front and the most-recently-used at the back.
/// Mirrors the contract `PrefetcherManager` must satisfy without reusing its
/// code.
struct LruOracle {
    order: Vec<usize>,
    cap: usize,
}

impl LruOracle {
    fn new(cap: usize) -> Self {
        Self {
            order: Vec::new(),
            cap,
        }
    }

    /// Move `key` to most-recently-used if present; absent keys are a no-op
    /// (mirrors `PrefetcherManager::get` returning `None`).
    fn touch(&mut self, key: usize) {
        if let Some(pos) = self.order.iter().position(|&k| k == key) {
            self.order.remove(pos);
            self.order.push(key);
        }
    }

    /// Admit `key` as most-recently-used (replacing any existing entry), then
    /// evict least-recently-used keys until at most `cap` remain (Req 7.6).
    fn insert(&mut self, key: usize) {
        if let Some(pos) = self.order.iter().position(|&k| k == key) {
            self.order.remove(pos);
        }
        self.order.push(key);
        while self.order.len() > self.cap {
            self.order.remove(0);
        }
    }

    fn contains(&self, key: usize) -> bool {
        self.order.contains(&key)
    }

    fn len(&self) -> usize {
        self.order.len()
    }
}

/// A bounded access sequence over a key universe that is strictly larger than
/// the configured cap, so eviction pressure is guaranteed: `cap ∈ [1, 8]`, an
/// `extra ∈ [1, 6]` headroom of keys beyond the cap, and `1..=60` operations
/// each an insert or a touch of one of the `cap + extra` keys.
fn case_strategy() -> impl Strategy<Value = (usize, usize, Vec<Op>)> {
    (1usize..=8, 1usize..=6).prop_flat_map(|(cap, extra)| {
        let universe = cap + extra;
        let op = (any::<bool>(), 0..universe).prop_map(|(is_insert, key)| {
            if is_insert {
                Op::Insert(key)
            } else {
                Op::Touch(key)
            }
        });
        (
            Just(cap),
            Just(universe),
            prop::collection::vec(op, 1..=60),
        )
    })
}

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 17 — for any interleaving of inserts and
    /// touches over a key universe larger than the cap, the manager keeps
    /// `len() <= prebuffer_cache_size` after every operation, and the surviving
    /// prefetchers are exactly the most-recently-used set (so the evicted ones
    /// are exactly the least-recently-used), matching an independent LRU oracle.
    /// **Validates: Requirements 7.6**
    #[test]
    fn prefetcher_lru_bound_holds_over_arbitrary_access_sequences(
        (cap, universe, ops) in case_strategy(),
    ) {
        let client = outbound();
        let segment_cache = SegmentCache::new(Duration::from_secs(300));

        // A far-future idle timeout that is never reached: the idle reaper
        // (Req 7.5) is never invoked, isolating the LRU bound (Req 7.6).
        let mgr = PrefetcherManager::new(cap, Duration::from_secs(86_400));
        let mut oracle = LruOracle::new(cap);

        let key = |idx: usize| format!("k{idx}");

        for op in &ops {
            match *op {
                Op::Insert(idx) => {
                    mgr.insert(key(idx), Arc::new(make_prefetcher(&client, &segment_cache, idx)));
                    oracle.insert(idx);
                }
                Op::Touch(idx) => {
                    let _ = mgr.get(&key(idx));
                    oracle.touch(idx);
                }
            }

            // -- Bound: never exceeds the configured cap (Req 7.6) -----------
            prop_assert!(
                mgr.len() <= cap,
                "len {} exceeded the configured prebuffer cache size {} after {:?}",
                mgr.len(), cap, op,
            );
            // The live count tracks the oracle exactly at every step.
            prop_assert_eq!(
                mgr.len(),
                oracle.len(),
                "live count diverged from the LRU oracle after {:?}",
                op,
            );
        }

        // -- LRU survivors: the surviving set equals the most-recently-used
        //    set the oracle retains, so the evicted prefetchers are exactly the
        //    least-recently-used ones (Req 7.6). ----------------------------
        for idx in 0..universe {
            prop_assert_eq!(
                mgr.contains(&key(idx)),
                oracle.contains(idx),
                "survivor set diverged for key k{}: manager kept it = {}, LRU oracle kept it = {}",
                idx, mgr.contains(&key(idx)), oracle.contains(idx),
            );
        }
    }
}
