//! Opt-in warmup pool (`warmup`) — Req 45.
//!
//! The pool tracks frequently requested store/content keys and keeps a bounded
//! set of pre-resolved links warm. It is disabled by default, excludes costly
//! stores unless explicitly allowed, rate-limits refreshes per store, and uses
//! LRU eviction to stay within the configured pool size.

use std::collections::{BTreeMap, VecDeque};

use crate::config::WarmupConfig;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WarmupKey {
    pub store: String,
    pub content_id: String,
}

impl WarmupKey {
    pub fn new(store: impl Into<String>, content_id: impl Into<String>) -> Self {
        Self {
            store: store.into(),
            content_id: content_id.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreCost {
    Free,
    RateLimited,
    PerLinkCharged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarmedLink {
    pub url: String,
    pub expires_at: u64,
    pub refreshed_at: u64,
}

#[derive(Clone, Debug)]
struct Entry {
    access_count: u64,
    link: Option<WarmedLink>,
    last_accessed_at: u64,
}

#[derive(Clone, Debug)]
pub struct WarmupPool {
    config: WarmupConfig,
    entries: BTreeMap<WarmupKey, Entry>,
    lru: VecDeque<WarmupKey>,
    refreshes_by_store: BTreeMap<String, VecDeque<u64>>,
}

impl WarmupPool {
    pub fn new(config: WarmupConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            lru: VecDeque::new(),
            refreshes_by_store: BTreeMap::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, key: &WarmupKey) -> bool {
        self.entries.contains_key(key)
    }

    pub fn record_access(&mut self, key: WarmupKey, cost: StoreCost, now: u64) -> bool {
        if !self.config.enabled || self.config.pool_size == 0 {
            return false;
        }
        if self.is_costly(cost) {
            return false;
        }

        let promoted = {
            let entry = self.entries.entry(key.clone()).or_insert(Entry {
                access_count: 0,
                link: None,
                last_accessed_at: now,
            });
            entry.access_count = entry.access_count.saturating_add(1);
            entry.last_accessed_at = now;
            entry.access_count >= self.config.popularity_threshold
        };
        self.touch(&key);
        self.evict_to_cap();
        promoted
    }

    pub fn upsert_link(
        &mut self,
        key: WarmupKey,
        url: impl Into<String>,
        now: u64,
        validity_secs: Option<u64>,
    ) {
        if !self.config.enabled || self.config.pool_size == 0 {
            return;
        }
        let validity = validity_secs.unwrap_or(self.config.link_validity_secs);
        let entry = self.entries.entry(key.clone()).or_insert(Entry {
            access_count: self.config.popularity_threshold,
            link: None,
            last_accessed_at: now,
        });
        entry.link = Some(WarmedLink {
            url: url.into(),
            expires_at: now.saturating_add(validity),
            refreshed_at: now,
        });
        entry.last_accessed_at = now;
        self.touch(&key);
        self.evict_to_cap();
    }

    pub fn get(&mut self, key: &WarmupKey, now: u64) -> Option<WarmedLink> {
        let entry = self.entries.get_mut(key)?;
        let link = entry.link.as_ref()?;
        if link.expires_at <= now {
            entry.link = None;
            return None;
        }
        entry.last_accessed_at = now;
        let out = link.clone();
        self.touch(key);
        Some(out)
    }

    pub fn refresh_due(&self, key: &WarmupKey, now: u64) -> bool {
        let Some(entry) = self.entries.get(key) else {
            return false;
        };
        if entry.access_count < self.config.popularity_threshold {
            return false;
        }
        match &entry.link {
            None => true,
            Some(link) => {
                link.expires_at > now
                    && now.saturating_sub(link.refreshed_at)
                        >= self.config.min_refresh_interval_secs
            }
        }
    }

    pub fn can_refresh_store(&mut self, store: &str, now: u64) -> bool {
        let limit = self.config.per_store_max_refresh_per_minute;
        if limit == 0 {
            return false;
        }
        let bucket = self
            .refreshes_by_store
            .entry(store.to_string())
            .or_default();
        while bucket
            .front()
            .is_some_and(|ts| now.saturating_sub(*ts) >= 60)
        {
            bucket.pop_front();
        }
        bucket.len() < limit as usize
    }

    pub fn record_refresh(&mut self, store: &str, now: u64) {
        self.refreshes_by_store
            .entry(store.to_string())
            .or_default()
            .push_back(now);
    }

    fn is_costly(&self, cost: StoreCost) -> bool {
        !self.config.allow_costly_stores
            && matches!(cost, StoreCost::RateLimited | StoreCost::PerLinkCharged)
    }

    fn touch(&mut self, key: &WarmupKey) {
        self.lru.retain(|existing| existing != key);
        self.lru.push_back(key.clone());
    }

    fn evict_to_cap(&mut self) {
        while self.entries.len() > self.config.pool_size {
            let Some(oldest) = self.lru.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> WarmupConfig {
        WarmupConfig {
            enabled: true,
            pool_size: 2,
            popularity_threshold: 2,
            min_refresh_interval_secs: 10,
            link_validity_secs: 100,
            allow_costly_stores: false,
            per_store_max_refresh_per_minute: 2,
        }
    }

    #[test]
    fn disabled_pool_never_promotes() {
        let mut c = cfg();
        c.enabled = false;
        let mut pool = WarmupPool::new(c);
        assert!(!pool.record_access(WarmupKey::new("rd", "a"), StoreCost::Free, 0));
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn promotes_after_popularity_threshold() {
        let mut pool = WarmupPool::new(cfg());
        let key = WarmupKey::new("rd", "a");
        assert!(!pool.record_access(key.clone(), StoreCost::Free, 1));
        assert!(pool.record_access(key, StoreCost::Free, 2));
    }

    #[test]
    fn excludes_costly_stores_by_default() {
        let mut pool = WarmupPool::new(cfg());
        assert!(!pool.record_access(WarmupKey::new("charged", "a"), StoreCost::PerLinkCharged, 1,));
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn serves_fresh_link_and_expires_stale_link() {
        let mut pool = WarmupPool::new(cfg());
        let key = WarmupKey::new("rd", "a");
        pool.upsert_link(key.clone(), "https://cdn/a", 10, None);
        assert_eq!(pool.get(&key, 20).unwrap().url, "https://cdn/a");
        assert!(pool.get(&key, 111).is_none());
    }

    #[test]
    fn refresh_due_obeys_min_interval_and_validity() {
        let mut pool = WarmupPool::new(cfg());
        let key = WarmupKey::new("rd", "a");
        pool.record_access(key.clone(), StoreCost::Free, 0);
        pool.record_access(key.clone(), StoreCost::Free, 1);
        pool.upsert_link(key.clone(), "https://cdn/a", 5, None);
        assert!(!pool.refresh_due(&key, 14));
        assert!(pool.refresh_due(&key, 15));
        assert!(!pool.refresh_due(&key, 106));
    }

    #[test]
    fn lru_eviction_bounds_pool_size() {
        let mut pool = WarmupPool::new(cfg());
        pool.upsert_link(WarmupKey::new("rd", "a"), "a", 1, None);
        pool.upsert_link(WarmupKey::new("rd", "b"), "b", 2, None);
        pool.upsert_link(WarmupKey::new("rd", "c"), "c", 3, None);
        assert_eq!(pool.len(), 2);
        assert!(pool.get(&WarmupKey::new("rd", "a"), 4).is_none());
    }

    #[test]
    fn per_store_refresh_rate_is_bounded() {
        let mut pool = WarmupPool::new(cfg());
        assert!(pool.can_refresh_store("rd", 1));
        pool.record_refresh("rd", 1);
        assert!(pool.can_refresh_store("rd", 2));
        pool.record_refresh("rd", 2);
        assert!(!pool.can_refresh_store("rd", 3));
        assert!(pool.can_refresh_store("rd", 62));
    }
}
