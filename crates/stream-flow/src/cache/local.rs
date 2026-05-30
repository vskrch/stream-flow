//! [`LocalCache`] — the always-present in-process [`CacheBackend`] (Req 30.1).
//!
//! Backed by `moka::future::Cache` for TTL + LRU eviction. Each entry stores
//! the value alongside its **expiry deadline** (`Instant`), exactly as the
//! design specifies (`moka::future::Cache<String, (Bytes, Instant)>`); `get`
//! treats an entry whose deadline has passed as absent (Req 30.4) so a stale
//! value is never served. `moka`'s `max_capacity` provides LRU eviction so the
//! cache stays bounded regardless of how many distinct keys are written.
//!
//! Every physical key written to or read from the underlying `moka` cache is
//! prefixed with the configured namespace (Req 30.3); callers always pass the
//! logical, un-prefixed key.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use moka::future::Cache;

use crate::errors::AppError;

use super::{namespaced_key, CacheBackend};

/// Default maximum number of entries before LRU eviction kicks in.
///
/// The cache is a hot-lookup tier (CheckMagnet results, id-map, integration
/// freshness — design: Persistence note), so a generous-but-bounded default
/// keeps memory predictable while leaving room for the working set. Callers
/// that need a different bound use [`LocalCache::with_capacity`].
pub const DEFAULT_MAX_CAPACITY: u64 = 100_000;

/// In-process TTL + LRU cache backing the no-Redis path and the local tier of
/// the `FailoverCache` (Req 30.1).
#[derive(Clone)]
pub struct LocalCache {
    /// Maps the **namespaced** physical key to `(value, expiry_deadline)`.
    inner: Cache<String, (Bytes, Instant)>,
    /// Key prefix applied to every physical key (Req 30.3).
    namespace: String,
}

impl LocalCache {
    /// Build a `LocalCache` for `namespace` with the [`DEFAULT_MAX_CAPACITY`]
    /// LRU bound.
    pub fn new(namespace: impl Into<String>) -> Self {
        Self::with_capacity(namespace, DEFAULT_MAX_CAPACITY)
    }

    /// Build a `LocalCache` for `namespace` with an explicit `max_capacity`
    /// (number of entries) LRU bound.
    pub fn with_capacity(namespace: impl Into<String>, max_capacity: u64) -> Self {
        Self {
            inner: Cache::builder().max_capacity(max_capacity).build(),
            namespace: namespace.into(),
        }
    }

    /// Approximate number of live entries (for tests / metrics). Includes
    /// not-yet-evicted expired entries until `moka` reconciles them.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

#[async_trait]
impl CacheBackend for LocalCache {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, AppError> {
        let physical = namespaced_key(&self.namespace, key);
        match self.inner.get(&physical).await {
            // Treat an entry whose TTL has elapsed as absent and proactively
            // drop it so the next access refreshes from source (Req 30.4).
            Some((_, deadline)) if Instant::now() >= deadline => {
                self.inner.invalidate(&physical).await;
                Ok(None)
            }
            Some((value, _)) => Ok(Some(value)),
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, val: Bytes, ttl: Duration) -> Result<(), AppError> {
        let physical = namespaced_key(&self.namespace, key);
        // Saturate rather than overflow for pathologically large TTLs; the
        // entry simply never expires by deadline (LRU still bounds it).
        let deadline = Instant::now().checked_add(ttl).unwrap_or_else(|| {
            Instant::now()
                .checked_add(Duration::from_secs(u32::MAX as u64))
                .expect("a u32-seconds deadline is always representable")
        });
        self.inner.insert(physical, (val, deadline)).await;
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<(), AppError> {
        let physical = namespaced_key(&self.namespace, key);
        self.inner.invalidate(&physical).await;
        Ok(())
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Req 30.6 / 30.1: a value retrieved immediately after storing it under
    /// the same key returns the stored value while unexpired.
    #[tokio::test]
    async fn store_retrieve_round_trip_while_unexpired() {
        let cache = LocalCache::new("test-ns");
        cache
            .set("k1", Bytes::from_static(b"hello"), Duration::from_secs(60))
            .await
            .unwrap();

        let got = cache.get("k1").await.unwrap();
        assert_eq!(got, Some(Bytes::from_static(b"hello")));
    }

    /// A never-written key is absent.
    #[tokio::test]
    async fn missing_key_is_absent() {
        let cache = LocalCache::new("test-ns");
        assert_eq!(cache.get("nope").await.unwrap(), None);
    }

    /// `del` removes a present entry.
    #[tokio::test]
    async fn del_removes_entry() {
        let cache = LocalCache::new("test-ns");
        cache
            .set("k", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();
        cache.del("k").await.unwrap();
        assert_eq!(cache.get("k").await.unwrap(), None);
    }

    /// `del` on an absent key is not an error.
    #[tokio::test]
    async fn del_absent_key_is_ok() {
        let cache = LocalCache::new("test-ns");
        assert!(cache.del("ghost").await.is_ok());
    }

    /// Req 30.3: every physical key written to the underlying store is
    /// prefixed with the configured namespace. We observe the prefix directly
    /// on the inner `moka` cache: the namespaced key is present and the bare
    /// logical key is not.
    #[tokio::test]
    async fn keys_are_namespace_prefixed() {
        let cache = LocalCache::new("my-namespace");
        cache
            .set("session:42", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();

        // Force pending writes to be applied before inspecting the inner map.
        cache.inner.run_pending_tasks().await;

        assert!(
            cache.inner.contains_key("my-namespace:session:42"),
            "physical key must be namespace-prefixed",
        );
        assert!(
            !cache.inner.contains_key("session:42"),
            "the bare logical key must never be stored",
        );
        assert_eq!(cache.namespace(), "my-namespace");
    }

    /// Two namespaces are isolated: the same logical key in different
    /// namespaces maps to different physical keys (Req 30.3).
    #[tokio::test]
    async fn distinct_namespaces_isolate_the_same_logical_key() {
        let a = LocalCache::new("ns-a");
        let b = LocalCache::new("ns-b");
        a.set("k", Bytes::from_static(b"a-val"), Duration::from_secs(60))
            .await
            .unwrap();
        b.set("k", Bytes::from_static(b"b-val"), Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(a.get("k").await.unwrap(), Some(Bytes::from_static(b"a-val")));
        assert_eq!(b.get("k").await.unwrap(), Some(Bytes::from_static(b"b-val")));
    }

    /// Req 30.4: once an entry's TTL elapses it is treated as absent.
    #[tokio::test]
    async fn ttl_expiry_treats_entry_as_absent() {
        let cache = LocalCache::new("test-ns");
        cache
            .set("short", Bytes::from_static(b"v"), Duration::from_millis(20))
            .await
            .unwrap();

        // Present while unexpired.
        assert_eq!(
            cache.get("short").await.unwrap(),
            Some(Bytes::from_static(b"v")),
        );

        // After the TTL elapses the entry is absent.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(cache.get("short").await.unwrap(), None);
    }

    /// A subsequent `set` after expiry refreshes the value (Req 30.4).
    #[tokio::test]
    async fn expired_entry_can_be_refreshed() {
        let cache = LocalCache::new("test-ns");
        cache
            .set("k", Bytes::from_static(b"old"), Duration::from_millis(20))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(cache.get("k").await.unwrap(), None);

        cache
            .set("k", Bytes::from_static(b"new"), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(cache.get("k").await.unwrap(), Some(Bytes::from_static(b"new")));
    }
}
