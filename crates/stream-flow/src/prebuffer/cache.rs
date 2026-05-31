//! Pre-buffered segment cache (`prebuffer::cache`) — Req 7.4, 7.7.
//!
//! A `moka`-backed TTL cache holding the bytes of segments that a
//! [`Prefetcher`](super::Prefetcher) has speculatively fetched ahead of the
//! client (design: Components → Pre-Buffering). When the client later requests
//! a pre-buffered segment it is served from here **without re-fetching it from
//! upstream** (Req 7.4); entries are retained for the configured segment-cache
//! TTL (Req 7.7) and then expire so the cache stays bounded.
//!
//! Keys are the segment's absolute upstream URL string, so the same segment
//! prefetched by a prefetcher and later requested by the client resolves to the
//! same entry regardless of which prefetcher cached it.

use std::time::Duration;

use bytes::Bytes;
use moka::future::Cache;

/// The cached representation of one pre-buffered segment: its bytes plus the
/// upstream `Content-Type` to replay to the client (Req 1.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSegment {
    /// The full segment bytes as fetched from upstream.
    pub body: Bytes,
    /// The upstream `Content-Type`, preserved so a cache hit replays the same
    /// content type the client would have seen on a direct fetch (Req 1.5).
    pub content_type: Option<String>,
}

impl CachedSegment {
    /// Build a cached segment from its bytes and optional content type.
    pub fn new(body: Bytes, content_type: Option<String>) -> Self {
        Self { body, content_type }
    }
}

/// Default maximum number of cached segments before `moka` LRU-evicts. The
/// cache is also TTL-bounded (Req 7.7); this entry cap is a memory backstop so
/// a very long live session cannot grow the cache without bound.
pub const DEFAULT_MAX_SEGMENTS: u64 = 1_000;

/// A TTL + LRU cache of pre-buffered segment bytes keyed by absolute upstream
/// URL (Req 7.4, 7.7).
///
/// Cloneable and cheap to share (`moka` caches are `Arc`-backed internally), so
/// every [`Prefetcher`](super::Prefetcher) writing into it and the client read
/// path serving from it share one cache.
#[derive(Clone)]
pub struct SegmentCache {
    inner: Cache<String, CachedSegment>,
}

impl SegmentCache {
    /// Build a segment cache whose entries expire `ttl` after they are written
    /// (Req 7.7), with the [`DEFAULT_MAX_SEGMENTS`] LRU backstop.
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_MAX_SEGMENTS)
    }

    /// Build a segment cache with an explicit `ttl` (Req 7.7) and `max_segments`
    /// LRU bound.
    pub fn with_capacity(ttl: Duration, max_segments: u64) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(max_segments)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// Store a prefetched segment under its absolute upstream URL (Req 7.4).
    pub async fn put(&self, url: &str, segment: CachedSegment) {
        self.inner.insert(url.to_string(), segment).await;
    }

    /// Fetch a pre-buffered segment by absolute upstream URL, or `None` when it
    /// was never prefetched or its TTL has elapsed (Req 7.4, 7.7).
    pub async fn get(&self, url: &str) -> Option<CachedSegment> {
        self.inner.get(url).await
    }

    /// Whether a segment for `url` is currently cached (test/metrics helper).
    pub async fn contains(&self, url: &str) -> bool {
        self.inner.contains_key(url)
    }

    /// Approximate number of cached segments (test/metrics helper).
    pub async fn entry_count(&self) -> u64 {
        self.inner.run_pending_tasks().await;
        self.inner.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(body: &'static [u8]) -> CachedSegment {
        CachedSegment::new(Bytes::from_static(body), Some("video/mp2t".to_string()))
    }

    // -- Req 7.4: a prefetched segment is served from cache ------------------

    #[tokio::test]
    async fn stored_segment_is_served_without_refetch() {
        let cache = SegmentCache::new(Duration::from_secs(300));
        cache
            .put("https://cdn.example/seg1.ts", seg(b"tsbytes"))
            .await;

        let got = cache.get("https://cdn.example/seg1.ts").await;
        assert_eq!(got, Some(seg(b"tsbytes")));
    }

    #[tokio::test]
    async fn missing_segment_is_absent() {
        let cache = SegmentCache::new(Duration::from_secs(300));
        assert!(cache.get("https://cdn.example/never.ts").await.is_none());
    }

    #[tokio::test]
    async fn content_type_is_preserved_on_hit() {
        let cache = SegmentCache::new(Duration::from_secs(300));
        cache
            .put(
                "https://cdn.example/seg.ts",
                CachedSegment::new(Bytes::from_static(b"x"), Some("video/mp4".to_string())),
            )
            .await;
        let got = cache.get("https://cdn.example/seg.ts").await.unwrap();
        assert_eq!(got.content_type.as_deref(), Some("video/mp4"));
    }

    // -- Req 7.7: entries expire after the configured TTL --------------------

    #[tokio::test]
    async fn segment_expires_after_ttl() {
        let cache = SegmentCache::new(Duration::from_millis(30));
        cache.put("https://cdn.example/seg.ts", seg(b"v")).await;
        assert!(cache.get("https://cdn.example/seg.ts").await.is_some());

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            cache.get("https://cdn.example/seg.ts").await.is_none(),
            "an entry past its TTL must be absent (Req 7.7)"
        );
    }

    // -- LRU backstop bounds the cache ---------------------------------------

    #[tokio::test]
    async fn lru_capacity_bounds_the_cache() {
        let cache = SegmentCache::with_capacity(Duration::from_secs(300), 2);
        for i in 0..10 {
            cache
                .put(&format!("https://cdn.example/seg{i}.ts"), seg(b"v"))
                .await;
        }
        assert!(
            cache.entry_count().await <= 2,
            "the LRU cap must bound the number of cached segments"
        );
    }
}
