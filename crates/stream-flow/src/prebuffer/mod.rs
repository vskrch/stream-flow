//! Smart pre-buffering (`prebuffer`) — Req 7.
//!
//! Speculatively fetches upcoming HLS/DASH media segments ahead of the client's
//! playback position so playback starts faster and stalls less (design:
//! Components → Pre-Buffering). The module is composed of four pieces, each its
//! own submodule so the pure logic is unit/property-testable in isolation:
//!
//! * [`variant`] — pure HLS master-playlist variant selection: the
//!   highest-`BANDWIDTH` variant at or under the configured pre-buffer ceiling,
//!   else the lowest when all exceed it (Req 7.2; Property 16).
//! * [`plan`] — pure upcoming-segment planning: the next up-to-`N` segments
//!   after the requested position, resolved against the manifest base, with a
//!   media-sequence watermark that makes live-refresh prefetching idempotent
//!   (Req 7.1, 7.3).
//! * [`cache`] — the `moka` TTL + LRU [`SegmentCache`] that serves pre-buffered
//!   segments without a re-fetch (Req 7.4) and retains them for the segment
//!   cache TTL (Req 7.7).
//! * [`prefetcher`] — the per-playlist [`Prefetcher`] that fetches the planned
//!   segments through the single egress seam into the cache (Req 7.1, 7.3, 7.4).
//! * [`manager`] — the [`PrefetcherManager`] registry that bounds active
//!   prefetchers by LRU down to the configured prebuffer cache size (Req 7.6)
//!   and evicts idle prefetchers after the inactivity timeout (Req 7.5) via the
//!   leaked-resource reaper seam.
//!
//! The top-level [`PreBuffer`] facade wires the manager + shared segment cache
//! together from [`PrebufferRuntimeConfig`] and is the entry point the HLS/MPD
//! handlers (later tasks) call to register/drive prefetchers and to serve a
//! pre-buffered segment from cache.

pub mod cache;
pub mod manager;
pub mod plan;
pub mod prefetcher;
pub mod variant;

use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::egress::OutboundClient;
use crate::supervisor::reaper::Reapable;

pub use cache::{CachedSegment, SegmentCache};
pub use manager::{Clock, MonotonicClock, PrefetcherManager};
pub use plan::{is_live, plan_upcoming_segments, PlannedSegment};
pub use prefetcher::Prefetcher;
pub use variant::select_prebuffer_variant;

/// The resolved pre-buffering tunables the runtime needs (derived from
/// [`HlsConfig`](crate::config::HlsConfig) + the pre-buffer enable flag).
///
/// Kept as a small owned struct so the facade does not depend on the whole
/// `Config` and is trivial to construct in tests.
#[derive(Clone, Debug)]
pub struct PrebufferRuntimeConfig {
    /// Whether pre-buffering is enabled at all (Req 7.1, gated by config).
    pub enabled: bool,
    /// How many upcoming segments to prefetch ahead of the position (Req 7.1).
    pub prebuffer_segments: usize,
    /// Maximum number of active prefetchers before LRU eviction (Req 7.6).
    pub prebuffer_cache_size: usize,
    /// How long a prefetched segment is retained in the cache (Req 7.7).
    pub segment_cache_ttl: Duration,
    /// Inactivity timeout after which an idle prefetcher is evicted (Req 7.5).
    pub inactivity_timeout: Duration,
    /// The pre-buffer bandwidth ceiling for HLS variant selection (Req 7.2).
    pub bandwidth_ceiling: u64,
}

/// A generous default bandwidth ceiling (~8 Mbps) used when no explicit ceiling
/// is configured — high enough to admit typical 1080p variants while still
/// excluding very high-bitrate 4K renditions from speculative prefetch.
pub const DEFAULT_BANDWIDTH_CEILING: u64 = 8_000_000;

impl PrebufferRuntimeConfig {
    /// Derive the runtime config from the HLS sub-config and the pre-buffer
    /// enable flag (design: Configuration Model → HlsConfig / PrebufferConfig).
    pub fn from_hls(hls: &crate::config::HlsConfig, enabled: bool, bandwidth_ceiling: u64) -> Self {
        Self {
            enabled,
            prebuffer_segments: hls.prebuffer_segments,
            prebuffer_cache_size: hls.prebuffer_cache_size,
            segment_cache_ttl: Duration::from_secs(hls.segment_cache_ttl_secs),
            inactivity_timeout: Duration::from_secs(hls.inactivity_timeout_secs),
            bandwidth_ceiling,
        }
    }
}

/// The smart pre-buffering subsystem: a bounded registry of per-playlist
/// prefetchers plus the shared segment cache (Req 7).
///
/// Cloneable (`Arc`-backed components) so the HLS/MPD handlers and the
/// background reaper share one instance.
#[derive(Clone)]
pub struct PreBuffer {
    client: Arc<OutboundClient>,
    cache: SegmentCache,
    manager: PrefetcherManager,
    cfg: PrebufferRuntimeConfig,
}

impl PreBuffer {
    /// Build the pre-buffering subsystem over the egress seam and the resolved
    /// runtime config (Req 7.5, 7.6, 7.7).
    pub fn new(client: Arc<OutboundClient>, cfg: PrebufferRuntimeConfig) -> Self {
        let cache = SegmentCache::new(cfg.segment_cache_ttl);
        let manager = PrefetcherManager::new(cfg.prebuffer_cache_size, cfg.inactivity_timeout);
        Self {
            client,
            cache,
            manager,
            cfg,
        }
    }

    /// Whether pre-buffering is enabled (Req 7.1).
    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// The shared pre-buffered-segment cache (Req 7.4, 7.7).
    pub fn cache(&self) -> &SegmentCache {
        &self.cache
    }

    /// The prefetcher registry (Req 7.5, 7.6).
    pub fn manager(&self) -> &PrefetcherManager {
        &self.manager
    }

    /// Select the variant to pre-buffer from a master playlist's variants,
    /// using the configured bandwidth ceiling (Req 7.2). Returns `None` for an
    /// empty master.
    pub fn select_variant<'a>(
        &self,
        variants: &'a [m3u8_rs::VariantStream],
    ) -> Option<&'a m3u8_rs::VariantStream> {
        select_prebuffer_variant(variants, self.cfg.bandwidth_ceiling)
    }

    /// Get-or-create the prefetcher for the media playlist at `base`, keyed by
    /// its absolute URL, forwarding `headers` to derived prefetch requests
    /// (Req 1.6). Marks the prefetcher most-recently-used so it is not evicted
    /// while in use (Req 7.5, 7.6).
    pub fn prefetcher_for(
        &self,
        base: &Url,
        headers: std::collections::BTreeMap<String, String>,
    ) -> Arc<Prefetcher> {
        let key = base.as_str().to_string();
        let client = self.client.clone();
        let cache = self.cache.clone();
        let base = base.clone();
        let count = self.cfg.prebuffer_segments;
        self.manager.get_or_create(&key, move || {
            Prefetcher::new(client, cache, base, count).with_headers(headers)
        })
    }

    /// Serve a pre-buffered segment by absolute upstream URL, or `None` when it
    /// was not pre-buffered (or its TTL has elapsed) — the client read path that
    /// avoids a re-fetch (Req 7.4).
    pub async fn serve_cached_segment(&self, url: &str) -> Option<CachedSegment> {
        self.cache.get(url).await
    }

    /// The [`Reapable`] adapter that evicts idle prefetchers, for registration
    /// with the leaked-resource [`Reaper`](crate::supervisor::reaper) (Req 7.5,
    /// 50.12).
    pub fn as_reapable(&self) -> Arc<dyn Reapable> {
        self.manager.as_reapable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode, HlsConfig};
    use crate::egress::tunnel::test_support::MockReflector;
    use m3u8_rs::VariantStream;

    fn outbound() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn variant(uri: &str, bandwidth: u64) -> VariantStream {
        VariantStream {
            uri: uri.to_string(),
            bandwidth,
            ..VariantStream::default()
        }
    }

    fn prebuffer(ceiling: u64) -> PreBuffer {
        let cfg = PrebufferRuntimeConfig {
            enabled: true,
            prebuffer_segments: 3,
            prebuffer_cache_size: 5,
            segment_cache_ttl: Duration::from_secs(300),
            inactivity_timeout: Duration::from_secs(60),
            bandwidth_ceiling: ceiling,
        };
        PreBuffer::new(outbound(), cfg)
    }

    #[test]
    fn runtime_config_derives_from_hls_config() {
        let hls = HlsConfig::default();
        let cfg = PrebufferRuntimeConfig::from_hls(&hls, true, DEFAULT_BANDWIDTH_CEILING);
        assert_eq!(cfg.prebuffer_segments, hls.prebuffer_segments);
        assert_eq!(cfg.prebuffer_cache_size, hls.prebuffer_cache_size);
        assert_eq!(cfg.segment_cache_ttl, Duration::from_secs(hls.segment_cache_ttl_secs));
        assert_eq!(cfg.inactivity_timeout, Duration::from_secs(hls.inactivity_timeout_secs));
    }

    #[test]
    fn facade_selects_variant_with_configured_ceiling() {
        let pb = prebuffer(2_000_000);
        let variants = vec![
            variant("low.m3u8", 400_000),
            variant("mid.m3u8", 1_500_000),
            variant("high.m3u8", 6_000_000),
        ];
        let selected = pb.select_variant(&variants).unwrap();
        assert_eq!(selected.uri, "mid.m3u8");
    }

    #[test]
    fn facade_reuses_prefetcher_per_playlist() {
        let pb = prebuffer(DEFAULT_BANDWIDTH_CEILING);
        let base = Url::parse("https://cdn.example/v/media.m3u8").unwrap();
        let a = pb.prefetcher_for(&base, Default::default());
        let b = pb.prefetcher_for(&base, Default::default());
        assert!(Arc::ptr_eq(&a, &b), "the same playlist reuses its prefetcher");
        assert_eq!(pb.manager().len(), 1);
    }

    #[tokio::test]
    async fn facade_serves_cached_segment() {
        let pb = prebuffer(DEFAULT_BANDWIDTH_CEILING);
        pb.cache()
            .put(
                "https://cdn.example/seg.ts",
                CachedSegment::new(bytes::Bytes::from_static(b"v"), None),
            )
            .await;
        assert!(pb.serve_cached_segment("https://cdn.example/seg.ts").await.is_some());
        assert!(pb.serve_cached_segment("https://cdn.example/missing.ts").await.is_none());
    }

    #[test]
    fn facade_exposes_reapable_prefetcher_kind() {
        let pb = prebuffer(DEFAULT_BANDWIDTH_CEILING);
        assert_eq!(pb.as_reapable().kind(), "prefetcher");
    }
}
