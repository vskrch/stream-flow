//! Per-playlist segment prefetcher (`prebuffer::prefetcher`) — Req 7.1, 7.3,
//! 7.4.
//!
//! A [`Prefetcher`] is created per `(playlist, variant)` and speculatively
//! fetches up to the configured number of upcoming segments **ahead of the
//! client's position**, storing each in the shared [`SegmentCache`] so a later
//! client request is served without a re-fetch (design: Components →
//! Pre-Buffering; Req 7.1, 7.4). It fetches **only** through the single egress
//! seam ([`OutboundClient`](crate::egress::OutboundClient)) so every prefetch is
//! tunnelled and carries no client-identifying header (Req 51.1–51.3).
//!
//! Each prefetcher tracks a monotonic **watermark** — the highest media-sequence
//! number it has already planned — so:
//!
//! * repeated calls never re-fetch a segment it already has; and
//! * for a live presentation, re-invoking [`prefetch_ahead`](Prefetcher::prefetch_ahead)
//!   after a playlist refresh fetches only the newly published segments past the
//!   watermark (Req 7.3).
//!
//! Prefetching is **best-effort**: a segment that fails to fetch is skipped (and
//! logged) rather than surfacing an error, because a speculative miss must never
//! break the client's actual playback.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use m3u8_rs::MediaPlaylist;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::{DirectSource, UpstreamSource};

use super::cache::{CachedSegment, SegmentCache};
use super::plan::plan_upcoming_segments;

/// The maximum size of a single prefetched segment buffered in memory. A real
/// HLS segment is a few MiB; this guards a hostile/oversized "segment" from
/// blowing the prefetch memory budget on the 512 MB-VPS.
const MAX_SEGMENT_BYTES: usize = 32 * 1024 * 1024;

/// Speculatively fetches upcoming segments of one media playlist into the shared
/// [`SegmentCache`] (design: Components → Pre-Buffering; Req 7.1, 7.3, 7.4).
pub struct Prefetcher {
    /// The single outbound seam — the only path to the network (Req 51.1).
    client: Arc<OutboundClient>,
    /// The shared pre-buffered-segment cache prefetched bytes are written to
    /// (Req 7.4).
    cache: SegmentCache,
    /// The media-playlist URL, used as the base for resolving relative segment
    /// URIs (Req 1.4).
    base: Url,
    /// Custom upstream headers forwarded on every prefetch request (Req 1.6).
    headers: BTreeMap<String, String>,
    /// How many upcoming segments to prefetch ahead of the position (Req 7.1).
    count: usize,
    /// The highest media-sequence number planned so far; makes repeated /
    /// live-refresh prefetching idempotent (Req 7.3).
    watermark: Mutex<Option<u64>>,
}

impl Prefetcher {
    /// Build a prefetcher for the media playlist at `base`, writing prefetched
    /// segments into `cache`, fetching up to `count` segments ahead (Req 7.1).
    pub fn new(
        client: Arc<OutboundClient>,
        cache: SegmentCache,
        base: Url,
        count: usize,
    ) -> Self {
        Self {
            client,
            cache,
            base,
            headers: BTreeMap::new(),
            count,
            watermark: Mutex::new(None),
        }
    }

    /// Attach the custom upstream headers forwarded on every prefetch request
    /// (Req 1.6).
    pub fn with_headers(mut self, headers: BTreeMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// The current watermark (highest media-sequence number planned), for tests
    /// / diagnostics.
    pub fn watermark(&self) -> Option<u64> {
        *self.watermark.lock().unwrap()
    }

    /// Prefetch up to `count` segments of `playlist` that come after the larger
    /// of the client's `position` and the current watermark, storing each in the
    /// cache (Req 7.1, 7.3, 7.4).
    ///
    /// * On the first call (`position = None`, watermark unset) it prefetches
    ///   the first `count` segments.
    /// * `position = Some(seq)` keeps the prefetch window ahead of the client's
    ///   current segment (Req 7.1); a forward seek past the watermark advances
    ///   the window.
    /// * Re-invoked after a live playlist refresh it fetches only segments past
    ///   the watermark — the newly published ones (Req 7.3).
    ///
    /// Returns the number of segments successfully prefetched this call.
    /// Per-segment fetch failures are skipped (best-effort) so a speculative
    /// miss never breaks playback.
    pub async fn prefetch_ahead(
        &self,
        playlist: &MediaPlaylist,
        position: Option<u64>,
    ) -> usize {
        // Stay ahead of the requested position without re-fetching what we
        // already have: plan after the larger of the position and the
        // watermark.
        let after = match (position, self.watermark()) {
            (Some(p), Some(w)) => Some(p.max(w)),
            (Some(p), None) => Some(p),
            (None, w) => w,
        };

        let plan = plan_upcoming_segments(playlist, &self.base, after, self.count);
        let mut fetched = 0;
        let mut highest = self.watermark();
        for segment in plan {
            // Track the planned watermark even if the fetch fails, so a failed
            // segment is not retried forever on every refresh.
            highest = Some(highest.map_or(segment.seq, |h| h.max(segment.seq)));

            // Skip a segment already cached (e.g. served + cached by the client
            // path) — no re-fetch (Req 7.4).
            if self.cache.contains(segment.url.as_str()).await {
                continue;
            }
            match self.fetch_segment(&segment.url).await {
                Ok(cached) => {
                    self.cache.put(segment.url.as_str(), cached).await;
                    fetched += 1;
                }
                Err(e) => {
                    tracing::debug!(
                        target: "prebuffer",
                        url = %segment.url,
                        error = %e.message,
                        "prefetch of an upcoming segment failed (best-effort, skipping)",
                    );
                }
            }
        }

        *self.watermark.lock().unwrap() = highest;
        fetched
    }

    /// Fetch one segment's full bytes + content type through the egress seam
    /// (Req 51.1), capped at [`MAX_SEGMENT_BYTES`].
    async fn fetch_segment(&self, url: &Url) -> Result<CachedSegment, AppError> {
        let source =
            DirectSource::new(self.client.clone(), url.clone()).with_headers(to_header_map(&self.headers));
        let body = source.open(RangeSpec::Full).await?;

        // A non-2xx upstream is not a cacheable segment.
        if !(200..300).contains(&body.status) {
            return Err(AppError::upstream_unavailable(format!(
                "prefetch of {url} returned HTTP {}",
                body.status
            ))
            .with_upstream_status(body.status));
        }

        let content_type = body.content_type.clone();
        let mut buf = BytesMut::new();
        let mut stream = body.stream;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if buf.len() + chunk.len() > MAX_SEGMENT_BYTES {
                return Err(AppError::payload_too_large(format!(
                    "prefetched segment {url} exceeds {MAX_SEGMENT_BYTES} bytes"
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(CachedSegment::new(Bytes::from(buf), content_type))
    }
}

/// Convert a `name → value` header map into a `reqwest` [`HeaderMap`], skipping
/// any entry whose name or value is not a valid HTTP header (config/extractor
/// supplied, never inbound client headers).
fn to_header_map(headers: &BTreeMap<String, String>) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) else {
            continue;
        };
        map.insert(name, value);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use m3u8_rs::{MediaPlaylist, MediaSegment};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An [`OutboundClient`] with no tunnel under fail-open, so prefetches dial
    /// the in-process wiremock origin directly (mirrors the HLS fetch tests).
    fn outbound() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    /// A media playlist of `n` segments served by `server`, named
    /// `seg{media_sequence+i}.ts`.
    fn playlist_on(server: &MockServer, media_sequence: u64, n: u64, end_list: bool) -> MediaPlaylist {
        let _ = server;
        let segments = (0..n)
            .map(|i| MediaSegment {
                uri: format!("seg{}.ts", media_sequence + i),
                duration: 6.0,
                ..MediaSegment::default()
            })
            .collect();
        MediaPlaylist {
            target_duration: 6,
            media_sequence,
            segments,
            end_list,
            ..MediaPlaylist::default()
        }
    }

    fn base_for(server: &MockServer) -> Url {
        Url::parse(&format!("{}/v/media.m3u8", server.uri())).unwrap()
    }

    /// Mount `n` segment responses `seg{start}.ts..` each returning unique bytes,
    /// counting hits in `hits`.
    async fn mount_segments(server: &MockServer, start: u64, n: u64, hits: Arc<AtomicUsize>) {
        for i in start..start + n {
            let h = hits.clone();
            Mock::given(method("GET"))
                .and(path(format!("/v/seg{i}.ts")))
                .respond_with(move |_req: &wiremock::Request| {
                    h.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(200)
                        .insert_header("Content-Type", "video/mp2t")
                        .set_body_bytes(format!("seg-{i}-bytes").into_bytes())
                })
                .mount(server)
                .await;
        }
    }

    // -- Req 7.1 / 7.4: prefetch up to N upcoming segments into the cache ----

    #[tokio::test]
    async fn prefetches_up_to_count_segments_into_cache() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));
        mount_segments(&server, 0, 10, hits.clone()).await;

        let cache = SegmentCache::new(Duration::from_secs(300));
        let pf = Prefetcher::new(outbound(), cache.clone(), base_for(&server), 3);
        let pl = playlist_on(&server, 0, 10, true);

        let fetched = pf.prefetch_ahead(&pl, None).await;
        assert_eq!(fetched, 3, "prefetch up to the configured count (Req 7.1)");

        // The three segments are now in the cache (Req 7.4).
        for i in 0..3 {
            let url = format!("{}/v/seg{i}.ts", server.uri());
            let cached = cache.get(&url).await.expect("segment cached");
            assert_eq!(cached.body, Bytes::from(format!("seg-{i}-bytes")));
            assert_eq!(cached.content_type.as_deref(), Some("video/mp2t"));
        }
        // Only the prefetched segments were fetched upstream.
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    // -- Req 7.4: an already-cached segment is not re-fetched ----------------

    #[tokio::test]
    async fn does_not_refetch_already_cached_segments() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));
        mount_segments(&server, 0, 5, hits.clone()).await;

        let cache = SegmentCache::new(Duration::from_secs(300));
        // Pre-seed seg0 as if the client already fetched + cached it.
        cache
            .put(
                &format!("{}/v/seg0.ts", server.uri()),
                CachedSegment::new(Bytes::from_static(b"existing"), None),
            )
            .await;

        let pf = Prefetcher::new(outbound(), cache.clone(), base_for(&server), 3);
        let pl = playlist_on(&server, 0, 5, true);
        let fetched = pf.prefetch_ahead(&pl, None).await;

        // seg0 was already cached → only seg1, seg2 fetched.
        assert_eq!(fetched, 2);
        assert_eq!(hits.load(Ordering::SeqCst), 2, "cached segment not re-fetched (Req 7.4)");
        // The pre-seeded value is untouched.
        let seg0 = cache.get(&format!("{}/v/seg0.ts", server.uri())).await.unwrap();
        assert_eq!(seg0.body, Bytes::from_static(b"existing"));
    }

    // -- Req 7.1: prefetch stays ahead of the requested position -------------

    #[tokio::test]
    async fn prefetches_ahead_of_requested_position() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));
        mount_segments(&server, 0, 10, hits.clone()).await;

        let cache = SegmentCache::new(Duration::from_secs(300));
        let pf = Prefetcher::new(outbound(), cache.clone(), base_for(&server), 2);
        let pl = playlist_on(&server, 0, 10, true);

        // Client at segment 4 → prefetch 5, 6.
        let fetched = pf.prefetch_ahead(&pl, Some(4)).await;
        assert_eq!(fetched, 2);
        assert!(cache.contains(&format!("{}/v/seg5.ts", server.uri())).await);
        assert!(cache.contains(&format!("{}/v/seg6.ts", server.uri())).await);
        assert!(!cache.contains(&format!("{}/v/seg4.ts", server.uri())).await);
        assert_eq!(pf.watermark(), Some(6));
    }

    // -- Req 7.3: live refresh keeps prefetching newly published segments ----

    #[tokio::test]
    async fn live_refresh_prefetches_only_new_segments() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));
        mount_segments(&server, 0, 20, hits.clone()).await;

        let cache = SegmentCache::new(Duration::from_secs(300));
        let pf = Prefetcher::new(outbound(), cache.clone(), base_for(&server), 3);

        // First live poll: window [0..5), prefetch 0,1,2.
        let first = playlist_on(&server, 0, 5, false);
        assert_eq!(pf.prefetch_ahead(&first, None).await, 3);
        assert_eq!(pf.watermark(), Some(2));
        let after_first = hits.load(Ordering::SeqCst);
        assert_eq!(after_first, 3);

        // Window advances to [3..8); a refresh prefetches only 3,4,5 (past the
        // watermark) — newly published segments (Req 7.3).
        let second = playlist_on(&server, 3, 5, false);
        let fetched = pf.prefetch_ahead(&second, None).await;
        assert_eq!(fetched, 3);
        assert_eq!(pf.watermark(), Some(5));
        assert!(cache.contains(&format!("{}/v/seg5.ts", server.uri())).await);
        // No segment fetched twice.
        assert_eq!(hits.load(Ordering::SeqCst), 6);
    }

    // -- Best-effort: a failing segment is skipped, others still cached ------

    #[tokio::test]
    async fn failing_segment_is_skipped_best_effort() {
        let server = MockServer::start().await;
        // seg0 OK, seg1 500, seg2 OK.
        Mock::given(method("GET"))
            .and(path("/v/seg0.ts"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"a".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v/seg1.ts"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v/seg2.ts"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"c".to_vec()))
            .mount(&server)
            .await;

        let cache = SegmentCache::new(Duration::from_secs(300));
        let pf = Prefetcher::new(outbound(), cache.clone(), base_for(&server), 3);
        let pl = playlist_on(&server, 0, 3, true);

        let fetched = pf.prefetch_ahead(&pl, None).await;
        assert_eq!(fetched, 2, "the failing segment is skipped, the rest cached");
        assert!(cache.contains(&format!("{}/v/seg0.ts", server.uri())).await);
        assert!(!cache.contains(&format!("{}/v/seg1.ts", server.uri())).await);
        assert!(cache.contains(&format!("{}/v/seg2.ts", server.uri())).await);
        // Watermark still advanced past the failed segment so it is not retried
        // forever.
        assert_eq!(pf.watermark(), Some(2));
    }
}
