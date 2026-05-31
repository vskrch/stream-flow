//! Telegram MTProto chunked download with range (`telegram`) — Req 11.
//!
//! Proxies media stored in Telegram: a configured instance downloads a
//! referenced file over MTProto in fixed-size chunks — fetching them **in
//! parallel up to the configured maximum connection count** (Req 11.2) — and
//! streams the assembled bytes to the client. A `Range` request fetches **only
//! the chunks covering the requested byte range** and returns `206 Partial
//! Content` (Req 11.3). The instance also exposes the *mechanism* to generate a
//! session string from API credentials (Req 11.4), and reports a typed
//! not-configured / not-authorized error when credentials or the session string
//! are missing or invalid (Req 11.5).
//!
//! ## Why this is unit-testable without a live Telegram connection
//!
//! A real MTProto download needs the `grammers-client` runtime and live
//! Telegram servers, neither of which can run in a unit test. So the network
//! interaction is abstracted behind the [`TelegramChunkSource`] trait — "fetch
//! chunk *N*" — and everything that can be decided *locally* is built on top of
//! it and tested with an in-process fake (matching the design's Testing
//! Strategy: "Acestream / Telegram / FFmpeg / SSE / Redis: behind trait seams
//! with in-process fakes"):
//!
//! * **Chunk-range arithmetic** ([`chunk`]) — which chunk indices cover a byte
//!   range and how each chunk is sliced (pure, Property 48).
//! * **Parallelism bounding + range/`206` shaping** ([`TelegramDownloader`]) —
//!   fetches covering chunks through the trait with bounded concurrency and
//!   produces an [`UpstreamBody`](crate::proxy::UpstreamBody) the generic proxy
//!   core renders as `200`/`206`/`416`.
//! * **Credential validation + session generation** ([`session`]) — the
//!   not-configured / not-authorized error paths (Req 11.5) and the
//!   session-string generation orchestration (Req 11.4).
//!
//! ## The grammers backend (gated)
//!
//! The production [`TelegramChunkSource`] implementation wraps a
//! `grammers-client` MTProto session (`upload.getFile` chunked reads) and a
//! [`session::SessionAuthenticator`] performing the interactive login.
//! `grammers-client` is a heavy, optional dependency, so that backend is kept
//! behind a `telegram` cfg/feature and is **not** compiled here; this module —
//! the pure logic and the seam — is always compiled and always tested. Wiring
//! the backend (and the `/proxy/telegram/*` routes) is a later integration
//! step; nothing in this module imports grammers.

pub mod chunk;
pub mod session;

use std::sync::Arc;

use actix_web::HttpResponse;
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::{self, Stream, StreamExt};

use crate::config::PrebufferConfig;
use crate::errors::AppError;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::{ContentRange, UpstreamBody, UpstreamSource};
use crate::proxy::{self};

pub use chunk::{chunks_covering, ChunkCoverage, DEFAULT_CHUNK_SIZE};
pub use session::{
    generate_session_string, ApiCredentials, SessionAuthenticator, TelegramCredentials,
};

/// The MTProto chunk-fetching seam (Req 11.1, 11.2).
///
/// Abstracts "download chunk *N* of the referenced media" so the
/// parallelism-bounding, range-coverage, and `206`-shaping logic can be unit
/// tested with an in-process fake — no live Telegram connection. The production
/// implementation (gated, not compiled here) issues MTProto `upload.getFile`
/// reads at `index * chunk_size`.
///
/// Implementations must be cheap to `clone`-share (`Arc`-friendly): the
/// downloader clones an `Arc<dyn TelegramChunkSource>` into each concurrent
/// chunk fetch.
#[async_trait]
pub trait TelegramChunkSource: Send + Sync {
    /// Total size of the referenced media, in bytes (drives `Content-Length` /
    /// `videoSize` / the `416` decision — Req 11.3).
    fn total_size(&self) -> u64;

    /// The fixed download chunk size, in bytes (always ≥ 1). Chunk `index`
    /// covers absolute bytes `[index * chunk_size, (index+1) * chunk_size)`,
    /// truncated by [`total_size`](TelegramChunkSource::total_size) for the
    /// final chunk.
    fn chunk_size(&self) -> u64 {
        DEFAULT_CHUNK_SIZE
    }

    /// The media content type, when known.
    fn content_type(&self) -> Option<&str> {
        None
    }

    /// Fetch chunk `index`, returning its raw bytes (Req 11.1). A transport /
    /// MTProto failure surfaces as a typed [`AppError`].
    async fn fetch_chunk(&self, index: u64) -> Result<Bytes, AppError>;
}

/// Downloads Telegram media through a [`TelegramChunkSource`], fetching chunks
/// in parallel up to a bounded connection count and assembling them in order
/// (Req 11.1, 11.2, 11.3).
#[derive(Clone)]
pub struct TelegramDownloader {
    source: Arc<dyn TelegramChunkSource>,
    /// The maximum number of chunk fetches in flight at once (Req 11.2).
    max_connections: usize,
}

impl TelegramDownloader {
    /// Build a downloader over `source`, capping concurrent chunk fetches at
    /// `max_connections` (floored at 1 so a misconfigured `0` still makes
    /// progress — Req 11.2).
    pub fn new(source: Arc<dyn TelegramChunkSource>, max_connections: usize) -> Self {
        Self {
            source,
            max_connections: max_connections.max(1),
        }
    }

    /// The total size of the referenced media (Req 11.3).
    pub fn total_size(&self) -> u64 {
        self.source.total_size()
    }

    /// The configured maximum concurrent chunk fetches (Req 11.2).
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Open the referenced media for the requested [`RangeSpec`], producing an
    /// [`UpstreamBody`] whose stream fetches exactly the covering chunks in
    /// parallel (≤ `max_connections`) and slices them to the requested bytes
    /// (Req 11.1, 11.2, 11.3).
    ///
    /// * [`RangeSpec::Full`] → status `200`, `Content-Length` = total size.
    /// * A satisfiable partial range → status `206`, `Content-Range`
    ///   `bytes start-end/total`, `Content-Length` = range length (Req 11.3).
    /// * An unsatisfiable range → [`AppError::range_not_satisfiable`] (`416`).
    pub fn open_range(&self, range: RangeSpec) -> Result<UpstreamBody, AppError> {
        let total = self.source.total_size();
        let chunk_size = self.source.chunk_size().max(1);
        let content_type = self.source.content_type().map(str::to_string);

        // Resolve the range against the known size → 200 / 206 / 416 (Req 11.3).
        let resolved = range.resolve(total)?; // Err(Unsatisfiable) → 416.

        let (status, content_length, content_range, cov) = match resolved {
            // Full body → 200 over every chunk.
            None => {
                let end = total.saturating_sub(1);
                let cov = chunks_covering(total, chunk_size, 0, end);
                (200u16, total, None, cov)
            }
            // Partial body → 206 over only the covering chunks (Req 11.3).
            Some(r) => {
                let cov = chunks_covering(total, chunk_size, r.start, r.end);
                let cr = ContentRange {
                    start: r.start,
                    end: r.end,
                    total: Some(total),
                };
                (206u16, r.length(), Some(cr), cov)
            }
        };

        let stream = chunk_stream(self.source.clone(), cov, self.max_connections);

        Ok(UpstreamBody {
            status,
            content_length: Some(content_length),
            content_range,
            content_type,
            // The total size is always known for Telegram media, so range
            // support is always advertised (Req 11.3).
            accept_ranges: true,
            stream: Box::pin(stream),
        })
    }

    /// Serve the referenced media as an actix [`HttpResponse`] through the
    /// generic ranged proxy core (Req 11.1, 11.3).
    ///
    /// Reuses [`proxy::serve`] so the `200`/`206`/`Content-Range`/
    /// `Accept-Ranges` shaping and the bounded-buffer relay are identical to
    /// every other byte-serving surface; a `HEAD` yields the same headers with
    /// no body.
    pub async fn serve(
        &self,
        range: RangeSpec,
        is_head: bool,
        prebuffer: &PrebufferConfig,
    ) -> Result<HttpResponse, AppError> {
        let source: Arc<dyn UpstreamSource> = Arc::new(TelegramSource::new(self.clone()));
        proxy::serve(source, range, is_head, prebuffer).await
    }
}

/// Adapts a [`TelegramDownloader`] to the [`UpstreamSource`] trait so it plugs
/// into the generic streaming core ([`proxy::serve`]).
///
/// Telegram media is **not** renewable in the link-renewal sense (there is no
/// expiring debrid link to regenerate — the reference is stable), so it
/// inherits the default [`UpstreamSource::renew`] returning the non-renewable
/// signal.
pub struct TelegramSource {
    downloader: TelegramDownloader,
    content_type: Option<String>,
}

impl TelegramSource {
    /// Wrap a [`TelegramDownloader`] as an [`UpstreamSource`].
    pub fn new(downloader: TelegramDownloader) -> Self {
        let content_type = downloader.source.content_type().map(str::to_string);
        Self {
            downloader,
            content_type,
        }
    }
}

#[async_trait]
impl UpstreamSource for TelegramSource {
    fn total_size(&self) -> Option<u64> {
        Some(self.downloader.total_size())
    }

    fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    fn accept_ranges(&self) -> bool {
        true
    }

    async fn open(&self, range: RangeSpec) -> Result<UpstreamBody, AppError> {
        self.downloader.open_range(range)
    }
}

/// Build the ordered, bounded-parallelism byte stream that fetches the chunks
/// in `cov` through `source` and slices each to the requested range (Req 11.2,
/// 11.3).
///
/// [`StreamExt::buffered`] runs up to `max_connections` chunk fetches
/// concurrently while **preserving input order**, so the assembled bytes are
/// emitted in offset order regardless of which fetch completes first — and at
/// most `max_connections` fetches are ever in flight (Req 11.2). The returned
/// stream is `'static + Send` (each future owns an `Arc` clone of `source` and
/// a `Copy` of `cov`), so it can back an [`UpstreamBody`].
fn chunk_stream(
    source: Arc<dyn TelegramChunkSource>,
    cov: ChunkCoverage,
    max_connections: usize,
) -> impl Stream<Item = Result<Bytes, AppError>> + Send + 'static {
    let indices: Vec<u64> = cov.indices().collect();
    stream::iter(indices)
        .map(move |idx| {
            let source = source.clone();
            async move {
                let bytes = source.fetch_chunk(idx).await?;
                // Slice the fetched chunk to the portion that lies within the
                // requested range (the first/last covering chunks are trimmed —
                // Req 11.3). Bounded by the *actual* fetched length so a short
                // final chunk is handled safely.
                let (local_start, local_len) = cov.slice_within(idx, bytes.len());
                if local_len == 0 {
                    Ok(Bytes::new())
                } else {
                    Ok(bytes.slice(local_start..local_start + local_len))
                }
            }
        })
        .buffered(max_connections.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use actix_web::body::to_bytes;
    use actix_web::http::{header, StatusCode};

    /// An in-process [`TelegramChunkSource`] over an in-memory byte vector.
    ///
    /// It records which chunk indices were fetched and tracks the peak number
    /// of concurrent `fetch_chunk` calls, so the parallelism bound (Req 11.2)
    /// and the covering-chunks-only behaviour (Req 11.3) are observable without
    /// a live Telegram connection.
    struct FakeChunkSource {
        data: Vec<u8>,
        chunk_size: u64,
        content_type: Option<String>,
        per_chunk_delay: Duration,
        fetched: Mutex<Vec<u64>>,
        in_flight: AtomicUsize,
        peak_in_flight: AtomicUsize,
    }

    impl FakeChunkSource {
        fn new(data: Vec<u8>, chunk_size: u64) -> Self {
            Self {
                data,
                chunk_size,
                content_type: Some("video/mp4".to_string()),
                per_chunk_delay: Duration::from_millis(0),
                fetched: Mutex::new(Vec::new()),
                in_flight: AtomicUsize::new(0),
                peak_in_flight: AtomicUsize::new(0),
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.per_chunk_delay = delay;
            self
        }

        fn fetched_indices(&self) -> Vec<u64> {
            let mut v = self.fetched.lock().unwrap().clone();
            v.sort_unstable();
            v
        }

        fn peak_concurrency(&self) -> usize {
            self.peak_in_flight.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl TelegramChunkSource for FakeChunkSource {
        fn total_size(&self) -> u64 {
            self.data.len() as u64
        }

        fn chunk_size(&self) -> u64 {
            self.chunk_size
        }

        fn content_type(&self) -> Option<&str> {
            self.content_type.as_deref()
        }

        async fn fetch_chunk(&self, index: u64) -> Result<Bytes, AppError> {
            // Track concurrency: bump in-flight, record the peak, then release.
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak_in_flight.fetch_max(now, Ordering::SeqCst);
            if !self.per_chunk_delay.is_zero() {
                tokio::time::sleep(self.per_chunk_delay).await;
            }
            self.fetched.lock().unwrap().push(index);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);

            let start = (index * self.chunk_size) as usize;
            if start >= self.data.len() {
                return Ok(Bytes::new());
            }
            let end = (start + self.chunk_size as usize).min(self.data.len());
            Ok(Bytes::copy_from_slice(&self.data[start..end]))
        }
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    async fn collect_body(mut body: UpstreamBody) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = body.stream.next().await {
            out.extend_from_slice(&chunk.expect("chunk must not error"));
        }
        out
    }

    // -- Full download streams the assembled media (Req 11.1) ---------------

    #[tokio::test]
    async fn full_download_streams_the_whole_file_in_order() {
        let data = payload(5000);
        let source = Arc::new(FakeChunkSource::new(data.clone(), 1000));
        let downloader = TelegramDownloader::new(source.clone(), 4);

        let body = downloader.open_range(RangeSpec::Full).expect("open full");
        assert_eq!(body.status, 200);
        assert_eq!(body.content_length, Some(5000));
        assert!(body.content_range.is_none());
        assert_eq!(body.content_type.as_deref(), Some("video/mp4"));
        assert!(body.accept_ranges);

        let out = collect_body(body).await;
        assert_eq!(out, data, "assembled bytes must equal the source, in order");

        // Every chunk (0..=4) was fetched for the full body.
        assert_eq!(source.fetched_indices(), vec![0, 1, 2, 3, 4]);
    }

    // -- Chunks fetched in parallel up to max_connections (Req 11.2) --------

    #[tokio::test]
    async fn parallel_fetch_is_bounded_by_max_connections() {
        // 12 chunks, each taking 30ms; cap concurrency at 3.
        let data = payload(12_000);
        let source = Arc::new(
            FakeChunkSource::new(data.clone(), 1000).with_delay(Duration::from_millis(30)),
        );
        let downloader = TelegramDownloader::new(source.clone(), 3);

        let body = downloader.open_range(RangeSpec::Full).expect("open full");
        let out = collect_body(body).await;
        assert_eq!(out, data);

        let peak = source.peak_concurrency();
        // Never exceeds the configured maximum (Req 11.2)...
        assert!(peak <= 3, "peak concurrency {peak} exceeded max_connections 3");
        // ...and genuinely ran in parallel (more than one at once).
        assert!(peak >= 2, "expected parallel fetches, peak concurrency was {peak}");
    }

    #[tokio::test]
    async fn max_connections_one_serializes_fetches() {
        let data = payload(6_000);
        let source = Arc::new(
            FakeChunkSource::new(data.clone(), 1000).with_delay(Duration::from_millis(10)),
        );
        let downloader = TelegramDownloader::new(source.clone(), 1);

        let out = collect_body(downloader.open_range(RangeSpec::Full).expect("open")).await;
        assert_eq!(out, data);
        assert_eq!(
            source.peak_concurrency(),
            1,
            "max_connections=1 must serialize chunk fetches",
        );
    }

    #[tokio::test]
    async fn zero_max_connections_is_floored_to_one() {
        let data = payload(3_000);
        let source = Arc::new(FakeChunkSource::new(data.clone(), 1000));
        let downloader = TelegramDownloader::new(source.clone(), 0);
        assert_eq!(downloader.max_connections(), 1);
        let out = collect_body(downloader.open_range(RangeSpec::Full).expect("open")).await;
        assert_eq!(out, data);
    }

    // -- Range fetches only the covering chunks → 206 (Req 11.3) ------------

    #[tokio::test]
    async fn range_request_fetches_only_covering_chunks_and_returns_206() {
        let data = payload(10_000);
        let source = Arc::new(FakeChunkSource::new(data.clone(), 1000));
        let downloader = TelegramDownloader::new(source.clone(), 4);

        // bytes 1500-3500 → chunks 1,2,3 only.
        let body = downloader
            .open_range(RangeSpec::Inclusive(1500, 3500))
            .expect("open range");

        assert_eq!(body.status, 206);
        assert_eq!(body.content_length, Some(2001));
        assert_eq!(
            body.content_range,
            Some(ContentRange { start: 1500, end: 3500, total: Some(10_000) })
        );

        let out = collect_body(body).await;
        assert_eq!(out, data[1500..=3500], "must return exactly the requested bytes");

        // Only the covering chunks were fetched — not chunks 0, 4..9 (Req 11.3).
        assert_eq!(source.fetched_indices(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn suffix_range_fetches_only_the_trailing_chunks() {
        let data = payload(10_000);
        let source = Arc::new(FakeChunkSource::new(data.clone(), 1000));
        let downloader = TelegramDownloader::new(source.clone(), 4);

        // bytes=-2500 → last 2500 bytes [7500,9999] → chunks 7,8,9.
        let body = downloader.open_range(RangeSpec::Suffix(2500)).expect("open suffix");
        assert_eq!(body.status, 206);
        assert_eq!(
            body.content_range,
            Some(ContentRange { start: 7500, end: 9999, total: Some(10_000) })
        );
        let out = collect_body(body).await;
        assert_eq!(out, data[7500..=9999]);
        assert_eq!(source.fetched_indices(), vec![7, 8, 9]);
    }

    #[tokio::test]
    async fn open_ended_range_fetches_from_offset_chunk_to_end() {
        let data = payload(4_096);
        let source = Arc::new(FakeChunkSource::new(data.clone(), 1024));
        let downloader = TelegramDownloader::new(source.clone(), 4);

        // bytes=2048- → [2048,4095] → chunks 2,3.
        let body = downloader.open_range(RangeSpec::FromOffset(2048)).expect("open");
        assert_eq!(body.status, 206);
        assert_eq!(
            body.content_range,
            Some(ContentRange { start: 2048, end: 4095, total: Some(4096) })
        );
        let out = collect_body(body).await;
        assert_eq!(out, data[2048..=4095]);
        assert_eq!(source.fetched_indices(), vec![2, 3]);
    }

    // -- Unsatisfiable range → 416 (Req 11.3 / 5.5) -------------------------

    #[tokio::test]
    async fn range_past_end_is_416() {
        let data = payload(1_000);
        let source = Arc::new(FakeChunkSource::new(data, 256));
        let downloader = TelegramDownloader::new(source.clone(), 4);

        let err = downloader
            .open_range(RangeSpec::FromOffset(1_000))
            .expect_err("start == size is unsatisfiable");
        assert_eq!(err.category, ErrorCategory::RangeNotSatisfiable);
        // No chunk should have been fetched for an unsatisfiable range.
        assert!(source.fetched_indices().is_empty());
    }

    // -- serve(): end-to-end 206 response shaping (Req 11.3) ----------------

    #[tokio::test]
    async fn serve_range_renders_206_with_content_range_header() {
        let data = payload(10_000);
        let source = Arc::new(FakeChunkSource::new(data.clone(), 1000));
        let downloader = TelegramDownloader::new(source, 4);

        let resp = downloader
            .serve(RangeSpec::Inclusive(1500, 3500), false, &PrebufferConfig::default())
            .await
            .expect("serve ok");

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers().get(header::CONTENT_RANGE).unwrap().to_str().unwrap(),
            "bytes 1500-3500/10000",
        );
        assert_eq!(
            resp.headers().get(header::ACCEPT_RANGES).unwrap().to_str().unwrap(),
            "bytes",
        );
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&bytes[..], &data[1500..=3500]);
    }

    #[tokio::test]
    async fn serve_full_renders_200_with_content_length() {
        let data = payload(2_048);
        let source = Arc::new(FakeChunkSource::new(data.clone(), 1024));
        let downloader = TelegramDownloader::new(source, 4);

        let resp = downloader
            .serve(RangeSpec::Full, false, &PrebufferConfig::default())
            .await
            .expect("serve ok");

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_LENGTH).unwrap().to_str().unwrap(),
            "2048",
        );
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&bytes[..], &data[..]);
    }

    #[tokio::test]
    async fn serve_head_has_headers_and_no_body() {
        let data = payload(2_048);
        let source = Arc::new(FakeChunkSource::new(data.clone(), 1024));
        let downloader = TelegramDownloader::new(source.clone(), 4);

        let resp = downloader
            .serve(RangeSpec::Full, true, &PrebufferConfig::default())
            .await
            .expect("serve head ok");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_LENGTH).unwrap().to_str().unwrap(),
            "2048",
        );
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert!(bytes.is_empty(), "HEAD response must carry no body");
        // A HEAD must not fetch any chunk.
        assert!(source.fetched_indices().is_empty());
    }

    // -- A mid-download chunk failure surfaces as a typed error -------------

    #[tokio::test]
    async fn chunk_fetch_failure_surfaces_as_typed_error() {
        struct FailingSource;
        #[async_trait]
        impl TelegramChunkSource for FailingSource {
            fn total_size(&self) -> u64 {
                10_000
            }
            fn chunk_size(&self) -> u64 {
                1000
            }
            async fn fetch_chunk(&self, _index: u64) -> Result<Bytes, AppError> {
                Err(AppError::upstream_unavailable("MTProto read failed"))
            }
        }

        let downloader = TelegramDownloader::new(Arc::new(FailingSource), 4);
        let body = downloader.open_range(RangeSpec::Full).expect("open ok");

        // The error surfaces while draining the body stream (not at open time).
        let mut body = body;
        let mut saw_error = false;
        while let Some(item) = body.stream.next().await {
            if let Err(e) = item {
                assert_eq!(e.category, ErrorCategory::UpstreamUnavailable);
                saw_error = true;
                break;
            }
        }
        assert!(saw_error, "a failing chunk fetch must surface as a typed error");
    }
}
