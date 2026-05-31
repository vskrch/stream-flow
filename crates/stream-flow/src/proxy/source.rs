//! `UpstreamSource` trait + `DirectSource` (`proxy::source`) — Req 5.1, 5.6,
//! 37.10, 51.1, 51.2, 51.3.
//!
//! The streaming core is built around an [`UpstreamSource`] abstraction: a
//! thing that can produce a byte stream for a given byte offset, *repeatedly*,
//! so the [`ResilientStream`](crate::proxy) state machine (task 15) can re-open
//! the upstream to resume after a drop (Req 37.5) or after a link renewal
//! (Req 37.6) without the client ever noticing (design: Components → Streaming
//! Core). This module lands the trait, its byte-stream payload types
//! ([`UpstreamBody`] / [`ContentRange`]), and the first implementation,
//! [`DirectSource`].
//!
//! ## The single-outbound-seam invariant (Req 51.1–51.3)
//!
//! Every [`UpstreamSource`] obtains its HTTP client **exclusively** from
//! [`egress::OutboundClient`](crate::egress::OutboundClient) — never by building
//! its own `reqwest`/`wreq` client. That is the load-bearing isolation
//! guarantee: routing through the seam means every upstream request is tunnelled
//! through the configured Egress_Tunnel (so debrid/media hosts observe only the
//! Egress_IP — Req 51.1), is gated by the fail-closed policy before any dial
//! (Req 51.8), and starts from a request that carries **none** of the
//! client-identifying headers (Req 51.2, 51.3). [`DirectSource`] holds an
//! `Arc<OutboundClient>` and threads every probe/open through it; it has no
//! other way to reach the network.
//!
//! ## [`DirectSource`] (Req 5.1, 5.6, 37.10)
//!
//! A plain-URL source: an extractor result, an HLS segment, or a generic
//! forward-proxy target. It is **not** renewable — there is no store to
//! re-resolve the URL — so it inherits the default [`UpstreamSource::renew`]
//! that returns the non-renewable signal ([`AppError::not_renewable`],
//! Req 37.6). Behaviour:
//!
//! * [`open`](DirectSource::open) issues a ranged `GET` for the requested
//!   [`RangeSpec`], following any redirect chain **server-side** so the client
//!   sees one stable connection to the final origin (Req 37.10); the response
//!   becomes an [`UpstreamBody`] whose body is a zero-copy
//!   `Stream<Item = Result<Bytes, AppError>>` (Req 5.1).
//! * Custom upstream headers supplied at construction are forwarded on every
//!   derived request (Req 5.6).
//! * [`connect`](DirectSource::connect) probes the upstream once to surface
//!   [`total_size`](DirectSource::total_size) /
//!   [`content_type`](DirectSource::content_type) /
//!   [`accept_ranges`](DirectSource::accept_ranges) (Req 37.8) so the proxy
//!   core (task 14) can compute the `200`/`206`/`416` response metadata before
//!   opening the body.

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use reqwest::header::{
    HeaderMap, ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE,
};
use reqwest::Method;
use url::Url;

use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::proxy::range::RangeSpec;

/// The zero-copy byte body of one upstream response (design: Data Models →
/// Streaming Core Types).
///
/// Produced by [`UpstreamSource::open`]. The metadata fields mirror the
/// upstream's response so the proxy core can build the client-facing headers,
/// and [`stream`](UpstreamBody::stream) is the bounded, zero-copy body the
/// adaptive/jitter buffer drains (Req 5.7, 35.1) — the full body is never
/// buffered in memory here.
pub struct UpstreamBody {
    /// The upstream HTTP status (`200`/`206`/…), preserved so the core can
    /// relay an upstream `206`/`Content-Range` verbatim and surface upstream
    /// errors with their status (Req 1.7, 5.2).
    pub status: u16,
    /// The upstream `Content-Length`, when declared (Req 5.4).
    pub content_length: Option<u64>,
    /// The parsed upstream `Content-Range`, present on a `206` (Req 5.2).
    pub content_range: Option<ContentRange>,
    /// The upstream `Content-Type`, when declared (Req 37.13).
    pub content_type: Option<String>,
    /// Whether the upstream advertised range support (`Accept-Ranges: bytes`)
    /// or answered with a `206` (Req 5.3).
    pub accept_ranges: bool,
    /// The zero-copy body stream. Each item is a chunk of bytes or a typed
    /// error (a mid-stream upstream drop surfaces here as an `AppError`, which
    /// the core turns into a terminate-and-log / resilient-resume — Req 5.8,
    /// 37.5).
    pub stream: Pin<Box<dyn Stream<Item = Result<Bytes, AppError>> + Send>>,
}

impl std::fmt::Debug for UpstreamBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamBody")
            .field("status", &self.status)
            .field("content_length", &self.content_length)
            .field("content_range", &self.content_range)
            .field("content_type", &self.content_type)
            .field("accept_ranges", &self.accept_ranges)
            .field("stream", &"<byte stream>")
            .finish()
    }
}

impl UpstreamBody {
    /// Build an [`UpstreamBody`] from a `reqwest` response, capturing the
    /// header-derived metadata before consuming the response into its
    /// zero-copy byte stream (Req 5.1, 5.2, 5.4).
    pub(crate) fn from_response(resp: reqwest::Response) -> Self {
        let status = resp.status().as_u16();
        let headers = resp.headers();

        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let content_range = headers
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(ContentRange::parse);
        // Prefer the body length reqwest derived; fall back to a manual header
        // parse so a `Content-Range`-only response still reports a length.
        let content_length = resp.content_length().or_else(|| {
            headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
        });
        let accept_ranges = status == 206
            || headers
                .get(ACCEPT_RANGES)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("bytes")));

        // Consume the response into a zero-copy chunk stream; a transport-level
        // error mid-body surfaces as a typed `AppError` item (Req 5.8).
        let stream = resp.bytes_stream().map(|chunk| {
            chunk.map_err(|e| {
                AppError::upstream_unavailable(format!("upstream stream interrupted: {e}"))
            })
        });

        Self {
            status,
            content_length,
            content_range,
            content_type,
            accept_ranges,
            stream: Box::pin(stream),
        }
    }
}

/// A parsed `Content-Range: bytes start-end/total` value (design: Data Models →
/// Streaming Core Types). `total` is `None` for the `bytes start-end/*`
/// (unknown-total) form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    /// First byte offset (inclusive).
    pub start: u64,
    /// Last byte offset (inclusive).
    pub end: u64,
    /// The total resource size, or `None` for the `*` (unknown) form.
    pub total: Option<u64>,
}

impl ContentRange {
    /// Parse a `Content-Range` header value of the form
    /// `bytes start-end/total` or `bytes start-end/*` (Req 5.2).
    ///
    /// Returns `None` for any value that is not a well-formed single
    /// `bytes`-unit range (e.g. an unsatisfiable `bytes */total`, a non-`bytes`
    /// unit, or non-numeric positions), so a malformed upstream header is
    /// simply treated as "no parseable content range" rather than a panic.
    pub fn parse(value: &str) -> Option<ContentRange> {
        let rest = value.trim();
        let rest = rest
            .strip_prefix("bytes")
            .or_else(|| rest.strip_prefix("BYTES"))?
            .trim_start();
        let (range_part, total_part) = rest.split_once('/')?;
        let (start_str, end_str) = range_part.split_once('-')?;
        let start = start_str.trim().parse::<u64>().ok()?;
        let end = end_str.trim().parse::<u64>().ok()?;
        if end < start {
            return None;
        }
        let total = match total_part.trim() {
            "*" => None,
            s => Some(s.parse::<u64>().ok()?),
        };
        Some(ContentRange { start, end, total })
    }
}

/// Something that can produce a byte stream for a given byte offset,
/// repeatedly (design: Components → Streaming Core).
///
/// The metadata accessors describe the resource as a whole and drive the
/// `Content-Length` / `videoSize` / `416` computation in the proxy core
/// (Req 37.8, 37.12); [`open`](UpstreamSource::open) produces the body for one
/// (possibly ranged) request, re-issuable for resilient resume (Req 37.5) and
/// seek (Req 37.4); [`renew`](UpstreamSource::renew) re-resolves the underlying
/// URL and defaults to the non-renewable signal (Req 37.6).
#[async_trait]
pub trait UpstreamSource: Send + Sync {
    /// Total size if known — drives `Content-Length` / `videoSize` / the `416`
    /// logic (Req 37.8, 37.12). `None` when the upstream never declared a size.
    fn total_size(&self) -> Option<u64>;

    /// The resource `Content-Type`, when known (Req 37.13).
    fn content_type(&self) -> Option<&str>;

    /// Whether range requests are supported for this source (Req 5.3).
    fn accept_ranges(&self) -> bool;

    /// Open the upstream for the requested [`RangeSpec`] (Req 5.1, 5.2).
    ///
    /// Implementations follow redirects server-side (Req 37.10), apply
    /// transport routing/forwarding (Req 13), and obtain their HTTP client from
    /// [`egress::OutboundClient`](crate::egress::OutboundClient) so the request
    /// is tunnelled and all client-identifying headers are stripped
    /// (Req 51.1–51.3).
    async fn open(&self, range: RangeSpec) -> Result<UpstreamBody, AppError>;

    /// Re-resolve the underlying URL (e.g. regenerate an expired debrid link).
    ///
    /// Defaults to [`AppError::not_renewable`] — a plain source has no way to
    /// re-resolve its URL; debrid-backed sources override this to regenerate
    /// the link (Req 37.6).
    async fn renew(&self) -> Result<(), AppError> {
        Err(AppError::not_renewable())
    }
}

/// A plain-URL [`UpstreamSource`]: an extractor result, an HLS segment, or a
/// generic forward-proxy target (design: Components → Streaming Core).
///
/// Holds an [`OutboundClient`](crate::egress::OutboundClient) and reaches the
/// network **only** through it (Req 51.1–51.3). It is not renewable — there is
/// no store to re-resolve the URL — so it inherits the default
/// [`UpstreamSource::renew`] that returns [`AppError::not_renewable`]
/// (Req 37.6).
pub struct DirectSource {
    /// The single outbound seam — the only path to the network (Req 51.1).
    client: Arc<OutboundClient>,
    /// The (post-redirect-resolution) upstream URL to fetch.
    url: Url,
    /// Custom upstream request headers forwarded on every derived request
    /// (Req 5.6). Config/extractor-supplied (never inbound client headers), so
    /// they carry no client IP.
    headers: HeaderMap,
    /// Probed total size (Req 37.8), `None` until/unless
    /// [`connect`](DirectSource::connect) discovered it.
    total_size: Option<u64>,
    /// Probed content type (Req 37.13).
    content_type: Option<String>,
    /// Whether the upstream advertised range support (Req 5.3).
    accept_ranges: bool,
}

impl std::fmt::Debug for DirectSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectSource")
            .field("url", &self.url.as_str())
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("total_size", &self.total_size)
            .field("content_type", &self.content_type)
            .field("accept_ranges", &self.accept_ranges)
            .finish()
    }
}

impl DirectSource {
    /// Build a [`DirectSource`] for `url` without probing — the metadata
    /// accessors report "unknown" until a later [`open`](DirectSource::open)
    /// (or a [`connect`](DirectSource::connect)-built instance) supplies them.
    pub fn new(client: Arc<OutboundClient>, url: Url) -> Self {
        Self {
            client,
            url,
            headers: HeaderMap::new(),
            total_size: None,
            content_type: None,
            accept_ranges: false,
        }
    }

    /// Attach the custom upstream headers forwarded on every derived request
    /// (Req 5.6).
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Build a [`DirectSource`] and probe the upstream once to surface
    /// `total_size`/`content_type`/`accept_ranges` (Req 37.8, 37.13, 5.3).
    ///
    /// The probe is a `GET` through the [`OutboundClient`] seam (Req 51.1) that
    /// follows redirects server-side (Req 37.10) and reads only the response
    /// headers — the body is dropped — so the proxy core can compute the
    /// `200`/`206`/`416` metadata before opening the body for real. The size is
    /// taken from a `Content-Range` total when present, else the
    /// `Content-Length`.
    pub async fn connect(
        client: Arc<OutboundClient>,
        url: Url,
        headers: HeaderMap,
    ) -> Result<Self, AppError> {
        let mut builder = client.upstream(Method::GET, &url)?;
        if !headers.is_empty() {
            builder = builder.headers(headers.clone());
        }
        let resp = builder.send().await.map_err(|e| map_send_error(&url, e))?;

        let resp_headers = resp.headers();
        let content_type = resp_headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let content_range = resp_headers
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(ContentRange::parse);
        let accept_ranges_hdr = resp_headers
            .get(ACCEPT_RANGES)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("bytes")));
        let status = resp.status().as_u16();
        let content_length = resp.content_length();
        // Drop the response (and its body) — only the headers were needed.
        drop(resp);

        let total_size = content_range.and_then(|cr| cr.total).or(content_length);
        let accept_ranges = accept_ranges_hdr || status == 206 || content_range.is_some();

        Ok(Self {
            client,
            url,
            headers,
            total_size,
            content_type,
            accept_ranges,
        })
    }

    /// The upstream URL this source fetches.
    pub fn url(&self) -> &Url {
        &self.url
    }
}

#[async_trait]
impl UpstreamSource for DirectSource {
    fn total_size(&self) -> Option<u64> {
        self.total_size
    }

    fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    fn accept_ranges(&self) -> bool {
        self.accept_ranges
    }

    async fn open(&self, range: RangeSpec) -> Result<UpstreamBody, AppError> {
        // The client comes ONLY from the OutboundClient seam: this both applies
        // the fail-closed egress gate before any dial (Req 51.8) and starts
        // from a request carrying no client-identifying headers (Req 51.2,
        // 51.3). Redirects are followed server-side by the seam's client
        // (Req 37.10).
        let mut builder = self.client.upstream(Method::GET, &self.url)?;
        // Forward the configured custom upstream headers (Req 5.6).
        if !self.headers.is_empty() {
            builder = builder.headers(self.headers.clone());
        }
        // Translate the requested range into an upstream `Range` header
        // (`Full` forwards no header → full body, Req 5.1).
        if let Some(value) = range_header_value(range) {
            builder = builder.header(RANGE, value);
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| map_send_error(&self.url, e))?;
        Ok(UpstreamBody::from_response(resp))
    }
}

/// Translate a [`RangeSpec`] into the `Range` header value to forward upstream,
/// or `None` for [`RangeSpec::Full`] (no header → full body, Req 5.1).
fn range_header_value(range: RangeSpec) -> Option<String> {
    match range {
        RangeSpec::Full => None,
        RangeSpec::FromOffset(start) => Some(format!("bytes={start}-")),
        RangeSpec::Inclusive(start, end) => Some(format!("bytes={start}-{end}")),
        RangeSpec::Suffix(n) => Some(format!("bytes=-{n}")),
    }
}

/// Map a `reqwest` send error onto the canonical taxonomy: a connect/timeout/
/// reset against an upstream is an `UpstreamUnavailable` (`503`, Req 5.8,
/// 35.4), carrying the upstream status when the error surfaced one.
fn map_send_error(url: &Url, err: reqwest::Error) -> AppError {
    let host = url.host_str().unwrap_or("<unknown>");
    let app = AppError::upstream_unavailable(format!("upstream request to {host} failed: {err}"));
    match err.status() {
        Some(status) => app.with_upstream_status(status.as_u16()),
        None => app,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::egress::CLIENT_IDENTIFYING_HEADERS;
    use crate::errors::ErrorCategory;
    use futures::StreamExt;
    use reqwest::header::{HeaderName, HeaderValue};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build an [`OutboundClient`] with no tunnel configured under `policy`.
    ///
    /// * `FailOpen` → the egress decision is "dial untunnelled (with a
    ///   warning)", so the source dials the in-process `wiremock` origin
    ///   directly — exercising the real HTTP open/connect path with no network
    ///   dependency.
    /// * `FailClosed` → the egress decision is "refuse with no dial", used to
    ///   prove the source reaches the network *only* through the gated seam.
    fn outbound(policy: EgressPolicy) -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy,
            ..EgressConfig::default()
        };
        // Disabled mode never consults the reflector; supply a mock anyway.
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid url")
    }

    /// Drain an [`UpstreamBody`] stream into a single buffer.
    async fn collect_body(mut body: UpstreamBody) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = body.stream.next().await {
            out.extend_from_slice(&chunk.expect("chunk must not error"));
        }
        out
    }

    // -- RangeSpec → upstream `Range` header (Req 5.2, 37.15, 37.16) --------

    #[test]
    fn range_header_value_translates_every_spec() {
        assert_eq!(range_header_value(RangeSpec::Full), None);
        assert_eq!(
            range_header_value(RangeSpec::FromOffset(100)),
            Some("bytes=100-".to_string())
        );
        assert_eq!(
            range_header_value(RangeSpec::Inclusive(100, 199)),
            Some("bytes=100-199".to_string())
        );
        assert_eq!(
            range_header_value(RangeSpec::Suffix(500)),
            Some("bytes=-500".to_string())
        );
    }

    // -- ContentRange parsing (Req 5.2) -------------------------------------

    #[test]
    fn content_range_parses_known_total() {
        assert_eq!(
            ContentRange::parse("bytes 100-199/1000"),
            Some(ContentRange {
                start: 100,
                end: 199,
                total: Some(1000)
            })
        );
    }

    #[test]
    fn content_range_parses_unknown_total_star() {
        assert_eq!(
            ContentRange::parse("bytes 0-499/*"),
            Some(ContentRange {
                start: 0,
                end: 499,
                total: None
            })
        );
    }

    #[test]
    fn content_range_rejects_malformed_values() {
        assert_eq!(ContentRange::parse("items 0-10/20"), None);
        assert_eq!(ContentRange::parse("bytes */1000"), None);
        assert_eq!(ContentRange::parse("bytes 200-100/1000"), None);
        assert_eq!(ContentRange::parse("garbage"), None);
    }

    // -- DirectSource::renew returns the non-renewable signal (Req 37.6) ----

    #[tokio::test]
    async fn direct_source_renew_returns_not_renewable() {
        let source = DirectSource::new(
            outbound(EgressPolicy::FailOpen),
            url("https://cdn.example/v.mp4"),
        );
        let err = source
            .renew()
            .await
            .expect_err("a plain source cannot renew");
        assert!(
            err.is_not_renewable(),
            "DirectSource::renew must return the non-renewable signal"
        );
        // The signal sits on the upstream-unavailable family (renders 503 if it
        // ever reaches a client) without panicking.
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    // -- open() obtains its client ONLY from OutboundClient (Req 51.1) ------
    //    The fail-closed gate refuses with no dial; since DirectSource has no
    //    other client, no upstream request can be made.

    #[tokio::test]
    async fn open_is_refused_by_fail_closed_egress_with_no_dial() {
        // No tunnel + FailClosed (the safe default) → the seam refuses.
        let source = DirectSource::new(
            outbound(EgressPolicy::FailClosed),
            url("https://cdn.example/v.mp4"),
        );
        let err = source
            .open(RangeSpec::Full)
            .await
            .expect_err("fail-closed egress must refuse the dial");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(
            err.message.contains("egress tunnel"),
            "the refusal must come from the egress seam, got: {err}"
        );
    }

    // -- open(Full) streams the full body + surfaces metadata (Req 5.1) -----

    #[tokio::test]
    async fn open_full_streams_body_and_surfaces_metadata() {
        let server = MockServer::start().await;
        let payload = b"hello stream-flow direct source body".to_vec();
        Mock::given(method("GET"))
            .and(path("/video.mp4"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "video/mp4")
                    .insert_header("Accept-Ranges", "bytes")
                    .set_body_bytes(payload.clone()),
            )
            .mount(&server)
            .await;

        let source = DirectSource::new(
            outbound(EgressPolicy::FailOpen),
            url(&format!("{}/video.mp4", server.uri())),
        );
        let body = source.open(RangeSpec::Full).await.expect("open succeeds");

        assert_eq!(body.status, 200);
        assert_eq!(body.content_type.as_deref(), Some("video/mp4"));
        assert!(body.accept_ranges, "Accept-Ranges: bytes must surface");
        assert_eq!(body.content_length, Some(payload.len() as u64));
        assert_eq!(collect_body(body).await, payload);
    }

    // -- open(range) issues a ranged request → 206 + Content-Range (Req 5.2)-

    #[tokio::test]
    async fn open_range_issues_ranged_request_and_surfaces_content_range() {
        let server = MockServer::start().await;
        let partial = b"PARTIAL-BYTES".to_vec();
        // The mock only matches when the upstream `Range` header was forwarded.
        Mock::given(method("GET"))
            .and(path("/video.mp4"))
            .and(header("range", "bytes=100-199"))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header("Content-Type", "video/mp4")
                    .insert_header("Content-Range", "bytes 100-199/1000")
                    .set_body_bytes(partial.clone()),
            )
            .mount(&server)
            .await;

        let source = DirectSource::new(
            outbound(EgressPolicy::FailOpen),
            url(&format!("{}/video.mp4", server.uri())),
        );
        let body = source
            .open(RangeSpec::Inclusive(100, 199))
            .await
            .expect("ranged open succeeds");

        assert_eq!(body.status, 206);
        assert_eq!(
            body.content_range,
            Some(ContentRange {
                start: 100,
                end: 199,
                total: Some(1000)
            })
        );
        // A 206 implies range support even absent an explicit Accept-Ranges.
        assert!(body.accept_ranges);
        assert_eq!(collect_body(body).await, partial);
    }

    // -- Redirects are followed server-side (Req 37.10) ---------------------

    #[tokio::test]
    async fn open_follows_redirect_chain_server_side() {
        let server = MockServer::start().await;
        let final_body = b"redirected final body".to_vec();
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/final", server.uri())),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(final_body.clone()))
            .mount(&server)
            .await;

        let source = DirectSource::new(
            outbound(EgressPolicy::FailOpen),
            url(&format!("{}/start", server.uri())),
        );
        let body = source
            .open(RangeSpec::Full)
            .await
            .expect("open follows redirect");

        // The client transparently followed the 302 to the final origin.
        assert_eq!(body.status, 200);
        assert_eq!(collect_body(body).await, final_body);
    }

    // -- Custom upstream headers are forwarded (Req 5.6) --------------------

    #[tokio::test]
    async fn open_forwards_custom_upstream_headers() {
        let server = MockServer::start().await;
        // Only matches when the custom header was forwarded to the upstream.
        Mock::given(method("GET"))
            .and(path("/secured"))
            .and(header("x-upstream-auth", "secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".to_vec()))
            .mount(&server)
            .await;

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-upstream-auth"),
            HeaderValue::from_static("secret-token"),
        );
        let source = DirectSource::new(
            outbound(EgressPolicy::FailOpen),
            url(&format!("{}/secured", server.uri())),
        )
        .with_headers(headers);

        let body = source
            .open(RangeSpec::Full)
            .await
            .expect("open with custom headers succeeds");
        assert_eq!(
            body.status, 200,
            "the custom header must have matched upstream"
        );
    }

    // -- No client-identifying header is ever sent upstream (Req 51.2/51.3) -
    //    DirectSource never receives a client IP or inbound headers, so even a
    //    custom header *named* like a forbidden one is not in play; this guards
    //    that a vanilla open() carries none of the forbidden header names.

    #[tokio::test]
    async fn open_request_carries_no_client_identifying_headers() {
        use std::sync::{Arc as StdArc, Mutex};

        let server = MockServer::start().await;
        let seen: StdArc<Mutex<Vec<String>>> = StdArc::new(Mutex::new(Vec::new()));
        let seen_clone = seen.clone();

        // A responder that records the inbound request's header names.
        Mock::given(method("GET"))
            .and(path("/probe"))
            .respond_with(move |req: &wiremock::Request| {
                let mut names = seen_clone.lock().unwrap();
                for h in req.headers.iter() {
                    names.push(h.0.as_str().to_ascii_lowercase());
                }
                ResponseTemplate::new(200).set_body_bytes(b"ok".to_vec())
            })
            .mount(&server)
            .await;

        let source = DirectSource::new(
            outbound(EgressPolicy::FailOpen),
            url(&format!("{}/probe", server.uri())),
        );
        let _ = source.open(RangeSpec::Full).await.expect("open succeeds");

        let names = seen.lock().unwrap();
        for forbidden in CLIENT_IDENTIFYING_HEADERS {
            assert!(
                !names.iter().any(|n| n == forbidden),
                "upstream request must not carry client-identifying header {forbidden}; saw {names:?}",
            );
        }
    }

    // -- connect() probes once and surfaces source metadata (Req 37.8) ------

    #[tokio::test]
    async fn connect_probes_and_surfaces_total_size_and_type() {
        let server = MockServer::start().await;
        let payload = vec![0u8; 4096];
        Mock::given(method("GET"))
            .and(path("/movie.mkv"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "video/x-matroska")
                    .insert_header("Accept-Ranges", "bytes")
                    .set_body_bytes(payload.clone()),
            )
            .mount(&server)
            .await;

        let source = DirectSource::connect(
            outbound(EgressPolicy::FailOpen),
            url(&format!("{}/movie.mkv", server.uri())),
            HeaderMap::new(),
        )
        .await
        .expect("probe succeeds");

        assert_eq!(source.total_size(), Some(payload.len() as u64));
        assert_eq!(source.content_type(), Some("video/x-matroska"));
        assert!(source.accept_ranges());
    }

    #[tokio::test]
    async fn connect_derives_total_from_content_range_when_present() {
        let server = MockServer::start().await;
        // Some origins answer a plain GET with a 206 + Content-Range carrying
        // the authoritative total; the probe must derive total from it.
        Mock::given(method("GET"))
            .and(path("/clip.mp4"))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header("Content-Type", "video/mp4")
                    .insert_header("Content-Range", "bytes 0-9/123456")
                    .set_body_bytes(vec![0u8; 10]),
            )
            .mount(&server)
            .await;

        let source = DirectSource::connect(
            outbound(EgressPolicy::FailOpen),
            url(&format!("{}/clip.mp4", server.uri())),
            HeaderMap::new(),
        )
        .await
        .expect("probe succeeds");

        assert_eq!(source.total_size(), Some(123_456));
        assert!(source.accept_ranges());
    }

    // -- A bare DirectSource has unknown metadata until probed --------------

    #[tokio::test]
    async fn new_source_reports_unknown_metadata() {
        let source = DirectSource::new(
            outbound(EgressPolicy::FailOpen),
            url("https://cdn.example/v.mp4"),
        );
        assert_eq!(source.total_size(), None);
        assert_eq!(source.content_type(), None);
        assert!(!source.accept_ranges());
    }
}
