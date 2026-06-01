//! Generic ranged proxy core (`proxy::core`) — Req 5.1, 5.2, 5.4, 5.6, 5.7,
//! 5.8, 13.7, 51.10, 51.11.
//!
//! This is the heart of the generic HTTP(S) byte proxy: it wires an
//! [`UpstreamSource`] (which obtains its client only through the
//! [`egress::OutboundClient`](crate::egress::OutboundClient) seam — Req 51) to
//! the [`AdaptiveJitterBuffer`] bounded relay and the [`RangeSpec`] request
//! model, then renders the result as an actix [`HttpResponse`] (design:
//! Components → Streaming Core, Transport routing).
//!
//! ## What the core does
//!
//! * **Forwards the `Range` upstream** (Req 5.2). The requested [`RangeSpec`]
//!   is handed to [`UpstreamSource::open`], which translates it into an
//!   upstream `Range` header; the upstream's own `206 Partial Content` +
//!   `Content-Range` is relayed back verbatim. A request with no `Range`
//!   ([`RangeSpec::Full`]) streams the full body (Req 5.1).
//! * **Propagates `Content-Length`** for non-range responses (and the partial
//!   length for a `206`, Req 5.4) and advertises `Accept-Ranges: bytes`
//!   whenever the upstream does (Req 5.3) and the upstream `Content-Type`
//!   (Req 37.13).
//! * **Forwards custom upstream headers** (Req 5.6) — these live on the
//!   [`UpstreamSource`] (config/extractor-supplied, never inbound client
//!   headers, so they carry no client IP — Req 51.2).
//! * **Relays through a bounded buffer** (Req 5.7). [`relay_stream`] drains the
//!   upstream body through the [`AdaptiveJitterBuffer`] one chunk at a time,
//!   so peak memory is bounded by the buffer capacity regardless of the total
//!   body size — the whole body is **never** loaded into memory (the
//!   512 MB-VPS constraint, Req 35.1).
//! * **Terminates + logs on a mid-stream interruption** (Req 5.8). A
//!   transport-level upstream drop surfaces as a typed [`AppError`] item in the
//!   relay stream, which terminates the client response and is logged with the
//!   cause.
//!
//! ## `/proxy/ip` (Req 13.7, 51.10, 51.11)
//!
//! [`proxy_ip_endpoint`] returns the tunnel-observed Egress_IP from
//! [`OutboundClient::egress_ip`](crate::egress::OutboundClient::egress_ip) as
//! the mediaflow-compatible `{ "ip": "<egress-ip>" }` JSON, so operators
//! allowlist exactly one IP at their debrid provider for all users (Req 51.11).
//! Under the fail-closed default a down/leaking/unconfigured tunnel exposes no
//! verified Egress_IP, so the endpoint answers `503` rather than leaking the
//! host's real IP (Req 51.8).

use std::sync::Arc;

use actix_web::http::{header, StatusCode};
use actix_web::{web, HttpResponse};
use bytes::Bytes;
use futures::{Stream, StreamExt};

use crate::app::AppState;
use crate::config::PrebufferConfig;
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::proxy::buffer::AdaptiveJitterBuffer;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::{ContentRange, UpstreamBody, UpstreamSource};

/// Relay an upstream byte body to the client through the bounded
/// [`AdaptiveJitterBuffer`] (Req 5.7, 5.8, 37.11).
///
/// Each upstream chunk is pushed into the ring (which only accepts what fits)
/// and immediately drained toward the client, so at no point is more than the
/// buffer's [`capacity`](AdaptiveJitterBuffer::capacity) held in memory — peak
/// memory is bounded by the configured buffer size and is **independent of the
/// total body length** (Req 35.1, 5.7), and the full body is never buffered.
///
/// A transport-level upstream error (a mid-stream drop) surfaces as a typed
/// [`AppError`] item: the relay logs the interruption and terminates the
/// stream, which closes the client response (Req 5.8).
pub fn relay_stream(
    mut body: UpstreamBody,
    mut buffer: AdaptiveJitterBuffer,
) -> impl Stream<Item = Result<Bytes, AppError>> {
    async_stream::try_stream! {
        loop {
            match body.stream.next().await {
                Some(Ok(chunk)) => {
                    // Push the chunk into the ring in capacity-bounded slices,
                    // draining toward the client between pushes so the buffer
                    // never grows past its capacity (Req 5.7, 35.1).
                    let mut pending = chunk;
                    while !pending.is_empty() {
                        let remainder = buffer.push(pending);
                        while !buffer.is_empty() {
                            let drained = buffer.pull(buffer.buffered());
                            if !drained.is_empty() {
                                yield drained;
                            }
                        }
                        pending = remainder;
                    }
                }
                Some(Err(err)) => {
                    // Mid-stream upstream interruption: terminate the client
                    // response and record the interruption (Req 5.8).
                    tracing::warn!(
                        category = %err.category,
                        "generic proxy upstream interrupted mid-stream; terminating client response: {}",
                        err.message,
                    );
                    Err(err)?;
                }
                None => {
                    // Upstream completed: drain any trailing buffered bytes.
                    while !buffer.is_empty() {
                        let drained = buffer.pull(buffer.buffered());
                        if !drained.is_empty() {
                            yield drained;
                        }
                    }
                    break;
                }
            }
        }
    }
}

/// Serve a generic ranged proxy request from an [`UpstreamSource`] (Req 5.1,
/// 5.2, 5.4, 5.6, 5.7).
///
/// Opens the source for the requested [`RangeSpec`] (which forwards the `Range`
/// upstream — Req 5.2), maps the upstream response metadata onto the client
/// response (status, `Content-Type`, `Content-Range`, `Content-Length`,
/// `Accept-Ranges`), and attaches the bounded-buffer relay body
/// ([`relay_stream`], Req 5.7). A `HEAD` request (`is_head == true`) produces
/// the identical header set with no body (Req 37.14).
///
/// A non-`2xx`-style upstream status is mapped onto the canonical [`AppError`]
/// taxonomy carrying the upstream status (Req 1.7); the success path relays the
/// upstream `200`/`206` verbatim.
pub async fn serve(
    source: Arc<dyn UpstreamSource>,
    range: RangeSpec,
    is_head: bool,
    prebuffer: &PrebufferConfig,
) -> Result<HttpResponse, AppError> {
    let body = source.open(range).await?;
    build_response(body, is_head, prebuffer)
}

/// Build the client [`HttpResponse`] from an already-opened [`UpstreamBody`]
/// (Req 5.1, 5.2, 5.4, 5.7).
///
/// Separated from [`serve`] so the response-shaping logic is unit-testable from
/// a synthesized [`UpstreamBody`] without a live upstream.
pub fn build_response(
    body: UpstreamBody,
    is_head: bool,
    prebuffer: &PrebufferConfig,
) -> Result<HttpResponse, AppError> {
    // Only a deliverable 200/206 body is relayed; any other status is surfaced
    // as a typed error carrying the upstream status (Req 1.7).
    if !matches!(body.status, 200 | 206) {
        return Err(map_upstream_status(body.status));
    }

    let status = StatusCode::from_u16(body.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);

    // Preserve the upstream content type (Req 37.13, 1.5).
    if let Some(content_type) = &body.content_type {
        builder.insert_header((header::CONTENT_TYPE, content_type.clone()));
    }
    // Advertise range support when the upstream does (Req 5.3).
    if body.accept_ranges {
        builder.insert_header((header::ACCEPT_RANGES, "bytes"));
    }
    // Relay the upstream `Content-Range` on a partial response (Req 5.2).
    if let Some(content_range) = &body.content_range {
        builder.insert_header((header::CONTENT_RANGE, content_range_header(content_range)));
    }

    // Propagate the upstream `Content-Length` — the full size for a non-range
    // `200` (Req 5.4) and the partial length for a `206`.
    let content_length = body.content_length;

    if is_head {
        // HEAD: identical headers, no body (Req 37.14). Set the length header
        // explicitly since there is no body for actix to size.
        if let Some(len) = content_length {
            builder.insert_header((header::CONTENT_LENGTH, len));
        }
        return Ok(builder.finish());
    }

    let buffer = AdaptiveJitterBuffer::from_config(prebuffer);
    let stream = relay_stream(body, buffer);

    match content_length {
        // Known length: send a sized (non-chunked) response (Req 5.4).
        Some(len) => Ok(builder.no_chunking(len).streaming(Box::pin(stream))),
        // Unknown length: stream chunked.
        None => Ok(builder.streaming(Box::pin(stream))),
    }
}

/// Format a parsed [`ContentRange`] as its `Content-Range` header value:
/// `bytes start-end/total` or `bytes start-end/*` for the unknown-total form
/// (Req 5.2).
fn content_range_header(cr: &ContentRange) -> String {
    match cr.total {
        Some(total) => format!("bytes {}-{}/{}", cr.start, cr.end, total),
        None => format!("bytes {}-{}/*", cr.start, cr.end),
    }
}

/// Map a non-success upstream status onto the canonical [`AppError`] taxonomy,
/// carrying the upstream status (Req 1.7, 47.2).
fn map_upstream_status(status: u16) -> AppError {
    let err = match status {
        404 => AppError::not_found(format!("upstream returned status {status}")),
        416 => AppError::range_not_satisfiable(format!("upstream returned status {status}")),
        s if (500..=599).contains(&s) => {
            AppError::upstream_unavailable(format!("upstream returned status {status}"))
        }
        _ => {
            AppError::upstream_unavailable(format!("upstream returned unexpected status {status}"))
        }
    };
    err.with_upstream_status(status)
}

/// The `/proxy/ip` actix handler (Req 13.7, 51.10, 51.11).
///
/// Reads the shared [`AppState`]'s [`OutboundClient`] and returns the
/// tunnel-observed Egress_IP. Registered on the mediaflow surface by the
/// dual-surface router.
pub async fn proxy_ip_endpoint(state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    proxy_ip(state.egress())
}

/// Build the `/proxy/ip` response from the egress seam (Req 51.11).
///
/// Returns the mediaflow-compatible `{ "ip": "<egress-ip>" }` JSON when a
/// leak-verified Egress_IP is available, so operators allowlist exactly one IP
/// at their debrid provider for all users (Req 51.11). When the tunnel is
/// down / leaking / unconfigured there is no verified Egress_IP to report, so —
/// consistent with the fail-closed default (Req 51.8) — the endpoint answers a
/// typed `503` rather than leaking the host's real IP.
pub fn proxy_ip(client: &OutboundClient) -> Result<HttpResponse, AppError> {
    match client.egress_ip() {
        Some(ip) => Ok(HttpResponse::Ok().json(serde_json::json!({ "ip": ip.to_string() }))),
        None => Err(AppError::upstream_unavailable(
            "egress tunnel unavailable: no verified Egress_IP to report",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::egress::{EgressResolver, Tunnel};
    use crate::errors::ErrorCategory;
    use crate::proxy::source::DirectSource;

    use actix_web::body::to_bytes;
    use bytes::Bytes;
    use futures::stream;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use url::Url;
    use wiremock::matchers::{header as match_header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PREBUFFER: fn() -> PrebufferConfig = PrebufferConfig::default;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid url")
    }

    /// A `FailOpen` `OutboundClient` with no tunnel: the egress decision is
    /// "dial untunneled", so a [`DirectSource`] reaches the in-process wiremock
    /// origin directly — exercising the real open/relay path with no network
    /// dependency (mirrors the `proxy::source` tests).
    fn outbound_fail_open() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    /// An [`UpstreamBody`] over a fixed set of chunk results.
    fn body_from(
        status: u16,
        content_length: Option<u64>,
        content_range: Option<ContentRange>,
        content_type: Option<&str>,
        accept_ranges: bool,
        chunks: Vec<Result<Bytes, AppError>>,
    ) -> UpstreamBody {
        UpstreamBody {
            status,
            content_length,
            content_range,
            content_type: content_type.map(str::to_string),
            accept_ranges,
            stream: Box::pin(stream::iter(chunks)),
        }
    }

    /// Drain a relay stream into one buffer.
    async fn collect<S>(stream: S) -> Result<Vec<u8>, AppError>
    where
        S: Stream<Item = Result<Bytes, AppError>>,
    {
        futures::pin_mut!(stream);
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            out.extend_from_slice(&item?);
        }
        Ok(out)
    }

    // -- Bounded-buffer relay round-trips the body (Req 5.7) ----------------

    #[tokio::test]
    async fn relay_round_trips_a_body_larger_than_the_buffer() {
        // Tiny buffer (capacity 8) but a body many times larger: the relay must
        // reproduce every byte in order while never holding the whole body.
        let prebuffer = PrebufferConfig {
            initial_buffer_bytes: 8,
            steady_buffer_bytes: 4,
            initial_window_bytes: 16,
            ..PrebufferConfig::default()
        };
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        // Deliver in irregular chunks.
        let chunks: Vec<Result<Bytes, AppError>> = payload
            .chunks(37)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let body = body_from(
            200,
            Some(payload.len() as u64),
            None,
            Some("video/mp4"),
            true,
            chunks,
        );

        let buffer = AdaptiveJitterBuffer::from_config(&prebuffer);
        let out = collect(relay_stream(body, buffer)).await.expect("relay ok");
        assert_eq!(out, payload, "relay must reproduce the exact byte stream");
    }

    // -- Relay does NOT load the whole body (Req 5.7) -----------------------

    #[tokio::test]
    async fn relay_is_incremental_and_never_loads_the_whole_body() {
        // A body that records how many chunks have actually been polled. Pulling
        // a single relayed item must consume only the first upstream chunk(s) —
        // proving the relay streams incrementally rather than buffering the
        // whole body up front (Req 5.7).
        let polled = Arc::new(AtomicUsize::new(0));
        let total_chunks = 100usize;
        let chunk_size = 8usize;

        let polled_inner = polled.clone();
        let upstream = stream::unfold(0usize, move |i| {
            let polled = polled_inner.clone();
            async move {
                if i >= total_chunks {
                    return None;
                }
                polled.fetch_add(1, Ordering::SeqCst);
                let chunk = Bytes::from(vec![(i % 251) as u8; chunk_size]);
                Some((Ok::<Bytes, AppError>(chunk), i + 1))
            }
        });
        let body = UpstreamBody {
            status: 200,
            content_length: Some((total_chunks * chunk_size) as u64),
            content_range: None,
            content_type: Some("application/octet-stream".to_string()),
            accept_ranges: true,
            stream: Box::pin(upstream),
        };

        // A buffer large enough to hold one upstream chunk.
        let prebuffer = PrebufferConfig {
            initial_buffer_bytes: 64,
            steady_buffer_bytes: 64,
            initial_window_bytes: 1024,
            ..PrebufferConfig::default()
        };
        let buffer = AdaptiveJitterBuffer::from_config(&prebuffer);
        let relay = relay_stream(body, buffer);
        futures::pin_mut!(relay);

        // Pull exactly one relayed item.
        let first = relay.next().await.expect("first item").expect("ok");
        assert!(!first.is_empty());

        // Only a small number of upstream chunks were polled — nowhere near all
        // 100 — so the whole body was not loaded to satisfy one client read.
        let polled_now = polled.load(Ordering::SeqCst);
        assert!(
            polled_now < total_chunks,
            "relay loaded {polled_now}/{total_chunks} chunks for one client read; \
             it must stream incrementally, not buffer the whole body",
        );
    }

    // -- Mid-stream interruption terminates + (logs) (Req 5.8) --------------

    #[tokio::test]
    async fn relay_terminates_on_mid_stream_interruption() {
        // The upstream delivers two good chunks then drops mid-stream.
        let chunks: Vec<Result<Bytes, AppError>> = vec![
            Ok(Bytes::from_static(b"first-")),
            Ok(Bytes::from_static(b"second-")),
            Err(AppError::upstream_unavailable(
                "connection reset mid-stream",
            )),
            // Anything after the error must never be delivered.
            Ok(Bytes::from_static(b"NEVER")),
        ];
        let body = body_from(200, None, None, Some("video/mp4"), false, chunks);
        let buffer = AdaptiveJitterBuffer::from_config(&PREBUFFER());
        let relay = relay_stream(body, buffer);
        futures::pin_mut!(relay);

        let mut delivered = Vec::new();
        let mut terminating_err = None;
        while let Some(item) = relay.next().await {
            match item {
                Ok(bytes) => delivered.extend_from_slice(&bytes),
                Err(e) => {
                    terminating_err = Some(e);
                    break;
                }
            }
        }

        // The good prefix was delivered, then the stream terminated with the
        // typed upstream error — and the post-error chunk was never delivered.
        assert_eq!(&delivered, b"first-second-");
        let err = terminating_err.expect("relay must terminate with the upstream error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(
            relay.next().await.is_none(),
            "no bytes after a mid-stream drop"
        );
    }

    // -- Full body (no Range) → 200 + Content-Length (Req 5.1, 5.4) ---------

    #[tokio::test]
    async fn serve_full_body_is_200_with_content_length() {
        let server = MockServer::start().await;
        let payload = b"a generic full-body response".to_vec();
        Mock::given(method("GET"))
            .and(path("/file"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/octet-stream")
                    .insert_header("Accept-Ranges", "bytes")
                    .set_body_bytes(payload.clone()),
            )
            .mount(&server)
            .await;

        let source: Arc<dyn UpstreamSource> = Arc::new(DirectSource::new(
            outbound_fail_open(),
            url(&format!("{}/file", server.uri())),
        ));
        let resp = serve(source, RangeSpec::Full, false, &PREBUFFER())
            .await
            .expect("serve ok");

        assert_eq!(resp.status(), StatusCode::OK);
        // Content-Length propagated for the non-range response (Req 5.4).
        assert_eq!(
            resp.headers().get(header::CONTENT_LENGTH).unwrap(),
            payload.len().to_string().as_str(),
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .map(|v| v.to_str().unwrap()),
            Some("bytes"),
        );
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&bytes[..], &payload[..]);
    }

    // -- Range forwarded upstream → 206 + Content-Range (Req 5.2) -----------

    #[tokio::test]
    async fn serve_range_forwards_upstream_and_relays_206_content_range() {
        let server = MockServer::start().await;
        let partial = b"PARTIAL-RANGE-BYTES".to_vec();
        Mock::given(method("GET"))
            .and(path("/movie.mp4"))
            // Only matches when the upstream `Range` was forwarded (Req 5.2).
            .and(match_header("range", "bytes=100-199"))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header("Content-Type", "video/mp4")
                    .insert_header("Content-Range", "bytes 100-199/1000")
                    .set_body_bytes(partial.clone()),
            )
            .mount(&server)
            .await;

        let source: Arc<dyn UpstreamSource> = Arc::new(DirectSource::new(
            outbound_fail_open(),
            url(&format!("{}/movie.mp4", server.uri())),
        ));
        let resp = serve(source, RangeSpec::Inclusive(100, 199), false, &PREBUFFER())
            .await
            .expect("serve ok");

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 100-199/1000",
        );
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&bytes[..], &partial[..]);
    }

    // -- Custom upstream headers forwarded (Req 5.6) ------------------------

    #[tokio::test]
    async fn serve_forwards_custom_upstream_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secured"))
            .and(match_header("x-upstream-auth", "secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".to_vec()))
            .mount(&server)
            .await;

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-upstream-auth"),
            HeaderValue::from_static("secret-token"),
        );
        let source: Arc<dyn UpstreamSource> = Arc::new(
            DirectSource::new(
                outbound_fail_open(),
                url(&format!("{}/secured", server.uri())),
            )
            .with_headers(headers),
        );
        let resp = serve(source, RangeSpec::Full, false, &PREBUFFER())
            .await
            .expect("serve ok");

        // A 200 here proves the custom header matched at the upstream (Req 5.6).
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -- HEAD produces headers with no body (Req 37.14) ---------------------

    #[test]
    fn build_response_head_has_headers_and_no_body() {
        let body = body_from(
            200,
            Some(1000),
            None,
            Some("video/mp4"),
            true,
            vec![Ok(Bytes::from_static(b"should-not-be-sent"))],
        );
        let resp = build_response(body, true, &PREBUFFER()).expect("head ok");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "1000",);
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .map(|v| v.to_str().unwrap()),
            Some("bytes"),
        );
    }

    // -- Non-success upstream status → typed error (Req 1.7) ----------------

    #[test]
    fn build_response_maps_non_success_status_to_error() {
        let body = body_from(404, None, None, None, false, vec![]);
        let err = build_response(body, false, &PREBUFFER()).expect_err("404 is an error");
        assert_eq!(err.category, ErrorCategory::NotFound);
        assert_eq!(err.upstream_status, Some(404));

        let body = body_from(503, None, None, None, false, vec![]);
        let err = build_response(body, false, &PREBUFFER()).expect_err("503 is an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(503));
    }

    // -- /proxy/ip returns the tunnel-observed Egress_IP (Req 51.10, 51.11) -

    /// An `OutboundClient` whose resolver has verified a leak-free Egress_IP.
    async fn outbound_with_verified_egress(egress: &str, host: &str) -> Arc<OutboundClient> {
        let tunnel = Tunnel::proxy(
            "http://proxy:8888",
            Arc::new(MockReflector::isolated(egress, host)),
        );
        let resolver = Arc::new(EgressResolver::new(
            Arc::new(tunnel),
            Duration::from_secs(3600),
        ));
        resolver.refresh().await; // populate the leak-verified cache
        let (tunneled, impersonate) = (
            reqwest::Client::builder().no_proxy().build().unwrap(),
            wreq::Client::builder().no_proxy().build().unwrap(),
        );
        Arc::new(OutboundClient::new(
            tunneled,
            impersonate,
            EgressPolicy::FailClosed,
            Some(resolver),
            None,
            std::collections::HashMap::new(),
        ))
    }

    #[tokio::test]
    async fn proxy_ip_returns_the_verified_egress_ip() {
        let client = outbound_with_verified_egress("203.0.113.7", "198.51.100.1").await;
        let resp = proxy_ip(&client).expect("proxy_ip ok");
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = to_bytes(resp.into_body()).await.expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        // The tunnel-observed Egress_IP, not the host's real IP (Req 51.11).
        assert_eq!(json["ip"], "203.0.113.7");
    }

    #[test]
    fn proxy_ip_is_503_when_no_verified_egress_ip() {
        // No tunnel configured → no verified Egress_IP → fail-closed 503.
        let cfg = EgressConfig::default();
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let client = OutboundClient::from_config(&cfg, reflector).expect("builds");
        let err = proxy_ip(&client).expect_err("no egress IP → error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.http_status().as_u16(), 503);
    }
}
