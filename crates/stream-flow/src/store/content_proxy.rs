//! Content proxy with byte serving and per-user connection limits
//! (`store::content_proxy`) — Req 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.7, 19.8.
//!
//! The `/v0/proxy/{token}` endpoint resolves a `Proxy_Link` token to its
//! upstream link + request headers + tunnel type, then proxies the upstream
//! response to the client with full byte-serving support (`Range` → `206` +
//! `Content-Range`), per-user connection limiting (RAII `ConnGuard`), and
//! optional `Content-Disposition` filename.
//!
//! ## Behaviour
//!
//! * **Token resolution (Req 19.1):** The token is decoded via [`ProxyCodec`]
//!   to recover the upstream URL, embedded headers, filename, and expiry/IP
//!   binding. The resolved payload drives the upstream fetch.
//! * **Byte serving (Req 19.2):** The client's `Range` header is parsed into a
//!   [`RangeSpec`] and forwarded upstream. A `206 Partial Content` response
//!   carries the `Content-Range` header; a full `200` carries `Content-Length`.
//! * **Per-user headers (Req 19.3):** Headers embedded in the proxy-link
//!   payload are applied to the upstream request.
//! * **Per-user connection limit (Req 19.4, 19.5):** A configurable cap on
//!   concurrent proxy connections per user. When at the limit, new requests
//!   receive a `429 Too Many Requests` response. Active connections are tracked
//!   via an RAII [`ConnGuard`] that increments on creation and decrements on
//!   drop.
//! * **Accept-Ranges (Req 19.6):** The response advertises `Accept-Ranges: bytes`
//!   when the upstream supports range requests.
//! * **Content-Length (Req 19.3 / 5.4):** Propagated from the upstream for
//!   non-range responses.
//! * **Content-Disposition (Req 19.8):** When the proxy-link specifies a
//!   filename, the response includes `Content-Disposition: attachment;
//!   filename="<name>"`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use actix_web::http::header::{self};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use dashmap::DashMap;
use reqwest::header::HeaderMap;

use crate::config::PrebufferConfig;
use crate::errors::AppError;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::UpstreamBody;
use crate::proxy::AdaptiveJitterBuffer;

/// Configuration for the content proxy's per-user connection limiting.
#[derive(Clone, Debug)]
pub struct ContentProxyConfig {
    /// Maximum concurrent proxy connections per user. `0` means unlimited.
    pub max_connections_per_user: u32,
}

impl Default for ContentProxyConfig {
    fn default() -> Self {
        Self {
            max_connections_per_user: 0, // unlimited by default
        }
    }
}

/// Per-user active connection counter, shared across all requests.
///
/// Each user (identified by username string) has an [`AtomicU32`] tracking
/// their active proxy connections. The counter is incremented when a
/// [`ConnGuard`] is created and decremented when it is dropped (RAII,
/// Req 19.5).
#[derive(Default)]
pub struct ConnectionRegistry {
    counters: DashMap<String, Arc<AtomicU32>>,
}

impl ConnectionRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
        }
    }

    /// Get the current active connection count for a user.
    pub fn active_connections(&self, user: &str) -> u32 {
        self.counters
            .get(user)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Attempt to acquire a connection slot for the given user.
    ///
    /// If `max_connections` is 0 (unlimited) or the user is below the limit,
    /// returns `Ok(ConnGuard)`. Otherwise returns an error indicating the
    /// connection limit has been reached (Req 19.4).
    pub fn try_acquire(
        self: &Arc<Self>,
        user: &str,
        max_connections: u32,
    ) -> Result<ConnGuard, AppError> {
        let counter = self
            .counters
            .entry(user.to_string())
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .clone();

        if max_connections == 0 {
            // Unlimited — always acquire.
            counter.fetch_add(1, Ordering::Relaxed);
            return Ok(ConnGuard {
                counter,
                _registry: Arc::clone(self),
            });
        }

        // Attempt to increment only if below the limit (CAS loop).
        loop {
            let current = counter.load(Ordering::Relaxed);
            if current >= max_connections {
                return Err(AppError::too_many_requests(format!(
                    "per-user connection limit reached ({max_connections} concurrent)"
                )));
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(ConnGuard {
                        counter,
                        _registry: Arc::clone(self),
                    });
                }
                Err(_) => continue, // retry CAS
            }
        }
    }
}

/// RAII guard that decrements the user's active connection count on drop
/// (Req 19.5).
///
/// Created by [`ConnectionRegistry::try_acquire`]. Dropping the guard —
/// whether normally, on early return, or on panic — releases the connection
/// slot.
pub struct ConnGuard {
    counter: Arc<AtomicU32>,
    /// Prevent the registry from being dropped while guards are alive.
    _registry: Arc<ConnectionRegistry>,
}

impl std::fmt::Debug for ConnGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnGuard")
            .field("active", &self.counter.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Build the proxy response for a resolved payload.
///
/// This is the core content-proxy logic: it takes a resolved [`ProxyPayload`],
/// opens the upstream via a provided [`UpstreamSource`], and builds the
/// actix response with byte-serving headers.
///
/// The caller is responsible for:
/// - Resolving the token (via [`ProxyCodec`])
/// - Acquiring the [`ConnGuard`] (per-user connection limit)
/// - Providing the [`UpstreamSource`] (constructed from the payload's URL + headers)
pub fn build_content_proxy_response(
    body: UpstreamBody,
    is_head: bool,
    filename: Option<&str>,
) -> Result<HttpResponse, AppError> {
    // Only a deliverable 200/206 body is relayed; any other status is surfaced
    // as a typed error carrying the upstream status.
    if !matches!(body.status, 200 | 206) {
        return Err(map_upstream_status(body.status));
    }

    let status = StatusCode::from_u16(body.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);

    // Preserve the upstream content type.
    if let Some(content_type) = &body.content_type {
        builder.insert_header((header::CONTENT_TYPE, content_type.clone()));
    }

    // Advertise range support (Req 19.6).
    if body.accept_ranges {
        builder.insert_header((header::ACCEPT_RANGES, "bytes"));
    }

    // Relay the upstream `Content-Range` on a partial response (Req 19.2).
    if let Some(content_range) = &body.content_range {
        let cr_value = format!(
            "bytes {}-{}/{}",
            content_range.start,
            content_range.end,
            content_range
                .total
                .map(|t| t.to_string())
                .unwrap_or_else(|| "*".to_string())
        );
        builder.insert_header((header::CONTENT_RANGE, cr_value));
    }

    // Content-Disposition filename (Req 19.8).
    if let Some(name) = filename {
        builder.insert_header((
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        ));
    }

    // Propagate Content-Length (Req 19.3 / 5.4).
    let content_length = body.content_length;

    if is_head {
        if let Some(len) = content_length {
            builder.insert_header((header::CONTENT_LENGTH, len));
        }
        return Ok(builder.finish());
    }

    // Stream the body through the adaptive buffer.
    let buffer = AdaptiveJitterBuffer::from_config(&PrebufferConfig::default());
    let stream = crate::proxy::relay_stream(body, buffer);

    match content_length {
        Some(len) => Ok(builder.no_chunking(len).streaming(Box::pin(stream))),
        None => Ok(builder.streaming(Box::pin(stream))),
    }
}

/// Map a non-success upstream HTTP status to the canonical error taxonomy.
fn map_upstream_status(status: u16) -> AppError {
    let err = match status {
        401 => AppError::unauthorized("upstream returned 401"),
        403 => AppError::forbidden("upstream returned 403"),
        404 => AppError::not_found("upstream returned 404"),
        416 => AppError::range_not_satisfiable("upstream returned 416"),
        429 => AppError::too_many_requests("upstream returned 429"),
        s if (500..600).contains(&s) => {
            AppError::upstream_unavailable(format!("upstream returned {s}"))
        }
        s => AppError::upstream_unavailable(format!("upstream returned unexpected status {s}")),
    };
    err.with_upstream_status(status)
}

/// Convert a [`ProxyPayload`]'s headers map (BTreeMap) into a
/// [`reqwest::header::HeaderMap`] suitable for the upstream request (Req 19.3).
pub fn btree_headers_to_headermap(
    headers: &std::collections::BTreeMap<String, String>,
) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            map.insert(n, v);
        }
    }
    map
}

/// Parse the `Range` header from an actix [`HttpRequest`].
pub fn parse_range_from_request(req: &HttpRequest) -> Result<RangeSpec, AppError> {
    let range_header = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok());
    RangeSpec::from_header(range_header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::source::ContentRange;
    use bytes::Bytes;
    use futures::stream;

    /// Helper: build an [`UpstreamBody`] from parts for testing.
    fn make_body(
        status: u16,
        content_length: Option<u64>,
        content_range: Option<ContentRange>,
        content_type: Option<&str>,
        accept_ranges: bool,
        chunks: Vec<Bytes>,
    ) -> UpstreamBody {
        let stream = stream::iter(chunks.into_iter().map(Ok));
        UpstreamBody {
            status,
            content_length,
            content_range,
            content_type: content_type.map(str::to_string),
            accept_ranges,
            stream: Box::pin(stream),
        }
    }

    // -- Req 19.1: content proxy serves full body on no-Range request --------

    #[actix_web::test]
    async fn full_body_no_range_returns_200_with_content_length() {
        let payload = Bytes::from_static(b"full body content here");
        let body = make_body(
            200,
            Some(payload.len() as u64),
            None,
            Some("video/mp4"),
            true,
            vec![payload.clone()],
        );

        let resp =
            build_content_proxy_response(body, false, None).expect("should build response");

        assert_eq!(resp.status(), StatusCode::OK);
        // Content-Length propagated (Req 19.3 / 5.4).
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            payload.len().to_string()
        );
        // Accept-Ranges advertised (Req 19.6).
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
    }

    // -- Req 19.2: serves 206 with Content-Range on Range request ------------

    #[actix_web::test]
    async fn range_request_returns_206_with_content_range() {
        let partial = Bytes::from_static(b"partial bytes");
        let body = make_body(
            206,
            Some(partial.len() as u64),
            Some(ContentRange {
                start: 100,
                end: 199,
                total: Some(1000),
            }),
            Some("video/mp4"),
            true,
            vec![partial.clone()],
        );

        let resp =
            build_content_proxy_response(body, false, None).expect("should build 206 response");

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 100-199/1000"
        );
        // Accept-Ranges advertised (Req 19.6).
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
    }

    // -- Req 19.4/19.5: per-user connection limit rejects with 429 -----------

    #[tokio::test]
    async fn connection_limit_rejects_with_429_when_exceeded() {
        let registry = Arc::new(ConnectionRegistry::new());
        let max = 2;

        // Acquire up to the limit.
        let _g1 = registry.try_acquire("user-a", max).expect("first ok");
        let _g2 = registry.try_acquire("user-a", max).expect("second ok");

        // Third should be rejected with 429.
        let err = registry
            .try_acquire("user-a", max)
            .expect_err("should reject at limit");
        assert_eq!(err.category, crate::errors::ErrorCategory::TooManyRequests);
        assert_eq!(err.http_status().as_u16(), 429);
    }

    #[tokio::test]
    async fn connection_guard_decrements_on_drop() {
        let registry = Arc::new(ConnectionRegistry::new());
        let max = 1;

        let guard = registry.try_acquire("user-b", max).expect("acquire ok");
        assert_eq!(registry.active_connections("user-b"), 1);

        // Dropping the guard releases the slot (RAII, Req 19.5).
        drop(guard);
        assert_eq!(registry.active_connections("user-b"), 0);

        // Can acquire again after drop.
        let _g = registry.try_acquire("user-b", max).expect("re-acquire ok");
        assert_eq!(registry.active_connections("user-b"), 1);
    }

    #[tokio::test]
    async fn different_users_have_independent_limits() {
        let registry = Arc::new(ConnectionRegistry::new());
        let max = 1;

        let _g1 = registry.try_acquire("alice", max).expect("alice ok");
        // Alice is at limit, but Bob is independent.
        let _g2 = registry.try_acquire("bob", max).expect("bob ok");

        // Alice is rejected.
        assert!(registry.try_acquire("alice", max).is_err());
        // Bob is rejected.
        assert!(registry.try_acquire("bob", max).is_err());
    }

    #[tokio::test]
    async fn unlimited_connections_when_max_is_zero() {
        let registry = Arc::new(ConnectionRegistry::new());
        let max = 0; // unlimited

        let mut guards = Vec::new();
        for _ in 0..100 {
            guards.push(registry.try_acquire("user-c", max).expect("unlimited"));
        }
        assert_eq!(registry.active_connections("user-c"), 100);
    }

    // -- Req 19.3 / 5.4: Content-Length propagated ---------------------------

    #[actix_web::test]
    async fn content_length_propagated_for_full_response() {
        let body = make_body(200, Some(4096), None, Some("application/octet-stream"), false, vec![]);

        let resp =
            build_content_proxy_response(body, false, None).expect("should build response");

        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "4096"
        );
    }

    // -- Req 19.6: Accept-Ranges: bytes advertised ---------------------------

    #[actix_web::test]
    async fn accept_ranges_advertised_when_upstream_supports_it() {
        let body = make_body(200, Some(1000), None, None, true, vec![]);

        let resp =
            build_content_proxy_response(body, false, None).expect("should build response");

        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
    }

    #[actix_web::test]
    async fn accept_ranges_not_advertised_when_upstream_does_not_support() {
        let body = make_body(200, Some(1000), None, None, false, vec![]);

        let resp =
            build_content_proxy_response(body, false, None).expect("should build response");

        assert!(resp.headers().get(header::ACCEPT_RANGES).is_none());
    }

    // -- Req 19.8: Content-Disposition filename when specified ----------------

    #[actix_web::test]
    async fn content_disposition_set_when_filename_specified() {
        let body = make_body(200, Some(100), None, None, false, vec![]);

        let resp = build_content_proxy_response(body, false, Some("movie.mkv"))
            .expect("should build response");

        assert_eq!(
            resp.headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap(),
            "attachment; filename=\"movie.mkv\""
        );
    }

    #[actix_web::test]
    async fn no_content_disposition_when_no_filename() {
        let body = make_body(200, Some(100), None, None, false, vec![]);

        let resp =
            build_content_proxy_response(body, false, None).expect("should build response");

        assert!(resp.headers().get(header::CONTENT_DISPOSITION).is_none());
    }

    // -- HEAD request returns headers without body ---------------------------

    #[actix_web::test]
    async fn head_request_returns_headers_without_body() {
        let body = make_body(200, Some(5000), None, Some("video/mp4"), true, vec![]);

        let resp =
            build_content_proxy_response(body, true, Some("video.mp4"))
                .expect("should build HEAD response");

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "5000"
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap(),
            "attachment; filename=\"video.mp4\""
        );
    }

    // -- Non-success upstream status maps to error ---------------------------

    #[actix_web::test]
    async fn non_success_upstream_status_maps_to_error() {
        let body = make_body(404, None, None, None, false, vec![]);
        let err = build_content_proxy_response(body, false, None).expect_err("404 is error");
        assert_eq!(err.category, crate::errors::ErrorCategory::NotFound);
        assert_eq!(err.upstream_status, Some(404));

        let body = make_body(503, None, None, None, false, vec![]);
        let err = build_content_proxy_response(body, false, None).expect_err("503 is error");
        assert_eq!(err.category, crate::errors::ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(503));
    }

    // -- BTreeMap headers conversion -----------------------------------------

    #[test]
    fn btree_headers_converts_to_headermap() {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("Referer".to_string(), "https://example.com/".to_string());
        headers.insert("X-Custom".to_string(), "value".to_string());

        let map = btree_headers_to_headermap(&headers);
        assert_eq!(
            map.get("referer").unwrap().to_str().unwrap(),
            "https://example.com/"
        );
        assert_eq!(map.get("x-custom").unwrap().to_str().unwrap(), "value");
    }

    // -- Content-Range with unknown total ------------------------------------

    #[actix_web::test]
    async fn content_range_with_unknown_total_uses_star() {
        let body = make_body(
            206,
            Some(100),
            Some(ContentRange {
                start: 0,
                end: 99,
                total: None,
            }),
            None,
            true,
            vec![],
        );

        let resp =
            build_content_proxy_response(body, false, None).expect("should build 206 response");

        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 0-99/*"
        );
    }
}
