//! Content proxy with byte serving and per-user connection limits
//! (`content_proxy`) — Req 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.7, 19.8.
//!
//! The content proxy resolves a `Proxy_Link` token to its **upstream link +
//! request headers + tunnel type** ([`resolve_target`], Req 19.1) and proxies
//! the upstream response to the client **through the streaming core**
//! ([`crate::proxy`]) with full byte-serving support (`Range` → `206` +
//! `Content-Range`, Req 19.2). It applies the embedded per-user headers to the
//! upstream request (Req 19.3), counts each active connection against the
//! user's per-user limit via an RAII [`ConnGuard`] (Req 19.5) and **redirects
//! to a "limit reached" placeholder** when the user is at the cap instead of
//! opening a new upstream connection (Req 19.4). When a per-store tunnel
//! configuration is in **api-only** mode it does not proxy media bytes and
//! returns the direct link instead (Req 19.6). It applies configured stale
//! times distinctly for cached versus uncached content (Req 19.7) and sets the
//! response `Content-Disposition` filename when the proxy-link specifies one
//! (Req 19.8).
//!
//! ## Flow (design: Components → Content Proxy)
//!
//! 1. [`resolve_target`] decodes the `token`/`d` parameter via the
//!    [`ProxyCodec`], enforces the embedded `exp`/`ip` (Req 14.5/14.6), and
//!    resolves the per-host [`TunnelMode`] — yielding the upstream link, the
//!    embedded headers, the filename, and the tunnel type (Req 19.1).
//! 2. An **api-only** target short-circuits to [`api_only_redirect`] (a `302`
//!    to the direct link) so no media bytes are proxied (Req 19.6).
//! 3. Otherwise the user acquires a [`ConnGuard`] from the shared
//!    [`ConnectionRegistry`]; a user already at the cap is sent to the
//!    [`limit_reached_redirect`] placeholder (Req 19.4) rather than opening a
//!    new upstream connection.
//! 4. A [`DirectSource`] is built for the upstream URL + embedded headers
//!    (Req 19.3) and opened for the requested [`RangeSpec`]; the response is
//!    relayed through the bounded [`AdaptiveJitterBuffer`] streaming core
//!    (Req 19.1, 19.2) with the [`ConnGuard`] held for the lifetime of the
//!    body stream so the count is decremented when the connection closes
//!    (Req 19.5).

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::http::header;
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};
use bytes::Bytes;
use dashmap::DashMap;
use futures::{Stream, StreamExt};
use reqwest::header::HeaderMap;
use url::Url;

use crate::config::PrebufferConfig;
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::http::client_ip::client_ip;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::{DirectSource, UpstreamBody, UpstreamSource};
use crate::proxy::AdaptiveJitterBuffer;
use crate::proxylink::ProxyCodec;
use crate::AppState;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Per-store tunnel mode resolved for a content-proxy target (Req 19.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TunnelMode {
    /// Proxy media bytes through the streaming core (the default behaviour).
    #[default]
    Full,
    /// API-only: do **not** proxy media bytes for this store — return the
    /// direct link to the client instead (Req 19.6).
    ApiOnly,
}

/// Whether the content being served is cached or uncached upstream, selecting
/// which configured stale time applies (Req 19.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cacheability {
    /// The content is cached upstream — apply the cached stale time.
    Cached,
    /// The content is not cached upstream — apply the uncached stale time.
    Uncached,
}

/// Content-proxy tunables: the per-user connection cap, the distinct
/// cached/uncached stale times, and the per-host tunnel-mode overrides.
#[derive(Clone, Debug)]
pub struct ContentProxyConfig {
    /// Maximum concurrent proxy connections per user. `0` means unlimited
    /// (Req 19.4).
    pub max_connections_per_user: u32,
    /// `Cache-Control` `max-age` (seconds) applied to **cached** content
    /// (Req 19.7).
    pub cached_stale_secs: u64,
    /// `Cache-Control` `max-age` (seconds) applied to **uncached** content
    /// (Req 19.7).
    pub uncached_stale_secs: u64,
    /// Per-host tunnel-mode overrides. A host present here with
    /// [`TunnelMode::ApiOnly`] makes the proxy return the direct link rather
    /// than proxying its bytes (Req 19.6). Hosts absent from the map default
    /// to [`TunnelMode::Full`].
    pub tunnel_modes: HashMap<String, TunnelMode>,
}

impl Default for ContentProxyConfig {
    fn default() -> Self {
        Self {
            // Unlimited by default — a per-user cap is opt-in (Req 19.4).
            max_connections_per_user: 0,
            // Cached content can be held longer than uncached; the two are
            // configurable and applied distinctly (Req 19.7).
            cached_stale_secs: 3600,
            uncached_stale_secs: 60,
            tunnel_modes: HashMap::new(),
        }
    }
}

impl ContentProxyConfig {
    /// The [`TunnelMode`] configured for `host`, defaulting to
    /// [`TunnelMode::Full`] for any host with no explicit override (Req 19.6).
    pub fn tunnel_mode_for(&self, host: &str) -> TunnelMode {
        self.tunnel_modes
            .get(host)
            .copied()
            .unwrap_or(TunnelMode::Full)
    }

    /// The stale time (seconds) for the given cacheability (Req 19.7).
    pub fn stale_secs(&self, cacheability: Cacheability) -> u64 {
        match cacheability {
            Cacheability::Cached => self.cached_stale_secs,
            Cacheability::Uncached => self.uncached_stale_secs,
        }
    }

    /// The `Cache-Control` header value applied for the given cacheability,
    /// using the distinct cached/uncached stale times (Req 19.7).
    pub fn cache_control_value(&self, cacheability: Cacheability) -> String {
        format!("public, max-age={}", self.stale_secs(cacheability))
    }
}

// ---------------------------------------------------------------------------
// Per-user connection limiting (Req 19.4, 19.5)
// ---------------------------------------------------------------------------

/// Per-user active connection counter, shared across all requests.
///
/// Each user (identified by username string) has an [`AtomicU32`] tracking
/// their active proxy connections. The counter is incremented when a
/// [`ConnGuard`] is acquired and decremented when it is dropped (RAII,
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

    /// The current active connection count for a user.
    pub fn active_connections(&self, user: &str) -> u32 {
        self.counters
            .get(user)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Attempt to acquire a connection slot for `user` (Req 19.4, 19.5).
    ///
    /// Returns `Some(ConnGuard)` when `max_connections` is `0` (unlimited) or
    /// the user is below the limit, having incremented the count. Returns
    /// `None` when the user is **already at the cap** — the caller then sends
    /// the client to the "limit reached" placeholder rather than opening a new
    /// upstream connection (Req 19.4).
    pub fn try_acquire(self: &Arc<Self>, user: &str, max_connections: u32) -> Option<ConnGuard> {
        let counter = self
            .counters
            .entry(user.to_string())
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .clone();

        if max_connections == 0 {
            // Unlimited — always acquire.
            counter.fetch_add(1, Ordering::Relaxed);
            return Some(ConnGuard {
                counter,
                _registry: Arc::clone(self),
            });
        }

        // Increment only if strictly below the limit (CAS loop so concurrent
        // acquirers never exceed the cap).
        loop {
            let current = counter.load(Ordering::Relaxed);
            if current >= max_connections {
                return None;
            }
            if counter
                .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Some(ConnGuard {
                    counter,
                    _registry: Arc::clone(self),
                });
            }
            // CAS lost a race — retry.
        }
    }
}

/// RAII guard that decrements the user's active connection count on drop
/// (Req 19.5).
///
/// Acquired from [`ConnectionRegistry::try_acquire`] and held for the lifetime
/// of the proxied body stream. Dropping the guard — whether the stream
/// completes normally, the client disconnects, or a panic unwinds — releases
/// the connection slot.
pub struct ConnGuard {
    counter: Arc<AtomicU32>,
    /// Keeps the registry alive while guards exist.
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

// ---------------------------------------------------------------------------
// Token resolution (Req 19.1)
// ---------------------------------------------------------------------------

/// A resolved content-proxy target: the upstream link, the embedded per-user
/// request headers, the optional download filename, and the per-store tunnel
/// type (Req 19.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// The upstream URL to fetch (or, in api-only mode, return).
    pub url: String,
    /// The embedded per-user request headers applied upstream (Req 19.3).
    pub headers: BTreeMap<String, String>,
    /// The optional download filename (Req 19.8).
    pub filename: Option<String>,
    /// The resolved tunnel type for this target's host (Req 19.6).
    pub tunnel: TunnelMode,
}

/// Resolve a `Proxy_Link` token (`token` or `d` query parameter) to its
/// upstream link, request headers, filename, and tunnel type (Req 19.1).
///
/// The token is decoded by the [`ProxyCodec`], which also enforces the embedded
/// expiry (Req 14.5) and IP binding (Req 14.6) against `client_ip` /
/// `now_unix_secs`. The per-store [`TunnelMode`] is resolved from the upstream
/// URL's host via [`ContentProxyConfig::tunnel_mode_for`] (Req 19.6).
pub fn resolve_target(
    codec: &ProxyCodec,
    token: Option<&str>,
    d: Option<&str>,
    client_ip: Option<IpAddr>,
    now_unix_secs: i64,
    config: &ContentProxyConfig,
) -> Result<ResolvedTarget, AppError> {
    let payload = codec.resolve_params(token, d, client_ip, now_unix_secs)?;

    // Resolve the per-store tunnel type from the upstream host (Req 19.6).
    let tunnel = Url::parse(&payload.url)
        .ok()
        .and_then(|u| u.host_str().map(|h| config.tunnel_mode_for(h)))
        .unwrap_or(TunnelMode::Full);

    Ok(ResolvedTarget {
        url: payload.url,
        headers: payload.headers,
        filename: payload.filename,
        tunnel,
    })
}

// ---------------------------------------------------------------------------
// Redirects (Req 19.4, 19.6)
// ---------------------------------------------------------------------------

/// Build the `302 Found` redirect to the "limit reached" placeholder served
/// when a user is at their per-user connection cap (Req 19.4).
pub fn limit_reached_redirect(placeholder_url: &str) -> HttpResponse {
    HttpResponse::Found()
        .insert_header((header::LOCATION, placeholder_url.to_string()))
        .finish()
}

/// Build the `302 Found` redirect to the upstream **direct link**, used when
/// the per-store tunnel configuration is in api-only mode and the proxy must
/// not relay media bytes (Req 19.6).
pub fn api_only_redirect(direct_link: &str) -> HttpResponse {
    HttpResponse::Found()
        .insert_header((header::LOCATION, direct_link.to_string()))
        .finish()
}

// ---------------------------------------------------------------------------
// Header conversion (Req 19.3)
// ---------------------------------------------------------------------------

/// Convert the embedded proxy-link headers (a sorted [`BTreeMap`]) into a
/// [`reqwest::header::HeaderMap`] applied to the upstream request (Req 19.3).
///
/// Header names/values that are not valid HTTP header tokens are skipped rather
/// than aborting the request.
pub fn btree_headers_to_headermap(headers: &BTreeMap<String, String>) -> HeaderMap {
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

// ---------------------------------------------------------------------------
// Response building (Req 19.2, 19.7, 19.8)
// ---------------------------------------------------------------------------

/// Sanitize a `Content-Disposition` filename: strip control characters and
/// double quotes so the value cannot inject extra header content (Req 19.8).
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect()
}

/// Relay an upstream body through the bounded streaming-core buffer while
/// holding the per-user [`ConnGuard`] for the lifetime of the stream (Req 19.2,
/// 19.5).
///
/// The guard is dropped when the body completes, the client disconnects, or the
/// stream errors, decrementing the user's active connection count (Req 19.5).
fn relay_with_guard(
    body: UpstreamBody,
    buffer: AdaptiveJitterBuffer,
    guard: ConnGuard,
) -> impl Stream<Item = Result<Bytes, AppError>> {
    async_stream::try_stream! {
        // Held for the whole stream — decremented on drop (Req 19.5).
        let _guard = guard;
        let inner = crate::proxy::relay_stream(body, buffer);
        futures::pin_mut!(inner);
        while let Some(item) = inner.next().await {
            yield item?;
        }
    }
}

/// Build the client [`HttpResponse`] from an opened [`UpstreamBody`], applying
/// byte serving (Req 19.2), the cached/uncached `Cache-Control` stale time
/// (Req 19.7), and the optional `Content-Disposition` filename (Req 19.8).
///
/// When `guard` is `Some` and the request is not a `HEAD`, the body is relayed
/// through [`relay_with_guard`] so the per-user connection count is held for the
/// lifetime of the stream (Req 19.5). A `HEAD` request produces the identical
/// header set with no body and releases the guard immediately.
#[allow(clippy::too_many_arguments)]
pub fn build_content_proxy_response(
    body: UpstreamBody,
    is_head: bool,
    filename: Option<&str>,
    cacheability: Cacheability,
    config: &ContentProxyConfig,
    prebuffer: &PrebufferConfig,
    guard: Option<ConnGuard>,
) -> Result<HttpResponse, AppError> {
    // Only a deliverable 200/206 body is relayed; any other status is surfaced
    // as a typed error carrying the upstream status (Req 1.7).
    if !matches!(body.status, 200 | 206) {
        return Err(map_upstream_status(body.status));
    }

    let status = StatusCode::from_u16(body.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);

    // Preserve the upstream content type.
    if let Some(content_type) = &body.content_type {
        builder.insert_header((header::CONTENT_TYPE, content_type.clone()));
    }

    // Advertise range support when the upstream does (Req 19.2 byte serving).
    if body.accept_ranges {
        builder.insert_header((header::ACCEPT_RANGES, "bytes"));
    }

    // Relay the upstream `Content-Range` on a partial response (Req 19.2).
    if let Some(content_range) = &body.content_range {
        builder.insert_header((header::CONTENT_RANGE, content_range_header(content_range)));
    }

    // Distinct cached/uncached stale time (Req 19.7).
    builder.insert_header((
        header::CACHE_CONTROL,
        config.cache_control_value(cacheability),
    ));

    // Content-Disposition filename when specified (Req 19.8).
    if let Some(name) = filename {
        let safe = sanitize_filename(name);
        builder.insert_header((
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{safe}\""),
        ));
    }

    let content_length = body.content_length;

    if is_head {
        // HEAD: identical headers, no body (Req 37.14). The guard drops here.
        drop(guard);
        if let Some(len) = content_length {
            builder.insert_header((header::CONTENT_LENGTH, len));
        }
        return Ok(builder.finish());
    }

    let buffer = AdaptiveJitterBuffer::from_config(prebuffer);
    let response = match guard {
        Some(guard) => {
            let stream = relay_with_guard(body, buffer, guard);
            match content_length {
                Some(len) => builder.no_chunking(len).streaming(Box::pin(stream)),
                None => builder.streaming(Box::pin(stream)),
            }
        }
        None => {
            let stream = crate::proxy::relay_stream(body, buffer);
            match content_length {
                Some(len) => builder.no_chunking(len).streaming(Box::pin(stream)),
                None => builder.streaming(Box::pin(stream)),
            }
        }
    };
    Ok(response)
}

/// Format a parsed [`ContentRange`](crate::proxy::source::ContentRange) as its
/// `Content-Range` header value: `bytes start-end/total` or `bytes start-end/*`
/// for the unknown-total form (Req 19.2).
fn content_range_header(cr: &crate::proxy::source::ContentRange) -> String {
    match cr.total {
        Some(total) => format!("bytes {}-{}/{}", cr.start, cr.end, total),
        None => format!("bytes {}-{}/*", cr.start, cr.end),
    }
}

/// Map a non-success upstream HTTP status onto the canonical [`AppError`]
/// taxonomy, carrying the upstream status (Req 1.7).
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

// ---------------------------------------------------------------------------
// Orchestration (Req 19.1–19.8)
// ---------------------------------------------------------------------------

/// Serve a content-proxy request end to end (Req 19.1–19.8).
///
/// Resolves the token to its upstream link + headers + tunnel type (Req 19.1);
/// an api-only target returns the direct link without proxying bytes (Req 19.6);
/// otherwise acquires a per-user connection slot — redirecting to the
/// `limit_placeholder` when the user is at the cap (Req 19.4) — opens the
/// upstream through the egress seam applying the embedded headers (Req 19.3),
/// and relays the response through the streaming core with byte serving
/// (Req 19.2), the cached/uncached stale time (Req 19.7), and the optional
/// `Content-Disposition` filename (Req 19.8), holding the [`ConnGuard`] for the
/// lifetime of the body (Req 19.5).
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    client: &Arc<OutboundClient>,
    codec: &ProxyCodec,
    registry: &Arc<ConnectionRegistry>,
    config: &ContentProxyConfig,
    prebuffer: &PrebufferConfig,
    request: ContentProxyRequest<'_>,
) -> Result<HttpResponse, AppError> {
    let target = resolve_target(
        codec,
        request.token,
        request.d,
        request.client_ip,
        request.now_unix_secs,
        config,
    )?;

    // Merge `r_*` extra headers into the target headers. Extra headers are
    // lower-priority: the encrypted/token payload headers take precedence.
    let mut merged_headers = request.extra_headers;
    for (name, value) in &target.headers {
        merged_headers.entry(name.clone()).or_insert_with(|| value.clone());
    }

    // Req 19.6: api-only tunnel mode returns the direct link, no byte proxying.
    if target.tunnel == TunnelMode::ApiOnly {
        return Ok(api_only_redirect(&target.url));
    }

    // Req 19.4/19.5: acquire a per-user connection slot or redirect to the
    // "limit reached" placeholder when the user is at the cap.
    let guard = match registry.try_acquire(request.user, config.max_connections_per_user) {
        Some(guard) => guard,
        None => return Ok(limit_reached_redirect(request.limit_placeholder)),
    };

    // Build the upstream source (Req 19.1) applying the embedded headers
    // (Req 19.3); the client comes ONLY from the egress seam (Req 51.1).
    let url = Url::parse(&target.url)
        .map_err(|e| AppError::bad_request(format!("invalid upstream URL in proxy link: {e}")))?;
    let headers = btree_headers_to_headermap(&merged_headers);
    let source: Arc<dyn UpstreamSource> =
        Arc::new(DirectSource::new(Arc::clone(client), url).with_headers(headers));

    // Open the upstream for the requested range and relay it (Req 19.1, 19.2).
    // A failed open returns here, dropping the guard (the slot is released).
    let body = source.open(request.range).await?;
    build_content_proxy_response(
        body,
        request.is_head,
        target.filename.as_deref(),
        request.cacheability,
        config,
        prebuffer,
        Some(guard),
    )
}

/// The per-request inputs to [`serve`].
#[derive(Clone, Debug)]
pub struct ContentProxyRequest<'a> {
    /// The authenticated user the connection is counted against (Req 19.4,
    /// 19.5).
    pub user: &'a str,
    /// The `token` query parameter (stremthru format), if present.
    pub token: Option<&'a str>,
    /// The `d` query parameter (mediaflow encrypted format), if present.
    pub d: Option<&'a str>,
    /// Extra upstream request headers extracted from `r_*` query parameters
    /// (MediaFusion convention: `r_Content-Type=video/mp4`).
    pub extra_headers: BTreeMap<String, String>,
    /// The parsed client `Range` request (Req 19.2).
    pub range: RangeSpec,
    /// Whether this is a `HEAD` request (headers only, no body).
    pub is_head: bool,
    /// The requester's `Client_IP`, for the embedded IP-binding check
    /// (Req 14.6).
    pub client_ip: Option<IpAddr>,
    /// The current unix-second time, for the embedded expiry check (Req 14.5).
    pub now_unix_secs: i64,
    /// Whether the content is cached or uncached upstream, selecting the stale
    /// time (Req 19.7).
    pub cacheability: Cacheability,
    /// The URL of the "limit reached" placeholder to redirect to when the user
    /// is at their connection cap (Req 19.4).
    pub limit_placeholder: &'a str,
}

/// Actix endpoint for `/proxy/stream`.
///
/// Accepts either `d=<mediaflow encrypted payload>` or `token=<stremthru signed
/// payload>`, enforces embedded expiry/IP binding, applies request `Range`, and
/// relays the upstream through the shared egress/content-proxy path.
pub async fn content_proxy_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let query = web::Query::<HashMap<String, String>>::from_query(req.query_string())
        .map_err(|e| AppError::bad_request(format!("invalid proxy query: {e}")))?
        .into_inner();
    let range = RangeSpec::from_header(
        req.headers()
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok()),
    )?;
    let api_password = state
        .config()
        .auth
        .api_password
        .as_ref()
        .map(|secret| secret.expose())
        .unwrap_or_default();
    let token_secret = state
        .config()
        .auth
        .proxy_auth
        .first()
        .and_then(|entry| entry.split_once(':').map(|(_, pass)| pass))
        .unwrap_or(api_password);
    let codec = ProxyCodec::from_secrets(api_password, token_secret);
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let is_head = req.method() == actix_web::http::Method::HEAD;
    let cacheability = match query.get("cached").map(|v| v.as_str()) {
        Some("1") | Some("true") | Some("yes") => Cacheability::Cached,
        _ => Cacheability::Uncached,
    };
    let user = query.get("user").map(String::as_str).unwrap_or("anonymous");
    let limit_placeholder = query
        .get("limit_placeholder")
        .map(String::as_str)
        .unwrap_or("/limit-reached");
    let config = ContentProxyConfig::default();

    // Extract `r_*` query parameters as upstream request headers (MediaFusion
    // convention: `r_Content-Type=video/mp4` → upstream header
    // `Content-Type: video/mp4`).
    let r_headers: BTreeMap<String, String> = query
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix("r_")
                .map(|name| (name.to_string(), v.clone()))
        })
        .collect();

    // When a raw URL is passed in `d` (not encrypted), attach any `r_*` headers
    // directly to the resolved target via the content proxy request. The
    // `resolve_target` function handles encrypted `d` and `token` params; for
    // raw URLs, we pass the headers separately.
    let d_value = query.get("d").map(String::as_str);

    serve(
        state.egress(),
        &codec,
        state.content_connections(),
        &config,
        &state.config().prebuffer,
        ContentProxyRequest {
            user,
            token: query.get("token").map(String::as_str),
            d: d_value,
            extra_headers: r_headers,
            range,
            is_head,
            client_ip: client_ip(&req),
            now_unix_secs,
            cacheability,
            limit_placeholder,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::encryption::ProxyPayload;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::errors::ErrorCategory;
    use crate::proxy::source::ContentRange;
    use actix_web::body::to_bytes;
    use bytes::Bytes;
    use futures::stream;
    use std::net::IpAddr;
    use wiremock::matchers::{header as match_header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const API_PASSWORD: &str = "content-proxy-api-password";
    const STREMTHRU_SECRET: &str = "content-proxy-stremthru-secret";

    fn codec() -> ProxyCodec {
        ProxyCodec::from_secrets(API_PASSWORD, STREMTHRU_SECRET)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A `FailOpen` `OutboundClient` with no tunnel: the egress decision is
    /// "dial untunneled", so a [`DirectSource`] reaches the in-process wiremock
    /// origin directly — exercising the real open/relay path with no network
    /// dependency (mirrors the `proxy::core` tests).
    fn outbound_fail_open() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    /// Helper: build an [`UpstreamBody`] from parts for response-shaping tests.
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

    fn token_for(codec: &ProxyCodec, payload: &ProxyPayload) -> String {
        match codec.encode_token(payload).unwrap() {
            crate::proxylink::ProxyLink::Token { token } => token,
            _ => unreachable!(),
        }
    }

    fn request<'a>(
        user: &'a str,
        token: Option<&'a str>,
        range: RangeSpec,
        limit_placeholder: &'a str,
    ) -> ContentProxyRequest<'a> {
        ContentProxyRequest {
            user,
            token,
            d: None,
            extra_headers: BTreeMap::new(),
            range,
            is_head: false,
            client_ip: None,
            now_unix_secs: 0,
            cacheability: Cacheability::Uncached,
            limit_placeholder,
        }
    }

    // -- Req 19.1: resolve token -> upstream link + headers + tunnel type ----

    #[test]
    fn resolve_target_recovers_link_headers_filename_and_tunnel() {
        let codec = codec();
        let mut payload = ProxyPayload::new("https://cdn.example.com/movie.mkv");
        payload
            .headers
            .insert("Referer".to_string(), "https://example.com/".to_string());
        payload.filename = Some("movie.mkv".to_string());
        let token = token_for(&codec, &payload);

        let target = resolve_target(
            &codec,
            Some(&token),
            None,
            None,
            0,
            &ContentProxyConfig::default(),
        )
        .expect("token resolves");

        assert_eq!(target.url, "https://cdn.example.com/movie.mkv");
        assert_eq!(
            target.headers.get("Referer").unwrap(),
            "https://example.com/"
        );
        assert_eq!(target.filename.as_deref(), Some("movie.mkv"));
        // No per-host override → Full tunnel (proxy bytes).
        assert_eq!(target.tunnel, TunnelMode::Full);
    }

    #[test]
    fn resolve_target_enforces_embedded_expiry() {
        // A past `exp` rejects with 403 (Req 14.5), surfaced through resolution.
        let codec = codec();
        let mut payload = ProxyPayload::new("https://cdn.example.com/v.mp4");
        payload.exp = Some(1_000);
        let token = token_for(&codec, &payload);

        let err = resolve_target(
            &codec,
            Some(&token),
            None,
            None,
            2_000,
            &ContentProxyConfig::default(),
        )
        .expect_err("expired link is forbidden");
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn resolve_target_enforces_embedded_ip_binding() {
        let codec = codec();
        let mut payload = ProxyPayload::new("https://cdn.example.com/v.mp4");
        payload.ip = Some(ip("203.0.113.7"));
        let token = token_for(&codec, &payload);

        // Mismatched client IP -> forbidden + ip_restricted (Req 14.6).
        let err = resolve_target(
            &codec,
            Some(&token),
            None,
            Some(ip("198.51.100.9")),
            0,
            &ContentProxyConfig::default(),
        )
        .expect_err("ip-bound link rejects a different client");
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.ip_restricted);

        // Matching client IP -> resolves.
        assert!(resolve_target(
            &codec,
            Some(&token),
            None,
            Some(ip("203.0.113.7")),
            0,
            &ContentProxyConfig::default(),
        )
        .is_ok());
    }

    #[test]
    fn resolve_target_picks_per_host_tunnel_mode() {
        // A host configured api-only resolves to ApiOnly (Req 19.6).
        let codec = codec();
        let payload = ProxyPayload::new("https://api-only.example.com/file.mkv");
        let token = token_for(&codec, &payload);

        let mut config = ContentProxyConfig::default();
        config
            .tunnel_modes
            .insert("api-only.example.com".to_string(), TunnelMode::ApiOnly);

        let target = resolve_target(&codec, Some(&token), None, None, 0, &config).unwrap();
        assert_eq!(target.tunnel, TunnelMode::ApiOnly);
    }

    // -- Req 19.1/19.2: proxy via streaming core with 200/206 + Content-Range -

    #[actix_web::test]
    async fn serve_full_body_streams_200_with_content_length() {
        let server = MockServer::start().await;
        let payload = b"full content-proxy body".to_vec();
        Mock::given(method("GET"))
            .and(path("/movie.mkv"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "video/mp4")
                    .insert_header("Accept-Ranges", "bytes")
                    .set_body_bytes(payload.clone()),
            )
            .mount(&server)
            .await;

        let codec = codec();
        let url = format!("{}/movie.mkv", server.uri());
        let token = token_for(&codec, &ProxyPayload::new(&url));
        let registry = Arc::new(ConnectionRegistry::new());

        let resp = serve(
            &outbound_fail_open(),
            &codec,
            &registry,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            request("alice", Some(&token), RangeSpec::Full, "/placeholder"),
        )
        .await
        .expect("serve ok");

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_LENGTH).unwrap(),
            payload.len().to_string().as_str(),
        );
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&bytes[..], &payload[..]);
    }

    #[actix_web::test]
    async fn serve_range_request_relays_206_and_content_range() {
        let server = MockServer::start().await;
        let partial = b"PARTIAL-BYTES".to_vec();
        Mock::given(method("GET"))
            .and(path("/movie.mkv"))
            .and(match_header("range", "bytes=100-199"))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header("Content-Type", "video/mp4")
                    .insert_header("Content-Range", "bytes 100-199/1000")
                    .set_body_bytes(partial.clone()),
            )
            .mount(&server)
            .await;

        let codec = codec();
        let url = format!("{}/movie.mkv", server.uri());
        let token = token_for(&codec, &ProxyPayload::new(&url));
        let registry = Arc::new(ConnectionRegistry::new());

        let resp = serve(
            &outbound_fail_open(),
            &codec,
            &registry,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            request(
                "alice",
                Some(&token),
                RangeSpec::Inclusive(100, 199),
                "/placeholder",
            ),
        )
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

    // -- Req 19.3: embedded per-user headers applied upstream ----------------

    #[actix_web::test]
    async fn serve_applies_embedded_per_user_headers() {
        let server = MockServer::start().await;
        // Only matches when the embedded Referer header was forwarded upstream.
        Mock::given(method("GET"))
            .and(path("/secured.mkv"))
            .and(match_header("referer", "https://example.com/"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".to_vec()))
            .mount(&server)
            .await;

        let codec = codec();
        let url = format!("{}/secured.mkv", server.uri());
        let mut payload = ProxyPayload::new(&url);
        payload
            .headers
            .insert("Referer".to_string(), "https://example.com/".to_string());
        let token = token_for(&codec, &payload);
        let registry = Arc::new(ConnectionRegistry::new());

        let resp = serve(
            &outbound_fail_open(),
            &codec,
            &registry,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            request("alice", Some(&token), RangeSpec::Full, "/placeholder"),
        )
        .await
        .expect("serve ok");

        // A 200 proves the embedded header matched at the upstream (Req 19.3).
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn btree_headers_convert_to_headermap_skipping_invalid() {
        let mut headers = BTreeMap::new();
        headers.insert("Referer".to_string(), "https://example.com/".to_string());
        headers.insert("X-Custom".to_string(), "value".to_string());
        // An invalid header name is skipped, not fatal.
        headers.insert("Bad Name".to_string(), "v".to_string());

        let map = btree_headers_to_headermap(&headers);
        assert_eq!(
            map.get("referer").unwrap().to_str().unwrap(),
            "https://example.com/"
        );
        assert_eq!(map.get("x-custom").unwrap().to_str().unwrap(), "value");
        assert!(map.get("bad name").is_none());
    }

    // -- Req 19.4: at the cap -> redirect to placeholder, no upstream open ---

    #[actix_web::test]
    async fn serve_redirects_to_placeholder_when_at_connection_cap() {
        let codec = codec();
        // A bogus upstream URL: if the proxy ever opened it the test would fail,
        // proving the cap short-circuits before any upstream connection.
        let token = token_for(
            &codec,
            &ProxyPayload::new("https://must-not-dial.example/x.mkv"),
        );
        let registry = Arc::new(ConnectionRegistry::new());
        let config = ContentProxyConfig {
            max_connections_per_user: 1,
            ..ContentProxyConfig::default()
        };

        // Occupy the user's single slot.
        let _g = registry.try_acquire("alice", 1).expect("first slot");
        assert_eq!(registry.active_connections("alice"), 1);

        let resp = serve(
            &outbound_fail_open(),
            &codec,
            &registry,
            &config,
            &PrebufferConfig::default(),
            request("alice", Some(&token), RangeSpec::Full, "/limit-reached"),
        )
        .await
        .expect("serve returns the redirect");

        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "/limit-reached",
        );
        // The held slot is unchanged — no new connection was opened (Req 19.4).
        assert_eq!(registry.active_connections("alice"), 1);
    }

    #[test]
    fn limit_reached_redirect_targets_the_placeholder() {
        let resp = limit_reached_redirect("/limit-reached");
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "/limit-reached",
        );
    }

    // -- Req 19.4/19.5: registry cap + RAII increment/decrement --------------

    #[test]
    fn registry_acquire_increments_and_rejects_at_cap() {
        let registry = Arc::new(ConnectionRegistry::new());
        let max = 2;

        let _g1 = registry.try_acquire("user-a", max).expect("first ok");
        let _g2 = registry.try_acquire("user-a", max).expect("second ok");
        assert_eq!(registry.active_connections("user-a"), 2);

        // At the cap -> None (the caller redirects to the placeholder).
        assert!(registry.try_acquire("user-a", max).is_none());
        assert_eq!(registry.active_connections("user-a"), 2);
    }

    #[test]
    fn conn_guard_decrements_on_drop() {
        let registry = Arc::new(ConnectionRegistry::new());
        let max = 1;

        let guard = registry.try_acquire("user-b", max).expect("acquire ok");
        assert_eq!(registry.active_connections("user-b"), 1);

        drop(guard); // RAII decrement (Req 19.5).
        assert_eq!(registry.active_connections("user-b"), 0);

        // Can acquire again after the slot is released.
        let _g = registry.try_acquire("user-b", max).expect("re-acquire ok");
        assert_eq!(registry.active_connections("user-b"), 1);
    }

    #[test]
    fn different_users_have_independent_caps() {
        let registry = Arc::new(ConnectionRegistry::new());
        let max = 1;

        let _alice = registry.try_acquire("alice", max).expect("alice ok");
        let _bob = registry.try_acquire("bob", max).expect("bob independent");

        assert!(registry.try_acquire("alice", max).is_none());
        assert!(registry.try_acquire("bob", max).is_none());
        assert_eq!(registry.active_connections("alice"), 1);
        assert_eq!(registry.active_connections("bob"), 1);
    }

    #[test]
    fn zero_max_is_unlimited() {
        let registry = Arc::new(ConnectionRegistry::new());
        let mut guards = Vec::new();
        for _ in 0..100 {
            guards.push(registry.try_acquire("user-c", 0).expect("unlimited"));
        }
        assert_eq!(registry.active_connections("user-c"), 100);
    }

    #[actix_web::test]
    async fn serve_holds_then_releases_the_slot_across_the_stream() {
        // After a successful serve + full body drain, the per-user slot is
        // released (the guard held across the stream is dropped — Req 19.5).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v.mkv"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"abcdefgh".to_vec()))
            .mount(&server)
            .await;

        let codec = codec();
        let url = format!("{}/v.mkv", server.uri());
        let token = token_for(&codec, &ProxyPayload::new(&url));
        let registry = Arc::new(ConnectionRegistry::new());
        let config = ContentProxyConfig {
            max_connections_per_user: 2,
            ..ContentProxyConfig::default()
        };

        let resp = serve(
            &outbound_fail_open(),
            &codec,
            &registry,
            &config,
            &PrebufferConfig::default(),
            request("alice", Some(&token), RangeSpec::Full, "/placeholder"),
        )
        .await
        .expect("serve ok");

        // While the response body is unconsumed, the slot is held (Req 19.5).
        assert_eq!(registry.active_connections("alice"), 1);

        // Draining the body to completion drops the guard, releasing the slot.
        let _ = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(registry.active_connections("alice"), 0);
    }

    // -- Req 19.6: api-only tunnel mode returns the direct link --------------

    #[actix_web::test]
    async fn serve_api_only_returns_direct_link_without_proxying() {
        let codec = codec();
        let direct = "https://api-only.example.com/direct.mkv";
        let token = token_for(&codec, &ProxyPayload::new(direct));
        let registry = Arc::new(ConnectionRegistry::new());

        let mut config = ContentProxyConfig::default();
        config
            .tunnel_modes
            .insert("api-only.example.com".to_string(), TunnelMode::ApiOnly);

        let resp = serve(
            &outbound_fail_open(),
            &codec,
            &registry,
            &config,
            &PrebufferConfig::default(),
            request("alice", Some(&token), RangeSpec::Full, "/placeholder"),
        )
        .await
        .expect("api-only serve returns the direct link");

        // 302 to the direct link; no upstream byte proxying (Req 19.6).
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            direct,
        );
        // No connection slot was consumed for an api-only target.
        assert_eq!(registry.active_connections("alice"), 0);
    }

    #[test]
    fn api_only_redirect_targets_the_direct_link() {
        let resp = api_only_redirect("https://cdn.example.com/direct.mkv");
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "https://cdn.example.com/direct.mkv",
        );
    }

    // -- Req 19.7: distinct cached / uncached stale times --------------------

    #[test]
    fn config_applies_distinct_cached_and_uncached_stale_times() {
        let config = ContentProxyConfig {
            cached_stale_secs: 7200,
            uncached_stale_secs: 30,
            ..ContentProxyConfig::default()
        };
        assert_eq!(config.stale_secs(Cacheability::Cached), 7200);
        assert_eq!(config.stale_secs(Cacheability::Uncached), 30);
        assert_ne!(
            config.stale_secs(Cacheability::Cached),
            config.stale_secs(Cacheability::Uncached),
            "cached and uncached stale times must be distinct (Req 19.7)"
        );
        assert_eq!(
            config.cache_control_value(Cacheability::Cached),
            "public, max-age=7200"
        );
        assert_eq!(
            config.cache_control_value(Cacheability::Uncached),
            "public, max-age=30"
        );
    }

    #[actix_web::test]
    async fn response_cache_control_reflects_cacheability() {
        let config = ContentProxyConfig {
            cached_stale_secs: 7200,
            uncached_stale_secs: 30,
            ..ContentProxyConfig::default()
        };

        // Cached content -> cached stale time.
        let cached = make_body(200, Some(4), None, Some("video/mp4"), true, vec![]);
        let resp = build_content_proxy_response(
            cached,
            false,
            None,
            Cacheability::Cached,
            &config,
            &PrebufferConfig::default(),
            None,
        )
        .expect("build ok");
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "public, max-age=7200",
        );

        // Uncached content -> uncached stale time.
        let uncached = make_body(200, Some(4), None, Some("video/mp4"), true, vec![]);
        let resp = build_content_proxy_response(
            uncached,
            false,
            None,
            Cacheability::Uncached,
            &config,
            &PrebufferConfig::default(),
            None,
        )
        .expect("build ok");
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "public, max-age=30",
        );
    }

    // -- Req 19.8: Content-Disposition filename when specified ---------------

    #[actix_web::test]
    async fn content_disposition_set_when_filename_specified() {
        let body = make_body(200, Some(100), None, None, false, vec![]);
        let resp = build_content_proxy_response(
            body,
            false,
            Some("movie.mkv"),
            Cacheability::Uncached,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            None,
        )
        .expect("build ok");

        assert_eq!(
            resp.headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap(),
            "attachment; filename=\"movie.mkv\"",
        );
    }

    #[actix_web::test]
    async fn no_content_disposition_when_no_filename() {
        let body = make_body(200, Some(100), None, None, false, vec![]);
        let resp = build_content_proxy_response(
            body,
            false,
            None,
            Cacheability::Uncached,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            None,
        )
        .expect("build ok");
        assert!(resp.headers().get(header::CONTENT_DISPOSITION).is_none());
    }

    #[actix_web::test]
    async fn content_disposition_filename_is_sanitized() {
        // Control characters and quotes are stripped so the value cannot inject
        // additional header content (Req 19.8).
        let body = make_body(200, Some(100), None, None, false, vec![]);
        let resp = build_content_proxy_response(
            body,
            false,
            Some("ev\"il\r\n.mkv"),
            Cacheability::Uncached,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            None,
        )
        .expect("build ok");
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap(),
            "attachment; filename=\"evil.mkv\"",
        );
    }

    #[actix_web::test]
    async fn serve_sets_content_disposition_from_proxy_link_filename() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/f.mkv"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"data".to_vec()))
            .mount(&server)
            .await;

        let codec = codec();
        let url = format!("{}/f.mkv", server.uri());
        let mut payload = ProxyPayload::new(&url);
        payload.filename = Some("My Movie.mkv".to_string());
        let token = token_for(&codec, &payload);
        let registry = Arc::new(ConnectionRegistry::new());

        let resp = serve(
            &outbound_fail_open(),
            &codec,
            &registry,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            request("alice", Some(&token), RangeSpec::Full, "/placeholder"),
        )
        .await
        .expect("serve ok");

        assert_eq!(
            resp.headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap(),
            "attachment; filename=\"My Movie.mkv\"",
        );
    }

    // -- HEAD request: headers only, no body, guard released -----------------

    #[actix_web::test]
    async fn head_request_returns_headers_without_body() {
        let body = make_body(200, Some(5000), None, Some("video/mp4"), true, vec![]);
        let registry = Arc::new(ConnectionRegistry::new());
        let guard = registry.try_acquire("alice", 0).unwrap();
        assert_eq!(registry.active_connections("alice"), 1);

        let resp = build_content_proxy_response(
            body,
            true,
            Some("video.mp4"),
            Cacheability::Cached,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            Some(guard),
        )
        .expect("HEAD ok");

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "5000",
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes",
        );
        // The guard is dropped for a HEAD response (no body to hold it).
        assert_eq!(registry.active_connections("alice"), 0);
    }

    // -- Non-success upstream status maps to a typed error -------------------

    #[actix_web::test]
    async fn non_success_upstream_status_maps_to_error() {
        let body = make_body(404, None, None, None, false, vec![]);
        let err = build_content_proxy_response(
            body,
            false,
            None,
            Cacheability::Uncached,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            None,
        )
        .expect_err("404 is an error");
        assert_eq!(err.category, ErrorCategory::NotFound);
        assert_eq!(err.upstream_status, Some(404));

        let body = make_body(503, None, None, None, false, vec![]);
        let err = build_content_proxy_response(
            body,
            false,
            None,
            Cacheability::Uncached,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            None,
        )
        .expect_err("503 is an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(503));
    }

    // -- Content-Range with unknown total uses `*` ---------------------------

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
        let resp = build_content_proxy_response(
            body,
            false,
            None,
            Cacheability::Uncached,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            None,
        )
        .expect("206 ok");
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 0-99/*",
        );
    }

    // -- A bad upstream URL in the proxy link is a bad request ---------------

    #[actix_web::test]
    async fn serve_rejects_invalid_upstream_url() {
        let codec = codec();
        // "not a url" parses with no host; build the source step fails closed.
        let token = token_for(&codec, &ProxyPayload::new("not a url"));
        let registry = Arc::new(ConnectionRegistry::new());

        let err = serve(
            &outbound_fail_open(),
            &codec,
            &registry,
            &ContentProxyConfig::default(),
            &PrebufferConfig::default(),
            request("alice", Some(&token), RangeSpec::Full, "/placeholder"),
        )
        .await
        .expect_err("an invalid upstream URL is a bad request");
        assert_eq!(err.category, ErrorCategory::BadRequest);
        // The slot acquired for the attempt was released on the error path.
        assert_eq!(registry.active_connections("alice"), 0);
    }
}
