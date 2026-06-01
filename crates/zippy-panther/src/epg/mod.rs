//! EPG / XMLTV proxy (`epg`) — Req 8.
//!
//! [`EpgProxy`] fetches an upstream XMLTV document and returns its body
//! **unchanged** (Req 8.1), optionally serving it from a TTL cache and
//! advertising the cache outcome through the `X-EPG-Cache` response header
//! (`HIT`/`MISS`, Req 8.2–8.4). All upstream I/O goes through the single egress
//! seam ([`OutboundClient`](crate::egress::OutboundClient)) so every fetch is
//! tunnelled and carries no client-identifying header (Req 51.1–51.3).
//!
//! ## Behaviour (design: Components → EPG)
//!
//! * **Body unchanged (Req 8.1):** the upstream XMLTV bytes are returned
//!   verbatim; the upstream `Content-Type` is preserved on the response and
//!   across the cache.
//! * **Cache HIT (Req 8.2):** when the EPG cache TTL is `> 0` and unexpired
//!   cached data for the resolved upstream URL exists, it is served with
//!   `X-EPG-Cache: HIT` and **no** upstream fetch.
//! * **Cache MISS (Req 8.3):** with no unexpired cache, the document is fetched
//!   upstream, cached for the configured TTL, and returned with
//!   `X-EPG-Cache: MISS`.
//! * **TTL == 0 (Req 8.4):** caching is disabled — every request fetches
//!   upstream and is `X-EPG-Cache: MISS`; nothing is read from or written to
//!   the cache.
//! * **Custom headers (Req 8.5):** `h_<Name>` query parameters become `<Name>`
//!   request headers on the upstream fetch (see [`parse_header_params`]).
//! * **URL decoding (Req 8.6):** the upstream URL may be supplied plain or
//!   base64-encoded; [`decode_upstream_url`] decodes the base64 form before
//!   fetching and uses a plain URL directly.
//! * **Upstream failure (Req 8.7):** a network error or non-2xx upstream
//!   surfaces a typed [`AppError`] carrying the upstream HTTP status when one
//!   was received.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::Method;
use url::Url;

use crate::cache::CacheBackend;
use crate::config::EpgConfig;
use crate::egress::OutboundClient;
use crate::errors::AppError;

/// The response header that advertises the EPG cache outcome (Req 8.2–8.4).
pub const X_EPG_CACHE_HEADER: &str = "X-EPG-Cache";

/// The maximum upstream XMLTV body buffered, guarding against a hostile /
/// runaway upstream. EPG documents are large but bounded; this cap keeps a
/// single fetch from exhausting memory on a small VPS while comfortably
/// admitting real-world combined guides.
const MAX_EPG_BYTES: usize = 256 * 1024 * 1024;

/// The cache outcome for an EPG response, rendered into the `X-EPG-Cache`
/// header (Req 8.2–8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpgCacheStatus {
    /// Served from unexpired cached data (Req 8.2).
    Hit,
    /// Fetched from upstream this request (Req 8.3, 8.4).
    Miss,
}

impl EpgCacheStatus {
    /// The `X-EPG-Cache` header value for this outcome (`"HIT"` / `"MISS"`).
    pub fn header_value(self) -> &'static str {
        match self {
            EpgCacheStatus::Hit => "HIT",
            EpgCacheStatus::Miss => "MISS",
        }
    }
}

/// A proxied EPG document plus the cache outcome to advertise (Req 8.1–8.4).
#[derive(Debug, Clone)]
pub struct EpgResponse {
    /// The XMLTV body, returned unchanged from upstream (Req 8.1).
    pub body: Bytes,
    /// The upstream `Content-Type`, preserved on the response and across the
    /// cache when one was received.
    pub content_type: Option<String>,
    /// Whether the body was served from cache (`HIT`) or freshly fetched
    /// (`MISS`) — drives the `X-EPG-Cache` header (Req 8.2–8.4).
    pub cache: EpgCacheStatus,
}

/// The EPG/XMLTV proxy: fetches upstream XMLTV through the egress seam and
/// caches it for the configured TTL (design: Components → EPG; Req 8).
#[derive(Clone)]
pub struct EpgProxy {
    /// The single outbound seam — the only path to the network (Req 51.1).
    client: Arc<OutboundClient>,
    /// The shared cache backend keyed by resolved upstream URL (Req 8.2, 8.3).
    cache: Arc<dyn CacheBackend>,
    /// The EPG cache TTL; `Duration::ZERO` disables caching (Req 8.4).
    cache_ttl: Duration,
}

impl EpgProxy {
    /// Build an [`EpgProxy`] over the shared egress client and cache backend
    /// with an explicit TTL (`Duration::ZERO` disables caching, Req 8.4).
    pub fn new(
        client: Arc<OutboundClient>,
        cache: Arc<dyn CacheBackend>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            client,
            cache,
            cache_ttl,
        }
    }

    /// Build an [`EpgProxy`] deriving the cache TTL from the [`EpgConfig`]
    /// (`cache_ttl_secs`).
    pub fn from_config(
        client: Arc<OutboundClient>,
        cache: Arc<dyn CacheBackend>,
        cfg: &EpgConfig,
    ) -> Self {
        Self::new(client, cache, Duration::from_secs(cfg.cache_ttl_secs))
    }

    /// Proxy an EPG request for `raw_url` (plain or base64, Req 8.6),
    /// forwarding the `h_<Name>`-derived `headers` upstream (Req 8.5).
    ///
    /// Honors the TTL cache: a `HIT` when unexpired cached data exists and the
    /// TTL is `> 0` (Req 8.2), otherwise a `MISS` that fetches upstream and
    /// caches the result for the TTL (Req 8.3); with `TTL == 0` it always
    /// fetches and never touches the cache (Req 8.4). The XMLTV body is
    /// returned unchanged (Req 8.1). An upstream failure surfaces a typed
    /// error carrying the upstream status when one was received (Req 8.7).
    pub async fn proxy(
        &self,
        raw_url: &str,
        headers: &BTreeMap<String, String>,
    ) -> Result<EpgResponse, AppError> {
        let url = decode_upstream_url(raw_url)?;
        let caching = !self.cache_ttl.is_zero();
        let cache_key = url.as_str();

        // Cache HIT path (Req 8.2): only when caching is enabled and unexpired
        // data exists. The cache backend already treats an expired entry as
        // absent (Req 30.4), so a `Some` here is present-and-unexpired.
        if caching {
            if let Some(cached) = self.cache.get(cache_key).await? {
                let (content_type, body) = decode_entry(cached);
                return Ok(EpgResponse {
                    body,
                    content_type,
                    cache: EpgCacheStatus::Hit,
                });
            }
        }

        // MISS path (Req 8.3, 8.4): fetch upstream, then cache for the TTL when
        // caching is enabled.
        let (body, content_type) = self.fetch_upstream(&url, headers).await?;
        if caching {
            self.cache
                .set(
                    cache_key,
                    encode_entry(content_type.as_deref(), &body),
                    self.cache_ttl,
                )
                .await?;
        }

        Ok(EpgResponse {
            body,
            content_type,
            cache: EpgCacheStatus::Miss,
        })
    }

    /// Fetch the upstream XMLTV body and its `Content-Type`, forwarding
    /// `headers` (Req 8.5) and returning the body unchanged (Req 8.1).
    ///
    /// A network error or non-2xx upstream surfaces an [`AppError`] carrying
    /// the upstream status when one was received (Req 8.7).
    async fn fetch_upstream(
        &self,
        url: &Url,
        headers: &BTreeMap<String, String>,
    ) -> Result<(Bytes, Option<String>), AppError> {
        let mut builder = self.client.upstream(Method::GET, url)?;
        let header_map = to_header_map(headers);
        if !header_map.is_empty() {
            builder = builder.headers(header_map);
        }

        let resp = builder.send().await.map_err(|e| map_send_error(url, e))?;

        // Upstream HTTP error → carry the upstream status (Req 8.7).
        let status = resp.status();
        if !status.is_success() {
            return Err(AppError::upstream_unavailable(format!(
                "upstream EPG request to {url} returned HTTP {}",
                status.as_u16()
            ))
            .with_upstream_status(status.as_u16()));
        }

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body = resp.bytes().await.map_err(|e| map_send_error(url, e))?;
        if body.len() > MAX_EPG_BYTES {
            return Err(AppError::payload_too_large(format!(
                "upstream EPG document from {url} exceeds {MAX_EPG_BYTES} bytes"
            )));
        }

        Ok((body, content_type))
    }
}

/// Extract the `h_<Name>` query parameters as `<Name>` upstream request
/// headers (Req 8.5).
///
/// Each `(key, value)` whose `key` begins with the `h_` prefix yields a header
/// named by the remainder of the key (e.g. `h_Referer=foo` → `Referer: foo`);
/// every other parameter is ignored. The result feeds the upstream fetch's
/// header map. Header names are matched case-insensitively by the HTTP layer,
/// so the suffix's case is preserved as supplied.
pub fn parse_header_params<I>(params: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut headers = BTreeMap::new();
    for (key, value) in params {
        if let Some(name) = key.strip_prefix("h_") {
            if !name.is_empty() {
                headers.insert(name.to_string(), value);
            }
        }
    }
    headers
}

/// Resolve the upstream XMLTV URL from its plain or base64-encoded form
/// (Req 8.6).
///
/// A base64-encoded URL (standard or URL-safe, padded or not) that decodes to
/// a valid `http`/`https` URL is decoded before fetching; otherwise the input
/// is parsed directly as the URL. A plain URL always contains a `:` scheme
/// delimiter (outside the base64 alphabet) so it never decodes as base64 and
/// is used as-is — the two forms can never be confused. An input that is
/// neither a base64-of-URL nor a valid `http`/`https` URL is a
/// [`bad_request`](AppError::bad_request).
pub fn decode_upstream_url(raw: &str) -> Result<Url, AppError> {
    let raw = raw.trim();

    // base64 form first: a plain URL fails to decode (the `:` scheme delimiter
    // is outside every base64 alphabet), so this never misfires on a plain URL.
    if let Some(url) = try_base64_to_url(raw) {
        return Ok(url);
    }

    Url::parse(raw)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .ok_or_else(|| AppError::bad_request(format!("invalid EPG upstream URL: {raw}")))
}

/// Attempt to interpret `raw` as a base64-encoded `http`/`https` URL.
///
/// Tries the standard and URL-safe alphabets in both padded and unpadded
/// forms; returns the decoded [`Url`] only when the bytes are valid UTF-8 and
/// parse as an `http`/`https` URL, so arbitrary base64 that does not decode to
/// a web URL is rejected here and the caller falls back to plain parsing.
fn try_base64_to_url(raw: &str) -> Option<Url> {
    use base64::engine::general_purpose::{
        GeneralPurpose, STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
    };
    use base64::Engine as _;

    let engines: [GeneralPurpose; 4] = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD];
    for engine in engines {
        let Ok(bytes) = engine.decode(raw) else {
            continue;
        };
        let Ok(decoded) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if let Ok(url) = Url::parse(decoded) {
            if matches!(url.scheme(), "http" | "https") {
                return Some(url);
            }
        }
    }
    None
}

/// Frame a cached EPG entry as `len(content_type)[u32 BE] || content_type ||
/// body` so the upstream `Content-Type` is preserved across the cache without
/// a separate key. An absent content type frames as a zero-length prefix.
fn encode_entry(content_type: Option<&str>, body: &Bytes) -> Bytes {
    let ct = content_type.unwrap_or("");
    let ct_bytes = ct.as_bytes();
    let mut buf = BytesMut::with_capacity(4 + ct_bytes.len() + body.len());
    buf.extend_from_slice(&(ct_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(ct_bytes);
    buf.extend_from_slice(body);
    buf.freeze()
}

/// Decode a cached entry framed by [`encode_entry`] back into its
/// `(content_type, body)`. A malformed frame (too short / inconsistent length)
/// degrades gracefully to "no content type, raw bytes as body" rather than
/// erroring, so a corrupt cache entry can never wedge EPG delivery.
fn decode_entry(raw: Bytes) -> (Option<String>, Bytes) {
    if raw.len() < 4 {
        return (None, raw);
    }
    let len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if 4 + len > raw.len() {
        return (None, raw);
    }
    let content_type = if len == 0 {
        None
    } else {
        std::str::from_utf8(&raw[4..4 + len])
            .ok()
            .map(|s| s.to_string())
    };
    let body = raw.slice(4 + len..);
    (content_type, body)
}

/// Convert a `name → value` header map into a `reqwest` [`HeaderMap`],
/// skipping any entry whose name or value is not a valid HTTP header. These
/// are `h_<Name>`-derived (never inbound client headers), so they carry no
/// client IP.
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

/// Map a `reqwest` send/read error onto the canonical taxonomy: a connect /
/// timeout / reset against an upstream is an `UpstreamUnavailable` (`503`,
/// Req 8.7), carrying the upstream status when the error surfaced one.
fn map_send_error(url: &Url, err: reqwest::Error) -> AppError {
    let host = url.host_str().unwrap_or("<unknown>");
    let app =
        AppError::upstream_unavailable(format!("upstream EPG request to {host} failed: {err}"));
    match err.status() {
        Some(status) => app.with_upstream_status(status.as_u16()),
        None => app,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::LocalCache;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::egress::CLIENT_IDENTIFYING_HEADERS;
    use crate::errors::ErrorCategory;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc as StdArc, Mutex};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An [`OutboundClient`] with no tunnel under the given policy (mirrors the
    /// `hls::fetch` test harness): `FailOpen` dials the in-process wiremock
    /// origin directly; `FailClosed` refuses with no dial.
    fn outbound(policy: EgressPolicy) -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    /// An [`EpgProxy`] over a fresh `LocalCache` with the given TTL.
    fn proxy_with(policy: EgressPolicy, ttl: Duration) -> EpgProxy {
        let cache: Arc<dyn CacheBackend> = Arc::new(LocalCache::new("epg-test"));
        EpgProxy::new(outbound(policy), cache, ttl)
    }

    const SAMPLE_XMLTV: &[u8] = b"<?xml version=\"1.0\"?>\n<tv><channel id=\"c1\"/></tv>\n";

    // -- Req 8.1: valid upstream URL fetched, body returned unchanged --------

    #[tokio::test]
    async fn fetches_upstream_and_returns_body_unchanged() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/epg.xml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/xml")
                    .set_body_bytes(SAMPLE_XMLTV.to_vec()),
            )
            .mount(&server)
            .await;

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::from_secs(3600));
        let resp = proxy
            .proxy(&format!("{}/epg.xml", server.uri()), &BTreeMap::new())
            .await
            .expect("EPG fetch succeeds");

        assert_eq!(
            &resp.body[..],
            SAMPLE_XMLTV,
            "body must be returned unchanged"
        );
        assert_eq!(resp.content_type.as_deref(), Some("application/xml"));
    }

    // -- Req 8.3: no cache -> fetch, cache, X-EPG-Cache: MISS ----------------

    #[tokio::test]
    async fn first_request_is_miss_and_caches() {
        let server = MockServer::start().await;
        let hits = StdArc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        Mock::given(method("GET"))
            .and(path("/epg.xml"))
            .respond_with(move |_req: &wiremock::Request| {
                hits_clone.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_bytes(SAMPLE_XMLTV.to_vec())
            })
            .mount(&server)
            .await;

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::from_secs(3600));
        let resp = proxy
            .proxy(&format!("{}/epg.xml", server.uri()), &BTreeMap::new())
            .await
            .expect("fetch succeeds");

        assert_eq!(resp.cache, EpgCacheStatus::Miss);
        assert_eq!(resp.cache.header_value(), "MISS");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "first request hits upstream"
        );
    }

    // -- Req 8.2: TTL>0 + present unexpired cache -> HIT, no upstream call ---

    #[tokio::test]
    async fn second_request_is_served_from_cache_hit() {
        let server = MockServer::start().await;
        let hits = StdArc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        Mock::given(method("GET"))
            .and(path("/epg.xml"))
            .respond_with(move |_req: &wiremock::Request| {
                hits_clone.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/xml")
                    .set_body_bytes(SAMPLE_XMLTV.to_vec())
            })
            .mount(&server)
            .await;

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::from_secs(3600));
        let url = format!("{}/epg.xml", server.uri());

        let first = proxy.proxy(&url, &BTreeMap::new()).await.unwrap();
        assert_eq!(first.cache, EpgCacheStatus::Miss);

        let second = proxy.proxy(&url, &BTreeMap::new()).await.unwrap();
        assert_eq!(second.cache, EpgCacheStatus::Hit);
        assert_eq!(second.cache.header_value(), "HIT");
        // Body + content type preserved across the cache (Req 8.1).
        assert_eq!(&second.body[..], SAMPLE_XMLTV);
        assert_eq!(second.content_type.as_deref(), Some("application/xml"));
        // The HIT served from cache: upstream was hit exactly once.
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "cache HIT must not re-fetch"
        );
    }

    // -- Req 8.4: TTL==0 -> fetch every request, always MISS, never cached ---

    #[tokio::test]
    async fn ttl_zero_always_misses_and_refetches() {
        let server = MockServer::start().await;
        let hits = StdArc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        Mock::given(method("GET"))
            .and(path("/epg.xml"))
            .respond_with(move |_req: &wiremock::Request| {
                hits_clone.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_bytes(SAMPLE_XMLTV.to_vec())
            })
            .mount(&server)
            .await;

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::ZERO);
        let url = format!("{}/epg.xml", server.uri());

        for _ in 0..3 {
            let resp = proxy.proxy(&url, &BTreeMap::new()).await.unwrap();
            assert_eq!(resp.cache, EpgCacheStatus::Miss, "TTL=0 is always MISS");
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "TTL=0 fetches upstream on every request",
        );
    }

    // -- Req 8.5: h_<Name> query params forwarded as <Name> headers ----------

    #[tokio::test]
    async fn forwards_h_prefixed_headers_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/epg.xml"))
            .and(header("x-api-key", "secret"))
            .and(header("referer", "https://guide.example/"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(SAMPLE_XMLTV.to_vec()))
            .mount(&server)
            .await;

        let params = vec![
            ("h_X-API-Key".to_string(), "secret".to_string()),
            (
                "h_Referer".to_string(),
                "https://guide.example/".to_string(),
            ),
            // Non-`h_` params are ignored.
            ("api_password".to_string(), "ignored".to_string()),
        ];
        let headers = parse_header_params(params);

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::from_secs(3600));
        let resp = proxy
            .proxy(&format!("{}/epg.xml", server.uri()), &headers)
            .await
            .expect("forwarded headers must match the upstream mock");
        assert_eq!(&resp.body[..], SAMPLE_XMLTV);
    }

    #[test]
    fn parse_header_params_extracts_only_h_prefixed() {
        let params = vec![
            ("h_Referer".to_string(), "r".to_string()),
            ("h_".to_string(), "empty-name".to_string()),
            ("url".to_string(), "u".to_string()),
            ("h_User-Agent".to_string(), "ua".to_string()),
        ];
        let headers = parse_header_params(params);
        assert_eq!(headers.get("Referer").map(String::as_str), Some("r"));
        assert_eq!(headers.get("User-Agent").map(String::as_str), Some("ua"));
        assert_eq!(headers.len(), 2, "empty-name and non-h_ params dropped");
    }

    // -- Req 8.6: base64-encoded upstream URL decoded before fetching --------

    #[tokio::test]
    async fn base64_encoded_upstream_url_is_decoded_before_fetching() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/epg.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(SAMPLE_XMLTV.to_vec()))
            .mount(&server)
            .await;

        let plain = format!("{}/epg.xml", server.uri());
        let encoded = STANDARD.encode(&plain);

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::from_secs(3600));
        let resp = proxy
            .proxy(&encoded, &BTreeMap::new())
            .await
            .expect("base64 URL must be decoded and fetched");
        assert_eq!(&resp.body[..], SAMPLE_XMLTV);
    }

    #[test]
    fn decode_upstream_url_handles_plain_and_base64() {
        let plain = "https://guide.example/epg.xml";
        // Plain used directly.
        assert_eq!(decode_upstream_url(plain).unwrap().as_str(), plain);

        // base64 (standard + url-safe-no-pad) decodes to the same URL.
        let std_enc = STANDARD.encode(plain);
        assert_eq!(decode_upstream_url(&std_enc).unwrap().as_str(), plain);
        let url_enc = URL_SAFE_NO_PAD.encode(plain);
        assert_eq!(decode_upstream_url(&url_enc).unwrap().as_str(), plain);
    }

    #[test]
    fn decode_upstream_url_rejects_garbage() {
        let err = decode_upstream_url("not a url at all !!!").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    // -- Req 8.7: upstream failure carries the upstream HTTP status ----------

    #[tokio::test]
    async fn upstream_http_error_carries_upstream_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing.xml"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::from_secs(3600));
        let err = proxy
            .proxy(&format!("{}/missing.xml", server.uri()), &BTreeMap::new())
            .await
            .expect_err("a 502 upstream must surface as an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(
            err.upstream_status,
            Some(502),
            "must carry the upstream status"
        );
    }

    #[tokio::test]
    async fn upstream_failure_is_not_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/epg.xml"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::from_secs(3600));
        let url = format!("{}/epg.xml", server.uri());
        assert!(proxy.proxy(&url, &BTreeMap::new()).await.is_err());
        // A second request still errors (nothing poisoned the cache).
        assert!(proxy.proxy(&url, &BTreeMap::new()).await.is_err());
    }

    // -- Req 51.1: all fetches go through the egress seam (fail-closed) ------

    #[tokio::test]
    async fn fetch_is_gated_by_fail_closed_egress() {
        let proxy = proxy_with(EgressPolicy::FailClosed, Duration::from_secs(3600));
        let err = proxy
            .proxy("https://guide.example/epg.xml", &BTreeMap::new())
            .await
            .expect_err("fail-closed egress must refuse the EPG dial");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("egress tunnel"));
    }

    // -- Req 51.2/51.3: derived requests carry no client-identifying header --

    #[tokio::test]
    async fn fetch_carries_no_client_identifying_headers() {
        let server = MockServer::start().await;
        let seen: StdArc<Mutex<Vec<String>>> = StdArc::new(Mutex::new(Vec::new()));
        let seen_clone = seen.clone();
        Mock::given(method("GET"))
            .and(path("/epg.xml"))
            .respond_with(move |req: &wiremock::Request| {
                let mut names = seen_clone.lock().unwrap();
                for h in req.headers.iter() {
                    names.push(h.0.as_str().to_ascii_lowercase());
                }
                ResponseTemplate::new(200).set_body_bytes(SAMPLE_XMLTV.to_vec())
            })
            .mount(&server)
            .await;

        let proxy = proxy_with(EgressPolicy::FailOpen, Duration::from_secs(3600));
        let _ = proxy
            .proxy(&format!("{}/epg.xml", server.uri()), &BTreeMap::new())
            .await
            .expect("fetch succeeds");

        let names = seen.lock().unwrap();
        for forbidden in CLIENT_IDENTIFYING_HEADERS {
            assert!(
                !names.iter().any(|n| n == forbidden),
                "EPG request must not carry client-identifying header {forbidden}; saw {names:?}",
            );
        }
    }

    // -- Cache framing round trip preserves content type + body --------------

    #[test]
    fn cache_entry_framing_round_trips() {
        let body = Bytes::from_static(b"<tv></tv>");
        let framed = encode_entry(Some("application/xml"), &body);
        let (ct, decoded) = decode_entry(framed);
        assert_eq!(ct.as_deref(), Some("application/xml"));
        assert_eq!(decoded, body);

        // No content type frames as zero-length and round-trips to None.
        let framed_none = encode_entry(None, &body);
        let (ct_none, decoded_none) = decode_entry(framed_none);
        assert_eq!(ct_none, None);
        assert_eq!(decoded_none, body);
    }
}
