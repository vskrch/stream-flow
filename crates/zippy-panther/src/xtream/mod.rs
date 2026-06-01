//! Xtream Codes IPTV stateless proxy (`xtream`) — Req 9.
//!
//! A drop-in proxy for an Xtream Codes IPTV panel. It forwards the three panel
//! API endpoints and resolves the panel's short stream URLs, **statelessly**:
//! every upstream target is derived from the incoming request (its path +
//! query) plus the configured upstream base, with no per-session state stored
//! anywhere (Req 9.5; design: Components → Xtream).
//!
//! ## What it does
//!
//! * **`player_api.php`** (Req 9.1) — forwards the request (preserving the
//!   query string) to the configured Xtream upstream and returns the upstream
//!   JSON response.
//! * **`xmltv.php`** (Req 9.2) — forwards and returns the upstream XMLTV.
//! * **`get.php`** (Req 9.3) — forwards and returns the upstream playlist;
//!   because a playlist enumerates stream URLs, every upstream stream URL in
//!   the body is rewritten to route back through this proxy (Req 9.6).
//! * **short stream URL** (Req 9.4) — a
//!   `/proxy/xtream/stream/{cat}/{user}/{pass}/…/{id}.{ext}` request is parsed
//!   back into a [`XtreamStreamRef`](stream_url::XtreamStreamRef), resolved to
//!   the upstream stream URL, and proxied through the generic ranged streaming
//!   core (so seeking / `Range` work).
//!
//! ## Statelessness + isolation
//!
//! The proxy holds only the immutable configured upstream base (and the public
//! proxy base for rewriting). Every request derives its own upstream target, so
//! the same [`XtreamProxy`] serves any account/stream with no shared mutable
//! state (Req 9.5). All upstream HTTP goes through the single
//! [`egress::OutboundClient`](crate::egress::OutboundClient) seam, so upstreams
//! observe only the Egress_IP and never a user's Client_IP (Req 51).
//!
//! ## Error propagation (Req 9.7)
//!
//! When the upstream returns an authentication failure (or any error status)
//! for an API endpoint, the proxy **propagates the upstream status and body**
//! to the client verbatim via [`UpstreamResponse`], rather than collapsing it
//! onto a generic error — an IPTV client must see the panel's own `401`/`403`
//! body to react correctly.

pub mod stream_url;

use std::sync::Arc;

use actix_web::http::header;
use actix_web::{web, HttpRequest, HttpResponse};
use reqwest::Method;
use url::Url;

use crate::app::AppState;
use crate::config::{PrebufferConfig, XtreamConfig};
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::DirectSource;
use crate::proxy::{self};

use self::stream_url::{parse_stream_tail, rewrite_playlist, stream_tail_from_path};

/// The three forwarded Xtream panel API endpoints (Req 9.1–9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiEndpoint {
    /// `player_api.php` — JSON panel API (Req 9.1).
    PlayerApi,
    /// `xmltv.php` — XMLTV EPG (Req 9.2).
    Xmltv,
    /// `get.php` — M3U playlist (Req 9.3); its body is URL-rewritten (Req 9.6).
    Get,
}

impl ApiEndpoint {
    /// The upstream path (relative to the base) for this endpoint.
    fn upstream_path(self) -> &'static str {
        match self {
            ApiEndpoint::PlayerApi => "player_api.php",
            ApiEndpoint::Xmltv => "xmltv.php",
            ApiEndpoint::Get => "get.php",
        }
    }
}

/// A captured upstream response: the status, content type, and raw body, ready
/// to be relayed to the client verbatim (Req 9.1–9.3, 9.7).
///
/// The whole body is buffered because the API endpoints return small documents
/// (JSON / XMLTV / a playlist) and `get.php` must be rewritten in full before
/// it is sent (Req 9.6) — distinct from the short-stream path, which streams
/// through the bounded relay core.
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    /// The upstream HTTP status, propagated to the client (Req 9.7).
    pub status: u16,
    /// The upstream `Content-Type`, when present, propagated unchanged.
    pub content_type: Option<String>,
    /// The raw upstream body.
    pub body: Vec<u8>,
}

impl UpstreamResponse {
    /// Render this captured upstream response as an actix [`HttpResponse`],
    /// propagating the status, content type, and body verbatim (Req 9.1–9.3,
    /// 9.7).
    pub fn into_http_response(self) -> HttpResponse {
        let status = actix_web::http::StatusCode::from_u16(self.status)
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
        let mut builder = HttpResponse::build(status);
        if let Some(ct) = &self.content_type {
            builder.insert_header((header::CONTENT_TYPE, ct.clone()));
        }
        builder.body(self.body)
    }
}

/// The stateless Xtream Codes proxy (Req 9).
///
/// Holds only immutable configuration: the upstream panel base, the public
/// proxy base used to rewrite stream URLs (Req 9.6), and the single outbound
/// seam (Req 51). Every request derives its own upstream target from the
/// incoming request, so there is no per-session state (Req 9.5).
#[derive(Clone)]
pub struct XtreamProxy {
    /// The configured upstream Xtream panel base URL (no trailing slash).
    base_url: String,
    /// The public base for rewritten proxy URLs (no trailing slash).
    proxy_base: String,
    /// The single outbound seam — the only path to the network (Req 51.1).
    egress: Arc<OutboundClient>,
}

impl XtreamProxy {
    /// Build a proxy from the upstream `base_url`, the public `proxy_base`, and
    /// the egress seam.
    pub fn new(
        base_url: impl Into<String>,
        proxy_base: impl Into<String>,
        egress: Arc<OutboundClient>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            proxy_base: proxy_base.into().trim_end_matches('/').to_string(),
            egress,
        }
    }

    /// Build a proxy from the [`XtreamConfig`], or `None` when no upstream base
    /// URL is configured (the Xtream surface is then unavailable).
    pub fn from_config(
        cfg: &XtreamConfig,
        proxy_base: impl Into<String>,
        egress: Arc<OutboundClient>,
    ) -> Option<Self> {
        let base_url = cfg.base_url.as_ref()?.clone();
        Some(Self::new(base_url, proxy_base, egress))
    }

    /// Build the upstream API URL for `endpoint`, appending the incoming
    /// `query` string verbatim so the panel sees the original parameters
    /// (`username`, `password`, `action`, …) — the stateless target derivation
    /// (Req 9.1–9.3, 9.5).
    fn api_url(&self, endpoint: ApiEndpoint, query: &str) -> Result<Url, AppError> {
        let mut full = format!("{}/{}", self.base_url, endpoint.upstream_path());
        if !query.is_empty() {
            full.push('?');
            full.push_str(query);
        }
        Url::parse(&full).map_err(|e| {
            AppError::bad_request(format!("invalid Xtream upstream URL `{full}`: {e}"))
        })
    }

    /// Forward an API request to the upstream panel and capture the response
    /// (Req 9.1–9.3). The upstream status and body are propagated verbatim,
    /// including an authentication failure (Req 9.7).
    ///
    /// For [`ApiEndpoint::Get`] the captured body is rewritten so every
    /// upstream stream URL routes back through this proxy (Req 9.6).
    pub async fn forward_api(
        &self,
        endpoint: ApiEndpoint,
        query: &str,
    ) -> Result<UpstreamResponse, AppError> {
        let url = self.api_url(endpoint, query)?;
        // The client comes ONLY from the OutboundClient seam: tunnelled, gated
        // fail-closed, and carrying no client-identifying headers (Req 51).
        let resp = self
            .egress
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| map_send_error(&url, e))?;

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = resp.bytes().await.map_err(|e| {
            AppError::upstream_unavailable(format!("failed reading Xtream upstream body: {e}"))
        })?;
        let mut body = bytes.to_vec();

        // get.php enumerates stream URLs → rewrite them through the proxy
        // (Req 9.6). Only rewrite a successful playlist body; an error body is
        // propagated verbatim (Req 9.7).
        if endpoint == ApiEndpoint::Get && (200..300).contains(&status) {
            if let Ok(text) = String::from_utf8(body.clone()) {
                let rewritten = rewrite_playlist(&text, &self.base_url, &self.proxy_base);
                body = rewritten.into_bytes();
            }
        }

        Ok(UpstreamResponse {
            status,
            content_type,
            body,
        })
    }

    /// Resolve a proxy short stream `path` to its upstream stream URL and proxy
    /// the stream through the generic ranged streaming core (Req 9.4).
    ///
    /// `path` is the incoming request path; the short stream tail is located by
    /// its [`STREAM_PATH_PREFIX`](stream_url::STREAM_PATH_PREFIX) marker so the
    /// resolution is independent of any `Server_Path_Prefix`. The upstream
    /// target is derived purely from the path coordinates — no session lookup
    /// (Req 9.5).
    pub async fn serve_stream(
        &self,
        path: &str,
        range: RangeSpec,
        is_head: bool,
        prebuffer: &PrebufferConfig,
    ) -> Result<HttpResponse, AppError> {
        let tail = stream_tail_from_path(path).ok_or_else(|| {
            AppError::bad_request(format!("not an Xtream short stream path: `{path}`"))
        })?;
        let stream_ref = parse_stream_tail(tail)?;
        let upstream_url = stream_ref.upstream_url(&self.base_url)?;

        let source: Arc<dyn proxy::UpstreamSource> =
            Arc::new(DirectSource::new(self.egress.clone(), upstream_url));
        proxy::serve(source, range, is_head, prebuffer).await
    }
}

/// Map a `reqwest` send error onto the canonical taxonomy: a connect/timeout/
/// reset against the Xtream panel is an `UpstreamUnavailable` (`503`), carrying
/// the upstream status when the error surfaced one.
fn map_send_error(url: &Url, err: reqwest::Error) -> AppError {
    let host = url.host_str().unwrap_or("<unknown>");
    let app =
        AppError::upstream_unavailable(format!("Xtream upstream request to {host} failed: {err}"));
    match err.status() {
        Some(status) => app.with_upstream_status(status.as_u16()),
        None => app,
    }
}

// ---------------------------------------------------------------------------
// actix handlers
// ---------------------------------------------------------------------------

/// Resolve the [`XtreamProxy`] for the current request from shared state, or a
/// `404` when no Xtream upstream is configured (the surface is unavailable).
fn proxy_from_state(state: &AppState) -> Result<XtreamProxy, AppError> {
    let cfg = state.config();
    let proxy_base = public_base(state);
    XtreamProxy::from_config(&cfg.xtream, proxy_base, state.egress().clone()).ok_or_else(|| {
        AppError::not_found("Xtream Codes proxy is not configured (no upstream base URL)")
    })
}

/// The public base used for rewritten proxy URLs: the configured
/// `Server_Path_Prefix` (so generated URLs work behind a reverse proxy).
///
/// The host/scheme are not known to the server config, so rewritten URLs are
/// path-absolute under the prefix; a fronting reverse proxy supplies the
/// authority. This keeps rewriting stateless and host-agnostic.
fn public_base(state: &AppState) -> String {
    state.config().server.path_prefix.clone()
}

/// `GET …/player_api.php` — forward to the Xtream upstream, return its JSON
/// (Req 9.1, 9.7).
pub async fn player_api_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let proxy = proxy_from_state(&state)?;
    let resp = proxy
        .forward_api(ApiEndpoint::PlayerApi, req.query_string())
        .await?;
    Ok(resp.into_http_response())
}

/// `GET …/xmltv.php` — forward to the Xtream upstream, return its XMLTV
/// (Req 9.2, 9.7).
pub async fn xmltv_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let proxy = proxy_from_state(&state)?;
    let resp = proxy
        .forward_api(ApiEndpoint::Xmltv, req.query_string())
        .await?;
    Ok(resp.into_http_response())
}

/// `GET …/get.php` — forward to the Xtream upstream, return its playlist with
/// stream URLs rewritten through the proxy (Req 9.3, 9.6, 9.7).
pub async fn get_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let proxy = proxy_from_state(&state)?;
    let resp = proxy
        .forward_api(ApiEndpoint::Get, req.query_string())
        .await?;
    Ok(resp.into_http_response())
}

/// `GET …/proxy/xtream/stream/{cat}/{user}/{pass}/…/{id}.{ext}` — resolve the
/// short stream URL to the upstream stream and proxy it (Req 9.4).
pub async fn stream_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let proxy = proxy_from_state(&state)?;
    let range = RangeSpec::from_header(
        req.headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok()),
    )?;
    let is_head = req.method() == actix_web::http::Method::HEAD;
    proxy
        .serve_stream(req.path(), range, is_head, &state.config().prebuffer)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::errors::ErrorCategory;

    use actix_web::body::to_bytes;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A `FailOpen` egress with no tunnel: the decision is "dial untunneled",
    /// so the proxy reaches the in-process wiremock origin directly — the real
    /// open/forward path with no network dependency (mirrors proxy::core tests).
    fn outbound_fail_open() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn proxy_for(base_url: &str) -> XtreamProxy {
        XtreamProxy::new(base_url, "https://proxy.example", outbound_fail_open())
    }

    // -- player_api.php forwarded, upstream JSON returned (Req 9.1) ---------

    #[tokio::test]
    async fn player_api_forwarded_returns_upstream_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/player_api.php"))
            .and(query_param("username", "u1"))
            .and(query_param("password", "p1"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"user_info":{"auth":1}}"#.as_bytes().to_vec(),
                "application/json",
            ))
            .mount(&server)
            .await;

        let proxy = proxy_for(&server.uri());
        let resp = proxy
            .forward_api(ApiEndpoint::PlayerApi, "username=u1&password=p1")
            .await
            .expect("forward ok");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type.as_deref(), Some("application/json"));
        assert_eq!(resp.body, br#"{"user_info":{"auth":1}}"#.to_vec());
    }

    // -- xmltv.php forwarded, XMLTV returned (Req 9.2) ----------------------

    #[tokio::test]
    async fn xmltv_forwarded_returns_upstream_xmltv() {
        let server = MockServer::start().await;
        let xml = r#"<?xml version="1.0"?><tv><channel id="a"/></tv>"#;
        Mock::given(method("GET"))
            .and(path("/xmltv.php"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(xml.as_bytes().to_vec(), "application/xml"),
            )
            .mount(&server)
            .await;

        let proxy = proxy_for(&server.uri());
        let resp = proxy
            .forward_api(ApiEndpoint::Xmltv, "username=u1&password=p1")
            .await
            .expect("forward ok");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type.as_deref(), Some("application/xml"));
        assert_eq!(resp.body, xml.as_bytes().to_vec());
    }

    // -- get.php forwarded, playlist returned + stream URLs rewritten -------
    //    (Req 9.3 + 9.6)

    #[tokio::test]
    async fn get_forwarded_returns_playlist_with_rewritten_stream_urls() {
        let server = MockServer::start().await;
        let base = server.uri();
        let playlist = format!(
            "#EXTM3U\n#EXTINF:-1,Channel A\n{base}/live/u1/p1/10.ts\n\
             #EXTINF:-1,Movie B\n{base}/movie/u1/p1/20.mp4\n"
        );
        Mock::given(method("GET"))
            .and(path("/get.php"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/x-mpegurl")
                    .set_body_string(playlist),
            )
            .mount(&server)
            .await;

        let proxy = proxy_for(&base);
        let resp = proxy
            .forward_api(ApiEndpoint::Get, "username=u1&password=p1&type=m3u")
            .await
            .expect("forward ok");

        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body).unwrap();
        // Stream URLs rewritten through the proxy (Req 9.6).
        assert!(body.contains("https://proxy.example/proxy/xtream/stream/live/u1/p1/10.ts"));
        assert!(body.contains("https://proxy.example/proxy/xtream/stream/vod/u1/p1/20.mp4"));
        // No upstream-origin stream URL survives.
        assert!(!body.contains(&format!("{base}/live")));
        assert!(!body.contains(&format!("{base}/movie")));
        // Tag lines preserved.
        assert!(body.contains("#EXTINF:-1,Channel A"));
    }

    // -- Short stream URL resolved + proxied (Req 9.4) ----------------------

    #[tokio::test]
    async fn short_stream_url_resolved_and_proxied() {
        let server = MockServer::start().await;
        let payload = b"TS-SEGMENT-BYTES".to_vec();
        Mock::given(method("GET"))
            .and(path("/live/u1/p1/10.ts"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "video/mp2t")
                    .set_body_bytes(payload.clone()),
            )
            .mount(&server)
            .await;

        let proxy = proxy_for(&server.uri());
        let resp = proxy
            .serve_stream(
                "/proxy/xtream/stream/live/u1/p1/10.ts",
                RangeSpec::Full,
                false,
                &PrebufferConfig::default(),
            )
            .await
            .expect("serve ok");

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&bytes[..], &payload[..]);
    }

    #[tokio::test]
    async fn short_stream_url_forwards_range_and_returns_206() {
        let server = MockServer::start().await;
        let partial = b"PARTIAL".to_vec();
        Mock::given(method("GET"))
            .and(path("/movie/u1/p1/20.mp4"))
            .and(wiremock::matchers::header("range", "bytes=10-99"))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header("Content-Type", "video/mp4")
                    .insert_header("Content-Range", "bytes 10-99/1000")
                    .set_body_bytes(partial.clone()),
            )
            .mount(&server)
            .await;

        let proxy = proxy_for(&server.uri());
        let resp = proxy
            .serve_stream(
                "/proxy/xtream/stream/vod/u1/p1/20.mp4",
                RangeSpec::Inclusive(10, 99),
                false,
                &PrebufferConfig::default(),
            )
            .await
            .expect("serve ok");

        assert_eq!(resp.status(), actix_web::http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 10-99/1000"
        );
    }

    // -- Statelessness: every target derived from the request (Req 9.5) -----

    #[tokio::test]
    async fn proxy_is_stateless_targets_derived_from_request() {
        // One proxy instance serves two distinct accounts/streams with no
        // shared mutable state: the upstream target is a pure function of the
        // request path/query.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/live/userA/passA/1.ts"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"A".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/live/userB/passB/2.ts"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"B".to_vec()))
            .mount(&server)
            .await;

        let proxy = proxy_for(&server.uri());

        let a = proxy
            .serve_stream(
                "/proxy/xtream/stream/live/userA/passA/1.ts",
                RangeSpec::Full,
                false,
                &PrebufferConfig::default(),
            )
            .await
            .expect("A ok");
        let b = proxy
            .serve_stream(
                "/proxy/xtream/stream/live/userB/passB/2.ts",
                RangeSpec::Full,
                false,
                &PrebufferConfig::default(),
            )
            .await
            .expect("B ok");

        assert_eq!(&to_bytes(a.into_body()).await.unwrap()[..], b"A");
        assert_eq!(&to_bytes(b.into_body()).await.unwrap()[..], b"B");
    }

    // -- Upstream auth failure → status + body propagated (Req 9.7) ---------

    #[tokio::test]
    async fn upstream_auth_failure_propagates_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/player_api.php"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"user_info":{"auth":0,"status":"Disabled"}}"#),
            )
            .mount(&server)
            .await;

        let proxy = proxy_for(&server.uri());
        let resp = proxy
            .forward_api(ApiEndpoint::PlayerApi, "username=bad&password=bad")
            .await
            .expect("forward returns the captured upstream response, not an error");

        // Status and body propagated verbatim (Req 9.7).
        assert_eq!(resp.status, 401);
        assert_eq!(
            resp.body,
            br#"{"user_info":{"auth":0,"status":"Disabled"}}"#.to_vec()
        );

        // And the rendered HttpResponse carries the upstream 401 + body.
        let http = resp.into_http_response();
        assert_eq!(http.status().as_u16(), 401);
        let bytes = to_bytes(http.into_body()).await.unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("Disabled"));
    }

    #[tokio::test]
    async fn get_php_error_body_is_not_rewritten() {
        // A non-2xx get.php body is propagated verbatim (no rewrite attempt).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get.php"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let proxy = proxy_for(&server.uri());
        let resp = proxy
            .forward_api(ApiEndpoint::Get, "username=bad&password=bad")
            .await
            .expect("forward ok");
        assert_eq!(resp.status, 403);
        assert_eq!(resp.body, b"Forbidden".to_vec());
    }

    // -- Egress seam is the only path to the network (Req 51.1) -------------

    #[tokio::test]
    async fn fail_closed_egress_refuses_with_no_dial() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailClosed,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let egress = Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"));
        let proxy = XtreamProxy::new("http://origin:8080", "https://proxy.example", egress);

        let err = proxy
            .forward_api(ApiEndpoint::PlayerApi, "username=u&password=p")
            .await
            .expect_err("fail-closed egress must refuse the dial");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("egress tunnel"));
    }

    // -- from_config gating --------------------------------------------------

    #[test]
    fn from_config_is_none_without_base_url() {
        let cfg = XtreamConfig::default();
        assert!(
            XtreamProxy::from_config(&cfg, "https://proxy.example", outbound_fail_open()).is_none()
        );
    }

    #[test]
    fn from_config_builds_when_base_url_set() {
        let cfg = XtreamConfig {
            base_url: Some("http://origin:8080".into()),
            ..XtreamConfig::default()
        };
        assert!(
            XtreamProxy::from_config(&cfg, "https://proxy.example", outbound_fail_open()).is_some()
        );
    }
}
