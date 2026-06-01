//! Subtitle proxy and extraction (`subtitles`) — Req 39.
//!
//! This module provides:
//!
//! * [`SubtitleFormat`] — the three supported subtitle formats (SRT, VTT,
//!   ASS/SSA) with their correct `Content-Type` values (Req 39.3, 39.4).
//! * [`content_type_for_url`] — infer the subtitle format (and thus the
//!   `Content-Type`) from a URL's file extension (Req 39.4).
//! * [`SubtitleProxy`] — fetches an upstream subtitle file through the single
//!   egress seam and returns it with the correct `Content-Type` header
//!   (Req 39.1, 39.3, 39.4, 39.5).
//! * [`merge_subtitles`] — de-duplicated merge of subtitle lists from multiple
//!   upstream sources, keyed by `(lang, url)` (Req 39.6).
//! * [`subtitle_proxy_endpoint`] — the actix handler wired at
//!   `/proxy/subtitle` (Req 39.1).

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::Method;
use url::Url;

use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::stremio::types::Subtitle;

// ---------------------------------------------------------------------------
// Subtitle format and Content-Type mapping (Req 39.3, 39.4)
// ---------------------------------------------------------------------------

/// The three subtitle formats supported for proxying (Req 39.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubtitleFormat {
    /// SubRip Text (`.srt`). Content-Type: `application/x-subrip` (Req 39.4).
    Srt,
    /// WebVTT (`.vtt`). Content-Type: `text/vtt` (Req 39.4).
    Vtt,
    /// Advanced SubStation Alpha / SubStation Alpha (`.ass` / `.ssa`).
    /// Content-Type: `text/x-ssa` (Req 39.4).
    AssSsa,
}

impl SubtitleFormat {
    /// The correct `Content-Type` header value for this format (Req 39.4).
    pub fn content_type(self) -> &'static str {
        match self {
            SubtitleFormat::Srt => "application/x-subrip",
            SubtitleFormat::Vtt => "text/vtt",
            SubtitleFormat::AssSsa => "text/x-ssa",
        }
    }
}

/// Infer the [`SubtitleFormat`] from a URL's file extension (case-insensitive).
///
/// Returns `None` when the extension is absent or not one of the three
/// supported formats. The caller may fall back to the upstream `Content-Type`
/// in that case.
pub fn format_from_url(url: &str) -> Option<SubtitleFormat> {
    // Extract the path component (strip query/fragment) and look at the last
    // dot-separated segment of the final path component.
    let path = url.split('?').next().unwrap_or(url);
    let path = path.split('#').next().unwrap_or(path);
    let ext = path.rsplit('.').next()?;
    match ext.to_ascii_lowercase().as_str() {
        "srt" => Some(SubtitleFormat::Srt),
        "vtt" => Some(SubtitleFormat::Vtt),
        "ass" | "ssa" => Some(SubtitleFormat::AssSsa),
        _ => None,
    }
}

/// Return the correct `Content-Type` string for the subtitle URL, falling back
/// to `application/octet-stream` when the format cannot be inferred (Req 39.4).
pub fn content_type_for_url(url: &str) -> &'static str {
    match format_from_url(url) {
        Some(fmt) => fmt.content_type(),
        None => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// De-duplicated subtitle merge (Req 39.6)
// ---------------------------------------------------------------------------

/// Merge subtitle lists from multiple upstream sources, removing duplicates
/// keyed by `(lang, url)` (Req 39.6).
///
/// The first occurrence of each `(lang, url)` pair is kept; subsequent
/// duplicates are dropped. The relative order of non-duplicate entries is
/// preserved (stable de-duplication).
pub fn merge_subtitles(lists: impl IntoIterator<Item = Vec<Subtitle>>) -> Vec<Subtitle> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut result: Vec<Subtitle> = Vec::new();
    for list in lists {
        for sub in list {
            let key = (sub.lang.clone(), sub.url.clone());
            if seen.insert(key) {
                result.push(sub);
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Subtitle proxy (Req 39.1, 39.3, 39.4, 39.5)
// ---------------------------------------------------------------------------

/// Maximum subtitle body size buffered in memory. Subtitle files are small
/// text documents; this cap guards against a hostile upstream.
const MAX_SUBTITLE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// The subtitle proxy: fetches an upstream subtitle file through the egress
/// seam and returns it with the correct `Content-Type` (Req 39.1, 39.4, 39.5).
#[derive(Clone)]
pub struct SubtitleProxy {
    /// The single outbound seam — the only approved path to the network
    /// (Req 51.1).
    client: Arc<OutboundClient>,
}

impl SubtitleProxy {
    /// Build a [`SubtitleProxy`] over the shared egress client.
    pub fn new(client: Arc<OutboundClient>) -> Self {
        Self { client }
    }

    /// Fetch the subtitle at `url`, forwarding `headers` upstream (Req 39.5),
    /// and return the body with the correct `Content-Type` (Req 39.4).
    ///
    /// The `Content-Type` is determined by the URL extension (Req 39.3, 39.4);
    /// when the extension is unrecognised the upstream `Content-Type` is used
    /// as a fallback, and `application/octet-stream` is the final fallback.
    pub async fn fetch(
        &self,
        url: &str,
        headers: &BTreeMap<String, String>,
    ) -> Result<SubtitleResponse, AppError> {
        let parsed = Url::parse(url)
            .map_err(|e| AppError::bad_request(format!("invalid subtitle URL: {e}")))?;

        let mut builder = self.client.upstream(Method::GET, &parsed)?;
        let header_map = to_header_map(headers);
        if !header_map.is_empty() {
            builder = builder.headers(header_map);
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| map_send_error(&parsed, e))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(AppError::upstream_unavailable(format!(
                "upstream subtitle request to {url} returned HTTP {}",
                status.as_u16()
            ))
            .with_upstream_status(status.as_u16()));
        }

        // Determine Content-Type: URL extension wins; fall back to upstream
        // Content-Type; final fallback is application/octet-stream (Req 39.4).
        let content_type = if let Some(fmt) = format_from_url(url) {
            fmt.content_type().to_string()
        } else {
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string()
        };

        let body = resp.bytes().await.map_err(|e| map_send_error(&parsed, e))?;

        if body.len() > MAX_SUBTITLE_BYTES {
            return Err(AppError::payload_too_large(format!(
                "upstream subtitle from {url} exceeds {MAX_SUBTITLE_BYTES} bytes"
            )));
        }

        Ok(SubtitleResponse { body, content_type })
    }
}

/// A fetched subtitle body with its resolved `Content-Type`.
#[derive(Debug, Clone)]
pub struct SubtitleResponse {
    /// The subtitle file bytes.
    pub body: Bytes,
    /// The resolved `Content-Type` header value (Req 39.4).
    pub content_type: String,
}

// ---------------------------------------------------------------------------
// HTTP handler (Req 39.1)
// ---------------------------------------------------------------------------

/// Query parameters for `GET /proxy/subtitle`.
#[derive(Debug, serde::Deserialize)]
pub struct SubtitleQuery {
    /// The upstream subtitle URL to proxy (required).
    pub url: String,
    /// Optional pipe-separated `Key:Value` request headers forwarded upstream
    /// (Req 39.5).
    #[serde(default)]
    pub headers: Option<String>,
}

/// `GET /proxy/subtitle?url=<upstream>&headers=<Key:Value|...>`
///
/// Fetches the upstream subtitle file through the egress seam and returns it
/// with the correct `Content-Type` (Req 39.1, 39.4, 39.5). Authenticated by
/// `api_password` (mediaflow surface).
pub async fn subtitle_proxy_endpoint(
    req: HttpRequest,
    query: web::Query<SubtitleQuery>,
    state: web::Data<crate::app::AppState>,
) -> Result<HttpResponse, AppError> {
    // Auth: verify api_password (mediaflow surface, Req 36.1, 36.5).
    let api_password = req
        .headers()
        .get("api_password")
        .or_else(|| req.headers().get("x-api-password"))
        .and_then(|v| v.to_str().ok());
    let auth = crate::auth::Auth::from_config(&state.config().auth);
    auth.verify_api_password(api_password)?;

    // Parse optional forwarded headers (Req 39.5).
    let headers = query
        .headers
        .as_deref()
        .map(parse_pipe_headers)
        .unwrap_or_default();

    let proxy = SubtitleProxy::new(Arc::clone(state.egress()));
    let result = proxy.fetch(&query.url, &headers).await?;

    Ok(HttpResponse::Ok()
        .insert_header((
            actix_web::http::header::CONTENT_TYPE,
            result.content_type.as_str(),
        ))
        .body(result.body))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a pipe-separated `Key:Value` header string into a `BTreeMap`.
///
/// Format: `Key1:Value1|Key2:Value2|...`
pub fn parse_pipe_headers(raw: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in raw.split('|') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once(':') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            if !key.is_empty() {
                map.insert(key, value);
            }
        }
    }
    map
}

/// Convert a `name → value` header map into a `reqwest` [`HeaderMap`],
/// skipping any entry whose name or value is not a valid HTTP header.
fn to_header_map(headers: &BTreeMap<String, String>) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) else {
            continue;
        };
        map.insert(n, v);
    }
    map
}

/// Map a `reqwest` send/read error onto the canonical taxonomy.
fn map_send_error(url: &Url, err: reqwest::Error) -> AppError {
    let host = url.host_str().unwrap_or("<unknown>");
    let app = AppError::upstream_unavailable(format!(
        "upstream subtitle request to {host} failed: {err}"
    ));
    match err.status() {
        Some(status) => app.with_upstream_status(status.as_u16()),
        None => app,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::errors::ErrorCategory;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn outbound_fail_open() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn outbound_fail_closed() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Proxy,
            tunnel_url: Some("http://proxy:8888".to_string()),
            policy: EgressPolicy::FailClosed,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    // -- Content-Type mapping (Req 39.3, 39.4) --------------------------------

    #[test]
    fn srt_extension_maps_to_application_x_subrip() {
        assert_eq!(
            format_from_url("https://example.com/sub.srt")
                .unwrap()
                .content_type(),
            "application/x-subrip"
        );
    }

    #[test]
    fn vtt_extension_maps_to_text_vtt() {
        assert_eq!(
            format_from_url("https://example.com/sub.vtt")
                .unwrap()
                .content_type(),
            "text/vtt"
        );
    }

    #[test]
    fn ass_extension_maps_to_text_x_ssa() {
        assert_eq!(
            format_from_url("https://example.com/sub.ass")
                .unwrap()
                .content_type(),
            "text/x-ssa"
        );
    }

    #[test]
    fn ssa_extension_maps_to_text_x_ssa() {
        assert_eq!(
            format_from_url("https://example.com/sub.ssa")
                .unwrap()
                .content_type(),
            "text/x-ssa"
        );
    }

    #[test]
    fn extension_matching_is_case_insensitive() {
        assert_eq!(
            format_from_url("https://x.com/s.SRT").unwrap(),
            SubtitleFormat::Srt
        );
        assert_eq!(
            format_from_url("https://x.com/s.VTT").unwrap(),
            SubtitleFormat::Vtt
        );
        assert_eq!(
            format_from_url("https://x.com/s.ASS").unwrap(),
            SubtitleFormat::AssSsa
        );
        assert_eq!(
            format_from_url("https://x.com/s.SSA").unwrap(),
            SubtitleFormat::AssSsa
        );
    }

    #[test]
    fn unknown_extension_returns_none() {
        assert!(format_from_url("https://example.com/sub.xyz").is_none());
        assert!(format_from_url("https://example.com/sub").is_none());
    }

    #[test]
    fn content_type_for_url_falls_back_to_octet_stream_for_unknown() {
        assert_eq!(
            content_type_for_url("https://example.com/sub.xyz"),
            "application/octet-stream"
        );
    }

    #[test]
    fn format_from_url_ignores_query_and_fragment() {
        // Query string after .srt should not confuse the extension detection.
        assert_eq!(
            format_from_url("https://example.com/sub.srt?token=abc&lang=en"),
            Some(SubtitleFormat::Srt)
        );
        assert_eq!(
            format_from_url("https://example.com/sub.vtt#anchor"),
            Some(SubtitleFormat::Vtt)
        );
    }

    // -- Subtitle proxy fetches upstream with correct Content-Type (Req 39.1, 39.4) --

    #[tokio::test]
    async fn proxy_fetches_srt_and_returns_correct_content_type() {
        let server = MockServer::start().await;
        let body = b"1\n00:00:01,000 --> 00:00:02,000\nHello\n".to_vec();
        Mock::given(method("GET"))
            .and(path("/sub.srt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/plain")
                    .set_body_bytes(body.clone()),
            )
            .mount(&server)
            .await;

        let proxy = SubtitleProxy::new(outbound_fail_open());
        let url = format!("{}/sub.srt", server.uri());
        let resp = proxy
            .fetch(&url, &BTreeMap::new())
            .await
            .expect("fetch succeeds");

        // URL extension wins over upstream Content-Type (Req 39.4).
        assert_eq!(resp.content_type, "application/x-subrip");
        assert_eq!(&resp.body[..], &body[..]);
    }

    #[tokio::test]
    async fn proxy_fetches_vtt_and_returns_text_vtt() {
        let server = MockServer::start().await;
        let body = b"WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello\n".to_vec();
        Mock::given(method("GET"))
            .and(path("/sub.vtt"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let proxy = SubtitleProxy::new(outbound_fail_open());
        let url = format!("{}/sub.vtt", server.uri());
        let resp = proxy
            .fetch(&url, &BTreeMap::new())
            .await
            .expect("fetch succeeds");

        assert_eq!(resp.content_type, "text/vtt");
        assert_eq!(&resp.body[..], &body[..]);
    }

    #[tokio::test]
    async fn proxy_fetches_ass_and_returns_text_x_ssa() {
        let server = MockServer::start().await;
        let body = b"[Script Info]\nTitle: Test\n".to_vec();
        Mock::given(method("GET"))
            .and(path("/sub.ass"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let proxy = SubtitleProxy::new(outbound_fail_open());
        let url = format!("{}/sub.ass", server.uri());
        let resp = proxy
            .fetch(&url, &BTreeMap::new())
            .await
            .expect("fetch succeeds");

        assert_eq!(resp.content_type, "text/x-ssa");
    }

    #[tokio::test]
    async fn proxy_fetches_ssa_and_returns_text_x_ssa() {
        let server = MockServer::start().await;
        let body = b"[Script Info]\n".to_vec();
        Mock::given(method("GET"))
            .and(path("/sub.ssa"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let proxy = SubtitleProxy::new(outbound_fail_open());
        let url = format!("{}/sub.ssa", server.uri());
        let resp = proxy
            .fetch(&url, &BTreeMap::new())
            .await
            .expect("fetch succeeds");

        assert_eq!(resp.content_type, "text/x-ssa");
    }

    // -- Proxy forwards custom headers upstream (Req 39.5) --------------------

    #[tokio::test]
    async fn proxy_forwards_custom_headers_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sub.vtt"))
            .and(wiremock::matchers::header("x-auth-token", "secret123"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"WEBVTT\n".to_vec()))
            .mount(&server)
            .await;

        let proxy = SubtitleProxy::new(outbound_fail_open());
        let url = format!("{}/sub.vtt", server.uri());
        let mut headers = BTreeMap::new();
        headers.insert("x-auth-token".to_string(), "secret123".to_string());

        let resp = proxy
            .fetch(&url, &headers)
            .await
            .expect("fetch with headers succeeds");
        assert_eq!(resp.content_type, "text/vtt");
    }

    // -- Proxy upstream error carries status (Req 39.1) -----------------------

    #[tokio::test]
    async fn proxy_upstream_error_carries_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing.srt"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let proxy = SubtitleProxy::new(outbound_fail_open());
        let url = format!("{}/missing.srt", server.uri());
        let err = proxy
            .fetch(&url, &BTreeMap::new())
            .await
            .expect_err("404 must error");

        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(404));
    }

    // -- Proxy is gated by fail-closed egress (Req 51.1) ----------------------

    #[tokio::test]
    async fn proxy_is_gated_by_fail_closed_egress() {
        let proxy = SubtitleProxy::new(outbound_fail_closed());
        let err = proxy
            .fetch("https://example.com/sub.srt", &BTreeMap::new())
            .await
            .expect_err("fail-closed egress must refuse the dial");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("egress tunnel"));
    }

    // -- Unknown extension falls back to upstream Content-Type ----------------

    #[tokio::test]
    async fn unknown_extension_uses_upstream_content_type() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sub.xyz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/vtt")
                    .set_body_bytes(b"WEBVTT\n".to_vec()),
            )
            .mount(&server)
            .await;

        let proxy = SubtitleProxy::new(outbound_fail_open());
        let url = format!("{}/sub.xyz", server.uri());
        let resp = proxy
            .fetch(&url, &BTreeMap::new())
            .await
            .expect("fetch succeeds");

        // No extension match → use upstream Content-Type.
        assert_eq!(resp.content_type, "text/vtt");
    }

    // -- De-duplicated merge (Req 39.6) ---------------------------------------

    #[test]
    fn merge_empty_lists_returns_empty() {
        let result = merge_subtitles(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn merge_single_list_returns_all_entries() {
        let subs = vec![
            Subtitle {
                id: "1".into(),
                url: "https://a.com/en.srt".into(),
                lang: "en".into(),
                ..Default::default()
            },
            Subtitle {
                id: "2".into(),
                url: "https://a.com/fr.srt".into(),
                lang: "fr".into(),
                ..Default::default()
            },
        ];
        let result = merge_subtitles(vec![subs.clone()]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn merge_removes_duplicates_by_lang_and_url() {
        let sub_en = Subtitle {
            id: "1".into(),
            url: "https://a.com/en.srt".into(),
            lang: "en".into(),
            ..Default::default()
        };
        let sub_fr = Subtitle {
            id: "2".into(),
            url: "https://a.com/fr.srt".into(),
            lang: "fr".into(),
            ..Default::default()
        };
        // Duplicate: same lang + url as sub_en, different id.
        let sub_en_dup = Subtitle {
            id: "99".into(),
            url: "https://a.com/en.srt".into(),
            lang: "en".into(),
            ..Default::default()
        };

        let list1 = vec![sub_en.clone(), sub_fr.clone()];
        let list2 = vec![sub_en_dup, sub_fr.clone()];

        let result = merge_subtitles(vec![list1, list2]);

        // Only 2 unique (lang, url) pairs.
        assert_eq!(result.len(), 2);
        // First occurrence is kept (id "1" for en, id "2" for fr).
        assert!(result.iter().any(|s| s.id == "1" && s.lang == "en"));
        assert!(result.iter().any(|s| s.id == "2" && s.lang == "fr"));
    }

    #[test]
    fn merge_same_url_different_lang_are_not_duplicates() {
        // Same URL but different language → both kept.
        let sub_en = Subtitle {
            id: "1".into(),
            url: "https://a.com/sub.srt".into(),
            lang: "en".into(),
            ..Default::default()
        };
        let sub_fr = Subtitle {
            id: "2".into(),
            url: "https://a.com/sub.srt".into(),
            lang: "fr".into(),
            ..Default::default()
        };

        let result = merge_subtitles(vec![vec![sub_en], vec![sub_fr]]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn merge_same_lang_different_url_are_not_duplicates() {
        // Same language but different URL → both kept.
        let sub1 = Subtitle {
            id: "1".into(),
            url: "https://a.com/en1.srt".into(),
            lang: "en".into(),
            ..Default::default()
        };
        let sub2 = Subtitle {
            id: "2".into(),
            url: "https://a.com/en2.srt".into(),
            lang: "en".into(),
            ..Default::default()
        };

        let result = merge_subtitles(vec![vec![sub1], vec![sub2]]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn merge_preserves_order_of_first_occurrences() {
        let subs: Vec<Subtitle> = (0..5)
            .map(|i| Subtitle {
                id: i.to_string(),
                url: format!("https://a.com/{i}.srt"),
                lang: "en".into(),
                ..Default::default()
            })
            .collect();

        let result = merge_subtitles(vec![subs.clone()]);
        assert_eq!(result.len(), 5);
        for (i, sub) in result.iter().enumerate() {
            assert_eq!(sub.id, i.to_string());
        }
    }

    #[test]
    fn merge_multiple_lists_with_overlapping_entries() {
        let make = |id: &str, lang: &str, url: &str| Subtitle {
            id: id.into(),
            url: url.into(),
            lang: lang.into(),
            ..Default::default()
        };

        let list1 = vec![
            make("1", "en", "https://a.com/en.srt"),
            make("2", "fr", "https://a.com/fr.srt"),
        ];
        let list2 = vec![
            make("3", "de", "https://b.com/de.srt"),
            make("4", "en", "https://a.com/en.srt"), // dup of list1[0]
        ];
        let list3 = vec![
            make("5", "es", "https://c.com/es.vtt"),
            make("6", "fr", "https://a.com/fr.srt"), // dup of list1[1]
        ];

        let result = merge_subtitles(vec![list1, list2, list3]);

        // 4 unique (lang, url) pairs: en/a.com, fr/a.com, de/b.com, es/c.com
        assert_eq!(result.len(), 4);
        // First occurrences kept.
        assert!(result.iter().any(|s| s.id == "1"));
        assert!(result.iter().any(|s| s.id == "2"));
        assert!(result.iter().any(|s| s.id == "3"));
        assert!(result.iter().any(|s| s.id == "5"));
        // Duplicates dropped.
        assert!(!result.iter().any(|s| s.id == "4"));
        assert!(!result.iter().any(|s| s.id == "6"));
    }

    // -- parse_pipe_headers ---------------------------------------------------

    #[test]
    fn parse_pipe_headers_basic() {
        let headers = parse_pipe_headers("Referer:https://example.com/|User-Agent:test");
        assert_eq!(
            headers.get("Referer").map(String::as_str),
            Some("https://example.com/")
        );
        assert_eq!(headers.get("User-Agent").map(String::as_str), Some("test"));
    }

    #[test]
    fn parse_pipe_headers_empty_string() {
        let headers = parse_pipe_headers("");
        assert!(headers.is_empty());
    }

    #[test]
    fn parse_pipe_headers_skips_empty_key() {
        // A pair with no key before the colon is skipped.
        let headers = parse_pipe_headers(":value|Valid:ok");
        assert!(!headers.contains_key(""));
        assert_eq!(headers.get("Valid").map(String::as_str), Some("ok"));
    }
}
