//! Proxify-links HTTP handler (`proxylink::handler`) — Req 21.1–21.9.
//!
//! `GET|POST /v0/proxy`: accepts a list of upstream URLs + headers via
//! `X-StremThru-Authorization` Basic auth, returns one proxy link per URL
//! using the stremthru token codec (Req 21.2) or the mediaflow encrypted
//! format (when `token` is empty/absent).

use std::collections::BTreeMap;

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::auth::encryption::ProxyPayload;
use crate::auth::Auth;
use crate::errors::AppError;
use crate::proxylink::{ProxyCodec, ProxyLink};

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// JSON body for POST /v0/proxy (Req 21.1).
///
/// Also used to parse query parameters for GET /v0/proxy.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProxifyRequest {
    /// One or more upstream URLs to proxify (Req 21.1).
    #[serde(default)]
    pub url: Vec<String>,
    /// Per-index request headers: `req_headers[0]`, `req_headers[1]`, etc.
    /// Each value is a pipe-separated `Key:Value` list (Req 21.4).
    #[serde(default)]
    pub req_headers: IndexedOrShared,
    /// Per-index filenames: `filename[0]`, `filename[1]`, etc. (Req 21.5).
    #[serde(default)]
    pub filename: IndexedOrShared,
    /// When present (even if empty), selects the stremthru token format;
    /// when absent, selects the mediaflow encrypted format (Req 21.2).
    pub token: Option<String>,
    /// Expiration value. A trailing digit is treated as seconds (Req 21.3).
    pub expiration: Option<String>,
    /// When present on a GET with exactly one URL, respond with 302 (Req 21.6).
    pub redirect: Option<String>,
}

/// A value that can be either a shared string or per-index strings.
///
/// In the stremthru wire format, headers/filenames can be supplied as:
/// - A single shared value (applies to all URLs)
/// - Per-index values like `req_headers[0]`, `req_headers[1]`, etc.
#[derive(Debug, Clone, Default)]
pub struct IndexedOrShared {
    /// The shared fallback value (applies when no per-index value exists).
    pub shared: Option<String>,
    /// Per-index values keyed by their numeric index.
    pub indexed: BTreeMap<usize, String>,
}

impl IndexedOrShared {
    /// Get the value for a given index, falling back to the shared value.
    pub fn get(&self, index: usize) -> Option<&str> {
        self.indexed
            .get(&index)
            .map(|s| s.as_str())
            .or(self.shared.as_deref())
    }
}

/// Custom deserializer for `IndexedOrShared` that handles both forms.
impl<'de> Deserialize<'de> for IndexedOrShared {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // For JSON body deserialization, we accept either a string (shared) or
        // a map of index->value. For query params, the actix Query extractor
        // won't call this — we parse query params manually.
        use serde::de;

        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = IndexedOrShared;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string or map of index->string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(IndexedOrShared {
                    shared: Some(v.to_string()),
                    indexed: BTreeMap::new(),
                })
            }

            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut indexed = BTreeMap::new();
                let mut shared = None;
                while let Some(key) = map.next_key::<String>()? {
                    let val: String = map.next_value()?;
                    if let Ok(idx) = key.parse::<usize>() {
                        indexed.insert(idx, val);
                    } else {
                        // Non-numeric key treated as shared
                        shared = Some(val);
                    }
                }
                Ok(IndexedOrShared { shared, indexed })
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(IndexedOrShared::default())
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(IndexedOrShared::default())
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A single proxy link item in the response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxifyItem {
    /// The generated proxy link URL/token.
    pub url: String,
}

/// JSON response for GET|POST /v0/proxy (Req 21.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxifyResponse {
    /// One proxy link per input URL, in input order.
    pub items: Vec<ProxifyItem>,
    /// Total count == items.len() == input URL count.
    pub total_items: usize,
}

// ---------------------------------------------------------------------------
// Expiration parsing (Req 21.3)
// ---------------------------------------------------------------------------

/// Parse an expiration string into a unix-second timestamp (Req 21.3).
///
/// A trailing digit is treated as a duration in seconds from now. Otherwise
/// the value is parsed as a unix timestamp directly.
pub fn parse_expiration(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Try parsing as a number — if it's a small number (trailing digit
    // convention: the value IS seconds-from-now), compute now + seconds.
    // The stremthru convention: the raw value is seconds-from-now.
    if let Ok(secs) = trimmed.parse::<i64>() {
        if secs > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            return Some(now + secs);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Header parsing (Req 21.4)
// ---------------------------------------------------------------------------

/// Parse a pipe-separated header string into a BTreeMap.
///
/// Format: `Key1:Value1|Key2:Value2|...`
pub fn parse_headers(raw: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    if raw.trim().is_empty() {
        return headers;
    }
    for pair in raw.split('|') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once(':') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            if !key.is_empty() {
                headers.insert(key, value);
            }
        }
    }
    headers
}

// ---------------------------------------------------------------------------
// Query parameter parsing for GET requests
// ---------------------------------------------------------------------------

/// Parse query parameters into a `ProxifyRequest`.
///
/// Handles repeated `url` params and indexed `req_headers[N]`/`filename[N]`.
pub fn parse_query_string(query: &str) -> ProxifyRequest {
    let mut req = ProxifyRequest::default();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, urlencoding::decode(v).unwrap_or_default().into_owned()),
            None => (pair, String::new()),
        };

        match key {
            "url" => {
                if !value.is_empty() {
                    req.url.push(value);
                }
            }
            "token" => req.token = Some(value),
            "expiration" => req.expiration = Some(value),
            "redirect" => req.redirect = Some(value),
            "req_headers" => req.req_headers.shared = Some(value),
            "filename" => req.filename.shared = Some(value),
            _ => {
                // Check for indexed params: req_headers[N], filename[N]
                if let Some(idx_str) = extract_index(key, "req_headers") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        req.req_headers.indexed.insert(idx, value);
                    }
                } else if let Some(idx_str) = extract_index(key, "filename") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        req.filename.indexed.insert(idx, value);
                    }
                }
            }
        }
    }
    req
}

/// Extract the index from a key like `prefix[N]`.
fn extract_index<'a>(key: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = key.strip_prefix(prefix)?;
    let rest = rest.strip_prefix('[')?;
    let rest = rest.strip_suffix(']')?;
    Some(rest)
}

// ---------------------------------------------------------------------------
// Core proxify logic
// ---------------------------------------------------------------------------

/// Build proxy links from the parsed request (Req 21.1–21.8).
pub fn proxify(
    req: &ProxifyRequest,
    codec: &ProxyCodec,
    _base_url: &str,
) -> Result<Vec<ProxyLink>, AppError> {
    // Req 21.8: no URL -> bad-request
    if req.url.is_empty() {
        return Err(AppError::bad_request("no url supplied"));
    }

    // Determine format (Req 21.2): an empty/absent `token` selects the
    // mediaflow encrypted (`d`) format; a present, non-empty `token` selects
    // the stremthru token format. This mirrors `ProxyCodec::select`, which
    // treats an empty `token` as absent on the decode side — so the encode and
    // decode sides agree and links round-trip on the playback path (Req 36.7).
    let use_token_format = req.token.as_deref().is_some_and(|t| !t.is_empty());

    // Parse expiration (Req 21.3)
    let exp = req.expiration.as_deref().and_then(parse_expiration);

    let mut links = Vec::with_capacity(req.url.len());

    for (i, url) in req.url.iter().enumerate() {
        // Per-index headers with shared fallback (Req 21.4)
        let headers = req
            .req_headers
            .get(i)
            .map(parse_headers)
            .unwrap_or_default();

        // Per-index filename (Req 21.5)
        let filename = req.filename.get(i).map(|s| s.to_string());

        let mut payload = ProxyPayload::new(url.clone());
        payload.headers = headers;
        payload.filename = filename;
        payload.exp = exp;

        let link = if use_token_format {
            codec.encode_token(&payload)?
        } else {
            codec.encode_mediaflow(&payload)?
        };

        links.push(link);
    }

    Ok(links)
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

/// GET /v0/proxy — proxify-links endpoint (Req 21.1–21.9).
///
/// Authenticated via `X-StremThru-Authorization` Basic (Req 21.9).
pub async fn proxify_get_endpoint(
    req: HttpRequest,
    state: web::Data<crate::app::AppState>,
) -> Result<HttpResponse, AppError> {
    // Auth: verify proxy auth (Req 21.9)
    let auth_header = req
        .headers()
        .get("X-StremThru-Authorization")
        .and_then(|v| v.to_str().ok());
    let auth = Auth::from_config(&state.config().auth);
    let _user = auth.verify_proxy_auth(auth_header)?;

    // Parse query string
    let query_string = req.query_string();
    let parsed = parse_query_string(query_string);

    handle_proxify(parsed, &state, &req)
}

/// POST /v0/proxy — proxify-links endpoint (Req 21.1–21.9).
///
/// Authenticated via `X-StremThru-Authorization` Basic (Req 21.9).
pub async fn proxify_post_endpoint(
    req: HttpRequest,
    state: web::Data<crate::app::AppState>,
    body: web::Json<ProxifyRequest>,
) -> Result<HttpResponse, AppError> {
    // Auth: verify proxy auth (Req 21.9)
    let auth_header = req
        .headers()
        .get("X-StremThru-Authorization")
        .and_then(|v| v.to_str().ok());
    let auth = Auth::from_config(&state.config().auth);
    let _user = auth.verify_proxy_auth(auth_header)?;

    handle_proxify(body.into_inner(), &state, &req)
}

/// Shared logic for GET and POST /v0/proxy.
fn handle_proxify(
    parsed: ProxifyRequest,
    state: &web::Data<crate::app::AppState>,
    req: &HttpRequest,
) -> Result<HttpResponse, AppError> {
    // Req 21.7: redirect with >1 URL -> bad-request
    if parsed.redirect.is_some() && parsed.url.len() > 1 {
        return Err(AppError::bad_request(
            "redirect is only allowed with exactly one URL",
        ));
    }

    // Build the codec from config
    let config = state.config();
    let api_password = config
        .auth
        .api_password
        .as_ref()
        .map(|s| s.expose())
        .unwrap_or("");
    // For the stremthru token key, use the first proxy_auth entry's password
    // as the signing secret (matching stremthru behavior), or fall back to
    // the api_password.
    let token_secret = config
        .auth
        .proxy_auth
        .first()
        .and_then(|entry| entry.split_once(':').map(|(_, pass)| pass))
        .unwrap_or(api_password);
    let codec = ProxyCodec::from_secrets(api_password, token_secret);

    // Build the base URL for proxy links
    let base_url = format!(
        "{}://{}",
        req.connection_info().scheme(),
        req.connection_info().host(),
    );

    let links = proxify(&parsed, &codec, &base_url)?;

    // Req 21.6: redirect with exactly one URL -> 302
    if parsed.redirect.is_some() && links.len() == 1 {
        let link = &links[0];
        let redirect_url = format!("{}/v0/proxy/stream?{}", base_url, link.as_query_param());
        return Ok(HttpResponse::Found()
            .insert_header(("Location", redirect_url))
            .finish());
    }

    // Build response (Req 21.1)
    let items: Vec<ProxifyItem> = links
        .iter()
        .map(|link| ProxifyItem {
            url: format!("{}/v0/proxy/stream?{}", base_url, link.as_query_param()),
        })
        .collect();

    let response = ProxifyResponse {
        total_items: items.len(),
        items,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::config::{AuthConfig, Config, Secret};
    use actix_web::{test, App};

    const API_PASSWORD: &str = "test-api-password";
    const PROXY_USER: &str = "alice";
    const PROXY_PASS: &str = "wonderland";

    fn test_config() -> Config {
        let mut config = Config::default();
        config.auth = AuthConfig {
            api_password: Some(Secret::from(API_PASSWORD)),
            metrics_password: None,
            proxy_auth: vec![format!("{PROXY_USER}:{PROXY_PASS}")],
            per_user_store: vec![],
            admins: vec![],
        };
        config
    }

    fn auth_header() -> (&'static str, String) {
        (
            "X-StremThru-Authorization",
            format!("{PROXY_USER}:{PROXY_PASS}"),
        )
    }

    // Build the in-memory test service. This is a `macro_rules!` rather than a
    // helper `fn` because `test::init_service` returns an `impl Service<Request,
    // ..>` whose `Request` type is `actix_http::Request` — and `actix-http` is
    // not a direct dependency of this crate, so that type cannot be named in a
    // function return signature. Expanding inline at each call site sidesteps
    // naming the un-nameable service type while keeping the setup DRY.
    macro_rules! build_app {
        () => {{
            let state = AppState::new(test_config());
            test::init_service(
                App::new()
                    .app_data(web::Data::new(state))
                    .route("/v0/proxy", web::get().to(proxify_get_endpoint))
                    .route("/v0/proxy", web::post().to(proxify_post_endpoint)),
            )
            .await
        }};
    }

    // -- Req 21.1: one Proxy_Link per URL + total --

    #[actix_web::test]
    async fn returns_one_link_per_url_with_total() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://a.com/1.mp4&url=https://b.com/2.mp4&token=yes")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;
        assert_eq!(body.total_items, 2);
        assert_eq!(body.items.len(), 2);
    }

    // -- Req 21.2: token present -> token format, absent -> encrypted --

    #[actix_web::test]
    async fn token_present_produces_token_links() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://cdn.example.com/v.mp4&token=yes")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;
        assert_eq!(body.items.len(), 1);
        // Token format links contain "token=" in the URL
        assert!(body.items[0].url.contains("token="));
    }

    #[actix_web::test]
    async fn token_absent_produces_encrypted_links() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://cdn.example.com/v.mp4")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;
        assert_eq!(body.items.len(), 1);
        // Encrypted format links contain "d=" in the URL
        assert!(body.items[0].url.contains("d="));
    }

    // Req 21.2: an *empty* `token` parameter selects the encrypted (`d`) format,
    // matching the decode-side `ProxyCodec::select` (empty token == absent) so
    // links round-trip on the playback path.
    #[actix_web::test]
    async fn empty_token_produces_encrypted_links() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://cdn.example.com/v.mp4&token=")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;
        assert_eq!(body.items.len(), 1);
        // Empty token -> encrypted `d` link, not a stremthru `token` link.
        assert!(body.items[0].url.contains("d="));
        assert!(!body.items[0].url.contains("token="));
    }

    // -- Req 21.3: expiration embedded --

    #[actix_web::test]
    async fn expiration_embedded_in_links() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://cdn.example.com/v.mp4&token=yes&expiration=3600")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;
        assert_eq!(body.items.len(), 1);

        // Decode the token to verify expiration is embedded
        let url = &body.items[0].url;
        let token_str = url.split("token=").nth(1).unwrap();
        let token_secret = PROXY_PASS;
        let key = crate::proxylink::TokenKey::from_secret(token_secret);
        let payload = crate::proxylink::token::TokenCodec::decode(token_str, &key).unwrap();
        assert!(payload.exp.is_some());
        // The exp should be roughly now + 3600
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = payload.exp.unwrap();
        assert!(exp >= now + 3590 && exp <= now + 3610);
    }

    // -- Req 21.4: per-index req_headers with shared fallback --

    #[actix_web::test]
    async fn per_index_headers_embedded_in_links() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://a.com/1.mp4&url=https://b.com/2.mp4&token=yes&req_headers[0]=Referer:https://a.com/&req_headers[1]=Referer:https://b.com/")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;
        assert_eq!(body.items.len(), 2);

        // Decode each token and verify headers
        let token_secret = PROXY_PASS;
        let key = crate::proxylink::TokenKey::from_secret(token_secret);

        let token0 = body.items[0].url.split("token=").nth(1).unwrap();
        let p0 = crate::proxylink::token::TokenCodec::decode(token0, &key).unwrap();
        assert_eq!(p0.headers.get("Referer").unwrap(), "https://a.com/");

        let token1 = body.items[1].url.split("token=").nth(1).unwrap();
        let p1 = crate::proxylink::token::TokenCodec::decode(token1, &key).unwrap();
        assert_eq!(p1.headers.get("Referer").unwrap(), "https://b.com/");
    }

    #[actix_web::test]
    async fn shared_headers_fallback() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://a.com/1.mp4&url=https://b.com/2.mp4&token=yes&req_headers=User-Agent:test-agent")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;

        let token_secret = PROXY_PASS;
        let key = crate::proxylink::TokenKey::from_secret(token_secret);

        // Both links should have the shared header
        for item in &body.items {
            let token_str = item.url.split("token=").nth(1).unwrap();
            let payload = crate::proxylink::token::TokenCodec::decode(token_str, &key).unwrap();
            assert_eq!(payload.headers.get("User-Agent").unwrap(), "test-agent");
        }
    }

    // -- Req 21.5: per-index filename --

    #[actix_web::test]
    async fn per_index_filename_embedded() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://a.com/1.mp4&url=https://b.com/2.mp4&token=yes&filename[0]=movie1.mp4&filename[1]=movie2.mp4")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;

        let token_secret = PROXY_PASS;
        let key = crate::proxylink::TokenKey::from_secret(token_secret);

        let t0 = body.items[0].url.split("token=").nth(1).unwrap();
        let p0 = crate::proxylink::token::TokenCodec::decode(t0, &key).unwrap();
        assert_eq!(p0.filename.as_deref(), Some("movie1.mp4"));

        let t1 = body.items[1].url.split("token=").nth(1).unwrap();
        let p1 = crate::proxylink::token::TokenCodec::decode(t1, &key).unwrap();
        assert_eq!(p1.filename.as_deref(), Some("movie2.mp4"));
    }

    // -- Req 21.6: redirect with one URL -> 302 --

    #[actix_web::test]
    async fn redirect_with_one_url_returns_302() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://cdn.example.com/v.mp4&token=yes&redirect=true")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 302);
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert!(location.contains("token="));
        assert!(location.contains("/v0/proxy/stream"));
    }

    // -- Req 21.7: redirect with >1 URL -> bad-request --

    #[actix_web::test]
    async fn redirect_with_multiple_urls_returns_400() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri(
                "/v0/proxy?url=https://a.com/1.mp4&url=https://b.com/2.mp4&token=yes&redirect=true",
            )
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // -- Req 21.8: no URL -> bad-request --

    #[actix_web::test]
    async fn no_url_returns_400() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?token=yes")
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // -- Req 21.9: missing/invalid Proxy_Auth -> 403 + challenge --

    #[actix_web::test]
    async fn missing_auth_returns_403() {
        let app = build_app!();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://cdn.example.com/v.mp4&token=yes")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    #[actix_web::test]
    async fn invalid_auth_returns_403() {
        let app = build_app!();
        let req = test::TestRequest::get()
            .uri("/v0/proxy?url=https://cdn.example.com/v.mp4&token=yes")
            .insert_header(("X-StremThru-Authorization", "wrong:creds"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    // -- Cardinality: output == input --

    #[actix_web::test]
    async fn output_cardinality_equals_input() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let urls: Vec<String> = (0..5)
            .map(|i| format!("https://cdn.example.com/{i}.mp4"))
            .collect();
        let query = urls
            .iter()
            .map(|u| format!("url={u}"))
            .collect::<Vec<_>>()
            .join("&");
        let uri = format!("/v0/proxy?{query}&token=yes");
        let req = test::TestRequest::get()
            .uri(&uri)
            .insert_header((hdr_name, hdr_val))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: ProxifyResponse = test::read_body_json(resp).await;
        assert_eq!(body.total_items, 5);
        assert_eq!(body.items.len(), 5);
    }

    // -- POST body support --

    #[actix_web::test]
    async fn post_body_produces_links() {
        let app = build_app!();
        let (hdr_name, hdr_val) = auth_header();
        let body = serde_json::json!({
            "url": ["https://a.com/1.mp4", "https://b.com/2.mp4"],
            "token": "yes",
            "req_headers": {"0": "Referer:https://a.com/", "1": "Referer:https://b.com/"},
            "filename": {"0": "movie1.mp4", "1": "movie2.mp4"}
        });
        let req = test::TestRequest::post()
            .uri("/v0/proxy")
            .insert_header((hdr_name, hdr_val))
            .insert_header(("Content-Type", "application/json"))
            .set_json(&body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let resp_body: ProxifyResponse = test::read_body_json(resp).await;
        assert_eq!(resp_body.total_items, 2);
        assert_eq!(resp_body.items.len(), 2);
        // Verify each link embeds the correct URL
        for item in &resp_body.items {
            assert!(item.url.contains("token="));
        }
    }

    // -- Unit tests for helper functions --

    #[::core::prelude::v1::test]
    fn parse_headers_basic() {
        let headers = parse_headers("Referer:https://example.com/|User-Agent:test");
        assert_eq!(headers.get("Referer").unwrap(), "https://example.com/");
        assert_eq!(headers.get("User-Agent").unwrap(), "test");
    }

    #[::core::prelude::v1::test]
    fn parse_headers_empty() {
        let headers = parse_headers("");
        assert!(headers.is_empty());
    }

    #[::core::prelude::v1::test]
    fn parse_expiration_seconds_from_now() {
        let exp = parse_expiration("3600").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(exp >= now + 3590 && exp <= now + 3610);
    }

    #[::core::prelude::v1::test]
    fn parse_expiration_empty_returns_none() {
        assert_eq!(parse_expiration(""), None);
        assert_eq!(parse_expiration("  "), None);
    }

    #[::core::prelude::v1::test]
    fn parse_expiration_zero_returns_none() {
        assert_eq!(parse_expiration("0"), None);
    }

    #[::core::prelude::v1::test]
    fn parse_query_string_basic() {
        let req = parse_query_string("url=https://a.com/1.mp4&url=https://b.com/2.mp4&token=yes");
        assert_eq!(req.url.len(), 2);
        assert_eq!(req.url[0], "https://a.com/1.mp4");
        assert_eq!(req.url[1], "https://b.com/2.mp4");
        assert_eq!(req.token, Some("yes".to_string()));
    }

    #[::core::prelude::v1::test]
    fn parse_query_string_indexed_headers() {
        let req = parse_query_string(
            "url=https://a.com&req_headers[0]=Referer:https://a.com/&req_headers[1]=Referer:https://b.com/"
        );
        assert_eq!(req.req_headers.get(0), Some("Referer:https://a.com/"));
        assert_eq!(req.req_headers.get(1), Some("Referer:https://b.com/"));
    }

    #[::core::prelude::v1::test]
    fn parse_query_string_shared_headers_fallback() {
        let req = parse_query_string("url=https://a.com&req_headers=UA:test");
        assert_eq!(req.req_headers.get(0), Some("UA:test"));
        assert_eq!(req.req_headers.get(99), Some("UA:test"));
    }

    #[::core::prelude::v1::test]
    fn indexed_or_shared_get_prefers_indexed() {
        let ios = IndexedOrShared {
            shared: Some("shared-val".to_string()),
            indexed: {
                let mut m = BTreeMap::new();
                m.insert(0, "indexed-val".to_string());
                m
            },
        };
        assert_eq!(ios.get(0), Some("indexed-val"));
        assert_eq!(ios.get(1), Some("shared-val"));
    }
}
