//! Proxy-URL generation (`utils::generate_url`) — Req 15.7.
//!
//! Backs the mediaflow `/generate_url` endpoint: given a destination URL plus
//! optional injected headers, expiry, IP binding, and a target proxy endpoint,
//! it returns a ready-to-use proxy URL whose parameters are sealed in an
//! encrypted `d` token (the mediaflow AES-CBC form, [`auth::encryption`]) and
//! whose path is prefixed with the configured `Server_Path_Prefix` so links
//! work behind a reverse proxy (Req 15.7, 31.4).
//!
//! The URL shape mirrors `mediaflow-proxy-light` for drop-in compatibility
//! (Req 36.5/36.7):
//!
//! ```text
//! {base}{server_path_prefix}{endpoint}?d={base64url(IV || AES-CBC-PKCS7(json))}
//! ```
//!
//! where `json` is the [`ProxyPayload`] holding the destination `url`, injected
//! `headers`, optional `filename`, `exp`, and `ip`. The encryption key is
//! derived from the configured `API_Password` ([`CbcKey::from_api_password`]),
//! so the generated `d` token is decryptable by the streaming surface that
//! consumes it (task 20.2).

use std::collections::BTreeMap;
use std::net::IpAddr;

use actix_web::{web, HttpResponse};
use url::Url;

use crate::app::AppState;
use crate::auth::encryption::{encrypt, CbcKey, ProxyPayload};
use crate::config::Config;
use crate::errors::AppError;

/// The default proxy endpoint a generated link targets when the caller does not
/// specify one — the generic byte-stream proxy (Req 5).
const DEFAULT_ENDPOINT: &str = "/proxy/stream";

/// The request body / query for `/generate_url` (Req 15.7).
///
/// Field names mirror the `mediaflow-proxy-light` `GenerateUrlRequest` so
/// existing clients are drop-in compatible (Req 36.5).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct GenerateUrlRequest {
    /// The public base URL of this proxy (scheme + host[:port]); when omitted
    /// the request is rejected (we cannot synthesize a host from the config
    /// bind address behind a reverse proxy).
    #[serde(default)]
    pub mediaflow_proxy_url: Option<String>,
    /// The proxy endpoint to target, e.g. `/proxy/stream` or
    /// `/proxy/hls/manifest.m3u8`. Defaults to [`DEFAULT_ENDPOINT`].
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The upstream URL the proxy will fetch (sealed into the `d` token).
    pub destination_url: String,
    /// Extra query parameters appended verbatim to the generated URL.
    #[serde(default)]
    pub query_params: BTreeMap<String, String>,
    /// Upstream request headers to inject (sealed into the `d` token).
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
    /// Optional download filename hint (sealed into the `d` token).
    #[serde(default)]
    pub filename: Option<String>,
    /// Optional lifetime in seconds; when set, the sealed payload carries an
    /// `exp` of `now + expiration` (Req 14.2).
    #[serde(default)]
    pub expiration: Option<i64>,
    /// Optional client-IP binding sealed into the payload (Req 14.3).
    #[serde(default)]
    pub ip: Option<IpAddr>,
}

/// Build a sealed proxy URL from the request, the configured
/// `Server_Path_Prefix`, and an AES-CBC key (Req 15.7).
///
/// `now_unix_secs` is threaded in (rather than read from the clock) so the
/// expiry computation is deterministic and unit-testable. Returns a
/// [`bad_request`](AppError::bad_request) when a required field is missing or a
/// supplied URL does not parse.
pub fn build_proxy_url(
    req: &GenerateUrlRequest,
    path_prefix: &str,
    key: &CbcKey,
    now_unix_secs: i64,
) -> Result<String, AppError> {
    if req.destination_url.trim().is_empty() {
        return Err(AppError::bad_request("missing required `destination_url`"));
    }
    let base = req
        .mediaflow_proxy_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("missing required `mediaflow_proxy_url`"))?;

    let mut url = Url::parse(base)
        .map_err(|e| AppError::bad_request(format!("invalid `mediaflow_proxy_url` `{base}`: {e}")))?;

    // The generated path is the configured public prefix (Req 31.4) followed by
    // the target endpoint, with the endpoint normalized to a single leading
    // slash so callers may pass `proxy/stream` or `/proxy/stream` alike.
    let endpoint = req.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT);
    let endpoint = normalize_endpoint(endpoint);
    let full_path = format!("{path_prefix}{endpoint}");
    url.set_path(&full_path);

    // Seal the upstream URL + headers + expiry/ip into the mediaflow `d` token.
    let payload = ProxyPayload {
        url: req.destination_url.clone(),
        headers: req.request_headers.clone(),
        filename: req.filename.clone(),
        exp: req.expiration.map(|secs| now_unix_secs + secs),
        ip: req.ip,
    };
    let token = encrypt(&payload, key)?;

    // `d` first, then any extra query params, all percent-encoded by `url`.
    {
        let mut pairs = url.query_pairs_mut();
        pairs.clear();
        pairs.append_pair("d", &token);
        for (k, v) in &req.query_params {
            pairs.append_pair(k, v);
        }
    }

    Ok(url.into())
}

/// Normalize a caller-supplied endpoint to exactly one leading slash and no
/// trailing slash padding, collapsing accidental empties to the default.
fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return DEFAULT_ENDPOINT.to_string();
    }
    if let Some(stripped) = trimmed.strip_prefix('/') {
        format!("/{}", stripped.trim_start_matches('/'))
    } else {
        format!("/{trimmed}")
    }
}

/// Derive the AES-CBC key from the configured `API_Password` (Req 14.1).
///
/// The `API_Password` is the one required config value (validated at load), so
/// it is always present in a running system; a defensive empty-string fallback
/// keeps this total.
fn key_from_config(config: &Config) -> CbcKey {
    let password = config
        .auth
        .api_password
        .as_ref()
        .map(|s| s.expose())
        .unwrap_or("");
    CbcKey::from_api_password(password)
}

/// `POST /generate_url` — return a sealed proxy URL built from the request body
/// and the configured `Server_Path_Prefix` (Req 15.7).
pub async fn generate_url_endpoint(
    state: web::Data<AppState>,
    body: web::Json<GenerateUrlRequest>,
) -> Result<HttpResponse, AppError> {
    let config = state.config();
    let key = key_from_config(config);
    let now = now_unix_secs();
    let url = build_proxy_url(&body, &config.server.path_prefix, &key, now)?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "url": url })))
}

/// Current unix time in whole seconds (wall clock). Isolated here so
/// [`build_proxy_url`] stays a pure function of its `now_unix_secs` argument.
fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::encryption::decrypt;
    use crate::errors::ErrorCategory;

    fn key() -> CbcKey {
        CbcKey::from_api_password("test-password")
    }

    fn base_request() -> GenerateUrlRequest {
        GenerateUrlRequest {
            mediaflow_proxy_url: Some("https://proxy.example.com".to_string()),
            endpoint: Some("/proxy/stream".to_string()),
            destination_url: "https://cdn.example.com/movie.mkv".to_string(),
            ..GenerateUrlRequest::default()
        }
    }

    // -- Req 15.7: URL built from params + Server_Path_Prefix -----------------

    #[test]
    fn builds_url_with_endpoint_and_no_prefix() {
        let url = build_proxy_url(&base_request(), "", &key(), 1_000).unwrap();
        let parsed = Url::parse(&url).unwrap();
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("proxy.example.com"));
        assert_eq!(parsed.path(), "/proxy/stream");
        // The `d` token is present.
        assert!(parsed.query_pairs().any(|(k, _)| k == "d"));
    }

    #[test]
    fn applies_configured_server_path_prefix() {
        let url = build_proxy_url(&base_request(), "/api/v1", &key(), 1_000).unwrap();
        let parsed = Url::parse(&url).unwrap();
        assert_eq!(
            parsed.path(),
            "/api/v1/proxy/stream",
            "the generated path must carry the configured Server_Path_Prefix",
        );
    }

    #[test]
    fn defaults_endpoint_when_absent() {
        let mut req = base_request();
        req.endpoint = None;
        let url = build_proxy_url(&req, "", &key(), 1_000).unwrap();
        assert_eq!(Url::parse(&url).unwrap().path(), "/proxy/stream");
    }

    #[test]
    fn endpoint_without_leading_slash_is_normalized() {
        let mut req = base_request();
        req.endpoint = Some("proxy/hls/manifest.m3u8".to_string());
        let url = build_proxy_url(&req, "/p", &key(), 1_000).unwrap();
        assert_eq!(Url::parse(&url).unwrap().path(), "/p/proxy/hls/manifest.m3u8");
    }

    // -- The sealed `d` token round-trips back to the destination params ------

    #[test]
    fn d_token_decrypts_back_to_the_destination_and_headers() {
        let mut req = base_request();
        req.request_headers
            .insert("Referer".to_string(), "https://ref.example/".to_string());
        req.filename = Some("movie.mkv".to_string());

        let url = build_proxy_url(&req, "", &key(), 1_000).unwrap();
        let parsed = Url::parse(&url).unwrap();
        let token = parsed
            .query_pairs()
            .find(|(k, _)| k == "d")
            .map(|(_, v)| v.into_owned())
            .expect("d token present");

        let payload = decrypt(&token, &key()).expect("d decrypts with the configured key");
        assert_eq!(payload.url, "https://cdn.example.com/movie.mkv");
        assert_eq!(payload.headers.get("Referer").map(String::as_str), Some("https://ref.example/"));
        assert_eq!(payload.filename.as_deref(), Some("movie.mkv"));
    }

    #[test]
    fn expiration_is_relative_to_now() {
        let mut req = base_request();
        req.expiration = Some(3_600);
        let url = build_proxy_url(&req, "", &key(), 1_000).unwrap();
        let token = Url::parse(&url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "d")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        let payload = decrypt(&token, &key()).unwrap();
        assert_eq!(payload.exp, Some(4_600), "exp must be now + expiration");
    }

    #[test]
    fn ip_binding_is_sealed_into_the_token() {
        let mut req = base_request();
        req.ip = Some("203.0.113.7".parse().unwrap());
        let url = build_proxy_url(&req, "", &key(), 1_000).unwrap();
        let token = Url::parse(&url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "d")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        let payload = decrypt(&token, &key()).unwrap();
        assert_eq!(payload.ip, Some("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn extra_query_params_are_appended_and_encoded() {
        let mut req = base_request();
        req.query_params
            .insert("api_password".to_string(), "p@ss word".to_string());
        let url = build_proxy_url(&req, "", &key(), 1_000).unwrap();
        let parsed = Url::parse(&url).unwrap();
        let got: Option<String> = parsed
            .query_pairs()
            .find(|(k, _)| k == "api_password")
            .map(|(_, v)| v.into_owned());
        assert_eq!(got.as_deref(), Some("p@ss word"), "value must round-trip through percent-encoding");
    }

    // -- Validation errors ----------------------------------------------------

    #[test]
    fn rejects_missing_destination_url() {
        let mut req = base_request();
        req.destination_url = "".to_string();
        let err = build_proxy_url(&req, "", &key(), 1_000).unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    #[test]
    fn rejects_missing_base_url() {
        let mut req = base_request();
        req.mediaflow_proxy_url = None;
        let err = build_proxy_url(&req, "", &key(), 1_000).unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    #[test]
    fn rejects_unparseable_base_url() {
        let mut req = base_request();
        req.mediaflow_proxy_url = Some("not a url".to_string());
        let err = build_proxy_url(&req, "", &key(), 1_000).unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }
}
