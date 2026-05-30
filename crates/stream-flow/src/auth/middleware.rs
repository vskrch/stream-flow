//! Request-time auth extraction (`auth::middleware`) — Req 28.
//!
//! [`Auth`](crate::auth::Auth) holds the pure, transport-agnostic verifiers
//! (testable without an HTTP request). This module is the thin actix glue that
//! pulls the relevant material **out of a request** and hands it to those
//! verifiers, so handlers and the dual-surface router (task 11.2) call a single
//! function rather than re-implementing header/query plucking per endpoint.
//!
//! Two extraction surfaces mirror the two API families (design: Components →
//! Dual-Surface Router):
//!
//! * **Streaming_Proxy_Engine** (`mediaflow` paths) authenticate with the
//!   `API_Password`, presented either as the `api_password` query parameter or
//!   the `X-Api-Password` header (Req 36.5). [`verify_api_password_req`].
//! * **Orchestration_Layer** (`stremthru` paths) authenticate with the
//!   `X-StremThru-Authorization` HTTP Basic header (Req 28.2).
//!   [`verify_proxy_auth_req`].
//!
//! Both delegate the actual secret check (including the constant-time
//! comparison, Req 28.8) to [`Auth`], and surface the same typed [`AppError`]
//! the verifiers return (`401` / `403` + challenge).

use actix_web::HttpRequest;

use super::{Auth, UserId};
use crate::errors::AppError;

/// The header carrying the Orchestration_Layer's HTTP Basic Proxy_Auth
/// credentials (Req 28.2).
pub const PROXY_AUTH_HEADER: &str = "X-StremThru-Authorization";

/// An alternative header for presenting the `API_Password` (the `mediaflow`
/// surface primarily uses the `api_password` query parameter; this header is
/// accepted as a convenience for clients that prefer not to put the secret in
/// the URL).
pub const API_PASSWORD_HEADER: &str = "X-Api-Password";

/// The query-parameter name carrying the `API_Password` on `mediaflow` paths
/// (Req 36.5).
pub const API_PASSWORD_QUERY: &str = "api_password";

/// Extract the presented `API_Password` from a request, preferring the
/// `X-Api-Password` header and falling back to the `api_password` query
/// parameter.
///
/// Returns `None` when neither is present (the verifier then decides between a
/// `401` and no-auth passthrough).
pub fn extract_api_password(req: &HttpRequest) -> Option<String> {
    if let Some(value) = req
        .headers()
        .get(API_PASSWORD_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        return Some(value.to_string());
    }
    extract_query_value(req.query_string(), API_PASSWORD_QUERY)
}

/// Extract the raw `X-StremThru-Authorization` header value, if present.
pub fn extract_proxy_auth_header(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(PROXY_AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Verify the request's `API_Password` against `auth` (Req 28.1).
///
/// `401 Unauthorized` when absent/incorrect; `Ok(())` on match or in no-auth
/// mode. Thin wrapper over [`Auth::verify_api_password`].
pub fn verify_api_password_req(auth: &Auth, req: &HttpRequest) -> Result<(), AppError> {
    auth.verify_api_password(extract_api_password(req).as_deref())
}

/// Validate the request's Proxy_Auth header against `auth`, returning the
/// matched [`UserId`] (Req 28.2, 28.3).
///
/// `403 Forbidden` + authenticate challenge on failure. Thin wrapper over
/// [`Auth::verify_proxy_auth`].
pub fn verify_proxy_auth_req(auth: &Auth, req: &HttpRequest) -> Result<UserId, AppError> {
    auth.verify_proxy_auth(extract_proxy_auth_header(req).as_deref())
}

/// Pull a single, URL-decoded value for `key` out of a raw query string.
///
/// Mirrors the lenient parsing of `mediaflow-proxy-light`'s middleware: split
/// on `&`, match the first `key=value` pair, and percent-decode the value.
fn extract_query_value(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(
                    urlencoding_decode(v).unwrap_or_else(|| v.to_string()),
                );
            }
        }
    }
    None
}

/// Minimal percent-decoding for query values (no extra dependency): decodes
/// `%XX` escapes and `+` as space. Returns `None` on a malformed escape so the
/// caller can fall back to the raw value.
fn urlencoding_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = hex_val(*bytes.get(i + 1)?)?;
                let lo = hex_val(*bytes.get(i + 2)?)?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Decode a single ASCII hex digit to its 0–15 value.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::errors::ErrorCategory;
    use actix_web::test::TestRequest;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    fn auth_with(
        api_password: Option<&str>,
        proxy_auth: &[&str],
    ) -> Auth {
        let config = AuthConfig {
            api_password: api_password.map(Into::into),
            metrics_password: None,
            proxy_auth: proxy_auth.iter().map(|s| s.to_string()).collect(),
            per_user_store: Vec::new(),
            admins: Vec::new(),
        };
        Auth::from_config(&config)
    }

    // -- API password extraction (Req 28.1, 36.5) ----------------------------

    #[test]
    fn api_password_from_query_param_is_verified() {
        let auth = auth_with(Some("s3cret"), &[]);
        let req = TestRequest::get()
            .uri("/proxy/stream?d=abc&api_password=s3cret")
            .to_http_request();
        assert!(verify_api_password_req(&auth, &req).is_ok());
    }

    #[test]
    fn api_password_from_header_is_verified() {
        let auth = auth_with(Some("s3cret"), &[]);
        let req = TestRequest::get()
            .uri("/proxy/stream")
            .insert_header((API_PASSWORD_HEADER, "s3cret"))
            .to_http_request();
        assert!(verify_api_password_req(&auth, &req).is_ok());
    }

    #[test]
    fn header_takes_precedence_over_query() {
        let auth = auth_with(Some("s3cret"), &[]);
        let req = TestRequest::get()
            .uri("/proxy/stream?api_password=wrong")
            .insert_header((API_PASSWORD_HEADER, "s3cret"))
            .to_http_request();
        assert!(verify_api_password_req(&auth, &req).is_ok());
    }

    #[test]
    fn missing_api_password_is_401() {
        let auth = auth_with(Some("s3cret"), &[]);
        let req = TestRequest::get().uri("/proxy/stream").to_http_request();
        let err = verify_api_password_req(&auth, &req).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
    }

    #[test]
    fn wrong_api_password_is_401() {
        let auth = auth_with(Some("s3cret"), &[]);
        let req = TestRequest::get()
            .uri("/proxy/stream?api_password=nope")
            .to_http_request();
        let err = verify_api_password_req(&auth, &req).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
    }

    #[test]
    fn url_encoded_api_password_is_decoded() {
        let auth = auth_with(Some("p @ss"), &[]);
        let req = TestRequest::get()
            .uri("/proxy/stream?api_password=p%20%40ss")
            .to_http_request();
        assert!(verify_api_password_req(&auth, &req).is_ok());
    }

    // -- Proxy auth extraction (Req 28.2, 28.3) ------------------------------

    #[test]
    fn proxy_auth_header_plain_is_verified() {
        let auth = auth_with(Some("x"), &["alice:wonderland"]);
        let req = TestRequest::get()
            .uri("/v0/proxy")
            .insert_header((PROXY_AUTH_HEADER, "alice:wonderland"))
            .to_http_request();
        let user = verify_proxy_auth_req(&auth, &req).unwrap();
        assert_eq!(user, UserId("alice".to_string()));
    }

    #[test]
    fn proxy_auth_header_base64_is_verified() {
        let auth = auth_with(Some("x"), &["alice:wonderland"]);
        let encoded = STANDARD.encode("alice:wonderland");
        let req = TestRequest::get()
            .uri("/v0/proxy")
            .insert_header((PROXY_AUTH_HEADER, format!("Basic {encoded}")))
            .to_http_request();
        let user = verify_proxy_auth_req(&auth, &req).unwrap();
        assert_eq!(user, UserId("alice".to_string()));
    }

    #[test]
    fn missing_proxy_auth_header_is_403_with_challenge() {
        let auth = auth_with(Some("x"), &["alice:wonderland"]);
        let req = TestRequest::get().uri("/v0/proxy").to_http_request();
        let err = verify_proxy_auth_req(&auth, &req).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.auth_challenge);
    }

    #[test]
    fn wrong_proxy_auth_header_is_403() {
        let auth = auth_with(Some("x"), &["alice:wonderland"]);
        let req = TestRequest::get()
            .uri("/v0/proxy")
            .insert_header((PROXY_AUTH_HEADER, "alice:wrong"))
            .to_http_request();
        let err = verify_proxy_auth_req(&auth, &req).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.auth_challenge);
    }
}
