//! The `/metrics` HTTP endpoint (`observability::endpoint`) — Req 32.1, 32.2.
//!
//! Renders the shared [`Metrics`] registry in Prometheus text exposition format
//! (Req 32.1) **behind the metrics password** (Req 32.2): a request with a
//! valid metrics password gets the exposition, anything else gets a
//! `401 Unauthorized`.
//!
//! The metrics password is presented either as the `X-Metrics-Password` header
//! or the `metrics_password` query parameter (mirroring how the API password is
//! presented on the mediaflow surface, [`auth::middleware`](crate::auth::middleware)).
//! When **no** metrics password is configured the endpoint is open — matching
//! `mediaflow-proxy-light`, whose `/metrics` is unauthenticated because the data
//! is not sensitive — so a drop-in deployment keeps working; an operator opts
//! into protection by setting `auth.metrics_password` (Req 32.2).

use actix_web::{web, HttpRequest, HttpResponse};

use crate::app::AppState;
use crate::auth::constant_time_eq;
use crate::errors::AppError;

/// The header carrying the metrics password.
pub const METRICS_PASSWORD_HEADER: &str = "X-Metrics-Password";

/// The query-parameter carrying the metrics password.
pub const METRICS_PASSWORD_QUERY: &str = "metrics_password";

/// The `/metrics` handler (Req 32.1, 32.2).
///
/// Reads the shared [`AppState`] from app data, authorizes the request against
/// the configured metrics password, and on success returns the Prometheus
/// exposition with the correct `Content-Type`.
pub async fn metrics_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    authorize_metrics(&req, &state)?;

    let metrics = state.metrics();
    Ok(HttpResponse::Ok()
        .content_type(metrics.content_type())
        .body(metrics.gather()))
}

/// Authorize a `/metrics` request against the configured metrics password
/// (Req 32.2). `Ok(())` when authorized (or when no password is configured);
/// `401 Unauthorized` otherwise. The comparison is constant-time (Req 28.8).
fn authorize_metrics(req: &HttpRequest, state: &AppState) -> Result<(), AppError> {
    let Some(expected) = state
        .config()
        .auth
        .metrics_password
        .as_ref()
        .map(|s| s.expose())
        .filter(|p| !p.is_empty())
    else {
        // No metrics password configured: open endpoint (drop-in parity).
        return Ok(());
    };

    let presented = extract_metrics_password(req);
    match presented {
        Some(p) if constant_time_eq(expected.as_bytes(), p.as_bytes()) => Ok(()),
        _ => Err(AppError::unauthorized(
            "invalid or missing metrics password",
        )),
    }
}

/// Extract the presented metrics password, preferring the
/// `X-Metrics-Password` header and falling back to the `metrics_password`
/// query parameter.
fn extract_metrics_password(req: &HttpRequest) -> Option<String> {
    if let Some(value) = req
        .headers()
        .get(METRICS_PASSWORD_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        return Some(value.to_string());
    }
    extract_query_value(req.query_string(), METRICS_PASSWORD_QUERY)
}

/// Pull a single value for `key` out of a raw query string (split on `&`, match
/// the first `key=value`). Values are used only for a constant-time comparison,
/// so no percent-decoding is required for parity here.
fn extract_query_value(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, Config};
    use actix_web::test::TestRequest;

    fn state_with(password: Option<&str>) -> AppState {
        let mut config = Config::default();
        config.auth = AuthConfig {
            metrics_password: password.map(Into::into),
            ..AuthConfig::default()
        };
        AppState::new(config)
    }

    #[test]
    fn open_when_no_password_configured() {
        let state = state_with(None);
        let req = TestRequest::get().uri("/metrics").to_http_request();
        assert!(authorize_metrics(&req, &state).is_ok());
    }

    #[test]
    fn header_password_authorizes() {
        let state = state_with(Some("pw"));
        let req = TestRequest::get()
            .uri("/metrics")
            .insert_header((METRICS_PASSWORD_HEADER, "pw"))
            .to_http_request();
        assert!(authorize_metrics(&req, &state).is_ok());
    }

    #[test]
    fn query_password_authorizes() {
        let state = state_with(Some("pw"));
        let req = TestRequest::get()
            .uri("/metrics?metrics_password=pw")
            .to_http_request();
        assert!(authorize_metrics(&req, &state).is_ok());
    }

    #[test]
    fn missing_password_is_unauthorized() {
        let state = state_with(Some("pw"));
        let req = TestRequest::get().uri("/metrics").to_http_request();
        let err = authorize_metrics(&req, &state).unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::Unauthorized);
    }

    #[test]
    fn wrong_password_is_unauthorized() {
        let state = state_with(Some("pw"));
        let req = TestRequest::get()
            .uri("/metrics?metrics_password=nope")
            .to_http_request();
        let err = authorize_metrics(&req, &state).unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::Unauthorized);
    }
}
