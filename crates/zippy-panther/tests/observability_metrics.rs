//! Observability integration tests (task 12.1) — Req 32.1, 32.2, 32.5, 32.6, 46.7.
//!
//! Exercises the public observability surface the way the binary and the
//! dual-surface router do: the `/metrics` endpoint is guarded by the metrics
//! password (Prometheus exposition on success, `401` otherwise — Req 32.1,
//! 32.2), the [`Metrics`](zippy_panther::observability::Metrics) registry records
//! counters/latencies for proxied requests, store ops, cache hit/miss, and
//! upstream failures (Req 32.5), and the
//! [`Redactor`](zippy_panther::observability::Redactor) scrubs known secrets out
//! of URLs/headers before they reach a log line (Req 32.6, 46.7).

use actix_web::{http::StatusCode, test, App};
use zippy_panther::config::{AuthConfig, Config};
use zippy_panther::observability::{Metrics, Redactor};
use zippy_panther::{build_app, AppState};

// NOTE: actix's `test` is imported as a *module* path (`test::init_service`)
// only; we never bring its attribute macro into attribute position. Async
// tests use the fully-qualified `#[actix_web::test]`, and the synchronous unit
// tests below use the standard-library `#[::core::prelude::v1::test]` so the
// imported `test` module never shadows the built-in `#[test]` attribute.

/// Build an [`AppState`] whose config carries the given metrics password.
fn state_with_metrics_password(password: Option<&str>) -> AppState {
    let config = Config {
        auth: AuthConfig {
            api_password: Some("api".into()),
            metrics_password: password.map(Into::into),
            ..AuthConfig::default()
        },
        ..Config::default()
    };
    AppState::new(config)
}

// -- /metrics endpoint (Req 32.1, 32.2) --------------------------------------

#[actix_web::test]
async fn metrics_with_correct_password_returns_prometheus_exposition() {
    let state = state_with_metrics_password(Some("metrics-pw"));
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get()
        .uri("/metrics")
        .insert_header(("X-Metrics-Password", "metrics-pw"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.contains("text/plain"),
        "Prometheus exposition is text/plain, got {content_type:?}"
    );

    let body = test::read_body(resp).await;
    let text = String::from_utf8(body.to_vec()).unwrap();
    // Prometheus exposition format always carries HELP/TYPE comment lines.
    assert!(text.contains("# HELP"), "missing HELP lines:\n{text}");
    assert!(text.contains("# TYPE"), "missing TYPE lines:\n{text}");
}

#[actix_web::test]
async fn metrics_password_via_query_param_is_accepted() {
    let state = state_with_metrics_password(Some("metrics-pw"));
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get()
        .uri("/metrics?metrics_password=metrics-pw")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn metrics_without_password_is_401_when_configured() {
    let state = state_with_metrics_password(Some("metrics-pw"));
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn metrics_with_wrong_password_is_401() {
    let state = state_with_metrics_password(Some("metrics-pw"));
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get()
        .uri("/metrics?metrics_password=nope")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// -- Metrics registry (Req 32.5) ---------------------------------------------

#[::core::prelude::v1::test]
fn metrics_registry_records_and_exposes_all_required_series() {
    let metrics = Metrics::new();

    metrics.record_proxied_request("success", std::time::Duration::from_millis(12));
    metrics.record_store_op(
        "realdebrid",
        "success",
        std::time::Duration::from_millis(30),
    );
    metrics.record_cache_hit();
    metrics.record_cache_miss();
    metrics.record_upstream_failure("timeout");

    let exposition = metrics.gather();
    for series in [
        "zippy_panther_proxied_requests_total",
        "zippy_panther_proxied_request_duration_seconds",
        "zippy_panther_store_operations_total",
        "zippy_panther_cache_hits_total",
        "zippy_panther_cache_misses_total",
        "zippy_panther_upstream_failures_total",
    ] {
        assert!(
            exposition.contains(series),
            "exposition missing {series}:\n{exposition}"
        );
    }
}

#[::core::prelude::v1::test]
fn metrics_registry_records_self_healing_actions() {
    // Req 50.14: every self-healing action is observable via metrics.
    let metrics = Metrics::new();

    metrics.record_retry();
    metrics.record_breaker_open("realdebrid");
    metrics.record_breaker_close("realdebrid");
    metrics.record_store_fallback();
    metrics.record_task_restart("prefetcher");
    metrics.record_redis_reattach();
    metrics.record_resource_reclaimed("sse_subscription");

    let exposition = metrics.gather();
    for series in [
        "zippy_panther_retries_total",
        "zippy_panther_circuit_breaker_transitions_total",
        "zippy_panther_store_fallbacks_total",
        "zippy_panther_task_restarts_total",
        "zippy_panther_redis_reattach_total",
        "zippy_panther_resources_reclaimed_total",
    ] {
        assert!(
            exposition.contains(series),
            "self-healing exposition missing {series}:\n{exposition}"
        );
    }
}

// -- Redaction (Req 32.6, 46.7) ----------------------------------------------

#[::core::prelude::v1::test]
fn redactor_scrubs_sensitive_query_parameters() {
    let redactor = Redactor::new();
    let line = "GET /proxy/stream?d=ENCRYPTED&api_password=hunter2&x=1 HTTP/1.1";
    let redacted = redactor.redact(line);
    assert!(
        !redacted.contains("hunter2"),
        "api_password leaked: {redacted}"
    );
    assert!(
        !redacted.contains("ENCRYPTED"),
        "encrypted d leaked: {redacted}"
    );
    // Non-secret params survive.
    assert!(redacted.contains("x=1"));
}

#[::core::prelude::v1::test]
fn redactor_scrubs_registered_secret_values_anywhere() {
    let redactor = Redactor::new();
    redactor.register_secret("super-secret-token");
    let line = "store call failed with Authorization: Bearer super-secret-token";
    let redacted = redactor.redact(line);
    assert!(
        !redacted.contains("super-secret-token"),
        "registered secret leaked: {redacted}"
    );
}

#[::core::prelude::v1::test]
fn redactor_scrubs_authorization_header_values() {
    let redactor = Redactor::new();
    let line = "X-StremThru-Authorization: Basic YWxpY2U6d29uZGVybGFuZA==";
    let redacted = redactor.redact(line);
    assert!(
        !redacted.contains("YWxpY2U6d29uZGVybGFuZA=="),
        "basic auth value leaked: {redacted}"
    );
}
