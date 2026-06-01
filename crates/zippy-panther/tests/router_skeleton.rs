//! Dual-surface router skeleton smoke test (task 11.2) — Req 36.1, 36.2, 49.6.
//!
//! Asserts that [`zippy_panther::build_app`] wires the **two disjoint path
//! namespaces** (the `mediaflow-proxy-light` surface and the `stremthru`
//! surface) plus the **shared** routes (`/health`, `/metrics`, `/v0/events`,
//! web UI) onto one routing tree, and that this is the *identical*
//! `build_app(state)` factory the binary boots from (Req 49.6).
//!
//! This is an **external** integration crate: it can only see the crate's
//! *public* surface (`zippy_panther::AppState`, `zippy_panther::build_app`), which
//! is exactly the reuse path the binary, the FFI bridge, and the SDKs rely on
//! (Req 49.6). A route from each namespace must be *registered* (not `404`).

use actix_web::{http::StatusCode, test, App};
use zippy_panther::config::Config;
use zippy_panther::{build_app, AppState};

/// The shared surface answers `/health` with `200` (the health registry is
/// threaded through `AppState`, Req 49.6).
#[actix_web::test]
async fn shared_surface_serves_health() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "shared /health should be 200"
    );
}

/// The mediaflow namespace is registered: representative mediaflow paths route
/// to production handlers rather than `404` (Req 36.1).
#[actix_web::test]
async fn mediaflow_surface_routes_are_registered() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    // `/proxy/stream` is backed by the real content-proxy endpoint. Without a
    // `d`/`token` parameter it rejects the request as malformed, proving the
    // route is registered and no longer a placeholder.
    let req = test::TestRequest::get().uri("/proxy/stream").to_request();
    let resp = test::call_service(&app, req).await;
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "mediaflow route /proxy/stream should be registered"
    );
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "mediaflow route /proxy/stream validates proxy-link input"
    );

    // `/proxy/ip` is backed by its real handler (task 14.2): registered (not
    // `404`). With the default config the egress tunnel is disabled, so it
    // falls back to querying the host's public IP directly (safe: traffic goes
    // direct anyway). The endpoint returns 200 with a valid IP.
    let req = test::TestRequest::get().uri("/proxy/ip").to_request();
    let resp = test::call_service(&app, req).await;
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "mediaflow route /proxy/ip should be registered"
    );
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/proxy/ip falls back to host IP when no tunnel is configured"
    );
}

/// The stremthru namespace is registered: representative stremthru paths route
/// to a handler rather than `404` (Req 36.2).
#[actix_web::test]
async fn stremthru_surface_routes_are_registered() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    // `/v0/proxy` is backed by its real proxify-links handler (task 24.4):
    // an unauthenticated request is rejected by the proxy-auth gate with
    // `403 Forbidden` (Req 21.9) — registered (not `404`) and no longer the
    // skeleton `501`.
    let req = test::TestRequest::get().uri("/v0/proxy").to_request();
    let resp = test::call_service(&app, req).await;
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "stremthru route /v0/proxy should be registered"
    );
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "/v0/proxy rejects a missing Proxy_Auth with 403 (Req 21.9)"
    );
}

/// The two namespaces are **disjoint** and an unrelated path is genuinely
/// `404`, proving the smoke test above is not vacuously passing.
#[actix_web::test]
async fn unregistered_path_is_404() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get()
        .uri("/definitely/not/a/route")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// `build_app(state)` is reusable from an external crate — the exact contract
/// the binary, FFI bridge, and SDKs depend on (Req 49.6).
#[actix_web::test]
async fn build_app_is_reusable_with_shared_state() {
    // Binding the function item proves the public `build_app` symbol exists and
    // links from this external crate.
    let factory = build_app;
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(factory(state))).await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
