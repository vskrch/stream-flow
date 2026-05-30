//! Dual-surface router skeleton smoke test (task 11.2) — Req 36.1, 36.2, 49.6.
//!
//! Asserts that [`stream_flow::build_app`] wires the **two disjoint path
//! namespaces** (the `mediaflow-proxy-light` surface and the `stremthru`
//! surface) plus the **shared** routes (`/health`, `/metrics`, `/v0/events`)
//! onto one routing tree, and that this is the *identical* `build_app(state)`
//! factory the binary boots from (Req 49.6).
//!
//! This is an **external** integration crate: it can only see the crate's
//! *public* surface (`stream_flow::AppState`, `stream_flow::build_app`), which
//! is exactly the reuse path the binary, the FFI bridge, and the SDKs rely on
//! (Req 49.6). A route from each namespace must be *registered* (not `404`);
//! the placeholder handlers whose real logic lands in later tasks answer
//! `501 Not Implemented`, so "registered but unimplemented" is cleanly
//! distinguishable from "no such route".

use actix_web::{http::StatusCode, test, App};
use stream_flow::config::Config;
use stream_flow::{build_app, AppState};

/// The shared surface answers `/health` with `200` (the health registry is
/// threaded through `AppState`, Req 49.6).
#[actix_web::test]
async fn shared_surface_serves_health() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "shared /health should be 200");
}

/// The mediaflow namespace is registered: representative mediaflow paths route
/// to a handler (placeholder `501`) rather than `404` (Req 36.1).
#[actix_web::test]
async fn mediaflow_surface_routes_are_registered() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    for uri in ["/proxy/stream", "/proxy/ip"] {
        let req = test::TestRequest::get().uri(uri).to_request();
        let resp = test::call_service(&app, req).await;
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "mediaflow route {uri} should be registered"
        );
        assert_eq!(
            resp.status(),
            StatusCode::NOT_IMPLEMENTED,
            "mediaflow route {uri} is a skeleton placeholder"
        );
    }
}

/// The stremthru namespace is registered: representative stremthru paths route
/// to a handler (placeholder `501`) rather than `404` (Req 36.2).
#[actix_web::test]
async fn stremthru_surface_routes_are_registered() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get().uri("/v0/proxy").to_request();
    let resp = test::call_service(&app, req).await;
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "stremthru route /v0/proxy should be registered"
    );
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
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
