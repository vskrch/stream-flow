//! Workspace smoke test (task 1.3) — Req 49.6.
//!
//! Asserts that the `stream_flow` *library* crate exposes the public
//! [`stream_flow::build_app`] factory and that it is reusable from an
//! **external** crate. This integration test is compiled as its own crate that
//! depends on `stream_flow`, exercising the exact reuse path the FFI bridge and
//! the JS/Python SDKs rely on (Req 49.6: "expose both a library crate and a
//! binary crate from one workspace so that the library is reusable by the
//! FFI_Bridge and SDKs").
//!
//! Unlike the `#[cfg(test)]` unit test inside `lib.rs` (which can see private
//! items), this test only has access to the crate's *public* surface — so if
//! `build_app` were not `pub`, this test would fail to compile, which is
//! precisely the contract we want to lock in.

use actix_web::App;
use stream_flow::config::Config;
use stream_flow::AppState;

/// The library publicly exposes `build_app`, and the routing tree it returns
/// is mountable by any external consumer (binary, FFI bridge, or SDK).
#[actix_web::test]
async fn library_exposes_reusable_build_app() {
    // Binding the function item proves the public `build_app` symbol exists and
    // resolves at link time from this external crate (Req 49.6); the binary and
    // the FFI/SDK consumers construct the *identical* routing tree from it.
    let factory = stream_flow::build_app;

    // Reusing `build_app` from this external test crate proves it is part of
    // the public API and links against the library crate (Req 49.6). It takes
    // the shared `AppState` (also part of the public surface) the binary builds.
    let state = AppState::new(Config::default());
    let app = actix_web::test::init_service(App::new().service(factory(state))).await;

    // The reused factory produces a live routing tree.
    let req = actix_web::test::TestRequest::get().uri("/health").to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "build_app's routing tree should serve /health, got {}",
        resp.status()
    );
}
