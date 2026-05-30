//! Binary-crate smoke test (task 1.3) — Req 49.6.
//!
//! Asserts that the `stream-flow-bin` package (whose `[[bin]]` target is named
//! `stream-flow`) links against the `stream_flow` library crate. The binary's
//! `main.rs` constructs its server from [`stream_flow::build_app`]; this
//! integration test — compiled as part of the same package's dependency graph
//! — reuses that very symbol, proving the library is on the binary's link path
//! (Req 49.6: "expose both a library crate and a binary crate from one
//! workspace so that the library is reusable").
//!
//! If the binary package ever dropped its dependency on the library, this test
//! would fail to compile, locking in the cross-crate link contract.

use actix_web::{test, App};

/// The binary package can reach `stream_flow::build_app` — the same factory its
/// `main.rs` mounts — confirming the binary target links against the library.
#[actix_web::test]
async fn binary_package_links_against_library() {
    // Identical construction path to `main.rs`: `App::new().service(build_app())`.
    let app = test::init_service(App::new().service(stream_flow::build_app())).await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "the library's build_app (as used by the binary) should serve /health, got {}",
        resp.status()
    );
}
