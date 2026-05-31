//! Streaming-utility endpoint integration tests (task 20.1) — Req 15.
//!
//! Drives the real [`stream_flow::build_app`] routing tree (the same factory
//! the binary boots from, Req 49.6) and asserts the mediaflow streaming-utility
//! surface is wired to its real handlers:
//!
//! * `/base64/{encode,decode,check}` (Req 15.3–15.5, 15.9),
//! * `/generate_url` (Req 15.7),
//! * `/playlist/builder` (Req 15.1),
//! * `/health` success (Req 15.8).
//!
//! These are **external** integration tests, so they exercise only the public
//! surface — exactly the reuse path real clients depend on.

use actix_web::{http::StatusCode, test, App};
use serde_json::json;
use stream_flow::config::Config;
use stream_flow::{build_app, AppState};

/// Req 15.8: `/health` returns a success response.
#[actix_web::test]
async fn health_returns_success() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "/health must indicate the service is operational"
    );
}

/// Req 15.3: base64 encode returns the encoding of the input.
#[actix_web::test]
async fn base64_encode_returns_encoding() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get()
        .uri("/base64/encode?value=hello")
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(body["encoded"], "aGVsbG8=");
}

/// Req 15.4: base64 decode returns the decoded value for valid input.
#[actix_web::test]
async fn base64_decode_returns_decoded_value() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get()
        .uri("/base64/decode?value=aGVsbG8=")
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(body["decoded"], "hello");
}

/// Req 15.9: base64 decode of invalid input is a descriptive error.
#[actix_web::test]
async fn base64_decode_invalid_is_error() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::get()
        .uri("/base64/decode?value=%2A%2A%2Anope%2A%2A%2A")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "invalid base64 must be a 400"
    );
}

/// Req 15.5: base64 check reports validity.
#[actix_web::test]
async fn base64_check_reports_validity() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let valid = test::TestRequest::get()
        .uri("/base64/check?value=aGVsbG8=")
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, valid).await;
    assert_eq!(body["valid"], true);

    let invalid = test::TestRequest::get()
        .uri("/base64/check?value=not%2Avalid")
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, invalid).await;
    assert_eq!(body["valid"], false);
}

/// Req 15.7: generate-URL returns a proxy URL built from the request params.
#[actix_web::test]
async fn generate_url_returns_proxy_url() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::post()
        .uri("/generate_url")
        .set_json(json!({
            "mediaflow_proxy_url": "https://proxy.example.com",
            "endpoint": "/proxy/stream",
            "destination_url": "https://cdn.example.com/movie.mkv",
        }))
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let url = body["url"].as_str().expect("url field present");
    assert!(
        url.starts_with("https://proxy.example.com/proxy/stream?"),
        "got: {url}"
    );
    assert!(
        url.contains("d="),
        "the generated URL must carry the encrypted d token"
    );
    assert!(
        !url.contains("cdn.example.com"),
        "origin URL must not leak in cleartext"
    );
}

/// Req 15.1: the playlist builder rewrites every channel URL through the proxy.
#[actix_web::test]
async fn playlist_builder_rewrites_channel_urls() {
    let state = AppState::new(Config::default());
    let app = test::init_service(App::new().service(build_app(state))).await;

    let req = test::TestRequest::post()
        .uri("/playlist/builder")
        .set_json(json!({
            "mediaflow_proxy_url": "https://proxy.example.com",
            "endpoint": "/proxy/stream",
            "channels": [
                { "name": "One", "url": "https://origin.example/one.m3u8" },
                { "name": "Two", "url": "https://origin.example/two.m3u8" }
            ]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let playlist = String::from_utf8(body.to_vec()).expect("utf8 playlist");

    assert!(playlist.starts_with("#EXTM3U"));
    // Every non-comment URL line is rewritten to the proxy host, none to origin.
    for line in playlist
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        assert!(
            line.starts_with("https://proxy.example.com/proxy/stream?d="),
            "got: {line}"
        );
        assert!(
            !line.contains("origin.example"),
            "origin must not leak: {line}"
        );
    }
}
