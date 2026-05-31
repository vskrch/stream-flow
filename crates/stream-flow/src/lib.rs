//! `stream_flow` — unified Stremio streaming-proxy + debrid-orchestration
//! library crate.
//!
//! All application logic lives in this library crate. The `stream-flow-bin`
//! binary is a thin `main` that wires config + server, and the
//! `stream-flow-ffi` staticlib re-uses these same APIs across the C-ABI
//! (design: Workspace and Crate Layout; Req 49.6).
//!
//! [`build_app`] is the single factory both the binary and the integration
//! test harness construct their routing tree from, so they exercise the
//! *identical* service graph (Req 49.6). It takes the shared [`AppState`]
//! (defined in [`app`]) and mounts the dual-surface
//! [`router`](http::router): the two disjoint `mediaflow` / `stremthru` path
//! namespaces plus the shared routes onto one handler set (Req 36.1, 36.2).
//! Endpoint behaviour is filled in by later tasks; this is the router skeleton
//! (task 11.2).

pub mod acestream;
pub mod app;
pub mod health_score;
pub mod auth;
pub mod cache;
pub mod config;
pub mod content_proxy;
pub mod drm;
pub mod egress;
pub mod epg;
pub mod errors;
pub mod extractor;
pub mod integrations;
pub mod health;
pub mod hls;
pub mod http;
pub mod meta;
pub mod mpd;
pub mod quality;
pub mod observability;
pub mod persistence;
pub mod prebuffer;
pub mod proxy;
pub mod proxylink;
pub mod rate_limit;
pub mod resilience;
pub mod security;
pub mod sse;
pub mod store;
pub mod stremio;
pub mod subtitles;
pub mod supervisor;
pub mod telegram;
pub mod transcode;
pub mod utils;
pub mod xtream;

use actix_web::{dev::HttpServiceFactory, web};

pub use crate::app::AppState;
use crate::http::PanicBoundary;

/// Build the application's routing tree from the shared [`AppState`].
///
/// Returns an actix [`HttpServiceFactory`] so the binary
/// (`App::new().service(build_app(state))`) and the test harness
/// (`test::init_service(App::new().service(build_app(state)))`) construct the
/// exact same service graph over the exact same dependencies (Req 49.6).
///
/// The returned scope is wrapped by the top-level [`PanicBoundary`] so a
/// panicking handler is isolated to its own request and converted to a `500`
/// without terminating the worker (Req 47.3, 50.8), and delegates route
/// registration to [`http::router::configure`], which layers the two disjoint
/// path namespaces (`mediaflow` + `stremthru`) plus the shared routes onto one
/// handler set (Req 36.1, 36.2).
///
/// When rate limiting is enabled in the config (Req 40), the
/// [`RateLimiterMiddleware`](rate_limit::RateLimiterMiddleware) is applied to
/// the scope so every route (except `/health` and `/metrics`, which are exempt
/// per Req 40.6) is subject to per-user / per-IP token-bucket enforcement.
pub fn build_app(state: AppState) -> impl HttpServiceFactory {
    use std::sync::Arc;
    use rate_limit::{RateLimiter, RateLimiterMiddleware};

    // Build the rate limiter from the config. When disabled, the limiter is
    // still constructed but the middleware checks `is_exempt` for all paths
    // (since the config has `enabled: false`, the middleware is a no-op).
    // We always wrap with the middleware so the return type is uniform.
    let limiter = Arc::new(RateLimiter::new(
        &state.config().ratelimit,
        state.rate_limit_cache(),
    ));

    web::scope("")
        .wrap(PanicBoundary)
        .wrap(RateLimiterMiddleware::new(limiter))
        .configure(move |cfg| http::router::configure(cfg, &state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn build_app_registers_health_route() {
        let state = AppState::new(Config::default());
        let app = test::init_service(App::new().service(build_app(state))).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
