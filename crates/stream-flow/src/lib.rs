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
pub mod auth;
pub mod cache;
pub mod config;
pub mod drm;
pub mod egress;
pub mod epg;
pub mod errors;
pub mod extractor;
pub mod health;
pub mod hls;
pub mod http;
pub mod mpd;
pub mod observability;
pub mod persistence;
pub mod prebuffer;
pub mod proxy;
pub mod proxylink;
pub mod resilience;
pub mod security;
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
pub fn build_app(state: AppState) -> impl HttpServiceFactory {
    web::scope("")
        .wrap(PanicBoundary)
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
