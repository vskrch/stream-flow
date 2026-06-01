//! Dual-surface router (`http::router`) — Req 36.1, 36.2.
//!
//! Registers **two disjoint path namespaces** against **one** set of internal
//! handlers (design: Subsystem Interaction Principle; Components → Dual-Surface
//! Router):
//!
//! * [`mediaflow_surface`] — the `mediaflow-proxy-light` paths (`/proxy/stream`,
//!   `/proxy/hls/*`, `/proxy/mpd/*`, `/proxy/ip`, `/extractor/video`,
//!   `/generate_url`, …), authenticated by `api_password` / AES-CBC `d` params
//!   (Req 36.1, 36.5).
//! * [`stremthru_surface`] — the `stremthru` paths (`/v0/proxy`, `/v0/store/*`,
//!   `/v0/meta/id-map/*`, `/stremio/*`), authenticated by
//!   `X-StremThru-Authorization` Basic + token proxy links (Req 36.2, 36.6).
//! * [`shared`] — surface-agnostic endpoints both projects expose
//!   (`/health`, `/metrics`, `/v0/events`, web UI).
//!
//! The router **never duplicates logic**: each surface decodes its own
//! auth/token form and then funnels into the shared internal handlers (e.g. the
//! mediaflow `/proxy/stream` and the stremthru `/v0/proxy` both terminate in
//! `proxy::core` in later tasks). Both surfaces run on the same listener and
//! share one [`AppState`] (design: "Both run on the same listener, sharing the
//! same `AppState`").
//!
//! The router is also the production composition point: endpoint modules own
//! their behavior, while this module keeps path registration consistent between
//! the binary, tests, and embedded deployments.

use actix_web::web;

use crate::app::AppState;

/// Configure the whole dual-surface routing tree onto an actix
/// [`ServiceConfig`](actix_web::web::ServiceConfig).
///
/// This is the single composition point the design specifies: it layers the
/// two disjoint namespaces plus the shared routes onto one config, so
/// [`build_app`](crate::build_app) — used identically by the binary and the
/// integration tests (Req 49.6) — produces one consistent service graph.
pub fn configure(cfg: &mut web::ServiceConfig, state: &AppState) {
    // The shared `AppState` is registered once as app data so every handler in
    // either namespace reaches the same dependency set (design: shared
    // `AppState`). Cloning is an `Arc` bump.
    cfg.app_data(web::Data::new(state.clone()));
    // The `/health` handler (task 7.3) extracts the `HealthRegistry` directly
    // from app data, so register the shared registry too — this is the wiring
    // the health module documents for task 11.2 ("wired into the dual-surface
    // router once `AppState` threads the shared registry").
    cfg.app_data(web::Data::new(state.health().clone()));
    // The SSE registry (task 28.4) is registered as app data so the
    // `/v0/events` handler can subscribe to per-user broadcast channels and
    // other handlers can publish events (Req 41.1, 41.4).
    cfg.app_data(web::Data::new(state.sse().clone()));

    mediaflow_surface::configure(cfg); // Req 36.1, 36.5
    stremthru_surface::configure(cfg); // Req 36.2, 36.6
    shared::configure(cfg); // /health, /metrics, /v0/events, web UI
}

/// The `mediaflow-proxy-light` path namespace (Req 36.1, 36.5).
pub mod mediaflow_surface {
    use super::*;

    /// Register the mediaflow surface's representative routes.
    ///
    /// The streaming-utility paths (`/generate_url`, `/base64/*`,
    /// `/playlist/builder`, `/speedtest`) are backed by their real handlers
    /// (task 20.1, [`crate::utils`]). The remaining path set (`/proxy/hls/*`,
    /// `/proxy/mpd/*`, `/proxy/epg`, `/extractor/video`, `/player_api.php`,
    /// `/xmltv.php`, `/get.php`, `/proxy/acestream/*`, `/proxy/telegram/*`) is
    /// filled in by the tasks that own each handler; the skeleton registers the
    /// streaming entry points that anchor the namespace.
    ///
    /// `/proxy/ip` is backed by its real handler (task 14.2): it returns the
    /// tunnel-observed Egress_IP from the shared egress
    /// [`OutboundClient`](crate::egress::OutboundClient) (Req 13.7, 51.10,
    /// 51.11).
    pub fn configure(cfg: &mut web::ServiceConfig) {
        cfg.route(
            "/proxy/stream",
            web::get().to(crate::content_proxy::content_proxy_endpoint),
        ) // Req 36.1, 19.1-19.8
        .route(
            "/proxy/stream",
            web::head().to(crate::content_proxy::content_proxy_endpoint),
        )
        .route("/proxy/ip", web::get().to(crate::proxy::proxy_ip_endpoint)) // Req 51.10/51.11
        // Subtitle proxy (Req 39.1, 39.3, 39.4, 39.5) — task 28.2.
        .route(
            "/proxy/subtitle",
            web::get().to(crate::subtitles::subtitle_proxy_endpoint),
        ) // Req 39.1
        // Streaming utilities (Req 15) — task 20.1.
        .route(
            "/base64/encode",
            web::get().to(crate::utils::base64::base64_encode_endpoint),
        ) // Req 15.3
        .route(
            "/base64/decode",
            web::get().to(crate::utils::base64::base64_decode_endpoint),
        ) // Req 15.4
        .route(
            "/base64/check",
            web::get().to(crate::utils::base64::base64_check_endpoint),
        ) // Req 15.5
        .route(
            "/generate_url",
            web::post().to(crate::utils::generate_url::generate_url_endpoint),
        ) // Req 15.7
        .route(
            "/playlist/builder",
            web::post().to(crate::utils::playlist::playlist_builder_endpoint),
        ) // Req 15.1
        .route(
            "/speedtest",
            web::get().to(crate::utils::speedtest::speedtest_endpoint),
        ); // Req 15.2
    }
}

/// The `stremthru` path namespace (Req 36.2, 36.6).
pub mod stremthru_surface {
    use super::*;

    /// Register the stremthru surface's representative routes.
    ///
    /// `/v0/proxy` is backed by its real proxify-links handler (task 24.4,
    /// [`crate::proxylink::handler`]): both `GET` and `POST` convert the
    /// supplied upstream URLs into one `Proxy_Link` each, behind the
    /// `X-StremThru-Authorization` Basic proxy-auth (Req 21.1–21.9). The
    /// remaining path set (`/v0/store/*`, `/v0/meta/id-map/*`, `/stremio/*`) is
    /// filled in by the tasks that own each handler.
    pub fn configure(cfg: &mut web::ServiceConfig) {
        cfg.route(
            "/v0/proxy",
            web::get().to(crate::proxylink::handler::proxify_get_endpoint),
        ) // Req 21.1-21.9, 36.2, 36.6
        .route(
            "/v0/proxy",
            web::post().to(crate::proxylink::handler::proxify_post_endpoint),
        ); // Req 21.1-21.9
           // Store magnet endpoints (task 24.1, Req 17)
        crate::store::endpoints::configure_store_routes(cfg);
        // Meta / ID-map endpoint (task 24.5, Req 22)
        crate::meta::configure_meta_routes(cfg);
        // Store addon routes (task 26.2, Req 23)
        crate::stremio::store_addon::configure_store_addon_routes(cfg);
        // Wrap addon routes (task 26.3, Req 24)
        crate::stremio::wrap_addon::configure_wrap_addon_routes(cfg);
    }
}

/// Surface-agnostic routes both projects expose (Req 32, 36).
pub mod shared {
    use super::*;
    use crate::health::health_endpoint;
    use crate::observability::metrics_endpoint;
    use crate::sse::sse_events_endpoint;

    /// Register the shared routes.
    ///
    /// `/health` is backed by its real handler (task 7.3) and `/metrics` by the
    /// observability handler (task 12.1), which renders the Prometheus
    /// exposition behind the metrics password (Req 32.1, 32.2). `/v0/events`
    /// is backed by the real SSE handler (task 28.4, Req 41.1). The web UI
    /// assets are mounted by the web-UI task.
    pub fn configure(cfg: &mut web::ServiceConfig) {
        cfg.route("/health", web::get().to(health_endpoint)) // Req 50.10, 32.4
            .route("/metrics", web::get().to(metrics_endpoint)) // Req 32.1, 32.2
            .route("/v0/events", web::get().to(sse_events_endpoint)); // Req 41.1
        crate::web_ui::configure_web_routes(cfg);
    }
}
