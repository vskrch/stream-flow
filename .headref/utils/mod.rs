//! Streaming utilities (`utils`) — Req 15.
//!
//! The operator-facing helpers both projects expose on the mediaflow surface
//! (design: Components → Utilities):
//!
//! * [`base64`] — base64 encode / decode / check, with a descriptive error on
//!   invalid decode input and a round-trip guarantee (Req 15.3–15.6, 15.9).
//! * [`generate_url`] — build a sealed proxy URL from request parameters and the
//!   configured `Server_Path_Prefix` (Req 15.7).
//! * [`playlist`] — the M3U playlist builder that rewrites every channel URL
//!   through the proxy (Req 15.1), reusing [`generate_url`] per channel.
//! * [`speedtest`] — measure download throughput against a provider through the
//!   single egress [`OutboundClient`](crate::egress::OutboundClient) seam
//!   (Req 15.2).
//!
//! The `/health` success endpoint (Req 15.8) is served by the shared
//! [`health`](crate::health) module and registered on the shared routes by the
//! dual-surface router; the utilities here are the mediaflow-surface routes
//! [`configure`] mounts.

pub mod base64;
pub mod generate_url;
pub mod playlist;
pub mod speedtest;

use actix_web::web;

/// Register the utility routes on the mediaflow surface (Req 15).
///
/// Mounts `/generate_url`, `/playlist/builder`, `/speedtest`, and the
/// `/base64/{encode,decode,check}` endpoints against their real handlers. The
/// `/health` route (Req 15.8) is registered by the shared-surface configuration
/// (it is surface-agnostic), so it is intentionally not duplicated here.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/generate_url", web::post().to(generate_url::generate_url_endpoint)) // Req 15.7
        .route("/playlist/builder", web::post().to(playlist::playlist_builder_endpoint)) // Req 15.1
        .route("/speedtest", web::get().to(speedtest::speedtest_endpoint)) // Req 15.2
        .route("/base64/encode", web::get().to(base64::base64_encode_endpoint)) // Req 15.3
        .route("/base64/decode", web::get().to(base64::base64_decode_endpoint)) // Req 15.4
        .route("/base64/check", web::get().to(base64::base64_check_endpoint)); // Req 15.5
}
