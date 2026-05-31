//! Streaming utilities (`utils`) — Req 15.
//!
//! The operator-facing helpers both projects expose on the mediaflow surface
//! (design: Components → Utilities):
//!
//! * [`base64`] — base64 encode / decode / check, with a descriptive error
//!   on invalid decode input and a round-trip guarantee (Req 15.3–15.6, 15.9).
//! * [`generate_url`] — build a sealed proxy URL from request parameters and the
//!   configured `Server_Path_Prefix` (Req 15.7).
//! * [`playlist`] — the M3U playlist builder that rewrites every channel URL
//!   through the proxy (Req 15.1), reusing [`generate_url`] per channel.
//! * [`speedtest`] — measure download throughput against a provider through the
//!   single egress [`OutboundClient`](crate::egress::OutboundClient) seam
//!   (Req 15.2).
//!
//! The endpoint handlers are mounted on the mediaflow surface by the
//! dual-surface [`router`](crate::http::router) (`/generate_url`,
//! `/playlist/builder`, `/speedtest`, `/base64/{encode,decode,check}`). The
//! `/health` success endpoint (Req 15.8) is surface-agnostic and served by the
//! shared [`health`](crate::health) module, so it is not duplicated here.

pub mod base64;
pub mod generate_url;
pub mod playlist;
pub mod speedtest;
