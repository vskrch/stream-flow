//! HTTP edge: middleware and the dual-surface router.
//!
//! Task 2.2 lands the [`panic_boundary`] middleware (the top-level panic →
//! `500` boundary, Req 47.3 / 50.8). Task 11.1 adds the [`client_ip`] resolver
//! (Req 28.7, 51.2). Task 11.2 lands the dual-surface [`router`] skeleton (the
//! two disjoint path namespaces + shared routes onto one handler set, Req 36.1
//! / 36.2). Task 11.3 adds the [`degradation`] guard (the basic connection /
//! RSS high-water-mark load shedder + shared `LoadState`, Req 44.1/44.3-44.6);
//! the full L1–L5 ladder lands in task 29 (design: Components → HTTP edge).

pub mod client_ip;
pub mod degradation;
pub mod panic_boundary;
pub mod protocol;
pub mod router;

pub use client_ip::{client_ip, resolve_client_ip};
pub use panic_boundary::PanicBoundary;
// Surface the Degradation Guard's pure decision API + thresholds/classes at the
// `http` module level so the basic guard's load-state logic is reachable from
// the public crate surface (mirrors the `client_ip`/`PanicBoundary` re-exports
// above). The property test (task 11.5, Property 46) drives these directly.
pub use degradation::{
    classify_path, next_load_state, shed_new_request, DegradationLadder, DegradationLevel,
    LoadController, LoadThresholds, RequestClass,
};
pub use protocol::{
    bulk_media_uses_http2, control_plane_protocol, upstream_api_uses_http2, ProtocolMode,
};
