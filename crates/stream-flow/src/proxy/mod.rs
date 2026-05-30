//! Streaming proxy core (`proxy`) — Req 5, 19, 37.
//!
//! This module houses the generic streaming-proxy building blocks shared by
//! every byte-serving surface (generic forward proxy, debrid content proxy,
//! ResilientStream). Task 13.1 lands [`range`], the pure byte-range parser +
//! response-metadata computation that turns a `Range` header and a known total
//! size into the `200`/`206`/`416` status, `Content-Range`, `Content-Length`,
//! and `Accept-Ranges` a Byte_Serving response carries (design: Components →
//! Range handling). Later tasks add the adaptive/jitter buffer
//! (`proxy::buffer`), transport routing (`proxy::routing`), and the
//! `UpstreamSource` streaming core.

pub mod range;

pub use range::{
    compute_response_metadata, RangeSpec, ResolvedRange, ResponseMetadata, Unsatisfiable,
};
