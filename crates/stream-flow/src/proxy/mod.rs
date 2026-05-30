//! Streaming proxy core (`proxy`) — Req 5, 19, 37.
//!
//! This module houses the generic streaming-proxy building blocks shared by
//! every byte-serving surface (generic forward proxy, debrid content proxy,
//! ResilientStream). Task 13.1 lands [`range`], the pure byte-range parser +
//! response-metadata computation that turns a `Range` header and a known total
//! size into the `200`/`206`/`416` status, `Content-Range`, `Content-Length`,
//! and `Accept-Ranges` a Byte_Serving response carries (design: Components →
//! Range handling). Task 13.2 lands [`buffer`], the bounded adaptive + jitter
//! ring buffer that decouples the upstream reader from the client writer with
//! offset-driven refill sizing and bounded peak memory (design: Components →
//! Adaptive + jitter buffer). Task 13.3 lands [`source`], the `UpstreamSource`
//! abstraction + `DirectSource` (egress-backed) that produce the re-issuable
//! zero-copy byte stream the streaming core relays (design: Components →
//! Streaming Core). Task 14.1 lands [`routing`], the per-pattern transport
//! routing + forwarding-client machinery (`select_route` most-specific match,
//! `all://`/`*` patterns, http/https/socks4/socks5 schemes, per-route SSL
//! policy, and the `(proxy, verify_ssl)` client LRU — design: Components →
//! Transport routing & forwarding). Later tasks add the `ResilientStream`
//! streaming-core state machine.

pub mod buffer;
pub mod range;
pub mod resilient;
pub mod routing;
pub mod source;

pub use buffer::AdaptiveJitterBuffer;
pub use range::{
    compute_response_metadata, RangeSpec, ResolvedRange, ResponseMetadata, Unsatisfiable,
};
pub use resilient::ResilientStream;
pub use routing::{
    ClientCache, ProxyScheme, ProxyUrl, PatternError, RoutePattern, RouteSelection, RoutingTable,
    TransportRoute,
};
pub use source::{ContentRange, DirectSource, UpstreamBody, UpstreamSource};
