//! HLS manifest & segment proxying (`hls`) — Req 1.
//!
//! The HLS module proxies `M3U8_Manifest`s and their derived segments/keys so
//! all playback traffic flows back through `ZippyPanther` with consistent auth,
//! headers, and egress isolation (design: Components → HLS). It has two halves:
//!
//! * [`rewrite`] — the pure parse + full-rewrite core. [`HlsRewriter`] parses a
//!   master or media manifest with [`m3u8_rs`] and rewrites **every** variant,
//!   segment, `#EXT-X-KEY`, and `#EXT-X-MAP` URL to a `ZippyPanther` proxy URL,
//!   resolving relative URIs against the manifest base first (Req 1.1–1.4) and
//!   returning a descriptive parse error for an unparseable body (Req 1.8).
//! * [`fetch`] — the I/O half. [`HlsClient`] fetches the upstream manifest body
//!   and opens upstream segment/key bytes, always through the single egress
//!   seam ([`OutboundClient`](crate::egress::OutboundClient)), forwarding the
//!   custom upstream headers to every derived request (Req 1.6), preserving the
//!   upstream content type on segments (Req 1.5), and surfacing the upstream
//!   HTTP status on failure (Req 1.7).
//!
//! ## End-to-end flow
//!
//! 1. [`HlsClient::fetch_manifest`] retrieves the upstream `.m3u8` (Req 1.6,
//!    1.7).
//! 2. [`HlsRewriter::rewrite`] rewrites every embedded URL to a proxy URL whose
//!    encrypted `d` token carries the resolved upstream URL + forwarded headers
//!    (Req 1.1–1.4, 1.8).
//! 3. The client requests a rewritten segment/key URL; the engine decrypts the
//!    token and calls [`HlsClient::open_segment`] to stream the upstream bytes
//!    with the upstream content type preserved (Req 1.5).
//!
//! The HTTP handlers that decrypt the `d` token and wire these pieces to the
//! dual-surface router land with the proxy core (task 14.2); this task lands
//! the reusable parse/rewrite/fetch building blocks.

pub mod fetch;
pub mod rewrite;

pub use fetch::HlsClient;
pub use rewrite::HlsRewriter;
