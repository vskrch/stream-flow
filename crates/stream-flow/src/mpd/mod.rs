//! MPEG-DASH parsing + DASH→HLS conversion (`mpd`) — Req 2, 3.
//!
//! This module turns an upstream `.mpd` (Media Presentation Description) into
//! an equivalent HLS presentation an HLS-only client (e.g. Stremio's player)
//! can consume (design: Components → MPD / DASH→HLS; Sequence Diagram 2).
//!
//! Pipeline:
//!
//! 1. [`parse_mpd`] ([`parser`]) decodes the MPD XML via `quick-xml` into the
//!    structured [`Mpd`] tree of [`Period`] → [`AdaptationSet`] →
//!    [`Representation`], each representation recording its
//!    [`SegmentAddressing`] (Req 2.1). Failures name the offending element
//!    ([`MpdError`], Req 2.8).
//! 2. [`to_hls_master`] ([`convert`]) emits one HLS variant per representation
//!    (Req 2.2); [`to_hls_media`] emits a representation's media playlist —
//!    all segments for VOD (Req 2.5), the most-recent `live_playlist_depth`
//!    for live (Req 2.4) — referencing the init segment (Req 2.6) and honoring
//!    the optional remux-to-MPEG-TS output (Req 2.7).
//!
//! ## Task boundary (16.2 vs 16.3)
//!
//! Task **16.2** (this task) owns the parser, the domain model including the
//! [`SegmentAddressing`] enum *shape*, and the `to_hls_master` / `to_hls_media`
//! conversion functions. The four-mode segment-addressing **resolution
//! dispatch** (`SegmentTemplate` `$Number$`/`$Time$` substitution,
//! `SegmentTimeline` `(t,d,r)` expansion, `SegmentBase`/`SegmentList` byte
//! ranges) is task **16.3** — it produces the
//! [`MediaSegment`](convert::MediaSegment) lists the conversion functions here
//! consume.

pub mod convert;
pub mod error;
pub mod model;
pub mod parser;
pub mod segments;

pub use convert::{init_segment_ref, to_hls_master, to_hls_media, HlsMediaOptions, MediaSegment};
pub use error::MpdError;
pub use segments::{
    resolve_segments, ByteRange, InitRef, ResolvedRepresentation, ResolvedSegment,
};
pub use model::{
    AdaptationSet, Mpd, Period, PresentationType, Representation, SegmentAddressing, SegmentBase,
    SegmentList, SegmentTemplate, SegmentTimeline, SegmentUrl, TimelineEntry, UrlRange,
};
pub use parser::parse_mpd;
