//! MPD domain model (`mpd::model`) — Req 2.1, 3.
//!
//! The structured, parser-agnostic representation an [`Mpd`](crate::mpd::Mpd)
//! is decoded into: a tree of [`Period`] → [`AdaptationSet`] →
//! [`Representation`], each representation carrying its [`SegmentAddressing`]
//! (design: Components → MPD / DASH→HLS — `Mpd { periods, adaptation_sets,
//! representations }`).
//!
//! ## Scope (task 16.2)
//!
//! This module owns the **parsed shape**. The [`SegmentAddressing`] enum and
//! the four addressing structs ([`SegmentTemplate`], [`SegmentList`],
//! [`SegmentBase`], plus [`SegmentTimeline`]) are populated by the parser so a
//! representation faithfully records *how* it addresses its segments, but the
//! four-mode **resolution dispatch** (substituting `$Number$`/`$Time$`,
//! expanding `(t,d,r)` timelines, deriving `SegmentBase`/`SegmentList` byte
//! ranges) is task 16.3. The conversion functions in
//! [`convert`](crate::mpd::convert) operate on already-resolved
//! [`MediaSegment`](crate::mpd::convert::MediaSegment) lists, so they are
//! independent of that dispatch.

/// Whether the presentation is video-on-demand or live (design: Req 2.4, 2.5).
///
/// Derived from the MPD `@type` attribute: `dynamic` → [`Dynamic`](Self::Dynamic)
/// (live), `static` or absent → [`Static`](Self::Static) (VOD — the DASH
/// default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationType {
    /// Video-on-demand: the media playlist enumerates **all** segments
    /// (Req 2.5).
    Static,
    /// Live: the media playlist includes only the most recent
    /// `live_playlist_depth` segments (Req 2.4).
    Dynamic,
}

impl PresentationType {
    /// `true` for a live (`dynamic`) presentation.
    pub fn is_live(self) -> bool {
        matches!(self, PresentationType::Dynamic)
    }
}

/// A parsed MPD presentation (Req 2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct Mpd {
    /// VOD vs live (Req 2.4, 2.5).
    pub presentation_type: PresentationType,
    /// ISO-8601 total media duration (`@mediaPresentationDuration`), when
    /// declared. Retained verbatim; segment-time arithmetic is task 16.3.
    pub media_presentation_duration: Option<String>,
    /// A document-level `<BaseURL>` against which relative segment/template
    /// URLs resolve (resolution is task 16.3; recorded here for it).
    pub base_url: Option<String>,
    /// The presentation's periods, in document order (Req 2.1).
    pub periods: Vec<Period>,
}

impl Mpd {
    /// Iterate every [`Representation`] across all periods and adaptation sets,
    /// in document order.
    ///
    /// This is the enumeration `to_hls_master` walks to emit **one variant per
    /// representation** (Req 2.2).
    pub fn representations(&self) -> impl Iterator<Item = &Representation> {
        self.periods
            .iter()
            .flat_map(|p| p.adaptation_sets.iter())
            .flat_map(|a| a.representations.iter())
    }

    /// Total number of selectable representations across the presentation.
    pub fn representation_count(&self) -> usize {
        self.representations().count()
    }

    /// Find a representation by its `@id` anywhere in the presentation.
    ///
    /// Used to serve a per-representation media playlist / init segment
    /// (Req 2.3, 2.6) given the id carried in the rewritten variant URL.
    pub fn representation(&self, id: &str) -> Option<&Representation> {
        self.representations().find(|r| r.id == id)
    }
}

/// A DASH period: a contiguous slice of the presentation timeline (Req 2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct Period {
    /// `@id`, when present.
    pub id: Option<String>,
    /// ISO-8601 `@duration`, when present.
    pub duration: Option<String>,
    /// A period-level `<BaseURL>`.
    pub base_url: Option<String>,
    /// The period's adaptation sets, in document order.
    pub adaptation_sets: Vec<AdaptationSet>,
}

/// An adaptation set: a group of interchangeable representations of one media
/// component (e.g. all video renditions, or one audio language) (Req 2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct AdaptationSet {
    /// `@mimeType` (e.g. `video/mp4`, `audio/mp4`), when present.
    pub mime_type: Option<String>,
    /// `@contentType` (e.g. `video`, `audio`, `text`), when present.
    pub content_type: Option<String>,
    /// `@lang` BCP-47 language tag, when present (audio/subtitle sets).
    pub lang: Option<String>,
    /// An adaptation-set-level `<BaseURL>`.
    pub base_url: Option<String>,
    /// The set's representations, in document order.
    pub representations: Vec<Representation>,
}

/// A single representation: one encoded rendition of a media component
/// (Req 2.1). Becomes exactly one HLS variant (Req 2.2).
#[derive(Debug, Clone, PartialEq)]
pub struct Representation {
    /// `@id` — required by DASH; used to address the representation in
    /// rewritten variant / media-playlist URLs (Req 2.3).
    pub id: String,
    /// `@bandwidth` in bits per second — required by DASH; becomes the HLS
    /// `BANDWIDTH` variant attribute (Req 2.2).
    pub bandwidth: u64,
    /// `@width` in pixels (video), when present.
    pub width: Option<u64>,
    /// `@height` in pixels (video), when present.
    pub height: Option<u64>,
    /// `@codecs` (RFC 6381), when present — becomes the HLS `CODECS`
    /// attribute.
    pub codecs: Option<String>,
    /// `@mimeType`, when present (falls back to the adaptation set's).
    pub mime_type: Option<String>,
    /// `@frameRate` (e.g. `30` or `30000/1001`), when present.
    pub frame_rate: Option<String>,
    /// A representation-level `<BaseURL>`.
    pub base_url: Option<String>,
    /// How this representation's segments are addressed (Req 3). The variant is
    /// populated by the parser; resolving it to concrete segments is task 16.3.
    pub segment_addressing: SegmentAddressing,
}

impl Representation {
    /// The pixel resolution `(width, height)` when both are known.
    pub fn resolution(&self) -> Option<(u64, u64)> {
        match (self.width, self.height) {
            (Some(w), Some(h)) => Some((w, h)),
            _ => None,
        }
    }
}

/// The DASH segment-addressing scheme of a representation (Req 3).
///
/// One of the four compliant modes, or [`None`](Self::None) for a
/// single-file representation addressed solely by its `<BaseURL>`. The parser
/// records which mode is in effect and its raw parameters; the four-mode
/// resolution dispatch (computing concrete segment URLs / byte ranges) is
/// task 16.3.
#[derive(Debug, Clone, PartialEq)]
pub enum SegmentAddressing {
    /// `SegmentTemplate` — fixed-duration or with an embedded
    /// [`SegmentTimeline`] (Req 3.1, 3.2, 3.5).
    Template(SegmentTemplate),
    /// `SegmentList` — explicit per-segment URLs / byte ranges (Req 3.4).
    List(SegmentList),
    /// `SegmentBase` — single-file representation with an index range
    /// (Req 3.3).
    Base(SegmentBase),
    /// No segment-addressing element: the representation is a single file
    /// referenced by its `<BaseURL>`.
    None,
}

/// `SegmentTemplate` parameters (Req 3.1, 3.2, 3.5).
///
/// The `media`/`initialization` strings may contain the `$Number$`, `$Time$`,
/// `$RepresentationID$`, and `$Bandwidth$` identifiers (with optional width
/// specifiers like `$Number%05d$`); substituting them is task 16.3.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SegmentTemplate {
    /// `@media` URL template for media segments.
    pub media: Option<String>,
    /// `@initialization` URL template for the init segment (Req 2.6).
    pub initialization: Option<String>,
    /// `@startNumber` (defaults to 1 in DASH when absent).
    pub start_number: Option<u64>,
    /// `@duration` in `@timescale` units (fixed-duration mode).
    pub duration: Option<u64>,
    /// `@timescale` ticks per second (defaults to 1 when absent).
    pub timescale: Option<u64>,
    /// An embedded `<SegmentTimeline>`, when present (Req 3.2).
    pub timeline: Option<SegmentTimeline>,
}

/// A `<SegmentTimeline>`: an ordered list of `S` entries (Req 3.2).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SegmentTimeline {
    /// The `S` entries, in document order.
    pub entries: Vec<TimelineEntry>,
}

/// A single `<S>` entry in a [`SegmentTimeline`] (Req 3.2).
///
/// Expanding `(t, d, r)` into `r + 1` non-overlapping monotonic segments is
/// task 16.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimelineEntry {
    /// `@t` — the segment start time in timescale units, when present.
    pub t: Option<u64>,
    /// `@d` — the segment duration in timescale units (required on an `S`).
    pub d: u64,
    /// `@r` — the repeat count (the entry describes `r + 1` segments). A
    /// negative `r` means "repeat until the period/timeline end"; defaults to 0.
    pub r: i64,
}

/// `SegmentList` parameters (Req 3.4).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SegmentList {
    /// `@duration` in `@timescale` units.
    pub duration: Option<u64>,
    /// `@timescale` ticks per second.
    pub timescale: Option<u64>,
    /// The `<Initialization>` reference (Req 2.6).
    pub initialization: Option<UrlRange>,
    /// The explicit `<SegmentURL>` entries, in document order.
    pub segment_urls: Vec<SegmentUrl>,
}

/// A single `<SegmentURL>` entry of a [`SegmentList`] (Req 3.4).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SegmentUrl {
    /// `@media` URL of the media segment.
    pub media: Option<String>,
    /// `@mediaRange` byte range within `media` (or the base URL).
    pub media_range: Option<String>,
    /// `@index` URL of the segment index.
    pub index: Option<String>,
    /// `@indexRange` byte range of the segment index.
    pub index_range: Option<String>,
}

/// `SegmentBase` parameters — a single-file representation (Req 3.3).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SegmentBase {
    /// `@indexRange` — the byte range of the `sidx` index box.
    pub index_range: Option<String>,
    /// `@timescale` ticks per second.
    pub timescale: Option<u64>,
    /// The `<Initialization>` reference (Req 2.6).
    pub initialization: Option<UrlRange>,
}

/// A `<Initialization>` reference: an optional source URL plus an optional
/// byte range (Req 2.6, 3.3, 3.4).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UrlRange {
    /// `@sourceURL`, when present (defaults to the representation base URL).
    pub source_url: Option<String>,
    /// `@range` byte range (e.g. `0-799`), when present.
    pub range: Option<String>,
}
