//! DASH segment-addressing resolution (`mpd::segments`) — Req 3.1–3.6.
//!
//! The four-mode **resolution dispatch** that turns a [`Representation`]'s
//! [`SegmentAddressing`] into a concrete, ordered list of media segments plus
//! the initialization-segment reference the
//! [`convert`](crate::mpd::convert) layer consumes (design: Components → MPD /
//! DASH→HLS — `SegmentAddressing`):
//!
//! * **`SegmentTemplate` (fixed duration)** — enumerate `startNumber..` and
//!   substitute `$Number$`/`$Time$`/`$RepresentationID$`/`$Bandwidth$` into the
//!   `@media` template, honoring width specifiers like `$Number%05d$`
//!   (Req 3.1, 3.5).
//! * **`SegmentTemplate` + `SegmentTimeline`** — expand each `S(t, d, r)` entry
//!   to `r + 1` segments, accumulating start times so the produced set is
//!   strictly non-overlapping and monotonically increasing; an unresolved gap
//!   (an explicit `@t` that does not continue the previous segment) is an error
//!   naming the missing segment (Req 3.2, 3.6).
//! * **`SegmentBase`** — a single-file representation: derive the
//!   initialization byte range and the index (`sidx`) byte range from the
//!   declared ranges (Req 3.3).
//! * **`SegmentList`** — enumerate the explicit `<SegmentURL>` media URLs and
//!   their `@mediaRange` byte ranges (Req 3.4).
//!
//! This module operates purely on the parsed [`Mpd`](crate::mpd::model) model —
//! it performs no byte fetching and no proxy-URL rewriting (those are the
//! concern of the HLS/proxy layer), so the addressing arithmetic is verifiable
//! in isolation.

use super::convert::MediaSegment;
use super::error::MpdError;
use super::model::{
    Representation, SegmentAddressing, SegmentBase, SegmentList, SegmentTemplate, SegmentTimeline,
    UrlRange,
};

/// An inclusive byte range `[start, end]` as declared by DASH `@range` /
/// `@mediaRange` / `@indexRange` (`"start-end"`), with an optional open end for
/// a range that runs to the end of the resource (e.g. the media payload after
/// a `SegmentBase` index box).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte offset (inclusive).
    pub start: u64,
    /// Last byte offset (inclusive), or `None` for "to end of resource".
    pub end: Option<u64>,
}

impl ByteRange {
    /// Parse a DASH `"start-end"` byte-range string. A missing end
    /// (`"start-"`) yields an open-ended range.
    pub fn parse(s: &str) -> Result<ByteRange, MpdError> {
        let (start_s, end_s) = s.split_once('-').ok_or_else(|| {
            MpdError::malformed("byte range", format!("'{s}' is not a 'start-end' range"))
        })?;
        let start: u64 = start_s.trim().parse().map_err(|e| {
            MpdError::malformed("byte range", format!("invalid start in '{s}': {e}"))
        })?;
        let end = if end_s.trim().is_empty() {
            None
        } else {
            let e: u64 = end_s.trim().parse().map_err(|err| {
                MpdError::malformed("byte range", format!("invalid end in '{s}': {err}"))
            })?;
            if e < start {
                return Err(MpdError::malformed(
                    "byte range",
                    format!("end {e} precedes start {start} in '{s}'"),
                ));
            }
            Some(e)
        };
        Ok(ByteRange { start, end })
    }

    /// The byte length of the range, when the end is known.
    pub fn length(&self) -> Option<u64> {
        self.end.map(|e| e - self.start + 1)
    }

    /// The HLS `#EXT-X-BYTERANGE` value (`length@offset`), when the length is
    /// known. Open-ended ranges have no HLS representation and yield `None`.
    pub fn to_hls(&self) -> Option<String> {
        self.length().map(|len| format!("{len}@{}", self.start))
    }
}

/// One resolved segment of a representation, in addressing-agnostic form.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedSegment {
    /// The segment's (declared, not yet proxy-rewritten) media URL.
    pub url: String,
    /// The DASH segment number (`$Number$`), when number-addressed.
    pub number: Option<u64>,
    /// The segment start time in `timescale` units (`$Time$`), when known.
    pub time: Option<u64>,
    /// The segment duration in `timescale` units (`0` when unknown).
    pub duration_ts: u64,
    /// Ticks per second for `duration_ts` (≥ 1).
    pub timescale: u64,
    /// The byte range within `url`, for byte-range addressing.
    pub byte_range: Option<ByteRange>,
}

impl ResolvedSegment {
    /// The segment duration in seconds (`0.0` when unknown).
    pub fn duration_secs(&self) -> f64 {
        if self.timescale == 0 {
            0.0
        } else {
            self.duration_ts as f64 / self.timescale as f64
        }
    }

    /// Convert to the HLS-facing [`MediaSegment`] the converter consumes.
    pub fn to_media_segment(&self) -> MediaSegment {
        MediaSegment {
            url: self.url.clone(),
            duration_secs: self.duration_secs(),
            byte_range: self.byte_range.and_then(|r| r.to_hls()),
        }
    }
}

/// The initialization-segment reference of a representation (Req 2.6).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InitRef {
    /// The (substituted, declared) init-segment URL, when one is addressable.
    pub url: Option<String>,
    /// The init-segment byte range, for byte-range addressing.
    pub byte_range: Option<ByteRange>,
}

/// The fully resolved segment set of a representation: the init reference plus
/// every media segment in presentation order.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedRepresentation {
    /// The initialization segment, when the representation declares one.
    pub init: Option<InitRef>,
    /// The media segments, in presentation order.
    pub segments: Vec<ResolvedSegment>,
}

impl ResolvedRepresentation {
    /// The HLS-facing [`MediaSegment`] list the converter consumes.
    pub fn to_media_segments(&self) -> Vec<MediaSegment> {
        self.segments.iter().map(ResolvedSegment::to_media_segment).collect()
    }
}

/// Resolve a representation's [`SegmentAddressing`] to a concrete segment set
/// (Req 3.1–3.6).
///
/// `total_duration_secs` is the presentation/period duration used to enumerate
/// **fixed-duration** `SegmentTemplate` segments (and to bound a
/// `SegmentTimeline` with an open-ended `@r = -1` repeat); it is ignored by the
/// timeline / list / base modes that are self-describing.
pub fn resolve_segments(
    rep: &Representation,
    total_duration_secs: Option<f64>,
) -> Result<ResolvedRepresentation, MpdError> {
    match &rep.segment_addressing {
        SegmentAddressing::Template(t) => resolve_template(rep, t, total_duration_secs),
        SegmentAddressing::List(l) => resolve_list(l),
        SegmentAddressing::Base(b) => resolve_base(rep, b, total_duration_secs),
        SegmentAddressing::None => resolve_none(rep, total_duration_secs),
    }
}

/// `@timescale` defaults to 1 when absent (DASH default).
fn timescale_or_default(ts: Option<u64>) -> u64 {
    ts.unwrap_or(1).max(1)
}

// ---------------------------------------------------------------------------
// SegmentTemplate (Req 3.1, 3.2, 3.5, 3.6)
// ---------------------------------------------------------------------------

fn resolve_template(
    rep: &Representation,
    template: &SegmentTemplate,
    total_duration_secs: Option<f64>,
) -> Result<ResolvedRepresentation, MpdError> {
    let timescale = timescale_or_default(template.timescale);
    let start_number = template.start_number.unwrap_or(1);

    // The init reference substitutes $RepresentationID$/$Bandwidth$ (never
    // $Number$/$Time$, which are per-media-segment).
    let init = template.initialization.as_ref().map(|tpl| InitRef {
        url: Some(substitute(tpl, rep, None, None)),
        byte_range: None,
    });

    let media = template.media.as_ref().ok_or_else(|| {
        MpdError::missing(format!("SegmentTemplate (rep {})", rep.id), "media")
    })?;

    let segments = if let Some(timeline) = &template.timeline {
        expand_timeline(rep, media, timeline, timescale, start_number)?
    } else {
        expand_fixed(rep, media, template, timescale, start_number, total_duration_secs)?
    };

    Ok(ResolvedRepresentation { init, segments })
}

/// Fixed-duration template: enumerate `startNumber..startNumber+count`,
/// substituting `$Number$` (and `$Time$` derived from `number * duration`).
fn expand_fixed(
    rep: &Representation,
    media: &str,
    template: &SegmentTemplate,
    timescale: u64,
    start_number: u64,
    total_duration_secs: Option<f64>,
) -> Result<Vec<ResolvedSegment>, MpdError> {
    let duration_ts = template.duration.ok_or_else(|| {
        MpdError::missing(format!("SegmentTemplate (rep {})", rep.id), "duration")
    })?;
    if duration_ts == 0 {
        return Err(MpdError::malformed(
            format!("SegmentTemplate (rep {})", rep.id),
            "segment @duration must be non-zero",
        ));
    }

    // Number of segments to enumerate from the presentation duration. Round up
    // so a partial trailing segment is still addressed.
    let seg_secs = duration_ts as f64 / timescale as f64;
    let count = match total_duration_secs {
        Some(total) if seg_secs > 0.0 => (total / seg_secs).ceil() as u64,
        // No duration known: a single segment is the safest enumeration.
        _ => 1,
    };

    let mut segments = Vec::with_capacity(count as usize);
    for i in 0..count {
        let number = start_number + i;
        let time = i * duration_ts;
        let url = substitute(media, rep, Some(number), Some(time));
        segments.push(ResolvedSegment {
            url,
            number: Some(number),
            time: Some(time),
            duration_ts,
            timescale,
            byte_range: None,
        });
    }
    Ok(segments)
}

/// Expand a `SegmentTimeline` to `Σ(r + 1)` segments with monotonic,
/// non-overlapping start times (Req 3.2); a forward `@t` jump that leaves a
/// hole is an error naming the missing segment (Req 3.6).
fn expand_timeline(
    rep: &Representation,
    media: &str,
    timeline: &SegmentTimeline,
    timescale: u64,
    start_number: u64,
) -> Result<Vec<ResolvedSegment>, MpdError> {
    let mut segments = Vec::new();
    let mut number = start_number;
    // `current` tracks the time the next segment is expected to start at.
    let mut current: u64 = 0;
    let mut have_current = false;

    for entry in &timeline.entries {
        if entry.d == 0 {
            return Err(MpdError::malformed(
                format!("SegmentTimeline (rep {})", rep.id),
                "S@d must be non-zero",
            ));
        }

        // Resolve this entry's start time. An explicit @t must continue the
        // running timeline exactly; a forward jump is an unresolved gap
        // (Req 3.6). A backward @t (overlap) is likewise rejected.
        let start = match entry.t {
            Some(t) => {
                if have_current && t > current {
                    return Err(MpdError::missing_segment(
                        &rep.id,
                        format!("time {current} (timeline gap before t={t})"),
                    ));
                }
                if have_current && t < current {
                    return Err(MpdError::malformed(
                        format!("SegmentTimeline (rep {})", rep.id),
                        format!("S@t={t} overlaps the previous segment ending at {current}"),
                    ));
                }
                t
            }
            None => {
                if !have_current {
                    // First entry with no @t starts at 0 (DASH default).
                    0
                } else {
                    current
                }
            }
        };

        // `@r` may be negative ("repeat to end"); since a bare timeline carries
        // no end marker here, treat negative as a single segment (no repeat).
        let repeats: u64 = if entry.r < 0 { 0 } else { entry.r as u64 };

        let mut t = start;
        for _ in 0..=repeats {
            let url = substitute(media, rep, Some(number), Some(t));
            segments.push(ResolvedSegment {
                url,
                number: Some(number),
                time: Some(t),
                duration_ts: entry.d,
                timescale,
                byte_range: None,
            });
            t += entry.d;
            number += 1;
        }
        current = t;
        have_current = true;
    }

    Ok(segments)
}

// ---------------------------------------------------------------------------
// Template identifier substitution (Req 3.5)
// ---------------------------------------------------------------------------

/// Substitute the DASH template identifiers in `template`, honoring width
/// specifiers like `$Number%05d$` and the `$$` literal-dollar escape.
///
/// `$RepresentationID$` and `$Bandwidth$` are always substitutable; `$Number$`
/// and `$Time$` are substituted only when their value is supplied (the init
/// template carries neither).
fn substitute(
    template: &str,
    rep: &Representation,
    number: Option<u64>,
    time: Option<u64>,
) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            // Copy the UTF-8 char starting at i.
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&template[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        // At a '$'. Find the matching closing '$'.
        // `$$` is a literal dollar.
        if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
            out.push('$');
            i += 2;
            continue;
        }
        match template[i + 1..].find('$') {
            Some(rel) => {
                let close = i + 1 + rel;
                let token = &template[i + 1..close];
                out.push_str(&expand_identifier(token, rep, number, time));
                i = close + 1;
            }
            None => {
                // No closing '$': emit the rest verbatim.
                out.push_str(&template[i..]);
                break;
            }
        }
    }
    out
}

/// The byte length of the UTF-8 character whose leading byte is `b`.
fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

/// Expand a single `$...$` token (without the surrounding `$`), honoring an
/// optional `%0Nd` width specifier on `Number`/`Time`. An unknown identifier is
/// left intact (re-wrapped in `$`), matching lenient DASH players.
fn expand_identifier(
    token: &str,
    rep: &Representation,
    number: Option<u64>,
    time: Option<u64>,
) -> String {
    // Split an optional width specifier: "Number%05d" -> ("Number", "%05d").
    let (name, spec) = match token.split_once('%') {
        Some((n, s)) => (n, Some(s)),
        None => (token, None),
    };

    match name {
        "RepresentationID" => rep.id.clone(),
        "Bandwidth" => format_with_spec(rep.bandwidth, spec),
        "Number" => match number {
            Some(n) => format_with_spec(n, spec),
            None => rewrap(token),
        },
        "Time" => match time {
            Some(t) => format_with_spec(t, spec),
            None => rewrap(token),
        },
        _ => rewrap(token),
    }
}

fn rewrap(token: &str) -> String {
    format!("${token}$")
}

/// Format `n` honoring a C-style `0Nd` width specifier (e.g. `%05d`). Any other
/// / absent specifier renders the plain decimal.
fn format_with_spec(n: u64, spec: Option<&str>) -> String {
    match spec {
        Some(s) => {
            // Strip a trailing conversion char (e.g. 'd') and optional leading 0.
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(width) = digits.parse::<usize>() {
                format!("{n:0>width$}")
            } else {
                n.to_string()
            }
        }
        None => n.to_string(),
    }
}

// ---------------------------------------------------------------------------
// SegmentList (Req 3.4)
// ---------------------------------------------------------------------------

fn resolve_list(list: &SegmentList) -> Result<ResolvedRepresentation, MpdError> {
    let timescale = timescale_or_default(list.timescale);
    let duration_ts = list.duration.unwrap_or(0);

    let init = list.initialization.as_ref().map(resolve_url_range).transpose()?;

    let mut segments = Vec::with_capacity(list.segment_urls.len());
    for su in &list.segment_urls {
        let url = su.media.clone().unwrap_or_default();
        let byte_range = match &su.media_range {
            Some(r) => Some(ByteRange::parse(r)?),
            None => None,
        };
        segments.push(ResolvedSegment {
            url,
            number: None,
            time: None,
            duration_ts,
            timescale,
            byte_range,
        });
    }

    Ok(ResolvedRepresentation { init, segments })
}

// ---------------------------------------------------------------------------
// SegmentBase (Req 3.3)
// ---------------------------------------------------------------------------

fn resolve_base(
    rep: &Representation,
    base: &SegmentBase,
    total_duration_secs: Option<f64>,
) -> Result<ResolvedRepresentation, MpdError> {
    let timescale = timescale_or_default(base.timescale);
    // The single file the representation addresses by byte range.
    let file = rep.base_url.clone().unwrap_or_default();

    // Init: the declared <Initialization> range over the single file.
    let init = match &base.initialization {
        Some(i) => {
            let mut r = resolve_url_range(i)?;
            // For SegmentBase the init source defaults to the representation's
            // own single file.
            if r.url.is_none() {
                r.url = Some(file.clone());
            }
            Some(r)
        }
        None => None,
    };

    // The media payload begins immediately after the index (`sidx`) box: the
    // byte after `indexRange.end`. The range is contiguous with the index box.
    let media_start = match &base.index_range {
        Some(ir) => {
            let idx = ByteRange::parse(ir)?;
            idx.end
                .map(|e| e + 1)
                // open-ended index range has no determinable media start.
                .ok_or_else(|| {
                    MpdError::malformed(
                        format!("SegmentBase (rep {})", rep.id),
                        "indexRange must be bounded to locate the media payload",
                    )
                })?
        }
        // No index: the media payload is the whole file (or the bytes after the
        // init range, when one is declared).
        None => init
            .as_ref()
            .and_then(|i| i.byte_range)
            .and_then(|r| r.end)
            .map(|e| e + 1)
            .unwrap_or(0),
    };

    let duration_ts = total_duration_secs
        .map(|secs| (secs * timescale as f64).round() as u64)
        .unwrap_or(0);

    let segment = ResolvedSegment {
        url: file,
        number: None,
        time: Some(0),
        duration_ts,
        timescale,
        byte_range: Some(ByteRange {
            start: media_start,
            end: None,
        }),
    };

    Ok(ResolvedRepresentation {
        init,
        segments: vec![segment],
    })
}

// ---------------------------------------------------------------------------
// No addressing element: a single-file representation (BaseURL only).
// ---------------------------------------------------------------------------

fn resolve_none(
    rep: &Representation,
    total_duration_secs: Option<f64>,
) -> Result<ResolvedRepresentation, MpdError> {
    let url = rep.base_url.clone().unwrap_or_default();
    let timescale = 1;
    let duration_ts = total_duration_secs.map(|s| s.round() as u64).unwrap_or(0);
    Ok(ResolvedRepresentation {
        init: None,
        segments: vec![ResolvedSegment {
            url,
            number: None,
            time: Some(0),
            duration_ts,
            timescale,
            byte_range: None,
        }],
    })
}

/// Resolve a `<Initialization>` `UrlRange` into an [`InitRef`].
fn resolve_url_range(i: &UrlRange) -> Result<InitRef, MpdError> {
    let byte_range = match &i.range {
        Some(r) => Some(ByteRange::parse(r)?),
        None => None,
    };
    Ok(InitRef {
        url: i.source_url.clone(),
        byte_range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpd::model::{SegmentUrl, TimelineEntry};

    // ---- test helpers -----------------------------------------------------

    fn rep_with(id: &str, bandwidth: u64, addressing: SegmentAddressing) -> Representation {
        Representation {
            id: id.to_string(),
            bandwidth,
            width: None,
            height: None,
            codecs: None,
            mime_type: None,
            frame_rate: None,
            base_url: None,
            segment_addressing: addressing,
        }
    }

    // ---- ByteRange (Req 3.3, 3.4) -----------------------------------------

    #[test]
    fn byte_range_parses_inclusive_bounds() {
        let r = ByteRange::parse("0-799").unwrap();
        assert_eq!(r.start, 0);
        assert_eq!(r.end, Some(799));
        assert_eq!(r.length(), Some(800));
        // HLS #EXT-X-BYTERANGE is length@offset.
        assert_eq!(r.to_hls().as_deref(), Some("800@0"));
    }

    #[test]
    fn byte_range_parses_open_end() {
        let r = ByteRange::parse("1201-").unwrap();
        assert_eq!(r.start, 1201);
        assert_eq!(r.end, None);
        assert_eq!(r.length(), None);
        assert_eq!(r.to_hls(), None);
    }

    #[test]
    fn byte_range_rejects_malformed() {
        assert!(ByteRange::parse("not-a-range").is_err());
        assert!(ByteRange::parse("").is_err());
        // end before start is invalid.
        assert!(ByteRange::parse("800-700").is_err());
    }

    // ---- SegmentTemplate fixed substitution (Req 3.1, 3.5) ----------------

    #[test]
    fn template_substitutes_number_and_representation_id() {
        // Req 3.1/3.5: $RepresentationID$ + $Number$ substituted.
        let template = SegmentTemplate {
            media: Some("$RepresentationID$/seg-$Number$.m4s".into()),
            initialization: Some("$RepresentationID$/init.mp4".into()),
            start_number: Some(1),
            duration: Some(4000),
            timescale: Some(1000),
            timeline: None,
        };
        let rep = rep_with("v0", 800_000, SegmentAddressing::Template(template));
        // 12s / 4s = 3 segments.
        let resolved = resolve_segments(&rep, Some(12.0)).unwrap();
        let urls: Vec<&str> = resolved.segments.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls,
            vec!["v0/seg-1.m4s", "v0/seg-2.m4s", "v0/seg-3.m4s"]
        );
        // each segment is 4s.
        for s in &resolved.segments {
            assert!((s.duration_secs() - 4.0).abs() < 1e-9);
        }
        // init substitutes $RepresentationID$.
        assert_eq!(
            resolved.init.unwrap().url.as_deref(),
            Some("v0/init.mp4")
        );
    }

    #[test]
    fn template_honors_width_specifier() {
        // Req 3.5: $Number%05d$ zero-pads to width 5.
        let template = SegmentTemplate {
            media: Some("seg-$Number%05d$.m4s".into()),
            initialization: None,
            start_number: Some(1),
            duration: Some(1000),
            timescale: Some(1000),
            timeline: None,
        };
        let rep = rep_with("v0", 800_000, SegmentAddressing::Template(template));
        let resolved = resolve_segments(&rep, Some(3.0)).unwrap();
        let urls: Vec<&str> = resolved.segments.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls,
            vec!["seg-00001.m4s", "seg-00002.m4s", "seg-00003.m4s"]
        );
    }

    #[test]
    fn template_substitutes_bandwidth_and_dollar_escape() {
        // $Bandwidth$ substituted; $$ collapses to a literal $.
        let template = SegmentTemplate {
            media: Some("b$Bandwidth$/$$lit/seg-$Number$.m4s".into()),
            initialization: None,
            start_number: Some(1),
            duration: Some(2000),
            timescale: Some(1000),
            timeline: None,
        };
        let rep = rep_with("v0", 128_000, SegmentAddressing::Template(template));
        let resolved = resolve_segments(&rep, Some(2.0)).unwrap();
        assert_eq!(resolved.segments[0].url, "b128000/$lit/seg-1.m4s");
    }

    // ---- SegmentTemplate + SegmentTimeline (Req 3.2) ----------------------

    #[test]
    fn timeline_expands_repeat_counts_to_sum_r_plus_one() {
        // Req 3.2: S(t=0,d=4000,r=1) + S(d=2000) -> 2 + 1 = 3 segments.
        let timeline = SegmentTimeline {
            entries: vec![
                TimelineEntry { t: Some(0), d: 4000, r: 1 },
                TimelineEntry { t: None, d: 2000, r: 0 },
            ],
        };
        let template = SegmentTemplate {
            media: Some("seg-$Number$-$Time$.m4s".into()),
            initialization: Some("init.mp4".into()),
            start_number: Some(1),
            duration: None,
            timescale: Some(1000),
            timeline: Some(timeline),
        };
        let rep = rep_with("v0", 800_000, SegmentAddressing::Template(template));
        let resolved = resolve_segments(&rep, None).unwrap();

        assert_eq!(resolved.segments.len(), 3, "sum(r+1) = 3");

        // $Time$ accumulates: 0, 4000, 8000; $Number$ increments from 1.
        let urls: Vec<&str> = resolved.segments.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls,
            vec!["seg-1-0.m4s", "seg-2-4000.m4s", "seg-3-8000.m4s"]
        );

        // Strictly increasing, non-overlapping start times.
        let times: Vec<u64> = resolved.segments.iter().map(|s| s.time.unwrap()).collect();
        assert_eq!(times, vec![0, 4000, 8000]);
        for w in times.windows(2) {
            assert!(w[1] > w[0], "monotonic start times");
        }
        // last segment is the 2000-unit one.
        assert_eq!(resolved.segments[2].duration_ts, 2000);
    }

    #[test]
    fn timeline_non_overlapping_across_explicit_t() {
        // An explicit continuing @t that matches the running time is fine.
        let timeline = SegmentTimeline {
            entries: vec![
                TimelineEntry { t: Some(0), d: 3000, r: 0 },
                TimelineEntry { t: Some(3000), d: 3000, r: 1 },
            ],
        };
        let template = SegmentTemplate {
            media: Some("s$Time$.m4s".into()),
            initialization: None,
            start_number: Some(1),
            duration: None,
            timescale: Some(1000),
            timeline: Some(timeline),
        };
        let rep = rep_with("v0", 1, SegmentAddressing::Template(template));
        let resolved = resolve_segments(&rep, None).unwrap();
        let times: Vec<u64> = resolved.segments.iter().map(|s| s.time.unwrap()).collect();
        assert_eq!(times, vec![0, 3000, 6000]);
    }

    // ---- SegmentTimeline gap (Req 3.6) ------------------------------------

    #[test]
    fn timeline_gap_errors_naming_missing_segment() {
        // Req 3.6: a forward @t jump leaves a hole -> error naming the segment.
        let timeline = SegmentTimeline {
            entries: vec![
                TimelineEntry { t: Some(0), d: 3000, r: 0 },
                // expected continuation at t=3000, but jumps to 9000: a gap.
                TimelineEntry { t: Some(9000), d: 3000, r: 0 },
            ],
        };
        let template = SegmentTemplate {
            media: Some("s$Time$.m4s".into()),
            initialization: None,
            start_number: Some(1),
            duration: None,
            timescale: Some(1000),
            timeline: Some(timeline),
        };
        let rep = rep_with("vid", 1, SegmentAddressing::Template(template));
        let err = resolve_segments(&rep, None).unwrap_err();
        match &err {
            MpdError::MissingSegment { representation, segment } => {
                assert_eq!(representation, "vid");
                // The gap is at t=3000.
                assert!(segment.contains("3000"), "names the missing segment: {segment}");
            }
            other => panic!("expected MissingSegment, got {other:?}"),
        }
    }

    // ---- SegmentBase (Req 3.3) --------------------------------------------

    #[test]
    fn segment_base_derives_init_and_index_byte_ranges() {
        // Req 3.3: init range + index (sidx) range derived; contiguous.
        let base = SegmentBase {
            index_range: Some("800-1200".into()),
            timescale: Some(90000),
            initialization: Some(UrlRange {
                source_url: None,
                range: Some("0-799".into()),
            }),
        };
        let mut rep = rep_with("r0", 500_000, SegmentAddressing::Base(base));
        rep.base_url = Some("single.mp4".into());
        let resolved = resolve_segments(&rep, Some(10.0)).unwrap();

        // init: bytes [0-799] of the single file.
        let init = resolved.init.expect("init present");
        assert_eq!(init.url.as_deref(), Some("single.mp4"));
        let init_range = init.byte_range.unwrap();
        assert_eq!(init_range.start, 0);
        assert_eq!(init_range.end, Some(799));
        assert_eq!(init_range.length(), Some(800));

        // one media segment for the single file; its data begins right after
        // the index box (contiguous: index ends at 1200 -> media starts 1201).
        assert_eq!(resolved.segments.len(), 1);
        let seg = &resolved.segments[0];
        assert_eq!(seg.url, "single.mp4");
        let mr = seg.byte_range.unwrap();
        assert_eq!(mr.start, 1201, "media starts after the index box");
        // init.end + 1 == index.start: contiguous and within bounds.
        assert_eq!(init_range.end.unwrap() + 1, 800);
    }

    // ---- SegmentList (Req 3.4) --------------------------------------------

    #[test]
    fn segment_list_enumerates_urls_and_byte_ranges() {
        // Req 3.4: explicit SegmentURL media + mediaRange enumerated.
        let list = SegmentList {
            duration: Some(4000),
            timescale: Some(1000),
            initialization: Some(UrlRange {
                source_url: Some("audio/init.mp4".into()),
                range: None,
            }),
            segment_urls: vec![
                SegmentUrl {
                    media: Some("audio/all.mp4".into()),
                    media_range: Some("0-999".into()),
                    index: None,
                    index_range: None,
                },
                SegmentUrl {
                    media: Some("audio/all.mp4".into()),
                    media_range: Some("1000-1999".into()),
                    index: None,
                    index_range: None,
                },
            ],
        };
        let rep = rep_with("a0", 128_000, SegmentAddressing::List(list));
        let resolved = resolve_segments(&rep, None).unwrap();

        assert_eq!(resolved.init.unwrap().url.as_deref(), Some("audio/init.mp4"));
        assert_eq!(resolved.segments.len(), 2);

        let r0 = resolved.segments[0].byte_range.unwrap();
        let r1 = resolved.segments[1].byte_range.unwrap();
        assert_eq!((r0.start, r0.end), (0, Some(999)));
        assert_eq!((r1.start, r1.end), (1000, Some(1999)));
        // contiguous: r0.end + 1 == r1.start.
        assert_eq!(r0.end.unwrap() + 1, r1.start);
        // each segment is 4s.
        assert!((resolved.segments[0].duration_secs() - 4.0).abs() < 1e-9);
        // HLS byte range form.
        assert_eq!(
            resolved.segments[0].to_media_segment().byte_range.as_deref(),
            Some("1000@0")
        );
    }

    #[test]
    fn segment_list_without_range_yields_plain_urls() {
        let list = SegmentList {
            duration: Some(2000),
            timescale: Some(1000),
            initialization: None,
            segment_urls: vec![
                SegmentUrl { media: Some("s1.m4s".into()), media_range: None, index: None, index_range: None },
                SegmentUrl { media: Some("s2.m4s".into()), media_range: None, index: None, index_range: None },
            ],
        };
        let rep = rep_with("a0", 1, SegmentAddressing::List(list));
        let resolved = resolve_segments(&rep, None).unwrap();
        let urls: Vec<&str> = resolved.segments.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(urls, vec!["s1.m4s", "s2.m4s"]);
        assert!(resolved.segments[0].byte_range.is_none());
    }

    // ---- None addressing --------------------------------------------------

    #[test]
    fn none_addressing_yields_single_file_segment() {
        let mut rep = rep_with("r0", 1, SegmentAddressing::None);
        rep.base_url = Some("movie.mp4".into());
        let resolved = resolve_segments(&rep, Some(90.0)).unwrap();
        assert!(resolved.init.is_none());
        assert_eq!(resolved.segments.len(), 1);
        assert_eq!(resolved.segments[0].url, "movie.mp4");
        assert!((resolved.segments[0].duration_secs() - 90.0).abs() < 1e-9);
    }

    // ---- to_media_segments integration ------------------------------------

    #[test]
    fn to_media_segments_carries_duration_and_byte_range() {
        let list = SegmentList {
            duration: Some(6000),
            timescale: Some(1000),
            initialization: None,
            segment_urls: vec![SegmentUrl {
                media: Some("seg.mp4".into()),
                media_range: Some("100-199".into()),
                index: None,
                index_range: None,
            }],
        };
        let rep = rep_with("a0", 1, SegmentAddressing::List(list));
        let resolved = resolve_segments(&rep, None).unwrap();
        let media = resolved.to_media_segments();
        assert_eq!(media.len(), 1);
        assert_eq!(media[0].url, "seg.mp4");
        assert!((media[0].duration_secs - 6.0).abs() < 1e-9);
        assert_eq!(media[0].byte_range.as_deref(), Some("100@100"));
    }
}
