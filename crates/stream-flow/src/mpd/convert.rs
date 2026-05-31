//! DASH→HLS conversion (`mpd::convert`) — Req 2.2, 2.3, 2.4, 2.5, 2.6, 2.7.
//!
//! Turns a parsed [`Mpd`](crate::mpd::model::Mpd) into the HLS manifests an
//! HLS-only client consumes:
//!
//! * [`to_hls_master`] emits an HLS **master** manifest with exactly **one
//!   variant per selectable representation** (Req 2.2). The caller supplies a
//!   `variant_url` builder that maps a representation to the proxy URL its
//!   media playlist is served from (Req 2.3), so this module stays free of the
//!   proxy-URL/auth machinery.
//! * [`to_hls_media`] emits a representation's HLS **media** playlist. For a
//!   **VOD** presentation it includes *all* of the representation's segments
//!   (Req 2.5); for a **live** presentation it includes only the most recent
//!   `live_playlist_depth` segments (Req 2.4). When the output is fragmented
//!   MP4 it references the representation's initialization segment with
//!   `#EXT-X-MAP` (Req 2.6); when [`remux_to_ts`](HlsMediaOptions::remux_to_ts)
//!   is set the segments are self-contained MPEG-TS and no init map is emitted
//!   (Req 2.7).
//!
//! The concrete segment list ([`MediaSegment`]) and the init reference are the
//! *output* of the four-mode segment-addressing resolution (task 16.3); this
//! module consumes them, so the conversion arithmetic is verifiable in
//! isolation from that dispatch.

use std::fmt::Write as _;

use super::model::{Mpd, PresentationType, Representation, SegmentAddressing};

/// One resolved media segment of a representation: the URL its bytes are
/// fetched from, its presentation duration, and an optional byte range.
///
/// Produced by the segment-addressing resolution (task 16.3) and consumed by
/// [`to_hls_media`]. The `url` is the (already proxy-rewritten) URL the client
/// fetches; `byte_range` is the `start@length`-style HLS `#EXT-X-BYTERANGE`
/// value for `SegmentBase`/`SegmentList` byte-range addressing, when used.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaSegment {
    /// The segment's fetch URL (proxy-rewritten by the caller).
    pub url: String,
    /// The segment's duration in seconds (`#EXTINF`).
    pub duration_secs: f64,
    /// An optional `#EXT-X-BYTERANGE` value (`length[@offset]`).
    pub byte_range: Option<String>,
}

impl MediaSegment {
    /// A simple full-segment entry with no byte range.
    pub fn new(url: impl Into<String>, duration_secs: f64) -> Self {
        Self {
            url: url.into(),
            duration_secs,
            byte_range: None,
        }
    }
}

/// Options controlling [`to_hls_media`] generation.
#[derive(Debug, Clone)]
pub struct HlsMediaOptions {
    /// VOD (all segments, Req 2.5) vs live (most-recent window, Req 2.4).
    pub presentation_type: PresentationType,
    /// For a live presentation, the number of most-recent segments to retain
    /// in the playlist (Req 2.4). Ignored for VOD.
    pub live_playlist_depth: usize,
    /// Deliver MPEG-TS segments instead of fragmented MP4 (Req 2.7). When set,
    /// no `#EXT-X-MAP` init segment is emitted (TS segments are self-contained).
    pub remux_to_ts: bool,
    /// The `#EXT-X-MAP` initialization-segment URI for fragmented-MP4 output
    /// (Req 2.6). Omitted when `remux_to_ts` is set or when `None`.
    pub init_segment_url: Option<String>,
}

impl HlsMediaOptions {
    /// VOD options with fragmented-MP4 output and the given init segment URL.
    pub fn vod(init_segment_url: Option<String>) -> Self {
        Self {
            presentation_type: PresentationType::Static,
            live_playlist_depth: 0,
            remux_to_ts: false,
            init_segment_url,
        }
    }

    /// Live options retaining the most recent `depth` segments.
    pub fn live(depth: usize, init_segment_url: Option<String>) -> Self {
        Self {
            presentation_type: PresentationType::Dynamic,
            live_playlist_depth: depth,
            remux_to_ts: false,
            init_segment_url,
        }
    }
}

/// Build an HLS **master** manifest with one `#EXT-X-STREAM-INF` variant per
/// representation (Req 2.2).
///
/// `variant_url` maps each representation to the (proxy) URL its media playlist
/// is served from (Req 2.3). Representations are emitted in document order so
/// the master deterministically corresponds 1:1 with the MPD's representations.
pub fn to_hls_master<F>(mpd: &Mpd, mut variant_url: F) -> String
where
    F: FnMut(&Representation) -> String,
{
    let mut out = String::from("#EXTM3U\n#EXT-X-VERSION:7\n");
    for rep in mpd.representations() {
        out.push_str("#EXT-X-STREAM-INF:");
        let mut attrs: Vec<String> = Vec::new();
        attrs.push(format!("BANDWIDTH={}", rep.bandwidth));
        if let Some((w, h)) = rep.resolution() {
            attrs.push(format!("RESOLUTION={w}x{h}"));
        }
        if let Some(codecs) = &rep.codecs {
            attrs.push(format!("CODECS=\"{codecs}\""));
        }
        if let Some(fr) = &rep.frame_rate {
            if let Some(frac) = parse_frame_rate(fr) {
                attrs.push(format!("FRAME-RATE={frac:.3}"));
            }
        }
        out.push_str(&attrs.join(","));
        out.push('\n');
        out.push_str(&variant_url(rep));
        out.push('\n');
    }
    out
}

/// Build a representation's HLS **media** playlist from its resolved segments.
///
/// VOD includes every segment and terminates with `#EXT-X-ENDLIST` (Req 2.5);
/// live includes only the most recent `live_playlist_depth` segments and omits
/// the end tag, advancing `#EXT-X-MEDIA-SEQUENCE` past the dropped ones
/// (Req 2.4). Fragmented-MP4 output emits the `#EXT-X-MAP` init segment
/// (Req 2.6); MPEG-TS output omits it (Req 2.7).
pub fn to_hls_media(segments: &[MediaSegment], opts: &HlsMediaOptions) -> String {
    // For live, keep only the most-recent window; track how many were dropped
    // so the media sequence number stays correct (Req 2.4).
    let (window, dropped) = if opts.presentation_type.is_live() {
        let depth = opts.live_playlist_depth.min(segments.len());
        let start = segments.len() - depth;
        (&segments[start..], start)
    } else {
        (segments, 0)
    };

    let target_duration = target_duration(window);

    let mut out = String::new();
    out.push_str("#EXTM3U\n");
    out.push_str("#EXT-X-VERSION:7\n");
    let _ = writeln!(out, "#EXT-X-TARGETDURATION:{target_duration}");
    let _ = writeln!(out, "#EXT-X-MEDIA-SEQUENCE:{dropped}");
    if !opts.presentation_type.is_live() {
        // VOD playlists are immutable; advertise the type for player hints.
        out.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    }

    // #EXT-X-MAP init segment for fragmented-MP4 output only (Req 2.6, 2.7).
    if !opts.remux_to_ts {
        if let Some(init) = &opts.init_segment_url {
            let _ = writeln!(out, "#EXT-X-MAP:URI=\"{init}\"");
        }
    }

    for seg in window {
        if let Some(range) = &seg.byte_range {
            let _ = writeln!(out, "#EXT-X-BYTERANGE:{range}");
        }
        let _ = writeln!(out, "#EXTINF:{:.6},", seg.duration_secs);
        out.push_str(&seg.url);
        out.push('\n');
    }

    // VOD is a complete, immutable playlist (Req 2.5); live is open-ended
    // (Req 2.4) so no end tag is written.
    if !opts.presentation_type.is_live() {
        out.push_str("#EXT-X-ENDLIST\n");
    }

    out
}

/// The declared initialization-segment reference of a representation, if any
/// (Req 2.6).
///
/// Returns the raw `@initialization` template string for `SegmentTemplate`
/// addressing, or the `<Initialization>` `@sourceURL` for
/// `SegmentList`/`SegmentBase`. For a template the returned string may still
/// contain `$RepresentationID$`/`$Bandwidth$` identifiers — substituting them
/// is task 16.3; this surfaces the declared reference a handler serves
/// (Req 2.6).
pub fn init_segment_ref(rep: &Representation) -> Option<String> {
    match &rep.segment_addressing {
        SegmentAddressing::Template(t) => t.initialization.clone(),
        SegmentAddressing::List(l) => {
            l.initialization.as_ref().and_then(|i| i.source_url.clone())
        }
        SegmentAddressing::Base(b) => {
            b.initialization.as_ref().and_then(|i| i.source_url.clone())
        }
        SegmentAddressing::None => None,
    }
}

/// `#EXT-X-TARGETDURATION` for a set of segments: the maximum segment duration
/// rounded to the nearest integer, with a floor of 1 (HLS requires an integer
/// ≥ every `#EXTINF`, rounded).
fn target_duration(segments: &[MediaSegment]) -> u64 {
    let max = segments
        .iter()
        .map(|s| s.duration_secs)
        .fold(0.0_f64, f64::max);
    (max.round() as u64).max(1)
}

/// Parse a DASH `@frameRate` (`"30"` or `"30000/1001"`) into frames per second.
fn parse_frame_rate(s: &str) -> Option<f64> {
    if let Some((num, den)) = s.split_once('/') {
        let num: f64 = num.trim().parse().ok()?;
        let den: f64 = den.trim().parse().ok()?;
        if den == 0.0 {
            return None;
        }
        Some(num / den)
    } else {
        s.trim().parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpd::parser::parse_mpd;

    const VOD_MPD: &str = r#"<?xml version="1.0"?>
<MPD type="static" mediaPresentationDuration="PT10S">
  <Period>
    <AdaptationSet mimeType="video/mp4" contentType="video" codecs="avc1.4d401f">
      <SegmentTemplate media="$RepresentationID$/seg-$Number$.m4s"
                       initialization="$RepresentationID$/init.mp4" startNumber="1"/>
      <Representation id="v0" bandwidth="800000" width="640" height="360" frameRate="30"/>
      <Representation id="v1" bandwidth="2400000" width="1280" height="720" frameRate="30000/1001"/>
    </AdaptationSet>
  </Period>
</MPD>"#;

    fn sample_segments(n: usize) -> Vec<MediaSegment> {
        (0..n)
            .map(|i| MediaSegment::new(format!("seg-{i}.m4s"), 4.0))
            .collect()
    }

    // -- to_hls_master ------------------------------------------------------

    #[test]
    fn master_emits_one_variant_per_representation() {
        // Req 2.2: one variant per selectable representation.
        let mpd = parse_mpd(VOD_MPD).unwrap();
        let master = to_hls_master(&mpd, |r| format!("media/{}.m3u8", r.id));

        let variant_lines = master.matches("#EXT-X-STREAM-INF").count();
        assert_eq!(variant_lines, 2, "two representations -> two variants");

        // Req 2.3: variant URL maps to the representation's media playlist.
        assert!(master.contains("media/v0.m3u8"));
        assert!(master.contains("media/v1.m3u8"));
    }

    #[test]
    fn master_carries_bandwidth_resolution_codecs_framerate() {
        let mpd = parse_mpd(VOD_MPD).unwrap();
        let master = to_hls_master(&mpd, |r| format!("media/{}.m3u8", r.id));

        assert!(master.contains("BANDWIDTH=800000"));
        assert!(master.contains("BANDWIDTH=2400000"));
        assert!(master.contains("RESOLUTION=640x360"));
        assert!(master.contains("RESOLUTION=1280x720"));
        assert!(master.contains("CODECS=\"avc1.4d401f\""));
        // 30 fps fixed, and 30000/1001 ~= 29.970.
        assert!(master.contains("FRAME-RATE=30.000"));
        assert!(master.contains("FRAME-RATE=29.970"));
        assert!(master.starts_with("#EXTM3U"));
    }

    #[test]
    fn master_variant_order_matches_representation_order() {
        let mpd = parse_mpd(VOD_MPD).unwrap();
        let master = to_hls_master(&mpd, |r| format!("media/{}.m3u8", r.id));
        let v0 = master.find("media/v0.m3u8").unwrap();
        let v1 = master.find("media/v1.m3u8").unwrap();
        assert!(v0 < v1, "v0 variant precedes v1 (document order)");
    }

    // -- to_hls_media VOD ---------------------------------------------------

    #[test]
    fn vod_media_playlist_includes_all_segments() {
        // Req 2.5: VOD includes all segments of the representation.
        let segments = sample_segments(5);
        let opts = HlsMediaOptions::vod(Some("init.mp4".into()));
        let playlist = to_hls_media(&segments, &opts);

        assert_eq!(playlist.matches("#EXTINF").count(), 5);
        for i in 0..5 {
            assert!(playlist.contains(&format!("seg-{i}.m4s")));
        }
        // VOD is immutable and complete.
        assert!(playlist.contains("#EXT-X-PLAYLIST-TYPE:VOD"));
        assert!(playlist.contains("#EXT-X-ENDLIST"));
        assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:0"));
    }

    #[test]
    fn vod_media_playlist_emits_init_map_for_fmp4() {
        // Req 2.6: init segment referenced via #EXT-X-MAP for fMP4 output.
        let segments = sample_segments(2);
        let opts = HlsMediaOptions::vod(Some("v0/init.mp4".into()));
        let playlist = to_hls_media(&segments, &opts);
        assert!(playlist.contains("#EXT-X-MAP:URI=\"v0/init.mp4\""));
    }

    // -- to_hls_media live --------------------------------------------------

    #[test]
    fn live_media_playlist_includes_only_most_recent_depth_segments() {
        // Req 2.4: live includes the most recent `live_playlist_depth` segments.
        let segments = sample_segments(10);
        let opts = HlsMediaOptions::live(3, Some("init.mp4".into()));
        let playlist = to_hls_media(&segments, &opts);

        assert_eq!(playlist.matches("#EXTINF").count(), 3, "only 3 most-recent");
        // The last 3 segments (7,8,9) are present; the earlier ones are dropped.
        assert!(playlist.contains("seg-7.m4s"));
        assert!(playlist.contains("seg-8.m4s"));
        assert!(playlist.contains("seg-9.m4s"));
        assert!(!playlist.contains("seg-6.m4s"));
        assert!(!playlist.contains("seg-0.m4s"));

        // Media sequence advances past the dropped (7) segments (Req 2.4).
        assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:7"));
        // Live playlists are open-ended: no end tag.
        assert!(!playlist.contains("#EXT-X-ENDLIST"));
        assert!(!playlist.contains("#EXT-X-PLAYLIST-TYPE:VOD"));
    }

    #[test]
    fn live_depth_larger_than_available_includes_all() {
        let segments = sample_segments(2);
        let opts = HlsMediaOptions::live(8, None);
        let playlist = to_hls_media(&segments, &opts);
        assert_eq!(playlist.matches("#EXTINF").count(), 2);
        assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:0"));
    }

    // -- remux to TS (Req 2.7) ----------------------------------------------

    #[test]
    fn remux_to_ts_omits_init_map() {
        // Req 2.7: MPEG-TS segments are self-contained -> no #EXT-X-MAP.
        let segments = vec![
            MediaSegment::new("seg-0.ts", 4.0),
            MediaSegment::new("seg-1.ts", 4.0),
        ];
        let opts = HlsMediaOptions {
            presentation_type: PresentationType::Static,
            live_playlist_depth: 0,
            remux_to_ts: true,
            init_segment_url: Some("init.mp4".into()),
        };
        let playlist = to_hls_media(&segments, &opts);
        assert!(!playlist.contains("#EXT-X-MAP"), "no init map for TS output");
        assert!(playlist.contains("seg-0.ts"));
        assert_eq!(playlist.matches("#EXTINF").count(), 2);
    }

    // -- byte ranges + target duration --------------------------------------

    #[test]
    fn media_playlist_emits_byte_ranges_when_present() {
        // SegmentBase/SegmentList byte-range addressing -> #EXT-X-BYTERANGE.
        let segments = vec![MediaSegment {
            url: "single.mp4".into(),
            duration_secs: 6.0,
            byte_range: Some("1200@800".into()),
        }];
        let opts = HlsMediaOptions::vod(None);
        let playlist = to_hls_media(&segments, &opts);
        assert!(playlist.contains("#EXT-X-BYTERANGE:1200@800"));
    }

    #[test]
    fn target_duration_is_rounded_max_segment_duration() {
        let segments = vec![
            MediaSegment::new("a", 4.0),
            MediaSegment::new("b", 5.6),
            MediaSegment::new("c", 4.0),
        ];
        let opts = HlsMediaOptions::vod(None);
        let playlist = to_hls_media(&segments, &opts);
        // max is 5.6 -> rounds to 6.
        assert!(playlist.contains("#EXT-X-TARGETDURATION:6"));
    }

    #[test]
    fn target_duration_has_floor_of_one() {
        let segments: Vec<MediaSegment> = vec![];
        let opts = HlsMediaOptions::vod(None);
        let playlist = to_hls_media(&segments, &opts);
        assert!(playlist.contains("#EXT-X-TARGETDURATION:1"));
    }

    // -- init_segment_ref (Req 2.6) -----------------------------------------

    #[test]
    fn init_segment_ref_reads_template_initialization() {
        let mpd = parse_mpd(VOD_MPD).unwrap();
        let v0 = mpd.representation("v0").unwrap();
        assert_eq!(
            init_segment_ref(v0).as_deref(),
            Some("$RepresentationID$/init.mp4")
        );
    }

    #[test]
    fn init_segment_ref_reads_segment_list_initialization() {
        let xml = r#"<?xml version="1.0"?>
<MPD type="static">
  <Period>
    <AdaptationSet mimeType="audio/mp4">
      <Representation id="a0" bandwidth="128000">
        <SegmentList>
          <Initialization sourceURL="audio/init.mp4"/>
          <SegmentURL media="audio/1.m4s"/>
        </SegmentList>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>"#;
        let mpd = parse_mpd(xml).unwrap();
        let a0 = mpd.representation("a0").unwrap();
        assert_eq!(init_segment_ref(a0).as_deref(), Some("audio/init.mp4"));
    }
}
