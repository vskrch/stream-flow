//! Upcoming-segment planning for pre-buffering (`prebuffer::plan`) — Req 7.1,
//! 7.3.
//!
//! Given a parsed HLS media playlist and the client's current position, decide
//! **which upcoming segments to prefetch** (design: Components → Pre-Buffering).
//! The rule (Req 7.1) is: prefetch up to the configured number of segments that
//! come *after* the requested position. For a live presentation the playlist is
//! refreshed periodically and newly published segments must keep being
//! prefetched (Req 7.3); modelling segments by their **absolute media sequence
//! number** makes that a single, idempotent computation — the prefetcher tracks
//! the highest sequence it has already planned and asks for the next `count`
//! beyond it on every refresh.
//!
//! This module is pure (no I/O): it resolves each chosen segment's URI against
//! the manifest base (Req 1.4) and returns the plan; the [`Prefetcher`] does the
//! actual fetching.
//!
//! [`Prefetcher`]: super::Prefetcher

use m3u8_rs::MediaPlaylist;
use url::Url;

/// One segment chosen for prefetching: its absolute media-sequence number and
/// the resolved absolute upstream URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedSegment {
    /// The segment's absolute media-sequence number
    /// (`#EXT-X-MEDIA-SEQUENCE` base + index), monotonic across a live
    /// playlist's refreshes so the prefetcher never re-fetches a segment.
    pub seq: u64,
    /// The resolved absolute upstream URL of the segment (relative URIs are
    /// joined onto the manifest base — Req 1.4).
    pub url: Url,
}

/// `true` when `playlist` is a live/event presentation rather than a complete
/// VOD one.
///
/// A playlist that carries `#EXT-X-ENDLIST` is complete (VOD); anything without
/// it is still being appended to (live/event), so the prefetcher keeps polling
/// for newly published segments (Req 7.3). An explicit
/// `#EXT-X-PLAYLIST-TYPE:VOD` is treated as complete even if the endlist tag is
/// missing.
pub fn is_live(playlist: &MediaPlaylist) -> bool {
    use m3u8_rs::MediaPlaylistType;
    if matches!(playlist.playlist_type, Some(MediaPlaylistType::Vod)) {
        return false;
    }
    !playlist.end_list
}

/// Plan up to `count` segments to prefetch from `playlist` that come **after**
/// `after_seq` (Req 7.1), resolving each URI against the manifest `base`
/// (Req 1.4).
///
/// * `after_seq = None` plans from the very start of the playlist (the first
///   `count` segments) — the initial prefetch when a media playlist is first
///   served.
/// * `after_seq = Some(n)` plans the next `count` segments whose absolute
///   media-sequence number is strictly greater than `n` — the steady-state /
///   live-refresh call that never re-fetches an already-planned segment
///   (Req 7.3).
///
/// Segments whose URI cannot be resolved against `base` are skipped (they
/// cannot be fetched) rather than aborting the whole plan.
pub fn plan_upcoming_segments(
    playlist: &MediaPlaylist,
    base: &Url,
    after_seq: Option<u64>,
    count: usize,
) -> Vec<PlannedSegment> {
    if count == 0 {
        return Vec::new();
    }

    let mut planned = Vec::with_capacity(count);
    for (idx, segment) in playlist.segments.iter().enumerate() {
        let seq = playlist.media_sequence + idx as u64;
        // Only segments strictly after the requested position (Req 7.1).
        if let Some(after) = after_seq {
            if seq <= after {
                continue;
            }
        }
        // Resolve a possibly-relative segment URI against the manifest base
        // (Req 1.4); skip a segment whose URI cannot be resolved.
        let Ok(url) = base.join(&segment.uri) else {
            continue;
        };
        planned.push(PlannedSegment { seq, url });
        if planned.len() >= count {
            break;
        }
    }
    planned
}

#[cfg(test)]
mod tests {
    use super::*;
    use m3u8_rs::{MediaPlaylist, MediaPlaylistType, MediaSegment};

    fn base() -> Url {
        Url::parse("https://cdn.example.com/v/media.m3u8").unwrap()
    }

    /// A media playlist with `n` sequential segments `seg{media_sequence+i}.ts`,
    /// starting at media-sequence `media_sequence`.
    fn media_playlist(media_sequence: u64, n: u64, end_list: bool) -> MediaPlaylist {
        let segments = (0..n)
            .map(|i| MediaSegment {
                uri: format!("seg{}.ts", media_sequence + i),
                duration: 6.0,
                ..MediaSegment::default()
            })
            .collect();
        MediaPlaylist {
            target_duration: 6,
            media_sequence,
            segments,
            end_list,
            ..MediaPlaylist::default()
        }
    }

    // -- Req 7.1: prefetch up to N upcoming segments -------------------------

    #[test]
    fn plans_first_n_segments_from_start() {
        let pl = media_playlist(0, 10, true);
        let plan = plan_upcoming_segments(&pl, &base(), None, 3);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].seq, 0);
        assert_eq!(plan[2].seq, 2);
        assert_eq!(plan[0].url.as_str(), "https://cdn.example.com/v/seg0.ts");
    }

    #[test]
    fn plans_segments_strictly_after_requested_position() {
        let pl = media_playlist(0, 10, true);
        // Client is at segment 4 → prefetch 5, 6, 7 (not 4).
        let plan = plan_upcoming_segments(&pl, &base(), Some(4), 3);
        assert_eq!(
            plan.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
    }

    #[test]
    fn caps_plan_at_available_segments() {
        let pl = media_playlist(0, 5, true);
        // Ask for 10 but only 3 remain after position 1.
        let plan = plan_upcoming_segments(&pl, &base(), Some(1), 10);
        assert_eq!(
            plan.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn count_zero_plans_nothing() {
        let pl = media_playlist(0, 5, true);
        assert!(plan_upcoming_segments(&pl, &base(), None, 0).is_empty());
    }

    #[test]
    fn nothing_to_plan_when_position_at_end() {
        let pl = media_playlist(0, 5, true);
        let plan = plan_upcoming_segments(&pl, &base(), Some(4), 3);
        assert!(plan.is_empty(), "no segments after the last one");
    }

    // -- Req 1.4: relative segment URIs resolved against the base ------------

    #[test]
    fn relative_uris_resolved_against_manifest_base() {
        let mut pl = media_playlist(0, 1, true);
        pl.segments[0].uri = "../seg/abs.ts".to_string();
        let plan = plan_upcoming_segments(&pl, &base(), None, 1);
        // `../seg/abs.ts` ascends from `/v/` → `/seg/abs.ts`.
        assert_eq!(plan[0].url.as_str(), "https://cdn.example.com/seg/abs.ts");
    }

    // -- Req 7.3: media-sequence offset makes live refresh idempotent --------

    #[test]
    fn respects_media_sequence_base_for_absolute_seq() {
        // A live window that has rolled forward: media-sequence base 100.
        let pl = media_playlist(100, 5, false);
        let plan = plan_upcoming_segments(&pl, &base(), None, 2);
        assert_eq!(
            plan.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![100, 101]
        );
        assert_eq!(plan[0].url.as_str(), "https://cdn.example.com/v/seg100.ts");
    }

    #[test]
    fn live_refresh_only_plans_newly_published_segments() {
        // First poll: live window [100..105), prefetch 100..102.
        let first = media_playlist(100, 5, false);
        let plan1 = plan_upcoming_segments(&first, &base(), None, 5);
        let watermark = plan1.last().unwrap().seq; // 104

        // Window advances: now [103..108). With watermark 104, only 105..107
        // are newly published.
        let second = media_playlist(103, 5, false);
        let plan2 = plan_upcoming_segments(&second, &base(), Some(watermark), 5);
        assert_eq!(
            plan2.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![105, 106, 107],
            "a live refresh only plans segments past the watermark (Req 7.3)"
        );
    }

    // -- is_live detection ----------------------------------------------------

    #[test]
    fn endlist_means_vod() {
        let pl = media_playlist(0, 3, true);
        assert!(!is_live(&pl));
    }

    #[test]
    fn missing_endlist_means_live() {
        let pl = media_playlist(0, 3, false);
        assert!(is_live(&pl));
    }

    #[test]
    fn explicit_vod_type_is_not_live_even_without_endlist() {
        let mut pl = media_playlist(0, 3, false);
        pl.playlist_type = Some(MediaPlaylistType::Vod);
        assert!(!is_live(&pl), "an explicit VOD type is complete");
    }
}
