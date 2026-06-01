//! Property-based test for DASH segment-addressing resolution (task 16.8).
//!
//! Feature: ZippyPanther, Property 12
//!
//! **Property 12: DASH segment addressing correctness**
//!
//! *For any* representation using `SegmentTemplate` (fixed or
//! `SegmentTimeline`), `SegmentBase`, or `SegmentList`, the computed segment
//! set is correct: template identifiers
//! `$Number$`/`$Time$`/`$RepresentationID$`/`$Bandwidth$` are substituted with
//! their computed values honoring width specifiers; a `SegmentTimeline` with
//! `S` entries `(t,d,r)` expands to `Σ(r+1)` segments with strictly
//! non-overlapping, monotonically increasing start times; and
//! `SegmentBase`/`SegmentList` byte ranges are contiguous and within bounds.
//!
//! **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6**
//!
//! The four DASH segment-addressing modes (Req 3.1–3.6) are exercised as
//! independent properties against the real
//! [`zippy_panther::mpd::resolve_segments`] dispatch (`src/mpd/segments.rs`):
//!
//! * **`SegmentTemplate` fixed (Req 3.1, 3.5):** an arbitrary template using
//!   all four identifiers (with arbitrary `%0Nd` width specifiers and the `$$`
//!   literal-dollar escape) resolves to `ceil(total / segment_secs)` segments
//!   whose `$Number$`/`$Time$` accumulate as `startNumber + i` / `i * duration`
//!   and whose URLs equal an independently-computed substitution; start times
//!   are strictly increasing and touch without overlap.
//! * **`SegmentTimeline` (Req 3.2):** an arbitrary `(t,d,r)` entry set
//!   (continuation via explicit `@t` or implicit) expands to exactly `Σ(r+1)`
//!   segments with strictly increasing start times where each segment ends
//!   exactly where the next begins (non-overlapping).
//! * **`SegmentTimeline` gap (Req 3.6):** a forward `@t` jump that leaves a
//!   hole is a `MissingSegment` error naming the representation and the gap.
//! * **`SegmentList` (Req 3.4):** explicit `<SegmentURL>` media + `@mediaRange`
//!   are enumerated verbatim; generated contiguous ranges round-trip and stay
//!   contiguous and within bounds.
//! * **`SegmentBase` (Req 3.3):** the init range and the media payload byte
//!   range are derived from the declared init / index ranges; the regions are
//!   ordered (init < index < media), non-overlapping, and contiguous.

use proptest::prelude::*;
use zippy_panther::mpd::{
    resolve_segments, MpdError, Representation, SegmentAddressing, SegmentBase, SegmentList,
    SegmentTemplate, SegmentTimeline, SegmentUrl, TimelineEntry, UrlRange,
};

// ---------------------------------------------------------------------------
// Shared generators
// ---------------------------------------------------------------------------

/// Representation builder: only the fields the addressing dispatch reads
/// (`id`, `bandwidth`, `base_url`, `segment_addressing`) vary.
fn rep_with(
    id: &str,
    bandwidth: u64,
    base_url: Option<String>,
    addressing: SegmentAddressing,
) -> Representation {
    Representation {
        id: id.to_string(),
        bandwidth,
        width: None,
        height: None,
        codecs: None,
        mime_type: None,
        frame_rate: None,
        base_url,
        segment_addressing: addressing,
    }
}

/// `@bandwidth` in bits/s, biased toward the `1` boundary plus realistic spreads.
fn bandwidth() -> impl Strategy<Value = u64> {
    prop_oneof![Just(1u64), 1u64..=5_000_000u64, 1u64..=20_000_000u64]
}

/// `@timescale` ticks/s drawn from the values real encoders emit (plus `1`,
/// the DASH default).
fn timescale() -> impl Strategy<Value = u64> {
    prop_oneof![Just(1u64), Just(1000u64), Just(48_000u64), Just(90_000u64)]
}

/// A `(timescale, duration_ts)` pair where `duration_ts = timescale * k` for
/// `k ∈ 1..=10`, so the per-segment duration is a whole `1..=10` seconds and
/// the enumerated segment count stays bounded.
fn ts_and_duration() -> impl Strategy<Value = (u64, u64)> {
    timescale().prop_flat_map(|ts| (1u64..=10u64).prop_map(move |k| (ts, ts * k)))
}

// ---------------------------------------------------------------------------
// SegmentTemplate — fixed duration (Req 3.1, 3.5)
// ---------------------------------------------------------------------------

proptest! {
    // 256 cases > the 100-iteration floor required for a property task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 12 — fixed `SegmentTemplate` identifier
    /// substitution and segment enumeration. **Validates: Requirements 3.1, 3.5**
    #[test]
    fn fixed_template_substitutes_identifiers_and_enumerates_segments(
        id in "[a-zA-Z][a-zA-Z0-9_-]{0,7}",
        bandwidth in bandwidth(),
        (timescale, duration_ts) in ts_and_duration(),
        start_number in prop_oneof![Just(Option::<u64>::None), (0u64..=1000u64).prop_map(Some)],
        total in prop_oneof![1 => Just(Option::<f64>::None), 3 => (1.0f64..=120.0f64).prop_map(Some)],
        num_w in prop_oneof![2 => Just(Option::<usize>::None), 1 => (1usize..=8usize).prop_map(Some)],
        time_w in prop_oneof![2 => Just(Option::<usize>::None), 1 => (1usize..=8usize).prop_map(Some)],
    ) {
        // A media template exercising all four identifiers, an optional width
        // specifier on each numeric one, and the `$$` literal-dollar escape.
        let num_tok = match num_w {
            Some(w) => format!("$Number%0{w}d$"),
            None => "$Number$".to_string(),
        };
        let time_tok = match time_w {
            Some(w) => format!("$Time%0{w}d$"),
            None => "$Time$".to_string(),
        };
        let media = format!("$RepresentationID$/$$x/b$Bandwidth$/{num_tok}-{time_tok}.m4s");

        let template = SegmentTemplate {
            media: Some(media),
            initialization: Some("$RepresentationID$/init-$Bandwidth$.mp4".to_string()),
            start_number,
            duration: Some(duration_ts),
            timescale: Some(timescale),
            timeline: None,
        };
        let rep = rep_with(&id, bandwidth, None, SegmentAddressing::Template(template));
        let resolved = resolve_segments(&rep, total).expect("fixed template must resolve");

        // -- Segment count: ceil(total / segment_secs), or 1 when no duration.
        let eff_start = start_number.unwrap_or(1);
        let seg_secs = duration_ts as f64 / timescale as f64;
        let expected_count = match total {
            Some(t) if seg_secs > 0.0 => (t / seg_secs).ceil() as u64,
            _ => 1,
        };
        prop_assert_eq!(resolved.segments.len() as u64, expected_count);

        // -- Init substitutes $RepresentationID$ + $Bandwidth$ (never $Number$/$Time$).
        let want_init = format!("{id}/init-{bandwidth}.mp4");
        prop_assert_eq!(
            resolved.init.as_ref().and_then(|i| i.url.as_deref()),
            Some(want_init.as_str())
        );

        // -- Per-segment: $Number$/$Time$ accumulate, URL substitution exact.
        for (idx, seg) in resolved.segments.iter().enumerate() {
            let i = idx as u64;
            let number = eff_start + i;
            let time = i * duration_ts;

            prop_assert_eq!(seg.number, Some(number));
            prop_assert_eq!(seg.time, Some(time));
            prop_assert_eq!(seg.duration_ts, duration_ts);
            prop_assert_eq!(seg.timescale, timescale);

            let num_str = match num_w {
                Some(w) => format!("{number:0>w$}"),
                None => number.to_string(),
            };
            let time_str = match time_w {
                Some(w) => format!("{time:0>w$}"),
                None => time.to_string(),
            };
            // `$$x` collapses to the literal `$x`; identifiers substituted.
            let want_url = format!("{id}/$x/b{bandwidth}/{num_str}-{time_str}.m4s");
            prop_assert_eq!(seg.url.as_str(), want_url.as_str());
        }

        // -- Start times: strictly increasing and touching (non-overlapping):
        //    each segment ends exactly where the next begins.
        let times: Vec<u64> = resolved.segments.iter().map(|s| s.time.unwrap()).collect();
        for w in times.windows(2) {
            prop_assert!(w[1] > w[0], "monotonically increasing start times");
            prop_assert_eq!(w[1] - w[0], duration_ts, "non-overlapping fixed segments");
        }
    }
}

// ---------------------------------------------------------------------------
// SegmentTemplate + SegmentTimeline — expansion (Req 3.2)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 12 — `SegmentTimeline` `(t,d,r)`
    /// expansion to `Σ(r+1)` strictly non-overlapping monotonic segments.
    /// **Validates: Requirements 3.2**
    #[test]
    fn timeline_expands_to_sum_r_plus_one_monotonic_non_overlapping(
        id in "[a-zA-Z][a-zA-Z0-9_-]{0,7}",
        bandwidth in bandwidth(),
        timescale in timescale(),
        start_number in prop_oneof![Just(Option::<u64>::None), (0u64..=1000u64).prop_map(Some)],
        // Each S entry: (d, r, use_explicit_t). `d >= 1`; `r ∈ -1..=8`
        // (`-1` = "no repeat" since a bare timeline carries no end marker).
        entries in proptest::collection::vec(
            (1u64..=100_000u64, -1i64..=8i64, any::<bool>()),
            1..=8,
        ),
    ) {
        // Build the timeline, computing an explicit `@t` exactly equal to the
        // running time when requested (a valid continuation), else leaving it
        // implicit. Both must yield the identical monotonic expansion.
        let mut running = 0u64;
        let mut tl_entries = Vec::with_capacity(entries.len());
        for &(d, r, explicit_t) in &entries {
            let t = if explicit_t { Some(running) } else { None };
            tl_entries.push(TimelineEntry { t, d, r });
            let reps = if r < 0 { 0 } else { r as u64 };
            running += d * (reps + 1);
        }

        let template = SegmentTemplate {
            media: Some("$RepresentationID$/seg-$Number$-$Time$.m4s".to_string()),
            initialization: Some("$RepresentationID$/init.mp4".to_string()),
            start_number,
            duration: None,
            timescale: Some(timescale),
            timeline: Some(SegmentTimeline { entries: tl_entries }),
        };
        let rep = rep_with(&id, bandwidth, None, SegmentAddressing::Template(template));
        let resolved = resolve_segments(&rep, None).expect("valid timeline must resolve");

        // -- Expected expansion: Σ(r+1) segments, $Number$/$Time$ accumulating.
        let eff_start = start_number.unwrap_or(1);
        let mut exp_times = Vec::new();
        let mut exp_numbers = Vec::new();
        let mut exp_durs = Vec::new();
        let mut t = 0u64;
        let mut number = eff_start;
        for &(d, r, _) in &entries {
            let reps = if r < 0 { 0 } else { r as u64 };
            for _ in 0..=reps {
                exp_times.push(t);
                exp_numbers.push(number);
                exp_durs.push(d);
                t += d;
                number += 1;
            }
        }
        let expected_count: usize =
            entries.iter().map(|&(_, r, _)| if r < 0 { 1 } else { (r as usize) + 1 }).sum();

        prop_assert_eq!(resolved.segments.len(), expected_count, "Σ(r+1) segments");
        prop_assert_eq!(resolved.segments.len(), exp_times.len());

        for (i, seg) in resolved.segments.iter().enumerate() {
            prop_assert_eq!(seg.number, Some(exp_numbers[i]));
            prop_assert_eq!(seg.time, Some(exp_times[i]));
            prop_assert_eq!(seg.duration_ts, exp_durs[i]);
            prop_assert_eq!(seg.timescale, timescale);
            let want_url = format!("{id}/seg-{}-{}.m4s", exp_numbers[i], exp_times[i]);
            prop_assert_eq!(seg.url.as_str(), want_url.as_str());
        }

        // -- Strictly increasing + non-overlapping: each segment ends exactly
        //    where the next begins (start[i] + duration[i] == start[i+1]).
        for i in 1..resolved.segments.len() {
            let prev = &resolved.segments[i - 1];
            let cur = &resolved.segments[i];
            prop_assert!(
                cur.time.unwrap() > prev.time.unwrap(),
                "monotonically increasing start times"
            );
            prop_assert_eq!(
                cur.time.unwrap(),
                prev.time.unwrap() + prev.duration_ts,
                "non-overlapping timeline segments"
            );
        }

        let want_init = format!("{id}/init.mp4");
        prop_assert_eq!(
            resolved.init.as_ref().and_then(|i| i.url.as_deref()),
            Some(want_init.as_str())
        );
    }
}

// ---------------------------------------------------------------------------
// SegmentTimeline — unresolved gap (Req 3.6)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 12 — a forward `@t` jump that leaves a
    /// hole is a `MissingSegment` error naming the representation and the gap.
    /// **Validates: Requirements 3.6**
    #[test]
    fn timeline_forward_jump_gap_errors_naming_missing_segment(
        id in "[a-zA-Z][a-zA-Z0-9_-]{0,7}",
        bandwidth in bandwidth(),
        timescale in timescale(),
        d in 1u64..=10_000u64,
        gap in 1u64..=10_000u64,
    ) {
        // First entry t=0,d (ends at d). Second entry jumps forward to d+gap,
        // leaving a hole between `d` and `d+gap`: an unresolved gap (Req 3.6).
        let jump = d + gap;
        let entries = vec![
            TimelineEntry { t: Some(0), d, r: 0 },
            TimelineEntry { t: Some(jump), d, r: 0 },
        ];
        let template = SegmentTemplate {
            media: Some("$RepresentationID$/s$Time$.m4s".to_string()),
            initialization: None,
            start_number: Some(1),
            duration: None,
            timescale: Some(timescale),
            timeline: Some(SegmentTimeline { entries }),
        };
        let rep = rep_with(&id, bandwidth, None, SegmentAddressing::Template(template));

        let result = resolve_segments(&rep, None);
        prop_assert!(result.is_err(), "a forward @t gap must be an error");
        match result.unwrap_err() {
            MpdError::MissingSegment { representation, segment } => {
                prop_assert_eq!(representation, id);
                // The error names the gap location (the time the next segment
                // was expected to start, `d`).
                prop_assert!(
                    segment.contains(&d.to_string()),
                    "error must name the missing segment, got: {}",
                    segment
                );
            }
            other => prop_assert!(false, "expected MissingSegment, got {:?}", other),
        }
    }
}

// ---------------------------------------------------------------------------
// SegmentList — explicit URLs + byte ranges (Req 3.4)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 12 — `SegmentList` enumerates explicit
    /// `<SegmentURL>` media URLs and `@mediaRange` byte ranges; generated
    /// contiguous ranges stay contiguous and within bounds.
    /// **Validates: Requirements 3.4**
    #[test]
    fn segment_list_enumerates_urls_and_contiguous_byte_ranges(
        tag in "[a-zA-Z][a-zA-Z0-9_-]{0,5}",
        (timescale, duration_ts) in ts_and_duration(),
        base_offset in 0u64..=10_000u64,
        lens in proptest::collection::vec(1u64..=100_000u64, 1..=12),
        with_ranges in any::<bool>(),
        init_source in "[a-zA-Z][a-zA-Z0-9_/.-]{0,12}",
        init_has_range in any::<bool>(),
    ) {
        // Build explicit segment URLs with contiguous media byte ranges
        // (each segment's range begins one byte after the previous one ends).
        let mut segment_urls = Vec::with_capacity(lens.len());
        let mut expected: Vec<(String, Option<(u64, u64)>)> = Vec::with_capacity(lens.len());
        let mut offset = base_offset;
        for (i, &len) in lens.iter().enumerate() {
            let url = format!("{tag}/s{i}.m4s");
            let (media_range, exp_range) = if with_ranges {
                let start = offset;
                let end = offset + len - 1;
                offset = end + 1;
                (Some(format!("{start}-{end}")), Some((start, end)))
            } else {
                (None, None)
            };
            segment_urls.push(SegmentUrl {
                media: Some(url.clone()),
                media_range,
                index: None,
                index_range: None,
            });
            expected.push((url, exp_range));
        }

        let list = SegmentList {
            duration: Some(duration_ts),
            timescale: Some(timescale),
            initialization: Some(UrlRange {
                source_url: Some(init_source.clone()),
                range: if init_has_range { Some("0-99".to_string()) } else { None },
            }),
            segment_urls,
        };
        let rep = rep_with("a0", 128_000, None, SegmentAddressing::List(list));
        let resolved = resolve_segments(&rep, None).expect("segment list must resolve");

        // Init URL is the declared sourceURL verbatim.
        prop_assert_eq!(
            resolved.init.as_ref().and_then(|i| i.url.as_deref()),
            Some(init_source.as_str())
        );

        prop_assert_eq!(resolved.segments.len(), expected.len());
        let dur_secs = duration_ts as f64 / timescale as f64;
        let mut prev_end: Option<u64> = None;
        for (seg, (want_url, want_range)) in resolved.segments.iter().zip(expected.iter()) {
            prop_assert_eq!(seg.url.as_str(), want_url.as_str());
            prop_assert!((seg.duration_secs() - dur_secs).abs() < 1e-9);
            match want_range {
                Some((start, end)) => {
                    let br = seg.byte_range.expect("media range present");
                    prop_assert_eq!(br.start, *start);
                    prop_assert_eq!(br.end, Some(*end));
                    prop_assert!(*end >= *start, "within bounds: end >= start");
                    if let Some(pe) = prev_end {
                        prop_assert_eq!(*start, pe + 1, "byte ranges are contiguous");
                    }
                    prev_end = Some(*end);
                }
                None => prop_assert!(seg.byte_range.is_none()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SegmentBase — init + indexed media byte ranges (Req 3.3)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 12 — `SegmentBase` derives the init byte
    /// range and the indexed media byte range; the regions are ordered,
    /// non-overlapping, and contiguous. **Validates: Requirements 3.3**
    #[test]
    fn segment_base_derives_contiguous_init_and_media_byte_ranges(
        file in "[a-zA-Z][a-zA-Z0-9_/.-]{0,15}",
        bandwidth in bandwidth(),
        timescale in timescale(),
        init_end in 0u64..=100_000u64,
        index_len in 1u64..=100_000u64,
        secs in 1.0f64..=300.0f64,
        with_index in any::<bool>(),
    ) {
        // Init range [0, init_end]; when present the index box is contiguous
        // with the init range, and the media payload begins right after the
        // index box (or after the init range when there is no index).
        let init_range = format!("0-{init_end}");
        let (index_range, expected_media_start) = if with_index {
            let index_start = init_end + 1;
            let index_end = index_start + index_len - 1;
            (Some(format!("{index_start}-{index_end}")), index_end + 1)
        } else {
            (None, init_end + 1)
        };

        let base = SegmentBase {
            index_range,
            timescale: Some(timescale),
            initialization: Some(UrlRange {
                source_url: None,
                range: Some(init_range),
            }),
        };
        let rep = rep_with("r0", bandwidth, Some(file.clone()), SegmentAddressing::Base(base));
        let resolved = resolve_segments(&rep, Some(secs)).expect("segment base must resolve");

        // Init: URL falls back to the representation's single file; range [0, init_end].
        let init = resolved.init.expect("init present");
        prop_assert_eq!(init.url.as_deref(), Some(file.as_str()));
        let ir = init.byte_range.expect("init byte range");
        prop_assert_eq!(ir.start, 0);
        prop_assert_eq!(ir.end, Some(init_end));

        // A single media segment over the same file.
        prop_assert_eq!(resolved.segments.len(), 1);
        let seg = &resolved.segments[0];
        prop_assert_eq!(seg.url.as_str(), file.as_str());
        prop_assert_eq!(seg.time, Some(0));
        prop_assert_eq!(seg.timescale, timescale);

        let mr = seg.byte_range.expect("media byte range");
        prop_assert_eq!(mr.start, expected_media_start);
        prop_assert_eq!(mr.end, None, "media payload runs to end of resource");

        // Ordered + non-overlapping + within bounds: media starts strictly
        // after the init region (and, with an index, after the index box).
        prop_assert!(
            mr.start > ir.end.unwrap(),
            "media payload begins after the init region"
        );
        if with_index {
            // Contiguous: index follows init, media follows index.
            prop_assert_eq!(expected_media_start, init_end + 1 + index_len);
        } else {
            prop_assert_eq!(expected_media_start, init_end + 1);
        }

        // Duration ticks derived from the presentation duration.
        let expected_dur = (secs * timescale as f64).round() as u64;
        prop_assert_eq!(seg.duration_ts, expected_dur);
    }
}
