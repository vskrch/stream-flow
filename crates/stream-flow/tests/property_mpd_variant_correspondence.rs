//! Property-based test for MPD parsing + DASH→HLS conversion (task 16.7).
//!
//! Feature: stream-flow, Property 11
//!
//! **Property 11: MPD parse and DASH→HLS variant correspondence**
//!
//! *For any* valid MPD, parsing then reconstructing the structured
//! representation round-trips, and the generated HLS master manifest contains
//! exactly one variant per selectable representation (in document order,
//! carrying that representation's `BANDWIDTH`); for a VOD (static) presentation
//! the generated media playlist contains all segments of the representation,
//! and for a live (dynamic) presentation it contains only the most recent
//! `live_playlist_depth` segments (or all, when fewer exist) with the media
//! sequence advanced past the dropped ones.
//!
//! **Validates: Requirements 2.1, 2.2, 2.4, 2.5, 48.4**
//!
//! Requirement 2.1: parse the MPD into a structured tree of periods /
//! adaptation sets / representations. Requirement 2.2: the HLS master manifest
//! enumerates one variant per selectable representation. Requirement 2.4: a
//! live presentation's media playlist contains the most recent
//! `live_playlist_depth` segments. Requirement 2.5: a VOD presentation's media
//! playlist contains all segments. Requirement 48.4: property-based tests for
//! MPD parser behavior.
//!
//! The test drives an *arbitrary* MPD from a proptest **model** (varying
//! period / adaptation-set / representation counts, bandwidths, resolutions,
//! and static vs dynamic), renders that model to an MPD XML document, parses it
//! with [`stream_flow::mpd::parse_mpd`], and asserts the parsed structure and
//! the conversion output correspond to the model:
//!
//! * **Structural correspondence / round-trip (Req 2.1, 48.4):** the parsed
//!   [`Mpd`] equals the [`Mpd`] reconstructed directly from the model
//!   (periods, adaptation sets, representations, ids, bandwidths, presentation
//!   type, durations, inheritance), so rendering→parsing is the identity on the
//!   structured representation.
//! * **Variant correspondence (Req 2.2):** [`to_hls_master`] emits exactly one
//!   `#EXT-X-STREAM-INF` variant per representation, in document order, each
//!   carrying its representation's `BANDWIDTH`.
//! * **VOD all-segments (Req 2.5):** for a static presentation
//!   [`to_hls_media`] includes every segment and terminates with
//!   `#EXT-X-ENDLIST`.
//! * **Live window (Req 2.4):** for a dynamic presentation [`to_hls_media`]
//!   includes only the most-recent `live_playlist_depth` segments and advances
//!   `#EXT-X-MEDIA-SEQUENCE` by the number dropped.
//!
//! The resolved [`MediaSegment`] lists the media-playlist assertions need are
//! constructed directly in the test (the four-mode segment-addressing
//! resolution is task 16.3); [`to_hls_media`] consumes a `&[MediaSegment]`
//! slice, so the VOD/live windowing arithmetic is verified in isolation.

use proptest::prelude::*;
use stream_flow::mpd::{
    parse_mpd, to_hls_master, to_hls_media, AdaptationSet, HlsMediaOptions, MediaSegment, Mpd,
    Period, PresentationType, Representation, SegmentAddressing,
};

// ---------------------------------------------------------------------------
// Generator model: a structural description of an MPD, kept free of segment
// addressing so the rendered XML round-trips exactly through the parser. The
// same model is reused to compute the expected variant count / order and the
// expected parsed structure.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RepModel {
    id: String,
    bandwidth: u64,
    width: Option<u64>,
    height: Option<u64>,
}

#[derive(Debug, Clone)]
struct SetModel {
    mime_type: Option<String>,
    content_type: Option<String>,
    lang: Option<String>,
    reps: Vec<RepModel>,
}

#[derive(Debug, Clone)]
struct PeriodModel {
    id: Option<String>,
    duration: Option<String>,
    sets: Vec<SetModel>,
}

#[derive(Debug, Clone)]
struct MpdModel {
    dynamic: bool,
    mpd_duration: Option<String>,
    base_url: Option<String>,
    periods: Vec<PeriodModel>,
}

// Raw (id-less) spec tuples produced by the strategies; ids are assigned
// deterministically during `build_model` so they are globally unique and
// addressable (Req 2.3).
type ResSpec = (Option<u64>, Option<u64>);
type RepSpec = (u64, ResSpec);
type SetSpec = (
    (Option<String>, Option<String>),
    Option<String>,
    Vec<RepSpec>,
);
type PeriodSpec = (bool, Option<String>, Vec<SetSpec>);
type MpdSpec = (bool, Option<String>, Option<String>, Vec<PeriodSpec>);

fn rep_spec() -> impl Strategy<Value = RepSpec> {
    // Bandwidths biased toward the `1` boundary plus a spread up to ~20 Mbit/s.
    let bw = prop_oneof![
        2 => Just(1u64),
        5 => 1u64..=5_000_000u64,
        2 => 1u64..=20_000_000u64,
    ];
    // Resolution is either absent or a realistic (w, h) pair (kept tied so the
    // master only ever emits a `RESOLUTION` attribute for a complete pair).
    let res = prop_oneof![
        3 => Just((None, None)),
        1 => prop_oneof![
            Just((Some(426u64), Some(240u64))),
            Just((Some(640u64), Some(360u64))),
            Just((Some(1280u64), Some(720u64))),
            Just((Some(1920u64), Some(1080u64))),
        ],
    ];
    (bw, res)
}

fn set_spec() -> impl Strategy<Value = SetSpec> {
    let mime_content = prop_oneof![
        2 => Just((Some("video/mp4".to_string()), Some("video".to_string()))),
        1 => Just((Some("audio/mp4".to_string()), Some("audio".to_string()))),
        1 => Just((None, None)),
    ];
    let lang = prop_oneof![
        2 => Just(None),
        1 => Just(Some("en".to_string())),
        1 => Just(Some("fr".to_string())),
    ];
    let reps = proptest::collection::vec(rep_spec(), 0..=4);
    (mime_content, lang, reps)
}

fn period_spec() -> impl Strategy<Value = PeriodSpec> {
    let has_id = any::<bool>();
    let dur = prop_oneof![
        2 => Just(None),
        1 => Just(Some("PT4S".to_string())),
        1 => Just(Some("PT2.5S".to_string())),
    ];
    let sets = proptest::collection::vec(set_spec(), 0..=3);
    (has_id, dur, sets)
}

fn mpd_spec() -> impl Strategy<Value = MpdSpec> {
    let dynamic = any::<bool>();
    let mpd_dur = prop_oneof![
        2 => Just(None),
        1 => Just(Some("PT60S".to_string())),
    ];
    let base = prop_oneof![
        2 => Just(None),
        1 => Just(Some("https://cdn.example.com/v/".to_string())),
    ];
    let periods = proptest::collection::vec(period_spec(), 0..=3);
    (dynamic, mpd_dur, base, periods)
}

/// Resolved media segments for the media-playlist assertions, generated
/// independently of the MPD (constructed directly, per task 16.7) as a list of
/// segment durations plus a live window depth.
fn seg_spec() -> impl Strategy<Value = (Vec<f64>, usize)> {
    let durs = proptest::collection::vec(
        prop_oneof![
            Just(2.0f64),
            Just(4.0f64),
            Just(6.0f64),
            (1u64..=10_000u64).prop_map(|ms| ms as f64 / 1000.0),
        ],
        0..=20,
    );
    (durs, 0usize..=25usize)
}

/// Assign globally-unique representation ids (`r0`, `r1`, …) and period ids
/// (`p{idx}`) as the raw spec is folded into the structural model.
fn build_model(spec: MpdSpec) -> MpdModel {
    let (dynamic, mpd_duration, base_url, periods_spec) = spec;
    let mut rep_counter = 0usize;
    let mut periods = Vec::with_capacity(periods_spec.len());

    for (p_idx, (has_id, duration, sets_spec)) in periods_spec.into_iter().enumerate() {
        let mut sets = Vec::with_capacity(sets_spec.len());
        for ((mime_type, content_type), lang, reps_spec) in sets_spec {
            let mut reps = Vec::with_capacity(reps_spec.len());
            for (bandwidth, (width, height)) in reps_spec {
                reps.push(RepModel {
                    id: format!("r{rep_counter}"),
                    bandwidth,
                    width,
                    height,
                });
                rep_counter += 1;
            }
            sets.push(SetModel {
                mime_type,
                content_type,
                lang,
                reps,
            });
        }
        periods.push(PeriodModel {
            id: if has_id {
                Some(format!("p{p_idx}"))
            } else {
                None
            },
            duration,
            sets,
        });
    }

    MpdModel {
        dynamic,
        mpd_duration,
        base_url,
        periods,
    }
}

/// Render the structural model to an MPD XML document. All attribute values are
/// drawn from a safe character set (alphanumerics plus `/ : . -`), so no XML
/// escaping is required.
fn render_xml(m: &MpdModel) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str("<MPD type=\"");
    s.push_str(if m.dynamic { "dynamic" } else { "static" });
    s.push('"');
    if let Some(d) = &m.mpd_duration {
        s.push_str(&format!(" mediaPresentationDuration=\"{d}\""));
    }
    s.push_str(">\n");

    if let Some(b) = &m.base_url {
        s.push_str(&format!("  <BaseURL>{b}</BaseURL>\n"));
    }

    for p in &m.periods {
        s.push_str("  <Period");
        if let Some(id) = &p.id {
            s.push_str(&format!(" id=\"{id}\""));
        }
        if let Some(d) = &p.duration {
            s.push_str(&format!(" duration=\"{d}\""));
        }
        s.push_str(">\n");

        for set in &p.sets {
            s.push_str("    <AdaptationSet");
            if let Some(mt) = &set.mime_type {
                s.push_str(&format!(" mimeType=\"{mt}\""));
            }
            if let Some(ct) = &set.content_type {
                s.push_str(&format!(" contentType=\"{ct}\""));
            }
            if let Some(l) = &set.lang {
                s.push_str(&format!(" lang=\"{l}\""));
            }
            s.push_str(">\n");

            for r in &set.reps {
                s.push_str(&format!(
                    "      <Representation id=\"{}\" bandwidth=\"{}\"",
                    r.id, r.bandwidth
                ));
                if let Some(w) = r.width {
                    s.push_str(&format!(" width=\"{w}\""));
                }
                if let Some(h) = r.height {
                    s.push_str(&format!(" height=\"{h}\""));
                }
                s.push_str("/>\n");
            }

            s.push_str("    </AdaptationSet>\n");
        }

        s.push_str("  </Period>\n");
    }

    s.push_str("</MPD>\n");
    s
}

/// Reconstruct the [`Mpd`] the parser must yield for `m`, directly from the
/// model. The model declares no segment addressing, so every representation
/// resolves to [`SegmentAddressing::None`]; codecs/mimeType inheritance mirrors
/// the parser (a representation inherits its adaptation set's `mimeType`, and
/// has no codecs of its own).
fn expected_mpd(m: &MpdModel) -> Mpd {
    Mpd {
        presentation_type: if m.dynamic {
            PresentationType::Dynamic
        } else {
            PresentationType::Static
        },
        media_presentation_duration: m.mpd_duration.clone(),
        base_url: m.base_url.clone(),
        periods: m
            .periods
            .iter()
            .map(|p| Period {
                id: p.id.clone(),
                duration: p.duration.clone(),
                base_url: None,
                adaptation_sets: p
                    .sets
                    .iter()
                    .map(|s| AdaptationSet {
                        mime_type: s.mime_type.clone(),
                        content_type: s.content_type.clone(),
                        lang: s.lang.clone(),
                        base_url: None,
                        representations: s
                            .reps
                            .iter()
                            .map(|r| Representation {
                                id: r.id.clone(),
                                bandwidth: r.bandwidth,
                                width: r.width,
                                height: r.height,
                                codecs: None,
                                // Inherited from the adaptation set (Req 2.1 parse).
                                mime_type: s.mime_type.clone(),
                                frame_rate: None,
                                base_url: None,
                                segment_addressing: SegmentAddressing::None,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// The model's representations flattened in document order (period → set →
/// representation) — the order `to_hls_master` must emit variants in (Req 2.2).
fn flat_reps(m: &MpdModel) -> Vec<&RepModel> {
    m.periods
        .iter()
        .flat_map(|p| p.sets.iter())
        .flat_map(|s| s.reps.iter())
        .collect()
}

/// The non-comment, non-empty lines of an HLS playlist (i.e. the URL lines),
/// in order.
fn url_lines(playlist: &str) -> Vec<String> {
    playlist
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Pair each `#EXT-X-STREAM-INF` line in an HLS master with the variant URL on
/// the immediately following line, in document order.
fn master_variants(master: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = master.lines().collect();
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].starts_with("#EXT-X-STREAM-INF") {
            let inf = lines[i].to_string();
            let url = lines.get(i + 1).copied().unwrap_or("").to_string();
            pairs.push((inf, url));
            i += 2;
        } else {
            i += 1;
        }
    }
    pairs
}

proptest! {
    // 256 cases > the 100-iteration floor required for a property task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 11 — MPD parse and DASH→HLS variant
    /// correspondence. **Validates: Requirements 2.1, 2.2, 2.4, 2.5, 48.4**
    #[test]
    fn mpd_parse_and_dash_to_hls_variant_correspondence(
        (spec, (durations, depth)) in (mpd_spec(), seg_spec())
    ) {
        let model = build_model(spec);
        let xml = render_xml(&model);

        // -- Parse (Req 2.1): a well-formed generated MPD must parse. ---------
        let parsed = parse_mpd(&xml);
        prop_assert!(
            parsed.is_ok(),
            "generated MPD must parse, got {:?}\nXML:\n{}",
            parsed.as_ref().err(),
            xml
        );
        let mpd = parsed.unwrap();

        // -- Structural correspondence / round-trip (Req 2.1, 48.4): the parsed
        //    tree equals the model reconstructed directly. ------------------
        let expected = expected_mpd(&model);
        prop_assert_eq!(
            &mpd,
            &expected,
            "parsed MPD structure must correspond to the model\nXML:\n{}",
            xml
        );

        // The representation enumeration matches the model's document order.
        let flat = flat_reps(&model);
        prop_assert_eq!(mpd.representation_count(), flat.len());
        let parsed_ids: Vec<&str> = mpd.representations().map(|r| r.id.as_str()).collect();
        let model_ids: Vec<&str> = flat.iter().map(|r| r.id.as_str()).collect();
        prop_assert_eq!(parsed_ids, model_ids);

        // -- Variant correspondence (Req 2.2): exactly one master variant per
        //    representation, in document order, carrying its BANDWIDTH. -----
        let master = to_hls_master(&mpd, |r| format!("media/{}.m3u8", r.id));
        let variants = master_variants(&master);
        prop_assert_eq!(
            variants.len(),
            flat.len(),
            "one #EXT-X-STREAM-INF variant per representation\nmaster:\n{}",
            master
        );
        for (variant, rep) in variants.iter().zip(flat.iter()) {
            let (inf, url) = variant;
            // Variant URL is in document order, mapping to this representation.
            let want_url = format!("media/{}.m3u8", rep.id);
            prop_assert_eq!(url, &want_url, "variant URL order / mapping\nmaster:\n{}", master);

            // BANDWIDTH is the first attribute and carries this rep's bandwidth.
            let attrs = inf
                .strip_prefix("#EXT-X-STREAM-INF:")
                .expect("variant line has the #EXT-X-STREAM-INF: prefix");
            let first_attr = attrs.split(',').next().unwrap_or("");
            let want_bw = format!("BANDWIDTH={}", rep.bandwidth);
            prop_assert_eq!(
                first_attr,
                want_bw.as_str(),
                "variant must carry the representation's BANDWIDTH\nmaster:\n{}",
                master
            );
        }

        // -- Media playlist (Req 2.4 live / Req 2.5 VOD). --------------------
        // Resolved segments are built directly (segment-addressing resolution
        // is task 16.3); `to_hls_media` consumes the slice.
        let segments: Vec<MediaSegment> = durations
            .iter()
            .enumerate()
            .map(|(i, &d)| MediaSegment::new(format!("seg-{i}.m4s"), d))
            .collect();
        let all_urls: Vec<String> = (0..segments.len()).map(|i| format!("seg-{i}.m4s")).collect();

        if model.dynamic {
            // Live (Req 2.4): only the most-recent `depth` segments; media
            // sequence advanced past the dropped ones; open-ended (no ENDLIST).
            let opts = HlsMediaOptions::live(depth, Some("init.mp4".to_string()));
            let playlist = to_hls_media(&segments, &opts);

            let eff = depth.min(segments.len());
            let start = segments.len() - eff;
            let expected_window: Vec<String> = all_urls[start..].to_vec();

            let got = url_lines(&playlist);
            prop_assert_eq!(
                &got,
                &expected_window,
                "live playlist must contain only the most recent live_playlist_depth segments\nplaylist:\n{}",
                playlist
            );
            prop_assert_eq!(playlist.matches("#EXTINF").count(), eff);
            prop_assert!(
                playlist.contains(&format!("#EXT-X-MEDIA-SEQUENCE:{start}\n")),
                "media sequence must advance by the dropped count ({start})\nplaylist:\n{}",
                playlist
            );
            prop_assert!(
                !playlist.contains("#EXT-X-ENDLIST"),
                "live playlists are open-ended (no #EXT-X-ENDLIST)\nplaylist:\n{}",
                playlist
            );
        } else {
            // VOD (Req 2.5): every segment, in order; immutable + ENDLIST.
            let opts = HlsMediaOptions::vod(Some("init.mp4".to_string()));
            let playlist = to_hls_media(&segments, &opts);

            let got = url_lines(&playlist);
            prop_assert_eq!(
                &got,
                &all_urls,
                "VOD playlist must contain all segments of the representation\nplaylist:\n{}",
                playlist
            );
            prop_assert_eq!(playlist.matches("#EXTINF").count(), segments.len());
            prop_assert!(
                playlist.contains("#EXT-X-MEDIA-SEQUENCE:0\n"),
                "VOD media sequence starts at 0\nplaylist:\n{}",
                playlist
            );
            prop_assert!(
                playlist.contains("#EXT-X-ENDLIST"),
                "VOD playlists are complete (#EXT-X-ENDLIST)\nplaylist:\n{}",
                playlist
            );
        }
    }
}
