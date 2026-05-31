//! Property-based tests for the quality selection module.
//!
//! **Property 37: Quality ranking respects constraints and ordering**
//! **Property 38: Release-name parsing recovers embedded tokens**
//!
//! These tests use `proptest` to verify universal properties across many
//! generated inputs.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::quality::{
        parse_release_name, AudioCodec, HdrFlag, QualityPrefs, QualityRanker, RankedFile,
        Resolution, Source, VideoCodec,
    };

    // -----------------------------------------------------------------------
    // Generators
    // -----------------------------------------------------------------------

    fn arb_resolution() -> impl Strategy<Value = Resolution> {
        prop_oneof![
            Just(Resolution::R480p),
            Just(Resolution::R720p),
            Just(Resolution::R1080p),
            Just(Resolution::R2160p),
        ]
    }

    fn arb_video_codec() -> impl Strategy<Value = VideoCodec> {
        prop_oneof![
            Just(VideoCodec::H264),
            Just(VideoCodec::H265),
            Just(VideoCodec::AV1),
            Just(VideoCodec::VP9),
        ]
    }

    fn arb_audio_codec() -> impl Strategy<Value = AudioCodec> {
        prop_oneof![
            Just(AudioCodec::TrueHD),
            Just(AudioCodec::DTS),
            Just(AudioCodec::Atmos),
            Just(AudioCodec::AAC),
            Just(AudioCodec::AC3),
            Just(AudioCodec::EAC3),
            Just(AudioCodec::DTSHD),
            Just(AudioCodec::FLAC),
            Just(AudioCodec::MP3),
        ]
    }

    fn arb_source() -> impl Strategy<Value = Source> {
        prop_oneof![
            Just(Source::BluRay),
            Just(Source::WebDL),
            Just(Source::WebRip),
            Just(Source::HDTV),
            Just(Source::DVDRip),
            Just(Source::BluRayRemux),
        ]
    }

    fn arb_hdr_flag() -> impl Strategy<Value = HdrFlag> {
        prop_oneof![
            Just(HdrFlag::HDR),
            Just(HdrFlag::HDR10),
            Just(HdrFlag::HDR10Plus),
            Just(HdrFlag::DolbyVision),
            Just(HdrFlag::HLG),
        ]
    }

    /// Generate a release name from standard tokens.
    fn arb_release_name(
        resolution: Resolution,
        video_codec: VideoCodec,
        audio_codec: AudioCodec,
    ) -> String {
        let res_token = match resolution {
            Resolution::R480p => "480p",
            Resolution::R720p => "720p",
            Resolution::R1080p => "1080p",
            Resolution::R2160p => "2160p",
        };
        let codec_token = match video_codec {
            VideoCodec::H264 => "x264",
            VideoCodec::H265 => "x265",
            VideoCodec::AV1 => "AV1",
            VideoCodec::VP9 => "VP9",
        };
        let audio_token = match audio_codec {
            AudioCodec::TrueHD => "TrueHD",
            AudioCodec::DTS => "DTS",
            AudioCodec::Atmos => "Atmos",
            AudioCodec::AAC => "AAC",
            AudioCodec::AC3 => "AC3",
            AudioCodec::EAC3 => "EAC3",
            AudioCodec::DTSHD => "DTS-HD",
            AudioCodec::FLAC => "FLAC",
            AudioCodec::MP3 => "MP3",
        };
        format!("Movie.2023.{res_token}.BluRay.{codec_token}.{audio_token}-GROUP")
    }

    // -----------------------------------------------------------------------
    // Property 38: Release-name parsing recovers embedded tokens (Req 38.4)
    // -----------------------------------------------------------------------

    /// **Property 38: Release-name parsing recovers embedded tokens**
    ///
    /// *For any* filename constructed from standard release tokens (resolution
    /// such as `1080p`/`2160p`, video codec such as `x265`/`HEVC`, audio such
    /// as `AAC`/`DTS`), the parser extracts exactly the tokens that are present.
    ///
    /// **Validates: Requirements 38.4**
    #[test]
    fn property_38_release_name_parsing_recovers_embedded_tokens() {
        let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
            cases: 200,
            ..Default::default()
        });

        runner
            .run(
                &(arb_resolution(), arb_video_codec(), arb_audio_codec()),
                |(resolution, video_codec, audio_codec)| {
                    let name = arb_release_name(resolution, video_codec, audio_codec);
                    let info = parse_release_name(&name);

                    // Resolution must be recovered.
                    prop_assert_eq!(
                        info.resolution,
                        Some(resolution),
                        "resolution not recovered from name={}",
                        name
                    );

                    // Video codec must be recovered.
                    prop_assert_eq!(
                        info.video_codec,
                        Some(video_codec),
                        "video_codec not recovered from name={}",
                        name
                    );

                    // Audio codec must be recovered (may be in a list).
                    prop_assert!(
                        info.audio_codecs.contains(&audio_codec),
                        "audio_codec {audio_codec:?} not recovered from name={name}, got {:?}",
                        info.audio_codecs
                    );

                    Ok(())
                },
            )
            .unwrap();
    }

    /// **Property 38b: Parser is total — never panics on arbitrary input**
    ///
    /// **Validates: Requirements 38.4**
    #[test]
    fn property_38b_parser_is_total_on_arbitrary_input() {
        let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
            cases: 200,
            ..Default::default()
        });

        runner
            .run(&any::<String>(), |name| {
                // Must not panic.
                let _info = parse_release_name(&name);
                Ok(())
            })
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // Property 37: Quality ranking respects constraints and ordering (Req 38.1, 38.2, 38.5)
    // -----------------------------------------------------------------------

    /// **Property 37: Quality ranking respects constraints and ordering**
    ///
    /// *For any* set of debrid files and a quality preference, the ranked
    /// output excludes every file whose detected resolution exceeds the
    /// configured maximum and every file whose bitrate exceeds 80% of an
    /// available bandwidth estimate, and the remaining files are ordered by
    /// the preference (default: resolution descending, then size descending).
    ///
    /// **Validates: Requirements 38.1, 38.2, 38.5**
    #[test]
    fn property_37_quality_ranking_respects_constraints_and_ordering() {
        let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
            cases: 200,
            ..Default::default()
        });

        runner
            .run(
                &(
                    // Generate 1–8 files with random resolutions and sizes.
                    prop::collection::vec(
                        (arb_resolution(), 1i64..=50_000_000_000i64),
                        1..=8,
                    ),
                    // Optional max resolution.
                    prop::option::of(arb_resolution()),
                    // Optional bandwidth estimate (1 Mbps – 1 Gbps).
                    prop::option::of(1_000_000u64..=1_000_000_000u64),
                ),
                |(file_specs, max_resolution, bandwidth_bps)| {
                    let files: Vec<RankedFile> = file_specs
                        .iter()
                        .enumerate()
                        .map(|(i, (res, size))| {
                            let res_token = match res {
                                Resolution::R480p => "480p",
                                Resolution::R720p => "720p",
                                Resolution::R1080p => "1080p",
                                Resolution::R2160p => "2160p",
                            };
                            RankedFile::new(
                                format!("Movie.{res_token}.BluRay.x265.AAC-G{i}"),
                                *size,
                            )
                        })
                        .collect();

                    let prefs = QualityPrefs {
                        max_resolution,
                        ..Default::default()
                    };

                    let ranked = QualityRanker::rank(files.clone(), &prefs, bandwidth_bps);

                    // --- Constraint 1: no file exceeds max_resolution (Req 38.2) ---
                    if let Some(max) = max_resolution {
                        for f in &ranked {
                            if let Some(res) = f.release_info.resolution {
                                prop_assert!(
                                    res <= max,
                                    "file {:?} has resolution {:?} > max {:?}",
                                    f.name,
                                    res,
                                    max
                                );
                            }
                        }
                    }

                    // --- Constraint 2: no file exceeds 80% of bandwidth (Req 38.5) ---
                    if let Some(bw) = bandwidth_bps {
                        let threshold = (bw as f64 * 0.8) as u64;
                        for f in &ranked {
                            if f.size > 0 {
                                let bits = f.size as f64 * 8.0;
                                let estimated_bps = (bits / 7200.0) as u64;
                                prop_assert!(
                                    estimated_bps <= threshold,
                                    "file {:?} estimated bitrate {} > threshold {}",
                                    f.name,
                                    estimated_bps,
                                    threshold
                                );
                            }
                        }
                    }

                    // --- Ordering: default = resolution desc, then size desc (Req 38.1) ---
                    // (Only check when all health scores are equal = 0.0, which is the
                    // default for files created with RankedFile::new.)
                    for window in ranked.windows(2) {
                        let a = &window[0];
                        let b = &window[1];
                        // Health scores are equal (both 0.0), so quality score governs.
                        // Resolution of a must be >= resolution of b.
                        if let (Some(ra), Some(rb)) =
                            (a.release_info.resolution, b.release_info.resolution)
                        {
                            if ra < rb {
                                prop_assert!(
                                    false,
                                    "ordering violated: {:?} ({:?}) ranked before {:?} ({:?})",
                                    a.name,
                                    ra,
                                    b.name,
                                    rb
                                );
                            }
                            // Same resolution: larger size first.
                            if ra == rb && a.size < b.size {
                                prop_assert!(
                                    false,
                                    "size tiebreaker violated: {:?} (size={}) ranked before {:?} (size={})",
                                    a.name, a.size, b.name, b.size
                                );
                            }
                        }
                    }

                    Ok(())
                },
            )
            .unwrap();
    }

    /// **Property 37b: Excluded files are never in the ranked output**
    ///
    /// Every file excluded by max_resolution or bandwidth is absent from the
    /// ranked output.
    ///
    /// **Validates: Requirements 38.2, 38.5**
    #[test]
    fn property_37b_excluded_files_absent_from_ranked_output() {
        let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
            cases: 200,
            ..Default::default()
        });

        runner
            .run(
                &(
                    prop::collection::vec((arb_resolution(), 1i64..=50_000_000_000i64), 1..=6),
                    arb_resolution(),
                    1_000_000u64..=100_000_000u64,
                ),
                |(file_specs, max_resolution, bandwidth_bps)| {
                    let files: Vec<RankedFile> = file_specs
                        .iter()
                        .enumerate()
                        .map(|(i, (res, size))| {
                            let res_token = match res {
                                Resolution::R480p => "480p",
                                Resolution::R720p => "720p",
                                Resolution::R1080p => "1080p",
                                Resolution::R2160p => "2160p",
                            };
                            RankedFile::new(
                                format!("Movie.{res_token}.BluRay.x265.AAC-G{i}"),
                                *size,
                            )
                        })
                        .collect();

                    let prefs = QualityPrefs {
                        max_resolution: Some(max_resolution),
                        ..Default::default()
                    };

                    let ranked = QualityRanker::rank(files.clone(), &prefs, Some(bandwidth_bps));

                    let threshold = (bandwidth_bps as f64 * 0.8) as u64;

                    for original in &files {
                        let res = parse_release_name(&original.name).resolution;
                        let estimated_bps = if original.size > 0 {
                            (original.size as f64 * 8.0 / 7200.0) as u64
                        } else {
                            0
                        };

                        let should_be_excluded = res.is_some_and(|r| r > max_resolution)
                            || (original.size > 0 && estimated_bps > threshold);

                        let in_ranked = ranked.iter().any(|f| f.name == original.name);

                        if should_be_excluded {
                            prop_assert!(
                                !in_ranked,
                                "excluded file {:?} (res={:?}, bps={}) found in ranked output",
                                original.name,
                                res,
                                estimated_bps
                            );
                        }
                    }

                    Ok(())
                },
            )
            .unwrap();
    }

    /// **Property 37c: Source token parsing is total — never panics**
    ///
    /// **Validates: Requirements 38.4**
    #[test]
    fn property_37c_source_token_parsing_is_total() {
        let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
            cases: 200,
            ..Default::default()
        });

        runner
            .run(&(arb_source(), arb_hdr_flag()), |(source, hdr)| {
                let source_token = match source {
                    Source::BluRay => "BluRay",
                    Source::WebDL => "WEB-DL",
                    Source::WebRip => "WEBRip",
                    Source::HDTV => "HDTV",
                    Source::DVDRip => "DVDRip",
                    Source::CAM => "CAM",
                    Source::BluRayRemux => "Remux",
                };
                let hdr_token = match hdr {
                    HdrFlag::HDR => "HDR",
                    HdrFlag::HDR10 => "HDR10",
                    HdrFlag::HDR10Plus => "HDR10+",
                    HdrFlag::DolbyVision => "DV",
                    HdrFlag::HLG => "HLG",
                };
                let name = format!("Movie.2023.1080p.{source_token}.x265.{hdr_token}.AAC-GROUP");
                let info = parse_release_name(&name);

                prop_assert_eq!(
                    info.source,
                    Some(source),
                    "source not recovered from {}",
                    name
                );
                prop_assert!(
                    info.hdr_flags.contains(&hdr),
                    "hdr flag {:?} not recovered from {}",
                    hdr,
                    name
                );

                Ok(())
            })
            .unwrap();
    }
}
