//! Property-based test for the remux-vs-transcode decision table
//! (`transcode::decide_mode`, task 18.5).
//!
//! Feature: ZippyPanther, Property 15
//!
//! **Property 15: Transcode-vs-remux decision table**
//!
//! *For any* probed `CodecInfo`, `decide_mode` returns: `Remux` when video is
//! H.264 and only the container is incompatible (audio copied when AAC, else
//! transcoded); `TranscodeVideo` to H.264 when video is HEVC/VP9/AV1; audio
//! transcoded to AAC when non-AAC and copied when AAC; and `FullTranscode` when
//! the source codecs cannot be determined.
//!
//! **Validates: Requirements 6.2, 6.3, 6.4, 6.13**
//!
//! Requirement clauses exercised:
//!
//! * **6.2** — H.264 source video + an incompatible container is a
//!   container-only **remux**: video is copied (`-c:v copy`), audio copied when
//!   already AAC and re-encoded otherwise.
//! * **6.3** — HEVC/VP9/AV1 (any non-H.264) source video is **transcoded** to
//!   H.264.
//! * **6.4** — non-AAC source audio is transcoded to AAC; AAC (or absent) audio
//!   is copied.
//! * **6.13** — when the source codecs cannot be determined the system falls
//!   back to a **full transcode**.
//!
//! ## How the invariant is exercised
//!
//! Each case generates an arbitrary `CodecInfo` from the full input space —
//! `video ∈ {undetermined, H264, HEVC, VP9, AV1, Other(name)}` and
//! `audio ∈ {absent, AAC, Other(name)}` — driving the real
//! [`zippy_panther::transcode::decide_mode`] and comparing its result against an
//! **independent oracle** that encodes the decision table directly from the
//! requirement clauses. Beyond the oracle equality, each case asserts the
//! structural guarantees the requirements mandate:
//!
//! * video is copied (mode does **not** re-encode video) **iff** the source
//!   video is the one client-compatible codec, H.264 (Req 6.2 vs 6.3/6.13);
//! * for a *determined* source, the audio is copied **iff** it is AAC or absent
//!   and transcoded otherwise (Req 6.4);
//! * an undetermined source is always a `FullTranscode` regardless of audio
//!   (Req 6.13).
//!
//! Codec values are constructed as the typed enums directly (rather than via
//! `from_codec_name`) so the generator covers the classification space the
//! decision consumes; `Other(_)` payloads are arbitrary because the decision
//! keys off the enum variant, never the contained string.

use proptest::prelude::*;
use zippy_panther::transcode::{
    decide_mode, AudioAction, AudioCodec, CodecInfo, TranscodeMode, VideoCodec,
};

// ---------------------------------------------------------------------------
// Generators — cover the whole (video, audio) classification space
// ---------------------------------------------------------------------------

/// Source video codec, or `None` (undeterminable — Req 6.13). The known
/// incompatible codecs (HEVC/VP9/AV1) and an arbitrary `Other(_)` name all
/// arise so both the H.264 (Req 6.2) and the transcode-video (Req 6.3) arms are
/// well covered.
fn arb_video() -> impl Strategy<Value = Option<VideoCodec>> {
    prop_oneof![
        // Undeterminable source video (Req 6.13).
        2 => Just(None),
        // The one client-compatible video codec (Req 6.2).
        4 => Just(Some(VideoCodec::H264)),
        // Known incompatible codecs (Req 6.3).
        2 => Just(Some(VideoCodec::Hevc)),
        2 => Just(Some(VideoCodec::Vp9)),
        2 => Just(Some(VideoCodec::Av1)),
        // Any other recognised-but-incompatible codec name (Req 6.3).
        2 => "[a-z][a-z0-9]{0,9}".prop_map(|s| Some(VideoCodec::Other(s))),
    ]
}

/// Source audio codec, or `None` (no audio stream — copied as a harmless
/// no-op). AAC is copied (Req 6.4), everything else is transcoded to AAC.
fn arb_audio() -> impl Strategy<Value = Option<AudioCodec>> {
    prop_oneof![
        // No audio stream — nothing to copy or transcode.
        2 => Just(None),
        // The one client-compatible audio codec (Req 6.4).
        3 => Just(Some(AudioCodec::Aac)),
        // Any other audio codec name → transcoded to AAC (Req 6.4).
        3 => "[a-z][a-z0-9]{0,9}".prop_map(|s| Some(AudioCodec::Other(s))),
    ]
}

/// An arbitrary probed [`CodecInfo`] over the full input space.
fn arb_codec_info() -> impl Strategy<Value = CodecInfo> {
    (arb_video(), arb_audio()).prop_map(|(video, audio)| CodecInfo { video, audio })
}

// ---------------------------------------------------------------------------
// Independent oracle — the decision table read straight from Req 6.2/6.3/6.4/6.13
// ---------------------------------------------------------------------------

/// The expected audio action: copy AAC / absent audio, transcode everything
/// else (Req 6.4).
fn expected_audio_action(audio: &Option<AudioCodec>) -> AudioAction {
    match audio {
        Some(AudioCodec::Aac) | None => AudioAction::Copy,
        Some(AudioCodec::Other(_)) => AudioAction::Transcode,
    }
}

/// The decision table, independently of the implementation under test.
fn expected_mode(info: &CodecInfo) -> TranscodeMode {
    match &info.video {
        // Req 6.13: undeterminable source codecs → full transcode.
        None => TranscodeMode::FullTranscode,
        // Req 6.2: H.264 video → copy video; audio per Req 6.4.
        Some(VideoCodec::H264) => match expected_audio_action(&info.audio) {
            AudioAction::Copy => TranscodeMode::Remux,
            AudioAction::Transcode => TranscodeMode::TranscodeAudio,
        },
        // Req 6.3: any non-H.264 video → transcode video to H.264; audio per 6.4.
        Some(_) => TranscodeMode::TranscodeVideo {
            audio: expected_audio_action(&info.audio),
        },
    }
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 15 — transcode-vs-remux decision table.
    /// **Validates: Requirements 6.2, 6.3, 6.4, 6.13**
    #[test]
    fn decide_mode_matches_the_decision_table(info in arb_codec_info()) {
        let mode = decide_mode(&info);

        // -- Equality with the independent oracle ---------------------------
        prop_assert_eq!(
            mode,
            expected_mode(&info),
            "decide_mode disagreed with the decision table for {:?}",
            info,
        );

        let video_compatible = matches!(info.video, Some(VideoCodec::H264));
        let undetermined = info.video.is_none();
        let audio_compatible =
            matches!(info.audio, Some(AudioCodec::Aac) | None);

        // -- Req 6.13: undeterminable source → full transcode (both streams) -
        if undetermined {
            prop_assert_eq!(
                mode,
                TranscodeMode::FullTranscode,
                "undeterminable codecs must fall back to full transcode (Req 6.13)",
            );
            prop_assert!(mode.video_reencoded(), "full transcode re-encodes video");
            prop_assert_eq!(
                mode.audio_action(),
                AudioAction::Transcode,
                "full transcode re-encodes audio",
            );
        }

        // -- Video is copied IFF the source is H.264 (Req 6.2 vs 6.3/6.13) --
        prop_assert_eq!(
            mode.video_reencoded(),
            !video_compatible,
            "video must be copied exactly when the source is H.264 (Req 6.2/6.3); info {:?}",
            info,
        );

        // -- Req 6.2: H.264 source → container-only remux, audio per Req 6.4 -
        if video_compatible {
            prop_assert!(
                !mode.video_reencoded(),
                "H.264 video must be copied, never re-encoded (Req 6.2)",
            );
            if audio_compatible {
                prop_assert_eq!(
                    mode,
                    TranscodeMode::Remux,
                    "H.264 + AAC/none is a pure remux (Req 6.2)",
                );
            } else {
                prop_assert_eq!(
                    mode,
                    TranscodeMode::TranscodeAudio,
                    "H.264 + non-AAC audio copies video, transcodes audio (Req 6.2/6.4)",
                );
            }
        }

        // -- Req 6.3: non-H.264, determined source → transcode video to H.264 -
        if !video_compatible && !undetermined {
            prop_assert_eq!(
                mode,
                TranscodeMode::TranscodeVideo { audio: expected_audio_action(&info.audio) },
                "non-H.264 video must be transcoded to H.264 (Req 6.3); info {:?}",
                info,
            );
            prop_assert!(mode.video_reencoded(), "incompatible video is re-encoded (Req 6.3)");
        }

        // -- Req 6.4: for a determined source, audio copied IFF AAC/absent ---
        if !undetermined {
            prop_assert_eq!(
                mode.audio_action(),
                expected_audio_action(&info.audio),
                "audio: copy AAC/none, transcode otherwise (Req 6.4); info {:?}",
                info,
            );
            prop_assert_eq!(
                mode.audio_action() == AudioAction::Copy,
                audio_compatible,
                "audio is copied exactly when it is AAC or absent (Req 6.4)",
            );
        }
    }
}
