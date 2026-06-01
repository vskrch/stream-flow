//! Remux-vs-transcode decision table (`transcode::decision`) — Req 6.2, 6.3,
//! 6.4, 6.10, 6.13.
//!
//! [`decide_mode`] is the **pure** core of Requirement 6: given the probed
//! source [`CodecInfo`], it picks the cheapest processing mode that yields
//! client-compatible output (design: Components → Transcode; Property 15):
//!
//! | source video         | source audio | mode                       | video     | audio        |
//! |----------------------|--------------|----------------------------|-----------|--------------|
//! | H.264                | AAC / none   | [`Remux`]                  | `copy`    | `copy`       |
//! | H.264                | non-AAC      | [`TranscodeAudio`]         | `copy`    | → AAC        |
//! | HEVC / VP9 / AV1 / … | AAC / none   | [`TranscodeVideo`]`{Copy}` | → H.264   | `copy`       |
//! | HEVC / VP9 / AV1 / … | non-AAC      | [`TranscodeVideo`]`{Tr.}`  | → H.264   | → AAC        |
//! | *undeterminable*     | *any*        | [`FullTranscode`]          | → H.264   | → AAC        |
//!
//! [`Remux`]: TranscodeMode::Remux
//! [`TranscodeAudio`]: TranscodeMode::TranscodeAudio
//! [`TranscodeVideo`]: TranscodeMode::TranscodeVideo
//! [`FullTranscode`]: TranscodeMode::FullTranscode
//!
//! The decision is intentionally independent of whether transcoding is
//! *enabled*: [`decide_mode`] always names the ideal mode, and the
//! configuration gate (Req 6.10 — transcode disabled + incompatible media →
//! `404`) is the separate [`TranscodeMode::requires_video_reencode`] check the
//! session builder applies (so the pure table stays trivially testable —
//! Property 15 validates 6.2/6.3/6.4/6.13 only).

use super::codec::{AudioCodec, CodecInfo, VideoCodec};

/// What to do with the source audio stream (Req 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioAction {
    /// Source audio is already AAC (or absent): pass through (`-c:a copy`).
    Copy,
    /// Source audio is not AAC: re-encode to AAC (`-c:a aac`).
    Transcode,
}

impl AudioAction {
    /// The action for a source audio codec: copy AAC, transcode everything
    /// else; a source with no audio stream copies (a harmless no-op) (Req 6.4).
    fn for_audio(audio: Option<&AudioCodec>) -> AudioAction {
        match audio {
            Some(a) if a.is_client_compatible() => AudioAction::Copy,
            Some(_) => AudioAction::Transcode,
            None => AudioAction::Copy,
        }
    }

    /// `true` when the audio stream is re-encoded (Req 6.4, 6.9).
    pub fn is_transcode(self) -> bool {
        matches!(self, AudioAction::Transcode)
    }
}

/// The processing mode chosen by [`decide_mode`] (design: Components →
/// Transcode; Property 15).
///
/// Each variant fully determines both the video and the audio action; use
/// [`video_reencoded`](TranscodeMode::video_reencoded) /
/// [`audio_action`](TranscodeMode::audio_action) to drive FFmpeg-argument
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscodeMode {
    /// Container-only change: copy video (`-c:v copy`) and audio (`-c:a copy`).
    /// Source video is H.264 and audio is AAC / absent (Req 6.2).
    Remux,
    /// Copy video (`-c:v copy`), re-encode audio to AAC. Source video is H.264
    /// but the audio codec is incompatible (Req 6.2, 6.4).
    TranscodeAudio,
    /// Re-encode video to H.264; the audio is copied or transcoded per the
    /// carried [`AudioAction`]. Source video is HEVC/VP9/AV1/other (Req 6.3,
    /// 6.4).
    TranscodeVideo {
        /// What to do with the audio while the video is re-encoded.
        audio: AudioAction,
    },
    /// Re-encode both video (→ H.264) and audio (→ AAC). The source codecs
    /// could not be determined, so fall back to a full transcode (Req 6.13).
    FullTranscode,
}

impl TranscodeMode {
    /// `true` when the video stream is re-encoded (`TranscodeVideo` /
    /// `FullTranscode`) rather than copied (`Remux` / `TranscodeAudio`).
    ///
    /// This is the Req 6.10 gate: a mode that re-encodes video is impossible
    /// when transcoding is disabled, so the transcode-only endpoint answers
    /// `404` for it (see [`requires_video_reencode`](Self::requires_video_reencode)).
    pub fn video_reencoded(self) -> bool {
        matches!(
            self,
            TranscodeMode::TranscodeVideo { .. } | TranscodeMode::FullTranscode
        )
    }

    /// Alias of [`video_reencoded`](Self::video_reencoded) reading naturally at
    /// the Req 6.10 configuration gate.
    pub fn requires_video_reencode(self) -> bool {
        self.video_reencoded()
    }

    /// What happens to the audio stream under this mode (Req 6.4).
    pub fn audio_action(self) -> AudioAction {
        match self {
            TranscodeMode::Remux => AudioAction::Copy,
            TranscodeMode::TranscodeAudio => AudioAction::Transcode,
            TranscodeMode::TranscodeVideo { audio } => audio,
            TranscodeMode::FullTranscode => AudioAction::Transcode,
        }
    }
}

/// Decide the processing mode purely from the probed source codecs (Req 6.2,
/// 6.3, 6.4, 6.13) — the pure heart of Property 15.
///
/// * Undeterminable source video → [`FullTranscode`](TranscodeMode::FullTranscode)
///   (Req 6.13).
/// * H.264 video → video copied; [`Remux`](TranscodeMode::Remux) when audio is
///   AAC/absent, [`TranscodeAudio`](TranscodeMode::TranscodeAudio) otherwise
///   (Req 6.2, 6.4).
/// * HEVC/VP9/AV1/other video → video re-encoded to H.264 via
///   [`TranscodeVideo`](TranscodeMode::TranscodeVideo) carrying the audio
///   action (copy when AAC, transcode otherwise — Req 6.3, 6.4).
pub fn decide_mode(info: &CodecInfo) -> TranscodeMode {
    match &info.video {
        // Req 6.13: codecs undeterminable → full transcode.
        None => TranscodeMode::FullTranscode,
        // Req 6.2: client-compatible video (H.264) → copy video, audio per 6.4.
        Some(VideoCodec::H264) => match AudioAction::for_audio(info.audio.as_ref()) {
            AudioAction::Copy => TranscodeMode::Remux,
            AudioAction::Transcode => TranscodeMode::TranscodeAudio,
        },
        // Req 6.3: incompatible video → transcode video to H.264, audio per 6.4.
        Some(_) => TranscodeMode::TranscodeVideo {
            audio: AudioAction::for_audio(info.audio.as_ref()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(v: Option<VideoCodec>, a: Option<AudioCodec>) -> CodecInfo {
        CodecInfo { video: v, audio: a }
    }

    // -- Req 6.2: H.264 + container-only → remux (audio copy/transcode) ------

    #[test]
    fn h264_aac_is_remux_both_copy() {
        let mode = decide_mode(&info(Some(VideoCodec::H264), Some(AudioCodec::Aac)));
        assert_eq!(mode, TranscodeMode::Remux);
        assert!(!mode.video_reencoded(), "H.264 video must be copied");
        assert_eq!(mode.audio_action(), AudioAction::Copy);
    }

    #[test]
    fn h264_no_audio_is_remux() {
        let mode = decide_mode(&info(Some(VideoCodec::H264), None));
        assert_eq!(mode, TranscodeMode::Remux);
        assert!(!mode.video_reencoded());
    }

    #[test]
    fn h264_nonaac_audio_is_transcode_audio_only() {
        let mode = decide_mode(&info(
            Some(VideoCodec::H264),
            Some(AudioCodec::Other("ac3".into())),
        ));
        assert_eq!(mode, TranscodeMode::TranscodeAudio);
        assert!(
            !mode.video_reencoded(),
            "video must still be copied (Req 6.2)"
        );
        assert_eq!(mode.audio_action(), AudioAction::Transcode);
    }

    // -- Req 6.3 / 6.4: incompatible video → transcode video, audio per rule -

    #[test]
    fn hevc_aac_transcodes_video_copies_audio() {
        let mode = decide_mode(&info(Some(VideoCodec::Hevc), Some(AudioCodec::Aac)));
        assert_eq!(
            mode,
            TranscodeMode::TranscodeVideo {
                audio: AudioAction::Copy
            }
        );
        assert!(mode.video_reencoded());
        assert_eq!(mode.audio_action(), AudioAction::Copy);
    }

    #[test]
    fn vp9_nonaac_transcodes_both() {
        let mode = decide_mode(&info(
            Some(VideoCodec::Vp9),
            Some(AudioCodec::Other("opus".into())),
        ));
        assert_eq!(
            mode,
            TranscodeMode::TranscodeVideo {
                audio: AudioAction::Transcode
            }
        );
        assert!(mode.video_reencoded());
        assert_eq!(mode.audio_action(), AudioAction::Transcode);
    }

    #[test]
    fn av1_and_other_video_transcode_video() {
        for v in [VideoCodec::Av1, VideoCodec::Other("mpeg2video".into())] {
            let mode = decide_mode(&info(Some(v.clone()), Some(AudioCodec::Aac)));
            assert!(
                matches!(mode, TranscodeMode::TranscodeVideo { .. }),
                "{v:?} must transcode video"
            );
        }
    }

    // -- Req 6.13: undeterminable codecs → full transcode -------------------

    #[test]
    fn undetermined_codecs_full_transcode() {
        let mode = decide_mode(&CodecInfo::undetermined());
        assert_eq!(mode, TranscodeMode::FullTranscode);
        assert!(mode.video_reencoded());
        assert_eq!(mode.audio_action(), AudioAction::Transcode);
    }

    #[test]
    fn undetermined_video_with_known_audio_still_full_transcode() {
        // No recognisable video stream → full transcode regardless of audio.
        let mode = decide_mode(&info(None, Some(AudioCodec::Aac)));
        assert_eq!(mode, TranscodeMode::FullTranscode);
    }

    // -- Req 6.10 gate: only video-reencoding modes are blocked when disabled -

    #[test]
    fn requires_video_reencode_matches_video_reencoded() {
        assert!(!TranscodeMode::Remux.requires_video_reencode());
        assert!(!TranscodeMode::TranscodeAudio.requires_video_reencode());
        assert!(TranscodeMode::TranscodeVideo {
            audio: AudioAction::Copy
        }
        .requires_video_reencode());
        assert!(TranscodeMode::FullTranscode.requires_video_reencode());
    }
}
