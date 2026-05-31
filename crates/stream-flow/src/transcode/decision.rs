//! Remux-vs-transcode decision table (`transcode::decision`) — Req 6.2, 6.3,
//! 6.4, 6.13.
//!
//! Given a probed [`CodecInfo`], [`decide_mode`] picks the cheapest processing
//! mode that still yields client-compatible output (design: Components →
//! Transcode; Property 15):
//!
//! | source video | source audio | mode             | `-c:v` | `-c:a`        |
//! |--------------|--------------|------------------|--------|---------------|
//! | H.264        | AAC / none   | [`Remux`]        | `copy` | `copy`/none   |
//! | H.264        | non-AAC      | [`Remux`]        | `copy` | `aac`         |
//! | HEVC/VP9/AV1 | AAC / none   | [`TranscodeVideo`]| H.264 | `copy`/none   |
//! | HEVC/VP9/AV1 | non-AAC      | [`TranscodeVideo`]| H.264 | `aac`         |
//! | undetermined | any          | [`FullTranscode`]| H.264  | `aac`/`copy`  |
//!
//! [`Remux`]: ProcessingMode::Remux
//! [`TranscodeVideo`]: ProcessingMode::TranscodeVideo
//! [`FullTranscode`]: ProcessingMode::FullTranscode
//!
//! The mode is **video-driven**: H.264 only ever needs the container changed
//! (`-c:v copy`, Req 6.2); HEVC/VP9/AV1 must be re-encoded to H.264 (Req 6.3);
//! and an undeterminable source falls back to full transcoding rather than
//! failing (Req 6.13). Audio is an independent sub-decision — copied when
//! already AAC (or absent), transcoded to AAC otherwise (Req 6.4) — carried in
//! the [`TranscodeDecision::audio`] field so the FFmpeg command builder emits
//! the right `-c:a` flag regardless of the coarse mode.

use crate::transcode::codec::{AudioCodec, CodecInfo, VideoCodec};

/// The coarse processing mode chosen for a transcode-or-remux request
/// (design: Components → Transcode `{Remux, TranscodeVideo, TranscodeAudio,
/// FullTranscode}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingMode {
    /// Source video is client-compatible (H.264) and only the container is
    /// wrong: copy the video stream, re-encoding only audio if needed
    /// (Req 6.2).
    Remux,
    /// Source video is incompatible (HEVC/VP9/AV1, …): re-encode the video to
    /// H.264 (Req 6.3).
    TranscodeVideo,
    /// Source video is client-compatible (H.264, copied) but the audio must be
    /// re-encoded to AAC (Req 6.4). The video-driven [`decide_mode`] folds this
    /// case into [`Remux`](ProcessingMode::Remux) (per Property 15); this
    /// variant is the fine-grained classification produced by
    /// [`ProcessingMode::for_actions`] for metrics/logging.
    TranscodeAudio,
    /// Source codecs could not be determined: fall back to transcoding the
    /// video to H.264 (and audio to AAC) rather than failing (Req 6.13).
    FullTranscode,
}

/// What FFmpeg should do with the video stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoAction {
    /// `-c:v copy` — stream-copy the already-compatible H.264 video (Req 6.2).
    Copy,
    /// Re-encode the video to H.264 (Req 6.3, 6.13).
    TranscodeToH264,
}

/// What FFmpeg should do with the audio stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioAction {
    /// `-c:a copy` — stream-copy the already-compatible AAC audio (Req 6.4).
    Copy,
    /// Re-encode the audio to AAC (Req 6.4).
    TranscodeToAac,
    /// The source has no audio stream — emit no audio mapping/flags.
    None,
}

/// The full decision for a transcode-or-remux request: the coarse
/// [`ProcessingMode`] plus the per-stream video/audio actions that drive the
/// FFmpeg `-c:v` / `-c:a` flags (design: Components → Transcode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscodeDecision {
    /// The coarse, video-driven mode (Req 6.2, 6.3, 6.13; Property 15).
    pub mode: ProcessingMode,
    /// What to do with the video stream.
    pub video: VideoAction,
    /// What to do with the audio stream.
    pub audio: AudioAction,
}

impl TranscodeDecision {
    /// `true` when neither stream is re-encoded — a pure container remux
    /// (`-c:v copy -c:a copy`, Req 6.2). The cheapest path.
    pub fn is_pure_remux(&self) -> bool {
        matches!(self.video, VideoAction::Copy)
            && matches!(self.audio, AudioAction::Copy | AudioAction::None)
    }

    /// The fine-grained classification of this decision's per-stream actions,
    /// distinguishing the audio-only re-encode case (Req 6.4) from a pure
    /// remux for metrics/logging.
    pub fn effective_mode(&self) -> ProcessingMode {
        ProcessingMode::for_actions(self.video, self.audio)
    }
}

impl ProcessingMode {
    /// Classify a `(video, audio)` action pair into the fine-grained mode,
    /// using all four design variants (the audio-only re-encode becomes
    /// [`TranscodeAudio`](ProcessingMode::TranscodeAudio)).
    pub fn for_actions(video: VideoAction, audio: AudioAction) -> Self {
        let audio_transcode = matches!(audio, AudioAction::TranscodeToAac);
        match (video, audio_transcode) {
            (VideoAction::Copy, false) => ProcessingMode::Remux,
            (VideoAction::Copy, true) => ProcessingMode::TranscodeAudio,
            (VideoAction::TranscodeToH264, false) => ProcessingMode::TranscodeVideo,
            (VideoAction::TranscodeToH264, true) => ProcessingMode::FullTranscode,
        }
    }
}

/// Decide the processing mode + per-stream actions for a probed source
/// (Req 6.2, 6.3, 6.4, 6.13; Property 15).
///
/// Video-driven: an undeterminable video codec falls back to full transcoding
/// (Req 6.13); a compatible H.264 video is remuxed (`-c:v copy`, Req 6.2); any
/// other video codec is transcoded to H.264 (Req 6.3). Audio is decided
/// independently via [`decide_audio`].
pub fn decide_mode(info: &CodecInfo) -> TranscodeDecision {
    let audio = decide_audio(&info.audio);

    if info.video.is_undetermined() {
        // Req 6.13: probe could not determine the codec → full transcode.
        return TranscodeDecision {
            mode: ProcessingMode::FullTranscode,
            video: VideoAction::TranscodeToH264,
            audio,
        };
    }

    if info.video.is_client_compatible() {
        // Req 6.2: H.264 video → copy video, re-encode audio only if needed.
        TranscodeDecision {
            mode: ProcessingMode::Remux,
            video: VideoAction::Copy,
            audio,
        }
    } else {
        // Req 6.3: HEVC/VP9/AV1/other → transcode video to H.264.
        TranscodeDecision {
            mode: ProcessingMode::TranscodeVideo,
            video: VideoAction::TranscodeToH264,
            audio,
        }
    }
}

/// Decide the audio action from the source audio codec (Req 6.4): AAC is
/// copied, no-audio maps to no action, everything else (including an
/// undeterminable codec) is transcoded to AAC.
pub fn decide_audio(audio: &AudioCodec) -> AudioAction {
    match audio {
        AudioCodec::Aac => AudioAction::Copy,
        AudioCodec::None => AudioAction::None,
        AudioCodec::Other(_) | AudioCodec::Unknown => AudioAction::TranscodeToAac,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(video: VideoCodec, audio: AudioCodec) -> CodecInfo {
        CodecInfo { video, audio }
    }

    #[test]
    fn h264_aac_remuxes_with_pure_copy() {
        let d = decide_mode(&info(VideoCodec::H264, AudioCodec::Aac));
        assert_eq!(d.mode, ProcessingMode::Remux);
        assert_eq!(d.video, VideoAction::Copy);
        assert_eq!(d.audio, AudioAction::Copy);
        assert!(d.is_pure_remux());
    }

    #[test]
    fn h264_no_audio_remuxes() {
        let d = decide_mode(&info(VideoCodec::H264, AudioCodec::None));
        assert_eq!(d.mode, ProcessingMode::Remux);
        assert_eq!(d.video, VideoAction::Copy);
        assert_eq!(d.audio, AudioAction::None);
        assert!(d.is_pure_remux());
    }

    #[test]
    fn h264_non_aac_remuxes_video_but_transcodes_audio() {
        // Property 15: video H.264 → Remux mode, audio transcoded since non-AAC.
        let d = decide_mode(&info(VideoCodec::H264, AudioCodec::Other("ac3".into())));
        assert_eq!(d.mode, ProcessingMode::Remux);
        assert_eq!(d.video, VideoAction::Copy);
        assert_eq!(d.audio, AudioAction::TranscodeToAac);
        assert!(!d.is_pure_remux());
        // The fine-grained classification distinguishes the audio re-encode.
        assert_eq!(d.effective_mode(), ProcessingMode::TranscodeAudio);
    }

    #[test]
    fn hevc_aac_transcodes_video_copies_audio() {
        let d = decide_mode(&info(VideoCodec::Hevc, AudioCodec::Aac));
        assert_eq!(d.mode, ProcessingMode::TranscodeVideo);
        assert_eq!(d.video, VideoAction::TranscodeToH264);
        assert_eq!(d.audio, AudioAction::Copy);
    }

    #[test]
    fn vp9_and_av1_and_other_all_transcode_video() {
        for v in [
            VideoCodec::Vp9,
            VideoCodec::Av1,
            VideoCodec::Other("mpeg2video".into()),
        ] {
            let d = decide_mode(&info(v.clone(), AudioCodec::Other("opus".into())));
            assert_eq!(d.mode, ProcessingMode::TranscodeVideo, "{v:?}");
            assert_eq!(d.video, VideoAction::TranscodeToH264);
            assert_eq!(d.audio, AudioAction::TranscodeToAac);
        }
    }

    #[test]
    fn undetermined_codecs_fall_back_to_full_transcode() {
        // Req 6.13 / Property 15: codecs cannot be determined → FullTranscode.
        let d = decide_mode(&CodecInfo::undetermined());
        assert_eq!(d.mode, ProcessingMode::FullTranscode);
        assert_eq!(d.video, VideoAction::TranscodeToH264);
        assert_eq!(d.audio, AudioAction::TranscodeToAac);
    }

    #[test]
    fn undetermined_video_with_known_aac_audio_still_full_transcodes_video() {
        let d = decide_mode(&info(VideoCodec::Unknown, AudioCodec::Aac));
        assert_eq!(d.mode, ProcessingMode::FullTranscode);
        assert_eq!(d.video, VideoAction::TranscodeToH264);
        // Known AAC audio is still copied even in the fallback.
        assert_eq!(d.audio, AudioAction::Copy);
    }

    #[test]
    fn for_actions_covers_all_four_modes() {
        assert_eq!(
            ProcessingMode::for_actions(VideoAction::Copy, AudioAction::Copy),
            ProcessingMode::Remux
        );
        assert_eq!(
            ProcessingMode::for_actions(VideoAction::Copy, AudioAction::None),
            ProcessingMode::Remux
        );
        assert_eq!(
            ProcessingMode::for_actions(VideoAction::Copy, AudioAction::TranscodeToAac),
            ProcessingMode::TranscodeAudio
        );
        assert_eq!(
            ProcessingMode::for_actions(VideoAction::TranscodeToH264, AudioAction::Copy),
            ProcessingMode::TranscodeVideo
        );
        assert_eq!(
            ProcessingMode::for_actions(VideoAction::TranscodeToH264, AudioAction::TranscodeToAac),
            ProcessingMode::FullTranscode
        );
    }
}
