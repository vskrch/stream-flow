//! Source codec model + `ffprobe` codec probe (`transcode::codec`) — Req 6.1,
//! 6.13.
//!
//! The remux-vs-transcode decision (Req 6.2–6.4, [`decide_mode`]) is driven by
//! the *source* video and audio codecs. This module models those codecs
//! ([`VideoCodec`] / [`AudioCodec`] / [`CodecInfo`]), the **pure**
//! `ffprobe`-JSON → [`CodecInfo`] parser ([`parse_ffprobe_output`]), and the
//! process-backed [`probe_codecs`] that runs `ffprobe` against an upstream URL
//! (Req 6.1).
//!
//! [`decide_mode`](super::decide_mode): VideoCodec::H264 is the only
//! client-compatible video codec; AudioCodec::Aac the only compatible audio
//! codec. A probe that cannot determine the source codecs surfaces as
//! [`CodecInfo::undetermined`], which `decide_mode` maps to a full transcode
//! (Req 6.13).

use std::path::Path;
use std::process::Stdio;

use serde::Deserialize;

use crate::errors::AppError;

/// A source video codec, classified for the compatibility decision (Req 6.2,
/// 6.3).
///
/// Only [`H264`](VideoCodec::H264) is client-compatible; every other codec
/// (including [`Other`](VideoCodec::Other) unknown names) requires a transcode
/// to H.264.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoCodec {
    /// H.264 / AVC — the one client-compatible video codec (copied on remux,
    /// Req 6.2).
    H264,
    /// H.265 / HEVC — incompatible, transcoded to H.264 (Req 6.3).
    Hevc,
    /// VP9 — incompatible, transcoded to H.264 (Req 6.3).
    Vp9,
    /// AV1 — incompatible, transcoded to H.264 (Req 6.3).
    Av1,
    /// Any other recognised-but-incompatible codec name (transcoded to H.264).
    Other(String),
}

impl VideoCodec {
    /// Classify an `ffprobe` `codec_name` string (case-insensitive).
    pub fn from_codec_name(name: &str) -> VideoCodec {
        match name.trim().to_ascii_lowercase().as_str() {
            "h264" | "avc" | "avc1" => VideoCodec::H264,
            "hevc" | "h265" | "hvc1" => VideoCodec::Hevc,
            "vp9" => VideoCodec::Vp9,
            "av1" => VideoCodec::Av1,
            other => VideoCodec::Other(other.to_string()),
        }
    }

    /// `true` when the client can play this video codec directly (only H.264).
    pub fn is_client_compatible(&self) -> bool {
        matches!(self, VideoCodec::H264)
    }
}

/// A source audio codec, classified for the compatibility decision (Req 6.4).
///
/// Only [`Aac`](AudioCodec::Aac) is client-compatible; every other codec is
/// transcoded to AAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioCodec {
    /// AAC — the one client-compatible audio codec (copied, Req 6.4).
    Aac,
    /// Any other audio codec name (transcoded to AAC, Req 6.4).
    Other(String),
}

impl AudioCodec {
    /// Classify an `ffprobe` `codec_name` string (case-insensitive).
    pub fn from_codec_name(name: &str) -> AudioCodec {
        match name.trim().to_ascii_lowercase().as_str() {
            "aac" => AudioCodec::Aac,
            other => AudioCodec::Other(other.to_string()),
        }
    }

    /// `true` when the client can play this audio codec directly (only AAC).
    pub fn is_client_compatible(&self) -> bool {
        matches!(self, AudioCodec::Aac)
    }
}

/// The probed source codecs driving [`decide_mode`](super::decide_mode).
///
/// `video == None` means the source video codec could not be determined — a
/// probe failure or a source with no recognisable video stream — which the
/// decision maps to a full transcode (Req 6.13). `audio == None` means the
/// source carries no audio stream (nothing to copy or transcode).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodecInfo {
    /// The source video codec, or `None` when undeterminable (Req 6.13).
    pub video: Option<VideoCodec>,
    /// The source audio codec, or `None` when the source has no audio stream.
    pub audio: Option<AudioCodec>,
}

impl CodecInfo {
    /// A [`CodecInfo`] with known video + audio codecs.
    pub fn new(video: VideoCodec, audio: AudioCodec) -> Self {
        Self {
            video: Some(video),
            audio: Some(audio),
        }
    }

    /// The "codecs could not be determined" sentinel (Req 6.13). Both streams
    /// unknown — [`decide_mode`](super::decide_mode) returns a full transcode.
    pub fn undetermined() -> Self {
        Self {
            video: None,
            audio: None,
        }
    }

    /// `true` when the source video codec could not be determined (Req 6.13).
    pub fn is_undetermined(&self) -> bool {
        self.video.is_none()
    }
}

// ---------------------------------------------------------------------------
// ffprobe JSON model + pure parser
// ---------------------------------------------------------------------------

/// The subset of `ffprobe -show_streams -print_format json` we consume.
#[derive(Debug, Deserialize)]
struct FfprobeOutput {
    #[serde(default)]
    streams: Vec<FfprobeStream>,
}

#[derive(Debug, Deserialize)]
struct FfprobeStream {
    #[serde(default)]
    codec_type: String,
    #[serde(default)]
    codec_name: String,
}

/// Parse `ffprobe -print_format json -show_streams` output into a [`CodecInfo`]
/// (Req 6.1) — **pure**, so the decision pipeline is testable without running
/// `ffprobe`.
///
/// Takes the first video stream and the first audio stream. Returns
/// [`AppError`] when the JSON is unparseable or carries no recognisable video
/// stream; callers treat that as [`CodecInfo::undetermined`] and fall back to a
/// full transcode (Req 6.13).
pub fn parse_ffprobe_output(json: &str) -> Result<CodecInfo, AppError> {
    let probed: FfprobeOutput = serde_json::from_str(json)
        .map_err(|e| AppError::bad_request(format!("unparseable ffprobe output: {e}")))?;

    let video = probed
        .streams
        .iter()
        .find(|s| s.codec_type.eq_ignore_ascii_case("video") && !s.codec_name.is_empty())
        .map(|s| VideoCodec::from_codec_name(&s.codec_name));

    let audio = probed
        .streams
        .iter()
        .find(|s| s.codec_type.eq_ignore_ascii_case("audio") && !s.codec_name.is_empty())
        .map(|s| AudioCodec::from_codec_name(&s.codec_name));

    if video.is_none() {
        return Err(AppError::bad_request(
            "ffprobe output carried no recognisable video stream",
        ));
    }

    Ok(CodecInfo { video, audio })
}

/// Probe the source media's video + audio codecs via `ffprobe` (Req 6.1).
///
/// Runs `ffprobe -v quiet -print_format json -show_streams <input>` through the
/// supplied binary path and parses the JSON with [`parse_ffprobe_output`]. On
/// **any** failure — `ffprobe` missing, non-zero exit, or unparseable output —
/// it returns [`CodecInfo::undetermined`] rather than erroring, so the caller
/// falls back to a full transcode (Req 6.13) instead of failing the request.
pub async fn probe_codecs(ffprobe: &Path, input: &str) -> CodecInfo {
    let output = tokio::process::Command::new(ffprobe)
        .args(["-v", "quiet", "-print_format", "json", "-show_streams"])
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            match parse_ffprobe_output(&String::from_utf8_lossy(&out.stdout)) {
                Ok(info) => info,
                Err(err) => {
                    tracing::warn!(
                        target: "transcode",
                        reason = %err.message,
                        "ffprobe output could not be parsed; falling back to full transcode",
                    );
                    CodecInfo::undetermined()
                }
            }
        }
        Ok(out) => {
            tracing::warn!(
                target: "transcode",
                exit = ?out.status.code(),
                "ffprobe exited non-zero; falling back to full transcode",
            );
            CodecInfo::undetermined()
        }
        Err(err) => {
            tracing::warn!(
                target: "transcode",
                error = %err,
                "ffprobe could not be launched; falling back to full transcode",
            );
            CodecInfo::undetermined()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- codec classification (Req 6.2, 6.3, 6.4) ---------------------------

    #[test]
    fn video_codec_classifies_h264_aliases_as_compatible() {
        for name in ["h264", "H264", "avc", "avc1", "  h264 "] {
            assert_eq!(VideoCodec::from_codec_name(name), VideoCodec::H264);
            assert!(VideoCodec::from_codec_name(name).is_client_compatible());
        }
    }

    #[test]
    fn video_codec_classifies_incompatible_codecs() {
        assert_eq!(VideoCodec::from_codec_name("hevc"), VideoCodec::Hevc);
        assert_eq!(VideoCodec::from_codec_name("h265"), VideoCodec::Hevc);
        assert_eq!(VideoCodec::from_codec_name("vp9"), VideoCodec::Vp9);
        assert_eq!(VideoCodec::from_codec_name("av1"), VideoCodec::Av1);
        assert_eq!(
            VideoCodec::from_codec_name("mpeg2video"),
            VideoCodec::Other("mpeg2video".to_string())
        );
        for c in [
            VideoCodec::Hevc,
            VideoCodec::Vp9,
            VideoCodec::Av1,
            VideoCodec::Other("mpeg2video".to_string()),
        ] {
            assert!(!c.is_client_compatible(), "{c:?} must be incompatible");
        }
    }

    #[test]
    fn audio_codec_classifies_aac_as_compatible_others_not() {
        assert_eq!(AudioCodec::from_codec_name("aac"), AudioCodec::Aac);
        assert_eq!(AudioCodec::from_codec_name("AAC"), AudioCodec::Aac);
        assert!(AudioCodec::from_codec_name("aac").is_client_compatible());

        assert_eq!(
            AudioCodec::from_codec_name("ac3"),
            AudioCodec::Other("ac3".to_string())
        );
        assert!(!AudioCodec::from_codec_name("dts").is_client_compatible());
    }

    // -- ffprobe JSON parsing (Req 6.1) -------------------------------------

    #[test]
    fn parse_ffprobe_output_extracts_first_video_and_audio() {
        let json = r#"{
            "streams": [
                {"codec_type": "video", "codec_name": "h264"},
                {"codec_type": "audio", "codec_name": "aac"}
            ]
        }"#;
        let info = parse_ffprobe_output(json).expect("parses");
        assert_eq!(info.video, Some(VideoCodec::H264));
        assert_eq!(info.audio, Some(AudioCodec::Aac));
    }

    #[test]
    fn parse_ffprobe_output_picks_first_of_each_type() {
        let json = r#"{
            "streams": [
                {"codec_type": "video", "codec_name": "hevc"},
                {"codec_type": "video", "codec_name": "h264"},
                {"codec_type": "audio", "codec_name": "ac3"},
                {"codec_type": "audio", "codec_name": "aac"}
            ]
        }"#;
        let info = parse_ffprobe_output(json).expect("parses");
        assert_eq!(info.video, Some(VideoCodec::Hevc));
        assert_eq!(info.audio, Some(AudioCodec::Other("ac3".to_string())));
    }

    #[test]
    fn parse_ffprobe_output_allows_video_only_source() {
        let json = r#"{"streams": [{"codec_type": "video", "codec_name": "av1"}]}"#;
        let info = parse_ffprobe_output(json).expect("parses");
        assert_eq!(info.video, Some(VideoCodec::Av1));
        assert_eq!(info.audio, None);
    }

    #[test]
    fn parse_ffprobe_output_errors_on_unparseable_json() {
        let err = parse_ffprobe_output("not json").expect_err("must error");
        assert!(err.message.contains("unparseable"));
    }

    #[test]
    fn parse_ffprobe_output_errors_when_no_video_stream() {
        let json = r#"{"streams": [{"codec_type": "audio", "codec_name": "aac"}]}"#;
        let err = parse_ffprobe_output(json).expect_err("no video → error");
        assert!(err.message.contains("video"));
    }

    #[test]
    fn codec_info_undetermined_reports_undetermined() {
        let info = CodecInfo::undetermined();
        assert!(info.is_undetermined());
        assert_eq!(info.video, None);
    }
}
