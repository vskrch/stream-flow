//! Source codec probing model (`transcode::codec`) — Req 6.1, 6.13.
//!
//! Before deciding how to process a transcode-or-remux request, the engine
//! probes the upstream media's video and audio codecs (Req 6.1). This module
//! owns the codec value types ([`VideoCodec`] / [`AudioCodec`] / [`CodecInfo`])
//! plus the classification rules that drive the remux-vs-transcode decision
//! table (design: Components → Transcode):
//!
//! * The single **client-compatible** video codec is H.264 — anything else
//!   (HEVC/VP9/AV1, or any other known codec) must be re-encoded to H.264
//!   (Req 6.2, 6.3).
//! * The single **client-compatible** audio codec is AAC — anything else must
//!   be re-encoded to AAC; AAC is copied (Req 6.4).
//! * When the probe cannot determine the source codecs (the probe failed,
//!   produced unparseable output, or reported no recognizable streams), the
//!   codec is [`VideoCodec::Unknown`] and the engine falls back to **full
//!   transcoding** rather than failing (Req 6.13).
//!
//! The ffprobe JSON parsing ([`CodecInfo::from_ffprobe_json`]) is a pure
//! function so the classification + fall-back behaviour is unit-testable
//! without ever spawning ffprobe.

/// The source video codec, classified for the remux/transcode decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoCodec {
    /// H.264 / AVC — the client-compatible codec; only ever copied (Req 6.2).
    H264,
    /// H.265 / HEVC — incompatible, must be transcoded to H.264 (Req 6.3).
    Hevc,
    /// VP9 — incompatible, must be transcoded to H.264 (Req 6.3).
    Vp9,
    /// AV1 — incompatible, must be transcoded to H.264 (Req 6.3).
    Av1,
    /// Any other recognized-but-incompatible codec (e.g. `mpeg2video`,
    /// `vp8`) — transcoded to H.264 like the named incompatible codecs.
    Other(String),
    /// The probe could not determine the codec → fall back to full
    /// transcoding (Req 6.13).
    Unknown,
}

impl VideoCodec {
    /// Classify an ffprobe `codec_name` string (case-insensitive). An empty
    /// name maps to [`VideoCodec::Unknown`] (Req 6.13).
    pub fn from_codec_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "h264" | "avc" | "avc1" => Self::H264,
            "hevc" | "h265" | "hvc1" | "hev1" => Self::Hevc,
            "vp9" => Self::Vp9,
            "av1" | "av01" => Self::Av1,
            "" => Self::Unknown,
            other => Self::Other(other.to_string()),
        }
    }

    /// `true` when the video codec is already client-compatible (H.264) and
    /// therefore only needs remuxing, never re-encoding (Req 6.2).
    pub fn is_client_compatible(&self) -> bool {
        matches!(self, Self::H264)
    }

    /// `true` when the probe could not determine the codec, triggering the
    /// full-transcode fall-back (Req 6.13).
    pub fn is_undetermined(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// The source audio codec, classified for the remux/transcode decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioCodec {
    /// AAC — the client-compatible codec; copied with `-c:a copy` (Req 6.4).
    Aac,
    /// No audio stream present — nothing to copy or transcode.
    None,
    /// Any other recognized audio codec — transcoded to AAC (Req 6.4).
    Other(String),
    /// The probe could not determine the audio codec — transcoded to AAC as
    /// the safe default (folds into the full-transcode fall-back, Req 6.13).
    Unknown,
}

impl AudioCodec {
    /// Classify an ffprobe `codec_name` string (case-insensitive). An empty
    /// name maps to [`AudioCodec::Unknown`].
    pub fn from_codec_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "aac" => Self::Aac,
            "" => Self::Unknown,
            other => Self::Other(other.to_string()),
        }
    }

    /// `true` when the audio must be re-encoded to AAC (Req 6.4): a non-AAC
    /// codec or an undeterminable one. AAC and "no audio" are copied.
    pub fn needs_transcode(&self) -> bool {
        matches!(self, Self::Other(_) | Self::Unknown)
    }

    /// `true` when the audio is already client-compatible (AAC) or absent and
    /// can therefore be copied (Req 6.4).
    pub fn is_client_compatible(&self) -> bool {
        matches!(self, Self::Aac | Self::None)
    }
}

/// The probed video + audio codecs of a source (design: Components →
/// Transcode `probe_codecs(source) -> CodecInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecInfo {
    /// The source video codec (Req 6.2, 6.3).
    pub video: VideoCodec,
    /// The source audio codec (Req 6.4).
    pub audio: AudioCodec,
}

impl CodecInfo {
    /// The "codecs could not be determined" sentinel that drives the
    /// full-transcode fall-back (Req 6.13).
    pub fn undetermined() -> Self {
        Self {
            video: VideoCodec::Unknown,
            audio: AudioCodec::Unknown,
        }
    }

    /// Parse an `ffprobe -print_format json -show_streams` document into a
    /// [`CodecInfo`] (Req 6.1).
    ///
    /// Lenient by design: unparseable JSON, a missing `streams` array, or no
    /// recognizable video stream all collapse to an undeterminable video
    /// codec so the caller falls back to full transcoding rather than failing
    /// (Req 6.13).
    pub fn from_ffprobe_json(json: &str) -> Self {
        let value: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => value,
            Err(_) => return Self::undetermined(),
        };

        let streams = match value.get("streams").and_then(|s| s.as_array()) {
            Some(streams) => streams,
            None => return Self::undetermined(),
        };

        let mut video = VideoCodec::Unknown;
        let mut audio = AudioCodec::None;

        for stream in streams {
            let codec_type = stream
                .get("codec_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let codec_name = stream
                .get("codec_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            match codec_type {
                // Keep the first video/audio stream's codec (the primary one).
                "video" if matches!(video, VideoCodec::Unknown) => {
                    video = VideoCodec::from_codec_name(codec_name);
                }
                "audio" if matches!(audio, AudioCodec::None) => {
                    audio = AudioCodec::from_codec_name(codec_name);
                }
                _ => {}
            }
        }

        Self { video, audio }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_codec_classification_is_case_insensitive() {
        assert_eq!(VideoCodec::from_codec_name("h264"), VideoCodec::H264);
        assert_eq!(VideoCodec::from_codec_name("H264"), VideoCodec::H264);
        assert_eq!(VideoCodec::from_codec_name("avc1"), VideoCodec::H264);
        assert_eq!(VideoCodec::from_codec_name("hevc"), VideoCodec::Hevc);
        assert_eq!(VideoCodec::from_codec_name("h265"), VideoCodec::Hevc);
        assert_eq!(VideoCodec::from_codec_name("vp9"), VideoCodec::Vp9);
        assert_eq!(VideoCodec::from_codec_name("av1"), VideoCodec::Av1);
        assert_eq!(
            VideoCodec::from_codec_name("mpeg2video"),
            VideoCodec::Other("mpeg2video".to_string())
        );
        assert_eq!(VideoCodec::from_codec_name(""), VideoCodec::Unknown);
    }

    #[test]
    fn only_h264_is_client_compatible_video() {
        assert!(VideoCodec::H264.is_client_compatible());
        assert!(!VideoCodec::Hevc.is_client_compatible());
        assert!(!VideoCodec::Vp9.is_client_compatible());
        assert!(!VideoCodec::Av1.is_client_compatible());
        assert!(!VideoCodec::Other("vp8".into()).is_client_compatible());
        assert!(!VideoCodec::Unknown.is_client_compatible());
    }

    #[test]
    fn only_unknown_video_is_undetermined() {
        assert!(VideoCodec::Unknown.is_undetermined());
        assert!(!VideoCodec::H264.is_undetermined());
        assert!(!VideoCodec::Hevc.is_undetermined());
        assert!(!VideoCodec::Other("x".into()).is_undetermined());
    }

    #[test]
    fn audio_codec_classification_and_transcode_need() {
        assert_eq!(AudioCodec::from_codec_name("aac"), AudioCodec::Aac);
        assert_eq!(AudioCodec::from_codec_name("AAC"), AudioCodec::Aac);
        assert_eq!(
            AudioCodec::from_codec_name("ac3"),
            AudioCodec::Other("ac3".to_string())
        );
        assert_eq!(AudioCodec::from_codec_name(""), AudioCodec::Unknown);

        // AAC + absent audio are copied; everything else is re-encoded.
        assert!(!AudioCodec::Aac.needs_transcode());
        assert!(!AudioCodec::None.needs_transcode());
        assert!(AudioCodec::Other("ac3".into()).needs_transcode());
        assert!(AudioCodec::Unknown.needs_transcode());

        assert!(AudioCodec::Aac.is_client_compatible());
        assert!(AudioCodec::None.is_client_compatible());
        assert!(!AudioCodec::Other("opus".into()).is_client_compatible());
    }

    #[test]
    fn parses_h264_aac_streams() {
        let json = r#"{
            "streams": [
                { "codec_type": "video", "codec_name": "h264" },
                { "codec_type": "audio", "codec_name": "aac" }
            ]
        }"#;
        let info = CodecInfo::from_ffprobe_json(json);
        assert_eq!(info.video, VideoCodec::H264);
        assert_eq!(info.audio, AudioCodec::Aac);
    }

    #[test]
    fn parses_hevc_ac3_streams() {
        let json = r#"{
            "streams": [
                { "codec_type": "audio", "codec_name": "ac3" },
                { "codec_type": "video", "codec_name": "hevc" }
            ]
        }"#;
        let info = CodecInfo::from_ffprobe_json(json);
        assert_eq!(info.video, VideoCodec::Hevc);
        assert_eq!(info.audio, AudioCodec::Other("ac3".to_string()));
    }

    #[test]
    fn video_only_source_reports_no_audio() {
        let json = r#"{ "streams": [ { "codec_type": "video", "codec_name": "h264" } ] }"#;
        let info = CodecInfo::from_ffprobe_json(json);
        assert_eq!(info.video, VideoCodec::H264);
        assert_eq!(info.audio, AudioCodec::None);
    }

    #[test]
    fn unparseable_or_empty_json_is_undetermined() {
        // Garbage input → undetermined (Req 6.13).
        assert_eq!(CodecInfo::from_ffprobe_json("not json"), CodecInfo::undetermined());
        // Valid JSON but no streams array → undetermined.
        assert_eq!(CodecInfo::from_ffprobe_json("{}"), CodecInfo::undetermined());
        // Empty streams → video stays Unknown (undeterminable video).
        let info = CodecInfo::from_ffprobe_json(r#"{"streams":[]}"#);
        assert!(info.video.is_undetermined());
    }
}
