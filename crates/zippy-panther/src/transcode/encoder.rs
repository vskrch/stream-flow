//! Video-encoder selection + output container (`transcode::encoder`) — Req
//! 6.5, 6.7, 6.8.
//!
//! When the video stream is re-encoded, the encoder is chosen by
//! [`select_video_encoder`]: if GPU acceleration is *preferred* and a supported
//! hardware H.264 encoder is *detected*, the hardware encoder wins (Req 6.7);
//! otherwise it falls back to software `libx264` (Req 6.8). Detection of the
//! available encoder set runs `ffmpeg -encoders` (process-backed,
//! [`detect_hw_encoders`]); the *selection* given a detected set is **pure**
//! and unit-testable.
//!
//! [`OutputContainer`] models the fMP4 (default) / MPEG-TS choice (Req 6.5) and
//! supplies the muxer flags used by the FFmpeg-argument builder.

use std::path::Path;
use std::process::Stdio;

/// The supported hardware H.264 encoders, in preference order (Req 6.7).
///
/// The list mirrors the requirement's examples; `select_video_encoder` picks
/// the first one present in the detected encoder set, so the order here is the
/// platform-priority order (NVIDIA → Apple → VAAPI → QuickSync → AMD).
pub const HW_VIDEO_ENCODERS: &[&str] = &[
    "h264_nvenc",        // NVIDIA NVENC
    "h264_videotoolbox", // Apple VideoToolbox
    "h264_vaapi",        // VAAPI (Intel/AMD on Linux)
    "h264_qsv",          // Intel QuickSync
    "h264_amf",          // AMD AMF
];

/// The software H.264 encoder fallback (Req 6.8).
pub const SW_VIDEO_ENCODER: &str = "libx264";

/// The AAC audio encoder used when re-encoding audio (Req 6.4).
pub const AUDIO_ENCODER: &str = "aac";

/// Select the H.264 video encoder for a re-encode (Req 6.7, 6.8) — **pure**.
///
/// * `prefer_gpu == true` and at least one [`HW_VIDEO_ENCODERS`] entry is in
///   `available`: return the highest-priority available hardware encoder
///   (Req 6.7).
/// * Otherwise (GPU not preferred, or preferred but none detected): return
///   [`SW_VIDEO_ENCODER`] (`libx264`, Req 6.8).
pub fn select_video_encoder(prefer_gpu: bool, available: &[String]) -> String {
    if prefer_gpu {
        if let Some(hw) = HW_VIDEO_ENCODERS
            .iter()
            .find(|enc| available.iter().any(|a| a == *enc))
        {
            return (*hw).to_string();
        }
    }
    SW_VIDEO_ENCODER.to_string()
}

/// Detect the hardware H.264 encoders available to the local FFmpeg build
/// (Req 6.7) by parsing `ffmpeg -hide_banner -encoders`.
///
/// Returns the subset of [`HW_VIDEO_ENCODERS`] whose name appears in the
/// output. On any launch/exit failure it returns an empty vector, so
/// [`select_video_encoder`] falls back to software encoding (Req 6.8). This is
/// a one-time startup detection (Req 49.5 — never fatal at boot).
pub async fn detect_hw_encoders(ffmpeg: &Path) -> Vec<String> {
    let output = tokio::process::Command::new(ffmpeg)
        .args(["-hide_banner", "-encoders"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_available_encoders(&text)
        }
        _ => Vec::new(),
    }
}

/// Extract the supported hardware H.264 encoder names from `ffmpeg -encoders`
/// output (Req 6.7) — **pure**, so detection parsing is unit-testable.
///
/// `ffmpeg -encoders` lists one encoder per line as `<flags> <name> <desc>`;
/// we keep the [`HW_VIDEO_ENCODERS`] entries that appear as a whitespace token.
pub fn parse_available_encoders(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        for token in line.split_whitespace() {
            if HW_VIDEO_ENCODERS.contains(&token) && !found.iter().any(|f: &String| f == token) {
                found.push(token.to_string());
            }
        }
    }
    found
}

/// The output container the client requested (Req 6.5).
///
/// fMP4 is the default; MPEG-TS is selected per request. Applies in both remux
/// and transcode modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputContainer {
    /// Fragmented MP4 (default, Req 6.5). Streamable without a seekable output:
    /// `-movflags +frag_keyframe+empty_moov+default_base_moof`.
    #[default]
    FragmentedMp4,
    /// MPEG-TS (Req 6.5).
    MpegTs,
}

impl OutputContainer {
    /// The FFmpeg `-f` muxer name for this container.
    pub fn format_name(self) -> &'static str {
        match self {
            OutputContainer::FragmentedMp4 => "mp4",
            OutputContainer::MpegTs => "mpegts",
        }
    }

    /// The MIME type advertised to the client for this container.
    pub fn content_type(self) -> &'static str {
        match self {
            OutputContainer::FragmentedMp4 => "video/mp4",
            OutputContainer::MpegTs => "video/mp2t",
        }
    }

    /// Extra muxer flags needed to stream this container from a pipe.
    ///
    /// fMP4 needs fragment movflags so the output is playable as it is produced
    /// (Req 6.6 — no seekable `moov` at the end); MPEG-TS needs none.
    pub fn muxer_args(self) -> Vec<String> {
        match self {
            OutputContainer::FragmentedMp4 => vec![
                "-movflags".to_string(),
                "+frag_keyframe+empty_moov+default_base_moof".to_string(),
            ],
            OutputContainer::MpegTs => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // -- Req 6.7: GPU preferred + detected → hardware encoder ----------------

    #[test]
    fn prefers_available_hw_encoder_when_gpu_preferred() {
        let available = owned(&["libx264", "h264_nvenc"]);
        assert_eq!(select_video_encoder(true, &available), "h264_nvenc");
    }

    #[test]
    fn picks_highest_priority_hw_encoder_when_several_present() {
        // vaapi + videotoolbox available; videotoolbox is higher priority.
        let available = owned(&["h264_vaapi", "h264_videotoolbox"]);
        assert_eq!(select_video_encoder(true, &available), "h264_videotoolbox");
    }

    // -- Req 6.8: GPU preferred but none detected → libx264 ------------------

    #[test]
    fn falls_back_to_libx264_when_no_hw_encoder_detected() {
        let available = owned(&["libx264", "mpeg4"]);
        assert_eq!(select_video_encoder(true, &available), SW_VIDEO_ENCODER);
    }

    #[test]
    fn falls_back_to_libx264_when_gpu_not_preferred_even_if_hw_present() {
        let available = owned(&["h264_nvenc"]);
        assert_eq!(select_video_encoder(false, &available), SW_VIDEO_ENCODER);
    }

    #[test]
    fn falls_back_to_libx264_for_empty_encoder_set() {
        assert_eq!(select_video_encoder(true, &[]), SW_VIDEO_ENCODER);
    }

    // -- encoder-list parsing (Req 6.7) -------------------------------------

    #[test]
    fn parse_available_encoders_extracts_hw_names() {
        let text = "\
Encoders:
 V..... libx264              libx264 H.264 / AVC
 V..... h264_nvenc           NVIDIA NVENC H.264 encoder
 V..... h264_videotoolbox    VideoToolbox H.264 Encoder
 A..... aac                  AAC (Advanced Audio Coding)
";
        let found = parse_available_encoders(text);
        assert!(found.contains(&"h264_nvenc".to_string()));
        assert!(found.contains(&"h264_videotoolbox".to_string()));
        assert!(
            !found.contains(&"libx264".to_string()),
            "sw encoder is not 'hardware'"
        );
    }

    #[test]
    fn parse_available_encoders_empty_when_none_present() {
        let text = " V..... libx264              libx264 H.264 / AVC\n";
        assert!(parse_available_encoders(text).is_empty());
    }

    // -- output container (Req 6.5, 6.6) ------------------------------------

    #[test]
    fn output_container_default_is_fragmented_mp4() {
        assert_eq!(OutputContainer::default(), OutputContainer::FragmentedMp4);
    }

    #[test]
    fn fragmented_mp4_uses_streamable_movflags() {
        let c = OutputContainer::FragmentedMp4;
        assert_eq!(c.format_name(), "mp4");
        assert_eq!(c.content_type(), "video/mp4");
        let args = c.muxer_args();
        assert_eq!(
            args,
            vec![
                "-movflags".to_string(),
                "+frag_keyframe+empty_moov+default_base_moof".to_string(),
            ]
        );
    }

    #[test]
    fn mpegts_has_no_extra_muxer_args() {
        let c = OutputContainer::MpegTs;
        assert_eq!(c.format_name(), "mpegts");
        assert_eq!(c.content_type(), "video/mp2t");
        assert!(c.muxer_args().is_empty());
    }
}
