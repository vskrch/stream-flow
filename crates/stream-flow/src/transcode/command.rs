//! FFmpeg/ffprobe command construction (`transcode::command`) — Req 6.5, 6.6,
//! 6.7, 6.8, 6.9.
//!
//! Pure command-line construction, decoupled from process spawning so the
//! argument vector is unit-testable without FFmpeg present (design: Components
//! → Transcode). Covers:
//!
//! * **Output container** ([`OutputContainer`]): fragmented MP4 (default) or
//!   MPEG-TS as selected by the request (Req 6.5), with the matching
//!   `-f`/`-movflags` flags and response `Content-Type`.
//! * **Encoder selection** ([`VideoEncoder`] / [`select_video_encoder`]): a
//!   detected GPU encoder when GPU is preferred (`h264_nvenc`,
//!   `h264_videotoolbox`, `h264_vaapi`, `h264_qsv`, `h264_amf`), else the
//!   software fallback `libx264` (Req 6.7, 6.8).
//! * **The ffprobe + ffmpeg argument vectors** ([`build_ffprobe_args`] /
//!   [`build_ffmpeg_args`]) honouring the [`TranscodeDecision`] per-stream
//!   actions and the configured target bitrates (Req 6.9), writing fragmented
//!   output to stdout so it can be streamed incrementally (Req 6.6).

use crate::transcode::decision::{AudioAction, TranscodeDecision, VideoAction};

/// The output container selected by the request (Req 6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputContainer {
    /// Fragmented MP4 — the default (Req 6.5).
    #[default]
    FragmentedMp4,
    /// MPEG-TS (Req 6.5).
    MpegTs,
}

impl OutputContainer {
    /// The `-f` muxer name FFmpeg writes this container with.
    pub fn ffmpeg_format(self) -> &'static str {
        match self {
            // Fragmented MP4 is still the `mp4` muxer; fragmentation is driven
            // by the `-movflags` below so the stream is playable as it is
            // produced (Req 6.6).
            OutputContainer::FragmentedMp4 => "mp4",
            OutputContainer::MpegTs => "mpegts",
        }
    }

    /// The `Content-Type` the client response advertises for this container.
    pub fn content_type(self) -> &'static str {
        match self {
            OutputContainer::FragmentedMp4 => "video/mp4",
            OutputContainer::MpegTs => "video/mp2t",
        }
    }

    /// The extra muxer flags needed to make the container streamable as FFmpeg
    /// produces it (Req 6.6). Fragmented MP4 needs `-movflags` so the `moov`
    /// atom is not deferred to the end of a non-seekable stdout pipe; MPEG-TS
    /// is inherently streamable and needs none.
    pub fn movflags(self) -> Option<&'static str> {
        match self {
            OutputContainer::FragmentedMp4 => {
                Some("frag_keyframe+empty_moov+default_base_moof")
            }
            OutputContainer::MpegTs => None,
        }
    }
}

/// A supported H.264 video encoder (design: Components → Transcode; Req 6.7,
/// 6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoEncoder {
    /// NVIDIA NVENC hardware encoder.
    Nvenc,
    /// Apple VideoToolbox hardware encoder.
    VideoToolbox,
    /// VA-API hardware encoder (Intel/AMD on Linux).
    Vaapi,
    /// Intel Quick Sync hardware encoder.
    Qsv,
    /// AMD AMF hardware encoder.
    Amf,
    /// Software fallback (Req 6.8).
    Libx264,
}

impl VideoEncoder {
    /// The FFmpeg `-c:v` encoder name.
    pub fn ffmpeg_name(self) -> &'static str {
        match self {
            VideoEncoder::Nvenc => "h264_nvenc",
            VideoEncoder::VideoToolbox => "h264_videotoolbox",
            VideoEncoder::Vaapi => "h264_vaapi",
            VideoEncoder::Qsv => "h264_qsv",
            VideoEncoder::Amf => "h264_amf",
            VideoEncoder::Libx264 => "libx264",
        }
    }

    /// `true` when this is a GPU/hardware encoder (Req 6.7).
    pub fn is_hardware(self) -> bool {
        !matches!(self, VideoEncoder::Libx264)
    }

    /// The preferred GPU encoders, in detection-priority order (Req 6.7).
    pub const HARDWARE_CANDIDATES: [VideoEncoder; 5] = [
        VideoEncoder::Nvenc,
        VideoEncoder::VideoToolbox,
        VideoEncoder::Vaapi,
        VideoEncoder::Qsv,
        VideoEncoder::Amf,
    ];
}

/// Select the video encoder for a re-encode (Req 6.7, 6.8).
///
/// When GPU acceleration is preferred and at least one of the detected
/// hardware encoders is available, the highest-priority detected hardware
/// encoder is chosen (Req 6.7); otherwise — GPU not preferred, or no supported
/// hardware encoder detected — fall back to software `libx264` (Req 6.8).
///
/// `detected` is the set of hardware encoders FFmpeg reported as available
/// (probed once at startup, Req 49.5 / startup encoder probe).
pub fn select_video_encoder(prefer_gpu: bool, detected: &[VideoEncoder]) -> VideoEncoder {
    if prefer_gpu {
        for candidate in VideoEncoder::HARDWARE_CANDIDATES {
            if detected.contains(&candidate) {
                return candidate;
            }
        }
    }
    VideoEncoder::Libx264
}

/// The bitrate targets applied when re-encoding (Req 6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitrateTargets {
    /// Target video bitrate, e.g. `"4M"` — applied as `-b:v` when the video is
    /// re-encoded (Req 6.9).
    pub video: String,
    /// Target audio bitrate in bits per second — applied as `-b:a` when the
    /// audio is re-encoded (Req 6.9).
    pub audio_bps: u32,
}

/// Build the ffprobe argument vector that probes a source's codecs (Req 6.1).
///
/// Emits compact JSON on stdout listing each stream's `codec_type` +
/// `codec_name`, which [`CodecInfo::from_ffprobe_json`](crate::transcode::codec::CodecInfo::from_ffprobe_json)
/// parses.
pub fn build_ffprobe_args(source_url: &str) -> Vec<String> {
    vec![
        "-v".into(),
        "error".into(),
        "-print_format".into(),
        "json".into(),
        "-show_streams".into(),
        "-show_entries".into(),
        "stream=codec_type,codec_name".into(),
        source_url.into(),
    ]
}

/// Build the FFmpeg argument vector for a decided transcode/remux (Req 6.2–6.9).
///
/// The vector reads from `source_url`, applies the per-stream
/// [`TranscodeDecision`] actions (copy vs re-encode), selects the chosen
/// `encoder` for any video re-encode with the configured target bitrates
/// (Req 6.9), and writes the requested `container` to **stdout** (`pipe:1`) so
/// the caller can stream the output incrementally as FFmpeg produces it
/// (Req 6.6).
pub fn build_ffmpeg_args(
    source_url: &str,
    decision: &TranscodeDecision,
    container: OutputContainer,
    encoder: VideoEncoder,
    bitrates: &BitrateTargets,
) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    // Quieter logs; never prompt for overwrite confirmation on the pipe.
    args.push("-hide_banner".into());
    args.push("-loglevel".into());
    args.push("error".into());

    // Input.
    args.push("-i".into());
    args.push(source_url.into());

    // Video stream handling (Req 6.2, 6.3).
    args.push("-c:v".into());
    match decision.video {
        VideoAction::Copy => {
            args.push("copy".into());
        }
        VideoAction::TranscodeToH264 => {
            args.push(encoder.ffmpeg_name().into());
            // Target video bitrate (Req 6.9).
            args.push("-b:v".into());
            args.push(bitrates.video.clone());
        }
    }

    // Audio stream handling (Req 6.4).
    match decision.audio {
        AudioAction::Copy => {
            args.push("-c:a".into());
            args.push("copy".into());
        }
        AudioAction::TranscodeToAac => {
            args.push("-c:a".into());
            args.push("aac".into());
            // Target audio bitrate (Req 6.9).
            args.push("-b:a".into());
            args.push(format!("{}", bitrates.audio_bps));
        }
        AudioAction::None => {
            // No audio stream — drop audio explicitly so FFmpeg does not error.
            args.push("-an".into());
        }
    }

    // Output container (Req 6.5) + streamable muxer flags (Req 6.6).
    args.push("-f".into());
    args.push(container.ffmpeg_format().into());
    if let Some(movflags) = container.movflags() {
        args.push("-movflags".into());
        args.push(movflags.into());
    }

    // Write to stdout so the caller streams it incrementally (Req 6.6).
    args.push("pipe:1".into());

    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcode::codec::{AudioCodec, CodecInfo, VideoCodec};
    use crate::transcode::decision::decide_mode;

    fn targets() -> BitrateTargets {
        BitrateTargets {
            video: "4M".into(),
            audio_bps: 192_000,
        }
    }

    #[test]
    fn fmp4_is_default_container_with_streamable_flags() {
        assert_eq!(OutputContainer::default(), OutputContainer::FragmentedMp4);
        assert_eq!(OutputContainer::FragmentedMp4.ffmpeg_format(), "mp4");
        assert_eq!(OutputContainer::FragmentedMp4.content_type(), "video/mp4");
        assert!(OutputContainer::FragmentedMp4.movflags().is_some());
    }

    #[test]
    fn mpegts_container_metadata() {
        assert_eq!(OutputContainer::MpegTs.ffmpeg_format(), "mpegts");
        assert_eq!(OutputContainer::MpegTs.content_type(), "video/mp2t");
        assert!(OutputContainer::MpegTs.movflags().is_none());
    }

    #[test]
    fn gpu_preferred_selects_highest_priority_detected_hardware() {
        // NVENC wins when present (Req 6.7).
        let detected = [VideoEncoder::Qsv, VideoEncoder::Nvenc, VideoEncoder::Vaapi];
        assert_eq!(select_video_encoder(true, &detected), VideoEncoder::Nvenc);

        // Without NVENC, the next-priority detected hardware encoder wins.
        let detected = [VideoEncoder::Amf, VideoEncoder::Vaapi];
        assert_eq!(select_video_encoder(true, &detected), VideoEncoder::Vaapi);
    }

    #[test]
    fn gpu_preferred_but_none_detected_falls_back_to_libx264() {
        // Req 6.8: GPU preferred but nothing detected → software encoder.
        assert_eq!(select_video_encoder(true, &[]), VideoEncoder::Libx264);
    }

    #[test]
    fn gpu_not_preferred_always_uses_libx264() {
        // Even with hardware available, software is used when GPU not preferred.
        let detected = [VideoEncoder::Nvenc];
        assert_eq!(select_video_encoder(false, &detected), VideoEncoder::Libx264);
    }

    #[test]
    fn ffprobe_args_request_json_streams_for_the_source() {
        let args = build_ffprobe_args("http://example/video.mkv");
        assert!(args.contains(&"json".to_string()));
        assert!(args.contains(&"-show_streams".to_string()));
        assert_eq!(args.last().unwrap(), "http://example/video.mkv");
    }

    #[test]
    fn remux_args_copy_both_streams_to_fmp4_on_stdout() {
        // H.264 + AAC → pure remux: -c:v copy -c:a copy, fMP4 to pipe:1 (Req 6.2, 6.5, 6.6).
        let decision = decide_mode(&CodecInfo {
            video: VideoCodec::H264,
            audio: AudioCodec::Aac,
        });
        let args = build_ffmpeg_args(
            "http://example/video.mkv",
            &decision,
            OutputContainer::FragmentedMp4,
            VideoEncoder::Libx264,
            &targets(),
        );
        assert!(contains_pair(&args, "-c:v", "copy"));
        assert!(contains_pair(&args, "-c:a", "copy"));
        assert!(contains_pair(&args, "-f", "mp4"));
        // No re-encode bitrate flags on a pure copy (Req 6.9 only on re-encode).
        assert!(!args.iter().any(|a| a == "-b:v"));
        assert!(!args.iter().any(|a| a == "-b:a"));
        assert_eq!(args.last().unwrap(), "pipe:1");
    }

    #[test]
    fn remux_with_audio_transcode_reencodes_audio_only() {
        // H.264 + AC3 → copy video, transcode audio to AAC with -b:a (Req 6.2, 6.4, 6.9).
        let decision = decide_mode(&CodecInfo {
            video: VideoCodec::H264,
            audio: AudioCodec::Other("ac3".into()),
        });
        let args = build_ffmpeg_args(
            "src",
            &decision,
            OutputContainer::FragmentedMp4,
            VideoEncoder::Libx264,
            &targets(),
        );
        assert!(contains_pair(&args, "-c:v", "copy"));
        assert!(contains_pair(&args, "-c:a", "aac"));
        assert!(contains_pair(&args, "-b:a", "192000"));
        assert!(!args.iter().any(|a| a == "-b:v"));
    }

    #[test]
    fn transcode_video_uses_selected_encoder_and_video_bitrate() {
        // HEVC + AAC → transcode video to H.264 via the chosen encoder, copy audio.
        let decision = decide_mode(&CodecInfo {
            video: VideoCodec::Hevc,
            audio: AudioCodec::Aac,
        });
        let args = build_ffmpeg_args(
            "src",
            &decision,
            OutputContainer::MpegTs,
            VideoEncoder::Nvenc,
            &targets(),
        );
        assert!(contains_pair(&args, "-c:v", "h264_nvenc"));
        assert!(contains_pair(&args, "-b:v", "4M"));
        assert!(contains_pair(&args, "-c:a", "copy"));
        assert!(contains_pair(&args, "-f", "mpegts"));
        // MPEG-TS needs no -movflags.
        assert!(!args.iter().any(|a| a == "-movflags"));
    }

    #[test]
    fn full_transcode_reencodes_both_with_bitrates() {
        let decision = decide_mode(&CodecInfo::undetermined());
        let args = build_ffmpeg_args(
            "src",
            &decision,
            OutputContainer::FragmentedMp4,
            VideoEncoder::Libx264,
            &targets(),
        );
        assert!(contains_pair(&args, "-c:v", "libx264"));
        assert!(contains_pair(&args, "-b:v", "4M"));
        assert!(contains_pair(&args, "-c:a", "aac"));
        assert!(contains_pair(&args, "-b:a", "192000"));
    }

    #[test]
    fn no_audio_source_disables_audio() {
        let decision = decide_mode(&CodecInfo {
            video: VideoCodec::H264,
            audio: AudioCodec::None,
        });
        let args = build_ffmpeg_args(
            "src",
            &decision,
            OutputContainer::FragmentedMp4,
            VideoEncoder::Libx264,
            &targets(),
        );
        assert!(args.iter().any(|a| a == "-an"));
        assert!(!args.iter().any(|a| a == "-c:a"));
    }

    /// Assert `flag` is immediately followed by `value` in the arg vector.
    fn contains_pair(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2)
            .any(|w| w[0] == flag && w[1] == value)
    }
}
