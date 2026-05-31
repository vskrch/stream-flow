//! FFmpeg-argument construction (`transcode::args`) — Req 6.2, 6.4, 6.5, 6.7,
//! 6.8, 6.9.
//!
//! [`build_ffmpeg_args`] turns a resolved [`TranscodeMode`], an
//! [`OutputContainer`], the selected video encoder, and the [`TranscodeConfig`]
//! bitrates into the full `ffmpeg` argument vector for a streaming
//! remux/transcode. It is **pure**, so the exact codec flags, bitrate flags,
//! and muxer flags are unit-testable without ever launching FFmpeg.
//!
//! The produced command always:
//! * reads from the upstream `input` URL (`-i <input>`),
//! * copies (`-c:v copy`) or re-encodes (`-c:v <encoder>`) video per the mode
//!   (Req 6.2, 6.3),
//! * copies (`-c:a copy`) or re-encodes (`-c:a aac`) audio per the mode
//!   (Req 6.4),
//! * applies the configured target bitrate to **each re-encoded** stream only
//!   (Req 6.9),
//! * muxes to the requested container with streamable flags (Req 6.5, 6.6),
//! * writes to stdout (`pipe:1`) so the output is streamed incrementally
//!   (Req 6.6).

use crate::config::TranscodeConfig;

use super::decision::{AudioAction, TranscodeMode};
use super::encoder::{OutputContainer, AUDIO_ENCODER};

/// Build the full `ffmpeg` argument vector for a streaming remux/transcode
/// (Req 6.2, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9) — **pure**.
///
/// `video_encoder` is the already-[selected](super::encoder::select_video_encoder)
/// H.264 encoder (hardware or `libx264`); it is only emitted when the mode
/// re-encodes video. Target bitrates from `cfg` are attached only to the
/// stream(s) actually re-encoded (Req 6.9).
pub fn build_ffmpeg_args(
    input: &str,
    mode: TranscodeMode,
    container: OutputContainer,
    video_encoder: &str,
    cfg: &TranscodeConfig,
) -> Vec<String> {
    // Quiet, no stdin, never block on a prompt — the process is unattended.
    // Then the input.
    let mut args: Vec<String> = vec![
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-nostdin".into(),
        "-i".into(),
        input.to_string(),
    ];

    // -- Video stream (Req 6.2, 6.3, 6.9) -----------------------------------
    args.push("-c:v".into());
    if mode.video_reencoded() {
        args.push(video_encoder.to_string());
        // Target video bitrate applies only to the re-encoded video (Req 6.9).
        if !cfg.video_bitrate.is_empty() {
            args.push("-b:v".into());
            args.push(cfg.video_bitrate.clone());
        }
    } else {
        // H.264 source copied without re-encoding (Req 6.2).
        args.push("copy".into());
    }

    // -- Audio stream (Req 6.4, 6.9) ----------------------------------------
    args.push("-c:a".into());
    match mode.audio_action() {
        AudioAction::Copy => {
            args.push("copy".into());
        }
        AudioAction::Transcode => {
            args.push(AUDIO_ENCODER.to_string());
            // Target audio bitrate applies only to the re-encoded audio (Req 6.9).
            if cfg.audio_bitrate > 0 {
                args.push("-b:a".into());
                args.push(cfg.audio_bitrate.to_string());
            }
        }
    }

    // -- Output container (Req 6.5, 6.6) ------------------------------------
    args.extend(container.muxer_args());
    args.push("-f".into());
    args.push(container.format_name().to_string());

    // Stream to stdout so the body is delivered incrementally (Req 6.6).
    args.push("pipe:1".into());

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TranscodeConfig {
        TranscodeConfig {
            enabled: true,
            prefer_gpu: true,
            video_bitrate: "4M".to_string(),
            audio_bitrate: 192_000,
        }
    }

    /// Find the argument value immediately following `flag`.
    fn value_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
    }

    /// `true` when the args contain the flag→value pair adjacently.
    fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
        value_after(args, flag) == Some(value)
    }

    // -- common shape -------------------------------------------------------

    #[test]
    fn always_reads_input_and_writes_to_stdout() {
        let args = build_ffmpeg_args(
            "https://cdn.example/v.mkv",
            TranscodeMode::Remux,
            OutputContainer::FragmentedMp4,
            "libx264",
            &cfg(),
        );
        assert!(has_pair(&args, "-i", "https://cdn.example/v.mkv"));
        assert_eq!(args.last().map(String::as_str), Some("pipe:1"));
    }

    // -- Req 6.2: remux copies both streams, no bitrate flags ---------------

    #[test]
    fn remux_copies_video_and_audio_without_bitrates() {
        let args = build_ffmpeg_args(
            "in",
            TranscodeMode::Remux,
            OutputContainer::FragmentedMp4,
            "h264_nvenc",
            &cfg(),
        );
        assert!(has_pair(&args, "-c:v", "copy"), "video must be copied");
        assert!(has_pair(&args, "-c:a", "copy"), "audio must be copied");
        // No re-encode → no bitrate flags applied (Req 6.9).
        assert!(!args.iter().any(|a| a == "-b:v"));
        assert!(!args.iter().any(|a| a == "-b:a"));
        // Copy mode must NOT name the encoder.
        assert!(!args.iter().any(|a| a == "h264_nvenc"));
    }

    // -- Req 6.2 + 6.4: H.264 + non-AAC → copy video, transcode audio -------

    #[test]
    fn transcode_audio_copies_video_reencodes_audio_with_bitrate() {
        let args = build_ffmpeg_args(
            "in",
            TranscodeMode::TranscodeAudio,
            OutputContainer::FragmentedMp4,
            "libx264",
            &cfg(),
        );
        assert!(has_pair(&args, "-c:v", "copy"), "video copied (Req 6.2)");
        assert!(
            has_pair(&args, "-c:a", AUDIO_ENCODER),
            "audio → aac (Req 6.4)"
        );
        // Audio bitrate applied, video bitrate not (only audio re-encoded).
        assert!(
            has_pair(&args, "-b:a", "192000"),
            "audio bitrate applied (Req 6.9)"
        );
        assert!(
            !args.iter().any(|a| a == "-b:v"),
            "no video bitrate (video copied)"
        );
    }

    // -- Req 6.3 + 6.7: transcode video with hardware encoder + bitrate -----

    #[test]
    fn transcode_video_uses_selected_encoder_and_video_bitrate() {
        let args = build_ffmpeg_args(
            "in",
            TranscodeMode::TranscodeVideo {
                audio: AudioAction::Copy,
            },
            OutputContainer::FragmentedMp4,
            "h264_videotoolbox",
            &cfg(),
        );
        assert!(
            has_pair(&args, "-c:v", "h264_videotoolbox"),
            "video → selected encoder"
        );
        assert!(
            has_pair(&args, "-b:v", "4M"),
            "video bitrate applied (Req 6.9)"
        );
        assert!(
            has_pair(&args, "-c:a", "copy"),
            "AAC audio copied (Req 6.4)"
        );
        assert!(
            !args.iter().any(|a| a == "-b:a"),
            "no audio bitrate (audio copied)"
        );
    }

    // -- Req 6.13 path: full transcode re-encodes both with bitrates --------

    #[test]
    fn full_transcode_reencodes_both_with_both_bitrates() {
        let args = build_ffmpeg_args(
            "in",
            TranscodeMode::FullTranscode,
            OutputContainer::FragmentedMp4,
            "libx264",
            &cfg(),
        );
        assert!(has_pair(&args, "-c:v", "libx264"));
        assert!(has_pair(&args, "-b:v", "4M"));
        assert!(has_pair(&args, "-c:a", AUDIO_ENCODER));
        assert!(has_pair(&args, "-b:a", "192000"));
    }

    // -- Req 6.5: output container selection --------------------------------

    #[test]
    fn fragmented_mp4_output_sets_format_and_movflags() {
        let args = build_ffmpeg_args(
            "in",
            TranscodeMode::Remux,
            OutputContainer::FragmentedMp4,
            "libx264",
            &cfg(),
        );
        assert!(has_pair(&args, "-f", "mp4"));
        assert!(has_pair(
            &args,
            "-movflags",
            "+frag_keyframe+empty_moov+default_base_moof"
        ));
    }

    #[test]
    fn mpegts_output_sets_format_without_movflags() {
        let args = build_ffmpeg_args(
            "in",
            TranscodeMode::Remux,
            OutputContainer::MpegTs,
            "libx264",
            &cfg(),
        );
        assert!(has_pair(&args, "-f", "mpegts"));
        assert!(!args.iter().any(|a| a == "-movflags"));
    }

    // -- Req 6.9: empty/zero bitrate config omits the flag ------------------

    #[test]
    fn empty_video_bitrate_omits_video_bitrate_flag() {
        let mut c = cfg();
        c.video_bitrate = String::new();
        c.audio_bitrate = 0;
        let args = build_ffmpeg_args(
            "in",
            TranscodeMode::FullTranscode,
            OutputContainer::FragmentedMp4,
            "libx264",
            &c,
        );
        assert!(!args.iter().any(|a| a == "-b:v"));
        assert!(!args.iter().any(|a| a == "-b:a"));
    }
}
