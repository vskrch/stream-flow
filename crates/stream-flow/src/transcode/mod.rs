//! On-the-fly transcoding + remuxing (`transcode`) — Req 6.
//!
//! Turns an upstream media URL into a client-compatible **fragmented MP4
//! (default) or MPEG-TS** byte stream, doing the *least* work necessary: a
//! container-only remux when the source is already H.264 + AAC, an audio-only
//! re-encode when only the audio is incompatible, a video transcode to H.264
//! for HEVC/VP9/AV1, and a full transcode when the source codecs cannot even be
//! determined (design: Components → Transcode; Property 15).
//!
//! ## Pipeline ([`TranscodeEngine::open`])
//!
//! 1. **Probe** the source codecs via `ffprobe` ([`codec::probe_codecs`],
//!    Req 6.1); an unprobeable source yields [`CodecInfo::undetermined`].
//! 2. **Decide** the mode purely from the codecs ([`decide_mode`], Req 6.2–6.4,
//!    6.13).
//! 3. **Gate** on configuration: a transcode-*only* request for media that
//!    needs a video re-encode while transcoding is disabled → `404`
//!    ([`rejected_as_not_found`], Req 6.10).
//! 4. **Select** the H.264 encoder — a detected hardware encoder when GPU is
//!    preferred, else `libx264` ([`select_video_encoder`], Req 6.7, 6.8).
//! 5. **Build** the FFmpeg argument vector applying the target bitrates and the
//!    requested container ([`build_ffmpeg_args`], Req 6.5, 6.9).
//! 6. **Stream** FFmpeg stdout incrementally, killing + reaping the child on
//!    client disconnect and terminating + logging on a non-zero exit
//!    ([`spawn_ffmpeg_output`], Req 6.6, 6.11, 6.12).
//!
//! ## FFmpeg presence (Req 49.5)
//!
//! [`TranscodeEngine::detect`] never fails when FFmpeg is absent — it records
//! "no FFmpeg" and the descriptive error surfaces only when [`open`] is
//! invoked, so the server still starts on a box without FFmpeg.

pub mod args;
pub mod codec;
pub mod decision;
pub mod encoder;
pub mod process;

use std::path::PathBuf;
use std::pin::Pin;

use bytes::Bytes;
use futures::Stream;

use crate::config::TranscodeConfig;
use crate::errors::AppError;

pub use args::build_ffmpeg_args;
pub use codec::{parse_ffprobe_output, probe_codecs, AudioCodec, CodecInfo, VideoCodec};
pub use decision::{decide_mode, AudioAction, TranscodeMode};
pub use encoder::{
    detect_hw_encoders, parse_available_encoders, select_video_encoder, OutputContainer,
};
pub use process::{ffmpeg_available, spawn_ffmpeg_output};

/// Default `ffmpeg` binary name (resolved on `PATH`).
const DEFAULT_FFMPEG: &str = "ffmpeg";
/// Default `ffprobe` binary name (resolved on `PATH`).
const DEFAULT_FFPROBE: &str = "ffprobe";

/// One transcode/remux request (design: Components → Transcode).
#[derive(Debug, Clone)]
pub struct TranscodeRequest {
    /// The upstream media URL FFmpeg reads from.
    pub input: String,
    /// The requested output container — fMP4 (default) or MPEG-TS (Req 6.5).
    pub container: OutputContainer,
    /// `true` when this is a transcode-*only* endpoint: media that needs a
    /// video re-encode while transcoding is disabled is rejected with `404`
    /// (Req 6.10). `false` for a best-effort remux-or-transcode endpoint.
    pub transcode_only: bool,
}

impl TranscodeRequest {
    /// A fMP4, best-effort (non-transcode-only) request for `input`.
    pub fn new(input: impl Into<String>) -> Self {
        Self {
            input: input.into(),
            container: OutputContainer::FragmentedMp4,
            transcode_only: false,
        }
    }

    /// Set the output container (Req 6.5).
    pub fn with_container(mut self, container: OutputContainer) -> Self {
        self.container = container;
        self
    }

    /// Mark this as a transcode-only endpoint (Req 6.10).
    pub fn transcode_only(mut self) -> Self {
        self.transcode_only = true;
        self
    }
}

/// The incremental output of a remux/transcode (Req 6.6).
pub struct TranscodeOutput {
    /// The decided processing mode (for logging / metrics).
    pub mode: TranscodeMode,
    /// The MIME type for the output container (Req 6.5).
    pub content_type: &'static str,
    /// The incremental FFmpeg-stdout byte stream (Req 6.6). Dropping it kills +
    /// reaps the FFmpeg child (Req 6.12).
    pub stream: Pin<Box<dyn Stream<Item = Result<Bytes, AppError>> + Send>>,
}

impl std::fmt::Debug for TranscodeOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranscodeOutput")
            .field("mode", &self.mode)
            .field("content_type", &self.content_type)
            .field("stream", &"<byte stream>")
            .finish()
    }
}

/// The transcode subsystem: FFmpeg/ffprobe binary paths, the one-time detected
/// hardware-encoder set, and the [`TranscodeConfig`] (design: Components →
/// Transcode).
#[derive(Debug, Clone)]
pub struct TranscodeEngine {
    ffmpeg: PathBuf,
    ffprobe: PathBuf,
    /// Detected supported hardware H.264 encoders (Req 6.7). Empty when none
    /// detected or FFmpeg is absent — selection then falls back to `libx264`
    /// (Req 6.8).
    hw_encoders: Vec<String>,
    /// `true` when a usable `ffmpeg` binary was found at detection (Req 49.5).
    ffmpeg_present: bool,
    config: TranscodeConfig,
}

impl TranscodeEngine {
    /// Build an engine with explicit binary paths and a known encoder set
    /// (used by tests and callers that probed encoders themselves).
    pub fn new(
        ffmpeg: PathBuf,
        ffprobe: PathBuf,
        hw_encoders: Vec<String>,
        ffmpeg_present: bool,
        config: TranscodeConfig,
    ) -> Self {
        Self {
            ffmpeg,
            ffprobe,
            hw_encoders,
            ffmpeg_present,
            config,
        }
    }

    /// Detect FFmpeg + its hardware encoders once at startup (Req 6.7, 49.5).
    ///
    /// Resolves `ffmpeg`/`ffprobe` from `PATH`. **Never fails**: if FFmpeg is
    /// absent, the engine is still built with `ffmpeg_present == false` and an
    /// empty encoder set, so the server starts and the descriptive error only
    /// surfaces when [`open`](Self::open) is invoked (Req 49.5).
    pub async fn detect(config: TranscodeConfig) -> Self {
        let ffmpeg = PathBuf::from(DEFAULT_FFMPEG);
        let ffprobe = PathBuf::from(DEFAULT_FFPROBE);
        let ffmpeg_present = ffmpeg_available(&ffmpeg).await;
        let hw_encoders = if ffmpeg_present {
            detect_hw_encoders(&ffmpeg).await
        } else {
            Vec::new()
        };
        if !ffmpeg_present {
            tracing::warn!(
                target: "transcode",
                "FFmpeg not found at startup; transcode endpoints will error on invocation (Req 49.5)",
            );
        }
        Self {
            ffmpeg,
            ffprobe,
            hw_encoders,
            ffmpeg_present,
            config,
        }
    }

    /// The configured transcode tunables.
    pub fn config(&self) -> &TranscodeConfig {
        &self.config
    }

    /// `true` when a usable FFmpeg was detected at startup (Req 49.5).
    pub fn ffmpeg_present(&self) -> bool {
        self.ffmpeg_present
    }

    /// The detected hardware encoder set (Req 6.7).
    pub fn hw_encoders(&self) -> &[String] {
        &self.hw_encoders
    }

    /// Run the full probe → decide → gate → encode pipeline and return the
    /// incremental output stream (Req 6.1–6.13).
    ///
    /// Errors:
    /// * `503` when FFmpeg is unavailable at invocation (Req 49.5).
    /// * `404` when a transcode-only request needs a video re-encode but
    ///   transcoding is disabled (Req 6.10).
    pub async fn open(&self, req: &TranscodeRequest) -> Result<TranscodeOutput, AppError> {
        // Req 49.5: FFmpeg absent → descriptive error only at invocation.
        if !self.ffmpeg_present {
            return Err(AppError::upstream_unavailable(
                "transcoding is unavailable: FFmpeg is not installed",
            ));
        }

        // 1. Probe (Req 6.1) — undeterminable codecs fall through to a full
        //    transcode in `decide_mode` (Req 6.13).
        let info = probe_codecs(&self.ffprobe, &req.input).await;
        // 2. Decide (Req 6.2–6.4, 6.13).
        let mode = decide_mode(&info);

        // 3. Config gate (Req 6.10): transcode-only + disabled + needs a video
        //    re-encode → 404.
        if rejected_as_not_found(mode, self.config.enabled, req.transcode_only) {
            return Err(AppError::not_found(
                "transcoding is disabled and this media requires a video re-encode",
            ));
        }

        // 4. Encoder selection (Req 6.7, 6.8) — only matters when re-encoding.
        let video_encoder = select_video_encoder(self.config.prefer_gpu, &self.hw_encoders);

        // 5. Build the FFmpeg arguments (Req 6.5, 6.9).
        let args = build_ffmpeg_args(&req.input, mode, req.container, &video_encoder, &self.config);

        // 6. Spawn + stream incrementally (Req 6.6, 6.11, 6.12).
        let stream = spawn_ffmpeg_output(&self.ffmpeg, &args)?;

        Ok(TranscodeOutput {
            mode,
            content_type: req.container.content_type(),
            stream: Box::pin(stream),
        })
    }
}

/// The Req 6.10 gate — **pure**.
///
/// `true` (→ `404`) exactly when transcoding is **disabled**, the request is
/// **transcode-only**, and the decided mode **requires a video re-encode**
/// (the source video codec is incompatible). A best-effort remux (`Remux` /
/// `TranscodeAudio`) is never blocked by this gate, and an enabled transcoder
/// never is either.
pub fn rejected_as_not_found(
    mode: TranscodeMode,
    transcode_enabled: bool,
    transcode_only: bool,
) -> bool {
    !transcode_enabled && transcode_only && mode.requires_video_reencode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool) -> TranscodeConfig {
        TranscodeConfig {
            enabled,
            prefer_gpu: true,
            video_bitrate: "4M".to_string(),
            audio_bitrate: 192_000,
        }
    }

    // -- Req 6.10 gate is pure and exact ------------------------------------

    #[test]
    fn gate_blocks_only_disabled_transcode_only_video_reencode() {
        // Disabled + transcode-only + needs video re-encode → 404.
        assert!(rejected_as_not_found(TranscodeMode::FullTranscode, false, true));
        assert!(rejected_as_not_found(
            TranscodeMode::TranscodeVideo { audio: AudioAction::Copy },
            false,
            true
        ));
    }

    #[test]
    fn gate_allows_remux_even_when_disabled() {
        // A container-only remux / audio-only re-encode never needs the video
        // transcoder, so it is not blocked even when transcoding is disabled.
        assert!(!rejected_as_not_found(TranscodeMode::Remux, false, true));
        assert!(!rejected_as_not_found(TranscodeMode::TranscodeAudio, false, true));
    }

    #[test]
    fn gate_allows_video_reencode_when_enabled() {
        assert!(!rejected_as_not_found(TranscodeMode::FullTranscode, true, true));
        assert!(!rejected_as_not_found(
            TranscodeMode::TranscodeVideo { audio: AudioAction::Transcode },
            true,
            true
        ));
    }

    #[test]
    fn gate_allows_non_transcode_only_endpoint_when_disabled() {
        // A best-effort endpoint (not transcode-only) is never 404'd by the gate.
        assert!(!rejected_as_not_found(TranscodeMode::FullTranscode, false, false));
    }

    // -- Req 49.5: engine built without FFmpeg errors only at invocation ----

    #[tokio::test]
    async fn open_errors_when_ffmpeg_absent_built_without_present() {
        let engine = TranscodeEngine::new(
            PathBuf::from("/nonexistent/ffmpeg"),
            PathBuf::from("/nonexistent/ffprobe"),
            Vec::new(),
            false, // ffmpeg_present == false
            cfg(true),
        );
        // The engine was constructed fine (startup succeeds, Req 49.5)…
        assert!(!engine.ffmpeg_present());
        // …and the descriptive error surfaces only here, on invocation.
        let err = engine
            .open(&TranscodeRequest::new("https://cdn.example/v.mkv"))
            .await
            .expect_err("must error when FFmpeg absent");
        assert!(err.message.contains("FFmpeg"), "error names FFmpeg: {err}");
    }

    #[tokio::test]
    async fn detect_is_non_fatal_and_reports_presence() {
        // detect() must never panic/abort regardless of the host's FFmpeg.
        let engine = TranscodeEngine::detect(cfg(true)).await;
        // The detected encoder set is a (possibly empty) subset of the known
        // hardware encoders; when FFmpeg is absent it is empty.
        if !engine.ffmpeg_present() {
            assert!(engine.hw_encoders().is_empty());
        }
    }

    // -- request builder defaults (Req 6.5) ---------------------------------

    #[test]
    fn request_defaults_to_fragmented_mp4_best_effort() {
        let req = TranscodeRequest::new("u");
        assert_eq!(req.container, OutputContainer::FragmentedMp4);
        assert!(!req.transcode_only);
    }
}
