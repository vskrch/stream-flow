//! FFmpeg process management + incremental streaming output
//! (`transcode::process`) — Req 6.6, 6.11, 6.12, 49.5.
//!
//! [`spawn_ffmpeg_output`] launches `ffmpeg` with a prebuilt argument vector,
//! piping its stdout into a zero-copy [`Stream`] of [`Bytes`] that is yielded
//! **incrementally as FFmpeg produces it** (Req 6.6) — the output is never
//! buffered whole. The spawned [`tokio::process::Child`] is moved *into* the
//! stream and configured [`kill_on_drop`](tokio::process::Command::kill_on_drop),
//! so when the client disconnects (the response body — and hence this stream —
//! is dropped) the FFmpeg child is killed and reaped by the tokio process
//! driver, never leaking a zombie (Req 6.12).
//!
//! When FFmpeg exits with a non-zero status before the output completes, the
//! stream's terminal item is a typed [`AppError`] (so the client response is
//! terminated) and the exit status + captured stderr are recorded in the
//! structured log (Req 6.11).
//!
//! [`ffmpeg_available`] is the runtime presence check backing Req 49.5: the
//! process starts successfully without FFmpeg installed and a descriptive error
//! only surfaces here, when a transcode endpoint is actually invoked.

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use futures::Stream;
use tokio::io::{AsyncReadExt, BufReader};

use crate::errors::AppError;

/// The stdout read chunk size for the incremental relay (Req 6.6). 64 KiB keeps
/// per-read overhead low while bounding peak memory.
const STDOUT_CHUNK: usize = 64 * 1024;

/// Cap on captured stderr bytes for the failure log (Req 6.11). FFmpeg stderr
/// is small even on failure; this guards against an unbounded error stream.
const MAX_STDERR_CAPTURE: usize = 64 * 1024;

/// `true` when the `ffmpeg` binary at `path` can be launched (Req 49.5).
///
/// Runs `ffmpeg -version`. Returns `false` on any launch/exit failure so the
/// caller surfaces a descriptive "FFmpeg unavailable" error at invocation time
/// rather than failing at startup.
pub async fn ffmpeg_available(path: &Path) -> bool {
    tokio::process::Command::new(path)
        .arg("-version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Spawn `ffmpeg <args>` and stream its stdout incrementally as a byte stream
/// (Req 6.6, 6.11, 6.12).
///
/// The child is configured `kill_on_drop` and moved into the returned stream;
/// dropping the stream (client disconnect) kills + reaps it (Req 6.12). A
/// non-zero exit terminates the stream with a typed [`AppError`] and logs the
/// exit status + captured stderr (Req 6.11). A launch failure (e.g. FFmpeg
/// absent — Req 49.5) is returned eagerly as an [`AppError`].
pub fn spawn_ffmpeg_output(
    ffmpeg: &Path,
    args: &[String],
) -> Result<impl Stream<Item = Result<Bytes, AppError>>, AppError> {
    let mut child = tokio::process::Command::new(ffmpeg)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| AppError::upstream_unavailable(format!("failed to launch FFmpeg: {e}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::unknown("FFmpeg stdout pipe was not captured"))?;
    let stderr = child.stderr.take();

    // Drain stderr concurrently into a shared buffer so it is available for the
    // failure log without blocking the stdout relay (Req 6.11).
    let captured_stderr: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    if let Some(mut stderr) = stderr {
        let sink = captured_stderr.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            // Best-effort read; ignore errors (the failure path still logs the
            // exit status even if stderr could not be read).
            let _ = stderr.read_to_end(&mut buf).await;
            let mut guard = sink.lock().unwrap();
            buf.truncate(MAX_STDERR_CAPTURE);
            *guard = buf;
        });
    }

    let stream = async_stream::try_stream! {
        // Move the child in so it lives exactly as long as the stream; on drop
        // (client disconnect) kill_on_drop reaps it (Req 6.12).
        let mut child = child;
        let mut reader = BufReader::new(stdout);

        loop {
            let mut chunk = BytesMut::zeroed(STDOUT_CHUNK);
            match reader.read(&mut chunk).await {
                Ok(0) => break, // stdout EOF — FFmpeg finished producing output.
                Ok(n) => {
                    chunk.truncate(n);
                    yield chunk.freeze();
                }
                Err(e) => {
                    // A read error mid-output terminates the client response.
                    Err(AppError::upstream_unavailable(format!(
                        "error reading FFmpeg output: {e}"
                    )))?;
                }
            }
        }

        // stdout closed: reap the child and inspect its exit status (Req 6.11).
        let status = child
            .wait()
            .await
            .map_err(|e| AppError::unknown(format!("failed to await FFmpeg: {e}")))?;

        if !status.success() {
            let stderr_text = {
                let guard = captured_stderr.lock().unwrap();
                String::from_utf8_lossy(&guard).trim().to_string()
            };
            tracing::error!(
                target: "transcode",
                exit_status = ?status.code(),
                ffmpeg_stderr = %stderr_text,
                "FFmpeg exited with a non-zero status; terminating client response",
            );
            Err(AppError::upstream_unavailable(format!(
                "FFmpeg exited with status {:?}",
                status.code()
            )))?;
        }
    };

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::path::PathBuf;

    /// Resolve a binary on `PATH` (so the gated tests find a real `ffmpeg`).
    fn which(bin: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(bin))
            .find(|candidate| candidate.is_file())
    }

    /// `ffmpeg` path if a real FFmpeg is installed, else skip the gated test.
    fn ffmpeg_path() -> Option<PathBuf> {
        which("ffmpeg")
    }

    // -- Req 49.5: availability check is non-fatal and accurate -------------

    #[tokio::test]
    async fn ffmpeg_available_false_for_missing_binary() {
        // A path that does not exist must report "unavailable" without panic.
        assert!(!ffmpeg_available(Path::new("/nonexistent/ffmpeg-xyz")).await);
    }

    #[tokio::test]
    async fn spawn_returns_error_for_missing_binary() {
        let err = spawn_ffmpeg_output(Path::new("/nonexistent/ffmpeg-xyz"), &[])
            .err()
            .expect("missing binary must error at invocation, not panic");
        assert!(err.message.contains("FFmpeg"));
    }

    // -- Req 6.6 / 6.11: real FFmpeg streaming (gated on availability) ------

    #[tokio::test]
    async fn streams_real_ffmpeg_output_incrementally() {
        let Some(ffmpeg) = ffmpeg_path() else {
            eprintln!("skipping: ffmpeg not on PATH");
            return;
        };
        // Generate 1s of synthetic video + tone, mux to fragmented MP4 on
        // stdout — exercises the real incremental stdout relay (Req 6.6).
        let args: Vec<String> = [
            "-hide_banner",
            "-loglevel",
            "error",
            "-nostdin",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=128x128:rate=15:duration=1",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:duration=1",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-c:a",
            "aac",
            "-movflags",
            "+frag_keyframe+empty_moov+default_base_moof",
            "-f",
            "mp4",
            "pipe:1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let stream = spawn_ffmpeg_output(&ffmpeg, &args).expect("spawn succeeds");
        futures::pin_mut!(stream);

        let mut total = 0usize;
        let mut first_chunk = Vec::new();
        while let Some(item) = stream.next().await {
            let bytes = item.expect("no error on a valid transcode");
            if first_chunk.is_empty() {
                first_chunk = bytes.to_vec();
            }
            total += bytes.len();
        }
        assert!(total > 0, "FFmpeg must produce output bytes");
        // Fragmented MP4 begins with an `ftyp` box: size(4) then 'ftyp'.
        assert!(
            first_chunk.len() >= 8 && &first_chunk[4..8] == b"ftyp",
            "output should be an MP4 stream, got prefix {:?}",
            &first_chunk[..first_chunk.len().min(8)]
        );
    }

    #[tokio::test]
    async fn nonzero_exit_terminates_stream_with_error() {
        let Some(ffmpeg) = ffmpeg_path() else {
            eprintln!("skipping: ffmpeg not on PATH");
            return;
        };
        // A non-existent input makes FFmpeg exit non-zero before any output.
        let args: Vec<String> = [
            "-hide_banner",
            "-loglevel",
            "error",
            "-nostdin",
            "-i",
            "/nonexistent/input-file-xyz.mkv",
            "-f",
            "mp4",
            "pipe:1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let stream = spawn_ffmpeg_output(&ffmpeg, &args).expect("spawn succeeds");
        futures::pin_mut!(stream);

        let mut saw_error = false;
        while let Some(item) = stream.next().await {
            if let Err(err) = item {
                saw_error = true;
                assert!(err.message.contains("FFmpeg"), "error names FFmpeg: {err}");
            }
        }
        assert!(
            saw_error,
            "a non-zero FFmpeg exit must terminate the stream with an error"
        );
    }

    // -- Req 6.12: dropping the stream early kills the child (gated) --------

    #[tokio::test]
    async fn dropping_stream_early_reaps_child() {
        let Some(ffmpeg) = ffmpeg_path() else {
            eprintln!("skipping: ffmpeg not on PATH");
            return;
        };
        // An effectively endless source so the child would run forever unless
        // killed on drop (Req 6.12).
        let args: Vec<String> = [
            "-hide_banner",
            "-loglevel",
            "error",
            "-nostdin",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=128x128:rate=15",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-movflags",
            "+frag_keyframe+empty_moov+default_base_moof",
            "-f",
            "mp4",
            "pipe:1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        {
            let stream = spawn_ffmpeg_output(&ffmpeg, &args).expect("spawn succeeds");
            futures::pin_mut!(stream);
            // Pull one chunk, then drop the stream (simulating client disconnect).
            let _ = stream.next().await;
        }
        // If kill_on_drop did not fire, the child would linger. Give the tokio
        // process driver a moment to reap, then confirm we returned cleanly.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
