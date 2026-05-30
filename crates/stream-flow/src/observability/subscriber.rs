//! Structured-logging stack with central secret redaction
//! (`observability::subscriber`) — Req 32.3, 32.6, 46.7.
//!
//! The design calls for structured `tracing` logs for request handling,
//! upstream errors, cache events, and lifecycle events (Req 32.3) with a
//! redaction layer that scrubs secrets out of URLs/headers before they are
//! emitted (Req 32.6, 46.7). Rather than scrub at every individual call site
//! (easy to forget, impossible to audit), redaction is enforced **centrally**
//! at the one place every log record must pass through: the writer.
//!
//! [`RedactingMakeWriter`] wraps any [`MakeWriter`] (stdout by default) and runs
//! every fully-rendered log line through a shared [`Redactor`] before it
//! reaches the real sink. Because `tracing-subscriber`'s `fmt` layer formats the
//! whole record — span fields, event fields, and the message — into the writer,
//! a single scrub point covers messages *and* structured fields, so no secret
//! can slip through in either (Req 32.6, 46.7).
//!
//! [`init_logging`] installs a `tracing-subscriber` `fmt` subscriber over this
//! writer with an `EnvFilter` honoring the configured log level (Req 32.3). It
//! is `try_init`-based so tests and repeated calls never panic on a
//! double-install.

use std::io::{self, Write};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use super::redaction::Redactor;

/// A [`MakeWriter`] that redacts every rendered log line through a shared
/// [`Redactor`] before forwarding it to the wrapped writer (Req 32.6, 46.7).
#[derive(Clone)]
pub struct RedactingMakeWriter<M> {
    inner: M,
    redactor: Redactor,
}

impl<M> RedactingMakeWriter<M> {
    /// Wrap `inner` so every line written through it is scrubbed by `redactor`.
    pub fn new(inner: M, redactor: Redactor) -> Self {
        Self { inner, redactor }
    }
}

impl<'a, M> MakeWriter<'a> for RedactingMakeWriter<M>
where
    M: MakeWriter<'a>,
{
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer(),
            redactor: self.redactor.clone(),
        }
    }
}

/// The per-write redacting wrapper produced by [`RedactingMakeWriter`].
///
/// `tracing-subscriber`'s `fmt` layer writes one rendered record per
/// [`Write::write_all`] call, so redacting the bytes of each write scrubs the
/// whole record (message + fields) before it reaches the real sink.
pub struct RedactingWriter<W> {
    inner: W,
    redactor: Redactor,
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Render the chunk as text and scrub it. Non-UTF-8 bytes are passed
        // through unchanged (log lines are UTF-8 in practice); we still report
        // the original length as consumed so the fmt layer sees a full write.
        match std::str::from_utf8(buf) {
            Ok(text) => {
                let redacted = self.redactor.redact(text);
                self.inner.write_all(redacted.as_bytes())?;
            }
            Err(_) => {
                self.inner.write_all(buf)?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Install the global structured-logging subscriber with central secret
/// redaction (Req 32.3, 32.6, 46.7).
///
/// Logs are written to stdout through a [`RedactingMakeWriter`] keyed by
/// `redactor`, with the verbosity controlled by the `RUST_LOG` env filter
/// falling back to `level` (e.g. `"info"`). Uses `try_init`, so a second call
/// (or a test that already installed a subscriber) is a no-op rather than a
/// panic; returns `false` when a subscriber was already installed.
pub fn init_logging(level: &str, redactor: Redactor) -> bool {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let make_writer = RedactingMakeWriter::new(io::stdout, redactor);

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_writer(make_writer)
        .finish();

    tracing::subscriber::set_global_default(subscriber).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A `MakeWriter` capturing everything written into a shared buffer.
    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufHandle;
        fn make_writer(&'a self) -> Self::Writer {
            BufHandle(self.0.clone())
        }
    }

    struct BufHandle(Arc<Mutex<Vec<u8>>>);
    impl Write for BufHandle {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_redacts_secrets_before_the_sink_sees_them() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let redactor = Redactor::new();
        redactor.register_secret("topsecret");
        let mw = RedactingMakeWriter::new(BufWriter(buf.clone()), redactor);

        let mut w = mw.make_writer();
        // A URL-shaped query param (boundary-matched) plus a registered secret
        // value embedded in free text: both must be scrubbed at the writer.
        write!(
            w,
            "GET /proxy/stream?token=abc123 logged in with topsecret value"
        )
        .unwrap();

        let written = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(!written.contains("topsecret"), "registered secret leaked: {written}");
        assert!(!written.contains("token=abc123"), "token param leaked: {written}");
        assert!(written.contains("[REDACTED]"));
    }

    #[test]
    fn writer_reports_full_length_consumed() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mw = RedactingMakeWriter::new(BufWriter(buf), Redactor::new());
        let mut w = mw.make_writer();
        // Even when redaction changes the byte count, the writer reports the
        // original input length so the fmt layer treats it as fully written.
        let input = b"/x?token=secret";
        let n = w.write(input).unwrap();
        assert_eq!(n, input.len());
    }
}
