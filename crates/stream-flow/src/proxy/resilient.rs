//! ResilientStream state machine (`proxy::resilient`) — Req 37.4, 37.5, 37.6,
//! 37.9, 5.8.
//!
//! [`ResilientStream`] is the reconnect-with-resume + link-renewal
//! streaming-core state machine that wraps a re-issuable
//! [`UpstreamSource`](super::UpstreamSource) for Stremio delivery (design:
//! Components → ResilientStream state machine). It is the capability that makes
//! drop-recovery (Req 37.5) and transparent link renewal (Req 37.6) possible —
//! neither source project had it.
//!
//! ## The machine (design: Components → ResilientStream state machine)
//!
//! ```text
//! [*] -> Opening
//! Opening    -> Streaming    : 200/206 + first bytes
//! Opening    -> Renewing     : 401/403/410 (link expired)
//! Opening    -> Failed       : non-retryable
//! Streaming  -> Reconnecting : upstream read error / drop
//! Streaming  -> Seeking      : client issued a new Range
//! Streaming  -> [*]          : completed / client closed
//! Reconnecting -> Streaming  : reopened at last_delivered_offset
//! Reconnecting -> Renewing   : reopen reports auth expiry
//! Reconnecting -> Failed     : retries exhausted (3)               (Req 37.5)
//! Renewing   -> Reconnecting : link renewed -> reopen at offset    (Req 37.6)
//! Renewing   -> Failed       : renew failed AND no fallback store  (Req 37.7)
//! Seeking    -> Streaming    : reopened at seek offset (<=500ms)   (Req 37.4)
//! ```
//!
//! ## Invariants
//!
//! * [`last_delivered_offset`](ResilientStream::last_delivered_offset)
//!   **monotonically** tracks the absolute byte position delivered to the
//!   client. Reconnection always resumes from exactly this offset, so the
//!   client byte stream is **continuous and gap-free** with no duplication or
//!   reordering across reconnects and renewals (Req 37.5, 37.6). If a
//!   reconnect's upstream ignores the `Range` and replays from an earlier
//!   offset (e.g. a `200` to a ranged request), the overlap is discarded so
//!   resume stays exact.
//! * The mid-stream resume schedule is **exactly 3 attempts** with the fixed,
//!   **un-jittered** backoff [`RESUME_BACKOFF`] = `[100ms, 500ms, 2s]`
//!   (Req 37.5). The control-plane jitter of
//!   [`RetryPolicy`](crate::resilience) governs the inner `renew()`/link-gen
//!   call, not this byte-resume cadence. After exhaustion the machine emits an
//!   [`AppError::upstream_unavailable`], terminates the client response, and
//!   logs (Req 5.8).
//! * A seek aborts the current upstream read (drops the body) and reopens at
//!   the seek offset (Req 37.4).
//! * A client disconnect ([`disconnect`](ResilientStream::disconnect), or
//!   simply dropping the stream) drops the upstream body so the upstream
//!   connection is released immediately (Req 5.8).
//!
//! The machine yields a clean byte stream via
//! [`next_chunk`](ResilientStream::next_chunk); the proxy core (task 14.2)
//! drives it through the [`AdaptiveJitterBuffer`](super::AdaptiveJitterBuffer)
//! for jitter absorption (Req 37.11) and writes it to the client inside a
//! `select!` loop that also watches for client disconnect.
//!
//! Link **renewal** is structured here (the `Renewing` state calls
//! [`UpstreamSource::renew`](super::UpstreamSource::renew) and resumes on
//! success): a plain [`DirectSource`](super::DirectSource) returns the
//! non-renewable signal ([`AppError::is_not_renewable`]) so the machine
//! terminates gracefully, while the debrid-backed source whose `renew()`
//! regenerates the link lands in task 24.2.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;

use crate::errors::AppError;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::{UpstreamBody, UpstreamSource};

/// The fixed, un-jittered mid-stream resume backoff schedule: exactly 3
/// attempts at `100ms`, `500ms`, `2s` (Req 37.5).
pub const RESUME_BACKOFF: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(500),
    Duration::from_secs(2),
];

/// The observable phase of a [`ResilientStream`] (design: Components →
/// ResilientStream state machine).
///
/// `Reconnecting`/`Renewing`/`Seeking` are transient phases entered *within* an
/// `await` (a reconnect/renew/seek routine) and never persist between
/// [`next_chunk`](ResilientStream::next_chunk) calls; `Opening`, `Streaming`,
/// `Completed`, and `Failed` are the phases observable at rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Constructed but not yet opened (or opening the first body).
    Opening,
    /// Actively delivering bytes from an open upstream body.
    Streaming,
    /// Reopening the upstream at `last_delivered_offset` after a drop
    /// (Req 37.5).
    Reconnecting,
    /// Re-resolving an expired upstream link before reopening (Req 37.6).
    Renewing,
    /// Aborting the current read and reopening at a seek offset (Req 37.4).
    Seeking,
    /// The upstream body was fully delivered, or the client disconnected.
    Completed,
    /// Terminated after exhausting reconnection / a non-recoverable failure
    /// (Req 5.8).
    Failed,
}

/// How an upstream open's HTTP status routes the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusClass {
    /// `200`/`206` — deliverable body.
    Success,
    /// `401`/`403`/`410` — the link expired; route to `Renewing` (Req 37.6).
    RenewRequired,
    /// Any other status — non-resumable, terminate.
    Fatal(u16),
}

impl StatusClass {
    fn of(status: u16) -> StatusClass {
        match status {
            200 | 206 => StatusClass::Success,
            401 | 403 | 410 => StatusClass::RenewRequired,
            other => StatusClass::Fatal(other),
        }
    }
}

/// The reconnect-with-resume + link-renewal streaming-core state machine
/// (design: Components → ResilientStream state machine; Req 37.4, 37.5, 37.6,
/// 5.8).
///
/// Wrap a re-issuable [`UpstreamSource`] with [`new`](ResilientStream::new),
/// [`open`](ResilientStream::open) the initial (optionally ranged) body, then
/// pull bytes with [`next_chunk`](ResilientStream::next_chunk) — which
/// transparently reconnects on a drop and renews on an expiry — and
/// [`seek`](ResilientStream::seek) to a new position on a client seek.
pub struct ResilientStream {
    /// The re-issuable upstream the machine reopens on drop / renewal.
    source: Arc<dyn UpstreamSource>,
    /// The current phase.
    state: StreamState,
    /// Absolute byte position of the **next** byte to deliver: bytes
    /// `[start, last_delivered_offset)` have been delivered. The resume point
    /// (Req 37.5, 37.6) and the seek target (Req 37.4).
    last_delivered_offset: u64,
    /// Inclusive end of a bounded request (`Range: bytes=N-M`), so resume
    /// preserves the upper bound and delivery never overshoots it. `None` for
    /// open-ended / full delivery.
    end_bound: Option<u64>,
    /// Bytes still to discard from the front of the open body before delivery,
    /// used to keep resume exact when an upstream replays from before the
    /// resume point (e.g. answers a ranged reopen with a `200`).
    skip_bytes: u64,
    /// The currently open upstream body, if any. Dropping it releases the
    /// upstream connection (the client-disconnect / abort mechanism).
    body: Option<UpstreamBody>,
}

impl ResilientStream {
    /// Wrap an [`UpstreamSource`] in a [`ResilientStream`]. The machine starts
    /// in [`StreamState::Opening`]; call [`open`](Self::open) to fetch the
    /// first body.
    pub fn new(source: Arc<dyn UpstreamSource>) -> Self {
        Self {
            source,
            state: StreamState::Opening,
            last_delivered_offset: 0,
            end_bound: None,
            skip_bytes: 0,
            body: None,
        }
    }

    /// The current observable phase.
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// The absolute byte position of the next byte to deliver — the monotonic
    /// resume point / seek target (Req 37.4, 37.5, 37.6).
    pub fn last_delivered_offset(&self) -> u64 {
        self.last_delivered_offset
    }

    /// Total size if known, delegated to the source (drives `Content-Length` /
    /// `videoSize` / `416`, Req 37.8, 37.12).
    pub fn total_size(&self) -> Option<u64> {
        self.source.total_size()
    }

    /// The resource `Content-Type`, delegated to the source (Req 37.13).
    pub fn content_type(&self) -> Option<&str> {
        self.source.content_type()
    }

    /// Whether range requests are supported, delegated to the source (Req 5.3).
    pub fn accept_ranges(&self) -> bool {
        self.source.accept_ranges()
    }

    /// Open the upstream for the initial [`RangeSpec`] (`Opening` →
    /// `Streaming`, Req 5.1, 5.2).
    ///
    /// On an auth-expiry status the machine renews the link first (`Opening` →
    /// `Renewing`, Req 37.6); a non-resumable status or a connection failure
    /// moves it to [`StreamState::Failed`].
    pub async fn open(&mut self, range: RangeSpec) -> Result<(), AppError> {
        let (start, end_bound, open_spec) = self.plan_range(range);
        self.last_delivered_offset = start;
        self.end_bound = end_bound;
        self.skip_bytes = 0;
        self.state = StreamState::Opening;

        let body = match self.source.open(open_spec).await {
            Ok(body) => body,
            Err(e) => {
                self.state = StreamState::Failed;
                return Err(e);
            }
        };

        match StatusClass::of(body.status) {
            StatusClass::Success => self.install_body(body, start).inspect_err(|_| {
                self.state = StreamState::Failed;
            }),
            StatusClass::RenewRequired => match self.renew_and_reopen(start).await {
                Ok(()) => Ok(()),
                Err(e) => Err(self.fail(e)),
            },
            StatusClass::Fatal(status) => {
                self.state = StreamState::Failed;
                Err(AppError::upstream_unavailable(format!(
                    "upstream returned status {status} on open"
                ))
                .with_upstream_status(status))
            }
        }
    }

    /// Pull the next chunk of bytes, transparently reconnecting on a mid-stream
    /// drop (Req 37.5) and renewing on an expiry (Req 37.6).
    ///
    /// * `Some(Ok(bytes))` — the next contiguous bytes to write to the client.
    /// * `Some(Err(e))` — terminal: reconnection was exhausted or the failure
    ///   is non-recoverable; the client response is terminated and the event
    ///   logged (Req 5.8).
    /// * `None` — the upstream completed normally, or the client disconnected.
    pub async fn next_chunk(&mut self) -> Option<Result<Bytes, AppError>> {
        loop {
            match self.state {
                StreamState::Streaming => {}
                StreamState::Completed | StreamState::Failed => return None,
                StreamState::Opening => {
                    self.state = StreamState::Failed;
                    return Some(Err(AppError::upstream_unavailable(
                        "resilient stream polled before open()",
                    )));
                }
                // Transient phases never persist between calls; treat as done.
                StreamState::Reconnecting | StreamState::Renewing | StreamState::Seeking => {
                    return None;
                }
            }

            let next = match self.body.as_mut() {
                Some(body) => body.stream.next().await,
                None => {
                    self.state = StreamState::Completed;
                    return None;
                }
            };

            match next {
                Some(Ok(chunk)) => {
                    let delivered = self.accept_chunk(chunk);
                    if delivered.is_empty() {
                        // Fully skipped overlap, an empty upstream chunk, or the
                        // bounded end reached — re-evaluate state and loop.
                        continue;
                    }
                    return Some(Ok(delivered));
                }
                Some(Err(_drop)) => {
                    // Mid-stream upstream drop → reconnect from the resume point.
                    match self.reconnect_with_resume().await {
                        Ok(()) => continue,
                        Err(e) => return Some(Err(e)),
                    }
                }
                None => {
                    // Upstream body completed normally.
                    self.state = StreamState::Completed;
                    self.body = None;
                    return None;
                }
            }
        }
    }

    /// Seek to a new absolute byte offset: abort the current read and reopen at
    /// the seek target (`Streaming` → `Seeking` → `Streaming`, Req 37.4).
    pub async fn seek(&mut self, offset: u64) -> Result<(), AppError> {
        // Abort the current upstream read by dropping the body (Req 37.4).
        self.body = None;
        self.skip_bytes = 0;
        self.end_bound = None;
        self.last_delivered_offset = offset;
        self.state = StreamState::Seeking;
        tracing::debug!(offset, "resilient stream seeking");

        let body = match self.source.open(RangeSpec::FromOffset(offset)).await {
            Ok(body) => body,
            Err(e) => return Err(self.fail(e)),
        };

        match StatusClass::of(body.status) {
            StatusClass::Success => self.install_body(body, offset).map_err(|e| self.fail(e)),
            StatusClass::RenewRequired => match self.renew_and_reopen(offset).await {
                Ok(()) => Ok(()),
                Err(e) => Err(self.fail(e)),
            },
            StatusClass::Fatal(status) => {
                let e = AppError::upstream_unavailable(format!(
                    "upstream returned status {status} on seek"
                ))
                .with_upstream_status(status);
                Err(self.fail(e))
            }
        }
    }

    /// The client disconnected: drop the upstream body so the upstream
    /// connection is released immediately, and move to a terminal state
    /// (Req 5.8). Dropping the [`ResilientStream`] itself does the same.
    pub fn disconnect(&mut self) {
        self.body = None;
        self.state = StreamState::Completed;
    }

    // -- internals ----------------------------------------------------------

    /// Resolve a [`RangeSpec`] into `(start_offset, end_bound, open_spec)`.
    ///
    /// A suffix range is resolved against the source's known total size so the
    /// resume point and upper bound are absolute; when the total is unknown the
    /// suffix is opened as-is and resume falls back to offset `0`.
    fn plan_range(&self, range: RangeSpec) -> (u64, Option<u64>, RangeSpec) {
        match range {
            RangeSpec::Full => (0, None, RangeSpec::Full),
            RangeSpec::FromOffset(n) => (n, None, RangeSpec::FromOffset(n)),
            RangeSpec::Inclusive(n, m) => (n, Some(m), RangeSpec::Inclusive(n, m)),
            RangeSpec::Suffix(n) => match self.source.total_size() {
                Some(total) if total > 0 => {
                    let effective = n.min(total);
                    let start = total - effective;
                    (
                        start,
                        Some(total - 1),
                        RangeSpec::Inclusive(start, total - 1),
                    )
                }
                _ => (0, None, RangeSpec::Suffix(n)),
            },
        }
    }

    /// The range to reopen at for resume: the bounded `Inclusive` form when an
    /// end bound is set (so we never re-deliver past it), else open-ended.
    fn resume_range(&self) -> RangeSpec {
        match self.end_bound {
            Some(end) => RangeSpec::Inclusive(self.last_delivered_offset, end),
            None => RangeSpec::FromOffset(self.last_delivered_offset),
        }
    }

    /// Install a freshly opened body as the active stream, computing the skip
    /// needed to keep resume exact (`Streaming`).
    fn install_body(&mut self, body: UpstreamBody, requested_offset: u64) -> Result<(), AppError> {
        // Where do the body's bytes actually begin? A 206 reports it via
        // Content-Range; a 200 (range ignored) begins at byte 0.
        let actual_start = match body.content_range {
            Some(cr) => cr.start,
            None if body.status == 206 => requested_offset,
            None => 0,
        };
        if actual_start > requested_offset {
            // The upstream skipped *ahead* of our resume point — accepting this
            // would leave a gap, so it is non-recoverable.
            return Err(AppError::upstream_unavailable(format!(
                "upstream resumed at offset {actual_start} beyond resume point {requested_offset}"
            )));
        }
        self.skip_bytes = requested_offset - actual_start;
        self.body = Some(body);
        self.state = StreamState::Streaming;
        Ok(())
    }

    /// Trim an incoming chunk against the resume-skip and the bounded end, and
    /// advance the delivered offset by what is actually delivered.
    fn accept_chunk(&mut self, mut chunk: Bytes) -> Bytes {
        // Discard any resume overlap (bytes before the resume point).
        if self.skip_bytes > 0 {
            let drop = (self.skip_bytes as usize).min(chunk.len());
            let _ = chunk.split_to(drop);
            self.skip_bytes -= drop as u64;
            if chunk.is_empty() {
                return chunk;
            }
        }

        // Never deliver past a bounded range's inclusive end.
        if let Some(end) = self.end_bound {
            if self.last_delivered_offset > end {
                self.state = StreamState::Completed;
                self.body = None;
                return Bytes::new();
            }
            let max_len = (end - self.last_delivered_offset + 1) as usize;
            if chunk.len() > max_len {
                chunk.truncate(max_len);
            }
        }

        self.last_delivered_offset += chunk.len() as u64;

        if let Some(end) = self.end_bound {
            if self.last_delivered_offset > end {
                // The inclusive end has been delivered — done.
                self.state = StreamState::Completed;
                self.body = None;
            }
        }

        chunk
    }

    /// Reopen the upstream at the resume point with the fixed 3-attempt backoff
    /// (Req 37.5). On an auth-expiry reopen, route through renewal (Req 37.6).
    /// After exhaustion, terminate and log (Req 5.8).
    async fn reconnect_with_resume(&mut self) -> Result<(), AppError> {
        // Drop the broken body up front so the dead connection is released.
        self.body = None;
        let offset = self.last_delivered_offset;
        let mut last_err: Option<AppError> = None;

        for (attempt, delay) in RESUME_BACKOFF.iter().enumerate() {
            self.state = StreamState::Reconnecting;
            tracing::debug!(
                attempt = attempt + 1,
                offset,
                "resilient stream reconnecting after upstream drop"
            );
            tokio::time::sleep(*delay).await;

            match self.source.open(self.resume_range()).await {
                Ok(body) => match StatusClass::of(body.status) {
                    StatusClass::Success => {
                        return self.install_body(body, offset).map_err(|e| self.fail(e));
                    }
                    StatusClass::RenewRequired => match self.renew_and_reopen(offset).await {
                        Ok(()) => return Ok(()),
                        // A source that can never renew (e.g. a DirectSource)
                        // is terminal — do not burn the remaining attempts.
                        Err(e) if e.is_not_renewable() => return Err(self.fail(e)),
                        Err(e) => last_err = Some(e),
                    },
                    StatusClass::Fatal(status) => {
                        let e = AppError::upstream_unavailable(format!(
                            "upstream returned non-resumable status {status} on reconnect"
                        ))
                        .with_upstream_status(status);
                        return Err(self.fail(e));
                    }
                },
                Err(e) => last_err = Some(e),
            }
        }

        let cause = last_err.unwrap_or_else(|| {
            AppError::upstream_unavailable("resilient resume exhausted with no upstream response")
        });
        Err(self.fail(cause))
    }

    /// Re-resolve an expired link then reopen at `offset` (`Renewing` →
    /// `Reconnecting` → `Streaming`, Req 37.6). The non-renewable signal and
    /// any renew error propagate to the caller.
    async fn renew_and_reopen(&mut self, offset: u64) -> Result<(), AppError> {
        self.state = StreamState::Renewing;
        tracing::debug!(offset, "resilient stream renewing expired upstream link");
        self.source.renew().await?;

        // Link renewed — reopen at the resume point.
        self.state = StreamState::Reconnecting;
        let body = self.source.open(self.resume_range()).await?;
        match StatusClass::of(body.status) {
            StatusClass::Success => self.install_body(body, offset),
            StatusClass::RenewRequired => Err(AppError::upstream_unavailable(
                "upstream link still rejected after renewal",
            )),
            StatusClass::Fatal(status) => Err(AppError::upstream_unavailable(format!(
                "upstream returned status {status} after renewal"
            ))
            .with_upstream_status(status)),
        }
    }

    /// Move to [`StreamState::Failed`], drop the body, log, and produce the
    /// terminal [`AppError::upstream_unavailable`] (Req 5.8).
    fn fail(&mut self, cause: AppError) -> AppError {
        self.state = StreamState::Failed;
        self.body = None;
        let mut err = AppError::upstream_unavailable(format!(
            "resilient stream terminated at offset {} after exhausting reconnection: {}",
            self.last_delivered_offset, cause.message
        ));
        if let Some(status) = cause.upstream_status {
            err = err.with_upstream_status(status);
        }
        tracing::warn!(
            offset = self.last_delivered_offset,
            category = %err.category,
            "resilient stream terminated and client response closed: {}",
            err.message
        );
        err
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use crate::proxy::range::RangeSpec;
    use crate::proxy::source::{ContentRange, UpstreamBody, UpstreamSource};

    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::StreamExt;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Sets its flag on drop so a test can prove that dropping an
    /// [`UpstreamBody`] released the upstream connection (Req 5.8).
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// One scripted upstream open outcome.
    #[derive(Clone)]
    enum Episode {
        /// The open succeeds with `status`; the body emits `deliver` bytes
        /// (`None` = to the end of the data) in `chunk_size` pieces, then
        /// either errors mid-stream (`drop_after`) or completes.
        Body {
            status: u16,
            chunk_size: usize,
            deliver: Option<usize>,
            drop_after: bool,
        },
        /// The open itself fails with a connection-style error.
        OpenError,
    }

    /// The absolute byte offset a given range opens at (for the mock body).
    fn start_of(range: &RangeSpec, total: u64) -> u64 {
        match *range {
            RangeSpec::Full => 0,
            RangeSpec::FromOffset(n) => n,
            RangeSpec::Inclusive(n, _) => n,
            RangeSpec::Suffix(n) => total.saturating_sub(n),
        }
    }

    /// A fully scriptable [`UpstreamSource`] over an in-memory byte vector.
    ///
    /// Each [`open`](UpstreamSource::open) consumes the next [`Episode`] from
    /// the script, records the requested range + a virtual timestamp (for
    /// backoff-timing assertions), and (for a `200`) deliberately *ignores* the
    /// requested range — replaying from byte 0 — so the resume-overlap logic is
    /// exercised.
    struct MockSource {
        data: Vec<u8>,
        total: Option<u64>,
        content_type: Option<String>,
        accept_ranges: bool,
        renewable: bool,
        script: Mutex<VecDeque<Episode>>,
        open_calls: Mutex<Vec<(RangeSpec, tokio::time::Instant)>>,
        renew_calls: AtomicUsize,
        /// One drop flag per body handed out, in creation order.
        body_drops: Mutex<Vec<Arc<AtomicBool>>>,
    }

    impl MockSource {
        fn new(data: Vec<u8>) -> Self {
            let total = Some(data.len() as u64);
            Self {
                data,
                total,
                content_type: Some("video/mp4".to_string()),
                accept_ranges: true,
                renewable: false,
                script: Mutex::new(VecDeque::new()),
                open_calls: Mutex::new(Vec::new()),
                renew_calls: AtomicUsize::new(0),
                body_drops: Mutex::new(Vec::new()),
            }
        }

        fn with_script(self, episodes: Vec<Episode>) -> Self {
            *self.script.lock().unwrap() = episodes.into();
            self
        }

        fn renewable(mut self) -> Self {
            self.renewable = true;
            self
        }

        fn open_count(&self) -> usize {
            self.open_calls.lock().unwrap().len()
        }

        fn renew_count(&self) -> usize {
            self.renew_calls.load(Ordering::SeqCst)
        }

        /// `true` once the body at `idx` (in creation order) was dropped.
        fn body_dropped(&self, idx: usize) -> bool {
            self.body_drops.lock().unwrap()[idx].load(Ordering::SeqCst)
        }

        fn body_count(&self) -> usize {
            self.body_drops.lock().unwrap().len()
        }

        fn make_body(
            &self,
            range: &RangeSpec,
            status: u16,
            chunk_size: usize,
            deliver: Option<usize>,
            drop_after: bool,
        ) -> UpstreamBody {
            let total = self.data.len() as u64;
            // A 200 ignores the requested range and replays from byte 0; a 206
            // honours it.
            let body_start = if status == 200 {
                0
            } else {
                start_of(range, total)
            } as usize;
            let body_start = body_start.min(self.data.len());
            let slice = &self.data[body_start..];

            let deliver = deliver.unwrap_or(slice.len()).min(slice.len());
            let chunk_size = chunk_size.max(1);
            let mut items: Vec<Result<Bytes, AppError>> = Vec::new();
            let mut i = 0;
            while i < deliver {
                let end = (i + chunk_size).min(deliver);
                items.push(Ok(Bytes::copy_from_slice(&slice[i..end])));
                i = end;
            }
            if drop_after {
                items.push(Err(AppError::upstream_unavailable("mock upstream drop")));
            }

            let content_range = if status == 206 {
                Some(ContentRange {
                    start: body_start as u64,
                    end: total.saturating_sub(1),
                    total: Some(total),
                })
            } else {
                None
            };

            let flag = Arc::new(AtomicBool::new(false));
            self.body_drops.lock().unwrap().push(flag.clone());
            let guard = DropFlag(flag);
            let stream = futures::stream::iter(items).map(move |it| {
                let _ = &guard;
                it
            });

            UpstreamBody {
                status,
                content_length: Some(slice.len() as u64),
                content_range,
                content_type: self.content_type.clone(),
                accept_ranges: status == 206 || self.accept_ranges,
                stream: Box::pin(stream),
            }
        }
    }

    #[async_trait]
    impl UpstreamSource for MockSource {
        fn total_size(&self) -> Option<u64> {
            self.total
        }
        fn content_type(&self) -> Option<&str> {
            self.content_type.as_deref()
        }
        fn accept_ranges(&self) -> bool {
            self.accept_ranges
        }

        async fn open(&self, range: RangeSpec) -> Result<UpstreamBody, AppError> {
            self.open_calls
                .lock()
                .unwrap()
                .push((range, tokio::time::Instant::now()));
            let ep = self.script.lock().unwrap().pop_front();
            match ep {
                Some(Episode::OpenError) => Err(AppError::upstream_unavailable("mock open error")),
                Some(Episode::Body {
                    status,
                    chunk_size,
                    deliver,
                    drop_after,
                }) => Ok(self.make_body(&range, status, chunk_size, deliver, drop_after)),
                None => Err(AppError::upstream_unavailable("mock script exhausted")),
            }
        }

        async fn renew(&self) -> Result<(), AppError> {
            self.renew_calls.fetch_add(1, Ordering::SeqCst);
            if self.renewable {
                Ok(())
            } else {
                Err(AppError::not_renewable())
            }
        }
    }

    fn body(status: u16, chunk_size: usize, deliver: Option<usize>, drop_after: bool) -> Episode {
        Episode::Body {
            status,
            chunk_size,
            deliver,
            drop_after,
        }
    }

    /// Drain a stream to completion, asserting `last_delivered_offset` is
    /// monotonically non-decreasing across every chunk (Req 37.5).
    async fn drain_monotonic(stream: &mut ResilientStream) -> Result<Vec<u8>, AppError> {
        let mut out = Vec::new();
        let mut prev = stream.last_delivered_offset();
        while let Some(item) = stream.next_chunk().await {
            let chunk = item?;
            let now = stream.last_delivered_offset();
            assert!(
                now >= prev,
                "last_delivered_offset regressed: {now} < {prev}"
            );
            // Each delivered chunk advances the offset by exactly its length.
            assert_eq!(
                now - prev,
                chunk.len() as u64,
                "offset advance must equal bytes delivered"
            );
            prev = now;
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    // -- last_delivered_offset is monotonic and reaches the total (Req 37.5) -

    #[tokio::test]
    async fn last_delivered_offset_is_monotonic_and_reaches_total() {
        let data: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let source =
            Arc::new(MockSource::new(data.clone()).with_script(vec![body(206, 33, None, false)]));
        let mut stream = ResilientStream::new(source.clone());
        stream.open(RangeSpec::Full).await.expect("open succeeds");
        assert_eq!(stream.last_delivered_offset(), 0);

        let out = drain_monotonic(&mut stream).await.expect("drain succeeds");
        assert_eq!(out, data, "delivered bytes equal the source");
        assert_eq!(stream.last_delivered_offset(), data.len() as u64);
        assert_eq!(stream.state(), StreamState::Completed);
    }

    // -- reconnection resumes from exactly the last offset, gap-free (Req 37.5)

    #[tokio::test]
    async fn reconnect_resumes_gap_free_no_dup_no_reorder() {
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let source = Arc::new(MockSource::new(data.clone()).with_script(vec![
            // Deliver 40 bytes (in 30-byte chunks) then drop mid-stream.
            body(206, 30, Some(40), true),
            // Resume from offset 40 to the end.
            body(206, 30, None, false),
        ]));
        let mut stream = ResilientStream::new(source.clone());
        stream.open(RangeSpec::Full).await.expect("open succeeds");

        let out = drain_monotonic(&mut stream).await.expect("resume succeeds");
        assert_eq!(
            out, data,
            "resumed stream equals the source exactly (no gap/dup/reorder)"
        );
        assert_eq!(stream.last_delivered_offset(), 100);
        // 1 initial open + 1 resume open.
        assert_eq!(source.open_count(), 2);
    }

    // -- resume stays exact even when the upstream ignores Range (200 replay) -

    #[tokio::test]
    async fn reconnect_with_200_replay_discards_overlap() {
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let source = Arc::new(MockSource::new(data.clone()).with_script(vec![
            // 200: ignores range; delivers 50 bytes from 0 then drops.
            body(200, 30, Some(50), true),
            // 200 again on reopen: replays from 0 — the overlap [0,50) must be
            // discarded so resume stays gap-free.
            body(200, 1000, None, false),
        ]));
        let mut stream = ResilientStream::new(source.clone());
        stream.open(RangeSpec::Full).await.expect("open succeeds");

        let out = drain_monotonic(&mut stream).await.expect("resume succeeds");
        assert_eq!(out, data, "overlap discarded; result equals the source");
        assert_eq!(stream.last_delivered_offset(), 100);
    }

    // -- exactly 3 attempts on fixed [100ms,500ms,2s] backoff, then terminate -
    //    (Req 37.5, 5.8). Uses the paused clock for deterministic timing.

    #[tokio::test(start_paused = true)]
    async fn resume_exhausts_exactly_three_attempts_with_fixed_backoff() {
        let data = vec![7u8; 100];
        let source = Arc::new(MockSource::new(data).with_script(vec![
            // Deliver 40 bytes then drop.
            body(206, 40, Some(40), true),
            // All three resume attempts fail to even open.
            Episode::OpenError,
            Episode::OpenError,
            Episode::OpenError,
        ]));
        let mut stream = ResilientStream::new(source.clone());
        stream.open(RangeSpec::Full).await.expect("open succeeds");

        let start = tokio::time::Instant::now();
        let mut terminal: Option<AppError> = None;
        loop {
            match stream.next_chunk().await {
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    terminal = Some(e);
                    break;
                }
                None => break,
            }
        }

        let err = terminal.expect("must terminate with an error after exhausting retries");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(stream.state(), StreamState::Failed);

        // Exactly 1 initial open + 3 resume attempts.
        let calls = source.open_calls.lock().unwrap();
        assert_eq!(calls.len(), 4, "1 initial open + exactly 3 resume attempts");
        let t0 = calls[0].1;
        let deltas: Vec<Duration> = calls.iter().map(|(_, t)| *t - t0).collect();
        // Cumulative un-jittered schedule: 100ms, +500ms, +2s.
        assert_eq!(deltas[1], Duration::from_millis(100));
        assert_eq!(deltas[2], Duration::from_millis(600));
        assert_eq!(deltas[3], Duration::from_millis(2600));
        // Total resume time is the full 2.6s schedule.
        assert_eq!(
            tokio::time::Instant::now() - start,
            Duration::from_millis(2600)
        );
    }

    // -- seek aborts the current read and reopens at the seek offset (Req 37.4)

    #[tokio::test]
    async fn seek_aborts_current_read_and_reopens_at_offset() {
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let source = Arc::new(MockSource::new(data.clone()).with_script(vec![
            // Initial body would stream the whole thing in 25-byte chunks.
            body(206, 25, None, false),
            // After the seek, a fresh body opens at the seek offset.
            body(206, 25, None, false),
        ]));
        let mut stream = ResilientStream::new(source.clone());
        stream.open(RangeSpec::Full).await.expect("open succeeds");

        // Pull two chunks (50 bytes) then seek away — the rest of body #0 is
        // abandoned.
        let c1 = stream.next_chunk().await.unwrap().unwrap();
        let c2 = stream.next_chunk().await.unwrap().unwrap();
        assert_eq!([c1, c2].concat(), data[0..50]);
        assert_eq!(stream.last_delivered_offset(), 50);

        stream.seek(60).await.expect("seek succeeds");
        assert_eq!(stream.state(), StreamState::Streaming);
        assert_eq!(stream.last_delivered_offset(), 60);
        // The first body was dropped (its read aborted, connection released).
        assert!(
            source.body_dropped(0),
            "seek must abort/drop the current read"
        );

        let rest = drain_monotonic(&mut stream).await.expect("post-seek drain");
        assert_eq!(rest, data[60..100], "delivers exactly from the seek offset");
        assert_eq!(stream.last_delivered_offset(), 100);
    }

    // -- a client disconnect drops the upstream body (Req 5.8) ---------------

    #[tokio::test]
    async fn client_disconnect_drops_upstream_body() {
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let source = Arc::new(MockSource::new(data).with_script(vec![body(206, 10, None, false)]));
        let mut stream = ResilientStream::new(source.clone());
        stream.open(RangeSpec::Full).await.expect("open succeeds");

        // Open the body by pulling one chunk; it is live and not yet dropped.
        let _ = stream.next_chunk().await.unwrap().unwrap();
        assert_eq!(source.body_count(), 1);
        assert!(!source.body_dropped(0), "body live while streaming");

        // Client goes away.
        stream.disconnect();
        assert_eq!(stream.state(), StreamState::Completed);
        assert!(
            source.body_dropped(0),
            "client disconnect must drop the upstream body"
        );
        // No further bytes are produced after disconnect.
        assert!(stream.next_chunk().await.is_none());
    }

    // -- an expired link is renewed transparently, then resumes (Req 37.6) ---

    #[tokio::test(start_paused = true)]
    async fn expired_link_triggers_renew_then_resumes() {
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let source = Arc::new(MockSource::new(data.clone()).renewable().with_script(vec![
            // Deliver 40 bytes then drop.
            body(206, 40, Some(40), true),
            // First reconnect open reports the link expired (410).
            body(410, 1, Some(0), false),
            // After renewal, reopen at offset 40 and finish.
            body(206, 1000, None, false),
        ]));
        let mut stream = ResilientStream::new(source.clone());
        stream.open(RangeSpec::Full).await.expect("open succeeds");

        let out = drain_monotonic(&mut stream)
            .await
            .expect("renew + resume succeeds");
        assert_eq!(
            out, data,
            "renewed stream is gap-free and equals the source"
        );
        assert_eq!(source.renew_count(), 1, "the link was renewed exactly once");
        assert_eq!(stream.state(), StreamState::Completed);
    }

    // -- a non-renewable source terminates on expiry without burning retries -
    //    (Req 37.6 default: DirectSource::renew -> NotRenewable).

    #[tokio::test(start_paused = true)]
    async fn non_renewable_source_terminates_on_expiry() {
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        // Default MockSource is non-renewable (mirrors DirectSource).
        let source = Arc::new(MockSource::new(data).with_script(vec![
            body(206, 40, Some(40), true),
            // Reconnect open reports expiry; renew is unsupported.
            body(410, 1, Some(0), false),
        ]));
        let mut stream = ResilientStream::new(source.clone());
        stream.open(RangeSpec::Full).await.expect("open succeeds");

        let mut terminal: Option<AppError> = None;
        loop {
            match stream.next_chunk().await {
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    terminal = Some(e);
                    break;
                }
                None => break,
            }
        }
        let err = terminal.expect("non-renewable expiry must terminate");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(stream.state(), StreamState::Failed);
        assert_eq!(source.renew_count(), 1, "renew attempted once then gave up");
        // Initial open + a single reconnect attempt (it did not burn all 3).
        assert_eq!(
            source.open_count(),
            2,
            "non-renewable expiry stops immediately"
        );
    }

    // -- a non-resumable status on the initial open fails fast (Req 5.8) -----

    #[tokio::test]
    async fn fatal_status_on_open_moves_to_failed() {
        let data = vec![0u8; 10];
        let source =
            Arc::new(MockSource::new(data).with_script(vec![body(404, 1, Some(0), false)]));
        let mut stream = ResilientStream::new(source.clone());
        let err = stream
            .open(RangeSpec::Full)
            .await
            .expect_err("a 404 open must fail");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(404));
        assert_eq!(stream.state(), StreamState::Failed);
    }

    // -- a bounded (Inclusive) request never delivers past its end ----------

    #[tokio::test]
    async fn bounded_range_stops_at_inclusive_end() {
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let source =
            Arc::new(MockSource::new(data.clone()).with_script(vec![body(206, 1000, None, false)]));
        let mut stream = ResilientStream::new(source.clone());
        // Request bytes [10, 49] — 40 bytes.
        stream
            .open(RangeSpec::Inclusive(10, 49))
            .await
            .expect("open succeeds");
        assert_eq!(stream.last_delivered_offset(), 10);

        let out = drain_monotonic(&mut stream).await.expect("bounded drain");
        assert_eq!(out, data[10..=49], "delivers exactly the inclusive range");
        assert_eq!(stream.last_delivered_offset(), 50);
        assert_eq!(stream.state(), StreamState::Completed);
    }
}
