//! Property-based test for the `ResilientStream` reconnect-with-resume +
//! link-renewal state machine (task 15.2).
//!
//! Feature: ZippyPanther, Property 2
//!
//! **Property 2: Resilient resume yields a gap-free byte stream equal to the
//! source**
//!
//! *For any* source byte vector, *any* (full or ranged) request, *any* chunking,
//! and *any* sequence of injected mid-stream upstream drops — under either the
//! `206` (range-honouring) or the `200` (range-ignoring, replay-from-zero)
//! reopen behaviour, and across transparent link renewals — the bytes
//! [`ResilientStream`] delivers to the client (by repeatedly calling
//! [`ResilientStream::next_chunk`] until completion) are **byte-for-byte equal**
//! to the slice of the source the request asked for, with
//! [`ResilientStream::last_delivered_offset`] **monotonically non-decreasing**
//! and advancing by **exactly** the number of bytes delivered (i.e. the stream
//! is gap-free, with no duplication and no reordering across every reconnect
//! and renewal).
//!
//! **Validates: Requirements 37.5, 37.6, 5.8**
//!
//! * Req 37.5: when an upstream connection drops mid-stream, the system retries
//!   from the last successfully delivered byte position (up to 3 times with
//!   `100ms,500ms,2s` backoff) before returning an error. This property covers
//!   the *success* side of that contract: every injected drop is recovered
//!   within the budget, and recovery resumes from exactly the last delivered
//!   byte so the client byte stream is continuous. (The *exhaustion* side —
//!   terminate-and-log after 3 failed attempts — is covered by the unit tests
//!   in `proxy::resilient`.)
//! * Req 37.6: when a debrid direct link expires during an active stream, the
//!   system transparently re-generates the link and resumes from the current
//!   byte offset without interrupting the client. Modelled here by injecting
//!   `410`-on-reopen at arbitrary drops against a renewable source: the renewal
//!   is invisible in the delivered byte stream.
//! * Req 5.8: a mid-stream interruption is handled (here: recovered) without
//!   corrupting the delivered bytes.
//!
//! ## The unit under test and how the property exercises it
//!
//! The production state machine is the real
//! [`zippy_panther::proxy::ResilientStream`], driven against a fully scriptable
//! in-memory [`UpstreamSource`] ([`ScriptedSource`]) that owns the source bytes
//! and re-issues them on every reopen — exactly the re-issuable-upstream
//! contract the machine is built around. Crucially the mock decides each
//! reopen's behaviour the way a real CDN would and *independently* of the
//! machine, so the test never just mirrors the implementation:
//!
//! * **Drops** are injected at arbitrary absolute offsets (not aligned to the
//!   chunk grid): the body delivers up to the drop offset and then yields a
//!   transport error, which the machine must recover from by reopening at
//!   `last_delivered_offset`.
//! * **`206` vs `200` reopen** is generated per case. A `206` honours the
//!   `Range` (resumes at the requested offset); a `200` *ignores* the `Range`
//!   and replays from byte `0`, forcing the machine's overlap-discard path so
//!   resume stays exact even when the upstream re-sends already-delivered bytes.
//! * **Link renewal** is injected by answering an arbitrary subset of reopens
//!   with `410` once (the link "expired") against a renewable source; the
//!   machine must renew and resume at the same offset, with renewal invisible
//!   in the delivered bytes.
//!
//! Every injected drop is one-shot and strictly ahead of the resume point, so
//! each reconnection makes forward progress and succeeds within the 3-attempt
//! budget — the stream always completes, and the property then asserts the
//! delivered bytes equal `data[window]` exactly, the final offset equals the
//! window end, and the offset advanced by exactly the bytes delivered on every
//! chunk.
//!
//! Each case runs on a per-case **paused** Tokio runtime so the machine's fixed
//! `100ms,500ms,2s` resume backoff advances in virtual time — the property runs
//! its full case count without sleeping on the wall clock.

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use zippy_panther::errors::AppError;
use zippy_panther::proxy::resilient::StreamState;
use zippy_panther::proxy::{
    ContentRange, RangeSpec, ResilientStream, UpstreamBody, UpstreamSource,
};

/// The absolute byte offset at which a reopen of `range` begins delivering, for
/// a resource of size `total`. The machine only ever reopens with
/// `FromOffset`/`Inclusive` (and `Full`/`Suffix` on the initial open), so this
/// mirrors the start each form resolves to.
fn start_of(range: RangeSpec, total: u64) -> u64 {
    match range {
        RangeSpec::Full => 0,
        RangeSpec::FromOffset(n) => n,
        RangeSpec::Inclusive(n, _) => n,
        RangeSpec::Suffix(n) => total.saturating_sub(n),
    }
}

/// The absolute, half-open `[start, end)` slice of the source a request asks
/// for, resolved against `total`. This is the exact byte window
/// [`ResilientStream`] must deliver and the offset its `last_delivered_offset`
/// must end at — computed here independently of the implementation.
fn resolve_window(req: RangeSpec, total: u64) -> (u64, u64) {
    match req {
        RangeSpec::Full => (0, total),
        RangeSpec::FromOffset(n) => (n.min(total), total),
        RangeSpec::Inclusive(n, m) => {
            let start = n.min(total);
            let end = if m >= total { total } else { m + 1 };
            (start, end.max(start))
        }
        RangeSpec::Suffix(k) => {
            let eff = k.min(total);
            (total - eff, total)
        }
    }
}

/// A fully scriptable [`UpstreamSource`] over an in-memory byte vector.
///
/// Each [`open`](UpstreamSource::open) re-issues the source bytes for the
/// requested offset, optionally injecting a one-shot mid-stream drop at the next
/// scripted drop offset, and optionally answering with a one-shot `410` (link
/// expired) to drive renewal. A `206` reopen honours the range; a `200` reopen
/// ignores it and replays from byte `0` (exercising the overlap-discard path).
struct ScriptedSource {
    /// The source bytes, re-issued on every reopen.
    data: Vec<u8>,
    /// `data.len()` — the resource total size.
    total: u64,
    /// How the body is chunked.
    chunk_size: usize,
    /// `true` → reopens answer `200` and replay from byte `0`; `false` → `206`
    /// honouring the requested range.
    status_200: bool,
    /// Remaining one-shot drops as `(absolute offset, renew?)`, strictly
    /// increasing. A body delivers up to the next drop's offset, then errors;
    /// `renew = true` makes the following reopen answer `410` once.
    drops: Mutex<VecDeque<(u64, bool)>>,
    /// Resume offsets at which the next open must answer `410` exactly once.
    pending_renew: Mutex<BTreeSet<u64>>,
    open_calls: AtomicUsize,
    renew_calls: AtomicUsize,
}

impl ScriptedSource {
    fn new(data: Vec<u8>, chunk_size: usize, status_200: bool, drops: Vec<(u64, bool)>) -> Self {
        let total = data.len() as u64;
        Self {
            data,
            total,
            chunk_size: chunk_size.max(1),
            status_200,
            drops: Mutex::new(drops.into()),
            pending_renew: Mutex::new(BTreeSet::new()),
            open_calls: AtomicUsize::new(0),
            renew_calls: AtomicUsize::new(0),
        }
    }

    /// An empty `410` body (link expired) — the byte stream is never consumed;
    /// the machine drops it and routes to renewal (Req 37.6).
    fn renew_required_body(&self) -> UpstreamBody {
        UpstreamBody {
            status: 410,
            content_length: Some(0),
            content_range: None,
            content_type: Some("video/mp4".to_string()),
            accept_ranges: true,
            stream: Box::pin(futures::stream::iter(Vec::<Result<Bytes, AppError>>::new())),
        }
    }

    /// Build a deliverable body that emits `data[body_start..end_excl]` in
    /// `chunk_size` pieces, then (if `error_after`) yields a mid-stream
    /// transport error to simulate a dropped connection.
    fn make_body(&self, body_start: u64, end_excl: u64, error_after: bool) -> UpstreamBody {
        let bs = (body_start as usize).min(self.data.len());
        let ee = (end_excl as usize).min(self.data.len()).max(bs);
        let slice = &self.data[bs..ee];

        let mut items: Vec<Result<Bytes, AppError>> = Vec::new();
        let mut i = 0usize;
        while i < slice.len() {
            let j = (i + self.chunk_size).min(slice.len());
            items.push(Ok(Bytes::copy_from_slice(&slice[i..j])));
            i = j;
        }
        if error_after {
            items.push(Err(AppError::upstream_unavailable(
                "scripted mid-stream drop",
            )));
        }

        let (status, content_range) = if self.status_200 {
            // A 200 ignores the requested range and replays from byte 0.
            (200u16, None)
        } else {
            // A 206 honours the range: it begins at `bs`.
            (
                206u16,
                Some(ContentRange {
                    start: bs as u64,
                    end: self.total.saturating_sub(1),
                    total: Some(self.total),
                }),
            )
        };

        UpstreamBody {
            status,
            content_length: Some(slice.len() as u64),
            content_range,
            content_type: Some("video/mp4".to_string()),
            accept_ranges: true,
            stream: Box::pin(futures::stream::iter(items)),
        }
    }

    fn open_count(&self) -> usize {
        self.open_calls.load(Ordering::SeqCst)
    }

    fn renew_count(&self) -> usize {
        self.renew_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl UpstreamSource for ScriptedSource {
    fn total_size(&self) -> Option<u64> {
        Some(self.total)
    }

    fn content_type(&self) -> Option<&str> {
        Some("video/mp4")
    }

    fn accept_ranges(&self) -> bool {
        true
    }

    async fn open(&self, range: RangeSpec) -> Result<UpstreamBody, AppError> {
        self.open_calls.fetch_add(1, Ordering::SeqCst);
        let resume_point = start_of(range, self.total);

        // A scripted, one-shot link expiry at this resume point (Req 37.6).
        if self.pending_renew.lock().unwrap().remove(&resume_point) {
            return Ok(self.renew_required_body());
        }

        // The body begins at byte 0 for a replaying 200, else at the resume
        // point for a range-honouring 206.
        let body_start = if self.status_200 { 0 } else { resume_point };

        // Fire the next scripted drop strictly ahead of the resume point. Any
        // (defensively) stale drop at-or-before the resume point is discarded.
        let next_drop = {
            let mut dq = self.drops.lock().unwrap();
            while matches!(dq.front(), Some(&(o, _)) if o <= resume_point) {
                dq.pop_front();
            }
            dq.pop_front()
        };

        match next_drop {
            Some((d, renew)) => {
                if renew {
                    // The reopen at `d` must report the link expired once.
                    self.pending_renew.lock().unwrap().insert(d);
                }
                // Deliver up to the drop offset, then error mid-stream.
                Ok(self.make_body(body_start, d, true))
            }
            // No more drops — deliver to the end and complete cleanly.
            None => Ok(self.make_body(body_start, self.total, false)),
        }
    }

    async fn renew(&self) -> Result<(), AppError> {
        self.renew_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Source byte vectors: empty, small, and larger bodies.
fn arb_data() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        2 => prop_vec(any::<u8>(), 0..=64),
        4 => prop_vec(any::<u8>(), 1..=512),
        2 => prop_vec(any::<u8>(), 1..=2_048),
    ]
}

/// Any of the four request forms, with starts constrained to be in-bounds
/// (`<= total`) so the requested window is well-defined; covers full and ranged
/// requests (and beyond-end inclusive ends, which the machine caps at the body
/// end).
fn arb_request(total: u64) -> impl Strategy<Value = RangeSpec> {
    prop_oneof![
        1 => Just(RangeSpec::Full),
        3 => (0u64..=total).prop_map(RangeSpec::FromOffset),
        3 => (0u64..=total).prop_flat_map(move |n| {
            (Just(n), n..=total.saturating_add(8)).prop_map(|(n, m)| RangeSpec::Inclusive(n, m))
        }),
        3 => (0u64..=total.saturating_add(8)).prop_map(RangeSpec::Suffix),
    ]
}

/// One generated scenario: source bytes, the request, the chunking, the reopen
/// status mode, and the injected drops (each `(offset, renew?)`).
#[derive(Debug, Clone)]
struct Case {
    data: Vec<u8>,
    request: RangeSpec,
    chunk_size: usize,
    status_200: bool,
    drops: Vec<(u64, bool)>,
}

/// Drops are absolute offsets strictly inside the requested window
/// `(start, end)` — strictly ahead of the start (so the first segment always
/// delivers at least one new byte) and before the end (so they fall within the
/// delivered range). Sorted and de-duplicated by offset so each is one-shot and
/// strictly increasing.
fn arb_drops(start: u64, end: u64) -> BoxedStrategy<Vec<(u64, bool)>> {
    if end <= start + 1 {
        return Just(Vec::new()).boxed();
    }
    let lo = start + 1;
    let hi = end - 1;
    prop_vec((lo..=hi, any::<bool>()), 0..=8)
        .prop_map(|mut v| {
            v.sort_by_key(|(o, _)| *o);
            v.dedup_by_key(|(o, _)| *o);
            v
        })
        .boxed()
}

fn arb_case() -> impl Strategy<Value = Case> {
    arb_data().prop_flat_map(|data| {
        let total = data.len() as u64;
        arb_request(total).prop_flat_map(move |request| {
            let data = data.clone();
            let (start, end) = resolve_window(request, total);
            (
                Just(data),
                Just(request),
                1usize..=2_048,
                any::<bool>(),
                arb_drops(start, end),
            )
                .prop_map(|(data, request, chunk_size, status_200, drops)| Case {
                    data,
                    request,
                    chunk_size,
                    status_200,
                    drops,
                })
        })
    })
}

/// A per-case **paused** current-thread runtime: the machine's resume backoff
/// sleeps (`100ms,500ms,2s`) advance in virtual time, so the property never
/// sleeps on the wall clock.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("paused current-thread tokio runtime must build")
}

proptest! {
    // 256 cases > the 100-iteration floor for a property task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 2 — resilient resume yields a gap-free
    /// byte stream equal to the source. **Validates: Requirements 37.5, 37.6,
    /// 5.8**
    #[test]
    fn resilient_resume_is_gap_free_and_equals_source(case in arb_case()) {
        let rt = runtime();
        let outcome: Result<(), TestCaseError> = rt.block_on(async move {
            let total = case.data.len() as u64;
            let (win_start, win_end) = resolve_window(case.request, total);
            let expected: Vec<u8> = case.data[win_start as usize..win_end as usize].to_vec();
            let renew_drops = case.drops.iter().filter(|(_, r)| *r).count();

            let source = Arc::new(ScriptedSource::new(
                case.data.clone(),
                case.chunk_size,
                case.status_200,
                case.drops.clone(),
            ));
            let mut stream = ResilientStream::new(source.clone());

            // -- The initial open always yields a deliverable body -----------
            if let Err(e) = stream.open(case.request).await {
                return Err(TestCaseError::fail(format!(
                    "initial open failed for {:?}: {e}",
                    case.request
                )));
            }
            prop_assert_eq!(
                stream.last_delivered_offset(),
                win_start,
                "open must position at the window start for {:?}",
                case.request,
            );

            // -- Drain to completion, asserting the gap-free invariants ------
            let mut out: Vec<u8> = Vec::new();
            let mut prev = stream.last_delivered_offset();
            loop {
                match stream.next_chunk().await {
                    Some(Ok(chunk)) => {
                        let now = stream.last_delivered_offset();
                        // Monotonic non-decreasing (Req 37.5).
                        prop_assert!(
                            now >= prev,
                            "last_delivered_offset regressed: {} < {}",
                            now,
                            prev,
                        );
                        // Advance by exactly the bytes delivered: no gap, no
                        // duplication, no reordering (Req 37.5, 37.6, 5.8).
                        prop_assert_eq!(
                            now - prev,
                            chunk.len() as u64,
                            "offset must advance by exactly the bytes delivered",
                        );
                        prev = now;
                        out.extend_from_slice(&chunk);
                    }
                    Some(Err(e)) => {
                        return Err(TestCaseError::fail(format!(
                            "stream terminated unexpectedly (every drop is recoverable \
                             within budget): {e}"
                        )));
                    }
                    None => break,
                }
            }

            // -- Delivered bytes equal the requested source slice exactly ----
            prop_assert_eq!(
                &out,
                &expected,
                "delivered bytes must equal data[{}..{}] exactly (gap-free, no dup/reorder)",
                win_start,
                win_end,
            );
            prop_assert_eq!(
                stream.last_delivered_offset(),
                win_end,
                "final offset must equal the window end",
            );
            prop_assert_eq!(stream.state(), StreamState::Completed);

            // -- The reopen/renew machinery was actually exercised -----------
            // One open per drop recovery, plus one extra open per renewal, plus
            // the initial open — so at least `1 + drops + renew_drops`.
            let expected_min_opens = 1 + case.drops.len() + renew_drops;
            prop_assert!(
                source.open_count() >= expected_min_opens,
                "expected at least {} opens (1 initial + {} drops + {} renewals), saw {}",
                expected_min_opens,
                case.drops.len(),
                renew_drops,
                source.open_count(),
            );
            prop_assert_eq!(
                source.renew_count(),
                renew_drops,
                "renew must be called exactly once per renew-flagged drop",
            );

            Ok(())
        });
        outcome?;
    }
}
