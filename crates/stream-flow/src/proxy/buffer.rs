//! Adaptive + jitter buffer (`proxy::buffer`) — Req 37.3, 37.11, 35.1, 5.7.
//!
//! [`AdaptiveJitterBuffer`] is the bounded ring buffer that sits between the
//! upstream body (the *reader*, which fills the buffer ahead of playback) and
//! the client writer (the *drainer*, which empties it at the client's pace). It
//! does two jobs for the streaming core (design: Components → Adaptive + jitter
//! buffer):
//!
//! * **Adaptive sizing (Req 37.3).** The read/refill chunk size is the larger
//!   *initial* size (default 512 KiB) while the delivered playback offset is
//!   below the *initial window* (default 2 MiB) — so playback *starts* smoothly
//!   — then drops to the *steady* size (default 256 KiB) for the remainder.
//!   [`AdaptiveJitterBuffer::active_size`] / [`AdaptiveJitterBuffer::size_at`]
//!   expose that decision.
//!
//! * **Jitter absorption (Req 37.11).** The reader pushes upstream bytes as
//!   they arrive — bursty, variable-bitrate, slow-CDN timing — while the writer
//!   pulls a steady amount toward the client. The ring decouples the two so the
//!   client sees a steady byte flow even when the source is jittery.
//!
//! The ring is **bounded**: its capacity is `max(initial_size, steady_size)`,
//! so it holds at most one larger-chunk's worth of bytes and total memory is
//! independent of the total stream size (Req 35.1, 5.7) — the buffer is the
//! *only* in-memory copy of the body, satisfying the 512 MB-VPS constraint.
//! [`AdaptiveJitterBuffer::push`] only accepts what currently fits and returns
//! the unaccepted tail as backpressure, so the reader can never push the buffer
//! past its capacity.
//!
//! This type is pure, synchronous, and I/O-free: it is the data structure the
//! async streaming core (task 14.2) and the [`ResilientStream`](super) drive,
//! so its sizing and bounding invariants are verified here in isolation (the
//! adaptive-sizing property is task 13.7 / Property 5).

use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};

use crate::config::PrebufferConfig;

/// A bounded ring buffer with offset-driven adaptive refill sizing and jitter
/// absorption between an upstream reader and a client writer (design:
/// Components → Adaptive + jitter buffer; Req 37.3, 37.11, 35.1, 5.7).
///
/// Bytes enter via [`push`](Self::push) (the reader, filling ahead) and leave
/// via [`pull`](Self::pull) (the writer, draining at the client's pace),
/// strictly FIFO. The amount of *buffered* data never exceeds
/// [`capacity`](Self::capacity) = `max(initial_size, steady_size)`, regardless
/// of how many total bytes flow through, which is what bounds peak memory
/// independently of stream length (Req 35.1, 5.7).
#[derive(Debug)]
pub struct AdaptiveJitterBuffer {
    /// The larger refill chunk size used for the first `initial_window` bytes
    /// to smooth playback start (default 512 KiB, Req 37.3).
    initial_size: usize,
    /// The steady-state refill chunk size used after the initial window
    /// (default 256 KiB, Req 37.3).
    steady_size: usize,
    /// The delivered-offset threshold (default 2 MiB, Req 37.3) below which the
    /// initial size is used and at/above which the steady size is used.
    initial_window: u64,
    /// The hard upper bound on buffered bytes: `max(initial_size, steady_size)`.
    /// This is the peak-memory bound (Req 35.1, 5.7).
    capacity: usize,
    /// The queued, not-yet-delivered chunks (zero-copy `Bytes` views), oldest
    /// first. The sum of their lengths is [`buffered`](Self::buffered).
    queue: VecDeque<Bytes>,
    /// Running sum of `queue` chunk lengths, kept in step with push/pull so
    /// `buffered`/`free_space` are O(1).
    buffered: usize,
    /// Total bytes drained toward the client — i.e. the current playback
    /// offset that drives adaptive sizing (Req 37.3).
    delivered: u64,
}

impl AdaptiveJitterBuffer {
    /// Build a buffer from explicit sizes.
    ///
    /// `capacity` is derived as `max(initial_size, steady_size)` so the ring
    /// can always hold one full refill chunk while still bounding peak memory
    /// by the larger configured size (Req 35.1, 5.7).
    pub fn new(initial_size: usize, steady_size: usize, initial_window: u64) -> Self {
        Self {
            initial_size,
            steady_size,
            initial_window,
            capacity: initial_size.max(steady_size),
            queue: VecDeque::new(),
            buffered: 0,
            delivered: 0,
        }
    }

    /// Build a buffer from the [`PrebufferConfig`] tunables (Req 37.3).
    pub fn from_config(cfg: &PrebufferConfig) -> Self {
        Self::new(
            cfg.initial_buffer_bytes,
            cfg.steady_buffer_bytes,
            cfg.initial_window_bytes as u64,
        )
    }

    /// The peak-memory bound: the most bytes the ring will ever hold,
    /// `max(initial_size, steady_size)` (Req 35.1, 5.7).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of bytes currently buffered (filled but not yet drained).
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// The remaining free space the reader may fill, `capacity - buffered`.
    pub fn free_space(&self) -> usize {
        self.capacity - self.buffered
    }

    /// Whether the buffer holds no undelivered bytes.
    pub fn is_empty(&self) -> bool {
        self.buffered == 0
    }

    /// Whether the buffer is at capacity (the reader must wait for the writer
    /// to drain before more can be accepted).
    pub fn is_full(&self) -> bool {
        self.buffered == self.capacity
    }

    /// The current playback offset: total bytes delivered toward the client.
    pub fn delivered_offset(&self) -> u64 {
        self.delivered
    }

    /// The active refill chunk size for an arbitrary delivered `offset`
    /// (Req 37.3): the initial size while `offset < initial_window`, the steady
    /// size at or beyond it.
    pub fn size_at(&self, offset: u64) -> usize {
        if offset < self.initial_window {
            self.initial_size
        } else {
            self.steady_size
        }
    }

    /// The active refill chunk size for the *current* playback offset
    /// (Req 37.3). Equivalent to `size_at(delivered_offset())`.
    pub fn active_size(&self) -> usize {
        self.size_at(self.delivered)
    }

    /// How many bytes the reader should fetch next: the [`active_size`] for the
    /// current offset, capped by the available [`free_space`] so a refill can
    /// never push the buffer past its capacity (Req 35.1).
    ///
    /// [`active_size`]: Self::active_size
    /// [`free_space`]: Self::free_space
    pub fn refill_quota(&self) -> usize {
        self.active_size().min(self.free_space())
    }

    /// Fill the buffer with bytes read from upstream, FIFO.
    ///
    /// Accepts only the prefix of `chunk` that fits in the current
    /// [`free_space`](Self::free_space) and returns the unaccepted remainder
    /// (empty when the whole chunk was accepted). Returning the tail is the
    /// backpressure signal: the buffer never grows past [`capacity`](Self::capacity),
    /// so peak memory stays bounded regardless of how fast or how much the
    /// reader supplies (Req 35.1, 5.7). The split is zero-copy.
    pub fn push(&mut self, mut chunk: Bytes) -> Bytes {
        let space = self.free_space();
        if chunk.len() > space {
            // Keep the prefix that fits; hand the rest back to the reader.
            let keep = chunk.split_to(space);
            self.enqueue(keep);
            chunk
        } else {
            self.enqueue(chunk);
            Bytes::new()
        }
    }

    /// Drain up to `max` bytes toward the client at the client's pace, FIFO,
    /// advancing the playback offset (Req 37.11).
    ///
    /// Returns fewer than `max` bytes only when fewer are buffered (including
    /// an empty `Bytes` when the buffer is empty). The returned bytes are the
    /// exact bytes pushed, in order — the buffer never reorders, duplicates, or
    /// drops data.
    pub fn pull(&mut self, max: usize) -> Bytes {
        let take = max.min(self.buffered);
        if take == 0 {
            return Bytes::new();
        }

        // Fast path: the whole request comes from the front chunk — a zero-copy
        // split, no concatenation.
        let front_len = self.queue.front().map(Bytes::len).unwrap_or(0);
        let out = if front_len >= take {
            let front = self.queue.front_mut().expect("non-empty queue");
            let taken = front.split_to(take);
            if front.is_empty() {
                self.queue.pop_front();
            }
            taken
        } else {
            // Spanning multiple chunks: concatenate into one contiguous buffer.
            let mut out = BytesMut::with_capacity(take);
            let mut remaining = take;
            while remaining > 0 {
                let front = self.queue.front_mut().expect("buffered bytes accounted");
                if front.len() <= remaining {
                    let whole = self.queue.pop_front().expect("non-empty queue");
                    remaining -= whole.len();
                    out.extend_from_slice(&whole);
                } else {
                    let part = front.split_to(remaining);
                    out.extend_from_slice(&part);
                    remaining = 0;
                }
            }
            out.freeze()
        };

        self.buffered -= take;
        self.delivered += take as u64;
        out
    }

    /// Append a (non-empty) chunk and keep the byte accounting in step.
    fn enqueue(&mut self, chunk: Bytes) {
        if !chunk.is_empty() {
            self.buffered += chunk.len();
            self.queue.push_back(chunk);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: usize = 1024;
    const INITIAL: usize = 512 * KIB;
    const STEADY: usize = 256 * KIB;
    const WINDOW: u64 = 2 * 1024 * 1024;

    fn buffer() -> AdaptiveJitterBuffer {
        AdaptiveJitterBuffer::new(INITIAL, STEADY, WINDOW)
    }

    // -- Adaptive sizing: initial within the window, steady after (Req 37.3) --

    #[test]
    fn size_at_is_initial_below_window_and_steady_at_or_above() {
        let buf = buffer();
        assert_eq!(buf.size_at(0), INITIAL);
        assert_eq!(buf.size_at(1), INITIAL);
        // The byte just inside the window still uses the initial size.
        assert_eq!(buf.size_at(WINDOW - 1), INITIAL);
        // The window boundary flips to the steady size.
        assert_eq!(buf.size_at(WINDOW), STEADY);
        assert_eq!(buf.size_at(WINDOW + 1), STEADY);
        // Arbitrarily deep into a long stream remains steady.
        assert_eq!(buf.size_at(u64::MAX), STEADY);
    }

    #[test]
    fn active_size_tracks_the_delivered_offset_across_the_window_boundary() {
        // Use small sizes so we can actually cross the window by pulling.
        // initial 8, steady 4, window 16 bytes.
        let mut buf = AdaptiveJitterBuffer::new(8, 4, 16);
        assert_eq!(buf.active_size(), 8);

        // Deliver up to (but not past) the window — still the initial size.
        feed_and_drain(&mut buf, 15);
        assert_eq!(buf.delivered_offset(), 15);
        assert_eq!(buf.active_size(), 8);

        // Cross the window boundary — now the steady size.
        feed_and_drain(&mut buf, 1);
        assert_eq!(buf.delivered_offset(), 16);
        assert_eq!(buf.active_size(), 4);

        feed_and_drain(&mut buf, 100);
        assert_eq!(buf.active_size(), 4);
    }

    #[test]
    fn refill_quota_is_active_size_capped_by_free_space() {
        let mut buf = AdaptiveJitterBuffer::new(8, 4, 16);
        // Empty buffer below the window: a full initial chunk fits.
        assert_eq!(buf.free_space(), 8);
        assert_eq!(buf.refill_quota(), 8);

        // Partially filled: quota shrinks to the remaining space.
        buf.push(Bytes::from_static(&[0u8; 5]));
        assert_eq!(buf.free_space(), 3);
        assert_eq!(buf.refill_quota(), 3);

        // Full: nothing more may be fetched until the writer drains.
        buf.push(Bytes::from_static(&[0u8; 3]));
        assert!(buf.is_full());
        assert_eq!(buf.refill_quota(), 0);
    }

    // -- Capacity is the larger configured size (Req 35.1, 5.7) --------------

    #[test]
    fn capacity_is_the_larger_of_the_two_sizes() {
        assert_eq!(buffer().capacity(), INITIAL);
        // Even when steady is (pathologically) larger, capacity is the max.
        assert_eq!(AdaptiveJitterBuffer::new(100, 300, 16).capacity(), 300);
    }

    #[test]
    fn from_config_uses_the_prebuffer_tunables() {
        let buf = AdaptiveJitterBuffer::from_config(&PrebufferConfig::default());
        assert_eq!(buf.size_at(0), 512 * KIB);
        assert_eq!(buf.size_at(2 * 1024 * 1024), 256 * KIB);
        assert_eq!(buf.capacity(), 512 * KIB);
    }

    // -- Bounded peak memory regardless of stream length (Req 35.1, 5.7) -----

    #[test]
    fn push_only_accepts_what_fits_and_returns_the_remainder() {
        let mut buf = AdaptiveJitterBuffer::new(8, 4, 16); // capacity 8
        let remainder = buf.push(Bytes::from(vec![1u8; 20]));
        // Only 8 bytes were accepted; the buffer is full and bounded.
        assert_eq!(buf.buffered(), 8);
        assert!(buf.is_full());
        // The unaccepted 12 bytes are handed back as backpressure.
        assert_eq!(remainder.len(), 12);

        // A push into a full buffer accepts nothing and returns it all.
        let again = buf.push(Bytes::from(vec![2u8; 5]));
        assert_eq!(buf.buffered(), 8);
        assert_eq!(again.len(), 5);
    }

    #[test]
    fn peak_memory_is_bounded_by_capacity_over_a_long_stream() {
        // Stream far more than capacity, interleaving steady pulls, and assert
        // the buffered amount never exceeds capacity at any step — peak memory
        // is independent of the total bytes streamed (Req 35.1, 5.7).
        let mut buf = AdaptiveJitterBuffer::new(8, 4, 16); // capacity 8
        let cap = buf.capacity();

        let total: usize = 50 * cap; // a "long" stream relative to the buffer
        let mut produced = 0usize;
        let mut drained = 0usize;
        let mut peak = 0usize;

        while drained < total {
            // Reader fills toward capacity in 6-byte bursts.
            if produced < total {
                let burst = 6.min(total - produced);
                let accepted_before = buf.buffered();
                let remainder = buf.push(Bytes::from(vec![0u8; burst]));
                produced += burst - remainder.len();
                // Re-credit the rejected tail to the producer's backlog.
                let _ = accepted_before; // accounting sanity only
            }
            peak = peak.max(buf.buffered());
            assert!(
                buf.buffered() <= cap,
                "buffered {} exceeded capacity {cap}",
                buf.buffered()
            );

            // Writer drains a steady 4 bytes.
            let got = buf.pull(4);
            drained += got.len();

            // Guard against a stall when nothing can move.
            if got.is_empty() && produced >= total && buf.is_empty() {
                break;
            }
        }

        assert!(peak <= cap, "peak {peak} exceeded capacity {cap}");
        assert_eq!(drained, total);
        assert_eq!(buf.delivered_offset(), total as u64);
    }

    // -- Jitter absorption: bursty fill, steady drain, FIFO integrity (37.11) -

    #[test]
    fn jitter_absorption_preserves_byte_order_under_variable_timing() {
        // A reader that supplies bytes in irregular bursts (variable-bitrate /
        // slow-CDN jitter) and a writer that drains a steady amount must yield
        // the exact source bytes, in order — the ring smooths the timing
        // without reordering, duplicating, or dropping anything (Req 37.11).
        let mut buf = AdaptiveJitterBuffer::new(16, 8, 32); // capacity 16

        // Distinct byte pattern so order/identity is observable.
        let input: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

        // Irregular burst sizes cycled to simulate jittery arrival.
        let bursts = [1usize, 7, 3, 31, 0, 13, 2, 64, 5];
        let mut burst_idx = 0;
        let mut backlog: Vec<u8> = Vec::new(); // not-yet-accepted producer bytes
        let mut src = 0usize; // next source index to enqueue into backlog
        let mut output: Vec<u8> = Vec::new();

        while output.len() < input.len() {
            // Produce a (variable) burst into the backlog.
            if src < input.len() {
                let n = bursts[burst_idx % bursts.len()].min(input.len() - src);
                burst_idx += 1;
                backlog.extend_from_slice(&input[src..src + n]);
                src += n;
            }

            // Push as much of the backlog as currently fits; keep the remainder.
            if !backlog.is_empty() {
                let remainder = buf.push(Bytes::from(std::mem::take(&mut backlog)));
                backlog = remainder.to_vec();
            }

            // The bound holds at every step.
            assert!(buf.buffered() <= buf.capacity());

            // Writer drains a steady 5 bytes.
            let got = buf.pull(5);
            output.extend_from_slice(&got);
        }

        assert_eq!(output, input, "jitter buffer must preserve the byte stream");
        assert_eq!(buf.delivered_offset(), input.len() as u64);
    }

    #[test]
    fn pull_spanning_multiple_chunks_concatenates_in_order() {
        let mut buf = AdaptiveJitterBuffer::new(64, 32, 1024);
        buf.push(Bytes::from_static(b"abc"));
        buf.push(Bytes::from_static(b"de"));
        buf.push(Bytes::from_static(b"fghij"));
        // One pull larger than any single chunk stitches them together.
        let got = buf.pull(7);
        assert_eq!(&got[..], b"abcdefg");
        // The rest remains, in order.
        let rest = buf.pull(100);
        assert_eq!(&rest[..], b"hij");
        assert!(buf.is_empty());
    }

    #[test]
    fn pull_on_empty_buffer_yields_no_bytes() {
        let mut buf = buffer();
        assert!(buf.pull(1024).is_empty());
        assert_eq!(buf.delivered_offset(), 0);
    }

    #[test]
    fn push_of_empty_chunk_is_a_noop() {
        let mut buf = buffer();
        let remainder = buf.push(Bytes::new());
        assert!(remainder.is_empty());
        assert!(buf.is_empty());
    }

    /// Fill then fully drain exactly `n` bytes, advancing the delivered offset
    /// by `n`. Used to march the playback offset across the adaptive-window
    /// boundary in the sizing tests.
    fn feed_and_drain(buf: &mut AdaptiveJitterBuffer, n: usize) {
        let mut backlog = vec![0u8; n];
        let mut delivered = 0usize;
        while delivered < n {
            if !backlog.is_empty() {
                let remainder = buf.push(Bytes::from(std::mem::take(&mut backlog)));
                backlog = remainder.to_vec();
            }
            let got = buf.pull(n - delivered);
            delivered += got.len();
            if got.is_empty() && backlog.is_empty() {
                break;
            }
        }
    }
}
