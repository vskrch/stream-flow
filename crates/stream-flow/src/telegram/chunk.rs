//! Telegram MTProto chunk-range arithmetic (`telegram::chunk`) — Req 11.2,
//! 11.3.
//!
//! This is the single, **pure** place that turns a (resolved, inclusive) byte
//! range `[start, end]` over a known `total_size` into the set of fixed-size
//! download chunks that cover it. MTProto downloads a file in fixed-size
//! aligned chunks (`upload.getFile` with an `offset`/`limit`), so a `Range`
//! request must be served by fetching exactly the chunks the range touches and
//! then slicing each chunk to the requested sub-interval (design: Components →
//! Telegram; Req 11.3).
//!
//! It contains **no** I/O and **no** Telegram client — the parallel-bounded
//! downloader ([`crate::telegram::TelegramDownloader`]) consumes a
//! [`ChunkCoverage`] to decide which chunk indices to fetch and how to slice
//! each fetched chunk, so the arithmetic is verified in isolation here without
//! any live Telegram connection.
//!
//! ## The coverage invariant (Property 48, validated by task 19.4)
//!
//! For any `total_size`, `chunk_size`, and requested byte range, the computed
//! set of chunk indices ([`ChunkCoverage::indices`]) covers **exactly** the
//! bytes of the requested range: every requested byte lies in some selected
//! chunk, and no selected chunk lies entirely outside the requested range.
//! With `first = start / chunk_size` and `last = end / chunk_size`, the set is
//! the contiguous `first..=last`.

use std::ops::RangeInclusive;

/// The default MTProto download chunk size: 1 MiB.
///
/// MTProto requires the `upload.getFile` `limit` to be a multiple of 1 KiB and
/// to evenly divide 1 MiB; 1 MiB satisfies both and keeps the per-chunk
/// round-trip count low for large media (design: Components → Telegram).
pub const DEFAULT_CHUNK_SIZE: u64 = 1024 * 1024;

/// The chunks that cover a resolved, inclusive byte range `[start, end]` over a
/// resource of `total_size` bytes split into `chunk_size`-byte chunks
/// (design: Components → Telegram; Req 11.3).
///
/// Construct with [`chunks_covering`]. A request that selects no bytes (an
/// empty resource, or a start at/after the end) yields an
/// [`is_empty`](ChunkCoverage::is_empty) coverage whose [`indices`] iterator is
/// empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkCoverage {
    /// The total resource size in bytes.
    total_size: u64,
    /// The fixed chunk size in bytes (always ≥ 1).
    chunk_size: u64,
    /// First requested byte offset (inclusive). Meaningless when `empty`.
    start: u64,
    /// Last requested byte offset (inclusive). Meaningless when `empty`.
    end: u64,
    /// `true` when the range selects no bytes.
    empty: bool,
}

impl ChunkCoverage {
    /// An empty coverage over `total_size`/`chunk_size` (selects no bytes, no
    /// chunks).
    pub fn empty(total_size: u64, chunk_size: u64) -> Self {
        Self {
            total_size,
            chunk_size: chunk_size.max(1),
            start: 0,
            end: 0,
            empty: true,
        }
    }

    /// `true` when the coverage selects no bytes (so [`indices`] is empty).
    pub fn is_empty(&self) -> bool {
        self.empty
    }

    /// The total resource size the range was resolved against.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// The fixed chunk size (always ≥ 1).
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// The first requested byte offset (inclusive), or `None` when empty.
    pub fn start(&self) -> Option<u64> {
        (!self.empty).then_some(self.start)
    }

    /// The last requested byte offset (inclusive), or `None` when empty.
    pub fn end(&self) -> Option<u64> {
        (!self.empty).then_some(self.end)
    }

    /// The index of the first chunk the range touches (`start / chunk_size`),
    /// or `None` when empty.
    pub fn first_index(&self) -> Option<u64> {
        (!self.empty).then(|| self.start / self.chunk_size)
    }

    /// The index of the last chunk the range touches (`end / chunk_size`), or
    /// `None` when empty.
    pub fn last_index(&self) -> Option<u64> {
        (!self.empty).then(|| self.end / self.chunk_size)
    }

    /// The number of chunks the range touches.
    pub fn chunk_count(&self) -> u64 {
        match (self.first_index(), self.last_index()) {
            (Some(first), Some(last)) => last - first + 1,
            _ => 0,
        }
    }

    /// The contiguous set of chunk indices that cover the range: `first..=last`
    /// (empty when the coverage selects no bytes) — Req 11.3, Property 48.
    pub fn indices(&self) -> RangeInclusive<u64> {
        match (self.first_index(), self.last_index()) {
            (Some(first), Some(last)) => first..=last,
            // A canonically-empty inclusive range (start > end) yields nothing.
            _ => 1..=0,
        }
    }

    /// The number of bytes chunk `index` *should* contain for this resource:
    /// `chunk_size`, except the final chunk which is the `total_size`
    /// remainder. Used by the downloader to reject a short/over-long fetched
    /// chunk before assembling.
    pub fn expected_chunk_len(&self, index: u64) -> u64 {
        let chunk_abs_start = index.saturating_mul(self.chunk_size);
        if chunk_abs_start >= self.total_size {
            return 0;
        }
        (self.total_size - chunk_abs_start).min(self.chunk_size)
    }

    /// Given chunk `index` was fetched with `actual_len` bytes, return the
    /// `(local_start, local_len)` slice of that chunk that lies within the
    /// requested `[start, end]` range — i.e. the bytes the downloader should
    /// forward to the client. `local_len == 0` means the chunk contributes no
    /// bytes (it lies entirely outside the range).
    pub fn slice_within(&self, index: u64, actual_len: usize) -> (usize, usize) {
        if self.empty {
            return (0, 0);
        }
        let chunk_abs_start = index.saturating_mul(self.chunk_size);
        // Half-open chunk span [chunk_abs_start, chunk_abs_end).
        let chunk_abs_end = chunk_abs_start.saturating_add(actual_len as u64);
        // Half-open requested span [start, end + 1).
        let req_end_excl = self.end + 1;
        let lo = self.start.max(chunk_abs_start);
        let hi = req_end_excl.min(chunk_abs_end);
        if hi <= lo {
            return (0, 0);
        }
        let local_start = (lo - chunk_abs_start) as usize;
        let local_len = (hi - lo) as usize;
        (local_start, local_len)
    }
}

/// Compute the [`ChunkCoverage`] for a resolved, inclusive byte range
/// `[start, end]` over a `total_size`-byte resource split into `chunk_size`
/// chunks (Req 11.3).
///
/// The range is expected to already be satisfiable (as produced by
/// [`RangeSpec::resolve`](crate::proxy::range::RangeSpec::resolve)); this
/// function defensively returns an [empty](ChunkCoverage::empty) coverage —
/// rather than panicking — for a degenerate input (`chunk_size == 0`, an empty
/// resource, `start ≥ total_size`, or `start > end`), and clamps `end` to the
/// last byte of the resource per `Content-Range` semantics.
pub fn chunks_covering(total_size: u64, chunk_size: u64, start: u64, end: u64) -> ChunkCoverage {
    if chunk_size == 0 || total_size == 0 || start >= total_size || start > end {
        return ChunkCoverage::empty(total_size, chunk_size.max(1));
    }
    let end = end.min(total_size - 1);
    ChunkCoverage {
        total_size,
        chunk_size,
        start,
        end,
        empty: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- The contiguous covering set first..=last (Req 11.3) ----------------

    #[test]
    fn single_byte_in_first_chunk_selects_only_chunk_zero() {
        let cov = chunks_covering(10_000, 1000, 0, 0);
        assert_eq!(cov.indices().collect::<Vec<_>>(), vec![0]);
        assert_eq!(cov.chunk_count(), 1);
    }

    #[test]
    fn range_within_one_chunk_selects_only_that_chunk() {
        // bytes 1500-1999 all live in chunk 1 (chunk_size 1000).
        let cov = chunks_covering(10_000, 1000, 1500, 1999);
        assert_eq!(cov.first_index(), Some(1));
        assert_eq!(cov.last_index(), Some(1));
        assert_eq!(cov.indices().collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn range_spanning_multiple_chunks_selects_first_through_last() {
        // bytes 1500-3500 → chunks 1,2,3 (chunk_size 1000).
        let cov = chunks_covering(10_000, 1000, 1500, 3500);
        assert_eq!(cov.first_index(), Some(1));
        assert_eq!(cov.last_index(), Some(3));
        assert_eq!(cov.indices().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(cov.chunk_count(), 3);
    }

    #[test]
    fn range_on_chunk_boundaries_is_exact() {
        // bytes 1000-2999 → exactly chunks 1 and 2.
        let cov = chunks_covering(10_000, 1000, 1000, 2999);
        assert_eq!(cov.indices().collect::<Vec<_>>(), vec![1, 2]);
        // bytes 999-1000 straddles the 0/1 boundary → chunks 0 and 1.
        let cov = chunks_covering(10_000, 1000, 999, 1000);
        assert_eq!(cov.indices().collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test]
    fn full_range_covers_every_chunk_including_partial_last() {
        // 2500-byte resource, 1000-byte chunks → chunks 0,1,2 (2 is partial).
        let cov = chunks_covering(2500, 1000, 0, 2499);
        assert_eq!(cov.indices().collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(cov.expected_chunk_len(0), 1000);
        assert_eq!(cov.expected_chunk_len(1), 1000);
        // The final chunk only holds the 500-byte remainder.
        assert_eq!(cov.expected_chunk_len(2), 500);
    }

    // -- Degenerate inputs are empty, never panic --------------------------

    #[test]
    fn empty_resource_yields_empty_coverage() {
        let cov = chunks_covering(0, 1000, 0, 0);
        assert!(cov.is_empty());
        assert_eq!(cov.indices().collect::<Vec<_>>(), Vec::<u64>::new());
        assert_eq!(cov.chunk_count(), 0);
    }

    #[test]
    fn start_at_or_after_total_is_empty() {
        assert!(chunks_covering(1000, 256, 1000, 1000).is_empty());
        assert!(chunks_covering(1000, 256, 2000, 3000).is_empty());
    }

    #[test]
    fn zero_chunk_size_is_empty_not_a_panic() {
        let cov = chunks_covering(1000, 0, 0, 999);
        assert!(cov.is_empty());
        assert_eq!(cov.chunk_size(), 1, "chunk_size is floored at 1");
    }

    #[test]
    fn end_beyond_total_is_clamped_to_last_byte() {
        // end 9999 clamped to total-1 (1999) → chunks 0 and 1.
        let cov = chunks_covering(2000, 1000, 0, 9999);
        assert_eq!(cov.end(), Some(1999));
        assert_eq!(cov.indices().collect::<Vec<_>>(), vec![0, 1]);
    }

    // -- The coverage invariant by exhaustive check (Property 48 shape) -----

    #[test]
    fn coverage_is_exact_every_byte_in_some_chunk_no_chunk_fully_outside() {
        // Small exhaustive sweep over totals/chunk sizes/ranges asserting the
        // two halves of the coverage invariant directly (the property test in
        // task 19.4 generalizes this with proptest).
        for total in [1u64, 5, 16, 37, 64] {
            for chunk_size in [1u64, 3, 8, 16] {
                for start in 0..total {
                    for end in start..total {
                        let cov = chunks_covering(total, chunk_size, start, end);
                        let indices: Vec<u64> = cov.indices().collect();
                        assert!(!indices.is_empty(), "non-empty range must select ≥1 chunk");

                        // (a) every requested byte lies in some selected chunk.
                        for b in start..=end {
                            let idx = b / chunk_size;
                            assert!(
                                indices.contains(&idx),
                                "byte {b} (chunk {idx}) not covered for total={total} cs={chunk_size} [{start},{end}]",
                            );
                        }

                        // (b) no selected chunk lies entirely outside the range.
                        for &idx in &indices {
                            let c_start = idx * chunk_size;
                            let c_end = (c_start + chunk_size - 1).min(total - 1);
                            let overlaps = c_start <= end && c_end >= start;
                            assert!(
                                overlaps,
                                "chunk {idx} [{c_start},{c_end}] is entirely outside [{start},{end}]",
                            );
                        }
                    }
                }
            }
        }
    }

    // -- slice_within: the per-chunk portion within the range ---------------

    #[test]
    fn slice_within_first_and_last_chunks_are_trimmed() {
        // bytes 1500-3500 over 1000-byte chunks.
        let cov = chunks_covering(10_000, 1000, 1500, 3500);
        // Chunk 1 [1000,1999]: only [1500,1999] is in range → local (500, 500).
        assert_eq!(cov.slice_within(1, 1000), (500, 500));
        // Chunk 2 [2000,2999]: wholly in range → local (0, 1000).
        assert_eq!(cov.slice_within(2, 1000), (0, 1000));
        // Chunk 3 [3000,3999]: only [3000,3500] is in range → local (0, 501).
        assert_eq!(cov.slice_within(3, 1000), (0, 501));
    }

    #[test]
    fn slice_within_respects_a_short_final_chunk() {
        // 2500-byte resource; request the whole thing.
        let cov = chunks_covering(2500, 1000, 0, 2499);
        // The final chunk only fetched 500 bytes; all of it is in range.
        assert_eq!(cov.slice_within(2, 500), (0, 500));
    }

    #[test]
    fn slice_within_chunk_outside_range_contributes_nothing() {
        let cov = chunks_covering(10_000, 1000, 1500, 1999);
        // Chunk 0 is not selected and lies before the range → no contribution.
        assert_eq!(cov.slice_within(0, 1000), (0, 0));
        // Chunk 5 lies after the range → no contribution.
        assert_eq!(cov.slice_within(5, 1000), (0, 0));
    }

    #[test]
    fn slice_bounds_reassemble_the_exact_requested_range() {
        // Reassembling each selected chunk's slice must reproduce the exact
        // requested byte interval with no gaps or overlaps.
        let total = 2500u64;
        let chunk_size = 1000u64;
        let (start, end) = (1234u64, 2345u64);
        let cov = chunks_covering(total, chunk_size, start, end);
        let mut reassembled: u64 = 0;
        for idx in cov.indices() {
            let actual = cov.expected_chunk_len(idx) as usize;
            let (_, local_len) = cov.slice_within(idx, actual);
            reassembled += local_len as u64;
        }
        assert_eq!(reassembled, end - start + 1);
    }
}
