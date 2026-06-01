//! Property-based test for Telegram MTProto range chunk coverage (task 19.4).
//!
//! Feature: ZippyPanther, Property 48
//!
//! **Property 48: Telegram range chunk coverage**
//!
//! *For any* total size, chunk size, and requested byte range, the computed set
//! of chunk indices covers exactly the bytes of the requested range (every
//! requested byte lies in some selected chunk) and includes no chunk that lies
//! entirely outside the requested range.
//!
//! **Validates: Requirements 11.3**
//!
//! Requirement 11.3: when a `Range` request for Telegram media is received, the
//! engine fetches **only** the chunks covering the requested byte range. This
//! exercises the pure chunk-range arithmetic of
//! [`zippy_panther::telegram::chunks_covering`] (and the [`ChunkCoverage`] it
//! returns) against an **independent oracle** that re-derives the covering set
//! and the per-chunk slices straight from the requirement semantics:
//!
//! * a request is degenerate (`chunk_size == 0`, an empty resource,
//!   `start >= total`, or `start > end`) ⇒ an *empty* coverage that selects no
//!   chunks and slices nothing; otherwise
//! * with `end` clamped to the last byte (`Content-Range` semantics), the
//!   covering set is exactly the contiguous `first..=last` where
//!   `first = start / chunk_size` and `last = end / chunk_size`, every
//!   requested byte `b` lands in chunk `b / chunk_size`, no selected chunk lies
//!   wholly outside `[start, end]`, and laying each chunk's
//!   [`slice_within`](ChunkCoverage::slice_within) interval end-to-end
//!   reproduces the exact requested byte interval with no gaps or overlaps.
//!
//! Generators bias toward small totals / chunk sizes and the `start == total`
//! boundary (where the satisfiable↔empty frontier is dense), include a
//! medium-sized arm, and a large arm (multi-gigabyte totals, megabyte-scale
//! chunks incl. [`zippy_panther::telegram::DEFAULT_CHUNK_SIZE`]) with short
//! ranges so the arithmetic is verified across the full `u32::MAX` size span
//! while keeping the per-byte oracle bounded.

use proptest::prelude::*;
use zippy_panther::telegram::{chunks_covering, DEFAULT_CHUNK_SIZE};

/// A generated request: `(total_size, chunk_size, start, end)` fed verbatim to
/// [`chunks_covering`]. `start`/`end` are the resolved inclusive offsets and
/// may be degenerate (`start > end`, or `start >= total`) to exercise the
/// empty-coverage arm.
type Case = (u64, u64, u64, u64);

/// Dense small arm: tiny totals and chunk sizes (incl. the `0` chunk size and
/// `0`/`1` totals) where the per-byte coverage check is cheap and boundary
/// behaviour is packed close together.
fn small_case() -> impl Strategy<Value = Case> {
    let total = prop_oneof![
        2 => Just(0u64),
        2 => Just(1u64),
        6 => 0u64..=512,
    ];
    let chunk_size = prop_oneof![
        1 => Just(0u64), // degenerate: floored-but-empty coverage
        9 => prop_oneof![Just(1u64), Just(2), Just(3), Just(5), Just(8), Just(16), Just(64), Just(256), Just(512)],
    ];
    (total, chunk_size).prop_flat_map(|(total, chunk_size)| {
        let hi = total.saturating_add(2);
        let start = 0u64..=hi;
        start.prop_flat_map(move |start| {
            // Mostly `end >= start` (a real range); occasionally `end < start`
            // so the `start > end` empty arm is hit too.
            let end = prop_oneof![
                4 => start..=start.saturating_add(600),
                1 => 0u64..=hi,
            ];
            (Just(total), Just(chunk_size), Just(start), end)
        })
    })
}

/// Medium arm: kilobyte-scale totals and chunk sizes — enough chunks to span
/// many indices while the requested range (clamped to the resource) stays
/// within a few thousand bytes.
fn medium_case() -> impl Strategy<Value = Case> {
    let total = 0u64..=8192;
    let chunk_size = 1u64..=4096;
    (total, chunk_size).prop_flat_map(|(total, chunk_size)| {
        let hi = total.saturating_add(2);
        let start = 0u64..=hi;
        start.prop_flat_map(move |start| {
            let end = prop_oneof![
                4 => start..=start.saturating_add(8200),
                1 => 0u64..=hi,
            ];
            (Just(total), Just(chunk_size), Just(start), end)
        })
    })
}

/// Large arm: multi-gigabyte totals (up to `u32::MAX`) and megabyte-scale chunk
/// sizes (incl. [`DEFAULT_CHUNK_SIZE`]). The requested range is kept short
/// (`<= 4096` bytes past the start) so the absolute-offset / per-byte oracle
/// stays bounded while the chunk *index* arithmetic runs against huge offsets.
fn large_case() -> impl Strategy<Value = Case> {
    let total = 1_000u64..=u64::from(u32::MAX);
    let chunk_size = prop_oneof![
        2 => Just(DEFAULT_CHUNK_SIZE),
        1 => Just(4096u64),
        2 => 1024u64..=2_000_000,
    ];
    (total, chunk_size).prop_flat_map(|(total, chunk_size)| {
        // Bias the start toward the interior, the last byte, and the `>= total`
        // boundary so the empty arm and the final partial chunk both get hit.
        let last = total.saturating_sub(1);
        let start = prop_oneof![
            4 => 0u64..=last,
            1 => Just(last),
            1 => Just(total),
            1 => total..=total.saturating_add(8),
        ];
        start.prop_flat_map(move |start| {
            let end = start..=start.saturating_add(4096);
            (Just(total), Just(chunk_size), Just(start), end)
        })
    })
}

fn any_case() -> impl Strategy<Value = Case> {
    prop_oneof![
        4 => small_case(),
        3 => medium_case(),
        3 => large_case(),
    ]
}

proptest! {
    // 256 cases comfortably exceeds the 100-iteration floor for a property task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 48 — Telegram range chunk coverage.
    /// **Validates: Requirements 11.3**
    #[test]
    fn telegram_range_chunk_coverage_is_exact((total, chunk_size, start, end) in any_case()) {
        let cov = chunks_covering(total, chunk_size, start, end);

        // Independent oracle for the degenerate (no-bytes-selected) inputs that
        // `chunks_covering` defends against.
        let degenerate = chunk_size == 0 || total == 0 || start >= total || start > end;
        prop_assert_eq!(
            cov.is_empty(),
            degenerate,
            "empty-coverage disagreement for total={} cs={} [{},{}]",
            total, chunk_size, start, end,
        );

        if degenerate {
            // Empty coverage selects no chunks and slices nothing.
            prop_assert_eq!(cov.indices().count(), 0, "empty coverage must select no chunks");
            prop_assert_eq!(cov.chunk_count(), 0);
            prop_assert_eq!(cov.first_index(), None);
            prop_assert_eq!(cov.last_index(), None);
            prop_assert_eq!(cov.start(), None);
            prop_assert_eq!(cov.end(), None);
            // No index can contribute bytes, regardless of the fetched length.
            prop_assert_eq!(cov.slice_within(0, 4096), (0, 0));
            prop_assert_eq!(cov.slice_within(123, 4096), (0, 0));
            return Ok(());
        }

        // -- Non-degenerate: re-derive the covering set from the requirement --
        let cs = cov.chunk_size();
        prop_assert_eq!(cs, chunk_size, "non-degenerate chunk_size is preserved verbatim");

        // `Content-Range` semantics: a last-byte-pos past the resource clamps.
        let end_clamped = end.min(total - 1);
        prop_assert_eq!(cov.start(), Some(start));
        prop_assert_eq!(cov.end(), Some(end_clamped));

        let first_oracle = start / cs;
        let last_oracle = end_clamped / cs;

        let indices: Vec<u64> = cov.indices().collect();

        // The covering set is exactly the contiguous `first..=last`.
        let expected_indices: Vec<u64> = (first_oracle..=last_oracle).collect();
        prop_assert_eq!(
            &indices,
            &expected_indices,
            "covering set mismatch for total={} cs={} [{},{}]",
            total, chunk_size, start, end_clamped,
        );
        prop_assert!(!indices.is_empty(), "a satisfiable range must select >= 1 chunk");
        prop_assert_eq!(cov.first_index(), Some(first_oracle));
        prop_assert_eq!(cov.last_index(), Some(last_oracle));
        prop_assert_eq!(cov.chunk_count(), last_oracle - first_oracle + 1);
        prop_assert_eq!(cov.chunk_count(), indices.len() as u64);

        // (a) Every requested byte lies in some selected chunk. The requested
        // range is bounded by the generators, so this per-byte sweep is cheap.
        for b in start..=end_clamped {
            let idx = b / cs;
            prop_assert!(
                indices.contains(&idx),
                "byte {} (chunk {}) not covered for total={} cs={} [{},{}]",
                b, idx, total, chunk_size, start, end_clamped,
            );
        }

        // (b) No selected chunk lies entirely outside the requested range, and
        //     reassembling each chunk's `slice_within` portion reproduces the
        //     exact requested interval with no gaps or overlaps.
        let mut covered: Vec<(u64, u64)> = Vec::with_capacity(indices.len());
        for &idx in &indices {
            // The chunk's resource-bounded absolute span [c_start, c_end].
            let c_start = idx * cs;
            let chunk_len = cov.expected_chunk_len(idx);
            prop_assert!(
                chunk_len > 0,
                "selected chunk {} must hold >= 1 byte (total={} cs={})",
                idx, total, cs,
            );
            let c_end = c_start + chunk_len - 1;
            let overlaps = c_start <= end_clamped && c_end >= start;
            prop_assert!(
                overlaps,
                "selected chunk {} [{},{}] lies entirely outside [{},{}]",
                idx, c_start, c_end, start, end_clamped,
            );

            // Slice the chunk (fetched at its expected length) to the in-range
            // portion and record its absolute interval.
            let (local_start, local_len) = cov.slice_within(idx, chunk_len as usize);
            prop_assert!(
                local_len > 0,
                "selected chunk {} must contribute bytes to the range", idx,
            );
            let abs_start = c_start + local_start as u64;
            let abs_end_excl = abs_start + local_len as u64;
            // Each slice stays within its own chunk's fetched bytes.
            prop_assert!(abs_end_excl <= c_start + chunk_len, "slice escapes chunk {}", idx);
            covered.push((abs_start, abs_end_excl));
        }

        // The slices, laid end-to-end in index order, are contiguous and equal
        // exactly the half-open requested span [start, end_clamped + 1).
        prop_assert_eq!(covered.first().map(|s| s.0), Some(start), "reassembly must begin at start");
        prop_assert_eq!(
            covered.last().map(|s| s.1),
            Some(end_clamped + 1),
            "reassembly must end at the last requested byte",
        );
        for win in covered.windows(2) {
            prop_assert_eq!(
                win[0].1, win[1].0,
                "reassembled slices must be contiguous (gap/overlap between {:?} and {:?})",
                win[0], win[1],
            );
        }
        let reassembled_len: u64 = covered.iter().map(|(s, e)| e - s).sum();
        prop_assert_eq!(
            reassembled_len,
            end_clamped - start + 1,
            "reassembled length must equal the requested range length",
        );
    }
}
