//! HLS master-playlist variant selection for pre-buffering (`prebuffer::variant`)
//! — Req 7.2.
//!
//! When pre-buffering an HLS master manifest the engine must pick exactly one
//! variant to prefetch (design: Components → Pre-Buffering). The rule
//! (Req 7.2) is:
//!
//! * pick the variant whose advertised `BANDWIDTH` is the **highest that does
//!   not exceed** the configured pre-buffer bandwidth ceiling; and
//! * when **every** variant exceeds the ceiling, pick the **lowest-bandwidth**
//!   variant (so playback still starts, just at the cheapest rate).
//!
//! [`select_prebuffer_variant`] is the pure, deterministic implementation of
//! that rule — it does no I/O and is the unit under Property 16 (task 18.6).
//! I-frame-only trick-play variants (`#EXT-X-I-FRAME-STREAM-INF`) are not real
//! playback variants, so they are excluded from selection whenever at least one
//! normal variant exists; a master that advertises *only* I-frame variants
//! falls back to selecting among them rather than returning nothing.

use m3u8_rs::VariantStream;

/// Select the variant to pre-buffer from a master playlist's `variants`, given
/// the configured pre-buffer `bandwidth_ceiling` (Req 7.2).
///
/// Returns the highest-`BANDWIDTH` variant that does not exceed
/// `bandwidth_ceiling`; if every (selectable) variant exceeds the ceiling,
/// returns the lowest-`BANDWIDTH` variant. Ties are broken toward the first
/// occurrence in `variants` so the choice is deterministic. Returns `None` only
/// when `variants` is empty.
///
/// I-frame-only variants are skipped when at least one normal variant is
/// present; when the master advertises only I-frame variants they become the
/// candidate pool so a selection is still made.
pub fn select_prebuffer_variant(
    variants: &[VariantStream],
    bandwidth_ceiling: u64,
) -> Option<&VariantStream> {
    if variants.is_empty() {
        return None;
    }

    // Prefer real (non-I-frame) playback variants; only fall back to I-frame
    // trick-play variants when there is nothing else to choose from.
    let has_playable = variants.iter().any(|v| !v.is_i_frame);
    let is_candidate = |v: &&VariantStream| has_playable != v.is_i_frame || !has_playable;

    let mut best_under_ceiling: Option<&VariantStream> = None;
    let mut lowest_overall: Option<&VariantStream> = None;

    for variant in variants.iter().filter(is_candidate) {
        // Track the lowest-bandwidth candidate (first on ties): replace only on
        // a strictly smaller bandwidth.
        match lowest_overall {
            Some(current) if variant.bandwidth >= current.bandwidth => {}
            _ => lowest_overall = Some(variant),
        }

        // Track the highest-bandwidth candidate at or under the ceiling (first
        // on ties): replace only on a strictly larger bandwidth.
        if variant.bandwidth <= bandwidth_ceiling {
            match best_under_ceiling {
                Some(current) if variant.bandwidth <= current.bandwidth => {}
                _ => best_under_ceiling = Some(variant),
            }
        }
    }

    // Highest under the ceiling, else (all exceed) the lowest overall.
    best_under_ceiling.or(lowest_overall)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a normal (non-I-frame) variant advertising `bandwidth`.
    fn variant(uri: &str, bandwidth: u64) -> VariantStream {
        VariantStream {
            is_i_frame: false,
            uri: uri.to_string(),
            bandwidth,
            ..VariantStream::default()
        }
    }

    /// Build an I-frame-only (trick-play) variant advertising `bandwidth`.
    fn iframe_variant(uri: &str, bandwidth: u64) -> VariantStream {
        VariantStream {
            is_i_frame: true,
            uri: uri.to_string(),
            bandwidth,
            ..VariantStream::default()
        }
    }

    // -- Req 7.2: highest BANDWIDTH not exceeding the ceiling ----------------

    #[test]
    fn picks_highest_bandwidth_at_or_under_ceiling() {
        let variants = vec![
            variant("low.m3u8", 400_000),
            variant("mid.m3u8", 1_200_000),
            variant("high.m3u8", 5_000_000),
        ];
        // Ceiling 2 Mbps → the 1.2 Mbps variant is the highest that fits.
        let selected = select_prebuffer_variant(&variants, 2_000_000).unwrap();
        assert_eq!(selected.uri, "mid.m3u8");
        assert_eq!(selected.bandwidth, 1_200_000);
    }

    /// A variant whose bandwidth is exactly the ceiling is eligible (≤, not <).
    #[test]
    fn variant_exactly_at_ceiling_is_selected() {
        let variants = vec![variant("a.m3u8", 800_000), variant("b.m3u8", 1_000_000)];
        let selected = select_prebuffer_variant(&variants, 1_000_000).unwrap();
        assert_eq!(
            selected.uri, "b.m3u8",
            "a variant at the ceiling must be eligible"
        );
    }

    // -- Req 7.2: all exceed the ceiling → lowest bandwidth ------------------

    #[test]
    fn picks_lowest_bandwidth_when_all_exceed_ceiling() {
        let variants = vec![
            variant("hi.m3u8", 8_000_000),
            variant("mid.m3u8", 5_000_000),
            variant("hi2.m3u8", 6_000_000),
        ];
        // Ceiling below every variant → the cheapest (5 Mbps) is chosen.
        let selected = select_prebuffer_variant(&variants, 1_000_000).unwrap();
        assert_eq!(selected.uri, "mid.m3u8");
        assert_eq!(selected.bandwidth, 5_000_000);
    }

    // -- Determinism: ties resolve to the first occurrence -------------------

    #[test]
    fn ties_under_ceiling_resolve_to_first_occurrence() {
        let variants = vec![
            variant("first.m3u8", 1_000_000),
            variant("second.m3u8", 1_000_000),
        ];
        let selected = select_prebuffer_variant(&variants, 2_000_000).unwrap();
        assert_eq!(selected.uri, "first.m3u8");
    }

    #[test]
    fn ties_for_lowest_resolve_to_first_occurrence() {
        let variants = vec![
            variant("first.m3u8", 9_000_000),
            variant("second.m3u8", 9_000_000),
        ];
        // Both exceed the ceiling and tie for lowest → first wins.
        let selected = select_prebuffer_variant(&variants, 1_000_000).unwrap();
        assert_eq!(selected.uri, "first.m3u8");
    }

    // -- Empty master → no selection -----------------------------------------

    #[test]
    fn empty_variants_yield_none() {
        assert!(select_prebuffer_variant(&[], 5_000_000).is_none());
    }

    // -- I-frame variants are not real playback variants ---------------------

    #[test]
    fn iframe_variants_excluded_when_normal_variants_exist() {
        let variants = vec![
            iframe_variant("iframe.m3u8", 100_000),
            variant("normal.m3u8", 1_500_000),
        ];
        // The cheap I-frame variant must NOT be chosen over the normal one,
        // even though it fits well under the ceiling.
        let selected = select_prebuffer_variant(&variants, 2_000_000).unwrap();
        assert_eq!(selected.uri, "normal.m3u8");
    }

    #[test]
    fn iframe_only_master_falls_back_to_iframe_variants() {
        let variants = vec![
            iframe_variant("a.m3u8", 200_000),
            iframe_variant("b.m3u8", 100_000),
        ];
        // No normal variant exists → select among the I-frame variants.
        let selected = select_prebuffer_variant(&variants, 5_000_000).unwrap();
        assert_eq!(
            selected.uri, "a.m3u8",
            "highest under ceiling among i-frame variants"
        );
    }

    /// A single-variant master always selects that variant, ceiling or not.
    #[test]
    fn single_variant_is_always_selected() {
        let variants = vec![variant("only.m3u8", 12_000_000)];
        let selected = select_prebuffer_variant(&variants, 1_000).unwrap();
        assert_eq!(selected.uri, "only.m3u8");
    }
}
