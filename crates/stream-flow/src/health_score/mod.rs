//! Torrent health scoring (`health_score`) — Req 42.
//!
//! [`HealthScorer`] computes a [`HealthScore`] (a `f64` in `[0.0, 1.0]`) for a
//! torrent from four factors:
//!
//! 1. **Cache status** — `cached` > `downloading` > `queued`/other (Req 42.2).
//! 2. **File quality** — resolution (1080p > 720p > 480p > …) and codec
//!    (AV1 > H.265 > H.264 > other) (Req 42.2).
//! 3. **Seed count** — logarithmically scaled contribution (Req 42.2).
//! 4. **Historical success rate** from the [`HealthHistory`] SQLite table,
//!    with time-decay so older entries contribute less (Req 42.3, 42.4, 42.5).
//!
//! The final score is a weighted sum of the four components, clamped to
//! `[0.0, 1.0]`.  Weights are tuned so that cache status dominates (a cached
//! torrent always outscores an uncached one with equal quality/seeds/history),
//! while quality and history provide meaningful tie-breaking.
//!
//! ## Time-decay
//!
//! History entries are decayed by `exp(-age_days / half_life_days)` where
//! `half_life_days = decay_window_days / 2`.  An entry at the edge of the
//! window contributes `exp(-2) ≈ 0.135` of its face value; an entry from
//! today contributes its full face value.  Entries older than the window are
//! treated as absent (Req 42.5).

use time::OffsetDateTime;

use crate::persistence::models::HealthHistory;
use crate::store::types::MagnetStatus;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A computed health score in `[0.0, 1.0]` (Req 42.1, 42.2).
///
/// Higher is better. Use [`HealthScorer::score`] to compute one.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct HealthScore(f64);

impl HealthScore {
    /// The minimum possible score.
    pub const MIN: HealthScore = HealthScore(0.0);
    /// The maximum possible score.
    pub const MAX: HealthScore = HealthScore(1.0);

    /// Construct a score, clamping to `[0.0, 1.0]`.
    pub fn new(v: f64) -> Self {
        HealthScore(v.clamp(0.0, 1.0))
    }

    /// The raw `f64` value.
    pub fn value(self) -> f64 {
        self.0
    }
}

impl From<HealthScore> for f64 {
    fn from(s: HealthScore) -> f64 {
        s.0
    }
}

// ---------------------------------------------------------------------------
// Quality signals
// ---------------------------------------------------------------------------

/// Video resolution tier, ordered from lowest to highest quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resolution {
    Unknown = 0,
    Sd480 = 1,
    Sd576 = 2,
    Hd720 = 3,
    Fhd1080 = 4,
    Uhd4k = 5,
}

impl Resolution {
    /// Parse a resolution from a release-name token (case-insensitive).
    pub fn from_str(s: &str) -> Resolution {
        match s.to_ascii_lowercase().as_str() {
            "480p" | "480" => Resolution::Sd480,
            "576p" | "576" => Resolution::Sd576,
            "720p" | "720" => Resolution::Hd720,
            "1080p" | "1080" | "fhd" => Resolution::Fhd1080,
            "2160p" | "4k" | "uhd" | "2160" => Resolution::Uhd4k,
            _ => Resolution::Unknown,
        }
    }

    /// Normalized quality contribution in `[0.0, 1.0]`.
    fn quality_score(self) -> f64 {
        match self {
            Resolution::Unknown => 0.0,
            Resolution::Sd480 => 0.1,
            Resolution::Sd576 => 0.2,
            Resolution::Hd720 => 0.5,
            Resolution::Fhd1080 => 0.8,
            Resolution::Uhd4k => 1.0,
        }
    }
}

/// Video codec tier, ordered from lowest to highest quality/efficiency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Codec {
    Unknown = 0,
    H264 = 1,
    H265 = 2,
    Av1 = 3,
}

impl Codec {
    /// Parse a codec from a release-name token (case-insensitive).
    pub fn from_str(s: &str) -> Codec {
        match s.to_ascii_lowercase().as_str() {
            "h264" | "x264" | "avc" => Codec::H264,
            "h265" | "x265" | "hevc" => Codec::H265,
            "av1" => Codec::Av1,
            _ => Codec::Unknown,
        }
    }

    /// Normalized quality contribution in `[0.0, 1.0]`.
    fn quality_score(self) -> f64 {
        match self {
            Codec::Unknown => 0.0,
            Codec::H264 => 0.4,
            Codec::H265 => 0.7,
            Codec::Av1 => 1.0,
        }
    }
}

/// Quality signals extracted from a torrent's file name or metadata.
#[derive(Debug, Clone, Default)]
pub struct FileQuality {
    /// Detected resolution (defaults to [`Resolution::Unknown`]).
    pub resolution: Resolution,
    /// Detected codec (defaults to [`Codec::Unknown`]).
    pub codec: Codec,
}

impl Default for Resolution {
    fn default() -> Self {
        Resolution::Unknown
    }
}

impl Default for Codec {
    fn default() -> Self {
        Codec::Unknown
    }
}

impl FileQuality {
    /// Combined quality score in `[0.0, 1.0]`.
    ///
    /// Resolution contributes 70 % and codec 30 % of the quality component.
    fn score(&self) -> f64 {
        0.7 * self.resolution.quality_score() + 0.3 * self.codec.quality_score()
    }
}

// ---------------------------------------------------------------------------
// Scorer configuration
// ---------------------------------------------------------------------------

/// Configuration for [`HealthScorer`].
#[derive(Debug, Clone)]
pub struct HealthScorerConfig {
    /// History decay window in days (default 7). Entries older than this are
    /// treated as absent (Req 42.5).
    pub decay_window_days: f64,
    /// Weight for the cache-status component (default 0.45).
    pub weight_cache: f64,
    /// Weight for the file-quality component (default 0.25).
    pub weight_quality: f64,
    /// Weight for the seed-count component (default 0.15).
    pub weight_seeds: f64,
    /// Weight for the historical success-rate component (default 0.15).
    pub weight_history: f64,
    /// Maximum seed count used for normalization (default 100).
    pub max_seeds: f64,
}

impl Default for HealthScorerConfig {
    fn default() -> Self {
        Self {
            decay_window_days: 7.0,
            weight_cache: 0.45,
            weight_quality: 0.25,
            weight_seeds: 0.15,
            weight_history: 0.15,
            max_seeds: 100.0,
        }
    }
}

impl HealthScorerConfig {
    /// Validate that weights sum to approximately 1.0 and all values are
    /// positive. Panics in debug builds; silently clamps in release.
    fn assert_valid(&self) {
        let sum = self.weight_cache
            + self.weight_quality
            + self.weight_seeds
            + self.weight_history;
        debug_assert!(
            (sum - 1.0).abs() < 1e-6,
            "HealthScorerConfig weights must sum to 1.0, got {sum}"
        );
        debug_assert!(self.decay_window_days > 0.0);
        debug_assert!(self.max_seeds > 0.0);
    }
}

// ---------------------------------------------------------------------------
// HealthScorer
// ---------------------------------------------------------------------------

/// Computes [`HealthScore`] values for torrents (Req 42).
///
/// Construct with [`HealthScorer::new`] (custom config) or
/// [`HealthScorer::default`] (default weights / 7-day decay window).
#[derive(Debug, Clone)]
pub struct HealthScorer {
    cfg: HealthScorerConfig,
}

impl Default for HealthScorer {
    fn default() -> Self {
        Self::new(HealthScorerConfig::default())
    }
}

impl HealthScorer {
    /// Create a scorer with the given configuration.
    pub fn new(cfg: HealthScorerConfig) -> Self {
        cfg.assert_valid();
        Self { cfg }
    }

    /// Compute the health score for a torrent.
    ///
    /// # Parameters
    /// - `status`: the magnet cache status from the store (Req 42.2).
    /// - `quality`: file quality signals (resolution + codec) (Req 42.2).
    /// - `seed_count`: optional seed count (Req 42.2).
    /// - `history`: optional [`HealthHistory`] row from SQLite (Req 42.3-42.5).
    /// - `now`: the current time (used for decay; pass `OffsetDateTime::now_utc()`
    ///   in production, or a fixed value in tests).
    pub fn score(
        &self,
        status: MagnetStatus,
        quality: &FileQuality,
        seed_count: Option<u32>,
        history: Option<&HealthHistory>,
        now: OffsetDateTime,
    ) -> HealthScore {
        let cache_score = self.cache_component(status);
        let quality_score = quality.score();
        let seed_score = self.seed_component(seed_count);
        let history_score = self.history_component(history, now);

        let raw = self.cfg.weight_cache * cache_score
            + self.cfg.weight_quality * quality_score
            + self.cfg.weight_seeds * seed_score
            + self.cfg.weight_history * history_score;

        HealthScore::new(raw)
    }

    /// Cache-status component in `[0.0, 1.0]` (Req 42.2).
    ///
    /// `cached` > `downloading`/`processing`/`downloaded`/`uploading` > everything else.
    fn cache_component(&self, status: MagnetStatus) -> f64 {
        match status {
            MagnetStatus::Cached => 1.0,
            MagnetStatus::Downloaded | MagnetStatus::Processing | MagnetStatus::Uploading => 0.6,
            MagnetStatus::Downloading => 0.4,
            MagnetStatus::Queued => 0.2,
            MagnetStatus::Failed | MagnetStatus::Invalid => 0.0,
            MagnetStatus::Unknown => 0.1,
        }
    }

    /// Seed-count component in `[0.0, 1.0]` (Req 42.2).
    ///
    /// Uses a logarithmic scale so the first few seeds matter most and the
    /// contribution saturates at `max_seeds`.
    fn seed_component(&self, seed_count: Option<u32>) -> f64 {
        match seed_count {
            None | Some(0) => 0.0,
            Some(n) => {
                let n = n as f64;
                let max = self.cfg.max_seeds;
                // log(1 + n) / log(1 + max_seeds) — saturates at 1.0
                (1.0 + n).ln() / (1.0 + max).ln()
            }
        }
        .min(1.0)
    }

    /// Historical success-rate component in `[0.0, 1.0]` with time-decay
    /// (Req 42.3, 42.4, 42.5).
    ///
    /// Returns `0.5` (neutral) when no history is available.
    fn history_component(&self, history: Option<&HealthHistory>, now: OffsetDateTime) -> f64 {
        let h = match history {
            None => return 0.5,
            Some(h) => h,
        };

        // Age in days since last_seen.
        let age_secs = (now - h.last_seen).whole_seconds().max(0) as f64;
        let age_days = age_secs / 86_400.0;

        // Entries older than the window are treated as absent (Req 42.5).
        if age_days > self.cfg.decay_window_days {
            return 0.5;
        }

        let total = h.success + h.failure;
        if total == 0 {
            return 0.5;
        }

        // Raw success rate in [0, 1].
        let rate = h.success as f64 / total as f64;

        // Time-decay: exp(-age_days / half_life) where half_life = window / 2.
        let half_life = self.cfg.decay_window_days / 2.0;
        let decay = (-age_days / half_life).exp();

        // Blend toward neutral (0.5) as the entry ages.
        // At age=0: full rate. At age=window: rate * exp(-2) + 0.5*(1-exp(-2)).
        let decayed = rate * decay + 0.5 * (1.0 - decay);
        decayed.clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Ordering helper
// ---------------------------------------------------------------------------

/// Sort a slice of `(T, HealthScore)` pairs by descending score in-place
/// (Req 42.1, 42.6).
///
/// Ties are broken by the original order (stable sort).
pub fn sort_by_score<T>(items: &mut Vec<(T, HealthScore)>) {
    items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use time::OffsetDateTime;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn scorer() -> HealthScorer {
        HealthScorer::default()
    }

    fn no_history() -> Option<&'static HealthHistory> {
        None
    }

    fn quality(res: Resolution, codec: Codec) -> FileQuality {
        FileQuality { resolution: res, codec }
    }

    fn history_row(success: u32, failure: u32, age_days: f64) -> HealthHistory {
        let last_seen = now() - Duration::from_secs_f64(age_days * 86_400.0);
        HealthHistory {
            info_hash: "test".into(),
            store: "realdebrid".into(),
            success,
            failure,
            seed_count: None,
            last_seen,
        }
    }

    // -----------------------------------------------------------------------
    // Score is bounded [0.0, 1.0]
    // -----------------------------------------------------------------------

    #[test]
    fn score_is_bounded_zero_to_one() {
        let s = scorer();
        let q = FileQuality::default();
        for status in MagnetStatus::ALL {
            let score = s.score(status, &q, None, no_history(), now());
            assert!(
                score.value() >= 0.0 && score.value() <= 1.0,
                "score out of bounds for {status:?}: {}",
                score.value()
            );
        }
    }

    #[test]
    fn score_with_max_seeds_and_perfect_history_is_at_most_one() {
        let s = scorer();
        let q = quality(Resolution::Uhd4k, Codec::Av1);
        let h = history_row(1000, 0, 0.0);
        let score = s.score(MagnetStatus::Cached, &q, Some(9999), Some(&h), now());
        assert!(score.value() <= 1.0);
        assert!(score.value() >= 0.0);
    }

    // -----------------------------------------------------------------------
    // Cache status: cached scores higher than downloading
    // -----------------------------------------------------------------------

    #[test]
    fn cached_scores_higher_than_downloading() {
        let s = scorer();
        let q = FileQuality::default();
        let cached = s.score(MagnetStatus::Cached, &q, None, no_history(), now());
        let downloading = s.score(MagnetStatus::Downloading, &q, None, no_history(), now());
        assert!(
            cached.value() > downloading.value(),
            "cached ({}) should score higher than downloading ({})",
            cached.value(),
            downloading.value()
        );
    }

    #[test]
    fn cached_scores_higher_than_queued() {
        let s = scorer();
        let q = FileQuality::default();
        let cached = s.score(MagnetStatus::Cached, &q, None, no_history(), now());
        let queued = s.score(MagnetStatus::Queued, &q, None, no_history(), now());
        assert!(cached.value() > queued.value());
    }

    // -----------------------------------------------------------------------
    // Seed count: more seeds → higher score (monotonic)
    // -----------------------------------------------------------------------

    #[test]
    fn more_seeds_never_decreases_score() {
        let s = scorer();
        let q = FileQuality::default();
        let seed_counts = [0u32, 1, 5, 10, 50, 100, 500];
        let mut prev = 0.0_f64;
        for &n in &seed_counts {
            let score = s.score(MagnetStatus::Cached, &q, Some(n), no_history(), now());
            assert!(
                score.value() >= prev,
                "score should be non-decreasing with seeds: {n} seeds gave {} < prev {prev}",
                score.value()
            );
            prev = score.value();
        }
    }

    // -----------------------------------------------------------------------
    // Quality: 1080p > 720p when other factors equal
    // -----------------------------------------------------------------------

    #[test]
    fn fhd1080_scores_higher_than_hd720_equal_other_factors() {
        let s = scorer();
        let q1080 = quality(Resolution::Fhd1080, Codec::Unknown);
        let q720 = quality(Resolution::Hd720, Codec::Unknown);
        let s1080 = s.score(MagnetStatus::Cached, &q1080, Some(10), no_history(), now());
        let s720 = s.score(MagnetStatus::Cached, &q720, Some(10), no_history(), now());
        assert!(
            s1080.value() > s720.value(),
            "1080p ({}) should score higher than 720p ({})",
            s1080.value(),
            s720.value()
        );
    }

    // -----------------------------------------------------------------------
    // Time-decay: older entries contribute less
    // -----------------------------------------------------------------------

    #[test]
    fn time_decay_reduces_score_for_old_entries() {
        let s = scorer();
        let q = FileQuality::default();
        let fresh = history_row(10, 0, 0.0);
        let old = history_row(10, 0, 6.9); // just inside the 7-day window

        let score_fresh = s.score(MagnetStatus::Cached, &q, None, Some(&fresh), now());
        let score_old = s.score(MagnetStatus::Cached, &q, None, Some(&old), now());

        assert!(
            score_fresh.value() > score_old.value(),
            "fresh history ({}) should score higher than old history ({})",
            score_fresh.value(),
            score_old.value()
        );
    }

    #[test]
    fn entry_beyond_decay_window_treated_as_absent() {
        let s = scorer();
        let q = FileQuality::default();
        let beyond_window = history_row(100, 0, 8.0); // 8 days > 7-day window
        let no_hist_score = s.score(MagnetStatus::Cached, &q, None, no_history(), now());
        let beyond_score = s.score(MagnetStatus::Cached, &q, None, Some(&beyond_window), now());
        // Both should use the neutral 0.5 history component
        assert_eq!(
            no_hist_score.value(),
            beyond_score.value(),
            "entry beyond window should be treated as absent"
        );
    }

    // -----------------------------------------------------------------------
    // Ordering: cached+1080p > cached+720p > downloading+1080p
    // -----------------------------------------------------------------------

    #[test]
    fn ordering_cached_1080p_gt_cached_720p_gt_downloading_1080p() {
        let s = scorer();
        let q1080 = quality(Resolution::Fhd1080, Codec::Unknown);
        let q720 = quality(Resolution::Hd720, Codec::Unknown);

        let cached_1080 = s.score(MagnetStatus::Cached, &q1080, None, no_history(), now());
        let cached_720 = s.score(MagnetStatus::Cached, &q720, None, no_history(), now());
        let downloading_1080 = s.score(MagnetStatus::Downloading, &q1080, None, no_history(), now());

        assert!(
            cached_1080.value() > cached_720.value(),
            "cached+1080p ({}) > cached+720p ({})",
            cached_1080.value(),
            cached_720.value()
        );
        assert!(
            cached_720.value() > downloading_1080.value(),
            "cached+720p ({}) > downloading+1080p ({})",
            cached_720.value(),
            downloading_1080.value()
        );
    }

    // -----------------------------------------------------------------------
    // History: success boosts, failure penalizes
    // -----------------------------------------------------------------------

    #[test]
    fn all_success_history_boosts_score_above_no_history() {
        let s = scorer();
        let q = FileQuality::default();
        let good = history_row(10, 0, 0.0);
        let no_hist = s.score(MagnetStatus::Cached, &q, None, no_history(), now());
        let with_hist = s.score(MagnetStatus::Cached, &q, None, Some(&good), now());
        assert!(
            with_hist.value() > no_hist.value(),
            "all-success history ({}) should boost above no-history ({})",
            with_hist.value(),
            no_hist.value()
        );
    }

    #[test]
    fn all_failure_history_penalizes_score_below_no_history() {
        let s = scorer();
        let q = FileQuality::default();
        let bad = history_row(0, 10, 0.0);
        let no_hist = s.score(MagnetStatus::Cached, &q, None, no_history(), now());
        let with_hist = s.score(MagnetStatus::Cached, &q, None, Some(&bad), now());
        assert!(
            with_hist.value() < no_hist.value(),
            "all-failure history ({}) should penalize below no-history ({})",
            with_hist.value(),
            no_hist.value()
        );
    }

    // -----------------------------------------------------------------------
    // sort_by_score
    // -----------------------------------------------------------------------

    #[test]
    fn sort_by_score_orders_descending() {
        let s = scorer();
        let q1080 = quality(Resolution::Fhd1080, Codec::Unknown);
        let q720 = quality(Resolution::Hd720, Codec::Unknown);

        let mut items = vec![
            ("downloading+1080p", s.score(MagnetStatus::Downloading, &q1080, None, no_history(), now())),
            ("cached+720p",       s.score(MagnetStatus::Cached,       &q720,  None, no_history(), now())),
            ("cached+1080p",      s.score(MagnetStatus::Cached,       &q1080, None, no_history(), now())),
        ];
        sort_by_score(&mut items);

        assert_eq!(items[0].0, "cached+1080p");
        assert_eq!(items[1].0, "cached+720p");
        assert_eq!(items[2].0, "downloading+1080p");
    }

    // -----------------------------------------------------------------------
    // Resolution and Codec parsing
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_from_str_parses_known_tokens() {
        assert_eq!(Resolution::from_str("1080p"), Resolution::Fhd1080);
        assert_eq!(Resolution::from_str("720p"), Resolution::Hd720);
        assert_eq!(Resolution::from_str("480p"), Resolution::Sd480);
        assert_eq!(Resolution::from_str("4K"), Resolution::Uhd4k);
        assert_eq!(Resolution::from_str("unknown_token"), Resolution::Unknown);
    }

    #[test]
    fn codec_from_str_parses_known_tokens() {
        assert_eq!(Codec::from_str("x265"), Codec::H265);
        assert_eq!(Codec::from_str("HEVC"), Codec::H265);
        assert_eq!(Codec::from_str("x264"), Codec::H264);
        assert_eq!(Codec::from_str("AV1"), Codec::Av1);
        assert_eq!(Codec::from_str("unknown"), Codec::Unknown);
    }

    // -----------------------------------------------------------------------
    // Property test: health-score monotonicity and ordering (Property 42)
    // -----------------------------------------------------------------------
    // Feature: stream-flow, Property 42: Health-score monotonicity and ordering
    // Validates: Requirements 42.1, 42.2, 42.3, 42.4, 42.5, 42.6

    use proptest::prelude::*;

    proptest! {
        /// For any two otherwise-equal torrents, a cached torrent scores at
        /// least as high as an uncached one (Req 42.2).
        #[test]
        fn prop_cached_ge_uncached(
            seeds in 0u32..200u32,
            res_idx in 0usize..5usize,
            codec_idx in 0usize..4usize,
        ) {
            let resolutions = [
                Resolution::Unknown, Resolution::Sd480, Resolution::Sd576,
                Resolution::Hd720, Resolution::Fhd1080,
            ];
            let codecs = [Codec::Unknown, Codec::H264, Codec::H265, Codec::Av1];
            let q = FileQuality {
                resolution: resolutions[res_idx],
                codec: codecs[codec_idx],
            };
            let s = HealthScorer::default();
            let t = now();
            let cached = s.score(MagnetStatus::Cached, &q, Some(seeds), no_history(), t);
            for status in [MagnetStatus::Downloading, MagnetStatus::Queued,
                           MagnetStatus::Unknown, MagnetStatus::Failed] {
                let other = s.score(status, &q, Some(seeds), no_history(), t);
                prop_assert!(
                    cached.value() >= other.value(),
                    "cached ({}) should be >= {status:?} ({})",
                    cached.value(), other.value()
                );
            }
        }

        /// More seeds never decrease the score (Req 42.2).
        #[test]
        fn prop_more_seeds_nondecreasing(
            n1 in 0u32..500u32,
            n2 in 0u32..500u32,
        ) {
            let s = HealthScorer::default();
            let q = FileQuality::default();
            let t = now();
            let lo = n1.min(n2);
            let hi = n1.max(n2);
            let score_lo = s.score(MagnetStatus::Cached, &q, Some(lo), no_history(), t);
            let score_hi = s.score(MagnetStatus::Cached, &q, Some(hi), no_history(), t);
            prop_assert!(
                score_hi.value() >= score_lo.value(),
                "more seeds ({hi}) should score >= fewer seeds ({lo}): {} vs {}",
                score_hi.value(), score_lo.value()
            );
        }

        /// More historical successes never decrease the score (Req 42.3).
        #[test]
        fn prop_more_successes_nondecreasing(
            s1 in 0u32..100u32,
            s2 in 0u32..100u32,
            failures in 0u32..10u32,
        ) {
            let scorer = HealthScorer::default();
            let q = FileQuality::default();
            let t = now();
            let lo = s1.min(s2);
            let hi = s1.max(s2);
            let h_lo = HealthHistory {
                info_hash: "x".into(), store: "rd".into(),
                success: lo, failure: failures, seed_count: None,
                last_seen: t,
            };
            let h_hi = HealthHistory {
                info_hash: "x".into(), store: "rd".into(),
                success: hi, failure: failures, seed_count: None,
                last_seen: t,
            };
            let score_lo = scorer.score(MagnetStatus::Cached, &q, None, Some(&h_lo), t);
            let score_hi = scorer.score(MagnetStatus::Cached, &q, None, Some(&h_hi), t);
            prop_assert!(
                score_hi.value() >= score_lo.value(),
                "more successes ({hi}) should score >= fewer ({lo}): {} vs {}",
                score_hi.value(), score_lo.value()
            );
        }

        /// More historical failures never increase the score (Req 42.4).
        #[test]
        fn prop_more_failures_nonincreasing(
            f1 in 0u32..100u32,
            f2 in 0u32..100u32,
            successes in 0u32..10u32,
        ) {
            let scorer = HealthScorer::default();
            let q = FileQuality::default();
            let t = now();
            let lo = f1.min(f2);
            let hi = f1.max(f2);
            let h_lo = HealthHistory {
                info_hash: "x".into(), store: "rd".into(),
                success: successes, failure: lo, seed_count: None,
                last_seen: t,
            };
            let h_hi = HealthHistory {
                info_hash: "x".into(), store: "rd".into(),
                success: successes, failure: hi, seed_count: None,
                last_seen: t,
            };
            let score_lo = scorer.score(MagnetStatus::Cached, &q, None, Some(&h_lo), t);
            let score_hi = scorer.score(MagnetStatus::Cached, &q, None, Some(&h_hi), t);
            prop_assert!(
                score_lo.value() >= score_hi.value(),
                "more failures ({hi}) should score <= fewer ({lo}): {} vs {}",
                score_hi.value(), score_lo.value()
            );
        }

        /// Older history contributes no more than newer history (Req 42.5).
        #[test]
        fn prop_older_history_contributes_no_more(
            age1_days in 0.0f64..6.9f64,
            age2_days in 0.0f64..6.9f64,
            successes in 1u32..50u32,
        ) {
            let scorer = HealthScorer::default();
            let q = FileQuality::default();
            let t = now();
            let younger_age = age1_days.min(age2_days);
            let older_age = age1_days.max(age2_days);
            let h_young = HealthHistory {
                info_hash: "x".into(), store: "rd".into(),
                success: successes, failure: 0, seed_count: None,
                last_seen: t - Duration::from_secs_f64(younger_age * 86_400.0),
            };
            let h_old = HealthHistory {
                info_hash: "x".into(), store: "rd".into(),
                success: successes, failure: 0, seed_count: None,
                last_seen: t - Duration::from_secs_f64(older_age * 86_400.0),
            };
            let score_young = scorer.score(MagnetStatus::Cached, &q, None, Some(&h_young), t);
            let score_old = scorer.score(MagnetStatus::Cached, &q, None, Some(&h_old), t);
            prop_assert!(
                score_young.value() >= score_old.value(),
                "younger history ({younger_age:.2}d, {}) should score >= older ({older_age:.2}d, {})",
                score_young.value(), score_old.value()
            );
        }

        /// Score is always in [0.0, 1.0] for any input combination (Req 42.2).
        #[test]
        fn prop_score_bounded(
            status_idx in 0usize..9usize,
            seeds in proptest::option::of(0u32..500u32),
            successes in 0u32..100u32,
            failures in 0u32..100u32,
            age_days in 0.0f64..10.0f64,
        ) {
            let scorer = HealthScorer::default();
            let q = FileQuality::default();
            let t = now();
            let status = MagnetStatus::ALL[status_idx];
            let h = HealthHistory {
                info_hash: "x".into(), store: "rd".into(),
                success: successes, failure: failures, seed_count: None,
                last_seen: t - Duration::from_secs_f64(age_days * 86_400.0),
            };
            let score = scorer.score(status, &q, seeds, Some(&h), t);
            prop_assert!(
                score.value() >= 0.0 && score.value() <= 1.0,
                "score out of bounds: {}", score.value()
            );
        }

        /// sort_by_score produces a non-increasing sequence (Req 42.6).
        #[test]
        fn prop_sort_by_score_is_descending(
            statuses in proptest::collection::vec(0usize..9usize, 1..10),
        ) {
            let scorer = HealthScorer::default();
            let q = FileQuality::default();
            let t = now();
            let mut items: Vec<(&str, HealthScore)> = statuses
                .iter()
                .map(|&i| {
                    let status = MagnetStatus::ALL[i];
                    let score = scorer.score(status, &q, None, no_history(), t);
                    ("item", score)
                })
                .collect();
            sort_by_score(&mut items);
            for w in items.windows(2) {
                prop_assert!(
                    w[0].1.value() >= w[1].1.value(),
                    "sort_by_score not descending: {} < {}",
                    w[0].1.value(), w[1].1.value()
                );
            }
        }
    }
}
