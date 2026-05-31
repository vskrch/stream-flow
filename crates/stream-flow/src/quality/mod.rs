//! Quality selection (`quality`) — Req 38.
//!
//! Provides PTT-style release-name parsing and file ranking for intelligent
//! stream quality selection (design: Components -> Quality Selection).
//!
//! # Overview
//!
//! * [`parse_release_name`] — parses a torrent/file name into a [`ReleaseInfo`]
//!   extracting resolution, codec, audio, source, HDR flags, and release group
//!   (Req 38.4).
//! * [`QualityRanker`] — ranks a list of [`RankedFile`]s by quality preferences
//!   and bandwidth constraints (Req 38.1–38.6).
//! * [`QualityPrefs`] — per-user quality preferences (Req 38.6).

mod property_tests;

use std::fmt;
// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Video resolution extracted from a release name (Req 38.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Resolution {
    /// 480p / SD
    R480p,
    /// 720p / HD
    R720p,
    /// 1080p / Full HD
    R1080p,
    /// 4K / 2160p / UHD
    R2160p,
}

impl Resolution {
    /// Numeric pixel height for this resolution (used for ordering and
    /// bandwidth estimation).
    pub fn height(self) -> u32 {
        match self {
            Resolution::R480p => 480,
            Resolution::R720p => 720,
            Resolution::R1080p => 1080,
            Resolution::R2160p => 2160,
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Resolution::R480p => "480p",
            Resolution::R720p => "720p",
            Resolution::R1080p => "1080p",
            Resolution::R2160p => "2160p",
        }
    }

    /// Parse a resolution from a token string (case-insensitive).
    pub fn from_token(s: &str) -> Option<Resolution> {
        match s.to_ascii_lowercase().as_str() {
            "480p" | "480" | "sd" => Some(Resolution::R480p),
            "720p" | "720" | "hd" => Some(Resolution::R720p),
            "1080p" | "1080" | "fhd" | "fullhd" | "full-hd" => Some(Resolution::R1080p),
            "2160p" | "2160" | "4k" | "uhd" | "ultrahd" | "ultra-hd" => Some(Resolution::R2160p),
            _ => None,
        }
    }
}

impl fmt::Display for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Video codec
// ---------------------------------------------------------------------------

/// Video codec extracted from a release name (Req 38.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VideoCodec {
    /// H.264 / AVC / x264
    H264,
    /// H.265 / HEVC / x265
    H265,
    /// AV1
    AV1,
    /// VP9
    VP9,
}

impl VideoCodec {
    /// Parse a video codec from a token string (case-insensitive).
    pub fn from_token(s: &str) -> Option<VideoCodec> {
        match s.to_ascii_lowercase().as_str() {
            "h264" | "h.264" | "x264" | "avc" => Some(VideoCodec::H264),
            "h265" | "h.265" | "x265" | "hevc" => Some(VideoCodec::H265),
            "av1" => Some(VideoCodec::AV1),
            "vp9" => Some(VideoCodec::VP9),
            _ => None,
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            VideoCodec::H264 => "H.264",
            VideoCodec::H265 => "H.265",
            VideoCodec::AV1 => "AV1",
            VideoCodec::VP9 => "VP9",
        }
    }
}

impl fmt::Display for VideoCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Audio codec
// ---------------------------------------------------------------------------

/// Audio codec/format extracted from a release name (Req 38.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AudioCodec {
    /// Dolby TrueHD (lossless)
    TrueHD,
    /// DTS (lossless or lossy variants)
    DTS,
    /// Dolby Atmos (object-based, usually TrueHD or EAC3 carrier)
    Atmos,
    /// AAC
    AAC,
    /// Dolby Digital (AC-3)
    AC3,
    /// Dolby Digital Plus (E-AC-3)
    EAC3,
    /// DTS-HD Master Audio
    DTSHD,
    /// FLAC (lossless)
    FLAC,
    /// MP3
    MP3,
}

impl AudioCodec {
    /// Parse an audio codec from a token string (case-insensitive).
    pub fn from_token(s: &str) -> Option<AudioCodec> {
        match s.to_ascii_lowercase().as_str() {
            "truehd" | "true-hd" => Some(AudioCodec::TrueHD),
            "dts" => Some(AudioCodec::DTS),
            "atmos" | "dolby-atmos" | "dolbyatmos" => Some(AudioCodec::Atmos),
            "aac" => Some(AudioCodec::AAC),
            "ac3" | "ac-3" | "dolby" | "dd" => Some(AudioCodec::AC3),
            "eac3" | "e-ac3" | "e-ac-3" | "ddp" | "dd+" | "dolbydigitalplus" => {
                Some(AudioCodec::EAC3)
            }
            "dts-hd" | "dtshd" | "dts-hdma" | "dtshdma" => Some(AudioCodec::DTSHD),
            "flac" => Some(AudioCodec::FLAC),
            "mp3" => Some(AudioCodec::MP3),
            _ => None,
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            AudioCodec::TrueHD => "TrueHD",
            AudioCodec::DTS => "DTS",
            AudioCodec::Atmos => "Atmos",
            AudioCodec::AAC => "AAC",
            AudioCodec::AC3 => "AC3",
            AudioCodec::EAC3 => "EAC3",
            AudioCodec::DTSHD => "DTS-HD",
            AudioCodec::FLAC => "FLAC",
            AudioCodec::MP3 => "MP3",
        }
    }
}

impl fmt::Display for AudioCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------

/// Release source extracted from a release name (Req 38.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// Blu-ray disc rip
    BluRay,
    /// Web download (WEB-DL)
    WebDL,
    /// Web rip (WEBRip)
    WebRip,
    /// HDTV capture
    HDTV,
    /// DVD rip
    DVDRip,
    /// CAM / theater recording
    CAM,
    /// Blu-ray remux (lossless container swap)
    BluRayRemux,
}

impl Source {
    /// Parse a source from a token string (case-insensitive).
    pub fn from_token(s: &str) -> Option<Source> {
        match s.to_ascii_lowercase().as_str() {
            "bluray" | "blu-ray" | "bdrip" | "brrip" | "bd" => Some(Source::BluRay),
            "web-dl" | "webdl" => Some(Source::WebDL),
            "webrip" | "web-rip" | "web" => Some(Source::WebRip),
            "hdtv" => Some(Source::HDTV),
            "dvdrip" | "dvd" => Some(Source::DVDRip),
            "cam" | "camrip" | "ts" | "telesync" | "tc" | "telecine" => Some(Source::CAM),
            "remux" | "bdremux" | "blu-ray-remux" => Some(Source::BluRayRemux),
            _ => None,
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Source::BluRay => "BluRay",
            Source::WebDL => "WEB-DL",
            Source::WebRip => "WEBRip",
            Source::HDTV => "HDTV",
            Source::DVDRip => "DVDRip",
            Source::CAM => "CAM",
            Source::BluRayRemux => "BluRay Remux",
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// HDR flags
// ---------------------------------------------------------------------------

/// HDR format flags extracted from a release name (Req 38.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HdrFlag {
    /// Generic HDR
    HDR,
    /// HDR10 (static metadata)
    HDR10,
    /// HDR10+ (dynamic metadata)
    HDR10Plus,
    /// Dolby Vision
    DolbyVision,
    /// Hybrid Log-Gamma
    HLG,
}

impl HdrFlag {
    /// Parse an HDR flag from a token string (case-insensitive).
    pub fn from_token(s: &str) -> Option<HdrFlag> {
        match s.to_ascii_lowercase().as_str() {
            "hdr" => Some(HdrFlag::HDR),
            "hdr10" => Some(HdrFlag::HDR10),
            "hdr10+" | "hdr10plus" => Some(HdrFlag::HDR10Plus),
            "dv" | "dolbyvision" | "dolby-vision" | "dolby.vision" => Some(HdrFlag::DolbyVision),
            "hlg" => Some(HdrFlag::HLG),
            _ => None,
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            HdrFlag::HDR => "HDR",
            HdrFlag::HDR10 => "HDR10",
            HdrFlag::HDR10Plus => "HDR10+",
            HdrFlag::DolbyVision => "Dolby Vision",
            HdrFlag::HLG => "HLG",
        }
    }
}

impl fmt::Display for HdrFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ReleaseInfo — the parsed result
// ---------------------------------------------------------------------------

/// Parsed release information extracted from a torrent/file name (Req 38.4).
///
/// All fields are optional; a field is `None` when the corresponding token was
/// not found in the name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// Detected video resolution.
    pub resolution: Option<Resolution>,
    /// Detected video codec.
    pub video_codec: Option<VideoCodec>,
    /// Detected audio codec(s). Multiple audio tracks may be present.
    pub audio_codecs: Vec<AudioCodec>,
    /// Detected release source.
    pub source: Option<Source>,
    /// Detected HDR flags. Multiple HDR formats may be present.
    pub hdr_flags: Vec<HdrFlag>,
    /// Detected release group (the tag after the final `-` in the name).
    pub release_group: Option<String>,
    /// Audio language codes detected in the name (e.g. `"en"`, `"fr"`).
    pub audio_languages: Vec<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a torrent/file name into a [`ReleaseInfo`] (Req 38.4).
///
/// Uses standard release-naming conventions (PTT-style) to extract resolution,
/// codec, audio, source, HDR flags, and release group from the name.
///
/// # Examples
///
/// ```
/// use stream_flow::quality::{parse_release_name, Resolution, VideoCodec, AudioCodec};
///
/// let info = parse_release_name("Movie.2023.1080p.BluRay.x265.DTS-GROUP");
/// assert_eq!(info.resolution, Some(Resolution::R1080p));
/// assert_eq!(info.video_codec, Some(VideoCodec::H265));
/// assert!(info.audio_codecs.contains(&AudioCodec::DTS));
/// assert_eq!(info.release_group.as_deref(), Some("GROUP"));
/// ```
pub fn parse_release_name(name: &str) -> ReleaseInfo {
    let mut info = ReleaseInfo::default();

    // Normalize: replace dots, underscores, and brackets with spaces, then
    // split into tokens. This handles the common `Movie.Name.2023.1080p`
    // and `Movie_Name_[1080p]` patterns.
    let normalized = name
        .replace('.', " ")
        .replace('_', " ")
        .replace('[', " ")
        .replace(']', " ")
        .replace('(', " ")
        .replace(')', " ");

    // Extract release group: the segment after the last `-` in the *original*
    // name (before normalization), provided it looks like a group tag
    // (alphanumeric, no spaces, 2–20 chars).
    if let Some(pos) = name.rfind('-') {
        let candidate = &name[pos + 1..];
        let candidate = candidate.trim();
        if !candidate.is_empty()
            && candidate.len() <= 20
            && candidate.chars().all(|c| c.is_ascii_alphanumeric())
        {
            info.release_group = Some(candidate.to_string());
        }
    }

    // Tokenize and scan for known tokens.
    // After splitting on dots/underscores/brackets, we also split each token
    // on `-` to handle patterns like `DTS-GROUP` (audio codec + release group)
    // and `HDR10-RELEASE`. Source tokens like `WEB-DL` are tried as the full
    // compound token first, before sub-token splitting.
    let tokens: Vec<&str> = normalized.split_whitespace().collect();
    for token in &tokens {
        // Resolution (full token only)
        if info.resolution.is_none() {
            if let Some(r) = Resolution::from_token(token) {
                info.resolution = Some(r);
                continue;
            }
        }
        // Video codec (full token only)
        if info.video_codec.is_none() {
            if let Some(c) = VideoCodec::from_token(token) {
                info.video_codec = Some(c);
                continue;
            }
        }
        // Audio codec (full token, multiple allowed)
        if let Some(a) = AudioCodec::from_token(token) {
            if !info.audio_codecs.contains(&a) {
                info.audio_codecs.push(a);
            }
            continue;
        }
        // Source (full compound token first, e.g. WEB-DL)
        if info.source.is_none() {
            if let Some(s) = Source::from_token(token) {
                info.source = Some(s);
                continue;
            }
        }
        // HDR flags (full token, multiple allowed)
        if let Some(h) = HdrFlag::from_token(token) {
            if !info.hdr_flags.contains(&h) {
                info.hdr_flags.push(h);
            }
            continue;
        }
        // Audio language codes (full token)
        let lower = token.to_ascii_lowercase();
        if is_language_code(&lower) && !info.audio_languages.contains(&lower) {
            info.audio_languages.push(lower);
            continue;
        }

        // Sub-token splitting on `-`: handles `DTS-GROUP`, `TrueHD-Atmos`,
        // `HDR10-RELEASE`, etc. We only apply this for tokens that contain a
        // dash and were not already matched above.
        if token.contains('-') {
            let parts: Vec<&str> = token.split('-').collect();
            // Track which part indices were consumed by compound matching.
            let mut consumed = vec![false; parts.len()];

            // First pass: try adjacent pairs (e.g. "DTS-HD" from "DTS-HD-GROUP").
            for i in 0..parts.len().saturating_sub(1) {
                let compound = format!("{}-{}", parts[i], parts[i + 1]);
                let sub = compound.trim();
                // Audio codec compound sub-token
                if let Some(a) = AudioCodec::from_token(sub) {
                    if !info.audio_codecs.contains(&a) {
                        info.audio_codecs.push(a);
                    }
                    consumed[i] = true;
                    consumed[i + 1] = true;
                    continue;
                }
                // Source compound sub-token
                if info.source.is_none() {
                    if let Some(s) = Source::from_token(sub) {
                        info.source = Some(s);
                        consumed[i] = true;
                        consumed[i + 1] = true;
                        continue;
                    }
                }
            }

            // Second pass: individual sub-tokens not consumed by compound matching.
            for (i, sub) in parts.iter().enumerate() {
                if consumed[i] {
                    continue;
                }
                let sub = sub.trim();
                if sub.is_empty() {
                    continue;
                }
                // Resolution sub-token
                if info.resolution.is_none() {
                    if let Some(r) = Resolution::from_token(sub) {
                        info.resolution = Some(r);
                        continue;
                    }
                }
                // Video codec sub-token
                if info.video_codec.is_none() {
                    if let Some(c) = VideoCodec::from_token(sub) {
                        info.video_codec = Some(c);
                        continue;
                    }
                }
                // Audio codec sub-token
                if let Some(a) = AudioCodec::from_token(sub) {
                    if !info.audio_codecs.contains(&a) {
                        info.audio_codecs.push(a);
                    }
                    continue;
                }
                // HDR flag sub-token
                if let Some(h) = HdrFlag::from_token(sub) {
                    if !info.hdr_flags.contains(&h) {
                        info.hdr_flags.push(h);
                    }
                    continue;
                }
                // Language code sub-token
                let sub_lower = sub.to_ascii_lowercase();
                if is_language_code(&sub_lower) && !info.audio_languages.contains(&sub_lower) {
                    info.audio_languages.push(sub_lower);
                }
            }
        }
    }

    info
}

/// Heuristic: is this token a plausible audio language code?
///
/// Recognizes common 2-letter (ISO 639-1) and 3-letter (ISO 639-2) language
/// codes that appear in release names. We only match a curated set to avoid
/// false positives from short tokens that are also common English words.
fn is_language_code(s: &str) -> bool {
    matches!(
        s,
        // 2-letter codes
        "en" | "fr" | "de" | "es" | "it" | "pt" | "ru" | "ja" | "ko" | "zh"
        | "ar" | "nl" | "pl" | "sv" | "da" | "fi" | "no" | "tr" | "cs" | "hu"
        | "ro" | "el" | "he" | "hi" | "th" | "vi" | "id" | "ms" | "uk" | "bg"
        // 3-letter codes
        | "eng" | "fre" | "fra" | "ger" | "deu" | "spa" | "ita" | "por" | "rus"
        | "jpn" | "kor" | "chi" | "zho" | "ara" | "dut" | "nld" | "pol" | "swe"
        | "dan" | "fin" | "nor" | "tur" | "ces" | "hun" | "ron" | "ell" | "heb"
        | "hin" | "tha" | "vie" | "ind" | "msa" | "ukr" | "bul" | "mul"
    )
}

// ---------------------------------------------------------------------------
// Quality preferences
// ---------------------------------------------------------------------------

/// Per-user quality preferences (Req 38.6).
///
/// All fields are optional; absent fields use the system defaults.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QualityPrefs {
    /// Maximum resolution to include. Files above this are excluded (Req 38.2).
    /// `None` means no upper bound.
    pub max_resolution: Option<Resolution>,
    /// Preferred resolution order. Files matching earlier entries rank higher.
    /// Default: highest resolution first.
    pub preferred_resolutions: Vec<Resolution>,
    /// Preferred video codecs. Files matching earlier entries rank higher.
    pub preferred_video_codecs: Vec<VideoCodec>,
    /// Preferred audio codecs. Files matching earlier entries rank higher
    /// (Req 38.3).
    pub preferred_audio_codecs: Vec<AudioCodec>,
    /// Preferred audio language codes (Req 38.3). Files matching earlier
    /// entries rank higher.
    pub preferred_audio_languages: Vec<String>,
}

// ---------------------------------------------------------------------------
// RankedFile — input to the ranker
// ---------------------------------------------------------------------------

/// A file candidate for quality ranking (Req 38.1).
///
/// Callers supply the file name and size; the ranker parses the name and
/// applies preferences and bandwidth constraints.
#[derive(Clone, Debug)]
pub struct RankedFile {
    /// File name (used for PTT parsing — Req 38.4).
    pub name: String,
    /// File size in bytes. `-1` means unknown (mirrors [`MagnetFile::UNKNOWN`]).
    pub size: i64,
    /// Pre-computed health score (from the health_score module). Higher is
    /// better. Files are sorted by health score first, then quality score.
    pub health_score: f64,
    /// Parsed release info (populated by the ranker; callers may leave this
    /// as `Default::default()` and the ranker will fill it in).
    pub release_info: ReleaseInfo,
}

impl RankedFile {
    /// Construct a new [`RankedFile`] with the given name and size.
    pub fn new(name: impl Into<String>, size: i64) -> Self {
        Self {
            name: name.into(),
            size,
            health_score: 0.0,
            release_info: ReleaseInfo::default(),
        }
    }

    /// Construct a new [`RankedFile`] with a health score.
    pub fn with_health_score(mut self, score: f64) -> Self {
        self.health_score = score;
        self
    }
}

// ---------------------------------------------------------------------------
// QualityRanker
// ---------------------------------------------------------------------------

/// Ranks files by quality preferences and bandwidth constraints (Req 38.1–38.6).
///
/// # Ranking algorithm
///
/// 1. Parse each file's release name into a [`ReleaseInfo`].
/// 2. **Exclude** files whose detected resolution exceeds `prefs.max_resolution`
///    (Req 38.2).
/// 3. **Exclude** files whose estimated bitrate exceeds 80% of the available
///    bandwidth estimate (Req 38.5).
/// 4. **Score** remaining files:
///    - Primary key: `health_score` (descending) — Req 38.1 (files ranked by
///      Health_Score then quality score).
///    - Secondary key: quality score (descending):
///      - Resolution preference match (Req 38.1, 38.2).
///      - Audio codec/language preference match (Req 38.3).
///      - Video codec preference match.
///      - File size as tiebreaker (Req 38.1 default: largest size wins).
pub struct QualityRanker;

impl QualityRanker {
    /// Rank `files` by quality preferences and bandwidth constraints.
    ///
    /// Returns a new `Vec` of [`RankedFile`]s in descending quality order.
    /// Files that are excluded (resolution too high, bitrate too high) are
    /// omitted from the result.
    ///
    /// `bandwidth_bps` is the estimated client bandwidth in bits per second.
    /// Pass `None` when no estimate is available (bandwidth filtering is
    /// skipped — Req 38.5).
    pub fn rank(
        mut files: Vec<RankedFile>,
        prefs: &QualityPrefs,
        bandwidth_bps: Option<u64>,
    ) -> Vec<RankedFile> {
        // Step 1: parse release names.
        for f in &mut files {
            f.release_info = parse_release_name(&f.name);
        }

        // Step 2 & 3: filter.
        files.retain(|f| {
            // Exclude above max resolution (Req 38.2).
            if let (Some(max), Some(res)) = (prefs.max_resolution, f.release_info.resolution) {
                if res > max {
                    return false;
                }
            }
            // Exclude if bitrate would exceed 80% of bandwidth estimate (Req 38.5).
            if let Some(bw) = bandwidth_bps {
                if f.size > 0 {
                    // Estimate bitrate from file size. We don't know the exact
                    // duration, so we use a heuristic based on resolution.
                    let estimated_bitrate = estimate_bitrate_bps(f.size, &f.release_info);
                    if estimated_bitrate > (bw as f64 * 0.8) as u64 {
                        return false;
                    }
                }
            }
            true
        });

        // Step 4: sort by (health_score desc, quality_score desc).
        files.sort_by(|a, b| {
            // Primary: health score descending.
            let hs = b
                .health_score
                .partial_cmp(&a.health_score)
                .unwrap_or(std::cmp::Ordering::Equal);
            if hs != std::cmp::Ordering::Equal {
                return hs;
            }
            // Secondary: quality score descending.
            let qa = quality_score(a, prefs);
            let qb = quality_score(b, prefs);
            qb.partial_cmp(&qa)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        files
    }
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

/// Compute a quality score for a file given the user's preferences.
///
/// Higher is better. The score is a floating-point value composed of:
/// - Resolution score (0–4000, based on resolution height or preference rank).
/// - Audio preference bonus (0–300).
/// - Video codec preference bonus (0–200).
/// - Size tiebreaker (normalized to 0–1 range, scaled by 1.0).
fn quality_score(file: &RankedFile, prefs: &QualityPrefs) -> f64 {
    let mut score = 0.0_f64;

    // Resolution score.
    if let Some(res) = file.release_info.resolution {
        if !prefs.preferred_resolutions.is_empty() {
            // Preference-list rank: first entry = highest bonus.
            if let Some(pos) = prefs.preferred_resolutions.iter().position(|&r| r == res) {
                let n = prefs.preferred_resolutions.len() as f64;
                score += (n - pos as f64) / n * 4000.0;
            }
            // Not in preference list: use raw height as a fallback.
            else {
                score += res.height() as f64;
            }
        } else {
            // Default: highest resolution first (Req 38.1).
            score += res.height() as f64;
        }
    }

    // Audio codec preference bonus (Req 38.3).
    if !prefs.preferred_audio_codecs.is_empty() {
        let n = prefs.preferred_audio_codecs.len() as f64;
        for audio in &file.release_info.audio_codecs {
            if let Some(pos) = prefs.preferred_audio_codecs.iter().position(|a| a == audio) {
                score += (n - pos as f64) / n * 300.0;
                break; // only count the best match
            }
        }
    }

    // Audio language preference bonus (Req 38.3).
    if !prefs.preferred_audio_languages.is_empty() {
        let n = prefs.preferred_audio_languages.len() as f64;
        for lang in &file.release_info.audio_languages {
            if let Some(pos) = prefs
                .preferred_audio_languages
                .iter()
                .position(|l| l == lang)
            {
                score += (n - pos as f64) / n * 200.0;
                break;
            }
        }
    }

    // Video codec preference bonus.
    if !prefs.preferred_video_codecs.is_empty() {
        if let Some(codec) = file.release_info.video_codec {
            let n = prefs.preferred_video_codecs.len() as f64;
            if let Some(pos) = prefs.preferred_video_codecs.iter().position(|&c| c == codec) {
                score += (n - pos as f64) / n * 200.0;
            }
        }
    }

    // Size tiebreaker: larger files rank higher (Req 38.1 default).
    // Normalize to [0, 1) so it only breaks ties within the same quality tier.
    if file.size > 0 {
        // Use log scale to avoid huge files dominating the score.
        score += (file.size as f64).ln() / 50.0;
    }

    score
}

/// Estimate the bitrate of a file in bits per second.
///
/// Since we don't know the exact duration, we use a heuristic based on the
/// resolution and typical encoding parameters for that resolution tier.
fn estimate_bitrate_bps(size_bytes: i64, info: &ReleaseInfo) -> u64 {
    // Typical movie duration: 2 hours (7200 seconds).
    // For TV episodes: 45 minutes (2700 seconds).
    // We use 2 hours as a conservative estimate (underestimates bitrate for
    // short content, which is the safe direction — we'd rather not exclude
    // a file that would actually be fine).
    let duration_secs: f64 = match info.resolution {
        Some(Resolution::R2160p) => 7200.0,
        Some(Resolution::R1080p) => 7200.0,
        Some(Resolution::R720p) => 7200.0,
        Some(Resolution::R480p) => 7200.0,
        None => 7200.0,
    };

    let bits = size_bytes as f64 * 8.0;
    (bits / duration_secs) as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Resolution parsing
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_from_token_recognizes_all_variants() {
        assert_eq!(Resolution::from_token("480p"), Some(Resolution::R480p));
        assert_eq!(Resolution::from_token("SD"), Some(Resolution::R480p));
        assert_eq!(Resolution::from_token("720p"), Some(Resolution::R720p));
        assert_eq!(Resolution::from_token("HD"), Some(Resolution::R720p));
        assert_eq!(Resolution::from_token("1080p"), Some(Resolution::R1080p));
        assert_eq!(Resolution::from_token("FHD"), Some(Resolution::R1080p));
        assert_eq!(Resolution::from_token("2160p"), Some(Resolution::R2160p));
        assert_eq!(Resolution::from_token("4K"), Some(Resolution::R2160p));
        assert_eq!(Resolution::from_token("UHD"), Some(Resolution::R2160p));
        assert_eq!(Resolution::from_token("unknown"), None);
    }

    #[test]
    fn resolution_ordering_is_ascending_by_height() {
        assert!(Resolution::R480p < Resolution::R720p);
        assert!(Resolution::R720p < Resolution::R1080p);
        assert!(Resolution::R1080p < Resolution::R2160p);
    }

    // -----------------------------------------------------------------------
    // Video codec parsing
    // -----------------------------------------------------------------------

    #[test]
    fn video_codec_from_token_recognizes_all_variants() {
        assert_eq!(VideoCodec::from_token("x264"), Some(VideoCodec::H264));
        assert_eq!(VideoCodec::from_token("H264"), Some(VideoCodec::H264));
        assert_eq!(VideoCodec::from_token("AVC"), Some(VideoCodec::H264));
        assert_eq!(VideoCodec::from_token("x265"), Some(VideoCodec::H265));
        assert_eq!(VideoCodec::from_token("HEVC"), Some(VideoCodec::H265));
        assert_eq!(VideoCodec::from_token("H265"), Some(VideoCodec::H265));
        assert_eq!(VideoCodec::from_token("AV1"), Some(VideoCodec::AV1));
        assert_eq!(VideoCodec::from_token("VP9"), Some(VideoCodec::VP9));
        assert_eq!(VideoCodec::from_token("xvid"), None);
    }

    // -----------------------------------------------------------------------
    // Audio codec parsing
    // -----------------------------------------------------------------------

    #[test]
    fn audio_codec_from_token_recognizes_all_variants() {
        assert_eq!(AudioCodec::from_token("TrueHD"), Some(AudioCodec::TrueHD));
        assert_eq!(AudioCodec::from_token("DTS"), Some(AudioCodec::DTS));
        assert_eq!(AudioCodec::from_token("Atmos"), Some(AudioCodec::Atmos));
        assert_eq!(AudioCodec::from_token("AAC"), Some(AudioCodec::AAC));
        assert_eq!(AudioCodec::from_token("AC3"), Some(AudioCodec::AC3));
        assert_eq!(AudioCodec::from_token("DD"), Some(AudioCodec::AC3));
        assert_eq!(AudioCodec::from_token("EAC3"), Some(AudioCodec::EAC3));
        assert_eq!(AudioCodec::from_token("DDP"), Some(AudioCodec::EAC3));
        assert_eq!(AudioCodec::from_token("DTS-HD"), Some(AudioCodec::DTSHD));
        assert_eq!(AudioCodec::from_token("FLAC"), Some(AudioCodec::FLAC));
        assert_eq!(AudioCodec::from_token("MP3"), Some(AudioCodec::MP3));
        assert_eq!(AudioCodec::from_token("opus"), None);
    }

    // -----------------------------------------------------------------------
    // Source parsing
    // -----------------------------------------------------------------------

    #[test]
    fn source_from_token_recognizes_all_variants() {
        assert_eq!(Source::from_token("BluRay"), Some(Source::BluRay));
        assert_eq!(Source::from_token("BDRip"), Some(Source::BluRay));
        assert_eq!(Source::from_token("WEB-DL"), Some(Source::WebDL));
        assert_eq!(Source::from_token("WEBDL"), Some(Source::WebDL));
        assert_eq!(Source::from_token("WEBRip"), Some(Source::WebRip));
        assert_eq!(Source::from_token("HDTV"), Some(Source::HDTV));
        assert_eq!(Source::from_token("DVDRip"), Some(Source::DVDRip));
        assert_eq!(Source::from_token("CAM"), Some(Source::CAM));
        assert_eq!(Source::from_token("Remux"), Some(Source::BluRayRemux));
        assert_eq!(Source::from_token("VHS"), None);
    }

    // -----------------------------------------------------------------------
    // HDR flag parsing
    // -----------------------------------------------------------------------

    #[test]
    fn hdr_flag_from_token_recognizes_all_variants() {
        assert_eq!(HdrFlag::from_token("HDR"), Some(HdrFlag::HDR));
        assert_eq!(HdrFlag::from_token("HDR10"), Some(HdrFlag::HDR10));
        assert_eq!(HdrFlag::from_token("HDR10+"), Some(HdrFlag::HDR10Plus));
        assert_eq!(HdrFlag::from_token("DV"), Some(HdrFlag::DolbyVision));
        assert_eq!(HdrFlag::from_token("DolbyVision"), Some(HdrFlag::DolbyVision));
        assert_eq!(HdrFlag::from_token("HLG"), Some(HdrFlag::HLG));
        assert_eq!(HdrFlag::from_token("SDR"), None);
    }

    // -----------------------------------------------------------------------
    // parse_release_name — unit tests (Req 38.4)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_extracts_resolution_from_common_patterns() {
        let cases = [
            ("Movie.2023.1080p.BluRay.x265-GROUP", Some(Resolution::R1080p)),
            ("Show.S01E01.720p.WEB-DL.AAC-TEAM", Some(Resolution::R720p)),
            ("Film.2022.2160p.UHD.BluRay.HDR-RELEASE", Some(Resolution::R2160p)),
            ("Old.Movie.480p.DVDRip.XviD", Some(Resolution::R480p)),
            ("No.Resolution.Here.BluRay.x264", None),
        ];
        for (name, expected) in cases {
            let info = parse_release_name(name);
            assert_eq!(info.resolution, expected, "name={name}");
        }
    }

    #[test]
    fn parse_extracts_video_codec() {
        let info = parse_release_name("Movie.2023.1080p.BluRay.x265.DTS-GROUP");
        assert_eq!(info.video_codec, Some(VideoCodec::H265));

        let info = parse_release_name("Movie.2023.1080p.WEB-DL.H264.AAC");
        assert_eq!(info.video_codec, Some(VideoCodec::H264));

        let info = parse_release_name("Movie.2023.2160p.BluRay.HEVC.TrueHD");
        assert_eq!(info.video_codec, Some(VideoCodec::H265));

        let info = parse_release_name("Movie.2023.1080p.WEB.AV1.AAC");
        assert_eq!(info.video_codec, Some(VideoCodec::AV1));
    }

    #[test]
    fn parse_extracts_audio_codecs() {
        let info = parse_release_name("Movie.2023.1080p.BluRay.x265.DTS-GROUP");
        assert!(info.audio_codecs.contains(&AudioCodec::DTS), "{:?}", info.audio_codecs);

        let info = parse_release_name("Movie.2023.1080p.BluRay.TrueHD.Atmos.x265");
        assert!(info.audio_codecs.contains(&AudioCodec::TrueHD));
        assert!(info.audio_codecs.contains(&AudioCodec::Atmos));

        let info = parse_release_name("Show.S01E01.720p.WEB-DL.AAC-TEAM");
        assert!(info.audio_codecs.contains(&AudioCodec::AAC));
    }

    #[test]
    fn parse_extracts_source() {
        let info = parse_release_name("Movie.2023.1080p.BluRay.x265-GROUP");
        assert_eq!(info.source, Some(Source::BluRay));

        let info = parse_release_name("Show.S01E01.720p.WEB-DL.AAC");
        assert_eq!(info.source, Some(Source::WebDL));

        let info = parse_release_name("Movie.2023.1080p.WEBRip.x264");
        assert_eq!(info.source, Some(Source::WebRip));

        let info = parse_release_name("Show.S01E01.HDTV.x264");
        assert_eq!(info.source, Some(Source::HDTV));
    }

    #[test]
    fn parse_extracts_hdr_flags() {
        let info = parse_release_name("Movie.2023.2160p.BluRay.HDR10.x265");
        assert!(info.hdr_flags.contains(&HdrFlag::HDR10));

        let info = parse_release_name("Movie.2023.2160p.BluRay.HDR.DV.x265");
        assert!(info.hdr_flags.contains(&HdrFlag::HDR));
        assert!(info.hdr_flags.contains(&HdrFlag::DolbyVision));
    }

    #[test]
    fn parse_extracts_release_group() {
        let info = parse_release_name("Movie.2023.1080p.BluRay.x265-YIFY");
        assert_eq!(info.release_group.as_deref(), Some("YIFY"));

        let info = parse_release_name("Movie.2023.1080p.BluRay.x265-GROUP123");
        assert_eq!(info.release_group.as_deref(), Some("GROUP123"));

        // No group (no dash at end)
        let info = parse_release_name("Movie.2023.1080p.BluRay.x265");
        assert_eq!(info.release_group, None);
    }

    #[test]
    fn parse_handles_bracket_and_underscore_separators() {
        let info = parse_release_name("[1080p] Movie_2023_BluRay_x265_DTS");
        assert_eq!(info.resolution, Some(Resolution::R1080p));
        assert_eq!(info.video_codec, Some(VideoCodec::H265));
        assert!(info.audio_codecs.contains(&AudioCodec::DTS));
    }

    #[test]
    fn parse_is_case_insensitive() {
        let info = parse_release_name("movie.2023.1080P.BLURAY.X265.DTS-group");
        assert_eq!(info.resolution, Some(Resolution::R1080p));
        assert_eq!(info.video_codec, Some(VideoCodec::H265));
        assert!(info.audio_codecs.contains(&AudioCodec::DTS));
    }

    #[test]
    fn parse_empty_name_returns_default() {
        let info = parse_release_name("");
        assert_eq!(info, ReleaseInfo::default());
    }

    #[test]
    fn parse_does_not_duplicate_audio_codecs() {
        let info = parse_release_name("Movie.DTS.DTS.DTS-GROUP");
        assert_eq!(info.audio_codecs.len(), 1);
    }

    // -----------------------------------------------------------------------
    // QualityRanker — unit tests (Req 38.1–38.6)
    // -----------------------------------------------------------------------

    fn make_file(name: &str, size_gb: f64) -> RankedFile {
        RankedFile::new(name, (size_gb * 1024.0 * 1024.0 * 1024.0) as i64)
    }

    #[test]
    fn rank_default_orders_by_resolution_desc_then_size_desc() {
        // Req 38.1: default = highest resolution first, then largest size.
        let files = vec![
            make_file("Movie.720p.WEB-DL.x264", 2.0),
            make_file("Movie.1080p.BluRay.x265", 8.0),
            make_file("Movie.1080p.WEB-DL.x264", 4.0),
            make_file("Movie.480p.DVDRip.x264", 1.0),
        ];
        let ranked = QualityRanker::rank(files, &QualityPrefs::default(), None);
        assert_eq!(ranked.len(), 4);
        // First two should be 1080p (larger first), then 720p, then 480p.
        assert_eq!(ranked[0].release_info.resolution, Some(Resolution::R1080p));
        assert_eq!(ranked[1].release_info.resolution, Some(Resolution::R1080p));
        assert!(ranked[0].size >= ranked[1].size, "larger 1080p file should rank first");
        assert_eq!(ranked[2].release_info.resolution, Some(Resolution::R720p));
        assert_eq!(ranked[3].release_info.resolution, Some(Resolution::R480p));
    }

    #[test]
    fn rank_excludes_files_above_max_resolution() {
        // Req 38.2: exclude files whose resolution exceeds max_resolution.
        let files = vec![
            make_file("Movie.2160p.BluRay.x265", 50.0),
            make_file("Movie.1080p.BluRay.x265", 15.0),
            make_file("Movie.720p.WEB-DL.x264", 4.0),
        ];
        let prefs = QualityPrefs {
            max_resolution: Some(Resolution::R1080p),
            ..Default::default()
        };
        let ranked = QualityRanker::rank(files, &prefs, None);
        assert_eq!(ranked.len(), 2, "2160p should be excluded");
        assert!(ranked.iter().all(|f| {
            f.release_info.resolution.map_or(true, |r| r <= Resolution::R1080p)
        }));
    }

    #[test]
    fn rank_excludes_files_above_bandwidth_limit() {
        // Req 38.5: exclude files whose bitrate exceeds 80% of bandwidth.
        // A 50 GB 2160p file over 2h = ~55 Mbps. Set bandwidth to 10 Mbps.
        let files = vec![
            make_file("Movie.2160p.BluRay.x265", 50.0), // ~55 Mbps — too high
            make_file("Movie.1080p.WEB-DL.x264", 4.0),  // ~4.4 Mbps — ok
        ];
        let bandwidth_bps = 10_000_000_u64; // 10 Mbps
        let ranked = QualityRanker::rank(files, &QualityPrefs::default(), Some(bandwidth_bps));
        assert_eq!(ranked.len(), 1, "50 GB file should be excluded at 10 Mbps");
        assert_eq!(ranked[0].release_info.resolution, Some(Resolution::R1080p));
    }

    #[test]
    fn rank_bandwidth_threshold_is_80_percent() {
        // Req 38.5: threshold is exactly 80% of bandwidth.
        // File: 4 GB over 2h = ~4.4 Mbps.
        // Bandwidth: 5.5 Mbps → 80% = 4.4 Mbps → file is right at the edge.
        // We use a file that is clearly above and one clearly below.
        let files = vec![
            make_file("Movie.1080p.BluRay.x265", 20.0), // ~22 Mbps
            make_file("Movie.720p.WEB-DL.x264", 1.0),   // ~1.1 Mbps
        ];
        let bandwidth_bps = 15_000_000_u64; // 15 Mbps → 80% = 12 Mbps
        let ranked = QualityRanker::rank(files, &QualityPrefs::default(), Some(bandwidth_bps));
        // 20 GB file: ~22 Mbps > 12 Mbps → excluded.
        // 1 GB file: ~1.1 Mbps < 12 Mbps → included.
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].release_info.resolution, Some(Resolution::R720p));
    }

    #[test]
    fn rank_prefers_audio_codec_match() {
        // Req 38.3: prefer files matching preferred audio codec.
        let files = vec![
            make_file("Movie.1080p.BluRay.x265.AAC-GROUP", 8.0),
            make_file("Movie.1080p.BluRay.x265.DTS-GROUP", 8.0),
        ];
        let prefs = QualityPrefs {
            preferred_audio_codecs: vec![AudioCodec::DTS],
            ..Default::default()
        };
        let ranked = QualityRanker::rank(files, &prefs, None);
        assert_eq!(ranked.len(), 2);
        assert!(
            ranked[0].release_info.audio_codecs.contains(&AudioCodec::DTS),
            "DTS file should rank first"
        );
    }

    #[test]
    fn rank_prefers_audio_language_match() {
        // Req 38.3: prefer files matching preferred audio language.
        let files = vec![
            make_file("Movie.1080p.BluRay.x265.fr.AAC-GROUP", 8.0),
            make_file("Movie.1080p.BluRay.x265.en.AAC-GROUP", 8.0),
        ];
        let prefs = QualityPrefs {
            preferred_audio_languages: vec!["en".to_string()],
            ..Default::default()
        };
        let ranked = QualityRanker::rank(files, &prefs, None);
        assert_eq!(ranked.len(), 2);
        assert!(
            ranked[0].release_info.audio_languages.contains(&"en".to_string()),
            "English file should rank first"
        );
    }

    #[test]
    fn rank_respects_preferred_resolution_order() {
        // Req 38.1: preferred_resolutions overrides default ordering.
        let files = vec![
            make_file("Movie.2160p.BluRay.x265", 50.0),
            make_file("Movie.1080p.BluRay.x265", 15.0),
            make_file("Movie.720p.WEB-DL.x264", 4.0),
        ];
        let prefs = QualityPrefs {
            // Prefer 1080p over 4K (e.g. user wants 1080p for bandwidth reasons).
            preferred_resolutions: vec![
                Resolution::R1080p,
                Resolution::R720p,
                Resolution::R2160p,
            ],
            ..Default::default()
        };
        let ranked = QualityRanker::rank(files, &prefs, None);
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].release_info.resolution, Some(Resolution::R1080p));
        assert_eq!(ranked[1].release_info.resolution, Some(Resolution::R720p));
        assert_eq!(ranked[2].release_info.resolution, Some(Resolution::R2160p));
    }

    #[test]
    fn rank_health_score_is_primary_sort_key() {
        // Files ranked by health_score first, then quality score.
        let files = vec![
            RankedFile::new("Movie.2160p.BluRay.x265", 50 * 1024 * 1024 * 1024)
                .with_health_score(0.5),
            RankedFile::new("Movie.1080p.WEB-DL.x264", 4 * 1024 * 1024 * 1024)
                .with_health_score(0.9),
        ];
        let ranked = QualityRanker::rank(files, &QualityPrefs::default(), None);
        assert_eq!(ranked.len(), 2);
        // 1080p file has higher health score → ranks first despite lower resolution.
        assert_eq!(ranked[0].release_info.resolution, Some(Resolution::R1080p));
        assert_eq!(ranked[1].release_info.resolution, Some(Resolution::R2160p));
    }

    #[test]
    fn rank_empty_input_returns_empty() {
        let ranked = QualityRanker::rank(vec![], &QualityPrefs::default(), None);
        assert!(ranked.is_empty());
    }

    #[test]
    fn rank_unknown_size_files_are_not_excluded_by_bandwidth() {
        // Files with size = -1 (unknown) should not be excluded by bandwidth.
        let files = vec![RankedFile::new("Movie.1080p.BluRay.x265", -1)];
        let ranked = QualityRanker::rank(files, &QualityPrefs::default(), Some(1_000_000));
        assert_eq!(ranked.len(), 1, "unknown-size file should not be excluded");
    }

    #[test]
    fn rank_no_bandwidth_skips_bandwidth_filter() {
        // When bandwidth_bps is None, no files are excluded for bandwidth.
        let files = vec![
            make_file("Movie.2160p.BluRay.x265", 100.0), // would be excluded at low bandwidth
        ];
        let ranked = QualityRanker::rank(files, &QualityPrefs::default(), None);
        assert_eq!(ranked.len(), 1);
    }

    #[test]
    fn rank_max_resolution_none_includes_all_resolutions() {
        // When max_resolution is None, no files are excluded for resolution.
        let files = vec![
            make_file("Movie.2160p.BluRay.x265", 50.0),
            make_file("Movie.1080p.BluRay.x265", 15.0),
        ];
        let prefs = QualityPrefs {
            max_resolution: None,
            ..Default::default()
        };
        let ranked = QualityRanker::rank(files, &prefs, None);
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn rank_files_without_resolution_are_not_excluded_by_max_resolution() {
        // Files with no detected resolution should not be excluded by max_resolution.
        let files = vec![
            make_file("Movie.BluRay.x265-GROUP", 8.0), // no resolution token
            make_file("Movie.2160p.BluRay.x265", 50.0),
        ];
        let prefs = QualityPrefs {
            max_resolution: Some(Resolution::R1080p),
            ..Default::default()
        };
        let ranked = QualityRanker::rank(files, &prefs, None);
        // 2160p excluded, no-resolution file kept.
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].release_info.resolution, None);
    }
}
