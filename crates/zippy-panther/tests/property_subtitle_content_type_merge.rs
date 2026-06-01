//! Property-based test for subtitle content-type mapping and de-duplicated
//! merge (task 28.8).
//!
//! Feature: ZippyPanther, Property 39
//!
//! **Property 39: Subtitle content-type mapping and de-duplicated merge**
//!
//! **Validates: Requirements 39.3, 39.4**
//!
//! Requirement 39.3: "THE Stream_Flow_System SHALL support SRT, VTT, and
//! ASS/SSA subtitle formats for proxying."
//!
//! Requirement 39.4: "WHEN proxying subtitles, THE Stream_Flow_System SHALL
//! set the correct `Content-Type` header (`text/vtt`, `application/x-subrip`,
//! `text/x-ssa`)."
//!
//! Requirement 39.6: "WHEN the Wrap addon aggregates streams from upstream
//! addons, THE Stream_Flow_System SHALL merge subtitle lists from all upstreams
//! without duplicates."
//!
//! ## Properties exercised
//!
//! 1. **Content-type mapping is correct and deterministic** — for any URL
//!    whose path ends in a supported subtitle extension (`srt`, `vtt`, `ass`,
//!    `ssa`), `content_type_for_url` returns the exact `Content-Type` string
//!    mandated by Req 39.4, and calling it twice on the same URL always
//!    returns the same value (determinism).
//!
//! 2. **Unknown / unsupported extensions fall back deterministically** — for
//!    any URL whose extension is not one of the four supported ones (e.g.
//!    `sub`, `idx`, or arbitrary strings), `content_type_for_url` returns
//!    `"application/octet-stream"` consistently.
//!
//! 3. **De-duplicated merge produces no duplicate (lang, url) pairs** — for
//!    any collection of subtitle lists, `merge_subtitles` returns a list in
//!    which every `(lang, url)` pair appears at most once.
//!
//! 4. **Merged list contains all unique (lang, url) pairs** — every unique
//!    `(lang, url)` pair present in any input list appears in the output.

use proptest::prelude::*;
use zippy_panther::stremio::types::Subtitle;
use zippy_panther::subtitles::{content_type_for_url, format_from_url, merge_subtitles};

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// The four supported subtitle extensions (Req 39.3).
const SUPPORTED_EXTS: &[&str] = &["srt", "vtt", "ass", "ssa"];

/// The expected Content-Type for each supported extension (Req 39.4).
fn expected_content_type(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "srt" => "application/x-subrip",
        "vtt" => "text/vtt",
        "ass" | "ssa" => "text/x-ssa",
        _ => "application/octet-stream",
    }
}

/// Strategy: pick one of the four supported extensions.
fn arb_supported_ext() -> impl Strategy<Value = String> {
    (0..SUPPORTED_EXTS.len()).prop_map(|i| SUPPORTED_EXTS[i].to_string())
}

/// Strategy: pick one of the four supported extensions in an arbitrary case
/// mix (e.g. "SRT", "Vtt", "aSs").
fn arb_supported_ext_any_case() -> impl Strategy<Value = String> {
    arb_supported_ext().prop_flat_map(|ext| {
        // For each character, randomly uppercase or lowercase it.
        let len = ext.len();
        proptest::collection::vec(any::<bool>(), len).prop_map(move |cases| {
            ext.chars()
                .zip(cases.iter())
                .map(|(c, &upper)| if upper { c.to_ascii_uppercase() } else { c })
                .collect::<String>()
        })
    })
}

/// Strategy: produce a URL with a supported subtitle extension.
///
/// The URL is a simple `https://host/path/filename.<ext>` with an optional
/// query string and fragment to verify those are stripped before extension
/// detection.
fn arb_url_with_supported_ext() -> impl Strategy<Value = (String, String)> {
    (
        arb_supported_ext_any_case(),
        // Optional query string suffix (empty or "?token=abc").
        prop_oneof![Just("".to_string()), Just("?token=abc&lang=en".to_string())],
        // Optional fragment suffix.
        prop_oneof![Just("".to_string()), Just("#anchor".to_string())],
    )
        .prop_map(|(ext, query, fragment)| {
            let url = format!("https://cdn.example.com/subtitles/track.{ext}{query}{fragment}");
            let canonical_ext = ext.to_ascii_lowercase();
            (url, canonical_ext)
        })
}

/// Strategy: produce a URL with an unsupported / unknown extension.
///
/// We use a fixed set of known-unsupported extensions plus a few arbitrary
/// strings to keep the strategy simple and deterministic.
fn arb_url_with_unsupported_ext() -> impl Strategy<Value = String> {
    prop_oneof![
        // Known subtitle-adjacent formats that are NOT in the supported set.
        Just("https://cdn.example.com/sub.sub".to_string()),
        Just("https://cdn.example.com/sub.idx".to_string()),
        Just("https://cdn.example.com/sub.sbv".to_string()),
        Just("https://cdn.example.com/sub.dfxp".to_string()),
        Just("https://cdn.example.com/sub.ttml".to_string()),
        // Completely arbitrary extensions.
        Just("https://cdn.example.com/sub.xyz".to_string()),
        Just("https://cdn.example.com/sub.mp4".to_string()),
        // No extension at all.
        Just("https://cdn.example.com/subtitle".to_string()),
    ]
}

// ---------------------------------------------------------------------------
// Subtitle list strategies (for merge properties)
// ---------------------------------------------------------------------------

/// Strategy: produce a non-empty language code (1–5 ASCII lowercase letters).
fn arb_lang() -> impl Strategy<Value = String> {
    "[a-z]{1,5}"
}

/// Strategy: produce a subtitle URL (simple, no duplicates within a single
/// generated value — uniqueness across lists is handled by the merge test).
fn arb_subtitle_url() -> impl Strategy<Value = String> {
    ("[a-z]{3,8}", "[a-z]{3,8}", arb_supported_ext())
        .prop_map(|(host, path, ext)| format!("https://{host}.example.com/{path}.{ext}"))
}

/// Strategy: produce a single [`Subtitle`] with arbitrary lang and url.
fn arb_subtitle() -> impl Strategy<Value = Subtitle> {
    (arb_lang(), arb_subtitle_url()).prop_map(|(lang, url)| Subtitle {
        id: format!("{lang}-{url}"),
        url,
        lang,
        ..Default::default()
    })
}

/// Strategy: produce a list of 0–8 subtitles (may contain duplicates within
/// the list — the merge function must handle them).
fn arb_subtitle_list() -> impl Strategy<Value = Vec<Subtitle>> {
    proptest::collection::vec(arb_subtitle(), 0..=8)
}

/// Strategy: produce 1–4 subtitle lists (simulating multiple upstream sources).
fn arb_subtitle_lists() -> impl Strategy<Value = Vec<Vec<Subtitle>>> {
    proptest::collection::vec(arb_subtitle_list(), 1..=4)
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    // >= 100 iterations as required by the task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    // -----------------------------------------------------------------------
    // Property 1: Content-type mapping is correct for supported extensions
    // (Req 39.3, 39.4)
    // -----------------------------------------------------------------------

    /// Feature: ZippyPanther, Property 39 — supported extension maps to the
    /// correct Content-Type.
    ///
    /// **Validates: Requirements 39.3, 39.4**
    #[test]
    fn supported_extension_maps_to_correct_content_type(
        (url, canonical_ext) in arb_url_with_supported_ext()
    ) {
        let ct = content_type_for_url(&url);
        let expected = expected_content_type(&canonical_ext);
        prop_assert_eq!(
            ct, expected,
            "URL={:?} ext={:?}: expected Content-Type {:?}, got {:?}",
            url, canonical_ext, expected, ct
        );
    }

    /// Feature: ZippyPanther, Property 39 — content-type mapping is
    /// deterministic: calling it twice on the same URL always returns the same
    /// value.
    ///
    /// **Validates: Requirements 39.4**
    #[test]
    fn content_type_mapping_is_deterministic(
        (url, _ext) in arb_url_with_supported_ext()
    ) {
        let ct1 = content_type_for_url(&url);
        let ct2 = content_type_for_url(&url);
        prop_assert_eq!(
            ct1, ct2,
            "content_type_for_url must be deterministic for URL={:?}",
            url
        );
    }

    // -----------------------------------------------------------------------
    // Property 2: Unknown extensions fall back to application/octet-stream
    // deterministically (Req 39.4)
    // -----------------------------------------------------------------------

    /// Feature: ZippyPanther, Property 39 — unsupported extension falls back to
    /// `application/octet-stream` consistently.
    ///
    /// **Validates: Requirements 39.4**
    #[test]
    fn unsupported_extension_falls_back_to_octet_stream(url in arb_url_with_unsupported_ext()) {
        let ct = content_type_for_url(&url);
        prop_assert_eq!(
            ct,
            "application/octet-stream",
            "URL={:?}: unsupported extension must fall back to application/octet-stream, got {:?}",
            url, ct
        );
    }

    /// Feature: ZippyPanther, Property 39 — unsupported extension fallback is
    /// deterministic.
    ///
    /// **Validates: Requirements 39.4**
    #[test]
    fn unsupported_extension_fallback_is_deterministic(url in arb_url_with_unsupported_ext()) {
        let ct1 = content_type_for_url(&url);
        let ct2 = content_type_for_url(&url);
        prop_assert_eq!(
            ct1, ct2,
            "content_type_for_url must be deterministic for unsupported URL={:?}",
            url
        );
    }

    // -----------------------------------------------------------------------
    // Property 3: De-duplicated merge produces no duplicate (lang, url) pairs
    // (Req 39.6)
    // -----------------------------------------------------------------------

    /// Feature: ZippyPanther, Property 39 — merged subtitle list contains no
    /// duplicate (lang, url) pairs.
    ///
    /// **Validates: Requirements 39.6**
    #[test]
    fn merged_list_has_no_duplicate_lang_url_pairs(lists in arb_subtitle_lists()) {
        let merged = merge_subtitles(lists);

        // Collect all (lang, url) pairs and check for duplicates.
        let mut seen = std::collections::HashSet::new();
        for sub in &merged {
            let key = (sub.lang.clone(), sub.url.clone());
            let lang = key.0.clone();
            let url = key.1.clone();
            prop_assert!(
                seen.insert(key),
                "duplicate (lang, url) pair found in merged list: lang={:?} url={:?}",
                lang,
                url
            );
        }
    }

    // -----------------------------------------------------------------------
    // Property 4: Merged list contains all unique (lang, url) pairs from all
    // input lists (Req 39.6)
    // -----------------------------------------------------------------------

    /// Feature: ZippyPanther, Property 39 — every unique (lang, url) pair from
    /// any input list appears in the merged output.
    ///
    /// **Validates: Requirements 39.6**
    #[test]
    fn merged_list_contains_all_unique_pairs(lists in arb_subtitle_lists()) {
        // Collect all unique (lang, url) pairs from the inputs.
        let mut expected_pairs = std::collections::HashSet::new();
        for list in &lists {
            for sub in list {
                expected_pairs.insert((sub.lang.clone(), sub.url.clone()));
            }
        }

        let merged = merge_subtitles(lists);

        // Every expected pair must appear in the merged output.
        let merged_pairs: std::collections::HashSet<(String, String)> = merged
            .iter()
            .map(|s| (s.lang.clone(), s.url.clone()))
            .collect();

        for pair in &expected_pairs {
            prop_assert!(
                merged_pairs.contains(pair),
                "unique pair (lang={:?}, url={:?}) from input is missing from merged output",
                pair.0,
                pair.1
            );
        }
    }

    // -----------------------------------------------------------------------
    // Property 5: Merged list length equals the number of unique (lang, url)
    // pairs (no extras, no missing) (Req 39.6)
    // -----------------------------------------------------------------------

    /// Feature: ZippyPanther, Property 39 — the merged list length equals the
    /// number of unique (lang, url) pairs across all inputs (no extras, no
    /// missing entries).
    ///
    /// **Validates: Requirements 39.6**
    #[test]
    fn merged_list_length_equals_unique_pair_count(lists in arb_subtitle_lists()) {
        // Count unique (lang, url) pairs across all input lists.
        let mut unique_pairs = std::collections::HashSet::new();
        for list in &lists {
            for sub in list {
                unique_pairs.insert((sub.lang.clone(), sub.url.clone()));
            }
        }

        let merged = merge_subtitles(lists);

        prop_assert_eq!(
            merged.len(),
            unique_pairs.len(),
            "merged list length {} != unique pair count {}",
            merged.len(),
            unique_pairs.len()
        );
    }

    // -----------------------------------------------------------------------
    // Property 6: format_from_url is consistent with content_type_for_url
    // (Req 39.3, 39.4)
    // -----------------------------------------------------------------------

    /// Feature: ZippyPanther, Property 39 — `format_from_url` and
    /// `content_type_for_url` are consistent: when `format_from_url` returns
    /// `Some(fmt)`, `content_type_for_url` returns `fmt.content_type()`.
    ///
    /// **Validates: Requirements 39.3, 39.4**
    #[test]
    fn format_from_url_consistent_with_content_type_for_url(
        (url, _ext) in arb_url_with_supported_ext()
    ) {
        let fmt = format_from_url(&url);
        let ct = content_type_for_url(&url);

        match fmt {
            Some(f) => {
                let f_ct = f.content_type();
                prop_assert_eq!(
                    ct,
                    f_ct,
                    "content_type_for_url({:?}) = {:?} but format_from_url returned \
                     Some whose content_type() = {:?}",
                    url, ct, f_ct
                );
            }
            None => {
                prop_assert_eq!(
                    ct,
                    "application/octet-stream",
                    "when format_from_url returns None, content_type_for_url must return \
                     application/octet-stream for URL={:?}",
                    url
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Exhaustive / deterministic checks (non-property)
// ---------------------------------------------------------------------------

/// Exhaustive check: every supported extension maps to the exact Content-Type
/// mandated by Req 39.4, in both lower and upper case.
#[test]
fn all_supported_extensions_map_to_correct_content_types_exhaustively() {
    let cases = [
        ("srt", "application/x-subrip"),
        ("SRT", "application/x-subrip"),
        ("vtt", "text/vtt"),
        ("VTT", "text/vtt"),
        ("ass", "text/x-ssa"),
        ("ASS", "text/x-ssa"),
        ("ssa", "text/x-ssa"),
        ("SSA", "text/x-ssa"),
    ];

    for (ext, expected_ct) in cases {
        let url = format!("https://cdn.example.com/track.{ext}");
        let ct = content_type_for_url(&url);
        assert_eq!(
            ct, expected_ct,
            "extension {ext:?}: expected {expected_ct:?}, got {ct:?}"
        );
    }
}

/// Exhaustive check: known unsupported extensions (sub, idx, and others) fall
/// back to `application/octet-stream`.
#[test]
fn unsupported_extensions_fall_back_to_octet_stream_exhaustively() {
    let unsupported = ["sub", "idx", "sbv", "dfxp", "ttml", "xyz", "mp4", "mkv"];
    for ext in unsupported {
        let url = format!("https://cdn.example.com/track.{ext}");
        let ct = content_type_for_url(&url);
        assert_eq!(
            ct, "application/octet-stream",
            "extension {ext:?} should fall back to application/octet-stream, got {ct:?}"
        );
    }
}

/// Exhaustive check: merge of empty input produces empty output.
#[test]
fn merge_empty_input_produces_empty_output() {
    let result = merge_subtitles(vec![]);
    assert!(result.is_empty());
}

/// Exhaustive check: merge of a single list with no duplicates is a no-op.
#[test]
fn merge_single_list_no_duplicates_is_identity() {
    let subs: Vec<Subtitle> = (0..5)
        .map(|i| Subtitle {
            id: i.to_string(),
            url: format!("https://cdn.example.com/track{i}.srt"),
            lang: format!("lang{i}"),
            ..Default::default()
        })
        .collect();

    let result = merge_subtitles(vec![subs.clone()]);
    assert_eq!(result.len(), subs.len());
    for (orig, merged) in subs.iter().zip(result.iter()) {
        assert_eq!(orig.lang, merged.lang);
        assert_eq!(orig.url, merged.url);
    }
}

/// Exhaustive check: merge across three lists with known overlaps produces the
/// correct de-duplicated result.
#[test]
fn merge_three_lists_with_known_overlaps() {
    let make = |id: &str, lang: &str, url: &str| Subtitle {
        id: id.into(),
        url: url.into(),
        lang: lang.into(),
        ..Default::default()
    };

    let list1 = vec![
        make("1", "en", "https://a.com/en.srt"),
        make("2", "fr", "https://a.com/fr.srt"),
    ];
    let list2 = vec![
        make("3", "de", "https://b.com/de.vtt"),
        make("4", "en", "https://a.com/en.srt"), // dup of list1[0]
    ];
    let list3 = vec![
        make("5", "es", "https://c.com/es.ass"),
        make("6", "fr", "https://a.com/fr.srt"), // dup of list1[1]
        make("7", "de", "https://b.com/de.vtt"), // dup of list2[0]
    ];

    let result = merge_subtitles(vec![list1, list2, list3]);

    // 4 unique (lang, url) pairs.
    assert_eq!(result.len(), 4);

    // First occurrences are kept.
    assert!(
        result.iter().any(|s| s.id == "1"),
        "id=1 (en/a.com) must be present"
    );
    assert!(
        result.iter().any(|s| s.id == "2"),
        "id=2 (fr/a.com) must be present"
    );
    assert!(
        result.iter().any(|s| s.id == "3"),
        "id=3 (de/b.com) must be present"
    );
    assert!(
        result.iter().any(|s| s.id == "5"),
        "id=5 (es/c.com) must be present"
    );

    // Duplicates are dropped.
    assert!(
        !result.iter().any(|s| s.id == "4"),
        "id=4 is a dup and must be dropped"
    );
    assert!(
        !result.iter().any(|s| s.id == "6"),
        "id=6 is a dup and must be dropped"
    );
    assert!(
        !result.iter().any(|s| s.id == "7"),
        "id=7 is a dup and must be dropped"
    );
}
