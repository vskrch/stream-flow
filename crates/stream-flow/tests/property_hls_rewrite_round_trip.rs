//! Property-based test for HLS manifest parse/serialize round trip + full URL
//! rewriting (task 16.6).
//!
//! Feature: stream-flow, Property 10
//!
//! **Property 10: HLS manifest parse/serialize round trip and full rewriting**
//!
//! *For any* valid M3U8 manifest, parsing then serializing produces an
//! equivalent manifest; and after rewriting, every variant, segment,
//! `#EXT-X-KEY`, and `#EXT-X-MAP` URL in the output is a `stream-flow` proxy
//! URL (none remain pointing at the upstream origin), with relative URIs
//! resolved against the manifest base before rewriting.
//!
//! **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 48.4**
//!
//! * Requirement 1.1: every variant, segment, key, and media URL is rewritten
//!   to a `Stream_Flow_System` proxy URL.
//! * Requirement 1.2: each master variant playlist URL is rewritten to a proxy
//!   URL preserving the upstream URL.
//! * Requirement 1.3: each `#EXT-X-KEY`, segment, and `#EXT-X-MAP` URI in a
//!   media playlist is rewritten to a proxy URL.
//! * Requirement 1.4: relative segment/key URIs are resolved against the
//!   manifest base URL before rewriting.
//! * Requirement 48.4: property-based tests for `M3U8_Manifest` parser
//!   behavior.
//!
//! The test drives *arbitrary* valid master and media `.m3u8` manifests from a
//! proptest **model** (varying variant / alternative-rendition / segment
//! counts, and a per-URI mix of relative — bare, sub-directory, parent (`..`),
//! and current (`.`) — and absolute upstream URIs, plus optional `#EXT-X-MAP`
//! and `#EXT-X-KEY`), renders that model to manifest text, and asserts the two
//! arms of Property 10:
//!
//! **Arm A — parse/serialize round trip (Req 48.4).** Parsing the generated
//! manifest with [`m3u8_rs`], serializing it, and re-parsing recovers an
//! equivalent structured manifest (`parse → serialize → parse` is a fixed
//! point).
//!
//! **Arm B — full rewriting (Req 1.1–1.4).** [`HlsRewriter::rewrite`] produces
//! an output in which **every** embedded URL (master variants + alternative
//! renditions, media segments, `#EXT-X-KEY`, `#EXT-X-MAP`) is a `stream-flow`
//! proxy URL — none reference any upstream host — and the encrypted `d` token
//! each proxy URL carries decrypts to the *resolved-against-the-manifest-base*
//! absolute upstream URL. The multiset of those decrypted URLs equals the
//! multiset of the model's URIs resolved against the base, proving the rewrite
//! is a faithful, total, relative-resolving transform of exactly the manifest's
//! URLs.

use proptest::prelude::*;
use url::Url;

use stream_flow::auth::encryption::{decrypt, CbcKey};
use stream_flow::hls::HlsRewriter;

// ---------------------------------------------------------------------------
// Fixed test identities. Upstream hosts carry dotted labels that can never
// appear inside a base64url `d` token (whose alphabet is `[A-Za-z0-9_-]`), so
// "no output URL references an upstream host" is a clean substring assertion.
// ---------------------------------------------------------------------------

const ORIGIN_HOST: &str = "origin.upstream.invalid";
const ALT_HOST: &str = "alt.upstream.invalid";
const PROXY_BASE: &str = "https://proxy.test/mediaflow";
const API_PASSWORD: &str = "stream-flow-property-10-secret";

// ---------------------------------------------------------------------------
// Generator model
// ---------------------------------------------------------------------------

/// The shape of a single embedded URI: a mix of relative forms (resolved
/// against the manifest base — Req 1.4) and already-absolute upstream URLs.
#[derive(Debug, Clone)]
enum UriKind {
    /// `leafN.ts` — bare relative, resolves against the manifest directory.
    RelBare,
    /// `dN/leafN.ts` — relative sub-directory.
    RelSub,
    /// `../uN/leafN.ts` — relative parent reference.
    RelParent,
    /// `./leafN.ts` — relative current-directory reference.
    RelDot,
    /// `https://alt…/pN/leafN.ts` — absolute, different upstream host.
    AbsAlt,
    /// `https://origin…/xN/leafN.ts` — absolute, same upstream host.
    AbsOrigin,
}

/// A monotonically-increasing counter so every generated URI is globally
/// unique (the rewrite is a 1:1 transform, so unique inputs give an
/// unambiguous multiset to compare against).
struct UriGen {
    idx: usize,
}

impl UriGen {
    fn next(&mut self, kind: &UriKind, leaf: &str) -> String {
        let i = self.idx;
        self.idx += 1;
        match kind {
            UriKind::RelBare => format!("{leaf}{i}.ts"),
            UriKind::RelSub => format!("d{i}/{leaf}{i}.ts"),
            UriKind::RelParent => format!("../u{i}/{leaf}{i}.ts"),
            UriKind::RelDot => format!("./{leaf}{i}.ts"),
            UriKind::AbsAlt => format!("https://{ALT_HOST}/p{i}/{leaf}{i}.ts"),
            UriKind::AbsOrigin => format!("https://{ORIGIN_HOST}/x{i}/{leaf}{i}.ts"),
        }
    }
}

/// A generated master (`Vec` of `(bandwidth, variant-uri)` + alternative
/// renditions) or media (`#EXT-X-MAP`?, `#EXT-X-KEY`?, segments) manifest.
type MasterSpec = (Option<u32>, Vec<(u64, UriKind)>, Vec<UriKind>);
type MediaSpec = (u64, Option<UriKind>, Option<UriKind>, Vec<(f64, UriKind)>);

#[derive(Debug, Clone)]
enum Spec {
    Master(MasterSpec),
    Media(MediaSpec),
}

fn uri_kind() -> impl Strategy<Value = UriKind> {
    prop_oneof![
        Just(UriKind::RelBare),
        Just(UriKind::RelSub),
        Just(UriKind::RelParent),
        Just(UriKind::RelDot),
        Just(UriKind::AbsAlt),
        Just(UriKind::AbsOrigin),
    ]
}

fn opt_uri_kind() -> impl Strategy<Value = Option<UriKind>> {
    prop_oneof![
        2 => Just(None),
        3 => uri_kind().prop_map(Some),
    ]
}

/// Segment duration drawn from a small set of clean values so the rendered
/// `#EXTINF` always re-parses to the same `f32`.
fn seg_duration() -> impl Strategy<Value = f64> {
    prop_oneof![Just(2.0f64), Just(4.0), Just(6.0), Just(3.5)]
}

fn master_spec() -> impl Strategy<Value = MasterSpec> {
    let version = prop_oneof![
        Just(None),
        Just(Some(3u32)),
        Just(Some(4u32)),
        Just(Some(6u32)),
    ];
    // At least one variant so the playlist is unambiguously a master.
    let variants = proptest::collection::vec((1u64..=20_000_000u64, uri_kind()), 1..=5);
    let alts = proptest::collection::vec(uri_kind(), 0..=3);
    (version, variants, alts)
}

fn media_spec() -> impl Strategy<Value = MediaSpec> {
    let target = 1u64..=12u64;
    let map = opt_uri_kind();
    let key = opt_uri_kind();
    // At least one segment so `#EXT-X-MAP` / `#EXT-X-KEY` have a segment to
    // attach to and the playlist is unambiguously a media playlist.
    let segments = proptest::collection::vec((seg_duration(), uri_kind()), 1..=8);
    (target, map, key, segments)
}

fn manifest_spec() -> impl Strategy<Value = Spec> {
    prop_oneof![
        master_spec().prop_map(Spec::Master),
        media_spec().prop_map(Spec::Media),
    ]
}

/// The manifest base URL the relative URIs resolve against (Req 1.4); varied in
/// directory depth so `..` / `.` references resolve differently.
fn base_url() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(format!("https://{ORIGIN_HOST}/media.m3u8")),
        Just(format!("https://{ORIGIN_HOST}/a/media.m3u8")),
        Just(format!("https://{ORIGIN_HOST}/a/b/media.m3u8")),
        Just(format!("https://{ORIGIN_HOST}/a/b/c/media.m3u8")),
    ]
}

// ---------------------------------------------------------------------------
// Rendering: model -> manifest text + the model's raw URIs (in any order).
// ---------------------------------------------------------------------------

fn render_master(version: Option<u32>, variants: &[(u64, String)], alts: &[String]) -> String {
    let mut s = String::from("#EXTM3U\n");
    if let Some(v) = version {
        s.push_str(&format!("#EXT-X-VERSION:{v}\n"));
    }
    for (i, raw) in alts.iter().enumerate() {
        // A self-contained alternative rendition carrying a sub-playlist URI.
        s.push_str(&format!(
            "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"g{i}\",NAME=\"n{i}\",URI=\"{raw}\"\n"
        ));
    }
    for (bw, raw) in variants {
        s.push_str(&format!("#EXT-X-STREAM-INF:BANDWIDTH={bw}\n{raw}\n"));
    }
    s
}

fn render_media(
    target: u64,
    map: &Option<String>,
    key: &Option<String>,
    segments: &[(f64, String)],
) -> String {
    // Version 6 covers `#EXT-X-MAP` (added in v5/v6); harmless for plain media.
    let mut s = String::from("#EXTM3U\n#EXT-X-VERSION:6\n");
    s.push_str(&format!("#EXT-X-TARGETDURATION:{target}\n"));
    if let Some(m) = map {
        s.push_str(&format!("#EXT-X-MAP:URI=\"{m}\"\n"));
    }
    if let Some(k) = key {
        s.push_str(&format!(
            "#EXT-X-KEY:METHOD=AES-128,URI=\"{k}\",IV=0x0123456789abcdef0123456789abcdef\n"
        ));
    }
    for (dur, raw) in segments {
        s.push_str(&format!("#EXTINF:{dur},\n{raw}\n"));
    }
    s.push_str("#EXT-X-ENDLIST\n");
    s
}

/// Build the manifest text and the list of every raw URI it embeds (variants,
/// alternatives, map, key, segments), assigning each a globally-unique path.
fn build(spec: Spec) -> (String, Vec<String>) {
    let mut g = UriGen { idx: 0 };
    let mut raws = Vec::new();

    match spec {
        Spec::Master((version, variants, alts)) => {
            let variant_pairs: Vec<(u64, String)> = variants
                .iter()
                .map(|(bw, kind)| {
                    let raw = g.next(kind, "var");
                    raws.push(raw.clone());
                    (*bw, raw)
                })
                .collect();
            let alt_raws: Vec<String> = alts
                .iter()
                .map(|kind| {
                    let raw = g.next(kind, "alt");
                    raws.push(raw.clone());
                    raw
                })
                .collect();
            (render_master(version, &variant_pairs, &alt_raws), raws)
        }
        Spec::Media((target, map, key, segments)) => {
            let map_raw = map.as_ref().map(|k| {
                let raw = g.next(k, "map");
                raws.push(raw.clone());
                raw
            });
            let key_raw = key.as_ref().map(|k| {
                let raw = g.next(k, "key");
                raws.push(raw.clone());
                raw
            });
            let seg_pairs: Vec<(f64, String)> = segments
                .iter()
                .map(|(dur, kind)| {
                    let raw = g.next(kind, "seg");
                    raws.push(raw.clone());
                    (*dur, raw)
                })
                .collect();
            (render_media(target, &map_raw, &key_raw, &seg_pairs), raws)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers shared with the assertions.
// ---------------------------------------------------------------------------

/// Resolve a possibly-relative `uri` against the manifest `base` — the exact
/// operation the rewriter performs before embedding the URL in the `d` token
/// (Req 1.4).
fn resolve(base: &Url, uri: &str) -> String {
    base.join(uri)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| uri.to_string())
}

/// Every embedded URL in a manifest: each non-comment line (variant / segment
/// URI) and each `URI="…"` attribute value (on `#EXT-X-MEDIA` / `#EXT-X-KEY` /
/// `#EXT-X-MAP` lines).
fn all_urls(manifest: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            if let Some(start) = line.find("URI=\"") {
                let s = start + 5;
                if let Some(end) = line[s..].find('"') {
                    urls.push(line[s..s + end].to_string());
                }
            }
        } else {
            urls.push(line.to_string());
        }
    }
    urls
}

proptest! {
    // 256 cases comfortably exceeds the 100-iteration floor for a property task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 10 — HLS manifest parse/serialize round
    /// trip and full rewriting.
    /// **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 48.4**
    #[test]
    fn hls_parse_serialize_round_trip_and_full_rewriting(
        (spec, base_str) in (manifest_spec(), base_url())
    ) {
        let base = Url::parse(&base_str).expect("base URL parses");
        let (manifest, expected_raw) = build(spec);

        // -- Arm A: parse → serialize → parse is a fixed point (Req 48.4). ----
        let parsed = m3u8_rs::parse_playlist_res(manifest.as_bytes());
        prop_assert!(
            parsed.is_ok(),
            "generated manifest must parse, got {:?}\n---\n{manifest}",
            parsed.as_ref().err()
        );
        let parsed = parsed.unwrap();

        let mut serialized = Vec::new();
        prop_assert!(
            parsed.write_to(&mut serialized).is_ok(),
            "parsed manifest must serialize"
        );
        let reparsed = m3u8_rs::parse_playlist_res(&serialized);
        prop_assert!(
            reparsed.is_ok(),
            "serialized manifest must re-parse, got {:?}\n---\n{}",
            reparsed.as_ref().err(),
            String::from_utf8_lossy(&serialized)
        );
        prop_assert_eq!(
            &parsed,
            &reparsed.unwrap(),
            "parse → serialize → parse must recover an equivalent manifest\n---\n{}",
            manifest
        );

        // -- Arm B: full rewriting (Req 1.1–1.4). -----------------------------
        let key = CbcKey::from_api_password(API_PASSWORD);
        let rewriter = HlsRewriter::new(PROXY_BASE, key);
        let prefix = rewriter.proxy_prefix();

        let out = rewriter.rewrite(manifest.as_bytes(), &base);
        prop_assert!(
            out.is_ok(),
            "rewrite must succeed, got {:?}\n---\n{manifest}",
            out.as_ref().err()
        );
        let out = out.unwrap();

        // The rewritten manifest is itself still a valid M3U8 manifest.
        prop_assert!(
            m3u8_rs::parse_playlist_res(out.as_bytes()).is_ok(),
            "rewritten manifest must still parse\n---\n{out}"
        );

        let out_urls = all_urls(&out);

        // Every embedded URL is a `stream-flow` proxy URL and none reference an
        // upstream host (Req 1.1: nothing still points at the origin).
        for u in &out_urls {
            prop_assert!(
                u.starts_with(&prefix),
                "every output URL must be a proxy URL (prefix {prefix}), got {u}\n---\n{out}"
            );
            prop_assert!(
                !u.contains(ORIGIN_HOST),
                "no output URL may reference the upstream origin, got {u}"
            );
            prop_assert!(
                !u.contains(ALT_HOST),
                "no output URL may reference an upstream host, got {u}"
            );
        }

        // Each proxy URL's `d` token decrypts to the resolved-against-base
        // absolute upstream URL (Req 1.2, 1.4).
        let dec_key = CbcKey::from_api_password(API_PASSWORD);
        let mut decrypted = Vec::with_capacity(out_urls.len());
        for u in &out_urls {
            let token = u.split_once("?d=").map(|(_, t)| t);
            prop_assert!(token.is_some(), "proxy URL must carry a `?d=` token, got {u}");
            let payload = decrypt(token.unwrap(), &dec_key);
            prop_assert!(payload.is_ok(), "the `d` token must decrypt, got {u}");
            let embedded = payload.unwrap().url;

            // Relative URIs were resolved before rewriting: the embedded URL is
            // an absolute URL pointing at an upstream host (Req 1.4).
            let parsed_embedded = Url::parse(&embedded);
            prop_assert!(
                parsed_embedded.is_ok(),
                "embedded upstream URL must be absolute, got {embedded}"
            );
            let host = parsed_embedded.unwrap().host_str().unwrap_or_default().to_string();
            prop_assert!(
                host == ORIGIN_HOST || host == ALT_HOST,
                "embedded upstream URL must resolve to an upstream host, got {embedded}"
            );

            decrypted.push(embedded);
        }

        // The rewrite is a faithful, total transform: the multiset of embedded
        // upstream URLs equals the multiset of the model's URIs resolved
        // against the manifest base (Req 1.1–1.4).
        let mut expected: Vec<String> = expected_raw.iter().map(|r| resolve(&base, r)).collect();
        expected.sort();
        decrypted.sort();
        prop_assert_eq!(
            &decrypted,
            &expected,
            "rewritten URL set must equal the base-resolved input URL set\n---\n{}",
            out
        );
    }
}
