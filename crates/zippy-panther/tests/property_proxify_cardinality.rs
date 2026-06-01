//! Property-based test for the proxify-links endpoint core
//! (`proxylink::handler::proxify`, task 24.9).
//!
//! Feature: ZippyPanther, Property 24
//!
//! **Property 24: Proxify-links cardinality and per-index embedding**
//!
//! *For any* list of `N` input URLs, the response contains exactly `N` proxy
//! links in input order with `total == N`; each link embeds the per-index
//! header set and filename when supplied (falling back to the shared value),
//! and the encrypted-vs-token format is selected by the presence of the
//! `token` parameter.
//!
//! **Validates: Requirements 21.1, 21.2, 21.4, 21.5**
//!
//! * Req 21.1 — `proxify` returns exactly one `ProxyLink` per input URL
//!   (cardinality), in input order.
//! * Req 21.2 — a present, non-empty `token` selects the stremthru
//!   (`ProxyLink::Token`) format; an absent `token` selects the mediaflow
//!   encrypted (`ProxyLink::EncryptedMediaflow`) format.
//! * Req 21.4 — per-index `req_headers[<i>]` are embedded in link `i`, with a
//!   shared `req_headers` value used as the fallback for indices without a
//!   per-index entry.
//! * Req 21.5 — per-index `filename[<i>]` is embedded in link `i`, with a
//!   shared `filename` value used as the fallback.
//!
//! ## How the property is exercised
//!
//! Each case generates an arbitrary non-empty list of items. Every item carries
//! a URL seed plus an optional per-index header set and an optional per-index
//! filename; the scenario also carries an optional *shared* header set and an
//! optional *shared* filename, and a boolean selecting the on-the-wire format.
//! These are assembled directly into a [`ProxifyRequest`] (its fields and the
//! [`IndexedOrShared`] fields are public). `proxify` is then driven with a
//! [`ProxyCodec`] built from fixed secrets, and each produced link is **decoded
//! back** with the same codec so the embedded url / headers / filename can be
//! compared against the per-index input (with the documented shared fallback).
//!
//! Header strings round-trip through the endpoint's own pipe-separated
//! `Key:Value` wire form: keys/values are restricted to an alphanumeric
//! alphabet so `parse(serialize(map)) == map` exactly, making the expected
//! embedded header map deterministic without relying on parser internals.

use std::collections::BTreeMap;

use proptest::prelude::*;

use zippy_panther::proxylink::handler::{proxify, IndexedOrShared, ProxifyRequest};
use zippy_panther::proxylink::{ProxyCodec, ProxyLink};

/// Fixed key material — the property holds for any single codec instance that
/// holds both formats' keys.
const API_PASSWORD: &str = "mediaflow-api-password";
const STREMTHRU_SECRET: &str = "stremthru-proxy-secret";

/// `proxify` ignores its `base_url` argument (links are format tokens, not full
/// URLs), but the signature requires one.
const BASE_URL: &str = "https://proxy.example.com";

fn codec() -> ProxyCodec {
    ProxyCodec::from_secrets(API_PASSWORD, STREMTHRU_SECRET)
}

/// One generated input item: a URL seed plus optional per-index header set and
/// filename.
#[derive(Debug, Clone)]
struct ItemSpec {
    /// Alphanumeric seed used to build a unique upstream URL.
    seed: String,
    /// Per-index header set (`req_headers[<i>]`) when `Some`.
    headers: Option<BTreeMap<String, String>>,
    /// Per-index filename (`filename[<i>]`) when `Some`.
    filename: Option<String>,
}

/// A full generated scenario: the per-index items plus the shared fallbacks and
/// the format selector.
#[derive(Debug, Clone)]
struct Scenario {
    items: Vec<ItemSpec>,
    /// Shared `req_headers` fallback when `Some`.
    shared_headers: Option<BTreeMap<String, String>>,
    /// Shared `filename` fallback when `Some`.
    shared_filename: Option<String>,
    /// `true` -> set a non-empty `token` (stremthru format); `false` -> omit it
    /// (mediaflow encrypted format).
    use_token: bool,
}

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// An alphanumeric identifier of length `min..=max`. Used for URL seeds, header
/// keys/values, and filename stems so that the pipe/colon-delimited header wire
/// form is unambiguous and round-trips exactly.
fn arb_ident(min: usize, max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), min..=max).prop_map(|bytes| {
        bytes
            .into_iter()
            .map(|b| ALPHABET[(b as usize) % ALPHABET.len()] as char)
            .collect()
    })
}

/// An arbitrary header set (0..=4 entries) with non-empty alphanumeric keys and
/// values.
fn arb_header_map() -> impl Strategy<Value = BTreeMap<String, String>> {
    proptest::collection::btree_map(arb_ident(1, 8), arb_ident(1, 8), 0..=4)
}

/// An arbitrary filename like `abc12.mp4`.
fn arb_filename() -> impl Strategy<Value = String> {
    arb_ident(1, 10).prop_map(|s| format!("{s}.mp4"))
}

fn arb_item() -> impl Strategy<Value = ItemSpec> {
    (
        arb_ident(1, 8),
        proptest::option::of(arb_header_map()),
        proptest::option::of(arb_filename()),
    )
        .prop_map(|(seed, headers, filename)| ItemSpec {
            seed,
            headers,
            filename,
        })
}

fn arb_scenario() -> impl Strategy<Value = Scenario> {
    (
        proptest::collection::vec(arb_item(), 1..=6),
        proptest::option::of(arb_header_map()),
        proptest::option::of(arb_filename()),
        any::<bool>(),
    )
        .prop_map(
            |(items, shared_headers, shared_filename, use_token)| Scenario {
                items,
                shared_headers,
                shared_filename,
                use_token,
            },
        )
}

/// Serialize a header map into the endpoint's pipe-separated `Key:Value` wire
/// form. With alphanumeric keys/values this is the exact inverse of the
/// endpoint's `parse_headers`, so the embedded map equals the generated map.
fn serialize_headers(map: &BTreeMap<String, String>) -> String {
    map.iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join("|")
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 24 — `proxify` produces exactly one link
    /// per input URL (cardinality, Req 21.1), each link decodes back to that
    /// URL's per-index headers (Req 21.4) and filename (Req 21.5) with the
    /// shared value as fallback, and the on-the-wire format follows the
    /// presence of `token` (Req 21.2). **Validates: Requirements 21.1, 21.2,
    /// 21.4, 21.5**
    #[test]
    fn proxify_cardinality_and_per_index_embedding(scenario in arb_scenario()) {
        let codec = codec();

        // -- Build the upstream URL list (unique per index) -----------------
        let urls: Vec<String> = scenario
            .items
            .iter()
            .enumerate()
            .map(|(i, it)| format!("https://{}.example.com/path/{i}.mp4", it.seed))
            .collect();

        // -- Assemble the per-index + shared header / filename inputs --------
        let mut indexed_headers: BTreeMap<usize, String> = BTreeMap::new();
        let mut indexed_filename: BTreeMap<usize, String> = BTreeMap::new();
        for (i, it) in scenario.items.iter().enumerate() {
            if let Some(h) = &it.headers {
                indexed_headers.insert(i, serialize_headers(h));
            }
            if let Some(f) = &it.filename {
                indexed_filename.insert(i, f.clone());
            }
        }

        let req_headers = IndexedOrShared {
            shared: scenario.shared_headers.as_ref().map(serialize_headers),
            indexed: indexed_headers,
        };
        let filename = IndexedOrShared {
            shared: scenario.shared_filename.clone(),
            indexed: indexed_filename,
        };

        let token = if scenario.use_token {
            Some("on".to_string())
        } else {
            None
        };

        // Constructed directly; `..default()` keeps this forward-compatible
        // with any additional public fields (expiration, redirect, ...).
        let request = ProxifyRequest {
            url: urls.clone(),
            req_headers,
            filename,
            token,
            ..ProxifyRequest::default()
        };

        let links = proxify(&request, &codec, BASE_URL)
            .expect("proxify must succeed for a non-empty url list");

        // -- Req 21.1: exactly one link per input URL (cardinality) ---------
        prop_assert_eq!(
            links.len(),
            urls.len(),
            "proxify must return exactly one link per input URL",
        );

        for (i, link) in links.iter().enumerate() {
            // -- Req 21.2: format follows the presence of `token` -----------
            match link {
                ProxyLink::Token { .. } => prop_assert!(
                    scenario.use_token,
                    "token format produced without a `token` parameter",
                ),
                ProxyLink::EncryptedMediaflow { .. } => prop_assert!(
                    !scenario.use_token,
                    "encrypted format produced with a `token` parameter",
                ),
            }

            // Decode link `i` and recover its embedded payload.
            let payload = codec
                .decode(link)
                .expect("a freshly produced link must decode with the same codec");

            // -- Req 21.1 (order): link `i` carries URL `i` -----------------
            prop_assert_eq!(
                &payload.url,
                &urls[i],
                "link {} must embed input URL {}",
                i,
                i,
            );

            // -- Req 21.4: per-index headers with shared fallback -----------
            let expected_headers: BTreeMap<String, String> =
                match scenario.items[i].headers.as_ref() {
                    Some(h) => h.clone(),
                    None => scenario.shared_headers.clone().unwrap_or_default(),
                };
            prop_assert_eq!(
                &payload.headers,
                &expected_headers,
                "link {} must embed its per-index headers (with shared fallback)",
                i,
            );

            // -- Req 21.5: per-index filename with shared fallback ----------
            let expected_filename: Option<String> = scenario.items[i]
                .filename
                .clone()
                .or_else(|| scenario.shared_filename.clone());
            prop_assert_eq!(
                &payload.filename,
                &expected_filename,
                "link {} must embed its per-index filename (with shared fallback)",
                i,
            );
        }
    }
}
