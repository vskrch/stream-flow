//! Property-based test for EPG/Xtream upstream URL base64-or-plain decoding
//! (`stream_flow::epg::decode_upstream_url`, task 18.8).
//!
//! Feature: stream-flow, Property 49
//!
//! **Property 49: EPG/Xtream upstream URL base64-or-plain decoding**
//!
//! *For any* upstream URL, supplying it plain yields that URL and supplying it
//! base64-encoded decodes to the same URL before fetching.
//!
//! **Validates: Requirements 8.6**
//!
//! Requirement 8.6: "WHEN an EPG upstream URL is supplied base64-encoded, THE
//! Stream_Flow_System SHALL decode it before fetching; WHEN it is supplied
//! plain, THE Stream_Flow_System SHALL use it directly."
//!
//! ## How the property is exercised
//!
//! Each case generates an arbitrary, canonical `http`/`https` [`Url`] and
//! asserts both halves of Property 49 against
//! [`decode_upstream_url`](stream_flow::epg::decode_upstream_url):
//!
//! * **Round trip (Req 8.6):** the plain canonical URL string decodes back to
//!   the same URL (used directly), and encoding that same string in *every*
//!   base64 alphabet the decoder accepts — standard and URL-safe, padded and
//!   unpadded — decodes back to the very same URL before fetching.
//! * **Never confused:** a plain URL always carries the `:` scheme delimiter,
//!   which lies outside every base64 alphabet, so it is parsed as a URL
//!   directly and can never be mis-read as base64; conversely a base64 encoding
//!   of a URL carries no `:`, so it can never be parsed as a plain URL. The two
//!   input forms are therefore disjoint yet both recover the identical URL.
//!
//! The decoder is also **total**: across hundreds of generated URLs it always
//! returns `Ok(Url)` for a valid input without panicking (proptest fails the
//! property on any panic).

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use proptest::prelude::*;
use stream_flow::epg::decode_upstream_url;
use url::Url;

/// Arbitrary URL scheme — the decoder accepts only `http`/`https`.
fn arb_scheme() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("http"), Just("https")]
}

/// A single DNS label: starts with a letter, then lowercase alphanumerics.
/// Lowercase-only keeps the label clear of `Url::parse`'s host normalization
/// (host lowercasing, punycode), so the generated string is already canonical.
fn arb_label() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,9}".prop_map(|s| s)
}

/// A dotted host of 1..=3 labels (e.g. `guide.example.tv`).
fn arb_host() -> impl Strategy<Value = String> {
    proptest::collection::vec(arb_label(), 1..=3).prop_map(|labels| labels.join("."))
}

/// A path segment drawn from unreserved characters, so it survives
/// `Url::parse` without percent-encoding rewrites.
fn arb_path_seg() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9._~-]{1,8}".prop_map(|s| s)
}

/// Generate an arbitrary, already-canonical `http`/`https` [`Url`].
///
/// The components are assembled into a string and parsed once through
/// `Url::parse`; the resulting [`Url`] is used as the canonical subject so that
/// `Url::parse(url.as_str())` is idempotent and comparisons are exact. Inputs
/// that do not parse to an `http`/`https` URL are filtered out.
fn arb_url() -> impl Strategy<Value = Url> {
    (
        arb_scheme(),
        arb_host(),
        proptest::option::of(1u16..=65535),
        proptest::collection::vec(arb_path_seg(), 0..=4),
        proptest::option::of("[a-zA-Z0-9]{1,6}=[a-zA-Z0-9]{1,6}"),
    )
        .prop_filter_map("a valid http/https URL", |(scheme, host, port, segs, query)| {
            let mut s = format!("{scheme}://{host}");
            if let Some(p) = port {
                s.push(':');
                s.push_str(&p.to_string());
            }
            s.push('/');
            s.push_str(&segs.join("/"));
            if let Some(q) = query {
                s.push('?');
                s.push_str(&q);
            }
            Url::parse(&s)
                .ok()
                .filter(|u| matches!(u.scheme(), "http" | "https"))
        })
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 49 — a plain URL is used directly and
    /// every base64 alphabet of that URL decodes to the identical URL before
    /// fetching. **Validates: Requirements 8.6**
    #[test]
    fn plain_and_base64_recover_the_same_url(url in arb_url()) {
        // The canonical plain form (`Url::parse` of this is the identity).
        let plain = url.as_str().to_string();

        // -- Plain form is used directly (Req 8.6) --------------------------
        let from_plain = decode_upstream_url(&plain)
            .expect("a canonical http/https URL must decode from its plain form");
        prop_assert_eq!(
            from_plain.as_str(),
            url.as_str(),
            "plain form {:?} must be used directly",
            plain,
        );

        // -- Every accepted base64 alphabet decodes to the same URL ---------
        let encodings = [
            ("STANDARD", STANDARD.encode(&plain)),
            ("STANDARD_NO_PAD", STANDARD_NO_PAD.encode(&plain)),
            ("URL_SAFE", URL_SAFE.encode(&plain)),
            ("URL_SAFE_NO_PAD", URL_SAFE_NO_PAD.encode(&plain)),
        ];
        for (alphabet, encoded) in &encodings {
            let from_b64 = decode_upstream_url(encoded)
                .expect("a base64-encoded http/https URL must decode before fetching");
            prop_assert_eq!(
                from_b64.as_str(),
                url.as_str(),
                "{} base64 form {:?} must recover {:?}",
                alphabet,
                encoded,
                url.as_str(),
            );
        }
    }

    /// Feature: stream-flow, Property 49 — the plain and base64 forms are
    /// disjoint (a plain URL carries `:`, a base64 string never does) so the
    /// two forms can never be confused, yet both recover the identical URL.
    /// **Validates: Requirements 8.6**
    #[test]
    fn plain_and_base64_forms_are_never_confused(url in arb_url()) {
        let plain = url.as_str().to_string();

        // A plain URL always carries the `:` scheme delimiter, which is outside
        // every base64 alphabet — so the decoder never mis-reads it as base64.
        prop_assert!(plain.contains(':'), "a plain URL must carry its scheme `:`");

        // A base64 encoding of the URL carries no `:`, so it is not itself a
        // parseable URL — it can only be recovered via the base64 path.
        let encoded = STANDARD.encode(&plain);
        prop_assert!(
            !encoded.contains(':'),
            "a base64 encoding must not contain a scheme delimiter",
        );
        prop_assert!(
            Url::parse(&encoded).is_err(),
            "a base64 encoding {:?} must not parse as a plain URL",
            encoded,
        );

        // Both disjoint forms nonetheless recover the very same URL.
        let from_plain = decode_upstream_url(&plain)
            .expect("plain form decodes");
        let from_b64 = decode_upstream_url(&encoded)
            .expect("base64 form decodes");
        prop_assert_eq!(
            from_plain.as_str(),
            from_b64.as_str(),
            "plain and base64 forms of {:?} must recover the same URL",
            url.as_str(),
        );
    }
}
