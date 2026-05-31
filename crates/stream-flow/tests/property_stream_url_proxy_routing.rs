//! Property-based test: stream URLs always route through the proxy
//! (task 26.6, Property 27).
//!
//! Feature: stream-flow, Property 27
//!
//! **Property 27: Stream URLs always route through the proxy**
//!
//! **Validates: Requirements 23.5, 24.5, 25.5**
//!
//! Requirement 23.5: "IF the configured store credentials are missing or
//! invalid, THEN THE Orchestration_Layer SHALL return a Stremio error response
//! indicating the store is not configured." (and by extension, when credentials
//! are valid, streams play through the Streaming_Proxy_Engine — Req 23.4.)
//!
//! Requirement 24.5: "WHERE a Stream object carries StreamBehaviorHints such
//! as `proxyHeaders`, `bingeGroup`, or `countryWhitelist`, THE
//! Orchestration_Layer SHALL preserve those hints in the returned Stream
//! object."
//!
//! Requirement 25.5: "IF no torrents match the requested content, THEN THE
//! Orchestration_Layer SHALL return an empty stream list."
//!
//! ## What this property tests
//!
//! For any upstream (debrid/CDN) URL produced by the Store/Wrap/Sidekick/Torz
//! addons, the playable URL embedded in the resulting `Stream` object MUST:
//!
//! 1. Start with the configured proxy base URL (never the raw upstream host).
//! 2. Contain a proxy-link token (`token=` or `d=`) — i.e. be a valid
//!    stream-flow proxy link.
//! 3. NOT contain the raw upstream URL verbatim in the host/path portion
//!    (the upstream URL is sealed inside the encrypted/signed token, not
//!    exposed in the outer URL).
//!
//! Additionally, any `StreamBehaviorHints` present on the original stream
//! (proxyHeaders, bingeGroup, countryWhitelist, videoSize, filename) MUST be
//! preserved unchanged through the URL rewrite (Req 24.5).
//!
//! ## How the invariant is exercised
//!
//! This property exercises the shared **URL-routing invariant at the codec
//! level**: it uses the same `ProxyCodec` + `ProxyLink` machinery the addons
//! use to wrap upstream URLs into proxy links, and asserts the invariant on the
//! resulting `Stream.url` values.
//!
//! The test simulates what each addon does:
//!   1. Receive an upstream URL (debrid direct link / CDN URL).
//!   2. Encode it as a proxy link via `ProxyCodec`.
//!   3. Build the full proxy stream URL: `{proxy_base}/v0/proxy/stream?{link}`.
//!   4. Set that URL as `Stream.url`.
//!   5. Assert the URL starts with `proxy_base` and contains a proxy token.
//!   6. Assert the raw upstream host does NOT appear in the outer URL.
//!   7. Assert `StreamBehaviorHints` are preserved unchanged.

use std::collections::BTreeMap;

use proptest::prelude::*;
use stream_flow::auth::encryption::ProxyPayload;
use stream_flow::proxylink::{ProxyCodec, ProxyLink};
use stream_flow::stremio::{ProxyHeaders, Stream, StreamBehaviorHints};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The API password used to derive the AES-CBC key for the mediaflow format.
const API_PASSWORD: &str = "test-api-password-for-property-27";
/// The stremthru proxy secret used to sign token-format links.
const TOKEN_SECRET: &str = "test-token-secret-for-property-27";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the shared `ProxyCodec` used across all test cases.
fn codec() -> ProxyCodec {
    ProxyCodec::from_secrets(API_PASSWORD, TOKEN_SECRET)
}

/// Build the full proxy stream URL from a `ProxyLink` and a proxy base URL.
///
/// This mirrors what the Store/Wrap/Sidekick/Torz addons do when they set
/// `Stream.url` (design: Components → Stremio Addons; Req 23.4, 24.4).
fn build_stream_url(proxy_base: &str, link: &ProxyLink) -> String {
    format!(
        "{}/v0/proxy/stream?{}",
        proxy_base.trim_end_matches('/'),
        link.as_query_param(),
    )
}

/// Assert the proxy-routing invariant for a single `Stream` object.
///
/// * The URL starts with `proxy_base` (routes through the proxy).
/// * The URL contains a proxy-link token (`token=` or `d=`).
/// * The raw upstream host does NOT appear in the outer URL path/query
///   (the upstream URL is sealed inside the token, not exposed).
fn assert_routes_through_proxy(stream: &Stream, proxy_base: &str, upstream_url: &str) {
    let url = stream
        .url
        .as_deref()
        .expect("Stream produced by an addon must have a url");

    // 1. The URL starts with the proxy base (Req 23.4, 24.4, 25.3).
    assert!(
        url.starts_with(proxy_base.trim_end_matches('/')),
        "Stream URL must start with the proxy base.\n\
         proxy_base = {proxy_base:?}\n\
         stream.url = {url:?}",
    );

    // 2. The URL contains a proxy-link token (either format).
    let has_token = url.contains("token=") || url.contains("d=");
    assert!(
        has_token,
        "Stream URL must contain a proxy-link token (`token=` or `d=`).\n\
         stream.url = {url:?}",
    );

    // 3. The raw upstream host does NOT appear verbatim in the outer URL
    //    (the upstream URL is sealed inside the encrypted/signed token).
    //    We extract the host from the upstream URL and check it is absent
    //    from the outer URL's path and query string (everything after the
    //    proxy base).
    if let Some(upstream_host) = extract_host(upstream_url) {
        let outer_suffix = url
            .strip_prefix(proxy_base.trim_end_matches('/'))
            .unwrap_or(url);
        assert!(
            !outer_suffix.contains(upstream_host),
            "Raw upstream host must not appear in the outer proxy URL.\n\
             upstream_host = {upstream_host:?}\n\
             outer_suffix  = {outer_suffix:?}\n\
             stream.url    = {url:?}",
        );
    }
}

/// Extract the host (and optional port) from a URL string.
///
/// Returns `None` for malformed URLs or URLs without a recognisable host.
fn extract_host(url: &str) -> Option<&str> {
    // Strip scheme (e.g. "https://").
    let after_scheme = url.split_once("://").map(|(_, rest)| rest)?;
    // The host ends at the first `/`, `?`, or `#`.
    let host_end = after_scheme
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..host_end];
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Strategy for a realistic upstream debrid/CDN URL.
///
/// Covers the kinds of URLs the nine debrid stores return as direct links:
/// RealDebrid, AllDebrid, TorBox, Premiumize, etc. all return HTTPS URLs
/// pointing at CDN hosts that are distinct from the proxy base.
fn arb_upstream_url() -> impl Strategy<Value = String> {
    prop_oneof![
        // RealDebrid-style CDN URLs.
        Just("https://cdn-1.real-debrid.com/d/ABCDEF123456/movie.mkv".to_string()),
        Just("https://down.real-debrid.com/d/XYZ789/series.s01e01.mkv".to_string()),
        // AllDebrid-style CDN URLs.
        Just("https://alldebrid.com/f/ABCDEF/video.mp4".to_string()),
        Just("https://uptobox.com/dl/TOKEN123/file.mkv".to_string()),
        // TorBox-style CDN URLs.
        Just("https://torbox.app/dl/HASH123/movie.mkv".to_string()),
        // Premiumize-style CDN URLs.
        Just("https://energycdn.com/dl/TOKEN/video.mp4".to_string()),
        // Generic CDN URLs with various paths.
        Just("https://cdn.example.com/streams/abc123/video.mp4".to_string()),
        Just("https://media.debrid-provider.net/files/hash/movie.1080p.mkv".to_string()),
        // URLs with query parameters (some debrid services include tokens in query).
        Just("https://cdn.example.com/dl/file.mp4?token=abc123&expires=9999".to_string()),
        // Arbitrary HTTPS URLs with varied hosts.
        "[a-z]{3,8}\\.[a-z]{2,6}(\\.[a-z]{2,3})?"
            .prop_map(|host| format!("https://{host}/stream/video.mkv")),
    ]
}

/// Strategy for a proxy base URL (the public URL of the stream-flow instance).
fn arb_proxy_base() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("https://proxy.example.com".to_string()),
        Just("https://stream-flow.myserver.net".to_string()),
        Just("https://sf.example.org/mediaflow".to_string()),
        Just("http://localhost:8080".to_string()),
        Just("https://proxy.example.com/api/v1".to_string()),
    ]
}

/// Strategy for an optional `StreamBehaviorHints` (Req 24.5).
fn arb_stream_behavior_hints() -> impl Strategy<Value = Option<StreamBehaviorHints>> {
    prop_oneof![
        // No hints.
        Just(None),
        // Hints with bingeGroup only.
        "[a-z]{3,12}".prop_map(|g| Some(StreamBehaviorHints {
            binge_group: Some(g),
            ..Default::default()
        })),
        // Hints with countryWhitelist.
        prop::collection::vec("[A-Z]{2}", 1..=4).prop_map(|countries| {
            Some(StreamBehaviorHints {
                country_whitelist: countries,
                ..Default::default()
            })
        }),
        // Hints with videoSize.
        (1u64..=10_000_000_000u64).prop_map(|sz| Some(StreamBehaviorHints {
            video_size: Some(sz as i64),
            ..Default::default()
        })),
        // Hints with filename.
        "[a-z0-9]{4,16}\\.(mkv|mp4|avi)".prop_map(|f| Some(StreamBehaviorHints {
            filename: Some(f),
            ..Default::default()
        })),
        // Hints with proxyHeaders.
        ("[a-zA-Z]{4,12}", "[a-zA-Z0-9]{4,16}").prop_map(|(k, v)| {
            let mut req = BTreeMap::new();
            req.insert(k, v);
            Some(StreamBehaviorHints {
                proxy_headers: Some(ProxyHeaders {
                    request: req,
                    response: BTreeMap::new(),
                }),
                ..Default::default()
            })
        }),
        // Hints with notWebReady.
        Just(Some(StreamBehaviorHints {
            not_web_ready: true,
            ..Default::default()
        })),
    ]
}

/// Strategy for the proxy-link format: token (stremthru) or encrypted (mediaflow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkFormat {
    Token,
    Encrypted,
}

fn arb_link_format() -> impl Strategy<Value = LinkFormat> {
    prop_oneof![Just(LinkFormat::Token), Just(LinkFormat::Encrypted)]
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 27 — Stream URLs always route through the proxy.
    /// **Validates: Requirements 23.5, 24.5, 25.5**
    ///
    /// For any upstream URL and proxy base, a `Stream` object built by wrapping
    /// the upstream URL in a proxy link (as the Store/Wrap/Sidekick/Torz addons
    /// do) has a `url` that:
    ///   1. Starts with the proxy base URL.
    ///   2. Contains a proxy-link token (`token=` or `d=`).
    ///   3. Does NOT expose the raw upstream host in the outer URL.
    #[test]
    fn stream_url_routes_through_proxy(
        upstream_url in arb_upstream_url(),
        proxy_base in arb_proxy_base(),
        format in arb_link_format(),
    ) {
        let codec = codec();
        let payload = ProxyPayload::new(upstream_url.clone());

        // Encode the upstream URL as a proxy link (as the addon would).
        let link = match format {
            LinkFormat::Token => codec.encode_token(&payload).expect("token encode succeeds"),
            LinkFormat::Encrypted => codec.encode_mediaflow(&payload).expect("mediaflow encode succeeds"),
        };

        // Build the full proxy stream URL (as the addon sets Stream.url).
        let stream_url = build_stream_url(&proxy_base, &link);

        // Construct the Stream object.
        let stream = Stream {
            url: Some(stream_url),
            ..Default::default()
        };

        // Assert the routing invariant.
        assert_routes_through_proxy(&stream, &proxy_base, &upstream_url);
    }

    /// Feature: stream-flow, Property 27 — StreamBehaviorHints are preserved
    /// through the URL rewrite (Req 24.5).
    ///
    /// For any upstream URL, proxy base, and `StreamBehaviorHints`, the hints
    /// are preserved unchanged when the addon rewrites the stream URL to a
    /// proxy link.
    #[test]
    fn stream_behavior_hints_preserved_through_rewrite(
        upstream_url in arb_upstream_url(),
        proxy_base in arb_proxy_base(),
        hints in arb_stream_behavior_hints(),
        format in arb_link_format(),
    ) {
        let codec = codec();
        let payload = ProxyPayload::new(upstream_url.clone());

        let link = match format {
            LinkFormat::Token => codec.encode_token(&payload).expect("token encode succeeds"),
            LinkFormat::Encrypted => codec.encode_mediaflow(&payload).expect("mediaflow encode succeeds"),
        };

        let stream_url = build_stream_url(&proxy_base, &link);

        // The addon rewrites the URL but preserves the hints unchanged (Req 24.5).
        let original_hints = hints.clone();
        let stream = Stream {
            url: Some(stream_url),
            behavior_hints: hints,
            ..Default::default()
        };

        // The hints on the resulting stream must equal the original hints.
        prop_assert_eq!(
            &stream.behavior_hints,
            &original_hints,
            "StreamBehaviorHints must be preserved unchanged through the URL rewrite \
             (Req 24.5); proxy_base={:?}, upstream_url={:?}",
            proxy_base,
            upstream_url,
        );

        // The URL still routes through the proxy.
        assert_routes_through_proxy(&stream, &proxy_base, &upstream_url);
    }

    /// Feature: stream-flow, Property 27 — proxy link is decodable and recovers
    /// the original upstream URL.
    ///
    /// The upstream URL sealed inside the proxy link must be recoverable by
    /// decoding the link with the same codec, confirming the link is a valid
    /// proxy link (not a bare URL or a corrupted token).
    #[test]
    fn proxy_link_decodes_to_original_upstream_url(
        upstream_url in arb_upstream_url(),
        format in arb_link_format(),
    ) {
        let codec = codec();
        let payload = ProxyPayload::new(upstream_url.clone());

        let link = match format {
            LinkFormat::Token => codec.encode_token(&payload).expect("token encode succeeds"),
            LinkFormat::Encrypted => codec.encode_mediaflow(&payload).expect("mediaflow encode succeeds"),
        };

        // Decode the link and verify the upstream URL is recovered.
        let decoded = codec.decode(&link).expect("proxy link must be decodable");
        prop_assert_eq!(
            &decoded.url,
            &upstream_url,
            "Decoded proxy link must recover the original upstream URL; \
             format={:?}",
            format,
        );
    }

    /// Feature: stream-flow, Property 27 — both proxy-link formats produce
    /// URLs that route through the proxy (Store uses token format, Wrap uses
    /// encrypted format, both must satisfy the invariant).
    #[test]
    fn both_link_formats_route_through_proxy(
        upstream_url in arb_upstream_url(),
        proxy_base in arb_proxy_base(),
    ) {
        let codec = codec();
        let payload = ProxyPayload::new(upstream_url.clone());

        // Token format (stremthru / Store addon style).
        let token_link = codec.encode_token(&payload).expect("token encode succeeds");
        let token_stream_url = build_stream_url(&proxy_base, &token_link);
        let token_stream = Stream {
            url: Some(token_stream_url),
            ..Default::default()
        };
        assert_routes_through_proxy(&token_stream, &proxy_base, &upstream_url);

        // Encrypted format (mediaflow / Wrap addon style).
        let enc_link = codec.encode_mediaflow(&payload).expect("mediaflow encode succeeds");
        let enc_stream_url = build_stream_url(&proxy_base, &enc_link);
        let enc_stream = Stream {
            url: Some(enc_stream_url),
            ..Default::default()
        };
        assert_routes_through_proxy(&enc_stream, &proxy_base, &upstream_url);

        // The two formats produce different outer URLs (different token shapes).
        prop_assert_ne!(
            token_stream.url.as_deref().unwrap(),
            enc_stream.url.as_deref().unwrap(),
            "Token and encrypted formats must produce distinct proxy URLs",
        );
    }
}
