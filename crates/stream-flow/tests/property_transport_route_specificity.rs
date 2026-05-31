//! Property-based test for transport-route specificity selection
//! (`proxy::routing::RoutingTable::select_route` + `RoutePattern`, task 14.1).
//! Exercises task 14.3.
//!
//! Feature: stream-flow, Property 18
//!
//! **Property 18: Transport route specificity selection**
//!
//! *For any* set of transport routes and any URL, `select_route` returns a
//! route that matches the URL and has the fewest wildcards among all matching
//! routes (most specific wins), or no route when none matches.
//!
//! **Validates: Requirements 13.1, 13.2**
//!
//! Requirement 13.1: "THE Streaming_Proxy_Engine SHALL accept Transport_Route
//! rules expressed as URL patterns supporting domain, protocol (`all://`), and
//! wildcard (`*`) matching."
//!
//! Requirement 13.2: "WHEN an outbound upstream request is made, THE
//! Streaming_Proxy_Engine SHALL select the most specific matching
//! Transport_Route, where specificity is ordered by fewer wildcards first."
//!
//! ## How the invariant is exercised
//!
//! Each case generates an arbitrary set of *route descriptors* drawn from the
//! full pattern grammar of Req 13.1 — exact host (any scheme), scheme-qualified
//! exact host, `*.suffix` subdomain wildcards (with and without an exact
//! scheme), the `*` / `all://` catch-alls, and scheme-qualified host wildcards
//! (`https://*`) — together with an arbitrary `http`/`https` URL whose host is
//! drawn from a pool that produces a healthy mix of exact hits, suffix hits
//! (incl. deep subdomains), apex near-misses, and total misses.
//!
//! The descriptors are rendered to their pattern strings and parsed by the
//! production [`RoutePattern::parse`] into a [`RoutingTable`]; each route is
//! given a **unique** forwarding-proxy URL so the route actually chosen by
//! [`RoutingTable::select_route`] can be recovered unambiguously from the
//! returned [`RouteSelection`].
//!
//! An **independent oracle** (the `pat_*` helpers below) re-derives, directly
//! from each descriptor and the requirement text, both *whether* a pattern
//! matches the URL and *how many wildcards* it carries — without calling any of
//! the production matching / wildcard code under test. The case then asserts:
//!
//! * **No-match case (Req 13.2 "...or no route when none matches"):** when the
//!   oracle finds no matching descriptor, the selection is `matched == false`.
//! * **Match case (Req 13.1 + 13.2):** when the oracle finds at least one
//!   matching descriptor, the selection is `matched == true`, the chosen route
//!   (recovered via its unique proxy) genuinely matches the URL, and its
//!   wildcard count equals the *minimum* wildcard count over all matching
//!   descriptors — i.e. the most-specific match won. The selection's
//!   `verify_ssl` is the chosen route's own policy.
//!
//! `all_proxy` mode and a distinct default proxy are also randomized so the
//! `matched` flag is proven independent of the unmatched-fallback behavior.

use proptest::prelude::*;
use url::Url;

use stream_flow::proxy::{ProxyUrl, RoutePattern, RoutingTable, TransportRoute};

// ===========================================================================
// Independent pattern model + oracle (re-derived from Req 13.1 / 13.2 text;
// shares no code with the production matcher / wildcard counter under test).
// ===========================================================================

/// How a pattern constrains the URL scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SchemeSel {
    /// Matches any scheme (rendered as `all://` / no-scheme). One wildcard.
    Any,
    /// Matches exactly this (lower-case) scheme. Zero wildcards.
    Exact(String),
}

/// How a pattern constrains the URL host.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostSel {
    /// Matches any host (rendered as `*`). One wildcard.
    Any,
    /// Matches this exact host. Zero wildcards.
    Exact(String),
    /// Matches any host ending in `.{base}` (rendered as `*.{base}`); does not
    /// match the bare apex `{base}`. One wildcard.
    Suffix(String),
}

/// A generated route descriptor: a scheme + host selector pair.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pat {
    scheme: SchemeSel,
    host: HostSel,
}

impl Pat {
    /// Render to the pattern string the production parser consumes. Every form
    /// here round-trips through [`RoutePattern::parse`] to the same semantics.
    fn render(&self) -> String {
        match (&self.scheme, &self.host) {
            (SchemeSel::Exact(s), HostSel::Exact(h)) => format!("{}://{}", s, h),
            (SchemeSel::Exact(s), HostSel::Suffix(b)) => format!("{}://*.{}", s, b),
            (SchemeSel::Exact(s), HostSel::Any) => format!("{}://*", s),
            (SchemeSel::Any, HostSel::Exact(h)) => h.clone(),
            (SchemeSel::Any, HostSel::Suffix(b)) => format!("*.{}", b),
            (SchemeSel::Any, HostSel::Any) => "*".to_string(),
        }
    }

    /// Oracle: does this pattern match `(scheme, host)`? Mirrors Req 13.1.
    fn matches(&self, scheme: &str, host: &str) -> bool {
        let scheme_ok = match &self.scheme {
            SchemeSel::Any => true,
            SchemeSel::Exact(s) => s == scheme,
        };
        let host_ok = match &self.host {
            HostSel::Any => true,
            HostSel::Exact(h) => h == host,
            HostSel::Suffix(b) => host.ends_with(&format!(".{}", b)),
        };
        scheme_ok && host_ok
    }

    /// Oracle: the wildcard count (fewer == more specific — Req 13.2). An
    /// any-scheme is one wildcard; an any/suffix host is one wildcard; exact
    /// scheme/host are zero.
    fn wildcards(&self) -> usize {
        let scheme_wc = usize::from(matches!(self.scheme, SchemeSel::Any));
        let host_wc = usize::from(!matches!(self.host, HostSel::Exact(_)));
        scheme_wc + host_wc
    }
}

// ===========================================================================
// Generators
// ===========================================================================

/// Scheme selector pool: any-scheme plus the two concrete schemes used by URLs.
fn arb_scheme_sel() -> impl Strategy<Value = SchemeSel> {
    prop_oneof![
        2 => Just(SchemeSel::Any),
        1 => Just(SchemeSel::Exact("http".to_string())),
        1 => Just(SchemeSel::Exact("https".to_string())),
    ]
}

/// Host selector pool. Exact hosts and suffix bases are drawn from a shared
/// family so generated patterns frequently match the generated URLs (and
/// frequently *just miss*, e.g. apex vs. `*.apex`).
fn arb_host_sel() -> impl Strategy<Value = HostSel> {
    prop_oneof![
        // Any-host catch-all.
        2 => Just(HostSel::Any),
        // Exact hosts (incl. an apex and a deep host).
        5 => prop_oneof![
            Just(HostSel::Exact("api.example.com".to_string())),
            Just(HostSel::Exact("cdn.example.com".to_string())),
            Just(HostSel::Exact("example.com".to_string())),
            Just(HostSel::Exact("api.test.org".to_string())),
        ],
        // Subdomain-wildcard suffixes (nested suffixes overlap deliberately).
        4 => prop_oneof![
            Just(HostSel::Suffix("example.com".to_string())),
            Just(HostSel::Suffix("cdn.example.com".to_string())),
            Just(HostSel::Suffix("test.org".to_string())),
        ],
    ]
}

/// One route descriptor.
fn arb_pat() -> impl Strategy<Value = Pat> {
    (arb_scheme_sel(), arb_host_sel()).prop_map(|(scheme, host)| Pat { scheme, host })
}

/// The URL scheme pool.
fn arb_url_scheme() -> impl Strategy<Value = String> {
    prop_oneof![Just("http".to_string()), Just("https".to_string()),]
}

/// The URL host pool: exact-match targets, a deep subdomain (matches several
/// suffix patterns), the apex (a near-miss for `*.example.com`), and a host no
/// host-specific pattern can match (only `*` / `all://` / `https://*` reach it).
fn arb_url_host() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("api.example.com".to_string()),
        Just("cdn.example.com".to_string()),
        Just("deep.cdn.example.com".to_string()),
        Just("example.com".to_string()),
        Just("api.test.org".to_string()),
        Just("unmatched.net".to_string()),
    ]
}

/// A whole case: a set of route descriptors, the URL parts, and the
/// unmatched-fallback policy (`all_proxy` + whether a default proxy exists).
fn arb_case() -> impl Strategy<Value = (Vec<Pat>, String, String, bool, bool)> {
    (
        proptest::collection::vec(arb_pat(), 0..=8),
        arb_url_scheme(),
        arb_url_host(),
        any::<bool>(),
        any::<bool>(),
    )
}

/// Build the routing table, giving route `i` the unique proxy
/// `http://proxy-{i}.local:8080` so the chosen route is recoverable from the
/// selection. `verify_ssl` alternates by index for extra signal.
fn build_table(pats: &[Pat], all_proxy: bool, has_default: bool) -> RoutingTable {
    let routes: Vec<TransportRoute> = pats
        .iter()
        .enumerate()
        .map(|(i, p)| TransportRoute {
            pattern: RoutePattern::parse(&p.render()).expect("generated pattern parses"),
            proxy: Some(
                ProxyUrl::parse(&format!("http://proxy-{}.local:8080", i))
                    .expect("valid proxy url"),
            ),
            verify_ssl: i % 2 == 0,
        })
        .collect();

    // The default proxy uses a distinct host so it can never be mistaken for a
    // route proxy in the match case.
    let default_proxy = if has_default {
        Some(ProxyUrl::parse("http://default.fallback.local:9090").expect("valid default proxy"))
    } else {
        None
    };

    RoutingTable::new(routes, all_proxy, default_proxy)
}

/// Recover the route index from a chosen `http://proxy-{i}.local:8080` URL.
fn proxy_index(proxy: &str) -> Option<usize> {
    proxy
        .strip_prefix("http://proxy-")
        .and_then(|rest| rest.strip_suffix(".local:8080"))
        .and_then(|n| n.parse::<usize>().ok())
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 18 — `select_route` picks a matching
    /// route with the fewest wildcards, or reports no match when none applies.
    ///
    /// **Validates: Requirements 13.1, 13.2**
    #[test]
    fn transport_route_selection_prefers_fewest_wildcards(
        (pats, scheme, host, all_proxy, has_default) in arb_case(),
    ) {
        let url = Url::parse(&format!("{}://{}/some/path", scheme, host))
            .expect("valid generated url");
        let table = build_table(&pats, all_proxy, has_default);
        let selection = table.select_route(&url);

        // Independent oracle: indices of descriptors that match the URL, and the
        // minimum wildcard count among them.
        let matching: Vec<usize> = pats
            .iter()
            .enumerate()
            .filter(|(_, p)| p.matches(&scheme, &host))
            .map(|(i, _)| i)
            .collect();

        if matching.is_empty() {
            // Req 13.2: "...or no route when none matches" — no specific route
            // applied, regardless of the (randomized) all-proxy fallback.
            prop_assert!(
                !selection.matched,
                "no descriptor matches {} but selection reports matched=true \
                 (pats={:?}, all_proxy={}, has_default={})",
                url, pats, all_proxy, has_default,
            );
        } else {
            // Req 13.1/13.2: a specific route matched and it is the most
            // specific (fewest wildcards) among the matching ones.
            prop_assert!(
                selection.matched,
                "{} has matching descriptors {:?} but selection reports matched=false \
                 (pats={:?})",
                url, matching, pats,
            );

            let chosen_proxy = selection
                .proxy_str()
                .expect("a matched route always carries its unique proxy");
            let idx = proxy_index(chosen_proxy).unwrap_or_else(|| {
                panic!("selection proxy {} is not a known route proxy", chosen_proxy)
            });

            // The chosen route must itself match the URL.
            prop_assert!(
                pats[idx].matches(&scheme, &host),
                "chosen route #{} ({:?}) does not match {} (pats={:?})",
                idx, pats[idx], url, pats,
            );

            // ...and carry the minimum wildcard count among all matches.
            let min_wc = matching
                .iter()
                .map(|&i| pats[i].wildcards())
                .min()
                .expect("matching is non-empty");
            let chosen_wc = pats[idx].wildcards();
            prop_assert_eq!(
                chosen_wc,
                min_wc,
                "chosen route #{} has {} wildcards but the most-specific match has {} \
                 for {} (matching={:?}, pats={:?})",
                idx, chosen_wc, min_wc, url, matching, pats,
            );

            // The selection carries the chosen route's own SSL-verify policy.
            prop_assert_eq!(
                selection.verify_ssl,
                idx % 2 == 0,
                "selection verify_ssl must equal chosen route #{}'s policy",
                idx,
            );
        }
    }
}
