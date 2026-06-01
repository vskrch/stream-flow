//! Property-based test for `Client_IP` precedence
//! (`http::client_ip::resolve_client_ip`, task 11.1).
//!
//! Feature: stream-flow, Property 29
//!
//! **Property 29: Client IP precedence**
//!
//! *For any* combination of `X-Real-IP`, `X-Forwarded-For`, and TCP peer
//! address, the derived `Client_IP` is the `X-Real-IP` value when present, else
//! the first `X-Forwarded-For` entry when present, else the TCP peer address.
//!
//! **Validates: Requirements 28.7**
//!
//! Requirement 28.7: "WHEN deriving the Client_IP for access control, THE
//! Stream_Flow_System SHALL use the `X-Real-IP` header, then the
//! `X-Forwarded-For` header, then the TCP source address, in that order of
//! precedence."
//!
//! ## How the invariant is exercised
//!
//! Each case independently chooses, for every precedence source, whether it is
//! *absent*, *present-but-unparseable* (empty or garbage), or *present-and-
//! parseable* (a real IP, rendered in one of the forms the resolver tolerates —
//! canonical, surrounded by whitespace, or `[..]`-bracketed):
//!
//! * **`X-Real-IP`** — a single header value.
//! * **`X-Forwarded-For`** — either absent or a present `client, proxy1, ...`
//!   list of one-or-more entries, so multi-entry lists and the "only the first
//!   entry counts" rule are both exercised. A leading empty entry (rendered
//!   from a leading comma) is a natural fall-through case.
//! * **peer** — an arbitrary IPv4/IPv6 address or `None`.
//!
//! Because the structured choices are generated *before* rendering, an
//! **independent oracle** computes the expected `Client_IP` straight from those
//! choices (`X-Real-IP` valid → first-`XFF` valid → peer) without ever calling
//! the production resolver, then the rendered strings are fed to
//! [`resolve_client_ip`] and the two are compared. Garbage tokens are drawn
//! from a comma-free, never-parseable pool so they reliably model the
//! fall-through ("higher-precedence source unparseable") branch.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use stream_flow::http::resolve_client_ip;

/// How a *parseable* IP token is spelled. The resolver trims surrounding
/// whitespace and strips a single `[..]` bracket pair (some proxies wrap IPv6
/// literals that way), so all three forms parse back to the same address.
#[derive(Clone, Debug)]
enum Rendering {
    /// `1.2.3.4` / `2001:db8::1`
    Canonical,
    /// `  1.2.3.4 ` — leading and trailing whitespace.
    Spaced,
    /// `[2001:db8::1]` — bracket-wrapped.
    Bracketed,
}

/// State of the single-valued `X-Real-IP` source.
#[derive(Clone, Debug)]
enum Source {
    /// Header not present.
    Absent,
    /// Header present with an empty value.
    Empty,
    /// Header present with an unparseable value.
    Garbage(String),
    /// Header present with a parseable IP rendered as `Rendering`.
    Valid(IpAddr, Rendering),
}

/// One entry inside an `X-Forwarded-For` list. (`Absent` has no per-entry
/// meaning — absence is modelled at the list level by [`Xff::Absent`].)
#[derive(Clone, Debug)]
enum Entry {
    /// An empty token (e.g. produced by a leading comma).
    Empty,
    /// An unparseable token.
    Garbage(String),
    /// A parseable IP rendered as `Rendering`.
    Valid(IpAddr, Rendering),
}

/// State of the `X-Forwarded-For` source.
#[derive(Clone, Debug)]
enum Xff {
    /// Header not present.
    Absent,
    /// Header present as `first, rest...` (one or more entries).
    Present { first: Entry, rest: Vec<Entry> },
}

/// Arbitrary IPv4 or IPv6 address.
fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|o| IpAddr::V4(Ipv4Addr::from(o))),
        any::<[u16; 8]>().prop_map(|s| IpAddr::V6(Ipv6Addr::from(s))),
    ]
}

fn arb_rendering() -> impl Strategy<Value = Rendering> {
    prop_oneof![
        Just(Rendering::Canonical),
        Just(Rendering::Spaced),
        Just(Rendering::Bracketed),
    ]
}

/// Comma-free tokens that never parse as an IP, even after the resolver's
/// trim + bracket-strip (so they reliably trigger fall-through).
fn arb_garbage() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("not-an-ip".to_string()),
        Just("999.999.999.999".to_string()),
        Just("1.2.3".to_string()),
        Just("::zzz".to_string()),
        Just("12345".to_string()),
        "[a-zA-Z]{1,8}",
    ]
}

fn arb_source() -> impl Strategy<Value = Source> {
    prop_oneof![
        Just(Source::Absent),
        Just(Source::Empty),
        arb_garbage().prop_map(Source::Garbage),
        (arb_ip(), arb_rendering()).prop_map(|(ip, r)| Source::Valid(ip, r)),
    ]
}

fn arb_entry() -> impl Strategy<Value = Entry> {
    prop_oneof![
        Just(Entry::Empty),
        arb_garbage().prop_map(Entry::Garbage),
        (arb_ip(), arb_rendering()).prop_map(|(ip, r)| Entry::Valid(ip, r)),
    ]
}

fn arb_xff() -> impl Strategy<Value = Xff> {
    prop_oneof![
        Just(Xff::Absent),
        (arb_entry(), proptest::collection::vec(arb_entry(), 0..=4))
            .prop_map(|(first, rest)| Xff::Present { first, rest }),
    ]
}

fn arb_peer() -> impl Strategy<Value = Option<IpAddr>> {
    prop_oneof![Just(None), arb_ip().prop_map(Some)]
}

/// Render a parseable IP into one of the resolver-tolerated forms.
fn render_ip(ip: IpAddr, r: &Rendering) -> String {
    match r {
        Rendering::Canonical => ip.to_string(),
        Rendering::Spaced => format!("  {ip} "),
        Rendering::Bracketed => format!("[{ip}]"),
    }
}

/// Render the `X-Real-IP` header: `None` when absent, else its string value.
fn render_source(s: &Source) -> Option<String> {
    match s {
        Source::Absent => None,
        Source::Empty => Some(String::new()),
        Source::Garbage(g) => Some(g.clone()),
        Source::Valid(ip, r) => Some(render_ip(*ip, r)),
    }
}

fn render_entry(e: &Entry) -> String {
    match e {
        Entry::Empty => String::new(),
        Entry::Garbage(g) => g.clone(),
        Entry::Valid(ip, r) => render_ip(*ip, r),
    }
}

/// Render the `X-Forwarded-For` header: `None` when absent, else the entries
/// joined as a `client, proxy1, ...` list.
fn render_xff(x: &Xff) -> Option<String> {
    match x {
        Xff::Absent => None,
        Xff::Present { first, rest } => {
            let mut parts = vec![render_entry(first)];
            parts.extend(rest.iter().map(render_entry));
            Some(parts.join(", "))
        }
    }
}

/// Independent oracle for Req 28.7 precedence, computed purely from the
/// structured choices (never calls the production resolver):
/// `X-Real-IP` (if a real IP) → first `X-Forwarded-For` entry (if a real IP) →
/// peer.
fn oracle(xreal: &Source, xff: &Xff, peer: Option<IpAddr>) -> Option<IpAddr> {
    if let Source::Valid(ip, _) = xreal {
        return Some(*ip);
    }
    if let Xff::Present {
        first: Entry::Valid(ip, _),
        ..
    } = xff
    {
        return Some(*ip);
    }
    peer
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 29 — client IP precedence.
    /// **Validates: Requirements 28.7**
    #[test]
    fn client_ip_follows_x_real_ip_then_first_xff_then_peer(
        xreal in arb_source(),
        xff in arb_xff(),
        peer in arb_peer(),
    ) {
        let xreal_str = render_source(&xreal);
        let xff_str = render_xff(&xff);

        let got = resolve_client_ip(xreal_str.as_deref(), xff_str.as_deref(), peer);
        let want = oracle(&xreal, &xff, peer);

        // -- Equality with the independent oracle ---------------------------
        prop_assert_eq!(
            got,
            want,
            "x_real_ip={:?} x_forwarded_for={:?} peer={:?}",
            xreal_str,
            xff_str,
            peer,
        );

        // -- Structural guarantees of Req 28.7 precedence -------------------
        match (&xreal, &xff) {
            // 1. A parseable X-Real-IP wins outright, regardless of XFF/peer.
            (Source::Valid(ip, _), _) => prop_assert_eq!(
                got,
                Some(*ip),
                "parseable X-Real-IP must win; xff={:?} peer={:?}",
                xff_str,
                peer,
            ),
            // 2. No usable X-Real-IP, but a parseable first XFF entry: it wins
            //    over peer.
            (_, Xff::Present { first: Entry::Valid(ip, _), .. }) => prop_assert_eq!(
                got,
                Some(*ip),
                "first XFF entry must win when X-Real-IP absent/unparseable; peer={:?}",
                peer,
            ),
            // 3. Neither header yields a parseable IP: fall through to peer.
            _ => prop_assert_eq!(
                got,
                peer,
                "must fall through to peer; x_real_ip={:?} x_forwarded_for={:?}",
                xreal_str,
                xff_str,
            ),
        }
    }
}
