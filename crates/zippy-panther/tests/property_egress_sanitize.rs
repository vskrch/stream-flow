//! Property-based test for outbound header sanitization
//! (`egress::sanitize_outbound`, task 8.4).
//!
//! Feature: ZippyPanther, Property 60
//!
//! **Property 60: Outbound requests never carry client-identifying headers**
//!
//! *For any* inbound request carrying any combination of client-identifying
//! headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `Via`, `X-Client-IP`,
//! `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`,
//! `X-Cluster-Client-IP`) with any values, and *for any* target debrid/media
//! URL, the `HeaderMap` produced by `egress::sanitize_outbound` (the only
//! approved outbound-header builder) contains none of those header names and
//! contains no value equal to the inbound `Client_IP`.
//!
//! **Validates: Requirements 51.2, 51.3, 51.12**
//!
//! Requirement 51.2: "THE Stream_Flow_System SHALL NEVER forward, copy, or
//! otherwise expose a user's Client_IP to any debrid service or end media
//! server, including via `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `Via`, or
//! any other request header or parameter."
//!
//! Requirement 51.3: "WHEN constructing an upstream request, THE
//! Stream_Flow_System SHALL strip or omit all client-identifying headers ...
//! before the request leaves the system."
//!
//! Requirement 51.12: "THE Stream_Flow_System SHALL provide automated tests
//! proving that, for any user request, no client-identifying header or user IP
//! value appears in the corresponding upstream request ..."
//!
//! ## How the invariants are exercised
//!
//! Each case generates an arbitrary inbound [`HeaderMap`] mixing:
//!
//! * the nine forbidden client-identifying headers under arbitrary casings and
//!   with arbitrary (and sometimes repeated / multi-valued) values, and
//! * arbitrary benign headers whose values may *or may not* embed the generated
//!   client IP (as the whole value or as one token in a delimited list),
//!
//! together with an arbitrary optional `Client_IP` (IPv4 or IPv6). The case
//! then asserts the two independent guarantees of Property 60 on the sanitized
//! output:
//!
//! * **By name (Req 51.2, 51.3):** none of the nine
//!   [`CLIENT_IDENTIFYING_HEADERS`] survive, under any casing.
//! * **By value (Req 51.12):** when a `Client_IP` is supplied, no surviving
//!   header value equals it nor contains it as a comma / whitespace / semicolon
//!   / `=`-delimited token.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
use proptest::prelude::*;
use zippy_panther::egress::{
    is_client_identifying_header, sanitize_outbound, CLIENT_IDENTIFYING_HEADERS,
};

/// The nine forbidden header names, each rendered in a few casings so the
/// generator covers the case-insensitive match the requirement hinges on.
fn arb_forbidden_name() -> impl Strategy<Value = String> {
    let names: Vec<String> = CLIENT_IDENTIFYING_HEADERS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let len = names.len();
    (0..len, 0..3usize).prop_map(move |(idx, casing)| {
        let canonical = &names[idx];
        match casing {
            0 => canonical.clone(),            // lowercase, as stored
            1 => canonical.to_uppercase(),     // SHOUTING
            _ => title_case_header(canonical), // X-Forwarded-For style
        }
    })
}

/// Render a lowercase `a-b-c` header name in `A-B-C` title casing.
fn title_case_header(lower: &str) -> String {
    lower
        .split('-')
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Arbitrary benign (non-forbidden) header names — realistic request headers
/// plus generated `x-...` names. None of these is a client-identifying header,
/// so they should always survive *unless* their value carries the client IP.
fn arb_benign_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("user-agent".to_string()),
        Just("accept".to_string()),
        Just("accept-encoding".to_string()),
        Just("range".to_string()),
        Just("referer".to_string()),
        Just("x-trace".to_string()),
        Just("x-originating-ip".to_string()),
        "x-[a-z]{1,8}".prop_map(|s| s),
    ]
}

/// Arbitrary client IP — both IPv4 and IPv6 so the canonical `to_string()`
/// forms (e.g. "203.0.113.7", "2001:db8::1") are exercised by the value strip.
fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
        any::<u128>().prop_map(|bits| IpAddr::V6(Ipv6Addr::from(bits))),
    ]
}

/// Build a header value that *embeds* `ip`, either as the whole value or as one
/// token inside a delimited list, to stress the value-based strip (Req 51.12).
fn arb_value_with_ip(ip: String) -> impl Strategy<Value = String> {
    prop_oneof![
        Just(ip.clone()),                         // bare IP
        Just(format!("{ip}, 5.6.7.8")),           // first token of a list
        Just(format!("10.0.0.1, {ip}")),          // later token
        Just(format!("for={ip}")),                // Forwarded-style key=value
        Just(format!("edge=a; ip={ip}; node=b")), // semicolon list
    ]
}

/// Arbitrary benign value that does NOT contain the client IP as a token. Kept
/// to short ASCII tokens (and a few realistic values) so it is a valid
/// [`HeaderValue`] and cannot accidentally coincide with a generated IP.
fn arb_plain_value() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("ZippyPanther/1.0".to_string()),
        Just("*/*".to_string()),
        Just("bytes=0-1023".to_string()),
        Just("gzip, deflate, br".to_string()),
        "[a-zA-Z][a-zA-Z0-9/._-]{0,16}".prop_map(|s| s),
    ]
}

/// One inbound header entry: a (name, value) pair. Built from one of three
/// shapes so an arbitrary mix of forbidden / IP-bearing / benign headers
/// arises naturally, including multi-valued (repeated-name) headers.
#[derive(Debug, Clone)]
struct Entry {
    name: String,
    value: String,
}

/// Generate an inbound entry, given the case's client IP, across three shapes:
/// a forbidden header (any value), a benign header carrying the client IP, and
/// a benign header with a plain value.
fn arb_entry(ip: IpAddr) -> impl Strategy<Value = Entry> {
    let ip_str = ip.to_string();
    prop_oneof![
        // A forbidden, client-identifying header with an arbitrary value.
        (arb_forbidden_name(), arb_plain_value()).prop_map(|(name, value)| Entry { name, value }),
        // A benign header whose value embeds the client IP (defence-in-depth).
        (arb_benign_name(), arb_value_with_ip(ip_str.clone()))
            .prop_map(|(name, value)| Entry { name, value }),
        // A benign header with a value that does not carry the IP.
        (arb_benign_name(), arb_plain_value()).prop_map(|(name, value)| Entry { name, value }),
    ]
}

/// Build the inbound [`HeaderMap`] from generated entries, plus whether the
/// case supplies a `Client_IP` at all (`None` exercises the by-name-only path).
fn arb_case() -> impl Strategy<Value = (HeaderMap, Option<IpAddr>)> {
    arb_ip().prop_flat_map(|ip| {
        (
            proptest::collection::vec(arb_entry(ip), 0..=12),
            any::<bool>(),
        )
            .prop_map(move |(entries, supply_ip)| {
                let mut map = HeaderMap::new();
                for e in entries {
                    // Only append pairs that are individually valid HTTP header
                    // name/value; generated names/values are constrained to be
                    // valid, but guard defensively to keep the test total.
                    if let (Ok(name), Ok(value)) = (
                        HeaderName::from_bytes(e.name.as_bytes()),
                        HeaderValue::from_str(&e.value),
                    ) {
                        map.append(name, value);
                    }
                }
                (map, if supply_ip { Some(ip) } else { None })
            })
    })
}

/// Re-implementation of the by-value token match, independent of the
/// production code, so the assertion is an external oracle rather than the
/// same logic under test.
fn value_has_ip_token(value: &str, ip: &str) -> bool {
    value
        .split(|c: char| c == ',' || c == ';' || c == '=' || c.is_whitespace())
        .any(|token| token == ip)
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 60 — outbound requests never carry
    /// client-identifying headers. **Validates: Requirements 51.2, 51.3, 51.12**
    #[test]
    fn outbound_never_carries_client_identifying_headers(
        (inbound, client_ip) in arb_case(),
    ) {
        let out = sanitize_outbound(&inbound, client_ip);

        // -- Guarantee 1 — by name (Req 51.2, 51.3) --------------------------
        // None of the nine client-identifying header names survive, under any
        // casing. Checked two ways: against the canonical name set, and by
        // re-scanning every surviving header name through the predicate.
        for forbidden in CLIENT_IDENTIFYING_HEADERS {
            let name = HeaderName::from_bytes(forbidden.as_bytes()).unwrap();
            prop_assert!(
                !out.contains_key(&name),
                "forbidden header {forbidden:?} survived sanitization (inbound={inbound:?})",
            );
        }
        for (name, _value) in out.iter() {
            prop_assert!(
                !is_client_identifying_header(name),
                "a surviving header {:?} is client-identifying and must have been stripped",
                name,
            );
        }

        // -- Guarantee 2 — by value (Req 51.12) ------------------------------
        // When a Client_IP is supplied, no surviving header value equals it nor
        // contains it as a delimited token.
        if let Some(ip) = client_ip {
            let ip_str = ip.to_string();
            for (name, value) in out.iter() {
                if let Ok(v) = value.to_str() {
                    prop_assert!(
                        !value_has_ip_token(v, &ip_str),
                        "surviving header {:?} carries the client IP {ip_str:?} in value {v:?}",
                        name,
                    );
                }
            }
        }
    }
}
