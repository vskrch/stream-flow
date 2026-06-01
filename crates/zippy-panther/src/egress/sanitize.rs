//! Layer 1 — outbound header sanitization (`egress::sanitize`) — Req 51.2,
//! 51.3, 51.12.
//!
//! [`sanitize_outbound`] is the **only** approved way to build the
//! `HeaderMap` for an upstream (debrid / end-media) request. It copies an
//! inbound request's headers into a fresh outbound map while **stripping every
//! client-identifying header** so a user's real IP can never leave the process
//! (design: Components -> Egress -> Layer 1 header sanitization). It is the
//! application-layer half of the IP_Isolation invariant; Layer 2 (transport
//! tunneling) and the `OutboundClient` seam that *applies* this function on
//! every upstream path land in tasks 8.2/8.3.
//!
//! ## What is stripped
//!
//! Two independent guarantees hold for the produced map (Property 60):
//!
//! 1. **By name (Req 51.2, 51.3):** none of the nine client-identifying header
//!    names in [`CLIENT_IDENTIFYING_HEADERS`] survive — `X-Forwarded-For`,
//!    `X-Real-IP`, `Forwarded`, `Via`, `X-Client-IP`, `True-Client-IP`,
//!    `CF-Connecting-IP`, `Fastly-Client-IP`, `X-Cluster-Client-IP`. The match
//!    is case-insensitive (HTTP header names are case-insensitive, and
//!    [`HeaderName`] normalizes to lowercase).
//! 2. **By value (Req 51.12):** when the inbound request's resolved
//!    `Client_IP` is supplied, no header whose value *is* (or, for a
//!    comma/space/semicolon-separated list, *contains* a token equal to) that
//!    IP survives. This is defence-in-depth: even a non-standard header (a
//!    custom `X-Originating-IP`, a value smuggled into another field) cannot
//!    carry the client IP upstream.
//!
//! Every other inbound header is forwarded unchanged, preserving multi-valued
//! headers (each value is re-appended), mirroring `stremthru`'s
//! `copyHeaders(..., stripIpHeaders=true)` — except here stripping is mandatory
//! on *all* upstream paths, not just the content-proxy path.

use std::net::IpAddr;

use actix_web::http::header::{HeaderMap, HeaderName};

/// The nine client-identifying request headers that MUST NEVER reach an
/// upstream debrid service or end media server (Req 51.2, 51.3; design Layer 1).
///
/// Stored lowercase because [`HeaderName::as_str`] is always lowercase, so a
/// direct `==` comparison is a case-insensitive match against any inbound
/// casing.
pub const CLIENT_IDENTIFYING_HEADERS: [&str; 9] = [
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "via",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-cluster-client-ip",
];

/// Returns `true` when `name` is one of the [`CLIENT_IDENTIFYING_HEADERS`] that
/// must be stripped from any outbound request (Req 51.2, 51.3).
///
/// Case-insensitive: HTTP header names are case-insensitive and
/// [`HeaderName::as_str`] normalizes to lowercase, so the comparison against
/// the lowercase constant covers every inbound casing.
pub fn is_client_identifying_header(name: &HeaderName) -> bool {
    CLIENT_IDENTIFYING_HEADERS.contains(&name.as_str())
}

/// Build the sanitized outbound [`HeaderMap`] for an upstream request — the
/// single approved outbound-header builder (Req 51.2, 51.3, 51.12).
///
/// Copies every header from `inbound` into a fresh map **except**:
/// * any header named in [`CLIENT_IDENTIFYING_HEADERS`] (stripped by name);
/// * when `client_ip` is `Some`, any header whose value equals — or contains a
///   comma/space/semicolon-separated token equal to — the client IP (stripped
///   by value).
///
/// Multi-valued inbound headers are preserved: each value is re-appended in
/// order. Header values that are not valid ASCII (so cannot encode an IP) are
/// never matched by the value check and are forwarded as-is.
///
/// The result is **total**: any inbound map and any `client_ip` yield a
/// `HeaderMap` without panicking, and that map satisfies both guarantees above
/// (Property 60).
pub fn sanitize_outbound(inbound: &HeaderMap, client_ip: Option<IpAddr>) -> HeaderMap {
    // Canonical string form of the client IP (e.g. "203.0.113.7",
    // "2001:db8::1"), computed once for the value-based strip (Req 51.12).
    let client_ip_str = client_ip.map(|ip| ip.to_string());

    let mut out = HeaderMap::new();
    for (name, value) in inbound.iter() {
        // Guarantee 1 — strip by name (Req 51.2, 51.3).
        if is_client_identifying_header(name) {
            continue;
        }
        // Guarantee 2 — strip by value: drop any header that carries the
        // client IP, even under a non-standard name (Req 51.12). A value that
        // is not valid ASCII cannot encode an IP, so it is never matched.
        if let Some(ip) = client_ip_str.as_deref() {
            if value.to_str().is_ok_and(|v| value_contains_ip(v, ip)) {
                continue;
            }
        }
        // Forward everything else unchanged; `append` preserves the order and
        // multiplicity of multi-valued headers.
        out.append(name.clone(), value.clone());
    }
    out
}

/// Returns `true` when the header value `value` is, or contains as a delimited
/// token, the client IP string `ip` (Req 51.12).
///
/// Header values that embed a client IP do so either as the whole value
/// (`X-Real-IP: 1.2.3.4`) or as one token in a comma / whitespace / semicolon
/// separated list (`X-Forwarded-For: 1.2.3.4, 5.6.7.8`,
/// `Forwarded: for=1.2.3.4`). Splitting on those delimiters and the `=` of
/// `key=value` forms isolates the candidate tokens so a substring coincidence
/// inside an unrelated value does not over-match.
fn value_contains_ip(value: &str, ip: &str) -> bool {
    value
        .split(|c: char| c == ',' || c == ';' || c == '=' || c.is_whitespace())
        .any(|token| token == ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::HeaderValue;

    /// Convenience: build an inbound map from `(name, value)` pairs, appending
    /// so repeated names become multi-valued headers.
    fn map_of(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.append(
                HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        h
    }

    fn contains_name(map: &HeaderMap, name: &str) -> bool {
        map.contains_key(HeaderName::from_bytes(name.as_bytes()).unwrap())
    }

    #[test]
    fn strips_every_client_identifying_header() {
        // One inbound header per forbidden name (plus casing variants).
        let inbound = map_of(&[
            ("X-Forwarded-For", "1.2.3.4, 5.6.7.8"),
            ("X-Real-IP", "1.2.3.4"),
            ("Forwarded", "for=1.2.3.4"),
            ("Via", "1.1 proxy.example"),
            ("X-Client-IP", "1.2.3.4"),
            ("True-Client-IP", "1.2.3.4"),
            ("CF-Connecting-IP", "1.2.3.4"),
            ("Fastly-Client-IP", "1.2.3.4"),
            ("X-Cluster-Client-IP", "1.2.3.4"),
        ]);

        let out = sanitize_outbound(&inbound, None);

        for name in CLIENT_IDENTIFYING_HEADERS {
            assert!(
                !contains_name(&out, name),
                "forbidden header {name} must not survive sanitization"
            );
        }
        assert!(out.is_empty(), "only forbidden headers were present");
    }

    #[test]
    fn strips_forbidden_headers_regardless_of_casing() {
        let inbound = map_of(&[
            ("x-forwarded-for", "1.2.3.4"),
            ("X-FORWARDED-FOR", "5.6.7.8"),
            ("X-Real-Ip", "9.9.9.9"),
        ]);

        let out = sanitize_outbound(&inbound, None);

        assert!(!contains_name(&out, "x-forwarded-for"));
        assert!(!contains_name(&out, "x-real-ip"));
        assert!(out.is_empty());
    }

    #[test]
    fn preserves_non_identifying_headers() {
        let inbound = map_of(&[
            ("User-Agent", "stream-flow/1.0"),
            ("Range", "bytes=0-1023"),
            ("Accept", "*/*"),
            ("X-Forwarded-For", "1.2.3.4"),
        ]);

        let out = sanitize_outbound(&inbound, None);

        assert_eq!(
            out.get("user-agent").map(|v| v.to_str().unwrap()),
            Some("stream-flow/1.0")
        );
        assert_eq!(
            out.get("range").map(|v| v.to_str().unwrap()),
            Some("bytes=0-1023")
        );
        assert_eq!(out.get("accept").map(|v| v.to_str().unwrap()), Some("*/*"));
        assert!(!contains_name(&out, "x-forwarded-for"));
    }

    #[test]
    fn preserves_multi_valued_headers() {
        let inbound = map_of(&[
            ("Accept-Encoding", "gzip"),
            ("Accept-Encoding", "deflate"),
            ("Accept-Encoding", "br"),
        ]);

        let out = sanitize_outbound(&inbound, None);

        let values: Vec<&str> = out
            .get_all("accept-encoding")
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, vec!["gzip", "deflate", "br"]);
    }

    #[test]
    fn strips_non_standard_header_whose_value_equals_client_ip() {
        let client_ip: IpAddr = "203.0.113.7".parse().unwrap();
        let inbound = map_of(&[
            ("X-Originating-IP", "203.0.113.7"),
            ("User-Agent", "stream-flow/1.0"),
        ]);

        let out = sanitize_outbound(&inbound, Some(client_ip));

        assert!(
            !contains_name(&out, "x-originating-ip"),
            "a header smuggling the client IP must be stripped by value"
        );
        // Unrelated headers still pass through.
        assert!(contains_name(&out, "user-agent"));
        // No surviving value may equal the client IP.
        for (_name, value) in out.iter() {
            assert_ne!(value.to_str().unwrap(), "203.0.113.7");
        }
    }

    #[test]
    fn strips_value_when_client_ip_is_a_token_in_a_list() {
        let client_ip: IpAddr = "198.51.100.23".parse().unwrap();
        let inbound = map_of(&[("X-Trace", "edge=a; ip=198.51.100.23; node=b")]);

        let out = sanitize_outbound(&inbound, Some(client_ip));

        assert!(
            !contains_name(&out, "x-trace"),
            "a list-valued header containing the client IP token must be stripped"
        );
    }

    #[test]
    fn keeps_value_matching_client_ip_only_when_ip_unknown() {
        // With no client IP supplied, value-based stripping does not apply;
        // only the by-name strip runs.
        let inbound = map_of(&[("X-Originating-IP", "203.0.113.7")]);

        let out = sanitize_outbound(&inbound, None);

        assert!(contains_name(&out, "x-originating-ip"));
    }

    #[test]
    fn empty_inbound_yields_empty_outbound() {
        let out = sanitize_outbound(&HeaderMap::new(), None);
        assert!(out.is_empty());
    }

    #[test]
    fn ipv6_client_ip_is_stripped_by_value() {
        let client_ip: IpAddr = "2001:db8::1".parse().unwrap();
        // `IpAddr::to_string` for this address is the canonical "2001:db8::1".
        let inbound = map_of(&[("X-Originating-IP", "2001:db8::1")]);

        let out = sanitize_outbound(&inbound, Some(client_ip));

        assert!(!contains_name(&out, "x-originating-ip"));
    }

    #[test]
    fn is_client_identifying_header_matches_known_names_case_insensitively() {
        assert!(is_client_identifying_header(&HeaderName::from_static(
            "x-forwarded-for"
        )));
        assert!(is_client_identifying_header(
            &HeaderName::from_bytes(b"CF-Connecting-IP").unwrap()
        ));
        assert!(!is_client_identifying_header(&HeaderName::from_static(
            "user-agent"
        )));
    }
}
