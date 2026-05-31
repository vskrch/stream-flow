//! Client-IP resolver (`http::client_ip`) — Req 28.7, 51.2.
//!
//! A single function used everywhere a `Client_IP` is needed. The originating
//! client IP is derived with a fixed order of precedence (Req 28.7):
//!
//! 1. the `X-Real-IP` header, then
//! 2. the **first** entry of the `X-Forwarded-For` header, then
//! 3. the TCP peer (source) address of the connection.
//!
//! **`Client_IP` is for internal use only** — access control, rate limiting,
//! IP-bound proxy-link validation (Req 14.6), and (redacted) logging. It is
//! **never** passed to [`egress::OutboundClient`](crate::egress::OutboundClient)
//! and therefore can never reach a debrid service or end media server (Req
//! 51.2); debrid link IP-binding uses the Egress_IP instead (Req 51.4). The
//! outbound seam structurally enforces this: `OutboundClient::upstream` takes
//! only a target URL, with no parameter through which a `Client_IP` could be
//! supplied (design: Components → Egress → Multi-tenant fan-in/fan-out).

use std::net::IpAddr;

use actix_web::HttpRequest;

/// The `X-Real-IP` request header name (highest precedence, Req 28.7).
const X_REAL_IP: &str = "x-real-ip";
/// The `X-Forwarded-For` request header name (second precedence, Req 28.7).
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Resolve the originating [`Client_IP`](crate::http::client_ip) for an inbound
/// actix request, applying the Req 28.7 precedence
/// (`X-Real-IP` → first `X-Forwarded-For` → TCP peer).
///
/// Returns `None` only when *no* source yields a parseable IP (no usable
/// headers and no peer address — e.g. a synthetic test request without a peer).
///
/// The result is for **internal** use (auth / rate-limit / IP-bound proxy-link
/// validation / redacted logging) and must never be forwarded upstream (Req
/// 51.2); see the module docs.
pub fn client_ip(req: &HttpRequest) -> Option<IpAddr> {
    let headers = req.headers();
    let x_real_ip = headers.get(X_REAL_IP).and_then(|v| v.to_str().ok());
    let x_forwarded_for = headers.get(X_FORWARDED_FOR).and_then(|v| v.to_str().ok());
    let peer = req.peer_addr().map(|sa| sa.ip());
    resolve_client_ip(x_real_ip, x_forwarded_for, peer)
}

/// Pure core of the resolver (Req 28.7): given the raw `X-Real-IP` and
/// `X-Forwarded-For` header values and the TCP `peer` address, return the
/// derived `Client_IP`.
///
/// Precedence, with fall-through when a higher-precedence source is absent or
/// does not contain a parseable IP:
///
/// 1. `x_real_ip`, parsed as a single IP;
/// 2. the first comma-separated entry of `x_forwarded_for`, parsed as an IP;
/// 3. the TCP `peer` address.
///
/// Splitting the pure logic out keeps it trivially unit-testable and lets the
/// property test (task 11.4, Property 29) drive it directly with generated
/// inputs.
pub fn resolve_client_ip(
    x_real_ip: Option<&str>,
    x_forwarded_for: Option<&str>,
    peer: Option<IpAddr>,
) -> Option<IpAddr> {
    // 1. X-Real-IP (highest precedence): a single IP value.
    if let Some(ip) = x_real_ip.and_then(parse_ip) {
        return Some(ip);
    }
    // 2. First X-Forwarded-For entry: `client, proxy1, proxy2, ...`.
    if let Some(ip) = x_forwarded_for
        .and_then(|xff| xff.split(',').next())
        .and_then(parse_ip)
    {
        return Some(ip);
    }
    // 3. TCP peer (source) address.
    peer
}

/// Parse a single IP token, tolerating surrounding whitespace and the
/// `[..]` bracketing some proxies wrap around IPv6 literals. Returns `None`
/// for empty or unparseable tokens so the caller falls through to the next
/// source.
fn parse_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // -- Pure core: precedence (Req 28.7) ------------------------------------

    #[test]
    fn x_real_ip_wins_over_xff_and_peer() {
        let got = resolve_client_ip(
            Some("203.0.113.7"),
            Some("198.51.100.9, 10.0.0.1"),
            Some(ip("192.0.2.5")),
        );
        assert_eq!(got, Some(ip("203.0.113.7")));
    }

    #[test]
    fn first_xff_entry_wins_when_no_x_real_ip() {
        let got = resolve_client_ip(
            None,
            Some("198.51.100.9, 10.0.0.1, 172.16.0.1"),
            Some(ip("192.0.2.5")),
        );
        assert_eq!(got, Some(ip("198.51.100.9")));
    }

    #[test]
    fn peer_used_when_no_headers() {
        let got = resolve_client_ip(None, None, Some(ip("192.0.2.5")));
        assert_eq!(got, Some(ip("192.0.2.5")));
    }

    #[test]
    fn none_when_no_source_available() {
        assert_eq!(resolve_client_ip(None, None, None), None);
    }

    #[test]
    fn single_xff_entry_without_comma() {
        let got = resolve_client_ip(None, Some("198.51.100.9"), Some(ip("192.0.2.5")));
        assert_eq!(got, Some(ip("198.51.100.9")));
    }

    #[test]
    fn xff_first_entry_trimmed_of_whitespace() {
        let got = resolve_client_ip(None, Some("  198.51.100.9 , 10.0.0.1"), None);
        assert_eq!(got, Some(ip("198.51.100.9")));
    }

    #[test]
    fn ipv6_x_real_ip_is_parsed() {
        let got = resolve_client_ip(Some("2001:db8::1"), None, None);
        assert_eq!(
            got,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn bracketed_ipv6_x_real_ip_is_parsed() {
        // Some proxies emit IPv6 in `[..]` form; tolerate it.
        let got = resolve_client_ip(Some("[2001:db8::1]"), None, None);
        assert_eq!(got, Some(ip("2001:db8::1")));
    }

    // -- Fall-through on unparseable higher-precedence sources ---------------

    #[test]
    fn falls_through_to_xff_when_x_real_ip_unparseable() {
        let got = resolve_client_ip(
            Some("not-an-ip"),
            Some("198.51.100.9"),
            Some(ip("192.0.2.5")),
        );
        assert_eq!(got, Some(ip("198.51.100.9")));
    }

    #[test]
    fn falls_through_to_peer_when_headers_unparseable() {
        let got = resolve_client_ip(
            Some("garbage"),
            Some("also, garbage"),
            Some(ip("192.0.2.5")),
        );
        assert_eq!(got, Some(ip("192.0.2.5")));
    }

    #[test]
    fn empty_header_values_fall_through() {
        let got = resolve_client_ip(Some(""), Some(""), Some(ip("192.0.2.5")));
        assert_eq!(got, Some(ip("192.0.2.5")));
    }

    #[test]
    fn empty_first_xff_entry_falls_through_to_peer() {
        // A leading comma yields an empty first token; fall through to peer.
        let got = resolve_client_ip(None, Some(", 10.0.0.1"), Some(ip("192.0.2.5")));
        assert_eq!(got, Some(ip("192.0.2.5")));
    }

    // -- actix HttpRequest wiring (Req 28.7) ---------------------------------

    #[actix_web::test]
    async fn http_request_prefers_x_real_ip_header() {
        let req = TestRequest::default()
            .insert_header(("X-Real-IP", "203.0.113.7"))
            .insert_header(("X-Forwarded-For", "198.51.100.9, 10.0.0.1"))
            .peer_addr(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 5), 4444)))
            .to_http_request();
        assert_eq!(client_ip(&req), Some(ip("203.0.113.7")));
    }

    #[actix_web::test]
    async fn http_request_uses_first_xff_when_no_x_real_ip() {
        let req = TestRequest::default()
            .insert_header(("X-Forwarded-For", "198.51.100.9, 10.0.0.1"))
            .peer_addr(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 5), 4444)))
            .to_http_request();
        assert_eq!(client_ip(&req), Some(ip("198.51.100.9")));
    }

    #[actix_web::test]
    async fn http_request_falls_back_to_peer_addr() {
        let req = TestRequest::default()
            .peer_addr(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 5), 4444)))
            .to_http_request();
        assert_eq!(client_ip(&req), Some(ip("192.0.2.5")));
    }

    #[actix_web::test]
    async fn http_request_header_name_is_case_insensitive() {
        // HTTP header names are case-insensitive; actix normalizes them.
        let req = TestRequest::default()
            .insert_header(("x-ReAl-Ip", "203.0.113.7"))
            .to_http_request();
        assert_eq!(client_ip(&req), Some(ip("203.0.113.7")));
    }
}
