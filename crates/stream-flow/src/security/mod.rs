//! Security / SSRF guard + input validation + body-size caps (`security`) —
//! Req 46.
//!
//! This module is the single place that decides whether an *outbound* target
//! is safe to dial and that every body stays within its configured cap. It is
//! the first gate any forward/proxy path crosses before a request is handed to
//! [`crate::egress::OutboundClient`] (design: Components → Security / SSRF).
//!
//! * [`resolve_and_guard`] resolves a target host to an [`IpAddr`] and denies
//!   private/loopback/link-local ranges unless the host is explicitly
//!   allowlisted (Req 46.1), enforces a configured allowlist as a strict
//!   allow-only list (Req 46.2), and denies every denylisted host (Req 46.3).
//! * [`check_request_body_size`] rejects an over-cap inbound request body with
//!   a `payload-too-large` error (Req 46.4).
//! * [`check_response_body_size`] / [`read_to_cap`] abort a buffered upstream
//!   read that exceeds the configured cap and surface an error (Req 46.5).
//! * [`validate_url`] / [`validate_header_name`] / [`validate_header_value`] /
//!   [`validate_param`] reject malformed URLs, headers, and parameters before
//!   any upstream request is initiated (Req 46.6).
//!
//! Every rejection is a typed [`AppError`] from the canonical taxonomy
//! (Req 47); nothing here logs a secret value (Req 46.7).

use std::net::{IpAddr, ToSocketAddrs};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use url::Url;

use crate::config::SecurityConfig;
use crate::errors::AppError;

// ---------------------------------------------------------------------------
// SSRF guard (Req 46.1, 46.2, 46.3)
// ---------------------------------------------------------------------------

/// Resolve `host` to an [`IpAddr`] and apply the full SSRF guard (Req 46.1–3).
///
/// `host` is a bare hostname or IP literal (the host component of an already
/// [`validate_url`]-checked URL). It is resolved through the local resolver;
/// an IP literal resolves to itself without a network lookup. *Every* resolved
/// address is guarded — if any resolves into a disallowed range (and the host
/// is not allowlisted) the request is denied, closing the DNS-rebinding hole
/// where a name maps to both a public and an internal address.
///
/// Returns the first guarded address on success, a `Forbidden` [`AppError`]
/// when the target is disallowed (Req 46.1–3), or a `BadRequest` when the host
/// cannot be resolved (Req 46.6).
pub fn resolve_and_guard(host: &str, cfg: &SecurityConfig) -> Result<IpAddr, AppError> {
    // Port 0 is a placeholder; only the resolved IP matters here.
    let resolved = (host, 0u16)
        .to_socket_addrs()
        .map_err(|_| AppError::bad_request(format!("could not resolve host: {host}")))?;

    let mut first: Option<IpAddr> = None;
    for sock_addr in resolved {
        let ip = normalize(sock_addr.ip());
        // A denied address short-circuits the whole target (DNS-rebinding safe).
        guard_resolved_ip(ip, host, cfg)?;
        if first.is_none() {
            first = Some(ip);
        }
    }

    first.ok_or_else(|| AppError::bad_request(format!("host resolved to no addresses: {host}")))
}

/// Apply the SSRF guard to an already-resolved `ip` for `host` (Req 46.1–3).
///
/// Precedence: a denylist match always wins (Req 46.3); then, when an
/// allowlist is configured it becomes a strict allow-only list — listed hosts
/// pass (even private ones, satisfying the Req 46.1 allowlist exception) and
/// everything else is denied (Req 46.2); with no allowlist, a
/// private/loopback/link-local address is denied unless
/// [`allow_private_ranges`](SecurityConfig::allow_private_ranges) is set
/// (Req 46.1).
pub fn guard_resolved_ip(ip: IpAddr, host: &str, cfg: &SecurityConfig) -> Result<IpAddr, AppError> {
    if list_matches(&cfg.ssrf_denylist, ip, host) {
        return Err(AppError::forbidden(format!(
            "target host is denylisted: {host}"
        )));
    }

    if !cfg.ssrf_allowlist.is_empty() {
        if list_matches(&cfg.ssrf_allowlist, ip, host) {
            return Ok(ip);
        }
        return Err(AppError::forbidden(format!(
            "target host is not on the configured allowlist: {host}"
        )));
    }

    if is_disallowed_range(ip) && !cfg.allow_private_ranges {
        return Err(AppError::forbidden(format!(
            "target resolves to a private, loopback, or link-local address: {host}"
        )));
    }

    Ok(ip)
}

/// `true` when `ip` falls in a private, loopback, link-local, unspecified, or
/// otherwise non-routable-to-the-public-internet range (Req 46.1).
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped to their IPv4
/// form first so a mapped loopback cannot slip past the guard.
pub fn is_disallowed_range(ip: IpAddr) -> bool {
    match normalize(ip) {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            let seg = v6.octets();
            // ::1 loopback / :: unspecified.
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local (std `is_unique_local` is unstable).
                || (seg[0] & 0xfe) == 0xfc
                // fe80::/10 unicast link-local (std method is unstable).
                || (seg[0] == 0xfe && (seg[1] & 0xc0) == 0x80)
        }
    }
}

/// Collapse an IPv4-mapped IPv6 address to its IPv4 form; pass everything else
/// through unchanged.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// `true` when `ip` (or `host`) matches any entry in `entries`.
///
/// Each entry is matched as a CIDR (`addr/prefix`), then an exact IP literal,
/// and finally a case-insensitive host string — so the allow/deny lists accept
/// `10.0.0.0/8`, `8.8.8.8`, and `internal.svc.local` alike (Req 46.2, 46.3).
fn list_matches(entries: &[String], ip: IpAddr, host: &str) -> bool {
    entries.iter().any(|raw| {
        let entry = raw.trim();
        if entry.is_empty() {
            return false;
        }
        if entry.contains('/') {
            return cidr_contains(entry, ip);
        }
        if let Ok(entry_ip) = entry.parse::<IpAddr>() {
            return normalize(entry_ip) == ip;
        }
        entry.eq_ignore_ascii_case(host)
    })
}

/// `true` when `ip` is contained in the `addr/prefix` CIDR block `entry`.
///
/// Returns `false` for a malformed entry or an address-family mismatch rather
/// than erroring — config-load validation is responsible for rejecting bad
/// patterns; here a non-matching entry simply does not match.
fn cidr_contains(entry: &str, ip: IpAddr) -> bool {
    let (base_str, prefix_str) = match entry.split_once('/') {
        Some(parts) => parts,
        None => return false,
    };
    let prefix: u32 = match prefix_str.trim().parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let base: IpAddr = match base_str.trim().parse() {
        Ok(b) => normalize(b),
        Err(_) => return false,
    };

    match (base, ip) {
        (IpAddr::V4(base), IpAddr::V4(ip)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask: u32 = u32::MAX << (32 - prefix);
            (u32::from(base) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(base), IpAddr::V6(ip)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask: u128 = u128::MAX << (128 - prefix);
            (u128::from(base) & mask) == (u128::from(ip) & mask)
        }
        // Address-family mismatch never matches.
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Body-size caps (Req 46.4, 46.5)
// ---------------------------------------------------------------------------

/// Reject an inbound request body that exceeds
/// [`max_request_body_bytes`](SecurityConfig::max_request_body_bytes) with a
/// `payload-too-large` error (Req 46.4). A body exactly at the cap is accepted.
pub fn check_request_body_size(size: usize, cfg: &SecurityConfig) -> Result<(), AppError> {
    if size > cfg.max_request_body_bytes {
        return Err(AppError::payload_too_large(format!(
            "request body of {size} bytes exceeds the {}-byte cap",
            cfg.max_request_body_bytes
        )));
    }
    Ok(())
}

/// Reject a buffered upstream response body that exceeds
/// [`max_response_body_bytes`](SecurityConfig::max_response_body_bytes) with a
/// `payload-too-large` error (Req 46.5). A body exactly at the cap is accepted.
pub fn check_response_body_size(size: usize, cfg: &SecurityConfig) -> Result<(), AppError> {
    if size > cfg.max_response_body_bytes {
        return Err(AppError::payload_too_large(format!(
            "upstream response body of {size} bytes exceeds the {}-byte cap",
            cfg.max_response_body_bytes
        )));
    }
    Ok(())
}

/// Buffer a chunked upstream body into memory, aborting the moment the
/// accumulated size would exceed `cap` (Req 46.5).
///
/// As soon as the cap is crossed the function returns a `payload-too-large`
/// [`AppError`] and drops the stream, so no further chunks are polled — the
/// read is genuinely aborted rather than drained. A transport error on the
/// stream surfaces as an `UpstreamUnavailable` [`AppError`]. On success the
/// fully buffered body is returned.
pub async fn read_to_cap<S, E>(stream: S, cap: usize) -> Result<Vec<u8>, AppError>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: std::fmt::Display,
{
    let mut stream = std::pin::pin!(stream);
    let mut buf: Vec<u8> = Vec::new();

    while let Some(item) = stream.next().await {
        let chunk =
            item.map_err(|e| AppError::upstream_unavailable(format!("upstream read failed: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(AppError::payload_too_large(format!(
                "buffered upstream body exceeds the {cap}-byte cap"
            )));
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

// ---------------------------------------------------------------------------
// URL / header / parameter validation (Req 46.6)
// ---------------------------------------------------------------------------

/// Parse and validate an upstream target URL (Req 46.6).
///
/// Rejects anything that is not a syntactically valid absolute `http`/`https`
/// URL with a non-empty host. Non-web schemes (`file:`, `ftp:`, `javascript:`,
/// …) and host-less URLs are refused as `BadRequest` before any dial.
pub fn validate_url(raw: &str) -> Result<Url, AppError> {
    let url = Url::parse(raw).map_err(|e| AppError::bad_request(format!("malformed URL: {e}")))?;

    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(AppError::bad_request(format!(
                "unsupported URL scheme '{other}': only http/https are allowed"
            )));
        }
    }

    match url.host_str() {
        Some(host) if !host.is_empty() => {}
        _ => return Err(AppError::bad_request("URL is missing a host".to_string())),
    }

    Ok(url)
}

/// Validate an HTTP header *name* (Req 46.6).
///
/// A name must be a non-empty RFC 7230 token (`tchar`s only) — this rejects
/// empty names, embedded spaces, and CR/LF header-injection attempts.
pub fn validate_header_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::bad_request(
            "header name must not be empty".to_string(),
        ));
    }
    if !name.bytes().all(is_tchar) {
        return Err(AppError::bad_request(format!(
            "header name contains illegal characters: {name:?}"
        )));
    }
    Ok(())
}

/// Validate an HTTP header *value* (Req 46.6).
///
/// Rejects control characters — most importantly CR and LF (header/response
/// splitting) and NUL — while allowing ordinary visible text, spaces, and
/// horizontal tabs.
pub fn validate_header_value(value: &str) -> Result<(), AppError> {
    if value.bytes().any(is_forbidden_text_byte) {
        return Err(AppError::bad_request(
            "header value contains illegal control characters".to_string(),
        ));
    }
    Ok(())
}

/// Validate a free-form request parameter (Req 46.6).
///
/// Rejects control characters (CR/LF/NUL/etc.) that could smuggle structure
/// into a derived upstream request, while allowing ordinary text, spaces, and
/// horizontal tabs.
pub fn validate_param(value: &str) -> Result<(), AppError> {
    if value.bytes().any(is_forbidden_text_byte) {
        return Err(AppError::bad_request(
            "parameter contains illegal control characters".to_string(),
        ));
    }
    Ok(())
}

/// RFC 7230 `tchar`: the set of bytes allowed in a header field name / token.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// A byte that must never appear in a header value or parameter: any C0
/// control or DEL, except a horizontal tab (`0x09`).
fn is_forbidden_text_byte(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityConfig;
    use crate::errors::ErrorCategory;
    use futures::StreamExt;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn cfg() -> SecurityConfig {
        SecurityConfig::default()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // -- SSRF guard: private / loopback / link-local denied (Req 46.1) -------

    #[test]
    fn denies_private_ipv4_ranges_when_not_allowlisted() {
        for addr in ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1"] {
            let err = guard_resolved_ip(ip(addr), addr, &cfg()).unwrap_err();
            assert_eq!(
                err.category,
                ErrorCategory::Forbidden,
                "{addr} must be denied"
            );
        }
    }

    #[test]
    fn denies_loopback_addresses() {
        for addr in ["127.0.0.1", "127.255.255.254"] {
            let err = guard_resolved_ip(ip(addr), addr, &cfg()).unwrap_err();
            assert_eq!(err.category, ErrorCategory::Forbidden);
        }
        let err = guard_resolved_ip(ip("::1"), "::1", &cfg()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn denies_link_local_addresses() {
        let err = guard_resolved_ip(ip("169.254.0.1"), "169.254.0.1", &cfg()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        let err = guard_resolved_ip(ip("fe80::1"), "fe80::1", &cfg()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn denies_unspecified_and_unique_local_v6() {
        let err = guard_resolved_ip(ip("0.0.0.0"), "0.0.0.0", &cfg()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        let err = guard_resolved_ip(ip("fc00::1"), "fc00::1", &cfg()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn allows_public_addresses_by_default() {
        for addr in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            assert!(
                guard_resolved_ip(ip(addr), addr, &cfg()).is_ok(),
                "{addr} should pass"
            );
        }
        assert!(guard_resolved_ip(ip("2606:4700:4700::1111"), "h", &cfg()).is_ok());
    }

    // -- Allowlist override for private ranges (Req 46.1) -------------------

    #[test]
    fn allowlisted_private_ip_literal_is_permitted() {
        let mut c = cfg();
        c.ssrf_allowlist = vec!["10.0.0.5".to_string()];
        assert!(guard_resolved_ip(ip("10.0.0.5"), "10.0.0.5", &c).is_ok());
    }

    #[test]
    fn allowlisted_private_cidr_is_permitted() {
        let mut c = cfg();
        c.ssrf_allowlist = vec!["10.0.0.0/8".to_string()];
        assert!(guard_resolved_ip(ip("10.1.2.3"), "internal.example", &c).is_ok());
    }

    #[test]
    fn allowlisted_host_string_permits_private_ip() {
        let mut c = cfg();
        c.ssrf_allowlist = vec!["internal.svc.local".to_string()];
        assert!(guard_resolved_ip(ip("192.168.5.5"), "internal.svc.local", &c).is_ok());
    }

    #[test]
    fn allow_private_ranges_flag_permits_private() {
        let mut c = cfg();
        c.allow_private_ranges = true;
        assert!(guard_resolved_ip(ip("10.0.0.1"), "10.0.0.1", &c).is_ok());
        assert!(guard_resolved_ip(ip("127.0.0.1"), "127.0.0.1", &c).is_ok());
    }

    // -- Allowlist = strict allowlist when configured (Req 46.2) ------------

    #[test]
    fn configured_allowlist_denies_unlisted_public_host() {
        let mut c = cfg();
        c.ssrf_allowlist = vec!["1.2.3.4".to_string()];
        let err = guard_resolved_ip(ip("8.8.8.8"), "8.8.8.8", &c).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn configured_allowlist_permits_listed_host() {
        let mut c = cfg();
        c.ssrf_allowlist = vec!["1.2.3.4".to_string(), "good.example".to_string()];
        assert!(guard_resolved_ip(ip("1.2.3.4"), "1.2.3.4", &c).is_ok());
        assert!(guard_resolved_ip(ip("203.0.113.9"), "good.example", &c).is_ok());
    }

    // -- Denylist denies every listed host (Req 46.3) -----------------------

    #[test]
    fn denylist_denies_listed_ip_and_cidr() {
        let mut c = cfg();
        c.ssrf_denylist = vec!["8.8.8.8".to_string(), "203.0.113.0/24".to_string()];
        let err = guard_resolved_ip(ip("8.8.8.8"), "8.8.8.8", &c).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        let err = guard_resolved_ip(ip("203.0.113.55"), "h", &c).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn denylist_denies_by_host_string() {
        let mut c = cfg();
        c.ssrf_denylist = vec!["evil.example".to_string()];
        let err = guard_resolved_ip(ip("8.8.8.8"), "evil.example", &c).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn denylist_takes_precedence_over_allowlist() {
        let mut c = cfg();
        c.ssrf_allowlist = vec!["8.8.8.8".to_string()];
        c.ssrf_denylist = vec!["8.8.8.8".to_string()];
        let err = guard_resolved_ip(ip("8.8.8.8"), "8.8.8.8", &c).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    // -- resolve_and_guard end-to-end ---------------------------------------

    #[test]
    fn resolve_and_guard_accepts_public_ip_literal() {
        let resolved = resolve_and_guard("8.8.8.8", &cfg()).unwrap();
        assert_eq!(resolved, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn resolve_and_guard_denies_loopback_literal() {
        let err = resolve_and_guard("127.0.0.1", &cfg()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn resolve_and_guard_denies_resolved_localhost() {
        // `localhost` resolves to a loopback address via the local resolver.
        let err = resolve_and_guard("localhost", &cfg()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn resolve_and_guard_rejects_unresolvable_host_as_bad_request() {
        let err = resolve_and_guard("no-such-host.invalid", &cfg()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    // -- is_disallowed_range predicate --------------------------------------

    #[test]
    fn disallowed_range_predicate_matches_expected() {
        assert!(is_disallowed_range(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_disallowed_range(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_disallowed_range(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(is_disallowed_range(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_disallowed_range(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        // IPv4-mapped loopback must be unwrapped and denied.
        assert!(is_disallowed_range(ip("::ffff:127.0.0.1")));
    }

    // -- Request body cap (Req 46.4) ----------------------------------------

    #[test]
    fn request_body_within_cap_is_accepted() {
        let c = cfg();
        assert!(check_request_body_size(c.max_request_body_bytes, &c).is_ok());
        assert!(check_request_body_size(0, &c).is_ok());
    }

    #[test]
    fn request_body_over_cap_is_payload_too_large() {
        let mut c = cfg();
        c.max_request_body_bytes = 1024;
        let err = check_request_body_size(1025, &c).unwrap_err();
        assert_eq!(err.category, ErrorCategory::PayloadTooLarge);
        assert_eq!(err.http_status().as_u16(), 413);
    }

    // -- Response body cap (Req 46.5) ---------------------------------------

    #[test]
    fn response_body_at_cap_is_accepted_and_over_is_rejected() {
        let mut c = cfg();
        c.max_response_body_bytes = 2048;
        assert!(check_response_body_size(2048, &c).is_ok());
        let err = check_response_body_size(2049, &c).unwrap_err();
        assert_eq!(err.category, ErrorCategory::PayloadTooLarge);
    }

    #[tokio::test]
    async fn read_to_cap_returns_full_body_under_cap() {
        let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = vec![
            Ok(bytes::Bytes::from_static(b"hello ")),
            Ok(bytes::Bytes::from_static(b"world")),
        ];
        let stream = futures::stream::iter(chunks);
        let body = read_to_cap(stream, 1024).await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn read_to_cap_aborts_over_cap_without_consuming_rest() {
        let polled = Arc::new(AtomicUsize::new(0));
        let p = polled.clone();
        // Five 10-byte chunks (50 bytes) with a cap of 25 -> must abort after
        // the third chunk overflows, never polling the remaining chunks.
        let stream = futures::stream::iter(0..5).map(move |_| {
            p.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"0123456789"))
        });
        let err = read_to_cap(stream, 25).await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::PayloadTooLarge);
        assert!(
            polled.load(Ordering::SeqCst) < 5,
            "must abort before consuming all chunks"
        );
    }

    #[tokio::test]
    async fn read_to_cap_surfaces_upstream_stream_error() {
        let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = vec![
            Ok(bytes::Bytes::from_static(b"abc")),
            Err(std::io::Error::new(std::io::ErrorKind::Other, "reset")),
        ];
        let stream = futures::stream::iter(chunks);
        let err = read_to_cap(stream, 1024).await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    // -- URL / header / param validation (Req 46.6) -------------------------

    #[test]
    fn validate_url_accepts_http_and_https_with_host() {
        let u = validate_url("https://example.com/path?q=1").unwrap();
        assert_eq!(u.host_str(), Some("example.com"));
        assert!(validate_url("http://example.com:8080/").is_ok());
    }

    #[test]
    fn validate_url_rejects_malformed_and_non_http_schemes() {
        for bad in [
            "not a url",
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ] {
            let err = validate_url(bad).unwrap_err();
            assert_eq!(
                err.category,
                ErrorCategory::BadRequest,
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn validate_url_rejects_missing_host() {
        // A special-scheme URL with an empty authority is host-less and must
        // be rejected (the WHATWG parser surfaces this as an empty-host error).
        let err = validate_url("https://").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
        let err = validate_url("http://").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    #[test]
    fn validate_header_name_rejects_empty_and_illegal_chars() {
        assert!(validate_header_name("X-Custom-Header").is_ok());
        assert!(validate_header_name("").is_err());
        assert!(validate_header_name("bad header").is_err());
        assert!(validate_header_name("inject\r\nEvil").is_err());
    }

    #[test]
    fn validate_header_value_rejects_crlf_injection() {
        assert!(validate_header_value("normal value").is_ok());
        let err = validate_header_value("value\r\nInjected: 1").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
        assert!(validate_header_value("nul\0byte").is_err());
    }

    #[test]
    fn validate_param_rejects_control_chars() {
        assert!(validate_param("normal-param_123").is_ok());
        assert!(validate_param("with\r\nnewline").is_err());
        assert!(validate_param("with\ttab-is-ok").is_ok());
    }
}
