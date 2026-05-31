//! Property-based test for the SSRF guard predicate
//! (`security::guard_resolved_ip` / `security::is_disallowed_range`, task 12.4).
//!
//! Feature: stream-flow, Property 44
//!
//! **Property 44: SSRF guard predicate**
//!
//! *For any* resolved IP address and configured allow/deny lists, a request is
//! denied when the IP is private, loopback, or link-local and not allowlisted;
//! an explicit allowlist permits only listed hosts; and a denylist denies every
//! listed host.
//!
//! **Validates: Requirements 46.1, 46.2, 46.3**
//!
//! Requirement 46.1: "WHEN a forward or proxy target host is resolved, THE
//! Stream_Flow_System SHALL deny requests to private, loopback, and link-local
//! IP ranges unless the host is explicitly allowlisted."
//!
//! Requirement 46.2: "WHERE a forward allowlist is configured, THE
//! Stream_Flow_System SHALL permit only hosts on the allowlist and deny all
//! others."
//!
//! Requirement 46.3: "WHERE a forward denylist is configured, THE
//! Stream_Flow_System SHALL deny every host on the denylist."
//!
//! ## How the invariant is exercised
//!
//! Each case generates an arbitrary (normalized) IPv4 or IPv6 address — biased
//! toward the private / loopback / link-local / unique-local ranges so the
//! Req 46.1 branch is hit frequently — together with an arbitrary host string
//! and arbitrary allow / deny lists. Each list entry is drawn from a mix of
//! shapes that *match* the target (the exact IP literal, a covering CIDR, the
//! host string, the host string upper-cased) and shapes that usually *do not*
//! (random IP literals, random / malformed CIDRs, empty / whitespace strings,
//! random host names), so both the "listed" and "not-listed" sides of every
//! precedence branch are covered.
//!
//! The case then asserts the production decision from
//! [`guard_resolved_ip`] equals an **independent oracle** that re-implements
//! the precedence rules (denylist wins → strict allowlist when configured →
//! private-range default-deny). A denied target must surface a `Forbidden`
//! [`AppError`]; an allowed target must return the (normalized) IP unchanged.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use stream_flow::config::SecurityConfig;
use stream_flow::errors::ErrorCategory;
use stream_flow::security::{guard_resolved_ip, is_disallowed_range};

// ---------------------------------------------------------------------------
// Independent oracle (a separate re-implementation of the precedence rules)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny,
}

/// Collapse an IPv4-mapped IPv6 address to its IPv4 form (matches the guard's
/// own normalization), passing everything else through unchanged.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Oracle for the disallowed-range predicate (Req 46.1): private, loopback,
/// link-local, unspecified, broadcast (v4) / loopback, unspecified,
/// unique-local, link-local (v6). Implemented from explicit numeric ranges,
/// independently of the production bit math.
fn oracle_is_disallowed(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let private = o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168);
            let loopback = o[0] == 127;
            let link_local = o[0] == 169 && o[1] == 254;
            let unspecified = o == [0, 0, 0, 0];
            let broadcast = o == [255, 255, 255, 255];
            private || loopback || link_local || unspecified || broadcast
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let loopback = v6 == Ipv6Addr::LOCALHOST;
            let unspecified = v6 == Ipv6Addr::UNSPECIFIED;
            let unique_local = (o[0] & 0xfe) == 0xfc; // fc00::/7
            let link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80; // fe80::/10
            loopback || unspecified || unique_local || link_local
        }
    }
}

/// Oracle for CIDR containment, mirroring the guard's family-strict semantics:
/// a malformed entry or address-family mismatch never matches.
fn oracle_cidr_contains(entry: &str, ip: IpAddr) -> bool {
    let (base_str, prefix_str) = match entry.split_once('/') {
        Some(parts) => parts,
        None => return false,
    };
    let prefix: u32 = match prefix_str.trim().parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let base: IpAddr = match base_str.trim().parse() {
        Ok(b) => normalize_ip(b),
        Err(_) => return false,
    };
    match (base, ip) {
        (IpAddr::V4(b), IpAddr::V4(i)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(b) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(b), IpAddr::V6(i)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(b) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

/// Oracle for "does `ip`/`host` match any entry in `entries`": CIDR, then exact
/// IP literal, then case-insensitive host string (Req 46.2, 46.3).
fn oracle_list_matches(entries: &[String], ip: IpAddr, host: &str) -> bool {
    entries.iter().any(|raw| {
        let entry = raw.trim();
        if entry.is_empty() {
            return false;
        }
        if entry.contains('/') {
            return oracle_cidr_contains(entry, ip);
        }
        if let Ok(entry_ip) = entry.parse::<IpAddr>() {
            return normalize_ip(entry_ip) == ip;
        }
        entry.eq_ignore_ascii_case(host)
    })
}

/// The independent oracle for the full guard decision (Req 46.1–3): denylist
/// match always denies; a configured (non-empty) allowlist is strict
/// allow-only; otherwise a disallowed-range address is denied unless
/// `allow_private_ranges` is set.
fn oracle_decision(ip: IpAddr, host: &str, cfg: &SecurityConfig) -> Decision {
    if oracle_list_matches(&cfg.ssrf_denylist, ip, host) {
        return Decision::Deny;
    }
    if !cfg.ssrf_allowlist.is_empty() {
        if oracle_list_matches(&cfg.ssrf_allowlist, ip, host) {
            return Decision::Allow;
        }
        return Decision::Deny;
    }
    if oracle_is_disallowed(ip) && !cfg.allow_private_ranges {
        return Decision::Deny;
    }
    Decision::Allow
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

fn arb_v4() -> impl Strategy<Value = Ipv4Addr> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
        .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
}

fn arb_v6() -> impl Strategy<Value = Ipv6Addr> {
    any::<u128>().prop_map(Ipv6Addr::from)
}

/// IPv4 addresses biased toward the disallowed ranges so the Req 46.1 branch is
/// exercised often.
fn arb_special_v4() -> impl Strategy<Value = Ipv4Addr> {
    prop_oneof![
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(10, b, c, d)),
        (16u8..=31, any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(172, b, c, d)),
        (any::<u8>(), any::<u8>()).prop_map(|(c, d)| Ipv4Addr::new(192, 168, c, d)),
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(127, b, c, d)),
        (any::<u8>(), any::<u8>()).prop_map(|(c, d)| Ipv4Addr::new(169, 254, c, d)),
        Just(Ipv4Addr::new(0, 0, 0, 0)),
        Just(Ipv4Addr::new(255, 255, 255, 255)),
    ]
}

/// IPv6 addresses biased toward the disallowed ranges.
fn arb_special_v6() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        Just(Ipv6Addr::LOCALHOST),
        Just(Ipv6Addr::UNSPECIFIED),
        // fc00::/7 unique-local.
        any::<u128>().prop_map(|x| {
            let mut o = x.to_be_bytes();
            o[0] = 0xfc;
            Ipv6Addr::from(o)
        }),
        // fe80::/10 link-local (top ten bits = 1111111010).
        any::<u128>().prop_map(|x| {
            let mut o = x.to_be_bytes();
            o[0] = 0xfe;
            o[1] = (o[1] & 0x3f) | 0x80;
            Ipv6Addr::from(o)
        }),
    ]
}

/// Arbitrary already-normalized target IP — a mix of fully-random and
/// range-biased v4/v6 addresses.
fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        arb_v4().prop_map(IpAddr::V4),
        arb_v6().prop_map(IpAddr::V6),
        arb_special_v4().prop_map(IpAddr::V4),
        arb_special_v6().prop_map(IpAddr::V6),
    ]
    .prop_map(normalize_ip)
}

/// Arbitrary target host string (lowercase domain-like).
fn arb_host() -> impl Strategy<Value = String> {
    "[a-z]{3,10}\\.(com|net|local)".prop_map(|s| s)
}

/// A CIDR whose block is guaranteed to *contain* `ip` (network = ip masked to
/// the chosen prefix), so the covering-CIDR match path is exercised.
fn covering_cidr_v4(ip: Ipv4Addr, prefix: u32) -> String {
    let bits = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let net = Ipv4Addr::from(bits & mask);
    format!("{net}/{prefix}")
}

fn covering_cidr_v6(ip: Ipv6Addr, prefix: u32) -> String {
    let bits = u128::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let net = Ipv6Addr::from(bits & mask);
    format!("{net}/{prefix}")
}

/// Arbitrary (usually non-matching) random CIDR string.
fn arb_random_cidr() -> impl Strategy<Value = String> {
    prop_oneof![
        (arb_v4(), 0u32..=32).prop_map(|(ip, p)| format!("{ip}/{p}")),
        (arb_v6(), 0u32..=128).prop_map(|(ip, p)| format!("{ip}/{p}")),
    ]
}

/// One allow/deny list entry, mixing shapes that match the target with shapes
/// that usually do not (so every precedence branch sees both sides).
fn arb_list_entry(ip: IpAddr, host: String) -> BoxedStrategy<String> {
    let ip_str = ip.to_string();
    let covering = match ip {
        IpAddr::V4(v4) => (0u32..=32)
            .prop_map(move |p| covering_cidr_v4(v4, p))
            .boxed(),
        IpAddr::V6(v6) => (0u32..=128)
            .prop_map(move |p| covering_cidr_v6(v6, p))
            .boxed(),
    };
    let host_upper = host.to_uppercase();
    prop_oneof![
        // -- shapes that MATCH the target -----------------------------------
        Just(ip_str),       // exact IP literal
        covering,           // covering CIDR
        Just(host.clone()), // host string
        Just(host_upper),   // host string, upper-cased
        // -- shapes that usually DO NOT match -------------------------------
        arb_v4().prop_map(|i| i.to_string()), // random v4 literal
        arb_v6().prop_map(|i| i.to_string()), // random v6 literal
        arb_random_cidr(),                    // random CIDR
        Just(String::new()),                  // empty entry
        Just("   ".to_string()),              // whitespace entry
        Just("not-a-cidr/99".to_string()),    // malformed CIDR base
        Just("10.0.0.0/999".to_string()),     // out-of-range prefix
        Just("::/0".to_string()),             // family-dependent catch-all
        Just("0.0.0.0/0".to_string()),        // v4 catch-all
        "[a-z]{3,10}\\.(org|io|svc)".prop_map(|s| s), // random host name
    ]
    .boxed()
}

#[derive(Debug, Clone)]
struct Case {
    ip: IpAddr,
    host: String,
    allow: Vec<String>,
    deny: Vec<String>,
    allow_private: bool,
}

fn arb_case() -> impl Strategy<Value = Case> {
    (arb_ip(), arb_host())
        .prop_flat_map(|(ip, host)| {
            let allow = proptest::collection::vec(arb_list_entry(ip, host.clone()), 0..=6);
            let deny = proptest::collection::vec(arb_list_entry(ip, host.clone()), 0..=6);
            (Just(ip), Just(host), allow, deny, any::<bool>())
        })
        .prop_map(|(ip, host, allow, deny, allow_private)| Case {
            ip,
            host,
            allow,
            deny,
            allow_private,
        })
}

// ---------------------------------------------------------------------------
// The property
// ---------------------------------------------------------------------------

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 44 — SSRF guard predicate.
    /// **Validates: Requirements 46.1, 46.2, 46.3**
    #[test]
    fn ssrf_guard_predicate_matches_oracle(case in arb_case()) {
        let cfg = SecurityConfig {
            ssrf_allowlist: case.allow.clone(),
            ssrf_denylist: case.deny.clone(),
            allow_private_ranges: case.allow_private,
            ..SecurityConfig::default()
        };

        let expected = oracle_decision(case.ip, &case.host, &cfg);
        let actual = guard_resolved_ip(case.ip, &case.host, &cfg);

        match expected {
            Decision::Allow => {
                prop_assert!(
                    actual.is_ok(),
                    "expected Allow but guard denied: ip={} host={:?} allow={:?} deny={:?} allow_private={}",
                    case.ip, case.host, case.allow, case.deny, case.allow_private,
                );
                // An allowed target returns the (normalized) IP unchanged.
                prop_assert_eq!(actual.unwrap(), case.ip);
            }
            Decision::Deny => {
                prop_assert!(
                    actual.is_err(),
                    "expected Deny but guard allowed: ip={} host={:?} allow={:?} deny={:?} allow_private={}",
                    case.ip, case.host, case.allow, case.deny, case.allow_private,
                );
                // Every denial is a typed Forbidden error (Req 46.1–3 + Req 47).
                let category = actual.unwrap_err().category;
                prop_assert_eq!(
                    category, ErrorCategory::Forbidden,
                    "a denial must be Forbidden, got {:?} for ip={} host={:?}",
                    category, case.ip, case.host,
                );
            }
        }

        // Supporting check for the Req 46.1 private-range branch: with no list
        // configured, the decision is driven purely by the disallowed-range
        // predicate, which must agree with the independent oracle.
        if case.allow.is_empty() && case.deny.is_empty() {
            prop_assert_eq!(
                is_disallowed_range(case.ip), oracle_is_disallowed(case.ip),
                "is_disallowed_range disagrees with the oracle for ip={}",
                case.ip,
            );
        }
    }
}
