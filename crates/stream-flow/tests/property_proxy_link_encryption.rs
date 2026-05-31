//! Property-based test for the dual-format proxy-link codec
//! (`proxylink::ProxyCodec`, task 20.4).
//!
//! Feature: stream-flow, Property 8
//!
//! **Property 8: Proxy-link encryption round trip for both token formats, with
//! expiry/IP rejection**
//!
//! *For any* `ProxyPayload`, encrypting it as a mediaflow-style AES-CBC `d`
//! parameter and decrypting it recovers exactly the payload, and encoding it as
//! a stremthru-style token and decoding it recovers exactly the payload. *For
//! any* payload whose embedded expiration is in the past, access returns `403`;
//! and *for any* payload bound to an IP that differs from the requester's
//! `Client_IP`, access returns `403`.
//!
//! **Validates: Requirements 14.1, 14.4, 14.5, 14.6, 14.7, 36.7, 48.3**
//!
//! * Req 14.1 — the mediaflow `d` form is AES-CBC encrypted, keyed from the
//!   `API_Password`.
//! * Req 14.4 — decoding is fail-closed (exercised by the round trip never
//!   yielding a partial/incorrect payload, and by the negative cases below
//!   rejecting with a typed `403`).
//! * Req 14.5 — a past embedded `exp` rejects with `403 Forbidden` on resolve.
//! * Req 14.6 — an `ip` binding that differs from the requester's `Client_IP`
//!   rejects with `403 Forbidden` flagged `ip_restricted`.
//! * Req 14.7 — encode → decode recovers the payload exactly, for **both**
//!   on-the-wire formats.
//! * Req 36.7 — each format is decoded with its own key material (a single
//!   [`ProxyCodec`] holds both and routes correctly).
//! * Req 48.3 — the encode/decode round trip is verified as a property over
//!   arbitrary inputs (>= 100 cases).
//!
//! ## How the property is exercised
//!
//! Each case generates an arbitrary [`ProxyPayload`] — an arbitrary `url`,
//! arbitrary injected `headers`, an optional `filename`, an optional `exp`, and
//! an optional bound `ip` (IPv4 or IPv6). A single [`ProxyCodec`] built from a
//! fixed `API_Password` + stremthru secret encodes/decodes both formats, so the
//! three clauses of Property 8 are checked over the same input space:
//!
//! 1. **Round trip (Req 14.7 / 36.7):** `decode(encode_mediaflow(p)) == p` and
//!    `decode(encode_token(p)) == p`, and a non-expired, IP-matching link also
//!    `resolve`s back to `p` through both formats (the full access path).
//! 2. **Expiry rejection (Req 14.5):** a payload with `exp` strictly in the
//!    past is rejected with `403 Forbidden` on `resolve`, in both formats.
//! 3. **IP rejection (Req 14.6):** a payload bound to an IP different from the
//!    requester's `Client_IP` is rejected with `403 Forbidden` + `ip_restricted`,
//!    in both formats.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use stream_flow::auth::encryption::ProxyPayload;
use stream_flow::errors::ErrorCategory;
use stream_flow::proxylink::{ProxyCodec, ProxyLink};

/// Fixed key material — the property holds for any single codec instance that
/// holds both formats' keys (Req 36.7).
const API_PASSWORD: &str = "mediaflow-api-password";
const STREMTHRU_SECRET: &str = "stremthru-proxy-secret";

fn codec() -> ProxyCodec {
    ProxyCodec::from_secrets(API_PASSWORD, STREMTHRU_SECRET)
}

/// Arbitrary unicode string (including empty) — stresses the JSON serialization
/// that underlies both the AES-CBC ciphertext input and the signed token body.
fn arb_string() -> impl Strategy<Value = String> {
    any::<String>()
}

/// Arbitrary injected upstream headers (0..=8 entries).
fn arb_headers() -> impl Strategy<Value = BTreeMap<String, String>> {
    proptest::collection::btree_map(arb_string(), arb_string(), 0..=8)
}

/// Arbitrary IP binding (mix of IPv4 and IPv6) so both address families
/// round-trip and enforce.
fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|o| IpAddr::V4(Ipv4Addr::from(o))),
        any::<[u8; 16]>().prop_map(|o| IpAddr::V6(Ipv6Addr::from(o))),
    ]
}

/// Arbitrary unix-second expiry, kept in a realistic, non-overflowing range so
/// the positive-resolve control can pick `now = exp - 1` safely.
fn arb_opt_exp() -> impl Strategy<Value = Option<i64>> {
    prop_oneof![Just(None), (0i64..=4_000_000_000).prop_map(Some)]
}

/// Arbitrary optional IP binding.
fn arb_opt_ip() -> impl Strategy<Value = Option<IpAddr>> {
    prop_oneof![Just(None), arb_ip().prop_map(Some)]
}

/// A fully arbitrary [`ProxyPayload`] (arbitrary url/headers/filename, optional
/// exp, optional ip).
fn arb_payload() -> impl Strategy<Value = ProxyPayload> {
    (
        arb_string(),
        arb_headers(),
        proptest::option::of(arb_string()),
        arb_opt_exp(),
        arb_opt_ip(),
    )
        .prop_map(|(url, headers, filename, exp, ip)| ProxyPayload {
            url,
            headers,
            filename,
            exp,
            ip,
        })
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 8 — encode → decode recovers the payload
    /// exactly through BOTH the mediaflow AES-CBC `d` form and the stremthru
    /// signed `token` form, and a valid (non-expired, IP-matching) link
    /// resolves back to exactly the payload. **Validates: Requirements 14.1,
    /// 14.7, 36.7, 48.3**
    #[test]
    fn round_trip_recovers_payload_for_both_formats(payload in arb_payload()) {
        let codec = codec();

        // -- mediaflow AES-CBC `d` form (Req 14.1, 14.7) --------------------
        let d_link = codec.encode_mediaflow(&payload).unwrap();
        prop_assert!(
            matches!(d_link, ProxyLink::EncryptedMediaflow { .. }),
            "encode_mediaflow must produce the `d` form",
        );
        let from_d = codec.decode(&d_link).unwrap();
        prop_assert_eq!(from_d, payload.clone(), "mediaflow `d` round trip");

        // -- stremthru signed `token` form (Req 14.7, 36.7) ----------------
        let token_link = codec.encode_token(&payload).unwrap();
        prop_assert!(
            matches!(token_link, ProxyLink::Token { .. }),
            "encode_token must produce the `token` form",
        );
        let from_token = codec.decode(&token_link).unwrap();
        prop_assert_eq!(from_token, payload.clone(), "stremthru `token` round trip");

        // -- Positive control: the full access path (`resolve`) on a
        //    non-expired, IP-matching link recovers exactly the payload
        //    through both formats (Req 14.7). `now < exp` keeps it unexpired;
        //    presenting the bound IP (or `None` when unbound) satisfies 14.6.
        let now = match payload.exp {
            Some(exp) => exp - 1,
            None => 0,
        };
        let client_ip = payload.ip;
        prop_assert_eq!(
            codec.resolve(&d_link, client_ip, now).unwrap(),
            payload.clone(),
            "valid mediaflow link must resolve back to the payload",
        );
        prop_assert_eq!(
            codec.resolve(&token_link, client_ip, now).unwrap(),
            payload.clone(),
            "valid stremthru link must resolve back to the payload",
        );
    }

    /// Feature: stream-flow, Property 8 — a payload whose embedded `exp` is in
    /// the past is rejected with `403 Forbidden` on resolve, in both formats.
    /// **Validates: Requirements 14.5, 14.4**
    #[test]
    fn expired_payload_is_forbidden_for_both_formats(
        mut payload in arb_payload(),
        exp in 0i64..=4_000_000_000,
        delta in 1i64..=1_000_000,
    ) {
        let codec = codec();
        // Isolate expiry as the sole rejection cause: a past `exp` and no IP
        // binding. `now = exp + delta` is strictly after `exp` (in the past).
        payload.exp = Some(exp);
        payload.ip = None;
        let now = exp + delta;

        let links = [
            codec.encode_mediaflow(&payload).unwrap(),
            codec.encode_token(&payload).unwrap(),
        ];
        for link in &links {
            let err = codec
                .resolve(link, None, now)
                .expect_err("an expired link must be rejected");
            prop_assert_eq!(
                err.category,
                ErrorCategory::Forbidden,
                "expired link must map to 403 Forbidden",
            );
        }
    }

    /// Feature: stream-flow, Property 8 — a payload bound to an IP that differs
    /// from the requester's `Client_IP` is rejected with `403 Forbidden`
    /// flagged `ip_restricted`, in both formats.
    /// **Validates: Requirements 14.6, 14.4**
    #[test]
    fn ip_bound_mismatch_is_forbidden_and_ip_restricted_for_both_formats(
        mut payload in arb_payload(),
        bound in arb_ip(),
        requester in arb_ip(),
        now in 0i64..=4_000_000_000,
    ) {
        // Only mismatching pairs exercise the rejection path.
        prop_assume!(bound != requester);

        let codec = codec();
        // Isolate the IP binding as the sole rejection cause: bound IP, no
        // expiry (so `now` is irrelevant to expiry).
        payload.ip = Some(bound);
        payload.exp = None;

        let links = [
            codec.encode_mediaflow(&payload).unwrap(),
            codec.encode_token(&payload).unwrap(),
        ];
        for link in &links {
            let err = codec
                .resolve(link, Some(requester), now)
                .expect_err("an IP-bound link must reject a mismatched requester");
            prop_assert_eq!(
                err.category,
                ErrorCategory::Forbidden,
                "IP mismatch must map to 403 Forbidden",
            );
            prop_assert!(
                err.ip_restricted,
                "an IP-cause 403 must be flagged ip_restricted",
            );
        }
    }
}
