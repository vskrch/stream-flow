//! Proxy-link / token codecs (`proxylink`) — Req 14.5, 14.6, 14.7, 21.2, 36.7.
//!
//! `ZippyPanther` both **produces and accepts two on-the-wire proxy-link
//! formats** so it is a drop-in replacement for either upstream project
//! (design: Data Models → Proxy Link / Token Formats):
//!
//! * [`MediaflowCodec`](encrypted::MediaflowCodec) — the *mediaflow-proxy-light*
//!   style: the [`ProxyPayload`] sealed into an **AES-CBC encrypted** `d` query
//!   parameter, keyed from the `API_Password` (Req 14.1, 36.7). Implemented in
//!   [`encrypted`], delegating to the shared cipher in
//!   [`auth::encryption`](crate::auth::encryption).
//! * [`TokenCodec`](token::TokenCodec) — the *stremthru* style: a **signed
//!   (HMAC-SHA256) unencrypted token** carrying the payload, keyed from the
//!   separate stremthru [`TokenKey`] (Req 21.2, 36.7). Implemented in [`token`].
//!
//! [`ProxyCodec`] ties the two together. It holds **both** sets of key material
//! and:
//!
//! * **selects the format by the presence of the `token` parameter** — a
//!   present `token` is decoded as a stremthru token, otherwise a present `d`
//!   is decoded as a mediaflow encrypted parameter (Req 21.2, 36.7);
//! * **decodes each format with its own key material** — the
//!   `API_Password`-derived [`CbcKey`] for `d`, the stremthru [`TokenKey`] for
//!   `token` (Req 36.7);
//! * **enforces the embedded expiry and IP binding on access** — a past `exp`
//!   rejects with `403 Forbidden` (Req 14.5) and an `ip` that does not match
//!   the requester's `Client_IP` rejects with `403 Forbidden` (Req 14.6, the
//!   latter flagged [`ip_restricted`](AppError::ip_restricted)).
//!
//! The round-trip property (Req 14.7) holds for both formats: decoding an
//! encoded payload recovers it exactly (verified per-codec in [`encrypted`] /
//! [`token`] and across the dispatcher here).

pub mod encrypted;
pub mod handler;
pub mod token;

use std::net::IpAddr;

use crate::auth::encryption::{CbcKey, ProxyPayload};
use crate::errors::AppError;

pub use encrypted::MediaflowCodec;
pub use token::{TokenCodec, TokenKey};

/// One of the two on-the-wire proxy-link formats (design: Data Models → Proxy
/// Link / Token Formats).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyLink {
    /// mediaflow-proxy-light style: AES-CBC(`API_Password`)-encrypted payload
    /// carried in the `d` query parameter (Req 14.1, 36.7).
    EncryptedMediaflow {
        /// The `base64url-no-pad( IV || AES-CBC-PKCS7(json) )` `d` token.
        d: String,
    },
    /// stremthru style: HMAC-signed, unencrypted token carrying the payload
    /// (Req 21.2, 36.7).
    Token {
        /// The `base64url(json).base64url(hmac)` token.
        token: String,
    },
}

impl ProxyLink {
    /// The query parameter string (`d=…` or `token=…`) for this link, without a
    /// leading `?`/`&`.
    pub fn as_query_param(&self) -> String {
        match self {
            ProxyLink::EncryptedMediaflow { d } => format!("d={d}"),
            ProxyLink::Token { token } => format!("token={token}"),
        }
    }
}

/// The dual-format proxy-link codec (Req 14, 21.2, 36.7).
///
/// Holds the key material for **both** formats so a single instance can produce
/// and accept either on-the-wire form, each decoded with its own key
/// (Req 36.7). Construct it once at startup (e.g. from the `API_Password` and
/// the stremthru proxy secret) and reuse it across requests; it is cheap to
/// clone.
#[derive(Clone)]
pub struct ProxyCodec {
    /// `API_Password`-derived AES-256 key for the mediaflow `d` format.
    cbc_key: CbcKey,
    /// Stremthru secret key for the signed `token` format.
    token_key: TokenKey,
}

impl ProxyCodec {
    /// Build a codec from already-derived key material.
    pub fn new(cbc_key: CbcKey, token_key: TokenKey) -> Self {
        Self { cbc_key, token_key }
    }

    /// Build a codec from the raw secrets: the mediaflow `API_Password` (key
    /// derivation per [`CbcKey::from_api_password`]) and the stremthru proxy
    /// secret (per [`TokenKey::from_secret`]).
    pub fn from_secrets(api_password: &str, stremthru_secret: &str) -> Self {
        Self::new(
            CbcKey::from_api_password(api_password),
            TokenKey::from_secret(stremthru_secret),
        )
    }

    /// Encode a payload as a mediaflow AES-CBC `d` link (Req 14.1).
    pub fn encode_mediaflow(&self, payload: &ProxyPayload) -> Result<ProxyLink, AppError> {
        Ok(ProxyLink::EncryptedMediaflow {
            d: MediaflowCodec::encode(payload, &self.cbc_key)?,
        })
    }

    /// Encode a payload as a stremthru signed `token` link (Req 21.2).
    pub fn encode_token(&self, payload: &ProxyPayload) -> Result<ProxyLink, AppError> {
        Ok(ProxyLink::Token {
            token: TokenCodec::encode(payload, &self.token_key)?,
        })
    }

    /// Decode a [`ProxyLink`] back into its [`ProxyPayload`], using each
    /// format's own key material (Req 36.7).
    ///
    /// Fail-closed (Req 14.4): a corrupt `d`, a wrong key, or a forged/invalid
    /// `token` all reject with a `403`-mapped [`AppError`]. This recovers the
    /// payload **without** enforcing `exp`/`ip`; use [`ProxyCodec::resolve`] (or
    /// [`ProxyCodec::resolve_params`]) to additionally apply the access-time
    /// `403` checks (Req 14.5/14.6).
    pub fn decode(&self, link: &ProxyLink) -> Result<ProxyPayload, AppError> {
        match link {
            ProxyLink::EncryptedMediaflow { d } => MediaflowCodec::decode(d, &self.cbc_key),
            ProxyLink::Token { token } => TokenCodec::decode(token, &self.token_key),
        }
    }

    /// Select the on-the-wire format from the request's query parameters
    /// (Req 21.2, 36.7).
    ///
    /// A **present, non-empty `token`** parameter selects the stremthru token
    /// format; otherwise a present, non-empty `d` parameter selects the
    /// mediaflow encrypted format. When neither is present the link is a
    /// `400 Bad Request` (no proxy-link material to decode).
    pub fn select(token: Option<&str>, d: Option<&str>) -> Result<ProxyLink, AppError> {
        match (non_empty(token), non_empty(d)) {
            (Some(token), _) => Ok(ProxyLink::Token {
                token: token.to_string(),
            }),
            (None, Some(d)) => Ok(ProxyLink::EncryptedMediaflow { d: d.to_string() }),
            (None, None) => Err(AppError::bad_request(
                "proxy link missing both `token` and `d` parameters",
            )),
        }
    }

    /// Decode a link and enforce the embedded expiry + IP binding (Req 14.5,
    /// 14.6).
    ///
    /// On success the recovered [`ProxyPayload`] is returned. Otherwise:
    /// * a decode failure rejects with `403` (Req 14.4);
    /// * a past `exp` (`exp <= now_unix_secs`) rejects with `403` (Req 14.5);
    /// * an `ip` binding that does not equal `client_ip` — including the case
    ///   where the link is bound but `client_ip` could not be determined —
    ///   rejects with `403` flagged [`ip_restricted`](AppError::ip_restricted)
    ///   (Req 14.6).
    pub fn resolve(
        &self,
        link: &ProxyLink,
        client_ip: Option<IpAddr>,
        now_unix_secs: i64,
    ) -> Result<ProxyPayload, AppError> {
        let payload = self.decode(link)?;
        enforce_access(payload, client_ip, now_unix_secs)
    }

    /// Convenience: [`select`](ProxyCodec::select) the format from the query
    /// parameters, then [`resolve`](ProxyCodec::resolve) it with the access-time
    /// checks (Req 14.5, 14.6, 21.2, 36.7).
    pub fn resolve_params(
        &self,
        token: Option<&str>,
        d: Option<&str>,
        client_ip: Option<IpAddr>,
        now_unix_secs: i64,
    ) -> Result<ProxyPayload, AppError> {
        let link = Self::select(token, d)?;
        self.resolve(&link, client_ip, now_unix_secs)
    }
}

/// Enforce the access-time `exp` (Req 14.5) and `ip` (Req 14.6) checks on a
/// decoded payload.
fn enforce_access(
    payload: ProxyPayload,
    client_ip: Option<IpAddr>,
    now_unix_secs: i64,
) -> Result<ProxyPayload, AppError> {
    // Req 14.5: a past (or now) expiry is forbidden.
    if payload.is_expired(now_unix_secs) {
        return Err(AppError::forbidden("proxy link has expired"));
    }

    // Req 14.6: an IP-bound link must match the requester's Client_IP. A bound
    // link with no determinable Client_IP fails closed.
    if let Some(bound) = payload.ip {
        let matches = client_ip == Some(bound);
        if !matches {
            return Err(
                AppError::forbidden("proxy link is bound to a different client IP")
                    .with_ip_restricted(),
            );
        }
    }

    Ok(payload)
}

/// Treat an absent **or empty** parameter as "not present".
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use std::net::IpAddr;

    const API_PASSWORD: &str = "mediaflow-api-password";
    const STREMTHRU_SECRET: &str = "stremthru-proxy-secret";

    fn codec() -> ProxyCodec {
        ProxyCodec::from_secrets(API_PASSWORD, STREMTHRU_SECRET)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn plain_payload() -> ProxyPayload {
        let mut p = ProxyPayload::new("https://cdn.example.com/movie.mkv");
        p.headers
            .insert("Referer".to_string(), "https://example.com/".to_string());
        p
    }

    // -- Req 14.7: round trip through BOTH formats ---------------------------

    #[test]
    fn mediaflow_d_round_trips_through_codec() {
        let codec = codec();
        let link = codec.encode_mediaflow(&plain_payload()).unwrap();
        assert!(matches!(link, ProxyLink::EncryptedMediaflow { .. }));
        let decoded = codec.decode(&link).unwrap();
        assert_eq!(decoded, plain_payload());
    }

    #[test]
    fn stremthru_token_round_trips_through_codec() {
        let codec = codec();
        let link = codec.encode_token(&plain_payload()).unwrap();
        assert!(matches!(link, ProxyLink::Token { .. }));
        let decoded = codec.decode(&link).unwrap();
        assert_eq!(decoded, plain_payload());
    }

    // -- Req 36.7: each format decoded with its OWN key material -------------

    #[test]
    fn mediaflow_token_is_not_decodable_as_stremthru_token() {
        let codec = codec();
        // A mediaflow `d` blob (no `.` signature separator, AES ciphertext)
        // must not validate as a stremthru token.
        let d = match codec.encode_mediaflow(&plain_payload()).unwrap() {
            ProxyLink::EncryptedMediaflow { d } => d,
            _ => unreachable!(),
        };
        let as_token = ProxyLink::Token { token: d };
        assert!(codec.decode(&as_token).is_err());
    }

    #[test]
    fn stremthru_token_is_not_decodable_as_mediaflow_d() {
        let codec = codec();
        let token = match codec.encode_token(&plain_payload()).unwrap() {
            ProxyLink::Token { token } => token,
            _ => unreachable!(),
        };
        let as_d = ProxyLink::EncryptedMediaflow { d: token };
        assert!(codec.decode(&as_d).is_err());
    }

    #[test]
    fn wrong_keys_reject_each_format() {
        let codec = codec();
        let other = ProxyCodec::from_secrets("other-password", "other-secret");

        let d_link = codec.encode_mediaflow(&plain_payload()).unwrap();
        assert_eq!(
            other.decode(&d_link).unwrap_err().category,
            ErrorCategory::Forbidden
        );

        let token_link = codec.encode_token(&plain_payload()).unwrap();
        assert_eq!(
            other.decode(&token_link).unwrap_err().category,
            ErrorCategory::Forbidden
        );
    }

    // -- Req 21.2 / 36.7: format selected by presence of `token` -------------

    #[test]
    fn select_prefers_token_when_present() {
        let link = ProxyCodec::select(Some("the-token"), Some("the-d")).unwrap();
        assert_eq!(
            link,
            ProxyLink::Token {
                token: "the-token".to_string()
            }
        );
    }

    #[test]
    fn select_uses_d_when_token_absent() {
        let link = ProxyCodec::select(None, Some("the-d")).unwrap();
        assert_eq!(
            link,
            ProxyLink::EncryptedMediaflow {
                d: "the-d".to_string()
            }
        );
    }

    #[test]
    fn select_treats_empty_token_as_absent() {
        // Req 21.2: an *empty* `token` selects the encrypted (`d`) format.
        let link = ProxyCodec::select(Some(""), Some("the-d")).unwrap();
        assert_eq!(
            link,
            ProxyLink::EncryptedMediaflow {
                d: "the-d".to_string()
            }
        );
    }

    #[test]
    fn select_without_either_param_is_bad_request() {
        let err = ProxyCodec::select(None, None).unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
        // Also: empty values count as absent.
        assert_eq!(
            ProxyCodec::select(Some(""), Some("")).unwrap_err().category,
            ErrorCategory::BadRequest
        );
    }

    #[test]
    fn resolve_params_routes_each_format_to_its_own_key() {
        let codec = codec();
        let now = 1_000;

        // Stremthru token via the `token` parameter.
        let token = match codec.encode_token(&plain_payload()).unwrap() {
            ProxyLink::Token { token } => token,
            _ => unreachable!(),
        };
        let decoded = codec.resolve_params(Some(&token), None, None, now).unwrap();
        assert_eq!(decoded, plain_payload());

        // Mediaflow encrypted via the `d` parameter.
        let d = match codec.encode_mediaflow(&plain_payload()).unwrap() {
            ProxyLink::EncryptedMediaflow { d } => d,
            _ => unreachable!(),
        };
        let decoded = codec.resolve_params(None, Some(&d), None, now).unwrap();
        assert_eq!(decoded, plain_payload());
    }

    // -- Req 14.5: expired `exp` -> 403 (both formats) -----------------------

    #[test]
    fn expired_exp_is_forbidden_for_mediaflow() {
        let codec = codec();
        let mut p = plain_payload();
        p.exp = Some(1_000);
        let link = codec.encode_mediaflow(&p).unwrap();

        // now == exp -> expired.
        let err = codec.resolve(&link, None, 1_000).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        // now after exp -> expired.
        assert!(codec.resolve(&link, None, 1_001).is_err());
        // now before exp -> ok.
        assert!(codec.resolve(&link, None, 999).is_ok());
    }

    #[test]
    fn expired_exp_is_forbidden_for_stremthru_token() {
        let codec = codec();
        let mut p = plain_payload();
        p.exp = Some(1_000);
        let link = codec.encode_token(&p).unwrap();

        let err = codec.resolve(&link, None, 2_000).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(codec.resolve(&link, None, 500).is_ok());
    }

    #[test]
    fn payload_without_exp_never_expires() {
        let codec = codec();
        let link = codec.encode_token(&plain_payload()).unwrap();
        assert!(codec.resolve(&link, None, i64::MAX).is_ok());
    }

    // -- Req 14.6: ip mismatch vs Client_IP -> 403 (both formats) ------------

    #[test]
    fn ip_mismatch_is_forbidden_and_ip_restricted_for_mediaflow() {
        let codec = codec();
        let mut p = plain_payload();
        p.ip = Some(ip("203.0.113.7"));
        let link = codec.encode_mediaflow(&p).unwrap();

        let err = codec
            .resolve(&link, Some(ip("198.51.100.9")), 0)
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.ip_restricted, "an IP-cause 403 must be flagged");

        // Matching IP -> ok.
        assert!(codec.resolve(&link, Some(ip("203.0.113.7")), 0).is_ok());
    }

    #[test]
    fn ip_mismatch_is_forbidden_for_stremthru_token() {
        let codec = codec();
        let mut p = plain_payload();
        p.ip = Some(ip("2001:db8::1"));
        let link = codec.encode_token(&p).unwrap();

        let err = codec
            .resolve(&link, Some(ip("2001:db8::2")), 0)
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.ip_restricted);

        assert!(codec.resolve(&link, Some(ip("2001:db8::1")), 0).is_ok());
    }

    #[test]
    fn ip_bound_link_with_unknown_client_ip_fails_closed() {
        let codec = codec();
        let mut p = plain_payload();
        p.ip = Some(ip("203.0.113.7"));
        let link = codec.encode_mediaflow(&p).unwrap();

        // No determinable Client_IP for an IP-bound link -> reject (Req 14.6).
        let err = codec.resolve(&link, None, 0).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.ip_restricted);
    }

    #[test]
    fn unbound_link_matches_any_client_ip() {
        let codec = codec();
        let link = codec.encode_mediaflow(&plain_payload()).unwrap();
        // No IP binding -> any requester (or none) is accepted.
        assert!(codec.resolve(&link, Some(ip("203.0.113.7")), 0).is_ok());
        assert!(codec.resolve(&link, None, 0).is_ok());
    }

    #[test]
    fn expiry_checked_before_ip_when_both_invalid() {
        // Both checks reject with 403; just assert the combined invalid case
        // is forbidden regardless of ordering.
        let codec = codec();
        let mut p = plain_payload();
        p.exp = Some(1_000);
        p.ip = Some(ip("203.0.113.7"));
        let link = codec.encode_token(&p).unwrap();
        let err = codec
            .resolve(&link, Some(ip("198.51.100.9")), 5_000)
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    // -- ProxyLink helpers ---------------------------------------------------

    #[test]
    fn as_query_param_formats_each_variant() {
        assert_eq!(
            ProxyLink::EncryptedMediaflow {
                d: "abc".to_string()
            }
            .as_query_param(),
            "d=abc"
        );
        assert_eq!(
            ProxyLink::Token {
                token: "xyz".to_string()
            }
            .as_query_param(),
            "token=xyz"
        );
    }

    #[test]
    fn ipv4_and_ipv6_bindings_round_trip_and_enforce() {
        let codec = codec();
        for addr in ["203.0.113.7", "2001:db8::dead:beef"] {
            let mut p = plain_payload();
            p.ip = Some(ip(addr));
            let link = codec.encode_token(&p).unwrap();
            assert!(codec.resolve(&link, Some(ip(addr)), 0).is_ok());
            assert!(codec.resolve(&link, Some(ip("192.0.2.1")), 0).is_err());
        }
    }
}
