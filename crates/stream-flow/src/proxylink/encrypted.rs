//! Mediaflow-proxy-light AES-CBC `d`-parameter codec (`proxylink::encrypted`)
//! — Req 14.1, 14.4, 36.7.
//!
//! This is the *mediaflow* on-the-wire proxy-link format: the [`ProxyPayload`]
//! is sealed into an **encrypted** `d` query parameter so existing
//! mediaflow-style links (`?d=…`) remain drop-in compatible (Req 36.5, 36.7).
//!
//! The cipher itself — AES-256-CBC keyed from the `API_Password`, framed as
//! `base64url-no-pad( IV[16] || AES-CBC-PKCS7(json) )` — already lives in
//! [`auth::encryption`](crate::auth::encryption) (task 9.2). Rather than
//! reimplement it, this codec is a thin adapter that delegates to that module,
//! so the two surfaces share one cipher and one key derivation
//! ([`CbcKey::from_api_password`]). The round-trip property (Req 14.7) and the
//! fail-closed decryption (Req 14.4) are therefore inherited verbatim.

use crate::auth::encryption::{self, CbcKey, ProxyPayload};
use crate::errors::AppError;

/// The mediaflow AES-CBC `d`-parameter codec.
///
/// A zero-sized type carrying the format's `encode`/`decode` operations; the
/// key material ([`CbcKey`], derived from the `API_Password`) is passed in per
/// call so a single derived key can be reused across requests.
pub struct MediaflowCodec;

impl MediaflowCodec {
    /// Encrypt a [`ProxyPayload`] into the `d`-parameter token string (Req
    /// 14.1). Delegates to [`auth::encryption::encrypt`](encryption::encrypt);
    /// a fresh random IV is used per call so the same payload yields distinct
    /// tokens that both decrypt back (Req 14.7).
    pub fn encode(payload: &ProxyPayload, key: &CbcKey) -> Result<String, AppError> {
        encryption::encrypt(payload, key)
    }

    /// Decrypt a `d`-parameter token back into its [`ProxyPayload`] (Req 14.4).
    ///
    /// Fail-closed: an invalid encoding, a truncated token, a wrong key, or a
    /// non-`ProxyPayload` plaintext all reject with a `403`-mapped
    /// [`AppError`]. Embedded `exp`/`ip` are recovered exactly (Req 14.7);
    /// their *enforcement* (Req 14.5/14.6) is performed by the
    /// [`ProxyCodec`](super::ProxyCodec) dispatcher.
    pub fn decode(d: &str, key: &CbcKey) -> Result<ProxyPayload, AppError> {
        encryption::decrypt(d, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use std::net::{IpAddr, Ipv4Addr};

    fn key() -> CbcKey {
        CbcKey::from_api_password("mediaflow-api-password")
    }

    fn payload() -> ProxyPayload {
        let mut p = ProxyPayload::new("https://cdn.example.com/movie.mkv");
        p.headers
            .insert("Referer".to_string(), "https://example.com/".to_string());
        p.filename = Some("movie.mkv".to_string());
        p.exp = Some(1_900_000_000);
        p.ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        p
    }

    // -- Req 14.7: round trip through the mediaflow `d` codec ----------------

    #[test]
    fn encode_decode_round_trips_payload_exactly() {
        let key = key();
        let d = MediaflowCodec::encode(&payload(), &key).unwrap();
        let decoded = MediaflowCodec::decode(&d, &key).unwrap();
        assert_eq!(decoded, payload());
    }

    #[test]
    fn round_trip_preserves_expiry_and_ip() {
        let key = key();
        let d = MediaflowCodec::encode(&payload(), &key).unwrap();
        let decoded = MediaflowCodec::decode(&d, &key).unwrap();
        assert_eq!(decoded.exp, Some(1_900_000_000));
        assert_eq!(decoded.ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
    }

    // -- Req 14.4 / 36.7: decoded with its own (CbcKey) key material ---------

    #[test]
    fn wrong_cbc_key_rejects_with_forbidden() {
        let d = MediaflowCodec::encode(&payload(), &key()).unwrap();
        let wrong = CbcKey::from_api_password("a-different-password");
        let err = MediaflowCodec::decode(&d, &wrong).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }
}
