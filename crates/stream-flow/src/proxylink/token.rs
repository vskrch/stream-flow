//! Stremthru signed-token codec (`proxylink::token`) — Req 21.2, 36.7.
//!
//! This is the *stremthru* on-the-wire proxy-link format: a **signed but
//! unencrypted** token carrying the [`ProxyPayload`] (design: Data Models →
//! Proxy Link / Token Formats, "stremthru style: signed/unencrypted token").
//! It is the format produced when the `/v0/proxy` request carries a present
//! `token` query parameter (Req 21.2) and is accepted alongside the mediaflow
//! AES-CBC `d` parameter so an operator can drop `stream-flow` in for either
//! upstream project (Req 36.7).
//!
//! # Framing
//!
//! ```text
//! token := base64url-no-pad(json(payload)) "." base64url-no-pad(HMAC-SHA256(json, key))
//! ```
//!
//! The payload travels as plain (base64url-encoded) JSON — stremthru tokens are
//! *not* encrypted — while an appended **HMAC-SHA256** tag over the exact JSON
//! bytes makes the token tamper-evident. Verification is **fail-closed**: a
//! malformed token, a tag of the wrong length, a tag that does not match under
//! the configured [`TokenKey`], or a body that is not valid `ProxyPayload`
//! JSON all reject with a `403`-mapped [`AppError`] (Req 14.4 semantics carried
//! over to this format). The signature is checked in **constant time** so a
//! near-miss forgery costs the same as any other rejection.
//!
//! The key material is the stremthru-side secret ([`TokenKey`]), *separate*
//! from the mediaflow `API_Password`-derived
//! [`CbcKey`](crate::auth::encryption::CbcKey): each format is decoded with its
//! own key material (Req 36.7).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::auth::encryption::ProxyPayload;
use crate::errors::AppError;

type HmacSha256 = Hmac<Sha256>;

/// The HMAC-SHA256 tag length in bytes.
const TAG_LEN: usize = 32;

/// The `body.signature` separator.
const SEP: char = '.';

/// Stremthru-side key material used to sign and verify proxy-link tokens
/// (Req 36.7).
///
/// Distinct from the mediaflow [`CbcKey`](crate::auth::encryption::CbcKey):
/// stremthru tokens are signed (not encrypted) with **this** secret, so the two
/// formats are decoded with their own key material. Build it once with
/// [`TokenKey::from_secret`] (e.g. from the stremthru proxy-auth secret) and
/// reuse it across requests.
#[derive(Clone)]
pub struct TokenKey(Vec<u8>);

impl TokenKey {
    /// Derive the signing key from an arbitrary stremthru secret string. The
    /// secret's UTF-8 bytes are used as the HMAC key (HMAC accepts a key of any
    /// length).
    pub fn from_secret(secret: &str) -> Self {
        Self(secret.as_bytes().to_vec())
    }

    /// Build the signing key from raw secret bytes.
    pub fn from_bytes(secret: &[u8]) -> Self {
        Self(secret.to_vec())
    }

    /// HMAC-SHA256 of `msg` under this key, returning the 32-byte tag.
    fn tag(&self, msg: &[u8]) -> [u8; TAG_LEN] {
        let mut mac =
            HmacSha256::new_from_slice(&self.0).expect("HMAC accepts a key of any length");
        mac.update(msg);
        mac.finalize().into_bytes().into()
    }
}

/// The stremthru signed-token codec.
///
/// A zero-sized type carrying the format's `encode`/`decode` operations; the
/// [`TokenKey`] is passed in per call.
pub struct TokenCodec;

impl TokenCodec {
    /// Encode + sign a [`ProxyPayload`] into a stremthru token string (Req
    /// 21.2).
    ///
    /// The payload is serialized to JSON, the JSON bytes are base64url-encoded
    /// for the body, and an HMAC-SHA256 tag over those exact JSON bytes is
    /// appended (base64url-encoded) after a `.` separator. Encoding is
    /// deterministic — the same payload + key yield the same token — because
    /// the [`ProxyPayload`] header map is serialized in sorted order and no
    /// random nonce is involved.
    pub fn encode(payload: &ProxyPayload, key: &TokenKey) -> Result<String, AppError> {
        let json = serde_json::to_vec(payload)
            .map_err(|e| AppError::unknown(format!("failed to serialize proxy payload: {e}")))?;
        let body = URL_SAFE_NO_PAD.encode(&json);
        let tag = URL_SAFE_NO_PAD.encode(key.tag(&json));
        Ok(format!("{body}{SEP}{tag}"))
    }

    /// Verify + decode a stremthru token back into its [`ProxyPayload`] (Req
    /// 14.4 semantics).
    ///
    /// Fail-closed: a token without the `.` separator, a non-base64 body or
    /// tag, a tag of the wrong length, a signature that does not match under
    /// `key`, or a body that is not valid `ProxyPayload` JSON all reject with a
    /// `403`-mapped [`AppError`]. The signature comparison is constant-time.
    /// Embedded `exp`/`ip` are recovered exactly; their *enforcement* (Req
    /// 14.5/14.6) is performed by the [`ProxyCodec`](super::ProxyCodec)
    /// dispatcher.
    pub fn decode(token: &str, key: &TokenKey) -> Result<ProxyPayload, AppError> {
        let (body_b64, tag_b64) = token
            .rsplit_once(SEP)
            .ok_or_else(|| AppError::forbidden("malformed stremthru token: missing signature"))?;

        let json = URL_SAFE_NO_PAD.decode(body_b64).map_err(|e| {
            AppError::forbidden(format!("invalid stremthru token body encoding: {e}"))
        })?;
        let presented_tag = URL_SAFE_NO_PAD.decode(tag_b64).map_err(|e| {
            AppError::forbidden(format!("invalid stremthru token signature encoding: {e}"))
        })?;

        // Recompute the tag over the body JSON and compare in constant time.
        // A wrong-length presented tag can never match the fixed 32-byte tag.
        let expected_tag = key.tag(&json);
        if !constant_time_eq(&expected_tag, &presented_tag) {
            return Err(AppError::forbidden(
                "stremthru token signature verification failed",
            ));
        }

        serde_json::from_slice::<ProxyPayload>(&json)
            .map_err(|e| AppError::forbidden(format!("invalid stremthru token payload: {e}")))
    }
}

/// Constant-time equality over two byte slices. Comparing every byte of the
/// expected (fixed-length) tag — and treating any length mismatch as unequal —
/// keeps the running time independent of how many leading bytes a forgery
/// happens to match.
fn constant_time_eq(expected: &[u8], presented: &[u8]) -> bool {
    if expected.len() != presented.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(presented.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn key() -> TokenKey {
        TokenKey::from_secret("stremthru-proxy-secret")
    }

    fn payload() -> ProxyPayload {
        let mut p = ProxyPayload::new("https://cdn.example.com/movie.mkv");
        p.headers
            .insert("User-Agent".to_string(), "stream-flow/1.0".to_string());
        p.filename = Some("movie.mkv".to_string());
        p.exp = Some(1_900_000_000);
        p.ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        p
    }

    // -- Req 21.2 / 14.7: round trip through the stremthru token codec -------

    #[test]
    fn encode_decode_round_trips_payload_exactly() {
        let key = key();
        let token = TokenCodec::encode(&payload(), &key).unwrap();
        let decoded = TokenCodec::decode(&token, &key).unwrap();
        assert_eq!(decoded, payload());
    }

    #[test]
    fn round_trip_for_minimal_payload() {
        let key = key();
        let p = ProxyPayload::new("https://example.com/stream.m3u8");
        let token = TokenCodec::encode(&p, &key).unwrap();
        let decoded = TokenCodec::decode(&token, &key).unwrap();
        assert_eq!(decoded, p);
        assert!(decoded.headers.is_empty());
        assert_eq!(decoded.exp, None);
        assert_eq!(decoded.ip, None);
    }

    #[test]
    fn round_trip_preserves_ipv6_binding() {
        let key = key();
        let mut p = ProxyPayload::new("https://example.com/v.mp4");
        p.ip = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        let token = TokenCodec::encode(&p, &key).unwrap();
        assert_eq!(TokenCodec::decode(&token, &key).unwrap().ip, p.ip);
    }

    #[test]
    fn encoding_is_deterministic() {
        let key = key();
        let a = TokenCodec::encode(&payload(), &key).unwrap();
        let b = TokenCodec::encode(&payload(), &key).unwrap();
        assert_eq!(a, b, "stremthru tokens are signed, not nonced");
    }

    // -- Req 36.7: tokens are decoded with their own key material ------------

    #[test]
    fn wrong_token_key_rejects_with_forbidden() {
        let token = TokenCodec::encode(&payload(), &key()).unwrap();
        let wrong = TokenKey::from_secret("a-different-secret");
        let err = TokenCodec::decode(&token, &wrong).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    // -- Req 14.4 (carried over): fail-closed verification -------------------

    #[test]
    fn tampered_body_rejects() {
        let key = key();
        let token = TokenCodec::encode(&payload(), &key).unwrap();
        let (body, tag) = token.rsplit_once('.').unwrap();
        // Re-encode a different payload's body but keep the original tag.
        let other = TokenCodec::encode(&ProxyPayload::new("https://evil.example/x"), &key).unwrap();
        let other_body = other.rsplit_once('.').unwrap().0;
        assert_ne!(body, other_body);
        let forged = format!("{other_body}.{tag}");
        assert!(TokenCodec::decode(&forged, &key).is_err());
    }

    #[test]
    fn missing_signature_rejects() {
        let key = key();
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload()).unwrap());
        // No `.` separator -> malformed.
        let err = TokenCodec::decode(&body, &key).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn invalid_base64_body_rejects() {
        let key = key();
        // '*' is outside the base64url alphabet.
        let err = TokenCodec::decode("not*valid.AAAA", &key).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn wrong_length_signature_rejects() {
        let key = key();
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload()).unwrap());
        // A short (valid-base64) tag can never equal the 32-byte HMAC tag.
        let short_tag = URL_SAFE_NO_PAD.encode([0u8; 4]);
        let token = format!("{body}.{short_tag}");
        assert!(TokenCodec::decode(&token, &key).is_err());
    }

    #[test]
    fn empty_token_rejects() {
        let key = key();
        assert!(TokenCodec::decode("", &key).is_err());
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
    }
}
