//! AES-CBC URL-parameter encryption (`auth::encryption`) — Req 14.1–14.4.
//!
//! Generated proxy URLs embed their parameters (upstream `url`, injected
//! upstream `headers`, optional `filename`, optional `exp` expiry, optional
//! `ip` binding) inside an **encrypted** `d` query parameter so links cannot be
//! reused, shared, or tampered with (design: Data Models → Proxy Link / Token
//! Formats; requirements 14.1–14.7).
//!
//! This module implements the **mediaflow-proxy-light** style so existing
//! mediaflow `d` parameters remain drop-in compatible (Req 36.5/36.7):
//!
//! * **Cipher:** AES-256 in CBC mode with PKCS#7 padding (Req 14.1).
//! * **Key derivation:** the `API_Password`, UTF-8 encoded, space-padded
//!   (`0x20`) to 32 bytes and truncated to 32 bytes — byte-for-byte the Python
//!   `secret_key.encode("utf-8").ljust(32)[:32]` derivation (Req 14.1).
//! * **Token framing:** `base64url-no-pad( IV[16] || AES-CBC-PKCS7(json) )`,
//!   where `json` is the serialized [`ProxyPayload`]. A fresh random IV is
//!   generated per token, so encrypting the same payload twice yields distinct
//!   tokens that both decrypt back to the original (Req 14.7).
//!
//! Decryption is **fail-closed**: a corrupt, truncated, wrong-key, or
//! otherwise undecryptable token is rejected with a typed [`AppError`] rather
//! than yielding a partial or incorrect payload (Req 14.4). The embedded
//! `exp` / `ip` fields are preserved exactly across the round trip; the
//! HTTP-layer `403` enforcement on a past `exp` (Req 14.5) or a mismatched
//! `Client_IP` (Req 14.6) is layered on top via the [`ProxyPayload::is_expired`]
//! and [`ProxyPayload::ip_matches`] helpers by the request handler.

use std::collections::BTreeMap;
use std::net::IpAddr;

use aes::Aes256;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::errors::AppError;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// The IV length (and AES block size) in bytes.
const IV_LEN: usize = 16;

/// Format-agnostic representation of the parameters embedded in an encrypted
/// proxy link (design: Data Models → Proxy Link / Token Formats).
///
/// `exp` is a unix-second expiry (Req 14.2) and `ip` is the bound `Client_IP`
/// (Req 14.3); both are optional and, when present, are preserved exactly
/// across an encrypt → decrypt round trip (Req 14.7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPayload {
    /// The upstream URL the proxy will fetch.
    pub url: String,
    /// Upstream request headers to inject, serialized in sorted order so the
    /// JSON (and therefore the ciphertext input) is deterministic.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Optional download filename hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Optional unix-second expiry embedded in the payload (Req 14.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Optional bound client IP embedded in the payload (Req 14.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
}

impl ProxyPayload {
    /// Convenience constructor for a payload that carries only an upstream URL
    /// (no injected headers, filename, expiry, or IP binding).
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: BTreeMap::new(),
            filename: None,
            exp: None,
            ip: None,
        }
    }

    /// `true` when an `exp` is present and lies at or before `now_unix_secs`
    /// (Req 14.5). A payload with no `exp` never expires.
    pub fn is_expired(&self, now_unix_secs: i64) -> bool {
        matches!(self.exp, Some(exp) if exp <= now_unix_secs)
    }

    /// `true` when the payload either carries no IP binding or its bound IP
    /// equals `client_ip` (Req 14.6). A payload with no `ip` matches any
    /// requester.
    pub fn ip_matches(&self, client_ip: IpAddr) -> bool {
        match self.ip {
            Some(bound) => bound == client_ip,
            None => true,
        }
    }
}

/// A 32-byte AES-256 key derived from the configured `API_Password` (Req 14.1).
///
/// Construct it once with [`CbcKey::from_api_password`] and reuse it for both
/// [`encrypt`] and [`decrypt`]. The derivation mirrors the Python mediaflow
/// proxy (`ljust(32)[:32]`) so tokens are interchangeable between the two
/// implementations.
#[derive(Clone)]
pub struct CbcKey([u8; 32]);

impl CbcKey {
    /// Derive the AES-256 key from the `API_Password` (Req 14.1).
    ///
    /// The password's UTF-8 bytes are right-padded with ASCII spaces (`0x20`)
    /// to 32 bytes, or truncated to the first 32 bytes when longer.
    pub fn from_api_password(api_password: &str) -> Self {
        Self::from_bytes(api_password.as_bytes())
    }

    /// Derive the key from raw secret bytes (space-pad/truncate to 32 bytes).
    pub fn from_bytes(secret: &[u8]) -> Self {
        let mut key = [0x20u8; 32];
        let copy_len = secret.len().min(32);
        key[..copy_len].copy_from_slice(&secret[..copy_len]);
        Self(key)
    }

    /// Borrow the 32-byte derived key material.
    ///
    /// Exposed so adjacent key-derivation consumers (notably the stremthru
    /// token codec in [`crate::proxylink`], which keys an HMAC rather than an
    /// AES-CBC cipher) can reuse the same `ljust(32)[:32]` derivation without
    /// re-deriving it. The bytes are secret; call sites must not log them.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Encrypt a [`ProxyPayload`] into a `base64url-no-pad` `d`-parameter token
/// (Req 14.1).
///
/// The output is `base64url( IV[16] || AES-256-CBC-PKCS7(json(payload)) )` with
/// a fresh random IV, so two calls with the same payload produce different
/// tokens that both decrypt back to the original (Req 14.7).
pub fn encrypt(payload: &ProxyPayload, key: &CbcKey) -> Result<String, AppError> {
    let json = serde_json::to_vec(payload)
        .map_err(|e| AppError::unknown(format!("failed to serialize proxy payload: {e}")))?;

    let mut iv = [0u8; IV_LEN];
    rand::rng().fill_bytes(&mut iv);

    let ciphertext =
        Aes256CbcEnc::new(&key.0.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&json);

    let mut framed = Vec::with_capacity(IV_LEN + ciphertext.len());
    framed.extend_from_slice(&iv);
    framed.extend_from_slice(&ciphertext);

    Ok(URL_SAFE_NO_PAD.encode(framed))
}

/// Decrypt a `d`-parameter token back into its [`ProxyPayload`] (Req 14.4).
///
/// Fail-closed: an invalid base64 token, a token shorter than one IV + one
/// cipher block, a wrong key (PKCS#7 padding/unpad failure), or a payload that
/// is not valid `ProxyPayload` JSON all reject with a typed [`AppError`]
/// (`403 Forbidden`) rather than returning a partial result. On success the
/// embedded `exp`/`ip` fields are recovered exactly (Req 14.7); expiry and IP
/// *enforcement* (Req 14.5/14.6) is performed by the caller via
/// [`ProxyPayload::is_expired`] / [`ProxyPayload::ip_matches`].
pub fn decrypt(token: &str, key: &CbcKey) -> Result<ProxyPayload, AppError> {
    let framed = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|e| AppError::forbidden(format!("invalid proxy-link token encoding: {e}")))?;

    // Need at least the IV plus one full AES block of ciphertext.
    if framed.len() < IV_LEN + 16 {
        return Err(AppError::forbidden("proxy-link token is too short"));
    }

    let (iv, ciphertext) = framed.split_at(IV_LEN);

    let plaintext = Aes256CbcDec::new(&key.0.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| {
            AppError::forbidden("proxy-link decryption failed: corrupt token or wrong key")
        })?;

    serde_json::from_slice::<ProxyPayload>(&plaintext)
        .map_err(|e| AppError::forbidden(format!("invalid proxy-link payload: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn full_payload() -> ProxyPayload {
        let mut headers = BTreeMap::new();
        headers.insert("Referer".to_string(), "https://example.com/".to_string());
        headers.insert("User-Agent".to_string(), "stream-flow/1.0".to_string());
        ProxyPayload {
            url: "https://cdn.example.com/movie.mkv".to_string(),
            headers,
            filename: Some("movie.mkv".to_string()),
            exp: Some(1_900_000_000),
            ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        }
    }

    // -- Req 14.1 / 14.7: round-trip correctness keyed from API_Password ------

    #[test]
    fn encrypt_decrypt_round_trip_recovers_payload_exactly() {
        let key = CbcKey::from_api_password("super-secret-password");
        let payload = full_payload();

        let token = encrypt(&payload, &key).unwrap();
        let decrypted = decrypt(&token, &key).unwrap();

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn round_trip_for_minimal_payload() {
        let key = CbcKey::from_api_password("pw");
        let payload = ProxyPayload::new("https://example.com/stream.m3u8");

        let token = encrypt(&payload, &key).unwrap();
        let decrypted = decrypt(&token, &key).unwrap();

        assert_eq!(decrypted, payload);
        assert!(decrypted.headers.is_empty());
        assert_eq!(decrypted.filename, None);
        assert_eq!(decrypted.exp, None);
        assert_eq!(decrypted.ip, None);
    }

    #[test]
    fn fresh_iv_makes_tokens_unique_but_both_decrypt() {
        let key = CbcKey::from_api_password("api-password");
        let payload = full_payload();

        let token_a = encrypt(&payload, &key).unwrap();
        let token_b = encrypt(&payload, &key).unwrap();

        // Distinct ciphertext (random IV) ...
        assert_ne!(token_a, token_b);
        // ... yet both recover the original payload (Req 14.7).
        assert_eq!(decrypt(&token_a, &key).unwrap(), payload);
        assert_eq!(decrypt(&token_b, &key).unwrap(), payload);
    }

    // -- Req 14.2 / 14.3: embedded expiry + IP fields preserved ---------------

    #[test]
    fn embedded_expiry_is_preserved_across_round_trip() {
        let key = CbcKey::from_api_password("k");
        let mut payload = ProxyPayload::new("https://example.com/v.mp4");
        payload.exp = Some(1_712_345_678);

        let decrypted = decrypt(&encrypt(&payload, &key).unwrap(), &key).unwrap();

        assert_eq!(decrypted.exp, Some(1_712_345_678));
    }

    #[test]
    fn embedded_ipv4_and_ipv6_bindings_are_preserved() {
        let key = CbcKey::from_api_password("k");

        for ip in [
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            let mut payload = ProxyPayload::new("https://example.com/v.mp4");
            payload.ip = Some(ip);

            let decrypted = decrypt(&encrypt(&payload, &key).unwrap(), &key).unwrap();
            assert_eq!(decrypted.ip, Some(ip), "ip binding {ip} must round-trip");
        }
    }

    #[test]
    fn injected_headers_are_preserved_across_round_trip() {
        let key = CbcKey::from_api_password("k");
        let payload = full_payload();

        let decrypted = decrypt(&encrypt(&payload, &key).unwrap(), &key).unwrap();

        assert_eq!(decrypted.headers, payload.headers);
    }

    // -- Req 14.4: decryption failure rejects with a typed error --------------

    #[test]
    fn wrong_key_rejects() {
        let key = CbcKey::from_api_password("correct-password");
        let wrong = CbcKey::from_api_password("different-password");
        let token = encrypt(&full_payload(), &key).unwrap();

        let err = decrypt(&token, &wrong).unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::Forbidden);
    }

    #[test]
    fn tampered_ciphertext_rejects() {
        let key = CbcKey::from_api_password("password");
        let token = encrypt(&full_payload(), &key).unwrap();

        // Flip the final base64 character to corrupt the last cipher block.
        let mut bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let tampered = URL_SAFE_NO_PAD.encode(&bytes);

        assert!(decrypt(&tampered, &key).is_err());
    }

    #[test]
    fn invalid_base64_rejects() {
        let key = CbcKey::from_api_password("password");
        // '*' is not in the base64url alphabet.
        let err = decrypt("not*valid*base64", &key).unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::Forbidden);
    }

    #[test]
    fn truncated_token_rejects() {
        let key = CbcKey::from_api_password("password");
        // 8 bytes < IV(16) + one block(16): far too short to be a valid token.
        let short = URL_SAFE_NO_PAD.encode([0u8; 8]);
        assert!(decrypt(&short, &key).is_err());
    }

    #[test]
    fn empty_token_rejects() {
        let key = CbcKey::from_api_password("password");
        assert!(decrypt("", &key).is_err());
    }

    // -- Req 14.1: key derivation mirrors the mediaflow `ljust(32)[:32]` ------

    #[test]
    fn key_derivation_space_pads_short_passwords() {
        let key = CbcKey::from_api_password("short");
        let mut expected = [0x20u8; 32];
        expected[..5].copy_from_slice(b"short");
        assert_eq!(key.0, expected);
    }

    #[test]
    fn key_derivation_truncates_long_passwords() {
        let long = "this_is_a_very_long_password_that_exceeds_32_bytes";
        let key = CbcKey::from_api_password(long);
        assert_eq!(&key.0[..], &long.as_bytes()[..32]);
    }

    #[test]
    fn as_bytes_exposes_the_derived_key_material() {
        // The accessor must return exactly the `ljust(32)[:32]` derivation so
        // the token codec (which keys an HMAC) reuses identical key material.
        let key = CbcKey::from_api_password("short");
        let mut expected = [0x20u8; 32];
        expected[..5].copy_from_slice(b"short");
        assert_eq!(key.as_bytes(), &expected);
    }

    // -- Req 14.5 / 14.6 helpers (enforcement is done by the caller) ----------

    #[test]
    fn is_expired_reflects_embedded_expiry() {
        let mut payload = ProxyPayload::new("https://example.com");
        assert!(!payload.is_expired(1_000), "no exp never expires");

        payload.exp = Some(1_000);
        assert!(payload.is_expired(1_000), "exp at now is expired");
        assert!(payload.is_expired(1_001), "exp in the past is expired");
        assert!(!payload.is_expired(999), "exp in the future is not expired");
    }

    #[test]
    fn ip_matches_reflects_embedded_binding() {
        let bound = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));

        let mut payload = ProxyPayload::new("https://example.com");
        assert!(payload.ip_matches(other), "no binding matches any IP");

        payload.ip = Some(bound);
        assert!(payload.ip_matches(bound));
        assert!(!payload.ip_matches(other));
    }
}
