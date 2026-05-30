//! At-rest field encryption (`persistence::vault`) — Req 29.5.
//!
//! Sensitive persisted fields (store tokens, Trakt access/refresh tokens, peer
//! tokens) are encrypted **at rest** with **AES-256-GCM** keyed from the
//! configured `Vault_Secret` (design: Database -> Schema, "AES-GCM(Vault_Secret)
//! or plaintext if no vault"; Req 29.5). This module owns the field codec: a
//! [`Vault`] turns a plaintext field value into the ciphertext blob stored in a
//! `*_enc BLOB` column, and back.
//!
//! ## Key derivation
//!
//! `Vault_Secret` is an operator-supplied string of arbitrary length, but
//! AES-256 needs exactly 32 key bytes. We derive the key as
//! `SHA-256(secret_bytes)` — a fixed-length, deterministic mapping so the same
//! secret always yields the same key (and therefore decrypts what it encrypted)
//! without imposing a length requirement on the operator.
//!
//! ## Wire format
//!
//! Each encrypted blob is `nonce (12 bytes) ‖ ciphertext+tag`. AES-GCM requires
//! a unique nonce per message under a given key; we draw a fresh random 96-bit
//! nonce for every `encrypt` call and prepend it so `decrypt` can recover it.
//! The 16-byte GCM authentication tag is appended by the AEAD and verified on
//! decrypt, so any tampering or wrong key is rejected rather than silently
//! returning garbage.
//!
//! ## Disabled vault (plaintext passthrough)
//!
//! When **no** `Vault_Secret` is configured the vault is *disabled*: fields are
//! stored verbatim (the schema column then holds plaintext bytes, exactly as
//! the design's "or plaintext if no vault" note allows). The round-trip
//! contract still holds — `decrypt(encrypt(x)) == x` — so callers need no
//! special-casing.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::config::Secret;
use crate::errors::AppError;

/// AES-GCM nonce length in bytes (96-bit, the AES-GCM standard nonce size).
const NONCE_LEN: usize = 12;

/// At-rest field codec keyed from `Vault_Secret` (Req 29.5).
///
/// Construct with [`Vault::new`] from the configured optional secret. When a
/// secret is present the codec is *enabled* (AES-256-GCM); when it is absent or
/// empty the codec is *disabled* and passes fields through verbatim.
pub struct Vault {
    /// `Some` when a `Vault_Secret` is configured (enabled), `None` otherwise
    /// (plaintext passthrough). Holding the constructed cipher avoids redoing
    /// the AES key schedule on every field operation.
    cipher: Option<Aes256Gcm>,
}

impl std::fmt::Debug for Vault {
    /// Never render key material: only whether the vault is enabled.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("enabled", &self.cipher.is_some())
            .finish()
    }
}

impl Vault {
    /// Build a vault from the optionally-configured `Vault_Secret`
    /// ([`Config::vault_secret`](crate::config::Config)).
    ///
    /// A `None` or empty secret yields a *disabled* vault (plaintext
    /// passthrough); any non-empty secret yields an AES-256-GCM codec keyed by
    /// `SHA-256(secret)` (Req 29.5).
    pub fn new(secret: Option<&Secret>) -> Self {
        match secret {
            Some(s) if !s.is_empty() => Self::enabled_from_bytes(s.expose().as_bytes()),
            _ => Self::disabled(),
        }
    }

    /// An *enabled* vault keyed directly from raw secret bytes.
    ///
    /// Exposed for callers/tests that hold the secret as bytes rather than as a
    /// [`Secret`]; [`Vault::new`] is the config-driven entry point.
    pub fn enabled_from_bytes(secret_bytes: &[u8]) -> Self {
        let digest = Sha256::digest(secret_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&digest);
        Self {
            cipher: Some(Aes256Gcm::new(key)),
        }
    }

    /// A *disabled* vault that stores fields as plaintext (no `Vault_Secret`).
    pub fn disabled() -> Self {
        Self { cipher: None }
    }

    /// `true` when a `Vault_Secret` is configured and fields are encrypted at
    /// rest; `false` for plaintext passthrough.
    pub fn is_enabled(&self) -> bool {
        self.cipher.is_some()
    }

    /// Encrypt a sensitive field value for storage in a `*_enc BLOB` column.
    ///
    /// Enabled: returns `nonce ‖ ciphertext+tag` under a fresh random 96-bit
    /// nonce. Disabled: returns the plaintext bytes verbatim. The inverse is
    /// [`decrypt`](Self::decrypt) (Req 29.5).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
        match &self.cipher {
            None => Ok(plaintext.to_vec()),
            Some(cipher) => {
                let mut nonce_bytes = [0u8; NONCE_LEN];
                rand::rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ciphertext = cipher
                    .encrypt(nonce, plaintext)
                    // The AEAD error carries no plaintext/key material, but we
                    // emit a fixed message regardless so nothing sensitive can
                    // ever reach a log (Req 32.6).
                    .map_err(|_| AppError::unknown("vault: field encryption failed"))?;
                let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
                out.extend_from_slice(&nonce_bytes);
                out.extend_from_slice(&ciphertext);
                Ok(out)
            }
        }
    }

    /// Decrypt a `*_enc BLOB` column value back to the original field bytes.
    ///
    /// Enabled: splits off the 12-byte nonce, then AES-GCM-decrypts and
    /// authenticates the remainder — a wrong key, truncated blob, or any
    /// tampering is rejected with a typed [`AppError`] rather than returning
    /// corrupt data. Disabled: returns the stored bytes verbatim (Req 29.5).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, AppError> {
        match &self.cipher {
            None => Ok(data.to_vec()),
            Some(cipher) => {
                if data.len() < NONCE_LEN {
                    return Err(AppError::unknown(
                        "vault: encrypted field is too short to contain a nonce",
                    ));
                }
                let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
                let nonce = Nonce::from_slice(nonce_bytes);
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|_| AppError::unknown("vault: field decryption failed"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative enabled vault for the round-trip tests.
    fn enabled() -> Vault {
        Vault::enabled_from_bytes(b"correct horse battery staple")
    }

    /// Req 29.5: encrypting then decrypting a field with an enabled vault
    /// recovers exactly the original bytes (the core round-trip).
    #[test]
    fn enabled_vault_round_trips_a_field_value() {
        let vault = enabled();
        let plaintext = b"realdebrid-api-token-XYZ";
        let blob = vault.encrypt(plaintext).expect("encrypt");
        let recovered = vault.decrypt(&blob).expect("decrypt");
        assert_eq!(recovered, plaintext, "decrypt(encrypt(x)) must equal x");
    }

    /// The stored blob is genuinely ciphertext: it does not equal the plaintext
    /// and is longer (nonce + GCM tag overhead), proving the field is encrypted
    /// at rest (Req 29.5).
    #[test]
    fn enabled_vault_blob_is_not_the_plaintext() {
        let vault = enabled();
        let plaintext = b"super-secret-token";
        let blob = vault.encrypt(plaintext).expect("encrypt");

        assert_ne!(blob.as_slice(), plaintext.as_slice(), "blob must not be plaintext");
        // nonce (12) + ciphertext (== plaintext len) + tag (16).
        assert_eq!(blob.len(), NONCE_LEN + plaintext.len() + 16);
    }

    /// A fresh random nonce per call means encrypting the same value twice
    /// yields different blobs, yet both decrypt back to the original.
    #[test]
    fn encrypt_is_randomized_but_decrypts_consistently() {
        let vault = enabled();
        let plaintext = b"repeatable-value";

        let a = vault.encrypt(plaintext).expect("encrypt a");
        let b = vault.encrypt(plaintext).expect("encrypt b");
        assert_ne!(a, b, "distinct nonces must produce distinct blobs");

        assert_eq!(vault.decrypt(&a).expect("decrypt a"), plaintext);
        assert_eq!(vault.decrypt(&b).expect("decrypt b"), plaintext);
    }

    /// The empty field value round-trips too (an empty token is still a valid
    /// field; AES-GCM happily encrypts zero-length plaintext).
    #[test]
    fn enabled_vault_round_trips_empty_value() {
        let vault = enabled();
        let blob = vault.encrypt(b"").expect("encrypt empty");
        assert_eq!(vault.decrypt(&blob).expect("decrypt empty"), b"");
    }

    /// Arbitrary binary field values (not just UTF-8) round-trip.
    #[test]
    fn enabled_vault_round_trips_binary_value() {
        let vault = enabled();
        let plaintext: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let blob = vault.encrypt(&plaintext).expect("encrypt binary");
        assert_eq!(vault.decrypt(&blob).expect("decrypt binary"), plaintext);
    }

    /// A disabled vault (no `Vault_Secret`) passes fields through verbatim, and
    /// the round-trip contract still holds (design: "or plaintext if no vault").
    #[test]
    fn disabled_vault_is_plaintext_passthrough() {
        let vault = Vault::disabled();
        assert!(!vault.is_enabled());

        let plaintext = b"no-vault-configured";
        let stored = vault.encrypt(plaintext).expect("encrypt");
        assert_eq!(stored.as_slice(), plaintext.as_slice(), "disabled vault stores plaintext");
        assert_eq!(vault.decrypt(&stored).expect("decrypt"), plaintext);
    }

    /// `Vault::new` treats an absent or empty secret as disabled and any
    /// non-empty secret as enabled (Req 29.5 + the disabled fallback).
    #[test]
    fn new_enables_only_for_a_non_empty_secret() {
        assert!(!Vault::new(None).is_enabled(), "no secret => disabled");
        assert!(
            !Vault::new(Some(&Secret::from(""))).is_enabled(),
            "empty secret => disabled",
        );
        assert!(
            Vault::new(Some(&Secret::from("a-real-secret"))).is_enabled(),
            "non-empty secret => enabled",
        );
    }

    /// Decryption rejects a wrong key (different secret) rather than returning
    /// corrupt bytes — the GCM tag authentication fails.
    #[test]
    fn decrypt_with_wrong_key_is_rejected() {
        let writer = Vault::enabled_from_bytes(b"secret-one");
        let reader = Vault::enabled_from_bytes(b"secret-two");
        let blob = writer.encrypt(b"sensitive").expect("encrypt");
        assert!(reader.decrypt(&blob).is_err(), "wrong key must be rejected");
    }

    /// Decryption rejects a tampered blob (flipped ciphertext byte).
    #[test]
    fn decrypt_rejects_tampered_blob() {
        let vault = enabled();
        let mut blob = vault.encrypt(b"sensitive").expect("encrypt");
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(vault.decrypt(&blob).is_err(), "tampered blob must be rejected");
    }

    /// Decryption rejects a blob too short to even contain a nonce.
    #[test]
    fn decrypt_rejects_too_short_blob() {
        let vault = enabled();
        assert!(vault.decrypt(&[0u8; NONCE_LEN - 1]).is_err());
    }
}
