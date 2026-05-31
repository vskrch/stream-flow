//! ClearKey key store (`drm::clearkey`) — Req 4.6, 4.7, 4.8.
//!
//! [`ClearKeyStore`] holds the operator-configured ClearKey key set (a map of
//! 16-byte key identifier → 16-byte AES key) and resolves the decryption key
//! for a given KID encountered while parsing an encrypted MP4 fragment
//! (Req 4.6). A successful resolution is cached for the configured key-cache
//! TTL ([`DrmConfig::key_cache_ttl_secs`](crate::config::DrmConfig)) so a
//! repeated KID lookup during a long segment/stream does not re-walk the
//! configured set (Req 4.7). When no configured key matches a protected
//! representation's KID, resolution fails with a descriptive [`AppError`] that
//! **names the unresolved KID** in hex so the operator can see exactly which
//! key is missing (Req 4.8).
//!
//! This store is the configured-key path (the ClearKey scheme supplies keys in
//! the clear — no license server). It is pure and synchronous: the key set is
//! fixed at construction and the cache is an in-process, bounded TTL map keyed
//! by KID, so resolution never performs I/O and never blocks.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::errors::AppError;

/// A 16-byte CENC key identifier (`default_KID`).
pub type Kid = [u8; 16];
/// A 16-byte AES-128 ClearKey.
pub type Key = [u8; 16];

/// Resolves ClearKey decryption keys by KID against a configured key set, with
/// a TTL cache of resolved keys (Req 4.6, 4.7, 4.8).
///
/// Construct from the configured `KID → key` pairs ([`ClearKeyStore::new`]) or
/// from hex-encoded pairs ([`ClearKeyStore::from_hex_pairs`], for config
/// loading). [`resolve`](ClearKeyStore::resolve) returns the key for a KID or a
/// KID-naming error.
pub struct ClearKeyStore {
    /// The operator-configured key set (Req 4.6). Fixed at construction.
    keys: HashMap<Kid, Key>,
    /// TTL for cached resolved keys (Req 4.7).
    key_cache_ttl: Duration,
    /// In-process cache of resolved keys keyed by KID, each with an expiry
    /// deadline. Behind a `Mutex` so `resolve` can take `&self` and remain
    /// shareable across worker tasks; the critical section is a single map
    /// lookup/insert so contention is negligible.
    cache: Mutex<HashMap<Kid, CachedKey>>,
}

/// A cached resolved key plus the instant at which the cache entry expires.
struct CachedKey {
    key: Key,
    expires_at: Instant,
}

impl std::fmt::Debug for ClearKeyStore {
    /// Redacted debug view: reports counts and TTL but **never** prints key
    /// material or KIDs, so a `ClearKeyStore` in a log or error chain cannot
    /// leak configured keys.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClearKeyStore")
            .field("configured_keys", &self.keys.len())
            .field("key_cache_ttl", &self.key_cache_ttl)
            .finish_non_exhaustive()
    }
}

impl ClearKeyStore {
    /// Build a store from a configured `KID → key` map and the key-cache TTL
    /// (Req 4.6, 4.7).
    pub fn new(keys: HashMap<Kid, Key>, key_cache_ttl: Duration) -> Self {
        Self {
            keys,
            key_cache_ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Build a store from hex-encoded `(kid_hex, key_hex)` pairs, as carried in
    /// configuration (Req 4.6). Hyphens in the hex (common in dash-separated
    /// KID notation) are ignored. Each KID and key must decode to exactly 16
    /// bytes; otherwise a descriptive [`AppError`] names the offending value.
    pub fn from_hex_pairs<'a, I>(pairs: I, key_cache_ttl: Duration) -> Result<Self, AppError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut keys = HashMap::new();
        for (kid_hex, key_hex) in pairs {
            let kid = decode_hex16(kid_hex, "KID")?;
            let key = decode_hex16(key_hex, "key")?;
            keys.insert(kid, key);
        }
        Ok(Self::new(keys, key_cache_ttl))
    }

    /// Number of configured keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the configured key set is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether a key is configured for `kid` (does not touch the cache).
    pub fn contains(&self, kid: &Kid) -> bool {
        self.keys.contains_key(kid)
    }

    /// Resolve the decryption key for `kid` (Req 4.6).
    ///
    /// On a cache hit whose entry is still within the key-cache TTL, the cached
    /// key is returned without consulting the configured set (Req 4.7). On a
    /// miss (or an expired cache entry), the configured set is consulted; a
    /// match is cached for the TTL and returned. When no configured key matches
    /// the KID, an [`AppError`] naming the unresolved KID in hex is returned
    /// (Req 4.8).
    pub fn resolve(&self, kid: &Kid) -> Result<Key, AppError> {
        let now = Instant::now();

        // Fast path: a live cache entry (Req 4.7).
        {
            let cache = self.cache.lock().expect("clearkey cache mutex poisoned");
            if let Some(entry) = cache.get(kid) {
                if now < entry.expires_at {
                    return Ok(entry.key);
                }
            }
        }

        // Miss / expired: consult the configured set (Req 4.6).
        match self.keys.get(kid) {
            Some(&key) => {
                let mut cache = self.cache.lock().expect("clearkey cache mutex poisoned");
                cache.insert(
                    *kid,
                    CachedKey {
                        key,
                        // Saturate rather than overflow for pathologically
                        // large TTLs; the entry simply lives effectively
                        // forever.
                        expires_at: now.checked_add(self.key_cache_ttl).unwrap_or(now),
                    },
                );
                Ok(key)
            }
            None => Err(unresolved_kid_error(kid)),
        }
    }

    /// Test/diagnostic helper: number of live (un-expired) cache entries.
    #[cfg(test)]
    fn live_cache_len(&self) -> usize {
        let now = Instant::now();
        let cache = self.cache.lock().unwrap();
        cache.values().filter(|e| now < e.expires_at).count()
    }
}

/// Decode a hex string (hyphens ignored) into exactly 16 bytes, naming `label`
/// in any error.
fn decode_hex16(hex_str: &str, label: &str) -> Result<[u8; 16], AppError> {
    let cleaned: String = hex_str.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(&cleaned)
        .map_err(|e| AppError::bad_request(format!("clearkey: invalid {label} hex `{hex_str}`: {e}")))?;
    if bytes.len() != 16 {
        return Err(AppError::bad_request(format!(
            "clearkey: {label} `{hex_str}` must be 16 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build the unresolved-KID error naming the KID in hex (Req 4.8).
///
/// Categorised as `not-found` (`404`): the protected representation references
/// a key the operator has not configured, so the requested protected resource
/// cannot be served.
fn unresolved_kid_error(kid: &Kid) -> AppError {
    AppError::not_found(format!(
        "clearkey: no key configured for KID {}",
        hex::encode(kid)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;

    fn kid(byte: u8) -> Kid {
        [byte; 16]
    }
    fn key(byte: u8) -> Key {
        [byte; 16]
    }

    fn store_with(pairs: &[(Kid, Key)], ttl: Duration) -> ClearKeyStore {
        let map: HashMap<Kid, Key> = pairs.iter().copied().collect();
        ClearKeyStore::new(map, ttl)
    }

    #[test]
    fn resolves_configured_key_by_kid() {
        let store = store_with(&[(kid(0x11), key(0xAA)), (kid(0x22), key(0xBB))], Duration::from_secs(3600));
        assert_eq!(store.resolve(&kid(0x11)).unwrap(), key(0xAA));
        assert_eq!(store.resolve(&kid(0x22)).unwrap(), key(0xBB));
    }

    #[test]
    fn unresolved_kid_errors_naming_the_kid_in_hex() {
        let store = store_with(&[(kid(0x11), key(0xAA))], Duration::from_secs(3600));
        let missing = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let err = store.resolve(&missing).unwrap_err();
        assert_eq!(err.category, ErrorCategory::NotFound);
        // The exact KID hex must appear in the message (Req 4.8).
        assert!(
            err.message.contains("00112233445566778899aabbccddeeff"),
            "error must name the unresolved KID in hex: {}",
            err.message
        );
    }

    #[test]
    fn caches_resolved_key_for_ttl() {
        let store = store_with(&[(kid(0x05), key(0x50))], Duration::from_secs(3600));
        assert_eq!(store.live_cache_len(), 0);
        let _ = store.resolve(&kid(0x05)).unwrap();
        assert_eq!(store.live_cache_len(), 1, "a resolved key is cached (Req 4.7)");
        // A second resolve still returns the same key (served from cache).
        assert_eq!(store.resolve(&kid(0x05)).unwrap(), key(0x50));
        assert_eq!(store.live_cache_len(), 1);
    }

    #[test]
    fn expired_cache_entry_is_not_served() {
        // Zero TTL → entry expires immediately, so it is never a live hit.
        let store = store_with(&[(kid(0x05), key(0x50))], Duration::from_secs(0));
        let _ = store.resolve(&kid(0x05)).unwrap();
        // Cache entry exists but is already expired.
        assert_eq!(store.live_cache_len(), 0);
        // Still resolvable from the configured set (Req 4.6) despite expiry.
        assert_eq!(store.resolve(&kid(0x05)).unwrap(), key(0x50));
    }

    #[test]
    fn unresolved_kid_is_not_cached() {
        let store = store_with(&[(kid(0x05), key(0x50))], Duration::from_secs(3600));
        let _ = store.resolve(&kid(0x99)).unwrap_err();
        assert_eq!(store.live_cache_len(), 0, "failed resolutions are never cached");
    }

    #[test]
    fn from_hex_pairs_decodes_kid_and_key() {
        let store = ClearKeyStore::from_hex_pairs(
            [(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
            )],
            Duration::from_secs(3600),
        )
        .unwrap();
        let resolved = store
            .resolve(&[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ])
            .unwrap();
        assert_eq!(
            resolved,
            [
                0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00,
            ]
        );
    }

    #[test]
    fn from_hex_pairs_ignores_hyphens_in_kid() {
        let store = ClearKeyStore::from_hex_pairs(
            [(
                "00112233-4455-6677-8899-aabbccddeeff",
                "00112233445566778899aabbccddeeff",
            )],
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(store.contains(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]));
    }

    #[test]
    fn from_hex_pairs_rejects_wrong_length() {
        let err = ClearKeyStore::from_hex_pairs(
            [("00112233", "00112233445566778899aabbccddeeff")],
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
        assert!(err.message.contains("KID"));
        assert!(err.message.contains("16 bytes"));
    }

    #[test]
    fn from_hex_pairs_rejects_invalid_hex() {
        let err = ClearKeyStore::from_hex_pairs(
            [("zzzz", "00112233445566778899aabbccddeeff")],
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
        assert!(err.message.contains("invalid KID hex"));
    }

    #[test]
    fn empty_store_reports_empty_and_resolves_to_error() {
        let store = ClearKeyStore::new(HashMap::new(), Duration::from_secs(60));
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.resolve(&kid(0x01)).is_err());
    }
}
