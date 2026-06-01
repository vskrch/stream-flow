//! Cache backend (`cache`) — Req 30, 50.5.
//!
//! A single [`CacheBackend`] trait abstracts the in-process Local cache
//! (`moka`) and — in later tasks — the optional Redis backend and the
//! `FailoverCache` wrapper, so callers never branch on which storage is
//! active (design: Components -> Cache backend).
//!
//! ## What lives here
//!
//! * The [`CacheBackend`] trait: async `get`/`set`(+TTL)/`del` plus the
//!   [`CacheBackend::namespace`] key prefix (Req 30.3).
//! * [`LocalCache`] — the always-present in-process backend over
//!   `moka::future::Cache` with TTL + LRU eviction (Req 30.1, 30.4), in
//!   [`local`] (task 4.1).
//! * [`RedisCache`] — the optional distributed backend over `deadpool-redis`
//!   (Req 30.2), in [`redis`] (task 4.2).
//!
//! The `FailoverCache` (task 4.3) wraps an optional [`RedisCache`] over the
//! always-present [`LocalCache`]; the trait is shaped so both backends slot in
//! without changing any call site. All backends share the namespace-prefixing
//! and TTL contracts defined and exercised by this module.
//!
//! ## Contract
//!
//! * **Round trip (Req 30.6):** for any backend, `get(k)` immediately after
//!   `set(k, v, ttl)` returns `Some(v)` while the entry is unexpired.
//! * **Namespacing (Req 30.3):** every key a backend reads or writes in its
//!   underlying store is prefixed with [`CacheBackend::namespace`]. Callers
//!   pass *logical* keys; the backend owns the physical, namespaced key.
//! * **TTL (Req 30.1, 30.4):** entries carry a per-entry TTL; once it elapses
//!   the entry is treated as **absent** (`get` returns `None`) and is refreshed
//!   from its source on the next access.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use crate::errors::AppError;

pub mod local;
pub mod redis;

pub use local::LocalCache;
pub use redis::RedisCache;

pub mod failover;

pub use failover::{FailoverCache, FailoverConfig};

/// The single storage seam shared by the Local (moka) and Redis backends.
///
/// Implementors store opaque [`Bytes`] under string keys with a per-entry
/// TTL. The trait is intentionally minimal — `get`/`set`/`del` plus the
/// namespace accessor — so the `FailoverCache` (task 4.3) can hold a
/// `Box<dyn CacheBackend>` (or a concrete pair) and route between backends
/// without callers ever knowing which one served a request
/// (design: Components -> Cache backend).
///
/// Every implementor MUST:
/// * prefix the physical key it touches with [`namespace`](Self::namespace)
///   (Req 30.3); callers always pass the *logical*, un-prefixed key;
/// * honor the per-entry `ttl` and treat an expired entry as absent
///   (Req 30.1, 30.4);
/// * surface failures as [`AppError`] rather than panicking, so a backend
///   outage is a typed error the `FailoverCache` can react to (Req 50.5).
#[async_trait]
pub trait CacheBackend: Send + Sync {
    /// Fetch the value stored under the logical `key`.
    ///
    /// Returns `Ok(None)` when the key is absent **or** its TTL has elapsed
    /// (an expired entry is indistinguishable from a missing one — Req 30.4).
    async fn get(&self, key: &str) -> Result<Option<Bytes>, AppError>;

    /// Store `val` under the logical `key` with a time-to-live of `ttl`.
    ///
    /// After `ttl` elapses the entry is treated as absent (Req 30.4).
    async fn set(&self, key: &str, val: Bytes, ttl: Duration) -> Result<(), AppError>;

    /// Remove the logical `key`. Removing an absent key is not an error.
    async fn del(&self, key: &str) -> Result<(), AppError>;

    /// The namespace prefix applied to every physical cache key (Req 30.3).
    fn namespace(&self) -> &str;
}

/// The separator placed between the namespace and the logical key when
/// building a physical cache key. Colon is the conventional Redis-key
/// separator, so the same namespacing scheme carries across the Local and
/// Redis backends (Req 30.3).
pub const NAMESPACE_SEPARATOR: char = ':';

/// Build the physical cache key for a logical `key` under `namespace`
/// (Req 30.3).
///
/// An empty namespace yields the logical key unchanged, so an unset namespace
/// adds no prefix. Otherwise the result is `"{namespace}:{key}"`. This is the
/// single key-construction helper every [`CacheBackend`] uses, keeping the
/// Local and Redis backends byte-for-byte consistent.
pub fn namespaced_key(namespace: &str, key: &str) -> String {
    if namespace.is_empty() {
        key.to_string()
    } else {
        let mut out = String::with_capacity(namespace.len() + 1 + key.len());
        out.push_str(namespace);
        out.push(NAMESPACE_SEPARATOR);
        out.push_str(key);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaced_key_prefixes_with_separator() {
        assert_eq!(namespaced_key("ns", "k"), "ns:k");
        assert_eq!(
            namespaced_key("ZippyPanther", "magnet:abc"),
            "ZippyPanther:magnet:abc"
        );
    }

    #[test]
    fn empty_namespace_leaves_key_unchanged() {
        assert_eq!(namespaced_key("", "k"), "k");
    }
}
