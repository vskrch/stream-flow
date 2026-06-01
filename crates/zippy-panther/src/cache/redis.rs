//! [`RedisCache`] — the optional distributed [`CacheBackend`] (Req 30.2).
//!
//! Backed by a `deadpool-redis` connection pool over the async `redis` client.
//! When a Redis URL is configured the system uses this backend for cacheable
//! data so any replica reuses resolved data and peer-sharing rides the same
//! keyspace (design: Persistence note; Req 30.2). It honors the exact same
//! contracts as [`LocalCache`](super::local::LocalCache):
//!
//! * **Namespacing (Req 30.3):** every physical key is built with the shared
//!   [`namespaced_key`] helper, so the Local and Redis backends are
//!   byte-for-byte consistent. Callers always pass the logical, un-prefixed
//!   key.
//! * **TTL (Req 30.4):** `set` issues `SET key val PX <millis>` so Redis itself
//!   expires the entry; once it elapses `get` returns `None` (the entry is
//!   indistinguishable from a missing one).
//! * **Typed failures (Req 50.5):** a pool-checkout or command error surfaces
//!   as an [`AppError`] (category `UpstreamUnavailable`) rather than a panic,
//!   so the `FailoverCache` (task 4.3) can react — fall back to local and
//!   schedule a reattach — instead of failing the request.
//!
//! ## Testing without a live Redis
//!
//! Building the pool is lazy: [`RedisCache::from_url`] parses the URL and sets
//! up the `deadpool` manager but opens no socket, so construction succeeds
//! offline and is unit-tested directly. The get/set/del round-trip and TTL
//! integration tests require a reachable server and are gated on the
//! `REDIS_URL` environment variable — they skip cleanly when it is unset (so
//! `cargo test` is green without Redis) and exercise the real round trip when
//! it is set (design: Testing Strategy — "Redis tests use a `deadpool-redis`
//! test container only when available, otherwise the local fallback path is
//! asserted").

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use deadpool_redis::{Config, Pool, Runtime};
use redis::{AsyncCommands, SetExpiry, SetOptions};

use crate::errors::AppError;

use super::{namespaced_key, CacheBackend};

/// Optional Redis-backed [`CacheBackend`] (Req 30.2).
///
/// Holds a cloneable `deadpool-redis` [`Pool`] plus the configured namespace
/// prefix (design: Components -> Cache backend — `RedisCache { pool, ns }`).
#[derive(Clone)]
pub struct RedisCache {
    /// Connection pool over the async `redis` multiplexed connection.
    pool: Pool,
    /// Key prefix applied to every physical key (Req 30.3).
    namespace: String,
}

impl RedisCache {
    /// Build a `RedisCache` for `namespace` from a Redis connection `url`
    /// (e.g. `redis://127.0.0.1:6379`).
    ///
    /// Pool construction is **lazy** — the URL is parsed and the pool manager
    /// is created, but no connection is opened until the first operation — so
    /// this never blocks on or fails because of an unreachable server. A URL
    /// that cannot be parsed surfaces as an [`AppError`].
    pub fn from_url(
        url: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Result<Self, AppError> {
        let cfg = Config::from_url(url.into());
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| AppError::upstream_unavailable(format!("redis pool init failed: {e}")))?;
        Ok(Self {
            pool,
            namespace: namespace.into(),
        })
    }

    /// Build a `RedisCache` for `namespace` from an already-constructed
    /// `deadpool-redis` [`Pool`].
    ///
    /// Lets the application share a single pool (and its configured size /
    /// timeouts) across the cache and any other Redis-backed feature
    /// (rate-limit buckets, SSE pub/sub — design: Persistence note).
    pub fn from_pool(pool: Pool, namespace: impl Into<String>) -> Self {
        Self {
            pool,
            namespace: namespace.into(),
        }
    }

    /// Check out a pooled connection, mapping a checkout failure (e.g. the
    /// server is unreachable or the pool is exhausted) to a typed
    /// `UpstreamUnavailable` [`AppError`] (Req 50.5).
    async fn conn(&self) -> Result<deadpool_redis::Connection, AppError> {
        self.pool
            .get()
            .await
            .map_err(|e| AppError::upstream_unavailable(format!("redis connection failed: {e}")))
    }
}

#[async_trait]
impl CacheBackend for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, AppError> {
        let physical = namespaced_key(&self.namespace, key);
        let mut conn = self.conn().await?;
        // An expired or never-written key yields `nil`, decoded as `None`
        // (Req 30.4): an expired entry is indistinguishable from a missing one.
        let value: Option<Vec<u8>> = conn
            .get(&physical)
            .await
            .map_err(|e| AppError::upstream_unavailable(format!("redis GET failed: {e}")))?;
        Ok(value.map(Bytes::from))
    }

    async fn set(&self, key: &str, val: Bytes, ttl: Duration) -> Result<(), AppError> {
        let physical = namespaced_key(&self.namespace, key);
        // Express the TTL as Redis `PX <millis>` so the server owns expiry
        // (Req 30.4). Clamp to at least 1ms: Redis rejects a non-positive
        // expire, and a sub-millisecond TTL still means "expire as soon as
        // possible" rather than "no expiry".
        let millis = ttl.as_millis().clamp(1, u64::MAX as u128) as u64;
        let opts = SetOptions::default().with_expiration(SetExpiry::PX(millis));
        let mut conn = self.conn().await?;
        // `SET key val PX <millis>` — the literal SET-with-expiry form.
        conn.set_options::<_, _, ()>(&physical, val.as_ref(), opts)
            .await
            .map_err(|e| AppError::upstream_unavailable(format!("redis SET failed: {e}")))?;
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<(), AppError> {
        let physical = namespaced_key(&self.namespace, key);
        let mut conn = self.conn().await?;
        // DEL on an absent key returns 0 and is not an error.
        conn.del::<_, ()>(&physical)
            .await
            .map_err(|e| AppError::upstream_unavailable(format!("redis DEL failed: {e}")))?;
        Ok(())
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Offline unit tests (no live Redis) ---------------------------------

    /// Pool construction is lazy: a `RedisCache` builds from a URL without
    /// opening a socket, and reports its configured namespace (Req 30.3). This
    /// runs in the default `cargo test` with no server present.
    #[test]
    fn from_url_builds_lazily_and_reports_namespace() {
        let cache = RedisCache::from_url("redis://127.0.0.1:6379", "ZippyPanther")
            .expect("pool construction is offline-safe");
        assert_eq!(cache.namespace(), "ZippyPanther");
    }

    /// An empty namespace is permitted (it adds no prefix — see
    /// [`namespaced_key`]).
    #[test]
    fn empty_namespace_is_allowed() {
        let cache = RedisCache::from_url("redis://127.0.0.1:6379", "")
            .expect("pool construction is offline-safe");
        assert_eq!(cache.namespace(), "");
    }

    /// A malformed Redis URL surfaces as a typed `AppError`, never a panic
    /// (Req 50.5).
    #[test]
    fn invalid_url_is_a_typed_error() {
        let err = match RedisCache::from_url("not-a-redis-url", "ns") {
            Ok(_) => panic!("a malformed URL must be rejected"),
            Err(e) => e,
        };
        assert_eq!(
            err.category,
            crate::errors::ErrorCategory::UpstreamUnavailable
        );
    }

    // -- Integration tests (gated on a reachable Redis) ---------------------
    //
    // These require a live server and are skipped when `REDIS_URL` is unset or
    // the server is unreachable, so the default `cargo test` stays green
    // without Redis. Set `REDIS_URL=redis://127.0.0.1:6379` to exercise them.

    /// Build a `RedisCache` against `REDIS_URL` and confirm it is reachable.
    /// Returns `None` (with a skip note) when the env var is unset or the
    /// server cannot be reached, so the caller can `return` early.
    async fn reachable_cache(namespace: &str) -> Option<RedisCache> {
        let url = std::env::var("REDIS_URL").ok()?;
        let cache = match RedisCache::from_url(url, namespace) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping redis integration test: {e}");
                return None;
            }
        };
        // Probe reachability with a PING so an unreachable server skips rather
        // than fails the suite.
        match cache.pool.get().await {
            Ok(mut conn) => {
                let pong: Result<String, _> = redis::cmd("PING").query_async(&mut *conn).await;
                if let Err(e) = pong {
                    eprintln!("skipping redis integration test (PING failed): {e}");
                    return None;
                }
            }
            Err(e) => {
                eprintln!("skipping redis integration test (unreachable): {e}");
                return None;
            }
        }
        Some(cache)
    }

    /// A unique logical key per test run so concurrent/repeat runs against a
    /// shared server never collide.
    fn unique_key(label: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("test:{label}:{nanos}")
    }

    /// Req 30.6 / 30.2: a value retrieved immediately after storing it under
    /// the same key returns the stored value, and `del` removes it.
    #[tokio::test]
    async fn get_set_del_round_trip_with_namespace() {
        let Some(cache) = reachable_cache("sf-test").await else {
            return;
        };
        let key = unique_key("round-trip");

        // Absent before write.
        assert_eq!(cache.get(&key).await.unwrap(), None);

        // Store + retrieve round trip.
        cache
            .set(&key, Bytes::from_static(b"hello"), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(
            cache.get(&key).await.unwrap(),
            Some(Bytes::from_static(b"hello")),
        );

        // Delete removes it.
        cache.del(&key).await.unwrap();
        assert_eq!(cache.get(&key).await.unwrap(), None);
    }

    /// `del` on an absent key is not an error.
    #[tokio::test]
    async fn del_absent_key_is_ok() {
        let Some(cache) = reachable_cache("sf-test").await else {
            return;
        };
        let key = unique_key("ghost");
        assert!(cache.del(&key).await.is_ok());
    }

    /// Req 30.3: every physical key is namespace-prefixed. We write through a
    /// namespaced cache and read the *physical* key back through a second
    /// cache with an empty namespace — using only the public API — proving the
    /// prefix was applied.
    #[tokio::test]
    async fn keys_are_namespace_prefixed() {
        let ns = unique_key("ns");
        let Some(namespaced) = reachable_cache(&ns).await else {
            return;
        };
        let Some(raw) = reachable_cache("").await else {
            return;
        };
        let logical = "session:42";

        namespaced
            .set(logical, Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();

        // The physical key is "{ns}:session:42"; reading it through the
        // empty-namespace cache (no prefix) must return the value, while the
        // bare logical key must be absent.
        let physical = format!("{ns}:{logical}");
        assert_eq!(
            raw.get(&physical).await.unwrap(),
            Some(Bytes::from_static(b"v")),
        );
        assert_eq!(raw.get(logical).await.unwrap(), None);

        // Cleanup.
        namespaced.del(logical).await.unwrap();
    }

    /// Req 30.4: once the per-entry TTL elapses, the entry is treated as
    /// absent (Redis `PX` expiry).
    #[tokio::test]
    async fn ttl_expiry_treats_entry_as_absent() {
        let Some(cache) = reachable_cache("sf-test").await else {
            return;
        };
        let key = unique_key("ttl");

        cache
            .set(&key, Bytes::from_static(b"v"), Duration::from_millis(100))
            .await
            .unwrap();
        // Present while unexpired.
        assert_eq!(
            cache.get(&key).await.unwrap(),
            Some(Bytes::from_static(b"v")),
        );

        // After the TTL elapses the entry is absent.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(cache.get(&key).await.unwrap(), None);
    }
}
