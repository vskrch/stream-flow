//! Property-based test for the cache backend round trip, namespacing, and TTL
//! (task 4.4).
//!
//! Feature: stream-flow, Property 30
//!
//! **Property 30: Cache store/retrieve round trip, namespacing, and TTL**
//!
//! *For any* key/value and namespace, retrieving the value immediately after
//! storing it under the namespaced key returns the stored value while
//! unexpired, the same logical key is isolated across distinct namespaces, and
//! the entry is treated as absent once its TTL elapses.
//!
//! **Validates: Requirements 30.1, 30.3, 30.4, 30.6**
//!
//! The backend under test is [`stream_flow::cache::LocalCache`] — the
//! always-present in-process [`CacheBackend`] (moka, namespace-prefixed,
//! TTL + LRU). It is deterministic and needs no external server, so the
//! property exercises the real storage path rather than a mock. The three
//! invariants the requirement hinges on, asserted across arbitrary
//! namespaces, logical keys (including ones containing the namespace
//! separator), and byte-vector values (including empty):
//!
//! * **Round trip while unexpired (Req 30.6 / 30.1):** `get(k)` immediately
//!   after `set(k, v, ttl)` with a generous TTL returns exactly `Some(v)`.
//! * **Namespacing isolation (Req 30.3):** the physical key a backend touches
//!   is the namespace-prefixed logical key, so two distinct namespaces map the
//!   *same* logical key to *different* physical keys and never observe each
//!   other's value.
//! * **TTL expiry (Req 30.4):** once a short per-entry TTL elapses, `get(k)`
//!   returns `None` (an expired entry is indistinguishable from a missing one)
//!   and a subsequent `set` refreshes it.
//!
//! `proptest` cases run synchronously; each case drives the async
//! [`CacheBackend`] API on a per-case current-thread Tokio runtime. The TTL
//! used for the expiry arm is small but with a wide safety margin
//! (set well below the post-expiry wait) so the wall-clock assertion is
//! reliable rather than racy.

use std::time::Duration;

use bytes::Bytes;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use stream_flow::cache::{namespaced_key, CacheBackend, LocalCache, NAMESPACE_SEPARATOR};

/// A short-but-reliable TTL for the expiry arm. The post-expiry wait
/// ([`EXPIRY_WAIT`]) is several multiples of this, so by the time we re-`get`
/// the entry's deadline has comfortably passed.
const EXPIRY_TTL: Duration = Duration::from_millis(25);
/// How long to wait after [`EXPIRY_TTL`] before asserting the entry is absent.
const EXPIRY_WAIT: Duration = Duration::from_millis(120);
/// A generous TTL for the round-trip / isolation arms: long enough that the
/// entry is unambiguously unexpired for the duration of the case.
const LONG_TTL: Duration = Duration::from_secs(3_600);

/// Generates cache namespaces, including the empty "no prefix" namespace,
/// names containing the [`NAMESPACE_SEPARATOR`], and fully arbitrary strings.
/// Models "any namespace" (Req 30.3).
fn arb_namespace() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => Just(String::new()),
        5 => "[a-zA-Z0-9:_.\\-]{0,16}",
        2 => "stream-flow:[a-z]{1,8}",
        1 => any::<String>(),
    ]
}

/// Generates logical cache keys, including ones containing the namespace
/// separator (which must not break prefixing) and arbitrary strings.
fn arb_key() -> impl Strategy<Value = String> {
    prop_oneof![
        5 => "[a-zA-Z0-9:_.\\-]{1,32}",
        2 => "magnet:[0-9a-f]{4,12}",
        1 => "[^\u{0}]{1,48}",
    ]
}

/// Generates cache values as arbitrary byte vectors, including the empty value.
fn arb_value() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..256)
}

/// Build a per-case current-thread runtime with timers enabled.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime must build")
}

proptest! {
    // 128 cases (>= 100 required for a property task). Kept modest because the
    // TTL-expiry arm waits on a real (short) wall-clock interval per case.
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Feature: stream-flow, Property 30 — cache store/retrieve round trip,
    /// namespacing, and TTL. **Validates: Requirements 30.1, 30.3, 30.4, 30.6**
    #[test]
    fn cache_round_trip_namespacing_and_ttl(
        ns_a in arb_namespace(),
        ns_b in arb_namespace(),
        key in arb_key(),
        value_a in arb_value(),
        value_b in arb_value(),
    ) {
        let rt = runtime();
        let result: Result<(), TestCaseError> = rt.block_on(async {
            let bytes_a = Bytes::from(value_a.clone());
            let bytes_b = Bytes::from(value_b.clone());

            // -- Physical key construction is namespace-prefixed (Req 30.3) --
            // The single key-construction helper every backend uses: an empty
            // namespace adds no prefix, otherwise the physical key is
            // `"{namespace}{sep}{key}"`.
            let physical_a = namespaced_key(&ns_a, &key);
            if ns_a.is_empty() {
                prop_assert_eq!(
                    &physical_a, &key,
                    "an empty namespace must leave the logical key unchanged",
                );
            } else {
                let expected = format!("{ns_a}{NAMESPACE_SEPARATOR}{key}");
                prop_assert_eq!(
                    &physical_a, &expected,
                    "physical key must be the namespace-prefixed logical key",
                );
            }

            // -- Round trip while unexpired (Req 30.6 / 30.1) ----------------
            let cache_a = LocalCache::new(ns_a.clone());
            cache_a.set(&key, bytes_a.clone(), LONG_TTL).await.unwrap();
            prop_assert_eq!(
                cache_a.get(&key).await.unwrap(),
                Some(bytes_a.clone()),
                "get immediately after set (unexpired) must return the stored value",
            );
            // The backend reports the namespace it was built with.
            prop_assert_eq!(cache_a.namespace(), ns_a.as_str());

            // -- Namespacing isolation (Req 30.3) ----------------------------
            // A second cache under a (possibly different) namespace stores the
            // SAME logical key with a different value.
            let cache_b = LocalCache::new(ns_b.clone());
            cache_b.set(&key, bytes_b.clone(), LONG_TTL).await.unwrap();
            prop_assert_eq!(
                cache_b.get(&key).await.unwrap(),
                Some(bytes_b.clone()),
            );

            if ns_a != ns_b {
                // Distinct namespaces map the same logical key to distinct
                // physical keys — the heart of namespace isolation.
                prop_assert_ne!(
                    namespaced_key(&ns_a, &key),
                    namespaced_key(&ns_b, &key),
                    "distinct namespaces must produce distinct physical keys",
                );
            }
            // Either way, writing through `cache_b` never disturbs `cache_a`'s
            // view of the same logical key.
            prop_assert_eq!(
                cache_a.get(&key).await.unwrap(),
                Some(bytes_a.clone()),
                "a write under another namespace must not affect this entry",
            );

            // -- TTL expiry (Req 30.4) ---------------------------------------
            // A fresh entry with a short TTL is present immediately, then
            // treated as absent once the TTL elapses.
            cache_a.set(&key, bytes_a.clone(), EXPIRY_TTL).await.unwrap();
            prop_assert_eq!(
                cache_a.get(&key).await.unwrap(),
                Some(bytes_a.clone()),
                "entry must be present before its TTL elapses",
            );

            tokio::time::sleep(EXPIRY_TTL + EXPIRY_WAIT).await;
            prop_assert_eq!(
                cache_a.get(&key).await.unwrap(),
                None,
                "entry must be treated as absent once its TTL has elapsed",
            );

            // A subsequent set refreshes the expired entry (Req 30.4).
            cache_a.set(&key, bytes_b.clone(), LONG_TTL).await.unwrap();
            prop_assert_eq!(
                cache_a.get(&key).await.unwrap(),
                Some(bytes_b.clone()),
                "an expired entry must be refreshable by a subsequent set",
            );

            Ok(())
        });
        result?;
    }
}
