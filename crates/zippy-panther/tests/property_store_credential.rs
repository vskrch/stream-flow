//! Property-based test for per-user store credential resolution with `*`
//! wildcard fallback (`auth::Auth::resolve_store_credential`, task 9.4).
//!
//! Feature: ZippyPanther, Property 28
//!
//! **Property 28: Store credential resolution with wildcard fallback**
//!
//! *For any* configured set of `username:store:token` entries and any
//! `(username, store)` lookup, an exact username match is preferred; otherwise
//! the `*` wildcard entry is used; otherwise no credential is returned.
//!
//! **Validates: Requirements 28.4**
//!
//! Requirement 28.4: "WHEN a user accesses a store-backed endpoint, THE
//! Stream_Flow_System SHALL resolve the user's Per_User_Store_Credential as
//! `username:store:token`, applying a `*` username entry as the fallback when
//! no exact username match exists."
//!
//! ## How the invariant is exercised
//!
//! Each case generates an arbitrary list of `(username, store, token)` tuples
//! (drawn from small username/store pools — including the `*` wildcard
//! username — so exact hits, wildcard fallbacks, and misses all arise
//! naturally) plus an arbitrary `(username, store)` lookup. The tuples are
//! rendered into the `username:store:token` config form an [`Auth`] parses, and
//! an **independent oracle** built directly from the same tuples computes the
//! expected resolution. Usernames and stores are constrained to contain no `:`
//! so the rendered form round-trips faithfully, while tokens may embed `:` to
//! exercise the production `splitn(3, ':')` parse that keeps the colon-bearing
//! remainder as the token.
//!
//! The case asserts:
//!
//! * **Equality with the oracle:** `resolve_store_credential` returns exactly
//!   what the spec's preference order dictates (exact → `*` → none).
//! * **Preference (Req 28.4):** when an exact `(user, store)` entry exists, its
//!   token is returned even if a `(*, store)` entry also exists.
//! * **Fallback (Req 28.4):** when no exact entry exists but a `(*, store)`
//!   entry does, the wildcard token is returned.
//! * **Absence:** when neither exists, `None` is returned.

use std::collections::HashMap;

use proptest::prelude::*;
use zippy_panther::auth::Auth;
use zippy_panther::config::AuthConfig;

/// Build an [`Auth`] from a list of `username:store:token` entries, mirroring
/// how the config layer populates [`AuthConfig`].
fn auth_with_entries(entries: &[String]) -> Auth {
    let config = AuthConfig {
        api_password: None,
        metrics_password: None,
        proxy_auth: Vec::new(),
        per_user_store: entries.to_vec(),
        admins: Vec::new(),
    };
    Auth::from_config(&config)
}

/// Username pool — small so collisions (exact hits) are frequent, and includes
/// the literal `*` so wildcard entries are generated.
fn arb_username() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("alice".to_string()),
        Just("bob".to_string()),
        Just("carol".to_string()),
        Just("*".to_string()),
    ]
}

/// Store pool — plain store identifiers (never `*`), so a wildcard entry is
/// always keyed by username, never by store.
fn arb_store() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("realdebrid".to_string()),
        Just("alldebrid".to_string()),
        Just("torbox".to_string()),
    ]
}

/// Token — arbitrary short ASCII that MAY embed `:` (to exercise the
/// `splitn(3, ':')` parse) and MAY be empty (`user:store:`).
fn arb_token() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9:_-]{0,12}"
}

/// One configured `(username, store, token)` tuple.
fn arb_entry() -> impl Strategy<Value = (String, String, String)> {
    (arb_username(), arb_store(), arb_token())
}

/// A whole case: the configured entry tuples plus the `(username, store)`
/// lookup to resolve.
fn arb_case() -> impl Strategy<Value = (Vec<(String, String, String)>, String, String)> {
    (
        proptest::collection::vec(arb_entry(), 0..=16),
        arb_username(),
        arb_store(),
    )
}

/// Independent oracle for the spec's resolution order. Builds a
/// `(user, store) -> token` map from the tuples with the same last-write-wins
/// semantics as `Auth::from_config`, then applies exact → `*` → none.
fn expected(entries: &[(String, String, String)], user: &str, store: &str) -> Option<String> {
    let mut map: HashMap<(String, String), String> = HashMap::new();
    for (u, s, t) in entries {
        map.insert((u.clone(), s.clone()), t.clone());
    }
    map.get(&(user.to_string(), store.to_string()))
        .or_else(|| map.get(&("*".to_string(), store.to_string())))
        .cloned()
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 28 — store credential resolution with
    /// wildcard fallback. **Validates: Requirements 28.4**
    #[test]
    fn store_credential_resolution_prefers_exact_then_wildcard(
        (entries, user, store) in arb_case(),
    ) {
        let rendered: Vec<String> = entries
            .iter()
            .map(|(u, s, t)| format!("{u}:{s}:{t}"))
            .collect();
        let auth = auth_with_entries(&rendered);

        let actual = auth.resolve_store_credential(&user, &store);
        let want = expected(&entries, &user, &store);

        // -- Equality with the oracle ---------------------------------------
        prop_assert_eq!(
            actual,
            want.as_deref(),
            "lookup ({:?}, {:?}) over entries {:?}",
            user,
            store,
            entries,
        );

        // -- Structural guarantees of Req 28.4 ------------------------------
        // Reconstruct the parsed lookup map to classify this case explicitly.
        let mut map: HashMap<(String, String), String> = HashMap::new();
        for (u, s, t) in &entries {
            map.insert((u.clone(), s.clone()), t.clone());
        }
        let exact = map.get(&(user.clone(), store.clone()));
        let wildcard = map.get(&("*".to_string(), store.clone()));

        match (exact, wildcard) {
            // Preference: an exact entry wins, even when a wildcard also exists.
            (Some(exact_tok), _) => prop_assert_eq!(
                actual,
                Some(exact_tok.as_str()),
                "exact entry must be preferred for ({:?}, {:?})",
                user,
                store,
            ),
            // Fallback: no exact entry, but a per-store `*` entry exists.
            (None, Some(wild_tok)) => prop_assert_eq!(
                actual,
                Some(wild_tok.as_str()),
                "wildcard fallback must apply for ({:?}, {:?})",
                user,
                store,
            ),
            // Absence: neither an exact nor a wildcard entry exists.
            (None, None) => prop_assert!(
                actual.is_none(),
                "no credential must resolve for ({:?}, {:?})",
                user,
                store,
            ),
        }
    }
}
