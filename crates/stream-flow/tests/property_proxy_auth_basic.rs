//! Property-based test for HTTP Basic proxy-auth (`Auth::verify_proxy_auth`,
//! task 9.3).
//!
//! Feature: stream-flow, Property 27
//!
//! **Property 27: HTTP Basic proxy-auth accepts plain and base64 forms**
//!
//! *For any* `user:pass` credential, validation succeeds for both the plain
//! `user:pass` form and its base64-encoded form, and fails for any other value.
//!
//! **Validates: Requirements 28.2**
//!
//! Requirement 28.2: "WHEN a request presents an `X-StremThru-Authorization`
//! header, THE Stream_Flow_System SHALL validate it as HTTP Basic credentials
//! against the configured Proxy_Auth credentials, accepting both plain and
//! base64-encoded forms."
//!
//! ## How the property is exercised
//!
//! Each case builds an [`Auth`] from a configured set of unique-username
//! `user:pass` Proxy_Auth credentials (the table the verifier checks against)
//! and asserts the two halves of Property 27 on
//! [`Auth::verify_proxy_auth`](stream_flow::auth::Auth::verify_proxy_auth):
//!
//! * **Acceptance (Req 28.2):** for every configured credential, presenting
//!   *both* the plain `user:pass` form *and* its base64-encoded form (each also
//!   under an optional, case-insensitive `Basic ` scheme prefix) succeeds and
//!   resolves to the matching [`UserId`].
//! * **Rejection (Req 28.2 / 28.3):** for any candidate `user:pass` pair that
//!   is *not* one of the configured credentials, presenting either the plain or
//!   the base64-encoded form fails with a `403 Forbidden` that advertises the
//!   authenticate challenge. A non-credential garbage value is rejected the
//!   same way.
//!
//! The verifier is also **total**: it returns either `Ok(UserId)` or a typed
//! [`AppError`](stream_flow::errors::AppError) without ever panicking (proptest
//! fails the property on any panic).

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use proptest::prelude::*;
use stream_flow::auth::{Auth, UserId};
use stream_flow::config::AuthConfig;
use stream_flow::errors::ErrorCategory;

/// Build an [`Auth`] whose Proxy_Auth table is exactly `creds`
/// (`username -> password`), mirroring how the config layer populates
/// [`AuthConfig::proxy_auth`] from `user:pass` entries.
fn auth_with_creds(creds: &BTreeMap<String, String>) -> Auth {
    let proxy_auth: Vec<String> = creds
        .iter()
        .map(|(user, pass)| format!("{user}:{pass}"))
        .collect();
    let config = AuthConfig {
        // A configured API password keeps the server out of no-auth mode; it is
        // orthogonal to proxy-auth verification but realistic.
        api_password: Some("api-secret".into()),
        metrics_password: None,
        proxy_auth,
        per_user_store: Vec::new(),
        admins: Vec::new(),
    };
    Auth::from_config(&config)
}

/// Arbitrary Proxy_Auth username: non-empty, free of `:` (the config/header
/// `user:pass` separator), of surrounding whitespace, and of any character
/// that could form the optional `Basic ` scheme prefix. This is the realistic
/// shape of a configured username and round-trips cleanly through both the
/// plain and base64 forms.
fn arb_username() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_.-]{1,12}"
}

/// Arbitrary Proxy_Auth password. It MAY contain `:` (passwords with embedded
/// colons must still validate — the header is split only on the first colon)
/// and may be empty, but carries no whitespace so that the verifier's
/// whole-value `trim()` cannot alter it.
fn arb_password() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_.:@!#$%^&*()+-]{0,16}"
}

/// A non-empty map of configured credentials keyed by unique username (the
/// `BTreeMap` collapses duplicate usernames the way the verifier's
/// last-entry-wins `HashMap` would, so the generated table is unambiguous).
fn arb_creds() -> impl Strategy<Value = BTreeMap<String, String>> {
    proptest::collection::vec((arb_username(), arb_password()), 1..=6).prop_map(|pairs| {
        pairs.into_iter().collect::<BTreeMap<String, String>>()
    })
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 27 — every configured `user:pass`
    /// credential validates in both its plain and base64-encoded forms.
    /// **Validates: Requirements 28.2**
    #[test]
    fn proxy_auth_accepts_plain_and_base64_for_every_credential(
        creds in arb_creds(),
    ) {
        let auth = auth_with_creds(&creds);

        for (user, pass) in &creds {
            let plain = format!("{user}:{pass}");
            let encoded = STANDARD.encode(&plain);
            let expected = UserId(user.clone());

            // -- Plain `user:pass` form (Req 28.2) ---------------------------
            let via_plain = auth
                .verify_proxy_auth(Some(&plain))
                .expect("plain form should authenticate a configured credential");
            prop_assert_eq!(
                &via_plain,
                &expected,
                "plain form {:?} should resolve to {:?}",
                plain,
                user,
            );

            // -- base64(`user:pass`) form (Req 28.2) -------------------------
            let via_b64 = auth
                .verify_proxy_auth(Some(&encoded))
                .expect("base64 form should authenticate a configured credential");
            prop_assert_eq!(
                &via_b64,
                &expected,
                "base64 form {:?} of {:?} should resolve to {:?}",
                encoded,
                plain,
                user,
            );

            // -- Both forms also accepted under an optional `Basic ` scheme
            //    prefix (the header may carry it; matching is case-insensitive).
            let plain_scheme = format!("Basic {plain}");
            let encoded_scheme = format!("basic {encoded}");
            let via_plain_scheme = auth
                .verify_proxy_auth(Some(&plain_scheme))
                .expect("scheme-prefixed plain form should authenticate");
            prop_assert_eq!(
                &via_plain_scheme,
                &expected,
                "scheme-prefixed plain form {:?} should resolve to {:?}",
                plain_scheme,
                user,
            );
            let via_encoded_scheme = auth
                .verify_proxy_auth(Some(&encoded_scheme))
                .expect("scheme-prefixed base64 form should authenticate");
            prop_assert_eq!(
                &via_encoded_scheme,
                &expected,
                "scheme-prefixed base64 form {:?} should resolve to {:?}",
                encoded_scheme,
                user,
            );
        }
    }

    /// Feature: stream-flow, Property 27 — any value that is not one of the
    /// configured credentials (in either form) is rejected with a `403` + the
    /// authenticate challenge. **Validates: Requirements 28.2**
    #[test]
    fn proxy_auth_rejects_any_non_credential(
        creds in arb_creds(),
        cand_user in arb_username(),
        cand_pass in arb_password(),
        garbage in "[A-Za-z0-9]{0,10}\\.[A-Za-z0-9]{0,10}",
    ) {
        let auth = auth_with_creds(&creds);

        // The candidate pair is "valid" iff it matches a configured entry
        // exactly; only the genuinely-non-matching pairs exercise rejection.
        let is_configured = creds.get(&cand_user) == Some(&cand_pass);
        prop_assume!(!is_configured);

        let plain = format!("{cand_user}:{cand_pass}");
        let encoded = STANDARD.encode(&plain);

        // -- Plain non-credential form is rejected (Req 28.2 / 28.3) ---------
        let plain_err = auth
            .verify_proxy_auth(Some(&plain))
            .expect_err("a non-credential plain pair must be rejected");
        prop_assert_eq!(plain_err.category, ErrorCategory::Forbidden);
        prop_assert!(
            plain_err.auth_challenge,
            "rejection must advertise the authenticate challenge",
        );

        // -- base64 non-credential form is rejected the same way -------------
        let encoded_err = auth
            .verify_proxy_auth(Some(&encoded))
            .expect_err("a non-credential base64 pair must be rejected");
        prop_assert_eq!(encoded_err.category, ErrorCategory::Forbidden);
        prop_assert!(encoded_err.auth_challenge);

        // -- A value carrying no `user:pass` pair at all is also rejected ----
        // `garbage` contains a `.` and no `:`, so it is neither a plain pair
        // nor valid base64 (the `.` is outside the base64 alphabet); it must
        // fail closed rather than authenticate anyone.
        let garbage_err = auth
            .verify_proxy_auth(Some(&garbage))
            .expect_err("a non-credential garbage value must be rejected");
        prop_assert_eq!(garbage_err.category, ErrorCategory::Forbidden);
        prop_assert!(garbage_err.auth_challenge);
    }
}
