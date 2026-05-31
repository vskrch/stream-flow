//! Authentication, authorization, and proxy-link encryption (`auth`).
//!
//! This module groups the request-time security primitives (design:
//! Components → Auth). It owns the credential **verifiers** and **credential
//! resolution** (task 9.1, this file) and the AES-CBC URL-parameter encryption
//! used to seal proxy links (task 9.2, [`encryption`]). The actix
//! request-extraction wrappers live in [`middleware`].
//!
//! # The four verifiers (Req 28)
//!
//! All four are methods on [`Auth`], a parsed, immutable view of the
//! [`AuthConfig`](crate::config::AuthConfig) built once at startup with
//! [`Auth::from_config`]:
//!
//! * [`Auth::verify_api_password`] — guards protected Streaming_Proxy_Engine
//!   endpoints; `401 Unauthorized` when the presented `API_Password` is absent
//!   or incorrect (Req 28.1).
//! * [`Auth::verify_proxy_auth`] — validates the `X-StremThru-Authorization`
//!   header as HTTP Basic credentials, accepting **both** the plain
//!   `user:pass` form and its base64-encoded form, and resolving the matched
//!   [`UserId`]; `403 Forbidden` + an authenticate-challenge header on failure
//!   (Req 28.2, 28.3).
//! * [`Auth::resolve_store_credential`] — resolves a user's per-store token as
//!   `username:store:token`, preferring an exact username match and falling
//!   back to a `*` wildcard entry (Req 28.4).
//! * [`Auth::require_admin`] — authorizes administrative endpoints; `403
//!   Forbidden` for a non-admin user (Req 28.5, 28.6).
//!
//! # Constant-time secret comparison (Req 28.8)
//!
//! Every comparison of a secret value (the `API_Password`, Proxy_Auth
//! passwords, and store tokens) goes through [`constant_time_eq`], a
//! **double-HMAC** equality check: both sides are HMAC-SHA256'd under a fresh
//! random per-call key and the fixed-length 32-byte tags are compared with a
//! branch-free XOR-accumulate. Because only the equal-length tags are ever
//! compared, the check leaks neither the secret's bytes nor its length through
//! timing, and a wrong guess costs the same as a right one regardless of how
//! many leading bytes happen to match. This is the standard mitigation when a
//! dedicated `subtle`-style primitive is not pulled in (design: Components →
//! Auth, "constant-time compare via subtle/hmac-based equality").

pub mod encryption;
pub mod middleware;

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::AuthConfig;
use crate::errors::AppError;

type HmacSha256 = Hmac<Sha256>;

/// An authenticated user's identity — the `username` portion of a validated
/// Proxy_Auth credential (Req 28.2). Threaded onward so store calls resolve
/// *that* user's credentials (Req 28.4) and admin checks apply (Req 28.5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserId(pub String);

impl UserId {
    /// Borrow the username as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A parsed, immutable view of the auth-relevant configuration (Req 28).
///
/// Build it once at startup from the loaded [`AuthConfig`] with
/// [`Auth::from_config`]; it is cheap to clone-by-`Arc` into shared state and
/// is safe to share across worker threads.
#[derive(Clone, Debug, Default)]
pub struct Auth {
    /// The configured `API_Password`, or `None` for *no-auth* mode (the
    /// operator left it unset). When `None`, [`Auth::verify_api_password`]
    /// passes every request through — matching `mediaflow-proxy-light`'s
    /// drop-in behavior (Req 36.5).
    api_password: Option<String>,
    /// `username -> password` Proxy_Auth table parsed from the `user:pass`
    /// entries (Req 28.2). Multiple entries for the same user keep the last.
    proxy_auth: HashMap<String, String>,
    /// `(username, store) -> token` per-user store credentials parsed from the
    /// `username:store:token` entries, including any `*` wildcard usernames
    /// (Req 28.4).
    per_user_store: HashMap<(String, String), String>,
    /// Admin usernames (Req 28.5, 28.6).
    admins: Vec<String>,
}

impl Auth {
    /// Build the verifier view from the loaded [`AuthConfig`].
    ///
    /// The raw CSV-derived `user:pass` and `username:store:token` lists (config
    /// task 3.3) are parsed into lookup tables here. Malformed entries (missing
    /// the required separators) are skipped rather than aborting startup — the
    /// config layer is responsible for surfacing structurally-invalid config;
    /// here a junk entry simply never matches.
    pub fn from_config(config: &AuthConfig) -> Self {
        let api_password = config
            .api_password
            .as_ref()
            .map(|s| s.expose().to_string())
            .filter(|p| !p.is_empty());

        let mut proxy_auth = HashMap::new();
        for entry in &config.proxy_auth {
            // `user:pass` — the password may itself contain `:`, so split once.
            if let Some((user, pass)) = entry.split_once(':') {
                proxy_auth.insert(user.to_string(), pass.to_string());
            }
        }

        let mut per_user_store = HashMap::new();
        for entry in &config.per_user_store {
            // `username:store:token` — the token may contain `:`, so split into
            // at most three parts and keep the remainder as the token.
            let mut parts = entry.splitn(3, ':');
            if let (Some(user), Some(store), Some(token)) =
                (parts.next(), parts.next(), parts.next())
            {
                per_user_store.insert((user.to_string(), store.to_string()), token.to_string());
            }
        }

        Self {
            api_password,
            proxy_auth,
            per_user_store,
            admins: config.admins.clone(),
        }
    }

    /// `true` when no `API_Password` is configured (no-auth mode).
    pub fn is_open(&self) -> bool {
        self.api_password.is_none()
    }

    /// Verify the presented `API_Password` against the configured one
    /// (Req 28.1, 28.8).
    ///
    /// Returns `401 Unauthorized` when the password is **absent** (`None`) or
    /// **incorrect**. When no `API_Password` is configured the server is in
    /// no-auth mode and every request is accepted (drop-in parity with
    /// `mediaflow-proxy-light`). The comparison is constant-time
    /// ([`constant_time_eq`]).
    pub fn verify_api_password(&self, presented: Option<&str>) -> Result<(), AppError> {
        let Some(expected) = &self.api_password else {
            // No-auth mode: nothing to check.
            return Ok(());
        };
        match presented {
            Some(p) if constant_time_eq(expected.as_bytes(), p.as_bytes()) => Ok(()),
            _ => Err(AppError::unauthorized("invalid or missing API password")),
        }
    }

    /// Validate an `X-StremThru-Authorization` value as HTTP Basic credentials
    /// (Req 28.2, 28.3).
    ///
    /// The value may carry an optional `Basic ` scheme prefix and its credential
    /// portion may be **either** the plain `user:pass` form **or** its
    /// base64-encoded form; both are accepted and resolve to the matched
    /// [`UserId`]. Any other value — a malformed pair, an unknown user, or a
    /// wrong password — yields a `403 Forbidden` carrying the authenticate
    /// challenge header (rendered by the [`AppError`] response impl). The
    /// password comparison is constant-time ([`constant_time_eq`]).
    pub fn verify_proxy_auth(&self, header: Option<&str>) -> Result<UserId, AppError> {
        let challenge =
            || AppError::forbidden("invalid or missing proxy authorization").with_auth_challenge();

        let raw = header.ok_or_else(challenge)?;
        // Tolerate an optional `Basic ` scheme prefix (case-insensitive).
        let creds = strip_basic_scheme(raw).trim();

        // Form 1: plain `user:pass` straight from the header.
        if let Some(user) = self.match_basic_pair(creds) {
            return Ok(user);
        }

        // Form 2: base64(`user:pass`). A plain `user:pass` never decodes as
        // base64 (`:` is outside the base64 alphabet), so the two forms cannot
        // be confused.
        if let Some(decoded) = decode_base64_basic(creds) {
            if let Ok(pair) = std::str::from_utf8(&decoded) {
                if let Some(user) = self.match_basic_pair(pair) {
                    return Ok(user);
                }
            }
        }

        Err(challenge())
    }

    /// Match a decoded `user:pass` pair against the configured Proxy_Auth
    /// table, returning the [`UserId`] on a constant-time password match.
    fn match_basic_pair(&self, pair: &str) -> Option<UserId> {
        let (user, pass) = pair.split_once(':')?;
        if self.check_proxy_password(user, pass) {
            Some(UserId(user.to_string()))
        } else {
            None
        }
    }

    /// Constant-time check of `pass` against the configured password for
    /// `user`. Always performs a comparison (even for an unknown user) so the
    /// presence of a username is not revealed through timing.
    fn check_proxy_password(&self, user: &str, pass: &str) -> bool {
        match self.proxy_auth.get(user) {
            Some(expected) => constant_time_eq(expected.as_bytes(), pass.as_bytes()),
            None => {
                // Unknown user: run a same-shape comparison and discard it so
                // the not-found path costs the same as the found-but-wrong path.
                let _ = constant_time_eq(pass.as_bytes(), pass.as_bytes());
                false
            }
        }
    }

    /// Resolve a user's per-store credential token as `username:store:token`,
    /// preferring an exact username match and falling back to a `*` wildcard
    /// entry when no exact match exists (Req 28.4).
    ///
    /// Returns `None` when neither an exact `(user, store)` nor a `(*, store)`
    /// entry is configured.
    pub fn resolve_store_credential(&self, user: &str, store: &str) -> Option<&str> {
        if let Some(token) = self
            .per_user_store
            .get(&(user.to_string(), store.to_string()))
        {
            return Some(token.as_str());
        }
        self.per_user_store
            .get(&("*".to_string(), store.to_string()))
            .map(|t| t.as_str())
    }

    /// `true` when `user` is configured as an Admin_User (Req 28.5).
    pub fn is_admin(&self, user: &str) -> bool {
        self.admins.iter().any(|a| a == user)
    }

    /// Authorize an administrative endpoint: `Ok(())` for an Admin_User,
    /// `403 Forbidden` otherwise (Req 28.5, 28.6).
    pub fn require_admin(&self, user: &UserId) -> Result<(), AppError> {
        if self.is_admin(user.as_str()) {
            Ok(())
        } else {
            Err(AppError::forbidden(
                "administrative endpoint requires an admin user",
            ))
        }
    }
}

/// Strip an optional, case-insensitive `Basic ` scheme prefix from an
/// authorization header value, returning the credential portion unchanged when
/// no such prefix is present.
fn strip_basic_scheme(value: &str) -> &str {
    let trimmed = value.trim_start();
    if trimmed.len() >= 6 && trimmed[..6].eq_ignore_ascii_case("basic ") {
        &trimmed[6..]
    } else {
        trimmed
    }
}

/// Best-effort base64 decode of an HTTP Basic credential blob.
///
/// HTTP Basic uses standard base64; we also accept the unpadded variant so a
/// client that drops `=` padding still authenticates. Returns `None` when the
/// input is not valid base64 under either alphabet.
fn decode_base64_basic(creds: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    use base64::Engine as _;

    STANDARD
        .decode(creds)
        .or_else(|_| STANDARD_NO_PAD.decode(creds))
        .ok()
}

/// Constant-time equality of two secret byte strings (Req 28.8).
///
/// Uses the **double-HMAC** technique: both inputs are HMAC-SHA256'd under a
/// fresh random key drawn per call, and the resulting fixed-length 32-byte tags
/// are compared with a branch-free XOR-accumulate. Comparing only equal-length
/// tags means the running time is independent of the inputs' contents *and*
/// their lengths, so neither the secret's bytes nor its length leak through
/// timing. (HMAC under a secret random key is a PRF, so distinct inputs produce
/// colliding tags only with cryptographically negligible probability.)
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use rand::RngCore;

    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    let tag_a = hmac_tag(&key, a);
    let tag_b = hmac_tag(&key, b);

    let mut diff = 0u8;
    for i in 0..tag_a.len() {
        diff |= tag_a[i] ^ tag_b[i];
    }
    diff == 0
}

/// HMAC-SHA256 of `msg` under `key`, returning the 32-byte tag.
fn hmac_tag(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::errors::ErrorCategory;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    /// Build an [`Auth`] from explicit lists, mirroring how the config layer
    /// populates [`AuthConfig`].
    fn auth_with(
        api_password: Option<&str>,
        proxy_auth: &[&str],
        per_user_store: &[&str],
        admins: &[&str],
    ) -> Auth {
        let config = AuthConfig {
            api_password: api_password.map(Into::into),
            metrics_password: None,
            proxy_auth: proxy_auth.iter().map(|s| s.to_string()).collect(),
            per_user_store: per_user_store.iter().map(|s| s.to_string()).collect(),
            admins: admins.iter().map(|s| s.to_string()).collect(),
        };
        Auth::from_config(&config)
    }

    // -- verify_api_password (Req 28.1, 28.8) --------------------------------

    #[test]
    fn api_password_correct_is_accepted() {
        let auth = auth_with(Some("s3cret"), &[], &[], &[]);
        assert!(auth.verify_api_password(Some("s3cret")).is_ok());
    }

    #[test]
    fn api_password_absent_is_401() {
        let auth = auth_with(Some("s3cret"), &[], &[], &[]);
        let err = auth.verify_api_password(None).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
    }

    #[test]
    fn api_password_incorrect_is_401() {
        let auth = auth_with(Some("s3cret"), &[], &[], &[]);
        let err = auth.verify_api_password(Some("wrong")).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
    }

    #[test]
    fn api_password_wrong_prefix_is_401() {
        // A guess that shares a long common prefix must still be rejected (and
        // the constant-time compare must not short-circuit on the match).
        let auth = auth_with(Some("correct-horse-battery-staple"), &[], &[], &[]);
        let err = auth
            .verify_api_password(Some("correct-horse-battery-stapl"))
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
    }

    #[test]
    fn no_api_password_configured_is_open_mode() {
        // No-auth mode: drop-in parity with mediaflow-proxy-light.
        let auth = auth_with(None, &[], &[], &[]);
        assert!(auth.is_open());
        assert!(auth.verify_api_password(None).is_ok());
        assert!(auth.verify_api_password(Some("anything")).is_ok());
    }

    #[test]
    fn empty_api_password_is_treated_as_open_mode() {
        let auth = auth_with(Some(""), &[], &[], &[]);
        assert!(auth.is_open());
        assert!(auth.verify_api_password(None).is_ok());
    }

    // -- verify_proxy_auth (Req 28.2, 28.3) ----------------------------------

    #[test]
    fn proxy_auth_accepts_plain_user_pass() {
        let auth = auth_with(Some("x"), &["alice:wonderland"], &[], &[]);
        let user = auth.verify_proxy_auth(Some("alice:wonderland")).unwrap();
        assert_eq!(user, UserId("alice".to_string()));
    }

    #[test]
    fn proxy_auth_accepts_base64_user_pass() {
        let auth = auth_with(Some("x"), &["alice:wonderland"], &[], &[]);
        let encoded = STANDARD.encode("alice:wonderland");
        let user = auth.verify_proxy_auth(Some(&encoded)).unwrap();
        assert_eq!(user, UserId("alice".to_string()));
    }

    #[test]
    fn proxy_auth_accepts_basic_scheme_prefix_with_base64() {
        let auth = auth_with(Some("x"), &["bob:builder"], &[], &[]);
        let encoded = STANDARD.encode("bob:builder");
        let header = format!("Basic {encoded}");
        let user = auth.verify_proxy_auth(Some(&header)).unwrap();
        assert_eq!(user, UserId("bob".to_string()));
    }

    #[test]
    fn proxy_auth_scheme_prefix_is_case_insensitive() {
        let auth = auth_with(Some("x"), &["bob:builder"], &[], &[]);
        let user = auth.verify_proxy_auth(Some("basic bob:builder")).unwrap();
        assert_eq!(user, UserId("bob".to_string()));
    }

    #[test]
    fn proxy_auth_wrong_password_is_403_with_challenge() {
        let auth = auth_with(Some("x"), &["alice:wonderland"], &[], &[]);
        let err = auth.verify_proxy_auth(Some("alice:wrong")).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.auth_challenge, "failure must advertise a challenge");
    }

    #[test]
    fn proxy_auth_unknown_user_is_403() {
        let auth = auth_with(Some("x"), &["alice:wonderland"], &[], &[]);
        let err = auth.verify_proxy_auth(Some("mallory:secret")).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.auth_challenge);
    }

    #[test]
    fn proxy_auth_absent_header_is_403() {
        let auth = auth_with(Some("x"), &["alice:wonderland"], &[], &[]);
        let err = auth.verify_proxy_auth(None).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.auth_challenge);
    }

    #[test]
    fn proxy_auth_garbage_value_is_403() {
        let auth = auth_with(Some("x"), &["alice:wonderland"], &[], &[]);
        // No colon, not valid base64 of a user:pass pair.
        let err = auth
            .verify_proxy_auth(Some("not-a-credential"))
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    #[test]
    fn proxy_auth_password_may_contain_colons() {
        let auth = auth_with(Some("x"), &["alice:pa:ss:word"], &[], &[]);
        let user = auth.verify_proxy_auth(Some("alice:pa:ss:word")).unwrap();
        assert_eq!(user, UserId("alice".to_string()));
        // Base64 form of the same pair also works.
        let encoded = STANDARD.encode("alice:pa:ss:word");
        assert_eq!(
            auth.verify_proxy_auth(Some(&encoded)).unwrap(),
            UserId("alice".to_string())
        );
    }

    // -- resolve_store_credential (Req 28.4) ---------------------------------

    #[test]
    fn store_credential_exact_match_is_preferred() {
        let auth = auth_with(
            Some("x"),
            &[],
            &["alice:realdebrid:alice-token", "*:realdebrid:shared-token"],
            &[],
        );
        assert_eq!(
            auth.resolve_store_credential("alice", "realdebrid"),
            Some("alice-token")
        );
    }

    #[test]
    fn store_credential_falls_back_to_wildcard() {
        let auth = auth_with(
            Some("x"),
            &[],
            &["alice:realdebrid:alice-token", "*:realdebrid:shared-token"],
            &[],
        );
        // No exact entry for bob -> the `*` wildcard token is used.
        assert_eq!(
            auth.resolve_store_credential("bob", "realdebrid"),
            Some("shared-token")
        );
    }

    #[test]
    fn store_credential_none_when_no_match() {
        let auth = auth_with(Some("x"), &[], &["alice:realdebrid:tok"], &[]);
        // Different store, no wildcard -> nothing.
        assert_eq!(auth.resolve_store_credential("alice", "alldebrid"), None);
        // Different user, no wildcard -> nothing.
        assert_eq!(auth.resolve_store_credential("bob", "realdebrid"), None);
    }

    #[test]
    fn store_credential_token_may_contain_colons() {
        let auth = auth_with(Some("x"), &[], &["alice:premiumize:a:b:c"], &[]);
        assert_eq!(
            auth.resolve_store_credential("alice", "premiumize"),
            Some("a:b:c")
        );
    }

    #[test]
    fn store_credential_wildcard_is_per_store() {
        let auth = auth_with(Some("x"), &[], &["*:realdebrid:shared"], &[]);
        // Wildcard only covers the store it was configured for.
        assert_eq!(
            auth.resolve_store_credential("bob", "realdebrid"),
            Some("shared")
        );
        assert_eq!(auth.resolve_store_credential("bob", "torbox"), None);
    }

    // -- require_admin (Req 28.5, 28.6) --------------------------------------

    #[test]
    fn require_admin_allows_configured_admin() {
        let auth = auth_with(Some("x"), &[], &[], &["root", "ops"]);
        assert!(auth.require_admin(&UserId("root".to_string())).is_ok());
        assert!(auth.is_admin("ops"));
    }

    #[test]
    fn require_admin_rejects_non_admin_with_403() {
        let auth = auth_with(Some("x"), &[], &[], &["root"]);
        let err = auth
            .require_admin(&UserId("alice".to_string()))
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(!auth.is_admin("alice"));
    }

    #[test]
    fn require_admin_rejects_when_no_admins_configured() {
        let auth = auth_with(Some("x"), &[], &[], &[]);
        let err = auth
            .require_admin(&UserId("anyone".to_string()))
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    // -- constant_time_eq (Req 28.8) -----------------------------------------

    #[test]
    fn constant_time_eq_matches_only_identical_inputs() {
        assert!(constant_time_eq(b"hunter2", b"hunter2"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"hunter2", b"hunter3"));
        // Different lengths must compare unequal (and not panic).
        assert!(!constant_time_eq(b"short", b"a-much-longer-secret"));
        assert!(!constant_time_eq(b"prefix", b"prefix-extra"));
    }
}
