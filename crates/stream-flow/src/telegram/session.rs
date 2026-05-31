//! Telegram credential validation + session-string generation
//! (`telegram::session`) — Req 11.4, 11.5.
//!
//! This is the **pure**, always-compiled half of the Telegram surface: it
//! validates the configured MTProto credentials and session string and exposes
//! the *mechanism* for generating a session string from API credentials, all
//! without a live Telegram connection (design: Components → Telegram).
//!
//! ## Why this is testable without grammers
//!
//! A real MTProto login (and a real authorization check) requires the
//! `grammers-client` runtime and live Telegram servers, which cannot run in a
//! unit test. So the parts that *can* be decided locally are isolated here:
//!
//! * **Credential presence + shape** ([`ApiCredentials::new`],
//!   [`TelegramCredentials::from_config`]): an unset `api_id` (`0`), an
//!   empty/absent `api_hash`, or an empty/absent `session_string` is a
//!   configuration error surfaced *before* any network attempt (Req 11.5).
//! * **The generation orchestration** ([`generate_session_string`]): it
//!   validates the API credentials, drives an injected
//!   [`SessionAuthenticator`] (the seam the real grammers login implements),
//!   and rejects an empty exported session — all verifiable against a fake
//!   authenticator (Req 11.4).
//!
//! The actual interactive login (phone → code → optional 2FA → export) is the
//! [`SessionAuthenticator`] implementation, which the grammers-backed backend
//! provides; this module never imports grammers.

use async_trait::async_trait;

use crate::config::TelegramConfig;
use crate::errors::AppError;

/// Build the canonical "Telegram is not configured" error (Req 11.5).
///
/// Categorised as [`NotFound`](crate::errors::ErrorCategory::NotFound) (`404`):
/// the Telegram surface is *unavailable* because it was never configured,
/// mirroring how the other optional proxy surfaces (e.g. Xtream) report a
/// missing upstream. The message always names Telegram so the client can tell
/// the surface apart.
pub fn not_configured(detail: impl std::fmt::Display) -> AppError {
    AppError::not_found(format!(
        "Telegram MTProto proxy is not configured: {detail}"
    ))
}

/// Build the canonical "Telegram is not authorized" error (Req 11.5).
///
/// Categorised as [`Unauthorized`](crate::errors::ErrorCategory::Unauthorized)
/// (`401`): the API credentials are present but there is no usable session
/// string (the instance has not completed login), or the session is malformed.
pub fn not_authorized(detail: impl std::fmt::Display) -> AppError {
    AppError::unauthorized(format!(
        "Telegram MTProto proxy is not authorized: {detail}"
    ))
}

/// Validated Telegram API credentials: a non-zero `api_id` and a non-empty
/// `api_hash` (Req 11.5).
///
/// These identify the *application*, not the user session — they are required
/// both to download media and to generate a session string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiCredentials {
    api_id: i32,
    api_hash: String,
}

impl ApiCredentials {
    /// Validate and build [`ApiCredentials`] (Req 11.5).
    ///
    /// * `api_id` must be non-zero (Telegram issues positive application ids;
    ///   the config default of `0` means "unset").
    /// * `api_hash` must be present and non-empty after trimming.
    pub fn new(api_id: i32, api_hash: &str) -> Result<Self, AppError> {
        if api_id == 0 {
            return Err(not_configured("missing Telegram `api_id`"));
        }
        let api_hash = api_hash.trim();
        if api_hash.is_empty() {
            return Err(not_configured("missing Telegram `api_hash`"));
        }
        Ok(Self {
            api_id,
            api_hash: api_hash.to_string(),
        })
    }

    /// The validated application id.
    pub fn api_id(&self) -> i32 {
        self.api_id
    }

    /// The validated application hash.
    pub fn api_hash(&self) -> &str {
        &self.api_hash
    }
}

/// Fully validated Telegram credentials: [`ApiCredentials`] plus a present,
/// structurally-valid session string (Req 11.5).
///
/// Holding one of these is the local precondition for attempting an MTProto
/// download; a missing/empty session is reported as
/// [`not_authorized`](not_authorized) up front.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelegramCredentials {
    api: ApiCredentials,
    session_string: String,
}

impl TelegramCredentials {
    /// Validate the credentials carried by a [`TelegramConfig`] (Req 11.5).
    ///
    /// Returns:
    /// * [`not_configured`] when `api_id` is unset or `api_hash` is missing.
    /// * [`not_authorized`] when no (non-empty) `session_string` is present —
    ///   the app is configured but has not completed login.
    pub fn from_config(cfg: &TelegramConfig) -> Result<Self, AppError> {
        let api_hash = cfg
            .api_hash
            .as_ref()
            .map(|s| s.expose())
            .unwrap_or_default();
        let api = ApiCredentials::new(cfg.api_id, api_hash)?;

        let session_string = cfg
            .session_string
            .as_ref()
            .map(|s| s.expose())
            .unwrap_or_default()
            .trim()
            .to_string();
        if session_string.is_empty() {
            return Err(not_authorized("missing Telegram `session_string`"));
        }

        Ok(Self {
            api,
            session_string,
        })
    }

    /// The validated API credentials.
    pub fn api(&self) -> &ApiCredentials {
        &self.api
    }

    /// The validated session string.
    pub fn session_string(&self) -> &str {
        &self.session_string
    }
}

/// The interactive-login seam used to generate a session string (Req 11.4).
///
/// A real implementation (the grammers-backed backend) performs the MTProto
/// login flow — request a login code, sign in, satisfy any 2FA, then export the
/// session — and returns the exported session string. Abstracting it as a trait
/// keeps [`generate_session_string`]'s orchestration (credential validation +
/// empty-result rejection) verifiable against a fake without a live connection.
#[async_trait]
pub trait SessionAuthenticator: Send + Sync {
    /// Perform the login flow for `creds` and return the exported session
    /// string, or an [`AppError`] when login fails.
    async fn authenticate(&self, creds: &ApiCredentials) -> Result<String, AppError>;
}

/// The mechanism to generate a Telegram session string from API credentials
/// (Req 11.4).
///
/// Validates the API credentials first (so a missing `api_id`/`api_hash` is a
/// [`not_configured`] error before any login attempt), drives the injected
/// [`SessionAuthenticator`] login flow, and rejects an empty exported session
/// as [`not_authorized`]. The returned string is what an operator stores back
/// in `telegram.session_string` so future downloads are authorized.
pub async fn generate_session_string(
    api_id: i32,
    api_hash: &str,
    authenticator: &dyn SessionAuthenticator,
) -> Result<String, AppError> {
    let creds = ApiCredentials::new(api_id, api_hash)?;
    let session = authenticator.authenticate(&creds).await?;
    if session.trim().is_empty() {
        return Err(not_authorized(
            "session generation produced an empty session string",
        ));
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Secret, TelegramConfig};
    use crate::errors::ErrorCategory;

    fn cfg(api_id: i32, api_hash: Option<&str>, session: Option<&str>) -> TelegramConfig {
        TelegramConfig {
            api_id,
            api_hash: api_hash.map(Secret::from),
            session_string: session.map(Secret::from),
            max_connections: 8,
        }
    }

    // -- ApiCredentials validation (Req 11.5) -------------------------------

    #[test]
    fn api_credentials_require_non_zero_id() {
        let err = ApiCredentials::new(0, "abc").unwrap_err();
        assert_eq!(err.category, ErrorCategory::NotFound);
        assert!(err.message.contains("api_id"));
    }

    #[test]
    fn api_credentials_require_non_empty_hash() {
        let err = ApiCredentials::new(12345, "   ").unwrap_err();
        assert_eq!(err.category, ErrorCategory::NotFound);
        assert!(err.message.contains("api_hash"));
    }

    #[test]
    fn api_credentials_accept_valid_pair() {
        let creds = ApiCredentials::new(12345, " deadbeef ").expect("valid");
        assert_eq!(creds.api_id(), 12345);
        // Trimmed.
        assert_eq!(creds.api_hash(), "deadbeef");
    }

    // -- TelegramCredentials::from_config (Req 11.5) ------------------------

    #[test]
    fn from_config_default_is_not_configured() {
        // The default config has api_id 0 and no hash/session.
        let err = TelegramCredentials::from_config(&TelegramConfig::default()).unwrap_err();
        // Missing api_id is a configuration problem (404), checked first.
        assert_eq!(err.category, ErrorCategory::NotFound);
        assert!(err.message.to_lowercase().contains("telegram"));
    }

    #[test]
    fn from_config_missing_hash_is_not_configured() {
        let err = TelegramCredentials::from_config(&cfg(123, None, Some("sess"))).unwrap_err();
        assert_eq!(err.category, ErrorCategory::NotFound);
        assert!(err.message.contains("api_hash"));
    }

    #[test]
    fn from_config_missing_session_is_not_authorized() {
        // API credentials are present, but no session string → not authorized.
        let err = TelegramCredentials::from_config(&cfg(123, Some("hash"), None)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert!(err.message.contains("session_string"));
    }

    #[test]
    fn from_config_empty_session_is_not_authorized() {
        let err =
            TelegramCredentials::from_config(&cfg(123, Some("hash"), Some("   "))).unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
    }

    #[test]
    fn from_config_accepts_complete_credentials() {
        let creds = TelegramCredentials::from_config(&cfg(123, Some("hash"), Some(" my-session ")))
            .expect("valid");
        assert_eq!(creds.api().api_id(), 123);
        assert_eq!(creds.api().api_hash(), "hash");
        assert_eq!(creds.session_string(), "my-session");
    }

    #[test]
    fn not_configured_and_not_authorized_indicate_telegram() {
        // Req 11.5: the error must indicate Telegram is not configured/authorized.
        assert!(not_configured("x")
            .message
            .to_lowercase()
            .contains("telegram"));
        assert!(not_authorized("x")
            .message
            .to_lowercase()
            .contains("telegram"));
        assert_eq!(not_configured("x").category, ErrorCategory::NotFound);
        assert_eq!(not_authorized("x").category, ErrorCategory::Unauthorized);
    }

    // -- generate_session_string orchestration (Req 11.4) -------------------

    struct FakeAuth {
        result: Result<String, AppError>,
    }

    #[async_trait]
    impl SessionAuthenticator for FakeAuth {
        async fn authenticate(&self, _creds: &ApiCredentials) -> Result<String, AppError> {
            match &self.result {
                Ok(s) => Ok(s.clone()),
                Err(e) => Err(AppError::new(e.category, e.message.clone())),
            }
        }
    }

    #[tokio::test]
    async fn generate_session_validates_credentials_before_login() {
        // A bad api_id must fail fast, without ever calling the authenticator.
        struct PanicAuth;
        #[async_trait]
        impl SessionAuthenticator for PanicAuth {
            async fn authenticate(&self, _: &ApiCredentials) -> Result<String, AppError> {
                panic!("authenticator must not be called when credentials are invalid");
            }
        }
        let err = generate_session_string(0, "hash", &PanicAuth)
            .await
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::NotFound);
    }

    #[tokio::test]
    async fn generate_session_returns_exported_session() {
        let auth = FakeAuth {
            result: Ok("exported-session-string".to_string()),
        };
        let session = generate_session_string(123, "hash", &auth)
            .await
            .expect("session generated");
        assert_eq!(session, "exported-session-string");
    }

    #[tokio::test]
    async fn generate_session_rejects_empty_export() {
        let auth = FakeAuth {
            result: Ok("   ".to_string()),
        };
        let err = generate_session_string(123, "hash", &auth)
            .await
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
    }

    #[tokio::test]
    async fn generate_session_propagates_login_failure() {
        let auth = FakeAuth {
            result: Err(AppError::unauthorized("invalid login code")),
        };
        let err = generate_session_string(123, "hash", &auth)
            .await
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert!(err.message.contains("invalid login code"));
    }
}
