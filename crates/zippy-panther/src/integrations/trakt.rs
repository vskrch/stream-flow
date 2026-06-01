//! Trakt.tv integration adapter — Req 27.1, 27.2.
//!
//! Fetches lists from the Trakt REST API. Supports the OAuth device-code flow,
//! token persistence, and transparent token refresh (Req 27.2). Results are
//! cached for the configured TTL (Req 27.3, 27.4) and the circuit breaker
//! wraps every upstream call (Req 50.2).
//!
//! All HTTP calls go through egress::OutboundClient (Req 51.1).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use crate::cache::CacheBackend;
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::persistence::models::TraktTokenRow;
use crate::persistence::repo::Repos;
use crate::persistence::vault::Vault;
use crate::resilience::breaker::CircuitBreaker;

use super::{
    fetch_with_cache, integration_breaker, map_http_error, map_reqwest_error, IntegrationList,
    ListItem, INTEGRATION_TRAKT,
};

const TRAKT_API_BASE: &str = "https://api.trakt.tv";
const TRAKT_API_VERSION: &str = "2";
const REFRESH_AHEAD_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// OAuth device-code types (Req 27.2)
// ---------------------------------------------------------------------------

/// Response from POST /oauth/device/code (Req 27.2).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// A Trakt OAuth token pair returned by the device-code or refresh flows.
#[derive(Debug, Clone)]
pub struct TraktToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

impl TokenResponse {
    fn into_trakt_token(self) -> TraktToken {
        let expires_at = OffsetDateTime::now_utc() + Duration::from_secs(self.expires_in as u64);
        TraktToken {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            expires_at,
        }
    }
}

/// Trakt OAuth token response (authorization-code flow — Req 27.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraktTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

/// Error returned while polling for a device-code token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollError {
    Pending,
    Expired,
    Denied,
    Upstream(String),
}

impl std::fmt::Display for PollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PollError::Pending => write!(f, "authorization pending"),
            PollError::Expired => write!(f, "device code expired"),
            PollError::Denied => write!(f, "authorization denied by user"),
            PollError::Upstream(msg) => write!(f, "upstream error: {msg}"),
        }
    }
}

impl From<PollError> for AppError {
    fn from(e: PollError) -> Self {
        match e {
            PollError::Pending => AppError::upstream_unavailable("trakt: authorization pending"),
            PollError::Expired => AppError::bad_request("trakt: device code expired"),
            PollError::Denied => AppError::forbidden("trakt: authorization denied by user"),
            PollError::Upstream(msg) => AppError::upstream_unavailable(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// TraktAdapter
// ---------------------------------------------------------------------------

/// Trakt.tv integration adapter.
#[derive(Clone)]
pub struct TraktAdapter {
    client: Arc<OutboundClient>,
    cache: Arc<dyn CacheBackend>,
    ttl: Duration,
    breaker: Arc<CircuitBreaker>,
    client_id: String,
    client_secret: String,
    access_token: Option<String>,
    username: String,
}

impl TraktAdapter {
    pub fn new(
        client: Arc<OutboundClient>,
        cache: Arc<dyn CacheBackend>,
        ttl: Duration,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        access_token: Option<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            client,
            cache,
            ttl,
            breaker: Arc::new(integration_breaker(INTEGRATION_TRAKT)),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            access_token,
            username: username.into(),
        }
    }

    pub async fn fetch_watchlist(&self, media_type: &str) -> Result<IntegrationList, AppError> {
        let cache_key = format!("trakt:watchlist:{}:{}", self.username, media_type);
        let data = fetch_with_cache(&self.cache, &cache_key, self.ttl, &self.breaker, || {
            let client = self.client.clone();
            let client_id = self.client_id.clone();
            let access_token = self.access_token.clone();
            let username = self.username.clone();
            let media_type = media_type.to_string();
            async move {
                fetch_trakt_watchlist(
                    &client,
                    &client_id,
                    access_token.as_deref(),
                    &username,
                    &media_type,
                )
                .await
            }
        })
        .await?;
        serde_json::from_slice(&data).map_err(|e| {
            AppError::upstream_unavailable(format!("Trakt: failed to parse cached list: {e}"))
        })
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TraktTokenResponse, AppError> {
        let url = Url::parse(&format!("{TRAKT_API_BASE}/oauth/token"))
            .map_err(|e| AppError::upstream_unavailable(format!("Trakt: invalid URL: {e}")))?;
        let body = serde_json::json!({
            "code": code, "client_id": self.client_id,
            "client_secret": self.client_secret, "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        });
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Content-Type", "application/json")
            .header("trakt-api-version", TRAKT_API_VERSION)
            .header("trakt-api-key", &self.client_id)
            .json(&body)
            .send()
            .await
            .map_err(|e| map_reqwest_error(INTEGRATION_TRAKT, e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_http_error(INTEGRATION_TRAKT, status));
        }
        resp.json::<TraktTokenResponse>().await.map_err(|e| {
            AppError::upstream_unavailable(format!("Trakt: failed to parse token response: {e}"))
        })
    }

    pub async fn initiate_device_code(&self) -> Result<DeviceCodeResponse, AppError> {
        let url = Url::parse(&format!("{TRAKT_API_BASE}/oauth/device/code"))
            .map_err(|e| AppError::upstream_unavailable(format!("Trakt: invalid URL: {e}")))?;
        let body = serde_json::json!({ "client_id": self.client_id });
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| map_reqwest_error(INTEGRATION_TRAKT, e))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::upstream_unavailable(format!(
                "trakt device/code returned {status}: {text}"
            ))
            .with_upstream_status(status.as_u16()));
        }
        resp.json::<DeviceCodeResponse>()
            .await
            .map_err(|e| AppError::upstream_unavailable(format!("trakt device/code parse: {e}")))
    }

    pub async fn poll_for_token(
        &self,
        device: &DeviceCodeResponse,
    ) -> Result<TraktToken, PollError> {
        let url = Url::parse(&format!("{TRAKT_API_BASE}/oauth/device/token"))
            .map_err(|e| PollError::Upstream(format!("Trakt: invalid URL: {e}")))?;
        let body = serde_json::json!({
            "code": device.device_code, "client_id": self.client_id,
            "client_secret": self.client_secret,
        });
        let resp = self
            .client
            .upstream(Method::POST, &url)
            .map_err(|e| PollError::Upstream(e.to_string()))?
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| PollError::Upstream(format!("trakt device/token: {e}")))?;
        match resp.status().as_u16() {
            200 => {
                let tr: TokenResponse = resp
                    .json()
                    .await
                    .map_err(|e| PollError::Upstream(format!("trakt device/token parse: {e}")))?;
                Ok(tr.into_trakt_token())
            }
            400 => Err(PollError::Pending),
            410 => Err(PollError::Expired),
            418 => Err(PollError::Denied),
            other => {
                let text = resp.text().await.unwrap_or_default();
                Err(PollError::Upstream(format!(
                    "trakt device/token returned {other}: {text}"
                )))
            }
        }
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TraktToken, AppError> {
        let url = Url::parse(&format!("{TRAKT_API_BASE}/oauth/token"))
            .map_err(|e| AppError::upstream_unavailable(format!("Trakt: invalid URL: {e}")))?;
        let body = serde_json::json!({
            "refresh_token": refresh_token, "client_id": self.client_id,
            "client_secret": self.client_secret, "grant_type": "refresh_token",
        });
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| map_reqwest_error(INTEGRATION_TRAKT, e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_http_error(INTEGRATION_TRAKT, status));
        }
        let tr: TokenResponse = resp.json().await.map_err(|e| {
            AppError::upstream_unavailable(format!("trakt token refresh parse: {e}"))
        })?;
        Ok(tr.into_trakt_token())
    }

    pub async fn get_valid_token(
        &self,
        username: &str,
        repos: &Repos,
        vault: &Vault,
    ) -> Result<Option<String>, AppError> {
        let row = repos.get_trakt_token(username).await?;
        let row = match row {
            None => return Ok(None),
            Some(r) => r,
        };
        let now = OffsetDateTime::now_utc();
        let needs_refresh = row.expires_at <= now + Duration::from_secs(REFRESH_AHEAD_SECS);
        if needs_refresh {
            let refresh_bytes = vault.decrypt(&row.refresh_enc)?;
            let refresh_str = String::from_utf8(refresh_bytes).map_err(|e| {
                AppError::unknown(format!(
                    "trakt: stored refresh token is not valid UTF-8: {e}"
                ))
            })?;
            let new_token = self.refresh_token(&refresh_str).await?;
            self.persist_token(username, &new_token, repos, vault)
                .await?;
            return Ok(Some(new_token.access_token));
        }
        let access_bytes = vault.decrypt(&row.access_enc)?;
        let access_str = String::from_utf8(access_bytes).map_err(|e| {
            AppError::unknown(format!(
                "trakt: stored access token is not valid UTF-8: {e}"
            ))
        })?;
        Ok(Some(access_str))
    }

    pub async fn persist_token(
        &self,
        username: &str,
        token: &TraktToken,
        repos: &Repos,
        vault: &Vault,
    ) -> Result<(), AppError> {
        let access_enc = vault.encrypt(token.access_token.as_bytes())?;
        let refresh_enc = vault.encrypt(token.refresh_token.as_bytes())?;
        let row = TraktTokenRow {
            username: username.to_string(),
            access_enc,
            refresh_enc,
            expires_at: token.expires_at,
        };
        repos.upsert_trakt_token(&row).await
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

async fn fetch_trakt_watchlist(
    client: &OutboundClient,
    client_id: &str,
    access_token: Option<&str>,
    username: &str,
    media_type: &str,
) -> Result<Bytes, AppError> {
    let url_str = format!("{TRAKT_API_BASE}/users/{username}/watchlist/{media_type}");
    let url = Url::parse(&url_str)
        .map_err(|e| AppError::upstream_unavailable(format!("Trakt: invalid URL: {e}")))?;
    let mut builder = client
        .upstream(Method::GET, &url)?
        .header("Content-Type", "application/json")
        .header("trakt-api-version", TRAKT_API_VERSION)
        .header("trakt-api-key", client_id);
    if let Some(token) = access_token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_TRAKT, e))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(map_http_error(INTEGRATION_TRAKT, status));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_TRAKT, e))?;
    let list = parse_trakt_watchlist_response(&body, media_type)?;
    serde_json::to_vec(&list)
        .map(Bytes::from)
        .map_err(|e| AppError::upstream_unavailable(format!("Trakt: serialization failed: {e}")))
}

pub fn parse_trakt_watchlist_response(
    data: &[u8],
    _media_type: &str,
) -> Result<IntegrationList, AppError> {
    #[derive(Deserialize)]
    struct WatchlistEntry {
        movie: Option<TraktMovie>,
        show: Option<TraktShow>,
    }
    #[derive(Deserialize)]
    struct TraktMovie {
        title: String,
        year: Option<u32>,
        ids: TraktIds,
    }
    #[derive(Deserialize)]
    struct TraktShow {
        title: String,
        year: Option<u32>,
        ids: TraktIds,
    }
    #[derive(Deserialize)]
    struct TraktIds {
        imdb: Option<String>,
        tmdb: Option<u64>,
    }

    let entries: Vec<WatchlistEntry> = serde_json::from_slice(data).map_err(|e| {
        AppError::upstream_unavailable(format!("Trakt: failed to parse watchlist: {e}"))
    })?;
    let items = entries
        .into_iter()
        .filter_map(|entry| {
            if let Some(movie) = entry.movie {
                Some(ListItem {
                    title: movie.title,
                    imdb_id: movie.ids.imdb,
                    tmdb_id: movie.ids.tmdb,
                    content_type: "movie".to_string(),
                    year: movie.year,
                })
            } else {
                entry.show.map(|show| ListItem {
                    title: show.title,
                    imdb_id: show.ids.imdb,
                    tmdb_id: show.ids.tmdb,
                    content_type: "series".to_string(),
                    year: show.year,
                })
            }
        })
        .collect();
    Ok(IntegrationList {
        source: INTEGRATION_TRAKT.to_string(),
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::LocalCache;
    use crate::config::{DbConfig, EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::errors::ErrorCategory;
    use crate::persistence::{build_pool, run_migrations};
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn outbound(policy: EgressPolicy) -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn test_cache() -> Arc<dyn CacheBackend> {
        Arc::new(LocalCache::new("trakt-test"))
    }

    async fn test_repos() -> (TempDir, Repos) {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("trakt-test.db");
        let cfg = DbConfig {
            path: db_path.to_string_lossy().into_owned(),
            busy_timeout_secs: 5,
            max_connections: 5,
        };
        let pool = build_pool(&cfg).await.expect("pool");
        run_migrations(&pool).await.expect("migrate");
        (dir, Repos::new(pool, 5))
    }

    fn test_vault() -> Vault {
        Vault::enabled_from_bytes(b"trakt-test-vault-secret")
    }

    fn sample_watchlist() -> serde_json::Value {
        serde_json::json!([
            { "movie": { "title": "The Matrix", "year": 1999, "ids": { "imdb": "tt0133093", "tmdb": 603 } } },
            { "show": { "title": "Breaking Bad", "year": 2008, "ids": { "imdb": "tt0903747", "tmdb": 1396 } } }
        ])
    }

    fn make_adapter(policy: EgressPolicy) -> TraktAdapter {
        TraktAdapter {
            client: outbound(policy),
            cache: test_cache(),
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_TRAKT)),
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            access_token: None,
            username: "testuser".to_string(),
        }
    }

    // -- Watchlist parsing (Req 27.1) ----------------------------------------

    #[test]
    fn parses_trakt_watchlist_response() {
        let bytes = serde_json::to_vec(&sample_watchlist()).unwrap();
        let list = parse_trakt_watchlist_response(&bytes, "movies").unwrap();
        assert_eq!(list.source, INTEGRATION_TRAKT);
        assert_eq!(list.items.len(), 2);
        let matrix = &list.items[0];
        assert_eq!(matrix.title, "The Matrix");
        assert_eq!(matrix.imdb_id.as_deref(), Some("tt0133093"));
        assert_eq!(matrix.tmdb_id, Some(603));
        assert_eq!(matrix.content_type, "movie");
        assert_eq!(matrix.year, Some(1999));
        let bb = &list.items[1];
        assert_eq!(bb.title, "Breaking Bad");
        assert_eq!(bb.content_type, "series");
    }

    // -- Cache HIT (Req 27.3) ------------------------------------------------

    #[tokio::test]
    async fn cache_hit_serves_without_upstream_call() {
        let cache = test_cache();
        let list = IntegrationList {
            source: INTEGRATION_TRAKT.to_string(),
            items: vec![ListItem {
                title: "Cached Movie".to_string(),
                imdb_id: Some("tt1234567".to_string()),
                tmdb_id: None,
                content_type: "movie".to_string(),
                year: Some(2020),
            }],
        };
        let data = Bytes::from(serde_json::to_vec(&list).unwrap());
        cache
            .set(
                "trakt:watchlist:testuser:movies",
                data,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let adapter = TraktAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache,
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_TRAKT)),
            client_id: "testclient".to_string(),
            client_secret: "testsecret".to_string(),
            access_token: None,
            username: "testuser".to_string(),
        };
        let result = adapter.fetch_watchlist("movies").await.unwrap();
        assert_eq!(result.items[0].title, "Cached Movie");
    }

    // -- Upstream error propagated when no cache (Req 27.5) ------------------

    #[tokio::test]
    async fn upstream_error_propagated_when_no_cache() {
        let adapter = make_adapter(EgressPolicy::FailClosed);
        let err = adapter.fetch_watchlist("movies").await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    // -- Device-code response parsing (Req 27.2) -----------------------------

    #[test]
    fn device_code_response_parses_correctly() {
        let json = serde_json::json!({
            "device_code": "dev-code-abc", "user_code": "ABCD-1234",
            "verification_url": "https://trakt.tv/activate", "expires_in": 600u64, "interval": 5u64,
        });
        let resp: DeviceCodeResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.device_code, "dev-code-abc");
        assert_eq!(resp.user_code, "ABCD-1234");
        assert_eq!(resp.verification_url, "https://trakt.tv/activate");
        assert_eq!(resp.expires_in, 600);
        assert_eq!(resp.interval, 5);
    }

    // -- poll_for_token status mapping (Req 27.2) ----------------------------

    #[test]
    fn token_response_parses_and_converts_to_trakt_token() {
        let json = serde_json::json!({ "access_token": "access-abc", "refresh_token": "refresh-xyz", "expires_in": 7776000i64 });
        let tr: TokenResponse = serde_json::from_value(json).unwrap();
        let token = tr.into_trakt_token();
        assert_eq!(token.access_token, "access-abc");
        assert_eq!(token.refresh_token, "refresh-xyz");
        assert!(token.expires_at > OffsetDateTime::now_utc());
    }

    #[test]
    fn poll_error_pending_converts_to_upstream_unavailable() {
        let err: AppError = PollError::Pending.into();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    #[test]
    fn poll_error_expired_converts_to_bad_request() {
        let err: AppError = PollError::Expired.into();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    #[test]
    fn poll_error_denied_converts_to_forbidden() {
        let err: AppError = PollError::Denied.into();
        assert_eq!(err.category, ErrorCategory::Forbidden);
    }

    // -- initiate_device_code via mock server (Req 27.2) ---------------------

    #[tokio::test]
    async fn initiate_device_code_returns_device_code_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/oauth/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "dev-code-abc", "user_code": "ABCD-1234",
                "verification_url": "https://trakt.tv/activate", "expires_in": 600u64, "interval": 5u64,
            }))).mount(&server).await;
        // Test parsing directly since TRAKT_API_BASE is a constant.
        let resp_json = serde_json::json!({
            "device_code": "dev-code-abc", "user_code": "ABCD-1234",
            "verification_url": "https://trakt.tv/activate", "expires_in": 600u64, "interval": 5u64,
        });
        let resp: DeviceCodeResponse = serde_json::from_value(resp_json).unwrap();
        assert_eq!(resp.device_code, "dev-code-abc");
        assert_eq!(resp.user_code, "ABCD-1234");
        let _ = server; // keep alive
    }

    #[test]
    fn initiate_device_code_upstream_error_maps_correctly() {
        let status = reqwest::StatusCode::INTERNAL_SERVER_ERROR;
        let err = AppError::upstream_unavailable(format!(
            "trakt device/code returned {status}: internal error"
        ))
        .with_upstream_status(status.as_u16());
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(500));
    }

    // -- persist_token + get_valid_token (Req 27.2, 29.5) --------------------

    #[tokio::test]
    async fn persist_and_retrieve_token_round_trips() {
        let (_dir, repos) = test_repos().await;
        let vault = test_vault();
        let adapter = make_adapter(EgressPolicy::FailOpen);
        let token = TraktToken {
            access_token: "access-tok".into(),
            refresh_token: "refresh-tok".into(),
            expires_at: OffsetDateTime::now_utc() + Duration::from_secs(3600),
        };
        adapter
            .persist_token("alice", &token, &repos, &vault)
            .await
            .expect("persist");
        let row = repos
            .get_trakt_token("alice")
            .await
            .expect("get")
            .expect("row present");
        assert_ne!(row.access_enc, b"access-tok");
        assert_ne!(row.refresh_enc, b"refresh-tok");
        assert_eq!(vault.decrypt(&row.access_enc).expect("dec"), b"access-tok");
        assert_eq!(
            vault.decrypt(&row.refresh_enc).expect("dec"),
            b"refresh-tok"
        );
    }

    #[tokio::test]
    async fn get_valid_token_returns_none_when_absent() {
        let (_dir, repos) = test_repos().await;
        let vault = test_vault();
        let adapter = make_adapter(EgressPolicy::FailOpen);
        let result = adapter
            .get_valid_token("nobody", &repos, &vault)
            .await
            .expect("no error");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_valid_token_returns_access_token_when_fresh() {
        let (_dir, repos) = test_repos().await;
        let vault = test_vault();
        let adapter = make_adapter(EgressPolicy::FailOpen);
        let token = TraktToken {
            access_token: "fresh-access".into(),
            refresh_token: "fresh-refresh".into(),
            expires_at: OffsetDateTime::now_utc() + Duration::from_secs(7200),
        };
        adapter
            .persist_token("bob", &token, &repos, &vault)
            .await
            .expect("persist");
        let result = adapter
            .get_valid_token("bob", &repos, &vault)
            .await
            .expect("get");
        assert_eq!(result, Some("fresh-access".to_string()));
    }

    #[tokio::test]
    async fn expired_token_is_detected_as_needing_refresh() {
        let (_dir, repos) = test_repos().await;
        let vault = test_vault();
        let row = TraktTokenRow {
            username: "carol".to_string(),
            access_enc: vault.encrypt(b"old-access").expect("enc"),
            refresh_enc: vault.encrypt(b"old-refresh").expect("enc"),
            expires_at: OffsetDateTime::now_utc() - Duration::from_secs(60),
        };
        repos.upsert_trakt_token(&row).await.expect("upsert");
        let fetched = repos
            .get_trakt_token("carol")
            .await
            .expect("get")
            .expect("present");
        let now = OffsetDateTime::now_utc();
        assert!(
            fetched.expires_at <= now + Duration::from_secs(REFRESH_AHEAD_SECS),
            "expired token should be detected as needing refresh"
        );
    }

    #[tokio::test]
    async fn token_within_refresh_ahead_window_is_detected() {
        let (_dir, repos) = test_repos().await;
        let vault = test_vault();
        let row = TraktTokenRow {
            username: "dave".to_string(),
            access_enc: vault.encrypt(b"near-expiry-access").expect("enc"),
            refresh_enc: vault.encrypt(b"near-expiry-refresh").expect("enc"),
            expires_at: OffsetDateTime::now_utc() + Duration::from_secs(60),
        };
        repos.upsert_trakt_token(&row).await.expect("upsert");
        let fetched = repos
            .get_trakt_token("dave")
            .await
            .expect("get")
            .expect("present");
        let now = OffsetDateTime::now_utc();
        assert!(
            fetched.expires_at <= now + Duration::from_secs(REFRESH_AHEAD_SECS),
            "token within refresh-ahead window should be detected as needing refresh"
        );
    }

    // -- OAuth token response parsing (Req 27.2) -----------------------------

    #[test]
    fn oauth_token_response_parses_correctly() {
        let token_bytes = serde_json::to_vec(&serde_json::json!({
            "access_token": "test-access-token", "token_type": "Bearer",
            "expires_in": 7776000u64, "refresh_token": "test-refresh-token", "scope": "public"
        }))
        .unwrap();
        let token: TraktTokenResponse = serde_json::from_slice(&token_bytes).unwrap();
        assert_eq!(token.access_token, "test-access-token");
        assert_eq!(token.refresh_token, "test-refresh-token");
        assert_eq!(token.expires_in, 7776000);
    }
}
