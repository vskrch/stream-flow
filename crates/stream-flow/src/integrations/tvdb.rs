//! TVDB integration adapter — Req 27.1.
//!
//! Fetches series data from the [TVDB REST API](https://thetvdb.com/api-information).
//! Results are cached for the configured TTL (Req 27.3, 27.4) and the circuit
//! breaker wraps every upstream call (Req 50.2).
//!
//! All HTTP calls go through [`egress::OutboundClient`] (Req 51.1).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::Method;
use serde::Deserialize;
use url::Url;

use crate::cache::CacheBackend;
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::resilience::breaker::CircuitBreaker;

use super::{
    fetch_with_cache, integration_breaker, map_http_error, map_reqwest_error, IntegrationList,
    ListItem, INTEGRATION_TVDB,
};

/// TVDB API base URL.
const TVDB_API_BASE: &str = "https://api4.thetvdb.com/v4";

/// TVDB integration adapter.
///
/// Fetches series data from the TVDB API and caches the result for the
/// configured TTL (Req 27.3, 27.4). The circuit breaker wraps every upstream
/// call (Req 50.2).
#[derive(Clone)]
pub struct TvdbAdapter {
    /// The single outbound seam (Req 51.1).
    client: Arc<OutboundClient>,
    /// The shared cache backend (Req 27.3, 27.4).
    cache: Arc<dyn CacheBackend>,
    /// Cache TTL for list data.
    ttl: Duration,
    /// Circuit breaker for the TVDB upstream (Req 50.2).
    breaker: Arc<CircuitBreaker>,
    /// TVDB API key.
    api_key: String,
    /// Cached JWT token for TVDB API authentication.
    token: Arc<tokio::sync::RwLock<Option<String>>>,
}

impl TvdbAdapter {
    /// Build a [`TvdbAdapter`] for the given API key.
    pub fn new(
        client: Arc<OutboundClient>,
        cache: Arc<dyn CacheBackend>,
        ttl: Duration,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            client,
            cache,
            ttl,
            breaker: Arc::new(integration_breaker(INTEGRATION_TVDB)),
            api_key: api_key.into(),
            token: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Authenticate with the TVDB API and cache the JWT token.
    async fn authenticate(&self) -> Result<String, AppError> {
        // Check if we already have a token.
        {
            let guard = self.token.read().await;
            if let Some(token) = guard.as_ref() {
                return Ok(token.clone());
            }
        }

        let url = Url::parse(&format!("{TVDB_API_BASE}/login"))
            .map_err(|e| AppError::upstream_unavailable(format!("TVDB: invalid URL: {e}")))?;

        let body = serde_json::json!({ "apikey": self.api_key });

        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| map_reqwest_error(INTEGRATION_TVDB, e))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(map_http_error(INTEGRATION_TVDB, status));
        }

        #[derive(Deserialize)]
        struct LoginResponse {
            data: LoginData,
        }
        #[derive(Deserialize)]
        struct LoginData {
            token: String,
        }

        let login: LoginResponse = resp.json().await.map_err(|e| {
            AppError::upstream_unavailable(format!("TVDB: failed to parse login response: {e}"))
        })?;

        let token = login.data.token;
        *self.token.write().await = Some(token.clone());
        Ok(token)
    }

    /// Search for a series by name, serving from cache when fresh (Req 27.3,
    /// 27.4) and logging errors when the upstream fails (Req 27.5).
    pub async fn search_series(&self, query: &str) -> Result<IntegrationList, AppError> {
        let cache_key = format!("tvdb:search:{query}");
        let data = fetch_with_cache(&self.cache, &cache_key, self.ttl, &self.breaker, || {
            let client = self.client.clone();
            let api_key = self.api_key.clone();
            let token_lock = self.token.clone();
            let query = query.to_string();
            async move {
                let token = {
                    let guard = token_lock.read().await;
                    guard.clone()
                };
                fetch_tvdb_search(&client, &api_key, token.as_deref(), &query).await
            }
        })
        .await?;

        let list: IntegrationList = serde_json::from_slice(&data).map_err(|e| {
            AppError::upstream_unavailable(format!("TVDB: failed to parse cached list: {e}"))
        })?;
        Ok(list)
    }
}

/// Fetch TVDB search results.
async fn fetch_tvdb_search(
    client: &OutboundClient,
    _api_key: &str,
    token: Option<&str>,
    query: &str,
) -> Result<Bytes, AppError> {
    let encoded_query = urlencoding::encode(query);
    let url_str = format!("{TVDB_API_BASE}/search?query={encoded_query}&type=series");
    let url = Url::parse(&url_str)
        .map_err(|e| AppError::upstream_unavailable(format!("TVDB: invalid URL: {e}")))?;

    let mut builder = client
        .upstream(Method::GET, &url)?
        .header("Accept", "application/json");

    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }

    let resp = builder
        .send()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_TVDB, e))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(map_http_error(INTEGRATION_TVDB, status));
    }

    let body = resp
        .bytes()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_TVDB, e))?;

    let list = parse_tvdb_search_response(&body)?;
    let serialized = serde_json::to_vec(&list)
        .map_err(|e| AppError::upstream_unavailable(format!("TVDB: serialization failed: {e}")))?;
    Ok(Bytes::from(serialized))
}

/// Parse a TVDB search response.
pub fn parse_tvdb_search_response(data: &[u8]) -> Result<IntegrationList, AppError> {
    #[derive(Deserialize)]
    struct Response {
        data: Option<Vec<TvdbResult>>,
    }
    #[derive(Deserialize)]
    struct TvdbResult {
        name: Option<String>,
        #[serde(rename = "tvdb_id")]
        tvdb_id: Option<String>,
        imdb_id: Option<String>,
        year: Option<String>,
        #[serde(rename = "type")]
        result_type: Option<String>,
    }

    let resp: Response = serde_json::from_slice(data).map_err(|e| {
        AppError::upstream_unavailable(format!("TVDB: failed to parse search response: {e}"))
    })?;

    let items = resp
        .data
        .unwrap_or_default()
        .into_iter()
        .filter_map(|result| {
            let title = result.name?;
            let content_type = result
                .result_type
                .as_deref()
                .map(|t| if t == "movie" { "movie" } else { "series" })
                .unwrap_or("series")
                .to_string();
            let year = result.year.as_deref().and_then(|y| y.parse().ok());
            Some(ListItem {
                title,
                imdb_id: result.imdb_id,
                tmdb_id: None,
                content_type,
                year,
            })
        })
        .collect();

    Ok(IntegrationList {
        source: INTEGRATION_TVDB.to_string(),
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::LocalCache;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::errors::ErrorCategory;
    use std::sync::Arc;

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
        Arc::new(LocalCache::new("tvdb-test"))
    }

    // -- Search response parsed correctly ------------------------------------

    #[test]
    fn parses_tvdb_search_response() {
        let data = serde_json::json!({
            "data": [
                {
                    "name": "Breaking Bad",
                    "tvdb_id": "81189",
                    "imdb_id": "tt0903747",
                    "year": "2008",
                    "type": "series"
                },
                {
                    "name": "Better Call Saul",
                    "tvdb_id": "273181",
                    "imdb_id": "tt3032476",
                    "year": "2015",
                    "type": "series"
                }
            ]
        });
        let bytes = serde_json::to_vec(&data).unwrap();
        let list = parse_tvdb_search_response(&bytes).unwrap();

        assert_eq!(list.source, INTEGRATION_TVDB);
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].title, "Breaking Bad");
        assert_eq!(list.items[0].imdb_id.as_deref(), Some("tt0903747"));
        assert_eq!(list.items[0].content_type, "series");
        assert_eq!(list.items[0].year, Some(2008));
    }

    // -- Empty data field handled gracefully ---------------------------------

    #[test]
    fn handles_empty_data_field() {
        let data = serde_json::json!({ "data": null });
        let bytes = serde_json::to_vec(&data).unwrap();
        let list = parse_tvdb_search_response(&bytes).unwrap();
        assert_eq!(list.items.len(), 0);
    }

    // -- Cache HIT: no upstream call when unexpired data exists (Req 27.3) ---

    #[tokio::test]
    async fn cache_hit_serves_without_upstream_call() {
        let cache = test_cache();
        let list = IntegrationList {
            source: INTEGRATION_TVDB.to_string(),
            items: vec![ListItem {
                title: "Cached Series".to_string(),
                imdb_id: None,
                tmdb_id: None,
                content_type: "series".to_string(),
                year: Some(2020),
            }],
        };
        let data = Bytes::from(serde_json::to_vec(&list).unwrap());
        cache
            .set("tvdb:search:breaking bad", data, Duration::from_secs(3600))
            .await
            .unwrap();

        let adapter = TvdbAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache,
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_TVDB)),
            api_key: "testkey".to_string(),
            token: Arc::new(tokio::sync::RwLock::new(None)),
        };

        let result = adapter.search_series("breaking bad").await.unwrap();
        assert_eq!(result.items[0].title, "Cached Series");
    }

    // -- Upstream error propagated when no cache (Req 27.5) ------------------

    #[tokio::test]
    async fn upstream_error_propagated_when_no_cache() {
        let adapter = TvdbAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache: test_cache(),
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_TVDB)),
            api_key: "testkey".to_string(),
            token: Arc::new(tokio::sync::RwLock::new(None)),
        };

        let err = adapter.search_series("breaking bad").await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }
}
