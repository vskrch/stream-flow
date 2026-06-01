//! TMDB integration adapter — Req 27.1.
//!
//! Fetches lists from the [TMDB REST API](https://developer.themoviedb.org/docs).
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
    ListItem, INTEGRATION_TMDB,
};

/// TMDB API base URL.
const TMDB_API_BASE: &str = "https://api.themoviedb.org/3";

/// TMDB integration adapter.
///
/// Fetches a TMDB list and caches the result for the configured TTL
/// (Req 27.3, 27.4). The circuit breaker wraps every upstream call (Req 50.2).
#[derive(Clone)]
pub struct TmdbAdapter {
    /// The single outbound seam (Req 51.1).
    client: Arc<OutboundClient>,
    /// The shared cache backend (Req 27.3, 27.4).
    cache: Arc<dyn CacheBackend>,
    /// Cache TTL for list data.
    ttl: Duration,
    /// Circuit breaker for the TMDB upstream (Req 50.2).
    breaker: Arc<CircuitBreaker>,
    /// TMDB API read access token (Bearer).
    api_token: String,
    /// TMDB list ID to fetch.
    list_id: String,
}

impl TmdbAdapter {
    /// Build a [`TmdbAdapter`] for the given API token and list ID.
    pub fn new(
        client: Arc<OutboundClient>,
        cache: Arc<dyn CacheBackend>,
        ttl: Duration,
        api_token: impl Into<String>,
        list_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            cache,
            ttl,
            breaker: Arc::new(integration_breaker(INTEGRATION_TMDB)),
            api_token: api_token.into(),
            list_id: list_id.into(),
        }
    }

    /// Fetch the TMDB list, serving from cache when fresh (Req 27.3, 27.4)
    /// and logging errors when the upstream fails (Req 27.5).
    pub async fn fetch_list(&self) -> Result<IntegrationList, AppError> {
        let cache_key = format!("tmdb:list:{}", self.list_id);
        let data = fetch_with_cache(&self.cache, &cache_key, self.ttl, &self.breaker, || {
            let client = self.client.clone();
            let api_token = self.api_token.clone();
            let list_id = self.list_id.clone();
            async move { fetch_tmdb_list(&client, &api_token, &list_id).await }
        })
        .await?;

        let list: IntegrationList = serde_json::from_slice(&data).map_err(|e| {
            AppError::upstream_unavailable(format!("TMDB: failed to parse cached list: {e}"))
        })?;
        Ok(list)
    }

    /// Fetch trending movies from TMDB, serving from cache when fresh.
    pub async fn fetch_trending_movies(&self) -> Result<IntegrationList, AppError> {
        let cache_key = "tmdb:trending:movies".to_string();
        let data = fetch_with_cache(&self.cache, &cache_key, self.ttl, &self.breaker, || {
            let client = self.client.clone();
            let api_token = self.api_token.clone();
            async move { fetch_tmdb_trending(&client, &api_token, "movie").await }
        })
        .await?;

        let list: IntegrationList = serde_json::from_slice(&data).map_err(|e| {
            AppError::upstream_unavailable(format!("TMDB: failed to parse cached list: {e}"))
        })?;
        Ok(list)
    }

    /// Fetch trending TV shows from TMDB, serving from cache when fresh.
    pub async fn fetch_trending_shows(&self) -> Result<IntegrationList, AppError> {
        let cache_key = "tmdb:trending:shows".to_string();
        let data = fetch_with_cache(&self.cache, &cache_key, self.ttl, &self.breaker, || {
            let client = self.client.clone();
            let api_token = self.api_token.clone();
            async move { fetch_tmdb_trending(&client, &api_token, "tv").await }
        })
        .await?;

        let list: IntegrationList = serde_json::from_slice(&data).map_err(|e| {
            AppError::upstream_unavailable(format!("TMDB: failed to parse cached list: {e}"))
        })?;
        Ok(list)
    }
}

/// Fetch a TMDB list by ID.
async fn fetch_tmdb_list(
    client: &OutboundClient,
    api_token: &str,
    list_id: &str,
) -> Result<Bytes, AppError> {
    let url_str = format!("{TMDB_API_BASE}/list/{list_id}");
    let url = Url::parse(&url_str)
        .map_err(|e| AppError::upstream_unavailable(format!("TMDB: invalid URL: {e}")))?;

    let resp = client
        .upstream(Method::GET, &url)?
        .header("Authorization", format!("Bearer {api_token}"))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_TMDB, e))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(map_http_error(INTEGRATION_TMDB, status));
    }

    let body = resp
        .bytes()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_TMDB, e))?;

    let list = parse_tmdb_list_response(&body)?;
    let serialized = serde_json::to_vec(&list)
        .map_err(|e| AppError::upstream_unavailable(format!("TMDB: serialization failed: {e}")))?;
    Ok(Bytes::from(serialized))
}

/// Fetch trending content from TMDB.
async fn fetch_tmdb_trending(
    client: &OutboundClient,
    api_token: &str,
    media_type: &str,
) -> Result<Bytes, AppError> {
    let url_str = format!("{TMDB_API_BASE}/trending/{media_type}/week");
    let url = Url::parse(&url_str)
        .map_err(|e| AppError::upstream_unavailable(format!("TMDB: invalid URL: {e}")))?;

    let resp = client
        .upstream(Method::GET, &url)?
        .header("Authorization", format!("Bearer {api_token}"))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_TMDB, e))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(map_http_error(INTEGRATION_TMDB, status));
    }

    let body = resp
        .bytes()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_TMDB, e))?;

    let list = parse_tmdb_trending_response(&body, media_type)?;
    let serialized = serde_json::to_vec(&list)
        .map_err(|e| AppError::upstream_unavailable(format!("TMDB: serialization failed: {e}")))?;
    Ok(Bytes::from(serialized))
}

/// Parse a TMDB list response.
pub fn parse_tmdb_list_response(data: &[u8]) -> Result<IntegrationList, AppError> {
    #[derive(Deserialize)]
    struct Response {
        items: Vec<TmdbItem>,
    }
    #[derive(Deserialize)]
    struct TmdbItem {
        title: Option<String>,
        name: Option<String>,
        id: u64,
        media_type: Option<String>,
        release_date: Option<String>,
        first_air_date: Option<String>,
    }

    let resp: Response = serde_json::from_slice(data).map_err(|e| {
        AppError::upstream_unavailable(format!("TMDB: failed to parse list response: {e}"))
    })?;

    let items = resp
        .items
        .into_iter()
        .map(|item| {
            let title = item
                .title
                .or(item.name)
                .unwrap_or_else(|| format!("TMDB #{}", item.id));
            let content_type = item
                .media_type
                .as_deref()
                .map(|t| if t == "tv" { "series" } else { "movie" })
                .unwrap_or("movie")
                .to_string();
            let year = item
                .release_date
                .or(item.first_air_date)
                .and_then(|d| d.split('-').next().and_then(|y| y.parse().ok()));
            ListItem {
                title,
                imdb_id: None,
                tmdb_id: Some(item.id),
                content_type,
                year,
            }
        })
        .collect();

    Ok(IntegrationList {
        source: INTEGRATION_TMDB.to_string(),
        items,
    })
}

/// Parse a TMDB trending response.
pub fn parse_tmdb_trending_response(
    data: &[u8],
    media_type: &str,
) -> Result<IntegrationList, AppError> {
    #[derive(Deserialize)]
    struct Response {
        results: Vec<TmdbResult>,
    }
    #[derive(Deserialize)]
    struct TmdbResult {
        title: Option<String>,
        name: Option<String>,
        id: u64,
        release_date: Option<String>,
        first_air_date: Option<String>,
    }

    let resp: Response = serde_json::from_slice(data).map_err(|e| {
        AppError::upstream_unavailable(format!("TMDB: failed to parse trending response: {e}"))
    })?;

    let content_type = if media_type == "tv" {
        "series"
    } else {
        "movie"
    };

    let items = resp
        .results
        .into_iter()
        .map(|item| {
            let title = item
                .title
                .or(item.name)
                .unwrap_or_else(|| format!("TMDB #{}", item.id));
            let year = item
                .release_date
                .or(item.first_air_date)
                .and_then(|d| d.split('-').next().and_then(|y| y.parse().ok()));
            ListItem {
                title,
                imdb_id: None,
                tmdb_id: Some(item.id),
                content_type: content_type.to_string(),
                year,
            }
        })
        .collect();

    Ok(IntegrationList {
        source: INTEGRATION_TMDB.to_string(),
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
        Arc::new(LocalCache::new("tmdb-test"))
    }

    // -- List response parsed correctly --------------------------------------

    #[test]
    fn parses_tmdb_list_response() {
        let data = serde_json::json!({
            "items": [
                { "title": "The Matrix", "id": 603, "media_type": "movie", "release_date": "1999-03-31" },
                { "name": "Breaking Bad", "id": 1396, "media_type": "tv", "first_air_date": "2008-01-20" }
            ]
        });
        let bytes = serde_json::to_vec(&data).unwrap();
        let list = parse_tmdb_list_response(&bytes).unwrap();

        assert_eq!(list.source, INTEGRATION_TMDB);
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].title, "The Matrix");
        assert_eq!(list.items[0].tmdb_id, Some(603));
        assert_eq!(list.items[0].content_type, "movie");
        assert_eq!(list.items[0].year, Some(1999));
        assert_eq!(list.items[1].title, "Breaking Bad");
        assert_eq!(list.items[1].content_type, "series");
        assert_eq!(list.items[1].year, Some(2008));
    }

    // -- Trending response parsed correctly ----------------------------------

    #[test]
    fn parses_tmdb_trending_response() {
        let data = serde_json::json!({
            "results": [
                { "title": "Inception", "id": 27205, "release_date": "2010-07-16" }
            ]
        });
        let bytes = serde_json::to_vec(&data).unwrap();
        let list = parse_tmdb_trending_response(&bytes, "movie").unwrap();

        assert_eq!(list.source, INTEGRATION_TMDB);
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].title, "Inception");
        assert_eq!(list.items[0].tmdb_id, Some(27205));
        assert_eq!(list.items[0].content_type, "movie");
        assert_eq!(list.items[0].year, Some(2010));
    }

    // -- Cache HIT: no upstream call when unexpired data exists (Req 27.3) ---

    #[tokio::test]
    async fn cache_hit_serves_without_upstream_call() {
        let cache = test_cache();
        let list = IntegrationList {
            source: INTEGRATION_TMDB.to_string(),
            items: vec![ListItem {
                title: "Cached Movie".to_string(),
                imdb_id: None,
                tmdb_id: Some(12345),
                content_type: "movie".to_string(),
                year: Some(2020),
            }],
        };
        let data = Bytes::from(serde_json::to_vec(&list).unwrap());
        cache
            .set("tmdb:list:testlist", data, Duration::from_secs(3600))
            .await
            .unwrap();

        let adapter = TmdbAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache,
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_TMDB)),
            api_token: "testtoken".to_string(),
            list_id: "testlist".to_string(),
        };

        let result = adapter.fetch_list().await.unwrap();
        assert_eq!(result.items[0].title, "Cached Movie");
    }

    // -- Upstream error propagated when no cache (Req 27.5) ------------------

    #[tokio::test]
    async fn upstream_error_propagated_when_no_cache() {
        let adapter = TmdbAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache: test_cache(),
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_TMDB)),
            api_token: "testtoken".to_string(),
            list_id: "testlist".to_string(),
        };

        let err = adapter.fetch_list().await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }
}
