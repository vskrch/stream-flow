//! GitHub integration adapter — Req 27.1.
//!
//! Fetches raw file content from GitHub repositories (e.g. a JSON list file
//! hosted in a public repo). Results are cached for the configured TTL
//! (Req 27.3, 27.4) and the circuit breaker wraps every upstream call
//! (Req 50.2).
//!
//! All HTTP calls go through [`egress::OutboundClient`] (Req 51.1).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::cache::CacheBackend;
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::resilience::breaker::CircuitBreaker;

use super::{
    fetch_with_cache, integration_breaker, map_http_error, map_reqwest_error, IntegrationList,
    ListItem, INTEGRATION_GITHUB,
};

/// GitHub integration adapter.
///
/// Fetches a raw file from a GitHub repository URL and parses it as a JSON
/// list. Results are cached for the configured TTL (Req 27.3, 27.4). The
/// circuit breaker wraps every upstream call (Req 50.2).
#[derive(Clone)]
pub struct GitHubAdapter {
    /// The single outbound seam (Req 51.1).
    client: Arc<OutboundClient>,
    /// The shared cache backend (Req 27.3, 27.4).
    cache: Arc<dyn CacheBackend>,
    /// Cache TTL for list data.
    ttl: Duration,
    /// Circuit breaker for the GitHub upstream (Req 50.2).
    breaker: Arc<CircuitBreaker>,
    /// The raw GitHub content URL to fetch.
    raw_url: String,
}

impl GitHubAdapter {
    /// Build a [`GitHubAdapter`] for the given raw GitHub content URL.
    ///
    /// The `raw_url` should point to a raw file (e.g.
    /// `https://raw.githubusercontent.com/user/repo/main/list.json`).
    pub fn new(
        client: Arc<OutboundClient>,
        cache: Arc<dyn CacheBackend>,
        ttl: Duration,
        raw_url: impl Into<String>,
    ) -> Self {
        Self {
            client,
            cache,
            ttl,
            breaker: Arc::new(integration_breaker(INTEGRATION_GITHUB)),
            raw_url: raw_url.into(),
        }
    }

    /// Fetch the list from the configured GitHub URL, serving from cache when
    /// fresh (Req 27.3, 27.4) and logging errors when the upstream fails
    /// (Req 27.5).
    pub async fn fetch_list(&self) -> Result<IntegrationList, AppError> {
        let cache_key = format!("github:{}", self.raw_url);
        let data = fetch_with_cache(
            &self.cache,
            &cache_key,
            self.ttl,
            &self.breaker,
            || {
                let client = self.client.clone();
                let raw_url = self.raw_url.clone();
                async move { fetch_raw_content(&client, &raw_url).await }
            },
        )
        .await?;

        let list: IntegrationList = serde_json::from_slice(&data)
            .map_err(|e| AppError::upstream_unavailable(format!("GitHub: failed to parse cached list: {e}")))?;
        Ok(list)
    }
}

/// Fetch raw content from a GitHub URL and serialize it as an
/// [`IntegrationList`] for caching.
async fn fetch_raw_content(client: &OutboundClient, raw_url: &str) -> Result<Bytes, AppError> {
    let url = Url::parse(raw_url)
        .map_err(|e| AppError::bad_request(format!("GitHub: invalid URL `{raw_url}`: {e}")))?;

    let resp = client
        .upstream(Method::GET, &url)?
        .header("Accept", "application/json, text/plain, */*")
        .header("User-Agent", "stream-flow/1.0")
        .send()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_GITHUB, e))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(map_http_error(INTEGRATION_GITHUB, status));
    }

    let body = resp
        .bytes()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_GITHUB, e))?;

    // Try to parse as a JSON array of items, or wrap raw bytes in a list.
    let list = parse_github_content(&body, raw_url)?;
    let serialized = serde_json::to_vec(&list)
        .map_err(|e| AppError::upstream_unavailable(format!("GitHub: serialization failed: {e}")))?;
    Ok(Bytes::from(serialized))
}

/// Parse GitHub raw content into an [`IntegrationList`].
///
/// Supports two formats:
/// 1. A JSON array of objects with `title`, `imdb_id`, `type`, `year` fields.
/// 2. A plain text file with one title per line.
pub fn parse_github_content(data: &[u8], source_url: &str) -> Result<IntegrationList, AppError> {
    // Try JSON array first.
    if let Ok(items) = serde_json::from_slice::<Vec<GitHubListItem>>(data) {
        let list_items = items
            .into_iter()
            .map(|item| ListItem {
                title: item.title,
                imdb_id: item.imdb_id,
                tmdb_id: item.tmdb_id,
                content_type: item.content_type.unwrap_or_else(|| "movie".to_string()),
                year: item.year,
            })
            .collect();
        return Ok(IntegrationList {
            source: INTEGRATION_GITHUB.to_string(),
            items: list_items,
        });
    }

    // Fall back to plain text: one title per line.
    let text = std::str::from_utf8(data)
        .map_err(|_| AppError::upstream_unavailable("GitHub: response is not valid UTF-8"))?;

    let items = text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|title| ListItem {
            title: title.to_string(),
            imdb_id: None,
            tmdb_id: None,
            content_type: "movie".to_string(),
            year: None,
        })
        .collect();

    Ok(IntegrationList {
        source: INTEGRATION_GITHUB.to_string(),
        items,
    })
}

/// A single item in a GitHub-hosted JSON list.
#[derive(Debug, Deserialize, Serialize)]
struct GitHubListItem {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    imdb_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tmdb_id: Option<u64>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    year: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::LocalCache;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::errors::ErrorCategory;
    use std::sync::Arc;
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
        Arc::new(LocalCache::new("github-test"))
    }

    // -- JSON array format parsed correctly ----------------------------------

    #[test]
    fn parses_json_array_format() {
        let data = serde_json::json!([
            { "title": "The Matrix", "imdb_id": "tt0133093", "type": "movie", "year": 1999 },
            { "title": "Breaking Bad", "type": "series", "year": 2008 }
        ]);
        let bytes = serde_json::to_vec(&data).unwrap();
        let list = parse_github_content(&bytes, "https://raw.githubusercontent.com/test/repo/main/list.json").unwrap();

        assert_eq!(list.source, INTEGRATION_GITHUB);
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].title, "The Matrix");
        assert_eq!(list.items[0].imdb_id.as_deref(), Some("tt0133093"));
        assert_eq!(list.items[0].content_type, "movie");
        assert_eq!(list.items[0].year, Some(1999));
        assert_eq!(list.items[1].title, "Breaking Bad");
        assert_eq!(list.items[1].content_type, "series");
    }

    // -- Plain text format parsed correctly ----------------------------------

    #[test]
    fn parses_plain_text_format() {
        let text = b"# My list\nThe Matrix\nBreaking Bad\n\nInception\n";
        let list = parse_github_content(text, "https://raw.githubusercontent.com/test/repo/main/list.txt").unwrap();

        assert_eq!(list.source, INTEGRATION_GITHUB);
        assert_eq!(list.items.len(), 3);
        assert_eq!(list.items[0].title, "The Matrix");
        assert_eq!(list.items[1].title, "Breaking Bad");
        assert_eq!(list.items[2].title, "Inception");
        // Plain text defaults to "movie" content type.
        assert!(list.items.iter().all(|i| i.content_type == "movie"));
    }

    // -- Cache HIT: no upstream call when unexpired data exists (Req 27.3) ---

    #[tokio::test]
    async fn cache_hit_serves_without_upstream_call() {
        let cache = test_cache();
        let list = IntegrationList {
            source: INTEGRATION_GITHUB.to_string(),
            items: vec![ListItem {
                title: "Cached Movie".to_string(),
                imdb_id: Some("tt9999999".to_string()),
                tmdb_id: None,
                content_type: "movie".to_string(),
                year: Some(2021),
            }],
        };
        let data = Bytes::from(serde_json::to_vec(&list).unwrap());
        let url = "https://raw.githubusercontent.com/test/repo/main/list.json";
        cache
            .set(&format!("github:{url}"), data, Duration::from_secs(3600))
            .await
            .unwrap();

        let adapter = GitHubAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache,
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_GITHUB)),
            raw_url: url.to_string(),
        };

        // Should serve from cache without hitting the (fail-closed) egress.
        let result = adapter.fetch_list().await.unwrap();
        assert_eq!(result.items[0].title, "Cached Movie");
    }

    // -- Upstream error propagated when no cache (Req 27.5) ------------------

    #[tokio::test]
    async fn upstream_error_propagated_when_no_cache() {
        let adapter = GitHubAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache: test_cache(),
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_GITHUB)),
            raw_url: "https://raw.githubusercontent.com/test/repo/main/list.json".to_string(),
        };

        let err = adapter.fetch_list().await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    // -- HTTP error from upstream surfaces correctly (Req 27.5) --------------

    #[tokio::test]
    async fn http_404_surfaces_as_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/list.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let adapter = GitHubAdapter {
            client: outbound(EgressPolicy::FailOpen),
            cache: test_cache(),
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_GITHUB)),
            raw_url: format!("{}/list.json", server.uri()),
        };

        let err = adapter.fetch_list().await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::NotFound);
        assert_eq!(err.upstream_status, Some(404));
    }

    // -- Successful fetch from mock upstream (Req 27.4) ----------------------

    #[tokio::test]
    async fn fetches_json_list_from_upstream() {
        let server = MockServer::start().await;
        let list_data = serde_json::json!([
            { "title": "Inception", "type": "movie", "year": 2010 }
        ]);
        Mock::given(method("GET"))
            .and(path("/list.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_json(list_data),
            )
            .mount(&server)
            .await;

        let adapter = GitHubAdapter {
            client: outbound(EgressPolicy::FailOpen),
            cache: test_cache(),
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_GITHUB)),
            raw_url: format!("{}/list.json", server.uri()),
        };

        let result = adapter.fetch_list().await.unwrap();
        assert_eq!(result.source, INTEGRATION_GITHUB);
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].title, "Inception");
    }
}
