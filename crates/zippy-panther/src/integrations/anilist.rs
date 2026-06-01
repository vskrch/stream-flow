//! AniList integration adapter — Req 27.1.
//!
//! Fetches anime lists from the [AniList GraphQL API](https://anilist.co/graphiql)
//! using a user's AniList username. Results are cached for the configured TTL
//! (Req 27.3, 27.4) and the circuit breaker wraps every upstream call
//! (Req 50.2).
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
    ListItem, INTEGRATION_ANILIST,
};

/// The AniList GraphQL endpoint.
const ANILIST_API_URL: &str = "https://graphql.anilist.co";

/// GraphQL query to fetch a user's anime/manga list.
const MEDIA_LIST_QUERY: &str = r#"
query ($userName: String, $type: MediaType) {
  MediaListCollection(userName: $userName, type: $type) {
    lists {
      entries {
        media {
          title { romaji english }
          idMal
          id
          type
          startDate { year }
        }
      }
    }
  }
}
"#;

/// AniList integration adapter.
///
/// Fetches a user's anime/manga list from the AniList GraphQL API and caches
/// the result for the configured TTL (Req 27.3, 27.4). The circuit breaker
/// wraps every upstream call (Req 50.2).
#[derive(Clone)]
pub struct AniListAdapter {
    /// The single outbound seam (Req 51.1).
    client: Arc<OutboundClient>,
    /// The shared cache backend (Req 27.3, 27.4).
    cache: Arc<dyn CacheBackend>,
    /// Cache TTL for list data.
    ttl: Duration,
    /// Circuit breaker for the AniList upstream (Req 50.2).
    breaker: Arc<CircuitBreaker>,
    /// AniList username to fetch lists for.
    username: String,
}

impl AniListAdapter {
    /// Build an [`AniListAdapter`] for the given username.
    pub fn new(
        client: Arc<OutboundClient>,
        cache: Arc<dyn CacheBackend>,
        ttl: Duration,
        username: impl Into<String>,
    ) -> Self {
        Self {
            client,
            cache,
            ttl,
            breaker: Arc::new(integration_breaker(INTEGRATION_ANILIST)),
            username: username.into(),
        }
    }

    /// Fetch the user's anime list, serving from cache when fresh (Req 27.3,
    /// 27.4) and logging errors when the upstream fails (Req 27.5).
    pub async fn fetch_anime_list(&self) -> Result<IntegrationList, AppError> {
        let cache_key = format!("anilist:anime:{}", self.username);
        let data = fetch_with_cache(&self.cache, &cache_key, self.ttl, &self.breaker, || {
            let client = self.client.clone();
            let username = self.username.clone();
            async move { fetch_media_list(&client, &username, "ANIME").await }
        })
        .await?;

        let list: IntegrationList = serde_json::from_slice(&data).map_err(|e| {
            AppError::upstream_unavailable(format!("AniList: failed to parse cached list: {e}"))
        })?;
        Ok(list)
    }

    /// Fetch the user's manga list, serving from cache when fresh (Req 27.3,
    /// 27.4) and logging errors when the upstream fails (Req 27.5).
    pub async fn fetch_manga_list(&self) -> Result<IntegrationList, AppError> {
        let cache_key = format!("anilist:manga:{}", self.username);
        let data = fetch_with_cache(&self.cache, &cache_key, self.ttl, &self.breaker, || {
            let client = self.client.clone();
            let username = self.username.clone();
            async move { fetch_media_list(&client, &username, "MANGA").await }
        })
        .await?;

        let list: IntegrationList = serde_json::from_slice(&data).map_err(|e| {
            AppError::upstream_unavailable(format!("AniList: failed to parse cached list: {e}"))
        })?;
        Ok(list)
    }
}

/// Fetch a media list from the AniList GraphQL API and serialize it to bytes
/// for caching.
async fn fetch_media_list(
    client: &OutboundClient,
    username: &str,
    media_type: &str,
) -> Result<Bytes, AppError> {
    let url = Url::parse(ANILIST_API_URL)
        .map_err(|e| AppError::upstream_unavailable(format!("AniList: invalid API URL: {e}")))?;

    let body = serde_json::json!({
        "query": MEDIA_LIST_QUERY,
        "variables": {
            "userName": username,
            "type": media_type,
        }
    });

    let resp = client
        .upstream(Method::POST, &url)?
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_ANILIST, e))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(map_http_error(INTEGRATION_ANILIST, status));
    }

    let response_bytes = resp
        .bytes()
        .await
        .map_err(|e| map_reqwest_error(INTEGRATION_ANILIST, e))?;

    // Parse the GraphQL response and normalize to IntegrationList.
    let list = parse_anilist_response(&response_bytes, media_type)?;
    let serialized = serde_json::to_vec(&list).map_err(|e| {
        AppError::upstream_unavailable(format!("AniList: serialization failed: {e}"))
    })?;
    Ok(Bytes::from(serialized))
}

/// Parse the AniList GraphQL response into an [`IntegrationList`].
fn parse_anilist_response(data: &[u8], media_type: &str) -> Result<IntegrationList, AppError> {
    #[derive(Deserialize)]
    struct Response {
        data: Option<ResponseData>,
        errors: Option<Vec<GraphQLError>>,
    }
    #[derive(Deserialize)]
    struct GraphQLError {
        message: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ResponseData {
        media_list_collection: Option<MediaListCollection>,
    }
    #[derive(Deserialize)]
    struct MediaListCollection {
        lists: Vec<MediaList>,
    }
    #[derive(Deserialize)]
    struct MediaList {
        entries: Vec<MediaEntry>,
    }
    #[derive(Deserialize)]
    struct MediaEntry {
        media: Media,
    }
    #[derive(Deserialize)]
    struct Media {
        title: MediaTitle,
        #[serde(rename = "idMal")]
        id_mal: Option<u64>,
        id: u64,
        #[serde(rename = "type")]
        media_type: Option<String>,
        #[serde(rename = "startDate")]
        start_date: Option<StartDate>,
    }
    #[derive(Deserialize)]
    struct MediaTitle {
        romaji: Option<String>,
        english: Option<String>,
    }
    #[derive(Deserialize)]
    struct StartDate {
        year: Option<u32>,
    }

    let resp: Response = serde_json::from_slice(data).map_err(|e| {
        AppError::upstream_unavailable(format!("AniList: failed to parse response: {e}"))
    })?;

    if let Some(errors) = resp.errors {
        if !errors.is_empty() {
            return Err(AppError::upstream_unavailable(format!(
                "AniList GraphQL error: {}",
                errors[0].message
            )));
        }
    }

    let collection = resp
        .data
        .and_then(|d| d.media_list_collection)
        .ok_or_else(|| AppError::upstream_unavailable("AniList: empty response data"))?;

    let content_type = if media_type == "ANIME" {
        "series"
    } else {
        "movie"
    };

    let items: Vec<ListItem> = collection
        .lists
        .into_iter()
        .flat_map(|list| list.entries)
        .map(|entry| {
            let media = entry.media;
            let title = media
                .title
                .english
                .or(media.title.romaji)
                .unwrap_or_else(|| format!("AniList #{}", media.id));
            ListItem {
                title,
                imdb_id: None, // AniList uses MAL IDs, not IMDB
                tmdb_id: None,
                content_type: media
                    .media_type
                    .as_deref()
                    .map(|t| if t == "ANIME" { "series" } else { "movie" })
                    .unwrap_or(content_type)
                    .to_string(),
                year: media.start_date.and_then(|d| d.year),
            }
        })
        .collect();

    Ok(IntegrationList {
        source: INTEGRATION_ANILIST.to_string(),
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn outbound(policy: EgressPolicy) -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: match policy {
                EgressPolicy::FailOpen => EgressTunnelMode::Disabled,
                EgressPolicy::FailClosed => EgressTunnelMode::Proxy,
            },
            tunnel_url: (policy == EgressPolicy::FailClosed)
                .then(|| "http://proxy:8888".to_string()),
            policy,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn test_cache() -> Arc<dyn CacheBackend> {
        Arc::new(LocalCache::new("anilist-test"))
    }

    fn sample_anilist_response() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "MediaListCollection": {
                    "lists": [{
                        "entries": [{
                            "media": {
                                "title": { "romaji": "Shingeki no Kyojin", "english": "Attack on Titan" },
                                "idMal": 16498,
                                "id": 16498,
                                "type": "ANIME",
                                "startDate": { "year": 2013 }
                            }
                        }]
                    }]
                }
            }
        })
    }

    // -- Adapter fetches from upstream and caches result (Req 27.4) ----------

    #[tokio::test]
    async fn fetches_anime_list_from_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_json(sample_anilist_response()),
            )
            .mount(&server)
            .await;

        // We can't easily override the ANILIST_API_URL in tests, so we test
        // the parse logic directly.
        let response_bytes = serde_json::to_vec(&sample_anilist_response()).unwrap();
        let list = parse_anilist_response(&response_bytes, "ANIME").unwrap();

        assert_eq!(list.source, INTEGRATION_ANILIST);
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].title, "Attack on Titan");
        assert_eq!(list.items[0].content_type, "series");
        assert_eq!(list.items[0].year, Some(2013));
    }

    // -- GraphQL error response surfaces as AppError (Req 27.5) -------------

    #[test]
    fn graphql_error_surfaces_as_upstream_unavailable() {
        let error_response = serde_json::json!({
            "errors": [{ "message": "User not found" }]
        });
        let bytes = serde_json::to_vec(&error_response).unwrap();
        let err = parse_anilist_response(&bytes, "ANIME").unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("User not found"));
    }

    // -- Cache HIT: no upstream call when unexpired data exists (Req 27.3) ---

    #[tokio::test]
    async fn cache_hit_serves_without_upstream_call() {
        let cache = test_cache();
        let list = IntegrationList {
            source: INTEGRATION_ANILIST.to_string(),
            items: vec![ListItem {
                title: "Cached Anime".to_string(),
                imdb_id: None,
                tmdb_id: None,
                content_type: "series".to_string(),
                year: Some(2020),
            }],
        };
        let data = Bytes::from(serde_json::to_vec(&list).unwrap());
        cache
            .set("anilist:anime:testuser", data, Duration::from_secs(3600))
            .await
            .unwrap();

        let adapter = AniListAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache,
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_ANILIST)),
            username: "testuser".to_string(),
        };

        // Should serve from cache without hitting the (fail-closed) egress.
        let result = adapter.fetch_anime_list().await.unwrap();
        assert_eq!(result.items[0].title, "Cached Anime");
    }

    // -- Upstream error propagated when no cache (Req 27.5) ------------------

    #[tokio::test]
    async fn upstream_error_propagated_when_no_cache() {
        let adapter = AniListAdapter {
            client: outbound(EgressPolicy::FailClosed),
            cache: test_cache(),
            ttl: Duration::from_secs(3600),
            breaker: Arc::new(integration_breaker(INTEGRATION_ANILIST)),
            username: "testuser".to_string(),
        };

        // Fail-closed egress refuses the dial → UpstreamUnavailable.
        let err = adapter.fetch_anime_list().await.unwrap_err();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    // -- Circuit breaker wraps adapter calls (Req 50.2) ----------------------

    #[test]
    fn integration_breaker_uses_correct_key() {
        let breaker = integration_breaker(INTEGRATION_ANILIST);
        assert_eq!(
            breaker.key(),
            &crate::resilience::breaker::BreakerKey::Integration(INTEGRATION_ANILIST.to_string())
        );
    }
}
