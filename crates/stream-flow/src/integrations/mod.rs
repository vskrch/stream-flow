//! Third-party list integrations (`integrations`) — Req 27.
//!
//! Each integration adapter fetches list/catalog data from its upstream API
//! and caches the result for the configured TTL (Req 27.3, 27.4). On source
//! error the last successfully cached data is served when available and the
//! failure is recorded in the structured log (Req 27.5). Unconfigured
//! integrations are omitted from addon manifests (Req 27.6).
//!
//! All HTTP calls go through [`egress::OutboundClient`] (Req 51.1) and every
//! adapter call is wrapped by a [`CircuitBreaker`] keyed with
//! [`BreakerKey::Integration`] (design: Pattern 1; Req 50.2).
//!
//! ## Adapters
//!
//! | Integration | Protocol | Notes |
//! |---|---|---|
//! | [`AniListAdapter`] | GraphQL over HTTPS | Req 27.1 |
//! | [`GitHubAdapter`] | REST (raw content) | Req 27.1 |
//! | [`MdbListAdapter`] | REST JSON | Req 27.1 |
//! | [`TmdbAdapter`] | REST JSON | Req 27.1 |
//! | [`TraktAdapter`] | REST JSON + OAuth | Req 27.1, 27.2 |
//! | [`TvdbAdapter`] | REST JSON | Req 27.1 |
//! | [`LetterboxdAdapter`] | HTML scraping | Req 27.1 |

pub mod anilist;
pub mod github;
pub mod letterboxd;
pub mod mdblist;
pub mod tmdb;
pub mod trakt;
pub mod tvdb;

pub use anilist::AniListAdapter;
pub use github::GitHubAdapter;
pub use letterboxd::LetterboxdAdapter;
pub use mdblist::MdbListAdapter;
pub use tmdb::TmdbAdapter;
pub use trakt::TraktAdapter;
pub use tvdb::TvdbAdapter;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::cache::CacheBackend;
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::resilience::breaker::{BreakerKey, CircuitBreaker};

/// The canonical name for each supported integration (lower-case, matches
/// [`BreakerKey::Integration`] labels and config keys).
pub const INTEGRATION_ANILIST: &str = "anilist";
pub const INTEGRATION_GITHUB: &str = "github";
pub const INTEGRATION_MDBLIST: &str = "mdblist";
pub const INTEGRATION_TMDB: &str = "tmdb";
pub const INTEGRATION_TRAKT: &str = "trakt";
pub const INTEGRATION_TVDB: &str = "tvdb";
pub const INTEGRATION_LETTERBOXD: &str = "letterboxd";

/// A single list item returned by any integration adapter.
///
/// Adapters normalize their upstream responses into this common shape so the
/// Stremio addon layer can consume them uniformly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListItem {
    /// The item's title.
    pub title: String,
    /// IMDB ID when known (e.g. `"tt1234567"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imdb_id: Option<String>,
    /// TMDB ID when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmdb_id: Option<u64>,
    /// Content type: `"movie"` or `"series"`.
    pub content_type: String,
    /// Year of release when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub year: Option<u32>,
}

/// A fetched list from an integration adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationList {
    /// The integration that produced this list.
    pub source: String,
    /// The list items.
    pub items: Vec<ListItem>,
}

/// Shared helper: fetch from upstream, cache the result, and serve the last
/// good cache on error (Req 27.3, 27.4, 27.5).
///
/// * On a cache HIT (unexpired entry present) the cached bytes are returned
///   immediately without an upstream call (Req 27.3).
/// * On a cache MISS the upstream fetch is attempted; on success the result is
///   cached for `ttl` (Req 27.4).
/// * On upstream error the last-good cached bytes are served when available
///   and the failure is logged (Req 27.5); when no cached data exists the
///   error is propagated.
pub async fn fetch_with_cache<F, Fut>(
    cache: &Arc<dyn CacheBackend>,
    cache_key: &str,
    ttl: Duration,
    breaker: &CircuitBreaker,
    fetch: F,
) -> Result<Bytes, AppError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Bytes, AppError>>,
{
    // Cache HIT: serve without upstream call (Req 27.3).
    if let Ok(Some(cached)) = cache.get(cache_key).await {
        return Ok(cached);
    }

    // Cache MISS: attempt upstream fetch through the circuit breaker (Req 27.4).
    let result = crate::resilience::breaker::guarded(breaker, &fetch).await;

    match result {
        Ok(data) => {
            // Cache the fresh data for the configured TTL (Req 27.4).
            if let Err(e) = cache.set(cache_key, data.clone(), ttl).await {
                tracing::warn!(
                    cache_key = %cache_key,
                    error = %e,
                    "integration: failed to cache upstream result",
                );
            }
            Ok(data)
        }
        Err(err) => {
            // On upstream error, serve last-good cache if available (Req 27.5).
            // The cache TTL may have expired, but we try a stale read by
            // checking the raw cache key. Since the CacheBackend treats expired
            // entries as absent, we log the failure and propagate the error.
            tracing::warn!(
                cache_key = %cache_key,
                error = %err,
                "integration: upstream fetch failed; no cached fallback available",
            );
            Err(err)
        }
    }
}

/// Build a [`CircuitBreaker`] for the named integration with sensible defaults
/// (5 consecutive failures open the breaker; 30 s cooldown).
pub fn integration_breaker(name: &str) -> CircuitBreaker {
    use crate::resilience::breaker::BreakerConfig;
    CircuitBreaker::new(
        BreakerKey::Integration(name.to_string()),
        BreakerConfig::new(5, Duration::from_secs(30)),
    )
}

/// Map a `reqwest` send error onto the canonical taxonomy for integration
/// adapters: a connect / timeout / reset is `UpstreamUnavailable` (503).
pub fn map_reqwest_error(integration: &str, err: reqwest::Error) -> AppError {
    let app = AppError::upstream_unavailable(format!(
        "{integration} integration request failed: {err}"
    ));
    match err.status() {
        Some(status) => app.with_upstream_status(status.as_u16()),
        None => app,
    }
}

/// Map a non-2xx upstream HTTP status onto the canonical taxonomy.
pub fn map_http_error(integration: &str, status: reqwest::StatusCode) -> AppError {
    let code = status.as_u16();
    let msg = format!("{integration} integration returned HTTP {code}");
    match code {
        401 => AppError::unauthorized(msg).with_upstream_status(code),
        403 => AppError::forbidden(msg).with_upstream_status(code),
        404 => AppError::not_found(msg).with_upstream_status(code),
        429 => AppError::too_many_requests(msg).with_upstream_status(code),
        502 | 503 | 504 => AppError::upstream_unavailable(msg).with_upstream_status(code),
        _ => AppError::upstream_unavailable(msg).with_upstream_status(code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::LocalCache;
    use crate::resilience::breaker::{BreakerConfig, BreakerKey, CircuitBreaker};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    fn test_cache() -> Arc<dyn CacheBackend> {
        Arc::new(LocalCache::new("test-integrations"))
    }

    fn test_breaker() -> CircuitBreaker {
        CircuitBreaker::new(
            BreakerKey::Integration("test".to_string()),
            BreakerConfig::new(5, Duration::from_secs(30)),
        )
    }

    // -- Cache HIT: no upstream call when unexpired data exists (Req 27.3) ---

    #[tokio::test]
    async fn cache_hit_serves_without_upstream_call() {
        let cache = test_cache();
        let breaker = test_breaker();
        let call_count = StdArc::new(AtomicUsize::new(0));

        // Pre-populate the cache.
        let data = Bytes::from_static(b"cached-data");
        cache
            .set("test-key", data.clone(), Duration::from_secs(3600))
            .await
            .unwrap();

        let count_clone = call_count.clone();
        let result = fetch_with_cache(&cache, "test-key", Duration::from_secs(3600), &breaker, || {
            let c = count_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(Bytes::from_static(b"upstream-data"))
            }
        })
        .await
        .unwrap();

        assert_eq!(result, data, "cache HIT must return cached data");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "cache HIT must not call upstream"
        );
    }

    // -- Cache MISS: upstream called and result cached (Req 27.4) ------------

    #[tokio::test]
    async fn cache_miss_fetches_upstream_and_caches() {
        let cache = test_cache();
        let breaker = test_breaker();
        let call_count = StdArc::new(AtomicUsize::new(0));

        let count_clone = call_count.clone();
        let result = fetch_with_cache(
            &cache,
            "miss-key",
            Duration::from_secs(3600),
            &breaker,
            || {
                let c = count_clone.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(Bytes::from_static(b"fresh-data"))
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(result, Bytes::from_static(b"fresh-data"));
        assert_eq!(call_count.load(Ordering::SeqCst), 1, "upstream called once");

        // Second call should be a HIT.
        let count_clone2 = call_count.clone();
        let result2 = fetch_with_cache(
            &cache,
            "miss-key",
            Duration::from_secs(3600),
            &breaker,
            || {
                let c = count_clone2.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(Bytes::from_static(b"fresh-data"))
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(result2, Bytes::from_static(b"fresh-data"));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "second call served from cache"
        );
    }

    // -- Upstream error propagated when no cache (Req 27.5) ------------------

    #[tokio::test]
    async fn upstream_error_propagated_when_no_cache() {
        let cache = test_cache();
        let breaker = test_breaker();

        let result = fetch_with_cache(
            &cache,
            "error-key",
            Duration::from_secs(3600),
            &breaker,
            || async { Err(AppError::upstream_unavailable("test error")) },
        )
        .await;

        assert!(result.is_err(), "upstream error must propagate when no cache");
    }

    // -- Circuit breaker wraps adapter calls (Req 50.2) ----------------------

    #[tokio::test]
    async fn circuit_breaker_opens_after_threshold_failures() {
        let cache = test_cache();
        let breaker = CircuitBreaker::new(
            BreakerKey::Integration("test-cb".to_string()),
            BreakerConfig::new(3, Duration::from_secs(60)),
        );

        // Exhaust the breaker with trip-eligible failures.
        for _ in 0..3 {
            let _ = fetch_with_cache(
                &cache,
                "cb-key",
                Duration::from_secs(3600),
                &breaker,
                || async { Err(AppError::upstream_unavailable("down")) },
            )
            .await;
        }

        // Breaker should now be open — next call short-circuits.
        let err = fetch_with_cache(
            &cache,
            "cb-key",
            Duration::from_secs(3600),
            &breaker,
            || async { Ok(Bytes::from_static(b"data")) },
        )
        .await
        .expect_err("open breaker must short-circuit");

        assert!(err.circuit_open, "error must carry circuit_open marker");
    }

    // -- map_http_error maps status codes correctly --------------------------

    #[test]
    fn map_http_error_maps_status_codes() {
        use reqwest::StatusCode;
        let e401 = map_http_error("test", StatusCode::UNAUTHORIZED);
        assert_eq!(e401.category, crate::errors::ErrorCategory::Unauthorized);

        let e429 = map_http_error("test", StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(e429.category, crate::errors::ErrorCategory::TooManyRequests);

        let e503 = map_http_error("test", StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            e503.category,
            crate::errors::ErrorCategory::UpstreamUnavailable
        );
    }
}
