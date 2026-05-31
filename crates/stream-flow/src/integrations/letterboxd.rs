//! Letterboxd integration adapter — Req 27.1.
//!
//! Fetches lists from Letterboxd via HTML scraping.

use std::sync::Arc;
use std::time::Duration;

use crate::cache::CacheBackend;
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::resilience::breaker::CircuitBreaker;

use super::{
    fetch_with_cache, integration_breaker, map_http_error, map_reqwest_error, IntegrationList,
    ListItem, INTEGRATION_LETTERBOXD,
};

/// Letterboxd integration adapter (Req 27.1).
#[derive(Clone)]
pub struct LetterboxdAdapter {
    client: Arc<OutboundClient>,
    cache: Arc<dyn CacheBackend>,
    ttl: Duration,
    breaker: Arc<CircuitBreaker>,
    username: String,
}

impl LetterboxdAdapter {
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
            breaker: Arc::new(integration_breaker(INTEGRATION_LETTERBOXD)),
            username: username.into(),
        }
    }

    pub async fn fetch_watchlist(&self) -> Result<IntegrationList, AppError> {
        let url = format!(
            "https://letterboxd.com/{}/watchlist/",
            self.username.trim_matches('/')
        );
        let cache_key = format!("integration:letterboxd:{}:watchlist", self.username);
        let client = Arc::clone(&self.client);
        let bytes = fetch_with_cache(&self.cache, &cache_key, self.ttl, &self.breaker, || {
            let client = Arc::clone(&client);
            let url = url.clone();
            async move {
                let parsed = reqwest::Url::parse(&url)
                    .map_err(|e| AppError::bad_request(format!("invalid Letterboxd URL: {e}")))?;
                let response = client
                    .upstream(reqwest::Method::GET, &parsed)?
                    .send()
                    .await
                    .map_err(|e| map_reqwest_error(INTEGRATION_LETTERBOXD, e))?;
                if !response.status().is_success() {
                    return Err(map_http_error(INTEGRATION_LETTERBOXD, response.status()));
                }
                response
                    .bytes()
                    .await
                    .map_err(|e| map_reqwest_error(INTEGRATION_LETTERBOXD, e))
            }
        })
        .await?;
        parse_watchlist_html(&bytes, &self.username)
    }
}

pub fn parse_watchlist_html(data: &[u8], username: &str) -> Result<IntegrationList, AppError> {
    let html = std::str::from_utf8(data).map_err(|e| {
        AppError::upstream_unavailable(format!("Letterboxd returned non-UTF8 HTML: {e}"))
    })?;
    let document = scraper::Html::parse_document(html);
    let selectors = [
        "li.poster-container",
        "li.film-detail",
        "div.film-poster",
        "li[data-film-name]",
    ];
    let mut items = Vec::new();
    for selector in selectors {
        let selector = scraper::Selector::parse(selector)
            .map_err(|e| AppError::unknown(format!("invalid Letterboxd selector: {e}")))?;
        for node in document.select(&selector) {
            let value = node.value();
            let title = value
                .attr("data-film-name")
                .or_else(|| value.attr("data-item-name"))
                .or_else(|| value.attr("data-original-title"))
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let Some(title) = title else {
                continue;
            };
            let year = value
                .attr("data-film-release-year")
                .or_else(|| value.attr("data-release-year"))
                .and_then(|year| year.parse::<u32>().ok());
            items.push(ListItem {
                title: title.to_string(),
                imdb_id: value.attr("data-imdb-id").map(ToString::to_string),
                tmdb_id: value
                    .attr("data-tmdb-id")
                    .and_then(|id| id.parse::<u64>().ok()),
                content_type: "movie".to_string(),
                year,
            });
        }
        if !items.is_empty() {
            break;
        }
    }
    items.sort_by(|a, b| a.title.cmp(&b.title).then(a.year.cmp(&b.year)));
    items.dedup_by(|a, b| a.title == b.title && a.year == b.year);
    Ok(IntegrationList {
        source: format!("letterboxd:{username}:watchlist"),
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_letterboxd_poster_markup() {
        let html = br#"
        <ul>
          <li class="poster-container" data-film-name="Heat" data-film-release-year="1995" data-tmdb-id="949"></li>
          <li class="poster-container" data-film-name="Arrival" data-film-release-year="2016" data-imdb-id="tt2543164"></li>
        </ul>"#;
        let list = parse_watchlist_html(html, "alice").unwrap();
        assert_eq!(list.source, "letterboxd:alice:watchlist");
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].title, "Arrival");
        assert_eq!(list.items[0].imdb_id.as_deref(), Some("tt2543164"));
        assert_eq!(list.items[1].tmdb_id, Some(949));
    }

    #[test]
    fn parser_deduplicates_title_year_pairs() {
        let html = br#"
        <li data-film-name="Heat" data-film-release-year="1995"></li>
        <li data-film-name="Heat" data-film-release-year="1995"></li>"#;
        let list = parse_watchlist_html(html, "alice").unwrap();
        assert_eq!(list.items.len(), 1);
    }
}
