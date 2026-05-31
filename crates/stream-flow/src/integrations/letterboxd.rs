//! Letterboxd integration adapter — Req 27.1.
//!
//! Fetches lists from Letterboxd via HTML scraping. Implementation is a stub
//! pending task 27.1 completion.

use std::sync::Arc;
use std::time::Duration;

use crate::cache::CacheBackend;
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::resilience::breaker::CircuitBreaker;

use super::{integration_breaker, IntegrationList, INTEGRATION_LETTERBOXD};

/// Letterboxd integration adapter (stub — Req 27.1).
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

    /// Fetch the user's watchlist (stub — not yet implemented).
    pub async fn fetch_watchlist(&self) -> Result<IntegrationList, AppError> {
        Err(AppError::not_found(
            "Letterboxd integration is not yet implemented",
        ))
    }
}
