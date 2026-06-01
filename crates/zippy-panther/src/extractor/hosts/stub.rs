//! Structured stub extractor (`extractor::hosts::stub`) — Req 12.1.
//!
//! A [`StubExtractor`] is registered for every supported host whose bespoke
//! scraping logic is not yet implemented. It is **registered** so the
//! [`ExtractorFactory`](crate::extractor::ExtractorFactory) contract — the
//! case-insensitive host match (Req 12.1) and the header propagation /
//! client-pool selection plumbing — is fully exercised for all 24 hosts, while
//! [`extract`](StubExtractor::extract) returns a clear, typed
//! [`ExtractorError::NotImplemented`] (→ `404`) rather than a generic failure.
//!
//! This keeps "supported but not-yet-scraped" cleanly distinct from
//! "unsupported host" ([`ExtractorError::UnsupportedHost`] → `400`, Req 12.6)
//! and from "page had no media" ([`ExtractorError::ExtractionFailed`] → `502`,
//! Req 12.7).

use async_trait::async_trait;
use url::Url;

use crate::extractor::base::{ClientPool, ExtraParams, Extractor, ExtractorError, ExtractorResult};

/// A registered-but-unimplemented extractor for a supported host (Req 12.1).
pub struct StubExtractor {
    /// The canonical lowercase host name (one of the 24 supported hosts).
    host: &'static str,
    /// The client pool the eventual real implementation will use, declared up
    /// front so the registry's pool selection is wired correctly even while
    /// the scraping logic is a stub.
    pool: ClientPool,
}

impl StubExtractor {
    /// A stub for `host` that will use the default rustls client pool.
    pub fn new(host: &'static str) -> Self {
        Self {
            host,
            pool: ClientPool::Default,
        }
    }

    /// A stub for `host` declaring the client pool its real implementation will
    /// require (e.g. [`ClientPool::Impersonate`] for a Cloudflare-fronted
    /// host).
    pub fn with_pool(host: &'static str, pool: ClientPool) -> Self {
        Self { host, pool }
    }
}

#[async_trait]
impl Extractor for StubExtractor {
    fn host_name(&self) -> &'static str {
        self.host
    }

    fn client_pool(&self) -> ClientPool {
        self.pool
    }

    async fn extract(
        &self,
        _url: &Url,
        _extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        Err(ExtractorError::not_implemented(self.host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_returns_not_implemented_naming_the_host() {
        let stub = StubExtractor::new("vavoo");
        assert_eq!(stub.host_name(), "vavoo");
        let err = stub
            .extract(
                &Url::parse("https://vavoo.to/watch/123").unwrap(),
                &ExtraParams::empty(),
            )
            .await
            .expect_err("a stub extractor must report not-implemented");
        match err {
            ExtractorError::NotImplemented { host } => assert_eq!(host, "vavoo"),
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn with_pool_declares_the_client_pool() {
        let stub = StubExtractor::with_pool("voe", ClientPool::Impersonate);
        assert_eq!(stub.client_pool(), ClientPool::Impersonate);
    }
}
