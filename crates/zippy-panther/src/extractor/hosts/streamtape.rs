//! Streamtape extractor (`extractor::hosts::streamtape`) — Req 12.2, 12.4,
//! 12.7.
//!
//! Streamtape hides the direct media URL behind a tiny inline-JS obfuscation:
//! the page assembles the link by concatenating a visible prefix with a
//! `.substring(n)` slice of a second token string, e.g.
//!
//! ```js
//! document.getElementById('robotlink').innerHTML =
//!     '//streamtape.com/get_video?id=ABC&expires=123' + ('xxxxtoken=DEF').substring(4);
//! ```
//!
//! which evaluates to `//streamtape.com/get_video?id=ABC&expires=123&token=DEF`.
//! This is a representative **regex / inline-JS** extractor — the link builder
//! is not expressible as a DOM query, so it is recovered with a [`regex`]
//! rather than [`scraper`](https://docs.rs/scraper).
//!
//! Streamtape is Cloudflare-fronted, so it uses the browser-TLS impersonation
//! client pool (Req 12.4, 35.5). The page yielding no recoverable link →
//! [`ExtractionFailed`](ExtractorError::ExtractionFailed) (Req 12.7).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use async_trait::async_trait;
use regex::Regex;
use url::Url;

use crate::extractor::base::{ClientPool, ExtraParams, Extractor, ExtractorError, ExtractorResult};
use crate::extractor::http::ExtractorHttp;

/// The canonical host name (Req 12.1).
pub const HOST: &str = "streamtape";

/// A regex/inline-JS Streamtape extractor.
pub struct StreamtapeExtractor {
    http: ExtractorHttp,
}

/// The compiled link-builder regex, built once. Captures the visible prefix
/// (group 1), the token string (group 2), and the `substring` start offset
/// (group 3) from the `innerHTML = '...' + ('...').substring(n)` assignment.
fn link_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // innerHTML = '<prefix>' + ('<token>').substring(<n>)
        Regex::new(
            r#"innerHTML\s*=\s*['"]([^'"]*)['"]\s*\+\s*\(\s*['"]([^'"]*)['"]\s*\)\s*\.substring\(\s*(\d+)\s*\)"#,
        )
        .expect("streamtape link regex is valid")
    })
}

impl StreamtapeExtractor {
    /// Build a [`StreamtapeExtractor`] over the shared extractor HTTP layer.
    pub fn new(http: ExtractorHttp) -> Self {
        Self { http }
    }

    /// Recover the direct media URL from the page HTML (pure; unit-testable
    /// without any network).
    ///
    /// Replicates the page's `prefix + token.substring(n)` assembly and
    /// normalizes the protocol-relative result to an absolute `https` URL.
    pub fn parse_media_url(html: &str) -> Option<Url> {
        let caps = link_regex().captures(html)?;
        let prefix = caps.get(1)?.as_str();
        let token = caps.get(2)?.as_str();
        let start: usize = caps.get(3)?.as_str().parse().ok()?;

        // `String::substring(n)` in JS slices from char index `n`; mirror that
        // on char boundaries so multi-byte tokens are handled correctly.
        let suffix: String = token.chars().skip(start).collect();
        let assembled = format!("{prefix}{suffix}");

        let absolute = if let Some(rest) = assembled.strip_prefix("//") {
            format!("https://{rest}")
        } else if assembled.starts_with("http://") || assembled.starts_with("https://") {
            assembled
        } else {
            format!("https://{assembled}")
        };

        Url::parse(&absolute)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"))
    }
}

#[async_trait]
impl Extractor for StreamtapeExtractor {
    fn host_name(&self) -> &'static str {
        "streamtape"
    }

    fn client_pool(&self) -> ClientPool {
        // Cloudflare-fronted → browser-TLS impersonation (Req 12.4, 35.5).
        ClientPool::Impersonate
    }

    async fn extract(
        &self,
        url: &Url,
        extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        let html = self
            .http
            .fetch_page(url, &extra.headers, self.client_pool())
            .await?;

        let media = Self::parse_media_url(&html).ok_or_else(|| {
            ExtractorError::extraction_failed(HOST, "no get_video link found in page JS")
        })?;

        // Streamtape's CDN gate accepts the token-bearing URL directly; forward
        // any caller-supplied headers for parity (Req 12.2).
        let headers: BTreeMap<String, String> = extra.headers.clone();
        Ok(ExtractorResult::with_headers(media, headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::egress::OutboundClient;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PAGE: &str = r#"
        <html><head></head><body>
          <div id="robotlink" style="display:none;"></div>
          <script>
            document.getElementById('robotlink').innerHTML = '//streamtape.com/get_video?id=ABC123&expires=999' + ('zzzz&token=DEF456').substring(4);
          </script>
        </body></html>
    "#;

    fn http(policy: EgressPolicy) -> ExtractorHttp {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let client = Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"));
        ExtractorHttp::new(client, None)
    }

    #[test]
    fn parse_media_url_assembles_substring_link() {
        let media = StreamtapeExtractor::parse_media_url(PAGE).expect("link assembled");
        assert_eq!(
            media.as_str(),
            "https://streamtape.com/get_video?id=ABC123&expires=999&token=DEF456"
        );
    }

    #[test]
    fn parse_media_url_returns_none_without_link_js() {
        assert!(StreamtapeExtractor::parse_media_url("<html>no script</html>").is_none());
    }

    #[test]
    fn parse_media_url_handles_double_quoted_js() {
        let html = r#"<script>x.innerHTML = "//streamtape.com/get_video?id=Q" + ("0000W").substring(4);</script>"#;
        let media = StreamtapeExtractor::parse_media_url(html).expect("double-quoted form parsed");
        assert_eq!(media.as_str(), "https://streamtape.com/get_video?id=QW");
    }

    #[test]
    fn uses_impersonation_pool() {
        let extractor = StreamtapeExtractor::new(http(EgressPolicy::FailOpen));
        assert_eq!(extractor.client_pool(), ClientPool::Impersonate);
    }

    #[tokio::test]
    async fn extract_resolves_media_via_impersonation_pool() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v/abc/movie.html"))
            .respond_with(ResponseTemplate::new(200).set_body_string(PAGE))
            .mount(&server)
            .await;

        let extractor = StreamtapeExtractor::new(http(EgressPolicy::FailOpen));
        let page = Url::parse(&format!("{}/v/abc/movie.html", server.uri())).unwrap();
        let result = extractor
            .extract(&page, &ExtraParams::empty())
            .await
            .expect("extraction succeeds");
        assert_eq!(
            result.url.as_str(),
            "https://streamtape.com/get_video?id=ABC123&expires=999&token=DEF456"
        );
    }

    #[tokio::test]
    async fn extract_fails_when_no_link_in_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v/abc/movie.html"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>no script</html>"))
            .mount(&server)
            .await;

        let extractor = StreamtapeExtractor::new(http(EgressPolicy::FailOpen));
        let page = Url::parse(&format!("{}/v/abc/movie.html", server.uri())).unwrap();
        let err = extractor
            .extract(&page, &ExtraParams::empty())
            .await
            .expect_err("a page with no link must fail extraction");
        match err {
            ExtractorError::ExtractionFailed { host, .. } => assert_eq!(host, "streamtape"),
            other => panic!("expected ExtractionFailed, got {other:?}"),
        }
    }
}
