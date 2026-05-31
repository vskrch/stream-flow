//! Vidoza extractor (`extractor::hosts::vidoza`) — Req 12.2, 12.7.
//!
//! Vidoza serves a plain HTML5 player page: the direct media URL is the `src`
//! of the `<video>`'s `<source>` element (`<source src="https://…/video.mp4"
//! type="video/mp4">`). This is a representative **DOM-based** extractor — it
//! locates the media URL with a CSS selector via [`scraper`] rather than
//! unpacking inline JS.
//!
//! Vidoza is not Cloudflare-gated, so it uses the default rustls client pool.
//! The resolved media URL is returned with a `Referer` header pinned to the
//! page origin (the CDN rejects hot-linked requests without it), satisfying
//! "direct media URL + required playback headers" (Req 12.2). When the page
//! contains no usable `<source>`, an
//! [`ExtractionFailed`](ExtractorError::ExtractionFailed) is returned (Req
//! 12.7).

use std::collections::BTreeMap;

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::extractor::base::{ClientPool, ExtraParams, Extractor, ExtractorError, ExtractorResult};
use crate::extractor::http::ExtractorHttp;

/// The canonical host name (Req 12.1).
pub const HOST: &str = "vidoza";

/// A DOM-based Vidoza extractor.
pub struct VidozaExtractor {
    http: ExtractorHttp,
}

impl VidozaExtractor {
    /// Build a [`VidozaExtractor`] over the shared extractor HTTP layer.
    pub fn new(http: ExtractorHttp) -> Self {
        Self { http }
    }

    /// Locate the direct media URL in the page HTML (pure; unit-testable
    /// without any network). Returns the first `<source src>` whose value
    /// parses as an absolute `http(s)` URL.
    pub fn parse_media_url(html: &str) -> Option<Url> {
        // `Selector::parse` only fails on a malformed selector literal, which
        // these are not; treat a parse failure as "no match" defensively.
        let source_sel = Selector::parse("video source[src], source[src]").ok()?;
        let video_sel = Selector::parse("video[src]").ok()?;
        let document = Html::parse_document(html);

        document
            .select(&source_sel)
            .chain(document.select(&video_sel))
            .filter_map(|el| el.value().attr("src"))
            .filter_map(|src| Url::parse(src.trim()).ok())
            .find(|u| matches!(u.scheme(), "http" | "https"))
    }
}

#[async_trait]
impl Extractor for VidozaExtractor {
    fn host_name(&self) -> &'static str {
        "vidoza"
    }

    fn client_pool(&self) -> ClientPool {
        ClientPool::Default
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
            ExtractorError::extraction_failed(HOST, "no <source src> media URL found in page")
        })?;

        // The CDN rejects hot-linked requests without a Referer pinned to the
        // page origin; merge that in alongside any caller-supplied headers
        // (Req 12.2). Caller headers win on conflict.
        let mut headers = BTreeMap::new();
        headers.insert("Referer".to_string(), origin_referer(url));
        for (name, value) in &extra.headers {
            headers.insert(name.clone(), value.clone());
        }

        Ok(ExtractorResult::with_headers(media, headers))
    }
}

/// The `Referer` value pinned to the page's origin (scheme + host + optional
/// port), with a trailing slash — what the Vidoza CDN expects.
fn origin_referer(url: &Url) -> String {
    match (url.scheme(), url.host_str()) {
        (scheme, Some(host)) => match url.port() {
            Some(port) => format!("{scheme}://{host}:{port}/"),
            None => format!("{scheme}://{host}/"),
        },
        _ => url.to_string(),
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
        <html><body>
          <video id="player" width="640" controls>
            <source src="https://cdn.vidoza.example/get/abc123/video.mp4" type="video/mp4">
          </video>
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
    fn parse_media_url_extracts_source_src() {
        let media = VidozaExtractor::parse_media_url(PAGE).expect("media URL parsed");
        assert_eq!(
            media.as_str(),
            "https://cdn.vidoza.example/get/abc123/video.mp4"
        );
    }

    #[test]
    fn parse_media_url_returns_none_without_source() {
        assert!(VidozaExtractor::parse_media_url("<html><body>no player</body></html>").is_none());
    }

    #[test]
    fn parse_media_url_handles_video_src_fallback() {
        let html = r#"<video src="https://cdn.example/v.mp4"></video>"#;
        let media = VidozaExtractor::parse_media_url(html).expect("video[src] fallback");
        assert_eq!(media.as_str(), "https://cdn.example/v.mp4");
    }

    #[tokio::test]
    async fn extract_resolves_media_and_pins_referer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/watch"))
            .respond_with(ResponseTemplate::new(200).set_body_string(PAGE))
            .mount(&server)
            .await;

        let extractor = VidozaExtractor::new(http(EgressPolicy::FailOpen));
        let page = Url::parse(&format!("{}/watch", server.uri())).unwrap();
        let result = extractor
            .extract(&page, &ExtraParams::empty())
            .await
            .expect("extraction succeeds");

        assert_eq!(
            result.url.as_str(),
            "https://cdn.vidoza.example/get/abc123/video.mp4"
        );
        // A Referer pinned to the page origin must be attached (Req 12.2).
        let expected_referer = format!("{}/", server.uri());
        assert_eq!(result.headers.get("Referer"), Some(&expected_referer));
    }

    #[tokio::test]
    async fn extract_merges_caller_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/watch"))
            .respond_with(ResponseTemplate::new(200).set_body_string(PAGE))
            .mount(&server)
            .await;

        let extractor = VidozaExtractor::new(http(EgressPolicy::FailOpen));
        let page = Url::parse(&format!("{}/watch", server.uri())).unwrap();
        let extra = ExtraParams::with_headers([("Cookie".to_string(), "sess=1".to_string())]);
        let result = extractor.extract(&page, &extra).await.expect("extraction succeeds");
        assert_eq!(result.headers.get("Cookie"), Some(&"sess=1".to_string()));
        assert!(result.headers.contains_key("Referer"));
    }

    #[tokio::test]
    async fn extract_fails_when_no_media_in_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/watch"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>no player</html>"))
            .mount(&server)
            .await;

        let extractor = VidozaExtractor::new(http(EgressPolicy::FailOpen));
        let page = Url::parse(&format!("{}/watch", server.uri())).unwrap();
        let err = extractor
            .extract(&page, &ExtraParams::empty())
            .await
            .expect_err("a page with no media must fail extraction");
        match err {
            ExtractorError::ExtractionFailed { host, .. } => assert_eq!(host, "vidoza"),
            other => panic!("expected ExtractionFailed, got {other:?}"),
        }
    }
}
