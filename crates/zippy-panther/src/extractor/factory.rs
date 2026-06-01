//! Extractor factory / registry (`extractor::factory`) — Req 12.1, 12.2, 12.6.
//!
//! [`ExtractorFactory`] maps a **case-insensitive** host name (Req 12.1) onto
//! the [`Extractor`] that handles it, registering an entry for **every** one of
//! the 24 supported hosts (design: Components → Extractor "registry by host
//! name"). Two hosts have real parsing logic
//! ([`VidozaExtractor`](crate::extractor::hosts::vidoza::VidozaExtractor),
//! [`StreamtapeExtractor`](crate::extractor::hosts::streamtape::StreamtapeExtractor));
//! the remaining 22 are registered with a structured
//! [`StubExtractor`](crate::extractor::hosts::stub::StubExtractor) that returns
//! a typed [`NotImplemented`](ExtractorError::NotImplemented) error — so the
//! registry contract (host matching, header propagation, client-pool
//! selection) is fully implemented and tested for all 24.
//!
//! A request naming a host **not** in the registry yields
//! [`UnsupportedHost`](ExtractorError::UnsupportedHost) → `400` (Req 12.6); a
//! request naming a supported host resolves the page URL into a direct media
//! URL + playback headers (Req 12.2).

use std::collections::HashMap;
use std::sync::Arc;

use url::Url;

use crate::config::ExtractorConfig;
use crate::egress::OutboundClient;

use super::base::{ClientPool, ExtraParams, Extractor, ExtractorError, ExtractorResult};
use super::hosts::streamtape::StreamtapeExtractor;
use super::hosts::stub::StubExtractor;
use super::hosts::vidoza::VidozaExtractor;
use super::http::ExtractorHttp;

/// The 24 supported extractor host names, lowercase canonical form (Req 12.1).
///
/// Hosts annotated with a [`ClientPool`] hint here drive the stub registration
/// so an unimplemented Cloudflare-fronted host already declares the
/// impersonation pool; the two concrete extractors (`vidoza`, `streamtape`)
/// declare their own pool and are not stubbed.
pub const SUPPORTED_HOSTS: [&str; 24] = [
    "city",
    "doodstream",
    "f16px",
    "fastream",
    "filelions",
    "filemoon",
    "gupload",
    "livetv",
    "lulustream",
    "maxstream",
    "mixdrop",
    "okru",
    "sportsonline",
    "streamtape",
    "streamwish",
    "supervideo",
    "turbovidplay",
    "uqload",
    "vavoo",
    "vidfast",
    "vidmoly",
    "vidoza",
    "vixcloud",
    "voe",
];

/// Hosts whose (stubbed) implementation will require the browser-TLS
/// impersonation pool because they are Cloudflare-fronted (Req 12.4). The stub
/// declares the correct pool up front so the registry's pool selection is
/// exercised even before the scraping logic lands.
const IMPERSONATE_HOSTS: [&str; 7] = [
    "doodstream",
    "filelions",
    "filemoon",
    "mixdrop",
    "streamwish",
    "vidmoly",
    "voe",
];

/// The case-insensitive registry of host extractors (design: Components →
/// Extractor).
pub struct ExtractorFactory {
    /// Host name (lowercase) → the extractor that handles it. Every one of the
    /// 24 supported hosts has an entry (Req 12.1).
    registry: HashMap<&'static str, Arc<dyn Extractor>>,
}

impl ExtractorFactory {
    /// Build the registry from the shared egress client and extractor config,
    /// wiring the shared [`ExtractorHttp`] (with the optional Byparr solver,
    /// Req 12.5) into every entry.
    ///
    /// Registers the two concrete extractors and a structured stub for each of
    /// the remaining 22 supported hosts, so all 24 (Req 12.1) resolve through
    /// the same factory contract.
    pub fn from_config(client: Arc<OutboundClient>, cfg: &ExtractorConfig) -> Self {
        let http = ExtractorHttp::from_config(client, cfg);
        Self::with_http(http)
    }

    /// Build the registry over an already-constructed [`ExtractorHttp`] (used
    /// by tests to inject a mock-backed HTTP layer).
    pub fn with_http(http: ExtractorHttp) -> Self {
        let mut registry: HashMap<&'static str, Arc<dyn Extractor>> = HashMap::new();

        // -- Concrete extractors (real parsing logic) ----------------------
        registry.insert(
            "vidoza",
            Arc::new(VidozaExtractor::new(http.clone())) as Arc<dyn Extractor>,
        );
        registry.insert(
            "streamtape",
            Arc::new(StreamtapeExtractor::new(http.clone())) as Arc<dyn Extractor>,
        );

        // -- Structured stubs for the remaining supported hosts ------------
        // Every supported host that is not concrete is registered with a stub
        // declaring the client pool its real implementation will use, so the
        // registry contract is complete for all 24 (Req 12.1).
        for host in SUPPORTED_HOSTS {
            if registry.contains_key(host) {
                continue; // already a concrete extractor
            }
            let pool = if IMPERSONATE_HOSTS.contains(&host) {
                ClientPool::Impersonate
            } else {
                ClientPool::Default
            };
            registry.insert(host, Arc::new(StubExtractor::with_pool(host, pool)));
        }

        Self { registry }
    }

    /// Look up the extractor for `host`, matched **case-insensitively** (Req
    /// 12.1).
    ///
    /// Returns [`UnsupportedHost`](ExtractorError::UnsupportedHost) when no
    /// registered host matches (Req 12.6).
    pub fn get(&self, host: &str) -> Result<&Arc<dyn Extractor>, ExtractorError> {
        let key = host.trim().to_ascii_lowercase();
        self.registry
            .get(key.as_str())
            .ok_or_else(|| ExtractorError::UnsupportedHost(host.to_string()))
    }

    /// Whether `host` is supported (case-insensitive, Req 12.1).
    pub fn is_supported(&self, host: &str) -> bool {
        self.registry
            .contains_key(host.trim().to_ascii_lowercase().as_str())
    }

    /// The number of registered hosts (always the full 24).
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Whether the registry is empty (it never is in practice).
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    /// Resolve `page_url` for `host` into a direct media URL + playback headers
    /// (Req 12.2), dispatching to the registered extractor.
    ///
    /// This is the factory's single entry point: it performs the
    /// case-insensitive host match (Req 12.1, 12.6) and forwards the custom
    /// request headers (Req 12.2) to the host's extractor, which fetches the
    /// page through the correct client pool (Req 12.4, 12.5) and locates the
    /// media URL.
    pub async fn extract(
        &self,
        host: &str,
        page_url: &Url,
        extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError> {
        let extractor = self.get(host)?;
        extractor.extract(page_url, extra).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    fn factory() -> ExtractorFactory {
        ExtractorFactory::with_http(http(EgressPolicy::FailOpen))
    }

    // -- Req 12.1: all 24 hosts registered ----------------------------------

    #[test]
    fn registers_all_twenty_four_supported_hosts() {
        let factory = factory();
        assert_eq!(
            factory.len(),
            24,
            "all 24 supported hosts must be registered"
        );
        for host in SUPPORTED_HOSTS {
            assert!(
                factory.is_supported(host),
                "host `{host}` must be registered"
            );
        }
    }

    #[test]
    fn supported_hosts_list_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for host in SUPPORTED_HOSTS {
            assert!(
                seen.insert(host),
                "duplicate host in SUPPORTED_HOSTS: {host}"
            );
        }
    }

    // -- Req 12.1: host match is case-insensitive ---------------------------

    #[test]
    fn host_match_is_case_insensitive() {
        let factory = factory();
        for variant in ["VOE", "Voe", "vOe", "  voe  ", "VIDOZA", "StreamTape"] {
            assert!(
                factory.is_supported(variant),
                "case/whitespace variant `{variant}` must match",
            );
            assert!(factory.get(variant).is_ok());
        }
    }

    // -- Req 12.6: unsupported host -> UnsupportedHost -----------------------

    #[test]
    fn unsupported_host_is_rejected() {
        let factory = factory();
        let err = match factory.get("notahost") {
            Ok(_) => panic!("unknown host must be rejected"),
            Err(err) => err,
        };
        match err {
            ExtractorError::UnsupportedHost(h) => assert_eq!(h, "notahost"),
            other => panic!("expected UnsupportedHost, got {other:?}"),
        }
        assert!(!factory.is_supported("notahost"));
    }

    // -- Concrete vs stub pool wiring ---------------------------------------

    #[test]
    fn concrete_extractors_declare_their_pools() {
        let factory = factory();
        assert_eq!(
            factory.get("vidoza").unwrap().client_pool(),
            ClientPool::Default
        );
        assert_eq!(
            factory.get("streamtape").unwrap().client_pool(),
            ClientPool::Impersonate
        );
    }

    #[test]
    fn cloudflare_fronted_stub_hosts_declare_impersonation_pool() {
        let factory = factory();
        for host in IMPERSONATE_HOSTS {
            assert_eq!(
                factory.get(host).unwrap().client_pool(),
                ClientPool::Impersonate,
                "Cloudflare-fronted host `{host}` must declare the impersonation pool",
            );
        }
    }

    // -- Req 12.1/12.2: dispatch to a concrete extractor through the factory -

    #[tokio::test]
    async fn extract_dispatches_to_concrete_extractor_case_insensitively() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/watch"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<video><source src="https://cdn.example/v.mp4" type="video/mp4"></video>"#,
            ))
            .mount(&server)
            .await;

        let factory = factory();
        let page = Url::parse(&format!("{}/watch", server.uri())).unwrap();
        // Mixed-case host name still dispatches (Req 12.1).
        let result = factory
            .extract("ViDoZa", &page, &ExtraParams::empty())
            .await
            .expect("dispatch + extraction succeeds");
        assert_eq!(result.url.as_str(), "https://cdn.example/v.mp4");
        // The required playback header is propagated (Req 12.2).
        assert!(result.headers.contains_key("Referer"));
    }

    // -- Stub hosts return a typed NotImplemented through the factory --------

    #[tokio::test]
    async fn stub_host_returns_not_implemented_through_factory() {
        let factory = factory();
        let page = Url::parse("https://vavoo.to/watch/1").unwrap();
        let err = factory
            .extract("vavoo", &page, &ExtraParams::empty())
            .await
            .expect_err("a stubbed host must report not-implemented");
        match err {
            ExtractorError::NotImplemented { host } => assert_eq!(host, "vavoo"),
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    // -- Req 12.2: custom headers propagate through the factory to the result -

    #[tokio::test]
    async fn factory_forwards_custom_headers_into_result() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/watch"))
            .and(wiremock::matchers::header("x-token", "abc"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"<video><source src="https://cdn.example/v.mp4"></video>"#),
            )
            .mount(&server)
            .await;

        let factory = factory();
        let page = Url::parse(&format!("{}/watch", server.uri())).unwrap();
        let extra = ExtraParams::with_headers([("X-Token".to_string(), "abc".to_string())]);
        let result = factory
            .extract("vidoza", &page, &extra)
            .await
            .expect("forwarded header must match the upstream mock");
        // The caller header is merged into the playback headers (Req 12.2).
        assert_eq!(result.headers.get("X-Token"), Some(&"abc".to_string()));
    }
}
