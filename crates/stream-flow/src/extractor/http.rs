//! Shared extractor HTTP layer (`extractor::http`) — Req 12.2, 12.4, 12.5.
//!
//! [`ExtractorHttp`] is the single page-fetching seam every concrete extractor
//! uses to retrieve the host page HTML, so no extractor owns an HTTP client
//! directly. It funnels all upstream I/O through the shared egress
//! [`OutboundClient`](crate::egress::OutboundClient) (Req 51.1) and selects the
//! correct client pool per the host's [`ClientPool`] (design: Components →
//! Extractor "two client pools"):
//!
//! * [`ClientPool::Default`] → the rustls `reqwest` client
//!   ([`OutboundClient::upstream`]);
//! * [`ClientPool::Impersonate`] → the Chrome JA3/JA4 `wreq` client
//!   ([`OutboundClient::impersonate`]) so Cloudflare-fronted hosts see a real
//!   browser fingerprint (Req 12.4, 35.5);
//! * [`ClientPool::Byparr`] → the configured Byparr (FlareSolverr-style)
//!   solver ([`Byparr`]) when a bypass URL is configured (Req 12.5), falling
//!   back to the impersonation client otherwise.

use std::collections::BTreeMap;
use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use url::Url;

use crate::config::ExtractorConfig;
use crate::egress::OutboundClient;
use crate::errors::AppError;

use super::base::ClientPool;
use super::byparr::Byparr;

/// The maximum page body buffered while extracting, guarding against a hostile
/// / oversized "page". Host landing pages are tens-to-hundreds of kilobytes;
/// this cap keeps a single fetch from exhausting memory on a small VPS.
const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;

/// The shared page-fetching layer over the egress seam (design: Components →
/// Extractor). Cheaply cloneable (an `Arc` bump) so every extractor entry can
/// hold its own handle.
#[derive(Clone)]
pub struct ExtractorHttp {
    /// The single outbound seam — the only path to the network (Req 51.1).
    client: Arc<OutboundClient>,
    /// The optional Byparr (FlareSolverr-style) solver, present when a bypass
    /// URL is configured (Req 12.5).
    byparr: Option<Byparr>,
}

impl ExtractorHttp {
    /// Build an [`ExtractorHttp`] over the shared egress client with an
    /// explicit (optional) Byparr solver.
    pub fn new(client: Arc<OutboundClient>, byparr: Option<Byparr>) -> Self {
        Self { client, byparr }
    }

    /// Build an [`ExtractorHttp`] from the [`ExtractorConfig`], wiring a
    /// [`Byparr`] solver when `byparr_url` is configured (Req 12.5).
    pub fn from_config(client: Arc<OutboundClient>, cfg: &ExtractorConfig) -> Self {
        let byparr = cfg
            .byparr_url
            .as_deref()
            .map(|url| Byparr::new(client.clone(), url.to_string(), cfg.byparr_timeout_secs));
        Self::new(client, byparr)
    }

    /// Whether a Byparr (FlareSolverr-style) solver is configured (Req 12.5).
    pub fn has_byparr(&self) -> bool {
        self.byparr.is_some()
    }

    /// Fetch the host page at `url` as text, forwarding `headers` (Req 12.2)
    /// and using the client pool the host requires (Req 12.4, 12.5).
    ///
    /// A network error, non-2xx upstream, or egress refusal surfaces a typed
    /// [`AppError`] carrying the upstream HTTP status when one was received.
    pub async fn fetch_page(
        &self,
        url: &Url,
        headers: &BTreeMap<String, String>,
        pool: ClientPool,
    ) -> Result<String, AppError> {
        match pool {
            ClientPool::Default => self.fetch_default(url, headers).await,
            ClientPool::Impersonate => self.fetch_impersonate(url, headers).await,
            ClientPool::Byparr => match &self.byparr {
                // A configured Byparr solver resolves the challenge and returns
                // the page content (Req 12.5).
                Some(byparr) => byparr.fetch(url, headers).await,
                // No solver configured → fall back to browser-TLS impersonation
                // so a Cloudflare-fronted host still has a chance (Req 12.4).
                None => self.fetch_impersonate(url, headers).await,
            },
        }
    }

    /// Fetch through the default rustls `reqwest` client.
    async fn fetch_default(
        &self,
        url: &Url,
        headers: &BTreeMap<String, String>,
    ) -> Result<String, AppError> {
        let mut builder = self.client.upstream(Method::GET, url)?;
        let header_map = to_header_map(headers);
        if !header_map.is_empty() {
            builder = builder.headers(header_map);
        }
        let resp = builder.send().await.map_err(|e| map_send_error(url, e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(upstream_status_error(url, status.as_u16()));
        }
        let bytes = resp.bytes().await.map_err(|e| map_send_error(url, e))?;
        decode_body(url, &bytes)
    }

    /// Fetch through the Chrome JA3/JA4 impersonation `wreq` client (Req 12.4,
    /// 35.5).
    async fn fetch_impersonate(
        &self,
        url: &Url,
        headers: &BTreeMap<String, String>,
    ) -> Result<String, AppError> {
        let mut builder = self.client.impersonate(Method::GET, url)?;
        for (name, value) in headers {
            // `wreq` re-exports the http `header` types; build them defensively
            // and skip any invalid pair (these are config/extractor-supplied,
            // never inbound client headers, so they carry no client IP).
            if let (Ok(name), Ok(value)) = (
                wreq::header::HeaderName::from_bytes(name.as_bytes()),
                wreq::header::HeaderValue::from_str(value),
            ) {
                builder = builder.header(name, value);
            }
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| map_impersonate_error(url, e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(upstream_status_error(url, status.as_u16()));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| map_impersonate_error(url, e))?;
        decode_body(url, &bytes)
    }
}

/// Convert a `name → value` header map into a `reqwest` [`HeaderMap`],
/// skipping any entry whose name or value is not a valid HTTP header. These
/// are config/extractor-supplied, never inbound client headers, so they carry
/// no client IP.
fn to_header_map(headers: &BTreeMap<String, String>) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) else {
            continue;
        };
        map.insert(name, value);
    }
    map
}

/// Decode an upstream page body to text, enforcing the size cap. Page bodies
/// are HTML/JS; decoded lossily so a stray non-UTF-8 byte never fails an
/// otherwise-usable page.
fn decode_body(url: &Url, bytes: &[u8]) -> Result<String, AppError> {
    if bytes.len() > MAX_PAGE_BYTES {
        return Err(AppError::payload_too_large(format!(
            "extractor page from {url} exceeds {MAX_PAGE_BYTES} bytes"
        )));
    }
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// Build the "upstream returned HTTP N" error carrying the upstream status.
fn upstream_status_error(url: &Url, status: u16) -> AppError {
    AppError::upstream_unavailable(format!(
        "extractor page request to {url} returned HTTP {status}"
    ))
    .with_upstream_status(status)
}

/// Map a `reqwest` send/read error onto the canonical taxonomy.
fn map_send_error(url: &Url, err: reqwest::Error) -> AppError {
    let host = url.host_str().unwrap_or("<unknown>");
    let app =
        AppError::upstream_unavailable(format!("extractor page request to {host} failed: {err}"));
    match err.status() {
        Some(status) => app.with_upstream_status(status.as_u16()),
        None => app,
    }
}

/// Map a `wreq` send/read error onto the canonical taxonomy.
fn map_impersonate_error(url: &Url, err: wreq::Error) -> AppError {
    let host = url.host_str().unwrap_or("<unknown>");
    AppError::upstream_unavailable(format!(
        "extractor impersonation request to {host} failed: {err}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::egress::CLIENT_IDENTIFYING_HEADERS;
    use crate::errors::ErrorCategory;
    use std::sync::{Arc as StdArc, Mutex};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An [`OutboundClient`] with no tunnel under the given policy (mirrors the
    /// `hls::fetch` / `epg` test harness): `FailOpen` dials the in-process
    /// wiremock origin directly; `FailClosed` refuses with no dial.
    fn outbound(policy: EgressPolicy) -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn http(policy: EgressPolicy) -> ExtractorHttp {
        ExtractorHttp::new(outbound(policy), None)
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[tokio::test]
    async fn fetches_page_text_through_default_pool() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/watch"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>media</html>"))
            .mount(&server)
            .await;

        let body = http(EgressPolicy::FailOpen)
            .fetch_page(
                &url(&format!("{}/watch", server.uri())),
                &BTreeMap::new(),
                ClientPool::Default,
            )
            .await
            .expect("page fetch succeeds");
        assert_eq!(body, "<html>media</html>");
    }

    #[tokio::test]
    async fn forwards_custom_headers_to_page_fetch() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/watch"))
            .and(header("referer", "https://host.example/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let mut headers = BTreeMap::new();
        headers.insert("Referer".to_string(), "https://host.example/".to_string());

        let body = http(EgressPolicy::FailOpen)
            .fetch_page(
                &url(&format!("{}/watch", server.uri())),
                &headers,
                ClientPool::Default,
            )
            .await
            .expect("forwarded header must match the upstream mock");
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn upstream_http_error_carries_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/gone"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let err = http(EgressPolicy::FailOpen)
            .fetch_page(
                &url(&format!("{}/gone", server.uri())),
                &BTreeMap::new(),
                ClientPool::Default,
            )
            .await
            .expect_err("a 503 upstream must surface as an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(503));
    }

    #[tokio::test]
    async fn fetch_is_gated_by_fail_closed_egress() {
        let err = http(EgressPolicy::FailClosed)
            .fetch_page(
                &url("https://host.example/watch"),
                &BTreeMap::new(),
                ClientPool::Default,
            )
            .await
            .expect_err("fail-closed egress must refuse the page dial");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("egress tunnel"));
    }

    #[tokio::test]
    async fn page_fetch_carries_no_client_identifying_headers() {
        let server = MockServer::start().await;
        let seen: StdArc<Mutex<Vec<String>>> = StdArc::new(Mutex::new(Vec::new()));
        let seen_clone = seen.clone();
        Mock::given(method("GET"))
            .and(path("/watch"))
            .respond_with(move |req: &wiremock::Request| {
                let mut names = seen_clone.lock().unwrap();
                for h in req.headers.iter() {
                    names.push(h.0.as_str().to_ascii_lowercase());
                }
                ResponseTemplate::new(200).set_body_string("ok")
            })
            .mount(&server)
            .await;

        let _ = http(EgressPolicy::FailOpen)
            .fetch_page(
                &url(&format!("{}/watch", server.uri())),
                &BTreeMap::new(),
                ClientPool::Default,
            )
            .await
            .expect("fetch succeeds");

        let names = seen.lock().unwrap();
        for forbidden in CLIENT_IDENTIFYING_HEADERS {
            assert!(
                !names.iter().any(|n| n == forbidden),
                "page request must not carry client-identifying header {forbidden}; saw {names:?}",
            );
        }
    }

    #[test]
    fn from_config_wires_byparr_when_url_configured() {
        let client = outbound(EgressPolicy::FailOpen);
        let no_byparr = ExtractorHttp::from_config(client.clone(), &ExtractorConfig::default());
        assert!(!no_byparr.has_byparr());

        let cfg = ExtractorConfig {
            byparr_url: Some("http://byparr:8191/v1".to_string()),
            byparr_timeout_secs: 30,
        };
        let with_byparr = ExtractorHttp::from_config(client, &cfg);
        assert!(with_byparr.has_byparr());
    }
}
