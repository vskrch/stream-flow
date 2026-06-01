//! Extractor trait, request/result types, error taxonomy, and client-pool
//! selector (`extractor::base`) — Req 12.
//!
//! This is the contract every concrete host extractor implements (design:
//! Components → Extractor (+Byparr)). A [`Extractor`] resolves a streaming
//! *page* URL on a supported host into a direct, playable media URL plus the
//! request headers required to play it (Req 12.2), and declares which
//! [`ClientPool`] the upstream page fetch must use (Req 12.4, 12.5).
//!
//! All upstream HTTP is performed through the shared
//! [`ExtractorHttp`](crate::extractor::ExtractorHttp) over the single egress
//! seam ([`OutboundClient`](crate::egress::OutboundClient)), so every page
//! fetch is tunnelled and carries no client-identifying header (Req 51.1–51.3).
//! Concrete extractors therefore never own an HTTP client directly.

use std::collections::BTreeMap;

use async_trait::async_trait;
use url::Url;

use crate::errors::AppError;

/// Which of the two client pools (plus the Byparr fallback) a host's page
/// fetch must go through (Req 12.4, 12.5; design: Extractor "two client
/// pools").
///
/// The pool is a *property of the host*: a plain host fetches with the default
/// rustls client, a Cloudflare-fronted host needs the browser-TLS
/// impersonation client so JA3/JA4 fingerprinting does not block it, and a
/// challenge-protected host prefers the configured Byparr (FlareSolverr-style)
/// solver and falls back to impersonation when none is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPool {
    /// Default `reqwest` (rustls) client — for hosts with no TLS fingerprint
    /// gate.
    Default,
    /// `wreq`/`wreq-util` Chrome JA3/JA4 impersonation client — for
    /// Cloudflare-fronted hosts that require browser TLS (Req 12.4, 35.5).
    Impersonate,
    /// Prefer the configured Byparr (FlareSolverr-style) bypass service to
    /// obtain the page content for challenge-protected hosts (Req 12.5); when
    /// no Byparr URL is configured the fetch falls back to [`Impersonate`].
    ///
    /// [`Impersonate`]: ClientPool::Impersonate
    Byparr,
}

/// Per-request extraction inputs beyond the page URL (Req 12.2).
///
/// `headers` are the custom upstream request headers supplied with the
/// extraction request; they are forwarded to the page fetch and merged into
/// the [`ExtractorResult`] playback headers so the resolved media URL carries
/// the same upstream context (e.g. a `Referer`/`Cookie`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtraParams {
    /// Custom upstream request headers supplied with the extraction request.
    pub headers: BTreeMap<String, String>,
}

impl ExtraParams {
    /// An empty parameter set (no custom headers).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build params from an iterator of `(name, value)` header pairs.
    pub fn with_headers<I>(headers: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        Self {
            headers: headers.into_iter().collect(),
        }
    }
}

/// A resolved direct media URL plus the request headers required to play it
/// (Req 12.2).
///
/// The handler wraps this into a `ZippyPanther` proxy URL with the headers
/// attached (Req 12.3); that wrapping lives in the HTTP edge, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractorResult {
    /// The resolved direct, playable media URL (Req 12.2).
    pub url: Url,
    /// The request headers required to play the resolved media (Req 12.2).
    pub headers: BTreeMap<String, String>,
}

impl ExtractorResult {
    /// A result with the resolved media URL and no required playback headers.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            headers: BTreeMap::new(),
        }
    }

    /// A result with the resolved media URL and the given playback headers.
    pub fn with_headers(url: Url, headers: BTreeMap<String, String>) -> Self {
        Self { url, headers }
    }
}

/// The module-local typed error for extraction (design: Tech Stack
/// "module-local error enums use `thiserror`"; Req 12.6, 12.7).
///
/// Crosses back into the canonical [`AppError`] taxonomy via the
/// [`From`] impl below so handlers surface one consistent error shape (Req
/// 47.1).
#[derive(Debug, thiserror::Error)]
pub enum ExtractorError {
    /// The requested host is not one of the supported hosts (Req 12.6). → `400`
    #[error("unsupported extractor host: {0}")]
    UnsupportedHost(String),
    /// The host is supported and registered, but its bespoke scraping logic is
    /// not yet implemented — a structured stub. → `404`
    #[error("extractor for host `{host}` is not yet implemented")]
    NotImplemented {
        /// The supported host whose extractor is still a stub.
        host: String,
    },
    /// The page was fetched but no playable media URL could be located in it
    /// (Req 12.7). → `502`
    #[error("extraction failed for host `{host}`: {reason}")]
    ExtractionFailed {
        /// The host the extraction was attempted against.
        host: String,
        /// Why the media URL could not be located.
        reason: String,
    },
    /// The extraction request itself was malformed (e.g. an unparseable page
    /// URL). → `400`
    #[error("invalid extraction request: {0}")]
    BadRequest(String),
    /// An upstream failure surfaced while fetching the page (network error,
    /// non-2xx status, egress refusal). Carries the underlying [`AppError`] —
    /// including any upstream HTTP status — unchanged.
    #[error(transparent)]
    Upstream(AppError),
}

impl ExtractorError {
    /// Convenience constructor for [`ExtractorError::ExtractionFailed`].
    pub fn extraction_failed(host: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ExtractionFailed {
            host: host.into(),
            reason: reason.into(),
        }
    }

    /// Convenience constructor for [`ExtractorError::NotImplemented`].
    pub fn not_implemented(host: impl Into<String>) -> Self {
        Self::NotImplemented { host: host.into() }
    }
}

/// An upstream [`AppError`] (e.g. from the egress seam) becomes the
/// transparent [`ExtractorError::Upstream`] so `?` propagates page-fetch
/// failures without losing the canonical category / upstream status.
impl From<AppError> for ExtractorError {
    fn from(err: AppError) -> Self {
        ExtractorError::Upstream(err)
    }
}

/// Map the module-local [`ExtractorError`] back onto the canonical
/// [`AppError`] taxonomy (Req 47.1):
///
/// * [`UnsupportedHost`](ExtractorError::UnsupportedHost) /
///   [`BadRequest`](ExtractorError::BadRequest) → `400` (client named a bad
///   host / sent a bad request);
/// * [`NotImplemented`](ExtractorError::NotImplemented) → `404` (the
///   extraction capability for that host is not available yet);
/// * [`ExtractionFailed`](ExtractorError::ExtractionFailed) → `502`
///   `HosterUnavailable` (the host page yielded no usable media — Req 12.7);
/// * [`Upstream`](ExtractorError::Upstream) → the carried error verbatim.
impl From<ExtractorError> for AppError {
    fn from(err: ExtractorError) -> Self {
        match err {
            ExtractorError::UnsupportedHost(host) => {
                AppError::bad_request(format!("unsupported extractor host: {host}"))
            }
            ExtractorError::NotImplemented { host } => AppError::not_found(format!(
                "extractor for host `{host}` is not yet implemented"
            )),
            ExtractorError::ExtractionFailed { host, reason } => AppError::hoster_unavailable(
                format!("extraction failed for host `{host}`: {reason}"),
            ),
            ExtractorError::BadRequest(message) => AppError::bad_request(message),
            ExtractorError::Upstream(app) => app,
        }
    }
}

/// A video-host extractor: resolves a page URL into a direct media URL +
/// playback headers (design: Components → Extractor).
///
/// `#[async_trait]` keeps the trait object-safe so the
/// [`ExtractorFactory`](crate::extractor::ExtractorFactory) can store
/// `Arc<dyn Extractor>` entries keyed by host name.
#[async_trait]
pub trait Extractor: Send + Sync {
    /// The canonical, lowercase host name this extractor handles (one of the
    /// 24 supported hosts, Req 12.1).
    fn host_name(&self) -> &'static str;

    /// Which client pool the page fetch must use (Req 12.4, 12.5). Defaults to
    /// the plain rustls client; Cloudflare-fronted / challenge-protected hosts
    /// override this.
    fn client_pool(&self) -> ClientPool {
        ClientPool::Default
    }

    /// Resolve `url` into a direct media URL + required playback headers (Req
    /// 12.2), or a typed [`ExtractorError`] (unsupported handled by the
    /// factory; no-media → [`ExtractionFailed`](ExtractorError::ExtractionFailed),
    /// Req 12.7).
    async fn extract(
        &self,
        url: &Url,
        extra: &ExtraParams,
    ) -> Result<ExtractorResult, ExtractorError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;

    #[test]
    fn unsupported_host_maps_to_bad_request() {
        let app: AppError = ExtractorError::UnsupportedHost("nope".to_string()).into();
        assert_eq!(app.category, ErrorCategory::BadRequest);
        assert!(app.message.contains("nope"));
    }

    #[test]
    fn not_implemented_maps_to_not_found_naming_the_host() {
        let app: AppError = ExtractorError::not_implemented("vavoo").into();
        assert_eq!(app.category, ErrorCategory::NotFound);
        assert!(app.message.contains("vavoo"));
        assert!(app.message.contains("not yet implemented"));
    }

    #[test]
    fn extraction_failed_maps_to_hoster_unavailable() {
        let app: AppError = ExtractorError::extraction_failed("voe", "no media").into();
        assert_eq!(app.category, ErrorCategory::HosterUnavailable);
        assert!(app.message.contains("voe"));
        assert!(app.message.contains("no media"));
    }

    #[test]
    fn upstream_error_is_carried_verbatim() {
        let original = AppError::upstream_unavailable("dial failed").with_upstream_status(503);
        let app: AppError = ExtractorError::Upstream(original).into();
        assert_eq!(app.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(app.upstream_status, Some(503));
    }

    #[test]
    fn apperror_converts_into_upstream_variant() {
        let err: ExtractorError = AppError::bad_request("bad url").into();
        match err {
            ExtractorError::Upstream(app) => {
                assert_eq!(app.category, ErrorCategory::BadRequest);
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn extra_params_helpers_build_header_maps() {
        assert!(ExtraParams::empty().headers.is_empty());
        let p = ExtraParams::with_headers([("Referer".to_string(), "https://x/".to_string())]);
        assert_eq!(
            p.headers.get("Referer").map(String::as_str),
            Some("https://x/")
        );
    }
}
