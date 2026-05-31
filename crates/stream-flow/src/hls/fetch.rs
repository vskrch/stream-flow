//! HLS upstream fetching (`hls::fetch`) — Req 1.5, 1.6, 1.7.
//!
//! [`HlsClient`] is the I/O half of the HLS module: it fetches the upstream
//! manifest body to be rewritten and opens upstream segment/key bytes for
//! streaming, **always** through the single egress seam
//! ([`OutboundClient`](crate::egress::OutboundClient)) so every derived request
//! is tunnelled and carries no client-identifying header (Req 51.1–51.3). The
//! custom upstream request headers supplied with the HLS request are forwarded
//! to the manifest fetch and to every derived segment/key request (Req 1.6),
//! the upstream content type is preserved on streamed segments (Req 1.5), and
//! an upstream network/HTTP failure surfaces a typed error carrying the
//! upstream HTTP status when one was received (Req 1.7).
//!
//! Segment/key bytes reuse the streaming core's
//! [`DirectSource`](crate::proxy::DirectSource): it already opens a ranged body
//! through the egress seam, follows redirects server-side, and surfaces the
//! upstream `Content-Type` on the resulting [`UpstreamBody`], so HLS segment
//! delivery preserves the upstream content type for free (Req 1.5).

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use url::Url;

use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::{DirectSource, UpstreamBody, UpstreamSource};

/// The maximum manifest body the rewriter will buffer, guarding against a
/// hostile/oversized "manifest" (a real `.m3u8` is kilobytes, not megabytes).
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

/// Fetches HLS manifests and opens HLS segment/key bytes through the egress
/// seam (design: Components → HLS; Req 1.5, 1.6, 1.7).
#[derive(Clone)]
pub struct HlsClient {
    /// The single outbound seam — the only path to the network (Req 51.1).
    client: Arc<OutboundClient>,
}

impl HlsClient {
    /// Build an [`HlsClient`] over the shared egress [`OutboundClient`].
    pub fn new(client: Arc<OutboundClient>) -> Self {
        Self { client }
    }

    /// Fetch the raw upstream manifest body at `url`, forwarding `headers`
    /// (Req 1.6).
    ///
    /// On a network error, or an upstream HTTP error status (non-2xx), returns
    /// an [`AppError`] carrying the upstream HTTP status when one was received
    /// (Req 1.7). The body is capped at [`MAX_MANIFEST_BYTES`].
    pub async fn fetch_manifest(
        &self,
        url: &Url,
        headers: &BTreeMap<String, String>,
    ) -> Result<Bytes, AppError> {
        let mut builder = self.client.upstream(Method::GET, url)?;
        let header_map = to_header_map(headers);
        if !header_map.is_empty() {
            builder = builder.headers(header_map);
        }

        let resp = builder.send().await.map_err(|e| map_send_error(url, e))?;

        // Upstream HTTP error → carry the upstream status (Req 1.7).
        let status = resp.status();
        if !status.is_success() {
            return Err(AppError::upstream_unavailable(format!(
                "upstream HLS manifest request to {url} returned HTTP {}",
                status.as_u16()
            ))
            .with_upstream_status(status.as_u16()));
        }

        let body = resp.bytes().await.map_err(|e| map_send_error(url, e))?;
        if body.len() > MAX_MANIFEST_BYTES {
            return Err(AppError::payload_too_large(format!(
                "upstream HLS manifest from {url} exceeds {MAX_MANIFEST_BYTES} bytes"
            )));
        }
        Ok(body)
    }

    /// Open the upstream bytes for a derived HLS segment / `#EXT-X-MAP` init
    /// segment / key at `url`, forwarding `headers` (Req 1.6) and preserving
    /// the upstream content type on the returned [`UpstreamBody`] (Req 1.5).
    ///
    /// Routes through [`DirectSource`] so the open goes through the egress seam
    /// (Req 51.1) and follows redirects server-side; `range` forwards the
    /// client's `Range` header upstream (`Full` for a whole segment).
    pub async fn open_segment(
        &self,
        url: &Url,
        headers: &BTreeMap<String, String>,
        range: RangeSpec,
    ) -> Result<UpstreamBody, AppError> {
        let source = DirectSource::new(self.client.clone(), url.clone())
            .with_headers(to_header_map(headers));
        source.open(range).await
    }
}

/// Convert a `name → value` header map into a `reqwest` [`HeaderMap`],
/// skipping any entry whose name or value is not a valid HTTP header (these are
/// config/extractor-supplied, never inbound client headers, so they carry no
/// client IP). Header names are matched case-insensitively by `reqwest`.
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

/// Map a `reqwest` send/read error onto the canonical taxonomy: a connect/
/// timeout/reset against an upstream is an `UpstreamUnavailable` (`503`,
/// Req 1.7), carrying the upstream status when the error surfaced one.
fn map_send_error(url: &Url, err: reqwest::Error) -> AppError {
    let host = url.host_str().unwrap_or("<unknown>");
    let app =
        AppError::upstream_unavailable(format!("upstream HLS request to {host} failed: {err}"));
    match err.status() {
        Some(status) => app.with_upstream_status(status.as_u16()),
        None => app,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::egress::CLIENT_IDENTIFYING_HEADERS;
    use crate::errors::ErrorCategory;
    use futures::StreamExt;
    use std::sync::{Arc as StdArc, Mutex};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An [`OutboundClient`] with no tunnel under the given policy (mirrors the
    /// `proxy::source` test harness): `FailOpen` dials the in-process wiremock
    /// origin directly; `FailClosed` refuses with no dial.
    fn hls_client(policy: EgressPolicy) -> HlsClient {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        HlsClient::new(Arc::new(
            OutboundClient::from_config(&cfg, reflector).expect("builds"),
        ))
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    async fn collect(mut body: UpstreamBody) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = body.stream.next().await {
            out.extend_from_slice(&chunk.expect("chunk"));
        }
        out
    }

    // -- Req 1.7: upstream HTTP error carries the upstream status ------------

    #[tokio::test]
    async fn manifest_http_error_carries_upstream_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing.m3u8"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = hls_client(EgressPolicy::FailOpen);
        let err = client
            .fetch_manifest(
                &url(&format!("{}/missing.m3u8", server.uri())),
                &BTreeMap::new(),
            )
            .await
            .expect_err("a 404 upstream must surface as an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(
            err.upstream_status,
            Some(404),
            "must carry the upstream status"
        );
    }

    // -- Req 1.6: custom headers forwarded to the manifest fetch -------------

    #[tokio::test]
    async fn manifest_fetch_forwards_custom_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/master.m3u8"))
            .and(header("x-upstream-auth", "secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("#EXTM3U\n"))
            .mount(&server)
            .await;

        let mut headers = BTreeMap::new();
        headers.insert("X-Upstream-Auth".to_string(), "secret-token".to_string());

        let client = hls_client(EgressPolicy::FailOpen);
        let body = client
            .fetch_manifest(&url(&format!("{}/master.m3u8", server.uri())), &headers)
            .await
            .expect("forwarded header must match the upstream mock");
        assert_eq!(&body[..], b"#EXTM3U\n");
    }

    // -- Req 1.5: segment open preserves the upstream content type -----------

    #[tokio::test]
    async fn segment_open_preserves_upstream_content_type() {
        let server = MockServer::start().await;
        let payload = b"\x47segment-ts-bytes".to_vec();
        Mock::given(method("GET"))
            .and(path("/seg001.ts"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "video/mp2t")
                    .set_body_bytes(payload.clone()),
            )
            .mount(&server)
            .await;

        let client = hls_client(EgressPolicy::FailOpen);
        let body = client
            .open_segment(
                &url(&format!("{}/seg001.ts", server.uri())),
                &BTreeMap::new(),
                RangeSpec::Full,
            )
            .await
            .expect("segment opens");
        assert_eq!(
            body.content_type.as_deref(),
            Some("video/mp2t"),
            "the upstream content type must be preserved"
        );
        assert_eq!(collect(body).await, payload);
    }

    // -- Req 1.6: custom headers forwarded to derived segment requests -------

    #[tokio::test]
    async fn segment_open_forwards_custom_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/seg001.ts"))
            .and(header("referer", "https://referer.example/"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".to_vec()))
            .mount(&server)
            .await;

        let mut headers = BTreeMap::new();
        headers.insert(
            "Referer".to_string(),
            "https://referer.example/".to_string(),
        );

        let client = hls_client(EgressPolicy::FailOpen);
        let body = client
            .open_segment(
                &url(&format!("{}/seg001.ts", server.uri())),
                &headers,
                RangeSpec::Full,
            )
            .await
            .expect("forwarded header must match the upstream mock");
        assert_eq!(body.status, 200);
    }

    // -- Req 51.1: all fetches go through the egress seam (fail-closed) ------

    #[tokio::test]
    async fn manifest_fetch_is_gated_by_fail_closed_egress() {
        let client = hls_client(EgressPolicy::FailClosed);
        let err = client
            .fetch_manifest(&url("https://cdn.example/master.m3u8"), &BTreeMap::new())
            .await
            .expect_err("fail-closed egress must refuse the manifest dial");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("egress tunnel"));
    }

    // -- Req 51.2/51.3: derived requests carry no client-identifying header --

    #[tokio::test]
    async fn manifest_fetch_carries_no_client_identifying_headers() {
        let server = MockServer::start().await;
        let seen: StdArc<Mutex<Vec<String>>> = StdArc::new(Mutex::new(Vec::new()));
        let seen_clone = seen.clone();
        Mock::given(method("GET"))
            .and(path("/m.m3u8"))
            .respond_with(move |req: &wiremock::Request| {
                let mut names = seen_clone.lock().unwrap();
                for h in req.headers.iter() {
                    names.push(h.0.as_str().to_ascii_lowercase());
                }
                ResponseTemplate::new(200).set_body_string("#EXTM3U\n")
            })
            .mount(&server)
            .await;

        let client = hls_client(EgressPolicy::FailOpen);
        let _ = client
            .fetch_manifest(&url(&format!("{}/m.m3u8", server.uri())), &BTreeMap::new())
            .await
            .expect("fetch succeeds");

        let names = seen.lock().unwrap();
        for forbidden in CLIENT_IDENTIFYING_HEADERS {
            assert!(
                !names.iter().any(|n| n == forbidden),
                "manifest request must not carry client-identifying header {forbidden}; saw {names:?}",
            );
        }
    }
}
