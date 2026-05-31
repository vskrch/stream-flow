//! Byparr / FlareSolverr-style challenge-bypass integration
//! (`extractor::byparr`) — Req 12.5.
//!
//! When a Cloudflare-bypass service URL is configured, challenge-protected
//! hosts are fetched **through** that service instead of directly: the service
//! solves the JS/Captcha challenge in a real browser and returns the resolved
//! page HTML (design: Components → Extractor "(+Byparr)").
//!
//! [`Byparr`] speaks the FlareSolverr `v1` protocol that Byparr is API-
//! compatible with: a `POST` of `{ "cmd": "request.get", "url": ...,
//! "maxTimeout": <ms> }` returns `{ "status": "ok", "solution": { "response":
//! "<html>…", … } }`. The request to the solver itself still leaves through the
//! single egress seam ([`OutboundClient`](crate::egress::OutboundClient)) so it
//! is tunnelled and client-IP-stripped (Req 51.1–51.3).

use std::collections::BTreeMap;

use reqwest::Method;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::egress::OutboundClient;
use crate::errors::AppError;
use std::sync::Arc;

/// A FlareSolverr-style challenge solver client (Req 12.5). Cheaply cloneable.
#[derive(Clone)]
pub struct Byparr {
    /// The single outbound seam — the request to the solver is tunnelled too
    /// (Req 51.1).
    client: Arc<OutboundClient>,
    /// The solver endpoint (e.g. `http://byparr:8191/v1`).
    endpoint: String,
    /// Per-solve timeout passed to the solver as `maxTimeout` (milliseconds).
    timeout_secs: u64,
}

/// The FlareSolverr `v1` request envelope.
#[derive(Debug, Serialize)]
struct SolveRequest<'a> {
    /// The command — always `request.get` for a page fetch.
    cmd: &'a str,
    /// The target page URL to solve + fetch.
    url: &'a str,
    /// Max solve time in milliseconds.
    #[serde(rename = "maxTimeout")]
    max_timeout: u64,
}

/// The FlareSolverr `v1` response envelope.
#[derive(Debug, Deserialize)]
struct SolveResponse {
    /// `"ok"` on success; anything else is a failure.
    #[serde(default)]
    status: String,
    /// A human-readable message (used in the error path).
    #[serde(default)]
    message: String,
    /// The solved page, present on success.
    #[serde(default)]
    solution: Option<Solution>,
}

/// The solved-page payload inside a successful [`SolveResponse`].
#[derive(Debug, Deserialize)]
struct Solution {
    /// The resolved page HTML.
    #[serde(default)]
    response: String,
}

impl Byparr {
    /// Build a [`Byparr`] solver over the shared egress client.
    pub fn new(client: Arc<OutboundClient>, endpoint: String, timeout_secs: u64) -> Self {
        Self {
            client,
            endpoint,
            timeout_secs,
        }
    }

    /// The configured solver endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Solve and fetch the page at `target`, returning the resolved HTML (Req
    /// 12.5).
    ///
    /// `headers` are accepted for parity with the direct-fetch path; the
    /// FlareSolverr `request.get` command drives its own browser session, so
    /// they are advisory. A non-`ok` solver status or a missing solution
    /// surfaces a typed [`AppError`].
    pub async fn fetch(
        &self,
        target: &Url,
        _headers: &BTreeMap<String, String>,
    ) -> Result<String, AppError> {
        let endpoint = Url::parse(&self.endpoint).map_err(|e| {
            AppError::unknown(format!(
                "invalid Byparr endpoint URL `{}`: {e}",
                self.endpoint
            ))
        })?;

        let body = SolveRequest {
            cmd: "request.get",
            url: target.as_str(),
            max_timeout: self.timeout_secs.saturating_mul(1000),
        };

        let resp = self
            .client
            .upstream(Method::POST, &endpoint)?
            .json(&body)
            .send()
            .await
            .map_err(|e| map_send_error(&endpoint, e))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(AppError::hoster_unavailable(format!(
                "Byparr solver {endpoint} returned HTTP {}",
                status.as_u16()
            ))
            .with_upstream_status(status.as_u16()));
        }

        let parsed: SolveResponse = resp
            .json()
            .await
            .map_err(|e| AppError::hoster_unavailable(format!("Byparr solver returned an unparseable response: {e}")))?;

        if parsed.status != "ok" {
            return Err(AppError::hoster_unavailable(format!(
                "Byparr solver failed to solve {target}: {}",
                if parsed.message.is_empty() {
                    parsed.status.as_str()
                } else {
                    parsed.message.as_str()
                }
            )));
        }

        match parsed.solution {
            Some(solution) => Ok(solution.response),
            None => Err(AppError::hoster_unavailable(format!(
                "Byparr solver returned no solution for {target}"
            ))),
        }
    }
}

/// Map a `reqwest` send/read error against the solver onto the canonical
/// taxonomy.
fn map_send_error(endpoint: &Url, err: reqwest::Error) -> AppError {
    let app =
        AppError::hoster_unavailable(format!("Byparr solver request to {endpoint} failed: {err}"));
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
    use crate::errors::ErrorCategory;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn outbound(policy: EgressPolicy) -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[tokio::test]
    async fn solves_and_returns_page_html() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1"))
            .and(body_partial_json(json!({ "cmd": "request.get" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "ok",
                "message": "",
                "solution": { "response": "<html>solved</html>" }
            })))
            .mount(&server)
            .await;

        let byparr = Byparr::new(outbound(EgressPolicy::FailOpen), format!("{}/v1", server.uri()), 30);
        let html = byparr
            .fetch(&url("https://protected.example/watch"), &BTreeMap::new())
            .await
            .expect("solver returns the page");
        assert_eq!(html, "<html>solved</html>");
    }

    #[tokio::test]
    async fn non_ok_status_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "error",
                "message": "challenge not solved"
            })))
            .mount(&server)
            .await;

        let byparr = Byparr::new(outbound(EgressPolicy::FailOpen), format!("{}/v1", server.uri()), 30);
        let err = byparr
            .fetch(&url("https://protected.example/watch"), &BTreeMap::new())
            .await
            .expect_err("a non-ok solver status must surface as an error");
        assert_eq!(err.category, ErrorCategory::HosterUnavailable);
        assert!(err.message.contains("challenge not solved"));
    }

    #[tokio::test]
    async fn solver_http_error_carries_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let byparr = Byparr::new(outbound(EgressPolicy::FailOpen), format!("{}/v1", server.uri()), 30);
        let err = byparr
            .fetch(&url("https://protected.example/watch"), &BTreeMap::new())
            .await
            .expect_err("a 500 solver must surface as an error");
        assert_eq!(err.category, ErrorCategory::HosterUnavailable);
        assert_eq!(err.upstream_status, Some(500));
    }

    #[tokio::test]
    async fn solver_request_is_gated_by_fail_closed_egress() {
        let byparr = Byparr::new(outbound(EgressPolicy::FailClosed), "http://byparr:8191/v1".to_string(), 30);
        let err = byparr
            .fetch(&url("https://protected.example/watch"), &BTreeMap::new())
            .await
            .expect_err("fail-closed egress must refuse the solver dial");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }
}
