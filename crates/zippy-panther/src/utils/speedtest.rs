//! Throughput speedtest (`utils::speedtest`) — Req 15.2.
//!
//! Backs the mediaflow `/speedtest` endpoint: it downloads a test payload from
//! a selected provider through the single egress
//! [`OutboundClient`](crate::egress::OutboundClient) seam (never a directly
//! constructed HTTP client — Req 51.1), counts the bytes transferred and the
//! wall-clock elapsed time, and returns the measured throughput (Req 15.2).
//!
//! The download streams the body chunk-by-chunk and counts bytes as they
//! arrive, so a large test file never has to be buffered whole (consistent with
//! the streaming-core 512 MB-VPS constraint, Req 35.1). An optional
//! `max_bytes` cap stops the download early so the test is bounded regardless
//! of the provider's file size.

use std::time::{Duration, Instant};

use actix_web::{web, HttpResponse};
use futures::StreamExt;
use reqwest::Method;
use url::Url;

use crate::app::AppState;
use crate::egress::OutboundClient;
use crate::errors::AppError;

/// A built-in speedtest provider: a display name plus the URL of a test file to
/// download (design: Components → Utilities "speedtest against a provider").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeedtestProvider {
    /// Stable provider identifier (e.g. `"cloudflare"`).
    pub name: &'static str,
    /// The URL of the test payload downloaded to measure throughput.
    pub url: &'static str,
}

/// The built-in providers a speedtest can run against (Req 15.2).
pub const PROVIDERS: &[SpeedtestProvider] = &[
    SpeedtestProvider {
        name: "cloudflare",
        url: "https://speed.cloudflare.com/__down?bytes=10000000",
    },
    SpeedtestProvider {
        name: "hetzner",
        url: "https://speed.hetzner.de/100MB.bin",
    },
];

/// Resolve a provider by name (case-insensitive); the first provider is the
/// default when `name` is `None` (Req 15.2).
pub fn select_provider(name: Option<&str>) -> Result<&'static SpeedtestProvider, AppError> {
    match name {
        None => Ok(&PROVIDERS[0]),
        Some(n) => PROVIDERS
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(n))
            .ok_or_else(|| AppError::bad_request(format!("unknown speedtest provider `{n}`"))),
    }
}

/// The measured result of a throughput run (Req 15.2).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SpeedtestResult {
    /// Total bytes transferred during the measurement.
    pub bytes: u64,
    /// Elapsed wall-clock time in milliseconds.
    pub elapsed_ms: u64,
    /// Measured throughput in bits per second (the canonical "speed" figure).
    pub bits_per_second: u64,
    /// The same throughput expressed in megabits per second, for humans.
    pub megabits_per_second: f64,
}

impl SpeedtestResult {
    /// Compute the result from a byte count and an elapsed duration.
    ///
    /// Guards against a zero/sub-millisecond elapsed time (which would divide
    /// by zero) by flooring the divisor at one millisecond, so the throughput
    /// is always a finite, non-negative figure.
    pub fn from_measurement(bytes: u64, elapsed: Duration) -> Self {
        let elapsed_ms = elapsed.as_millis().max(1) as u64;
        let secs = elapsed_ms as f64 / 1000.0;
        let bits = bytes.saturating_mul(8);
        let bits_per_second = (bits as f64 / secs) as u64;
        let megabits_per_second = (bits_per_second as f64) / 1_000_000.0;
        Self {
            bytes,
            elapsed_ms,
            bits_per_second,
            megabits_per_second,
        }
    }
}

/// Measure download throughput against `url` through the egress seam (Req 15.2,
/// 51.1).
///
/// Streams the response body, counting bytes until the stream ends or the
/// optional `max_bytes` cap is reached, then returns a [`SpeedtestResult`]
/// computed from the byte count and the elapsed time. A connect/transport
/// failure surfaces as the canonical `UpstreamUnavailable` error from the
/// egress seam.
pub async fn measure_throughput(
    client: &OutboundClient,
    url: &Url,
    max_bytes: Option<u64>,
) -> Result<SpeedtestResult, AppError> {
    let start = Instant::now();

    let resp = client
        .upstream(Method::GET, url)?
        .send()
        .await
        .map_err(|e| {
            let host = url.host_str().unwrap_or("<unknown>");
            AppError::upstream_unavailable(format!("speedtest request to {host} failed: {e}"))
        })?;

    if !resp.status().is_success() {
        return Err(AppError::upstream_unavailable(format!(
            "speedtest provider returned status {}",
            resp.status().as_u16()
        ))
        .with_upstream_status(resp.status().as_u16()));
    }

    let mut stream = resp.bytes_stream();
    let mut bytes: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            AppError::upstream_unavailable(format!("speedtest download interrupted: {e}"))
        })?;
        bytes = bytes.saturating_add(chunk.len() as u64);
        if let Some(cap) = max_bytes {
            if bytes >= cap {
                break;
            }
        }
    }

    Ok(SpeedtestResult::from_measurement(bytes, start.elapsed()))
}

/// Query string for `/speedtest`: `?provider=<name>&max_bytes=<n>`.
#[derive(Debug, serde::Deserialize)]
pub struct SpeedtestQuery {
    /// The provider to test against; the default provider when absent.
    pub provider: Option<String>,
    /// Optional cap on the number of bytes to download (bounds the test).
    pub max_bytes: Option<u64>,
}

/// `GET /speedtest` — run a throughput measurement against the selected
/// provider and return the result (Req 15.2).
pub async fn speedtest_endpoint(
    state: web::Data<AppState>,
    query: web::Query<SpeedtestQuery>,
) -> Result<HttpResponse, AppError> {
    let provider = select_provider(query.provider.as_deref())?;
    let url = Url::parse(provider.url).map_err(|e| {
        AppError::unknown(format!(
            "invalid built-in provider URL `{}`: {e}",
            provider.url
        ))
    })?;
    let result = measure_throughput(state.egress(), &url, query.max_bytes).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "provider": provider.name,
        "result": result,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::errors::ErrorCategory;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An [`OutboundClient`] with no tunnel, fail-open, so it dials the
    /// in-process `wiremock` origin directly (the real HTTP path, no network).
    fn outbound() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid url")
    }

    // -- Req 15.2: measure throughput against a provider ---------------------

    #[tokio::test]
    async fn measures_bytes_transferred_against_a_provider() {
        let server = MockServer::start().await;
        let payload = vec![0u8; 64 * 1024]; // 64 KiB test file
        Mock::given(method("GET"))
            .and(path("/down"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.clone()))
            .mount(&server)
            .await;

        let result = measure_throughput(&outbound(), &url(&format!("{}/down", server.uri())), None)
            .await
            .expect("speedtest succeeds against the provider");

        assert_eq!(
            result.bytes,
            payload.len() as u64,
            "must count every downloaded byte"
        );
        assert!(result.elapsed_ms >= 1, "elapsed is floored at 1ms");
        // Throughput is a finite, non-negative figure derived from the measurement.
        assert!(
            result.bits_per_second > 0,
            "non-empty download yields positive throughput"
        );
    }

    #[tokio::test]
    async fn max_bytes_caps_the_download() {
        let server = MockServer::start().await;
        let payload = vec![0u8; 1024 * 1024]; // 1 MiB available
        Mock::given(method("GET"))
            .and(path("/down"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload))
            .mount(&server)
            .await;

        let result = measure_throughput(
            &outbound(),
            &url(&format!("{}/down", server.uri())),
            Some(100 * 1024),
        )
        .await
        .expect("capped speedtest succeeds");

        // Stops at-or-after the cap (a final chunk may overshoot), well under 1 MiB.
        assert!(result.bytes >= 100 * 1024, "must read at least the cap");
        assert!(
            result.bytes < 1024 * 1024,
            "must stop before draining the whole body"
        );
    }

    #[tokio::test]
    async fn upstream_failure_surfaces_typed_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/down"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let err = measure_throughput(&outbound(), &url(&format!("{}/down", server.uri())), None)
            .await
            .expect_err("a 5xx provider response is an upstream failure");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(503));
    }

    #[tokio::test]
    async fn fail_closed_egress_refuses_the_dial() {
        // A fail-closed client with no verified tunnel must refuse, proving the
        // speedtest only reaches the network through the gated egress seam.
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailClosed,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let client = OutboundClient::from_config(&cfg, reflector).expect("builds");

        let err = measure_throughput(&client, &url("https://speed.example/down"), None)
            .await
            .expect_err("fail-closed egress must refuse");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    // -- Provider selection --------------------------------------------------

    #[test]
    fn select_provider_defaults_and_is_case_insensitive() {
        assert_eq!(select_provider(None).unwrap().name, PROVIDERS[0].name);
        assert_eq!(
            select_provider(Some("CloudFlare")).unwrap().name,
            "cloudflare"
        );
    }

    #[test]
    fn select_unknown_provider_is_a_bad_request() {
        let err = select_provider(Some("nope")).unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    // -- Result math ---------------------------------------------------------

    #[test]
    fn throughput_math_is_bits_per_second() {
        // 1 MB in 1 second = 8 Mbit/s.
        let r = SpeedtestResult::from_measurement(1_000_000, Duration::from_secs(1));
        assert_eq!(r.bytes, 1_000_000);
        assert_eq!(r.elapsed_ms, 1000);
        assert_eq!(r.bits_per_second, 8_000_000);
        assert!((r.megabits_per_second - 8.0).abs() < 1e-9);
    }

    #[test]
    fn zero_elapsed_is_floored_to_avoid_divide_by_zero() {
        let r = SpeedtestResult::from_measurement(1000, Duration::ZERO);
        assert_eq!(r.elapsed_ms, 1, "elapsed floored at 1ms");
        // 1000 bytes * 8 / 0.001s = 8_000_000 bits/s, finite.
        assert_eq!(r.bits_per_second, 8_000_000);
    }

    #[test]
    fn empty_download_yields_zero_throughput() {
        let r = SpeedtestResult::from_measurement(0, Duration::from_secs(1));
        assert_eq!(r.bits_per_second, 0);
        assert_eq!(r.megabits_per_second, 0.0);
    }
}
