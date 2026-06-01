//! Production IP-reflection source (`egress::reflector`) — Req 51.5, 51.12.
//!
//! [`HttpIpReflector`] is the real, network-backed implementation of the
//! [`IpReflector`] seam the [`Tunnel`](super::tunnel::Tunnel) and
//! [`EgressResolver`](super::resolver::EgressResolver) depend on (the tunnel
//! module's unit tests use a controllable mock instead). It learns the
//! Egress_IP by querying the configured IP-reflection service **through the
//! tunnel**, and resolves the host's real IP **without** the tunnel for the
//! leak check (Req 51.12):
//!
//! * [`observed_ip`](IpReflector::observed_ip) issues the reflection request
//!   through the *tunneled* `reqwest` client — in
//!   [`Proxy`](crate::config::EgressTunnelMode::Proxy) mode that dials the
//!   configured forwarding proxy, in
//!   [`Netns`](crate::config::EgressTunnelMode::Netns) mode the host routing
//!   table forces it through the VPN namespace — so the reflected address is
//!   the Egress_IP (Req 51.5).
//! * [`host_ip`](IpReflector::host_ip) issues the same request through a plain
//!   *direct* client (explicitly `no_proxy`), so it observes the host's real
//!   public IP for the leak comparison and **never** carries upstream traffic
//!   (Req 51.12).
//!
//! ## Response parsing
//!
//! IP-reflection services answer in one of two shapes, both handled by
//! [`parse_reflected_ip`]: a bare address body (`api.ipify.org` default,
//! `203.0.113.7`) or a small JSON object carrying the address under `ip` /
//! `origin` (`api.ipify.org?format=json`, `ipinfo.io/json`, `httpbin.org/ip`).
//! Anything that does not yield a parseable [`IpAddr`] is a typed
//! [`AppError`] so the resolver maps it onto [`LeakCheck::Unresolved`] rather
//! than panicking (design: Components → Egress; the verification is **total**).
//!
//! [`LeakCheck::Unresolved`]: super::tunnel::LeakCheck::Unresolved

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Method;

use crate::config::{EgressConfig, EgressTunnelMode};
use crate::errors::AppError;

use super::tunnel::IpReflector;

/// The reflection request timeout. A reflection service that does not answer
/// quickly is treated as unreachable so the resolver fails closed rather than
/// blocking the refresh loop.
const REFLECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A network-backed [`IpReflector`] over the configured IP-reflection service
/// (Req 51.5, 51.12).
///
/// Build one with [`HttpIpReflector::from_config`]; it owns a *tunneled* client
/// (for the Egress_IP) and a *direct* client (for the host's real IP), so the
/// leak check compares the two paths.
pub struct HttpIpReflector {
    /// Dials the reflection service **through the tunnel** — yields the
    /// Egress_IP (Req 51.5).
    tunneled: reqwest::Client,
    /// Dials the reflection service **directly** — yields the host's real IP
    /// for the leak check only (Req 51.12); never carries upstream traffic.
    direct: reqwest::Client,
    /// The IP-reflection service URL (e.g. `https://api.ipify.org`).
    url: String,
}

impl std::fmt::Debug for HttpIpReflector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpIpReflector")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl HttpIpReflector {
    /// Build the reflector from the egress configuration (Req 51.5).
    ///
    /// The tunneled client routes through [`tunnel_url`](EgressConfig::tunnel_url)
    /// in [`Proxy`](EgressTunnelMode::Proxy) mode; in
    /// [`Netns`](EgressTunnelMode::Netns) / [`Disabled`](EgressTunnelMode::Disabled)
    /// mode it sets no proxy (netns relies on the host routing table). The
    /// direct client always sets `no_proxy` so the host-IP probe bypasses any
    /// ambient proxy. A malformed `tunnel_url` is a misconfiguration and
    /// surfaces as an error rather than silently probing direct.
    pub fn from_config(cfg: &EgressConfig) -> Result<Self, AppError> {
        let direct = reqwest::Client::builder()
            .timeout(REFLECT_TIMEOUT)
            .no_proxy()
            .build()
            .map_err(|e| {
                AppError::unknown(format!("failed to build direct IP-reflection client: {e}"))
            })?;

        let mut tunneled_builder = reqwest::Client::builder().timeout(REFLECT_TIMEOUT);
        match cfg.tunnel_mode {
            EgressTunnelMode::Proxy => {
                let proxy_url = cfg.tunnel_url.as_deref().ok_or_else(|| {
                    AppError::unknown(
                        "egress proxy tunnel configured (tunnel_mode=proxy) without a tunnel_url",
                    )
                })?;
                let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| {
                    AppError::unknown(format!(
                        "invalid egress tunnel proxy URL `{proxy_url}` for IP reflection: {e}"
                    ))
                })?;
                tunneled_builder = tunneled_builder.proxy(proxy);
            }
            EgressTunnelMode::Netns | EgressTunnelMode::Disabled => {
                tunneled_builder = tunneled_builder.no_proxy();
            }
        }
        let tunneled = tunneled_builder.build().map_err(|e| {
            AppError::unknown(format!(
                "failed to build tunneled IP-reflection client: {e}"
            ))
        })?;

        Ok(Self {
            tunneled,
            direct,
            url: cfg.ip_reflection_url.clone(),
        })
    }

    /// Fetch the reflection URL through `client` and parse the reflected
    /// address. Any transport/parse failure is a typed [`AppError`].
    async fn fetch(&self, client: &reqwest::Client) -> Result<IpAddr, AppError> {
        let resp = client
            .request(Method::GET, &self.url)
            .send()
            .await
            .map_err(|e| {
                AppError::upstream_unavailable(format!(
                    "IP-reflection request to {} failed: {e}",
                    self.url
                ))
            })?;
        let body = resp.text().await.map_err(|e| {
            AppError::upstream_unavailable(format!(
                "failed to read IP-reflection response from {}: {e}",
                self.url
            ))
        })?;
        parse_reflected_ip(&body)
    }
}

#[async_trait]
impl IpReflector for HttpIpReflector {
    async fn observed_ip(&self) -> Result<IpAddr, AppError> {
        self.fetch(&self.tunneled).await
    }

    async fn host_ip(&self) -> Result<IpAddr, AppError> {
        self.fetch(&self.direct).await
    }
}

/// Parse the body of an IP-reflection response into an [`IpAddr`] (Req 51.5).
///
/// Accepts both the bare-address form (`203.0.113.7`) and the small JSON forms
/// that carry the address under `ip` or `origin`. `origin` may be a
/// comma-separated proxy chain (`httpbin.org/ip`), in which case the first
/// entry is used. A body that yields no parseable address is a typed
/// [`AppError`] so the leak verification stays total.
fn parse_reflected_ip(body: &str) -> Result<IpAddr, AppError> {
    let trimmed = body.trim();

    // Bare-address form (the configured default `api.ipify.org`).
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ip);
    }

    // JSON form: pull the first parseable address out of `ip` / `origin`.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        for key in ["ip", "origin"] {
            if let Some(s) = value.get(key).and_then(|v| v.as_str()) {
                // `origin` may be a "client, proxy" chain; take the first.
                let candidate = s.split(',').next().unwrap_or(s).trim();
                if let Ok(ip) = candidate.parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
        }
    }

    Err(AppError::upstream_unavailable(format!(
        "IP-reflection response did not contain a parseable IP address: {trimmed:?}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // -- Bare-address parsing (api.ipify.org default) -----------------------

    #[test]
    fn parses_bare_ipv4_body() {
        assert_eq!(
            parse_reflected_ip("203.0.113.7").unwrap(),
            ip("203.0.113.7")
        );
        // Tolerates surrounding whitespace / trailing newline.
        assert_eq!(
            parse_reflected_ip("  203.0.113.7\n").unwrap(),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn parses_bare_ipv6_body() {
        assert_eq!(
            parse_reflected_ip("2001:db8::1").unwrap(),
            ip("2001:db8::1")
        );
    }

    // -- JSON forms (ipify ?format=json / ipinfo / httpbin) -----------------

    #[test]
    fn parses_json_ip_field() {
        assert_eq!(
            parse_reflected_ip(r#"{"ip":"203.0.113.7"}"#).unwrap(),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn parses_json_origin_field_with_proxy_chain() {
        // httpbin.org/ip returns the origin, sometimes a "client, proxy" chain.
        assert_eq!(
            parse_reflected_ip(r#"{"origin":"203.0.113.7, 198.51.100.9"}"#).unwrap(),
            ip("203.0.113.7")
        );
    }

    // -- Unparseable bodies are typed errors, never panics ------------------

    #[test]
    fn rejects_unparseable_body() {
        assert!(parse_reflected_ip("not an ip").is_err());
        assert!(parse_reflected_ip("").is_err());
        assert!(parse_reflected_ip(r#"{"unexpected":"field"}"#).is_err());
        assert!(parse_reflected_ip(r#"{"ip":"garbage"}"#).is_err());
    }

    // -- Builder wiring -----------------------------------------------------

    #[test]
    fn from_config_disabled_builds_without_a_proxy() {
        let cfg = EgressConfig::default(); // Disabled
        let reflector = HttpIpReflector::from_config(&cfg).expect("disabled reflector builds");
        assert_eq!(reflector.url, "https://api.ipify.org");
    }

    #[test]
    fn from_config_proxy_requires_a_tunnel_url() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Proxy,
            tunnel_url: None,
            ..EgressConfig::default()
        };
        let err = HttpIpReflector::from_config(&cfg)
            .expect_err("proxy mode without a URL is a misconfiguration");
        assert!(err.message.contains("tunnel_url"));
    }

    #[test]
    fn from_config_proxy_builds_with_a_tunnel_url() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Proxy,
            tunnel_url: Some("http://proxy:8888".into()),
            ..EgressConfig::default()
        };
        assert!(HttpIpReflector::from_config(&cfg).is_ok());
    }
}
