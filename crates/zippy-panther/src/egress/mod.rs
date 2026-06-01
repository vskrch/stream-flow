//! Egress isolation (`egress`) — the single outbound seam (Req 51).
//!
//! Every upstream request to a debrid service or end media server leaves the
//! process through this module so those upstreams observe only the Egress_IP
//! and never any user's Client_IP (design: Components -> Egress). The seam is
//! built in layers:
//!
//! * **Layer 1 — header sanitization ([`sanitize`], task 8.1):**
//!   [`sanitize::sanitize_outbound`] is the only approved outbound-`HeaderMap`
//!   builder; it strips every client-identifying header (Req 51.2, 51.3,
//!   51.12).
//! * **Layer 2 — transport tunneling + egress-IP resolution (tasks 8.2):**
//!   [`tunnel::Tunnel`] dials through the configured Egress_Tunnel and
//!   [`resolver::EgressResolver`] caches the leak-verified Egress_IP.
//! * **The single outbound seam ([`OutboundClient`], task 8.3):** the *only*
//!   way any module obtains an HTTP client for an upstream call. It owns the
//!   tunneled and direct `reqwest`/`wreq` clients, applies the fail-closed
//!   [`policy`] decision before any dial, and exposes the current
//!   [`egress_ip`](OutboundClient::egress_ip) (design: Components -> Egress ->
//!   OutboundClient).

pub mod policy;
pub mod reflector;
pub mod resolver;
pub mod sanitize;
pub mod tunnel;

pub use policy::{decide_egress, fail_closed_error, EgressDecision};
pub use reflector::HttpIpReflector;
pub use resolver::EgressResolver;
pub use sanitize::{is_client_identifying_header, sanitize_outbound, CLIENT_IDENTIFYING_HEADERS};
pub use tunnel::{IpReflector, LeakCheck, Tunnel};

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Method, Url};

use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
use crate::errors::AppError;
use crate::proxy::routing::{ProxyUrl, RoutePattern, RoutingTable, TransportRoute};

use self::tunnel::LeakCheck as TunnelState;

/// The **single outbound seam**: the only approved way any module obtains an
/// HTTP client for an upstream (debrid / end-media / extractor) call
/// (design: Components -> Egress -> OutboundClient; Req 51.1, 51.8, 51.9).
///
/// When a tunnel is configured, it funnels outbound requests through the
/// Egress_Tunnel so upstreams observe only the Egress_IP (Req 51.1), and it
/// makes the fail-closed [`policy`] decision *before* any dial so the host's
/// real IP can never leak when a strict tunnel is down or leaking (Req 51.8).
/// When no tunnel is configured, direct networking is the normal mode rather
/// than an egress failure. Two client flavours are held for both paths:
///
/// * [`upstream`](OutboundClient::upstream) → a `reqwest` request builder
///   (rustls), the default for debrid/media hosts;
/// * [`impersonate`](OutboundClient::impersonate) → a `wreq` request builder
///   with Chrome JA3/JA4 TLS emulation, for Cloudflare-fronted extractor hosts
///   (Req 35.5).
///
/// Per-host/per-store tunnel selection (Req 51.9) is performed by an embedded
/// [`proxy::routing`](crate::proxy::routing) [`RoutingTable`]: the configured
/// per-host tunnel overrides become most-specific-wins route patterns and the
/// default tunnel endpoint is the all-proxy fallback (Req 13.2, 13.5, 13.6).
/// [`select_tunnel_endpoint`](OutboundClient::select_tunnel_endpoint) reports
/// the selected endpoint and [`upstream`](OutboundClient::upstream) dials it
/// through the matching cached forwarding client.
pub struct OutboundClient {
    /// Default tunnelled client (rustls `reqwest`) — dials through the
    /// Egress_Tunnel (proxy mode) or the host routing table (netns mode). Used
    /// when no per-host tunnel override matches.
    tunneled: reqwest::Client,
    /// Direct `reqwest` client used when no tunnel is configured, or when the
    /// operator explicitly selects fail-open and the configured tunnel is down.
    direct: reqwest::Client,
    /// Chrome-JA3/JA4 impersonation client (`wreq`, BoringSSL), also
    /// tunnelled — used for browser-TLS extractor hosts (Req 35.5).
    tunneled_impersonate: wreq::Client,
    /// Direct Chrome-JA3/JA4 impersonation client for no-tunnel / fail-open
    /// fallback requests.
    direct_impersonate: wreq::Client,
    /// Fail-closed (default) vs fail-open behaviour (Req 51.8).
    policy: EgressPolicy,
    /// The egress-IP resolver / tunnel-state cache (task 8.2). `None` when no
    /// tunnel is configured ([`EgressTunnelMode::Disabled`]); direct egress is
    /// then the normal operating mode.
    resolver: Option<Arc<EgressResolver>>,
    /// The default tunnel endpoint (proxy URL) the clients dial through, kept
    /// for diagnostics and per-host routing (Req 51.9).
    default_endpoint: Option<String>,
    /// Per-host tunnel overrides (`host -> tunnel URL`) so an operator can pin
    /// specific stores/hosts to specific tunnels (Req 51.9), retained for
    /// diagnostics.
    per_host: HashMap<String, String>,
    /// The per-host/per-store tunnel routing table (Req 51.9): per-host
    /// overrides as most-specific route patterns, the default endpoint as the
    /// all-proxy fallback. Owns the `(proxy, verify_ssl)` client LRU so the
    /// selected tunnel is actually dialled (design: Components -> Transport
    /// routing & forwarding).
    tunnel_routes: RoutingTable,
}

/// A hand-written [`Debug`] that never dereferences the held clients or the
/// resolver's `dyn IpReflector` (neither of which implements [`Debug`]).
///
/// It surfaces the operationally-relevant state — policy, whether a tunnel
/// resolver is attached, the current tunnel state, the default endpoint, and
/// the set of pinned hosts — so diagnostics (and the `from_config` misconfig
/// test) can format an `OutboundClient` without requiring the inner transport
/// types to be `Debug`.
impl std::fmt::Debug for OutboundClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundClient")
            .field("policy", &self.policy)
            .field("tunnel_configured", &self.has_configured_tunnel())
            .field("has_resolver", &self.resolver.is_some())
            .field("tunnel_state", &self.tunnel_state())
            .field("default_endpoint", &self.default_endpoint)
            .field("per_host", &self.per_host)
            .finish_non_exhaustive()
    }
}

impl OutboundClient {
    /// Assemble an [`OutboundClient`] from already-built clients and state.
    ///
    /// Prefer [`from_config`](OutboundClient::from_config) in production; this
    /// low-level constructor exists so callers (and tests) can inject
    /// pre-built clients and a seeded resolver.
    pub fn new(
        tunneled: reqwest::Client,
        tunneled_impersonate: wreq::Client,
        policy: EgressPolicy,
        resolver: Option<Arc<EgressResolver>>,
        default_endpoint: Option<String>,
        per_host: HashMap<String, String>,
    ) -> Self {
        let direct = build_tunneled_reqwest(None)
            .expect("direct egress client without a proxy should always build");
        let direct_impersonate = build_tunneled_impersonate(None)
            .expect("direct impersonation client without a proxy should always build");
        let tunnel_routes = build_tunnel_routes(default_endpoint.as_deref(), &per_host);
        Self {
            tunneled,
            direct,
            tunneled_impersonate,
            direct_impersonate,
            policy,
            resolver,
            default_endpoint,
            per_host,
            tunnel_routes,
        }
    }

    /// Build the single outbound seam from the egress configuration plus a
    /// reflection source (Req 51.1, 51.8, 51.9).
    ///
    /// * Tunnel clients are constructed to dial through the configured
    ///   Egress_Tunnel: in [`Proxy`](EgressTunnelMode::Proxy) mode every
    ///   request routes through `tunnel_url`; in
    ///   [`Netns`](EgressTunnelMode::Netns)/[`Disabled`](EgressTunnelMode::Disabled)
    ///   mode no proxy is set (netns relies on the host routing table).
    /// * An [`EgressResolver`] is built when a tunnel is configured so the
    ///   fail-closed gate and [`egress_ip`](OutboundClient::egress_ip) read the
    ///   leak-verified Egress_IP; `Disabled` yields `None` and direct networking
    ///   is allowed without treating it as a broken tunnel.
    ///
    /// A `Proxy` mode without a `tunnel_url`, or a malformed proxy URL, is a
    /// misconfiguration and returns an error rather than silently dialling
    /// direct from the host's real IP.
    pub fn from_config(
        cfg: &EgressConfig,
        reflector: Arc<dyn IpReflector>,
    ) -> Result<Self, AppError> {
        // The endpoint the default clients dial through. Proxy mode *requires*
        // a URL; netns/disabled dial without an explicit proxy.
        let default_endpoint = match cfg.tunnel_mode {
            EgressTunnelMode::Proxy => Some(cfg.tunnel_url.clone().ok_or_else(|| {
                AppError::unknown(
                    "egress proxy tunnel configured (tunnel_mode=proxy) without a tunnel_url",
                )
            })?),
            EgressTunnelMode::Netns | EgressTunnelMode::Disabled => None,
        };

        let tunneled = build_tunneled_reqwest(default_endpoint.as_deref())?;
        let tunneled_impersonate = build_tunneled_impersonate(default_endpoint.as_deref())?;
        let resolver = EgressResolver::from_config(cfg, reflector)?.map(Arc::new);

        Ok(Self::new(
            tunneled,
            tunneled_impersonate,
            cfg.policy,
            resolver,
            default_endpoint,
            cfg.per_host.clone(),
        ))
    }

    /// The configured fail-closed / fail-open policy (Req 51.8).
    pub fn policy(&self) -> EgressPolicy {
        self.policy
    }

    /// The current tunnel state used by the fail-closed decision (Req 51.8,
    /// 51.12).
    ///
    /// Reads the resolver's lock-free cache; when no tunnel is configured the
    /// state is [`LeakCheck::Unresolved`], but [`decision`](Self::decision)
    /// handles that as direct mode before applying fail-closed tunnel policy.
    pub fn tunnel_state(&self) -> TunnelState {
        match &self.resolver {
            Some(resolver) => resolver.leak_check(),
            None => TunnelState::Unresolved,
        }
    }

    /// The deterministic egress decision for the current direct/tunnel state
    /// (Req 51.1, 51.8) — the single source of truth the dial path consults.
    ///
    /// Pure with respect to the snapshotted state: the same `(policy, state)`
    /// always yields the same [`EgressDecision`] (Property 62).
    pub fn decision(&self) -> EgressDecision {
        if !self.has_configured_tunnel() {
            return EgressDecision::DialDirect;
        }
        decide_egress(self.policy, self.tunnel_state())
    }

    fn has_configured_tunnel(&self) -> bool {
        self.resolver.is_some() || self.default_endpoint.is_some() || !self.per_host.is_empty()
    }

    /// The current leak-verified Egress_IP, or `None` when the tunnel is down /
    /// leaking / unconfigured (Req 51.5, 51.11).
    ///
    /// Backs `/proxy/ip` (Req 51.11) and store link IP-binding (Req 51.4). A
    /// lock-free read of the resolver cache.
    pub fn egress_ip(&self) -> Option<IpAddr> {
        self.resolver.as_ref().and_then(|r| r.egress_ip())
    }

    /// The egress-IP resolver, when a tunnel is configured.
    ///
    /// Lets the wiring layer spawn the resolver's refresh loop and forward
    /// reconnect events (task 8.2 / supervisor integration).
    pub fn resolver(&self) -> Option<&Arc<EgressResolver>> {
        self.resolver.as_ref()
    }

    /// Select the tunnel endpoint for `url` via the per-host/per-store routing
    /// table (Req 51.9).
    ///
    /// Returns the most-specific matching per-host tunnel override (Req 13.2),
    /// else the default tunnel endpoint when configured (the all-proxy
    /// fallback — Req 13.5), else `None` (direct — Req 13.6). Host match is
    /// case-insensitive.
    pub fn select_tunnel_endpoint(&self, url: &Url) -> Option<&str> {
        self.tunnel_routes.select_route(url).proxy_str()
    }

    /// Build a sanitized, tunnelled `reqwest` request for a debrid/media
    /// upstream — the primary outbound entry point (Req 51.1, 51.8, 51.9).
    ///
    /// The fail-closed [`policy`] decision is made **before** anything is
    /// built:
    ///
    /// * [`RefuseFailClosed`](EgressDecision::RefuseFailClosed) → returns
    ///   [`fail_closed_error`] (`UpstreamUnavailable`) and constructs **no**
    ///   request, so no dial can leak the host's real IP (Req 51.8);
    /// * [`DialDirect`](EgressDecision::DialDirect) → no tunnel is configured;
    ///   proceeds directly;
    /// * [`DialUntunneledWithWarning`](EgressDecision::DialUntunneledWithWarning)
    ///   (fail-open only) → logs a "traffic is not tunneled" warning and
    ///   proceeds through the direct client, not the broken tunnel proxy;
    /// * [`DialTunneled`](EgressDecision::DialTunneled) → proceeds through the
    ///   verified tunnel.
    ///
    /// Once authorized, the per-host/per-store tunnel routing table selects the
    /// endpoint for `url` (Req 51.9): a matching per-host override dials through
    /// its own cached forwarding client (built once per `(proxy, verify_ssl)`),
    /// while the unmatched / default path uses the pre-built default tunnelled
    /// client.
    ///
    /// The returned [`reqwest::RequestBuilder`] starts from a fresh request
    /// carrying no client-identifying headers; callers forwarding inbound
    /// headers must first pass them through [`sanitize_outbound`] (the only
    /// approved outbound-`HeaderMap` builder) and attach the result.
    pub fn upstream(&self, method: Method, url: &Url) -> Result<reqwest::RequestBuilder, AppError> {
        // Gate the dial on the deterministic fail-closed decision (Req 51.8).
        let decision = self.authorize_dial(url)?;
        // Per-host/per-store tunnel selection (Req 51.9): a matched override
        // dials its own forwarding client; everything else uses the default
        // tunnelled client.
        let client = self.client_for(url, decision)?;
        Ok(client.request(method, url.clone()))
    }

    /// Resolve the `reqwest::Client` to dial `url` through, honoring the
    /// per-host/per-store tunnel routing table (Req 51.9).
    ///
    /// A matched per-host override yields its dedicated cached forwarding
    /// client; the unmatched / default path yields the pre-built default
    /// tunnelled client (which already dials through the default endpoint, or
    /// direct in netns/disabled mode).
    fn client_for(&self, url: &Url, decision: EgressDecision) -> Result<reqwest::Client, AppError> {
        if matches!(
            decision,
            EgressDecision::DialDirect | EgressDecision::DialUntunneledWithWarning
        ) {
            return Ok(self.direct.clone());
        }

        let selection = self.tunnel_routes.select_route(url);
        if selection.matched {
            // A specific per-host tunnel override → its own cached client.
            self.tunnel_routes.client_for(url)
        } else {
            // Default / direct path → the pre-built default tunnelled client.
            Ok(self.tunneled.clone())
        }
    }

    /// Build a sanitized, tunnelled **impersonation** (`wreq`, Chrome
    /// JA3/JA4) request for a browser-TLS upstream (extractor hosts behind
    /// Cloudflare — Req 35.5), subject to the same fail-closed gate as
    /// [`upstream`](OutboundClient::upstream) (Req 51.8).
    pub fn impersonate(&self, method: Method, url: &Url) -> Result<wreq::RequestBuilder, AppError> {
        let decision = self.authorize_dial(url)?;
        let client = if matches!(
            decision,
            EgressDecision::DialDirect | EgressDecision::DialUntunneledWithWarning
        ) {
            &self.direct_impersonate
        } else {
            &self.tunneled_impersonate
        };
        // `wreq`'s `IntoUri` is implemented for `&str`/`String`/`Uri` (not
        // `url::Url`), so hand it the already-validated URL's string form.
        Ok(client.request(method, url.as_str()))
    }

    /// The shared fail-closed gate for both client flavours: apply the
    /// deterministic decision and either authorize the dial or refuse without
    /// building anything (Req 51.8).
    fn authorize_dial(&self, url: &Url) -> Result<EgressDecision, AppError> {
        let decision = self.decision();
        match decision {
            EgressDecision::DialDirect | EgressDecision::DialTunneled => Ok(decision),
            EgressDecision::DialUntunneledWithWarning => {
                // Fail-open opt-in: proceed but make the lost isolation loud
                // (Req 51.8). The host's real IP may be exposed upstream.
                tracing::warn!(
                    host = url.host_str().unwrap_or("<unknown>"),
                    "egress traffic is NOT tunneled (fail-open): the host's real IP may be exposed upstream",
                );
                Ok(decision)
            }
            EgressDecision::RefuseFailClosed => Err(fail_closed_error()),
        }
    }
}

/// Build the per-host/per-store tunnel routing table (Req 51.9) from the
/// default tunnel endpoint plus the `host -> tunnel URL` overrides.
///
/// Each override becomes an exact-host [`TransportRoute`] (the most specific
/// host match — Req 13.2) pinned to that tunnel as its forwarding proxy; the
/// default endpoint becomes the all-proxy fallback so unmatched hosts report
/// the default tunnel (Req 13.5), and no default (netns/disabled) means
/// unmatched hosts route direct (Req 13.6).
///
/// This runs in the infallible [`OutboundClient::new`] constructor, so an
/// override / default that is not a valid forwarding-proxy URL is **skipped
/// with a warning** rather than aborting: the affected host then falls back to
/// the default tunnelled client, never to the host's real IP. (Config load
/// validates the operator-facing transport-route table up front via
/// [`RoutingTable::from_proxy_config`].)
fn build_tunnel_routes(
    default_endpoint: Option<&str>,
    per_host: &HashMap<String, String>,
) -> RoutingTable {
    let mut routes = Vec::with_capacity(per_host.len());
    for (host, endpoint) in per_host {
        let pattern = match RoutePattern::parse(host) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "egress",
                    host = %host,
                    reason = %e,
                    "skipping per-host tunnel override with an invalid host pattern",
                );
                continue;
            }
        };
        match ProxyUrl::parse(endpoint) {
            Ok(proxy) => routes.push(TransportRoute {
                pattern,
                proxy: Some(proxy),
                verify_ssl: true,
            }),
            Err(e) => {
                tracing::warn!(
                    target: "egress",
                    host = %host,
                    reason = %e.message,
                    "skipping per-host tunnel override with an invalid tunnel URL",
                );
            }
        }
    }

    let default_proxy = default_endpoint.and_then(|e| ProxyUrl::parse(e).ok());
    let all_proxy = default_proxy.is_some();
    RoutingTable::new(routes, all_proxy, default_proxy)
}

/// Build the default tunnelled `reqwest` client (rustls), routing through the
/// optional proxy `endpoint` (design: Components -> Egress -> Layer 2; Req 51.1,
/// 35.2).
///
/// Connection pooling is enabled so pooled upstream connections are reused
/// (Req 35.2). When `endpoint` is `Some`, every request dials through that
/// HTTP/HTTPS/SOCKS proxy; when `None` (netns/disabled) no proxy is set.
fn build_tunneled_reqwest(endpoint: Option<&str>) -> Result<reqwest::Client, AppError> {
    let mut builder = reqwest::Client::builder()
        // Reuse pooled upstream connections (Req 35.2).
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        // Server-side redirect following matches the streaming-core contract;
        // refined per-route in task 14.
        .redirect(reqwest::redirect::Policy::default());

    if let Some(proxy_url) = endpoint {
        let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| {
            AppError::unknown(format!(
                "invalid egress tunnel proxy URL `{proxy_url}`: {e}"
            ))
        })?;
        builder = builder.proxy(proxy);
    } else {
        // No tunnel proxy: do not pick up an ambient system proxy that could
        // bypass the intended egress path.
        builder = builder.no_proxy();
    }

    builder
        .build()
        .map_err(|e| AppError::unknown(format!("failed to build tunneled egress client: {e}")))
}

/// Build the tunnelled Chrome-JA3/JA4 impersonation `wreq` client, routing
/// through the optional proxy `endpoint` (Req 35.5, 51.1).
///
/// Uses the latest Chrome emulation template from `wreq-util` so
/// Cloudflare-fronted extractor hosts see a real browser fingerprint.
fn build_tunneled_impersonate(endpoint: Option<&str>) -> Result<wreq::Client, AppError> {
    let mut builder = wreq::Client::builder().emulation(wreq_util::Emulation::Chrome134);

    if let Some(proxy_url) = endpoint {
        let proxy = wreq::Proxy::all(proxy_url).map_err(|e| {
            AppError::unknown(format!(
                "invalid egress tunnel proxy URL `{proxy_url}` for impersonation client: {e}"
            ))
        })?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }

    builder.build().map_err(|e| {
        AppError::unknown(format!(
            "failed to build tunneled impersonation client: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::tunnel::test_support::MockReflector;
    use super::*;
    use crate::config::EgressTunnelMode;
    use crate::errors::ErrorCategory;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// A pair of freshly-built (un-proxied) clients for constructing an
    /// [`OutboundClient`] directly in a test. Building a client performs no
    /// network I/O.
    fn test_clients() -> (reqwest::Client, wreq::Client) {
        (
            build_tunneled_reqwest(None).expect("reqwest client builds"),
            build_tunneled_impersonate(None).expect("wreq client builds"),
        )
    }

    /// An [`OutboundClient`] with the given policy and resolver state, no
    /// tunnel endpoint configured.
    fn client_with(policy: EgressPolicy, resolver: Option<Arc<EgressResolver>>) -> OutboundClient {
        let (tunneled, impersonate) = test_clients();
        OutboundClient::new(
            tunneled,
            impersonate,
            policy,
            resolver,
            None,
            HashMap::new(),
        )
    }

    /// A resolver over a proxy tunnel with the given mock reflector and a long
    /// refresh interval (the background loop stays idle; tests drive
    /// `refresh()` explicitly).
    fn resolver_with(reflector: MockReflector) -> Arc<EgressResolver> {
        let tunnel = Tunnel::proxy("http://proxy:8888", Arc::new(reflector));
        Arc::new(EgressResolver::new(
            Arc::new(tunnel),
            Duration::from_secs(3600),
        ))
    }

    fn unresolved_reflector() -> MockReflector {
        MockReflector::new(None, Some(ip("198.51.100.1")))
    }

    /// A resolver already refreshed to a verified, leak-free state.
    async fn verified_resolver(egress: &str, host: &str) -> Arc<EgressResolver> {
        let resolver = resolver_with(MockReflector::isolated(egress, host));
        resolver.refresh().await;
        resolver
    }

    // -- Healthy tunnel: upstream() builds a tunneled request (Req 51.1) -----

    #[tokio::test]
    async fn upstream_builds_request_when_tunnel_verified() {
        let resolver = verified_resolver("203.0.113.7", "198.51.100.1").await;
        let client = client_with(EgressPolicy::FailClosed, Some(resolver));

        let target = url("https://api.real-debrid.com/rest/1.0/unrestrict/link");
        let builder = client
            .upstream(Method::GET, &target)
            .expect("verified tunnel must allow the dial");

        // The produced request is sanitized: it carries none of the
        // client-identifying headers (it starts from a fresh request).
        let request = builder.build().expect("request builds");
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.url(), &target);
        for name in CLIENT_IDENTIFYING_HEADERS {
            assert!(
                request.headers().get(name).is_none(),
                "outbound request must not carry the client-identifying header {name}",
            );
        }
    }

    // -- No tunnel configured: direct networking is normal -------------------

    #[test]
    fn disabled_tunnel_dials_direct_even_under_fail_closed() {
        let client = client_with(EgressPolicy::FailClosed, None);
        let target = url("https://api.real-debrid.com/");
        let builder = client
            .upstream(Method::GET, &target)
            .expect("disabled egress mode must use normal direct networking");
        assert_eq!(client.decision(), EgressDecision::DialDirect);
        let request = builder.build().expect("request builds");
        assert_eq!(request.url(), &target);
    }

    // -- Fail-closed refuses with no dial when a configured tunnel is down / leaking (Req 51.8) -----

    #[test]
    fn fail_closed_refuses_when_configured_tunnel_unresolved() {
        // Resolver exists but has not verified yet -> configured tunnel is
        // Unresolved -> fail-closed refuses.
        let resolver = resolver_with(unresolved_reflector());
        let client = client_with(EgressPolicy::FailClosed, Some(resolver));
        let err = client
            .upstream(Method::GET, &url("https://api.real-debrid.com/"))
            .expect_err("fail-closed must refuse when the tunnel is down");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("egress tunnel"));
    }

    #[tokio::test]
    async fn fail_closed_refuses_when_tunnel_leaking() {
        // tunnel-observed IP == host real IP -> Leaking.
        let resolver = resolver_with(MockReflector::isolated("198.51.100.1", "198.51.100.1"));
        resolver.refresh().await;
        assert!(resolver.is_leaking());

        let client = client_with(EgressPolicy::FailClosed, Some(resolver));
        let err = client
            .upstream(Method::GET, &url("https://cdn.example/video.mp4"))
            .expect_err("fail-closed must refuse when the tunnel is leaking");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(client.decision().refuses());
    }

    #[test]
    fn fail_closed_refuses_impersonation_dial_too() {
        let resolver = resolver_with(unresolved_reflector());
        let client = client_with(EgressPolicy::FailClosed, Some(resolver));
        // `wreq::RequestBuilder` is not `Debug`, so match on the result rather
        // than `expect_err` (which would require `Debug` on the Ok variant).
        let err = match client.impersonate(Method::GET, &url("https://cloudflare-host.example/")) {
            Ok(_) => panic!("fail-closed must refuse the impersonation path as well"),
            Err(err) => err,
        };
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
    }

    // -- Fail-open proceeds (and warns) when down / leaking (Req 51.8) -------

    #[test]
    fn fail_open_proceeds_when_tunnel_down() {
        let resolver = resolver_with(unresolved_reflector());
        let client = client_with(EgressPolicy::FailOpen, Some(resolver));
        let target = url("https://api.real-debrid.com/");
        let builder = client
            .upstream(Method::GET, &target)
            .expect("fail-open must proceed even when the tunnel is down");
        assert!(client.decision().warns_not_tunneled());
        // The builder is usable.
        let request = builder.build().expect("request builds");
        assert_eq!(request.url(), &target);
    }

    #[tokio::test]
    async fn fail_open_proceeds_when_tunnel_leaking() {
        let resolver = resolver_with(MockReflector::isolated("198.51.100.1", "198.51.100.1"));
        resolver.refresh().await;
        let client = client_with(EgressPolicy::FailOpen, Some(resolver));
        assert!(client
            .upstream(Method::GET, &url("https://cdn.example/v.mp4"))
            .is_ok());
        assert!(client.decision().warns_not_tunneled());
    }

    // -- Verified tunnel dials tunneled under either policy (Req 51.8) -------

    #[tokio::test]
    async fn verified_tunnel_dials_under_both_policies() {
        for policy in [EgressPolicy::FailClosed, EgressPolicy::FailOpen] {
            let resolver = verified_resolver("203.0.113.7", "198.51.100.1").await;
            let client = client_with(policy, Some(resolver));
            assert_eq!(client.decision(), EgressDecision::DialTunneled);
            assert!(client
                .upstream(Method::GET, &url("https://api.real-debrid.com/"))
                .is_ok());
        }
    }

    // -- Decision is deterministic for a given (policy, state) (Req 51.8) ----

    #[tokio::test]
    async fn decision_is_deterministic_for_policy_and_state() {
        let resolver = verified_resolver("203.0.113.7", "198.51.100.1").await;
        let client = client_with(EgressPolicy::FailClosed, Some(resolver));
        let first = client.decision();
        for _ in 0..10 {
            assert_eq!(client.decision(), first);
        }
        assert_eq!(first, EgressDecision::DialTunneled);
    }

    // -- egress_ip() surfaces the verified Egress_IP (Req 51.5, 51.11) -------

    #[tokio::test]
    async fn egress_ip_reflects_resolver_state() {
        let client = client_with(EgressPolicy::FailClosed, None);
        assert_eq!(client.egress_ip(), None, "no tunnel -> no Egress_IP");

        let resolver = verified_resolver("203.0.113.7", "198.51.100.1").await;
        let client = client_with(EgressPolicy::FailClosed, Some(resolver));
        assert_eq!(client.egress_ip(), Some(ip("203.0.113.7")));
    }

    #[tokio::test]
    async fn egress_ip_is_none_while_leaking() {
        let resolver = resolver_with(MockReflector::isolated("198.51.100.1", "198.51.100.1"));
        resolver.refresh().await;
        let client = client_with(EgressPolicy::FailClosed, Some(resolver));
        assert_eq!(
            client.egress_ip(),
            None,
            "a leaking tunnel exposes no usable Egress_IP",
        );
    }

    // -- Per-host/per-store tunnel selection (Req 51.9) ----------------------

    #[test]
    fn select_tunnel_endpoint_prefers_per_host_override() {
        let (tunneled, impersonate) = test_clients();
        let mut per_host = HashMap::new();
        per_host.insert(
            "api.real-debrid.com".to_string(),
            "socks5://127.0.0.1:1080".to_string(),
        );
        let client = OutboundClient::new(
            tunneled,
            impersonate,
            EgressPolicy::FailClosed,
            None,
            Some("http://default-proxy:8888".to_string()),
            per_host,
        );

        // Pinned host -> its override (case-insensitive host match).
        assert_eq!(
            client.select_tunnel_endpoint(&url("https://API.Real-Debrid.com/rest")),
            Some("socks5://127.0.0.1:1080"),
        );
        // Unpinned host -> the default tunnel endpoint.
        assert_eq!(
            client.select_tunnel_endpoint(&url("https://cdn.example/video.mp4")),
            Some("http://default-proxy:8888"),
        );
    }

    // -- from_config wiring (Req 51.1, 51.8, 51.9) ---------------------------

    #[test]
    fn from_config_disabled_has_no_resolver_and_dials_direct() {
        let cfg = EgressConfig::default(); // Disabled, FailClosed
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let client = OutboundClient::from_config(&cfg, reflector).expect("builds");

        assert!(client.resolver().is_none());
        assert_eq!(client.egress_ip(), None);
        assert_eq!(client.decision(), EgressDecision::DialDirect);
        // Disabled tunnel means normal direct networking, even with the
        // fail-closed policy still available for configured tunnels.
        assert!(client
            .upstream(Method::GET, &url("https://api.real-debrid.com/"))
            .is_ok());
    }

    #[test]
    fn from_config_proxy_without_url_is_a_misconfiguration() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Proxy,
            tunnel_url: None,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let err = OutboundClient::from_config(&cfg, reflector)
            .expect_err("proxy mode without a URL must be rejected");
        assert!(err.message.contains("tunnel_url"));
    }

    #[tokio::test]
    async fn from_config_proxy_builds_resolver_and_dials_when_verified() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Proxy,
            tunnel_url: Some("http://proxy:8888".into()),
            policy: EgressPolicy::FailClosed,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let client = OutboundClient::from_config(&cfg, reflector).expect("builds");

        let resolver = client
            .resolver()
            .expect("proxy mode yields a resolver")
            .clone();
        // Before the first probe: unverified -> fail-closed refuses.
        assert!(client
            .upstream(Method::GET, &url("https://api.real-debrid.com/"))
            .is_err());

        // After a successful probe: verified -> dial allowed, Egress_IP set.
        resolver.refresh().await;
        assert_eq!(client.egress_ip(), Some(ip("203.0.113.7")));
        assert!(client
            .upstream(Method::GET, &url("https://api.real-debrid.com/"))
            .is_ok());
    }
}
