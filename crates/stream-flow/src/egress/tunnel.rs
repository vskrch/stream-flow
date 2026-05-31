//! Layer 2 — egress tunnel transport + leak verification (`egress::tunnel`) —
//! Req 51.1, 51.8, 51.12.
//!
//! All outbound debrid/media traffic must leave the process through an
//! [`Egress_Tunnel`] so upstreams observe only the Egress_IP and never a user's
//! real IP (design: Components -> Egress -> Layer 2 transport tunneling). This
//! module models the two supported tunnel modes and the **leak verification**
//! that proves the tunnel is actually isolating egress:
//!
//! * **Proxy mode** ([`Tunnel::proxy`]) — outbound clients dial through a
//!   configured HTTP/HTTPS/SOCKS5 forwarding proxy (a local Cloudflare WARP
//!   SOCKS endpoint, a Gluetun/WireGuard container exposing a proxy). The
//!   reflection source is built to route through that same proxy, so the
//!   observed IP is the proxy's public IP.
//! * **Network-namespace mode** ([`Tunnel::netns`]) — the container runs inside
//!   a VPN network namespace (Gluetun sidecar, `network_mode: service:vpn`) so
//!   "direct" calls are forced through the tunnel by the host routing table.
//!   The observed IP is still verified to differ from the host's real IP.
//!
//! ## The IP-reflection seam
//!
//! The actual network I/O — querying an IP-reflection service through the
//! tunnel, and resolving the host's real IP without it — is abstracted behind
//! the [`IpReflector`] trait. Production wires a `reqwest`/`rquest`-backed
//! reflector routed through the tunnel when the [`OutboundClient`] seam lands
//! (task 8.3); the unit tests substitute a controllable mock so the tunnel
//! modes and leak verification are exercised deterministically with **no real
//! network call**.
//!
//! ## Leak verification (Req 51.12)
//!
//! [`Tunnel::verify`] resolves the tunnel-observed IP and the host's real IP
//! and compares them:
//!
//! * different IPs → [`LeakCheck::Verified`] (egress is isolated; carries the
//!   Egress_IP);
//! * equal IPs → [`LeakCheck::Leaking`] (upstream traffic would expose the
//!   host's real IP — the egress is **broken** and, under `FailClosed`,
//!   upstream calls must be refused until healed);
//! * either IP unresolvable → [`LeakCheck::Unresolved`] (isolation cannot be
//!   proven, treated as unsafe under `FailClosed`).
//!
//! [`Egress_Tunnel`]: crate::config::EgressTunnelMode
//! [`OutboundClient`]: crate::egress

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::{EgressConfig, EgressTunnelMode};
use crate::errors::AppError;

/// Source that reflects the public IP observed for a network path (Req 51.5,
/// 51.12).
///
/// This is the single seam between the egress tunnel logic and real network
/// I/O. Implementors query an external IP-reflection service (e.g.
/// `https://api.ipify.org`, Cloudflare `cdn-trace`) and parse the reflected
/// address.
///
/// * [`observed_ip`](IpReflector::observed_ip) queries the service **through
///   the tunnel**, yielding the Egress_IP (Req 51.5).
/// * [`host_ip`](IpReflector::host_ip) resolves the host's real public IP
///   **without** the tunnel; it is used solely for leak verification
///   (Req 51.12) and never to make upstream requests.
///
/// Both methods are fallible and total: a network/parse failure surfaces as a
/// typed [`AppError`] rather than a panic, so the caller can apply the
/// fail-closed policy.
#[async_trait]
pub trait IpReflector: Send + Sync {
    /// Resolve the public IP observed when egressing **through the tunnel**
    /// (the Egress_IP — Req 51.5).
    async fn observed_ip(&self) -> Result<IpAddr, AppError>;

    /// Resolve the host's real public IP **without** the tunnel, for leak
    /// verification only (Req 51.12).
    async fn host_ip(&self) -> Result<IpAddr, AppError>;
}

/// The outcome of a tunnel leak-verification probe (Req 51.12).
///
/// Produced by [`Tunnel::verify`] and consumed by the
/// [`EgressResolver`](crate::egress::resolver::EgressResolver), which caches it
/// and exposes the derived Egress_IP / health state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeakCheck {
    /// The tunnel-observed IP differs from the host's real IP — egress is
    /// isolated. Carries the verified, leak-free Egress_IP.
    Verified {
        /// The verified Egress_IP upstreams will observe.
        egress_ip: IpAddr,
    },
    /// The tunnel-observed IP equals the host's real IP — upstream traffic
    /// would leak the host's real IP. The egress is considered **broken**.
    Leaking {
        /// The IP that is identical on both the tunnelled and direct paths.
        ip: IpAddr,
    },
    /// One of the IPs could not be resolved, so isolation cannot be proven
    /// (treated as unsafe under `FailClosed`).
    Unresolved,
}

impl LeakCheck {
    /// The usable Egress_IP — `Some` **only** when verified leak-free.
    ///
    /// A leaking or unresolved check yields `None` so a caller never treats an
    /// unverified address as a safe Egress_IP (Req 51.8, 51.12).
    pub fn egress_ip(self) -> Option<IpAddr> {
        match self {
            LeakCheck::Verified { egress_ip } => Some(egress_ip),
            LeakCheck::Leaking { .. } | LeakCheck::Unresolved => None,
        }
    }

    /// `true` only when the tunnel was verified leak-free.
    pub fn is_verified(self) -> bool {
        matches!(self, LeakCheck::Verified { .. })
    }

    /// `true` when the tunnel-observed IP equals the host's real IP (Req 51.12).
    pub fn is_leaking(self) -> bool {
        matches!(self, LeakCheck::Leaking { .. })
    }
}

/// A configured egress tunnel: its transport mode, the endpoint it dials, and
/// the reflection source used to learn the Egress_IP and verify isolation
/// (design: Components -> Egress -> Layer 2, tunnel modes).
///
/// Construct one with [`Tunnel::proxy`] / [`Tunnel::netns`], or directly from
/// configuration with [`Tunnel::from_config`]. The actual outbound-client
/// construction (routing `reqwest`/`rquest` through `endpoint`) is the
/// [`OutboundClient`](crate::egress) seam (task 8.3); this type owns the mode,
/// endpoint, and leak-verification policy that seam relies on.
pub struct Tunnel {
    mode: EgressTunnelMode,
    /// Proxy URL (proxy mode) or namespace identifier (netns mode). `None` is
    /// valid only for netns mode, where the host routing table — not an
    /// explicit endpoint — forces traffic through the tunnel.
    endpoint: Option<String>,
    reflector: Arc<dyn IpReflector>,
}

impl Tunnel {
    /// Build a **proxy-mode** tunnel that dials through the forwarding proxy at
    /// `endpoint` (design: Layer 2 — proxy mode).
    ///
    /// `reflector` must be constructed to route through the same proxy so
    /// [`observed_ip`](Tunnel::observed_ip) reports that proxy's public IP.
    pub fn proxy(endpoint: impl Into<String>, reflector: Arc<dyn IpReflector>) -> Self {
        Self {
            mode: EgressTunnelMode::Proxy,
            endpoint: Some(endpoint.into()),
            reflector,
        }
    }

    /// Build a **network-namespace-mode** tunnel (design: Layer 2 — netns
    /// mode). Calls are "direct" but the host routing table forces them through
    /// the VPN namespace; `endpoint` is an optional namespace identifier for
    /// reporting only.
    pub fn netns(endpoint: Option<String>, reflector: Arc<dyn IpReflector>) -> Self {
        Self {
            mode: EgressTunnelMode::Netns,
            endpoint,
            reflector,
        }
    }

    /// Build a tunnel from the egress configuration plus a reflection source
    /// (Req 51.1, 51.9).
    ///
    /// * [`Disabled`](EgressTunnelMode::Disabled) → `Ok(None)`: no tunnel is
    ///   configured, so the caller applies the fail-closed policy (Req 51.8).
    /// * [`Proxy`](EgressTunnelMode::Proxy) → requires
    ///   [`tunnel_url`](EgressConfig::tunnel_url); a proxy mode without a URL is
    ///   a misconfiguration and returns an error rather than silently dialling
    ///   direct.
    /// * [`Netns`](EgressTunnelMode::Netns) → uses `tunnel_url` as an optional
    ///   namespace identifier.
    pub fn from_config(
        cfg: &EgressConfig,
        reflector: Arc<dyn IpReflector>,
    ) -> Result<Option<Self>, AppError> {
        match cfg.tunnel_mode {
            EgressTunnelMode::Disabled => Ok(None),
            EgressTunnelMode::Proxy => {
                let endpoint = cfg.tunnel_url.clone().ok_or_else(|| {
                    AppError::unknown(
                        "egress proxy tunnel configured (tunnel_mode=proxy) without a tunnel_url",
                    )
                })?;
                Ok(Some(Self::proxy(endpoint, reflector)))
            }
            EgressTunnelMode::Netns => Ok(Some(Self::netns(cfg.tunnel_url.clone(), reflector))),
        }
    }

    /// The transport mode this tunnel operates in.
    pub fn mode(&self) -> EgressTunnelMode {
        self.mode
    }

    /// The proxy URL (proxy mode) or namespace identifier (netns mode), if any.
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// Resolve the current Egress_IP via the reflection service **through the
    /// tunnel** (Req 51.5).
    ///
    /// This is the raw tunnel-observed IP **without** the leak check; callers
    /// that need a leak-verified address use [`verify`](Tunnel::verify).
    pub async fn observed_ip(&self) -> Result<IpAddr, AppError> {
        self.reflector.observed_ip().await
    }

    /// Verify the tunnel is isolating egress by comparing the tunnel-observed
    /// IP against the host's real IP (Req 51.12).
    ///
    /// Returns:
    /// * [`LeakCheck::Verified`] when the two differ (egress is isolated);
    /// * [`LeakCheck::Leaking`] when they are equal (the host's real IP would
    ///   leak upstream — egress is broken);
    /// * [`LeakCheck::Unresolved`] when either IP cannot be resolved (isolation
    ///   cannot be proven; unsafe under `FailClosed`).
    ///
    /// The probe is **total**: any reflector error maps to `Unresolved` rather
    /// than propagating, so the resolver can always update its cache.
    pub async fn verify(&self) -> LeakCheck {
        let observed = match self.reflector.observed_ip().await {
            Ok(ip) => ip,
            // Can't even learn the Egress_IP → cannot prove isolation.
            Err(_) => return LeakCheck::Unresolved,
        };
        let host = match self.reflector.host_ip().await {
            Ok(ip) => ip,
            // Egress_IP known but host IP unknown → cannot prove the two
            // differ, so we refuse to call it verified (Req 51.8).
            Err(_) => return LeakCheck::Unresolved,
        };
        if observed == host {
            LeakCheck::Leaking { ip: observed }
        } else {
            LeakCheck::Verified {
                egress_ip: observed,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A controllable [`IpReflector`] used by the tunnel and resolver tests to
    //! exercise every path with no real network call.
    use super::*;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A mock reflection source. The observed/host IPs are swappable at runtime
    /// (a `None` slot makes that method error, standing in for an unreachable
    /// service) and every call is counted so tests can assert refresh activity.
    #[derive(Clone)]
    pub(crate) struct MockReflector {
        observed: Arc<Mutex<Option<IpAddr>>>,
        host: Arc<Mutex<Option<IpAddr>>>,
        observed_calls: Arc<AtomicUsize>,
        host_calls: Arc<AtomicUsize>,
    }

    impl MockReflector {
        /// A reflector that reports `observed` through the tunnel and `host`
        /// directly. Pass `None` to make that path error.
        pub(crate) fn new(observed: Option<IpAddr>, host: Option<IpAddr>) -> Self {
            Self {
                observed: Arc::new(Mutex::new(observed)),
                host: Arc::new(Mutex::new(host)),
                observed_calls: Arc::new(AtomicUsize::new(0)),
                host_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// Convenience: an isolated tunnel (observed != host), both resolvable.
        pub(crate) fn isolated(observed: &str, host: &str) -> Self {
            Self::new(Some(observed.parse().unwrap()), Some(host.parse().unwrap()))
        }

        /// Swap the IP reported through the tunnel (`None` → error).
        pub(crate) fn set_observed(&self, ip: Option<IpAddr>) {
            *self.observed.lock().unwrap() = ip;
        }

        /// Swap the host's real IP (`None` → error).
        pub(crate) fn set_host(&self, ip: Option<IpAddr>) {
            *self.host.lock().unwrap() = ip;
        }

        /// How many times the tunnelled-reflection path was queried.
        pub(crate) fn observed_calls(&self) -> usize {
            self.observed_calls.load(Ordering::SeqCst)
        }

        /// How many times the host-IP path was queried.
        pub(crate) fn host_calls(&self) -> usize {
            self.host_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl IpReflector for MockReflector {
        async fn observed_ip(&self) -> Result<IpAddr, AppError> {
            self.observed_calls.fetch_add(1, Ordering::SeqCst);
            self.observed
                .lock()
                .unwrap()
                .ok_or_else(|| AppError::upstream_unavailable("ip-reflection unreachable (test)"))
        }

        async fn host_ip(&self) -> Result<IpAddr, AppError> {
            self.host_calls.fetch_add(1, Ordering::SeqCst);
            self.host
                .lock()
                .unwrap()
                .ok_or_else(|| AppError::upstream_unavailable("host-ip probe unreachable (test)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockReflector;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // -- Tunnel modes (Req 51.1) -------------------------------------------

    #[test]
    fn proxy_tunnel_reports_proxy_mode_and_endpoint() {
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let tunnel = Tunnel::proxy("socks5://127.0.0.1:1080", reflector);
        assert_eq!(tunnel.mode(), EgressTunnelMode::Proxy);
        assert_eq!(tunnel.endpoint(), Some("socks5://127.0.0.1:1080"));
    }

    #[test]
    fn netns_tunnel_reports_netns_mode() {
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let tunnel = Tunnel::netns(Some("vpn0".into()), reflector);
        assert_eq!(tunnel.mode(), EgressTunnelMode::Netns);
        assert_eq!(tunnel.endpoint(), Some("vpn0"));
    }

    // -- Tunnel::from_config (Req 51.1, 51.9) ------------------------------

    #[test]
    fn from_config_disabled_returns_none() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let tunnel = Tunnel::from_config(&cfg, reflector).unwrap();
        assert!(tunnel.is_none(), "no tunnel when egress is disabled");
    }

    #[test]
    fn from_config_proxy_requires_a_url() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Proxy,
            tunnel_url: None,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let err = match Tunnel::from_config(&cfg, reflector) {
            Err(e) => e,
            Ok(_) => panic!("proxy mode without a URL must be a misconfiguration error"),
        };
        assert!(
            err.message.contains("tunnel_url"),
            "proxy mode without a URL must be a named misconfiguration, got: {err}"
        );
    }

    #[test]
    fn from_config_proxy_builds_with_url() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Proxy,
            tunnel_url: Some("http://proxy:8888".into()),
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let tunnel = Tunnel::from_config(&cfg, reflector).unwrap().unwrap();
        assert_eq!(tunnel.mode(), EgressTunnelMode::Proxy);
        assert_eq!(tunnel.endpoint(), Some("http://proxy:8888"));
    }

    #[test]
    fn from_config_netns_builds_without_a_url() {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Netns,
            tunnel_url: None,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let tunnel = Tunnel::from_config(&cfg, reflector).unwrap().unwrap();
        assert_eq!(tunnel.mode(), EgressTunnelMode::Netns);
        assert_eq!(tunnel.endpoint(), None);
    }

    // -- observed_ip (Req 51.5) --------------------------------------------

    #[tokio::test]
    async fn observed_ip_returns_the_reflected_egress_ip() {
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let tunnel = Tunnel::proxy("http://proxy:8888", reflector);
        assert_eq!(tunnel.observed_ip().await.unwrap(), ip("203.0.113.7"));
    }

    #[tokio::test]
    async fn observed_ip_propagates_reflection_failure() {
        let reflector = Arc::new(MockReflector::new(None, Some(ip("198.51.100.1"))));
        let tunnel = Tunnel::proxy("http://proxy:8888", reflector);
        assert!(tunnel.observed_ip().await.is_err());
    }

    // -- Leak verification (Req 51.12) -------------------------------------

    #[tokio::test]
    async fn verify_passes_when_observed_differs_from_host() {
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let tunnel = Tunnel::proxy("http://proxy:8888", reflector);

        let check = tunnel.verify().await;
        assert_eq!(
            check,
            LeakCheck::Verified {
                egress_ip: ip("203.0.113.7")
            }
        );
        assert!(check.is_verified());
        assert!(!check.is_leaking());
        assert_eq!(check.egress_ip(), Some(ip("203.0.113.7")));
    }

    #[tokio::test]
    async fn verify_flags_leak_when_observed_equals_host() {
        // The whole point of the leak check (Req 51.12): tunnel IP == host IP.
        let reflector = Arc::new(MockReflector::isolated("198.51.100.1", "198.51.100.1"));
        let tunnel = Tunnel::netns(None, reflector);

        let check = tunnel.verify().await;
        assert_eq!(
            check,
            LeakCheck::Leaking {
                ip: ip("198.51.100.1")
            }
        );
        assert!(check.is_leaking());
        assert!(!check.is_verified());
        // A leaking tunnel exposes no usable Egress_IP.
        assert_eq!(check.egress_ip(), None);
    }

    #[tokio::test]
    async fn verify_unresolved_when_egress_ip_cannot_be_resolved() {
        let reflector = Arc::new(MockReflector::new(None, Some(ip("198.51.100.1"))));
        let tunnel = Tunnel::proxy("http://proxy:8888", reflector);
        assert_eq!(tunnel.verify().await, LeakCheck::Unresolved);
    }

    #[tokio::test]
    async fn verify_unresolved_when_host_ip_cannot_be_resolved() {
        // Egress IP known but host IP unknown → cannot prove isolation, so the
        // conservative result is Unresolved (unsafe under FailClosed).
        let reflector = Arc::new(MockReflector::new(Some(ip("203.0.113.7")), None));
        let tunnel = Tunnel::netns(None, reflector);
        let check = tunnel.verify().await;
        assert_eq!(check, LeakCheck::Unresolved);
        assert_eq!(check.egress_ip(), None);
    }

    #[tokio::test]
    async fn verify_works_identically_for_both_tunnel_modes() {
        // Leak verification is mode-independent (Req 51.12 applies to proxy and
        // netns alike): the same observed/host pair yields the same outcome.
        let proxy = Tunnel::proxy(
            "http://proxy:8888",
            Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1")),
        );
        let netns = Tunnel::netns(
            None,
            Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1")),
        );
        assert_eq!(proxy.verify().await, netns.verify().await);
    }
}
