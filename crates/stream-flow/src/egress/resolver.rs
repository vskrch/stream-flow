//! [`EgressResolver`] — tunnel-observed Egress_IP cache + refresh + leak check
//! (Req 51.5, 51.12).
//!
//! The resolver owns the **current view** of the egress tunnel: it periodically
//! queries the IP-reflection service *through* the [`Tunnel`] to learn the
//! Egress_IP, verifies the tunnel is not leaking the host's real IP, and caches
//! the verified outcome so the hot path can read it without any network call or
//! lock (design: Components -> Egress -> EgressResolver).
//!
//! ## Cache: lock-free [`ArcSwap`]
//!
//! The last [`LeakCheck`] is held in an [`ArcSwap`] so reads
//! ([`egress_ip`](EgressResolver::egress_ip),
//! [`leak_check`](EgressResolver::leak_check)) are lock-free — the store layer
//! reads `egress_ip()` whenever it must bind a link (Req 51.4) and `/proxy/ip`
//! reads it per request (Req 51.11), so this must add no contention to the
//! streaming hot path. A [`refresh`](EgressResolver::refresh) atomically swaps
//! in the new outcome; an in-flight reader either sees the old value or the new
//! one, never a torn state.
//!
//! ## When it refreshes (Req 51.5)
//!
//! * **On an interval.** [`run_refresh_loop`](EgressResolver::run_refresh_loop)
//!   re-verifies every `refresh_interval` (configurable —
//!   [`EgressConfig::refresh_interval_secs`]). It is meant to be spawned under
//!   the task [`Supervisor`](crate::supervisor) in production.
//! * **On tunnel reconnect.** [`on_reconnect`](EgressResolver::on_reconnect)
//!   forces an immediate re-verification so a reconnect that changed the
//!   Egress_IP is reflected promptly instead of waiting for the next tick.
//!
//! ## Fail-closed default (Req 51.8, 51.12)
//!
//! The cache starts at [`LeakCheck::Unresolved`], so before the first
//! successful verification [`egress_ip`](EgressResolver::egress_ip) is `None`
//! and the egress is **not** considered verified — an `OutboundClient` under
//! `FailClosed` therefore refuses to dial until a leak-free Egress_IP has been
//! proven. A later refresh that observes the tunnel IP equal to the host's real
//! IP swaps the cache to [`LeakCheck::Leaking`], which likewise yields no usable
//! Egress_IP and marks the egress broken.
//!
//! [`ArcSwap`]: arc_swap::ArcSwap
//! [`EgressConfig::refresh_interval_secs`]: crate::config::EgressConfig::refresh_interval_secs

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::config::EgressConfig;
use crate::errors::AppError;

use super::tunnel::{IpReflector, LeakCheck, Tunnel};

/// Caches the tunnel-observed, leak-verified Egress_IP and keeps it fresh
/// (Req 51.5, 51.12).
///
/// Build one from configuration with [`EgressResolver::from_config`] (yielding
/// `None` when no tunnel is configured) or directly with
/// [`EgressResolver::new`]. Read the current state with
/// [`egress_ip`](EgressResolver::egress_ip) / [`leak_check`](EgressResolver::leak_check);
/// keep it fresh by spawning [`run_refresh_loop`](EgressResolver::run_refresh_loop)
/// and calling [`on_reconnect`](EgressResolver::on_reconnect) from the tunnel's
/// reconnect handler.
pub struct EgressResolver {
    tunnel: Arc<Tunnel>,
    /// Lock-free cache of the last verification outcome (design: `ArcSwap`
    /// cache). Starts `Unresolved` so the egress is unverified — and therefore
    /// fail-closed — until the first successful probe (Req 51.8).
    state: ArcSwap<LeakCheck>,
    /// How often [`run_refresh_loop`](EgressResolver::run_refresh_loop)
    /// re-verifies (Req 51.5).
    refresh_interval: Duration,
}

impl EgressResolver {
    /// Build a resolver over an existing [`Tunnel`], refreshing every
    /// `refresh_interval` (Req 51.5).
    ///
    /// The cache starts [`LeakCheck::Unresolved`]; call
    /// [`refresh`](EgressResolver::refresh) (or spawn the loop) to populate it.
    pub fn new(tunnel: Arc<Tunnel>, refresh_interval: Duration) -> Self {
        Self {
            tunnel,
            state: ArcSwap::from_pointee(LeakCheck::Unresolved),
            refresh_interval,
        }
    }

    /// Build a resolver from the egress configuration plus a reflection source
    /// (Req 51.5).
    ///
    /// Returns `Ok(None)` when no tunnel is configured
    /// ([`EgressTunnelMode::Disabled`](crate::config::EgressTunnelMode::Disabled));
    /// the caller then applies the fail-closed policy. Propagates the
    /// misconfiguration error from [`Tunnel::from_config`] (e.g. proxy mode
    /// without a URL). The refresh interval is taken from
    /// [`EgressConfig::refresh_interval_secs`].
    pub fn from_config(
        cfg: &EgressConfig,
        reflector: Arc<dyn IpReflector>,
    ) -> Result<Option<Self>, AppError> {
        match Tunnel::from_config(cfg, reflector)? {
            None => Ok(None),
            Some(tunnel) => Ok(Some(Self::new(
                Arc::new(tunnel),
                Duration::from_secs(cfg.refresh_interval_secs),
            ))),
        }
    }

    /// The configured refresh interval (Req 51.5).
    pub fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }

    /// The current cached Egress_IP — `Some` **only** when the last refresh
    /// verified the tunnel leak-free (Req 51.5, 51.12).
    ///
    /// Lock-free read. `None` before the first successful probe, while the
    /// tunnel is leaking, or while the IP is unresolved — so a caller never
    /// binds a link to an unverified address (Req 51.4, 51.8).
    pub fn egress_ip(&self) -> Option<IpAddr> {
        self.state.load().egress_ip()
    }

    /// The current cached verification outcome (Req 51.12). Lock-free read.
    ///
    /// Drives the health view (`connected` / `disconnected` / `leaking`,
    /// Req 51.10) and the fail-closed decision in the `OutboundClient` seam.
    pub fn leak_check(&self) -> LeakCheck {
        **self.state.load()
    }

    /// `true` when the last refresh verified the tunnel leak-free (a usable
    /// Egress_IP is cached).
    pub fn is_verified(&self) -> bool {
        self.leak_check().is_verified()
    }

    /// `true` when the last refresh found the tunnel IP equal to the host's
    /// real IP (Req 51.12) — the egress is leaking and must be treated as
    /// broken.
    pub fn is_leaking(&self) -> bool {
        self.leak_check().is_leaking()
    }

    /// Re-verify the tunnel now and atomically swap the result into the cache
    /// (Req 51.5, 51.12). Returns the freshly-resolved outcome.
    ///
    /// A leak transition (verified/unresolved → leaking) is logged at `warn`
    /// because, under `FailClosed`, it stops all upstream traffic; a recovery
    /// (leaking/unresolved → verified) is logged at `info`. Steady-state
    /// re-verifications that do not change the outcome are silent.
    pub async fn refresh(&self) -> LeakCheck {
        let previous = self.leak_check();
        let next = self.tunnel.verify().await;
        self.state.store(Arc::new(next));
        self.log_transition(previous, next);
        next
    }

    /// Force a refresh in response to a tunnel reconnect event (Req 51.5 —
    /// "whenever the tunnel reconnects").
    ///
    /// A reconnect can change the Egress_IP, so the cache is re-verified
    /// immediately rather than waiting for the next interval tick. Delegates to
    /// [`refresh`](EgressResolver::refresh).
    pub async fn on_reconnect(&self) -> LeakCheck {
        tracing::info!(
            mode = ?self.tunnel.mode(),
            "egress tunnel reconnected; re-resolving Egress_IP",
        );
        self.refresh().await
    }

    /// The supervised periodic refresh loop (Req 51.5): re-verify every
    /// [`refresh_interval`](EgressResolver::refresh_interval) for the life of
    /// the task.
    ///
    /// Intended to be spawned under the task
    /// [`Supervisor`](crate::supervisor); it never returns on its own. Aborting
    /// the spawned task (e.g. on shutdown) ends the loop.
    pub async fn run_refresh_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.refresh_interval).await;
            self.refresh().await;
        }
    }

    /// Emit a structured log line only when the verification outcome changed,
    /// at a severity matching the safety impact.
    fn log_transition(&self, previous: LeakCheck, next: LeakCheck) {
        match (previous.is_leaking() || !previous.is_verified(), next) {
            // Newly leaking — the most serious transition (Req 51.12).
            (_, LeakCheck::Leaking { ip }) if !previous.is_leaking() => {
                tracing::warn!(
                    leaking_ip = %ip,
                    mode = ?self.tunnel.mode(),
                    "egress LEAK detected: tunnel-observed IP equals host real IP; refusing upstream traffic under fail-closed",
                );
            }
            // Newly unresolved after having been verified — lost the Egress_IP.
            (false, LeakCheck::Unresolved) => {
                tracing::warn!(
                    mode = ?self.tunnel.mode(),
                    "egress Egress_IP could not be resolved; treating tunnel as down",
                );
            }
            // Recovered to verified from a non-verified state.
            (true, LeakCheck::Verified { egress_ip }) => {
                tracing::info!(
                    egress_ip = %egress_ip,
                    mode = ?self.tunnel.mode(),
                    "egress Egress_IP verified leak-free",
                );
            }
            // No meaningful change — stay quiet.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tunnel::test_support::MockReflector;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A resolver over a proxy tunnel with the given mock reflector and a long
    /// refresh interval (so the background loop is idle and tests drive
    /// `refresh`/`on_reconnect` deterministically).
    fn resolver_with(reflector: MockReflector) -> (Arc<EgressResolver>, MockReflector) {
        let tunnel = Tunnel::proxy("http://proxy:8888", Arc::new(reflector.clone()));
        let resolver = Arc::new(EgressResolver::new(Arc::new(tunnel), Duration::from_secs(3600)));
        (resolver, reflector)
    }

    // -- Initial state: fail-closed until proven (Req 51.8) -----------------

    #[test]
    fn starts_unresolved_with_no_egress_ip() {
        let (resolver, _) = resolver_with(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        assert_eq!(resolver.leak_check(), LeakCheck::Unresolved);
        assert_eq!(resolver.egress_ip(), None);
        assert!(!resolver.is_verified());
        assert!(!resolver.is_leaking());
    }

    // -- Resolves and caches Egress_IP (Req 51.5) ---------------------------

    #[tokio::test]
    async fn refresh_resolves_and_caches_egress_ip() {
        let (resolver, reflector) =
            resolver_with(MockReflector::isolated("203.0.113.7", "198.51.100.1"));

        let outcome = resolver.refresh().await;
        assert_eq!(outcome, LeakCheck::Verified { egress_ip: ip("203.0.113.7") });

        // Cached: subsequent reads are served from the ArcSwap with no extra
        // reflection call.
        let calls_after_refresh = reflector.observed_calls();
        assert_eq!(resolver.egress_ip(), Some(ip("203.0.113.7")));
        assert_eq!(resolver.egress_ip(), Some(ip("203.0.113.7")));
        assert!(resolver.is_verified());
        assert_eq!(
            reflector.observed_calls(),
            calls_after_refresh,
            "cached reads must not issue new reflection calls",
        );
    }

    // -- Leak check flags tunnel-IP == host-real-IP (Req 51.12) -------------

    #[tokio::test]
    async fn refresh_flags_leak_when_tunnel_ip_equals_host_ip() {
        let (resolver, _) =
            resolver_with(MockReflector::isolated("198.51.100.1", "198.51.100.1"));

        let outcome = resolver.refresh().await;
        assert_eq!(outcome, LeakCheck::Leaking { ip: ip("198.51.100.1") });
        assert!(resolver.is_leaking());
        // A leaking tunnel exposes no usable Egress_IP (fail-closed).
        assert_eq!(resolver.egress_ip(), None);
        assert!(!resolver.is_verified());
    }

    #[tokio::test]
    async fn refresh_is_unresolved_when_reflection_fails() {
        let (resolver, _) = resolver_with(MockReflector::new(None, Some(ip("198.51.100.1"))));
        assert_eq!(resolver.refresh().await, LeakCheck::Unresolved);
        assert_eq!(resolver.egress_ip(), None);
    }

    // -- Refresh tracks a changing Egress_IP --------------------------------

    #[tokio::test]
    async fn refresh_updates_cache_when_egress_ip_changes() {
        let (resolver, reflector) =
            resolver_with(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        resolver.refresh().await;
        assert_eq!(resolver.egress_ip(), Some(ip("203.0.113.7")));

        // The tunnel's public IP changes (e.g. WARP re-homed).
        reflector.set_observed(Some(ip("203.0.113.99")));
        resolver.refresh().await;
        assert_eq!(resolver.egress_ip(), Some(ip("203.0.113.99")));
    }

    #[tokio::test]
    async fn refresh_detects_a_newly_leaking_tunnel() {
        let (resolver, reflector) =
            resolver_with(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        resolver.refresh().await;
        assert!(resolver.is_verified());

        // The tunnel drops and traffic now egresses from the host IP.
        reflector.set_observed(Some(ip("198.51.100.1")));
        resolver.refresh().await;
        assert!(resolver.is_leaking());
        assert_eq!(resolver.egress_ip(), None);

        // ...and recovers when the tunnel comes back on a distinct IP.
        reflector.set_observed(Some(ip("203.0.113.7")));
        resolver.refresh().await;
        assert!(resolver.is_verified());
        assert_eq!(resolver.egress_ip(), Some(ip("203.0.113.7")));
    }

    // -- Refresh on reconnect (Req 51.5) ------------------------------------

    #[tokio::test]
    async fn on_reconnect_re_resolves_immediately() {
        let (resolver, reflector) =
            resolver_with(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        resolver.refresh().await;
        assert_eq!(resolver.egress_ip(), Some(ip("203.0.113.7")));

        // Reconnect with a new Egress_IP: on_reconnect must re-resolve now,
        // not wait for the next interval tick.
        reflector.set_observed(Some(ip("203.0.113.42")));
        let outcome = resolver.on_reconnect().await;
        assert_eq!(outcome, LeakCheck::Verified { egress_ip: ip("203.0.113.42") });
        assert_eq!(resolver.egress_ip(), Some(ip("203.0.113.42")));
    }

    // -- Refresh on interval (Req 51.5) -------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_loop_refreshes_on_interval() {
        let reflector = MockReflector::isolated("203.0.113.7", "198.51.100.1");
        let tunnel = Tunnel::proxy("http://proxy:8888", Arc::new(reflector.clone()));
        let resolver = Arc::new(EgressResolver::new(
            Arc::new(tunnel),
            Duration::from_millis(20),
        ));

        let handle = tokio::spawn(Arc::clone(&resolver).run_refresh_loop());

        // The loop should resolve the initial IP on its own.
        let mut resolved = false;
        for _ in 0..100 {
            if resolver.egress_ip() == Some(ip("203.0.113.7")) {
                resolved = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(resolved, "interval loop must resolve the Egress_IP");

        // Change the tunnel IP; the loop must pick it up on a later tick.
        reflector.set_observed(Some(ip("203.0.113.55")));
        let mut refreshed = false;
        for _ in 0..100 {
            if resolver.egress_ip() == Some(ip("203.0.113.55")) {
                refreshed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(refreshed, "interval loop must refresh a changed Egress_IP");

        handle.abort();
    }

    #[tokio::test]
    async fn from_config_disabled_yields_no_resolver() {
        let cfg = EgressConfig::default(); // tunnel_mode = Disabled
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        assert!(EgressResolver::from_config(&cfg, reflector).unwrap().is_none());
    }

    #[tokio::test]
    async fn from_config_proxy_builds_resolver_with_configured_interval() {
        let cfg = EgressConfig {
            tunnel_mode: crate::config::EgressTunnelMode::Proxy,
            tunnel_url: Some("http://proxy:8888".into()),
            refresh_interval_secs: 42,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        let resolver = EgressResolver::from_config(&cfg, reflector)
            .unwrap()
            .expect("proxy mode yields a resolver");
        assert_eq!(resolver.refresh_interval(), Duration::from_secs(42));

        let outcome = resolver.refresh().await;
        assert_eq!(outcome, LeakCheck::Verified { egress_ip: ip("203.0.113.7") });
    }
}
