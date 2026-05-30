//! The pure fail-closed / fail-open egress decision (`egress::policy`) —
//! Req 51.1, 51.8.
//!
//! This module isolates the **deterministic decision** the single outbound
//! seam ([`OutboundClient`](crate::egress)) makes *before* any dial: given the
//! configured [`EgressPolicy`](crate::config::EgressPolicy) and the current
//! tunnel state ([`LeakCheck`]), decide whether to dial the upstream or refuse
//! fail-closed (design: Components -> Egress -> OutboundClient, "Fail-closed
//! safety (Req 51.8)").
//!
//! Keeping the decision a **pure, total** function makes it trivially
//! deterministic and testable in isolation (Property 62) and gives
//! `OutboundClient::upstream` (task 8.3) a single source of truth to call on
//! the dial path instead of re-deriving the branch. The decision performs no
//! I/O and holds no state, so for any `(policy, state)` it always returns the
//! same [`EgressDecision`].
//!
//! ## The three tunnel states (Req 51.8)
//!
//! [`LeakCheck`] captures exactly the tunnel states the fail-closed policy
//! turns on:
//!
//! * [`LeakCheck::Verified`] — **healthy**: a leak-free Egress_IP is proven, so
//!   upstream traffic egresses from the tunnel.
//! * [`LeakCheck::Leaking`] — **leaking**: the tunnel-observed IP equals the
//!   host's real IP, so a dial would expose the host's real IP.
//! * [`LeakCheck::Unresolved`] — **down**: the Egress_IP could not be
//!   resolved/verified, so isolation cannot be proven.
//!
//! Only [`Verified`](LeakCheck::Verified) is safe to dial through; the other
//! two are "down or leaking" and trigger the fail-closed refusal.

use crate::config::EgressPolicy;
use crate::errors::AppError;

use super::tunnel::LeakCheck;

/// The decision the egress seam reaches for a `(policy, tunnel_state)` pair
/// (Req 51.1, 51.8).
///
/// Produced by [`decide_egress`] and consumed by `OutboundClient::upstream`
/// (task 8.3): a [`RefuseFailClosed`](EgressDecision::RefuseFailClosed)
/// short-circuits the dial with [`fail_closed_error`], while the two `Dial*`
/// variants proceed (the untunneled one additionally emitting a warning).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressDecision {
    /// Dial the upstream **through the verified, leak-free tunnel** — the
    /// tunnel is healthy, so the request egresses from the Egress_IP. Reached
    /// under either policy when the state is [`LeakCheck::Verified`].
    DialTunneled,
    /// Dial the upstream **without** a healthy tunnel, emitting a
    /// "traffic is not tunneled" warning (Req 51.8). Reached **only** under
    /// [`EgressPolicy::FailOpen`] when the tunnel is down or leaking — the
    /// operator has explicitly accepted that the host's real IP may be exposed.
    DialUntunneledWithWarning,
    /// Refuse to dial — perform **no** outbound request — and surface a typed
    /// [`fail_closed_error`] (Req 51.8). Reached under
    /// [`EgressPolicy::FailClosed`] (the default) when the tunnel is down or
    /// leaking, so the host's real IP can never leak upstream.
    RefuseFailClosed,
}

impl EgressDecision {
    /// `true` when this decision results in an outbound dial (either tunneled
    /// or — under fail-open — untunneled).
    pub fn dials(self) -> bool {
        matches!(
            self,
            EgressDecision::DialTunneled | EgressDecision::DialUntunneledWithWarning
        )
    }

    /// `true` when this decision refuses to dial entirely (fail-closed,
    /// Req 51.8) — no outbound request leaves the system.
    pub fn refuses(self) -> bool {
        matches!(self, EgressDecision::RefuseFailClosed)
    }

    /// `true` when the dial proceeds **without** a healthy tunnel and a
    /// not-tunneled warning must be emitted (fail-open only).
    pub fn warns_not_tunneled(self) -> bool {
        matches!(self, EgressDecision::DialUntunneledWithWarning)
    }
}

/// Decide whether to dial or refuse for the given `policy` and tunnel `state`
/// (Req 51.1, 51.8) — the pure heart of the egress fail-closed guarantee.
///
/// * Tunnel **healthy** ([`LeakCheck::Verified`]) →
///   [`EgressDecision::DialTunneled`] under either policy (the request egresses
///   from the verified Egress_IP).
/// * Tunnel **down** ([`LeakCheck::Unresolved`]) or **leaking**
///   ([`LeakCheck::Leaking`]):
///   * under [`EgressPolicy::FailClosed`] (the default) →
///     [`EgressDecision::RefuseFailClosed`] (no dial; the host's real IP is
///     never exposed);
///   * under [`EgressPolicy::FailOpen`] →
///     [`EgressDecision::DialUntunneledWithWarning`].
///
/// The function is **total** and **deterministic**: the same `(policy, state)`
/// always yields the same decision, with no I/O or hidden state. The grouping
/// of "down or leaking" is exactly [`LeakCheck::is_verified`] being `false`, so
/// any non-verified state is treated identically.
pub fn decide_egress(policy: EgressPolicy, state: LeakCheck) -> EgressDecision {
    // A healthy (verified leak-free) tunnel is the *only* state safe to dial
    // through; everything else is "down or leaking".
    if state.is_verified() {
        return EgressDecision::DialTunneled;
    }
    match policy {
        // Default: never leak the host's real IP — refuse without dialling.
        EgressPolicy::FailClosed => EgressDecision::RefuseFailClosed,
        // Explicitly opted in: proceed untunneled and warn (Req 51.8).
        EgressPolicy::FailOpen => EgressDecision::DialUntunneledWithWarning,
    }
}

/// The typed error a [`RefuseFailClosed`](EgressDecision::RefuseFailClosed)
/// decision surfaces (Req 51.8): an `UpstreamUnavailable` whose message names
/// the egress tunnel, matching the design's
/// `UpstreamUnavailable("egress tunnel unavailable")`.
///
/// Maps to `503 Service Unavailable` so drop-in clients see a familiar
/// upstream-down status rather than a new code.
pub fn fail_closed_error() -> AppError {
    AppError::upstream_unavailable("egress tunnel unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // -- Healthy tunnel: dial through it under either policy (Req 51.8) -----

    #[test]
    fn verified_tunnel_dials_tunneled_under_both_policies() {
        let state = LeakCheck::Verified { egress_ip: ip("203.0.113.7") };
        for policy in [EgressPolicy::FailClosed, EgressPolicy::FailOpen] {
            let decision = decide_egress(policy, state);
            assert_eq!(decision, EgressDecision::DialTunneled);
            assert!(decision.dials());
            assert!(!decision.warns_not_tunneled());
        }
    }

    // -- Fail-closed refuses when down or leaking (Req 51.1, 51.8) ----------

    #[test]
    fn fail_closed_refuses_when_down() {
        let decision = decide_egress(EgressPolicy::FailClosed, LeakCheck::Unresolved);
        assert_eq!(decision, EgressDecision::RefuseFailClosed);
        assert!(decision.refuses());
        assert!(!decision.dials(), "fail-closed must perform no dial when the tunnel is down");
    }

    #[test]
    fn fail_closed_refuses_when_leaking() {
        let state = LeakCheck::Leaking { ip: ip("198.51.100.1") };
        let decision = decide_egress(EgressPolicy::FailClosed, state);
        assert_eq!(decision, EgressDecision::RefuseFailClosed);
        assert!(!decision.dials(), "fail-closed must perform no dial when the tunnel is leaking");
    }

    // -- Fail-open proceeds untunneled + warns (Req 51.8) -------------------

    #[test]
    fn fail_open_dials_untunneled_with_warning_when_down_or_leaking() {
        for state in [LeakCheck::Unresolved, LeakCheck::Leaking { ip: ip("198.51.100.1") }] {
            let decision = decide_egress(EgressPolicy::FailOpen, state);
            assert_eq!(decision, EgressDecision::DialUntunneledWithWarning);
            assert!(decision.dials());
            assert!(decision.warns_not_tunneled());
        }
    }

    // -- The fail-closed refusal error is a typed UpstreamUnavailable -------

    #[test]
    fn fail_closed_error_is_upstream_unavailable() {
        let err = fail_closed_error();
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("egress tunnel"));
    }

    // -- Determinism (Req 51.8) ---------------------------------------------

    #[test]
    fn decision_is_deterministic() {
        let states = [
            LeakCheck::Verified { egress_ip: ip("203.0.113.7") },
            LeakCheck::Leaking { ip: ip("198.51.100.1") },
            LeakCheck::Unresolved,
        ];
        for policy in [EgressPolicy::FailClosed, EgressPolicy::FailOpen] {
            for state in states {
                assert_eq!(decide_egress(policy, state), decide_egress(policy, state));
            }
        }
    }
}
