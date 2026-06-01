//! Property-based test for the egress fail-closed decision
//! (`egress::decide_egress`, task 8.5).
//!
//! Feature: ZippyPanther, Property 62
//!
//! **Property 62: Egress fail-closed prevents real-IP leakage**
//!
//! *For any* tunnel state, when the policy is `FailClosed` and the tunnel is
//! down or the Egress_IP is unresolved/leaking (tunnel-observed IP equals host
//! real IP), `OutboundClient::upstream` returns a typed `UpstreamUnavailable`
//! error and performs no outbound dial; when the tunnel is healthy it proceeds;
//! and under `FailOpen` it proceeds while emitting a not-tunneled warning. The
//! decision is deterministic for a given `(policy, tunnel_state)`.
//!
//! **Validates: Requirements 51.1, 51.8**
//!
//! Requirement 51.1: "THE Stream_Flow_System SHALL route every outbound request
//! to a debrid service or an end media server through the configured
//! Egress_Tunnel ... so that those upstreams observe only the Egress_IP."
//!
//! Requirement 51.8: "IF the Egress_Tunnel is unavailable or its public IP
//! cannot be resolved, THEN THE Stream_Flow_System SHALL, according to a
//! configurable fail-closed policy, refuse to make upstream debrid/media
//! requests rather than leaking traffic from the host's real IP; WHERE
//! fail-open is explicitly configured, THE Stream_Flow_System SHALL proceed
//! directly and record a warning that traffic is not tunneled."
//!
//! ## Unit under test
//!
//! The single outbound seam's dial-or-refuse choice is isolated into the pure,
//! total function [`decide_egress`]`(policy, tunnel_state) -> EgressDecision`
//! (design: Components -> Egress -> OutboundClient, "Fail-closed safety
//! (Req 51.8)"). `OutboundClient::upstream` (task 8.3) calls this on the dial
//! path: a [`EgressDecision::RefuseFailClosed`] short-circuits with the typed
//! [`fail_closed_error`] and performs no dial, while the `Dial*` variants
//! proceed. Testing the predicate directly exercises the safety invariant
//! independent of the (concurrently-developed) async client surface.
//!
//! ## How the invariants are exercised
//!
//! Each case generates an arbitrary `(EgressPolicy, LeakCheck)` pair — the
//! three tunnel states (`Verified`/healthy, `Leaking`, `Unresolved`/down) with
//! arbitrary IPs, crossed with both policies — and asserts:
//!
//! * **Fail-closed safety (Req 51.8):** under `FailClosed`, a down or leaking
//!   tunnel yields `RefuseFailClosed` — `refuses()` and **not** `dials()`, so
//!   no outbound request leaves the host (no real-IP leak), and the surfaced
//!   error is a typed `UpstreamUnavailable`.
//! * **Healthy proceeds (Req 51.1):** a verified tunnel always dials *tunneled*
//!   under either policy.
//! * **Fail-open proceeds + warns (Req 51.8):** under `FailOpen`, a down or
//!   leaking tunnel dials untunneled and flags the not-tunneled warning.
//! * **Determinism (Req 51.8):** the decision recomputed for the same
//!   `(policy, state)` is identical.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use zippy_panther::config::EgressPolicy;
use zippy_panther::egress::{decide_egress, fail_closed_error, EgressDecision, LeakCheck};
use zippy_panther::errors::ErrorCategory;

/// Arbitrary IP — both IPv4 and IPv6 so the `Verified`/`Leaking` payloads carry
/// a representative spread of addresses (the decision ignores the value, but
/// generating it guards against any accidental value-dependence creeping in).
fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
        any::<u128>().prop_map(|bits| IpAddr::V6(Ipv6Addr::from(bits))),
    ]
}

/// Arbitrary tunnel state across all three [`LeakCheck`] shapes (Req 51.8):
/// `Verified` (healthy), `Leaking` (tunnel IP == host IP), and `Unresolved`
/// (down / Egress_IP could not be resolved).
fn arb_state() -> impl Strategy<Value = LeakCheck> {
    prop_oneof![
        arb_ip().prop_map(|egress_ip| LeakCheck::Verified { egress_ip }),
        arb_ip().prop_map(|ip| LeakCheck::Leaking { ip }),
        Just(LeakCheck::Unresolved),
    ]
}

/// Arbitrary egress policy: fail-closed (the safe default) or fail-open.
fn arb_policy() -> impl Strategy<Value = EgressPolicy> {
    prop_oneof![Just(EgressPolicy::FailClosed), Just(EgressPolicy::FailOpen)]
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 62 — egress fail-closed prevents real-IP
    /// leakage. **Validates: Requirements 51.1, 51.8**
    #[test]
    fn egress_fail_closed_prevents_real_ip_leakage(
        policy in arb_policy(),
        state in arb_state(),
    ) {
        let decision = decide_egress(policy, state);

        // A dial and a refusal are mutually exclusive and exhaustive — the
        // decision is always one or the other, never both/neither.
        prop_assert_eq!(
            decision.dials(), !decision.refuses(),
            "decision must either dial or refuse, exclusively (policy={:?}, state={:?})",
            policy, state,
        );

        match (policy, state.is_verified()) {
            // -- Healthy tunnel: dial *through* it under either policy (51.1)
            (_, true) => {
                prop_assert_eq!(
                    decision, EgressDecision::DialTunneled,
                    "a verified tunnel must dial tunneled (policy={:?})", policy,
                );
                prop_assert!(decision.dials());
                prop_assert!(!decision.warns_not_tunneled());
            }
            // -- Fail-closed + down/leaking: REFUSE, no dial, typed error (51.8)
            (EgressPolicy::FailClosed, false) => {
                prop_assert_eq!(
                    decision, EgressDecision::RefuseFailClosed,
                    "fail-closed must refuse when the tunnel is down or leaking (state={:?})",
                    state,
                );
                // The core safety guarantee: NO outbound dial occurs, so the
                // host's real IP can never leak upstream.
                prop_assert!(
                    !decision.dials(),
                    "fail-closed must perform no dial when down/leaking (state={:?})", state,
                );
                prop_assert!(decision.refuses());
                // ...and the refusal surfaces as a typed UpstreamUnavailable.
                let err = fail_closed_error();
                prop_assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
            }
            // -- Fail-open + down/leaking: proceed untunneled + warn (51.8)
            (EgressPolicy::FailOpen, false) => {
                prop_assert_eq!(
                    decision, EgressDecision::DialUntunneledWithWarning,
                    "fail-open must proceed untunneled when down or leaking (state={:?})",
                    state,
                );
                prop_assert!(decision.dials());
                prop_assert!(
                    decision.warns_not_tunneled(),
                    "fail-open dial without a healthy tunnel must flag the not-tunneled warning",
                );
            }
        }

        // -- Determinism (Req 51.8): same (policy, state) => same decision ---
        prop_assert_eq!(
            decision, decide_egress(policy, state),
            "decision must be deterministic for a given (policy, tunnel_state)",
        );
    }
}
