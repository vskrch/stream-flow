//! Property-based test for the Degradation Guard's pure decision logic
//! (task 11.5).
//!
//! Feature: ZippyPanther, Property 46
//!
//! **Property 46: Degradation guard state transitions**
//!
//! *For any* active-connection count and sampled RSS, the guard enters
//! `Degraded` at/above the connection **or** memory high-water mark and rejects
//! new non-streaming requests with `503` while active streams are unaffected;
//! it returns to `Normal` only once the connection count is **strictly below**
//! the (lower) low-water mark **and** RSS is below the memory mark — the
//! hysteresis gap that prevents flapping — so the transition is reversible
//! without oscillating on every connection open/close.
//!
//! **Validates: Requirements 44.1, 44.3, 44.4**
//!
//! The component under test is the pure, plain-data decision pair exported from
//! the crate's public HTTP surface:
//! [`zippy_panther::http::next_load_state`] (the hysteresis-aware
//! `Normal ⇄ Degraded` transition, Req 44.1/44.4) and
//! [`zippy_panther::http::shed_new_request`] (the per-class admission decision,
//! Req 44.1/44.3). Because both are pure functions over a generated snapshot,
//! the property drives them directly with no actix runtime, atomics, clock, or
//! mocking.
//!
//! ## How the invariants are exercised
//!
//! Each case generates arbitrary [`LoadThresholds`] (an enabled flag, a
//! `low ≤ high` connection band, and a memory mark), a connection count and an
//! RSS figure drawn from generators **anchored at those thresholds** (so the
//! boundaries `conns == low`, `conns == high`, `rss == mem` and the hysteresis
//! gap are hit densely rather than by chance), plus an arbitrary previous
//! [`LoadState`] and [`RequestClass`]. It then asserts the transition matches
//! an independent oracle and the four requirement-level sub-properties:
//!
//! * **Enter at/above a high-water mark (Req 44.1):** from `Normal`, the guard
//!   flips to `Degraded` *iff* a signal is at/above its high mark.
//! * **Relax with hysteresis (Req 44.4):** from `Degraded`, the guard relaxes
//!   to `Normal` *iff* connections are strictly below the low mark **and** RSS
//!   is below the memory mark.
//! * **No flapping in the gap (Req 44.4):** while a signal sits in the
//!   `low ≤ conns < high` band (RSS sub-mark), the state never changes — the
//!   guard holds whatever it was, so it cannot oscillate.
//! * **Stream/Exempt never shed; only Sheddable while Degraded (Req 44.1,
//!   44.3):** `shed_new_request` is `true` *iff* enabled, the class is
//!   `Sheddable`, and the state sheds traffic.

use proptest::prelude::*;
use zippy_panther::health::LoadState;
use zippy_panther::http::{next_load_state, shed_new_request, LoadThresholds, RequestClass};

/// The two coarse load states the basic guard reports (the full L1–L5 ladder
/// lands in task 29).
fn arb_load_state() -> impl Strategy<Value = LoadState> {
    prop_oneof![Just(LoadState::Normal), Just(LoadState::Degraded)]
}

/// All three request classes, so the admission decision is exercised across the
/// protected stream class, the always-admitted exempt class, and the sheddable
/// class.
fn arb_request_class() -> impl Strategy<Value = RequestClass> {
    prop_oneof![
        Just(RequestClass::Stream),
        Just(RequestClass::Exempt),
        Just(RequestClass::Sheddable),
    ]
}

/// Arbitrary thresholds with a valid `conn_low_water ≤ conn_high_water` band
/// (the real config invariant — the low mark is the strictly-lower hysteresis
/// floor) and a non-zero memory mark. The `enabled` flag is arbitrary so the
/// disabled-guard short-circuit is exercised too.
fn arb_thresholds() -> impl Strategy<Value = LoadThresholds> {
    (any::<bool>(), 1u64..=10_000u64)
        .prop_flat_map(|(enabled, high)| {
            (
                Just(enabled),
                Just(high),
                0u64..=high,           // low ≤ high
                1u64..=(u64::MAX / 4), // memory high-water (bytes)
            )
        })
        .prop_map(
            |(enabled, conn_high_water, conn_low_water, memory_high_water_bytes)| LoadThresholds {
                enabled,
                conn_high_water,
                conn_low_water,
                memory_high_water_bytes,
            },
        )
}

/// A connection count anchored at the thresholds: the exact boundaries around
/// the low and high marks (so `< low`, `== low`, the gap, `== high`, `≥ high`
/// all occur densely) plus a broad uniform spread up to twice the high mark.
fn arb_conns(low: u64, high: u64) -> impl Strategy<Value = u64> {
    let ceiling = high.saturating_mul(2).saturating_add(4);
    prop_oneof![
        Just(low.saturating_sub(1)),
        Just(low),
        Just(low.saturating_add(1)),
        Just(high.saturating_sub(1)),
        Just(high),
        Just(high.saturating_add(1)),
        Just(0u64),
        0u64..=ceiling,
    ]
}

/// An RSS figure anchored at the memory high-water mark, so `< mem`, `== mem`,
/// and `> mem` are all hit densely alongside a broad uniform spread.
fn arb_rss(mem: u64) -> impl Strategy<Value = u64> {
    let ceiling = mem.saturating_mul(2).saturating_add(4);
    prop_oneof![
        Just(mem.saturating_sub(1)),
        Just(mem),
        Just(mem.saturating_add(1)),
        Just(0u64),
        0u64..=ceiling,
    ]
}

/// One fully-generated scenario: thresholds plus connection/RSS signals drawn
/// relative to them, plus a previous state and an inbound request class.
#[derive(Clone, Copy, Debug)]
struct Case {
    thresholds: LoadThresholds,
    conns: u64,
    rss: u64,
    prev: LoadState,
    class: RequestClass,
}

fn arb_case() -> impl Strategy<Value = Case> {
    arb_thresholds()
        .prop_flat_map(|thresholds| {
            (
                Just(thresholds),
                arb_conns(thresholds.conn_low_water, thresholds.conn_high_water),
                arb_rss(thresholds.memory_high_water_bytes),
                arb_load_state(),
                arb_request_class(),
            )
        })
        .prop_map(|(thresholds, conns, rss, prev, class)| Case {
            thresholds,
            conns,
            rss,
            prev,
            class,
        })
}

/// Independent oracle for the hysteresis-aware transition, expressed directly
/// from the Req 44.1 / 44.4 semantics (enter at/above a high mark; relax only
/// strictly below the low connection mark *and* below the memory mark; pinned
/// to `Normal` while disabled). This is the specification the implementation
/// must satisfy — written separately from `next_load_state` so the test is a
/// genuine cross-check, not a tautology.
fn oracle_next(prev: LoadState, conns: u64, rss: u64, t: &LoadThresholds) -> LoadState {
    if !t.enabled {
        return LoadState::Normal;
    }
    let at_or_above_high = conns >= t.conn_high_water || rss >= t.memory_high_water_bytes;
    let strictly_below_low = conns < t.conn_low_water && rss < t.memory_high_water_bytes;
    match prev {
        LoadState::Normal => {
            if at_or_above_high {
                LoadState::Degraded
            } else {
                LoadState::Normal
            }
        }
        LoadState::Degraded => {
            if strictly_below_low {
                LoadState::Normal
            } else {
                LoadState::Degraded
            }
        }
    }
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 46 — degradation guard state transitions.
    /// **Validates: Requirements 44.1, 44.3, 44.4**
    #[test]
    fn degradation_guard_state_transitions(case in arb_case()) {
        let Case { thresholds, conns, rss, prev, class } = case;
        let t = &thresholds;

        let next = next_load_state(prev, conns, rss, t);

        // -- Transition matches the independent oracle ----------------------
        let expected = oracle_next(prev, conns, rss, t);
        prop_assert_eq!(
            next,
            expected,
            "next_load_state({:?}, conns={}, rss={}, {:?}) must equal oracle {:?}",
            prev, conns, rss, thresholds, expected,
        );

        let at_or_above_high =
            conns >= t.conn_high_water || rss >= t.memory_high_water_bytes;
        let strictly_below_low =
            conns < t.conn_low_water && rss < t.memory_high_water_bytes;

        if !t.enabled {
            // -- Disabled guard is pinned to Normal -------------------------
            prop_assert_eq!(
                next,
                LoadState::Normal,
                "a disabled guard must never leave Normal (conns={}, rss={})",
                conns, rss,
            );
        } else {
            match prev {
                LoadState::Normal => {
                    // -- Enter at/above a high-water mark (Req 44.1) --------
                    if at_or_above_high {
                        prop_assert_eq!(
                            next,
                            LoadState::Degraded,
                            "Normal must enter Degraded at/above a high mark \
                             (conns={} vs high={}, rss={} vs mem={})",
                            conns, t.conn_high_water, rss, t.memory_high_water_bytes,
                        );
                    } else {
                        prop_assert_eq!(
                            next,
                            LoadState::Normal,
                            "Normal must stay Normal below both high marks \
                             (conns={} vs high={}, rss={} vs mem={})",
                            conns, t.conn_high_water, rss, t.memory_high_water_bytes,
                        );
                    }
                }
                LoadState::Degraded => {
                    // -- Relax only with full hysteresis (Req 44.4) ---------
                    if strictly_below_low {
                        prop_assert_eq!(
                            next,
                            LoadState::Normal,
                            "Degraded must relax to Normal only strictly below \
                             low AND below mem (conns={} vs low={}, rss={} vs mem={})",
                            conns, t.conn_low_water, rss, t.memory_high_water_bytes,
                        );
                    } else {
                        prop_assert_eq!(
                            next,
                            LoadState::Degraded,
                            "Degraded must hold while conns>=low OR rss>=mem \
                             (conns={} vs low={}, rss={} vs mem={})",
                            conns, t.conn_low_water, rss, t.memory_high_water_bytes,
                        );
                    }
                }
            }

            // -- No flapping in the hysteresis gap (Req 44.4) ---------------
            // While a connection signal sits in [low, high) with RSS below the
            // memory mark, neither edge fires, so the guard MUST hold whatever
            // state it was in — it cannot oscillate on every open/close.
            let in_gap = conns >= t.conn_low_water
                && conns < t.conn_high_water
                && rss < t.memory_high_water_bytes;
            if in_gap {
                prop_assert_eq!(
                    next,
                    prev,
                    "state must not change inside the hysteresis gap \
                     (low={} <= conns={} < high={}, rss={} < mem={})",
                    t.conn_low_water, conns, t.conn_high_water,
                    rss, t.memory_high_water_bytes,
                );
            }

            // -- Reversibility (Req 44.4) -----------------------------------
            // Pushing connections to/over the high mark from Normal degrades;
            // from that Degraded state, dropping strictly below the low mark
            // (and RSS below the memory mark) restores Normal — a complete,
            // reversible round-trip with no terminal stuck state.
            let degraded = next_load_state(
                LoadState::Normal, t.conn_high_water, 0, t,
            );
            prop_assert_eq!(
                degraded,
                LoadState::Degraded,
                "Normal must degrade when conns reach the high mark (high={})",
                t.conn_high_water,
            );
            let recovered = next_load_state(
                degraded, t.conn_low_water.saturating_sub(1), 0, t,
            );
            // Only guaranteed Normal when a strictly-lower floor exists (low>0)
            // and the memory mark is non-zero (it always is here).
            if t.conn_low_water > 0 {
                prop_assert_eq!(
                    recovered,
                    LoadState::Normal,
                    "Degraded must recover below the low mark (low={})",
                    t.conn_low_water,
                );
            }
        }

        // -- Admission decision: Stream/Exempt never shed (Req 44.3);
        //    only Sheddable sheds while the state sheds traffic (Req 44.1) ---
        let shed = shed_new_request(next, class, t.enabled);
        let expected_shed =
            t.enabled && class == RequestClass::Sheddable && next.sheds_traffic();
        prop_assert_eq!(
            shed,
            expected_shed,
            "shed_new_request({:?}, {:?}, enabled={}) must equal \
             (enabled AND Sheddable AND sheds_traffic) = {}",
            next, class, t.enabled, expected_shed,
        );

        // The protected classes are categorically never shed, in any state.
        if matches!(class, RequestClass::Stream | RequestClass::Exempt) {
            prop_assert!(
                !shed,
                "{:?} requests must NEVER be shed (state={:?})",
                class, next,
            );
        }
    }
}
