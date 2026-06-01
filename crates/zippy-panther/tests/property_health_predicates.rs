//! Property-based test for the health-probe predicates (task 7.6).
//!
//! Feature: ZippyPanther, Property 57
//!
//! **Property 57: Readiness predicate correctness and liveness independence**
//!
//! *For any* component-health vector (migrations-applied, config-valid,
//! SQLite-reachable, load state `Normal`/`Degraded`, and the set of per-store
//! breaker states), the readiness signal is `ready` **if and only if**
//! migrations are applied, config is valid, SQLite is reachable, the load
//! state is not degraded-to-not-ready, and not all configured stores' breakers
//! are `Open`; and the liveness signal is **independent** of load state and the
//! readiness inputs (it is `alive` whenever the runtime heartbeat is fresh,
//! including while the instance is `not-ready`). Startup is complete iff
//! migrations are applied and the one-time startup probes have finished.
//!
//! **Validates: Requirements 50.10, 44.6, 29.2**
//!
//! The component under test is the pure, plain-data
//! [`zippy_panther::health::HealthInputs`] snapshot and its predicate methods
//! `readiness_ready`, `liveness_alive`, and `startup_complete` (design:
//! Resilience → Pattern 6 "Health Model & Probes"). Because the predicates are
//! pure functions over a fully-gathered snapshot, the property drives them
//! directly with no runtime, clock, or mocking.
//!
//! ## How the invariants are exercised
//!
//! Each case generates an arbitrary [`HealthInputs`] — every boolean signal,
//! an arbitrary [`LoadState`], and a small vector (including the empty set) of
//! per-store breakers whose states span `Closed`/`Open`/`HalfOpen`. The case
//! then asserts:
//!
//! * **Readiness iff (Req 50.10):** `readiness_ready()` equals the
//!   independently-recomputed conjunction (migrations ∧ config ∧ SQLite ∧
//!   ¬load-sheds ∧ ¬all-stores-open), so the predicate is exactly the
//!   specified five-way AND — no looser, no stricter.
//! * **`all_stores_open` semantics (Req 50.3):** true exactly when the store
//!   set is non-empty and every breaker is `Open` (vacuously false for a
//!   store-less deployment, which is therefore never marked not-ready on this
//!   account).
//! * **Liveness independence (Req 50.10):** `liveness_alive()` equals
//!   `liveness_fresh` regardless of every other field; flipping load,
//!   readiness inputs, or store breakers while holding the heartbeat constant
//!   never changes liveness — so a merely-busy / not-ready instance is never
//!   killed.
//! * **Startup iff (Req 29.2):** `startup_complete()` equals
//!   `migrations_applied ∧ startup_probes_done`.

use proptest::prelude::*;
use zippy_panther::health::{HealthInputs, LoadState, StoreBreaker};
use zippy_panther::resilience::breaker::BreakerState;

/// All three breaker states, so the generated store sets span the whole state
/// space (and combinations like "all Open" vs "some Open" arise naturally).
fn arb_breaker_state() -> impl Strategy<Value = BreakerState> {
    prop_oneof![
        Just(BreakerState::Closed),
        Just(BreakerState::Open),
        Just(BreakerState::HalfOpen),
    ]
}

/// The two coarse load states (the full L1–L5 ladder lands later; here the
/// guard reports `Normal | Degraded`).
fn arb_load_state() -> impl Strategy<Value = LoadState> {
    prop_oneof![Just(LoadState::Normal), Just(LoadState::Degraded)]
}

/// A single store breaker; names are drawn from a small pool so multiple
/// configured stores are realistic. The name does not affect the predicates.
fn arb_store_breaker() -> impl Strategy<Value = StoreBreaker> {
    (
        prop_oneof![
            Just("realdebrid"),
            Just("alldebrid"),
            Just("premiumize"),
            Just("torbox"),
        ],
        arb_breaker_state(),
    )
        .prop_map(|(name, state)| StoreBreaker::new(name, state))
}

/// 0..=5 store breakers — including the empty set, which must make
/// `all_stores_open` vacuously false (a store-less deployment stays ready).
fn arb_stores() -> impl Strategy<Value = Vec<StoreBreaker>> {
    proptest::collection::vec(arb_store_breaker(), 0..=5)
}

/// An arbitrary, fully-gathered health snapshot. `extra` is left empty: it only
/// feeds the human/dashboard breakdown and never affects the three predicates
/// under test (per the design's decoupling note).
fn arb_health_inputs() -> impl Strategy<Value = HealthInputs> {
    (
        any::<bool>(),    // migrations_applied
        any::<bool>(),    // config_valid
        any::<bool>(),    // sqlite_reachable
        any::<bool>(),    // startup_probes_done
        any::<bool>(),    // liveness_fresh
        arb_load_state(), // load
        arb_stores(),     // stores
    )
        .prop_map(
            |(
                migrations_applied,
                config_valid,
                sqlite_reachable,
                startup_probes_done,
                liveness_fresh,
                load,
                stores,
            )| HealthInputs {
                migrations_applied,
                config_valid,
                sqlite_reachable,
                startup_probes_done,
                liveness_fresh,
                load,
                stores,
                extra: vec![],
            },
        )
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 57 — readiness predicate correctness and
    /// liveness independence. **Validates: Requirements 50.10, 44.6, 29.2**
    #[test]
    fn readiness_predicate_correct_and_liveness_independent(
        inputs in arb_health_inputs(),
    ) {
        // -- `all_stores_open` semantics (Req 50.3) --------------------------
        // True exactly when the store set is non-empty AND every breaker is
        // Open; vacuously false for a store-less deployment.
        let expected_all_open = !inputs.stores.is_empty()
            && inputs.stores.iter().all(|s| s.state == BreakerState::Open);
        prop_assert_eq!(
            inputs.all_stores_open(),
            expected_all_open,
            "all_stores_open must be (non-empty AND every breaker Open) for {:?}",
            inputs.stores,
        );

        // -- Readiness iff the specified five-way conjunction (Req 50.10) ----
        let load_sheds = matches!(inputs.load, LoadState::Degraded);
        let expected_ready = inputs.migrations_applied
            && inputs.config_valid
            && inputs.sqlite_reachable
            && !load_sheds
            && !expected_all_open;
        prop_assert_eq!(
            inputs.readiness_ready(),
            expected_ready,
            "readiness_ready must equal (migrations AND config AND sqlite AND \
             !load_sheds AND !all_stores_open) for {:?}",
            inputs,
        );

        // -- Liveness independence (Req 50.10) -------------------------------
        // Liveness depends ONLY on heartbeat freshness, never on load,
        // readiness inputs, or store breakers.
        prop_assert_eq!(
            inputs.liveness_alive(),
            inputs.liveness_fresh,
            "liveness_alive must equal liveness_fresh regardless of other fields",
        );

        // Holding the heartbeat constant, mutating every readiness/load input
        // must leave liveness unchanged — the independence is total, not just
        // for this one snapshot.
        let mut flipped = inputs.clone();
        flipped.migrations_applied = !inputs.migrations_applied;
        flipped.config_valid = !inputs.config_valid;
        flipped.sqlite_reachable = !inputs.sqlite_reachable;
        flipped.startup_probes_done = !inputs.startup_probes_done;
        flipped.load = match inputs.load {
            LoadState::Normal => LoadState::Degraded,
            LoadState::Degraded => LoadState::Normal,
        };
        flipped.stores = inputs
            .stores
            .iter()
            .map(|s| StoreBreaker::new(s.name.clone(), BreakerState::Open))
            .collect();
        // liveness_fresh deliberately unchanged.
        prop_assert_eq!(
            flipped.liveness_alive(),
            inputs.liveness_alive(),
            "flipping load/readiness inputs must not change liveness (heartbeat held)",
        );

        // -- Startup iff migrations applied AND probes done (Req 29.2) -------
        let expected_startup = inputs.migrations_applied && inputs.startup_probes_done;
        prop_assert_eq!(
            inputs.startup_complete(),
            expected_startup,
            "startup_complete must equal (migrations_applied AND startup_probes_done)",
        );
    }
}
