//! Property-based test for bulkhead isolation between dependencies (task 6.9).
//!
//! Feature: stream-flow, Property 59
//!
//! **Property 59: Bulkhead isolation between dependencies**
//!
//! *For any* interleaving of acquire/release operations across multiple
//! per-dependency bulkhead pools, each pool's live permit count never exceeds
//! that pool's configured maximum, and saturating one dependency's pool never
//! prevents acquiring a permit from a different, unsaturated dependency's pool
//! (one slow or failing upstream cannot starve another). This extends
//! Property 6's per-counter bound with the cross-dependency isolation
//! guarantee.
//!
//! **Validates: Requirements 35.3, 20.3, 50.9**
//!
//! The component under test is
//! [`stream_flow::resilience::bulkhead::Bulkhead`] (task 6.4) — one bounded
//! [`tokio::sync::Semaphore`]-backed concurrency pool per upstream dependency.
//! The pools are deterministic and `acquire` is non-blocking (it fails fast
//! with an [`AppError`] when saturated rather than parking the caller), so the
//! property drives the real pools on a current-thread Tokio runtime without
//! any mocking, fake clock, or real wall-clock waiting.
//!
//! Each generated case builds several independent pools — one per distinct
//! [`BulkheadKey`], cycling through every dependency category (store / host /
//! integration / acestream / telegram) so the cross-dependency claim is
//! exercised for real — with arbitrary (possibly zero) sizes, then replays an
//! arbitrary interleaving of acquire/release operations. Held permits are kept
//! in per-pool vectors and dropped per the generated release ops (RAII). After
//! **every** step the following invariants are asserted across **all** pools:
//!
//! * **Bounded concurrency (Req 35.3 / 20.3):** for every pool,
//!   `in_flight() <= max_permits()`, and `in_flight()` equals the number of
//!   live permits we are holding (so `available_permits() == max - in_flight`).
//!   An acquire on a saturated pool fails fast (it never pushes the live count
//!   past the bound); an acquire on a non-saturated pool succeeds.
//! * **Cross-dependency isolation (Req 50.9):** a *probe* acquire on every
//!   non-saturated pool succeeds regardless of how many *other* pools are fully
//!   saturated at that instant — saturating one dependency never starves a
//!   different, unsaturated one. The probe permit is dropped immediately so it
//!   does not perturb the model.

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use stream_flow::resilience::bulkhead::{Bulkhead, BulkheadKey};
use tokio::sync::OwnedSemaphorePermit;

/// An interleaving of acquire/release operations over a set of pools.
#[derive(Clone, Debug)]
struct Scenario {
    /// Per-pool configured maximum permits (length == number of pools).
    sizes: Vec<usize>,
    /// Operation stream: `(pool_index, is_acquire)`. `true` = acquire,
    /// `false` = release one held permit (a no-op when none are held).
    ops: Vec<(usize, bool)>,
}

/// Generate a scenario: 2..=5 pools with arbitrary (including zero) sizes and
/// an arbitrary interleaving of acquire/release ops referencing those pools.
/// Small sizes plus many acquires make full saturation common, which is
/// exactly what the isolation guarantee is about.
fn arb_scenario() -> impl Strategy<Value = Scenario> {
    (2usize..=5).prop_flat_map(|num_pools| {
        let sizes = proptest::collection::vec(0usize..=4, num_pools);
        // `0..num_pools` is itself a `Strategy<Value = usize>`.
        let ops = proptest::collection::vec((0..num_pools, any::<bool>()), 0..80);
        (sizes, ops).prop_map(|(sizes, ops)| Scenario { sizes, ops })
    })
}

/// Build one independent pool per size, cycling through every dependency
/// category so the property spans *cross-dependency* isolation, not just
/// multiple pools of one kind. Each `Bulkhead::new` is its own pool regardless
/// of the key, so the keys are simply distinct dependency labels.
fn build_pools(sizes: &[usize]) -> Vec<Bulkhead> {
    sizes
        .iter()
        .enumerate()
        .map(|(i, &max)| {
            let key = match i % 5 {
                0 => BulkheadKey::Store(format!("store-{i}")),
                1 => BulkheadKey::Host(format!("host-{i}")),
                2 => BulkheadKey::Integration(format!("integration-{i}")),
                3 => BulkheadKey::Acestream,
                _ => BulkheadKey::Telegram,
            };
            Bulkhead::new(key, max)
        })
        .collect()
}

/// Assert the per-pool bound invariant holds for every pool given the permits
/// we are currently holding: `in_flight == held.len()`, `in_flight <= max`,
/// and `available == max - in_flight` (Req 35.3 / 20.3).
fn assert_bounds(
    pools: &[Bulkhead],
    held: &[Vec<OwnedSemaphorePermit>],
) -> Result<(), TestCaseError> {
    for (pool, held_permits) in pools.iter().zip(held.iter()) {
        let in_flight = pool.in_flight();
        prop_assert!(
            in_flight <= pool.max_permits(),
            "in_flight {} exceeded max_permits {} for {}",
            in_flight,
            pool.max_permits(),
            pool.key(),
        );
        prop_assert_eq!(
            in_flight,
            held_permits.len(),
            "in_flight must equal the number of live permits held for {}",
            pool.key(),
        );
        prop_assert_eq!(
            pool.available_permits(),
            pool.max_permits() - in_flight,
            "available must equal max - in_flight for {}",
            pool.key(),
        );
    }
    Ok(())
}

/// The cross-dependency isolation check (Req 50.9): for every *non-saturated*
/// pool, a probe acquire must succeed at this instant — no matter how many
/// *other* pools are fully saturated. The probe permit is dropped immediately
/// so it leaves the model untouched. `acquire` is non-blocking, so an
/// unsaturated pool resolves to a permit without ever parking on a saturated
/// neighbour.
async fn assert_isolation(pools: &[Bulkhead]) -> Result<(), TestCaseError> {
    for pool in pools {
        if pool.in_flight() < pool.max_permits() {
            let before = pool.in_flight();
            let probe = pool.acquire().await;
            prop_assert!(
                probe.is_ok(),
                "a non-saturated pool ({}) must admit a permit regardless of \
                 other saturated pools",
                pool.key(),
            );
            drop(probe); // release the probe permit (RAII)
            prop_assert_eq!(
                pool.in_flight(),
                before,
                "dropping the probe permit must restore the live count for {}",
                pool.key(),
            );
        }
    }
    Ok(())
}

/// Build a per-case current-thread runtime.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime must build")
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 59 — bulkhead isolation between
    /// dependencies. **Validates: Requirements 35.3, 20.3, 50.9**
    #[test]
    fn bulkhead_isolation_between_dependencies(scenario in arb_scenario()) {
        let rt = runtime();
        let result: Result<(), TestCaseError> = rt.block_on(async {
            let pools = build_pools(&scenario.sizes);
            // Per-pool stacks of live permits we are holding (RAII).
            let mut held: Vec<Vec<OwnedSemaphorePermit>> =
                pools.iter().map(|_| Vec::new()).collect();

            // Initial state: nothing acquired, every bound respected, every
            // pool (with capacity) isolated and admitting.
            assert_bounds(&pools, &held)?;
            assert_isolation(&pools).await?;

            for (idx, is_acquire) in scenario.ops.iter().copied() {
                let pool = &pools[idx];
                if is_acquire {
                    let saturated = pool.in_flight() >= pool.max_permits();
                    let outcome = pool.acquire().await;
                    if saturated {
                        // A full pool must fail fast — never pushing the live
                        // count past the configured bound (Req 35.3).
                        prop_assert!(
                            outcome.is_err(),
                            "saturated pool ({}) must fail fast on acquire",
                            pool.key(),
                        );
                    } else {
                        let permit = outcome.map_err(|e| {
                            TestCaseError::fail(format!(
                                "non-saturated pool ({}) must admit a permit, got {e:?}",
                                pool.key(),
                            ))
                        })?;
                        held[idx].push(permit);
                    }
                } else {
                    // Release one held permit (RAII drop). A no-op when the
                    // pool currently holds none.
                    held[idx].pop();
                }

                // Invariants re-checked after EVERY step.
                assert_bounds(&pools, &held)?;
                assert_isolation(&pools).await?;
            }

            // Draining every held permit returns each pool to fully available,
            // confirming RAII release across the whole interleaving.
            for stack in held.iter_mut() {
                stack.clear();
            }
            for pool in &pools {
                prop_assert_eq!(
                    pool.in_flight(),
                    0,
                    "all permits must release on drop for {}",
                    pool.key(),
                );
                prop_assert_eq!(pool.available_permits(), pool.max_permits());
            }

            Ok(())
        });
        result?;
    }
}
