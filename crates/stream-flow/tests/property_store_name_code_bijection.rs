//! Property-based test for the `StoreName` ↔ `StoreCode` bijection
//! (task 22.4).
//!
//! Feature: stream-flow, Property 19
//!
//! **Property 19: Store name/code bijection**
//!
//! *For any* `StoreName`, `name.code().name() == name` and for any
//! `StoreCode`, `code.name().code() == code`. The bijection is total over all
//! 9 stores.
//!
//! **Validates: Requirements 16.3, 16.6**
//!
//! Requirement 16.3: "WHEN GetName is called on a Store, THE
//! Orchestration_Layer SHALL return the store's name and the store's two-letter
//! Store_Code."
//!
//! Requirement 16.6: "WHEN a Store_Code is supplied, THE Orchestration_Layer
//! SHALL resolve it to its store name; WHEN a store name is supplied, THE
//! Orchestration_Layer SHALL resolve it to its Store_Code."
//!
//! ## How the invariant is exercised
//!
//! We generate arbitrary `StoreName` and `StoreCode` values (uniformly drawn
//! from the 9 variants) and assert the round-trip identity in both directions.
//! Additionally, we verify totality: every `StoreName` maps to a distinct
//! `StoreCode` and vice versa, and the `ALL` arrays cover exactly 9 entries.

use proptest::prelude::*;
use stream_flow::store::{StoreCode, StoreName};

/// Strategy that produces an arbitrary `StoreName` (uniform over all 9).
fn arb_store_name() -> impl Strategy<Value = StoreName> {
    (0..9usize).prop_map(|i| StoreName::ALL[i])
}

/// Strategy that produces an arbitrary `StoreCode` (uniform over all 9).
fn arb_store_code() -> impl Strategy<Value = StoreCode> {
    (0..9usize).prop_map(|i| StoreCode::ALL[i])
}

proptest! {
    // >= 100 iterations as required by the spec.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 19 — name → code → name is the identity.
    /// **Validates: Requirements 16.3, 16.6**
    #[test]
    fn name_to_code_to_name_is_identity(name in arb_store_name()) {
        let code = name.code();
        let back = code.name();
        prop_assert_eq!(
            back, name,
            "name.code().name() must equal name for {:?} (code={:?})",
            name, code,
        );
    }

    /// Feature: stream-flow, Property 19 — code → name → code is the identity.
    /// **Validates: Requirements 16.3, 16.6**
    #[test]
    fn code_to_name_to_code_is_identity(code in arb_store_code()) {
        let name = code.name();
        let back = name.code();
        prop_assert_eq!(
            back, code,
            "code.name().code() must equal code for {:?} (name={:?})",
            code, name,
        );
    }

    /// Feature: stream-flow, Property 19 — the bijection is total: every name
    /// maps to a code and every code maps to a name (no panics, no partial
    /// functions). **Validates: Requirements 16.3, 16.6**
    #[test]
    fn bijection_is_total_no_panics(name in arb_store_name(), code in arb_store_code()) {
        // These calls must not panic for any variant.
        let _ = name.code();
        let _ = code.name();
        let _ = name.as_str();
        let _ = code.as_str();
        // StoreName::from_code is the same as code.name()
        let from_code = StoreName::from_code(code);
        prop_assert_eq!(from_code, code.name());
    }
}

/// Exhaustive (non-property) check that the bijection covers exactly 9
/// distinct pairs and that `ALL` arrays are consistent.
#[test]
fn bijection_covers_all_nine_stores_exhaustively() {
    assert_eq!(StoreName::ALL.len(), 9);
    assert_eq!(StoreCode::ALL.len(), 9);

    // Every name maps to a unique code.
    let codes: Vec<StoreCode> = StoreName::ALL.iter().map(|n| n.code()).collect();
    let mut code_strs: Vec<&str> = codes.iter().map(|c| c.as_str()).collect();
    code_strs.sort();
    code_strs.dedup();
    assert_eq!(code_strs.len(), 9, "codes must be distinct");

    // Every code maps to a unique name.
    let names: Vec<StoreName> = StoreCode::ALL.iter().map(|c| c.name()).collect();
    let mut name_strs: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
    name_strs.sort();
    name_strs.dedup();
    assert_eq!(name_strs.len(), 9, "names must be distinct");

    // The ALL arrays are parallel (same order).
    for (i, (name, code)) in StoreName::ALL.iter().zip(StoreCode::ALL.iter()).enumerate() {
        assert_eq!(
            name.code(),
            *code,
            "StoreName::ALL[{i}].code() != StoreCode::ALL[{i}]"
        );
        assert_eq!(
            code.name(),
            *name,
            "StoreCode::ALL[{i}].name() != StoreName::ALL[{i}]"
        );
    }
}
