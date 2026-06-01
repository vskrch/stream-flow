//! Property-based test for store error mapping totality and taxonomy
//! membership (`store::error::map_store_error`, task 22.5).
//!
//! Feature: ZippyPanther, Property 20
//!
//! **Property 20: Store error mapping is total and within the taxonomy**
//!
//! *For any* native store error sample (numeric or string code, HTTP status, or
//! transport failure), the mapper returns exactly one `ErrorCategory` from the
//! canonical taxonomy without panicking, and the resulting `AppError` identifies
//! the originating store.
//!
//! **Validates: Requirements 16.8, 16.9, 16.10**
//!
//! ## How the invariant is exercised
//!
//! Each case generates an arbitrary `(StoreName, HTTP status 0..=999, arbitrary
//! body string)` triple and calls `map_store_error`. The test asserts:
//!
//! * **Totality (Req 16.10):** the call completes without panicking for every
//!   input combination — no `unwrap`, no index-out-of-bounds, no UTF-8 split.
//! * **Within the taxonomy (Req 16.10, 47.1):** the returned `AppError`'s
//!   `category` is one of the defined `ErrorCategory` variants.
//! * **Store identification (Req 16.8, 16.9):** the returned `AppError`'s
//!   `store` field is `Some(store.as_str())` — the error always identifies the
//!   originating store.

use proptest::prelude::*;
use zippy_panther::errors::ErrorCategory;
use zippy_panther::store::{map_store_error, StoreName};

/// Strategy producing any of the nine `StoreName` variants uniformly.
fn arb_store_name() -> impl Strategy<Value = StoreName> {
    prop_oneof![
        Just(StoreName::AllDebrid),
        Just(StoreName::Debrider),
        Just(StoreName::DebridLink),
        Just(StoreName::EasyDebrid),
        Just(StoreName::Offcloud),
        Just(StoreName::PikPak),
        Just(StoreName::Premiumize),
        Just(StoreName::RealDebrid),
        Just(StoreName::TorBox),
    ]
}

/// Strategy producing HTTP status codes in the full 0..=999 range (covering
/// valid statuses, edge cases like 0, and values beyond the standard range).
fn arb_status() -> impl Strategy<Value = u16> {
    0u16..=999u16
}

/// Strategy producing arbitrary body strings — including empty, ASCII, unicode
/// with multi-byte characters, and strings that look like JSON with error codes
/// to exercise the per-store parsers.
fn arb_body() -> impl Strategy<Value = String> {
    prop_oneof![
        // Empty body
        Just(String::new()),
        // Plain ASCII text
        "[a-zA-Z0-9 _\\-\\.]{0,100}",
        // JSON-like bodies that exercise RealDebrid numeric error_code parsing
        Just(r#"{"error":"bad_token","error_code":8}"#.to_string()),
        Just(r#"{"error":"something","error_code":999}"#.to_string()),
        Just(r#"{"error":"ip_not_allowed","error_code":9}"#.to_string()),
        // JSON-like bodies that exercise AllDebrid string code parsing
        Just(
            r#"{"status":"error","error":{"code":"AUTH_BAD_APIKEY","message":"bad"}}"#.to_string()
        ),
        Just(r#"{"status":"error","error":{"code":"UNKNOWN_CODE","message":"?"}}"#.to_string()),
        // Bodies with keywords that trigger specific mappings
        Just("download limit reached".to_string()),
        Just("IP not allowed".to_string()),
        Just("DMCA takedown notice".to_string()),
        Just("fair usage limit".to_string()),
        Just("infringing content".to_string()),
        // Arbitrary unicode (multi-byte chars that could cause panics on naive
        // truncation/slicing)
        "\\PC{0,80}",
    ]
}

/// The exhaustive set of valid `ErrorCategory` variants. Used to assert the
/// returned category is within the taxonomy.
const ALL_CATEGORIES: &[ErrorCategory] = &[
    ErrorCategory::InvalidStoreName,
    ErrorCategory::Unauthorized,
    ErrorCategory::Forbidden,
    ErrorCategory::PaymentRequired,
    ErrorCategory::NotFound,
    ErrorCategory::StoreLimitExceeded,
    ErrorCategory::InfringingContent,
    ErrorCategory::HosterUnavailable,
    ErrorCategory::TooManyRequests,
    ErrorCategory::UpstreamUnavailable,
    ErrorCategory::BadRequest,
    ErrorCategory::PayloadTooLarge,
    ErrorCategory::RangeNotSatisfiable,
    ErrorCategory::Unknown,
];

proptest! {
    // >= 100 iterations as required by the spec; use 256 for good coverage.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 20 — store error mapping is total and
    /// within the taxonomy. **Validates: Requirements 16.8, 16.9, 16.10**
    #[test]
    fn store_error_mapping_is_total_and_within_taxonomy(
        store in arb_store_name(),
        status in arb_status(),
        body in arb_body(),
    ) {
        // -- Totality (Req 16.10): the call must not panic for any input ----
        let err = map_store_error(store, status, &body);

        // -- Within the taxonomy (Req 16.10, 47.1): the category is one of
        //    the defined ErrorCategory variants. ----------------------------
        prop_assert!(
            ALL_CATEGORIES.contains(&err.category),
            "map_store_error({:?}, {}, {:?}) returned category {:?} which is \
             not in the canonical taxonomy",
            store, status, body, err.category,
        );

        // -- Store identification (Req 16.8, 16.9): the error always
        //    identifies the originating store. ------------------------------
        prop_assert_eq!(
            err.store.as_deref(),
            Some(store.as_str()),
            "map_store_error({:?}, {}, {:?}) must identify the store in the \
             AppError.store field, got {:?}",
            store, status, body, err.store,
        );
    }
}
