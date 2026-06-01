//! Property-based test for store list `limit` clamping (task 24.6, Property 22).
//!
//! Feature: ZippyPanther, Property 22
//!
//! **Property 22: List limit clamping**
//!
//! *For any* integer `limit` input, the effective list limit equals the input
//! when within `[1,500]`, equals `1` when below the range, and equals `500`
//! when above the range; `offset` defaults to `0`.
//!
//! **Validates: Requirements 17.4, 17.9**
//!
//! Requirement 17.4: "WHEN listing magnets, THE Orchestration_Layer SHALL
//! honor a `limit` (default 100) and `offset` (default 0) and return the page
//! plus the genuine total."
//!
//! Requirement 17.9: "WHEN a list `limit` is supplied, THE Orchestration_Layer
//! SHALL clamp it to the inclusive range `[1,500]`."
//!
//! ## How the invariant is exercised
//!
//! The implementation under test is
//! [`zippy_panther::store::ListMagnetsParams::new`] (and its helper
//! [`ListMagnetsParams::clamp_limit`]), which applies the canonical clamp:
//! a `None` limit becomes `LIMIT_DEFAULT` (100), any supplied value is clamped
//! to the nearest bound in `[LIMIT_MIN, LIMIT_MAX]` = `[1, 500]`, and a `None`
//! offset becomes `0` while a supplied offset passes through unchanged.
//!
//! 1. **Universal bound (Req 17.9):** for any `Option<u32>` limit, the
//!    resulting `params.limit` is always within `[1, 500]`.
//! 2. **Default (Req 17.4):** `None` yields exactly `100`.
//! 3. **Below-range:** any value `<= 1` yields exactly `1`.
//! 4. **Above-range:** any value `>= 500` yields exactly `500`.
//! 5. **Pass-through:** in-range values (`1..=500`) are returned unchanged.
//! 6. **Offset (Req 17.4):** `None` offset defaults to `0`; any supplied
//!    offset passes through unchanged.

use proptest::prelude::*;
use zippy_panther::store::{Ctx, ListMagnetsParams};

const LIMIT_MIN: u32 = ListMagnetsParams::LIMIT_MIN;
const LIMIT_MAX: u32 = ListMagnetsParams::LIMIT_MAX;
const LIMIT_DEFAULT: u32 = ListMagnetsParams::LIMIT_DEFAULT;

/// Strategy that biases toward the interesting regions of the input space:
/// the below-range tail (`0`/`1`), the in-range body, the boundaries, and the
/// above-range tail (including `u32::MAX`), interleaved with fully arbitrary
/// `u32` values so no region of the domain is left unexercised.
fn arb_limit() -> impl Strategy<Value = u32> {
    prop_oneof![
        // Below / at the lower bound.
        Just(0u32),
        Just(1u32),
        // In-range body (pass-through region).
        LIMIT_MIN..=LIMIT_MAX,
        // At / above the upper bound.
        Just(LIMIT_MAX),
        Just(LIMIT_MAX + 1),
        Just(u32::MAX),
        // Fully arbitrary — total coverage of the domain.
        any::<u32>(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Feature: ZippyPanther, Property 22 — clamped limit is always within `[1,500]`.
    /// **Validates: Requirements 17.9**
    ///
    /// For any `Option<u32>` limit (present or absent), the resulting
    /// `params.limit` is always within the inclusive range `[1, 500]`.
    #[test]
    fn clamped_limit_is_always_within_bounds(opt_limit in proptest::option::of(arb_limit())) {
        let params = ListMagnetsParams::new(Ctx::default(), opt_limit, None);
        prop_assert!(
            (LIMIT_MIN..=LIMIT_MAX).contains(&params.limit),
            "limit input {:?} produced clamped limit {} outside [{}, {}]",
            opt_limit,
            params.limit,
            LIMIT_MIN,
            LIMIT_MAX,
        );
    }

    /// Feature: ZippyPanther, Property 22 — absent limit yields the default (100).
    /// **Validates: Requirements 17.4**
    ///
    /// A `None` limit always resolves to `LIMIT_DEFAULT` (100), independent of
    /// the supplied offset.
    #[test]
    fn none_limit_yields_default(opt_offset in proptest::option::of(any::<u32>())) {
        let params = ListMagnetsParams::new(Ctx::default(), None, opt_offset);
        prop_assert_eq!(params.limit, LIMIT_DEFAULT);
        prop_assert_eq!(params.limit, 100);
    }

    /// Feature: ZippyPanther, Property 22 — below-range values clamp up to 1.
    /// **Validates: Requirements 17.9**
    ///
    /// Any supplied value `<= LIMIT_MIN` (i.e. `0` or `1`) yields exactly `1`.
    #[test]
    fn below_range_clamps_to_min(limit in 0u32..=LIMIT_MIN) {
        let params = ListMagnetsParams::new(Ctx::default(), Some(limit), None);
        prop_assert_eq!(
            params.limit,
            LIMIT_MIN,
            "limit {} (<= {}) should clamp to {}",
            limit,
            LIMIT_MIN,
            LIMIT_MIN,
        );
        // The standalone helper agrees with the constructor.
        prop_assert_eq!(ListMagnetsParams::clamp_limit(limit), LIMIT_MIN);
    }

    /// Feature: ZippyPanther, Property 22 — above-range values clamp down to 500.
    /// **Validates: Requirements 17.9**
    ///
    /// Any supplied value `>= LIMIT_MAX` (500 up to `u32::MAX`) yields exactly
    /// `500`.
    #[test]
    fn above_range_clamps_to_max(limit in LIMIT_MAX..=u32::MAX) {
        let params = ListMagnetsParams::new(Ctx::default(), Some(limit), None);
        prop_assert_eq!(
            params.limit,
            LIMIT_MAX,
            "limit {} (>= {}) should clamp to {}",
            limit,
            LIMIT_MAX,
            LIMIT_MAX,
        );
        prop_assert_eq!(ListMagnetsParams::clamp_limit(limit), LIMIT_MAX);
    }

    /// Feature: ZippyPanther, Property 22 — in-range values pass through unchanged.
    /// **Validates: Requirements 17.9**
    ///
    /// Any value strictly within `[1, 500]` is returned exactly as supplied.
    #[test]
    fn in_range_passes_through(limit in LIMIT_MIN..=LIMIT_MAX) {
        let params = ListMagnetsParams::new(Ctx::default(), Some(limit), None);
        prop_assert_eq!(
            params.limit,
            limit,
            "in-range limit {} should pass through unchanged, got {}",
            limit,
            params.limit,
        );
        prop_assert_eq!(ListMagnetsParams::clamp_limit(limit), limit);
    }

    /// Feature: ZippyPanther, Property 22 — offset defaults to 0 and otherwise
    /// passes through.
    /// **Validates: Requirements 17.4**
    ///
    /// A `None` offset resolves to `0`; any supplied offset is returned exactly
    /// as given, independent of the limit clamp.
    #[test]
    fn offset_defaults_to_zero_else_passes_through(
        opt_limit in proptest::option::of(arb_limit()),
        opt_offset in proptest::option::of(any::<u32>()),
    ) {
        let params = ListMagnetsParams::new(Ctx::default(), opt_limit, opt_offset);
        match opt_offset {
            None => prop_assert_eq!(
                params.offset,
                0,
                "None offset should default to 0, got {}",
                params.offset,
            ),
            Some(offset) => prop_assert_eq!(
                params.offset,
                offset,
                "supplied offset {} should pass through unchanged, got {}",
                offset,
                params.offset,
            ),
        }
    }
}
