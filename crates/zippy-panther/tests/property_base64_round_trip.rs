//! Property-based test for the base64 round trip (task 20.3).
//!
//! Feature: stream-flow, Property 7
//!
//! **Property 7: Base64 round trip**
//!
//! *For any* byte input, base64-decoding the base64-encoding of the input
//! recovers exactly the original bytes.
//!
//! **Validates: Requirements 15.3, 15.4, 15.5, 15.6, 48.3**
//!
//! Requirement 15.6: `decode(encode(x)) == x` for every byte input — the
//! base64 utilities backing the mediaflow `/base64/{encode,decode,check}`
//! surface must round-trip losslessly.
//!
//! This exercises the public [`stream_flow::utils::base64`] helpers across the
//! full input space — arbitrary byte vectors, including empty, all-`0x00`, and
//! all-`0xFF` payloads whose standard-base64 encoding uses every character of
//! the alphabet — and asserts:
//!
//! * **Round trip (Req 15.4, 15.6):** `decode(encode(x))` succeeds and equals
//!   the original bytes `x` exactly.
//! * **Validity of encoder output (Req 15.5):** `is_valid` returns `true` for
//!   any string produced by `encode`, i.e. the encoder never emits a string the
//!   checker would reject.
//! * **Encoder shape (Req 15.3):** the encoded length is the canonical
//!   standard-base64 padded length `4 * ceil(n / 3)`, confirming the encoder
//!   emits well-formed standard base64 (a non-empty input yields a non-empty
//!   encoding).

use proptest::prelude::*;
use stream_flow::utils::base64::{decode, encode, is_valid};

/// Canonical padded standard-base64 length for `n` input bytes:
/// `4 * ceil(n / 3)`.
fn expected_encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 7 — base64 round trip.
    /// **Validates: Requirements 15.3, 15.4, 15.5, 15.6, 48.3**
    #[test]
    fn base64_decode_is_left_inverse_of_encode(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        // -- Encode (Req 15.3): canonical standard-base64 padded length.
        let encoded = encode(&input);
        prop_assert_eq!(
            encoded.len(),
            expected_encoded_len(input.len()),
            "encoded length for {}-byte input was {:?}",
            input.len(),
            encoded,
        );

        // -- Validity (Req 15.5): the checker accepts any encoder output.
        prop_assert!(
            is_valid(&encoded),
            "is_valid rejected encoder output {:?}",
            encoded,
        );

        // -- Round trip (Req 15.4, 15.6): decode recovers the exact bytes.
        let decoded = decode(&encoded)
            .expect("decoding the encoder's own output must succeed");
        prop_assert_eq!(
            &decoded,
            &input,
            "decode(encode(x)) != x for input {:?} (encoded {:?})",
            input,
            encoded,
        );
    }
}
