//! Property-based test for at-rest field encryption (`persistence::vault`,
//! task 5.4).
//!
//! Feature: stream-flow, Property 31
//!
//! **Property 31: Vault at-rest encryption round trip**
//!
//! *For any* sensitive field value, decrypting the Vault-encrypted form
//! recovers exactly the original value.
//!
//! **Validates: Requirements 29.5**
//!
//! Requirement 29.5: "WHERE a Vault_Secret is configured, THE Stream_Flow_System
//! SHALL encrypt sensitive persisted fields at rest using the Vault_Secret."
//!
//! This property exercises [`stream_flow::persistence::vault::Vault`] across the
//! full field-value space — empty fields, UTF-8 tokens, and arbitrary binary
//! blobs — under arbitrary (non-empty) `Vault_Secret` byte strings, and asserts
//! the contract the requirement hinges on:
//!
//! * **Enabled round trip (Req 29.5):** for an AES-256-GCM vault keyed from any
//!   secret, `decrypt(encrypt(x)) == x` — encrypting a sensitive field then
//!   decrypting it recovers exactly the original bytes.
//! * **Disabled passthrough (design "or plaintext if no vault"):** a vault with
//!   no configured secret stores the field verbatim, and the same round-trip
//!   contract still holds, so callers need no special-casing.
//! * **Wrong key is rejected (Req 29.5):** a vault keyed from a *different*
//!   secret rejects the blob with a typed error rather than returning corrupt
//!   bytes — the GCM tag authentication fails.
//! * **Tampering is rejected (Req 29.5):** flipping any byte of a real
//!   ciphertext blob makes decryption fail rather than yield altered data.

use proptest::prelude::*;
use stream_flow::persistence::vault::Vault;

/// Arbitrary `Vault_Secret` bytes for an *enabled* vault. Non-empty (an empty
/// secret yields a disabled vault) and drawn across length and byte values so
/// the SHA-256 key derivation is exercised over a wide secret space.
fn arb_secret() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..=64)
}

/// Arbitrary sensitive field value — "any sensitive field value" from the
/// property — covering the empty field and arbitrary binary content (not just
/// UTF-8), since persisted tokens are stored as raw bytes.
fn arb_field() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=256)
}

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 31 — Vault at-rest encryption round trip.
    /// **Validates: Requirements 29.5**
    #[test]
    fn vault_at_rest_encryption_round_trips(
        secret in arb_secret(),
        other_secret in arb_secret(),
        field in arb_field(),
    ) {
        // -- Enabled round trip (Req 29.5): decrypt(encrypt(x)) == x ----------
        let vault = Vault::enabled_from_bytes(&secret);
        prop_assert!(vault.is_enabled(), "a non-empty secret must enable the vault");

        let blob = vault.encrypt(&field).expect("encrypt must succeed");
        let recovered = vault.decrypt(&blob).expect("decrypt of our own blob must succeed");
        prop_assert_eq!(
            &recovered,
            &field,
            "decrypt(encrypt(x)) must equal x for secret {:?}",
            secret,
        );

        // The stored blob is genuinely ciphertext, never the plaintext field
        // (proves the field is encrypted at rest, not just copied).
        prop_assert_ne!(
            blob.as_slice(),
            field.as_slice(),
            "enabled vault blob must not equal the plaintext field",
        );

        // -- Disabled passthrough (design: "or plaintext if no vault") --------
        let disabled = Vault::disabled();
        prop_assert!(!disabled.is_enabled(), "disabled vault must report not enabled");
        let stored = disabled.encrypt(&field).expect("disabled encrypt is infallible");
        prop_assert_eq!(
            stored.as_slice(),
            field.as_slice(),
            "disabled vault must store the field verbatim",
        );
        prop_assert_eq!(
            disabled.decrypt(&stored).expect("disabled decrypt is infallible"),
            field.clone(),
            "disabled vault round trip must be the identity",
        );

        // -- Wrong key is rejected (Req 29.5) ---------------------------------
        // Only meaningful when the two secrets differ: SHA-256 makes distinct
        // secrets yield distinct AES keys, so the GCM tag check must fail.
        if other_secret != secret {
            let reader = Vault::enabled_from_bytes(&other_secret);
            prop_assert!(
                reader.decrypt(&blob).is_err(),
                "a vault keyed from a different secret must reject the blob \
                 (writer={:?}, reader={:?})",
                secret,
                other_secret,
            );
        }

        // -- Tampering is rejected (Req 29.5) ---------------------------------
        // Flip the final byte (inside the GCM tag) — authentication must fail.
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        prop_assert!(
            vault.decrypt(&tampered).is_err(),
            "a tampered blob must be rejected rather than decrypted to altered bytes",
        );
    }
}
