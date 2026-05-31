//! Property-based test for per-scheme ClearKey sample decryption
//! (`drm::cenc::decrypt_sample`), task 16.9.
//!
//! Feature: stream-flow, Property 13
//!
//! **Property 13: CENC decryption round trip honoring crypt/skip patterns**
//!
//! *For any* scheme in `{cenc, cens, cbc1, cbcs}`, any 16-byte key, any
//! per-sample IV, any subsample layout, and any crypt/skip block pattern,
//! decrypting the encrypted sample recovers the original plaintext exactly;
//! bytes outside protected subsample ranges and bytes in "skip" blocks of the
//! pattern schemes (`cens`, `cbcs`) are left unchanged.
//!
//! **Validates: Requirements 4.2, 4.3, 4.4, 4.5**
//!
//! Requirement 4.2: "WHEN decrypting `cenc`-scheme content, THE
//! Streaming_Proxy_Engine SHALL apply AES-CTR decryption using the per-sample
//! initialization vector and subsample byte ranges."
//!
//! Requirement 4.3: "WHEN decrypting `cens`-scheme content, THE
//! Streaming_Proxy_Engine SHALL apply AES-CTR pattern decryption honoring the
//! crypt/skip block pattern."
//!
//! Requirement 4.4: "WHEN decrypting `cbc1`-scheme content, THE
//! Streaming_Proxy_Engine SHALL apply AES-CBC decryption using the per-sample
//! initialization vector and subsample byte ranges."
//!
//! Requirement 4.5: "WHEN decrypting `cbcs`-scheme content, THE
//! Streaming_Proxy_Engine SHALL apply AES-CBC pattern decryption honoring the
//! crypt/skip block pattern."
//!
//! ## How the invariant is exercised
//!
//! The decryptor under test is [`stream_flow::drm::cenc::decrypt_sample`]. To
//! produce valid ciphertext to feed it, this test implements an **independent
//! reference encryptor** for each of the four schemes whose structure mirrors
//! the scheme rules exactly (single CTR/CBC chain spanning the sample for
//! `cenc`/`cens`/`cbc1`, CBC chain reset per subsample for `cbcs`; the
//! `cens`/`cbcs` crypt/skip pattern feeding only the crypt blocks through the
//! cipher). The encryptor also returns a `touched` mask marking every byte it
//! fed through the cipher, so the test can assert that every *other* byte —
//! the clear leading bytes, the bytes outside the protected subsamples, the
//! skipped blocks of the pattern schemes, and the trailing partial block — is
//! left byte-for-byte unchanged.
//!
//! Crucially, the reference encryptor **honors the crypt/skip pattern**: it
//! never feeds the skipped blocks through the cipher. A decryptor that wrongly
//! treated `cens` as plain AES-CTR (the original mediaflow source's bug) would
//! XOR keystream over those never-encrypted skip blocks and so fail to recover
//! the plaintext — meaning the round-trip assertion directly guards the
//! `cens`/`cbcs` pattern correctness, not just the CTR/CBC engines.
//!
//! Each case asserts:
//! 1. the encryptor leaves every non-`touched` byte equal to the plaintext
//!    (the protected/skip distinction is real — clear and skip bytes are not
//!    encrypted);
//! 2. `decrypt_sample(encrypt(plaintext)) == plaintext` exactly (round trip);
//! 3. the decryptor passes every non-`touched` byte through unchanged
//!    (it does not corrupt clear/skip/out-of-subsample bytes).
//!
//! The reference encryptor is intentionally separate from the library
//! implementation (it lives in this integration-test crate, which does not see
//! the library's `#[cfg(test)]` helpers), so the round trip is a genuine
//! cross-check rather than a tautology.

use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncryptMut, KeyIvInit, StreamCipher};
use proptest::prelude::*;

use stream_flow::drm::cenc::{decrypt_sample, CencScheme};
use stream_flow::drm::mp4_atom::{SampleEncryptionInfo, SubsampleRange, TrackEncryption};

/// The AES block size (and CENC pattern block unit), in bytes.
const BLOCK: usize = 16;

/// AES-128 in big-endian 128-bit counter mode (`cenc`/`cens`) — the same
/// concrete type the implementation uses.
type Aes128Ctr = ctr::Ctr128BE<Aes128>;
/// AES-128 in CBC encryption mode (the inverse of the implementation's
/// `cbc::Decryptor<Aes128>`).
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

// ---------------------------------------------------------------------------
// Reference encryptor (mirrors `drm::cenc`'s scheme rules to build inputs).
//
// Each helper produces ciphertext in place AND fills a `touched` mask: `true`
// for every byte fed through the cipher, `false` for every byte the scheme
// leaves in the clear (leading clear bytes, out-of-subsample bytes, skipped
// pattern blocks, and trailing partial < 16-byte blocks).
// ---------------------------------------------------------------------------

/// Resolve the 16-byte IV / initial counter block exactly as the implementation
/// does: prefer the non-empty per-sample IV, else the constant IV; an 8-byte IV
/// occupies the high 8 bytes with the low 8 (counter) zeroed; a 16-byte IV is
/// used verbatim.
fn resolve_iv(per_sample_iv: &[u8], constant_iv: Option<&[u8]>) -> [u8; 16] {
    let mut iv = [0u8; 16];
    let src: &[u8] = if !per_sample_iv.is_empty() {
        per_sample_iv
    } else if let Some(c) = constant_iv {
        c
    } else {
        &[]
    };
    let n = src.len().min(BLOCK);
    iv[..n].copy_from_slice(&src[..n]);
    iv
}

/// Mark `[..whole]` of a touched sub-slice as fed through the cipher.
fn mark(touched: &mut [bool]) {
    for t in touched.iter_mut() {
        *t = true;
    }
}

/// AES-CTR over one protected run, applying the crypt/skip pattern (`cens`):
/// crypt `crypt_blocks` whole 16-byte blocks, skip `skip_blocks` (not fed
/// through the cipher, so the counter does not advance), repeating; a trailing
/// crypt run shorter than a full crypt run is still encrypted, only the final
/// partial (`< 16`) block is left clear. Mirrors `ctr_pattern`.
fn ctr_pattern_enc(
    cipher: &mut Aes128Ctr,
    data: &mut [u8],
    touched: &mut [bool],
    crypt_blocks: u8,
    skip_blocks: u8,
) {
    let crypt_bytes = crypt_blocks as usize * BLOCK;
    let skip_bytes = skip_blocks as usize * BLOCK;
    let whole = data.len() / BLOCK * BLOCK;

    if crypt_bytes == 0 {
        cipher.apply_keystream(&mut data[..whole]);
        mark(&mut touched[..whole]);
        return;
    }

    let mut pos = 0usize;
    while pos < whole {
        let c = crypt_bytes.min(whole - pos);
        cipher.apply_keystream(&mut data[pos..pos + c]);
        mark(&mut touched[pos..pos + c]);
        pos += c;
        pos += skip_bytes.min(whole - pos);
    }
}

/// CTR encryption (identical structure to decryption — XOR with the keystream)
/// for `cenc` (`pattern == false`) and `cens` (`pattern == true`). A single
/// cipher instance spans the whole sample so the keystream position carries
/// across protected runs. Mirrors `decrypt_ctr`.
fn ctr_encrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    info: &SampleEncryptionInfo,
    track: &TrackEncryption,
    out: &mut [u8],
    touched: &mut [bool],
    pattern: bool,
) {
    let mut cipher = Aes128Ctr::new_from_slices(key, iv).expect("valid AES-128 key/IV");

    if info.subsamples.is_empty() {
        cipher.apply_keystream(out);
        mark(touched);
        return;
    }

    let mut pos = 0usize;
    for s in &info.subsamples {
        let start = pos + s.clear_bytes as usize;
        let end = start + s.protected_bytes as usize;
        if pattern {
            ctr_pattern_enc(
                &mut cipher,
                &mut out[start..end],
                &mut touched[start..end],
                track.crypt_byte_block,
                track.skip_byte_block,
            );
        } else {
            cipher.apply_keystream(&mut out[start..end]);
            mark(&mut touched[start..end]);
        }
        pos = end;
    }
}

/// CBC-encrypt every complete 16-byte block of `data` in place, advancing the
/// encryptor's chaining state; a trailing partial (`< 16`) run is left
/// unchanged. The inverse of the implementation's `cbc_decrypt_blocks`.
fn cbc_encrypt_blocks(enc: &mut Aes128CbcEnc, data: &mut [u8], touched: &mut [bool]) {
    let complete = data.len() / BLOCK * BLOCK;
    for chunk in data[..complete].chunks_exact_mut(BLOCK) {
        enc.encrypt_block_mut(GenericArray::from_mut_slice(chunk));
    }
    mark(&mut touched[..complete]);
}

/// `cbc1` reference encryptor: one continuous CBC chain over the protected runs
/// of every subsample (or the whole sample when there is no subsample map).
fn cbc1_encrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    info: &SampleEncryptionInfo,
    out: &mut [u8],
    touched: &mut [bool],
) {
    let mut enc = Aes128CbcEnc::new_from_slices(key, iv).expect("valid AES-128 key/IV");

    if info.subsamples.is_empty() {
        cbc_encrypt_blocks(&mut enc, out, touched);
        return;
    }

    let mut pos = 0usize;
    for s in &info.subsamples {
        let start = pos + s.clear_bytes as usize;
        let end = start + s.protected_bytes as usize;
        cbc_encrypt_blocks(&mut enc, &mut out[start..end], &mut touched[start..end]);
        pos = end;
    }
}

/// `cbcs` crypt/skip pattern over one protected run, continuing the CBC chain
/// across crypt runs (skipped blocks are not chained). A trailing run shorter
/// than one full crypt run is left clear. Mirrors `cbc_pattern`.
fn cbc_pattern_enc(
    enc: &mut Aes128CbcEnc,
    data: &mut [u8],
    touched: &mut [bool],
    crypt_blocks: u8,
    skip_blocks: u8,
) {
    let crypt_bytes = crypt_blocks as usize * BLOCK;
    let skip_bytes = skip_blocks as usize * BLOCK;

    if crypt_bytes == 0 {
        cbc_encrypt_blocks(enc, data, touched);
        return;
    }

    let len = data.len();
    let mut pos = 0usize;
    loop {
        if len - pos < crypt_bytes {
            break; // trailing partial run left clear
        }
        cbc_encrypt_blocks(enc, &mut data[pos..pos + crypt_bytes], &mut touched[pos..pos + crypt_bytes]);
        pos += crypt_bytes;
        let s = skip_bytes.min(len - pos);
        pos += s;
    }
}

/// `cbcs` reference encryptor: the CBC chain resets to the sample IV at the
/// start of every subsample (whole-sample mode falls back to a single chain,
/// matching the implementation's `decrypt_cbcs` empty-subsample path).
fn cbcs_encrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    info: &SampleEncryptionInfo,
    track: &TrackEncryption,
    out: &mut [u8],
    touched: &mut [bool],
) {
    if info.subsamples.is_empty() {
        let mut enc = Aes128CbcEnc::new_from_slices(key, iv).expect("valid AES-128 key/IV");
        cbc_encrypt_blocks(&mut enc, out, touched);
        return;
    }

    let mut pos = 0usize;
    for s in &info.subsamples {
        let start = pos + s.clear_bytes as usize;
        let end = start + s.protected_bytes as usize;
        let mut enc = Aes128CbcEnc::new_from_slices(key, iv).expect("valid AES-128 key/IV");
        cbc_pattern_enc(
            &mut enc,
            &mut out[start..end],
            &mut touched[start..end],
            track.crypt_byte_block,
            track.skip_byte_block,
        );
        pos = end;
    }
}

/// Encrypt `plain` under `scheme`, returning the ciphertext and a `touched`
/// mask (`true` for every byte fed through the cipher).
fn encrypt_sample(
    scheme: CencScheme,
    key: &[u8; 16],
    track: &TrackEncryption,
    info: &SampleEncryptionInfo,
    plain: &[u8],
) -> (Vec<u8>, Vec<bool>) {
    let iv = resolve_iv(&info.iv, track.constant_iv.as_deref());
    let mut out = plain.to_vec();
    let mut touched = vec![false; plain.len()];
    match scheme {
        CencScheme::Cenc => ctr_encrypt(key, &iv, info, track, &mut out, &mut touched, false),
        CencScheme::Cens => ctr_encrypt(key, &iv, info, track, &mut out, &mut touched, true),
        CencScheme::Cbc1 => cbc1_encrypt(key, &iv, info, &mut out, &mut touched),
        CencScheme::Cbcs => cbcs_encrypt(key, &iv, info, track, &mut out, &mut touched),
    }
    (out, touched)
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// A coherent, generated CENC decryption case.
#[derive(Debug, Clone)]
struct Case {
    scheme: CencScheme,
    key: [u8; 16],
    /// The per-sample IV (8 or 16 bytes), empty when a constant IV is used.
    per_sample_iv: Vec<u8>,
    /// The track-level constant IV (the `cbcs` `per_sample_iv_size == 0` case).
    constant_iv: Option<Vec<u8>>,
    iv_size: u8,
    crypt: u8,
    skip: u8,
    /// `(clear_bytes, protected_bytes)` per subsample; empty = whole-sample.
    subsamples: Vec<(u16, u32)>,
    plaintext: Vec<u8>,
}

/// An arbitrary 16-byte value (used for the key and IV material).
fn arb_array16() -> impl Strategy<Value = [u8; 16]> {
    proptest::collection::vec(any::<u8>(), 16usize).prop_map(|v| {
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        a
    })
}

/// Generate a fully-coherent case: the plaintext length is derived from the
/// chosen subsample geometry so the protected spans never overrun the sample.
fn arb_case() -> impl Strategy<Value = Case> {
    (
        // scheme
        prop_oneof![
            Just(CencScheme::Cenc),
            Just(CencScheme::Cens),
            Just(CencScheme::Cbc1),
            Just(CencScheme::Cbcs),
        ],
        arb_array16(),          // key
        0u8..=2,                // iv_kind: 0=per-sample16, 1=per-sample8, 2=constant16
        arb_array16(),          // iv material
        0u8..=8,                // crypt blocks (pattern schemes)
        0u8..=8,                // skip blocks (pattern schemes)
        any::<bool>(),          // whole-sample (no subsample map)
        proptest::collection::vec((0u16..=32, 0u32..=160), 0..=6), // subsamples
        0usize..=24,            // trailing out-of-subsample bytes
        0usize..=80,            // whole-sample length
    )
        .prop_flat_map(
            |(scheme, key, iv_kind, ivb, crypt, skip, whole, subs, tail, whole_len)| {
                let (subsamples, total_len) = if whole {
                    (Vec::new(), whole_len)
                } else {
                    let body: usize =
                        subs.iter().map(|(c, p)| *c as usize + *p as usize).sum();
                    (subs, body + tail)
                };
                let (iv_size, per_sample_iv, constant_iv) = match iv_kind {
                    0 => (16u8, ivb[..16].to_vec(), None),
                    1 => (8u8, ivb[..8].to_vec(), None),
                    _ => (0u8, Vec::new(), Some(ivb[..16].to_vec())),
                };
                proptest::collection::vec(any::<u8>(), total_len).prop_map(move |plaintext| Case {
                    scheme,
                    key,
                    per_sample_iv: per_sample_iv.clone(),
                    constant_iv: constant_iv.clone(),
                    iv_size,
                    crypt,
                    skip,
                    subsamples: subsamples.clone(),
                    plaintext,
                })
            },
        )
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 13 — CENC decryption round trip honoring
    /// crypt/skip patterns. **Validates: Requirements 4.2, 4.3, 4.4, 4.5**
    #[test]
    fn cenc_decryption_round_trip_honors_crypt_skip_patterns(case in arb_case()) {
        let track = TrackEncryption {
            is_protected: true,
            per_sample_iv_size: case.iv_size,
            kid: [0u8; 16],
            crypt_byte_block: case.crypt,
            skip_byte_block: case.skip,
            constant_iv: case.constant_iv.clone(),
        };
        let info = SampleEncryptionInfo {
            iv: case.per_sample_iv.clone(),
            subsamples: case
                .subsamples
                .iter()
                .map(|(c, p)| SubsampleRange { clear_bytes: *c, protected_bytes: *p })
                .collect(),
        };

        // Build ciphertext with the independent reference encryptor.
        let (ct, touched) = encrypt_sample(case.scheme, &case.key, &track, &info, &case.plaintext);
        prop_assert_eq!(ct.len(), case.plaintext.len(), "encryption must preserve length");

        // (1) Bytes the scheme does not encrypt — leading clear bytes, bytes
        // outside the protected subsamples, the skipped blocks of the pattern
        // schemes, and the trailing partial block — must be byte-identical in
        // the ciphertext (Req 4.3/4.5 crypt/skip pattern; out-of-subsample).
        for i in 0..case.plaintext.len() {
            if !touched[i] {
                prop_assert_eq!(
                    ct[i],
                    case.plaintext[i],
                    "scheme {:?}: ciphertext byte {} is not in a crypt block and must equal the plaintext",
                    case.scheme,
                    i,
                );
            }
        }

        // (2) Round trip: decrypting recovers the original plaintext exactly.
        // Because the reference encryptor honors the crypt/skip pattern (it
        // never feeds skipped blocks through the cipher), a decryptor that
        // wrongly applied plain CTR/CBC over the skip blocks would corrupt them
        // and fail this assertion (Req 4.2-4.5).
        let decrypted = decrypt_sample(case.scheme, &case.key, &track, &info, &ct)
            .expect("decrypt_sample must not error on valid subsample geometry");
        prop_assert_eq!(
            &decrypted,
            &case.plaintext,
            "scheme {:?}: decryption must recover the original plaintext",
            case.scheme,
        );

        // (3) The decryptor passes every non-encrypted byte through unchanged
        // (it must not touch clear / skip / out-of-subsample bytes).
        for i in 0..ct.len() {
            if !touched[i] {
                prop_assert_eq!(
                    decrypted[i],
                    ct[i],
                    "scheme {:?}: decrypted byte {} (not in a crypt block) must be passed through unchanged",
                    case.scheme,
                    i,
                );
            }
        }
    }
}
