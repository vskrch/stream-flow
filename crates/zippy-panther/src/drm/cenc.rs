//! Per-scheme ClearKey sample decryption (`drm::cenc`) — Req 4.1–4.5.
//!
//! This module is the crypto half of the DRM pipeline: it consumes the typed
//! metadata produced by [`mp4_atom`](super::mp4_atom) (per-sample IVs +
//! subsample clear/protected ranges, and the track-level crypt/skip pattern
//! and constant IV) and a 16-byte AES-128 ClearKey resolved by
//! [`clearkey`](super::clearkey), and decrypts one MP4 sample under the
//! requested Common-Encryption scheme (design: Components → DRM):
//!
//! | Scheme | Cipher                | Coverage                                   | Req |
//! |--------|-----------------------|--------------------------------------------|-----|
//! | `cenc` | AES-128-CTR           | every protected subsample byte             | 4.2 |
//! | `cens` | AES-128-CTR **pattern** | crypt N / skip M 16-byte blocks, repeating | 4.3 |
//! | `cbc1` | AES-128-CBC           | every complete protected block             | 4.4 |
//! | `cbcs` | AES-128-CBC **pattern** | crypt N / skip M 16-byte blocks, repeating | 4.5 |
//!
//! Bytes that are **not** covered are left byte-for-byte unchanged: the clear
//! leading bytes of every subsample, any bytes outside the protected
//! subsamples, the *skipped* blocks of the `cens`/`cbcs` patterns, and the
//! trailing *partial* block (`< 16` bytes) at the end of a protected range that
//! the CENC pattern rules leave in the clear. Note that trailing **whole**
//! 16-byte blocks are always processed by the pattern even when the final crypt
//! run is shorter than `crypt_byte_block` — only the sub-block remainder is
//! ever left clear (ISO/IEC 23001-7 §10.4.2).
//!
//! ## The `cens` correctness note (design: Components → DRM, "cens bug note")
//!
//! The original mediaflow source decrypted `cens` as **plain** AES-CTR over
//! the whole protected range — it ignored the crypt/skip pattern entirely.
//! That corrupts every byte that the pattern leaves in the clear (the skipped
//! blocks), so `stream-flow` instead applies the crypt/skip pattern exactly:
//! it encrypts `crypt_byte_block` 16-byte blocks, skips `skip_byte_block`
//! blocks, and repeats, never feeding the skipped blocks through the cipher
//! (so the CTR counter does not advance over them) — matching the behaviour of
//! the ISO/IEC 23001-7 reference decoders.
//!
//! ### Counter / chaining state across subsamples
//!
//! * **CTR** (`cenc`/`cens`): a **single** cipher instance spans the whole
//!   sample. Its keystream position (block counter + intra-block offset)
//!   carries across every protected run; clear and skipped bytes are never
//!   fed through it, so the counter advances only over encrypted bytes.
//! * **`cbc1`**: a **single** CBC chain spans the whole sample — each
//!   protected run continues from the previous run's last ciphertext block.
//! * **`cbcs`**: the CBC chain is **reset to the sample IV at the start of
//!   every subsample** (per the reference decoders); within a subsample the
//!   chain continues across crypt runs (skipped blocks are not chained).
//!
//! The module is pure (no I/O) and never panics: malformed subsample geometry
//! (a clear+protected span that overruns the sample) maps onto the canonical
//! [`AppError`] as a descriptive `bad-request` error, consistent with the MP4
//! box parser's error style.

use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecryptMut, KeyIvInit, StreamCipher};

use super::mp4_atom::{SampleEncryptionInfo, TrackEncryption};
use crate::errors::AppError;

/// The AES block size (and CENC pattern block unit), in bytes.
const BLOCK: usize = 16;

/// AES-128 in big-endian 128-bit counter mode (`cenc`/`cens`).
type Aes128Ctr = ctr::Ctr128BE<Aes128>;
/// AES-128 in CBC decryption mode (`cbc1`/`cbcs`).
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// The four Common-Encryption protection schemes this module decrypts
/// (ISO/IEC 23001-7). Selected from the `schm` box's `scheme_type` fourcc and
/// dispatched by [`decrypt_sample`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CencScheme {
    /// `cenc`: AES-128-CTR over every protected subsample byte (Req 4.2).
    Cenc,
    /// `cens`: AES-128-CTR crypt/skip **pattern** (Req 4.3).
    Cens,
    /// `cbc1`: AES-128-CBC over every complete protected block (Req 4.4).
    Cbc1,
    /// `cbcs`: AES-128-CBC crypt/skip **pattern** (Req 4.5).
    Cbcs,
}

impl CencScheme {
    /// Map a 4-byte CENC `scheme_type` (from a `schm` box) to its scheme, or
    /// `None` when the fourcc is not one of the four supported schemes.
    pub fn from_fourcc(fourcc: &[u8]) -> Option<Self> {
        match fourcc {
            b"cenc" => Some(Self::Cenc),
            b"cens" => Some(Self::Cens),
            b"cbc1" => Some(Self::Cbc1),
            b"cbcs" => Some(Self::Cbcs),
            _ => None,
        }
    }

    /// `true` for the two pattern schemes (`cens`/`cbcs`), which honor the
    /// track's `crypt_byte_block`/`skip_byte_block` counts.
    pub fn is_pattern(self) -> bool {
        matches!(self, Self::Cens | Self::Cbcs)
    }
}

/// Decrypt one MP4 sample under `scheme` with the 16-byte AES-128 `key`
/// (Req 4.1–4.5).
///
/// `track` supplies the crypt/skip pattern and the constant IV; `info` supplies
/// the per-sample IV and subsample clear/protected ranges. The returned buffer
/// is the same length as `sample`, with the protected bytes decrypted and every
/// other byte (clear, out-of-subsample, skipped, trailing partial) copied
/// through unchanged.
///
/// Returns a descriptive `bad-request` [`AppError`] when a subsample's
/// clear+protected span overruns the sample (malformed geometry).
pub fn decrypt_sample(
    scheme: CencScheme,
    key: &[u8; 16],
    track: &TrackEncryption,
    info: &SampleEncryptionInfo,
    sample: &[u8],
) -> Result<Vec<u8>, AppError> {
    let iv = resolve_iv(track, info);
    match scheme {
        CencScheme::Cenc => decrypt_ctr(key, &iv, track, info, sample, false),
        CencScheme::Cens => decrypt_ctr(key, &iv, track, info, sample, true),
        CencScheme::Cbc1 => decrypt_cbc1(key, &iv, info, sample),
        CencScheme::Cbcs => decrypt_cbcs(key, &iv, track, info, sample),
    }
}

/// Resolve the 16-byte initialization vector / initial counter block for a
/// sample.
///
/// The per-sample IV (from the `senc` box) is preferred; when the track uses a
/// constant IV (`per_sample_iv_size == 0`, so the per-sample IV is empty —
/// typical for `cbcs`) the track's `constant_iv` is used. An 8-byte IV is
/// placed in the **high** 8 bytes with the low 8 bytes (the CTR block counter)
/// zeroed, per ISO/IEC 23001-7; a 16-byte IV is used verbatim.
fn resolve_iv(track: &TrackEncryption, info: &SampleEncryptionInfo) -> [u8; 16] {
    let mut iv = [0u8; 16];
    let src: &[u8] = if !info.iv.is_empty() {
        &info.iv
    } else if let Some(civ) = &track.constant_iv {
        civ
    } else {
        &[]
    };
    let n = src.len().min(BLOCK);
    iv[..n].copy_from_slice(&src[..n]);
    iv
}

// ---------------------------------------------------------------------------
// AES-CTR schemes (cenc / cens)
// ---------------------------------------------------------------------------

/// Decrypt under AES-128-CTR, either over every protected byte (`pattern ==
/// false`, `cenc`) or honoring the crypt/skip block pattern (`pattern ==
/// true`, `cens`).
///
/// A single cipher instance spans the whole sample so the keystream position
/// carries across protected runs; clear and skipped bytes are never fed
/// through it.
fn decrypt_ctr(
    key: &[u8; 16],
    iv: &[u8; 16],
    track: &TrackEncryption,
    info: &SampleEncryptionInfo,
    sample: &[u8],
    pattern: bool,
) -> Result<Vec<u8>, AppError> {
    let mut cipher = Aes128Ctr::new_from_slices(key, iv)
        .map_err(|_| AppError::unknown("clearkey: invalid AES-128 key/IV length for CTR"))?;
    let mut out = sample.to_vec();

    // Whole-sample encryption (no subsample map): the entire sample is the
    // protected payload.
    if info.subsamples.is_empty() {
        cipher.apply_keystream(&mut out);
        return Ok(out);
    }

    let mut pos = 0usize;
    for sub in &info.subsamples {
        let (start, end) = protected_span(&out, pos, sub)?;
        // Clear bytes [pos, start) are left unchanged.
        let protected = &mut out[start..end];
        if pattern {
            ctr_pattern(
                &mut cipher,
                protected,
                track.crypt_byte_block,
                track.skip_byte_block,
            );
        } else {
            cipher.apply_keystream(protected);
        }
        pos = end;
    }
    Ok(out)
}

/// Apply the `cens` crypt/skip pattern over one protected range: decrypt
/// `crypt_blocks` 16-byte blocks, skip `skip_blocks` blocks (not fed through
/// the cipher, so the counter does not advance), repeating over **every** whole
/// 16-byte block of the range.
///
/// Per ISO/IEC 23001-7 §10.4.2 (and the shaka-packager `AesPatternCryptor` /
/// Chromium `DecryptWithPattern` reference decoders), the pattern applies to
/// the whole 16-byte blocks only; a final crypt run that contains **fewer than
/// `crypt_blocks` whole blocks is still decrypted** — only the trailing
/// *partial* (`< 16` byte) block at the very end of the protected range is left
/// in the clear. (An earlier revision wrongly stopped at the first short crypt
/// run, leaving trailing whole blocks undecrypted.)
fn ctr_pattern(cipher: &mut Aes128Ctr, data: &mut [u8], crypt_blocks: u8, skip_blocks: u8) {
    let crypt_bytes = crypt_blocks as usize * BLOCK;
    let skip_bytes = skip_blocks as usize * BLOCK;
    // The pattern covers whole 16-byte blocks only; the trailing partial block
    // (if any) is always left clear.
    let whole = data.len() / BLOCK * BLOCK;

    // No crypt run defined: fall back to continuous CTR over the whole blocks
    // so a degenerate (missing) pattern still decrypts rather than looping
    // forever.
    if crypt_bytes == 0 {
        cipher.apply_keystream(&mut data[..whole]);
        return;
    }

    let mut pos = 0usize;
    while pos < whole {
        // A trailing crypt run shorter than crypt_bytes is still encrypted.
        let c = crypt_bytes.min(whole - pos);
        cipher.apply_keystream(&mut data[pos..pos + c]);
        pos += c;
        // Skipped blocks are not fed through the cipher (counter unchanged).
        pos += skip_bytes.min(whole - pos);
    }
}

// ---------------------------------------------------------------------------
// AES-CBC schemes (cbc1 / cbcs)
// ---------------------------------------------------------------------------

/// Decrypt under AES-128-CBC over complete blocks (`cbc1`): a single CBC chain
/// spans the whole sample, so each protected run continues from the previous
/// run's last ciphertext block. Any trailing partial (`< 16`) byte run is left
/// unchanged.
fn decrypt_cbc1(
    key: &[u8; 16],
    iv: &[u8; 16],
    info: &SampleEncryptionInfo,
    sample: &[u8],
) -> Result<Vec<u8>, AppError> {
    let mut dec = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|_| AppError::unknown("clearkey: invalid AES-128 key/IV length for CBC"))?;
    let mut out = sample.to_vec();

    if info.subsamples.is_empty() {
        cbc_decrypt_blocks(&mut dec, &mut out);
        return Ok(out);
    }

    let mut pos = 0usize;
    for sub in &info.subsamples {
        let (start, end) = protected_span(&out, pos, sub)?;
        cbc_decrypt_blocks(&mut dec, &mut out[start..end]);
        pos = end;
    }
    Ok(out)
}

/// Decrypt under the AES-128-CBC crypt/skip pattern (`cbcs`): the CBC chain is
/// reset to the sample IV at the start of every subsample; within a subsample
/// it decrypts `crypt_byte_block` blocks, skips `skip_byte_block` blocks, and
/// repeats. A trailing run shorter than one full crypt run (and any partial
/// `< 16`-byte block) is left in the clear.
fn decrypt_cbcs(
    key: &[u8; 16],
    iv: &[u8; 16],
    track: &TrackEncryption,
    info: &SampleEncryptionInfo,
    sample: &[u8],
) -> Result<Vec<u8>, AppError> {
    let mut out = sample.to_vec();

    if info.subsamples.is_empty() {
        let mut dec = new_cbc_dec(key, iv)?;
        cbc_decrypt_blocks(&mut dec, &mut out);
        return Ok(out);
    }

    let mut pos = 0usize;
    for sub in &info.subsamples {
        let (start, end) = protected_span(&out, pos, sub)?;
        // The CBC IV resets to the sample IV for each subsample.
        let mut dec = new_cbc_dec(key, iv)?;
        cbc_pattern(
            &mut dec,
            &mut out[start..end],
            track.crypt_byte_block,
            track.skip_byte_block,
        );
        pos = end;
    }
    Ok(out)
}

/// Apply the `cbcs` crypt/skip pattern over one protected range, continuing the
/// CBC chain across crypt runs (skipped blocks are not chained).
fn cbc_pattern(dec: &mut Aes128CbcDec, data: &mut [u8], crypt_blocks: u8, skip_blocks: u8) {
    let crypt_bytes = crypt_blocks as usize * BLOCK;
    let skip_bytes = skip_blocks as usize * BLOCK;

    // No crypt run defined: decrypt every complete block (no skipping).
    if crypt_bytes == 0 {
        cbc_decrypt_blocks(dec, data);
        return;
    }

    let len = data.len();
    let mut pos = 0usize;
    loop {
        if len - pos < crypt_bytes {
            break; // trailing partial run left clear
        }
        cbc_decrypt_blocks(dec, &mut data[pos..pos + crypt_bytes]);
        pos += crypt_bytes;
        let s = skip_bytes.min(len - pos);
        pos += s;
    }
}

/// Build a fresh CBC decryptor from the key and IV, mapping the (length-checked
/// — both are 16 bytes) error to a canonical [`AppError`].
fn new_cbc_dec(key: &[u8; 16], iv: &[u8; 16]) -> Result<Aes128CbcDec, AppError> {
    Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|_| AppError::unknown("clearkey: invalid AES-128 key/IV length for CBC"))
}

/// CBC-decrypt every complete 16-byte block of `data` in place, advancing the
/// decryptor's chaining state; a trailing partial (`< 16`) byte run is left
/// unchanged (CBC operates on whole blocks only).
fn cbc_decrypt_blocks(dec: &mut Aes128CbcDec, data: &mut [u8]) {
    let complete = data.len() / BLOCK * BLOCK;
    for chunk in data[..complete].chunks_exact_mut(BLOCK) {
        dec.decrypt_block_mut(GenericArray::from_mut_slice(chunk));
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Compute the `[start, end)` byte range of a subsample's protected payload
/// within `buf`, starting from `pos` (the byte after the previous subsample).
/// The clear bytes are `[pos, start)`. Errors when the clear+protected span
/// overruns the buffer (malformed geometry).
fn protected_span(
    buf: &[u8],
    pos: usize,
    sub: &super::mp4_atom::SubsampleRange,
) -> Result<(usize, usize), AppError> {
    let clear = sub.clear_bytes as usize;
    let protected = sub.protected_bytes as usize;
    let start = pos
        .checked_add(clear)
        .filter(|&s| s <= buf.len())
        .ok_or_else(subsample_overrun)?;
    let end = start
        .checked_add(protected)
        .filter(|&e| e <= buf.len())
        .ok_or_else(subsample_overrun)?;
    Ok((start, end))
}

/// The descriptive error for a subsample span that exceeds the sample length.
fn subsample_overrun() -> AppError {
    AppError::bad_request("clearkey: subsample clear+protected span overruns the sample")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::BlockEncryptMut;

    type Aes128CbcEnc = cbc::Encryptor<Aes128>;

    // -- Fixtures -----------------------------------------------------------

    /// NIST SP 800-38A AES-128 test key (shared by the CTR and CBC KATs).
    const NIST_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    fn track(crypt: u8, skip: u8, iv_size: u8, constant_iv: Option<Vec<u8>>) -> TrackEncryption {
        TrackEncryption {
            is_protected: true,
            per_sample_iv_size: iv_size,
            kid: [0u8; 16],
            crypt_byte_block: crypt,
            skip_byte_block: skip,
            constant_iv,
        }
    }

    fn sub(clear: u16, protected: u32) -> super::super::mp4_atom::SubsampleRange {
        super::super::mp4_atom::SubsampleRange {
            clear_bytes: clear,
            protected_bytes: protected,
        }
    }

    fn info(
        iv: Vec<u8>,
        subs: Vec<super::super::mp4_atom::SubsampleRange>,
    ) -> SampleEncryptionInfo {
        SampleEncryptionInfo {
            iv,
            subsamples: subs,
        }
    }

    /// Deterministic pseudo-plaintext of `n` bytes (not all-zero, so a missed
    /// decryption is visible).
    fn plaintext(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect()
    }

    // -- Reference encryptors (mirror the scheme rules, used to build inputs) --

    /// CTR encryption is identical to decryption (XOR with the keystream); this
    /// reference mirrors the scheme structure to produce ciphertext for the
    /// round-trip tests.
    fn ctr_encrypt(
        key: &[u8; 16],
        track: &TrackEncryption,
        info: &SampleEncryptionInfo,
        plain: &[u8],
        pattern: bool,
    ) -> Vec<u8> {
        let iv = resolve_iv(track, info);
        let mut cipher = Aes128Ctr::new_from_slices(key, &iv).unwrap();
        let mut out = plain.to_vec();
        if info.subsamples.is_empty() {
            cipher.apply_keystream(&mut out);
            return out;
        }
        let mut pos = 0usize;
        for s in &info.subsamples {
            let start = pos + s.clear_bytes as usize;
            let end = start + s.protected_bytes as usize;
            if pattern {
                ctr_pattern(
                    &mut cipher,
                    &mut out[start..end],
                    track.crypt_byte_block,
                    track.skip_byte_block,
                );
            } else {
                cipher.apply_keystream(&mut out[start..end]);
            }
            pos = end;
        }
        out
    }

    fn cbc_encrypt_blocks(enc: &mut Aes128CbcEnc, data: &mut [u8]) {
        let complete = data.len() / BLOCK * BLOCK;
        for chunk in data[..complete].chunks_exact_mut(BLOCK) {
            enc.encrypt_block_mut(GenericArray::from_mut_slice(chunk));
        }
    }

    /// `cbc1` reference encryptor: one continuous CBC chain over the protected
    /// runs.
    fn cbc1_encrypt(key: &[u8; 16], info: &SampleEncryptionInfo, plain: &[u8]) -> Vec<u8> {
        let iv = resolve_iv(&track(0, 0, 16, None), info);
        let mut enc = Aes128CbcEnc::new_from_slices(key, &iv).unwrap();
        let mut out = plain.to_vec();
        if info.subsamples.is_empty() {
            cbc_encrypt_blocks(&mut enc, &mut out);
            return out;
        }
        let mut pos = 0usize;
        for s in &info.subsamples {
            let start = pos + s.clear_bytes as usize;
            let end = start + s.protected_bytes as usize;
            cbc_encrypt_blocks(&mut enc, &mut out[start..end]);
            pos = end;
        }
        out
    }

    /// `cbcs` reference encryptor: IV resets per subsample, crypt/skip pattern.
    fn cbcs_encrypt(
        key: &[u8; 16],
        track: &TrackEncryption,
        info: &SampleEncryptionInfo,
        plain: &[u8],
    ) -> Vec<u8> {
        let iv = resolve_iv(track, info);
        let mut out = plain.to_vec();
        let crypt_bytes = track.crypt_byte_block as usize * BLOCK;
        let skip_bytes = track.skip_byte_block as usize * BLOCK;
        let mut pos = 0usize;
        for s in &info.subsamples {
            let start = pos + s.clear_bytes as usize;
            let end = start + s.protected_bytes as usize;
            let mut enc = Aes128CbcEnc::new_from_slices(key, &iv).unwrap();
            let data = &mut out[start..end];
            let len = data.len();
            let mut p = 0usize;
            loop {
                if len - p < crypt_bytes {
                    break;
                }
                cbc_encrypt_blocks(&mut enc, &mut data[p..p + crypt_bytes]);
                p += crypt_bytes;
                p += skip_bytes.min(len - p);
            }
            pos = end;
        }
        out
    }

    // -- Known-answer tests anchoring the cipher engines --------------------

    /// NIST SP 800-38A F.5.1 CTR-AES128: decrypting the published ciphertext
    /// block with the published initial counter recovers the plaintext block,
    /// exercised through the public `cenc` path (Req 4.2).
    #[test]
    fn cenc_matches_nist_ctr_known_answer() {
        let counter = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let plain = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let cipher = [
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d,
            0xb6, 0xce,
        ];
        let tk = track(0, 0, 16, None);
        let inf = info(counter.to_vec(), vec![]);
        let got = decrypt_sample(CencScheme::Cenc, &NIST_KEY, &tk, &inf, &cipher).unwrap();
        assert_eq!(got, plain, "cenc must match the NIST CTR-AES128 vector");
    }

    /// NIST SP 800-38A F.2.2 CBC-AES128: decrypting the published ciphertext
    /// block with the published IV recovers the plaintext block, exercised
    /// through the public `cbc1` path (Req 4.4).
    #[test]
    fn cbc1_matches_nist_cbc_known_answer() {
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plain = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let cipher = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d,
        ];
        let tk = track(0, 0, 16, None);
        let inf = info(iv.to_vec(), vec![]);
        let got = decrypt_sample(CencScheme::Cbc1, &NIST_KEY, &tk, &inf, &cipher).unwrap();
        assert_eq!(got, plain, "cbc1 must match the NIST CBC-AES128 vector");
    }

    // -- Round-trip tests (encrypt with reference, decrypt with impl) -------

    #[test]
    fn cenc_round_trips_whole_sample() {
        let tk = track(0, 0, 16, None);
        let inf = info(vec![0x11; 16], vec![]);
        let pt = plaintext(100); // not block-aligned: CTR is a stream cipher
        let ct = ctr_encrypt(&NIST_KEY, &tk, &inf, &pt, false);
        assert_ne!(ct, pt, "ciphertext must differ from plaintext");
        let got = decrypt_sample(CencScheme::Cenc, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn cenc_round_trips_with_subsamples_and_leaves_clear_bytes_unchanged() {
        let tk = track(0, 0, 16, None);
        // Two subsamples: 10 clear + 48 protected, then 6 clear + 32 protected.
        let subs = vec![sub(10, 48), sub(6, 32)];
        let inf = info(vec![0x22; 16], subs);
        let pt = plaintext(10 + 48 + 6 + 32);
        let ct = ctr_encrypt(&NIST_KEY, &tk, &inf, &pt, false);

        // Clear regions are byte-identical in the ciphertext.
        assert_eq!(&ct[0..10], &pt[0..10], "leading clear bytes unchanged");
        assert_eq!(
            &ct[58..64],
            &pt[58..64],
            "inter-subsample clear bytes unchanged"
        );
        // Protected regions are altered.
        assert_ne!(&ct[10..58], &pt[10..58]);

        let got = decrypt_sample(CencScheme::Cenc, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn cens_pattern_round_trips_and_leaves_skip_blocks_unchanged() {
        // Pattern 1:2 — crypt 1 block, skip 2 blocks.
        let tk = track(1, 2, 16, None);
        // One subsample: 4 clear + 9 blocks (144 bytes) protected.
        let subs = vec![sub(4, 9 * 16)];
        let inf = info(vec![0x33; 16], subs);
        let pt = plaintext(4 + 9 * 16);
        let ct = cens_encrypt_helper(&tk, &inf, &pt);

        // Within the protected range (starts at byte 4), the 1:2 pattern means
        // blocks 0,3,6 are encrypted and blocks 1,2,4,5,7,8 are skipped (clear).
        for blk in [1usize, 2, 4, 5, 7, 8] {
            let s = 4 + blk * 16;
            assert_eq!(
                &ct[s..s + 16],
                &pt[s..s + 16],
                "cens skip block {blk} must be left unchanged"
            );
        }
        for blk in [0usize, 3, 6] {
            let s = 4 + blk * 16;
            assert_ne!(
                &ct[s..s + 16],
                &pt[s..s + 16],
                "cens crypt block {blk} must be encrypted"
            );
        }

        let got = decrypt_sample(CencScheme::Cens, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_eq!(got, pt);
    }

    /// The `cens` correctness regression: decrypting `cens` content as **plain**
    /// CTR (the original source's bug) corrupts the skipped blocks, so it must
    /// NOT recover the plaintext — while the correct pattern path does.
    #[test]
    fn cens_is_not_plain_ctr_regression() {
        let tk = track(1, 2, 16, None);
        let subs = vec![sub(0, 9 * 16)];
        let inf = info(vec![0x44; 16], subs);
        let pt = plaintext(9 * 16);
        let ct = cens_encrypt_helper(&tk, &inf, &pt);

        // Correct cens pattern recovers the plaintext.
        let correct = decrypt_sample(CencScheme::Cens, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_eq!(correct, pt);

        // Treating it as plain CTR (cenc) does not — the skipped blocks get
        // XORed with keystream that was never applied during encryption.
        let plain_ctr = decrypt_sample(CencScheme::Cenc, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_ne!(
            plain_ctr, pt,
            "plain CTR must NOT recover cens content (the source bug)"
        );
    }

    #[test]
    fn cens_pattern_round_trips_with_trailing_partial_run() {
        // Pattern 2:1, protected length not a whole number of pattern cycles,
        // with a trailing partial (< 16 byte) tail — all left-clear bytes must
        // survive the round trip.
        let tk = track(2, 1, 8, None); // 8-byte IV exercises the high-bytes layout
        let subs = vec![sub(3, 100)]; // 100 protected bytes = 6 blocks + 4 bytes
        let inf = info(vec![0x55; 8], subs);
        let pt = plaintext(3 + 100);
        let ct = ctr_encrypt(&NIST_KEY, &tk, &inf, &pt, true);
        let got = decrypt_sample(CencScheme::Cens, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn cbc1_round_trips_with_subsamples() {
        let tk = track(0, 0, 16, None);
        // Block-aligned protected ranges (CBC requires whole blocks).
        let subs = vec![sub(5, 32), sub(7, 48)];
        let inf = info(vec![0x66; 16], subs);
        let pt = plaintext(5 + 32 + 7 + 48);
        let ct = cbc1_encrypt(&NIST_KEY, &inf, &pt);

        assert_eq!(&ct[0..5], &pt[0..5], "leading clear bytes unchanged");
        assert_eq!(
            &ct[37..44],
            &pt[37..44],
            "inter-subsample clear bytes unchanged"
        );

        let got = decrypt_sample(CencScheme::Cbc1, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn cbcs_pattern_round_trips_with_constant_iv_and_leaves_skip_and_partial_unchanged() {
        // cbcs commonly uses a constant IV (per_sample_iv_size == 0) and a 1:9
        // pattern. Here use 1:2 over a range with a trailing partial block.
        let constant_iv = vec![0x77; 16];
        let tk = track(1, 2, 0, Some(constant_iv));
        // 2 clear + 100 protected (6 full blocks + 4-byte partial tail).
        let subs = vec![sub(2, 100)];
        let inf = info(vec![], subs); // empty per-sample IV → uses constant_iv
        let pt = plaintext(2 + 100);
        let ct = cbcs_encrypt(&NIST_KEY, &tk, &inf, &pt);

        // Leading clear bytes unchanged.
        assert_eq!(&ct[0..2], &pt[0..2]);
        // 1:2 pattern over 6 whole blocks: crypt block0, skip 1,2, crypt 3,
        // skip 4,5; then 4 bytes remain (< 1 crypt block) -> left clear.
        for blk in [1usize, 2, 4, 5] {
            let s = 2 + blk * 16;
            assert_eq!(
                &ct[s..s + 16],
                &pt[s..s + 16],
                "cbcs skip block {blk} unchanged"
            );
        }
        // Trailing 4-byte partial (bytes 98..102) left clear.
        assert_eq!(
            &ct[98..102],
            &pt[98..102],
            "cbcs trailing partial block left clear"
        );
        for blk in [0usize, 3] {
            let s = 2 + blk * 16;
            assert_ne!(
                &ct[s..s + 16],
                &pt[s..s + 16],
                "cbcs crypt block {blk} encrypted"
            );
        }

        let got = decrypt_sample(CencScheme::Cbcs, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn cbcs_iv_resets_per_subsample() {
        // Two protected subsamples encrypted with a per-subsample IV reset must
        // round-trip; this would fail if the decryptor continued one chain.
        let tk = track(1, 1, 0, Some(vec![0x88; 16]));
        let subs = vec![sub(0, 64), sub(4, 64)];
        let inf = info(vec![], subs);
        let pt = plaintext(64 + 4 + 64);
        let ct = cbcs_encrypt(&NIST_KEY, &tk, &inf, &pt);
        let got = decrypt_sample(CencScheme::Cbcs, &NIST_KEY, &tk, &inf, &ct).unwrap();
        assert_eq!(got, pt);
    }

    // -- IV resolution + dispatch + error handling --------------------------

    #[test]
    fn resolve_iv_places_8_byte_iv_in_high_bytes() {
        let tk = track(0, 0, 8, None);
        let inf = info(vec![1, 2, 3, 4, 5, 6, 7, 8], vec![]);
        let iv = resolve_iv(&tk, &inf);
        assert_eq!(&iv[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&iv[8..16], &[0; 8], "low 8 bytes (counter) are zeroed");
    }

    #[test]
    fn resolve_iv_falls_back_to_constant_iv() {
        let tk = track(1, 9, 0, Some(vec![0xAB; 16]));
        let inf = info(vec![], vec![]); // no per-sample IV
        let iv = resolve_iv(&tk, &inf);
        assert_eq!(iv, [0xAB; 16]);
    }

    #[test]
    fn from_fourcc_maps_the_four_schemes() {
        assert_eq!(CencScheme::from_fourcc(b"cenc"), Some(CencScheme::Cenc));
        assert_eq!(CencScheme::from_fourcc(b"cens"), Some(CencScheme::Cens));
        assert_eq!(CencScheme::from_fourcc(b"cbc1"), Some(CencScheme::Cbc1));
        assert_eq!(CencScheme::from_fourcc(b"cbcs"), Some(CencScheme::Cbcs));
        assert_eq!(CencScheme::from_fourcc(b"abcd"), None);
        assert!(CencScheme::Cens.is_pattern());
        assert!(CencScheme::Cbcs.is_pattern());
        assert!(!CencScheme::Cenc.is_pattern());
        assert!(!CencScheme::Cbc1.is_pattern());
    }

    #[test]
    fn malformed_subsample_geometry_errors() {
        let tk = track(0, 0, 16, None);
        // Protected range claims more bytes than the sample contains.
        let subs = vec![sub(0, 1000)];
        let inf = info(vec![0x01; 16], subs);
        let sample = plaintext(32);
        let err = decrypt_sample(CencScheme::Cenc, &NIST_KEY, &tk, &inf, &sample).unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::BadRequest);
        assert!(
            err.message.contains("subsample"),
            "error names the cause: {}",
            err.message
        );
    }

    /// Helper: `cens` ciphertext (CTR pattern encryption == decryption).
    fn cens_encrypt_helper(
        track: &TrackEncryption,
        info: &SampleEncryptionInfo,
        plain: &[u8],
    ) -> Vec<u8> {
        ctr_encrypt(&NIST_KEY, track, info, plain, true)
    }
}
