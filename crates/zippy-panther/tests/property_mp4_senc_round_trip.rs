//! Property-based test for the MP4 sample-encryption box parser
//! (`drm::mp4_atom`) and the ClearKey key store (`drm::clearkey`), task 16.10.
//!
//! Feature: ZippyPanther, Property 14
//!
//! **Property 14: MP4 sample-encryption box parse round trip**
//!
//! *For any* generated CENC metadata — per-sample IVs of size 8 or 16 (and the
//! constant-IV / IV-size-0 case), arbitrary subsample clear/protected maps, an
//! arbitrary 16-byte KID, an arbitrary crypt/skip pattern, and an arbitrary
//! constant IV — encoding that metadata into `tenc`/`senc`/`saiz`/`saio` box
//! bytes and parsing them back recovers **exactly** the original values:
//! `build -> parse` is the identity on the metadata. *For any* configured set
//! of `(KID, key)` pairs, the ClearKey store resolves each configured KID to
//! its key and fails with a KID-naming error for an unconfigured KID.
//!
//! **Validates: Requirements 4.6, 4.9**
//!
//! Requirement 4.9: "WHEN parsing an MP4 sample-encryption box
//! (`senc`/`saiz`/`saio`), THE Streaming_Proxy_Engine SHALL extract per-sample
//! initialization vectors and subsample ranges required for decryption."
//!
//! Requirement 4.6: "WHEN a key identifier is encountered, THE
//! Streaming_Proxy_Engine SHALL resolve the key by matching its key identifier
//! against the configured ClearKey key set."
//!
//! ## How the invariant is exercised
//!
//! The in-module box-building helpers in `drm::mp4_atom` are private to that
//! crate's `#[cfg(test)]` module, so this integration test **replicates the
//! simple ISO-BMFF wire-format builders** (`box_bytes`, `tenc_payload`,
//! `senc_payload`, `saiz_payload`, `saio_payload`) here. Each case:
//!
//! 1. draws coherent CENC metadata (the track's per-sample IV size is shared
//!    between the `tenc` defaults and the `senc` per-sample IV lengths, exactly
//!    as a real fragment links them),
//! 2. constructs the *expected* typed values
//!    ([`TrackEncryption`], [`SampleEncryptionInfo`], [`SampleAuxInfoSizes`],
//!    [`SampleAuxInfoOffsets`]),
//! 3. builds the four boxes, frames them in their real container hierarchy
//!    (`tenc` under `moov/trak/.../stsd/encv/sinf/schi`, and `senc`/`saiz`/`saio`
//!    under `moof/traf`), locates each box with [`find_box`] (exercising the
//!    recursive container walk too), and parses the located payload,
//! 4. asserts the parsed value equals the expected value — i.e. the round trip
//!    is the identity.
//!
//! A separate case exercises the ClearKey store: every configured KID resolves
//! to its key, and an unconfigured KID yields a `not-found` error whose message
//! names the KID in hex (Req 4.6 / 4.8).

use std::collections::HashMap;
use std::time::Duration;

use proptest::prelude::*;

use zippy_panther::drm::clearkey::ClearKeyStore;
use zippy_panther::drm::mp4_atom::{
    find_box, parse_saio, parse_saiz, parse_senc, parse_tenc, SampleAuxInfoOffsets,
    SampleAuxInfoSizes, SampleEncryptionInfo, SubsampleRange, TrackEncryption,
};
use zippy_panther::errors::ErrorCategory;

// ---------------------------------------------------------------------------
// Wire-format builders (replicas of the private `#[cfg(test)]` helpers in
// `drm::mp4_atom`, since those are not visible to an integration test).
// ---------------------------------------------------------------------------

/// CENC `UseSubSampleEncryption` flag on a `senc` box.
const SENC_FLAG_USE_SUBSAMPLES: u32 = 0x0000_0002;
/// `aux-info-type-present` flag shared by `saiz`/`saio`.
const SAI_FLAG_AUX_INFO_TYPE_PRESENT: u32 = 0x0000_0001;

/// Visual sample-entry fixed header length (`VisualSampleEntry`).
const VISUAL_SAMPLE_ENTRY_HEADER: usize = 78;

/// Frame `payload` as a complete box: `size(4) || type(4) || payload`.
fn box_bytes(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let size = (8 + payload.len()) as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(box_type);
    out.extend_from_slice(payload);
    out
}

/// Build a `tenc` payload at version 1 (so the crypt/skip pattern byte is
/// honored by the parser).
fn tenc_payload(
    version: u8,
    crypt: u8,
    skip: u8,
    is_protected: u8,
    iv_size: u8,
    kid: [u8; 16],
    constant_iv: Option<&[u8]>,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(version);
    p.extend_from_slice(&[0, 0, 0]); // flags
    p.push(0); // reserved
    p.push((crypt << 4) | (skip & 0x0F)); // packed pattern byte
    p.push(is_protected);
    p.push(iv_size);
    p.extend_from_slice(&kid);
    if let Some(civ) = constant_iv {
        p.push(civ.len() as u8);
        p.extend_from_slice(civ);
    }
    p
}

type SampleSpec = (Vec<u8>, Vec<(u16, u32)>);

/// Build a `senc` payload from per-sample `(iv, subsamples)` tuples.
fn senc_payload(use_subsamples: bool, samples: &[SampleSpec]) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0); // version
    let flags: u32 = if use_subsamples {
        SENC_FLAG_USE_SUBSAMPLES
    } else {
        0
    };
    p.extend_from_slice(&flags.to_be_bytes()[1..]); // 3-byte flags
    p.extend_from_slice(&(samples.len() as u32).to_be_bytes());
    for (iv, subs) in samples {
        p.extend_from_slice(iv);
        if use_subsamples {
            p.extend_from_slice(&(subs.len() as u16).to_be_bytes());
            for (clear, protected) in subs {
                p.extend_from_slice(&clear.to_be_bytes());
                p.extend_from_slice(&protected.to_be_bytes());
            }
        }
    }
    p
}

/// Build a `saiz` payload. When `default_size == 0`, `per_sample_sizes` is
/// written and its length is the sample count; otherwise the default-size short
/// form is used with the given `sample_count`.
fn saiz_payload(
    aux_info_type_present: bool,
    default_size: u8,
    sample_count: u32,
    per_sample_sizes: &[u8],
) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0); // version
    let flags: u32 = if aux_info_type_present {
        SAI_FLAG_AUX_INFO_TYPE_PRESENT
    } else {
        0
    };
    p.extend_from_slice(&flags.to_be_bytes()[1..]); // 3-byte flags
    if aux_info_type_present {
        p.extend_from_slice(b"cenc"); // aux_info_type
        p.extend_from_slice(&0u32.to_be_bytes()); // aux_info_type_parameter
    }
    p.push(default_size);
    p.extend_from_slice(&sample_count.to_be_bytes());
    if default_size == 0 {
        p.extend_from_slice(per_sample_sizes);
    }
    p
}

/// Build a `saio` payload. `version == 0` writes 32-bit offsets, `version >= 1`
/// writes 64-bit offsets.
fn saio_payload(version: u8, aux_info_type_present: bool, offsets: &[u64]) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(version);
    let flags: u32 = if aux_info_type_present {
        SAI_FLAG_AUX_INFO_TYPE_PRESENT
    } else {
        0
    };
    p.extend_from_slice(&flags.to_be_bytes()[1..]); // 3-byte flags
    if aux_info_type_present {
        p.extend_from_slice(b"cenc");
        p.extend_from_slice(&0u32.to_be_bytes());
    }
    p.extend_from_slice(&(offsets.len() as u32).to_be_bytes());
    for off in offsets {
        if version == 0 {
            p.extend_from_slice(&(*off as u32).to_be_bytes());
        } else {
            p.extend_from_slice(&off.to_be_bytes());
        }
    }
    p
}

/// Frame a `tenc` box in its real container hierarchy
/// (`moov/trak/mdia/minf/stbl/stsd/encv/sinf/schi/tenc`), so [`find_box`]'s
/// recursive walk through the `stsd` header and the visual sample entry is
/// exercised.
fn wrap_tenc_in_moov(tenc_box: &[u8]) -> Vec<u8> {
    let schi = box_bytes(b"schi", tenc_box);
    let sinf = box_bytes(b"sinf", &schi);

    let mut encv_payload = vec![0u8; VISUAL_SAMPLE_ENTRY_HEADER];
    encv_payload.extend_from_slice(&sinf);
    let encv = box_bytes(b"encv", &encv_payload);

    let mut stsd_payload = vec![0u8, 0, 0, 0]; // version + flags
    stsd_payload.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsd_payload.extend_from_slice(&encv);
    let stsd = box_bytes(b"stsd", &stsd_payload);

    let stbl = box_bytes(b"stbl", &stsd);
    let minf = box_bytes(b"minf", &stbl);
    let mdia = box_bytes(b"mdia", &minf);
    let trak = box_bytes(b"trak", &mdia);
    box_bytes(b"moov", &trak)
}

/// Frame the fragment boxes in `moof/traf`.
fn wrap_in_moof(child_boxes: &[u8]) -> Vec<u8> {
    let traf = box_bytes(b"traf", child_boxes);
    box_bytes(b"moof", &traf)
}

/// Lowercase hex encoding of `bytes` (the `hex` crate is a regular dependency,
/// not a dev-dependency, so it is not visible to this integration test). This
/// matches `hex::encode`, which the unresolved-KID error message uses.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// An arbitrary 16-byte value (used for both KIDs and AES keys).
fn arb_array16() -> impl Strategy<Value = [u8; 16]> {
    proptest::collection::vec(any::<u8>(), 16usize).prop_map(|v| {
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        a
    })
}

/// One raw sample seed: a 16-byte IV buffer (truncated to the track IV size in
/// the body) and up to four candidate subsample `(clear, protected)` ranges.
fn arb_raw_sample() -> impl Strategy<Value = (Vec<u8>, Vec<(u16, u32)>)> {
    (
        proptest::collection::vec(any::<u8>(), 16usize),
        proptest::collection::vec((any::<u16>(), any::<u32>()), 0..=4),
    )
}

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 14 — MP4 sample-encryption box parse
    /// round trip. **Validates: Requirements 4.9**
    #[test]
    fn mp4_sample_encryption_boxes_round_trip(
        // -- tenc / fragment-shared track defaults --
        is_protected in any::<bool>(),
        crypt in 0u8..=15,
        skip in 0u8..=15,
        iv_size_sel in 0usize..=2,            // index into [0, 8, 16]
        kid in arb_array16(),
        constant_iv_is_16 in any::<bool>(),   // 8- or 16-byte constant IV
        constant_iv_buf in proptest::collection::vec(any::<u8>(), 16usize),
        // -- senc --
        use_subsamples in any::<bool>(),
        raw_samples in proptest::collection::vec(arb_raw_sample(), 0..=8),
        // -- saiz --
        saiz_aux_present in any::<bool>(),
        saiz_default in any::<u8>(),
        saiz_sizes in proptest::collection::vec(any::<u8>(), 0..=32),
        // -- saio --
        saio_version in prop_oneof![Just(0u8), Just(1u8)],
        saio_aux_present in any::<bool>(),
        saio_offsets_raw in proptest::collection::vec(any::<u64>(), 0..=16),
    ) {
        let iv_size = [0usize, 8, 16][iv_size_sel];

        // === tenc: build expected metadata, encode, locate, parse ===========
        // A constant IV is present only when the track is protected with a
        // per-sample IV size of 0 (the cbcs constant-IV case).
        let constant_iv: Option<Vec<u8>> = if is_protected && iv_size == 0 {
            let len = if constant_iv_is_16 { 16 } else { 8 };
            Some(constant_iv_buf[..len].to_vec())
        } else {
            None
        };

        let tenc_expected = TrackEncryption {
            is_protected,
            per_sample_iv_size: iv_size as u8,
            kid,
            crypt_byte_block: crypt,
            skip_byte_block: skip,
            constant_iv: constant_iv.clone(),
        };

        let tenc_box = box_bytes(
            b"tenc",
            &tenc_payload(
                1,
                crypt,
                skip,
                is_protected as u8,
                iv_size as u8,
                kid,
                constant_iv.as_deref(),
            ),
        );
        let moov = wrap_tenc_in_moov(&tenc_box);
        let located_tenc = find_box(&moov, b"tenc")
            .expect("tenc box walk must not error")
            .expect("tenc must be found in the moov hierarchy");
        let tenc_parsed = parse_tenc(&located_tenc.payload).expect("tenc must parse");
        prop_assert_eq!(
            &tenc_parsed,
            &tenc_expected,
            "tenc build->parse must be the identity",
        );

        // === senc: build expected per-sample info, encode, locate, parse ====
        let samples_expected: Vec<SampleEncryptionInfo> = raw_samples
            .iter()
            .map(|(iv_buf, subs)| {
                let iv = iv_buf[..iv_size].to_vec();
                let subsamples = if use_subsamples {
                    subs.iter()
                        .map(|(c, p)| SubsampleRange {
                            clear_bytes: *c,
                            protected_bytes: *p,
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                SampleEncryptionInfo { iv, subsamples }
            })
            .collect();

        let builder_samples: Vec<SampleSpec> = raw_samples
            .iter()
            .map(|(iv_buf, subs)| (iv_buf[..iv_size].to_vec(), subs.clone()))
            .collect();
        let senc_box = box_bytes(b"senc", &senc_payload(use_subsamples, &builder_samples));

        // === saiz: choose default-size form vs per-sample-sizes form ========
        let (saiz_default_size, saiz_count, saiz_sizes_vec) = if saiz_default == 0 {
            // per-sample sizes: sample_count is the length of the sizes list.
            (0u8, saiz_sizes.len() as u32, saiz_sizes.clone())
        } else {
            // default-size short form: no per-sample sizes are stored.
            (saiz_default, saiz_sizes.len() as u32, Vec::new())
        };
        let saiz_expected = SampleAuxInfoSizes {
            default_sample_info_size: saiz_default_size,
            sample_count: saiz_count,
            sample_info_sizes: saiz_sizes_vec.clone(),
        };
        let saiz_box = box_bytes(
            b"saiz",
            &saiz_payload(saiz_aux_present, saiz_default_size, saiz_count, &saiz_sizes_vec),
        );

        // === saio: mask offsets to the width the version can encode =========
        let saio_offsets: Vec<u64> = if saio_version == 0 {
            saio_offsets_raw.iter().map(|o| (*o as u32) as u64).collect()
        } else {
            saio_offsets_raw.clone()
        };
        let saio_expected = SampleAuxInfoOffsets {
            offsets: saio_offsets.clone(),
        };
        let saio_box = box_bytes(
            b"saio",
            &saio_payload(saio_version, saio_aux_present, &saio_offsets),
        );

        // Frame senc/saiz/saio together in one moof/traf and locate each.
        let mut traf_children = Vec::new();
        traf_children.extend_from_slice(&senc_box);
        traf_children.extend_from_slice(&saiz_box);
        traf_children.extend_from_slice(&saio_box);
        let moof = wrap_in_moof(&traf_children);

        let located_senc = find_box(&moof, b"senc")
            .expect("senc box walk must not error")
            .expect("senc must be found in moof/traf");
        let samples_parsed = parse_senc(&located_senc.payload, iv_size)
            .expect("senc must parse");
        prop_assert_eq!(
            &samples_parsed,
            &samples_expected,
            "senc build->parse must be the identity (iv_size={}, subsamples={})",
            iv_size,
            use_subsamples,
        );

        let located_saiz = find_box(&moof, b"saiz")
            .expect("saiz box walk must not error")
            .expect("saiz must be found in moof/traf");
        let saiz_parsed = parse_saiz(&located_saiz.payload).expect("saiz must parse");
        prop_assert_eq!(
            &saiz_parsed,
            &saiz_expected,
            "saiz build->parse must be the identity",
        );

        let located_saio = find_box(&moof, b"saio")
            .expect("saio box walk must not error")
            .expect("saio must be found in moof/traf");
        let saio_parsed = parse_saio(&located_saio.payload).expect("saio must parse");
        prop_assert_eq!(
            &saio_parsed,
            &saio_expected,
            "saio build->parse must be the identity (version={})",
            saio_version,
        );
    }

    /// Feature: ZippyPanther, Property 14 — ClearKey key resolution by KID.
    /// **Validates: Requirements 4.6**
    #[test]
    fn clearkey_store_resolves_configured_kids_and_names_unconfigured(
        pairs in proptest::collection::vec((arb_array16(), arb_array16()), 0..=8),
        probe_kid in arb_array16(),
    ) {
        // Build the configured key set with last-write-wins on duplicate KIDs,
        // exactly mirroring how the store is constructed.
        let mut map: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
        for (kid, key) in &pairs {
            map.insert(*kid, *key);
        }
        let store = ClearKeyStore::new(map.clone(), Duration::from_secs(3600));

        // -- Every configured KID resolves to its key (Req 4.6) --------------
        for (kid, expected_key) in &map {
            let resolved = store
                .resolve(kid)
                .expect("a configured KID must resolve to its key");
            prop_assert_eq!(
                resolved,
                *expected_key,
                "configured KID {} must resolve to its configured key",
                hex_encode(kid),
            );
        }

        // -- The probe KID: resolves if configured, else KID-naming error ----
        match map.get(&probe_kid) {
            Some(expected_key) => {
                let resolved = store
                    .resolve(&probe_kid)
                    .expect("a configured probe KID must resolve");
                prop_assert_eq!(resolved, *expected_key);
            }
            None => {
                let err = store
                    .resolve(&probe_kid)
                    .expect_err("an unconfigured KID must not resolve (Req 4.6)");
                prop_assert_eq!(
                    err.category,
                    ErrorCategory::NotFound,
                    "unconfigured KID must yield a not-found error",
                );
                prop_assert!(
                    err.message.contains(&hex_encode(&probe_kid)),
                    "the error must name the unresolved KID in hex: {}",
                    err.message,
                );
            }
        }
    }
}
