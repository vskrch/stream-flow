//! MP4 sample-encryption box parser (`drm::mp4_atom`) — Req 4.9.
//!
//! This module is the single, pure place that turns the raw bytes of an
//! ISO-BMFF (MP4) fragment into the typed CENC metadata the ClearKey
//! decryptor (task 16.5, `drm::cenc`) needs: per-sample initialization
//! vectors and subsample clear/protected byte ranges, plus the track-level
//! encryption parameters (KID, IV size, crypt/skip pattern, constant IV).
//!
//! It contains **no** crypto and **no** I/O — it only walks boxes and decodes
//! the four sample-encryption boxes defined by ISO/IEC 23001-7 (Common
//! Encryption) and ISO/IEC 14496-12 (ISO base media file format):
//!
//! | Box    | Container path                                   | Decodes |
//! |--------|--------------------------------------------------|---------|
//! | `tenc` | `moov/trak/mdia/minf/stbl/stsd/<enc*>/sinf/schi` | track defaults: `is_protected`, per-sample IV size, KID, crypt/skip pattern, constant IV |
//! | `senc` | `moof/traf`                                      | per-sample IVs + subsample ranges |
//! | `saiz` | `moof/traf`                                      | per-sample auxiliary-info sizes |
//! | `saio` | `moof/traf`                                      | auxiliary-info offsets into the fragment |
//!
//! The generic box reader ([`Mp4BoxParser`] / [`read_boxes`]) handles 32-bit
//! and 64-bit (`size == 1`) box sizes and the "extends to end" (`size == 0`)
//! form, and the recursive finder ([`find_box`]) navigates the known CENC
//! container hierarchy — including the special `stsd` header and the
//! audio/visual sample-entry fixed fields — so callers can locate a `tenc`
//! inside a `moov` or a `senc` inside a `moof` directly (design: Components →
//! DRM, "walks `moov/trak/.../senc/saiz/saio/tenc/sidx`").
//!
//! Every malformed input maps onto the canonical [`AppError`] taxonomy as a
//! descriptive `bad-request` parse error naming the offending box (design:
//! Error Handling; consistent with the HLS/MPD "unparseable body → descriptive
//! parse error" rule, Req 1.8/2.8), so no parse path panics or hangs.

use crate::errors::AppError;

/// CENC `UseSubSampleEncryption` flag on a `senc` box: when set, each sample
/// carries a subsample map (clear/protected byte split) after its IV.
const SENC_FLAG_USE_SUBSAMPLES: u32 = 0x0000_0002;

/// `aux-info-type-present` flag shared by `saiz`/`saio`: when set, the box
/// carries an `aux_info_type` + `aux_info_type_parameter` pair before its
/// per-sample data.
const SAI_FLAG_AUX_INFO_TYPE_PRESENT: u32 = 0x0000_0001;

/// Maximum box nesting depth the recursive finder will descend, guarding
/// against pathological/malicious deeply-nested input causing unbounded
/// recursion.
const MAX_BOX_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// Generic box model
// ---------------------------------------------------------------------------

/// A single parsed MP4 box: its 4-byte type tag and the payload bytes that
/// follow the box header (after `size` + `type`, and after the 64-bit
/// `largesize` when present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mp4Box {
    /// The 4-byte box type (e.g. `*b"moof"`, `*b"senc"`).
    pub box_type: [u8; 4],
    /// The box payload — everything after the box header.
    pub payload: Vec<u8>,
}

impl Mp4Box {
    /// The box type as a lossy UTF-8 string for diagnostics (`"????"` when the
    /// tag is not valid UTF-8).
    pub fn type_str(&self) -> String {
        std::str::from_utf8(&self.box_type)
            .unwrap_or("????")
            .to_string()
    }
}

/// Forward-only reader over a buffer of concatenated MP4 boxes.
///
/// Yields one [`Mp4Box`] per call to [`next_box`](Mp4BoxParser::next_box),
/// decoding the 32-bit `size`, the 64-bit extended `size == 1` form, and the
/// "extends to end of buffer" `size == 0` form. A truncated or
/// inconsistent header yields a descriptive [`AppError`] rather than a panic.
pub struct Mp4BoxParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Mp4BoxParser<'a> {
    /// Begin parsing the boxes in `data` from offset 0.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current read offset into the buffer.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read the next box, or `Ok(None)` when fewer than 8 bytes remain (no
    /// further complete box header is possible).
    pub fn next_box(&mut self) -> Result<Option<Mp4Box>, AppError> {
        if self.pos + 8 > self.data.len() {
            return Ok(None);
        }
        let start = self.pos;
        let raw_size = read_u32(self.data, start)? as usize;
        let mut box_type = [0u8; 4];
        box_type.copy_from_slice(&self.data[start + 4..start + 8]);

        let (header_len, box_size) = match raw_size {
            1 => {
                // 64-bit extended size: largesize occupies bytes [8..16].
                if start + 16 > self.data.len() {
                    return Err(parse_err(
                        box_type,
                        "truncated 64-bit box size (largesize field)",
                    ));
                }
                let largesize = read_u64(self.data, start + 8)? as usize;
                (16usize, largesize)
            }
            // size == 0 means the box runs to the end of the buffer.
            0 => (8usize, self.data.len() - start),
            n => (8usize, n),
        };

        if box_size < header_len {
            return Err(parse_err(
                box_type,
                "declared box size is smaller than its header",
            ));
        }
        if start + box_size > self.data.len() {
            return Err(parse_err(
                box_type,
                "declared box size overruns the available data",
            ));
        }

        let payload = self.data[start + header_len..start + box_size].to_vec();
        self.pos = start + box_size;
        Ok(Some(Mp4Box { box_type, payload }))
    }
}

/// Decode every top-level box in `data`.
pub fn read_boxes(data: &[u8]) -> Result<Vec<Mp4Box>, AppError> {
    let mut parser = Mp4BoxParser::new(data);
    let mut out = Vec::new();
    while let Some(b) = parser.next_box()? {
        out.push(b);
    }
    Ok(out)
}

/// Box types whose entire payload is a sequence of child boxes (pure
/// containers). The recursive [`find_box`] descends into these.
const CONTAINER_BOXES: &[&[u8; 4]] = &[
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"moof", b"traf", b"mvex", b"edts", b"dinf",
    b"udta", b"sinf", b"schi", b"mfra",
];

/// Visual sample-entry boxes carry a 78-byte fixed header before their child
/// boxes (e.g. `avcC`, `sinf`). ISO/IEC 14496-12 `VisualSampleEntry`.
const VISUAL_SAMPLE_ENTRY_HEADER: usize = 78;
/// Audio sample-entry boxes carry a 28-byte fixed header before their child
/// boxes (e.g. `esds`, `sinf`). ISO/IEC 14496-12 `AudioSampleEntry`.
const AUDIO_SAMPLE_ENTRY_HEADER: usize = 28;

/// Returns the fixed-header size to skip before a sample entry's child boxes,
/// or `None` when `box_type` is not a recognized sample entry.
fn sample_entry_header_len(box_type: &[u8; 4]) -> Option<usize> {
    match box_type {
        b"encv" | b"avc1" | b"avc3" | b"hev1" | b"hvc1" | b"mp4v" | b"dvav" | b"dvhe" => {
            Some(VISUAL_SAMPLE_ENTRY_HEADER)
        }
        b"enca" | b"mp4a" | b"ac-3" | b"ec-3" => Some(AUDIO_SAMPLE_ENTRY_HEADER),
        _ => None,
    }
}

/// Recursively locate the first box of `target` type within `data`, descending
/// into the known CENC container hierarchy (`moov → trak → … → stbl → stsd →
/// <enc*> → sinf → schi`, and `moof → traf`).
///
/// Descent rules (so the walker never misinterprets a leaf box's payload as
/// child boxes):
/// * Pure containers ([`CONTAINER_BOXES`]) are recursed over their whole
///   payload.
/// * `stsd` skips its 8-byte `FullBox` + `entry_count` header, then recurses
///   into the sample entries.
/// * Recognized audio/visual sample entries skip their fixed header, then
///   recurse into their child boxes (which include `sinf`).
///
/// Returns `Ok(None)` when no matching box exists; an error only when a box
/// header is structurally invalid.
pub fn find_box(data: &[u8], target: &[u8; 4]) -> Result<Option<Mp4Box>, AppError> {
    find_box_inner(data, target, 0)
}

fn find_box_inner(data: &[u8], target: &[u8; 4], depth: usize) -> Result<Option<Mp4Box>, AppError> {
    if depth >= MAX_BOX_DEPTH {
        return Ok(None);
    }
    let mut parser = Mp4BoxParser::new(data);
    while let Some(b) = parser.next_box()? {
        if &b.box_type == target {
            return Ok(Some(b));
        }
        // Recurse into children for box types we know how to descend.
        if CONTAINER_BOXES.contains(&&b.box_type) {
            if let Some(found) = find_box_inner(&b.payload, target, depth + 1)? {
                return Ok(Some(found));
            }
        } else if &b.box_type == b"stsd" {
            // stsd: version(1)+flags(3)+entry_count(4) header, then sample entries.
            if b.payload.len() >= 8 {
                if let Some(found) = find_box_inner(&b.payload[8..], target, depth + 1)? {
                    return Ok(Some(found));
                }
            }
        } else if let Some(skip) = sample_entry_header_len(&b.box_type) {
            // Sample entry: skip its fixed header, then descend into child boxes.
            if b.payload.len() >= skip {
                if let Some(found) = find_box_inner(&b.payload[skip..], target, depth + 1)? {
                    return Ok(Some(found));
                }
            }
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Typed CENC metadata
// ---------------------------------------------------------------------------

/// A single subsample's clear/protected byte split within a sample
/// (ISO/IEC 23001-7 `subsample`). The clear bytes precede the protected bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsampleRange {
    /// Number of leading clear (unencrypted) bytes (`BytesOfClearData`).
    pub clear_bytes: u16,
    /// Number of encrypted bytes that follow the clear bytes
    /// (`BytesOfProtectedData`).
    pub protected_bytes: u32,
}

/// Per-sample encryption info recovered from one entry of a `senc` box
/// (Req 4.9): the initialization vector and, when subsample encryption is in
/// use, the subsample clear/protected layout. When the sample is encrypted as
/// a whole (no subsample map), `subsamples` is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleEncryptionInfo {
    /// The per-sample initialization vector (8 or 16 bytes, per the track's
    /// `per_sample_iv_size`). Empty when the track uses a constant IV
    /// (`per_sample_iv_size == 0`, common for `cbcs`).
    pub iv: Vec<u8>,
    /// Subsample ranges, empty when the whole sample is encrypted.
    pub subsamples: Vec<SubsampleRange>,
}

/// Track-level encryption parameters parsed from a `tenc` box
/// (ISO/IEC 23001-7 `TrackEncryptionBox`): the defaults that apply to every
/// sample of the track unless overridden per-sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackEncryption {
    /// Whether samples of this track are protected (`default_isProtected`).
    pub is_protected: bool,
    /// Per-sample IV size in bytes (`default_Per_Sample_IV_Size`): 0, 8, or 16.
    /// 0 indicates a constant IV is used instead (see [`constant_iv`]).
    pub per_sample_iv_size: u8,
    /// The 16-byte key identifier (`default_KID`) used to resolve the
    /// decryption key (Req 4.6).
    pub kid: [u8; 16],
    /// Crypt block count of the crypt/skip pattern for pattern schemes
    /// (`cens`/`cbcs`); 0 for full-sample schemes (`cenc`/`cbc1`). Only present
    /// on `tenc` version ≥ 1.
    pub crypt_byte_block: u8,
    /// Skip block count of the crypt/skip pattern; see [`crypt_byte_block`].
    pub skip_byte_block: u8,
    /// The constant IV (`default_constant_IV`), present only when the track
    /// uses a constant IV (`per_sample_iv_size == 0`).
    pub constant_iv: Option<Vec<u8>>,
}

/// Per-sample auxiliary-information sizes parsed from a `saiz` box
/// (ISO/IEC 14496-12 `SampleAuxiliaryInformationSizesBox`). Used to locate the
/// CENC sample-auxiliary data when it is not carried inline in a `senc` box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleAuxInfoSizes {
    /// When non-zero, every sample's auxiliary info has this fixed size and
    /// [`sample_info_sizes`] is empty.
    pub default_sample_info_size: u8,
    /// Number of samples described.
    pub sample_count: u32,
    /// Per-sample sizes, present only when [`default_sample_info_size`] is 0.
    pub sample_info_sizes: Vec<u8>,
}

impl SampleAuxInfoSizes {
    /// The auxiliary-info size for sample `index`, honoring the
    /// default-size short form.
    pub fn size_of(&self, index: usize) -> Option<u8> {
        if self.default_sample_info_size != 0 {
            (index < self.sample_count as usize).then_some(self.default_sample_info_size)
        } else {
            self.sample_info_sizes.get(index).copied()
        }
    }
}

/// Auxiliary-information offsets parsed from a `saio` box
/// (ISO/IEC 14496-12 `SampleAuxiliaryInformationOffsetsBox`): byte offsets into
/// the fragment at which the sample-auxiliary (CENC) data begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleAuxInfoOffsets {
    /// One offset per entry (4 bytes for `saio` version 0, 8 bytes for
    /// version ≥ 1).
    pub offsets: Vec<u64>,
}

// ---------------------------------------------------------------------------
// Typed box parsers
// ---------------------------------------------------------------------------

/// Parse a `tenc` (track encryption) box payload (Req 4.6, 4.9).
///
/// Layout (ISO/IEC 23001-7):
/// `version(1) flags(3) reserved(1) {reserved|crypt/skip}(1)
///  default_isProtected(1) default_Per_Sample_IV_Size(1) default_KID(16)
///  [if isProtected==1 && iv_size==0: constant_iv_size(1) constant_iv(n)]`.
pub fn parse_tenc(payload: &[u8]) -> Result<TrackEncryption, AppError> {
    let mut cur = Cursor::new(payload, *b"tenc");
    let version = cur.u8()?;
    cur.skip(3)?; // flags
    cur.skip(1)?; // reserved

    // Byte 5: reserved (version 0) or packed crypt/skip pattern (version ≥ 1).
    let pattern_byte = cur.u8()?;
    let (crypt_byte_block, skip_byte_block) = if version > 0 {
        ((pattern_byte >> 4) & 0x0F, pattern_byte & 0x0F)
    } else {
        (0, 0)
    };

    let is_protected = cur.u8()? == 1;
    let per_sample_iv_size = cur.u8()?;
    let kid = cur.array16()?;

    let constant_iv = if is_protected && per_sample_iv_size == 0 {
        let civ_size = cur.u8()? as usize;
        Some(cur.bytes(civ_size)?.to_vec())
    } else {
        None
    };

    Ok(TrackEncryption {
        is_protected,
        per_sample_iv_size,
        kid,
        crypt_byte_block,
        skip_byte_block,
        constant_iv,
    })
}

/// Parse a `saiz` box payload (Req 4.9).
pub fn parse_saiz(payload: &[u8]) -> Result<SampleAuxInfoSizes, AppError> {
    let mut cur = Cursor::new(payload, *b"saiz");
    cur.skip(1)?; // version
    let flags = cur.u24()?;

    if flags & SAI_FLAG_AUX_INFO_TYPE_PRESENT != 0 {
        cur.skip(8)?; // aux_info_type(4) + aux_info_type_parameter(4)
    }

    let default_sample_info_size = cur.u8()?;
    let sample_count = cur.u32()?;

    let sample_info_sizes = if default_sample_info_size == 0 {
        let mut sizes = Vec::with_capacity(sample_count as usize);
        for _ in 0..sample_count {
            sizes.push(cur.u8()?);
        }
        sizes
    } else {
        Vec::new()
    };

    Ok(SampleAuxInfoSizes {
        default_sample_info_size,
        sample_count,
        sample_info_sizes,
    })
}

/// Parse a `saio` box payload (Req 4.9).
pub fn parse_saio(payload: &[u8]) -> Result<SampleAuxInfoOffsets, AppError> {
    let mut cur = Cursor::new(payload, *b"saio");
    let version = cur.u8()?;
    let flags = cur.u24()?;

    if flags & SAI_FLAG_AUX_INFO_TYPE_PRESENT != 0 {
        cur.skip(8)?; // aux_info_type(4) + aux_info_type_parameter(4)
    }

    let entry_count = cur.u32()?;
    let mut offsets = Vec::with_capacity(entry_count as usize);
    for _ in 0..entry_count {
        let offset = if version == 0 {
            cur.u32()? as u64
        } else {
            cur.u64()?
        };
        offsets.push(offset);
    }

    Ok(SampleAuxInfoOffsets { offsets })
}

/// Parse a `senc` (sample encryption) box payload, recovering per-sample IVs
/// and subsample ranges (Req 4.9).
///
/// The per-sample IV size is **not** stored in the `senc` box; it comes from
/// the track's `tenc` (`per_sample_iv_size`), so it must be supplied by the
/// caller. When `per_sample_iv_size == 0` the track uses a constant IV and no
/// per-sample IV bytes are present in the box, so each parsed
/// [`SampleEncryptionInfo::iv`] is empty.
///
/// Layout (ISO/IEC 23001-7):
/// `version(1) flags(3) sample_count(4)
///  per sample { iv(per_sample_iv_size)
///               [if flags&0x2: subsample_count(2)
///                              per subsample { clear(2) protected(4) }] }`.
pub fn parse_senc(
    payload: &[u8],
    per_sample_iv_size: usize,
) -> Result<Vec<SampleEncryptionInfo>, AppError> {
    let mut cur = Cursor::new(payload, *b"senc");
    cur.skip(1)?; // version
    let flags = cur.u24()?;
    let sample_count = cur.u32()?;
    let uses_subsamples = flags & SENC_FLAG_USE_SUBSAMPLES != 0;

    let mut samples = Vec::with_capacity(sample_count as usize);
    for _ in 0..sample_count {
        let iv = if per_sample_iv_size > 0 {
            cur.bytes(per_sample_iv_size)?.to_vec()
        } else {
            Vec::new()
        };

        let mut subsamples = Vec::new();
        if uses_subsamples {
            let subsample_count = cur.u16()?;
            subsamples.reserve(subsample_count as usize);
            for _ in 0..subsample_count {
                let clear_bytes = cur.u16()?;
                let protected_bytes = cur.u32()?;
                subsamples.push(SubsampleRange {
                    clear_bytes,
                    protected_bytes,
                });
            }
        }

        samples.push(SampleEncryptionInfo { iv, subsamples });
    }

    Ok(samples)
}

// ---------------------------------------------------------------------------
// Bounded big-endian cursor
// ---------------------------------------------------------------------------

/// A bounds-checked, big-endian reader over a box payload. Every read that
/// would underrun the buffer yields a descriptive [`AppError`] naming the box,
/// so no parser ever panics on truncated input.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    box_type: [u8; 4],
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], box_type: [u8; 4]) -> Self {
        Self {
            data,
            pos: 0,
            box_type,
        }
    }

    fn ensure(&self, n: usize) -> Result<(), AppError> {
        if self.pos + n > self.data.len() {
            Err(parse_err(
                self.box_type,
                "box payload is truncated (unexpected end of data)",
            ))
        } else {
            Ok(())
        }
    }

    fn skip(&mut self, n: usize) -> Result<(), AppError> {
        self.ensure(n)?;
        self.pos += n;
        Ok(())
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], AppError> {
        self.ensure(n)?;
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, AppError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AppError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<u32, AppError> {
        let b = self.bytes(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    fn u32(&mut self) -> Result<u32, AppError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, AppError> {
        let b = self.bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn array16(&mut self) -> Result<[u8; 16], AppError> {
        let b = self.bytes(16)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(b);
        Ok(out)
    }
}

/// Read a big-endian `u32` at `offset` from `data`, erroring when out of bounds.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, AppError> {
    let b = data
        .get(offset..offset + 4)
        .ok_or_else(|| AppError::bad_request("mp4: truncated box header (size field)"))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a big-endian `u64` at `offset` from `data`, erroring when out of bounds.
fn read_u64(data: &[u8], offset: usize) -> Result<u64, AppError> {
    let b = data
        .get(offset..offset + 8)
        .ok_or_else(|| AppError::bad_request("mp4: truncated box header (largesize field)"))?;
    Ok(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Build a descriptive `bad-request` parse error naming the box that failed to
/// parse (design: Error Handling; consistent with Req 1.8/2.8 parse errors).
fn parse_err(box_type: [u8; 4], detail: &str) -> AppError {
    let name = std::str::from_utf8(&box_type).unwrap_or("????");
    AppError::bad_request(format!("mp4: malformed `{name}` box: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Box-building helpers (mirror the wire format the parsers decode) ----

    /// Frame `payload` as a complete box: `size(4) || type(4) || payload`.
    fn box_bytes(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = (8 + payload.len()) as u32;
        let mut out = Vec::with_capacity(size as usize);
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(box_type);
        out.extend_from_slice(payload);
        out
    }

    /// Build a `tenc` payload (version 1 with crypt/skip pattern by default).
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
        p.push((crypt << 4) | (skip & 0x0F)); // pattern byte (reserved on v0)
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

    /// Build a `senc` payload from per-sample (iv, subsamples) tuples.
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

    // -- Generic box reader --------------------------------------------------

    #[test]
    fn reads_sequential_top_level_boxes() {
        let mut buf = box_bytes(b"ftyp", b"isom");
        buf.extend_from_slice(&box_bytes(b"free", b""));
        buf.extend_from_slice(&box_bytes(b"mdat", &[1, 2, 3, 4]));

        let boxes = read_boxes(&buf).unwrap();
        assert_eq!(boxes.len(), 3);
        assert_eq!(&boxes[0].box_type, b"ftyp");
        assert_eq!(boxes[0].payload, b"isom");
        assert_eq!(&boxes[1].box_type, b"free");
        assert!(boxes[1].payload.is_empty());
        assert_eq!(&boxes[2].box_type, b"mdat");
        assert_eq!(boxes[2].payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn reads_64bit_extended_size_box() {
        // size==1 marker, type, then 64-bit largesize, then payload.
        let payload = [0xAAu8; 4];
        let total = 16 + payload.len() as u64;
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(b"mdat");
        buf.extend_from_slice(&total.to_be_bytes());
        buf.extend_from_slice(&payload);

        let boxes = read_boxes(&buf).unwrap();
        assert_eq!(boxes.len(), 1);
        assert_eq!(&boxes[0].box_type, b"mdat");
        assert_eq!(boxes[0].payload, payload.to_vec());
    }

    #[test]
    fn size_zero_box_extends_to_end() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // size 0 → to end
        buf.extend_from_slice(b"mdat");
        buf.extend_from_slice(&[9, 8, 7, 6, 5]);

        let boxes = read_boxes(&buf).unwrap();
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].payload, vec![9, 8, 7, 6, 5]);
    }

    #[test]
    fn truncated_box_size_overrun_is_descriptive_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&64u32.to_be_bytes()); // claims 64 bytes
        buf.extend_from_slice(b"moof");
        buf.extend_from_slice(&[0u8; 4]); // but only 4 follow

        let err = read_boxes(&buf).unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::BadRequest);
        assert!(
            err.message.contains("moof"),
            "error names the box: {}",
            err.message
        );
        assert!(err.message.contains("overrun"));
    }

    #[test]
    fn box_size_smaller_than_header_is_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&4u32.to_be_bytes()); // size 4 < 8-byte header
        buf.extend_from_slice(b"moov");
        let err = read_boxes(&buf).unwrap_err();
        assert!(err.message.contains("moov"));
        assert!(err.message.contains("smaller"));
    }

    #[test]
    fn trailing_bytes_below_header_size_stop_parsing() {
        // 3 trailing bytes (< 8) after a valid box are ignored, not an error.
        let mut buf = box_bytes(b"ftyp", b"isom");
        buf.extend_from_slice(&[0, 0, 0]);
        let boxes = read_boxes(&buf).unwrap();
        assert_eq!(boxes.len(), 1);
    }

    // -- find_box recursion --------------------------------------------------

    #[test]
    fn find_box_locates_senc_inside_moof_traf() {
        let senc = box_bytes(b"senc", &senc_payload(false, &[(vec![0u8; 8], vec![])]));
        let traf = box_bytes(b"traf", &senc);
        let moof = box_bytes(b"moof", &traf);

        let found = find_box(&moof, b"senc").unwrap().expect("senc found");
        assert_eq!(&found.box_type, b"senc");
    }

    #[test]
    fn find_box_locates_tenc_through_stsd_sample_entry_sinf_schi() {
        // Build moov/trak/mdia/minf/stbl/stsd/encv/sinf/schi/tenc.
        let kid = [0x11u8; 16];
        let tenc = box_bytes(b"tenc", &tenc_payload(1, 1, 9, 1, 8, kid, None));
        let schi = box_bytes(b"schi", &tenc);
        let sinf = box_bytes(b"sinf", &schi);

        // encv sample entry: 78-byte fixed header then the sinf child.
        let mut encv_payload = vec![0u8; VISUAL_SAMPLE_ENTRY_HEADER];
        encv_payload.extend_from_slice(&sinf);
        let encv = box_bytes(b"encv", &encv_payload);

        // stsd: 8-byte header (version/flags + entry_count) then the entry.
        let mut stsd_payload = vec![0u8, 0, 0, 0]; // version+flags
        stsd_payload.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        stsd_payload.extend_from_slice(&encv);
        let stsd = box_bytes(b"stsd", &stsd_payload);

        let stbl = box_bytes(b"stbl", &stsd);
        let minf = box_bytes(b"minf", &stbl);
        let mdia = box_bytes(b"mdia", &minf);
        let trak = box_bytes(b"trak", &mdia);
        let moov = box_bytes(b"moov", &trak);

        let found = find_box(&moov, b"tenc").unwrap().expect("tenc found");
        let parsed = parse_tenc(&found.payload).unwrap();
        assert_eq!(parsed.kid, kid);
        assert_eq!(parsed.per_sample_iv_size, 8);
    }

    #[test]
    fn find_box_returns_none_when_absent() {
        let moof = box_bytes(b"moof", &box_bytes(b"traf", b""));
        assert_eq!(find_box(&moof, b"senc").unwrap(), None);
    }

    // -- tenc ----------------------------------------------------------------

    #[test]
    fn parse_tenc_recovers_kid_iv_size_and_pattern() {
        let kid = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let payload = tenc_payload(1, 1, 9, 1, 16, kid, None);
        let tenc = parse_tenc(&payload).unwrap();
        assert!(tenc.is_protected);
        assert_eq!(tenc.per_sample_iv_size, 16);
        assert_eq!(tenc.kid, kid);
        assert_eq!(tenc.crypt_byte_block, 1);
        assert_eq!(tenc.skip_byte_block, 9);
        assert_eq!(tenc.constant_iv, None);
    }

    #[test]
    fn parse_tenc_version0_ignores_pattern_byte() {
        let kid = [0x42u8; 16];
        // Even with a non-zero pattern byte, version 0 must report 0/0.
        let payload = tenc_payload(0, 1, 9, 1, 8, kid, None);
        let tenc = parse_tenc(&payload).unwrap();
        assert_eq!(tenc.crypt_byte_block, 0);
        assert_eq!(tenc.skip_byte_block, 0);
        assert_eq!(tenc.per_sample_iv_size, 8);
    }

    #[test]
    fn parse_tenc_recovers_constant_iv_for_cbcs() {
        let kid = [0x7u8; 16];
        let civ = [0xABu8; 16];
        // iv_size 0 + protected → constant IV present.
        let payload = tenc_payload(1, 1, 9, 1, 0, kid, Some(&civ));
        let tenc = parse_tenc(&payload).unwrap();
        assert_eq!(tenc.per_sample_iv_size, 0);
        assert_eq!(tenc.constant_iv.as_deref(), Some(&civ[..]));
    }

    #[test]
    fn parse_tenc_truncated_is_error() {
        let err = parse_tenc(&[0, 0, 0, 0]).unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::BadRequest);
        assert!(err.message.contains("tenc"));
    }

    // -- senc ----------------------------------------------------------------

    #[test]
    fn parse_senc_recovers_per_sample_ivs_no_subsamples() {
        let s = [
            (vec![1u8, 2, 3, 4, 5, 6, 7, 8], vec![]),
            (vec![9u8, 10, 11, 12, 13, 14, 15, 16], vec![]),
        ];
        let payload = senc_payload(false, &s);
        let samples = parse_senc(&payload, 8).unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].iv, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(samples[1].iv, vec![9, 10, 11, 12, 13, 14, 15, 16]);
        assert!(samples[0].subsamples.is_empty());
    }

    #[test]
    fn parse_senc_recovers_subsample_ranges() {
        let s = [
            (vec![0xAAu8; 16], vec![(100u16, 2048u32), (0u16, 4096u32)]),
            (vec![0xBBu8; 16], vec![(40u16, 512u32)]),
        ];
        let payload = senc_payload(true, &s);
        let samples = parse_senc(&payload, 16).unwrap();
        assert_eq!(samples.len(), 2);

        assert_eq!(samples[0].iv, vec![0xAA; 16]);
        assert_eq!(samples[0].subsamples.len(), 2);
        assert_eq!(
            samples[0].subsamples[0],
            SubsampleRange {
                clear_bytes: 100,
                protected_bytes: 2048
            }
        );
        assert_eq!(
            samples[0].subsamples[1],
            SubsampleRange {
                clear_bytes: 0,
                protected_bytes: 4096
            }
        );
        assert_eq!(
            samples[1].subsamples[0],
            SubsampleRange {
                clear_bytes: 40,
                protected_bytes: 512
            }
        );
    }

    #[test]
    fn parse_senc_constant_iv_track_has_empty_per_sample_ivs() {
        // per_sample_iv_size == 0 → no IV bytes in the box; subsample maps only.
        let s = [(vec![], vec![(10u16, 100u32)])];
        let payload = senc_payload(true, &s);
        let samples = parse_senc(&payload, 0).unwrap();
        assert_eq!(samples.len(), 1);
        assert!(samples[0].iv.is_empty());
        assert_eq!(samples[0].subsamples[0].protected_bytes, 100);
    }

    #[test]
    fn parse_senc_truncated_sample_data_is_error() {
        // Declares 4 samples but only provides one IV.
        let mut payload = Vec::new();
        payload.push(0); // version
        payload.extend_from_slice(&[0, 0, 0]); // flags (no subsamples)
        payload.extend_from_slice(&4u32.to_be_bytes()); // sample_count = 4
        payload.extend_from_slice(&[0u8; 8]); // only one 8-byte IV
        let err = parse_senc(&payload, 8).unwrap_err();
        assert!(err.message.contains("senc"));
        assert!(err.message.contains("truncated"));
    }

    // -- saiz / saio ---------------------------------------------------------

    #[test]
    fn parse_saiz_default_size_form() {
        let mut payload = Vec::new();
        payload.push(0); // version
        payload.extend_from_slice(&[0, 0, 0]); // flags (no aux info type)
        payload.push(24); // default_sample_info_size
        payload.extend_from_slice(&5u32.to_be_bytes()); // sample_count
        let saiz = parse_saiz(&payload).unwrap();
        assert_eq!(saiz.default_sample_info_size, 24);
        assert_eq!(saiz.sample_count, 5);
        assert!(saiz.sample_info_sizes.is_empty());
        assert_eq!(saiz.size_of(0), Some(24));
        assert_eq!(saiz.size_of(4), Some(24));
        assert_eq!(saiz.size_of(5), None);
    }

    #[test]
    fn parse_saiz_per_sample_sizes_form() {
        let mut payload = Vec::new();
        payload.push(0);
        payload.extend_from_slice(&[0, 0, 0]);
        payload.push(0); // default 0 → per-sample sizes follow
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(&[10, 20, 30]);
        let saiz = parse_saiz(&payload).unwrap();
        assert_eq!(saiz.sample_info_sizes, vec![10, 20, 30]);
        assert_eq!(saiz.size_of(1), Some(20));
        assert_eq!(saiz.size_of(3), None);
    }

    #[test]
    fn parse_saiz_honors_aux_info_type_flag() {
        let mut payload = Vec::new();
        payload.push(0);
        payload.extend_from_slice(&SAI_FLAG_AUX_INFO_TYPE_PRESENT.to_be_bytes()[1..]); // flags
        payload.extend_from_slice(b"cenc"); // aux_info_type
        payload.extend_from_slice(&0u32.to_be_bytes()); // aux_info_type_parameter
        payload.push(16); // default size
        payload.extend_from_slice(&2u32.to_be_bytes());
        let saiz = parse_saiz(&payload).unwrap();
        assert_eq!(saiz.default_sample_info_size, 16);
        assert_eq!(saiz.sample_count, 2);
    }

    #[test]
    fn parse_saio_version0_32bit_offsets() {
        let mut payload = Vec::new();
        payload.push(0); // version 0
        payload.extend_from_slice(&[0, 0, 0]); // flags
        payload.extend_from_slice(&2u32.to_be_bytes()); // entry_count
        payload.extend_from_slice(&1000u32.to_be_bytes());
        payload.extend_from_slice(&2000u32.to_be_bytes());
        let saio = parse_saio(&payload).unwrap();
        assert_eq!(saio.offsets, vec![1000, 2000]);
    }

    #[test]
    fn parse_saio_version1_64bit_offsets() {
        let mut payload = Vec::new();
        payload.push(1); // version 1 → 64-bit offsets
        payload.extend_from_slice(&[0, 0, 0]);
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&0x1_0000_0000u64.to_be_bytes());
        let saio = parse_saio(&payload).unwrap();
        assert_eq!(saio.offsets, vec![0x1_0000_0000]);
    }

    #[test]
    fn parse_saio_truncated_is_error() {
        let mut payload = Vec::new();
        payload.push(0);
        payload.extend_from_slice(&[0, 0, 0]);
        payload.extend_from_slice(&4u32.to_be_bytes()); // claims 4 entries
        payload.extend_from_slice(&1u32.to_be_bytes()); // only one present
        let err = parse_saio(&payload).unwrap_err();
        assert!(err.message.contains("saio"));
    }

    #[test]
    fn end_to_end_parse_moof_senc_with_tenc_iv_size() {
        // tenc declares iv_size 16; senc carries two 16-byte IVs + subsamples.
        let kid = [0x55u8; 16];
        let tenc = parse_tenc(&tenc_payload(1, 1, 9, 1, 16, kid, None)).unwrap();

        let senc_box = box_bytes(
            b"senc",
            &senc_payload(
                true,
                &[
                    (vec![0x01u8; 16], vec![(16, 1000)]),
                    (vec![0x02u8; 16], vec![(0, 2000)]),
                ],
            ),
        );
        let moof = box_bytes(b"moof", &box_bytes(b"traf", &senc_box));

        let senc = find_box(&moof, b"senc").unwrap().unwrap();
        let samples = parse_senc(&senc.payload, tenc.per_sample_iv_size as usize).unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].iv, vec![0x01; 16]);
        assert_eq!(samples[0].subsamples[0].protected_bytes, 1000);
        assert_eq!(samples[1].subsamples[0].clear_bytes, 0);
    }
}
