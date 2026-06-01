//! Byte-range parsing + response-metadata computation (`proxy::range`) —
//! Req 5.2, 5.5, 19.2, 37.14–37.17.
//!
//! This module is the single, pure place that turns an HTTP `Range` header
//! into a typed [`RangeSpec`] and resolves it against a known total size into
//! the response metadata a Byte_Serving response needs: the status
//! (`200`/`206`/`416`), the `Content-Range` header value, the body
//! `Content-Length`, and whether `Accept-Ranges: bytes` is advertised
//! (design: Components → Range handling).
//!
//! It contains *no* I/O — the streaming core (task 14.2) and the ResilientStream
//! (task 15.x) consume [`compute_response_metadata`] to drive the actual
//! upstream fetch and the client response, so the range arithmetic is verified
//! in isolation here.
//!
//! ## Behaviour (design: Components → Range handling)
//!
//! * `RangeSpec { Full, FromOffset, Inclusive, Suffix }` parsed from the
//!   `Range` header; a malformed header is a [`AppError::bad_request`]
//!   (Req 47.4).
//! * A satisfiable range → `206 Partial Content` with
//!   `Content-Range: bytes start-end/S` and `Content-Length` = the range length
//!   (Req 5.2, 19.2).
//! * Open-ended `bytes=N-` → `N..=S-1` (Req 37.15).
//! * Suffix `bytes=-N` → `max(0, S-N)..=S-1` (Req 37.16).
//! * An unsatisfiable range (start ≥ S, suffix length 0, or any range on an
//!   empty resource) → `416 Range Not Satisfiable` with
//!   `Content-Range: bytes */S` ([`Unsatisfiable`] → [`AppError::range_not_satisfiable`],
//!   Req 5.5).
//! * `Accept-Ranges: bytes` is advertised whenever the total size is known —
//!   even if the upstream never advertised it (Req 37.17).
//! * A `HEAD` request produces the *identical* header set a `GET` would, with
//!   no body ([`ResponseMetadata::include_body`], Req 37.14).

use actix_web::http::StatusCode;

use crate::errors::AppError;

/// A single byte range parsed from a `Range` header (design: Components →
/// Range handling). Only the single-range forms are modelled; multi-range
/// (`bytes=0-9,20-29`) is rejected at parse time as the streaming core does
/// not emit `multipart/byteranges`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeSpec {
    /// No range constraint — stream the whole body (`200`). Produced when the
    /// `Range` header is absent or empty (Req 5.1).
    Full,
    /// Open-ended `bytes=N-`: from offset `N` to the last byte (Req 37.15).
    FromOffset(u64),
    /// Closed `bytes=N-M`: the inclusive `[N, M]` interval (Req 5.2).
    Inclusive(u64, u64),
    /// Suffix `bytes=-N`: the final `N` bytes of the resource (Req 37.16).
    Suffix(u64),
}

/// A [`RangeSpec`] resolved against a known total size `total` into a concrete
/// satisfiable interval. `start` and `end` are **inclusive** absolute byte
/// offsets, matching `Content-Range` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRange {
    /// First byte offset (inclusive).
    pub start: u64,
    /// Last byte offset (inclusive).
    pub end: u64,
    /// The total resource size the range was resolved against.
    pub total: u64,
}

impl ResolvedRange {
    /// The number of bytes the range covers (`end - start + 1`). Always ≥ 1 for
    /// a satisfiable range.
    pub fn length(&self) -> u64 {
        self.end - self.start + 1
    }

    /// The `Content-Range` header value for a `206`: `bytes start-end/total`
    /// (Req 5.2, 19.2).
    pub fn content_range(&self) -> String {
        format!("bytes {}-{}/{}", self.start, self.end, self.total)
    }
}

/// The outcome of an unsatisfiable range request (`416`, Req 5.5).
///
/// Carries the `total` size so the caller can emit both the
/// `Content-Range: bytes */total` header and the canonical
/// [`AppError::range_not_satisfiable`] envelope, keeping the error on the
/// shared taxonomy (Req 47) while still surfacing the required header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsatisfiable {
    /// The known total resource size the range could not be satisfied against.
    pub total: u64,
}

impl Unsatisfiable {
    /// The `Content-Range` header value for the `416`: `bytes */total`
    /// (Req 5.5).
    pub fn content_range(&self) -> String {
        format!("bytes */{}", self.total)
    }

    /// Map onto the canonical taxonomy (`416`, Req 5.5, 47.1).
    pub fn to_app_error(&self) -> AppError {
        AppError::range_not_satisfiable(format!(
            "requested range is not satisfiable for a {}-byte resource",
            self.total
        ))
    }
}

impl From<Unsatisfiable> for AppError {
    fn from(unsat: Unsatisfiable) -> Self {
        unsat.to_app_error()
    }
}

impl RangeSpec {
    /// Parse an optional `Range` header value (Req 5.2, 37.15, 37.16).
    ///
    /// `None` (header absent) yields [`RangeSpec::Full`].
    pub fn from_header(value: Option<&str>) -> Result<RangeSpec, AppError> {
        match value {
            None => Ok(RangeSpec::Full),
            Some(raw) => RangeSpec::parse(raw),
        }
    }

    /// Parse a `Range` header *value* into a [`RangeSpec`] (Req 5.2, 37.15,
    /// 37.16).
    ///
    /// An empty/whitespace value yields [`RangeSpec::Full`]. A syntactically
    /// malformed value, an unsupported range unit, or a multi-range value is a
    /// [`AppError::bad_request`] (Req 47.4). Note that *satisfiability* (e.g.
    /// `start ≥ size`) is not decided here — it depends on the resource size
    /// and is determined by [`RangeSpec::resolve`].
    pub fn parse(raw: &str) -> Result<RangeSpec, AppError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(RangeSpec::Full);
        }

        let (unit, rest) = trimmed
            .split_once('=')
            .ok_or_else(|| AppError::bad_request(format!("malformed Range header: {raw:?}")))?;

        if !unit.trim().eq_ignore_ascii_case("bytes") {
            return Err(AppError::bad_request(format!(
                "unsupported range unit {:?}: only 'bytes' is supported",
                unit.trim()
            )));
        }

        let rest = rest.trim();
        if rest.is_empty() {
            return Err(AppError::bad_request(format!(
                "Range header specifies no byte range: {raw:?}"
            )));
        }
        // The streaming core never emits multipart/byteranges, so a
        // comma-separated multi-range request is rejected up front.
        if rest.contains(',') {
            return Err(AppError::bad_request(
                "multiple byte ranges in a single request are not supported".to_string(),
            ));
        }

        let (start_str, end_str) = rest
            .split_once('-')
            .ok_or_else(|| AppError::bad_request(format!("malformed byte range: {rest:?}")))?;
        let start_str = start_str.trim();
        let end_str = end_str.trim();

        match (start_str.is_empty(), end_str.is_empty()) {
            // `bytes=-` — neither a start nor a suffix length.
            (true, true) => Err(AppError::bad_request(
                "byte range must specify a start offset or a suffix length".to_string(),
            )),
            // `bytes=-N` — suffix.
            (true, false) => Ok(RangeSpec::Suffix(parse_u64(end_str, raw)?)),
            // `bytes=N-` — open-ended.
            (false, true) => Ok(RangeSpec::FromOffset(parse_u64(start_str, raw)?)),
            // `bytes=N-M` — closed interval.
            (false, false) => {
                let start = parse_u64(start_str, raw)?;
                let end = parse_u64(end_str, raw)?;
                if end < start {
                    return Err(AppError::bad_request(format!(
                        "invalid byte range: end {end} precedes start {start}"
                    )));
                }
                Ok(RangeSpec::Inclusive(start, end))
            }
        }
    }

    /// Resolve this spec against a known total size `total` (design:
    /// Components → Range handling).
    ///
    /// * `Ok(None)` — [`RangeSpec::Full`]: stream the whole body (`200`).
    /// * `Ok(Some(range))` — a satisfiable partial range (`206`). Open-ended
    ///   resolves to `N..=total-1` (Req 37.15); suffix to
    ///   `max(0, total-N)..=total-1` (Req 37.16); a closed range has its end
    ///   clamped to `total-1` per RFC 7233.
    /// * `Err(Unsatisfiable)` — `start ≥ total`, a zero-length suffix, or any
    ///   range against an empty resource (`416`, Req 5.5).
    pub fn resolve(&self, total: u64) -> Result<Option<ResolvedRange>, Unsatisfiable> {
        match *self {
            RangeSpec::Full => Ok(None),
            RangeSpec::FromOffset(start) => {
                if start >= total {
                    return Err(Unsatisfiable { total });
                }
                Ok(Some(ResolvedRange {
                    start,
                    end: total - 1,
                    total,
                }))
            }
            RangeSpec::Inclusive(start, end) => {
                if start >= total {
                    return Err(Unsatisfiable { total });
                }
                // RFC 7233: a last-byte-pos that exceeds the current length is
                // clamped to the last byte of the representation.
                let end = end.min(total - 1);
                Ok(Some(ResolvedRange { start, end, total }))
            }
            RangeSpec::Suffix(n) => {
                // A zero-length suffix, or any suffix of an empty resource,
                // selects no bytes and is unsatisfiable.
                if n == 0 || total == 0 {
                    return Err(Unsatisfiable { total });
                }
                // A suffix longer than the resource selects the whole thing.
                let effective = n.min(total);
                Ok(Some(ResolvedRange {
                    start: total - effective,
                    end: total - 1,
                    total,
                }))
            }
        }
    }
}

/// The response metadata a Byte_Serving response carries, derived from a
/// [`RangeSpec`] and the (optionally known) total size (design: Components →
/// Range handling; Req 5, 19.2, 37.14–37.17).
///
/// The header-bearing fields are **method-independent**: a `HEAD` and a `GET`
/// for the same request produce the same `status`, `content_range`,
/// `content_length`, and `accept_ranges`; only [`include_body`](Self::include_body)
/// differs (`false` for `HEAD`), so a player's `HEAD` probe sees exactly what a
/// subsequent `GET` would return (Req 37.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseMetadata {
    /// `200 OK` (full body) or `206 Partial Content` (a satisfiable range).
    /// The unsatisfiable `416` case is the [`Unsatisfiable`] error path, not a
    /// value here.
    pub status: StatusCode,
    /// The `Content-Range` header value, present only for a `206`
    /// (`bytes start-end/total`).
    pub content_range: Option<String>,
    /// The body `Content-Length` the client should see: the range length for a
    /// `206`, the total size for a full `200`, or `None` when the size is
    /// unknown (streamed without a declared length).
    pub content_length: Option<u64>,
    /// Whether to advertise `Accept-Ranges: bytes`. Set whenever the total
    /// size is known, regardless of whether the upstream advertised it
    /// (Req 37.17).
    pub accept_ranges: bool,
    /// The resolved upstream byte range to fetch for a `206`; `None` for a full
    /// `200`.
    pub range: Option<ResolvedRange>,
    /// Whether the response carries a body. `false` for a `HEAD` request so the
    /// header set matches a `GET` with no body (Req 37.14).
    pub include_body: bool,
}

/// Compute the [`ResponseMetadata`] for a request (design: Components → Range
/// handling; Req 5.2, 5.5, 19.2, 37.14–37.17).
///
/// * `total_size = Some(s)` — the size is known: a [`RangeSpec::Full`] yields a
///   `200` with `Content-Length: s`; a satisfiable range yields a `206` with
///   `Content-Range`/`Content-Length`; an unsatisfiable range yields
///   `Err(Unsatisfiable)` (`416`). `Accept-Ranges: bytes` is advertised in
///   every known-size case (Req 37.17).
/// * `total_size = None` — the size is unknown: the metadata describes a full
///   `200` passthrough with no `Content-Length` and `Accept-Ranges` *not*
///   advertised. Partial delivery cannot be computed without a size, so the
///   streaming core forwards the original `Range` upstream and relays the
///   upstream's `206`/`Content-Range` verbatim (out of scope of this pure
///   computation).
///
/// `is_head` only toggles [`ResponseMetadata::include_body`]; the header-bearing
/// fields are identical to the `GET` form (Req 37.14).
pub fn compute_response_metadata(
    spec: &RangeSpec,
    total_size: Option<u64>,
    is_head: bool,
) -> Result<ResponseMetadata, Unsatisfiable> {
    let include_body = !is_head;

    let Some(total) = total_size else {
        // Size unknown: a full passthrough, no Content-Length, and we cannot
        // honour Accept-Ranges since we cannot validate ranges locally.
        return Ok(ResponseMetadata {
            status: StatusCode::OK,
            content_range: None,
            content_length: None,
            accept_ranges: false,
            range: None,
            include_body,
        });
    };

    match spec.resolve(total)? {
        // Full body — 200 with the total as Content-Length.
        None => Ok(ResponseMetadata {
            status: StatusCode::OK,
            content_range: None,
            content_length: Some(total),
            accept_ranges: true,
            range: None,
            include_body,
        }),
        // Satisfiable partial range — 206.
        Some(range) => Ok(ResponseMetadata {
            status: StatusCode::PARTIAL_CONTENT,
            content_range: Some(range.content_range()),
            content_length: Some(range.length()),
            accept_ranges: true,
            range: Some(range),
            include_body,
        }),
    }
}

/// Parse a single byte position, mapping a non-numeric value onto a
/// [`AppError::bad_request`] (Req 47.4).
fn parse_u64(s: &str, raw: &str) -> Result<u64, AppError> {
    s.parse::<u64>().map_err(|_| {
        AppError::bad_request(format!(
            "invalid byte position {s:?} in Range header {raw:?}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;

    // -- Parsing the four RangeSpec forms (Req 5.2, 37.15, 37.16) -----------

    #[test]
    fn parse_absent_header_is_full() {
        assert_eq!(RangeSpec::from_header(None).unwrap(), RangeSpec::Full);
    }

    #[test]
    fn parse_empty_value_is_full() {
        assert_eq!(RangeSpec::parse("").unwrap(), RangeSpec::Full);
        assert_eq!(RangeSpec::parse("   ").unwrap(), RangeSpec::Full);
    }

    #[test]
    fn parse_open_ended_is_from_offset() {
        assert_eq!(
            RangeSpec::parse("bytes=0-").unwrap(),
            RangeSpec::FromOffset(0)
        );
        assert_eq!(
            RangeSpec::parse("bytes=500-").unwrap(),
            RangeSpec::FromOffset(500)
        );
    }

    #[test]
    fn parse_closed_is_inclusive() {
        assert_eq!(
            RangeSpec::parse("bytes=0-499").unwrap(),
            RangeSpec::Inclusive(0, 499)
        );
        assert_eq!(
            RangeSpec::parse("bytes=200-999").unwrap(),
            RangeSpec::Inclusive(200, 999)
        );
    }

    #[test]
    fn parse_suffix_is_suffix() {
        assert_eq!(
            RangeSpec::parse("bytes=-500").unwrap(),
            RangeSpec::Suffix(500)
        );
        assert_eq!(RangeSpec::parse("bytes=-1").unwrap(), RangeSpec::Suffix(1));
    }

    #[test]
    fn parse_is_unit_case_insensitive_and_tolerates_whitespace() {
        assert_eq!(
            RangeSpec::parse("BYTES=0-10").unwrap(),
            RangeSpec::Inclusive(0, 10)
        );
        assert_eq!(
            RangeSpec::parse("  bytes = 0 - 10 ").unwrap(),
            RangeSpec::Inclusive(0, 10)
        );
    }

    // -- Malformed headers map onto the BadRequest taxonomy (Req 47.4) ------

    #[test]
    fn parse_rejects_unsupported_unit() {
        let err = RangeSpec::parse("items=0-10").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    #[test]
    fn parse_rejects_missing_equals() {
        let err = RangeSpec::parse("bytes 0-10").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    #[test]
    fn parse_rejects_non_numeric_positions() {
        assert_eq!(
            RangeSpec::parse("bytes=abc-10").unwrap_err().category,
            ErrorCategory::BadRequest
        );
        assert_eq!(
            RangeSpec::parse("bytes=0-xyz").unwrap_err().category,
            ErrorCategory::BadRequest
        );
    }

    #[test]
    fn parse_rejects_end_before_start() {
        let err = RangeSpec::parse("bytes=500-100").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
    }

    #[test]
    fn parse_rejects_bare_dash_and_multi_range() {
        assert_eq!(
            RangeSpec::parse("bytes=-").unwrap_err().category,
            ErrorCategory::BadRequest
        );
        assert_eq!(
            RangeSpec::parse("bytes=0-10,20-30").unwrap_err().category,
            ErrorCategory::BadRequest
        );
    }

    // -- Resolution math (Req 37.15, 37.16, 5.5) ----------------------------

    #[test]
    fn resolve_full_is_whole_body() {
        assert_eq!(RangeSpec::Full.resolve(1000).unwrap(), None);
        // Even an empty resource has a (zero-length) full body.
        assert_eq!(RangeSpec::Full.resolve(0).unwrap(), None);
    }

    #[test]
    fn resolve_open_ended_spans_offset_to_last_byte() {
        // bytes=N- -> N..=S-1 (Req 37.15).
        let r = RangeSpec::FromOffset(100).resolve(1000).unwrap().unwrap();
        assert_eq!(
            r,
            ResolvedRange {
                start: 100,
                end: 999,
                total: 1000
            }
        );
        assert_eq!(r.length(), 900);
        assert_eq!(r.content_range(), "bytes 100-999/1000");
    }

    #[test]
    fn resolve_open_ended_from_zero_covers_everything_as_206() {
        // bytes=0- is still a 206 (Req 37.15), not a 200.
        let r = RangeSpec::FromOffset(0).resolve(1000).unwrap().unwrap();
        assert_eq!(
            r,
            ResolvedRange {
                start: 0,
                end: 999,
                total: 1000
            }
        );
        assert_eq!(r.content_range(), "bytes 0-999/1000");
    }

    #[test]
    fn resolve_closed_range_clamps_end_to_last_byte() {
        let r = RangeSpec::Inclusive(0, 499).resolve(1000).unwrap().unwrap();
        assert_eq!(
            r,
            ResolvedRange {
                start: 0,
                end: 499,
                total: 1000
            }
        );
        // last-byte-pos beyond the resource is clamped to S-1 (RFC 7233).
        let clamped = RangeSpec::Inclusive(900, 5000)
            .resolve(1000)
            .unwrap()
            .unwrap();
        assert_eq!(
            clamped,
            ResolvedRange {
                start: 900,
                end: 999,
                total: 1000
            }
        );
        assert_eq!(clamped.length(), 100);
    }

    #[test]
    fn resolve_suffix_spans_last_n_bytes() {
        // bytes=-N -> max(0, S-N)..=S-1 (Req 37.16).
        let r = RangeSpec::Suffix(500).resolve(1000).unwrap().unwrap();
        assert_eq!(
            r,
            ResolvedRange {
                start: 500,
                end: 999,
                total: 1000
            }
        );
        assert_eq!(r.length(), 500);
        assert_eq!(r.content_range(), "bytes 500-999/1000");
    }

    #[test]
    fn resolve_suffix_larger_than_resource_covers_everything() {
        // A suffix longer than the resource selects the whole representation.
        let r = RangeSpec::Suffix(5000).resolve(1000).unwrap().unwrap();
        assert_eq!(
            r,
            ResolvedRange {
                start: 0,
                end: 999,
                total: 1000
            }
        );
        assert_eq!(r.content_range(), "bytes 0-999/1000");
    }

    #[test]
    fn resolve_start_at_or_beyond_size_is_unsatisfiable() {
        // start == S (Req 5.5).
        assert_eq!(
            RangeSpec::FromOffset(1000).resolve(1000),
            Err(Unsatisfiable { total: 1000 })
        );
        // start > S.
        assert_eq!(
            RangeSpec::FromOffset(2000).resolve(1000),
            Err(Unsatisfiable { total: 1000 })
        );
        // closed range starting past the end.
        assert_eq!(
            RangeSpec::Inclusive(1000, 1100).resolve(1000),
            Err(Unsatisfiable { total: 1000 })
        );
    }

    #[test]
    fn resolve_zero_length_suffix_is_unsatisfiable() {
        assert_eq!(
            RangeSpec::Suffix(0).resolve(1000),
            Err(Unsatisfiable { total: 1000 })
        );
    }

    #[test]
    fn resolve_any_range_on_empty_resource_is_unsatisfiable() {
        assert_eq!(
            RangeSpec::FromOffset(0).resolve(0),
            Err(Unsatisfiable { total: 0 })
        );
        assert_eq!(
            RangeSpec::Inclusive(0, 0).resolve(0),
            Err(Unsatisfiable { total: 0 })
        );
        assert_eq!(
            RangeSpec::Suffix(10).resolve(0),
            Err(Unsatisfiable { total: 0 })
        );
    }

    #[test]
    fn unsatisfiable_yields_star_content_range_and_416_error() {
        let unsat = RangeSpec::FromOffset(1000).resolve(1000).unwrap_err();
        // Content-Range: bytes */S (Req 5.5).
        assert_eq!(unsat.content_range(), "bytes */1000");
        // Maps onto the canonical 416 taxonomy (Req 5.5, 47.1).
        let err: AppError = unsat.into();
        assert_eq!(err.category, ErrorCategory::RangeNotSatisfiable);
        assert_eq!(err.http_status().as_u16(), 416);
    }

    // -- Response metadata: satisfiable range -> 206 (Req 5.2, 19.2) --------

    #[test]
    fn metadata_satisfiable_range_is_206_with_content_range() {
        let spec = RangeSpec::parse("bytes=100-199").unwrap();
        let meta = compute_response_metadata(&spec, Some(1000), false).unwrap();
        assert_eq!(meta.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(meta.content_range.as_deref(), Some("bytes 100-199/1000"));
        assert_eq!(meta.content_length, Some(100));
        assert!(meta.accept_ranges);
        assert!(meta.include_body);
        assert_eq!(
            meta.range,
            Some(ResolvedRange {
                start: 100,
                end: 199,
                total: 1000
            })
        );
    }

    #[test]
    fn metadata_open_ended_is_206_spanning_to_last_byte() {
        // bytes=N- -> N..S-1, 206 (Req 37.15).
        let spec = RangeSpec::parse("bytes=250-").unwrap();
        let meta = compute_response_metadata(&spec, Some(1000), false).unwrap();
        assert_eq!(meta.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(meta.content_range.as_deref(), Some("bytes 250-999/1000"));
        assert_eq!(meta.content_length, Some(750));
    }

    #[test]
    fn metadata_suffix_is_206_spanning_last_n_bytes() {
        // bytes=-N -> max(0,S-N)..S-1, 206 (Req 37.16).
        let spec = RangeSpec::parse("bytes=-300").unwrap();
        let meta = compute_response_metadata(&spec, Some(1000), false).unwrap();
        assert_eq!(meta.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(meta.content_range.as_deref(), Some("bytes 700-999/1000"));
        assert_eq!(meta.content_length, Some(300));
    }

    // -- Response metadata: full body -> 200 (Req 5.1) ----------------------

    #[test]
    fn metadata_full_is_200_with_total_content_length() {
        let meta = compute_response_metadata(&RangeSpec::Full, Some(1000), false).unwrap();
        assert_eq!(meta.status, StatusCode::OK);
        assert_eq!(meta.content_range, None);
        assert_eq!(meta.content_length, Some(1000));
        assert!(meta.accept_ranges);
        assert_eq!(meta.range, None);
    }

    // -- Response metadata: unsatisfiable -> 416 (Req 5.5) ------------------

    #[test]
    fn metadata_unsatisfiable_range_is_416_with_star_content_range() {
        let spec = RangeSpec::parse("bytes=2000-3000").unwrap();
        let unsat = compute_response_metadata(&spec, Some(1000), false).unwrap_err();
        assert_eq!(unsat.content_range(), "bytes */1000");
        assert_eq!(unsat.to_app_error().http_status().as_u16(), 416);
    }

    // -- HEAD produces identical headers to GET, no body (Req 37.14) --------

    #[test]
    fn head_matches_get_headers_with_no_body_for_full() {
        let get = compute_response_metadata(&RangeSpec::Full, Some(1000), false).unwrap();
        let head = compute_response_metadata(&RangeSpec::Full, Some(1000), true).unwrap();
        // Identical header-bearing fields...
        assert_eq!(head.status, get.status);
        assert_eq!(head.content_range, get.content_range);
        assert_eq!(head.content_length, get.content_length);
        assert_eq!(head.accept_ranges, get.accept_ranges);
        // ...only the body differs.
        assert!(get.include_body);
        assert!(!head.include_body);
    }

    #[test]
    fn head_matches_get_headers_with_no_body_for_range() {
        let spec = RangeSpec::parse("bytes=100-199").unwrap();
        let get = compute_response_metadata(&spec, Some(1000), false).unwrap();
        let head = compute_response_metadata(&spec, Some(1000), true).unwrap();
        assert_eq!(head.status, get.status);
        assert_eq!(head.content_range, get.content_range);
        assert_eq!(head.content_length, get.content_length);
        assert_eq!(head.accept_ranges, get.accept_ranges);
        assert!(!head.include_body);
    }

    // -- Accept-Ranges advertised whenever the size is known (Req 37.17) ----

    #[test]
    fn accept_ranges_advertised_whenever_size_known() {
        // Full body, size known.
        assert!(
            compute_response_metadata(&RangeSpec::Full, Some(1000), false)
                .unwrap()
                .accept_ranges
        );
        // Partial, size known.
        let spec = RangeSpec::parse("bytes=0-99").unwrap();
        assert!(
            compute_response_metadata(&spec, Some(1000), false)
                .unwrap()
                .accept_ranges
        );
        // HEAD, size known.
        assert!(
            compute_response_metadata(&RangeSpec::Full, Some(1000), true)
                .unwrap()
                .accept_ranges
        );
    }

    #[test]
    fn accept_ranges_not_advertised_when_size_unknown() {
        let meta = compute_response_metadata(&RangeSpec::Full, None, false).unwrap();
        assert!(!meta.accept_ranges);
        assert_eq!(meta.status, StatusCode::OK);
        assert_eq!(meta.content_length, None);
        assert!(meta.include_body);
    }

    #[test]
    fn unknown_size_head_has_no_body_but_same_headers() {
        let get = compute_response_metadata(&RangeSpec::Full, None, false).unwrap();
        let head = compute_response_metadata(&RangeSpec::Full, None, true).unwrap();
        assert_eq!(head.status, get.status);
        assert_eq!(head.content_length, get.content_length);
        assert_eq!(head.accept_ranges, get.accept_ranges);
        assert!(!head.include_body);
    }
}
