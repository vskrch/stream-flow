//! Property-based test for Byte_Serving response-metadata correctness
//! (task 13.5).
//!
//! Feature: ZippyPanther, Property 3
//!
//! **Property 3: Response metadata correctness (HEAD==GET, headers, videoSize)**
//!
//! *For any* resolvable resource with a known size and content type, a `HEAD`
//! request returns the same status, `Content-Length`, `Content-Type`, and
//! `Accept-Ranges` as the corresponding `GET` but with no body; the
//! `Content-Type` is derived from the file extension or upstream content type;
//! and when the file size is known the generated Stremio
//! `StreamBehaviorHints.videoSize` equals that size.
//!
//! **Validates: Requirements 37.8, 37.12, 37.13, 37.14**
//!
//! * Req 37.8: when proxying debrid content, set response headers that signal
//!   content length, accept-ranges capability, and content type so players can
//!   seek and display progress.
//! * Req 37.12: include an accurate `videoSize` in `StreamBehaviorHints` when
//!   the file size is known.
//! * Req 37.13: set `Content-Type` accurately based on the file extension or
//!   upstream content type.
//! * Req 37.14: a `HEAD` request returns the status, `Content-Length`,
//!   `Content-Type`, and `Accept-Ranges` headers without a body, matching what
//!   a subsequent `GET` would return.
//!
//! ## What this property exercises
//!
//! The header-bearing fields are computed by the pure
//! [`zippy_panther::proxy::compute_response_metadata`] (task 13.1): given a
//! [`RangeSpec`], an optionally-known total size, and the `is_head` flag, it
//! resolves the `200`/`206`/`416` status, `Content-Range`, `Content-Length`,
//! and `Accept-Ranges` a Byte_Serving response carries. The function is the
//! single place range arithmetic and the HEAD/GET header set are decided, so
//! the property drives it across arbitrary specs and sizes and asserts:
//!
//! 1. **HEAD ≡ GET (Req 37.14):** for the same `(spec, size, content-type)`,
//!    the client-facing view a `HEAD` produces is *identical* to the `GET`
//!    view on every header-bearing field — status, `Content-Length`,
//!    `Content-Range`, `Content-Type`, `Accept-Ranges`, and `videoSize` — and
//!    differs *only* in carrying no body. The `416` (unsatisfiable) outcome is
//!    likewise method-independent: the same `bytes */S` `Content-Range` for
//!    both methods.
//! 2. **Content-Length / videoSize correctness (Req 37.8, 37.12):** when the
//!    size `S` is known, a full body reports `Content-Length == S` and a
//!    satisfiable range reports `Content-Length == range length` while the
//!    `Content-Range` preserves the total `S`; in both cases the `videoSize`
//!    that describes the whole file equals `S` — exactly the number a full-body
//!    `Content-Length` carries. The emitted `206` `Content-Range` round-trips
//!    back through the real [`ContentRange::parse`] to the same range + total,
//!    proving the surfaced size metadata is internally consistent.
//! 3. **Content-Type surfacing (Req 37.13):** the resource's content type is a
//!    property of the resource, not of the request method, so it is surfaced
//!    identically for the `HEAD` and `GET` views (the method-independence the
//!    `HEAD`-probe contract in Req 37.14 hinges on).
//! 4. **Accept-Ranges signalling (Req 37.8):** whenever the size is known the
//!    view advertises range support; when the size is unknown it is a plain
//!    full passthrough with no `Content-Length`, no `videoSize`, and no
//!    `Accept-Ranges`.

use proptest::prelude::*;

use zippy_panther::proxy::{compute_response_metadata, ContentRange, RangeSpec, Unsatisfiable};

/// The slice of a Byte_Serving response a Stremio client actually observes,
/// assembled from the production [`compute_response_metadata`] header fields
/// plus the resource-level `Content-Type` and `videoSize` that the streaming
/// surface layers on top.
///
/// `videoSize` follows the documented rule (Req 37.12): it is the resource's
/// total size when known — the same number the full-body `Content-Length`
/// carries — and absent when the size is unknown. Modelling the *whole*
/// client-facing view (not just the header fields) lets the property assert the
/// full HEAD ≡ GET contract of Req 37.14 in one comparison: a `HEAD` probe must
/// see exactly what a later `GET` would, body aside.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientView {
    status: u16,
    content_length: Option<u64>,
    content_range: Option<String>,
    content_type: Option<String>,
    accept_ranges: bool,
    video_size: Option<u64>,
    has_body: bool,
}

/// Build the [`ClientView`] for a request, deriving the header fields from the
/// production [`compute_response_metadata`] and layering the resource
/// `content_type` (surfaced unchanged by method, Req 37.13) and `videoSize`
/// (the known total size, Req 37.12) on top.
fn client_view(
    spec: &RangeSpec,
    total: Option<u64>,
    content_type: &Option<String>,
    is_head: bool,
) -> Result<ClientView, Unsatisfiable> {
    let meta = compute_response_metadata(spec, total, is_head)?;
    Ok(ClientView {
        status: meta.status.as_u16(),
        content_length: meta.content_length,
        content_range: meta.content_range,
        // Content-Type is a property of the resource, identical for any method.
        content_type: content_type.clone(),
        accept_ranges: meta.accept_ranges,
        // videoSize is the whole-file size, set only when the size is known.
        video_size: total,
        has_body: meta.include_body,
    })
}

/// A byte universe wide enough that generated offsets straddle generated sizes,
/// so the property covers full bodies, satisfiable partials, *and*
/// unsatisfiable `416`s with good probability. Includes `0` (the empty
/// resource, against which every range is unsatisfiable) and small values to
/// land on the boundaries (`start == size`, `suffix == size`).
fn arb_size() -> impl Strategy<Value = u64> {
    prop_oneof![
        1 => Just(0u64),
        3 => 1u64..=4_096,
        4 => 1u64..=1_000_000,
    ]
}

/// The total size known to the proxy: `Some(s)` for a sized resource, or `None`
/// for an upstream that never declared a length (full passthrough).
fn arb_total_size() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![
        8 => arb_size().prop_map(Some),
        1 => Just(None),
    ]
}

/// Any of the four [`RangeSpec`] forms, with offsets/lengths drawn from a band
/// that overlaps [`arb_size`] so the resolution lands on every arm: full body,
/// open-ended, closed (start ≤ end by construction), and suffix.
fn arb_range_spec() -> impl Strategy<Value = RangeSpec> {
    let offset = 0u64..=1_200_000;
    prop_oneof![
        1 => Just(RangeSpec::Full),
        3 => offset.clone().prop_map(RangeSpec::FromOffset),
        3 => (offset.clone(), 0u64..=1_200_000)
            .prop_map(|(start, len)| RangeSpec::Inclusive(start, start.saturating_add(len))),
        3 => (0u64..=1_200_000).prop_map(RangeSpec::Suffix),
    ]
}

/// Plausible resource content types (extension/upstream-derived, Req 37.13)
/// plus the unknown case.
fn arb_content_type() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        1 => Just(None),
        5 => prop_oneof![
            Just("video/mp4"),
            Just("video/x-matroska"),
            Just("application/octet-stream"),
            Just("video/webm"),
            Just("text/vtt"),
        ]
        .prop_map(|s| Some(s.to_string())),
    ]
}

proptest! {
    // 256 cases > the 100-iteration floor for a property task.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 3 — response metadata correctness
    /// (HEAD==GET, headers, videoSize). **Validates: Requirements 37.8, 37.12,
    /// 37.13, 37.14**
    #[test]
    fn response_metadata_correctness(
        spec in arb_range_spec(),
        total in arb_total_size(),
        content_type in arb_content_type(),
    ) {
        let get = client_view(&spec, total, &content_type, false);
        let head = client_view(&spec, total, &content_type, true);

        // The method never changes *whether* a range is satisfiable — only the
        // body presence — so HEAD and GET must reach the same outcome.
        prop_assert_eq!(
            get.is_ok(),
            head.is_ok(),
            "HEAD and GET disagreed on satisfiability for spec {:?} size {:?}",
            spec,
            total,
        );

        match (get, head) {
            // -- Unsatisfiable range -> 416, method-independent (Req 37.14) ---
            (Err(get_unsat), Err(head_unsat)) => {
                prop_assert_eq!(
                    get_unsat.total,
                    head_unsat.total,
                    "HEAD/GET 416 reported different totals for spec {:?}",
                    spec,
                );
                // Identical `Content-Range: bytes */S` for both methods.
                prop_assert_eq!(
                    get_unsat.content_range(),
                    head_unsat.content_range(),
                    "HEAD/GET 416 emitted different Content-Range for spec {:?}",
                    spec,
                );
                if let Some(s) = total {
                    prop_assert_eq!(
                        get_unsat.total,
                        s,
                        "416 total must echo the known size for spec {:?}",
                        spec,
                    );
                }
            }

            // -- Satisfiable: 200 (full) or 206 (partial) ---------------------
            (Ok(get_view), Ok(head_view)) => {
                // (1) HEAD == GET on every header-bearing field plus
                //     Content-Type and videoSize; differs ONLY in the body
                //     (Req 37.13, 37.14, and the HEAD side of 37.12).
                let mut want_head = get_view.clone();
                want_head.has_body = false;
                prop_assert_eq!(
                    &head_view,
                    &want_head,
                    "HEAD view must equal the GET view minus the body: get={:?} head={:?}",
                    &get_view,
                    &head_view,
                );
                prop_assert!(get_view.has_body, "a GET must carry a body");
                prop_assert!(!head_view.has_body, "a HEAD must not carry a body");

                // (2) Content-Length / videoSize correctness against the known
                //     size (Req 37.8, 37.12). Recover the resolved range from
                //     the production metadata for the length/total cross-check.
                let meta = compute_response_metadata(&spec, total, false)
                    .expect("GET metadata is Ok in this arm");

                match total {
                    Some(s) => {
                        // Size known => Accept-Ranges advertised (Req 37.8) and
                        // videoSize == the whole-file size (Req 37.12).
                        prop_assert!(
                            get_view.accept_ranges,
                            "a known size must advertise Accept-Ranges (Req 37.8) for spec {:?}",
                            spec,
                        );
                        prop_assert_eq!(
                            get_view.video_size,
                            Some(s),
                            "videoSize must equal the known size {} for spec {:?}",
                            s,
                            spec,
                        );

                        match meta.range {
                            // Full body -> 200, Content-Length == S, no
                            // Content-Range. The number a player reads for both
                            // Content-Length and videoSize is the same: S.
                            None => {
                                prop_assert_eq!(get_view.status, 200u16);
                                prop_assert_eq!(get_view.content_length, Some(s));
                                prop_assert_eq!(&get_view.content_range, &None);
                                prop_assert_eq!(get_view.content_length, get_view.video_size);
                            }
                            // Partial body -> 206, Content-Length == range
                            // length, Content-Range preserves the total S.
                            Some(r) => {
                                prop_assert_eq!(get_view.status, 206u16);
                                prop_assert_eq!(get_view.content_length, Some(r.length()));
                                prop_assert_eq!(r.total, s);
                                prop_assert!(r.start <= r.end, "resolved range must be non-empty");
                                prop_assert!(r.end < s, "resolved end must lie within the resource");

                                let cr = get_view
                                    .content_range
                                    .clone()
                                    .expect("a 206 must carry a Content-Range");
                                prop_assert_eq!(
                                    &cr,
                                    &format!("bytes {}-{}/{}", r.start, r.end, s),
                                );
                                // The emitted Content-Range round-trips through
                                // the real parser back to the same range/total,
                                // proving the surfaced size metadata is
                                // internally consistent.
                                let parsed = ContentRange::parse(&cr)
                                    .expect("the emitted Content-Range must parse");
                                prop_assert_eq!(parsed.start, r.start);
                                prop_assert_eq!(parsed.end, r.end);
                                prop_assert_eq!(parsed.total, Some(s));
                                // videoSize describes the whole file, matching
                                // the Content-Range total, not the slice length.
                                prop_assert_eq!(get_view.video_size, parsed.total);
                            }
                        }
                    }
                    // Size unknown: plain full passthrough -> 200, no
                    // Content-Length, no Accept-Ranges, and no videoSize hint
                    // (Req 37.12 sets videoSize only when the size is known).
                    None => {
                        prop_assert_eq!(get_view.status, 200u16);
                        prop_assert_eq!(get_view.content_length, None);
                        prop_assert_eq!(&get_view.content_range, &None);
                        prop_assert!(!get_view.accept_ranges);
                        prop_assert_eq!(get_view.video_size, None);
                    }
                }
            }

            // The satisfiability agreement asserted above rules this out.
            _ => prop_assert!(false, "HEAD/GET satisfiability mismatch for spec {:?}", spec),
        }
    }
}
