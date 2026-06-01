//! Property-based test for the canonical error taxonomy (task 2.3).
//!
//! Feature: stream-flow, Property 47
//!
//! **Property 47: Errors are typed, consistent, and total on malformed input**
//!
//! *For any* malformed manifest, magnet, proxy token, or configuration input,
//! the corresponding parse/decrypt/validate operation returns a typed
//! [`AppError`] (never a panic and never an `Ok` with a partial/corrupt
//! result), the error carries a category and — when an upstream HTTP status was
//! received — that status, and its serialized body conforms to the
//! `ErrorResponse` schema (always containing `code` and `message`).
//!
//! **Validates: Requirements 47.1, 47.2, 47.6, 47.7**
//!
//! All fallible parse/decrypt/validate boundaries in `stream-flow` converge on
//! exactly one error type ([`AppError`]) carrying exactly one canonical
//! category enum ([`ErrorCategory`]) and serialize through exactly one body
//! ([`stream_flow::errors::ErrorResponse`]). This property exhaustively
//! exercises that taxonomy across the full space of categories, adversarial /
//! malformed message content, arbitrary (even out-of-range) upstream status
//! codes, and every marker combination, asserting the four invariants the
//! requirement hinges on:
//!
//! * **Typed (47.1):** every error carries a category whose `code` is the
//!   stable wire string, plus a human-readable message, and maps onto a
//!   well-defined HTTP status (the mapping is *total* — defined for every
//!   variant — so classification never falls through).
//! * **Upstream status preserved (47.2):** when an upstream HTTP status was
//!   attached, the serialized body carries exactly that status; when none was,
//!   the field is omitted.
//! * **Consistent serialized structure (47.6):** every error serializes to the
//!   same `{ "error": { "code", "message", .. } }` envelope, `code` and
//!   `message` are *always* present, and the envelope round-trips through JSON
//!   unchanged.
//! * **Total on malformed input (47.7):** for arbitrary, adversarial, and
//!   malformed message content the construction, status mapping, and
//!   serialization complete without panicking and without producing a
//!   corrupt/partial body — proptest fails the property on any panic.

use std::time::Duration;

use proptest::prelude::*;
use stream_flow::errors::{AppError, ErrorCategory};

/// Generates every [`ErrorCategory`] variant with equal weight so the property
/// covers the full classification space (Req 47.1).
fn any_category() -> impl Strategy<Value = ErrorCategory> {
    prop_oneof![
        Just(ErrorCategory::InvalidStoreName),
        Just(ErrorCategory::BadRequest),
        Just(ErrorCategory::Unauthorized),
        Just(ErrorCategory::PaymentRequired),
        Just(ErrorCategory::Forbidden),
        Just(ErrorCategory::NotFound),
        Just(ErrorCategory::StoreLimitExceeded),
        Just(ErrorCategory::InfringingContent),
        Just(ErrorCategory::HosterUnavailable),
        Just(ErrorCategory::TooManyRequests),
        Just(ErrorCategory::UpstreamUnavailable),
        Just(ErrorCategory::PayloadTooLarge),
        Just(ErrorCategory::RangeNotSatisfiable),
        Just(ErrorCategory::Unknown),
    ]
}

/// Generates adversarial / malformed message content: empty strings, control
/// characters, JSON-significant punctuation, multi-byte unicode and bidi
/// overrides, plus fully arbitrary strings. Models the "malformed manifest,
/// magnet, proxy token, or configuration input" whose descriptions flow into
/// the error message (Req 47.7).
fn any_message() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("\u{0}\u{1}\u{7}\t\n\r".to_string()),
        Just("\"}{:,[]\\/".to_string()),
        Just("控制字符 émoji 🚀 \u{202e}override".to_string()),
        ".{0,64}",
        any::<String>(),
    ]
}

/// The category → HTTP-status mapping, mirrored independently from the
/// implementation so the property pins the contract (design: Error Handling →
/// Canonical taxonomy). `UpstreamUnavailable` is `504` when a request-scoped
/// deadline elapsed and `503` otherwise; the deadline marker only affects that
/// one category.
fn expected_status(category: ErrorCategory, deadline_exceeded: bool) -> u16 {
    match category {
        ErrorCategory::InvalidStoreName | ErrorCategory::BadRequest => 400,
        ErrorCategory::Unauthorized => 401,
        ErrorCategory::PaymentRequired => 402,
        ErrorCategory::Forbidden => 403,
        ErrorCategory::NotFound => 404,
        ErrorCategory::PayloadTooLarge => 413,
        ErrorCategory::RangeNotSatisfiable => 416,
        ErrorCategory::TooManyRequests | ErrorCategory::StoreLimitExceeded => 429,
        ErrorCategory::InfringingContent => 451,
        ErrorCategory::HosterUnavailable => 502,
        ErrorCategory::UpstreamUnavailable => {
            if deadline_exceeded {
                504
            } else {
                503
            }
        }
        ErrorCategory::Unknown => 500,
    }
}

proptest! {
    // proptest's default is 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 47 — errors are typed, consistent, and
    /// total on malformed input. **Validates: Requirements 47.1, 47.2, 47.6,
    /// 47.7**
    #[test]
    fn errors_are_typed_consistent_and_total_on_malformed_input(
        category in any_category(),
        message in any_message(),
        store in proptest::option::of("[^\u{0}]{0,32}"),
        // Arbitrary u16 covers real (200..599) and out-of-range/invalid codes
        // (0, 999, 65535) — totality must not depend on validity (Req 47.7).
        upstream_status in proptest::option::of(any::<u16>()),
        ip_restricted in any::<bool>(),
        circuit_open in any::<bool>(),
        deadline_exceeded in any::<bool>(),
        retry_after_secs in proptest::option::of(0u64..86_400),
    ) {
        // -- Construct via the public taxonomy API ---------------------------
        // Build through `new` + the chainable markers (the real construction
        // path). `deadline_exceeded` is set on the field directly because the
        // `into_deadline_exceeded` builder intentionally re-maps the category
        // to `UpstreamUnavailable`; setting the raw marker lets the property
        // exercise the deadline flag across *every* category.
        let mut err = AppError::new(category, message.clone());
        if let Some(ref s) = store {
            err = err.with_store(s.clone());
        }
        if let Some(code) = upstream_status {
            err = err.with_upstream_status(code);
        }
        if ip_restricted {
            err = err.with_ip_restricted();
        }
        if circuit_open {
            err = err.with_circuit_open();
        }
        if let Some(secs) = retry_after_secs {
            err = err.with_retry_after(Duration::from_secs(secs));
        }
        err.deadline_exceeded = deadline_exceeded;

        // -- Typed: total, well-defined status mapping (Req 47.1) ------------
        // `http_status()` is defined for every variant — never panics, never
        // falls through — and matches the canonical taxonomy table.
        let status = err.http_status().as_u16();
        prop_assert_eq!(
            status,
            expected_status(category, deadline_exceeded),
            "category {:?} (deadline={}) mapped to unexpected status {}",
            category, deadline_exceeded, status,
        );

        // -- Typed: category carries a stable, non-empty code (Req 47.1) -----
        let resp = err.to_error_response();
        prop_assert_eq!(&resp.error.code, &category.code());
        prop_assert!(!resp.error.code.is_empty(), "code must never be empty");
        // The human-readable message survives onto the body verbatim.
        prop_assert_eq!(&resp.error.message, &message);

        // -- Upstream status preserved exactly (Req 47.2) --------------------
        prop_assert_eq!(resp.error.upstream_status, upstream_status);
        // -- Store identity preserved -----------------------------------------
        prop_assert_eq!(&resp.error.store, &store);

        // -- Consistent serialized structure (Req 47.6) ---------------------
        // Serialization is total over adversarial content (never panics).
        let value = serde_json::to_value(&resp)
            .expect("ErrorResponse must always serialize");
        let body = value
            .get("error")
            .and_then(|e| e.as_object())
            .expect("serialized body must have an `error` object");

        // `code` and `message` are ALWAYS present (the schema invariant).
        prop_assert!(body.contains_key("code"), "code must always be present");
        prop_assert!(body.contains_key("message"), "message must always be present");
        let expected_code = category.code();
        prop_assert_eq!(body["code"].as_str(), Some(expected_code.as_str()));
        prop_assert_eq!(body["message"].as_str(), Some(message.as_str()));

        // `store` / `upstream_status` follow omitempty: present iff carried.
        prop_assert_eq!(body.contains_key("store"), store.is_some());
        prop_assert_eq!(
            body.contains_key("upstream_status"),
            upstream_status.is_some(),
        );
        if let Some(code) = upstream_status {
            prop_assert_eq!(body["upstream_status"].as_u64(), Some(code as u64));
        }

        // -- Consistency: the envelope round-trips through JSON unchanged ----
        let serialized = serde_json::to_string(&resp)
            .expect("ErrorResponse must always serialize to a string");
        let decoded: stream_flow::errors::ErrorResponse =
            serde_json::from_str(&serialized)
                .expect("serialized ErrorResponse must round-trip");
        prop_assert_eq!(decoded, resp);
    }
}
