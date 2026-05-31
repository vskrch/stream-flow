//! Base64 utilities (`utils::base64util`) — Req 15.3, 15.4, 15.5, 15.6, 15.9.
//!
//! Three pure helpers back the mediaflow-style `/base64/*` endpoints:
//!
//! * [`encode_base64`] returns the base64 encoding of an arbitrary byte input
//!   (Req 15.3).
//! * [`decode_base64`] decodes valid base64 back to the original bytes
//!   (Req 15.4) and rejects invalid input with a descriptive
//!   [`AppError`] (`400`, Req 15.9).
//! * [`is_valid_base64`] reports whether an input is well-formed base64
//!   (Req 15.5) without allocating the decoded value when the caller only
//!   needs the predicate.
//!
//! The encode/decode pair uses the **standard** base64 alphabet with padding
//! (`base64::engine::general_purpose::STANDARD`) on both sides, so the
//! round-trip property holds for *any* byte input: `decode(encode(x)) == x`
//! (Req 15.6, Property 7). Validation accepts the same alphabet so
//! `is_valid_base64(encode(x))` is always `true`.

use actix_web::{web, HttpResponse};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

use crate::errors::AppError;

/// Encode arbitrary bytes as standard (padded) base64 (Req 15.3).
pub fn encode_base64(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decode a standard (padded) base64 string back to its original bytes
/// (Req 15.4).
///
/// Invalid base64 — a character outside the alphabet, bad padding, or a
/// truncated group — is rejected with a descriptive `400` [`AppError`]
/// (Req 15.9) rather than yielding a partial or incorrect value.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, AppError> {
    STANDARD
        .decode(input)
        .map_err(|e| AppError::bad_request(format!("invalid base64 input: {e}")))
}

/// `true` when `input` is well-formed standard base64 (Req 15.5).
///
/// Defined as "decoding succeeds"; the empty string is valid base64 (decodes
/// to the empty byte slice).
pub fn is_valid_base64(input: &str) -> bool {
    STANDARD.decode(input).is_ok()
}

// ---------------------------------------------------------------------------
// HTTP handlers — `/base64/encode|decode|check`
// ---------------------------------------------------------------------------

/// Query string for the base64 endpoints: `?value=<text>`.
#[derive(Debug, Deserialize)]
pub struct ValueQuery {
    /// The input the operation is applied to. For `encode`/`check` it is the
    /// literal text; for `decode` it is the base64 to decode.
    pub value: String,
}

/// `GET /base64/encode?value=<text>` → `{ "encoded": "<base64>" }` (Req 15.3).
///
/// Encodes the UTF-8 bytes of `value`.
pub async fn encode_endpoint(query: web::Query<ValueQuery>) -> HttpResponse {
    let encoded = encode_base64(query.value.as_bytes());
    HttpResponse::Ok().json(serde_json::json!({ "encoded": encoded }))
}

/// `GET /base64/decode?value=<base64>` → `{ "decoded": "<text>" }` (Req 15.4),
/// or a descriptive `400` for invalid base64 (Req 15.9).
///
/// The decoded bytes are returned as a UTF-8 string (lossily, so binary input
/// never fails the response), alongside the raw byte length.
pub async fn decode_endpoint(query: web::Query<ValueQuery>) -> Result<HttpResponse, AppError> {
    let bytes = decode_base64(&query.value)?;
    let decoded = String::from_utf8_lossy(&bytes).into_owned();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "decoded": decoded,
        "bytes": bytes.len(),
    })))
}

/// `GET /base64/check?value=<text>` → `{ "valid": <bool> }` (Req 15.5).
pub async fn check_endpoint(query: web::Query<ValueQuery>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "valid": is_valid_base64(&query.value) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;

    // -- encode (Req 15.3) ---------------------------------------------------

    #[test]
    fn encode_matches_standard_base64() {
        assert_eq!(encode_base64(b"hello"), "aGVsbG8=");
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
    }

    // -- decode (Req 15.4) ---------------------------------------------------

    #[test]
    fn decode_recovers_the_original_bytes() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("Zm9v").unwrap(), b"foo");
    }

    #[test]
    fn decode_handles_non_utf8_bytes() {
        // 0xFF 0x00 is not valid UTF-8 but is valid base64 to decode.
        let encoded = encode_base64(&[0xFF, 0x00, 0x10]);
        assert_eq!(decode_base64(&encoded).unwrap(), vec![0xFF, 0x00, 0x10]);
    }

    // -- invalid decode → descriptive error (Req 15.9) -----------------------

    #[test]
    fn decode_invalid_input_is_descriptive_bad_request() {
        // '*' is not in the standard base64 alphabet.
        let err = decode_base64("not*valid*base64").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
        assert!(
            err.message.to_lowercase().contains("base64"),
            "error should name the offending input class, got: {}",
            err.message
        );
    }

    #[test]
    fn decode_bad_padding_is_rejected() {
        // A single stray base64 char cannot form a valid group.
        assert!(decode_base64("A").is_err());
    }

    // -- check (Req 15.5) ----------------------------------------------------

    #[test]
    fn check_reports_validity() {
        assert!(is_valid_base64("aGVsbG8="));
        assert!(is_valid_base64(""), "empty string is valid base64");
        assert!(!is_valid_base64("not*valid"));
        assert!(!is_valid_base64("A"));
    }

    // -- round trip (Req 15.6) ----------------------------------------------

    #[test]
    fn round_trip_recovers_input_for_representative_bytes() {
        for input in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"the quick brown fox"[..],
            &[0u8, 1, 2, 250, 251, 255][..],
        ] {
            let encoded = encode_base64(input);
            assert!(is_valid_base64(&encoded), "encoded output must be valid base64");
            assert_eq!(decode_base64(&encoded).unwrap(), input, "round trip must recover {input:?}");
        }
    }

    // -- HTTP handlers -------------------------------------------------------

    #[actix_web::test]
    async fn encode_endpoint_returns_base64() {
        use actix_web::{test, web, App};
        let app = test::init_service(
            App::new().route("/base64/encode", web::get().to(encode_endpoint)),
        )
        .await;
        let req = test::TestRequest::get().uri("/base64/encode?value=hello").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["encoded"], "aGVsbG8=");
    }

    #[actix_web::test]
    async fn decode_endpoint_round_trips_and_rejects_invalid() {
        use actix_web::{test, web, App};
        let app = test::init_service(
            App::new().route("/base64/decode", web::get().to(decode_endpoint)),
        )
        .await;

        let ok = test::TestRequest::get()
            .uri("/base64/decode?value=aGVsbG8%3D")
            .to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, ok).await;
        assert_eq!(body["decoded"], "hello");

        let bad = test::TestRequest::get()
            .uri("/base64/decode?value=not*valid")
            .to_request();
        let resp = test::call_service(&app, bad).await;
        assert_eq!(resp.status().as_u16(), 400);
    }

    #[actix_web::test]
    async fn check_endpoint_reports_validity() {
        use actix_web::{test, web, App};
        let app = test::init_service(
            App::new().route("/base64/check", web::get().to(check_endpoint)),
        )
        .await;
        let valid = test::TestRequest::get().uri("/base64/check?value=Zm9v").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, valid).await;
        assert_eq!(body["valid"], true);
    }
}
