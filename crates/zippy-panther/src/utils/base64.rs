//! Base64 encode / decode / check utilities (`utils::base64`) — Req 15.3,
//! 15.4, 15.5, 15.6, 15.9.
//!
//! Three operator-facing helpers backing the mediaflow `/base64/*` surface:
//!
//! * [`encode`] returns the canonical **standard** base64 encoding of the input
//!   bytes (Req 15.3).
//! * [`decode`] decodes a base64 string back to bytes (Req 15.4); it is
//!   **lenient** — it accepts the standard and URL-safe alphabets in both
//!   padded and unpadded forms (mirroring [`epg`](crate::epg)'s upstream-URL
//!   decoding) so a token produced by either convention round-trips, and a
//!   string that is not valid base64 under *any* of them is rejected with a
//!   descriptive [`AppError`] (Req 15.9).
//! * [`is_valid`] reports whether the input is valid base64 (Req 15.5).
//!
//! Because [`encode`] emits standard base64 and [`decode`] tries the standard
//! alphabet first, `decode(encode(x)) == x` for every byte input — the
//! round-trip property (Req 15.6, Property 7, exercised by task 20.3).

use actix_web::{web, HttpResponse};

use crate::errors::AppError;

// The four common base64 flavours, tried in order by `decode` (standard first
// so an `encode` output always round-trips through the standard alphabet).
use ::base64::engine::general_purpose::GeneralPurpose;
use ::base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ::base64::Engine as _;

/// Standard-base64-encode `input` (Req 15.3).
///
/// Operates on raw bytes so any payload (text or binary) encodes losslessly;
/// the produced string uses the canonical `+`/`/` alphabet with `=` padding.
pub fn encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decode a base64 string back to bytes (Req 15.4), or a descriptive
/// [`AppError`] when the input is not valid base64 (Req 15.9).
///
/// Lenient on the alphabet: the standard and URL-safe encodings, each in padded
/// and unpadded form, are all accepted (the standard alphabet is tried first so
/// an [`encode`] output decodes back to the exact original bytes — Req 15.6).
pub fn decode(input: &str) -> Result<Vec<u8>, AppError> {
    const ENGINES: [GeneralPurpose; 4] = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD];
    for engine in ENGINES {
        if let Ok(bytes) = engine.decode(input.as_bytes()) {
            return Ok(bytes);
        }
    }
    Err(AppError::bad_request(format!(
        "invalid base64 input: `{}` is not valid base64",
        truncate_for_message(input)
    )))
}

/// Whether `input` is valid base64 under any of the accepted alphabets
/// (Req 15.5).
pub fn is_valid(input: &str) -> bool {
    decode(input).is_ok()
}

/// Cap an echoed input in an error message so a huge body cannot bloat the
/// response (and so the message stays a non-secret, bounded description).
fn truncate_for_message(input: &str) -> String {
    const MAX: usize = 64;
    if input.chars().count() <= MAX {
        input.to_string()
    } else {
        let head: String = input.chars().take(MAX).collect();
        format!("{head}…")
    }
}

// ---------------------------------------------------------------------------
// HTTP handlers — mediaflow `/base64/{encode,decode,check}`
// ---------------------------------------------------------------------------

/// Query string for the base64 endpoints: `?value=<text-or-base64>`.
#[derive(Debug, serde::Deserialize)]
pub struct Base64Query {
    /// The value to operate on: the plaintext for `encode`, the base64 string
    /// for `decode` / `check`.
    pub value: Option<String>,
}

impl Base64Query {
    /// Borrow the required `value`, or a descriptive `400` when it is absent.
    fn require_value(&self) -> Result<&str, AppError> {
        self.value
            .as_deref()
            .ok_or_else(|| AppError::bad_request("missing required `value` query parameter"))
    }
}

/// `GET /base64/encode?value=<text>` — return the base64 encoding of the
/// (UTF-8 bytes of the) input (Req 15.3).
pub async fn base64_encode_endpoint(
    query: web::Query<Base64Query>,
) -> Result<HttpResponse, AppError> {
    let value = query.require_value()?;
    let encoded = encode(value.as_bytes());
    Ok(HttpResponse::Ok().json(serde_json::json!({ "value": value, "encoded": encoded })))
}

/// `GET /base64/decode?value=<base64>` — return the decoded value (Req 15.4),
/// or a descriptive error on invalid input (Req 15.9).
///
/// The decoded bytes are surfaced as a (lossy) UTF-8 string in the JSON body —
/// these utilities are text-oriented (URLs, tokens); the byte-exact decode
/// lives in [`decode`].
pub async fn base64_decode_endpoint(
    query: web::Query<Base64Query>,
) -> Result<HttpResponse, AppError> {
    let value = query.require_value()?;
    let bytes = decode(value)?;
    let decoded = String::from_utf8_lossy(&bytes).into_owned();
    Ok(HttpResponse::Ok().json(serde_json::json!({ "encoded": value, "decoded": decoded })))
}

/// `GET /base64/check?value=<maybe-base64>` — report whether the input is valid
/// base64 (Req 15.5).
pub async fn base64_check_endpoint(
    query: web::Query<Base64Query>,
) -> Result<HttpResponse, AppError> {
    let value = query.require_value()?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "value": value, "valid": is_valid(value) })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;

    // -- Req 15.3: encode ----------------------------------------------------

    #[test]
    fn encode_matches_known_standard_base64_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"hello"), "aGVsbG8=");
    }

    // -- Req 15.4: decode valid input ----------------------------------------

    #[test]
    fn decode_recovers_known_vectors() {
        assert_eq!(decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn decode_accepts_url_safe_and_unpadded_forms() {
        // The bytes 0xFB 0xFF 0xBF encode to "+/+/" (standard) / "-_-_" (url-safe).
        let raw = [0xFBu8, 0xFF, 0xBF];
        let std_padded = encode(&raw); // standard, padded
        assert_eq!(decode(&std_padded).unwrap(), raw);

        // URL-safe (the standard '+'/'/' become '-'/'_'), padded and unpadded.
        assert_eq!(decode("-_-_").unwrap(), raw);
        // Unpadded standard.
        assert_eq!(decode("Zm8").unwrap(), b"fo");
    }

    // -- Req 15.6: round trip (specific examples; Property 7 is task 20.3) ----

    #[test]
    fn decode_is_left_inverse_of_encode_for_sample_inputs() {
        for sample in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"the quick brown fox"[..],
            &[0u8, 1, 2, 250, 251, 252, 253, 254, 255][..],
        ] {
            assert_eq!(decode(&encode(sample)).unwrap(), sample);
        }
    }

    // -- Req 15.5: check -----------------------------------------------------

    #[test]
    fn is_valid_accepts_base64_and_rejects_garbage() {
        assert!(is_valid("aGVsbG8="));
        assert!(is_valid("Zm9v"));
        assert!(is_valid(""), "the empty string is valid (decodes to empty)");
        // '*' is in no base64 alphabet.
        assert!(!is_valid("not*valid*base64"));
        // A length that cannot be valid base64 (one leftover char).
        assert!(!is_valid("aGVsbG8=x@"));
    }

    // -- Req 15.9: invalid decode -> descriptive error -----------------------

    #[test]
    fn decode_rejects_invalid_input_with_a_descriptive_bad_request() {
        let err = decode("%%%not-base64%%%").unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
        assert!(
            err.message.contains("not valid base64"),
            "error must describe the failure, got: {}",
            err.message
        );
    }

    #[test]
    fn decode_error_message_is_bounded_for_huge_inputs() {
        let huge = "*".repeat(10_000);
        let err = decode(&huge).unwrap_err();
        // The echoed value is truncated, so the message stays small.
        assert!(
            err.message.len() < 200,
            "message must be bounded, got {} chars",
            err.message.len()
        );
    }
}
