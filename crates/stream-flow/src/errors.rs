//! Canonical error taxonomy (`errors`) — Req 16.10, 47.1, 47.2, 47.6.
//!
//! There is exactly **one** error type that crosses module boundaries
//! ([`AppError`]), **one** canonical category enum ([`ErrorCategory`]), and
//! **one** serialized body ([`ErrorResponse`]) returned by every endpoint
//! (design: Error Handling → Principle). No fallible operation produces a
//! crash, hang, or silent incorrect result — everything maps onto this
//! taxonomy.
//!
//! This module owns the *types*, the category → HTTP-status mapping
//! ([`AppError::http_status`]), the serialized shape, and the ergonomic
//! constructors. The actix `ResponseError` impl and the panic-catching
//! middleware are intentionally **not** here — they land in task 2.2 (design:
//! Error Handling → Panic boundary).
//!
//! ## Category → HTTP status (design: Error Handling → Canonical taxonomy)
//!
//! | [`ErrorCategory`]        | HTTP    |
//! |--------------------------|---------|
//! | `InvalidStoreName`       | 400     |
//! | `BadRequest`             | 400     |
//! | `Unauthorized`           | 401     |
//! | `PaymentRequired`        | 402     |
//! | `Forbidden`              | 403     |
//! | `NotFound`               | 404     |
//! | `PayloadTooLarge`        | 413     |
//! | `RangeNotSatisfiable`    | 416     |
//! | `TooManyRequests`        | 429     |
//! | `StoreLimitExceeded`     | 429     |
//! | `InfringingContent`      | 451     |
//! | `HosterUnavailable`      | 502     |
//! | `UpstreamUnavailable`    | 503/504 |
//! | `Unknown`                | 500     |
//!
//! `UpstreamUnavailable` is `504 Gateway Timeout` when the
//! [`deadline_exceeded`](AppError::deadline_exceeded) marker is set (a
//! request-scoped deadline elapsed — Req 50.9, 35.4) and `503 Service
//! Unavailable` otherwise. `StoreLimitExceeded` and `TooManyRequests` both
//! surface as `429` but stay **distinct categories** so account-limit and
//! rate-limit are never conflated (Req 16.12, 20.1). `Forbidden` carries an
//! [`ip_restricted`](AppError::ip_restricted) flag so an IP-cause `403` is
//! distinguishable from a generic one (Req 16.13).

use std::time::Duration;

use actix_web::http::StatusCode;

/// The canonical category every failure is mapped onto (Req 16.10, 47.1).
///
/// The [`Display`](std::fmt::Display) string of each variant is the stable
/// machine-readable `code` emitted in the serialized [`ErrorBody`] (e.g.
/// `"store-limit-exceeded"`), so it is part of the wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErrorCategory {
    /// Unknown store name or `Store_Code` (Req 16.7). → `400`
    #[error("invalid-store-name")]
    InvalidStoreName,
    /// Missing/incorrect credentials (Req 16.8, 28.1). → `401`
    #[error("unauthorized")]
    Unauthorized,
    /// Access denied, including IP-restriction (Req 16.13, 28.3). → `403`
    #[error("forbidden")]
    Forbidden,
    /// Debrid plan expired (Req 16.10). → `402`
    #[error("payment-required")]
    PaymentRequired,
    /// Resource absent (Req 6.10, 26.3). → `404`
    #[error("not-found")]
    NotFound,
    /// Per-account active-download / traffic / fair-usage cap (Req 16.12,
    /// 20.1) — distinct from a rate limit. → `429`
    #[error("store-limit-exceeded")]
    StoreLimitExceeded,
    /// Legally unavailable / infringing file (Req 16.11). → `451`
    #[error("infringing-content")]
    InfringingContent,
    /// Hoster down, or extractor/hoster circuit open (Req 16.10, 50.2). → `502`
    #[error("hoster-unavailable")]
    HosterUnavailable,
    /// Rate limit hit (Req 40.3) — distinct from an account cap. → `429`
    #[error("too-many-requests")]
    TooManyRequests,
    /// Upstream unreachable/timed out, resilient resume exhausted, store/CDN/
    /// Redis circuit open, or deadline exceeded (Req 16.9, 37.5, 50.2, 50.9).
    /// → `503` (or `504` when `deadline_exceeded`).
    #[error("upstream-unavailable")]
    UpstreamUnavailable,
    /// Invalid client input (Req 17.10, 47.4). → `400`
    #[error("bad-request")]
    BadRequest,
    /// Request/response body exceeds the configured cap (Req 46.4). → `413`
    #[error("payload-too-large")]
    PayloadTooLarge,
    /// Requested byte range unsatisfiable (Req 5.5). → `416`
    #[error("range-not-satisfiable")]
    RangeNotSatisfiable,
    /// Panic boundary or any unclassified failure (Req 47.3). → `500`
    #[error("unknown")]
    Unknown,
}

impl ErrorCategory {
    /// The machine-readable `code` string for this category (its `Display`).
    ///
    /// Convenience over `category.to_string()` for the hot serialization path.
    pub fn code(self) -> String {
        self.to_string()
    }
}

/// The single typed error used across every endpoint (Req 47.1, 47.6).
///
/// Construct with a category shorthand (e.g. [`AppError::bad_request`]) or a
/// store-identifying constructor (e.g. [`AppError::upstream_unavailable_for`]),
/// then attach optional markers with the chainable `with_*` / `into_*`
/// builders.
#[derive(Debug, thiserror::Error)]
#[error("{category}: {message}")]
pub struct AppError {
    /// Canonical category driving the HTTP status and the `code` field.
    pub category: ErrorCategory,
    /// Human-readable, non-secret description (Req 47.1).
    pub message: String,
    /// Identifies the originating store, when applicable (Req 16.8, 16.9).
    pub store: Option<String>,
    /// The upstream HTTP status when one was received (Req 1.7, 8.7, 47.2).
    pub upstream_status: Option<u16>,
    /// `true` when a `Forbidden` was caused by an IP restriction (Req 16.13).
    pub ip_restricted: bool,
    /// Retry-After hint for `429` responses (Req 40.3).
    pub retry_after: Option<Duration>,
    /// `true` when a circuit breaker short-circuited the call (Req 50.2).
    /// For metrics/logs only — does **not** change the client status.
    pub circuit_open: bool,
    /// `true` when a request-scoped deadline elapsed (Req 50.9, 35.4).
    pub deadline_exceeded: bool,
}

impl AppError {
    /// Base constructor: a category plus a human-readable message, all markers
    /// cleared.
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
            store: None,
            upstream_status: None,
            ip_restricted: false,
            retry_after: None,
            circuit_open: false,
            deadline_exceeded: false,
        }
    }

    // -- Category shorthands -------------------------------------------------

    /// `400` — unknown store name / code (Req 16.7).
    pub fn invalid_store_name(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::InvalidStoreName, message)
    }

    /// `400` — invalid client input (Req 47.4).
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::BadRequest, message)
    }

    /// `401` — missing/incorrect credentials (Req 28.1).
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Unauthorized, message)
    }

    /// `403` — access denied (Req 28.3).
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Forbidden, message)
    }

    /// `402` — Debrid plan expired (Req 16.10).
    pub fn payment_required(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::PaymentRequired, message)
    }

    /// `404` — resource absent (Req 6.10).
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::NotFound, message)
    }

    /// `451` — legally unavailable / infringing file (Req 16.11).
    pub fn infringing_content(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::InfringingContent, message)
    }

    /// `416` — requested byte range unsatisfiable (Req 5.5).
    pub fn range_not_satisfiable(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::RangeNotSatisfiable, message)
    }

    /// `413` — body exceeds the configured cap (Req 46.4).
    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::PayloadTooLarge, message)
    }

    /// `429` — rate limit hit (Req 40.3). Distinct from an account cap.
    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::TooManyRequests, message)
    }

    /// `429` — per-account active-download / traffic / fair-usage cap
    /// (Req 16.12, 20.1). Distinct from a rate limit.
    pub fn store_limit_exceeded(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::StoreLimitExceeded, message)
    }

    /// `502` — hoster down (Req 16.10).
    pub fn hoster_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::HosterUnavailable, message)
    }

    /// `503` — upstream unreachable/timed out (Req 16.9, 35.4).
    pub fn upstream_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::UpstreamUnavailable, message)
    }

    /// `500` — unclassified failure (Req 47.3).
    pub fn unknown(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Unknown, message)
    }

    // -- Store-identifying constructors -------------------------------------

    /// `401` identifying the store whose auth failed (Req 16.8).
    pub fn unauthorized_for(store: impl Into<String>, message: impl Into<String>) -> Self {
        Self::unauthorized(message).with_store(store)
    }

    /// `503` identifying the store that is unreachable/timed out (Req 16.9).
    pub fn upstream_unavailable_for(store: impl Into<String>, message: impl Into<String>) -> Self {
        Self::upstream_unavailable(message).with_store(store)
    }

    /// `403` identifying the store and flagging the IP-restriction cause
    /// (Req 16.13).
    pub fn ip_restricted_for(store: impl Into<String>, message: impl Into<String>) -> Self {
        Self::forbidden(message).with_store(store).with_ip_restricted()
    }

    // -- Chainable markers ---------------------------------------------------

    /// Attach the originating store identifier.
    pub fn with_store(mut self, store: impl Into<String>) -> Self {
        self.store = Some(store.into());
        self
    }

    /// Attach the upstream HTTP status that triggered this error (Req 47.2).
    pub fn with_upstream_status(mut self, status: u16) -> Self {
        self.upstream_status = Some(status);
        self
    }

    /// Attach a Retry-After hint (Req 40.3).
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Flag that a circuit breaker short-circuited the call (Req 50.2). The
    /// caller chooses the category (`UpstreamUnavailable` for store/CDN/Redis,
    /// `HosterUnavailable` for extractor/hoster); this only sets the marker.
    pub fn with_circuit_open(mut self) -> Self {
        self.circuit_open = true;
        self
    }

    /// Flag that a `Forbidden` was caused by an IP restriction (Req 16.13).
    pub fn with_ip_restricted(mut self) -> Self {
        self.ip_restricted = true;
        self
    }

    /// Re-map this error as a deadline-exceeded `UpstreamUnavailable`
    /// (Req 50.9, 35.4), preserving the message and store. Shares the
    /// `503/504` status family while staying distinct in metrics/logs.
    pub fn into_deadline_exceeded(mut self) -> Self {
        self.category = ErrorCategory::UpstreamUnavailable;
        self.deadline_exceeded = true;
        self
    }

    /// The HTTP status this error maps to (design: Canonical taxonomy table).
    pub fn http_status(&self) -> StatusCode {
        match self.category {
            ErrorCategory::InvalidStoreName | ErrorCategory::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCategory::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCategory::PaymentRequired => StatusCode::PAYMENT_REQUIRED,
            ErrorCategory::Forbidden => StatusCode::FORBIDDEN,
            ErrorCategory::NotFound => StatusCode::NOT_FOUND,
            ErrorCategory::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCategory::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
            ErrorCategory::TooManyRequests | ErrorCategory::StoreLimitExceeded => {
                StatusCode::TOO_MANY_REQUESTS
            }
            ErrorCategory::InfringingContent => StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            ErrorCategory::HosterUnavailable => StatusCode::BAD_GATEWAY,
            ErrorCategory::UpstreamUnavailable => {
                if self.deadline_exceeded {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }
            ErrorCategory::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Build the consistent serialized body for this error (Req 47.6).
    pub fn to_error_response(&self) -> ErrorResponse {
        ErrorResponse {
            error: ErrorBody {
                code: self.category.code(),
                message: self.message.clone(),
                store: self.store.clone(),
                upstream_status: self.upstream_status,
            },
        }
    }
}

impl From<&AppError> for ErrorResponse {
    fn from(err: &AppError) -> Self {
        err.to_error_response()
    }
}

/// The consistent serialized error envelope returned by every endpoint
/// (Req 47.6).
///
/// ```json
/// { "error": { "code": "store-limit-exceeded",
///              "message": "RealDebrid: active download limit reached",
///              "store": "realdebrid", "upstream_status": 429 } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErrorResponse {
    /// The single error body. Wrapped under `error` for a stable envelope.
    pub error: ErrorBody,
}

/// The body of an [`ErrorResponse`].
///
/// `code` and `message` are **always** present; `store` and `upstream_status`
/// are omitted from the JSON when absent (`omitempty` semantics).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErrorBody {
    /// The [`ErrorCategory`] string (e.g. `"bad-request"`).
    pub code: String,
    /// Human-readable, non-secret description.
    pub message: String,
    /// Originating store, omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// Upstream HTTP status, omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full category → HTTP-status mapping table (design: Error Handling →
    /// Canonical taxonomy). `UpstreamUnavailable` is tested in both the
    /// generic (`503`) and deadline (`504`) forms separately below.
    #[test]
    fn category_http_status_mapping_is_complete() {
        let cases = [
            (ErrorCategory::InvalidStoreName, 400),
            (ErrorCategory::BadRequest, 400),
            (ErrorCategory::Unauthorized, 401),
            (ErrorCategory::PaymentRequired, 402),
            (ErrorCategory::Forbidden, 403),
            (ErrorCategory::NotFound, 404),
            (ErrorCategory::PayloadTooLarge, 413),
            (ErrorCategory::RangeNotSatisfiable, 416),
            (ErrorCategory::TooManyRequests, 429),
            (ErrorCategory::StoreLimitExceeded, 429),
            (ErrorCategory::InfringingContent, 451),
            (ErrorCategory::HosterUnavailable, 502),
            (ErrorCategory::UpstreamUnavailable, 503),
            (ErrorCategory::Unknown, 500),
        ];
        for (category, expected) in cases {
            let err = AppError::new(category, "x");
            assert_eq!(
                err.http_status().as_u16(),
                expected,
                "category {category:?} should map to {expected}",
            );
        }
    }

    #[test]
    fn upstream_unavailable_is_503_without_deadline_and_504_with() {
        let generic = AppError::upstream_unavailable("upstream down");
        assert_eq!(generic.http_status(), StatusCode::SERVICE_UNAVAILABLE);

        let deadline = AppError::upstream_unavailable("slow").into_deadline_exceeded();
        assert_eq!(deadline.http_status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn category_code_strings_match_wire_contract() {
        assert_eq!(ErrorCategory::InvalidStoreName.code(), "invalid-store-name");
        assert_eq!(ErrorCategory::Unauthorized.code(), "unauthorized");
        assert_eq!(ErrorCategory::Forbidden.code(), "forbidden");
        assert_eq!(ErrorCategory::PaymentRequired.code(), "payment-required");
        assert_eq!(ErrorCategory::NotFound.code(), "not-found");
        assert_eq!(ErrorCategory::StoreLimitExceeded.code(), "store-limit-exceeded");
        assert_eq!(ErrorCategory::InfringingContent.code(), "infringing-content");
        assert_eq!(ErrorCategory::HosterUnavailable.code(), "hoster-unavailable");
        assert_eq!(ErrorCategory::TooManyRequests.code(), "too-many-requests");
        assert_eq!(ErrorCategory::UpstreamUnavailable.code(), "upstream-unavailable");
        assert_eq!(ErrorCategory::BadRequest.code(), "bad-request");
        assert_eq!(ErrorCategory::PayloadTooLarge.code(), "payload-too-large");
        assert_eq!(ErrorCategory::RangeNotSatisfiable.code(), "range-not-satisfiable");
        assert_eq!(ErrorCategory::Unknown.code(), "unknown");
    }

    #[test]
    fn display_combines_category_and_message() {
        let err = AppError::store_limit_exceeded("RealDebrid: active download limit reached");
        assert_eq!(
            err.to_string(),
            "store-limit-exceeded: RealDebrid: active download limit reached",
        );
    }

    #[test]
    fn error_body_serializes_code_and_message_always_and_omits_empty_fields() {
        let resp = AppError::bad_request("bad sid").to_error_response();
        let json = serde_json::to_value(&resp).unwrap();
        let body = &json["error"];

        // code + message always present.
        assert_eq!(body["code"], "bad-request");
        assert_eq!(body["message"], "bad sid");
        // store + upstream_status omitted when absent (omitempty).
        let obj = body.as_object().unwrap();
        assert!(!obj.contains_key("store"), "store must be omitted when None");
        assert!(
            !obj.contains_key("upstream_status"),
            "upstream_status must be omitted when None",
        );
    }

    #[test]
    fn error_body_includes_store_and_upstream_status_when_present() {
        let resp = AppError::store_limit_exceeded("RealDebrid: active download limit reached")
            .with_store("realdebrid")
            .with_upstream_status(429)
            .to_error_response();
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json["error"].as_object().unwrap();

        assert_eq!(obj["code"], "store-limit-exceeded");
        assert_eq!(obj["message"], "RealDebrid: active download limit reached");
        assert_eq!(obj["store"], "realdebrid");
        assert_eq!(obj["upstream_status"], 429);
    }

    #[test]
    fn error_response_round_trips_through_json() {
        let original = ErrorResponse {
            error: ErrorBody {
                code: "upstream-unavailable".into(),
                message: "RealDebrid unreachable".into(),
                store: Some("realdebrid".into()),
                upstream_status: Some(503),
            },
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ErrorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn error_response_deserializes_with_omitted_optional_fields() {
        let json = r#"{"error":{"code":"not-found","message":"missing"}}"#;
        let decoded: ErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.error.code, "not-found");
        assert_eq!(decoded.error.message, "missing");
        assert_eq!(decoded.error.store, None);
        assert_eq!(decoded.error.upstream_status, None);
    }

    #[test]
    fn ip_restricted_marker_sets_forbidden_store_and_flag() {
        let err = AppError::ip_restricted_for("realdebrid", "IP not allowed");
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert_eq!(err.http_status(), StatusCode::FORBIDDEN);
        assert!(err.ip_restricted);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
    }

    #[test]
    fn circuit_open_marker_is_set_without_changing_status() {
        let err = AppError::upstream_unavailable_for("realdebrid", "breaker open").with_circuit_open();
        assert!(err.circuit_open);
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        // The marker is for metrics/logs only — status is unchanged (503).
        assert_eq!(err.http_status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
    }

    #[test]
    fn deadline_exceeded_marker_remaps_category_and_sets_504() {
        let err = AppError::hoster_unavailable("slow control-plane call").into_deadline_exceeded();
        assert!(err.deadline_exceeded);
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.http_status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn retry_after_marker_is_carried() {
        let err = AppError::too_many_requests("rate limited").with_retry_after(Duration::from_secs(5));
        assert_eq!(err.retry_after, Some(Duration::from_secs(5)));
        assert_eq!(err.http_status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn upstream_status_marker_is_carried_and_serialized() {
        let err = AppError::not_found("gone").with_upstream_status(404);
        assert_eq!(err.upstream_status, Some(404));
        let resp = err.to_error_response();
        assert_eq!(resp.error.upstream_status, Some(404));
    }

    #[test]
    fn store_limit_and_too_many_requests_are_distinct_categories_sharing_429() {
        let account_cap = AppError::store_limit_exceeded("active downloads");
        let rate_limit = AppError::too_many_requests("rate limited");
        assert_ne!(account_cap.category, rate_limit.category);
        assert_eq!(account_cap.http_status(), rate_limit.http_status());
        assert_eq!(account_cap.http_status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn upstream_unavailable_for_identifies_store() {
        let err = AppError::upstream_unavailable_for("torbox", "connection reset");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.store.as_deref(), Some("torbox"));
        assert_eq!(err.http_status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
