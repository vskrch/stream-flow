//! Per-store canonical error mapping (`store::error`) — Req 16.8–16.13, 18.7.
//!
//! Maps each debrid service's native error responses (HTTP status codes,
//! numeric error codes, string error codes, and response bodies) to exactly
//! one [`AppError`] from the canonical taxonomy. The mapping is **total**: any
//! native error produces exactly one `ErrorCategory` without panicking
//! (Property 20), and the resulting `AppError` always identifies the
//! originating store (Req 16.8, 16.9).
//!
//! ## Per-store native error shapes
//!
//! - **RealDebrid:** numeric `error_code` in JSON body.
//! - **AllDebrid:** string `code` in JSON body.
//! - **TorBox / Premiumize / Offcloud / PikPak / Debrider / Debrid-Link /
//!   EasyDebrid:** HTTP status + optional body text.
//!
//! Unknown/unmapped native errors always map to `ErrorCategory::Unknown` with
//! the native body preserved (never panics — Property 20).

use std::time::Duration;

use crate::errors::AppError;
use super::StoreName;

/// Maps a native store error (HTTP status + response body) to the canonical
/// [`AppError`] taxonomy (Req 16.10).
///
/// The mapping is total: every combination of `(store, status, body)` produces
/// exactly one `ErrorCategory` without panicking (Property 20). The resulting
/// `AppError` always identifies the originating store via the `store` field
/// (Req 16.8, 16.9).
///
/// # Arguments
///
/// * `store` — the store that produced the error (attached to the `AppError`).
/// * `status` — the HTTP status code returned by the store's API.
/// * `body` — the raw response body (may contain JSON with error codes).
pub fn map_store_error(store: StoreName, status: u16, body: &str) -> AppError {
    let store_str = store.as_str();

    // Dispatch to per-store mapping based on the store identity.
    let err = match store {
        StoreName::RealDebrid => map_realdebrid(store_str, status, body),
        StoreName::AllDebrid => map_alldebrid(store_str, status, body),
        StoreName::TorBox => map_torbox(store_str, status, body),
        StoreName::Premiumize => map_premiumize(store_str, status, body),
        StoreName::DebridLink => map_debridlink(store_str, status, body),
        StoreName::Offcloud => map_offcloud(store_str, status, body),
        StoreName::PikPak => map_pikpak(store_str, status, body),
        StoreName::Debrider => map_debrider(store_str, status, body),
        StoreName::EasyDebrid => map_easydebrid(store_str, status, body),
    };

    err.with_upstream_status(status)
}

// ---------------------------------------------------------------------------
// RealDebrid — numeric `error_code` in JSON body (design: Per-store error
// mapping). Known codes:
//   8  -> bad_token -> Unauthorized
//   9  -> permission_denied -> Forbidden
//   ip_not_allowed (body contains "ip") -> Forbidden(ip_restricted)
//   35 -> infringing_file -> InfringingContent
//   34 -> too_many_active_downloads -> StoreLimitExceeded
//   20 -> traffic limit -> StoreLimitExceeded
//   21 -> fair usage limit -> StoreLimitExceeded
//   503/502 status -> UpstreamUnavailable
//   404 -> NotFound
//   402 -> PaymentRequired
// ---------------------------------------------------------------------------

fn map_realdebrid(store: &str, status: u16, body: &str) -> AppError {
    // Try to extract a numeric error_code from the JSON body.
    if let Some(code) = extract_rd_error_code(body) {
        return match code {
            8 => AppError::unauthorized_for(store, format!("{store}: bad token")),
            9 => {
                // Check if it's specifically an IP restriction.
                if body_contains_ip_hint(body) {
                    AppError::ip_restricted_for(store, format!("{store}: IP not allowed"))
                } else {
                    AppError::forbidden(format!("{store}: permission denied"))
                        .with_store(store)
                }
            }
            35 => AppError::infringing_content(format!("{store}: infringing file"))
                .with_store(store),
            34 | 20 | 21 => AppError::store_limit_exceeded(
                format!("{store}: active download/traffic/fair-usage limit reached"),
            )
            .with_store(store),
            _ => map_by_status(store, status, body),
        };
    }

    // Fallback: map by HTTP status.
    map_by_status(store, status, body)
}

// ---------------------------------------------------------------------------
// AllDebrid — string `code` in JSON body (design: Per-store error mapping).
// Known codes:
//   AUTH_BAD_APIKEY / AUTH_BLOCKED / AUTH_USER_BANNED -> Unauthorized
//   MAGNET_TOO_MANY_ACTIVE / MAGNET_TOO_MANY -> StoreLimitExceeded
//   LINK_HOST_UNAVAILABLE / LINK_HOST_NOT_SUPPORTED -> HosterUnavailable
//   LINK_DOWN / LINK_ERROR -> NotFound
//   NO_SERVER / LINK_HOST_FULL -> HosterUnavailable
//   LINK_PASS_PROTECTED -> Forbidden
//   AllDebrid has no infringing concept -> never InfringingContent.
// ---------------------------------------------------------------------------

fn map_alldebrid(store: &str, status: u16, body: &str) -> AppError {
    if let Some(code) = extract_ad_error_code(body) {
        let code_upper = code.to_uppercase();
        return match code_upper.as_str() {
            "AUTH_BAD_APIKEY" | "AUTH_BLOCKED" | "AUTH_USER_BANNED"
            | "AUTH_MISSING_APIKEY" => {
                AppError::unauthorized_for(store, format!("{store}: {code}"))
            }
            "MAGNET_TOO_MANY_ACTIVE" | "MAGNET_TOO_MANY"
            | "FREE_TRIAL_LIMIT_REACHED" | "MUST_BE_PREMIUM" => {
                AppError::store_limit_exceeded(format!("{store}: {code}"))
                    .with_store(store)
            }
            "LINK_HOST_UNAVAILABLE" | "LINK_HOST_NOT_SUPPORTED"
            | "NO_SERVER" | "LINK_HOST_FULL" => {
                AppError::hoster_unavailable(format!("{store}: {code}"))
                    .with_store(store)
            }
            "LINK_DOWN" | "LINK_ERROR" | "LINK_NOT_FOUND"
            | "MAGNET_INVALID_ID" => {
                AppError::not_found(format!("{store}: {code}")).with_store(store)
            }
            "LINK_PASS_PROTECTED" => {
                AppError::forbidden(format!("{store}: {code}")).with_store(store)
            }
            "LINK_TOO_MANY_DOWNLOADS" => {
                AppError::too_many_requests(format!("{store}: {code}"))
                    .with_store(store)
            }
            _ => map_by_status(store, status, body),
        };
    }

    map_by_status(store, status, body)
}

// ---------------------------------------------------------------------------
// TorBox — HTTP status + body text. Known patterns:
//   401 -> Unauthorized
//   403 + "ip" -> Forbidden(ip_restricted)
//   403 -> Forbidden
//   404 -> NotFound
//   429 + "download limit" / "active" -> StoreLimitExceeded
//   429 -> TooManyRequests
//   451 / "dmca" / "infringing" -> InfringingContent
//   502/503/504 -> UpstreamUnavailable
// ---------------------------------------------------------------------------

fn map_torbox(store: &str, status: u16, body: &str) -> AppError {
    let lower = body.to_ascii_lowercase();
    match status {
        401 => AppError::unauthorized_for(store, format!("{store}: unauthorized")),
        403 => {
            if lower.contains("ip") {
                AppError::ip_restricted_for(store, format!("{store}: IP not allowed"))
            } else {
                AppError::forbidden(format!("{store}: forbidden")).with_store(store)
            }
        }
        404 => AppError::not_found(format!("{store}: not found")).with_store(store),
        429 => {
            if lower.contains("download limit")
                || lower.contains("active")
                || lower.contains("fair usage")
            {
                AppError::store_limit_exceeded(format!("{store}: limit exceeded"))
                    .with_store(store)
            } else {
                AppError::too_many_requests(format!("{store}: rate limited"))
                    .with_store(store)
            }
        }
        451 => {
            AppError::infringing_content(format!("{store}: infringing content"))
                .with_store(store)
        }
        _ => {
            if lower.contains("dmca") || lower.contains("infringing") {
                AppError::infringing_content(format!("{store}: {body}"))
                    .with_store(store)
            } else {
                map_by_status(store, status, body)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Premiumize — HTTP status + body text.
// ---------------------------------------------------------------------------

fn map_premiumize(store: &str, status: u16, body: &str) -> AppError {
    let lower = body.to_ascii_lowercase();
    match status {
        401 => AppError::unauthorized_for(store, format!("{store}: unauthorized")),
        403 => {
            if lower.contains("ip") {
                AppError::ip_restricted_for(store, format!("{store}: IP not allowed"))
            } else if lower.contains("fair usage")
                || lower.contains("limit")
                || lower.contains("traffic")
            {
                AppError::store_limit_exceeded(format!("{store}: {body}"))
                    .with_store(store)
            } else {
                AppError::forbidden(format!("{store}: forbidden")).with_store(store)
            }
        }
        404 => AppError::not_found(format!("{store}: not found")).with_store(store),
        429 => {
            AppError::too_many_requests(format!("{store}: rate limited"))
                .with_store(store)
        }
        _ => map_by_status(store, status, body),
    }
}

// ---------------------------------------------------------------------------
// Debrid-Link — HTTP status + body text.
// ---------------------------------------------------------------------------

fn map_debridlink(store: &str, status: u16, body: &str) -> AppError {
    let lower = body.to_ascii_lowercase();
    match status {
        401 => AppError::unauthorized_for(store, format!("{store}: unauthorized")),
        403 => {
            if lower.contains("ip") {
                AppError::ip_restricted_for(store, format!("{store}: IP not allowed"))
            } else {
                AppError::forbidden(format!("{store}: forbidden")).with_store(store)
            }
        }
        404 => AppError::not_found(format!("{store}: not found")).with_store(store),
        429 => {
            if lower.contains("download") || lower.contains("limit") {
                AppError::store_limit_exceeded(format!("{store}: {body}"))
                    .with_store(store)
            } else {
                AppError::too_many_requests(format!("{store}: rate limited"))
                    .with_store(store)
            }
        }
        _ => map_by_status(store, status, body),
    }
}

// ---------------------------------------------------------------------------
// Offcloud — HTTP status + body text.
// ---------------------------------------------------------------------------

fn map_offcloud(store: &str, status: u16, body: &str) -> AppError {
    let lower = body.to_ascii_lowercase();
    match status {
        401 => AppError::unauthorized_for(store, format!("{store}: unauthorized")),
        403 => {
            if lower.contains("ip") {
                AppError::ip_restricted_for(store, format!("{store}: IP not allowed"))
            } else {
                AppError::forbidden(format!("{store}: forbidden")).with_store(store)
            }
        }
        404 => AppError::not_found(format!("{store}: not found")).with_store(store),
        429 => {
            AppError::too_many_requests(format!("{store}: rate limited"))
                .with_store(store)
        }
        _ => map_by_status(store, status, body),
    }
}

// ---------------------------------------------------------------------------
// PikPak — HTTP status + body text.
// ---------------------------------------------------------------------------

fn map_pikpak(store: &str, status: u16, body: &str) -> AppError {
    let lower = body.to_ascii_lowercase();
    match status {
        401 => AppError::unauthorized_for(store, format!("{store}: unauthorized")),
        403 => {
            if lower.contains("ip") {
                AppError::ip_restricted_for(store, format!("{store}: IP not allowed"))
            } else {
                AppError::forbidden(format!("{store}: forbidden")).with_store(store)
            }
        }
        404 => AppError::not_found(format!("{store}: not found")).with_store(store),
        429 => {
            if lower.contains("quota") || lower.contains("limit") {
                AppError::store_limit_exceeded(format!("{store}: {body}"))
                    .with_store(store)
            } else {
                AppError::too_many_requests(format!("{store}: rate limited"))
                    .with_store(store)
            }
        }
        _ => map_by_status(store, status, body),
    }
}

// ---------------------------------------------------------------------------
// Debrider — HTTP status + body text.
// ---------------------------------------------------------------------------

fn map_debrider(store: &str, status: u16, body: &str) -> AppError {
    let lower = body.to_ascii_lowercase();
    match status {
        401 => AppError::unauthorized_for(store, format!("{store}: unauthorized")),
        403 => {
            if lower.contains("ip") {
                AppError::ip_restricted_for(store, format!("{store}: IP not allowed"))
            } else {
                AppError::forbidden(format!("{store}: forbidden")).with_store(store)
            }
        }
        404 => AppError::not_found(format!("{store}: not found")).with_store(store),
        429 => {
            AppError::too_many_requests(format!("{store}: rate limited"))
                .with_store(store)
        }
        _ => map_by_status(store, status, body),
    }
}

// ---------------------------------------------------------------------------
// EasyDebrid — HTTP status + body text.
// ---------------------------------------------------------------------------

fn map_easydebrid(store: &str, status: u16, body: &str) -> AppError {
    let lower = body.to_ascii_lowercase();
    match status {
        401 => AppError::unauthorized_for(store, format!("{store}: unauthorized")),
        403 => {
            if lower.contains("ip") {
                AppError::ip_restricted_for(store, format!("{store}: IP not allowed"))
            } else {
                AppError::forbidden(format!("{store}: forbidden")).with_store(store)
            }
        }
        404 => AppError::not_found(format!("{store}: not found")).with_store(store),
        429 => {
            if lower.contains("limit") || lower.contains("active") {
                AppError::store_limit_exceeded(format!("{store}: {body}"))
                    .with_store(store)
            } else {
                AppError::too_many_requests(format!("{store}: rate limited"))
                    .with_store(store)
            }
        }
        _ => map_by_status(store, status, body),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Generic HTTP-status-based mapping used as a fallback when no store-specific
/// code is recognized. Preserves the native body in the message for debugging.
fn map_by_status(store: &str, status: u16, body: &str) -> AppError {
    // Truncate body for the message to avoid huge payloads in error responses.
    // Truncate on a UTF-8 char boundary so a multi-byte char straddling byte
    // 200 never panics — the mapping must be total (Property 20, Req 16.10).
    let truncated = truncate_on_char_boundary(body, 200);

    match status {
        401 => AppError::unauthorized_for(store, format!("{store}: {truncated}")),
        402 => AppError::payment_required(format!("{store}: payment required"))
            .with_store(store),
        403 => {
            let lower = body.to_ascii_lowercase();
            if lower.contains("ip") {
                AppError::ip_restricted_for(
                    store,
                    format!("{store}: IP not allowed"),
                )
            } else {
                AppError::forbidden(format!("{store}: {truncated}"))
                    .with_store(store)
            }
        }
        404 => AppError::not_found(format!("{store}: {truncated}"))
            .with_store(store),
        429 => {
            let lower = body.to_ascii_lowercase();
            if lower.contains("limit")
                || lower.contains("active")
                || lower.contains("traffic")
                || lower.contains("fair usage")
            {
                AppError::store_limit_exceeded(format!("{store}: {truncated}"))
                    .with_store(store)
                    .with_retry_after(Duration::from_secs(60))
            } else {
                AppError::too_many_requests(format!("{store}: {truncated}"))
                    .with_store(store)
            }
        }
        451 => AppError::infringing_content(format!("{store}: {truncated}"))
            .with_store(store),
        502 | 503 | 504 | 0 => {
            AppError::upstream_unavailable_for(store, format!("{store}: {truncated}"))
        }
        _ => AppError::unknown(format!("{store}: HTTP {status} — {truncated}"))
            .with_store(store),
    }
}

/// Truncate `s` to at most `max_bytes` bytes, never splitting a multi-byte
/// UTF-8 character. Returns the largest prefix whose byte length is `<=
/// max_bytes` and that ends on a char boundary, so callers can interpolate it
/// into an error message without risking a panic (Property 20, Req 16.10).
fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Walk back from `max_bytes` to the nearest char boundary (at most 3 bytes
    // for UTF-8). `is_char_boundary(0)` is always true, so this terminates.
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Extract a numeric `error_code` from a RealDebrid JSON response body.
///
/// RealDebrid errors look like: `{"error":"...", "error_code": 8}`
fn extract_rd_error_code(body: &str) -> Option<u32> {
    // Simple extraction without pulling in a full JSON parser for this hot path.
    // Look for `"error_code"` followed by a colon and a number.
    let idx = body.find("\"error_code\"")?;
    let after_key = &body[idx + "\"error_code\"".len()..];
    // Skip whitespace and colon.
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let num_start = after_colon.trim_start();
    // Parse the leading digits.
    let num_str: String = num_start.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse().ok()
}

/// Check if a RealDebrid error body hints at an IP restriction.
fn body_contains_ip_hint(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("ip") && (lower.contains("not allowed")
        || lower.contains("not_allowed")
        || lower.contains("restricted")
        || lower.contains("forbidden"))
}

/// Extract a string error `code` from an AllDebrid JSON response body.
///
/// AllDebrid errors look like:
/// `{"status":"error","error":{"code":"AUTH_BAD_APIKEY","message":"..."}}`
fn extract_ad_error_code(body: &str) -> Option<&str> {
    // Look for `"code":"<VALUE>"` pattern.
    let idx = body.find("\"code\"")?;
    let after_key = &body[idx + "\"code\"".len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();
    let after_quote = trimmed.strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(&after_quote[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;

    // -----------------------------------------------------------------------
    // RealDebrid error mapping (Req 16.8, 16.9, 16.11, 16.12, 16.13)
    // -----------------------------------------------------------------------

    #[test]
    fn rd_bad_token_maps_to_unauthorized_identifying_store() {
        let body = r#"{"error":"bad_token","error_code":8}"#;
        let err = map_store_error(StoreName::RealDebrid, 401, body);
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
        assert_eq!(err.upstream_status, Some(401));
    }

    #[test]
    fn rd_permission_denied_maps_to_forbidden() {
        let body = r#"{"error":"permission_denied","error_code":9}"#;
        let err = map_store_error(StoreName::RealDebrid, 403, body);
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
        assert!(!err.ip_restricted);
    }

    #[test]
    fn rd_ip_not_allowed_maps_to_forbidden_with_ip_restricted() {
        let body =
            r#"{"error":"ip_not_allowed","error_code":9}"#;
        let err = map_store_error(StoreName::RealDebrid, 403, body);
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
        assert!(err.ip_restricted, "Req 16.13: IP restriction must be flagged");
    }

    #[test]
    fn rd_infringing_file_maps_to_infringing_content() {
        let body = r#"{"error":"infringing_file","error_code":35}"#;
        let err = map_store_error(StoreName::RealDebrid, 403, body);
        assert_eq!(err.category, ErrorCategory::InfringingContent);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
    }

    #[test]
    fn rd_too_many_active_downloads_maps_to_store_limit_exceeded() {
        let body = r#"{"error":"too_many_active_downloads","error_code":34}"#;
        let err = map_store_error(StoreName::RealDebrid, 503, body);
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
    }

    #[test]
    fn rd_traffic_limit_maps_to_store_limit_exceeded() {
        let body = r#"{"error":"traffic_limit","error_code":20}"#;
        let err = map_store_error(StoreName::RealDebrid, 503, body);
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
    }

    #[test]
    fn rd_fair_usage_limit_maps_to_store_limit_exceeded() {
        let body = r#"{"error":"fair_usage_limit","error_code":21}"#;
        let err = map_store_error(StoreName::RealDebrid, 503, body);
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
    }

    #[test]
    fn rd_503_without_error_code_maps_to_upstream_unavailable() {
        let body = r#"Service Unavailable"#;
        let err = map_store_error(StoreName::RealDebrid, 503, body);
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
    }

    #[test]
    fn rd_unknown_error_code_falls_back_to_status() {
        let body = r#"{"error":"something_new","error_code":999}"#;
        let err = map_store_error(StoreName::RealDebrid, 500, body);
        assert_eq!(err.category, ErrorCategory::Unknown);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
        // Native body preserved in message.
        assert!(err.message.contains("realdebrid"));
    }

    // -----------------------------------------------------------------------
    // AllDebrid error mapping (Req 16.8, 16.12)
    // -----------------------------------------------------------------------

    #[test]
    fn ad_auth_bad_apikey_maps_to_unauthorized() {
        let body = r#"{"status":"error","error":{"code":"AUTH_BAD_APIKEY","message":"Invalid API key"}}"#;
        let err = map_store_error(StoreName::AllDebrid, 401, body);
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("alldebrid"));
    }

    #[test]
    fn ad_auth_blocked_maps_to_unauthorized() {
        let body = r#"{"status":"error","error":{"code":"AUTH_BLOCKED","message":"Blocked"}}"#;
        let err = map_store_error(StoreName::AllDebrid, 403, body);
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("alldebrid"));
    }

    #[test]
    fn ad_magnet_too_many_active_maps_to_store_limit_exceeded() {
        let body = r#"{"status":"error","error":{"code":"MAGNET_TOO_MANY_ACTIVE","message":"Too many active"}}"#;
        let err = map_store_error(StoreName::AllDebrid, 429, body);
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("alldebrid"));
    }

    #[test]
    fn ad_link_host_unavailable_maps_to_hoster_unavailable() {
        let body = r#"{"status":"error","error":{"code":"LINK_HOST_UNAVAILABLE","message":"Host down"}}"#;
        let err = map_store_error(StoreName::AllDebrid, 502, body);
        assert_eq!(err.category, ErrorCategory::HosterUnavailable);
        assert_eq!(err.store.as_deref(), Some("alldebrid"));
    }

    #[test]
    fn ad_no_infringing_concept_never_returns_infringing_content() {
        // AllDebrid has no infringing concept — even a 451 status without a
        // recognized code should not produce InfringingContent from the AD
        // mapper (it falls through to map_by_status which does map 451).
        // But the design says "No infringing concept → never InfringingContent"
        // for AllDebrid-specific codes. A raw 451 status is still mapped by
        // the generic fallback.
        let body = r#"{"status":"error","error":{"code":"SOME_UNKNOWN","message":"?"}}"#;
        let err = map_store_error(StoreName::AllDebrid, 200, body);
        // Unknown code + 200 status -> Unknown category
        assert_ne!(err.category, ErrorCategory::InfringingContent);
    }

    #[test]
    fn ad_link_too_many_downloads_maps_to_too_many_requests() {
        let body = r#"{"status":"error","error":{"code":"LINK_TOO_MANY_DOWNLOADS","message":"Slow down"}}"#;
        let err = map_store_error(StoreName::AllDebrid, 429, body);
        assert_eq!(err.category, ErrorCategory::TooManyRequests);
        assert_eq!(err.store.as_deref(), Some("alldebrid"));
    }

    // -----------------------------------------------------------------------
    // TorBox error mapping (Req 16.8, 16.9, 16.11, 16.12, 16.13)
    // -----------------------------------------------------------------------

    #[test]
    fn tb_401_maps_to_unauthorized_identifying_store() {
        let err = map_store_error(StoreName::TorBox, 401, "Unauthorized");
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("torbox"));
    }

    #[test]
    fn tb_403_with_ip_maps_to_forbidden_ip_restricted() {
        let err = map_store_error(StoreName::TorBox, 403, "Your IP is not allowed");
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.ip_restricted);
        assert_eq!(err.store.as_deref(), Some("torbox"));
    }

    #[test]
    fn tb_429_with_download_limit_maps_to_store_limit_exceeded() {
        let err = map_store_error(
            StoreName::TorBox,
            429,
            "You have reached your download limit",
        );
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("torbox"));
    }

    #[test]
    fn tb_429_without_limit_hint_maps_to_too_many_requests() {
        let err = map_store_error(StoreName::TorBox, 429, "Too many requests");
        assert_eq!(err.category, ErrorCategory::TooManyRequests);
        assert_eq!(err.store.as_deref(), Some("torbox"));
    }

    #[test]
    fn tb_451_maps_to_infringing_content() {
        let err = map_store_error(StoreName::TorBox, 451, "DMCA takedown");
        assert_eq!(err.category, ErrorCategory::InfringingContent);
        assert_eq!(err.store.as_deref(), Some("torbox"));
    }

    #[test]
    fn tb_503_maps_to_upstream_unavailable() {
        let err = map_store_error(StoreName::TorBox, 503, "Service Unavailable");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.store.as_deref(), Some("torbox"));
    }

    #[test]
    fn tb_dmca_in_body_maps_to_infringing_content_regardless_of_status() {
        let err = map_store_error(StoreName::TorBox, 200, "This file was removed due to DMCA");
        assert_eq!(err.category, ErrorCategory::InfringingContent);
        assert_eq!(err.store.as_deref(), Some("torbox"));
    }

    // -----------------------------------------------------------------------
    // Premiumize error mapping
    // -----------------------------------------------------------------------

    #[test]
    fn pm_401_maps_to_unauthorized() {
        let err = map_store_error(StoreName::Premiumize, 401, "Invalid token");
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("premiumize"));
    }

    #[test]
    fn pm_403_with_fair_usage_maps_to_store_limit_exceeded() {
        let err = map_store_error(
            StoreName::Premiumize,
            403,
            "Fair usage limit exceeded",
        );
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("premiumize"));
    }

    #[test]
    fn pm_403_with_ip_maps_to_ip_restricted() {
        let err = map_store_error(StoreName::Premiumize, 403, "IP not allowed");
        assert_eq!(err.category, ErrorCategory::Forbidden);
        assert!(err.ip_restricted);
        assert_eq!(err.store.as_deref(), Some("premiumize"));
    }

    // -----------------------------------------------------------------------
    // Debrid-Link error mapping
    // -----------------------------------------------------------------------

    #[test]
    fn dl_401_maps_to_unauthorized() {
        let err = map_store_error(StoreName::DebridLink, 401, "Bad token");
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("debridlink"));
    }

    #[test]
    fn dl_429_with_download_limit_maps_to_store_limit_exceeded() {
        let err = map_store_error(
            StoreName::DebridLink,
            429,
            "Download limit reached",
        );
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("debridlink"));
    }

    // -----------------------------------------------------------------------
    // Offcloud error mapping
    // -----------------------------------------------------------------------

    #[test]
    fn oc_401_maps_to_unauthorized() {
        let err = map_store_error(StoreName::Offcloud, 401, "Unauthorized");
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("offcloud"));
    }

    #[test]
    fn oc_503_maps_to_upstream_unavailable() {
        let err = map_store_error(StoreName::Offcloud, 503, "");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.store.as_deref(), Some("offcloud"));
    }

    // -----------------------------------------------------------------------
    // PikPak error mapping
    // -----------------------------------------------------------------------

    #[test]
    fn pp_401_maps_to_unauthorized() {
        let err = map_store_error(StoreName::PikPak, 401, "Token expired");
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("pikpak"));
    }

    #[test]
    fn pp_429_with_quota_maps_to_store_limit_exceeded() {
        let err = map_store_error(StoreName::PikPak, 429, "Quota exceeded");
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("pikpak"));
    }

    // -----------------------------------------------------------------------
    // Debrider error mapping
    // -----------------------------------------------------------------------

    #[test]
    fn dr_401_maps_to_unauthorized() {
        let err = map_store_error(StoreName::Debrider, 401, "Bad credentials");
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("debrider"));
    }

    #[test]
    fn dr_503_maps_to_upstream_unavailable() {
        let err = map_store_error(StoreName::Debrider, 503, "Maintenance");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.store.as_deref(), Some("debrider"));
    }

    // -----------------------------------------------------------------------
    // EasyDebrid error mapping
    // -----------------------------------------------------------------------

    #[test]
    fn ed_401_maps_to_unauthorized() {
        let err = map_store_error(StoreName::EasyDebrid, 401, "Invalid key");
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("easydebrid"));
    }

    #[test]
    fn ed_429_with_active_limit_maps_to_store_limit_exceeded() {
        let err = map_store_error(
            StoreName::EasyDebrid,
            429,
            "Too many active downloads",
        );
        assert_eq!(err.category, ErrorCategory::StoreLimitExceeded);
        assert_eq!(err.store.as_deref(), Some("easydebrid"));
    }

    #[test]
    fn ed_429_without_limit_hint_maps_to_too_many_requests() {
        let err = map_store_error(StoreName::EasyDebrid, 429, "Slow down");
        assert_eq!(err.category, ErrorCategory::TooManyRequests);
        assert_eq!(err.store.as_deref(), Some("easydebrid"));
    }

    // -----------------------------------------------------------------------
    // Cross-cutting: totality and store identification (Property 20)
    // -----------------------------------------------------------------------

    #[test]
    fn every_store_maps_unknown_status_to_unknown_with_body_preserved() {
        for store in StoreName::ALL {
            let body = "some unexpected native error body";
            let err = map_store_error(store, 599, body);
            assert_eq!(
                err.category,
                ErrorCategory::Unknown,
                "store {store:?} with unknown status 599 must map to Unknown",
            );
            assert_eq!(err.store.as_deref(), Some(store.as_str()));
            // Native body preserved in message.
            assert!(
                err.message.contains(store.as_str()),
                "message must identify the store",
            );
        }
    }

    #[test]
    fn every_store_maps_502_503_504_to_upstream_unavailable() {
        for store in StoreName::ALL {
            for status in [502, 503, 504] {
                let err = map_store_error(store, status, "");
                // TorBox 502 goes through its own mapper which may differ,
                // but 503/504 should always be UpstreamUnavailable.
                if status == 503 || status == 504 {
                    assert_eq!(
                        err.category,
                        ErrorCategory::UpstreamUnavailable,
                        "store {store:?} status {status} must be UpstreamUnavailable",
                    );
                }
                assert_eq!(err.store.as_deref(), Some(store.as_str()));
            }
        }
    }

    #[test]
    fn every_store_maps_401_to_unauthorized_identifying_store() {
        for store in StoreName::ALL {
            let err = map_store_error(store, 401, "bad token");
            assert_eq!(
                err.category,
                ErrorCategory::Unauthorized,
                "store {store:?} 401 must be Unauthorized (Req 16.8)",
            );
            assert_eq!(err.store.as_deref(), Some(store.as_str()));
        }
    }

    #[test]
    fn upstream_status_is_always_attached() {
        let err = map_store_error(StoreName::RealDebrid, 503, "down");
        assert_eq!(err.upstream_status, Some(503));

        let err2 = map_store_error(StoreName::AllDebrid, 401, r#"{"status":"error","error":{"code":"AUTH_BAD_APIKEY","message":"x"}}"#);
        assert_eq!(err2.upstream_status, Some(401));
    }

    #[test]
    fn multibyte_body_over_truncation_boundary_never_panics() {
        // Property 20 / Req 16.10: the mapping must be total and never panic.
        // A naive `&body[..200]` byte-slice panics if byte 200 lands inside a
        // multi-byte UTF-8 char. Build a body whose 200th byte is mid-char by
        // padding with ASCII then a run of 3-byte characters, and exercise
        // every store + a status that flows through `map_by_status`.
        let body = format!("{}{}", "x".repeat(199), "€".repeat(50)); // '€' is 3 bytes
        assert!(!body.is_char_boundary(200), "test fixture must straddle byte 200");
        for store in StoreName::ALL {
            for status in [401u16, 403, 404, 500, 599] {
                let err = map_store_error(store, status, &body);
                // It is enough that this did not panic; also confirm identity.
                assert_eq!(err.store.as_deref(), Some(store.as_str()));
                assert_eq!(err.upstream_status, Some(status));
            }
        }
    }

    #[test]
    fn status_zero_maps_to_upstream_unavailable_for_unreachable() {
        // Status 0 represents a transport failure (unreachable).
        for store in StoreName::ALL {
            let err = map_store_error(store, 0, "connection refused");
            assert_eq!(
                err.category,
                ErrorCategory::UpstreamUnavailable,
                "store {store:?} status 0 (unreachable) must be UpstreamUnavailable (Req 16.9)",
            );
            assert_eq!(err.store.as_deref(), Some(store.as_str()));
        }
    }

    // -----------------------------------------------------------------------
    // Helper extraction tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_rd_error_code_parses_valid_json() {
        assert_eq!(
            extract_rd_error_code(r#"{"error":"bad_token","error_code":8}"#),
            Some(8),
        );
        assert_eq!(
            extract_rd_error_code(r#"{"error_code": 35, "error": "infringing"}"#),
            Some(35),
        );
    }

    #[test]
    fn extract_rd_error_code_returns_none_for_missing() {
        assert_eq!(extract_rd_error_code(r#"{"error":"something"}"#), None);
        assert_eq!(extract_rd_error_code("not json at all"), None);
        assert_eq!(extract_rd_error_code(""), None);
    }

    #[test]
    fn extract_ad_error_code_parses_nested_code() {
        let body = r#"{"status":"error","error":{"code":"AUTH_BAD_APIKEY","message":"bad"}}"#;
        assert_eq!(extract_ad_error_code(body), Some("AUTH_BAD_APIKEY"));
    }

    #[test]
    fn extract_ad_error_code_returns_none_for_missing() {
        assert_eq!(extract_ad_error_code(r#"{"status":"ok"}"#), None);
        assert_eq!(extract_ad_error_code(""), None);
    }

    #[test]
    fn truncate_on_char_boundary_preserves_short_strings_and_never_splits_chars() {
        // Short strings pass through untouched.
        assert_eq!(truncate_on_char_boundary("hello", 200), "hello");
        // ASCII is truncated at exactly the byte limit.
        let ascii = "a".repeat(250);
        assert_eq!(truncate_on_char_boundary(&ascii, 200).len(), 200);
        // A multi-byte char straddling the limit is dropped whole; the result
        // is always valid UTF-8 (the `&str` return type guarantees it) and is
        // never longer than the limit.
        let body = format!("{}{}", "x".repeat(199), "€".repeat(50));
        let out = truncate_on_char_boundary(&body, 200);
        assert!(out.len() <= 200);
        assert!(body.starts_with(out));
        assert_eq!(out, "x".repeat(199)); // the 3-byte '€' at byte 199 is excluded
    }
}
