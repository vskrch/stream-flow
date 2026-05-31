//! `stream-flow-ffi` — C-ABI bridge over the `stream_flow` library (Req 34).
//!
//! Every `extern "C"` entry point wraps its work in
//! [`std::panic::catch_unwind`], converting panics into error status codes so
//! no panic ever unwinds across the C-ABI (Req 34.3, design: Profile note).
//! This crate is built with `panic = "abort"` (`--profile release-ffi`), so
//! the entry points must themselves never panic — they convert all errors to
//! status codes before returning.
//!
//! The C ABI is intentionally narrow and string-based: callers pass JSON
//! request/config documents and receive owned JSON strings that must be freed
//! with [`stream_flow_string_free`]. This keeps ownership clear across C,
//! Swift, Kotlin, and other FFI hosts while still exposing the core
//! streaming-proxy URL builder and canonical store helpers.

#[cfg(feature = "ffi")]
use std::ffi::{CStr, CString};
#[cfg(feature = "ffi")]
use std::os::raw::c_char;
#[cfg(feature = "ffi")]
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Status code returned across the C-ABI. Non-zero values indicate an error;
/// a caught panic maps to [`STREAM_FLOW_PANIC`].
pub const STREAM_FLOW_OK: i32 = 0;
/// A panic was caught at the boundary and converted to a status code (Req 34.3).
pub const STREAM_FLOW_PANIC: i32 = -1;
/// A null or invalid pointer was supplied.
pub const STREAM_FLOW_INVALID_ARGUMENT: i32 = -2;
/// The requested operation failed without panicking.
pub const STREAM_FLOW_ERROR: i32 = -3;

/// Minimal C-ABI smoke entry point demonstrating the panic boundary.
///
/// Wraps the (currently trivial) work in `catch_unwind` so a panic is
/// converted to [`STREAM_FLOW_PANIC`] instead of unwinding across the C-ABI.
#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn stream_flow_ffi_version() -> i32 {
    catch_unwind(|| {
        // Reference the library so the FFI crate genuinely links against it.
        let _ = stream_flow::build_app;
        STREAM_FLOW_OK
    })
    .unwrap_or(STREAM_FLOW_PANIC)
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn stream_flow_version_string() -> *mut c_char {
    catch_unwind(|| match CString::new(env!("CARGO_PKG_VERSION")) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    })
    .unwrap_or(std::ptr::null_mut())
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn stream_flow_string_free(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !ptr.is_null() {
            unsafe {
                drop(CString::from_raw(ptr));
            }
        }
    }));
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn stream_flow_validate_config_json(json: *const c_char) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Ok(text) = read_c_string(json) else {
            return STREAM_FLOW_INVALID_ARGUMENT;
        };
        match parse_config(&text) {
            Ok(_) => STREAM_FLOW_OK,
            Err(_) => STREAM_FLOW_ERROR,
        }
    }))
    .unwrap_or(STREAM_FLOW_PANIC)
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn stream_flow_generate_proxy_url_json(
    config_json: *const c_char,
    request_json: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if !prepare_output(out_json) {
            return STREAM_FLOW_INVALID_ARGUMENT;
        }
        let Ok(config_text) = read_c_string(config_json) else {
            return STREAM_FLOW_INVALID_ARGUMENT;
        };
        let Ok(request_text) = read_c_string(request_json) else {
            return STREAM_FLOW_INVALID_ARGUMENT;
        };
        let Ok(config) = parse_config(&config_text) else {
            return STREAM_FLOW_ERROR;
        };
        let Some(api_password) = config.auth.api_password.as_ref().map(|s| s.expose()) else {
            return STREAM_FLOW_ERROR;
        };
        if api_password.is_empty() {
            return STREAM_FLOW_ERROR;
        }
        let Ok(request) = serde_json::from_str::<
            stream_flow::utils::generate_url::GenerateUrlRequest,
        >(&request_text) else {
            return STREAM_FLOW_ERROR;
        };
        let key = stream_flow::auth::encryption::CbcKey::from_api_password(api_password);
        let now = now_unix_secs();
        let Ok(url) = stream_flow::utils::generate_url::build_proxy_url(
            &request,
            &config.server.path_prefix,
            &key,
            now,
        ) else {
            return STREAM_FLOW_ERROR;
        };
        write_json_output(out_json, serde_json::json!({ "url": url }))
    }))
    .unwrap_or(STREAM_FLOW_PANIC)
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn stream_flow_store_normalize_json(
    store: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if !prepare_output(out_json) {
            return STREAM_FLOW_INVALID_ARGUMENT;
        }
        let Ok(store_text) = read_c_string(store) else {
            return STREAM_FLOW_INVALID_ARGUMENT;
        };
        let Ok(store_name) = stream_flow::store::StoreName::require(&store_text) else {
            return STREAM_FLOW_ERROR;
        };
        write_json_output(
            out_json,
            serde_json::json!({
                "name": store_name.as_str(),
                "code": store_name.code().as_str(),
            }),
        )
    }))
    .unwrap_or(STREAM_FLOW_PANIC)
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn stream_flow_store_catalog_json(out_json: *mut *mut c_char) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if !prepare_output(out_json) {
            return STREAM_FLOW_INVALID_ARGUMENT;
        }
        let stores: Vec<_> = stream_flow::store::StoreName::ALL
            .iter()
            .map(|store| {
                serde_json::json!({
                    "name": store.as_str(),
                    "code": store.code().as_str(),
                })
            })
            .collect();
        write_json_output(out_json, serde_json::json!({ "stores": stores }))
    }))
    .unwrap_or(STREAM_FLOW_PANIC)
}

#[cfg(feature = "ffi")]
fn read_c_string(ptr: *const c_char) -> Result<String, i32> {
    if ptr.is_null() {
        return Err(STREAM_FLOW_INVALID_ARGUMENT);
    }
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str()
        .map(str::to_owned)
        .map_err(|_| STREAM_FLOW_INVALID_ARGUMENT)
}

#[cfg(feature = "ffi")]
fn parse_config(text: &str) -> Result<stream_flow::config::Config, serde_json::Error> {
    serde_json::from_str::<stream_flow::config::Config>(text)
}

#[cfg(feature = "ffi")]
fn prepare_output(out: *mut *mut c_char) -> bool {
    if out.is_null() {
        return false;
    }
    unsafe {
        *out = std::ptr::null_mut();
    }
    true
}

#[cfg(feature = "ffi")]
fn write_json_output(out: *mut *mut c_char, value: serde_json::Value) -> i32 {
    if out.is_null() {
        return STREAM_FLOW_INVALID_ARGUMENT;
    }
    match CString::new(value.to_string()) {
        Ok(value) => {
            unsafe {
                *out = value.into_raw();
            }
            STREAM_FLOW_OK
        }
        Err(_) => STREAM_FLOW_ERROR,
    }
}

#[cfg(feature = "ffi")]
fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(all(test, feature = "ffi"))]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::ptr;

    fn take_owned(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null());
        unsafe { CString::from_raw(ptr) }
            .into_string()
            .expect("FFI output is UTF-8")
    }

    #[test]
    fn null_config_pointer_is_error_not_panic() {
        assert_eq!(
            stream_flow_validate_config_json(std::ptr::null()),
            STREAM_FLOW_INVALID_ARGUMENT
        );
    }

    #[test]
    fn valid_config_json_is_ok() {
        let json = CString::new(r#"{"auth":{"api_password":"secret"}}"#).unwrap();
        assert_eq!(
            stream_flow_validate_config_json(json.as_ptr()),
            STREAM_FLOW_OK
        );
    }

    #[test]
    fn version_string_is_allocated_and_freeable() {
        let ptr = stream_flow_version_string();
        assert!(!ptr.is_null());
        stream_flow_string_free(ptr);
    }

    #[test]
    fn proxy_url_generation_returns_owned_json() {
        let config = CString::new(r#"{"auth":{"api_password":"secret"}}"#).unwrap();
        let request = CString::new(
            r#"{"mediaflow_proxy_url":"https://flow.example","destination_url":"https://cdn.example/video.mkv"}"#,
        )
        .unwrap();
        let mut out = ptr::null_mut();
        assert_eq!(
            stream_flow_generate_proxy_url_json(config.as_ptr(), request.as_ptr(), &mut out),
            STREAM_FLOW_OK
        );
        let body = take_owned(out);
        let value: Value = serde_json::from_str(&body).unwrap();
        let url = value["url"].as_str().unwrap();
        assert!(url.starts_with("https://flow.example/proxy/stream?d="));
    }

    #[test]
    fn proxy_url_generation_rejects_null_output() {
        let config = CString::new(r#"{"auth":{"api_password":"secret"}}"#).unwrap();
        let request =
            CString::new(r#"{"mediaflow_proxy_url":"https://flow.example","destination_url":"x"}"#)
                .unwrap();
        assert_eq!(
            stream_flow_generate_proxy_url_json(config.as_ptr(), request.as_ptr(), ptr::null_mut()),
            STREAM_FLOW_INVALID_ARGUMENT
        );
    }

    #[test]
    fn store_normalize_accepts_slug_or_code() {
        let store = CString::new("rd").unwrap();
        let mut out = ptr::null_mut();
        assert_eq!(
            stream_flow_store_normalize_json(store.as_ptr(), &mut out),
            STREAM_FLOW_OK
        );
        let body = take_owned(out);
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            serde_json::json!({"name":"realdebrid","code":"rd"})
        );
    }

    #[test]
    fn store_catalog_lists_all_supported_stores() {
        let mut out = ptr::null_mut();
        assert_eq!(stream_flow_store_catalog_json(&mut out), STREAM_FLOW_OK);
        let body = take_owned(out);
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["stores"].as_array().unwrap().len(), 9);
    }

    #[test]
    fn invalid_store_returns_error_and_nulls_output() {
        let store = CString::new("missing").unwrap();
        let mut out = std::ptr::dangling_mut();
        assert_eq!(
            stream_flow_store_normalize_json(store.as_ptr(), &mut out),
            STREAM_FLOW_ERROR
        );
        assert!(out.is_null());
    }
}
