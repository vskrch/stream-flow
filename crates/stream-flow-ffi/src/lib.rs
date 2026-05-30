//! `stream-flow-ffi` — C-ABI bridge over the `stream_flow` library (Req 34).
//!
//! Every `extern "C"` entry point wraps its work in
//! [`std::panic::catch_unwind`], converting panics into error status codes so
//! no panic ever unwinds across the C-ABI (Req 34.3, design: Profile note).
//! This crate is built with `panic = "abort"` (`--profile release-ffi`), so
//! the entry points must themselves never panic — they convert all errors to
//! status codes before returning.
//!
//! This is the task-1.1 skeleton: the real C-ABI functions (streaming-proxy +
//! store ops, alloc/free helpers, generated `include/stream_flow.h`) land with
//! the FFI task. The entire surface is gated behind the `ffi` feature.

/// Status code returned across the C-ABI. Non-zero values indicate an error;
/// a caught panic maps to [`STREAM_FLOW_PANIC`].
pub const STREAM_FLOW_OK: i32 = 0;
/// A panic was caught at the boundary and converted to a status code (Req 34.3).
pub const STREAM_FLOW_PANIC: i32 = -1;

/// Minimal C-ABI smoke entry point demonstrating the panic boundary.
///
/// Wraps the (currently trivial) work in `catch_unwind` so a panic is
/// converted to [`STREAM_FLOW_PANIC`] instead of unwinding across the C-ABI.
#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn stream_flow_ffi_version() -> i32 {
    std::panic::catch_unwind(|| {
        // Reference the library so the FFI crate genuinely links against it.
        let _ = stream_flow::build_app;
        STREAM_FLOW_OK
    })
    .unwrap_or(STREAM_FLOW_PANIC)
}
