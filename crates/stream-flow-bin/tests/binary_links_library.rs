//! Smoke test (Req 49.6): the `stream-flow` binary target builds and links
//! against the `stream_flow` library crate (design: Workspace and Crate
//! Layout).
//!
//! This is an *external* integration test belonging to the `stream-flow-bin`
//! package. Two independent facts establish the requirement:
//!
//!   1. **It builds.** Cargo compiles the package's binary target before
//!      running this integration test and exposes its path via the
//!      `CARGO_BIN_EXE_<name>` env var. The presence of that artifact on disk
//!      is proof the `stream-flow` binary built successfully.
//!
//!   2. **It links the library.** This test crate — like the binary's own
//!      `main` — depends on `stream_flow` and names `stream_flow::build_app`.
//!      Because the binary package declares `stream-flow` as a dependency, the
//!      binary target links against the library; if that dependency edge were
//!      missing this test would fail to compile.

/// `cargo test` builds the binary target first; assert the produced artifact
/// exists, proving the `stream-flow` binary builds.
#[test]
fn binary_artifact_builds() {
    // Cargo sets `CARGO_BIN_EXE_<bin-name>` for integration tests of the
    // package that defines the binary. The bin target is named `stream-flow`.
    let bin_path = env!(
        "CARGO_BIN_EXE_stream-flow",
        "Cargo should expose the built `stream-flow` binary path to its integration tests"
    );
    assert!(
        std::path::Path::new(bin_path).exists(),
        "the `stream-flow` binary should have been built at {bin_path}"
    );
}

/// Reference `stream_flow::build_app` from the binary package so the linker
/// edge `stream-flow-bin -> stream_flow` is exercised exactly as it is in the
/// binary's `main`. Compiling this function at all confirms the binary crate
/// links against the library and can construct the shared routing tree.
#[test]
fn binary_package_links_against_library() {
    // Constructing the service factory through the library dependency forces
    // the `stream-flow-bin -> stream_flow` link without standing up a server.
    // `build_app` returns an opaque `impl HttpServiceFactory`, so we simply
    // bind and drop it.
    let _factory = stream_flow::build_app();
}
