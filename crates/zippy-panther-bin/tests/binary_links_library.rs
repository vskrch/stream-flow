//! Smoke test (Req 49.6): the `ZippyPanther` binary target builds and links
//! against the `zippy_panther` library crate (design: Workspace and Crate
//! Layout).
//!
//! This is an *external* integration test belonging to the `zippy-panther-bin`
//! package. Two independent facts establish the requirement:
//!
//!   1. **It builds.** Cargo compiles the package's binary target before
//!      running this integration test and exposes its path via the
//!      `CARGO_BIN_EXE_<name>` env var. The presence of that artifact on disk
//!      is proof the `ZippyPanther` binary built successfully.
//!
//!   2. **It links the library.** This test crate — like the binary's own
//!      `main` — depends on `zippy_panther` and names `zippy_panther::build_app`.
//!      Because the binary package declares `zippy-panther` as a dependency, the
//!      binary target links against the library; if that dependency edge were
//!      missing this test would fail to compile.

/// `cargo test` builds the binary target first; assert the produced artifact
/// exists, proving the `ZippyPanther` binary builds.
#[test]
fn binary_artifact_builds() {
    // Cargo sets `CARGO_BIN_EXE_<bin-name>` for integration tests of the
    // package that defines the binary. The bin target is named `zippy-panther`.
    let bin_path = env!(
        "CARGO_BIN_EXE_zippy-panther",
        "Cargo should expose the built `ZippyPanther` binary path to its integration tests"
    );
    assert!(
        std::path::Path::new(bin_path).exists(),
        "the `ZippyPanther` binary should have been built at {bin_path}"
    );
}

/// Reference `zippy_panther::build_app` from the binary package so the linker
/// edge `zippy-panther-bin -> zippy_panther` is exercised exactly as it is in the
/// binary's `main`. Compiling this function at all confirms the binary crate
/// links against the library and can construct the shared routing tree.
#[test]
fn binary_package_links_against_library() {
    // Constructing the service factory through the library dependency forces
    // the `zippy-panther-bin -> zippy_panther` link without standing up a server.
    // `build_app` takes the shared `AppState` (also part of the library's
    // public surface) and returns an opaque `impl HttpServiceFactory`, so we
    // simply build and drop it.
    use zippy_panther::config::Config;
    use zippy_panther::{build_app, AppState};

    let _factory = build_app(AppState::new(Config::default()));
}
