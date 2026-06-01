# ZippyPanther

ZippyPanther is a Rust streaming proxy and Stremio/debrid companion. It is built
as a single Cargo workspace with a reusable library crate, server binary, FFI
crate, and Rust HTTP client SDK.

## Build

```bash
cargo build --release -p zippy-panther-bin
```

## Test

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
```

## Run

```bash
APP__AUTH__API_PASSWORD=change-me \
APP__SERVER__HOST=0.0.0.0 \
APP__SERVER__PORT=8080 \
cargo run -p zippy-panther-bin
```

The Docker and Heroku configuration start the `zippy-panther` binary and map
Heroku's dynamic `PORT` to `APP__SERVER__PORT`.
