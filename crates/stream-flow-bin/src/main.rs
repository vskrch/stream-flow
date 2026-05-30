//! `stream-flow` server binary.
//!
//! A thin `main` that wires configuration + the actix server over the
//! `stream_flow` library (design: Workspace and Crate Layout). It links
//! against the library and constructs the *same* routing tree via
//! [`stream_flow::build_app`] that the integration-test harness uses (Req
//! 49.6).
//!
//! This is the task-11.2 skeleton: it builds an [`AppState`] from the default
//! configuration and serves the dual-surface routing tree. Real config
//! loading (task 3), the full `AppState` dependency wiring, and graceful
//! shutdown are layered in later tasks (config: task 3; graceful shutdown: Req
//! 49.4).

use actix_web::{App, HttpServer};
use stream_flow::config::Config;
use stream_flow::{build_app, AppState};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // The binary constructs the shared `AppState` once and hands a clone to
    // each actix worker, so every worker serves the *identical* routing tree
    // over one shared dependency set (Req 49.6). Config loading replaces the
    // default here in task 3.
    let state = AppState::new(Config::default());

    let addr = ("127.0.0.1", 8080);
    HttpServer::new(move || App::new().service(build_app(state.clone())))
        .bind(addr)?
        .run()
        .await
}
