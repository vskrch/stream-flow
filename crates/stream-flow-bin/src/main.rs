//! `stream-flow` server binary.
//!
//! A thin `main` that wires configuration + the actix server over the
//! `stream_flow` library (design: Workspace and Crate Layout). It links
//! against the library and constructs the *same* routing tree via
//! [`stream_flow::build_app`] that the integration-test harness uses (Req
//! 49.6).
//!
//! This is the task-1.1 skeleton. Config loading, `AppState` construction, and
//! graceful shutdown are wired in later tasks (config: task 3; router/state:
//! task 11.2; graceful shutdown: Req 49.4).

use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let addr = ("127.0.0.1", 8080);
    HttpServer::new(|| App::new().service(stream_flow::build_app()))
        .bind(addr)?
        .run()
        .await
}
