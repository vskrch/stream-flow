//! `ZippyPanther` server binary.
//!
//! A thin `main` that wires configuration + the actix server over the
//! `zippy_panther` library (design: Workspace and Crate Layout). It links
//! against the library and constructs the *same* routing tree via
//! [`zippy_panther::build_app`] that the integration-test harness uses (Req
//! 49.6).
//!
//! The binary loads production configuration, builds the shared `AppState`,
//! starts supervised runtime tasks, and serves the same routing tree as tests.

use actix_web::{App, HttpServer};
use std::io;
use std::time::Duration;
use zippy_panther::config::Config;
use zippy_panther::http::degradation::{RssSampler, SysinfoRssReader};
use zippy_panther::observability::{init_logging, Redactor};
use zippy_panther::{build_app, AppState};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = Config::from_env().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to load ZippyPanther config: {err}"),
        )
    })?;

    let redactor = Redactor::new();
    if let Some(secret) = &config.auth.api_password {
        redactor.register_secret(secret.expose());
    }
    if let Some(secret) = &config.auth.metrics_password {
        redactor.register_secret(secret.expose());
    }
    if let Some(secret) = &config.vault_secret {
        redactor.register_secret(secret.expose());
    }
    init_logging("info", redactor);

    let bind_addr = (config.server.host.clone(), config.server.port);
    let workers = config.server.workers;
    let state = AppState::new(config);

    let sampler_handle = SysinfoRssReader::new().map(|reader| {
        tokio::spawn(
            RssSampler::new(
                state.load_controller().clone(),
                reader,
                Duration::from_secs(5),
            )
            .run(),
        )
    });

    let mut server = HttpServer::new(move || App::new().service(build_app(state.clone())));
    if workers > 0 {
        server = server.workers(workers);
    }
    let server = server.bind(bind_addr)?.run();
    let handle = server.handle();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            handle.stop(true).await;
        }
    });

    let result = server.await;
    if let Some(handle) = sampler_handle {
        handle.abort();
    }
    result
}
