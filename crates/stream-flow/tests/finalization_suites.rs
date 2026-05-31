use std::collections::HashMap;
use std::time::Duration;

use actix_web::{test as actix_test, App};
use stream_flow::config::{Config, LoadOptions};
use stream_flow::egress::sanitize_outbound;
use stream_flow::health::LoadState;
use stream_flow::http::degradation::{
    next_load_state, DegradationLadder, DegradationLevel, LoadThresholds,
};
use stream_flow::{build_app, AppState};

#[test]
fn replay_harness_compat_env_keeps_both_auth_surfaces_active() {
    let mut env = HashMap::new();
    env.insert(
        "APP__AUTH__API_PASSWORD".to_string(),
        "mediaflow-secret".to_string(),
    );
    env.insert(
        "STREMTHRU_PROXY_AUTH".to_string(),
        "alice:proxy-secret".to_string(),
    );
    env.insert(
        "STREMTHRU_STORE_AUTH".to_string(),
        "*:rd:store-token".to_string(),
    );
    let config = Config::load(&LoadOptions::new().with_env(env)).unwrap();
    assert_eq!(
        config.auth.api_password.as_ref().unwrap().expose(),
        "mediaflow-secret"
    );
    assert!(config
        .auth
        .proxy_auth
        .iter()
        .any(|entry| entry == "alice:proxy-secret"));
    assert!(config
        .auth
        .per_user_store
        .iter()
        .any(|entry| entry == "*:rd:store-token"));
}

#[test]
fn egress_leak_suite_strips_spoofed_client_identity_headers() {
    let mut inbound = actix_web::http::header::HeaderMap::new();
    inbound.insert(
        actix_web::http::header::HeaderName::from_static("x-forwarded-for"),
        "198.51.100.77".parse().unwrap(),
    );
    inbound.insert(
        actix_web::http::header::HeaderName::from_static("x-real-ip"),
        "198.51.100.77".parse().unwrap(),
    );
    inbound.insert(
        actix_web::http::header::HeaderName::from_static("user-agent"),
        "stremio".parse().unwrap(),
    );
    let outbound = sanitize_outbound(&inbound, Some("198.51.100.77".parse().unwrap()));
    assert!(!outbound.contains_key("X-Forwarded-For"));
    assert!(!outbound.contains_key("X-Real-IP"));
    assert_eq!(outbound.get("User-Agent").unwrap(), "stremio");
}

#[test]
fn resilience_chaos_suite_ladder_is_ordered_hysteretic_and_stream_protecting() {
    let ladder = DegradationLadder::default();
    let mut level = DegradationLevel::L0Normal;
    for _ in 0..5 {
        level = ladder.next_level(level, 100, None);
    }
    assert_eq!(level, DegradationLevel::L5Emergency);
    assert_eq!(
        ladder.next_level(level, 0, Some(ladder.cooldown_hold_secs - 1)),
        DegradationLevel::L5Emergency
    );
    assert_eq!(
        ladder.next_level(level, 0, Some(ladder.cooldown_hold_secs)),
        DegradationLevel::L4ShedNewStreams
    );
    assert!(DegradationLevel::L4ShedNewStreams.protects_active_streams());
}

#[test]
fn performance_policy_load_state_transitions_are_constant_time_and_bounded() {
    let thresholds = LoadThresholds {
        enabled: true,
        conn_high_water: 10,
        conn_low_water: 5,
        memory_high_water_bytes: 100,
    };
    let started = std::time::Instant::now();
    let mut state = LoadState::Normal;
    for i in 0..10_000 {
        state = next_load_state(state, i % 20, i % 120, &thresholds);
    }
    assert!(started.elapsed() < Duration::from_millis(50));
    assert!(matches!(state, LoadState::Normal | LoadState::Degraded));
}

#[actix_web::test]
async fn final_router_serves_web_and_wrap_surfaces() {
    let mut config = Config::default();
    config.stremio.wrap_upstreams = Vec::new();
    let app = actix_test::init_service(App::new().service(build_app(AppState::new(config)))).await;

    let root =
        actix_test::call_service(&app, actix_test::TestRequest::get().uri("/").to_request()).await;
    assert!(root.status().is_success());

    let wrap = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/stremio/wrap/manifest.json")
            .to_request(),
    )
    .await;
    assert!(wrap.status().is_success());
}
