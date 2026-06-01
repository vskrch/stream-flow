//! `APP__*` / `STREMTHRU_*` compatibility / translation layer
//! (`config::compat`) — Req 36.3, 36.4.
//!
//! [`CompatSource`] is a custom [`config::Source`] that lets `ZippyPanther` be a
//! **drop-in replacement** for both `mediaflow-proxy-light` (env vars prefixed
//! `APP__`) and `stremthru` (env vars prefixed `STREMTHRU_`): it translates the
//! legacy compatibility environment-variable names of both projects onto the
//! single internal [`Config`](super::Config) tree's dotted keys (Req 36.3).
//!
//! ## Where it sits in the layering
//!
//! [`Config::load`](super::Config::load) assembles the tree in the order
//! **defaults → file → `STREMTHRU_*` → `APP__*`**. This source occupies the
//! `STREMTHRU_*` slot (between the file and the native nested `APP__*`
//! environment source). Two things give `APP__*` the documented final say for a
//! genuinely overlapping *scalar* (Req 36.4):
//!
//! 1. Within this one source, the `APP__*`-derived mappings are applied **after**
//!    the `STREMTHRU_*`-derived ones, so they overwrite on conflict.
//! 2. The native nested `APP__*` source is added to the builder *after* this
//!    one, so standard `APP__SECTION__FIELD` names still win last.
//!
//! Crucially, the two **authentication mechanisms are not mutually exclusive**:
//! `APP__AUTH__API_PASSWORD` (mediaflow API password) feeds `auth.api_password`
//! while `STREMTHRU_PROXY_AUTH` feeds the *separate* `auth.proxy_auth[]` list,
//! so when both prefixes are set both remain active on their respective
//! endpoint groups (Req 36.4).
//!
//! ## Mapping table (design: Compatibility / translation layer)
//!
//! | External env var | Internal key |
//! |---|---|
//! | `APP__API_PASSWORD` (legacy, no `AUTH` segment) | `auth.api_password` |
//! | `APP__EGRESS__FAIL_POLICY` / `STREMTHRU_EGRESS_FAIL_POLICY` | `egress.policy` |
//! | `APP__EGRESS__IP_REFLECT_URL` | `egress.ip_reflection_url` |
//! | `APP__PROXY__PROXY_URL` (+ `APP__PROXY__ALL_PROXY=true`) | `egress.tunnel_url` |
//! | `STREMTHRU_PROXY_AUTH` (`user:pass` csv) | `auth.proxy_auth[]` |
//! | `STREMTHRU_STORE_AUTH` (`user:store:token` csv) | `auth.per_user_store[]` |
//! | `STREMTHRU_AUTH_ADMIN` (csv) | `auth.admins[]` |
//! | `STREMTHRU_DATABASE_URI` (`sqlite://…`) | `db.path` |
//! | `STREMTHRU_REDIS_URI` | `cache.redis_url` |
//! | `STREMTHRU_HTTP_PROXY` / `STREMTHRU_TUNNEL` / `STREMTHRU_STORE_TUNNEL` | `egress.tunnel_url` / `egress.per_host[]` |
//!
//! Standard nested `APP__SECTION__FIELD` names (e.g. `APP__PROXY__BUFFER_SIZE`
//! → `proxy.buffer_size`, `APP__PROXY__TRANSPORT_ROUTES` → the JSON parsed in
//! [`Config::load`](super::Config::load)) are already handled by the native
//! `APP__*` environment source and are intentionally **not** duplicated here.

use std::collections::HashMap;

use ::config::{ConfigError, Map, Value};

use super::LoadOptions;

/// Custom [`config::Source`] translating the `STREMTHRU_*` and legacy `APP__*`
/// compatibility environment variables onto the internal [`Config`](super::Config)
/// dotted keys (Req 36.3, 36.4).
#[derive(Clone, Debug)]
pub(crate) struct CompatSource {
    /// The environment snapshot to translate (explicit map in tests, otherwise
    /// the process environment).
    env: HashMap<String, String>,
}

impl CompatSource {
    /// Build a source from [`LoadOptions`]: use the caller-supplied environment
    /// map when present (deterministic tests) or the process environment.
    pub(crate) fn from_options(opts: &LoadOptions) -> Self {
        let env = match &opts.env {
            Some(map) => map.clone(),
            None => std::env::vars().collect(),
        };
        Self { env }
    }
}

impl ::config::Source for CompatSource {
    fn clone_into_box(&self) -> Box<dyn ::config::Source + Send + Sync> {
        Box::new(self.clone())
    }

    /// Translate the compatibility environment into internal dotted-key
    /// [`Value`]s. Returned keys are interpreted as `config` path expressions
    /// by the default `collect_to`, which deep-merges them onto the running
    /// configuration tree (so multiple `egress.*` keys combine rather than
    /// clobber). `per_host` is emitted as a single pre-merged table to keep
    /// dotted hostnames intact.
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut out: Map<String, Value> = Map::new();

        // -- auth.api_password: legacy mediaflow `APP__API_PASSWORD` (the
        //    nested `APP__AUTH__API_PASSWORD` is handled by the native source).
        if let Some(pw) = self.get("APP__API_PASSWORD") {
            out.insert("auth.api_password".into(), Value::from(pw));
        }

        // -- auth.proxy_auth[]: `STREMTHRU_PROXY_AUTH` (`user:pass` csv).
        if let Some(list) = self.csv("STREMTHRU_PROXY_AUTH") {
            out.insert("auth.proxy_auth".into(), Value::from(list));
        }

        // -- auth.per_user_store[]: `STREMTHRU_STORE_AUTH` (`user:store:token` csv).
        if let Some(list) = self.csv("STREMTHRU_STORE_AUTH") {
            out.insert("auth.per_user_store".into(), Value::from(list));
        }

        // -- auth.admins[]: `STREMTHRU_AUTH_ADMIN` (csv). Entries may carry an
        //    optional `:password`; only the username feeds the admin list.
        if let Some(list) = self.csv("STREMTHRU_AUTH_ADMIN") {
            let admins: Vec<String> = list
                .into_iter()
                .map(|entry| entry.split(':').next().unwrap_or("").to_string())
                .filter(|u| !u.is_empty())
                .collect();
            out.insert("auth.admins".into(), Value::from(admins));
        }

        // -- db.path: `STREMTHRU_DATABASE_URI` (`sqlite://…`) → bare path.
        if let Some(uri) = self.get("STREMTHRU_DATABASE_URI") {
            out.insert("db.path".into(), Value::from(strip_sqlite_scheme(&uri)));
        }

        // -- cache.redis_url: `STREMTHRU_REDIS_URI`.
        if let Some(uri) = self.get("STREMTHRU_REDIS_URI") {
            out.insert("cache.redis_url".into(), Value::from(uri));
        }

        // -- egress.ip_reflection_url: `APP__EGRESS__IP_REFLECT_URL`.
        if let Some(url) = self.get("APP__EGRESS__IP_REFLECT_URL") {
            out.insert("egress.ip_reflection_url".into(), Value::from(url));
        }

        // -- egress.policy: `APP__EGRESS__FAIL_POLICY` / `STREMTHRU_EGRESS_FAIL_POLICY`.
        //    Overlapping scalar → `APP__` wins (Req 36.4).
        if let Some(policy) = self
            .get("APP__EGRESS__FAIL_POLICY")
            .or_else(|| self.get("STREMTHRU_EGRESS_FAIL_POLICY"))
        {
            out.insert(
                "egress.policy".into(),
                Value::from(normalize_policy(&policy)),
            );
        }

        // -- egress tunnel URL + mode. Overlapping scalar → `APP__` wins:
        //    mediaflow's global proxy (`APP__PROXY__PROXY_URL` + `ALL_PROXY`)
        //    takes precedence over stremthru's `STREMTHRU_HTTP_PROXY`.
        let stremthru_proxy = self.get("STREMTHRU_HTTP_PROXY");
        let app_global_proxy = match self.get("APP__PROXY__PROXY_URL") {
            Some(url) if self.flag("APP__PROXY__ALL_PROXY") => Some(url),
            _ => None,
        };
        let tunnel_url = app_global_proxy.clone().or_else(|| stremthru_proxy.clone());
        if let Some(url) = &tunnel_url {
            out.insert("egress.tunnel_url".into(), Value::from(url.clone()));
            // A configured tunnel implies proxy transport mode.
            out.insert("egress.tunnel_mode".into(), Value::from("proxy"));
        }

        // -- egress.per_host: `STREMTHRU_TUNNEL` (`host:cfg` csv) and
        //    `STREMTHRU_STORE_TUNNEL` (`store:cfg` csv, store → content host).
        //    `cfg` of `true` reuses the stremthru global proxy; an explicit URL
        //    pins that URL; `false` (direct) records no entry (Req 51.9).
        let mut per_host: Map<String, Value> = Map::new();
        if let Some(raw) = self.get("STREMTHRU_TUNNEL") {
            for entry in split_csv(&raw) {
                let Some((host, cfg)) = entry.split_once(':') else {
                    continue;
                };
                // `*` controls the global default, represented by tunnel_url.
                if host == "*" {
                    continue;
                }
                if let Some(url) = resolve_tunnel_cfg(cfg, stremthru_proxy.as_deref()) {
                    per_host.insert(host.to_string(), Value::from(url));
                }
            }
        }
        if let Some(raw) = self.get("STREMTHRU_STORE_TUNNEL") {
            for entry in split_csv(&raw) {
                let Some((store, cfg)) = entry.split_once(':') else {
                    continue;
                };
                let Some(url) = resolve_tunnel_cfg(cfg, stremthru_proxy.as_deref()) else {
                    continue;
                };
                if store == "*" {
                    for host in STORE_CONTENT_HOSTS.iter().map(|(_, h)| *h) {
                        per_host
                            .entry(host.to_string())
                            .or_insert_with(|| Value::from(url.clone()));
                    }
                } else if let Some(host) = content_host_for_store(store) {
                    per_host.insert(host.to_string(), Value::from(url));
                }
            }
        }
        if !per_host.is_empty() {
            out.insert("egress.per_host".into(), Value::from(per_host));
        }

        Ok(out)
    }
}

impl CompatSource {
    /// Look up a non-empty trimmed env value.
    fn get(&self, key: &str) -> Option<String> {
        self.env
            .get(key)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// Parse a comma-separated env value into a list of trimmed, non-empty
    /// entries; `None` when the variable is absent/empty.
    fn csv(&self, key: &str) -> Option<Vec<String>> {
        self.get(key).map(|raw| split_csv(&raw))
    }

    /// Interpret an env value as a boolean flag (`true`/`1`/`yes`/`on`).
    fn flag(&self, key: &str) -> bool {
        matches!(
            self.get(key).map(|v| v.to_ascii_lowercase()).as_deref(),
            Some("true" | "1" | "yes" | "on")
        )
    }
}

/// Split a comma-separated value into trimmed, non-empty entries.
fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Strip a leading `sqlite://` (or `sqlite:`) scheme from a database URI,
/// yielding the bare filesystem path used by `db.path`.
fn strip_sqlite_scheme(uri: &str) -> String {
    uri.strip_prefix("sqlite://")
        .or_else(|| uri.strip_prefix("sqlite:"))
        .unwrap_or(uri)
        .to_string()
}

/// Normalize a fail-policy env value (`fail_open`/`fail-open` → `fail-open`)
/// into the kebab-case form expected by [`EgressPolicy`](super::EgressPolicy).
fn normalize_policy(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace('_', "-")
}

/// Resolve a stremthru tunnel config token for one host/store:
/// * `true`  → the stremthru global proxy URL (if any),
/// * `false` → direct (no tunnel, `None`),
/// * otherwise → the explicit proxy URL token.
fn resolve_tunnel_cfg(cfg: &str, global_proxy: Option<&str>) -> Option<String> {
    match cfg.trim() {
        "true" => global_proxy.map(str::to_string),
        "false" | "" => None,
        url => Some(url.to_string()),
    }
}

/// stremthru's debrid-store → content-CDN-host mapping (mirrors
/// `parseStoreTunnel` in stremthru's `internal/config/http.go`).
const STORE_CONTENT_HOSTS: &[(&str, &str)] = &[
    ("alldebrid", "debrid.it"),
    ("debridlink", "debrid.link"),
    ("premiumize", "energycdn.com"),
    ("realdebrid", "download.real-debrid.com"),
    ("torbox", "tb-cdn.st"),
];

/// Look up the content-CDN host for a debrid store name.
fn content_host_for_store(store: &str) -> Option<&'static str> {
    STORE_CONTENT_HOSTS
        .iter()
        .find(|(name, _)| *name == store)
        .map(|(_, host)| *host)
}

#[cfg(test)]
mod tests {
    use super::super::{Config, EgressPolicy, EgressTunnelMode, LoadOptions};
    use std::collections::HashMap;

    /// Build `LoadOptions` from a set of `(key, value)` env pairs, always
    /// including the one required value (`auth.api_password`) unless the caller
    /// already supplied one.
    fn load_with(pairs: &[(&str, &str)]) -> Config {
        let mut env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let has_pw =
            env.contains_key("APP__AUTH__API_PASSWORD") || env.contains_key("APP__API_PASSWORD");
        if !has_pw {
            env.insert("APP__AUTH__API_PASSWORD".to_string(), "secret".to_string());
        }
        Config::load(&LoadOptions::new().with_env(env)).expect("config load should succeed")
    }

    // -- api_password (legacy mediaflow `APP__API_PASSWORD`) ----------------

    #[test]
    fn app_api_password_legacy_maps_to_auth_api_password() {
        let config = load_with(&[("APP__API_PASSWORD", "legacy-pw")]);
        assert_eq!(
            config
                .auth
                .api_password
                .as_ref()
                .expect("api_password set")
                .expose(),
            "legacy-pw"
        );
    }

    // -- proxy.buffer_size (`APP__PROXY__BUFFER_SIZE`) ----------------------

    #[test]
    fn app_proxy_buffer_size_maps_to_proxy_buffer_size() {
        let config = load_with(&[("APP__PROXY__BUFFER_SIZE", "1048576")]);
        assert_eq!(config.proxy.buffer_size, 1_048_576);
    }

    // -- proxy.transport_routes JSON still parses alongside compat vars -----

    #[test]
    fn transport_routes_json_parses_alongside_compat_vars() {
        let config = load_with(&[
            ("STREMTHRU_PROXY_AUTH", "alice:pw"),
            (
                "APP__PROXY__TRANSPORT_ROUTES",
                r#"{"example.com":{"proxy":true,"proxy_url":"socks5://127.0.0.1:9050"}}"#,
            ),
        ]);
        let route = config
            .proxy
            .transport_routes
            .get("example.com")
            .expect("route present");
        assert!(route.proxy);
        assert_eq!(route.proxy_url.as_deref(), Some("socks5://127.0.0.1:9050"));
    }

    // -- auth.proxy_auth[] (`STREMTHRU_PROXY_AUTH` csv) ---------------------

    #[test]
    fn stremthru_proxy_auth_csv_maps_to_proxy_auth_list() {
        let config = load_with(&[("STREMTHRU_PROXY_AUTH", "alice:pw1,bob:pw2")]);
        assert_eq!(config.auth.proxy_auth, vec!["alice:pw1", "bob:pw2"]);
    }

    // -- auth.per_user_store[] (`STREMTHRU_STORE_AUTH` csv) -----------------

    #[test]
    fn stremthru_store_auth_csv_maps_to_per_user_store_list() {
        let config = load_with(&[(
            "STREMTHRU_STORE_AUTH",
            "*:realdebrid:tok1,bob:premiumize:tok2",
        )]);
        assert_eq!(
            config.auth.per_user_store,
            vec!["*:realdebrid:tok1", "bob:premiumize:tok2"]
        );
    }

    // -- auth.admins[] (`STREMTHRU_AUTH_ADMIN` csv) -------------------------

    #[test]
    fn stremthru_auth_admin_csv_maps_to_admins_usernames() {
        // Admin entries may be `username` or `username:password`; only the
        // username feeds `auth.admins[]`.
        let config = load_with(&[("STREMTHRU_AUTH_ADMIN", "alice,bob:adminpw")]);
        assert_eq!(config.auth.admins, vec!["alice", "bob"]);
    }

    // -- db.path (`STREMTHRU_DATABASE_URI`) ---------------------------------

    #[test]
    fn stremthru_database_uri_maps_to_db_path_stripping_scheme() {
        let config = load_with(&[("STREMTHRU_DATABASE_URI", "sqlite://./data/stremthru.db")]);
        assert_eq!(config.db.path, "./data/stremthru.db");
    }

    // -- cache.redis_url (`STREMTHRU_REDIS_URI`) ----------------------------

    #[test]
    fn stremthru_redis_uri_maps_to_cache_redis_url() {
        let config = load_with(&[("STREMTHRU_REDIS_URI", "redis://localhost:6379/0")]);
        assert_eq!(
            config.cache.redis_url.as_deref(),
            Some("redis://localhost:6379/0")
        );
    }

    // -- egress tunnel (`STREMTHRU_HTTP_PROXY` + `STREMTHRU_TUNNEL`) --------

    #[test]
    fn stremthru_http_proxy_and_tunnel_map_to_egress() {
        let config = load_with(&[
            ("STREMTHRU_HTTP_PROXY", "http://proxy:8888"),
            (
                "STREMTHRU_TUNNEL",
                "example.com:true,other.com:socks5://127.0.0.1:1080,skip.com:false",
            ),
        ]);
        // Global proxy → tunnel_url + proxy mode.
        assert_eq!(
            config.egress.tunnel_url.as_deref(),
            Some("http://proxy:8888")
        );
        assert_eq!(config.egress.tunnel_mode, EgressTunnelMode::Proxy);
        // `host:true` reuses the global proxy URL.
        assert_eq!(
            config
                .egress
                .per_host
                .get("example.com")
                .map(String::as_str),
            Some("http://proxy:8888")
        );
        // `host:<url>` uses the explicit per-host URL.
        assert_eq!(
            config.egress.per_host.get("other.com").map(String::as_str),
            Some("socks5://127.0.0.1:1080")
        );
        // `host:false` (direct) records no per-host tunnel.
        assert!(!config.egress.per_host.contains_key("skip.com"));
    }

    // -- store tunnel (`STREMTHRU_STORE_TUNNEL` → content host) ------------

    #[test]
    fn stremthru_store_tunnel_maps_store_to_content_host_in_egress() {
        let config = load_with(&[
            ("STREMTHRU_HTTP_PROXY", "http://proxy:8888"),
            ("STREMTHRU_STORE_TUNNEL", "realdebrid:true"),
        ]);
        assert_eq!(
            config
                .egress
                .per_host
                .get("download.real-debrid.com")
                .map(String::as_str),
            Some("http://proxy:8888")
        );
    }

    // -- egress.ip_reflection_url (`APP__EGRESS__IP_REFLECT_URL`) -----------

    #[test]
    fn app_ip_reflect_url_maps_to_egress_ip_reflection_url() {
        let config = load_with(&[("APP__EGRESS__IP_REFLECT_URL", "https://my.example/ip")]);
        assert_eq!(config.egress.ip_reflection_url, "https://my.example/ip");
    }

    // -- egress.policy fail-policy (both prefixes) --------------------------

    #[test]
    fn stremthru_fail_policy_maps_to_egress_policy() {
        let config = load_with(&[("STREMTHRU_EGRESS_FAIL_POLICY", "fail-open")]);
        assert_eq!(config.egress.policy, EgressPolicy::FailOpen);
    }

    #[test]
    fn app_fail_policy_overrides_stremthru_fail_policy() {
        // Req 36.4: for a genuinely overlapping scalar, `APP__` wins.
        let config = load_with(&[
            ("STREMTHRU_EGRESS_FAIL_POLICY", "fail-open"),
            ("APP__EGRESS__FAIL_POLICY", "fail-closed"),
        ]);
        assert_eq!(config.egress.policy, EgressPolicy::FailClosed);
    }

    // -- egress.tunnel_url via mediaflow global proxy -----------------------

    #[test]
    fn app_proxy_url_with_all_proxy_maps_to_egress_tunnel_url() {
        let config = load_with(&[
            ("APP__PROXY__PROXY_URL", "http://gw:3128"),
            ("APP__PROXY__ALL_PROXY", "true"),
        ]);
        assert_eq!(config.egress.tunnel_url.as_deref(), Some("http://gw:3128"));
        assert_eq!(config.egress.tunnel_mode, EgressTunnelMode::Proxy);
    }

    #[test]
    fn app_proxy_url_without_all_proxy_does_not_set_egress_tunnel() {
        let config = load_with(&[("APP__PROXY__PROXY_URL", "http://gw:3128")]);
        assert!(config.egress.tunnel_url.is_none());
        assert_eq!(config.egress.tunnel_mode, EgressTunnelMode::Disabled);
    }

    #[test]
    fn app_proxy_url_overrides_stremthru_http_proxy_for_tunnel_url() {
        // Req 36.4: `APP__` wins over `STREMTHRU_` for the overlapping
        // `egress.tunnel_url` scalar.
        let config = load_with(&[
            ("STREMTHRU_HTTP_PROXY", "http://stremthru-proxy:8888"),
            ("APP__PROXY__PROXY_URL", "http://app-gw:3128"),
            ("APP__PROXY__ALL_PROXY", "true"),
        ]);
        assert_eq!(
            config.egress.tunnel_url.as_deref(),
            Some("http://app-gw:3128")
        );
    }

    // -- both auth mechanisms remain active simultaneously (Req 36.4) -------

    #[test]
    fn both_auth_mechanisms_active_when_both_prefixes_set() {
        let config = load_with(&[
            ("APP__AUTH__API_PASSWORD", "mediaflow-pw"),
            ("STREMTHRU_PROXY_AUTH", "alice:stremthru-pw"),
        ]);
        // mediaflow API password is active …
        assert_eq!(
            config
                .auth
                .api_password
                .as_ref()
                .expect("api_password set")
                .expose(),
            "mediaflow-pw"
        );
        // … and the stremthru proxy-auth list is *also* active (not dropped).
        assert_eq!(config.auth.proxy_auth, vec!["alice:stremthru-pw"]);
    }
}
