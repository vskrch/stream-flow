//! Transport routing & forwarding (`proxy::routing`) — Req 13, 51.9.
//!
//! Per-pattern egress routing: a [`RoutePattern`] (domain / `all://` protocol /
//! `*` wildcard — Req 13.1) maps to a [`TransportRoute`], which pins matching
//! upstream requests to an optional [`Forwarding_Proxy`](ProxyUrl)
//! (http/https/socks4/socks5 — Req 13.3) and an SSL-verification policy
//! (Req 13.4). [`RoutingTable::select_route`] picks the **most specific** match
//! — the one with the fewest wildcards (Req 13.2) — and falls back to the
//! configured default forwarding proxy when *all-proxy* mode is on and nothing
//! matched (Req 13.5), or to a direct connection when all-proxy is off
//! (Req 13.6). Invalid patterns are rejected (and logged) at configuration load
//! (Req 13.8) via [`RoutePattern::parse`].
//!
//! Forwarding `reqwest::Client`s are expensive to rebuild per request, so a
//! small [`ClientCache`] LRU keyed by `(proxy, verify_ssl)` pre-builds and
//! reuses them (design: Components → Transport routing & forwarding), mirroring
//! mediaflow's per-route client cache.
//!
//! The same machinery backs the egress single-seam's per-host/per-store tunnel
//! selection (Req 51.9): [`egress::OutboundClient`](crate::egress::OutboundClient)
//! holds a [`RoutingTable`] of host → tunnel routes plus a [`ClientCache`] so
//! the selected tunnel is actually dialled, while the fail-closed gate still
//! guarantees no client-identifying header ever leaves the process.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use url::Url;

use crate::config::ProxyConfig;
use crate::errors::AppError;

/// Default capacity of the per-route forwarding-[`ClientCache`].
///
/// A handful of distinct `(proxy, verify_ssl)` combinations covers any
/// realistic transport-route table; the LRU caps memory if a pathological
/// config produces more.
pub const DEFAULT_CLIENT_CACHE_CAPACITY: usize = 32;

// ===========================================================================
// Pattern parsing & matching (Req 13.1, 13.2, 13.8)
// ===========================================================================

/// Why a [`RoutePattern`] string was rejected at parse / config-load time
/// (Req 13.8). The [`Display`](std::fmt::Display) is the human-readable reason
/// recorded in the structured log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    /// The pattern was empty (or only a scheme with no host on a form that
    /// requires one).
    #[error("transport-route pattern is empty")]
    Empty,
    /// The pattern (or a component of it) contained whitespace or a control
    /// character.
    #[error("transport-route pattern contains whitespace or control characters")]
    Whitespace,
    /// The scheme prefix was not one of `http`, `https`, or `all`.
    #[error(
        "transport-route pattern has an unsupported scheme `{0}` (expected http, https, or all)"
    )]
    UnsupportedScheme(String),
    /// The host contained a `*` somewhere other than a leading `*.` label, or
    /// was otherwise malformed.
    #[error(
        "transport-route pattern host `{0}` is malformed (use an exact host, `*.suffix`, or `*`)"
    )]
    MalformedHost(String),
}

/// How a pattern matches a request's URL scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SchemeMatch {
    /// Matches any scheme (`all://` form, or a pattern with no scheme). Counts
    /// as one wildcard for specificity (Req 13.2).
    Any,
    /// Matches exactly the given (lower-cased) scheme.
    Exact(String),
}

/// How a pattern matches a request's URL host.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostMatch {
    /// Matches any host (`*` or an empty host after `all://`). One wildcard.
    Any,
    /// Matches any host ending in the stored suffix (e.g. `.example.com` from
    /// `*.example.com`). One wildcard. Does **not** match the bare apex.
    Suffix(String),
    /// Matches exactly the stored (lower-cased) host. Zero wildcards.
    Exact(String),
}

/// A parsed transport-route URL pattern supporting domain, protocol (`all://`),
/// and wildcard (`*`) matching (Req 13.1).
///
/// Construct with [`RoutePattern::parse`]; an invalid pattern is rejected with
/// a [`PatternError`] so it can be refused (and logged) at config load
/// (Req 13.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePattern {
    raw: String,
    scheme: SchemeMatch,
    host: HostMatch,
}

impl RoutePattern {
    /// Parse a pattern string into a [`RoutePattern`] (Req 13.1), rejecting
    /// malformed input with a [`PatternError`] (Req 13.8).
    ///
    /// Accepted forms (case-insensitive scheme/host):
    /// * `https://api.example.com` — exact scheme + exact host (most specific).
    /// * `all://api.example.com` / `api.example.com` — any scheme + exact host.
    /// * `https://*.example.com` — exact scheme + subdomain wildcard.
    /// * `*.example.com` / `all://*.example.com` — subdomain wildcard.
    /// * `*` / `all://` — match everything (the catch-all).
    pub fn parse(pattern: &str) -> Result<RoutePattern, PatternError> {
        if pattern.is_empty() {
            return Err(PatternError::Empty);
        }
        if pattern.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(PatternError::Whitespace);
        }

        // Split an optional `scheme://` prefix from the host part.
        let (scheme, host_str) = match pattern.split_once("://") {
            Some((scheme_raw, host_raw)) => {
                let scheme = match scheme_raw.to_ascii_lowercase().as_str() {
                    "all" => SchemeMatch::Any,
                    "http" => SchemeMatch::Exact("http".to_string()),
                    "https" => SchemeMatch::Exact("https".to_string()),
                    other => return Err(PatternError::UnsupportedScheme(other.to_string())),
                };
                (scheme, host_raw)
            }
            // No scheme → matches any scheme (a plain "domain" pattern).
            None => (SchemeMatch::Any, pattern),
        };

        let host = parse_host(host_str)?;
        Ok(RoutePattern {
            raw: pattern.to_string(),
            scheme,
            host,
        })
    }

    /// `true` when this pattern matches `url`'s scheme **and** host.
    pub fn matches(&self, url: &Url) -> bool {
        self.scheme_matches(url) && self.host_matches(url)
    }

    fn scheme_matches(&self, url: &Url) -> bool {
        match &self.scheme {
            SchemeMatch::Any => true,
            SchemeMatch::Exact(s) => url.scheme().eq_ignore_ascii_case(s),
        }
    }

    fn host_matches(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            // No host (e.g. a `file:`/`data:` URL): only a fully-wildcard host
            // can match.
            return matches!(self.host, HostMatch::Any);
        };
        let host = host.to_ascii_lowercase();
        match &self.host {
            HostMatch::Any => true,
            HostMatch::Exact(h) => host == *h,
            HostMatch::Suffix(suffix) => host.ends_with(suffix.as_str()),
        }
    }

    /// The number of wildcards in this pattern; fewer == more specific
    /// (Req 13.2). An `all://` scheme is one wildcard; a `*`/`*.suffix` host is
    /// one wildcard; an exact scheme/host is zero.
    pub fn wildcard_count(&self) -> usize {
        let scheme_wc = usize::from(matches!(self.scheme, SchemeMatch::Any));
        let host_wc = match self.host {
            HostMatch::Any | HostMatch::Suffix(_) => 1,
            HostMatch::Exact(_) => 0,
        };
        scheme_wc + host_wc
    }

    /// The length of the literal (non-wildcard) host text, used only as a
    /// deterministic tiebreak between equally-wildcarded matches (a longer
    /// literal is the more specific host).
    fn literal_len(&self) -> usize {
        match &self.host {
            HostMatch::Exact(h) => h.len(),
            HostMatch::Suffix(s) => s.len(),
            HostMatch::Any => 0,
        }
    }

    /// The original pattern string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// Parse the host portion of a pattern into a [`HostMatch`] (Req 13.1, 13.8).
fn parse_host(host_str: &str) -> Result<HostMatch, PatternError> {
    // `all://` / `http://` with no host, or a bare `*`, match every host.
    if host_str.is_empty() || host_str == "*" {
        return Ok(HostMatch::Any);
    }
    if let Some(rest) = host_str.strip_prefix("*.") {
        // Subdomain wildcard `*.example.com` → suffix `.example.com`.
        if rest.is_empty() || rest.contains('*') {
            return Err(PatternError::MalformedHost(host_str.to_string()));
        }
        validate_host_literal(rest)?;
        return Ok(HostMatch::Suffix(format!(".{}", rest.to_ascii_lowercase())));
    }
    // Any other `*` usage is unsupported.
    if host_str.contains('*') {
        return Err(PatternError::MalformedHost(host_str.to_string()));
    }
    validate_host_literal(host_str)?;
    Ok(HostMatch::Exact(host_str.to_ascii_lowercase()))
}

/// Validate the literal characters of a host label sequence: a host may only
/// contain ASCII letters, digits, `-`, `.`, and `_` (Req 13.8). Rejects path /
/// query / userinfo delimiters that signal a malformed pattern.
fn validate_host_literal(host: &str) -> Result<(), PatternError> {
    if host.is_empty() {
        return Err(PatternError::MalformedHost(host.to_string()));
    }
    let ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    if ok {
        Ok(())
    } else {
        Err(PatternError::MalformedHost(host.to_string()))
    }
}

// ===========================================================================
// Forwarding proxy URL (Req 13.3)
// ===========================================================================

/// The transport scheme of a [`Forwarding_Proxy`](ProxyUrl) (Req 13.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScheme {
    /// `http://`
    Http,
    /// `https://`
    Https,
    /// `socks4://` / `socks4a://`
    Socks4,
    /// `socks5://` / `socks5h://`
    Socks5,
}

/// A validated forwarding-proxy URL whose scheme is one of HTTP, HTTPS,
/// SOCKS4, or SOCKS5 (Req 13.3).
///
/// The original string is preserved verbatim so it can be handed to
/// `reqwest::Proxy::all` unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyUrl {
    url: String,
    scheme: ProxyScheme,
}

impl ProxyUrl {
    /// Parse and validate a forwarding-proxy URL, accepting the http/https/
    /// socks4/socks5 family (incl. `socks4a`/`socks5h`) per Req 13.3.
    pub fn parse(url: &str) -> Result<ProxyUrl, AppError> {
        let scheme_raw = url
            .split_once("://")
            .map(|(s, _)| s.to_ascii_lowercase())
            .ok_or_else(|| {
                AppError::bad_request(format!("forwarding proxy URL `{url}` is missing a scheme"))
            })?;
        let scheme = match scheme_raw.as_str() {
            "http" => ProxyScheme::Http,
            "https" => ProxyScheme::Https,
            "socks4" | "socks4a" => ProxyScheme::Socks4,
            "socks5" | "socks5h" => ProxyScheme::Socks5,
            other => {
                return Err(AppError::bad_request(format!(
                    "forwarding proxy URL `{url}` has an unsupported scheme `{other}` \
                     (expected http, https, socks4, or socks5)"
                )))
            }
        };
        Ok(ProxyUrl {
            url: url.to_string(),
            scheme,
        })
    }

    /// The proxy URL string (verbatim).
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// The validated transport scheme.
    pub fn scheme(&self) -> ProxyScheme {
        self.scheme
    }
}

// ===========================================================================
// Transport route + routing table (Req 13.2, 13.5, 13.6)
// ===========================================================================

/// One transport-route rule: a [`RoutePattern`] bound to an optional
/// forwarding proxy and an SSL-verification policy (Req 13.3, 13.4).
///
/// `proxy == None` means matching requests go **direct** (no forwarding proxy)
/// but still honor `verify_ssl`.
#[derive(Debug, Clone)]
pub struct TransportRoute {
    /// The URL pattern this route applies to.
    pub pattern: RoutePattern,
    /// The forwarding proxy to route through, or `None` for a direct match.
    pub proxy: Option<ProxyUrl>,
    /// Whether TLS certificates are verified for matching requests (Req 13.4).
    pub verify_ssl: bool,
}

/// The resolved transport decision for one URL (the output of
/// [`RoutingTable::select_route`]).
#[derive(Debug, Clone, Copy)]
pub struct RouteSelection<'a> {
    /// The forwarding proxy to dial through, or `None` for a direct connection.
    pub proxy: Option<&'a ProxyUrl>,
    /// Whether to verify TLS certificates (Req 13.4).
    pub verify_ssl: bool,
    /// `true` when a specific route matched; `false` when this came from the
    /// all-proxy default / direct fallback (Req 13.5, 13.6).
    pub matched: bool,
}

impl<'a> RouteSelection<'a> {
    /// The selected forwarding-proxy URL string, if any.
    pub fn proxy_str(&self) -> Option<&'a str> {
        self.proxy.map(ProxyUrl::as_str)
    }
}

/// A set of [`TransportRoute`]s plus the all-proxy default-fallback policy, with
/// an attached forwarding-[`ClientCache`] (Req 13.2, 13.5, 13.6).
#[derive(Debug)]
pub struct RoutingTable {
    routes: Vec<TransportRoute>,
    /// When `true`, an unmatched request falls back to `default_proxy`
    /// (Req 13.5); when `false`, an unmatched request goes direct (Req 13.6).
    all_proxy: bool,
    /// The default forwarding proxy used by the all-proxy fallback (Req 13.5).
    default_proxy: Option<ProxyUrl>,
    /// Pre-built forwarding clients keyed by `(proxy, verify_ssl)`.
    clients: ClientCache,
}

impl RoutingTable {
    /// Assemble a routing table from explicit routes + the default-fallback
    /// policy. Uses the [`DEFAULT_CLIENT_CACHE_CAPACITY`] client LRU.
    pub fn new(
        routes: Vec<TransportRoute>,
        all_proxy: bool,
        default_proxy: Option<ProxyUrl>,
    ) -> Self {
        Self {
            routes,
            all_proxy,
            default_proxy,
            clients: ClientCache::with_capacity(DEFAULT_CLIENT_CACHE_CAPACITY),
        }
    }

    /// Build the routing table from the proxy configuration, validating every
    /// route pattern + proxy URL (Req 13.2, 13.3, 13.5, 13.6, 13.8).
    ///
    /// An invalid pattern or proxy URL is returned as an error (the caller —
    /// config load — logs and aborts; see [`RoutePattern::parse`]).
    pub fn from_proxy_config(cfg: &ProxyConfig) -> Result<RoutingTable, AppError> {
        let mut routes = Vec::with_capacity(cfg.transport_routes.len());
        for (pattern_str, route) in &cfg.transport_routes {
            let pattern = RoutePattern::parse(pattern_str).map_err(|e| {
                AppError::bad_request(format!(
                    "invalid transport-route pattern `{pattern_str}`: {e}"
                ))
            })?;
            // `proxy: true` requires a proxy URL; `proxy: false` is a direct
            // match (still honoring verify_ssl).
            let proxy = match (route.proxy, &route.proxy_url) {
                (true, Some(url)) => Some(ProxyUrl::parse(url)?),
                (true, None) => {
                    return Err(AppError::bad_request(format!(
                        "transport-route `{pattern_str}` sets proxy=true but has no proxy_url"
                    )))
                }
                (false, _) => None,
            };
            routes.push(TransportRoute {
                pattern,
                proxy,
                verify_ssl: route.verify_ssl,
            });
        }

        let default_proxy = match &cfg.forwarding_proxy {
            Some(url) => Some(ProxyUrl::parse(url)?),
            None => None,
        };

        Ok(RoutingTable::new(routes, cfg.all_proxy, default_proxy))
    }

    /// Select the transport decision for `url`: the most-specific matching
    /// route (fewest wildcards — Req 13.2), else the all-proxy default
    /// (Req 13.5), else direct (Req 13.6).
    pub fn select_route(&self, url: &Url) -> RouteSelection<'_> {
        let best = self
            .routes
            .iter()
            .filter(|r| r.pattern.matches(url))
            .min_by(|a, b| {
                // Fewer wildcards wins; ties broken by longer literal host,
                // then lexicographic pattern — fully deterministic.
                a.pattern
                    .wildcard_count()
                    .cmp(&b.pattern.wildcard_count())
                    .then_with(|| b.pattern.literal_len().cmp(&a.pattern.literal_len()))
                    .then_with(|| a.pattern.as_str().cmp(b.pattern.as_str()))
            });

        match best {
            // A specific route matched (Req 13.2) — even a `proxy: None`
            // (direct) match suppresses the all-proxy fallback (Req 13.6).
            Some(route) => RouteSelection {
                proxy: route.proxy.as_ref(),
                verify_ssl: route.verify_ssl,
                matched: true,
            },
            // No route matched: all-proxy → default proxy (Req 13.5); else
            // direct (Req 13.6).
            None => RouteSelection {
                proxy: if self.all_proxy {
                    self.default_proxy.as_ref()
                } else {
                    None
                },
                verify_ssl: true,
                matched: false,
            },
        }
    }

    /// Get (or lazily build + cache) the forwarding `reqwest::Client` to use for
    /// `url`, applying the selected proxy + SSL-verify policy (Req 13.3, 13.4).
    pub fn client_for(&self, url: &Url) -> Result<reqwest::Client, AppError> {
        let selection = self.select_route(url);
        self.clients
            .get_or_build(selection.proxy_str(), selection.verify_ssl)
    }

    /// The number of distinct forwarding clients currently cached.
    pub fn cached_client_count(&self) -> usize {
        self.clients.len()
    }
}

// ===========================================================================
// Forwarding-client LRU keyed by (proxy, verify_ssl)
// ===========================================================================

/// The cache key: a `(proxy URL, verify_ssl)` pair (Req 13.3, 13.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientKey {
    proxy: Option<String>,
    verify_ssl: bool,
}

/// A small LRU of pre-built forwarding `reqwest::Client`s keyed by
/// `(proxy, verify_ssl)` so a client is built once per distinct transport and
/// reused thereafter (design: Components → Transport routing & forwarding).
///
/// `reqwest::Client` is internally reference-counted, so the cached entry and
/// every returned clone share one connection pool.
#[derive(Debug)]
pub struct ClientCache {
    capacity: usize,
    inner: Mutex<CacheInner>,
    /// Count of real client builds (cache misses) — observability + tests.
    builds: AtomicU64,
}

#[derive(Debug)]
struct CacheInner {
    entries: HashMap<ClientKey, reqwest::Client>,
    /// Most-recently-used at the front, least-recently-used at the back.
    lru: VecDeque<ClientKey>,
}

impl ClientCache {
    /// Create a cache holding at most `capacity` distinct clients.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(CacheInner {
                entries: HashMap::new(),
                lru: VecDeque::new(),
            }),
            builds: AtomicU64::new(0),
        }
    }

    /// Return the cached client for `(proxy, verify_ssl)`, building and caching
    /// one on a miss (Req 13.3, 13.4). On a hit the key is promoted to
    /// most-recently-used.
    pub fn get_or_build(
        &self,
        proxy: Option<&str>,
        verify_ssl: bool,
    ) -> Result<reqwest::Client, AppError> {
        let key = ClientKey {
            proxy: proxy.map(str::to_string),
            verify_ssl,
        };

        let mut guard = self.inner.lock().expect("client-cache mutex poisoned");
        if let Some(client) = guard.entries.get(&key).cloned() {
            promote(&mut guard.lru, &key);
            return Ok(client);
        }

        // Miss: build the client outside-of nothing (build is cheap, no I/O).
        let client = build_forwarding_client(proxy, verify_ssl)?;
        self.builds.fetch_add(1, Ordering::Relaxed);
        guard.entries.insert(key.clone(), client.clone());
        guard.lru.push_front(key);

        // Evict the least-recently-used entry while over capacity.
        while guard.entries.len() > self.capacity {
            if let Some(evicted) = guard.lru.pop_back() {
                guard.entries.remove(&evicted);
            } else {
                break;
            }
        }

        Ok(client)
    }

    /// Total number of clients actually built (cache misses) over the cache's
    /// lifetime.
    pub fn builds(&self) -> u64 {
        self.builds.load(Ordering::Relaxed)
    }

    /// The number of clients currently cached.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("client-cache mutex poisoned")
            .entries
            .len()
    }

    /// `true` when no clients are cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Move `key` to the most-recently-used (front) position of the LRU order.
fn promote(lru: &mut VecDeque<ClientKey>, key: &ClientKey) {
    if let Some(pos) = lru.iter().position(|k| k == key) {
        lru.remove(pos);
    }
    lru.push_front(key.clone());
}

/// Build a forwarding `reqwest::Client` for the given proxy + SSL-verify policy
/// (Req 13.3, 13.4).
///
/// `verify_ssl == false` disables certificate verification **for this client
/// only** (Req 13.4); the scheme of `proxy` (http/https/socks4/socks5) selects
/// the proxy transport (Req 13.3). Connection pooling mirrors the egress
/// default client.
fn build_forwarding_client(
    proxy: Option<&str>,
    verify_ssl: bool,
) -> Result<reqwest::Client, AppError> {
    let mut builder = reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .redirect(reqwest::redirect::Policy::default());

    match proxy {
        Some(proxy_url) => {
            let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| {
                AppError::bad_request(format!("invalid forwarding proxy URL `{proxy_url}`: {e}"))
            })?;
            builder = builder.proxy(proxy);
        }
        None => {
            // Direct: do not inherit an ambient system proxy.
            builder = builder.no_proxy();
        }
    }

    if !verify_ssl {
        // Per-route SSL-verify disable (Req 13.4) — scoped to this client.
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder
        .build()
        .map_err(|e| AppError::unknown(format!("failed to build forwarding client: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportRouteConfig;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid test url")
    }

    fn route(pattern: &str, proxy: Option<&str>, verify_ssl: bool) -> TransportRoute {
        TransportRoute {
            pattern: RoutePattern::parse(pattern).expect("valid pattern"),
            proxy: proxy.map(|p| ProxyUrl::parse(p).expect("valid proxy url")),
            verify_ssl,
        }
    }

    // -- Pattern parsing: domain / all:// / * forms (Req 13.1) --------------

    #[test]
    fn parse_accepts_exact_domain_any_scheme() {
        let p = RoutePattern::parse("api.example.com").expect("plain domain parses");
        assert!(p.matches(&url("https://api.example.com/x")));
        assert!(p.matches(&url("http://api.example.com/x")));
        assert!(!p.matches(&url("https://other.com/x")));
        // No scheme + exact host => 1 wildcard (scheme).
        assert_eq!(p.wildcard_count(), 1);
    }

    #[test]
    fn parse_accepts_scheme_qualified_exact_host() {
        let p = RoutePattern::parse("https://api.example.com").expect("scheme+host parses");
        assert!(p.matches(&url("https://api.example.com/x")));
        // Scheme is exact: http must NOT match an https-only pattern.
        assert!(!p.matches(&url("http://api.example.com/x")));
        // Exact scheme + exact host => most specific (0 wildcards).
        assert_eq!(p.wildcard_count(), 0);
    }

    #[test]
    fn parse_accepts_all_scheme_form() {
        let p = RoutePattern::parse("all://api.example.com").expect("all:// parses");
        assert!(p.matches(&url("https://api.example.com/x")));
        assert!(p.matches(&url("http://api.example.com/x")));
        assert!(!p.matches(&url("https://nope.com/x")));
        // all:// => scheme wildcard.
        assert_eq!(p.wildcard_count(), 1);
    }

    #[test]
    fn parse_accepts_subdomain_wildcard() {
        let p = RoutePattern::parse("*.example.com").expect("subdomain wildcard parses");
        assert!(p.matches(&url("https://a.example.com/x")));
        assert!(p.matches(&url("https://a.b.example.com/x")));
        // Apex is not a subdomain match.
        assert!(!p.matches(&url("https://example.com/x")));
        assert!(!p.matches(&url("https://notexample.com/x")));
        // scheme wildcard + host wildcard => 2.
        assert_eq!(p.wildcard_count(), 2);
    }

    #[test]
    fn parse_accepts_total_wildcards() {
        for star in ["*", "all://"] {
            let p = RoutePattern::parse(star).unwrap_or_else(|_| panic!("`{star}` parses"));
            assert!(p.matches(&url("https://anything.example/x")));
            assert!(p.matches(&url("http://h/y")));
        }
    }

    #[test]
    fn parse_is_case_insensitive_for_scheme_and_host() {
        let p = RoutePattern::parse("HTTPS://API.Example.COM").expect("parses");
        assert!(p.matches(&url("https://api.example.com/x")));
        assert!(p.matches(&url("https://API.EXAMPLE.COM/x")));
    }

    // -- Invalid patterns rejected at config load (Req 13.8) ----------------

    #[test]
    fn parse_rejects_empty_pattern() {
        assert_eq!(RoutePattern::parse(""), Err(PatternError::Empty));
    }

    #[test]
    fn parse_rejects_whitespace_and_control() {
        assert_eq!(
            RoutePattern::parse("api .example.com"),
            Err(PatternError::Whitespace)
        );
        assert_eq!(
            RoutePattern::parse("api\texample.com"),
            Err(PatternError::Whitespace)
        );
    }

    #[test]
    fn parse_rejects_unsupported_scheme() {
        match RoutePattern::parse("ftp://host.example") {
            Err(PatternError::UnsupportedScheme(s)) => assert_eq!(s, "ftp"),
            other => panic!("expected UnsupportedScheme, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_malformed_host_wildcards() {
        // `*` in the middle / suffix is unsupported.
        assert!(matches!(
            RoutePattern::parse("api.*.com"),
            Err(PatternError::MalformedHost(_))
        ));
        assert!(matches!(
            RoutePattern::parse("*.*.com"),
            Err(PatternError::MalformedHost(_))
        ));
        // URL delimiters in the host are malformed.
        assert!(matches!(
            RoutePattern::parse("host.example/path"),
            Err(PatternError::MalformedHost(_))
        ));
    }

    // -- Most-specific (fewest-wildcards) match wins (Req 13.2) -------------

    #[test]
    fn select_route_prefers_fewest_wildcards() {
        let routes = vec![
            route("*", Some("http://catchall:1"), true),
            route("*.example.com", Some("http://suffix:2"), true),
            route("all://api.example.com", Some("http://anyscheme:3"), true),
            route("https://api.example.com", Some("http://exact:4"), true),
        ];
        let table = RoutingTable::new(routes, false, None);

        // Exact scheme+host (0 wildcards) wins over everything.
        let sel = table.select_route(&url("https://api.example.com/path"));
        assert_eq!(sel.proxy_str(), Some("http://exact:4"));
        assert!(sel.matched);
    }

    #[test]
    fn select_route_falls_through_specificity_when_exact_excluded_by_scheme() {
        let routes = vec![
            route("*", Some("http://catchall:1"), true),
            route("*.example.com", Some("http://suffix:2"), true),
            route("all://api.example.com", Some("http://anyscheme:3"), true),
            route("https://api.example.com", Some("http://exact:4"), true),
        ];
        let table = RoutingTable::new(routes, false, None);

        // http (not https) excludes the exact https-only route; the next most
        // specific is `all://api.example.com` (1 wildcard) over `*.example.com`
        // (2) and `*` (2).
        let sel = table.select_route(&url("http://api.example.com/path"));
        assert_eq!(sel.proxy_str(), Some("http://anyscheme:3"));
    }

    #[test]
    fn select_route_uses_suffix_over_catchall() {
        let routes = vec![
            route("*", Some("http://catchall:1"), true),
            route("*.example.com", Some("http://suffix:2"), true),
        ];
        let table = RoutingTable::new(routes, false, None);
        // Both patterns carry 2 wildcards (scheme-any + host-any/suffix), so the
        // tiebreak is the longer literal host: `*.example.com` (literal
        // `.example.com`) is more specific than the bare `*` catch-all (no
        // literal) and wins.
        let sel = table.select_route(&url("https://cdn.example.com/x"));
        assert_eq!(sel.proxy_str(), Some("http://suffix:2"));
    }

    #[test]
    fn select_route_suffix_beats_equal_wildcard_shorter_literal() {
        // Two equally-wildcarded (2 wc) suffix routes: the longer literal host
        // is the more specific tiebreak.
        let routes = vec![
            route("*.example.com", Some("http://short:1"), true),
            route("*.cdn.example.com", Some("http://long:2"), true),
        ];
        let table = RoutingTable::new(routes, false, None);
        let sel = table.select_route(&url("https://node.cdn.example.com/x"));
        assert_eq!(sel.proxy_str(), Some("http://long:2"));
    }

    // -- http/https/socks4/socks5 schemes (Req 13.3) ------------------------

    #[test]
    fn proxy_url_accepts_all_supported_schemes() {
        assert_eq!(
            ProxyUrl::parse("http://p:8080").unwrap().scheme(),
            ProxyScheme::Http
        );
        assert_eq!(
            ProxyUrl::parse("https://p:8443").unwrap().scheme(),
            ProxyScheme::Https
        );
        assert_eq!(
            ProxyUrl::parse("socks4://p:1080").unwrap().scheme(),
            ProxyScheme::Socks4
        );
        assert_eq!(
            ProxyUrl::parse("socks4a://p:1080").unwrap().scheme(),
            ProxyScheme::Socks4
        );
        assert_eq!(
            ProxyUrl::parse("socks5://p:1080").unwrap().scheme(),
            ProxyScheme::Socks5
        );
        assert_eq!(
            ProxyUrl::parse("socks5h://p:1080").unwrap().scheme(),
            ProxyScheme::Socks5
        );
    }

    #[test]
    fn proxy_url_rejects_unsupported_scheme_and_missing_scheme() {
        assert!(ProxyUrl::parse("ftp://p:21").is_err());
        assert!(ProxyUrl::parse("p:8080").is_err());
    }

    #[test]
    fn client_builds_for_every_supported_proxy_scheme() {
        // Building a client performs no network I/O; this proves each scheme is
        // accepted by reqwest::Proxy (Req 13.3).
        for proxy in [
            "http://proxy:8080",
            "https://proxy:8443",
            "socks4://proxy:1080",
            "socks5://proxy:1080",
            "socks5h://proxy:1080",
        ] {
            build_forwarding_client(Some(proxy), true)
                .unwrap_or_else(|e| panic!("client for {proxy} must build: {e}"));
        }
    }

    // -- Per-request SSL-verify disable (Req 13.4) --------------------------

    #[test]
    fn ssl_verify_disabled_builds_distinct_client() {
        // A verify=true and verify=false client for the same proxy are distinct
        // cache entries (the policy is per-request/per-route, Req 13.4).
        let cache = ClientCache::with_capacity(8);
        let _verify = cache.get_or_build(Some("http://p:8080"), true).unwrap();
        let _no_verify = cache.get_or_build(Some("http://p:8080"), false).unwrap();
        assert_eq!(cache.len(), 2, "verify_ssl is part of the cache key");
        assert_eq!(cache.builds(), 2);
    }

    #[test]
    fn ssl_verify_flag_flows_through_selection() {
        let routes = vec![route("insecure.example.com", Some("http://p:8080"), false)];
        let table = RoutingTable::new(routes, false, None);
        let sel = table.select_route(&url("https://insecure.example.com/x"));
        assert!(!sel.verify_ssl, "route disables SSL verification");
        // A non-matching host gets the default verify=true.
        let sel2 = table.select_route(&url("https://secure.example.com/x"));
        assert!(sel2.verify_ssl);
    }

    // -- all-proxy default fallback (Req 13.5) ------------------------------

    #[test]
    fn unmatched_falls_back_to_default_proxy_when_all_proxy_on() {
        let routes = vec![route("api.example.com", Some("http://specific:1"), true)];
        let default = ProxyUrl::parse("http://default:9").unwrap();
        let table = RoutingTable::new(routes, true, Some(default));

        // Unmatched host → all-proxy default (Req 13.5).
        let sel = table.select_route(&url("https://unmatched.host/x"));
        assert_eq!(sel.proxy_str(), Some("http://default:9"));
        assert!(!sel.matched, "the default fallback is not a specific match");

        // A matched host still uses its specific route.
        let sel2 = table.select_route(&url("https://api.example.com/x"));
        assert_eq!(sel2.proxy_str(), Some("http://specific:1"));
        assert!(sel2.matched);
    }

    // -- no-match direct when all-proxy off (Req 13.6) ----------------------

    #[test]
    fn unmatched_goes_direct_when_all_proxy_off() {
        let routes = vec![route("api.example.com", Some("http://specific:1"), true)];
        let default = ProxyUrl::parse("http://default:9").unwrap();
        // all_proxy = false: an unmatched request must go direct (Req 13.6),
        // even though a default proxy is configured.
        let table = RoutingTable::new(routes, false, Some(default));

        let sel = table.select_route(&url("https://unmatched.host/x"));
        assert_eq!(sel.proxy_str(), None, "no proxy when all-proxy is off");
        assert!(!sel.matched);
    }

    #[test]
    fn explicit_direct_route_suppresses_all_proxy_fallback() {
        // A `proxy: None` route is still a *match*, so it overrides the
        // all-proxy default for that host (Req 13.6 vs 13.5 precedence).
        let routes = vec![route("direct.example.com", None, true)];
        let default = ProxyUrl::parse("http://default:9").unwrap();
        let table = RoutingTable::new(routes, true, Some(default));

        let sel = table.select_route(&url("https://direct.example.com/x"));
        assert_eq!(
            sel.proxy_str(),
            None,
            "matched direct route beats all-proxy default"
        );
        assert!(sel.matched);
    }

    // -- Invalid patterns rejected at config load + logged (Req 13.8) -------

    #[test]
    fn from_proxy_config_rejects_invalid_pattern() {
        let mut cfg = ProxyConfig::default();
        cfg.transport_routes.insert(
            "bad pattern with space".to_string(),
            TransportRouteConfig {
                proxy: true,
                proxy_url: Some("http://p:8080".to_string()),
                verify_ssl: true,
            },
        );
        let err = RoutingTable::from_proxy_config(&cfg)
            .expect_err("invalid pattern must be rejected at load");
        assert!(err.message.contains("bad pattern with space"), "got: {err}");
    }

    #[test]
    fn from_proxy_config_rejects_invalid_proxy_url() {
        let mut cfg = ProxyConfig::default();
        cfg.transport_routes.insert(
            "api.example.com".to_string(),
            TransportRouteConfig {
                proxy: true,
                proxy_url: Some("ftp://p:21".to_string()),
                verify_ssl: true,
            },
        );
        let err = RoutingTable::from_proxy_config(&cfg)
            .expect_err("invalid proxy URL must be rejected at load");
        assert!(err.message.contains("unsupported scheme"), "got: {err}");
    }

    #[test]
    fn from_proxy_config_rejects_proxy_true_without_url() {
        let mut cfg = ProxyConfig::default();
        cfg.transport_routes.insert(
            "api.example.com".to_string(),
            TransportRouteConfig {
                proxy: true,
                proxy_url: None,
                verify_ssl: true,
            },
        );
        let err = RoutingTable::from_proxy_config(&cfg)
            .expect_err("proxy=true without a url must be rejected");
        assert!(err.message.contains("no proxy_url"), "got: {err}");
    }

    #[test]
    fn from_proxy_config_builds_valid_table() {
        let mut cfg = ProxyConfig {
            all_proxy: true,
            forwarding_proxy: Some("socks5://default:1080".to_string()),
            ..ProxyConfig::default()
        };
        cfg.transport_routes.insert(
            "https://api.example.com".to_string(),
            TransportRouteConfig {
                proxy: true,
                proxy_url: Some("http://specific:8080".to_string()),
                verify_ssl: false,
            },
        );
        let table = RoutingTable::from_proxy_config(&cfg).expect("valid config builds");

        let sel = table.select_route(&url("https://api.example.com/x"));
        assert_eq!(sel.proxy_str(), Some("http://specific:8080"));
        assert!(!sel.verify_ssl);

        // Unmatched → all-proxy default.
        let sel2 = table.select_route(&url("https://other.host/x"));
        assert_eq!(sel2.proxy_str(), Some("socks5://default:1080"));
    }

    // -- Client LRU keyed by (proxy, verify_ssl) (design: client cache) -----

    #[test]
    fn client_cache_reuses_client_for_same_key() {
        let cache = ClientCache::with_capacity(8);
        let _a = cache.get_or_build(Some("http://p:8080"), true).unwrap();
        let _b = cache.get_or_build(Some("http://p:8080"), true).unwrap();
        let _c = cache.get_or_build(Some("http://p:8080"), true).unwrap();
        // One build for three identical-key requests.
        assert_eq!(cache.builds(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn client_cache_distinguishes_proxy_and_direct() {
        let cache = ClientCache::with_capacity(8);
        cache.get_or_build(Some("http://p:8080"), true).unwrap();
        cache.get_or_build(Some("socks5://p:1080"), true).unwrap();
        cache.get_or_build(None, true).unwrap(); // direct
        assert_eq!(cache.builds(), 3);
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn client_cache_evicts_least_recently_used() {
        let cache = ClientCache::with_capacity(2);
        // Fill to capacity.
        cache.get_or_build(Some("http://a:1"), true).unwrap();
        cache.get_or_build(Some("http://b:2"), true).unwrap();
        assert_eq!(cache.len(), 2);

        // Touch `a` so `b` becomes least-recently-used.
        cache.get_or_build(Some("http://a:1"), true).unwrap();
        // Insert `c` → evicts `b`.
        cache.get_or_build(Some("http://c:3"), true).unwrap();
        assert_eq!(cache.len(), 2);

        // `b` was evicted (a fresh build); `a` is still cached (no rebuild).
        let builds_before = cache.builds();
        cache.get_or_build(Some("http://a:1"), true).unwrap();
        assert_eq!(cache.builds(), builds_before, "a must still be cached");
        cache.get_or_build(Some("http://b:2"), true).unwrap();
        assert_eq!(
            cache.builds(),
            builds_before + 1,
            "b must have been evicted"
        );
    }

    #[test]
    fn routing_table_client_for_caches_per_route() {
        let routes = vec![
            route(
                "https://api.example.com",
                Some("http://specific:8080"),
                true,
            ),
            route("insecure.example.com", Some("http://p:8080"), false),
        ];
        let table = RoutingTable::new(routes, false, None);

        // Same matched route twice → one build.
        table.client_for(&url("https://api.example.com/a")).unwrap();
        table.client_for(&url("https://api.example.com/b")).unwrap();
        assert_eq!(table.cached_client_count(), 1);

        // A different route (different proxy + verify) → a second client.
        table
            .client_for(&url("https://insecure.example.com/a"))
            .unwrap();
        assert_eq!(table.cached_client_count(), 2);

        // An unmatched direct request → a third (direct) client.
        table.client_for(&url("https://unmatched.host/x")).unwrap();
        assert_eq!(table.cached_client_count(), 3);
    }

    // -- select_route returns no proxy when table empty + all-proxy off -----

    #[test]
    fn empty_table_direct_by_default() {
        let table = RoutingTable::new(Vec::new(), false, None);
        let sel = table.select_route(&url("https://anything.host/x"));
        assert_eq!(sel.proxy_str(), None);
        assert!(!sel.matched);
        assert!(sel.verify_ssl);
    }
}
