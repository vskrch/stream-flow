//! M3U playlist builder (`utils::playlist`) — Req 15.1.
//!
//! Backs the mediaflow `/playlist/builder` endpoint: given a set of channels
//! (a display name plus an upstream URL, with optional EXTINF attributes), it
//! produces an `#EXTM3U` playlist in which **every** channel URL is rewritten
//! to a `Stream_Flow_System` proxy URL — the same sealed `d`-token proxy URL
//! [`generate_url`](super::generate_url) builds — so a player loading the
//! playlist streams through the proxy rather than hitting the origin directly
//! (Req 15.1).
//!
//! The rewrite reuses [`build_proxy_url`](super::generate_url::build_proxy_url),
//! so each channel's upstream URL, injected headers, expiry, and IP binding are
//! sealed into the encrypted `d` parameter and the path carries the configured
//! `Server_Path_Prefix` (Req 31.4) — identical to a single `/generate_url`
//! call, applied per channel.

use std::collections::BTreeMap;
use std::net::IpAddr;

use actix_web::{web, HttpResponse};

use crate::app::AppState;
use crate::auth::encryption::CbcKey;
use crate::errors::AppError;

use super::generate_url::{build_proxy_url, GenerateUrlRequest};

/// One channel entry in a playlist-build request.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChannelEntry {
    /// The channel display name (the EXTINF title).
    pub name: String,
    /// The upstream channel URL to proxy.
    pub url: String,
    /// Optional `tvg-*` / `group-title` style EXTINF attributes, emitted as
    /// `key="value"` pairs on the `#EXTINF` line.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// Optional upstream headers to inject for this channel (sealed into `d`).
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
}

/// A playlist-build request: the proxy base URL, the target proxy endpoint, the
/// channels, and optional global expiry / IP binding applied to every channel.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PlaylistBuildRequest {
    /// The public base URL of this proxy (scheme + host[:port]).
    pub mediaflow_proxy_url: String,
    /// The proxy endpoint each channel routes through. Defaults to the generic
    /// stream proxy when omitted (handled by `build_proxy_url`).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The channels to include.
    pub channels: Vec<ChannelEntry>,
    /// Optional lifetime in seconds applied to every channel's sealed token.
    #[serde(default)]
    pub expiration: Option<i64>,
    /// Optional client-IP binding applied to every channel's sealed token.
    #[serde(default)]
    pub ip: Option<IpAddr>,
}

/// Build an M3U playlist whose channel URLs are all rewritten through the proxy
/// (Req 15.1).
///
/// Pure over `now_unix_secs` so the per-channel expiry computation is
/// deterministic and testable. A channel with an empty/invalid URL surfaces a
/// [`bad_request`](AppError::bad_request) naming the offending channel.
pub fn build_playlist(
    req: &PlaylistBuildRequest,
    path_prefix: &str,
    key: &CbcKey,
    now_unix_secs: i64,
) -> Result<String, AppError> {
    let mut out = String::from("#EXTM3U\n");

    for channel in &req.channels {
        let gen = GenerateUrlRequest {
            mediaflow_proxy_url: Some(req.mediaflow_proxy_url.clone()),
            endpoint: req.endpoint.clone(),
            destination_url: channel.url.clone(),
            query_params: BTreeMap::new(),
            request_headers: channel.request_headers.clone(),
            filename: None,
            expiration: req.expiration,
            ip: req.ip,
        };
        let proxied = build_proxy_url(&gen, path_prefix, key, now_unix_secs).map_err(|e| {
            AppError::bad_request(format!(
                "failed to build proxy URL for channel `{}`: {}",
                channel.name, e.message
            ))
        })?;

        out.push_str(&extinf_line(channel));
        out.push('\n');
        out.push_str(&proxied);
        out.push('\n');
    }

    Ok(out)
}

/// Render a channel's `#EXTINF` line: `#EXTINF:-1 key="value" …,Name`.
fn extinf_line(channel: &ChannelEntry) -> String {
    let mut line = String::from("#EXTINF:-1");
    for (k, v) in &channel.attributes {
        // EXTINF attribute values are double-quoted; strip embedded quotes so a
        // value can never break out of the attribute (a non-secret, cosmetic
        // sanitization — the authoritative URL is the sealed `d` token).
        let sanitized = v.replace('"', "");
        line.push_str(&format!(" {k}=\"{sanitized}\""));
    }
    line.push(',');
    line.push_str(&channel.name);
    line
}

/// `POST /playlist/builder` — return the proxied M3U playlist (Req 15.1).
pub async fn playlist_builder_endpoint(
    state: web::Data<AppState>,
    body: web::Json<PlaylistBuildRequest>,
) -> Result<HttpResponse, AppError> {
    let config = state.config();
    let key = key_from_config(config);
    let now = now_unix_secs();
    let playlist = build_playlist(&body, &config.server.path_prefix, &key, now)?;
    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .body(playlist))
}

/// Derive the AES-CBC key from the configured `API_Password` (Req 14.1).
fn key_from_config(config: &crate::config::Config) -> CbcKey {
    let password = config
        .auth
        .api_password
        .as_ref()
        .map(|s| s.expose())
        .unwrap_or("");
    CbcKey::from_api_password(password)
}

/// Current unix time in whole seconds. Isolated so [`build_playlist`] stays
/// pure over its `now_unix_secs` argument.
fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::encryption::decrypt;
    use crate::errors::ErrorCategory;
    use url::Url;

    fn key() -> CbcKey {
        CbcKey::from_api_password("playlist-password")
    }

    fn request() -> PlaylistBuildRequest {
        PlaylistBuildRequest {
            mediaflow_proxy_url: "https://proxy.example.com".to_string(),
            endpoint: Some("/proxy/stream".to_string()),
            channels: vec![
                ChannelEntry {
                    name: "Channel One".to_string(),
                    url: "https://origin.example/one.m3u8".to_string(),
                    attributes: BTreeMap::new(),
                    request_headers: BTreeMap::new(),
                },
                ChannelEntry {
                    name: "Channel Two".to_string(),
                    url: "https://origin.example/two.m3u8".to_string(),
                    attributes: BTreeMap::new(),
                    request_headers: BTreeMap::new(),
                },
            ],
            expiration: None,
            ip: None,
        }
    }

    /// Collect the non-comment URL lines from a built playlist.
    fn url_lines(playlist: &str) -> Vec<&str> {
        playlist
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .collect()
    }

    // -- Req 15.1: playlist header + per-channel rewrite ---------------------

    #[test]
    fn starts_with_extm3u_header() {
        let pl = build_playlist(&request(), "", &key(), 1_000).unwrap();
        assert!(pl.starts_with("#EXTM3U"), "playlist must start with #EXTM3U");
    }

    #[test]
    fn emits_one_extinf_and_one_url_per_channel() {
        let pl = build_playlist(&request(), "", &key(), 1_000).unwrap();
        let extinf_count = pl.lines().filter(|l| l.starts_with("#EXTINF")).count();
        assert_eq!(extinf_count, 2);
        assert_eq!(url_lines(&pl).len(), 2);
    }

    #[test]
    fn every_channel_url_is_rewritten_through_the_proxy() {
        let req = request();
        let pl = build_playlist(&req, "", &key(), 1_000).unwrap();
        for line in url_lines(&pl) {
            let parsed = Url::parse(line).expect("each URL line parses");
            // Rewritten to the proxy host + endpoint, never the origin.
            assert_eq!(parsed.host_str(), Some("proxy.example.com"));
            assert_eq!(parsed.path(), "/proxy/stream");
            assert!(
                parsed.query_pairs().any(|(k, _)| k == "d"),
                "each rewritten URL carries an encrypted d token"
            );
            // No origin URL leaks into the playlist line in cleartext.
            assert!(!line.contains("origin.example"));
        }
    }

    #[test]
    fn sealed_token_recovers_each_channel_origin_url() {
        let req = request();
        let pl = build_playlist(&req, "", &key(), 1_000).unwrap();
        let urls = url_lines(&pl);

        for (line, channel) in urls.iter().zip(req.channels.iter()) {
            let token = Url::parse(line)
                .unwrap()
                .query_pairs()
                .find(|(k, _)| k == "d")
                .map(|(_, v)| v.into_owned())
                .expect("d token present");
            let payload = decrypt(&token, &key()).expect("d decrypts");
            assert_eq!(payload.url, channel.url, "the sealed token must carry the origin URL");
        }
    }

    #[test]
    fn applies_server_path_prefix_to_every_channel() {
        let pl = build_playlist(&request(), "/cdn/v1", &key(), 1_000).unwrap();
        for line in url_lines(&pl) {
            assert_eq!(Url::parse(line).unwrap().path(), "/cdn/v1/proxy/stream");
        }
    }

    #[test]
    fn extinf_carries_name_and_attributes() {
        let mut req = request();
        req.channels[0]
            .attributes
            .insert("group-title".to_string(), "News".to_string());
        let pl = build_playlist(&req, "", &key(), 1_000).unwrap();
        let extinf = pl
            .lines()
            .find(|l| l.starts_with("#EXTINF"))
            .expect("an EXTINF line");
        assert!(extinf.contains("group-title=\"News\""));
        assert!(extinf.ends_with(",Channel One"));
    }

    #[test]
    fn per_channel_headers_are_sealed() {
        let mut req = request();
        req.channels[0]
            .request_headers
            .insert("Referer".to_string(), "https://ref.example/".to_string());
        let pl = build_playlist(&req, "", &key(), 1_000).unwrap();
        let first = url_lines(&pl)[0];
        let token = Url::parse(first)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "d")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        let payload = decrypt(&token, &key()).unwrap();
        assert_eq!(payload.headers.get("Referer").map(String::as_str), Some("https://ref.example/"));
    }

    #[test]
    fn empty_channels_yield_header_only_playlist() {
        let mut req = request();
        req.channels.clear();
        let pl = build_playlist(&req, "", &key(), 1_000).unwrap();
        assert_eq!(pl.trim(), "#EXTM3U");
    }

    #[test]
    fn invalid_channel_url_is_rejected_naming_the_channel() {
        let mut req = request();
        req.channels[0].url = "".to_string();
        let err = build_playlist(&req, "", &key(), 1_000).unwrap_err();
        assert_eq!(err.category, ErrorCategory::BadRequest);
        assert!(
            err.message.contains("Channel One"),
            "error should name the offending channel, got: {}",
            err.message
        );
    }
}
