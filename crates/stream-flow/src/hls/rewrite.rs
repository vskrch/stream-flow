//! HLS manifest parse + full URL rewriting (`hls::rewrite`) — Req 1.1–1.4, 1.8.
//!
//! Given an upstream `.m3u8` body and the absolute URL it was fetched from,
//! [`HlsRewriter::rewrite`] parses it with [`m3u8_rs`] and returns a serialized
//! manifest in which **every** variant, segment, `#EXT-X-KEY`, and
//! `#EXT-X-MAP` URL has been rewritten to a `stream-flow` proxy URL (Req 1.1).
//! Each rewritten URL embeds the resolved upstream URL and the custom upstream
//! request headers inside an encrypted `d` proxy-link token (the
//! [`auth::encryption`](crate::auth::encryption) mediaflow-style AES-CBC
//! format), so the proxy can re-fetch the derived resource with the same
//! headers (Req 1.2, 1.6) and nothing in the output still points at the
//! upstream origin (Property 10).
//!
//! ## Rewrite rules (design: Components → HLS)
//!
//! * **Master playlist** — each variant (`#EXT-X-STREAM-INF`) and each
//!   alternative-rendition (`#EXT-X-MEDIA`) sub-playlist URI is rewritten to a
//!   *manifest* proxy URL so the sub-playlist is itself re-fetched and
//!   re-rewritten (Req 1.2). Session-key (`#EXT-X-SESSION-KEY`) URIs are
//!   rewritten to *key* proxy URLs.
//! * **Media playlist** — each segment URI is rewritten to a *segment* proxy
//!   URL (a sub-playlist URI to a *manifest* proxy URL), each `#EXT-X-KEY` URI
//!   to a *key* proxy URL, and each `#EXT-X-MAP` (init-segment) URI to a
//!   *segment* proxy URL (Req 1.3).
//! * **Relative URIs** — every URI is first resolved against the manifest base
//!   URL (the absolute URL the manifest was fetched from) before being
//!   rewritten, so a relative `seg001.ts` becomes an absolute upstream URL in
//!   the token (Req 1.4).
//! * **Unparseable body** — a body that is not a parseable `M3U8_Manifest`
//!   yields a descriptive [`AppError::bad_request`] parse error naming the
//!   manifest URL (Req 1.8).
//!
//! Tags that `m3u8_rs` keeps verbatim in `unknown_tags` (e.g. an
//! `#EXT-X-MEDIA` carrying `FORCED=NO` that the strict parser rejects into the
//! unknown bucket) are scanned for a `URI="…"` attribute and rewritten in place
//! too, so no rendition sub-playlist escapes rewriting.

use std::collections::BTreeMap;

use m3u8_rs::{MasterPlaylist, MediaPlaylist, Playlist};
use url::Url;

use crate::auth::encryption::{encrypt, CbcKey, ProxyPayload};
use crate::errors::AppError;

/// The proxy endpoint a rewritten URL routes through. Each maps to a distinct
/// `/proxy/hls/{…}` path so the engine knows whether the derived resource is a
/// (re-rewritten) manifest, an opaque segment, or a decryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    /// A sub-playlist that must itself be fetched and re-rewritten.
    Manifest,
    /// An opaque media segment (or `#EXT-X-MAP` init segment) streamed through.
    Segment,
    /// An `#EXT-X-KEY` / `#EXT-X-SESSION-KEY` decryption key.
    Key,
}

impl Endpoint {
    /// The `/proxy/hls/{…}` path component for this endpoint.
    fn path(self) -> &'static str {
        match self {
            Endpoint::Manifest => "manifest",
            Endpoint::Segment => "segment",
            Endpoint::Key => "key",
        }
    }
}

/// Rewrites upstream HLS manifests so every embedded URL flows back through the
/// `stream-flow` proxy (design: Components → HLS; Req 1.1–1.4).
///
/// Built once per HLS request from the public proxy base, the proxy-link
/// encryption key (derived from the `API_Password`), and the custom upstream
/// headers to forward to all derived requests (Req 1.6).
#[derive(Clone)]
pub struct HlsRewriter {
    /// Public base for generated URLs (e.g. `https://proxy.example/mediaflow`),
    /// stored without a trailing `/`.
    proxy_base: String,
    /// Key for the encrypted `d` proxy-link token (derived from `API_Password`).
    key: CbcKey,
    /// Custom upstream request headers embedded in every derived proxy URL so
    /// they are forwarded to the upstream for the manifest and all derived
    /// segment/key requests (Req 1.6).
    headers: BTreeMap<String, String>,
}

impl HlsRewriter {
    /// Build a rewriter for the given public `proxy_base` and proxy-link `key`.
    ///
    /// Any trailing `/` on `proxy_base` is trimmed so generated URLs do not
    /// contain a doubled slash.
    pub fn new(proxy_base: impl Into<String>, key: CbcKey) -> Self {
        Self {
            proxy_base: proxy_base.into().trim_end_matches('/').to_string(),
            key,
            headers: BTreeMap::new(),
        }
    }

    /// Attach the custom upstream headers to embed in every derived proxy URL
    /// (forwarded to the upstream for all derived requests — Req 1.6).
    pub fn with_headers(mut self, headers: BTreeMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// The `/proxy/hls/` URL prefix every rewritten URL begins with. A URL that
    /// starts with this prefix is a `stream-flow` proxy URL (used by Property
    /// 10 to assert no upstream-origin URL survives).
    pub fn proxy_prefix(&self) -> String {
        format!("{}/proxy/hls/", self.proxy_base)
    }

    /// Parse the `body` fetched from `manifest_url`, rewrite every embedded URL
    /// to a proxy URL, and return the serialized manifest (Req 1.1–1.4).
    ///
    /// Returns [`AppError::bad_request`] with a descriptive, manifest-naming
    /// message when `body` is not a parseable `M3U8_Manifest` (Req 1.8).
    pub fn rewrite(&self, body: &[u8], manifest_url: &Url) -> Result<String, AppError> {
        match m3u8_rs::parse_playlist_res(body) {
            Ok(Playlist::MasterPlaylist(pl)) => self.rewrite_master(pl, manifest_url),
            Ok(Playlist::MediaPlaylist(pl)) => self.rewrite_media(pl, manifest_url),
            Err(e) => Err(AppError::bad_request(format!(
                "failed to parse M3U8 manifest from {manifest_url}: {e}"
            ))),
        }
    }

    // -- Master playlist -----------------------------------------------------

    fn rewrite_master(
        &self,
        mut pl: MasterPlaylist,
        base: &Url,
    ) -> Result<String, AppError> {
        // Variant sub-playlists (#EXT-X-STREAM-INF / #EXT-X-I-FRAME-STREAM-INF).
        for variant in &mut pl.variants {
            variant.uri = self.proxy_uri(&variant.uri, base, Endpoint::Manifest)?;
        }
        // Alternative renditions (#EXT-X-MEDIA) that carry a sub-playlist URI.
        for alt in &mut pl.alternatives {
            if let Some(uri) = alt.uri.clone() {
                alt.uri = Some(self.proxy_uri(&uri, base, Endpoint::Manifest)?);
            }
        }
        // Session keys (#EXT-X-SESSION-KEY) carry a decryption-key URI.
        for session_key in &mut pl.session_key {
            if let Some(uri) = session_key.0.uri.clone() {
                session_key.0.uri = Some(self.proxy_uri(&uri, base, Endpoint::Key)?);
            }
        }
        // Tags m3u8-rs kept verbatim: rewrite any URI="…" inside them.
        for tag in &mut pl.unknown_tags {
            if let Some(rest) = tag.rest.clone() {
                let endpoint = endpoint_for_unknown_tag(&tag.tag);
                tag.rest = Some(self.rewrite_uri_attr(&rest, base, endpoint)?);
            }
        }
        serialize(&Playlist::MasterPlaylist(pl))
    }

    // -- Media playlist ------------------------------------------------------

    fn rewrite_media(&self, mut pl: MediaPlaylist, base: &Url) -> Result<String, AppError> {
        for seg in &mut pl.segments {
            // #EXT-X-KEY decryption key.
            if let Some(key) = seg.key.as_mut() {
                if let Some(uri) = key.uri.clone() {
                    key.uri = Some(self.proxy_uri(&uri, base, Endpoint::Key)?);
                }
            }
            // #EXT-X-MAP init segment.
            if let Some(map) = seg.map.as_mut() {
                map.uri = self.proxy_uri(&map.uri, base, Endpoint::Segment)?;
            }
            // The media segment URI itself; a sub-playlist (`.m3u8`) routes
            // through the manifest endpoint so it is re-rewritten.
            let endpoint = if is_playlist_uri(&seg.uri) {
                Endpoint::Manifest
            } else {
                Endpoint::Segment
            };
            seg.uri = self.proxy_uri(&seg.uri, base, endpoint)?;
            // URI="…" inside per-segment verbatim tags.
            for tag in &mut seg.unknown_tags {
                if let Some(rest) = tag.rest.clone() {
                    let endpoint = endpoint_for_unknown_tag(&tag.tag);
                    tag.rest = Some(self.rewrite_uri_attr(&rest, base, endpoint)?);
                }
            }
        }
        // URI="…" inside playlist-level verbatim tags (before the first segment).
        for tag in &mut pl.unknown_tags {
            if let Some(rest) = tag.rest.clone() {
                let endpoint = endpoint_for_unknown_tag(&tag.tag);
                tag.rest = Some(self.rewrite_uri_attr(&rest, base, endpoint)?);
            }
        }
        serialize(&Playlist::MediaPlaylist(pl))
    }

    // -- URL building --------------------------------------------------------

    /// Resolve `uri` against the manifest `base` (Req 1.4) and wrap it in a
    /// proxy URL routing through `endpoint`, embedding the resolved upstream
    /// URL + forwarded headers in the encrypted `d` token (Req 1.2, 1.6).
    fn proxy_uri(&self, uri: &str, base: &Url, endpoint: Endpoint) -> Result<String, AppError> {
        let resolved = resolve(base, uri);
        let token = self.encrypt_token(&resolved)?;
        Ok(format!(
            "{}/proxy/hls/{}?d={token}",
            self.proxy_base,
            endpoint.path()
        ))
    }

    /// Encrypt a proxy-link `d` token carrying `resolved_url` + the forwarded
    /// headers (Req 1.2, 1.6).
    fn encrypt_token(&self, resolved_url: &str) -> Result<String, AppError> {
        let payload = ProxyPayload {
            url: resolved_url.to_string(),
            headers: self.headers.clone(),
            filename: None,
            exp: None,
            ip: None,
        };
        encrypt(&payload, &self.key)
    }

    /// Rewrite the first `URI="…"` value inside a tag attribute string `rest`
    /// (resolving it against `base` and wrapping it for `endpoint`); other
    /// attributes are left untouched. Tags without a `URI="…"` are returned
    /// unchanged.
    fn rewrite_uri_attr(
        &self,
        rest: &str,
        base: &Url,
        endpoint: Endpoint,
    ) -> Result<String, AppError> {
        const NEEDLE: &str = "URI=\"";
        let Some(start) = rest.find(NEEDLE) else {
            return Ok(rest.to_string());
        };
        let value_start = start + NEEDLE.len();
        let Some(rel_end) = rest[value_start..].find('"') else {
            return Ok(rest.to_string());
        };
        let original = &rest[value_start..value_start + rel_end];
        let proxied = self.proxy_uri(original, base, endpoint)?;
        Ok(rest.replacen(
            &format!("{NEEDLE}{original}\""),
            &format!("{NEEDLE}{proxied}\""),
            1,
        ))
    }
}

/// Pick the proxy endpoint for a URI carried inside a verbatim tag: rendition
/// (`#EXT-X-MEDIA`) and I-frame (`#EXT-X-I-FRAME-STREAM-INF`) URIs are
/// sub-playlists → manifest; everything else (custom DRM/key tags) → key.
fn endpoint_for_unknown_tag(tag: &str) -> Endpoint {
    if tag.eq_ignore_ascii_case("X-MEDIA") || tag.eq_ignore_ascii_case("X-I-FRAME-STREAM-INF") {
        Endpoint::Manifest
    } else {
        Endpoint::Key
    }
}

/// Resolve a possibly-relative `uri` against the manifest `base` URL (Req 1.4).
///
/// Absolute URIs are returned unchanged; relative URIs are joined onto `base`.
/// A URI that cannot be joined (malformed) falls back to its raw form so it is
/// still wrapped in a proxy URL rather than silently leaking the original.
fn resolve(base: &Url, uri: &str) -> String {
    base.join(uri)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| uri.to_string())
}

/// `true` when a URI names an HLS sub-playlist (`.m3u8` / `.m3u`), ignoring any
/// query string or fragment.
fn is_playlist_uri(uri: &str) -> bool {
    let path = uri.split(['?', '#']).next().unwrap_or(uri);
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".m3u8") || lower.ends_with(".m3u")
}

/// Serialize a parsed playlist back to a UTF-8 string (the parse/serialize
/// round trip of Property 10).
fn serialize(playlist: &Playlist) -> Result<String, AppError> {
    let mut out = Vec::new();
    playlist
        .write_to(&mut out)
        .map_err(|e| AppError::unknown(format!("failed to serialize rewritten manifest: {e}")))?;
    String::from_utf8(out)
        .map_err(|e| AppError::unknown(format!("rewritten manifest is not valid UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::encryption::decrypt;

    fn key() -> CbcKey {
        CbcKey::from_api_password("test-secret")
    }

    fn rewriter() -> HlsRewriter {
        HlsRewriter::new("https://proxy.example.test/mediaflow", key())
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// Extract the decrypted upstream URL embedded in a rewritten proxy URL's
    /// `d` token.
    fn token_url(proxy_url: &str) -> String {
        let token = proxy_url
            .split_once("?d=")
            .unwrap_or_else(|| panic!("expected `?d=` proxy URL, got {proxy_url}"))
            .1;
        decrypt(token, &key()).expect("token decrypts").url
    }

    /// Extract the decrypted payload (url + headers) from a rewritten proxy URL.
    fn token_payload(proxy_url: &str) -> ProxyPayload {
        let token = proxy_url.split_once("?d=").expect("has token").1;
        decrypt(token, &key()).expect("token decrypts")
    }

    /// Every non-comment URL line (segments, sub-playlists) and every `URI="…"`
    /// value in a manifest, for "nothing points at the origin" assertions.
    fn all_urls(manifest: &str) -> Vec<String> {
        let mut urls = Vec::new();
        for line in manifest.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                // Pull out a URI="…" attribute when present.
                if let Some(start) = line.find("URI=\"") {
                    let s = start + 5;
                    if let Some(end) = line[s..].find('"') {
                        urls.push(line[s..s + end].to_string());
                    }
                }
            } else {
                urls.push(line.to_string());
            }
        }
        urls
    }

    // -- Req 1.8: unparseable body → descriptive parse error -----------------

    #[test]
    fn unparseable_body_is_a_descriptive_bad_request() {
        let body = b"this is definitely not an m3u8 playlist";
        let err = rewriter()
            .rewrite(body, &url("https://cdn.example.com/playlist.m3u8"))
            .expect_err("a non-m3u8 body must be a parse error");
        assert_eq!(err.category, crate::errors::ErrorCategory::BadRequest);
        // Descriptive: names the manifest URL.
        assert!(
            err.message.contains("https://cdn.example.com/playlist.m3u8"),
            "parse error must name the manifest URL, got: {}",
            err.message
        );
        assert!(
            err.message.to_lowercase().contains("parse"),
            "parse error must be descriptive, got: {}",
            err.message
        );
    }

    // -- Req 1.1/1.2: master variant URLs rewritten to proxy URLs ------------

    #[test]
    fn master_variants_rewritten_to_manifest_proxy_urls() {
        let m3u8 = b"#EXTM3U\n#EXT-X-VERSION:3\n\
            #EXT-X-STREAM-INF:BANDWIDTH=1400000\nhigh/index.m3u8\n\
            #EXT-X-STREAM-INF:BANDWIDTH=400000\nlow/index.m3u8\n";
        let out = rewriter()
            .rewrite(m3u8, &url("https://cdn.example.com/master.m3u8"))
            .expect("rewrite succeeds");

        let prefix = rewriter().proxy_prefix();
        let variant_urls: Vec<_> = all_urls(&out);
        assert_eq!(variant_urls.len(), 2);
        for u in &variant_urls {
            assert!(
                u.starts_with(&format!("{prefix}manifest?d=")),
                "variant must be a manifest proxy URL, got {u}"
            );
        }
        // Relative URIs resolved against the manifest base before wrapping.
        assert_eq!(
            token_url(&variant_urls[0]),
            "https://cdn.example.com/high/index.m3u8"
        );
        assert_eq!(
            token_url(&variant_urls[1]),
            "https://cdn.example.com/low/index.m3u8"
        );
    }

    // -- Req 1.3: media key/map/segment URIs rewritten -----------------------

    #[test]
    fn media_key_map_and_segment_uris_rewritten() {
        let m3u8 = b"#EXTM3U\n#EXT-X-VERSION:6\n#EXT-X-TARGETDURATION:6\n\
            #EXT-X-MAP:URI=\"init.mp4\"\n\
            #EXT-X-KEY:METHOD=AES-128,URI=\"https://keys.example.com/k1.bin\",IV=0x00000000000000000000000000000000\n\
            #EXTINF:6.0,\nseg001.ts\n\
            #EXTINF:6.0,\nseg002.ts\n#EXT-X-ENDLIST\n";
        let r = rewriter();
        let out = r
            .rewrite(m3u8, &url("https://cdn.example.com/v/media.m3u8"))
            .expect("rewrite succeeds");
        let prefix = r.proxy_prefix();

        // Segment URIs → segment proxy URLs, resolved against the base.
        let seg_lines: Vec<_> = out
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .collect();
        assert_eq!(seg_lines.len(), 2);
        assert!(seg_lines[0].starts_with(&format!("{prefix}segment?d=")));
        assert_eq!(token_url(seg_lines[0]), "https://cdn.example.com/v/seg001.ts");

        // #EXT-X-MAP URI → segment proxy URL (resolved).
        let map_line = out.lines().find(|l| l.starts_with("#EXT-X-MAP")).unwrap();
        let map_uri = map_line.split_once("URI=\"").unwrap().1.split('"').next().unwrap();
        assert!(map_uri.starts_with(&format!("{prefix}segment?d=")));
        assert_eq!(token_url(map_uri), "https://cdn.example.com/v/init.mp4");

        // #EXT-X-KEY URI → key proxy URL (already absolute, preserved).
        let key_line = out.lines().find(|l| l.starts_with("#EXT-X-KEY")).unwrap();
        let key_uri = key_line.split_once("URI=\"").unwrap().1.split('"').next().unwrap();
        assert!(key_uri.starts_with(&format!("{prefix}key?d=")));
        assert_eq!(token_url(key_uri), "https://keys.example.com/k1.bin");
    }

    // -- Req 1.1 / Property 10: nothing in the output points at the origin ---

    #[test]
    fn no_output_url_points_at_the_upstream_origin() {
        let m3u8 = b"#EXTM3U\n#EXT-X-VERSION:6\n#EXT-X-TARGETDURATION:6\n\
            #EXT-X-MAP:URI=\"https://cdn.example.com/v/init.mp4\"\n\
            #EXT-X-KEY:METHOD=AES-128,URI=\"key.bin\",IV=0x00000000000000000000000000000000\n\
            #EXTINF:6.0,\nhttps://cdn.example.com/v/seg001.ts\n\
            #EXTINF:6.0,\nseg002.ts\n#EXT-X-ENDLIST\n";
        let r = rewriter();
        let out = r
            .rewrite(m3u8, &url("https://cdn.example.com/v/media.m3u8"))
            .expect("rewrite succeeds");
        let prefix = r.proxy_prefix();

        for u in all_urls(&out) {
            assert!(
                u.starts_with(&prefix),
                "output URL must be a proxy URL, got {u}"
            );
            assert!(
                !u.contains("cdn.example.com"),
                "no output URL may reference the upstream origin, got {u}"
            );
        }
    }

    // -- Req 1.4: relative URIs resolved against the manifest base -----------

    #[test]
    fn relative_uris_resolved_against_manifest_base() {
        let m3u8 = b"#EXTM3U\n#EXT-X-TARGETDURATION:6\n\
            #EXTINF:6.0,\n../seg/abs.ts\n#EXT-X-ENDLIST\n";
        let r = rewriter();
        let out = r
            .rewrite(m3u8, &url("https://cdn.example.com/a/b/media.m3u8"))
            .expect("rewrite succeeds");
        let seg = out
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .unwrap();
        // `../seg/abs.ts` resolved against `/a/b/media.m3u8` → `/a/seg/abs.ts`.
        assert_eq!(token_url(seg), "https://cdn.example.com/a/seg/abs.ts");
    }

    // -- Req 1.2 / 1.6: custom headers forwarded into derived proxy URLs -----

    #[test]
    fn custom_headers_embedded_in_derived_proxy_urls() {
        let mut headers = BTreeMap::new();
        headers.insert("Referer".to_string(), "https://referer.example/".to_string());
        headers.insert("User-Agent".to_string(), "stream-flow/test".to_string());
        let r = rewriter().with_headers(headers.clone());

        let m3u8 = b"#EXTM3U\n#EXT-X-TARGETDURATION:6\n\
            #EXTINF:6.0,\nseg001.ts\n#EXT-X-ENDLIST\n";
        let out = r
            .rewrite(m3u8, &url("https://cdn.example.com/media.m3u8"))
            .expect("rewrite succeeds");
        let seg = out
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .unwrap();

        let payload = token_payload(seg);
        assert_eq!(payload.url, "https://cdn.example.com/seg001.ts");
        assert_eq!(payload.headers, headers, "headers must be forwarded to derived requests");
    }

    // -- EXT-X-MEDIA renditions (alternatives) rewritten to manifest URLs ----

    #[test]
    fn master_alternative_media_uris_rewritten() {
        let m3u8 = b"#EXTM3U\n#EXT-X-VERSION:4\n\
            #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",NAME=\"English\",DEFAULT=YES,URI=\"audio/eng.m3u8\"\n\
            #EXT-X-STREAM-INF:BANDWIDTH=1400000,AUDIO=\"aud\"\nvideo/index.m3u8\n";
        let r = rewriter();
        let out = r
            .rewrite(m3u8, &url("https://cdn.example.com/master.m3u8"))
            .expect("rewrite succeeds");
        let prefix = r.proxy_prefix();

        let media_line = out.lines().find(|l| l.starts_with("#EXT-X-MEDIA")).unwrap();
        let uri = media_line.split_once("URI=\"").unwrap().1.split('"').next().unwrap();
        assert!(uri.starts_with(&format!("{prefix}manifest?d=")));
        assert_eq!(token_url(uri), "https://cdn.example.com/audio/eng.m3u8");
    }

    // -- Parse/serialize round trip (Property 10 round-trip arm) -------------

    #[test]
    fn parse_serialize_round_trip_is_equivalent() {
        let m3u8 = b"#EXTM3U\n#EXT-X-VERSION:3\n\
            #EXT-X-STREAM-INF:BANDWIDTH=1400000,CODECS=\"avc1.4d401f\"\nhigh.m3u8\n\
            #EXT-X-STREAM-INF:BANDWIDTH=400000\nlow.m3u8\n";
        let parsed = m3u8_rs::parse_playlist_res(m3u8).expect("parses");
        let serialized = serialize(&parsed).expect("serializes");
        let reparsed = m3u8_rs::parse_playlist_res(serialized.as_bytes()).expect("re-parses");
        assert_eq!(parsed, reparsed, "parse→serialize→parse must be a fixed point");
    }

    // -- proxy_base trailing slash is normalized -----------------------------

    #[test]
    fn proxy_base_trailing_slash_trimmed() {
        let r = HlsRewriter::new("https://proxy.example/", key());
        assert_eq!(r.proxy_prefix(), "https://proxy.example/proxy/hls/");
    }
}
