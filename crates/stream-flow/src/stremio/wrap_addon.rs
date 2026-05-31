//! Wrap addon (`stremio::wrap_addon`) — Req 24.
//!
//! The Wrap addon turns one or more **upstream** Stremio addons into a single
//! addon served through stream-flow. It:
//!
//! * **aggregates the upstream manifests** into one [`Manifest`] declaring the
//!   union of their resources, content types, id prefixes, and catalogs
//!   (Req 24.1);
//! * **forwards + aggregates** `catalog` / `meta` / `stream` / `subtitles`
//!   requests to every relevant upstream and concatenates the responses
//!   (Req 24.2);
//! * **applies a configured [`Transformer`]** to the aggregated upstream
//!   response before returning it (Req 24.3);
//! * **rewrites every playable [`Stream`] URL to a stream-flow proxy link**
//!   ([`ProxyCodec`]-encoded `d` parameter pointing at `/proxy/stream`) so the
//!   bytes flow through the Streaming_Proxy_Engine with the configured
//!   encryption, header injection, DRM decryption, and transcoding applied
//!   (Req 24.4), while **preserving the stream's
//!   [`StreamBehaviorHints`](super::types::StreamBehaviorHints) unchanged**
//!   (Req 24.5);
//! * **skips an unreachable / erroring upstream** rather than failing the whole
//!   response (Req 24.6).
//!
//! All upstream HTTP goes through the single egress seam
//! ([`OutboundClient`](crate::egress::OutboundClient)) so upstream addons see
//! only the Egress_IP (Req 51).

use std::collections::BTreeMap;
use std::sync::Arc;

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;

use crate::auth::encryption::ProxyPayload;
use crate::egress::OutboundClient;
use crate::proxylink::{ProxyCodec, ProxyLink};

use super::types::{
    Manifest, Meta, MetaPreview, MetaResponse, MetasResponse, Resource, Stream, StreamsResponse,
    Subtitle, SubtitlesResponse,
};

/// The Wrap addon's own manifest identity (everything other than the
/// aggregated resources/types/catalogs, which are pulled from the upstreams).
#[derive(Clone, Debug)]
pub struct WrapManifestMeta {
    /// Addon id (e.g. `st:wrap`).
    pub id: String,
    /// Human-readable addon name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Human-readable description.
    pub description: String,
}

impl Default for WrapManifestMeta {
    fn default() -> Self {
        Self {
            id: "st:wrap".to_string(),
            name: "stream-flow Wrap".to_string(),
            version: "0.1.0".to_string(),
            description: "Wraps upstream Stremio addons through stream-flow".to_string(),
        }
    }
}

/// A configured upstream Stremio addon, identified by its base URL.
///
/// The base URL is the addon root (the `manifest.json` parent); resource URLs
/// are built from it in the standard Stremio shape
/// `{base}/{resource}/{type}/{id}.json` (with an optional `/{extra}` segment).
#[derive(Clone, Debug)]
pub struct UpstreamAddon {
    /// The normalized addon root (no trailing slash, no `manifest.json`).
    pub base_url: String,
}

impl UpstreamAddon {
    /// Build an upstream from a base URL or a full `…/manifest.json` URL; the
    /// trailing `manifest.json` and any trailing slashes are stripped so the
    /// stored [`base_url`](UpstreamAddon::base_url) is the addon root.
    pub fn new(url: impl Into<String>) -> Self {
        let mut base = url.into();
        if let Some(stripped) = base.strip_suffix("/manifest.json") {
            base = stripped.to_string();
        }
        while base.ends_with('/') {
            base.pop();
        }
        Self { base_url: base }
    }

    /// The upstream manifest URL.
    pub fn manifest_url(&self) -> String {
        format!("{}/manifest.json", self.base_url)
    }

    /// A Stremio resource URL: `{base}/{resource}/{type}/{id}.json`, with an
    /// optional `/{extra}` segment before the `.json` suffix when `extra` is a
    /// non-empty extra-args string (e.g. `genre=Action`).
    pub fn resource_url(
        &self,
        resource: &str,
        content_type: &str,
        id: &str,
        extra: Option<&str>,
    ) -> String {
        match extra {
            Some(extra) if !extra.is_empty() => format!(
                "{}/{}/{}/{}/{}.json",
                self.base_url, resource, content_type, id, extra
            ),
            _ => format!("{}/{}/{}/{}.json", self.base_url, resource, content_type, id),
        }
    }
}

/// How an upstream [`Stream`] URL is rewritten into a stream-flow proxy link
/// (Req 24.4).
///
/// The upstream media URL is sealed into an AES-CBC `d` proxy parameter
/// (encryption) carrying the injected upstream `headers` (header injection),
/// and the resulting `/proxy/stream` link additionally advertises the
/// configured `transcode` flag and any ClearKey `key_id`/`key` pairs (DRM
/// decryption / transcoding) so the Streaming_Proxy_Engine applies them on
/// playback.
#[derive(Clone, Debug)]
pub struct ProxyRewriteConfig {
    /// The stream-flow public base URL the proxy links point at (no trailing
    /// slash).
    pub base_url: String,
    /// Headers injected on every proxied upstream request (header injection).
    pub inject_headers: BTreeMap<String, String>,
    /// When `true`, proxy links carry `transcode=true` so the engine transcodes
    /// (Req 24.4).
    pub enable_transcode: bool,
    /// ClearKey `KID -> key` pairs advertised on proxy links for DRM decryption
    /// (Req 24.4). A `BTreeMap` keeps the emitted query deterministic.
    pub drm_key_ids: BTreeMap<String, String>,
}

impl ProxyRewriteConfig {
    /// Build a rewrite config pointing at the given stream-flow base URL
    /// (trailing slashes stripped).
    pub fn new(base_url: impl Into<String>) -> Self {
        let mut base = base_url.into();
        while base.ends_with('/') {
            base.pop();
        }
        Self {
            base_url: base,
            inject_headers: BTreeMap::new(),
            enable_transcode: false,
            drm_key_ids: BTreeMap::new(),
        }
    }

    /// Build the full `/proxy/stream` URL for an encoded proxy [`ProxyLink`],
    /// appending the configured `transcode` flag and DRM key parameters
    /// (Req 24.4).
    pub fn build_proxy_url(&self, link: &ProxyLink) -> String {
        // The `d=`/`token=` payload is the only mandatory parameter; the rest
        // are engine directives the proxy core consumes.
        let mut query = link.as_query_param();
        if self.enable_transcode {
            query.push_str("&transcode=true");
        }
        for (key_id, key) in &self.drm_key_ids {
            query.push_str(&format!("&key_id={key_id}&key={key}"));
        }
        format!("{}/proxy/stream?{}", self.base_url, query)
    }
}

/// A pluggable transformer applied to an aggregated upstream response before it
/// is returned (Req 24.3).
///
/// Every method defaults to the identity transform, so a concrete transformer
/// overrides only the resource kinds it cares about. The trait is object-safe
/// and `Send + Sync` so a `WrapAddon` can hold an `Arc<dyn Transformer>` shared
/// across worker tasks.
pub trait Transformer: Send + Sync {
    /// Transform the aggregated `stream` list (Req 24.3).
    fn transform_streams(&self, streams: Vec<Stream>) -> Vec<Stream> {
        streams
    }

    /// Transform the aggregated catalog `metas` list (Req 24.3).
    fn transform_metas(&self, metas: Vec<MetaPreview>) -> Vec<MetaPreview> {
        metas
    }

    /// Transform the aggregated `subtitles` list (Req 24.3).
    fn transform_subtitles(&self, subtitles: Vec<Subtitle>) -> Vec<Subtitle> {
        subtitles
    }

    /// Transform a `meta` object (Req 24.3).
    fn transform_meta(&self, meta: Meta) -> Meta {
        meta
    }
}

/// The Stremio Wrap addon (Req 24).
///
/// Holds the configured upstream addons, the single egress
/// [`OutboundClient`](crate::egress::OutboundClient) used to reach them, the
/// [`ProxyCodec`] + [`ProxyRewriteConfig`] used to rewrite stream URLs into
/// proxy links, and an optional [`Transformer`].
pub struct WrapAddon {
    meta: WrapManifestMeta,
    upstreams: Vec<UpstreamAddon>,
    client: Arc<OutboundClient>,
    codec: ProxyCodec,
    rewrite: ProxyRewriteConfig,
    transformer: Option<Arc<dyn Transformer>>,
}

impl WrapAddon {
    /// Construct a Wrap addon over the configured upstreams.
    pub fn new(
        meta: WrapManifestMeta,
        upstreams: Vec<UpstreamAddon>,
        client: Arc<OutboundClient>,
        codec: ProxyCodec,
        rewrite: ProxyRewriteConfig,
    ) -> Self {
        Self {
            meta,
            upstreams,
            client,
            codec,
            rewrite,
            transformer: None,
        }
    }

    /// Attach a [`Transformer`] applied to every aggregated response (Req 24.3).
    pub fn with_transformer(mut self, transformer: Arc<dyn Transformer>) -> Self {
        self.transformer = Some(transformer);
        self
    }

    /// The aggregated Wrap manifest (Req 24.1).
    ///
    /// Starts from this addon's [`WrapManifestMeta`] identity and unions the
    /// resources, content types, id prefixes, and catalogs of every reachable
    /// upstream. An unreachable / erroring upstream is omitted (Req 24.6).
    pub async fn manifest(&self) -> Manifest {
        let mut manifest = Manifest {
            id: self.meta.id.clone(),
            name: self.meta.name.clone(),
            description: self.meta.description.clone(),
            version: self.meta.version.clone(),
            ..Manifest::default()
        };

        for upstream in &self.upstreams {
            let Some(up) = self.fetch_json::<Manifest>(&upstream.manifest_url()).await else {
                // Req 24.6: omit the unreachable upstream, keep aggregating.
                continue;
            };
            for resource in up.resources {
                merge_resource(&mut manifest.resources, resource);
            }
            for content_type in up.types {
                if !manifest.types.contains(&content_type) {
                    manifest.types.push(content_type);
                }
            }
            for prefix in up.id_prefixes {
                if !manifest.id_prefixes.contains(&prefix) {
                    manifest.id_prefixes.push(prefix);
                }
            }
            manifest.catalogs.extend(up.catalogs);
            manifest.addon_catalogs.extend(up.addon_catalogs);
        }

        manifest
    }

    /// Aggregate `stream` results from every upstream, apply the transformer,
    /// then rewrite every URL to a proxy link (Req 24.2, 24.3, 24.4, 24.5).
    pub async fn get_streams(&self, content_type: &str, id: &str) -> StreamsResponse {
        let mut streams = Vec::new();
        for upstream in &self.upstreams {
            let url = upstream.resource_url("stream", content_type, id, None);
            if let Some(resp) = self.fetch_json::<StreamsResponse>(&url).await {
                streams.extend(resp.streams);
            }
        }

        if let Some(transformer) = &self.transformer {
            streams = transformer.transform_streams(streams);
        }

        let streams = streams
            .into_iter()
            .map(|s| self.rewrite_stream(s))
            .collect();
        StreamsResponse { streams }
    }

    /// Aggregate `catalog` previews from every upstream and apply the
    /// transformer (Req 24.2, 24.3).
    pub async fn get_catalog(
        &self,
        content_type: &str,
        id: &str,
        extra: Option<&str>,
    ) -> MetasResponse {
        let mut metas = Vec::new();
        for upstream in &self.upstreams {
            let url = upstream.resource_url("catalog", content_type, id, extra);
            if let Some(resp) = self.fetch_json::<MetasResponse>(&url).await {
                metas.extend(resp.metas);
            }
        }

        if let Some(transformer) = &self.transformer {
            metas = transformer.transform_metas(metas);
        }

        MetasResponse { metas }
    }

    /// Aggregate `subtitles` from every upstream and apply the transformer
    /// (Req 24.2, 24.3).
    pub async fn get_subtitles(&self, content_type: &str, id: &str) -> SubtitlesResponse {
        let mut subtitles = Vec::new();
        for upstream in &self.upstreams {
            let url = upstream.resource_url("subtitles", content_type, id, None);
            if let Some(resp) = self.fetch_json::<SubtitlesResponse>(&url).await {
                subtitles.extend(resp.subtitles);
            }
        }

        if let Some(transformer) = &self.transformer {
            subtitles = transformer.transform_subtitles(subtitles);
        }

        SubtitlesResponse { subtitles }
    }

    /// Forward a `meta` request to the upstreams, returning the first upstream
    /// that resolves it (a meta is a single object, not aggregatable). The
    /// transformer is applied and every inner video stream URL is rewritten to
    /// a proxy link (Req 24.2, 24.3, 24.4). Returns `None` when no reachable
    /// upstream provides the meta (Req 24.6).
    pub async fn get_meta(&self, content_type: &str, id: &str) -> Option<MetaResponse> {
        for upstream in &self.upstreams {
            let url = upstream.resource_url("meta", content_type, id, None);
            let Some(resp) = self.fetch_json::<MetaResponse>(&url).await else {
                continue;
            };

            let mut meta = resp.meta;
            if let Some(transformer) = &self.transformer {
                meta = transformer.transform_meta(meta);
            }
            // Rewrite any inner per-episode streams to proxy links (Req 24.4).
            for video in &mut meta.videos {
                let inner = std::mem::take(&mut video.streams);
                video.streams = inner.into_iter().map(|s| self.rewrite_stream(s)).collect();
            }
            return Some(MetaResponse { meta });
        }
        None
    }

    /// Rewrite a single upstream [`Stream`] so its playable URL flows through
    /// the stream-flow proxy (Req 24.4), **preserving the stream's
    /// `behaviorHints` unchanged** (Req 24.5).
    ///
    /// A stream with no HTTP `url` (an `infoHash` / `ytId` / external stream)
    /// is returned unchanged — there is nothing to proxy. The upstream media
    /// URL is sealed into an encrypted `d` proxy link carrying the configured
    /// injected headers plus the stream's own `proxyHeaders.request`, and the
    /// resulting `/proxy/stream` link advertises the configured transcode flag
    /// and DRM keys.
    pub fn rewrite_stream(&self, stream: Stream) -> Stream {
        let upstream_url = match stream.url.as_deref() {
            Some(u) if !u.is_empty() => u.to_string(),
            // No proxyable URL (infoHash/ytId/externalUrl): leave it untouched.
            _ => return stream,
        };

        let mut payload = ProxyPayload::new(upstream_url);
        // Configured header injection (Req 24.4) ...
        for (name, value) in &self.rewrite.inject_headers {
            payload.headers.insert(name.clone(), value.clone());
        }
        // ... augmented by the stream's own request proxyHeaders so the engine
        // replays them upstream (the hints themselves are preserved below).
        if let Some(hints) = &stream.behavior_hints {
            if let Some(proxy_headers) = &hints.proxy_headers {
                for (name, value) in &proxy_headers.request {
                    payload.headers.insert(name.clone(), value.clone());
                }
            }
        }

        // Encryption (Req 24.4): seal the payload into an AES-CBC `d` link.
        let proxy_url = match self.codec.encode_mediaflow(&payload) {
            Ok(link) => self.rewrite.build_proxy_url(&link),
            // Fail-safe: an encode error must not drop the stream; keep the
            // original (the engine/proxy-link layer will reject a bad link).
            Err(_) => return stream,
        };

        // Req 24.5: every other field — crucially `behavior_hints` — is carried
        // over unchanged; only the URL is rewritten.
        Stream {
            url: Some(proxy_url),
            ..stream
        }
    }

    /// `GET` a JSON resource through the egress seam, returning `None` on any
    /// failure (unreachable host, non-success status, unparseable body) so a
    /// single bad upstream never fails the aggregate (Req 24.6, 51.1).
    async fn fetch_json<T: DeserializeOwned>(&self, url: &str) -> Option<T> {
        let parsed = Url::parse(url).ok()?;
        let request = self.client.upstream(Method::GET, &parsed).ok()?;
        let response = request.send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.json::<T>().await.ok()
    }
}

/// Merge an upstream [`Resource`] into the aggregate, deduplicating by name and
/// unioning the per-resource `types` / `idPrefixes` (Req 24.1).
///
/// An empty `types` (the bare-string resource form) means "offered for every
/// content type", so it dominates the union (the merged resource stays bare).
/// The same rule applies to `idPrefixes`.
fn merge_resource(acc: &mut Vec<Resource>, incoming: Resource) {
    if let Some(existing) = acc.iter_mut().find(|r| r.name == incoming.name) {
        if existing.types.is_empty() || incoming.types.is_empty() {
            existing.types.clear();
        } else {
            for t in incoming.types {
                if !existing.types.contains(&t) {
                    existing.types.push(t);
                }
            }
        }
        if existing.id_prefixes.is_empty() || incoming.id_prefixes.is_empty() {
            existing.id_prefixes.clear();
        } else {
            for p in incoming.id_prefixes {
                if !existing.id_prefixes.contains(&p) {
                    existing.id_prefixes.push(p);
                }
            }
        }
    } else {
        acc.push(incoming);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::encryption::ProxyPayload;
    use crate::config::EgressPolicy;
    use crate::egress::OutboundClient;
    use crate::proxylink::{ProxyCodec, ProxyLink};
    use crate::stremio::types::Stream;
    use std::collections::HashMap;
    use std::sync::Arc;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const API_PASSWORD: &str = "wrap-test-password";
    const TOKEN_SECRET: &str = "wrap-token-secret";

    fn outbound() -> Arc<OutboundClient> {
        // FailOpen + no resolver -> DialUntunneledWithWarning, so the test
        // dials the wiremock origin directly (the store-impl test pattern).
        Arc::new(OutboundClient::new(
            reqwest::Client::new(),
            wreq::Client::new(),
            EgressPolicy::FailOpen,
            None,
            None,
            HashMap::new(),
        ))
    }

    fn codec() -> ProxyCodec {
        ProxyCodec::from_secrets(API_PASSWORD, TOKEN_SECRET)
    }

    fn rewrite_cfg() -> ProxyRewriteConfig {
        ProxyRewriteConfig::new("https://flow.example.com")
    }

    fn wrap_for(upstreams: Vec<UpstreamAddon>) -> WrapAddon {
        WrapAddon::new(
            WrapManifestMeta::default(),
            upstreams,
            outbound(),
            codec(),
            rewrite_cfg(),
        )
    }

    /// Decode the AES-CBC `d` payload out of a rewritten proxy URL.
    fn decode_proxy_url(codec: &ProxyCodec, url: &str) -> ProxyPayload {
        let query = url.split('?').nth(1).expect("proxy url has a query");
        let d = query
            .split('&')
            .find_map(|p| p.strip_prefix("d="))
            .expect("proxy url carries a `d` param");
        codec
            .decode(&ProxyLink::EncryptedMediaflow { d: d.to_string() })
            .expect("d payload decodes")
    }

    // -- Req 24.1: manifest aggregates upstream addons -----------------------

    #[tokio::test]
    async fn manifest_aggregates_upstream_resources_types_and_catalogs() {
        let up1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/manifest.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "up1", "name": "Up1", "version": "1.0.0", "description": "",
                "resources": ["catalog", "stream"],
                "types": ["movie"],
                "idPrefixes": ["tt"],
                "catalogs": [{"type": "movie", "id": "up1-top", "name": "Up1 Top"}],
            })))
            .mount(&up1)
            .await;

        let up2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/manifest.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "up2", "name": "Up2", "version": "2.0.0", "description": "",
                "resources": ["meta", "subtitles"],
                "types": ["series"],
                "idPrefixes": ["kitsu:"],
                "catalogs": [{"type": "series", "id": "up2-top", "name": "Up2 Top"}],
            })))
            .mount(&up2)
            .await;

        let wrap = wrap_for(vec![
            UpstreamAddon::new(&up1.uri()),
            UpstreamAddon::new(&up2.uri()),
        ]);
        let m = wrap.manifest().await;

        let names: Vec<&str> = m.resources.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"catalog"));
        assert!(names.contains(&"stream"));
        assert!(names.contains(&"meta"));
        assert!(names.contains(&"subtitles"));

        let types: Vec<&str> = m.types.iter().map(|t| t.as_str()).collect();
        assert!(types.contains(&"movie"));
        assert!(types.contains(&"series"));

        assert!(m.id_prefixes.contains(&"tt".to_string()));
        assert!(m.id_prefixes.contains(&"kitsu:".to_string()));

        assert_eq!(m.catalogs.len(), 2, "both upstream catalogs are aggregated");
    }

    // -- Req 24.6: manifest omits an unreachable/erroring upstream -----------

    #[tokio::test]
    async fn manifest_skips_unreachable_upstream() {
        let ok = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/manifest.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "ok", "name": "OK", "version": "1.0.0", "description": "",
                "resources": ["stream"], "types": ["movie"], "catalogs": [],
            })))
            .mount(&ok)
            .await;

        let bad = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/manifest.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&bad)
            .await;

        let wrap = wrap_for(vec![
            UpstreamAddon::new(&bad.uri()),
            UpstreamAddon::new(&ok.uri()),
        ]);
        let m = wrap.manifest().await;
        let names: Vec<&str> = m.resources.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["stream"], "only the reachable upstream contributes");
    }

    // -- Req 24.2/24.4/24.5: stream forward + aggregate + rewrite + hints ----

    #[tokio::test]
    async fn streams_are_aggregated_rewritten_and_hints_preserved() {
        let up1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/stream/movie/tt0111161.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "streams": [{
                    "url": "https://cdn1.example.com/a.mkv",
                    "name": "Up1",
                    "behaviorHints": {
                        "bingeGroup": "grp-1",
                        "notWebReady": true,
                        "countryWhitelist": ["US", "CA"],
                        "proxyHeaders": {"request": {"Referer": "https://cdn1.example.com/"}}
                    }
                }]
            })))
            .mount(&up1)
            .await;

        let up2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/stream/movie/tt0111161.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "streams": [{"url": "https://cdn2.example.com/b.mkv", "name": "Up2"}]
            })))
            .mount(&up2)
            .await;

        let wrap = wrap_for(vec![
            UpstreamAddon::new(&up1.uri()),
            UpstreamAddon::new(&up2.uri()),
        ]);
        let resp = wrap.get_streams("movie", "tt0111161").await;
        assert_eq!(resp.streams.len(), 2, "both upstreams aggregated");

        // Req 24.4: every returned Stream URL is a stream-flow proxy link.
        for s in &resp.streams {
            let u = s.url.as_ref().expect("stream has a url");
            assert!(
                u.starts_with("https://flow.example.com/proxy/stream?"),
                "url routes through the proxy: {u}"
            );
            assert!(u.contains("d="), "url carries the encrypted payload: {u}");
            assert!(!u.contains("cdn1.example.com"));
            assert!(!u.contains("cdn2.example.com"));
        }

        // Req 24.5: behaviorHints preserved unchanged on the first stream.
        let s0 = &resp.streams[0];
        let hints = s0.behavior_hints.as_ref().expect("hints preserved");
        assert_eq!(hints.binge_group.as_deref(), Some("grp-1"));
        assert!(hints.not_web_ready);
        assert_eq!(hints.country_whitelist, vec!["US".to_string(), "CA".to_string()]);
        assert_eq!(
            hints
                .proxy_headers
                .as_ref()
                .unwrap()
                .request
                .get("Referer")
                .unwrap(),
            "https://cdn1.example.com/"
        );

        // The proxy link decodes back to the original upstream URL, and the
        // upstream proxyHeaders.request were injected into the proxied request.
        let payload = decode_proxy_url(&codec(), s0.url.as_ref().unwrap());
        assert_eq!(payload.url, "https://cdn1.example.com/a.mkv");
        assert_eq!(payload.headers.get("Referer").unwrap(), "https://cdn1.example.com/");
    }

    // -- Req 24.4: rewrite applies configured headers / transcode / DRM ------

    #[tokio::test]
    async fn rewrite_applies_configured_headers_transcode_and_drm() {
        let mut cfg = ProxyRewriteConfig::new("https://flow.example.com");
        cfg.inject_headers
            .insert("User-Agent".into(), "stream-flow".into());
        cfg.enable_transcode = true;
        cfg.drm_key_ids.insert("kid1".into(), "deadbeef".into());

        let wrap = WrapAddon::new(
            WrapManifestMeta::default(),
            vec![],
            outbound(),
            codec(),
            cfg,
        );

        let stream = Stream {
            url: Some("https://cdn.example.com/v.mkv".into()),
            ..Default::default()
        };
        let rewritten = wrap.rewrite_stream(stream);
        let u = rewritten.url.expect("rewritten url");

        assert!(u.contains("transcode=true"), "transcode flag present: {u}");
        assert!(u.contains("key_id=kid1"), "DRM key id present: {u}");
        assert!(u.contains("key=deadbeef"), "DRM key present: {u}");

        let payload = decode_proxy_url(&codec(), &u);
        assert_eq!(payload.url, "https://cdn.example.com/v.mkv");
        assert_eq!(payload.headers.get("User-Agent").unwrap(), "stream-flow");
    }

    // -- Req 24.3: a configured transformer is applied before returning ------

    struct TagNameTransformer;
    impl Transformer for TagNameTransformer {
        fn transform_streams(&self, streams: Vec<Stream>) -> Vec<Stream> {
            streams
                .into_iter()
                .map(|mut s| {
                    s.name = Some(format!("[wrapped] {}", s.name.unwrap_or_default()));
                    s
                })
                .collect()
        }
    }

    #[tokio::test]
    async fn transformer_is_applied_to_streams_before_return() {
        let up = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/stream/movie/tt1.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "streams": [{"url": "https://cdn.example.com/v.mkv", "name": "HD"}]
            })))
            .mount(&up)
            .await;

        let wrap = wrap_for(vec![UpstreamAddon::new(&up.uri())])
            .with_transformer(Arc::new(TagNameTransformer));
        let resp = wrap.get_streams("movie", "tt1").await;
        assert_eq!(resp.streams.len(), 1);
        assert_eq!(resp.streams[0].name.as_deref(), Some("[wrapped] HD"));
        // Still rewritten through the proxy.
        assert!(resp.streams[0].url.as_ref().unwrap().contains("d="));
    }

    // -- Req 24.6: an unreachable upstream is skipped on stream aggregation --

    #[tokio::test]
    async fn unreachable_upstream_is_skipped_on_streams() {
        let ok = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/stream/movie/tt1.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "streams": [{"url": "https://cdn.example.com/v.mkv", "name": "OK"}]
            })))
            .mount(&ok)
            .await;

        let erroring = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/stream/movie/tt1.json"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&erroring)
            .await;

        // A genuinely unreachable upstream (nothing listening on port 1).
        let dead = UpstreamAddon::new("http://127.0.0.1:1");

        let wrap = wrap_for(vec![
            dead,
            UpstreamAddon::new(&erroring.uri()),
            UpstreamAddon::new(&ok.uri()),
        ]);
        let resp = wrap.get_streams("movie", "tt1").await;
        assert_eq!(resp.streams.len(), 1, "only the reachable upstream contributes");
        assert_eq!(
            decode_proxy_url(&codec(), resp.streams[0].url.as_ref().unwrap()).url,
            "https://cdn.example.com/v.mkv"
        );
    }

    // -- Req 24.2: catalog forward + aggregate -------------------------------

    #[tokio::test]
    async fn catalog_is_forwarded_and_aggregated() {
        let up1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/catalog/movie/top.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "metas": [{"id": "tt1", "type": "movie", "name": "A", "poster": "p1"}]
            })))
            .mount(&up1)
            .await;

        let up2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/catalog/movie/top.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "metas": [{"id": "tt2", "type": "movie", "name": "B", "poster": "p2"}]
            })))
            .mount(&up2)
            .await;

        let wrap = wrap_for(vec![
            UpstreamAddon::new(&up1.uri()),
            UpstreamAddon::new(&up2.uri()),
        ]);
        let resp = wrap.get_catalog("movie", "top", None).await;
        assert_eq!(resp.metas.len(), 2);
        let ids: Vec<&str> = resp.metas.iter().map(|m| m.id.as_str()).collect();
        assert!(ids.contains(&"tt1"));
        assert!(ids.contains(&"tt2"));
    }

    // -- Req 24.2: subtitles forward + aggregate -----------------------------

    #[tokio::test]
    async fn subtitles_are_forwarded_and_aggregated() {
        let up1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/subtitles/movie/tt1.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subtitles": [{"id": "s1", "url": "https://x.example/1.srt", "lang": "en"}]
            })))
            .mount(&up1)
            .await;

        let up2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/subtitles/movie/tt1.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "subtitles": [{"id": "s2", "url": "https://x.example/2.srt", "lang": "fr"}]
            })))
            .mount(&up2)
            .await;

        let wrap = wrap_for(vec![
            UpstreamAddon::new(&up1.uri()),
            UpstreamAddon::new(&up2.uri()),
        ]);
        let resp = wrap.get_subtitles("movie", "tt1").await;
        assert_eq!(resp.subtitles.len(), 2);
    }

    // -- Req 24.2/24.4: meta forward + inner video stream rewrite ------------

    #[tokio::test]
    async fn meta_is_forwarded_and_video_streams_rewritten() {
        let up = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/meta/series/tt1.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "meta": {
                    "id": "tt1", "type": "series", "name": "S",
                    "videos": [{
                        "id": "tt1:1:1",
                        "streams": [{"url": "https://cdn.example.com/ep.mkv", "name": "HD"}]
                    }]
                }
            })))
            .mount(&up)
            .await;

        let wrap = wrap_for(vec![UpstreamAddon::new(&up.uri())]);
        let resp = wrap.get_meta("series", "tt1").await.expect("meta present");
        assert_eq!(resp.meta.id, "tt1");
        let stream_url = resp.meta.videos[0].streams[0].url.as_ref().unwrap();
        assert!(stream_url.contains("flow.example.com/proxy/stream?"));
        assert_eq!(
            decode_proxy_url(&codec(), stream_url).url,
            "https://cdn.example.com/ep.mkv"
        );
    }

    // -- Pure helpers (no network) -------------------------------------------

    #[::core::prelude::v1::test]
    fn upstream_addon_normalizes_base_and_builds_urls() {
        let a = UpstreamAddon::new("https://host.example/manifest.json");
        assert_eq!(a.base_url, "https://host.example");
        assert_eq!(a.manifest_url(), "https://host.example/manifest.json");
        assert_eq!(
            a.resource_url("stream", "movie", "tt1", None),
            "https://host.example/stream/movie/tt1.json"
        );
        assert_eq!(
            a.resource_url("catalog", "movie", "top", Some("genre=Action")),
            "https://host.example/catalog/movie/top/genre=Action.json"
        );

        let b = UpstreamAddon::new("https://host.example/");
        assert_eq!(b.base_url, "https://host.example");
    }

    #[tokio::test]
    async fn rewrite_passes_through_streams_without_url() {
        let wrap = wrap_for(vec![]);
        let s = Stream {
            info_hash: Some("abcd".into()),
            file_index: Some(0),
            ..Default::default()
        };
        let out = wrap.rewrite_stream(s);
        assert_eq!(out.url, None, "an infoHash stream keeps no http url");
        assert_eq!(out.info_hash.as_deref(), Some("abcd"));
        assert_eq!(out.file_index, Some(0));
    }
}
