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
//!
//! ## Transformer pipeline
//!
//! The module ships four named concrete [`Transformer`] implementations that
//! can be composed into an ordered pipeline via [`ComposedTransformer`]:
//!
//! * [`ProxyLinkTransformer`] — rewrites every stream URL to a stream-flow
//!   proxy link (the core rewrite, Req 24.4). This is the default transformer
//!   applied by [`WrapAddon::rewrite_stream`]; the named type lets callers
//!   compose it explicitly in a pipeline.
//! * [`HeaderInjectionTransformer`] — injects a fixed set of request headers
//!   into every stream's proxy payload (Req 24.4 header injection).
//! * [`DrmKeyTransformer`] — appends ClearKey `key_id`/`key` pairs to every
//!   stream's proxy URL so the engine decrypts on playback (Req 24.4 DRM).
//! * [`QualityFilterTransformer`] — filters the stream list to those whose
//!   release-name quality tokens satisfy the configured constraints (Req 24.3).
//!
//! Compose them with [`ComposedTransformer::new`]:
//!
//! ```rust,ignore
//! let pipeline = ComposedTransformer::new(vec![
//!     Arc::new(HeaderInjectionTransformer::new(headers)),
//!     Arc::new(DrmKeyTransformer::new(keys)),
//!     Arc::new(QualityFilterTransformer::new(prefs)),
//! ]);
//! let wrap = wrap_addon.with_transformer(Arc::new(pipeline));
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use reqwest::{Method, Url};
use serde::de::DeserializeOwned;

use crate::app::AppState;
use crate::auth::encryption::ProxyPayload;
use crate::egress::OutboundClient;
use crate::proxylink::{ProxyCodec, ProxyLink};
use crate::quality::{QualityPrefs, QualityRanker, RankedFile};

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
            _ => format!(
                "{}/{}/{}/{}.json",
                self.base_url, resource, content_type, id
            ),
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
        rewrite_stream_with(&self.codec, &self.rewrite, stream)
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

// ---------------------------------------------------------------------------
// Concrete transformer implementations (Req 24.3, 24.4)
// ---------------------------------------------------------------------------

/// A transformer that rewrites every stream URL to a stream-flow proxy link
/// (Req 24.4).
///
/// This is the named, composable form of the rewrite that [`WrapAddon`] applies
/// internally via [`WrapAddon::rewrite_stream`]. Including it in a
/// [`ComposedTransformer`] pipeline makes the rewrite step explicit and
/// order-controllable.
pub struct ProxyLinkTransformer {
    codec: ProxyCodec,
    rewrite: ProxyRewriteConfig,
}

impl ProxyLinkTransformer {
    /// Build a [`ProxyLinkTransformer`] from the given codec and rewrite config.
    pub fn new(codec: ProxyCodec, rewrite: ProxyRewriteConfig) -> Self {
        Self { codec, rewrite }
    }
}

impl Transformer for ProxyLinkTransformer {
    fn transform_streams(&self, streams: Vec<Stream>) -> Vec<Stream> {
        streams
            .into_iter()
            .map(|s| rewrite_stream_with(&self.codec, &self.rewrite, s))
            .collect()
    }
}

/// A transformer that injects a fixed set of request headers into every
/// stream's proxy payload (Req 24.4 header injection).
///
/// The injected headers are merged into the stream's existing
/// `proxyHeaders.request` map (stream-specific headers take precedence over
/// the injected ones when both supply the same header name).
pub struct HeaderInjectionTransformer {
    /// Headers to inject on every proxied upstream request.
    headers: BTreeMap<String, String>,
}

impl HeaderInjectionTransformer {
    /// Build a [`HeaderInjectionTransformer`] that injects the given headers.
    pub fn new(headers: BTreeMap<String, String>) -> Self {
        Self { headers }
    }
}

impl Transformer for HeaderInjectionTransformer {
    fn transform_streams(&self, streams: Vec<Stream>) -> Vec<Stream> {
        if self.headers.is_empty() {
            return streams;
        }
        streams
            .into_iter()
            .map(|mut s| {
                // Inject into the stream's proxyHeaders.request so the engine
                // replays them upstream. Stream-specific headers take precedence.
                let hints = s.behavior_hints.get_or_insert_with(Default::default);
                let proxy_headers = hints.proxy_headers.get_or_insert_with(Default::default);
                for (name, value) in &self.headers {
                    // Only inject if the stream doesn't already supply this header.
                    proxy_headers
                        .request
                        .entry(name.clone())
                        .or_insert_with(|| value.clone());
                }
                s
            })
            .collect()
    }
}

/// A transformer that appends ClearKey `key_id`/`key` pairs to every stream's
/// proxy URL so the Streaming_Proxy_Engine decrypts on playback (Req 24.4 DRM).
///
/// The DRM keys are appended as `key_id=<kid>&key=<key>` query parameters on
/// the proxy URL. This transformer is applied **after** the proxy-link rewrite
/// (i.e. after [`ProxyLinkTransformer`] in the pipeline) so it can append to
/// the already-rewritten URL.
pub struct DrmKeyTransformer {
    /// ClearKey `KID -> key` pairs to append to every proxy URL.
    key_ids: BTreeMap<String, String>,
}

impl DrmKeyTransformer {
    /// Build a [`DrmKeyTransformer`] that appends the given ClearKey pairs.
    pub fn new(key_ids: BTreeMap<String, String>) -> Self {
        Self { key_ids }
    }
}

impl Transformer for DrmKeyTransformer {
    fn transform_streams(&self, streams: Vec<Stream>) -> Vec<Stream> {
        if self.key_ids.is_empty() {
            return streams;
        }
        streams
            .into_iter()
            .map(|mut s| {
                if let Some(url) = s.url.take() {
                    let mut new_url = url;
                    for (key_id, key) in &self.key_ids {
                        new_url.push_str(&format!("&key_id={key_id}&key={key}"));
                    }
                    s.url = Some(new_url);
                }
                s
            })
            .collect()
    }
}

/// A transformer that filters the stream list to those whose release-name
/// quality tokens satisfy the configured [`QualityPrefs`] constraints
/// (Req 24.3, 38.1–38.6).
///
/// Streams whose `behaviorHints.filename` (or `description`) can be parsed as
/// a release name are ranked and filtered by the quality ranker; streams with
/// no parseable name are kept (they cannot be excluded on quality grounds).
/// The output order follows the ranker's descending quality order.
pub struct QualityFilterTransformer {
    prefs: QualityPrefs,
    /// Optional bandwidth estimate in bits per second (Req 38.5).
    bandwidth_bps: Option<u64>,
}

impl QualityFilterTransformer {
    /// Build a [`QualityFilterTransformer`] with the given preferences and
    /// optional bandwidth estimate.
    pub fn new(prefs: QualityPrefs, bandwidth_bps: Option<u64>) -> Self {
        Self {
            prefs,
            bandwidth_bps,
        }
    }
}

impl Transformer for QualityFilterTransformer {
    fn transform_streams(&self, streams: Vec<Stream>) -> Vec<Stream> {
        if streams.is_empty() {
            return streams;
        }

        // Partition streams into those with a parseable name (rankable) and
        // those without (kept as-is, appended after the ranked set).
        let mut rankable: Vec<(usize, RankedFile)> = Vec::new();
        let mut unrankable: Vec<(usize, Stream)> = Vec::new();

        for (idx, s) in streams.iter().enumerate() {
            // Use filename from behaviorHints, then description, then name.
            let name = s
                .behavior_hints
                .as_ref()
                .and_then(|h| h.filename.as_deref())
                .or(s.description.as_deref())
                .or(s.name.as_deref())
                .unwrap_or("");

            if name.is_empty() {
                unrankable.push((idx, s.clone()));
            } else {
                let size = s
                    .behavior_hints
                    .as_ref()
                    .and_then(|h| h.video_size)
                    .unwrap_or(-1);
                rankable.push((idx, RankedFile::new(name, size)));
            }
        }

        // Rank the rankable streams.
        let ranked_files = QualityRanker::rank(
            rankable.iter().map(|(_, f)| f.clone()).collect(),
            &self.prefs,
            self.bandwidth_bps,
        );

        // Map ranked files back to their original streams (by name match).
        let mut result: Vec<Stream> = ranked_files
            .into_iter()
            .filter_map(|rf| {
                // Find the original stream whose name matches this ranked file.
                rankable.iter().find_map(|(orig_idx, _)| {
                    let s = &streams[*orig_idx];
                    let name = s
                        .behavior_hints
                        .as_ref()
                        .and_then(|h| h.filename.as_deref())
                        .or(s.description.as_deref())
                        .or(s.name.as_deref())
                        .unwrap_or("");
                    if name == rf.name {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Append unrankable streams at the end.
        result.extend(unrankable.into_iter().map(|(_, s)| s));
        result
    }
}

/// A composable transformer pipeline that applies a sequence of
/// [`Transformer`]s in order (Req 24.3).
///
/// The pipeline is order-preserving: each transformer receives the output of
/// the previous one, so the final result is the composition of all
/// transformers in the order they were added.
///
/// ```rust,ignore
/// let pipeline = ComposedTransformer::new(vec![
///     Arc::new(HeaderInjectionTransformer::new(headers)),
///     Arc::new(DrmKeyTransformer::new(keys)),
///     Arc::new(QualityFilterTransformer::new(prefs, None)),
/// ]);
/// ```
pub struct ComposedTransformer {
    transformers: Vec<Arc<dyn Transformer>>,
}

impl ComposedTransformer {
    /// Build a pipeline from an ordered list of transformers.
    pub fn new(transformers: Vec<Arc<dyn Transformer>>) -> Self {
        Self { transformers }
    }

    /// Append a transformer to the end of the pipeline.
    pub fn push(mut self, transformer: Arc<dyn Transformer>) -> Self {
        self.transformers.push(transformer);
        self
    }
}

impl Transformer for ComposedTransformer {
    fn transform_streams(&self, mut streams: Vec<Stream>) -> Vec<Stream> {
        for t in &self.transformers {
            streams = t.transform_streams(streams);
        }
        streams
    }

    fn transform_metas(&self, mut metas: Vec<MetaPreview>) -> Vec<MetaPreview> {
        for t in &self.transformers {
            metas = t.transform_metas(metas);
        }
        metas
    }

    fn transform_subtitles(&self, mut subtitles: Vec<Subtitle>) -> Vec<Subtitle> {
        for t in &self.transformers {
            subtitles = t.transform_subtitles(subtitles);
        }
        subtitles
    }

    fn transform_meta(&self, mut meta: Meta) -> Meta {
        for t in &self.transformers {
            meta = t.transform_meta(meta);
        }
        meta
    }
}

// ---------------------------------------------------------------------------
// Internal helper: rewrite a stream with an explicit codec + config
// ---------------------------------------------------------------------------

/// Rewrite a single upstream [`Stream`] so its playable URL flows through the
/// stream-flow proxy (Req 24.4), **preserving the stream's `behaviorHints`
/// unchanged** (Req 24.5).
///
/// This is the shared implementation used by both [`WrapAddon::rewrite_stream`]
/// and [`ProxyLinkTransformer`].
fn rewrite_stream_with(codec: &ProxyCodec, rewrite: &ProxyRewriteConfig, stream: Stream) -> Stream {
    let upstream_url = match stream.url.as_deref() {
        Some(u) if !u.is_empty() => u.to_string(),
        // No proxyable URL (infoHash/ytId/externalUrl): leave it untouched.
        _ => return stream,
    };

    let mut payload = ProxyPayload::new(upstream_url);
    // Configured header injection (Req 24.4) ...
    for (name, value) in &rewrite.inject_headers {
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
    let proxy_url = match codec.encode_mediaflow(&payload) {
        Ok(link) => rewrite.build_proxy_url(&link),
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

// ---------------------------------------------------------------------------
// HTTP handlers for the Wrap addon (stremthru surface, Req 24)
// ---------------------------------------------------------------------------

/// Query parameters for a Wrap addon resource request.
#[derive(serde::Deserialize)]
pub struct WrapResourceQuery {
    /// Optional extra args string (e.g. `genre=Action`).
    #[serde(default)]
    pub extra: Option<String>,
}

/// Path parameters for a Wrap addon resource request.
#[derive(serde::Deserialize)]
pub struct WrapResourcePath {
    /// The resource name (`catalog`/`meta`/`stream`/`subtitles`).
    pub resource: String,
    /// The content type (`movie`/`series`/…).
    pub content_type: String,
    /// The content id.
    pub id: String,
}

fn public_base_url(req: &HttpRequest, state: &AppState) -> String {
    if let Some(base) = state
        .config()
        .stremio
        .base_url
        .as_deref()
        .filter(|v| !v.is_empty())
    {
        return base.trim_end_matches('/').to_string();
    }
    format!(
        "{}://{}",
        req.connection_info().scheme(),
        req.connection_info().host()
    )
}

fn proxy_codec(state: &AppState) -> ProxyCodec {
    let api_password = state
        .config()
        .auth
        .api_password
        .as_ref()
        .map(|secret| secret.expose())
        .unwrap_or_default();
    let token_secret = state
        .config()
        .auth
        .proxy_auth
        .first()
        .and_then(|entry| entry.split_once(':').map(|(_, pass)| pass))
        .unwrap_or(api_password);
    ProxyCodec::from_secrets(api_password, token_secret)
}

fn build_wrap_addon(req: &HttpRequest, state: &AppState) -> WrapAddon {
    let name = state
        .config()
        .stremio
        .addon_name
        .clone()
        .unwrap_or_else(|| "stream-flow Wrap".to_string());
    let meta = WrapManifestMeta {
        name,
        ..WrapManifestMeta::default()
    };
    let upstreams = state
        .config()
        .stremio
        .wrap_upstreams
        .iter()
        .filter(|url| !url.trim().is_empty())
        .map(|url| UpstreamAddon::new(url.clone()))
        .collect();
    WrapAddon::new(
        meta,
        upstreams,
        Arc::clone(state.egress()),
        proxy_codec(state),
        ProxyRewriteConfig::new(public_base_url(req, state)),
    )
}

pub async fn wrap_manifest_endpoint(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let addon = build_wrap_addon(&req, &state);
    HttpResponse::Ok().json(addon.manifest().await)
}

pub async fn wrap_resource_endpoint(
    path: web::Path<WrapResourcePath>,
    query: web::Query<WrapResourceQuery>,
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let addon = build_wrap_addon(&req, &state);
    match path.resource.as_str() {
        "catalog" => HttpResponse::Ok().json(
            addon
                .get_catalog(&path.content_type, &path.id, query.extra.as_deref())
                .await,
        ),
        "stream" => HttpResponse::Ok().json(addon.get_streams(&path.content_type, &path.id).await),
        "subtitles" => {
            HttpResponse::Ok().json(addon.get_subtitles(&path.content_type, &path.id).await)
        }
        "meta" => match addon.get_meta(&path.content_type, &path.id).await {
            Some(meta) => HttpResponse::Ok().json(meta),
            None => HttpResponse::NotFound().json(super::types::StremioError::not_found("meta")),
        },
        other => HttpResponse::NotFound().json(super::types::StremioError::not_found(other)),
    }
}

pub fn configure_wrap_addon_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/stremio/wrap/manifest.json",
        web::get().to(wrap_manifest_endpoint),
    )
    .route(
        "/stremio/wrap/{resource}/{content_type}/{id}.json",
        web::get().to(wrap_resource_endpoint),
    );
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
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
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
            UpstreamAddon::new(up1.uri()),
            UpstreamAddon::new(up2.uri()),
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
            UpstreamAddon::new(bad.uri()),
            UpstreamAddon::new(ok.uri()),
        ]);
        let m = wrap.manifest().await;
        let names: Vec<&str> = m.resources.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["stream"],
            "only the reachable upstream contributes"
        );
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
            UpstreamAddon::new(up1.uri()),
            UpstreamAddon::new(up2.uri()),
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
        assert_eq!(
            hints.country_whitelist,
            vec!["US".to_string(), "CA".to_string()]
        );
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
        assert_eq!(
            payload.headers.get("Referer").unwrap(),
            "https://cdn1.example.com/"
        );
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

        let wrap = wrap_for(vec![UpstreamAddon::new(up.uri())])
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
            UpstreamAddon::new(erroring.uri()),
            UpstreamAddon::new(ok.uri()),
        ]);
        let resp = wrap.get_streams("movie", "tt1").await;
        assert_eq!(
            resp.streams.len(),
            1,
            "only the reachable upstream contributes"
        );
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
            UpstreamAddon::new(up1.uri()),
            UpstreamAddon::new(up2.uri()),
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
            UpstreamAddon::new(up1.uri()),
            UpstreamAddon::new(up2.uri()),
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

        let wrap = wrap_for(vec![UpstreamAddon::new(up.uri())]);
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

    // -- ProxyLinkTransformer: named composable proxy-link rewrite -----------

    #[test]
    fn proxy_link_transformer_rewrites_stream_urls() {
        let transformer = ProxyLinkTransformer::new(codec(), rewrite_cfg());
        let streams = vec![
            Stream {
                url: Some("https://cdn.example.com/a.mkv".into()),
                name: Some("HD".into()),
                ..Default::default()
            },
            Stream {
                info_hash: Some("abc123".into()),
                ..Default::default()
            },
        ];
        let result = transformer.transform_streams(streams);
        assert_eq!(result.len(), 2);
        // First stream: URL rewritten to proxy link.
        let u = result[0].url.as_ref().unwrap();
        assert!(
            u.starts_with("https://flow.example.com/proxy/stream?d="),
            "url is a proxy link: {u}"
        );
        let payload = decode_proxy_url(&codec(), u);
        assert_eq!(payload.url, "https://cdn.example.com/a.mkv");
        // Second stream: infoHash stream left unchanged.
        assert_eq!(result[1].url, None);
        assert_eq!(result[1].info_hash.as_deref(), Some("abc123"));
    }

    // -- HeaderInjectionTransformer: injects headers into streams ------------

    #[test]
    fn header_injection_transformer_injects_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("User-Agent".into(), "stream-flow/1.0".into());
        headers.insert("Referer".into(), "https://example.com/".into());
        let transformer = HeaderInjectionTransformer::new(headers);

        let streams = vec![Stream {
            url: Some("https://cdn.example.com/v.mkv".into()),
            ..Default::default()
        }];
        let result = transformer.transform_streams(streams);
        assert_eq!(result.len(), 1);
        let hints = result[0].behavior_hints.as_ref().expect("hints set");
        let req_headers = &hints
            .proxy_headers
            .as_ref()
            .expect("proxy_headers set")
            .request;
        assert_eq!(req_headers.get("User-Agent").unwrap(), "stream-flow/1.0");
        assert_eq!(req_headers.get("Referer").unwrap(), "https://example.com/");
    }

    #[test]
    fn header_injection_does_not_override_stream_specific_headers() {
        let mut inject = BTreeMap::new();
        inject.insert("User-Agent".into(), "injected".into());
        let transformer = HeaderInjectionTransformer::new(inject);

        // Stream already has a User-Agent in its proxyHeaders.
        let mut stream = Stream {
            url: Some("https://cdn.example.com/v.mkv".into()),
            ..Default::default()
        };
        let mut hints = crate::stremio::types::StreamBehaviorHints::default();
        let mut proxy_headers = crate::stremio::types::ProxyHeaders::default();
        proxy_headers
            .request
            .insert("User-Agent".into(), "stream-specific".into());
        hints.proxy_headers = Some(proxy_headers);
        stream.behavior_hints = Some(hints);

        let result = transformer.transform_streams(vec![stream]);
        let req_headers = &result[0]
            .behavior_hints
            .as_ref()
            .unwrap()
            .proxy_headers
            .as_ref()
            .unwrap()
            .request;
        // Stream-specific header takes precedence.
        assert_eq!(req_headers.get("User-Agent").unwrap(), "stream-specific");
    }

    #[test]
    fn header_injection_empty_headers_is_identity() {
        let transformer = HeaderInjectionTransformer::new(BTreeMap::new());
        let streams = vec![Stream {
            url: Some("https://cdn.example.com/v.mkv".into()),
            name: Some("HD".into()),
            ..Default::default()
        }];
        let result = transformer.transform_streams(streams.clone());
        assert_eq!(result[0].url, streams[0].url);
        assert_eq!(result[0].behavior_hints, streams[0].behavior_hints);
    }

    // -- DrmKeyTransformer: appends DRM key params to proxy URLs -------------

    #[test]
    fn drm_key_transformer_appends_key_params() {
        let mut keys = BTreeMap::new();
        keys.insert("kid1".into(), "key1value".into());
        keys.insert("kid2".into(), "key2value".into());
        let transformer = DrmKeyTransformer::new(keys);

        let streams = vec![Stream {
            url: Some("https://flow.example.com/proxy/stream?d=abc123".into()),
            ..Default::default()
        }];
        let result = transformer.transform_streams(streams);
        let u = result[0].url.as_ref().unwrap();
        assert!(u.contains("key_id=kid1"), "key_id=kid1 present: {u}");
        assert!(u.contains("key=key1value"), "key=key1value present: {u}");
        assert!(u.contains("key_id=kid2"), "key_id=kid2 present: {u}");
        assert!(u.contains("key=key2value"), "key=key2value present: {u}");
        // Original d param preserved.
        assert!(u.contains("d=abc123"), "original d param preserved: {u}");
    }

    #[test]
    fn drm_key_transformer_empty_keys_is_identity() {
        let transformer = DrmKeyTransformer::new(BTreeMap::new());
        let url = "https://flow.example.com/proxy/stream?d=abc123";
        let streams = vec![Stream {
            url: Some(url.into()),
            ..Default::default()
        }];
        let result = transformer.transform_streams(streams);
        assert_eq!(result[0].url.as_deref(), Some(url));
    }

    #[test]
    fn drm_key_transformer_skips_streams_without_url() {
        let mut keys = BTreeMap::new();
        keys.insert("kid1".into(), "key1".into());
        let transformer = DrmKeyTransformer::new(keys);
        let streams = vec![Stream {
            info_hash: Some("abc".into()),
            ..Default::default()
        }];
        let result = transformer.transform_streams(streams);
        assert_eq!(result[0].url, None);
        assert_eq!(result[0].info_hash.as_deref(), Some("abc"));
    }

    // -- QualityFilterTransformer: filters by quality prefs ------------------

    #[test]
    fn quality_filter_transformer_filters_by_max_resolution() {
        use crate::quality::Resolution;
        let prefs = QualityPrefs {
            max_resolution: Some(Resolution::R1080p),
            ..Default::default()
        };
        let transformer = QualityFilterTransformer::new(prefs, None);

        let streams = vec![
            Stream {
                url: Some("https://cdn.example.com/4k.mkv".into()),
                name: Some("4K".into()),
                behavior_hints: Some(crate::stremio::types::StreamBehaviorHints {
                    filename: Some("Movie.2160p.BluRay.x265".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Stream {
                url: Some("https://cdn.example.com/1080p.mkv".into()),
                name: Some("1080p".into()),
                behavior_hints: Some(crate::stremio::types::StreamBehaviorHints {
                    filename: Some("Movie.1080p.WEB-DL.x264".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        let result = transformer.transform_streams(streams);
        // 4K stream excluded (above max_resolution=1080p).
        assert_eq!(result.len(), 1, "4K stream excluded");
        assert_eq!(result[0].name.as_deref(), Some("1080p"));
    }

    #[test]
    fn quality_filter_transformer_keeps_streams_without_parseable_name() {
        let prefs = QualityPrefs {
            max_resolution: Some(crate::quality::Resolution::R720p),
            ..Default::default()
        };
        let transformer = QualityFilterTransformer::new(prefs, None);

        let streams = vec![Stream {
            url: Some("https://cdn.example.com/v.mkv".into()),
            // No name/description/filename — cannot be ranked.
            ..Default::default()
        }];
        let result = transformer.transform_streams(streams);
        // Unrankable stream is kept.
        assert_eq!(result.len(), 1);
    }

    // -- ComposedTransformer: order-preserving pipeline ----------------------

    #[test]
    fn composed_transformer_applies_in_order() {
        // Pipeline: inject header, then append DRM key.
        let mut headers = BTreeMap::new();
        headers.insert("X-Test".into(), "injected".into());
        let mut keys = BTreeMap::new();
        keys.insert("kid1".into(), "key1".into());

        let pipeline = ComposedTransformer::new(vec![
            Arc::new(HeaderInjectionTransformer::new(headers)),
            Arc::new(DrmKeyTransformer::new(keys)),
        ]);

        let streams = vec![Stream {
            url: Some("https://flow.example.com/proxy/stream?d=abc".into()),
            ..Default::default()
        }];
        let result = pipeline.transform_streams(streams);
        assert_eq!(result.len(), 1);
        // DRM key appended.
        let u = result[0].url.as_ref().unwrap();
        assert!(u.contains("key_id=kid1"), "DRM key appended: {u}");
        // Header injected.
        let req_headers = &result[0]
            .behavior_hints
            .as_ref()
            .unwrap()
            .proxy_headers
            .as_ref()
            .unwrap()
            .request;
        assert_eq!(req_headers.get("X-Test").unwrap(), "injected");
    }

    #[test]
    fn composed_transformer_empty_pipeline_is_identity() {
        let pipeline = ComposedTransformer::new(vec![]);
        let streams = vec![Stream {
            url: Some("https://cdn.example.com/v.mkv".into()),
            name: Some("HD".into()),
            ..Default::default()
        }];
        let result = pipeline.transform_streams(streams.clone());
        assert_eq!(result[0].url, streams[0].url);
        assert_eq!(result[0].name, streams[0].name);
    }

    #[test]
    fn composed_transformer_push_appends_to_pipeline() {
        let mut keys1 = BTreeMap::new();
        keys1.insert("kid1".into(), "key1".into());
        let mut keys2 = BTreeMap::new();
        keys2.insert("kid2".into(), "key2".into());

        let pipeline = ComposedTransformer::new(vec![Arc::new(DrmKeyTransformer::new(keys1))])
            .push(Arc::new(DrmKeyTransformer::new(keys2)));

        let streams = vec![Stream {
            url: Some("https://flow.example.com/proxy/stream?d=abc".into()),
            ..Default::default()
        }];
        let result = pipeline.transform_streams(streams);
        let u = result[0].url.as_ref().unwrap();
        assert!(u.contains("key_id=kid1"), "first DRM key present: {u}");
        assert!(u.contains("key_id=kid2"), "second DRM key present: {u}");
    }

    // -- Transformer chain composability and order-preservation --------------

    #[test]
    fn transformer_chain_is_composable_and_order_preserving() {
        // Verify that a pipeline of [HeaderInjection, ProxyLink, DrmKey]
        // produces the correct result: headers injected, URL rewritten, DRM appended.
        let mut headers = BTreeMap::new();
        headers.insert("Referer".into(), "https://source.example.com/".into());
        let mut keys = BTreeMap::new();
        keys.insert("kid-drm".into(), "drm-key-value".into());

        let pipeline = ComposedTransformer::new(vec![
            Arc::new(HeaderInjectionTransformer::new(headers)),
            Arc::new(ProxyLinkTransformer::new(codec(), rewrite_cfg())),
            Arc::new(DrmKeyTransformer::new(keys)),
        ]);

        let streams = vec![Stream {
            url: Some("https://cdn.example.com/movie.mkv".into()),
            name: Some("HD".into()),
            ..Default::default()
        }];
        let result = pipeline.transform_streams(streams);
        assert_eq!(result.len(), 1);

        let u = result[0].url.as_ref().unwrap();
        // URL is a proxy link (ProxyLinkTransformer ran).
        assert!(
            u.starts_with("https://flow.example.com/proxy/stream?d="),
            "proxy link: {u}"
        );
        // DRM key appended (DrmKeyTransformer ran after ProxyLinkTransformer).
        assert!(u.contains("key_id=kid-drm"), "DRM key appended: {u}");
        // Referer header injected into the payload (HeaderInjectionTransformer ran first).
        let payload = decode_proxy_url(&codec(), u);
        assert_eq!(payload.url, "https://cdn.example.com/movie.mkv");
        assert_eq!(
            payload.headers.get("Referer").unwrap(),
            "https://source.example.com/"
        );
    }
}
