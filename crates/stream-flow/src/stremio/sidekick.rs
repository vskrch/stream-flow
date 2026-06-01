//! Sidekick addon (`stremio::sidekick`) — Req 25 (25.1).
//!
//! The Sidekick addon is the Stremio "utilities" surface: it exposes a
//! [`Manifest`] plus the set of **configured resources** it serves (Req 25.1).
//! Unlike the Store / Wrap / Torz addons it does not resolve playable streams;
//! it advertises whatever resources an operator has configured and serves them,
//! answering a request for a resource it does **not** declare with the Stremio
//! not-found convention ([`StremioError::not_found`], Req 26.3).
//!
//! The manifest declares every supported content type and id prefix (Req 26.4),
//! and [`Sidekick::serve_resource`] is total over resource names: a configured
//! resource is served, an unconfigured one maps to a [`StremioError`] so a
//! Stremio client always sees a structured answer.

use crate::config::StremioConfig;

use super::types::{
    Catalog, ContentType, Manifest, MetasResponse, Resource, ResourceName, StreamsResponse,
    StremioError, SubtitlesResponse,
};

/// The default Sidekick addon id.
const DEFAULT_ID: &str = "st:sidekick";
/// The default Sidekick addon name.
const DEFAULT_NAME: &str = "StremThru Sidekick";
/// The addon version (matches the crate version line of the wider system).
const DEFAULT_VERSION: &str = "0.1.0";

/// A payload produced by serving one of the Sidekick addon's configured
/// resources (Req 25.1).
///
/// Sidekick carries no first-party content of its own, so serving a declared
/// resource yields the valid **empty** envelope for that resource kind; an
/// operator layering content on top fills these in. A request naming a resource
/// the addon does not declare never reaches here — it is rejected with a
/// [`StremioError::not_found`] (Req 26.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidekickResource {
    /// A `catalog` resource — a (possibly empty) list of catalog previews.
    Catalog(MetasResponse),
    /// A `stream` resource — a (possibly empty) list of streams.
    Stream(StreamsResponse),
    /// A `subtitles` resource — a (possibly empty) list of subtitle tracks.
    Subtitles(SubtitlesResponse),
}

/// The Stremio Sidekick utilities addon (Req 25.1).
///
/// Construct it with [`Sidekick::new`] for full control over the advertised
/// resources, or [`Sidekick::with_defaults`] for the standard utilities surface
/// derived from a [`StremioConfig`]. [`Sidekick::manifest`] returns the manifest
/// declaring the configured resources (Req 25.1) and [`Sidekick::serve_resource`]
/// serves a declared resource or returns a not-found error (Req 26.3).
#[derive(Clone, Debug)]
pub struct Sidekick {
    id: String,
    name: String,
    description: String,
    version: String,
    resources: Vec<Resource>,
    types: Vec<ContentType>,
    id_prefixes: Vec<String>,
    catalogs: Vec<Catalog>,
}

impl Sidekick {
    /// Build a Sidekick addon advertising an explicit set of `resources`,
    /// content `types`, and `id_prefixes` (Req 25.1, 26.4).
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        resources: Vec<Resource>,
        types: Vec<ContentType>,
        id_prefixes: Vec<String>,
        catalogs: Vec<Catalog>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            version: DEFAULT_VERSION.to_string(),
            resources,
            types,
            id_prefixes,
            catalogs,
        }
    }

    /// Build the standard Sidekick utilities addon from a [`StremioConfig`].
    ///
    /// Uses the configured `addon_name` when present, falling back to the
    /// default. The default surface advertises a `catalog` resource (the
    /// utilities catalog) for every canonical content type (Req 25.1, 26.4).
    pub fn with_defaults(config: &StremioConfig) -> Self {
        let name = config
            .addon_name
            .clone()
            .unwrap_or_else(|| DEFAULT_NAME.to_string());
        Self::new(
            DEFAULT_ID,
            name,
            "Stremio utilities (account, library, and catalog helpers).",
            vec![Resource::full(
                ResourceName::catalog(),
                ContentType::all(),
                vec![],
            )],
            ContentType::all(),
            Vec::new(),
            Vec::new(),
        )
    }

    /// The configured resource declarations this addon serves (Req 25.1).
    pub fn resources(&self) -> &[Resource] {
        &self.resources
    }

    /// Whether the addon declares the named resource (Req 25.1, 26.3).
    pub fn provides(&self, resource: &str) -> bool {
        self.resources.iter().any(|r| r.name.as_str() == resource)
    }

    /// The Sidekick [`Manifest`] declaring the configured resources, content
    /// types, and id prefixes (Req 25.1, 26.4).
    pub fn manifest(&self) -> Manifest {
        Manifest {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            version: self.version.clone(),
            resources: self.resources.clone(),
            types: self.types.clone(),
            id_prefixes: self.id_prefixes.clone(),
            catalogs: self.catalogs.clone(),
            ..Manifest::default()
        }
    }

    /// Serve one of the addon's configured resources by name (Req 25.1).
    ///
    /// A configured resource yields its (empty-but-valid) envelope; a resource
    /// the manifest does not declare is rejected with a
    /// [`StremioError::not_found`] (Req 26.3). Only `catalog`, `stream`, and
    /// `subtitles` carry a servable envelope — a declared resource of any other
    /// kind also resolves to not-found here (Sidekick serves no `meta`/
    /// `addon_catalog` payload of its own).
    pub fn serve_resource(&self, resource: &str) -> Result<SidekickResource, StremioError> {
        if !self.provides(resource) {
            return Err(StremioError::not_found(resource));
        }
        match resource {
            ResourceName::CATALOG => Ok(SidekickResource::Catalog(MetasResponse::default())),
            ResourceName::STREAM => Ok(SidekickResource::Stream(StreamsResponse::default())),
            ResourceName::SUBTITLES => {
                Ok(SidekickResource::Subtitles(SubtitlesResponse::default()))
            }
            other => Err(StremioError::not_found(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stremio::types::ResourceName;

    fn sidekick_with(resources: Vec<Resource>) -> Sidekick {
        Sidekick::new(
            DEFAULT_ID,
            DEFAULT_NAME,
            "desc",
            resources,
            ContentType::all(),
            vec!["tt".into()],
            Vec::new(),
        )
    }

    // -- Req 25.1: manifest declares the configured resources ---------------

    #[::core::prelude::v1::test]
    fn manifest_declares_configured_resources() {
        let resources = vec![
            Resource::full(ResourceName::catalog(), ContentType::all(), vec![]),
            Resource::bare("meta"),
        ];
        let sk = sidekick_with(resources.clone());
        let manifest = sk.manifest();

        assert!(manifest.is_valid(), "manifest must have id/name/version");
        assert_eq!(manifest.resources, resources);
        // Req 26.4: content types + id prefixes declared.
        assert_eq!(manifest.types, ContentType::all());
        assert_eq!(manifest.id_prefixes, vec!["tt".to_string()]);
        // Declared resources answer `provides`.
        assert!(manifest.provides("catalog"));
        assert!(manifest.provides("meta"));
    }

    #[::core::prelude::v1::test]
    fn with_defaults_uses_configured_addon_name_and_is_valid() {
        let cfg = StremioConfig {
            addon_name: Some("My Sidekick".into()),
            ..StremioConfig::default()
        };
        let sk = Sidekick::with_defaults(&cfg);
        let manifest = sk.manifest();

        assert_eq!(manifest.name, "My Sidekick");
        assert!(manifest.is_valid());
        assert!(manifest.provides("catalog"));
        assert_eq!(manifest.types, ContentType::all());
    }

    #[::core::prelude::v1::test]
    fn with_defaults_falls_back_to_default_name() {
        let sk = Sidekick::with_defaults(&StremioConfig::default());
        assert_eq!(sk.manifest().name, DEFAULT_NAME);
    }

    // -- Req 25.1 + 26.3: serve configured resources, not-found otherwise ---

    #[::core::prelude::v1::test]
    fn serves_declared_catalog_resource() {
        let sk = sidekick_with(vec![Resource::full(
            ResourceName::catalog(),
            ContentType::all(),
            vec![],
        )]);
        let served = sk.serve_resource("catalog").expect("catalog is declared");
        assert_eq!(served, SidekickResource::Catalog(MetasResponse::default()));
    }

    #[::core::prelude::v1::test]
    fn serves_declared_stream_and_subtitles_resources() {
        let sk = sidekick_with(vec![Resource::bare("stream"), Resource::bare("subtitles")]);
        assert_eq!(
            sk.serve_resource("stream").unwrap(),
            SidekickResource::Stream(StreamsResponse::default()),
        );
        assert_eq!(
            sk.serve_resource("subtitles").unwrap(),
            SidekickResource::Subtitles(SubtitlesResponse::default()),
        );
    }

    #[::core::prelude::v1::test]
    fn undeclared_resource_is_stremio_not_found() {
        let sk = sidekick_with(vec![Resource::bare("catalog")]);
        let err = sk.serve_resource("stream").unwrap_err();
        assert_eq!(err, StremioError::not_found("stream"));
        assert!(err.err.contains("stream"));
        assert!(!sk.provides("stream"));
    }

    // -- Manifest round-trips (serde) ---------------------------------------

    #[::core::prelude::v1::test]
    fn manifest_round_trips_through_json() {
        let sk = sidekick_with(vec![
            Resource::full(
                ResourceName::catalog(),
                ContentType::all(),
                vec!["tt".into()],
            ),
            Resource::bare("meta"),
        ]);
        let manifest = sk.manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
    }
}
