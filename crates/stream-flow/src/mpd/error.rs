//! MPD parse / conversion errors (`mpd::error`) — Req 2.8, 3.6.
//!
//! Every MPD failure is a descriptive [`MpdError`] that **identifies the
//! failing element** (Req 2.8) or the missing segment (Req 3.6, task 16.3),
//! and maps cleanly onto the canonical [`AppError`](crate::errors::AppError)
//! taxonomy so the proxy surface renders a consistent error body (Req 47).
//!
//! A malformed document or a required-attribute-missing element is a client-
//! facing **bad request** (the upstream returned a body that is not a parseable
//! MPD, mirroring the HLS "unparseable body → descriptive parse error" rule,
//! Req 1.8 / 2.8); an unresolved segment is likewise a bad request naming the
//! segment.

use crate::errors::AppError;

/// A descriptive MPD parse / conversion error that names the failing element
/// (Req 2.8) or missing segment (Req 3.6).
#[derive(Debug, thiserror::Error)]
pub enum MpdError {
    /// The document (or a sub-element) is not well-formed XML / not a parseable
    /// MPD. `element` names where parsing failed; `detail` carries the
    /// underlying parser message (Req 2.8).
    #[error("failed to parse MPD element <{element}>: {detail}")]
    Malformed {
        /// The element being parsed when the failure occurred.
        element: String,
        /// The underlying parser error message.
        detail: String,
    },
    /// A required element or attribute is absent. `element` identifies the
    /// owning element and `field` the missing attribute (Req 2.8).
    #[error("MPD element <{element}> is missing required `{field}`")]
    Missing {
        /// The element that is missing a required field.
        element: String,
        /// The name of the missing attribute / child element.
        field: String,
    },
    /// A requested segment index has no entry — e.g. an unresolved
    /// `SegmentTimeline` gap (Req 3.6). The resolution dispatch that produces
    /// this lands in task 16.3; the variant is defined here so the error
    /// taxonomy is complete.
    #[error("MPD representation `{representation}` has no segment for {segment}")]
    MissingSegment {
        /// The `@id` of the representation being addressed.
        representation: String,
        /// A human-readable identifier of the missing segment (number or time).
        segment: String,
    },
}

impl MpdError {
    /// A [`Malformed`](Self::Malformed) error naming the element being parsed.
    pub fn malformed(element: impl Into<String>, detail: impl std::fmt::Display) -> Self {
        MpdError::Malformed {
            element: element.into(),
            detail: detail.to_string(),
        }
    }

    /// A [`Missing`](Self::Missing) error naming the element and the absent
    /// required field.
    pub fn missing(element: impl Into<String>, field: impl Into<String>) -> Self {
        MpdError::Missing {
            element: element.into(),
            field: field.into(),
        }
    }

    /// A [`MissingSegment`](Self::MissingSegment) error naming the
    /// representation and the unresolved segment (Req 3.6).
    pub fn missing_segment(
        representation: impl Into<String>,
        segment: impl Into<String>,
    ) -> Self {
        MpdError::MissingSegment {
            representation: representation.into(),
            segment: segment.into(),
        }
    }
}

impl From<MpdError> for AppError {
    /// Map onto the canonical taxonomy. An unparseable / incomplete MPD, or an
    /// unresolved segment, is a `bad-request` (`400`) whose message names the
    /// failing element / segment (Req 2.8, 3.6, 47).
    fn from(err: MpdError) -> Self {
        AppError::bad_request(err.to_string())
    }
}
