//! Xtream Codes stream-URL model + stateless target derivation
//! (`xtream::stream_url`) — Req 9.4, 9.5, 9.6.
//!
//! Xtream Codes exposes media as **short stream URLs** whose path encodes the
//! content category (live / VOD / series / timeshift), the account credentials,
//! and the numeric stream id (design: Components → Xtream). The canonical
//! upstream forms are:
//!
//! * **Live:** `{base}/live/{user}/{pass}/{id}.{ext}`
//! * **VOD (movie):** `{base}/movie/{user}/{pass}/{id}.{ext}`
//! * **Series:** `{base}/series/{user}/{pass}/{id}.{ext}`
//! * **Timeshift:** `{base}/timeshift/{user}/{pass}/{duration}/{start}/{id}.{ext}`
//!
//! This module models that path as a [`XtreamStreamRef`] and provides the two
//! **pure** mappings the stateless proxy is built on (Req 9.5 — every upstream
//! target is derived from the incoming request alone, with no per-session
//! state):
//!
//! * [`XtreamStreamRef::upstream_url`] resolves a parsed ref + the configured
//!   upstream base into the upstream stream URL the proxy fetches (Req 9.4).
//! * [`parse_stream_tail`] parses the proxy's own short stream path back into a
//!   ref so an incoming short stream URL resolves to its upstream target
//!   (Req 9.4).
//! * [`XtreamStreamRef::proxy_url`] / [`parse_upstream_stream_url`] /
//!   [`rewrite_playlist`] rewrite upstream stream URLs (e.g. in a `get.php`
//!   M3U playlist) to route back through the system's proxy (Req 9.6).
//!
//! The proxy's short stream path mirrors the upstream structure under a fixed
//! prefix: `{proxy_base}/proxy/xtream/stream/{cat}/{user}/{pass}/…/{id}.{ext}`
//! where `cat` is the proxy category segment (`live`/`vod`/`series`/
//! `timeshift`). Because the path carries the full coordinates, resolution is a
//! pure function of the request — no lookup table, no session (Req 9.5).

use url::Url;

use crate::errors::AppError;

/// The fixed path prefix every proxy short stream URL begins with, used both to
/// build a rewritten URL ([`XtreamStreamRef::proxy_url`]) and to recognise an
/// incoming short stream request ([`stream_tail_from_path`]).
pub const STREAM_PATH_PREFIX: &str = "/proxy/xtream/stream/";

/// The content category of an Xtream stream (Req 9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCategory {
    /// Live channel — upstream segment `live`.
    Live,
    /// Video-on-demand / movie — upstream segment `movie`.
    Vod,
    /// Series episode — upstream segment `series`.
    Series,
    /// Catch-up / timeshift — upstream segment `timeshift`.
    Timeshift,
}

impl StreamCategory {
    /// The path segment used in the proxy's own short stream URL.
    pub fn proxy_segment(self) -> &'static str {
        match self {
            StreamCategory::Live => "live",
            StreamCategory::Vod => "vod",
            StreamCategory::Series => "series",
            StreamCategory::Timeshift => "timeshift",
        }
    }

    /// The path segment used by the upstream Xtream server (note VOD → `movie`).
    pub fn upstream_segment(self) -> &'static str {
        match self {
            StreamCategory::Live => "live",
            StreamCategory::Vod => "movie",
            StreamCategory::Series => "series",
            StreamCategory::Timeshift => "timeshift",
        }
    }

    /// Parse a proxy short-URL category segment (`live`/`vod`/`series`/
    /// `timeshift`).
    pub fn from_proxy_segment(seg: &str) -> Option<StreamCategory> {
        match seg {
            "live" => Some(StreamCategory::Live),
            "vod" => Some(StreamCategory::Vod),
            "series" => Some(StreamCategory::Series),
            "timeshift" => Some(StreamCategory::Timeshift),
            _ => None,
        }
    }

    /// Parse an upstream path category segment (`live`/`movie`/`series`/
    /// `timeshift`).
    pub fn from_upstream_segment(seg: &str) -> Option<StreamCategory> {
        match seg {
            "live" => Some(StreamCategory::Live),
            "movie" => Some(StreamCategory::Vod),
            "series" => Some(StreamCategory::Series),
            "timeshift" => Some(StreamCategory::Timeshift),
            _ => None,
        }
    }
}

/// The extra coordinates a timeshift/catch-up stream carries beyond the base
/// `{user}/{pass}/{id}` triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeshift {
    /// The catch-up duration (minutes), as it appears in the upstream path.
    pub duration: String,
    /// The catch-up start timestamp, as it appears in the upstream path.
    pub start: String,
}

/// A fully-resolved reference to one Xtream stream — the pure value the
/// stateless proxy maps to/from upstream and proxy URLs (Req 9.4, 9.5, 9.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XtreamStreamRef {
    /// The content category (live / VOD / series / timeshift).
    pub category: StreamCategory,
    /// The account username segment.
    pub username: String,
    /// The account password segment.
    pub password: String,
    /// The numeric stream id (the file stem).
    pub stream_id: String,
    /// The optional stream extension (`ts`, `m3u8`, `mp4`, …).
    pub ext: Option<String>,
    /// Present only for [`StreamCategory::Timeshift`] streams.
    pub timeshift: Option<Timeshift>,
}

impl XtreamStreamRef {
    /// The `{id}` or `{id}.{ext}` file segment.
    fn file_segment(&self) -> String {
        match &self.ext {
            Some(ext) => format!("{}.{}", self.stream_id, ext),
            None => self.stream_id.clone(),
        }
    }

    /// The path (relative to the base) using `segment`-style category segments.
    /// `proxy == true` uses the proxy category segments; otherwise the upstream
    /// ones (VOD → `movie`).
    fn relative_path(&self, proxy: bool) -> Result<String, AppError> {
        let cat = if proxy {
            self.category.proxy_segment()
        } else {
            self.category.upstream_segment()
        };
        let file = self.file_segment();
        match self.category {
            StreamCategory::Timeshift => {
                let ts = self.timeshift.as_ref().ok_or_else(|| {
                    AppError::bad_request(
                        "timeshift stream reference is missing its duration/start",
                    )
                })?;
                Ok(format!(
                    "{cat}/{}/{}/{}/{}/{file}",
                    self.username, self.password, ts.duration, ts.start
                ))
            }
            _ => Ok(format!("{cat}/{}/{}/{file}", self.username, self.password)),
        }
    }

    /// Resolve this ref against the configured upstream `base_url` into the
    /// upstream stream URL the proxy fetches (Req 9.4).
    pub fn upstream_url(&self, base_url: &str) -> Result<Url, AppError> {
        let trimmed = base_url.trim_end_matches('/');
        let full = format!("{trimmed}/{}", self.relative_path(false)?);
        Url::parse(&full).map_err(|e| {
            AppError::unknown(format!(
                "failed to build Xtream upstream stream URL from base `{base_url}`: {e}"
            ))
        })
    }

    /// Build the proxy's own short stream URL for this ref under `proxy_base`,
    /// so a rewritten URL routes back through the system's proxy (Req 9.6).
    pub fn proxy_url(&self, proxy_base: &str) -> Result<String, AppError> {
        let trimmed = proxy_base.trim_end_matches('/');
        Ok(format!(
            "{trimmed}{STREAM_PATH_PREFIX}{}",
            self.relative_path(true)?
        ))
    }
}

/// Split a `{id}` or `{id}.{ext}` file segment into `(stream_id, ext)`.
fn split_file(file: &str) -> (String, Option<String>) {
    match file.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => {
            (stem.to_string(), Some(ext.to_string()))
        }
        _ => (file.to_string(), None),
    }
}

/// Parse the proxy short stream path **tail** (the part after
/// [`STREAM_PATH_PREFIX`]) into a [`XtreamStreamRef`] (Req 9.4).
///
/// Accepts the live/VOD/series form
/// `{cat}/{user}/{pass}/{id}.{ext}` and the timeshift form
/// `{cat}/{user}/{pass}/{duration}/{start}/{id}.{ext}`. A tail that does not
/// match a known shape yields a descriptive [`AppError::bad_request`] (no panic
/// on any input — the parse is total).
pub fn parse_stream_tail(tail: &str) -> Result<XtreamStreamRef, AppError> {
    let tail = tail.trim_matches('/');
    let parts: Vec<&str> = tail.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < 4 {
        return Err(AppError::bad_request(format!(
            "malformed Xtream short stream path `{tail}`"
        )));
    }
    let category = StreamCategory::from_proxy_segment(parts[0]).ok_or_else(|| {
        AppError::bad_request(format!("unknown Xtream stream category `{}`", parts[0]))
    })?;
    let username = parts[1].to_string();
    let password = parts[2].to_string();

    match category {
        StreamCategory::Timeshift => {
            // {cat}/{user}/{pass}/{duration}/{start}/{id}.{ext}
            if parts.len() != 6 {
                return Err(AppError::bad_request(format!(
                    "malformed Xtream timeshift stream path `{tail}`"
                )));
            }
            let (stream_id, ext) = split_file(parts[5]);
            Ok(XtreamStreamRef {
                category,
                username,
                password,
                stream_id,
                ext,
                timeshift: Some(Timeshift {
                    duration: parts[3].to_string(),
                    start: parts[4].to_string(),
                }),
            })
        }
        _ => {
            // {cat}/{user}/{pass}/{id}.{ext}
            if parts.len() != 4 {
                return Err(AppError::bad_request(format!(
                    "malformed Xtream stream path `{tail}`"
                )));
            }
            let (stream_id, ext) = split_file(parts[3]);
            Ok(XtreamStreamRef {
                category,
                username,
                password,
                stream_id,
                ext,
                timeshift: None,
            })
        }
    }
}

/// Locate the proxy short stream tail inside a full request `path`, returning
/// the part after [`STREAM_PATH_PREFIX`].
///
/// Finding the marker anywhere in the path makes this independent of any
/// configured `Server_Path_Prefix` (e.g. `/mediaflow/proxy/xtream/stream/…`).
pub fn stream_tail_from_path(path: &str) -> Option<&str> {
    path.find(STREAM_PATH_PREFIX)
        .map(|i| &path[i + STREAM_PATH_PREFIX.len()..])
}

/// Parse an upstream Xtream stream `url` (relative to the configured
/// `base_url`) into a [`XtreamStreamRef`], or `None` when it is not a
/// recognisable Xtream stream URL under that base (Req 9.6).
///
/// Used to rewrite upstream stream URLs that appear in proxied responses (a
/// `get.php` playlist) back through the proxy. The match is purely structural:
/// the URL must begin with `base_url` and its remaining path must be a known
/// category shape.
pub fn parse_upstream_stream_url(url: &str, base_url: &str) -> Option<XtreamStreamRef> {
    let base = base_url.trim_end_matches('/');
    let rest = url.strip_prefix(base)?;
    let rest = rest.trim_start_matches('/');
    // Drop any query/fragment before structural parsing.
    let path = rest.split(['?', '#']).next().unwrap_or(rest);
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < 4 {
        return None;
    }
    let category = StreamCategory::from_upstream_segment(parts[0])?;
    let username = parts[1].to_string();
    let password = parts[2].to_string();

    match category {
        StreamCategory::Timeshift => {
            if parts.len() != 6 {
                return None;
            }
            let (stream_id, ext) = split_file(parts[5]);
            Some(XtreamStreamRef {
                category,
                username,
                password,
                stream_id,
                ext,
                timeshift: Some(Timeshift {
                    duration: parts[3].to_string(),
                    start: parts[4].to_string(),
                }),
            })
        }
        _ => {
            if parts.len() != 4 {
                return None;
            }
            let (stream_id, ext) = split_file(parts[3]);
            Some(XtreamStreamRef {
                category,
                username,
                password,
                stream_id,
                ext,
                timeshift: None,
            })
        }
    }
}

/// Rewrite every upstream stream URL line in an M3U `playlist` body to its
/// proxy short stream URL under `proxy_base` (Req 9.6).
///
/// Comment/tag lines (those beginning with `#`) and any line that is not a
/// recognisable upstream Xtream stream URL under `base_url` are passed through
/// unchanged, so a non-stream URL (or an unrelated host) is never mangled. The
/// original line terminators are preserved.
pub fn rewrite_playlist(playlist: &str, base_url: &str, proxy_base: &str) -> String {
    let mut out = String::with_capacity(playlist.len());
    for line in playlist.split_inclusive('\n') {
        let (content, newline) = match line.strip_suffix('\n') {
            Some(c) => (c.strip_suffix('\r').unwrap_or(c), &line[c.len()..]),
            None => (line, ""),
        };
        let trimmed = content.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(line);
            continue;
        }
        match parse_upstream_stream_url(trimmed, base_url)
            .and_then(|r| r.proxy_url(proxy_base).ok())
        {
            Some(proxied) => {
                out.push_str(&proxied);
                out.push_str(newline);
            }
            None => out.push_str(line),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_ref() -> XtreamStreamRef {
        XtreamStreamRef {
            category: StreamCategory::Live,
            username: "user1".into(),
            password: "pass1".into(),
            stream_id: "12345".into(),
            ext: Some("ts".into()),
            timeshift: None,
        }
    }

    // -- Upstream URL derivation per category (Req 9.4) ---------------------

    #[test]
    fn upstream_url_live_uses_live_segment() {
        let url = live_ref().upstream_url("http://xt.example:8080").unwrap();
        assert_eq!(
            url.as_str(),
            "http://xt.example:8080/live/user1/pass1/12345.ts"
        );
    }

    #[test]
    fn upstream_url_vod_uses_movie_segment() {
        let r = XtreamStreamRef {
            category: StreamCategory::Vod,
            ext: Some("mp4".into()),
            ..live_ref()
        };
        let url = r.upstream_url("http://xt.example:8080/").unwrap();
        // VOD maps to the upstream `movie` segment; trailing base slash trimmed.
        assert_eq!(
            url.as_str(),
            "http://xt.example:8080/movie/user1/pass1/12345.mp4"
        );
    }

    #[test]
    fn upstream_url_series_uses_series_segment() {
        let r = XtreamStreamRef {
            category: StreamCategory::Series,
            ext: Some("mkv".into()),
            ..live_ref()
        };
        let url = r.upstream_url("http://xt.example:8080").unwrap();
        assert_eq!(
            url.as_str(),
            "http://xt.example:8080/series/user1/pass1/12345.mkv"
        );
    }

    #[test]
    fn upstream_url_timeshift_includes_duration_and_start() {
        let r = XtreamStreamRef {
            category: StreamCategory::Timeshift,
            stream_id: "678".into(),
            ext: Some("ts".into()),
            timeshift: Some(Timeshift {
                duration: "60".into(),
                start: "2024-01-01:20-30".into(),
            }),
            ..live_ref()
        };
        let url = r.upstream_url("http://xt.example:8080").unwrap();
        assert_eq!(
            url.as_str(),
            "http://xt.example:8080/timeshift/user1/pass1/60/2024-01-01:20-30/678.ts"
        );
    }

    #[test]
    fn upstream_url_preserves_a_base_path_prefix() {
        let r = live_ref();
        let url = r.upstream_url("http://host/xtream-panel").unwrap();
        assert_eq!(
            url.as_str(),
            "http://host/xtream-panel/live/user1/pass1/12345.ts"
        );
    }

    // -- Proxy short URL round-trip (Req 9.4 + 9.6) -------------------------

    #[test]
    fn proxy_url_then_parse_tail_round_trips() {
        let r = live_ref();
        let proxy = r.proxy_url("https://proxy.example/mediaflow").unwrap();
        assert_eq!(
            proxy,
            "https://proxy.example/mediaflow/proxy/xtream/stream/live/user1/pass1/12345.ts"
        );
        let tail = stream_tail_from_path(&proxy).expect("marker present");
        let parsed = parse_stream_tail(tail).expect("parses");
        assert_eq!(parsed, r);
    }

    #[test]
    fn proxy_url_round_trips_for_every_category() {
        let cases = [
            XtreamStreamRef {
                category: StreamCategory::Live,
                ..live_ref()
            },
            XtreamStreamRef {
                category: StreamCategory::Vod,
                ext: Some("mp4".into()),
                ..live_ref()
            },
            XtreamStreamRef {
                category: StreamCategory::Series,
                ext: Some("mkv".into()),
                ..live_ref()
            },
            XtreamStreamRef {
                category: StreamCategory::Timeshift,
                ext: Some("ts".into()),
                timeshift: Some(Timeshift {
                    duration: "90".into(),
                    start: "s1".into(),
                }),
                ..live_ref()
            },
        ];
        for r in cases {
            let proxy = r.proxy_url("https://proxy.example").unwrap();
            let tail = stream_tail_from_path(&proxy).unwrap();
            assert_eq!(parse_stream_tail(tail).unwrap(), r, "round trip for {r:?}");
        }
    }

    #[test]
    fn proxy_short_url_resolves_to_upstream_url() {
        // The whole point of Req 9.4: a short URL maps back to the upstream
        // stream URL purely from its own path coordinates.
        let proxy = "https://proxy.example/proxy/xtream/stream/vod/u/p/42.mp4";
        let tail = stream_tail_from_path(proxy).unwrap();
        let parsed = parse_stream_tail(tail).unwrap();
        assert_eq!(
            parsed.upstream_url("http://origin:8080").unwrap().as_str(),
            "http://origin:8080/movie/u/p/42.mp4"
        );
    }

    // -- parse_stream_tail edge cases (totality, no panic) ------------------

    #[test]
    fn parse_stream_tail_handles_missing_extension() {
        let r = parse_stream_tail("live/u/p/123").unwrap();
        assert_eq!(r.stream_id, "123");
        assert_eq!(r.ext, None);
    }

    #[test]
    fn parse_stream_tail_rejects_unknown_category() {
        let err = parse_stream_tail("bogus/u/p/1.ts").unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::BadRequest);
    }

    #[test]
    fn parse_stream_tail_rejects_too_few_segments() {
        assert!(parse_stream_tail("live/u/p").is_err());
        assert!(parse_stream_tail("").is_err());
        assert!(parse_stream_tail("///").is_err());
    }

    #[test]
    fn parse_stream_tail_rejects_wrong_timeshift_arity() {
        // timeshift needs exactly 6 segments.
        assert!(parse_stream_tail("timeshift/u/p/1.ts").is_err());
    }

    // -- Upstream URL parsing for rewriting (Req 9.6) -----------------------

    #[test]
    fn parse_upstream_stream_url_recognises_live() {
        let r =
            parse_upstream_stream_url("http://origin:8080/live/u/p/55.ts", "http://origin:8080")
                .expect("recognised");
        assert_eq!(r.category, StreamCategory::Live);
        assert_eq!(r.stream_id, "55");
        assert_eq!(r.ext.as_deref(), Some("ts"));
    }

    #[test]
    fn parse_upstream_stream_url_rejects_foreign_host() {
        assert!(parse_upstream_stream_url(
            "http://other-host/live/u/p/55.ts",
            "http://origin:8080"
        )
        .is_none());
    }

    #[test]
    fn parse_upstream_stream_url_ignores_non_stream_paths() {
        assert!(parse_upstream_stream_url(
            "http://origin:8080/player_api.php?action=x",
            "http://origin:8080"
        )
        .is_none());
    }

    // -- Playlist rewriting (Req 9.6) ---------------------------------------

    #[test]
    fn rewrite_playlist_rewrites_only_stream_url_lines() {
        let base = "http://origin:8080";
        let proxy_base = "https://proxy.example";
        let playlist = "#EXTM3U\n\
            #EXTINF:-1 tvg-id=\"a\",Channel A\n\
            http://origin:8080/live/u/p/1.ts\n\
            #EXTINF:-1,Movie B\n\
            http://origin:8080/movie/u/p/2.mp4\n";
        let out = rewrite_playlist(playlist, base, proxy_base);

        assert!(out.contains("https://proxy.example/proxy/xtream/stream/live/u/p/1.ts"));
        assert!(out.contains("https://proxy.example/proxy/xtream/stream/vod/u/p/2.mp4"));
        // Tag lines untouched.
        assert!(out.contains("#EXTINF:-1 tvg-id=\"a\",Channel A"));
        assert!(out.starts_with("#EXTM3U\n"));
        // No upstream-origin stream URL survives.
        assert!(!out.contains("http://origin:8080/live"));
        assert!(!out.contains("http://origin:8080/movie"));
    }

    #[test]
    fn rewrite_playlist_passes_through_unrelated_urls() {
        let out = rewrite_playlist(
            "#EXTM3U\nhttp://other-host/stream.ts\n",
            "http://origin:8080",
            "https://proxy.example",
        );
        // Not an Xtream stream URL under the base → unchanged.
        assert!(out.contains("http://other-host/stream.ts"));
    }

    #[test]
    fn rewrite_playlist_preserves_line_endings_and_no_trailing_newline() {
        let out = rewrite_playlist(
            "http://origin:8080/live/u/p/1.ts",
            "http://origin:8080",
            "https://proxy.example",
        );
        // Single line, no trailing newline preserved.
        assert_eq!(
            out,
            "https://proxy.example/proxy/xtream/stream/live/u/p/1.ts"
        );
    }
}
