//! HTTP protocol-mode helpers — Req 43.
//!
//! TLS termination is commonly handled by a reverse proxy in this deployment,
//! so the server only enables HTTP/2 directly when the operator has enabled it
//! and TLS/ALPN is available. Bulk media remains HTTP/1.1 by policy.

use crate::config::Http2Config;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolMode {
    Http1Only,
    Http2AlpnWithHttp1Fallback,
}

pub fn control_plane_protocol(config: &Http2Config, tls_alpn_available: bool) -> ProtocolMode {
    if config.enabled && tls_alpn_available {
        ProtocolMode::Http2AlpnWithHttp1Fallback
    } else {
        ProtocolMode::Http1Only
    }
}

pub fn upstream_api_uses_http2(config: &Http2Config) -> bool {
    config.enabled
}

pub fn bulk_media_uses_http2(_config: &Http2Config) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plane_requires_enabled_and_tls_alpn() {
        assert_eq!(
            control_plane_protocol(&Http2Config { enabled: true }, true),
            ProtocolMode::Http2AlpnWithHttp1Fallback
        );
        assert_eq!(
            control_plane_protocol(&Http2Config { enabled: true }, false),
            ProtocolMode::Http1Only
        );
        assert_eq!(
            control_plane_protocol(&Http2Config { enabled: false }, true),
            ProtocolMode::Http1Only
        );
    }

    #[test]
    fn upstream_api_can_use_http2_but_bulk_media_does_not() {
        let enabled = Http2Config { enabled: true };
        assert!(upstream_api_uses_http2(&enabled));
        assert!(!bulk_media_uses_http2(&enabled));
        let disabled = Http2Config { enabled: false };
        assert!(!upstream_api_uses_http2(&disabled));
        assert!(!bulk_media_uses_http2(&disabled));
    }
}
