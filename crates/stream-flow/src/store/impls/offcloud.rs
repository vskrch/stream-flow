//! Offcloud store implementation — Req 16.1, 17.11, 17.12, 18.4.
//!
//! Quirks:
//! - `CheckMagnet` returns cached hashes with **no files** → emit `cached` +
//!   empty file list (Req 17.11), file idx/size `-1` (Req 17.12).
//! - `GenerateLink` is passthrough (Req 18.4 — omits IP, must not fail).
//! - Offcloud omits IP on link-gen and must not fail for lack of IP binding.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Method;
use serde::Deserialize;
use url::Url;

use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::store::{
    AddMagnetData, AddMagnetParams, CheckMagnetData, CheckMagnetItem, CheckMagnetParams,
    GenerateLinkData, GenerateLinkParams, GetMagnetData, GetMagnetParams, GetUserParams,
    ListMagnetsData, ListMagnetsParams, MagnetStatus, RemoveMagnetData, RemoveMagnetParams, Store,
    StoreName, SubscriptionStatus, User,
};

const BASE_URL: &str = "https://offcloud.com/api";

/// Offcloud [`Store`] implementation.
pub struct OffcloudStore {
    client: Arc<OutboundClient>,
    token: String,
    base_url: String,
}

impl OffcloudStore {
    pub fn new(client: Arc<OutboundClient>, token: String) -> Self {
        Self {
            client,
            token,
            base_url: BASE_URL.to_string(),
        }
    }

    #[cfg(test)]
    pub fn with_base_url(client: Arc<OutboundClient>, token: String, base_url: String) -> Self {
        Self {
            client,
            token,
            base_url,
        }
    }

    fn api_url(&self, path: &str) -> Url {
        Url::parse(&format!("{}{path}", self.base_url)).expect("valid Offcloud API URL")
    }

    pub fn map_error(status: u16, body: &str) -> AppError {
        if let Ok(err) = serde_json::from_str::<OcErrorResponse>(body) {
            if !err.error.is_empty() {
                let msg = err.error.to_ascii_lowercase();
                if msg.contains("auth") || msg.contains("api key") || msg.contains("token") {
                    return AppError::unauthorized_for("offcloud", err.error);
                }
                if msg.contains("limit") || msg.contains("quota") {
                    return AppError::store_limit_exceeded(err.error).with_store("offcloud");
                }
                return AppError::unknown(err.error)
                    .with_store("offcloud")
                    .with_upstream_status(status);
            }
        }

        match status {
            401 => AppError::unauthorized_for("offcloud", "authentication failed"),
            503 | 502 | 504 => {
                AppError::upstream_unavailable_for("offcloud", "service unavailable")
            }
            429 => AppError::too_many_requests("rate limited").with_store("offcloud"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("offcloud")
                .with_upstream_status(status),
        }
    }
}

#[derive(Deserialize, Default)]
struct OcErrorResponse {
    #[serde(default)]
    error: String,
}

#[derive(Deserialize)]
struct OcCacheResult {
    #[serde(default, rename = "cachedItems")]
    cached_items: Vec<String>,
}

#[async_trait]
impl Store for OffcloudStore {
    fn get_name(&self) -> StoreName {
        StoreName::Offcloud
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let url = self.api_url("/account/stats");
        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("offcloud", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("offcloud"))?;

        let email = data
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let is_premium = data
            .get("isPremium")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(User {
            id: email.clone(),
            email,
            subscription_status: if is_premium {
                SubscriptionStatus::Premium
            } else {
                SubscriptionStatus::Expired
            },
            has_usenet: false,
        })
    }

    async fn check_magnet(&self, p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError> {
        // Offcloud: cached status with empty file list is valid (Req 17.11)
        let hashes: Vec<String> = p
            .magnets
            .iter()
            .map(|m| super::realdebrid::extract_hash_from_magnet(m).to_lowercase())
            .collect();

        let url = self.api_url("/cache");
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&serde_json::json!({ "hashes": hashes }))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("offcloud", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let cache_result: OcCacheResult = resp.json().await.unwrap_or(OcCacheResult {
            cached_items: vec![],
        });

        let cached_set: std::collections::HashSet<String> = cache_result
            .cached_items
            .into_iter()
            .map(|h| h.to_lowercase())
            .collect();

        let items = p
            .magnets
            .iter()
            .map(|magnet| {
                let hash = super::realdebrid::extract_hash_from_magnet(magnet).to_lowercase();
                let is_cached = cached_set.contains(&hash);
                CheckMagnetItem {
                    hash,
                    magnet: magnet.clone(),
                    // Req 17.11: cached with empty file list
                    status: if is_cached {
                        MagnetStatus::Cached
                    } else {
                        MagnetStatus::Unknown
                    },
                    // Req 17.11: empty file list for Offcloud cached items
                    files: vec![],
                }
            })
            .collect();

        Ok(CheckMagnetData { items })
    }

    async fn add_magnet(&self, p: &AddMagnetParams) -> Result<AddMagnetData, AppError> {
        let url = self.api_url("/cloud");
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&serde_json::json!({ "url": p.magnet }))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("offcloud", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("offcloud"))?;

        let id = data
            .get("requestId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let hash = super::realdebrid::extract_hash_from_magnet(&p.magnet).to_lowercase();

        Ok(AddMagnetData {
            id,
            hash,
            magnet: p.magnet.clone(),
            name: String::new(),
            size: -1, // Req 17.12: unknown size
            status: MagnetStatus::Queued,
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn get_magnet(&self, p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
        let url = self.api_url(&format!("/cloud/status?requestId={}", p.id));
        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("offcloud", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("offcloud"))?;

        let native_status = data
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        Ok(GetMagnetData {
            id: p.id.clone(),
            name: data
                .get("fileName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            hash: String::new(),
            size: -1, // Req 17.12
            status: MagnetStatus::from_native(native_status),
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        let url = self.api_url("/cloud/history");
        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("offcloud", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let data: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();

        let all_items: Vec<crate::store::ListMagnetItem> = data
            .iter()
            .map(|v| {
                let id = v
                    .get("requestId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = v
                    .get("fileName")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let native_status = v
                    .get("status")
                    .and_then(|x| x.as_str())
                    .unwrap_or("unknown");
                crate::store::ListMagnetItem {
                    id,
                    name,
                    hash: String::new(),
                    size: -1, // Req 17.12
                    status: MagnetStatus::from_native(native_status),
                }
            })
            .collect();

        let total = all_items.len() as i64;
        let items = all_items
            .into_iter()
            .skip(p.offset as usize)
            .take(p.limit as usize)
            .collect();

        Ok(ListMagnetsData {
            items,
            total_items: total,
        })
    }

    async fn remove_magnet(&self, p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError> {
        let url = self.api_url(&format!("/cloud/remove/{}", p.id));
        let resp = self
            .client
            .upstream(Method::DELETE, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("offcloud", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() && status != 204 {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        // Offcloud: GenerateLink is passthrough — omits IP, must not fail (Req 18.4)
        // The link is already a direct link from Offcloud
        Ok(GenerateLinkData {
            link: p.link.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EgressPolicy;
    use crate::errors::ErrorCategory;
    use crate::store::Ctx;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn outbound() -> Arc<OutboundClient> {
        Arc::new(OutboundClient::new(
            reqwest::Client::new(),
            wreq::Client::new(),
            EgressPolicy::FailOpen,
            None,
            None,
            HashMap::new(),
        ))
    }

    fn ctx() -> Ctx {
        Ctx {
            request_id: "test-req".into(),
            client_ip: None,
            trusted: false,
        }
    }

    fn store_for(mock: &MockServer) -> OffcloudStore {
        OffcloudStore::with_base_url(outbound(), "tok".into(), format!("{}/api", mock.uri()))
    }

    #[tokio::test]
    async fn get_name_is_offcloud() {
        assert_eq!(
            OffcloudStore::new(outbound(), "tok".into()).get_name(),
            StoreName::Offcloud
        );
    }

    #[tokio::test]
    async fn check_magnet_cached_with_empty_file_list_is_valid() {
        // Req 17.11: Offcloud reports a cached hash WITHOUT per-file detail ->
        // emit Cached + an empty file list rather than failing.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cache"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cachedItems": ["abc123"]
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let magnets = vec!["magnet:?xt=urn:btih:ABC123".to_string()];
        let data = store_for(&mock)
            .check_magnet(&CheckMagnetParams {
                ctx: ctx(),
                magnets: &magnets,
                client_ip: None,
                sid: None,
                local_only: false,
            })
            .await
            .unwrap();
        assert_eq!(data.items.len(), 1);
        assert_eq!(data.items[0].status, MagnetStatus::Cached);
        assert!(data.items[0].files.is_empty(), "Req 17.11: empty file list");
    }

    #[tokio::test]
    async fn get_magnet_unknown_size_is_minus_one() {
        // Req 17.12: unknown size represented as -1.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/cloud/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "downloaded", "fileName": "movie.mkv"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let magnet = store_for(&mock)
            .get_magnet(&GetMagnetParams {
                ctx: ctx(),
                id: "req1".into(),
            })
            .await
            .unwrap();
        assert_eq!(magnet.size, -1);
        assert_eq!(magnet.status, MagnetStatus::Downloaded);
    }

    #[tokio::test]
    async fn generate_link_is_passthrough_and_ignores_ip() {
        // Req 18.4: Offcloud does not require IP binding — the link is returned
        // as-is and the call must not fail even when an IP is supplied, and
        // crucially makes NO upstream call.
        let data = OffcloudStore::new(outbound(), "tok".into())
            .generate_link(&GenerateLinkParams {
                ctx: ctx(),
                link: "https://offcloud.com/dl/abc".into(),
                client_ip: Some("203.0.113.7".parse::<IpAddr>().unwrap()),
            })
            .await
            .unwrap();
        assert_eq!(data.link, "https://offcloud.com/dl/abc");
    }

    #[tokio::test]
    async fn auth_failure_maps_to_unauthorized_identifying_store() {
        // Req 16.8.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/account/stats"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&mock)
            .await;

        let err = store_for(&mock)
            .get_user(&GetUserParams { ctx: ctx() })
            .await
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("offcloud"));
    }
}
