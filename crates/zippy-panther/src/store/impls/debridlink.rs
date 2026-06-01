//! Debrid-Link store implementation — Req 16.1.

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
    ListMagnetsData, ListMagnetsParams, MagnetFile, MagnetStatus, RemoveMagnetData,
    RemoveMagnetParams, Store, StoreName, SubscriptionStatus, User,
};

const BASE_URL: &str = "https://debrid-link.com/api/v2";

/// Debrid-Link [`Store`] implementation.
pub struct DebridLinkStore {
    client: Arc<OutboundClient>,
    token: String,
    base_url: String,
}

impl DebridLinkStore {
    pub fn new(client: Arc<OutboundClient>, token: String) -> Self {
        Self {
            client,
            token,
            base_url: BASE_URL.to_string(),
        }
    }

    /// Create with a custom base URL (for testing with wiremock).
    #[cfg(test)]
    pub fn with_base_url(client: Arc<OutboundClient>, token: String, base_url: String) -> Self {
        Self {
            client,
            token,
            base_url,
        }
    }

    fn api_url(&self, path: &str) -> Url {
        Url::parse(&format!("{}{path}", self.base_url)).expect("valid Debrid-Link API URL")
    }

    pub fn map_error(status: u16, body: &str) -> AppError {
        if let Ok(resp) = serde_json::from_str::<DlResponse>(body) {
            if !resp.error.is_empty() {
                let msg = resp.error.to_ascii_lowercase();
                if msg.contains("auth") || msg.contains("token") || msg.contains("key") {
                    return AppError::unauthorized_for("debridlink", resp.error);
                }
                if msg.contains("limit") || msg.contains("traffic") {
                    return AppError::store_limit_exceeded(resp.error).with_store("debridlink");
                }
                return AppError::unknown(resp.error)
                    .with_store("debridlink")
                    .with_upstream_status(status);
            }
        }

        match status {
            401 => AppError::unauthorized_for("debridlink", "authentication failed"),
            502..=504 => AppError::upstream_unavailable_for("debridlink", "service unavailable"),
            429 => AppError::too_many_requests("rate limited").with_store("debridlink"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("debridlink")
                .with_upstream_status(status),
        }
    }

    async fn api_get(&self, path: &str) -> Result<serde_json::Value, AppError> {
        let url = self.api_url(path);
        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("debridlink", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }
        resp.json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("debridlink"))
    }

    async fn api_post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        let url = self.api_url(path);
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .json(body)
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("debridlink", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body_text));
        }
        resp.json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("debridlink"))
    }
}

#[derive(Deserialize, Default)]
struct DlResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    error: String,
}

#[async_trait]
impl Store for DebridLinkStore {
    fn get_name(&self) -> StoreName {
        StoreName::DebridLink
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let data = self.api_get("/account/infos").await?;
        let value = data.get("value").unwrap_or(&data);
        let email = value
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let account_type = value
            .get("accountType")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        Ok(User {
            id: value
                .get("id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
            email,
            subscription_status: if account_type >= 2 {
                SubscriptionStatus::Premium
            } else if account_type == 1 {
                SubscriptionStatus::Trial
            } else {
                SubscriptionStatus::Expired
            },
            has_usenet: false,
        })
    }

    async fn check_magnet(&self, p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError> {
        let hashes: Vec<String> = p
            .magnets
            .iter()
            .map(|m| super::realdebrid::extract_hash_from_magnet(m).to_lowercase())
            .collect();

        let url_path = format!("/seedbox/cached?url={}", hashes.join(","));
        let data = self.api_get(&url_path).await?;
        let value = data.get("value").and_then(|v| v.as_object());

        let items = p
            .magnets
            .iter()
            .map(|magnet| {
                let hash = super::realdebrid::extract_hash_from_magnet(magnet).to_lowercase();
                let is_cached = value
                    .and_then(|obj| obj.get(&hash))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                CheckMagnetItem {
                    hash,
                    magnet: magnet.clone(),
                    status: if is_cached {
                        MagnetStatus::Cached
                    } else {
                        MagnetStatus::Unknown
                    },
                    files: vec![],
                }
            })
            .collect();

        Ok(CheckMagnetData { items })
    }

    async fn add_magnet(&self, p: &AddMagnetParams) -> Result<AddMagnetData, AppError> {
        let data = self
            .api_post_json("/seedbox/add", &serde_json::json!({ "url": p.magnet }))
            .await?;
        let value = data.get("value").unwrap_or(&data);
        let id = value
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let hash = super::realdebrid::extract_hash_from_magnet(&p.magnet).to_lowercase();

        Ok(AddMagnetData {
            id,
            hash,
            magnet: p.magnet.clone(),
            name: value
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            size: value
                .get("totalSize")
                .and_then(|v| v.as_i64())
                .unwrap_or(-1),
            status: MagnetStatus::Queued,
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn get_magnet(&self, p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
        let data = self.api_get(&format!("/seedbox/list?ids={}", p.id)).await?;
        let value = data
            .get("value")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or_default();
        let native_status = value
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let files = value
            .get("files")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .enumerate()
                    .map(|(i, f)| MagnetFile {
                        index: i as i32,
                        link: f
                            .get("downloadUrl")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        path: f
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        name: f
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        size: f.get("size").and_then(|v| v.as_i64()).unwrap_or(-1),
                        video_hash: None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(GetMagnetData {
            id: p.id.clone(),
            name: value
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            hash: value
                .get("hashString")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            size: value
                .get("totalSize")
                .and_then(|v| v.as_i64())
                .unwrap_or(-1),
            status: MagnetStatus::from_native(native_status),
            files,
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        let data = self.api_get("/seedbox/list").await?;
        let value = data.get("value").and_then(|v| v.as_array());

        let all_items: Vec<crate::store::ListMagnetItem> = value
            .map(|arr| {
                arr.iter()
                    .map(|t| {
                        let native_status = t
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        crate::store::ListMagnetItem {
                            id: t
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            name: t
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            hash: t
                                .get("hashString")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            size: t.get("totalSize").and_then(|v| v.as_i64()).unwrap_or(-1),
                            status: MagnetStatus::from_native(native_status),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

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
        let url = self.api_url(&format!("/seedbox/{}/remove", p.id));
        let resp = self
            .client
            .upstream(Method::DELETE, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("debridlink", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() && status != 204 {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        let data = self
            .api_post_json("/downloader/add", &serde_json::json!({ "url": p.link }))
            .await?;
        let value = data.get("value").unwrap_or(&data);
        let link = value
            .get("downloadUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(GenerateLinkData { link })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EgressPolicy;
    use crate::errors::ErrorCategory;
    use crate::store::Ctx;
    use std::collections::HashMap;
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

    fn store_for(mock: &MockServer) -> DebridLinkStore {
        DebridLinkStore::with_base_url(outbound(), "tok".into(), format!("{}/api/v2", mock.uri()))
    }

    #[tokio::test]
    async fn get_name_is_debridlink() {
        assert_eq!(
            DebridLinkStore::new(outbound(), "tok".into()).get_name(),
            StoreName::DebridLink
        );
    }

    #[tokio::test]
    async fn check_magnet_maps_cached_map() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/seedbox/cached"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "value": { "abc123": true }
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
    }

    #[tokio::test]
    async fn list_magnets_normalizes_error_state_to_failed() {
        // Req 16.14.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/seedbox/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "value": [ {"id": "a", "name": "x", "hashString": "h", "totalSize": 10, "status": "error"} ]
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let data = store_for(&mock)
            .list_magnets(&ListMagnetsParams::new(ctx(), None, None))
            .await
            .unwrap();
        assert_eq!(data.items.len(), 1);
        assert_eq!(data.items[0].status, MagnetStatus::Failed);
    }

    #[tokio::test]
    async fn generate_link_returns_download_url() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v2/downloader/add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "value": { "downloadUrl": "https://cdn.dl.example/file.mkv" }
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let data = store_for(&mock)
            .generate_link(&GenerateLinkParams {
                ctx: ctx(),
                link: "https://host.example/file".into(),
                client_ip: None,
            })
            .await
            .unwrap();
        assert_eq!(data.link, "https://cdn.dl.example/file.mkv");
    }

    #[tokio::test]
    async fn auth_failure_maps_to_unauthorized_identifying_store() {
        // Req 16.8.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/account/infos"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad token"))
            .expect(1)
            .mount(&mock)
            .await;

        let err = store_for(&mock)
            .get_user(&GetUserParams { ctx: ctx() })
            .await
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("debridlink"));
    }
}
