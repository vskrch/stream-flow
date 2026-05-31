//! PikPak store implementation — Req 16.1.

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

const BASE_URL: &str = "https://api-drive.mypikpak.com";

/// PikPak [`Store`] implementation.
pub struct PikPakStore {
    client: Arc<OutboundClient>,
    token: String,
    base_url: String,
}

impl PikPakStore {
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
        Url::parse(&format!("{}{path}", self.base_url)).expect("valid PikPak API URL")
    }

    pub fn map_error(status: u16, body: &str) -> AppError {
        if let Ok(resp) = serde_json::from_str::<PpErrorResponse>(body) {
            if !resp.error.is_empty() {
                let msg = resp.error.to_ascii_lowercase();
                if msg.contains("auth") || msg.contains("token") || msg.contains("unauthenticated")
                {
                    return AppError::unauthorized_for("pikpak", resp.error_description);
                }
                if msg.contains("limit") || msg.contains("quota") {
                    return AppError::store_limit_exceeded(resp.error_description)
                        .with_store("pikpak");
                }
                return AppError::unknown(resp.error_description)
                    .with_store("pikpak")
                    .with_upstream_status(status);
            }
        }

        match status {
            401 => AppError::unauthorized_for("pikpak", "authentication failed"),
            503 | 502 | 504 => AppError::upstream_unavailable_for("pikpak", "service unavailable"),
            429 => AppError::too_many_requests("rate limited").with_store("pikpak"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("pikpak")
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
            .map_err(|e| AppError::upstream_unavailable_for("pikpak", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }
        resp.json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("pikpak"))
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
            .map_err(|e| AppError::upstream_unavailable_for("pikpak", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body_text));
        }
        resp.json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("pikpak"))
    }
}

#[derive(Deserialize, Default)]
struct PpErrorResponse {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
}

#[async_trait]
impl Store for PikPakStore {
    fn get_name(&self) -> StoreName {
        StoreName::PikPak
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let data = self.api_get("/drive/v1/about").await?;
        let quota = data.get("quota").unwrap_or(&data);
        let kind = quota.get("kind").and_then(|v| v.as_str()).unwrap_or("");

        Ok(User {
            id: data
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            email: String::new(),
            subscription_status: if kind.contains("premium") || kind.contains("vip") {
                SubscriptionStatus::Premium
            } else {
                SubscriptionStatus::Expired
            },
            has_usenet: false,
        })
    }

    async fn check_magnet(&self, p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError> {
        let items = p
            .magnets
            .iter()
            .map(|magnet| {
                let hash = super::realdebrid::extract_hash_from_magnet(magnet).to_lowercase();
                CheckMagnetItem {
                    hash,
                    magnet: magnet.clone(),
                    status: MagnetStatus::Unknown,
                    files: vec![],
                }
            })
            .collect();

        Ok(CheckMagnetData { items })
    }

    async fn add_magnet(&self, p: &AddMagnetParams) -> Result<AddMagnetData, AppError> {
        let data = self
            .api_post_json(
                "/drive/v1/files",
                &serde_json::json!({
                    "kind": "drive#file",
                    "upload_type": "UPLOAD_TYPE_URL",
                    "url": { "url": p.magnet }
                }),
            )
            .await?;

        let task = data.get("task").unwrap_or(&data);
        let id = task
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let hash = super::realdebrid::extract_hash_from_magnet(&p.magnet).to_lowercase();

        Ok(AddMagnetData {
            id,
            hash,
            magnet: p.magnet.clone(),
            name: task
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            size: task
                .get("file_size")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(-1),
            status: MagnetStatus::Queued,
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn get_magnet(&self, p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
        let data = self.api_get(&format!("/drive/v1/tasks/{}", p.id)).await?;
        let native_status = data
            .get("phase")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        Ok(GetMagnetData {
            id: p.id.clone(),
            name: data
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            hash: data
                .get("params")
                .and_then(|v| v.get("info_hash"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            size: data
                .get("file_size")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(-1),
            status: MagnetStatus::from_native(native_status),
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        let data = self
            .api_get(&format!(
                "/drive/v1/tasks?limit={}&page_token={}",
                p.limit, p.offset
            ))
            .await?;

        let tasks = data.get("tasks").and_then(|v| v.as_array());
        let all_items: Vec<crate::store::ListMagnetItem> = tasks
            .map(|arr| {
                arr.iter()
                    .map(|t| {
                        let native_status =
                            t.get("phase").and_then(|v| v.as_str()).unwrap_or("unknown");
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
                                .get("params")
                                .and_then(|v| v.get("info_hash"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            size: t
                                .get("file_size")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(-1),
                            status: MagnetStatus::from_native(native_status),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let total = all_items.len() as i64;
        Ok(ListMagnetsData {
            items: all_items,
            total_items: total,
        })
    }

    async fn remove_magnet(&self, p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError> {
        let url = self.api_url(&format!("/drive/v1/tasks/{}", p.id));
        let resp = self
            .client
            .upstream(Method::DELETE, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("pikpak", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() && status != 204 {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        // PikPak: the link is already a direct download URL
        let data = self
            .api_get(&format!("/drive/v1/files/{}?usage=FETCH", p.link))
            .await?;
        let link = data
            .get("web_content_link")
            .and_then(|v| v.as_str())
            .unwrap_or(&p.link)
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
    use wiremock::matchers::{method, path, path_regex};
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

    fn store_for(mock: &MockServer) -> PikPakStore {
        PikPakStore::with_base_url(outbound(), "tok".into(), mock.uri())
    }

    #[tokio::test]
    async fn get_name_is_pikpak() {
        assert_eq!(
            PikPakStore::new(outbound(), "tok".into()).get_name(),
            StoreName::PikPak
        );
    }

    #[tokio::test]
    async fn get_magnet_error_phase_normalizes_to_failed() {
        // Req 16.14: PikPak reports task phase; an error phase -> Failed.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/drive/v1/tasks/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "movie", "phase": "error", "file_size": "100",
                "params": {"info_hash": "abc"}
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let magnet = store_for(&mock)
            .get_magnet(&GetMagnetParams {
                ctx: ctx(),
                id: "t1".into(),
            })
            .await
            .unwrap();
        assert_eq!(magnet.status, MagnetStatus::Failed);
    }

    #[tokio::test]
    async fn generate_link_resolves_web_content_link() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/drive/v1/files/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "web_content_link": "https://cdn.pikpak.example/file.mkv"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let data = store_for(&mock)
            .generate_link(&GenerateLinkParams {
                ctx: ctx(),
                link: "file_id_1".into(),
                client_ip: None,
            })
            .await
            .unwrap();
        assert_eq!(data.link, "https://cdn.pikpak.example/file.mkv");
    }

    #[tokio::test]
    async fn auth_failure_maps_to_unauthorized_identifying_store() {
        // Req 16.8.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/drive/v1/about"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthenticated"))
            .expect(1)
            .mount(&mock)
            .await;

        let err = store_for(&mock)
            .get_user(&GetUserParams { ctx: ctx() })
            .await
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("pikpak"));
    }
}
