//! Debrider store implementation — Req 16.1.

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
    ListMagnetsData, ListMagnetsParams, MagnetStatus, RemoveMagnetData,
    RemoveMagnetParams, Store, StoreName, SubscriptionStatus, User,
};

const BASE_URL: &str = "https://www.debrider.com/api";

/// Debrider [`Store`] implementation.
pub struct DebriderStore {
    client: Arc<OutboundClient>,
    token: String,
    base_url: String,
}

impl DebriderStore {
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
        Url::parse(&format!("{}{path}?token={}", self.base_url, self.token))
            .expect("valid Debrider API URL")
    }

    pub fn map_error(status: u16, body: &str) -> AppError {
        if let Ok(resp) = serde_json::from_str::<DrResponse>(body) {
            if !resp.error.is_empty() {
                let msg = resp.error.to_ascii_lowercase();
                if msg.contains("auth") || msg.contains("token") || msg.contains("key") {
                    return AppError::unauthorized_for("debrider", resp.error);
                }
                if msg.contains("limit") {
                    return AppError::store_limit_exceeded(resp.error).with_store("debrider");
                }
                return AppError::unknown(resp.error)
                    .with_store("debrider")
                    .with_upstream_status(status);
            }
        }

        match status {
            401 => AppError::unauthorized_for("debrider", "authentication failed"),
            503 | 502 | 504 => {
                AppError::upstream_unavailable_for("debrider", "service unavailable")
            }
            429 => AppError::too_many_requests("rate limited").with_store("debrider"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("debrider")
                .with_upstream_status(status),
        }
    }

    async fn api_get(&self, path: &str) -> Result<serde_json::Value, AppError> {
        let url = self.api_url(path);
        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("debrider", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }
        resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("debrider")
        })
    }
}

#[derive(Deserialize, Default)]
struct DrResponse {
    #[serde(default)]
    error: String,
}

#[async_trait]
impl Store for DebriderStore {
    fn get_name(&self) -> StoreName {
        StoreName::Debrider
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let data = self.api_get("/user").await?;
        let email = data.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let is_premium = data.get("premium").and_then(|v| v.as_bool()).unwrap_or(false);

        Ok(User {
            id: data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
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
        let hash = super::realdebrid::extract_hash_from_magnet(&p.magnet).to_lowercase();
        Ok(AddMagnetData {
            id: hash.clone(),
            hash,
            magnet: p.magnet.clone(),
            name: String::new(),
            size: -1,
            status: MagnetStatus::Queued,
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn get_magnet(&self, p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
        let data = self.api_get(&format!("/torrent/{}", p.id)).await?;
        let native_status = data.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");

        Ok(GetMagnetData {
            id: p.id.clone(),
            name: data.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            hash: data.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            size: data.get("size").and_then(|v| v.as_i64()).unwrap_or(-1),
            status: MagnetStatus::from_native(native_status),
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        let data = self.api_get("/torrents").await?;
        let arr = data.as_array();

        let all_items: Vec<crate::store::ListMagnetItem> = arr
            .map(|a| {
                a.iter()
                    .map(|t| {
                        let native_status = t.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                        crate::store::ListMagnetItem {
                            id: t.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            name: t.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            hash: t.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            size: t.get("size").and_then(|v| v.as_i64()).unwrap_or(-1),
                            status: MagnetStatus::from_native(native_status),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let total = all_items.len() as i64;
        let items = all_items.into_iter().skip(p.offset as usize).take(p.limit as usize).collect();

        Ok(ListMagnetsData { items, total_items: total })
    }

    async fn remove_magnet(&self, p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError> {
        let url = self.api_url(&format!("/torrent/{}/delete", p.id));
        let resp = self
            .client
            .upstream(Method::DELETE, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("debrider", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() && status != 204 {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        let data = self.api_get(&format!("/unrestrict?link={}", urlencoding::encode(&p.link))).await?;
        let link = data.get("download").and_then(|v| v.as_str()).unwrap_or("").to_string();

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

    fn store_for(mock: &MockServer) -> DebriderStore {
        DebriderStore::with_base_url(outbound(), "tok".into(), format!("{}/api", mock.uri()))
    }

    #[tokio::test]
    async fn get_name_is_debrider() {
        assert_eq!(
            DebriderStore::new(outbound(), "tok".into()).get_name(),
            StoreName::Debrider
        );
    }

    #[tokio::test]
    async fn get_magnet_dead_state_normalizes_to_failed() {
        // Req 16.14.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/api/torrent/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "t1", "name": "movie", "hash": "abc", "size": 100, "status": "dead"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let magnet = store_for(&mock)
            .get_magnet(&GetMagnetParams { ctx: ctx(), id: "t1".into() })
            .await
            .unwrap();
        assert_eq!(magnet.status, MagnetStatus::Failed);
    }

    #[tokio::test]
    async fn generate_link_returns_download() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/unrestrict"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "download": "https://cdn.dr.example/file.mkv"
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
        assert_eq!(data.link, "https://cdn.dr.example/file.mkv");
    }

    #[tokio::test]
    async fn auth_failure_maps_to_unauthorized_identifying_store() {
        // Req 16.8.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/user"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid token"))
            .expect(1)
            .mount(&mock)
            .await;

        let err = store_for(&mock)
            .get_user(&GetUserParams { ctx: ctx() })
            .await
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("debrider"));
    }
}
