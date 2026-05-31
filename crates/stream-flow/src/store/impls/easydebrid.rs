//! EasyDebrid store implementation — Req 16.1.

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

const BASE_URL: &str = "https://easydebrid.com/api/v1";

/// EasyDebrid [`Store`] implementation.
pub struct EasyDebridStore {
    client: Arc<OutboundClient>,
    token: String,
}

impl EasyDebridStore {
    pub fn new(client: Arc<OutboundClient>, token: String) -> Self {
        Self { client, token }
    }

    fn api_url(&self, path: &str) -> Url {
        Url::parse(&format!("{BASE_URL}{path}")).expect("valid EasyDebrid API URL")
    }

    pub fn map_error(status: u16, body: &str) -> AppError {
        if let Ok(resp) = serde_json::from_str::<EdResponse>(body) {
            if !resp.error.is_empty() {
                let msg = resp.error.to_ascii_lowercase();
                if msg.contains("auth") || msg.contains("token") || msg.contains("key") {
                    return AppError::unauthorized_for("easydebrid", resp.error);
                }
                if msg.contains("limit") {
                    return AppError::store_limit_exceeded(resp.error).with_store("easydebrid");
                }
                return AppError::unknown(resp.error)
                    .with_store("easydebrid")
                    .with_upstream_status(status);
            }
        }

        match status {
            401 => AppError::unauthorized_for("easydebrid", "authentication failed"),
            503 | 502 | 504 => {
                AppError::upstream_unavailable_for("easydebrid", "service unavailable")
            }
            429 => AppError::too_many_requests("rate limited").with_store("easydebrid"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("easydebrid")
                .with_upstream_status(status),
        }
    }

    async fn api_post(
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
            .map_err(|e| AppError::upstream_unavailable_for("easydebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body_text));
        }
        resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("easydebrid")
        })
    }
}

#[derive(Deserialize, Default)]
struct EdResponse {
    #[serde(default)]
    error: String,
}

#[async_trait]
impl Store for EasyDebridStore {
    fn get_name(&self) -> StoreName {
        StoreName::EasyDebrid
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let data = self
            .api_post("/user/details", &serde_json::json!({}))
            .await?;
        let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let email = data.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let is_premium = data.get("isPremium").and_then(|v| v.as_bool()).unwrap_or(false);

        Ok(User {
            id,
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
        let hashes: Vec<String> = p
            .magnets
            .iter()
            .map(|m| super::realdebrid::extract_hash_from_magnet(m).to_lowercase())
            .collect();

        let data = self
            .api_post(
                "/link/lookup",
                &serde_json::json!({ "urls": hashes }),
            )
            .await?;

        let cached = data.get("cached").and_then(|v| v.as_array());

        let items = p
            .magnets
            .iter()
            .enumerate()
            .map(|(i, magnet)| {
                let hash = super::realdebrid::extract_hash_from_magnet(magnet).to_lowercase();
                let is_cached = cached
                    .and_then(|arr| arr.get(i))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                CheckMagnetItem {
                    hash,
                    magnet: magnet.clone(),
                    status: if is_cached { MagnetStatus::Cached } else { MagnetStatus::Unknown },
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
        Ok(GetMagnetData {
            id: p.id.clone(),
            name: String::new(),
            hash: p.id.clone(),
            size: -1,
            status: MagnetStatus::Unknown,
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, _p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        Ok(ListMagnetsData {
            items: vec![],
            total_items: 0,
        })
    }

    async fn remove_magnet(&self, p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError> {
        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        let data = self
            .api_post(
                "/link/generate",
                &serde_json::json!({ "url": p.link }),
            )
            .await?;
        let link = data.get("download").and_then(|v| v.as_str()).unwrap_or("").to_string();

        Ok(GenerateLinkData { link })
    }
}
