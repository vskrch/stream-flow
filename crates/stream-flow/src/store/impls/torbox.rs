//! TorBox store implementation — Req 16.1, 17.14, 18.3.
//!
//! Quirks:
//! - Listings include **one extra trailing item** → normalized away (Req 17.14).
//! - TorBox forwards Egress_IP on link-gen (Req 18.3).

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

const BASE_URL: &str = "https://api.torbox.app/v1/api";

/// TorBox [`Store`] implementation.
pub struct TorBoxStore {
    client: Arc<OutboundClient>,
    token: String,
}

impl TorBoxStore {
    pub fn new(client: Arc<OutboundClient>, token: String) -> Self {
        Self { client, token }
    }

    fn api_url(&self, path: &str) -> Url {
        Url::parse(&format!("{BASE_URL}{path}")).expect("valid TorBox API URL")
    }

    pub fn map_error(status: u16, body: &str) -> AppError {
        if let Ok(resp) = serde_json::from_str::<TbApiResponse>(body) {
            if !resp.detail.is_empty() {
                let msg = resp.detail.to_ascii_lowercase();
                if msg.contains("auth") || msg.contains("api key") || msg.contains("token") {
                    return AppError::unauthorized_for("torbox", resp.detail);
                }
                if msg.contains("limit") || msg.contains("active") || msg.contains("plan") {
                    return AppError::store_limit_exceeded(resp.detail).with_store("torbox");
                }
                return AppError::unknown(resp.detail)
                    .with_store("torbox")
                    .with_upstream_status(status);
            }
        }

        match status {
            401 | 403 => AppError::unauthorized_for("torbox", "authentication failed"),
            503 | 502 | 504 => {
                AppError::upstream_unavailable_for("torbox", "service unavailable")
            }
            429 => AppError::too_many_requests("rate limited").with_store("torbox"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("torbox")
                .with_upstream_status(status),
        }
    }

    async fn get_json_with_auth<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
    ) -> Result<T, AppError> {
        let url = self.api_url(path);
        let resp = self
            .client
            .upstream(method, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("torbox", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }
        resp.json::<T>().await.map_err(|e| {
            AppError::unknown(format!("failed to parse TorBox response: {e}"))
                .with_store("torbox")
        })
    }
}

#[derive(Deserialize, Default)]
struct TbApiResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct TbTorrent {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: i64,
    #[serde(default)]
    download_state: String,
    #[serde(default)]
    files: Vec<TbFile>,
    #[serde(default)]
    created_at: String,
}

#[derive(Deserialize)]
struct TbFile {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: i64,
    #[serde(default, rename = "short_name")]
    short_name: String,
}

#[async_trait]
impl Store for TorBoxStore {
    fn get_name(&self) -> StoreName {
        StoreName::TorBox
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let resp: TbApiResponse = self.get_json_with_auth(Method::GET, "/user/me").await?;
        let data = resp.data.unwrap_or_default();

        let email = data.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let id = data.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let plan = data.get("plan").and_then(|v| v.as_u64()).unwrap_or(0);

        let subscription_status = match plan {
            0 => SubscriptionStatus::Expired,
            _ => SubscriptionStatus::Premium,
        };

        Ok(User {
            id: id.to_string(),
            email,
            subscription_status,
            has_usenet: data.get("is_usenet").and_then(|v| v.as_bool()).unwrap_or(false),
        })
    }

    async fn check_magnet(&self, p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError> {
        let hashes: Vec<String> = p
            .magnets
            .iter()
            .map(|m| super::realdebrid::extract_hash_from_magnet(m).to_lowercase())
            .collect();

        let hash_param = hashes.join(",");
        let path = format!("/torrents/checkcached?hash={}&format=list", hash_param);
        let resp: TbApiResponse = self.get_json_with_auth(Method::GET, &path).await?;
        let data = resp.data.unwrap_or_default();
        let cached_hashes: Vec<String> = data
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("hash").and_then(|h| h.as_str()).map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        let cached_set: std::collections::HashSet<String> = cached_hashes.into_iter().collect();

        let items = p
            .magnets
            .iter()
            .map(|magnet| {
                let hash = super::realdebrid::extract_hash_from_magnet(magnet).to_lowercase();
                let is_cached = cached_set.contains(&hash);
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
        let url = self.api_url("/torrents/createtorrent");
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&serde_json::json!({ "magnet": p.magnet }))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("torbox", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let api_resp: TbApiResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("torbox")
        })?;

        let data = api_resp.data.unwrap_or_default();
        let id = data.get("torrent_id").and_then(|v| v.as_u64()).unwrap_or(0);
        let hash = data
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(AddMagnetData {
            id: id.to_string(),
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
        let path = format!("/torrents/mylist?id={}", p.id);
        let resp: TbApiResponse = self.get_json_with_auth(Method::GET, &path).await?;
        let data = resp.data.unwrap_or_default();

        let torrent: TbTorrent = serde_json::from_value(data).unwrap_or(TbTorrent {
            id: 0,
            hash: String::new(),
            name: String::new(),
            size: -1,
            download_state: "unknown".into(),
            files: vec![],
            created_at: String::new(),
        });

        let files = torrent
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| MagnetFile {
                index: i as i32,
                link: None,
                path: f.name.clone(),
                name: f.short_name.clone(),
                size: f.size,
                video_hash: None,
            })
            .collect();

        Ok(GetMagnetData {
            id: torrent.id.to_string(),
            name: torrent.name,
            hash: torrent.hash,
            size: torrent.size,
            status: MagnetStatus::from_native(&torrent.download_state),
            files,
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        let path = format!(
            "/torrents/mylist?limit={}&offset={}",
            p.limit, p.offset
        );
        let resp: TbApiResponse = self.get_json_with_auth(Method::GET, &path).await?;
        let data = resp.data.unwrap_or_default();

        let torrents: Vec<TbTorrent> =
            serde_json::from_value(data).unwrap_or_default();

        // Req 17.14: TorBox listings include one extra trailing item → drop it
        let mut items: Vec<crate::store::ListMagnetItem> = torrents
            .into_iter()
            .map(|t| crate::store::ListMagnetItem {
                id: t.id.to_string(),
                name: t.name,
                hash: t.hash,
                size: t.size,
                status: MagnetStatus::from_native(&t.download_state),
            })
            .collect();

        // Drop the trailing quirk item (Req 17.14)
        if !items.is_empty() {
            items.pop();
        }

        let total = items.len() as i64;
        Ok(ListMagnetsData {
            items,
            total_items: total,
        })
    }

    async fn remove_magnet(&self, p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError> {
        let url = self.api_url("/torrents/controltorrent");
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&serde_json::json!({
                "torrent_id": p.id,
                "operation": "delete"
            }))
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("torbox", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        let url = self.api_url("/torrents/requestdl");

        let mut body = serde_json::json!({
            "link": p.link,
            "type": "torrent"
        });

        // TorBox forwards Egress_IP on link-gen (Req 18.3)
        if let Some(ip) = p.client_ip {
            body["ip"] = serde_json::Value::String(ip.to_string());
        }

        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("torbox", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body_text));
        }

        let api_resp: TbApiResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("torbox")
        })?;

        let data = api_resp.data.unwrap_or_default();
        let link = data.as_str().unwrap_or("").to_string();

        Ok(GenerateLinkData { link })
    }
}
