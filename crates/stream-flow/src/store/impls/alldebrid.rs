//! AllDebrid store implementation — Req 16.1, 16.10, 18.4.
//!
//! AllDebrid uses string error codes. Key mappings:
//! - `AUTH_BAD_APIKEY` → Unauthorized
//! - `MAGNET_TOO_MANY_ACTIVE` → StoreLimitExceeded
//! - `LINK_HOST_UNAVAILABLE` → HosterUnavailable
//! - No infringing concept → never InfringingContent.
//!
//! AllDebrid omits IP on link-gen and must not fail for lack of IP binding (Req 18.4).

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

const BASE_URL: &str = "https://api.alldebrid.com/v4";

/// AllDebrid [`Store`] implementation.
pub struct AllDebridStore {
    client: Arc<OutboundClient>,
    token: String,
}

impl AllDebridStore {
    pub fn new(client: Arc<OutboundClient>, token: String) -> Self {
        Self { client, token }
    }

    fn api_url(&self, path: &str) -> Url {
        Url::parse(&format!("{BASE_URL}{path}?agent=stream-flow&apikey={}", self.token))
            .expect("valid AllDebrid API URL")
    }

    /// Map a native AllDebrid error response into the canonical AppError taxonomy.
    pub fn map_error(status: u16, body: &str) -> AppError {
        if let Ok(resp) = serde_json::from_str::<AdApiResponse>(body) {
            if let Some(err) = resp.error {
                let code = err.code.to_ascii_uppercase();
                return match code.as_str() {
                    "AUTH_BAD_APIKEY" | "AUTH_MISSING_APIKEY" | "AUTH_BLOCKED" => {
                        AppError::unauthorized_for("alldebrid", err.message)
                    }
                    "MAGNET_TOO_MANY_ACTIVE" | "MAGNET_TOO_MANY" => {
                        AppError::store_limit_exceeded(err.message).with_store("alldebrid")
                    }
                    "LINK_HOST_UNAVAILABLE" | "LINK_HOST_NOT_SUPPORTED" => {
                        AppError::hoster_unavailable(err.message).with_store("alldebrid")
                    }
                    _ => AppError::unknown(err.message)
                        .with_store("alldebrid")
                        .with_upstream_status(status),
                };
            }
        }

        match status {
            401 => AppError::unauthorized_for("alldebrid", "authentication failed"),
            503 | 502 | 504 => {
                AppError::upstream_unavailable_for("alldebrid", "service unavailable")
            }
            429 => AppError::too_many_requests("rate limited").with_store("alldebrid"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("alldebrid")
                .with_upstream_status(status),
        }
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, AppError> {
        let url = self.api_url(path);
        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("alldebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }
        resp.json::<T>().await.map_err(|e| {
            AppError::unknown(format!("failed to parse AllDebrid response: {e}"))
                .with_store("alldebrid")
        })
    }
}

#[derive(Deserialize)]
struct AdApiResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    error: Option<AdError>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct AdError {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct AdUser {
    #[serde(default)]
    username: String,
    #[serde(default)]
    email: String,
    #[serde(default, rename = "isPremium")]
    is_premium: bool,
    #[serde(default, rename = "isTrial")]
    is_trial: bool,
}

#[derive(Deserialize)]
struct AdMagnet {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    size: i64,
    #[serde(default)]
    status: String,
    #[serde(default, rename = "statusCode")]
    status_code: u32,
    #[serde(default)]
    links: Vec<AdLink>,
}

#[derive(Deserialize)]
struct AdLink {
    #[serde(default)]
    link: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    size: i64,
}

#[derive(Deserialize)]
struct AdUnlockResponse {
    #[serde(default)]
    link: String,
}

#[async_trait]
impl Store for AllDebridStore {
    fn get_name(&self) -> StoreName {
        StoreName::AllDebrid
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let resp: AdApiResponse = self.get_json("/user").await?;
        let data = resp.data.unwrap_or_default();
        let user: AdUser = serde_json::from_value(data.get("user").cloned().unwrap_or_default())
            .unwrap_or(AdUser {
                username: String::new(),
                email: String::new(),
                is_premium: false,
                is_trial: false,
            });

        let subscription_status = if user.is_premium {
            SubscriptionStatus::Premium
        } else if user.is_trial {
            SubscriptionStatus::Trial
        } else {
            SubscriptionStatus::Expired
        };

        Ok(User {
            id: user.username.clone(),
            email: user.email,
            subscription_status,
            has_usenet: false,
        })
    }

    async fn check_magnet(&self, p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError> {
        let hashes: Vec<String> = p
            .magnets
            .iter()
            .map(|m| super::realdebrid::extract_hash_from_magnet(m).to_lowercase())
            .collect();

        let magnets_param = hashes.join(",");
        let url_str = format!(
            "{BASE_URL}/magnet/instant?agent=stream-flow&apikey={}&magnets[]={}",
            self.token, magnets_param
        );
        let url = Url::parse(&url_str).map_err(|e| AppError::unknown(e.to_string()))?;

        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("alldebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let api_resp: AdApiResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("alldebrid")
        })?;

        if let Some(err) = api_resp.error {
            return Err(Self::map_error(status, &serde_json::to_string(&serde_json::json!({"error": {"code": err.code, "message": err.message}})).unwrap_or_default()));
        }

        let data = api_resp.data.unwrap_or_default();
        let magnets_data = data.get("magnets").and_then(|v| v.as_array());

        let mut items = Vec::with_capacity(p.magnets.len());
        for (i, magnet) in p.magnets.iter().enumerate() {
            let hash = super::realdebrid::extract_hash_from_magnet(magnet).to_lowercase();
            let is_cached = magnets_data
                .and_then(|arr| arr.get(i))
                .and_then(|v| v.get("instant"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let files = if is_cached {
                magnets_data
                    .and_then(|arr| arr.get(i))
                    .and_then(|v| v.get("files"))
                    .and_then(|v| v.as_array())
                    .map(|files| {
                        files
                            .iter()
                            .enumerate()
                            .filter_map(|(idx, f)| {
                                let name = f.get("n")?.as_str()?.to_string();
                                let size = f.get("s").and_then(|v| v.as_i64()).unwrap_or(-1);
                                Some(MagnetFile {
                                    index: idx as i32,
                                    link: None,
                                    path: name.clone(),
                                    name,
                                    size,
                                    video_hash: None,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                vec![]
            };

            items.push(CheckMagnetItem {
                hash,
                magnet: magnet.clone(),
                status: if is_cached {
                    MagnetStatus::Cached
                } else {
                    MagnetStatus::Unknown
                },
                files,
            });
        }

        Ok(CheckMagnetData { items })
    }

    async fn add_magnet(&self, p: &AddMagnetParams) -> Result<AddMagnetData, AppError> {
        let url_str = format!(
            "{BASE_URL}/magnet/upload?agent=stream-flow&apikey={}&magnets[]={}",
            self.token,
            urlencoding::encode(&p.magnet)
        );
        let url = Url::parse(&url_str).map_err(|e| AppError::unknown(e.to_string()))?;

        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("alldebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let api_resp: AdApiResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("alldebrid")
        })?;

        let data = api_resp.data.unwrap_or_default();
        let magnets = data.get("magnets").and_then(|v| v.as_array());
        let first = magnets.and_then(|a| a.first()).cloned().unwrap_or_default();

        let id = first.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let hash = first
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = first
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let size = first.get("size").and_then(|v| v.as_i64()).unwrap_or(-1);

        Ok(AddMagnetData {
            id: id.to_string(),
            hash,
            magnet: p.magnet.clone(),
            name,
            size,
            status: MagnetStatus::Queued,
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn get_magnet(&self, p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
        let path = format!("/magnet/status?agent=stream-flow&apikey={}&id={}", self.token, p.id);
        let url = Url::parse(&format!("{BASE_URL}{path}"))
            .map_err(|e| AppError::unknown(e.to_string()))?;

        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("alldebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let api_resp: AdApiResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("alldebrid")
        })?;

        let data = api_resp.data.unwrap_or_default();
        let magnets = data.get("magnets").cloned().unwrap_or_default();
        let magnet: AdMagnet = serde_json::from_value(magnets).unwrap_or(AdMagnet {
            id: 0,
            hash: String::new(),
            filename: String::new(),
            size: -1,
            status: "unknown".into(),
            status_code: 0,
            links: vec![],
        });

        let files = magnet
            .links
            .iter()
            .enumerate()
            .map(|(i, l)| MagnetFile {
                index: i as i32,
                link: Some(l.link.clone()),
                path: l.filename.clone(),
                name: l.filename.clone(),
                size: l.size,
                video_hash: None,
            })
            .collect();

        Ok(GetMagnetData {
            id: magnet.id.to_string(),
            name: magnet.filename,
            hash: magnet.hash,
            size: magnet.size,
            status: MagnetStatus::from_native(&magnet.status),
            files,
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        let path = format!(
            "/magnet/status?agent=stream-flow&apikey={}",
            self.token
        );
        let url = Url::parse(&format!("{BASE_URL}{path}"))
            .map_err(|e| AppError::unknown(e.to_string()))?;

        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("alldebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let api_resp: AdApiResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("alldebrid")
        })?;

        let data = api_resp.data.unwrap_or_default();
        let magnets_val = data.get("magnets").and_then(|v| v.as_array());

        let all_items: Vec<crate::store::ListMagnetItem> = magnets_val
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let m: AdMagnet = serde_json::from_value(v.clone()).ok()?;
                        Some(crate::store::ListMagnetItem {
                            id: m.id.to_string(),
                            name: m.filename,
                            hash: m.hash,
                            size: m.size,
                            status: MagnetStatus::from_native(&m.status),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let total = all_items.len() as i64;
        let offset = p.offset as usize;
        let limit = p.limit as usize;
        let items = all_items
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        Ok(ListMagnetsData {
            items,
            total_items: total,
        })
    }

    async fn remove_magnet(&self, p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError> {
        let path = format!(
            "/magnet/delete?agent=stream-flow&apikey={}&id={}",
            self.token, p.id
        );
        let url = Url::parse(&format!("{BASE_URL}{path}"))
            .map_err(|e| AppError::unknown(e.to_string()))?;

        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("alldebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        // AllDebrid omits IP and must not fail for lack of IP binding (Req 18.4)
        let url_str = format!(
            "{BASE_URL}/link/unlock?agent=stream-flow&apikey={}&link={}",
            self.token,
            urlencoding::encode(&p.link)
        );
        let url = Url::parse(&url_str).map_err(|e| AppError::unknown(e.to_string()))?;

        let resp = self
            .client
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("alldebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let api_resp: AdApiResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("alldebrid")
        })?;

        let data = api_resp.data.unwrap_or_default();
        let link = data
            .get("link")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(GenerateLinkData { link })
    }
}
