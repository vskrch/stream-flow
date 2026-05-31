//! RealDebrid store implementation — Req 16.1, 16.10–16.14, 18.3.
//!
//! RealDebrid uses numeric error codes. Key mappings:
//! - `8` (bad_token) → Unauthorized
//! - `9` (permission_denied) / `ip_not_allowed` → Forbidden(ip)
//! - `35` (infringing_file) → InfringingContent
//! - `34` (too_many_active_downloads) / traffic/fair-usage → StoreLimitExceeded
//! - HTTP 503 → UpstreamUnavailable
//!
//! RealDebrid forwards Egress_IP on link-gen (Req 18.3).

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

const BASE_URL: &str = "https://api.real-debrid.com/rest/1.0";

/// RealDebrid [`Store`] implementation.
pub struct RealDebridStore {
    client: Arc<OutboundClient>,
    token: String,
}

impl RealDebridStore {
    /// Create a new RealDebrid store with the given outbound client and API token.
    pub fn new(client: Arc<OutboundClient>, token: String) -> Self {
        Self { client, token }
    }

    fn api_url(&self, path: &str) -> Url {
        Url::parse(&format!("{BASE_URL}{path}")).expect("valid RealDebrid API URL")
    }

    fn auth_header(&self) -> (&str, String) {
        ("Authorization", format!("Bearer {}", self.token))
    }

    /// Map a native RealDebrid error response into the canonical AppError taxonomy.
    pub fn map_error(status: u16, body: &str) -> AppError {
        // Try to parse the JSON error body
        if let Ok(err) = serde_json::from_str::<RdErrorResponse>(body) {
            return match err.error_code {
                8 => AppError::unauthorized_for("realdebrid", "bad token"),
                9 => AppError::ip_restricted_for("realdebrid", "permission denied / IP not allowed"),
                35 => AppError::infringing_content("infringing file")
                    .with_store("realdebrid"),
                34 => AppError::store_limit_exceeded("too many active downloads")
                    .with_store("realdebrid"),
                _ => {
                    // Check for traffic/fair-usage keywords in the error message
                    let msg = err.error.to_ascii_lowercase();
                    if msg.contains("traffic") || msg.contains("fair") || msg.contains("usage") {
                        AppError::store_limit_exceeded(err.error)
                            .with_store("realdebrid")
                    } else if msg.contains("ip") && (msg.contains("not allowed") || msg.contains("restricted")) {
                        AppError::ip_restricted_for("realdebrid", err.error)
                    } else {
                        AppError::unknown(err.error)
                            .with_store("realdebrid")
                            .with_upstream_status(status)
                    }
                }
            };
        }

        // Fallback based on HTTP status
        match status {
            401 => AppError::unauthorized_for("realdebrid", "authentication failed"),
            403 => AppError::forbidden("forbidden").with_store("realdebrid"),
            404 => AppError::not_found("not found").with_store("realdebrid"),
            503 | 502 | 504 => {
                AppError::upstream_unavailable_for("realdebrid", "service unavailable")
            }
            429 => AppError::too_many_requests("rate limited").with_store("realdebrid"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("realdebrid")
                .with_upstream_status(status),
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, AppError> {
        let url = self.api_url(path);
        let (header_name, header_value) = self.auth_header();
        let builder = self.client.upstream(method, &url)?;
        Ok(builder.header(header_name, header_value))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, AppError> {
        let resp = self.request(Method::GET, path).await?.send().await.map_err(|e| {
            AppError::upstream_unavailable_for("realdebrid", e.to_string())
        })?;
        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }
        resp.json::<T>().await.map_err(|e| {
            AppError::unknown(format!("failed to parse RealDebrid response: {e}"))
                .with_store("realdebrid")
        })
    }
}

#[derive(Deserialize)]
struct RdErrorResponse {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_code: u32,
}

#[derive(Deserialize)]
struct RdUser {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    email: String,
    #[serde(default, rename = "type")]
    account_type: String,
}

#[derive(Deserialize)]
struct RdTorrentInfo {
    #[serde(default)]
    id: String,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    bytes: i64,
    #[serde(default)]
    status: String,
    #[serde(default)]
    files: Vec<RdFile>,
    #[serde(default)]
    links: Vec<String>,
    #[serde(default)]
    added: String,
}

#[derive(Deserialize)]
struct RdFile {
    #[serde(default)]
    id: u32,
    #[serde(default)]
    path: String,
    #[serde(default)]
    bytes: i64,
    #[serde(default)]
    selected: u8,
}

#[derive(Deserialize)]
struct RdUnrestrictResponse {
    #[serde(default)]
    download: String,
}

#[derive(Deserialize)]
struct RdCheckResult {
    #[serde(flatten)]
    hashes: std::collections::HashMap<String, RdCheckHash>,
}

#[derive(Deserialize)]
struct RdCheckHash {
    #[serde(default, rename = "rd")]
    variants: Vec<std::collections::HashMap<String, RdCheckFile>>,
}

#[derive(Deserialize)]
struct RdCheckFile {
    #[serde(default)]
    filename: String,
    #[serde(default)]
    filesize: i64,
}

#[derive(Deserialize)]
struct RdAddMagnetResponse {
    #[serde(default)]
    id: String,
    #[serde(default)]
    uri: String,
}

#[async_trait]
impl Store for RealDebridStore {
    fn get_name(&self) -> StoreName {
        StoreName::RealDebrid
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let rd_user: RdUser = self.get_json("/user").await?;
        let subscription_status = match rd_user.account_type.as_str() {
            "premium" => SubscriptionStatus::Premium,
            "trial" => SubscriptionStatus::Trial,
            _ => SubscriptionStatus::Expired,
        };
        Ok(User {
            id: rd_user.id.to_string(),
            email: rd_user.email,
            subscription_status,
            has_usenet: false,
        })
    }

    async fn check_magnet(&self, p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError> {
        // RealDebrid instant availability check
        let hashes: Vec<&str> = p.magnets.iter().map(|m| extract_hash_from_magnet(m)).collect();
        let hash_path = format!("/torrents/instantAvailability/{}", hashes.join("/"));
        let resp = self.request(Method::GET, &hash_path).await?.send().await.map_err(|e| {
            AppError::upstream_unavailable_for("realdebrid", e.to_string())
        })?;
        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let body_text = resp.text().await.unwrap_or_default();
        let check_result: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_str(&body_text).unwrap_or_default();

        let mut items = Vec::with_capacity(p.magnets.len());
        for magnet in p.magnets {
            let hash = extract_hash_from_magnet(magnet).to_lowercase();
            let is_cached = check_result
                .get(&hash)
                .and_then(|v| v.get("rd"))
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);

            let files = if is_cached {
                // Extract files from the first variant
                if let Some(variants) = check_result
                    .get(&hash)
                    .and_then(|v| v.get("rd"))
                    .and_then(|v| v.as_array())
                {
                    if let Some(first_variant) = variants.first() {
                        parse_rd_check_files(first_variant)
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            items.push(CheckMagnetItem {
                hash: hash.clone(),
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
        let url = self.api_url("/torrents/addMagnet");
        let (header_name, header_value) = self.auth_header();
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header(header_name, header_value)
            .form(&[("magnet", &p.magnet)])
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("realdebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let add_resp: RdAddMagnetResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("realdebrid")
        })?;

        // Fetch the torrent info to get full details
        let info: RdTorrentInfo = self.get_json(&format!("/torrents/info/{}", add_resp.id)).await?;
        let magnet_status = MagnetStatus::from_native(&info.status);
        let files = info
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| MagnetFile {
                index: i as i32,
                link: info.links.get(i).cloned(),
                path: f.path.clone(),
                name: f.path.rsplit('/').next().unwrap_or(&f.path).to_string(),
                size: f.bytes,
                video_hash: None,
            })
            .collect();

        Ok(AddMagnetData {
            id: info.id,
            hash: info.hash,
            magnet: p.magnet.clone(),
            name: info.filename,
            size: info.bytes,
            status: magnet_status,
            files,
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn get_magnet(&self, p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
        let info: RdTorrentInfo = self.get_json(&format!("/torrents/info/{}", p.id)).await?;
        let magnet_status = MagnetStatus::from_native(&info.status);
        let files = info
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| MagnetFile {
                index: i as i32,
                link: info.links.get(i).cloned(),
                path: f.path.clone(),
                name: f.path.rsplit('/').next().unwrap_or(&f.path).to_string(),
                size: f.bytes,
                video_hash: None,
            })
            .collect();

        Ok(GetMagnetData {
            id: info.id,
            name: info.filename,
            hash: info.hash,
            size: info.bytes,
            status: magnet_status,
            files,
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        let path = format!(
            "/torrents?limit={}&offset={}",
            p.limit, p.offset
        );
        let resp = self.request(Method::GET, &path).await?.send().await.map_err(|e| {
            AppError::upstream_unavailable_for("realdebrid", e.to_string())
        })?;
        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let torrents: Vec<RdTorrentInfo> = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("realdebrid")
        })?;

        let items = torrents
            .into_iter()
            .map(|t| crate::store::ListMagnetItem {
                id: t.id,
                name: t.filename,
                hash: t.hash,
                size: t.bytes,
                status: MagnetStatus::from_native(&t.status),
            })
            .collect::<Vec<_>>();

        let total = items.len() as i64;
        Ok(ListMagnetsData {
            items,
            total_items: total,
        })
    }

    async fn remove_magnet(&self, p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError> {
        let url = self.api_url(&format!("/torrents/delete/{}", p.id));
        let (header_name, header_value) = self.auth_header();
        let resp = self
            .client
            .upstream(Method::DELETE, &url)?
            .header(header_name, header_value)
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("realdebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() && status != 204 {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        let url = self.api_url("/unrestrict/link");
        let (header_name, header_value) = self.auth_header();

        let mut form = vec![("link", p.link.clone())];
        // RealDebrid forwards Egress_IP on link-gen (Req 18.3)
        if let Some(ip) = p.client_ip {
            form.push(("ip", ip.to_string()));
        }

        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header(header_name, header_value)
            .form(&form)
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("realdebrid", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }

        let unrestrict: RdUnrestrictResponse = resp.json().await.map_err(|e| {
            AppError::unknown(format!("parse error: {e}")).with_store("realdebrid")
        })?;

        Ok(GenerateLinkData {
            link: unrestrict.download,
        })
    }
}

/// Extract the info-hash from a magnet URI or return the string as-is if it's
/// already a hash.
pub fn extract_hash_from_magnet(magnet: &str) -> &str {
    if let Some(pos) = magnet.find("btih:") {
        let start = pos + 5;
        let end = magnet[start..]
            .find('&')
            .map(|i| start + i)
            .unwrap_or(magnet.len());
        &magnet[start..end]
    } else {
        magnet
    }
}

/// Parse RealDebrid check files from a variant JSON value.
fn parse_rd_check_files(variant: &serde_json::Value) -> Vec<MagnetFile> {
    let obj = match variant.as_object() {
        Some(o) => o,
        None => return vec![],
    };
    obj.iter()
        .filter_map(|(key, val)| {
            let idx: i32 = key.parse().unwrap_or(-1);
            let filename = val.get("filename")?.as_str()?.to_string();
            let filesize = val.get("filesize").and_then(|v| v.as_i64()).unwrap_or(-1);
            Some(MagnetFile {
                index: idx,
                link: None,
                path: filename.clone(),
                name: filename,
                size: filesize,
                video_hash: None,
            })
        })
        .collect()
}
