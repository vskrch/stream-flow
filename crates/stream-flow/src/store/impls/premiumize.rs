//! Premiumize store implementation — Req 16.1.

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

const BASE_URL: &str = "https://www.premiumize.me/api";

/// Premiumize [`Store`] implementation.
pub struct PremiumizeStore {
    client: Arc<OutboundClient>,
    token: String,
    base_url: String,
}

impl PremiumizeStore {
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
        Url::parse(&format!("{}{path}", self.base_url)).expect("valid Premiumize API URL")
    }

    pub fn map_error(status: u16, body: &str) -> AppError {
        if let Ok(resp) = serde_json::from_str::<PmResponse>(body) {
            if resp.status != "success" && !resp.message.is_empty() {
                let msg = resp.message.to_ascii_lowercase();
                if msg.contains("auth")
                    || msg.contains("api key")
                    || msg.contains("token")
                    || msg.contains("invalid")
                {
                    return AppError::unauthorized_for("premiumize", resp.message);
                }
                if msg.contains("limit") || msg.contains("fair") {
                    return AppError::store_limit_exceeded(resp.message).with_store("premiumize");
                }
                return AppError::unknown(resp.message)
                    .with_store("premiumize")
                    .with_upstream_status(status);
            }
        }

        match status {
            401 => AppError::unauthorized_for("premiumize", "authentication failed"),
            502..=504 => AppError::upstream_unavailable_for("premiumize", "service unavailable"),
            429 => AppError::too_many_requests("rate limited").with_store("premiumize"),
            _ => AppError::unknown(format!("HTTP {status}"))
                .with_store("premiumize")
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
            .map_err(|e| AppError::upstream_unavailable_for("premiumize", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }
        resp.json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("premiumize"))
    }

    async fn api_post(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<serde_json::Value, AppError> {
        let url = self.api_url(path);
        let resp = self
            .client
            .upstream(Method::POST, &url)?
            .header("Authorization", format!("Bearer {}", self.token))
            .form(form)
            .send()
            .await
            .map_err(|e| AppError::upstream_unavailable_for("premiumize", e.to_string()))?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_error(status, &body));
        }
        resp.json()
            .await
            .map_err(|e| AppError::unknown(format!("parse error: {e}")).with_store("premiumize"))
    }
}

#[derive(Deserialize, Default)]
struct PmResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
}

#[async_trait]
impl Store for PremiumizeStore {
    fn get_name(&self) -> StoreName {
        StoreName::Premiumize
    }

    async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
        let data = self.api_get("/account/info").await?;
        let customer_id = data
            .get("customer_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let premium_until = data
            .get("premium_until")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        Ok(User {
            id: customer_id.to_string(),
            email: String::new(),
            subscription_status: if premium_until > 0.0 {
                SubscriptionStatus::Premium
            } else {
                SubscriptionStatus::Expired
            },
            has_usenet: true,
        })
    }

    async fn check_magnet(&self, p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError> {
        let hashes: Vec<String> = p
            .magnets
            .iter()
            .map(|m| super::realdebrid::extract_hash_from_magnet(m).to_lowercase())
            .collect();

        let items_param: Vec<(&str, &str)> =
            hashes.iter().map(|h| ("items[]", h.as_str())).collect();

        let data = self.api_post("/cache/check", &items_param).await?;
        let response_arr = data.get("response").and_then(|v| v.as_array());

        let items = p
            .magnets
            .iter()
            .enumerate()
            .map(|(i, magnet)| {
                let hash = super::realdebrid::extract_hash_from_magnet(magnet).to_lowercase();
                let is_cached = response_arr
                    .and_then(|arr| arr.get(i))
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
            .api_post("/transfer/create", &[("src", p.magnet.as_str())])
            .await?;
        let id = data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let hash = super::realdebrid::extract_hash_from_magnet(&p.magnet).to_lowercase();

        Ok(AddMagnetData {
            id,
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
        let data = self.api_get("/transfer/list").await?;
        let transfers = data.get("transfers").and_then(|v| v.as_array());

        let transfer = transfers
            .and_then(|arr| {
                arr.iter()
                    .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(&p.id))
            })
            .cloned()
            .unwrap_or_default();

        let native_status = transfer
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        Ok(GetMagnetData {
            id: p.id.clone(),
            name: transfer
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            hash: transfer
                .get("hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            size: transfer.get("size").and_then(|v| v.as_i64()).unwrap_or(-1),
            status: MagnetStatus::from_native(native_status),
            files: vec![],
            private: false,
            added_at: time::OffsetDateTime::now_utc(),
        })
    }

    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
        let data = self.api_get("/transfer/list").await?;
        let transfers = data.get("transfers").and_then(|v| v.as_array());

        let all_items: Vec<crate::store::ListMagnetItem> = transfers
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
                                .get("hash")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            size: t.get("size").and_then(|v| v.as_i64()).unwrap_or(-1),
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
        self.api_post("/transfer/delete", &[("id", p.id.as_str())])
            .await?;
        Ok(RemoveMagnetData { id: p.id.clone() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        let data = self
            .api_post("/transfer/directdl", &[("src", p.link.as_str())])
            .await?;
        let link = data
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("link"))
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

    fn store_for(mock: &MockServer) -> PremiumizeStore {
        PremiumizeStore::with_base_url(outbound(), "tok".into(), format!("{}/api", mock.uri()))
    }

    #[tokio::test]
    async fn get_name_is_premiumize() {
        assert_eq!(
            PremiumizeStore::new(outbound(), "tok".into()).get_name(),
            StoreName::Premiumize
        );
    }

    #[tokio::test]
    async fn check_magnet_maps_cache_check_response() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cache/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success", "response": [true]
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
            .and(path("/api/transfer/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success",
                "transfers": [ {"id": "a", "name": "x", "hash": "h", "size": 10, "status": "error"} ]
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
    async fn generate_link_returns_direct_link() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/transfer/directdl"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success",
                "content": [ {"link": "https://cdn.pm.example/file.mkv"} ]
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
        assert_eq!(data.link, "https://cdn.pm.example/file.mkv");
    }

    #[tokio::test]
    async fn auth_failure_maps_to_unauthorized_identifying_store() {
        // Req 16.8.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/account/info"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid token"))
            .expect(1)
            .mount(&mock)
            .await;

        let err = store_for(&mock)
            .get_user(&GetUserParams { ctx: ctx() })
            .await
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("premiumize"));
    }
}
