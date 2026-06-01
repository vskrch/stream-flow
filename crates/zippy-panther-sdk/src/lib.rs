//! Rust client SDK for `ZippyPanther`.
//!
//! The SDK is intentionally HTTP-first: it does not embed server internals or
//! duplicate routing logic. It provides typed helpers for the production
//! surfaces and returns JSON values for endpoint-specific payloads so clients
//! can adopt new server fields without upgrading immediately.

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(#[from] url::ParseError),
    #[error("invalid header value for {name}: {source}")]
    InvalidHeader {
        name: &'static str,
        source: reqwest::header::InvalidHeaderValue,
    },
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("ZippyPanther returned HTTP {status}: {body}")]
    Status {
        status: reqwest::StatusCode,
        body: String,
    },
}

pub type Result<T> = std::result::Result<T, SdkError>;

#[derive(Clone, Debug)]
pub struct ZippyPantherClient {
    base_url: Url,
    client: reqwest::Client,
    api_password: Option<String>,
    proxy_auth: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProxifyOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerateUrlRequest {
    pub mediaflow_proxy_url: String,
    pub destination_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyUrlResponse {
    pub url: String,
}

impl ZippyPantherClient {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        let mut base_url = Url::parse(base_url.as_ref().trim_end_matches('/'))?;
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path().trim_end_matches('/'));
            base_url.set_path(&path);
        }
        Ok(Self {
            base_url,
            client: reqwest::Client::new(),
            api_password: None,
            proxy_auth: None,
        })
    }

    pub fn with_api_password(mut self, value: impl Into<String>) -> Self {
        self.api_password = Some(value.into());
        self
    }

    pub fn with_proxy_auth(mut self, value: impl Into<String>) -> Self {
        self.proxy_auth = Some(value.into());
        self
    }

    pub async fn health(&self) -> Result<Value> {
        self.get_json("health").await
    }

    pub async fn metrics(&self, metrics_password: Option<&str>) -> Result<String> {
        let mut request = self.client.get(self.url("metrics")?);
        if let Some(password) = metrics_password {
            request = request.header("X-Metrics-Password", password);
        }
        let response = request.send().await?;
        self.text_response(response).await
    }

    pub async fn generate_url(&self, request: &GenerateUrlRequest) -> Result<ProxyUrlResponse> {
        self.post_json("generate_url", request).await
    }

    pub async fn proxify(&self, urls: &[impl AsRef<str>], opts: &ProxifyOptions) -> Result<Value> {
        let mut form: Vec<(&str, String)> = urls
            .iter()
            .map(|url| ("url", url.as_ref().to_string()))
            .collect();
        if let Some(token) = &opts.token {
            form.push(("token", token.clone()));
        }
        if let Some(expiration) = &opts.expiration {
            form.push(("expiration", expiration.clone()));
        }
        let response = self
            .client
            .post(self.url("v0/proxy")?)
            .headers(self.auth_headers()?)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await?;
        self.json_response(response).await
    }

    pub async fn store_user(&self, store: &str) -> Result<Value> {
        self.get_json_with_query("v0/store/user", &[("store", store)])
            .await
    }

    pub async fn check_magnets(
        &self,
        store: &str,
        magnets: &[impl AsRef<str>],
        sid: Option<&str>,
    ) -> Result<Value> {
        let magnet = magnets
            .iter()
            .map(|m| m.as_ref())
            .collect::<Vec<_>>()
            .join(",");
        let mut query = vec![("store", store.to_string()), ("magnet", magnet)];
        if let Some(sid) = sid {
            query.push(("sid", sid.to_string()));
        }
        self.get_json_with_owned_query("v0/store/magnets/check", &query)
            .await
    }

    pub async fn add_magnet(&self, store: &str, magnet: &str) -> Result<Value> {
        self.post_json(
            "v0/store/magnets",
            &serde_json::json!({ "store": store, "magnet": magnet }),
        )
        .await
    }

    pub async fn list_magnets(
        &self,
        store: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Value> {
        let mut query = vec![("store", store.to_string())];
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        if let Some(offset) = offset {
            query.push(("offset", offset.to_string()));
        }
        self.get_json_with_owned_query("v0/store/magnets", &query)
            .await
    }

    pub async fn get_magnet(&self, store: &str, id: &str) -> Result<Value> {
        self.get_json_with_query(&format!("v0/store/magnets/{id}"), &[("store", store)])
            .await
    }

    pub async fn remove_magnet(&self, store: &str, id: &str) -> Result<Value> {
        let response = self
            .client
            .delete(self.url(&format!("v0/store/magnets/{id}"))?)
            .headers(self.auth_headers()?)
            .query(&[("store", store)])
            .send()
            .await?;
        self.json_response(response).await
    }

    pub async fn meta_id_map(&self, namespace: &str, id: &str) -> Result<Value> {
        self.get_json(&format!("v0/meta/id-map/{namespace}/{id}"))
            .await
    }

    pub fn store_addon_manifest_url(&self, store: &str) -> Result<Url> {
        self.url(&format!("stremio/store/{store}/manifest.json"))
    }

    pub fn wrap_addon_manifest_url(&self) -> Result<Url> {
        self.url("stremio/wrap/manifest.json")
    }

    pub async fn stremio_manifest(&self, store: Option<&str>) -> Result<Value> {
        match store {
            Some(store) => {
                self.get_json(&format!("stremio/store/{store}/manifest.json"))
                    .await
            }
            None => self.get_json("stremio/wrap/manifest.json").await,
        }
    }

    async fn get_json(&self, path: &str) -> Result<Value> {
        let response = self
            .client
            .get(self.url(path)?)
            .headers(self.auth_headers()?)
            .send()
            .await?;
        self.json_response(response).await
    }

    async fn get_json_with_query(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        let response = self
            .client
            .get(self.url(path)?)
            .headers(self.auth_headers()?)
            .query(query)
            .send()
            .await?;
        self.json_response(response).await
    }

    async fn get_json_with_owned_query(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Value> {
        let response = self
            .client
            .get(self.url(path)?)
            .headers(self.auth_headers()?)
            .query(query)
            .send()
            .await?;
        self.json_response(response).await
    }

    async fn post_json<T, R>(&self, path: &str, body: &T) -> Result<R>
    where
        T: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let response = self
            .client
            .post(self.url(path)?)
            .headers(self.auth_headers()?)
            .json(body)
            .send()
            .await?;
        self.typed_json_response(response).await
    }

    async fn json_response(&self, response: reqwest::Response) -> Result<Value> {
        self.typed_json_response(response).await
    }

    async fn typed_json_response<R>(&self, response: reqwest::Response) -> Result<R>
    where
        R: for<'de> Deserialize<'de>,
    {
        let response = self.error_for_status(response).await?;
        Ok(response.json::<R>().await?)
    }

    async fn text_response(&self, response: reqwest::Response) -> Result<String> {
        let response = self.error_for_status(response).await?;
        Ok(response.text().await?)
    }

    async fn error_for_status(&self, response: reqwest::Response) -> Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = response.text().await.unwrap_or_default();
        Err(SdkError::Status { status, body })
    }

    fn auth_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        if let Some(password) = &self.api_password {
            headers.insert(
                "X-API-Password",
                HeaderValue::from_str(password).map_err(|source| SdkError::InvalidHeader {
                    name: "X-API-Password",
                    source,
                })?,
            );
        }
        if let Some(auth) = &self.proxy_auth {
            headers.insert(
                "X-StremThru-Authorization",
                HeaderValue::from_str(auth).map_err(|source| SdkError::InvalidHeader {
                    name: "X-StremThru-Authorization",
                    source,
                })?,
            );
        }
        Ok(headers)
    }

    fn url(&self, path: &str) -> Result<Url> {
        Ok(self.base_url.join(path.trim_start_matches('/'))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn health_gets_json_with_auth_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("X-API-Password", "secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status":"ok"})))
            .mount(&server)
            .await;

        let client = ZippyPantherClient::new(server.uri())
            .unwrap()
            .with_api_password("secret");
        assert_eq!(client.health().await.unwrap()["status"], "ok");
    }

    #[tokio::test]
    async fn proxify_posts_form_with_proxy_auth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/proxy"))
            .and(header("X-StremThru-Authorization", "Basic abc"))
            .and(body_string_contains(
                "url=https%3A%2F%2Fcdn.example%2Fv.mkv",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"links":["/v0/proxy?token=x"]})),
            )
            .mount(&server)
            .await;

        let client = ZippyPantherClient::new(server.uri())
            .unwrap()
            .with_proxy_auth("Basic abc");
        let result = client
            .proxify(&["https://cdn.example/v.mkv"], &ProxifyOptions::default())
            .await
            .unwrap();
        assert_eq!(result["links"][0], "/v0/proxy?token=x");
    }

    #[tokio::test]
    async fn store_helpers_use_expected_paths_and_query() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/store/magnets"))
            .and(query_param("store", "rd"))
            .and(query_param("limit", "25"))
            .and(query_param("offset", "5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":[]})))
            .mount(&server)
            .await;

        let client = ZippyPantherClient::new(server.uri()).unwrap();
        assert_eq!(
            client.list_magnets("rd", Some(25), Some(5)).await.unwrap()["items"],
            json!([])
        );
    }

    #[tokio::test]
    async fn stremio_manifest_urls_are_built_from_base() {
        let client = ZippyPantherClient::new("https://flow.example/root").unwrap();
        assert_eq!(
            client.store_addon_manifest_url("tb").unwrap().as_str(),
            "https://flow.example/root/stremio/store/tb/manifest.json"
        );
        assert_eq!(
            client.wrap_addon_manifest_url().unwrap().as_str(),
            "https://flow.example/root/stremio/wrap/manifest.json"
        );
    }

    #[tokio::test]
    async fn non_success_status_returns_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&server)
            .await;

        let client = ZippyPantherClient::new(server.uri()).unwrap();
        let err = client.health().await.unwrap_err();
        assert!(matches!(err, SdkError::Status { body, .. } if body == "unavailable"));
    }
}
