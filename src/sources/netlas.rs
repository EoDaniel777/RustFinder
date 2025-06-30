// src/sources/netlas.rs
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;
use log::warn;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct NetlasCountResponse {
    count: i32,
}

#[derive(Debug, Deserialize)]
struct NetlasItem {
    data: NetlasData,
}

#[derive(Debug, Deserialize)]
struct NetlasData {
    domain: String,
    #[serde(rename = "last_updated")]
    last_updated: Option<String>,
    #[serde(rename = "@timestamp")]
    timestamp: Option<String>,
    level: Option<i32>,
    zone: Option<String>,
}

#[derive(Debug, Serialize)]
struct NetlasSearchRequest {
    q: String,
    fields: Vec<String>,
    source_type: String,
    size: i32,
}

#[derive(Debug, Clone)]
pub struct NetlasSource {
    name: String,
    api_keys: Vec<String>,
}

impl Default for NetlasSource {
    fn default() -> Self {
        Self::new()
    }
}

impl NetlasSource {
    pub fn new() -> Self {
        Self {
            name: "netlas".to_string(),
            api_keys: Vec::new(),
        }
    }

    pub fn with_api_keys(mut self, keys: Vec<String>) -> Self {
        self.api_keys = keys;
        self
    }

    fn get_random_api_key(&self) -> Option<&String> {
        if self.api_keys.is_empty() {
            None
        } else {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            self.api_keys.choose(&mut rng)
        }
    }
}

#[async_trait]
impl Source for NetlasSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn info(&self) -> SourceInfo {
        SourceInfo {
            name: self.name().to_string(),
            needs_key: true,
            is_default: true,
        }
    }

    fn clone_source(&self) -> Box<dyn Source> {
        Box::new(self.clone())
    }

    async fn enumerate(&self, domain: &str, session: &Session) -> Result<Vec<SubdomainResult>, RustFinderError> {
        let api_key = match self.get_random_api_key() {
            Some(key) => key,
            None => {
                warn!("[{}] Pulando fonte: Nenhuma API key configurada.", self.name);
                return Ok(Vec::new());
            }
        };

        // Rate limiting
        session.check_rate_limit(&self.name).await?;

        // First, get count of domains
        let count_query = format!("domain:*.{} AND NOT domain:{}", domain, domain);
        let count_url = format!("https://app.netlas.io/api/domains_count/?q={}", urlencoding::encode(&count_query));

        let count = match session.client
            .get(&count_url)
            .header("accept", "application/json")
            .header("X-API-Key", api_key)
            .send()
            .await {
            Ok(response) => {
                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                let count_response: NetlasCountResponse = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                count_response.count.min(10000) // Limit to avoid large requests
            }
            Err(e) => {
                return Err(RustFinderError::SourceError {
                    source_name: self.name.to_string(),
                    message: format!("Failed to get domain count: {}", e),
                });
            }
        };

        if count == 0 {
            return Ok(Vec::new());
        }

        // Make download request to get all domains
        let download_url = "https://app.netlas.io/api/domains/download/";
        let search_request = NetlasSearchRequest {
            q: count_query,
            fields: vec!["*".to_string()],
            source_type: "include".to_string(),
            size: count,
        };

        let request_body = serde_json::to_string(&search_request)
            .map_err(|e| RustFinderError::SourceError {
                source_name: self.name.to_string(),
                message: format!("Failed to serialize request: {}", e),
            })?;

        match session.client
            .post(download_url)
            .header("Content-Type", "application/json")
            .header("accept", "application/json")
            .header("X-API-Key", api_key)
            .body(request_body)
            .send()
            .await {
            Ok(response) => {
                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                // Check if we got an error response
                if text.contains("\"detail\"") && text.contains("rate") {
                    return Err(RustFinderError::RateLimitError(self.name.to_string()));
                }

                #[derive(Debug, Deserialize)]
struct NetlasDownloadResponse {
    data: Vec<NetlasItem>,
}

// ... (restante do código)

                let netlas_download_response: NetlasDownloadResponse = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                let mut results = Vec::new();
                for item in netlas_download_response.data {
                    let subdomain = item.data.domain.trim_end_matches('.').to_lowercase();
                    
                    // Verify it's actually a subdomain of our target
                    if subdomain.ends_with(domain) && subdomain != domain {
                        results.push(SubdomainResult {
                            subdomain,
                            source: self.name.to_string(),
                            resolved: false,
                            ip_addresses: Vec::new(),
                        });
                    }
                }

                Ok(results)
            }
            Err(e) => Err(RustFinderError::SourceError {
                source_name: self.name.to_string(),
                message: format!("HTTP request failed: {}", e),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_creation() {
        let source = NetlasSource::new();
        assert_eq!(source.name(), "netlas");
        assert!(source.api_keys.is_empty());
    }

    #[test]
    fn test_api_key_management() {
        let source = NetlasSource::new();
        let source_with_keys = source.with_api_keys(vec!["test_key".to_string()]);
        assert_eq!(source_with_keys.get_random_api_key(), Some(&"test_key".to_string()));
    }
}