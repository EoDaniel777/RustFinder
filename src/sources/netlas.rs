// src/sources/netlas.rs
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;
use log::{info, warn};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
struct NetlasResponse {
    items: Vec<NetlasItem>,
    count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct NetlasItem {
    data: NetlasData,
}

#[derive(Debug, Deserialize)]
struct NetlasData {
    domain: Option<String>,
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

        session.check_rate_limit(&self.name).await?;

        let mut results = Vec::new();
        let mut found_subdomains = HashSet::new();
        
        let query = format!("domain:*.{}", domain);
        let url = "https://app.netlas.io/api/domains/";
        
        let request_builder = session.client
            .get(url)
            .query(&[
                ("q", query.as_str()),
                ("fields", "domain"),
                ("source_type", "include"),
                ("size", "100")
            ])
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {}", api_key));

        match session.send_request_with_retry(request_builder, &self.name).await {
            Ok(response) => {
                let status = response.status();
                
                if !status.is_success() {
                    let text = response.text().await
                        .unwrap_or_else(|_| "Failed to read response body".to_string());
                    
                    if status.as_u16() == 429 {
                        return Err(RustFinderError::RateLimitError(self.name.to_string()));
                    }
                    
                    return Err(RustFinderError::SourceError {
                        source_name: self.name.to_string(),
                        message: format!("Netlas API returned status: {}. Body: {}", status, text),
                    });
                }

                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                let netlas_response: NetlasResponse = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                for item in netlas_response.items {
                    if let Some(subdomain) = item.data.domain {
                        let subdomain = subdomain.trim_end_matches('.').to_lowercase();
                        
                        if subdomain.ends_with(domain) && 
                           subdomain != domain &&
                           found_subdomains.insert(subdomain.clone()) {
                            results.push(SubdomainResult {
                                subdomain,
                                source: self.name.to_string(),
                                resolved: false,
                                ip_addresses: Vec::new(),
                            });
                        }
                    }
                }

                info!("[{}] Encontrados {} subdomínios únicos", self.name, results.len());
                Ok(results)
            }
            Err(e) => Err(e),
        }
    }
}