// src/sources/chaos.rs
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;
use log::{info, warn};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
struct ChaosResponse {
    subdomains: Vec<String>,
    count: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ChaosSource {
    name: String,
    api_keys: Vec<String>,
}

impl Default for ChaosSource {
    fn default() -> Self {
        Self::new()
    }
}

impl ChaosSource {
    pub fn new() -> Self {
        Self {
            name: "chaos".to_string(),
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
impl Source for ChaosSource {
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

        let url = format!("https://dns.projectdiscovery.io/dns/{}/subdomains", domain);

        let request_builder = session.client
            .get(&url)
            .header("Authorization", api_key)
            .header("Accept", "application/json");

        match session.send_request_with_retry(request_builder, &self.name).await {
            Ok(response) => {
                let status = response.status();
                
                if !status.is_success() {
                    let text = response.text().await
                        .unwrap_or_else(|_| "Failed to read response body".to_string());
                    return Err(RustFinderError::SourceError {
                        source_name: self.name.to_string(),
                        message: format!("Chaos API returned status: {}. Body: {}", status, text),
                    });
                }

                let chaos_response: ChaosResponse = response.json().await.map_err(|e| {
                    RustFinderError::JsonParseError(e.to_string(), "Failed to parse Chaos response".to_string())
                })?;

                let mut found_subdomains = HashSet::new();
                let mut results = Vec::new();
                
                for subdomain in chaos_response.subdomains {
                    let full_subdomain = if subdomain.ends_with(&format!(".{}", domain)) {
                        subdomain
                    } else {
                        format!("{}.{}", subdomain, domain)
                    };

                    if found_subdomains.insert(full_subdomain.clone()) {
                        results.push(SubdomainResult {
                            subdomain: full_subdomain,
                            source: self.name.to_string(),
                            resolved: false,
                            ip_addresses: Vec::new(),
                        });
                    }
                }

                info!("[{}] Encontrados {} subdomínios únicos", self.name, results.len());
                Ok(results)
            }
            Err(e) => Err(e),
        }
    }
}