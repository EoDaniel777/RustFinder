// src/sources/securitytrails.rs
use crate::session::Session;
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use async_trait::async_trait;
use log::{info, warn};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
struct SecurityTrailsResponse {
    meta: Option<SecurityTrailsMeta>,
    subdomains: Option<Vec<String>>,
    subdomain_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SecurityTrailsMeta {
    limit_reached: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct SecurityTrailsSource {
    name: String,
    api_keys: Vec<String>,
}

impl Default for SecurityTrailsSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityTrailsSource {
    pub fn new() -> Self {
        Self {
            name: "securitytrails".to_string(),
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
impl Source for SecurityTrailsSource {
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

        let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains", domain);
        
        let request_builder = session.client
            .get(&url)
            .header("APIKEY", api_key)
            .header("Accept", "application/json");

        match session.send_request_with_retry(request_builder, &self.name).await {
            Ok(response) => {
                let status = response.status();
                
                if !status.is_success() {
                    let text = response.text().await
                        .unwrap_or_else(|_| "Failed to read response body".to_string());
                    return Err(RustFinderError::SourceError {
                        source_name: self.name.to_string(),
                        message: format!("SecurityTrails API returned status: {}. Body: {}", status, text),
                    });
                }

                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                let st_response: SecurityTrailsResponse = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                let mut found_subdomains = HashSet::new();
                let mut results = Vec::new();

                if let Some(subdomains) = st_response.subdomains {
                    for subdomain in subdomains {
                        let full_subdomain = format!("{}.{}", subdomain, domain);
                        
                        if found_subdomains.insert(full_subdomain.clone()) {
                            results.push(SubdomainResult {
                                subdomain: full_subdomain,
                                source: self.name.to_string(),
                                resolved: false,
                                ip_addresses: Vec::new(),
                            });
                        }
                    }
                }

                if let Some(meta) = st_response.meta {
                    if let Some(limit_reached) = meta.limit_reached {
                        if limit_reached {
                            warn!("[{}] Limite de resultados atingido. Total de subdomínios: {:?}", 
                                  self.name, st_response.subdomain_count);
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