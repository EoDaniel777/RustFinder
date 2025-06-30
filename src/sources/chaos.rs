// src/sources/chaos.rs
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;
use log::warn;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ChaosResponse {
    subdomains: Vec<String>,
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

        // Rate limiting
        session.check_rate_limit(&self.name).await?;

        let url = format!("https://dns.projectdiscovery.io/dns/{}/subdomains", domain);

        match session.client
            .get(&url)
            .header("X-API-Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await {
            Ok(response) => {
                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                let chaos_response: ChaosResponse = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                let mut results = Vec::new();
                for subdomain in chaos_response.subdomains {
                    // Create full subdomain if needed
                    let full_subdomain = if subdomain.ends_with(&format!(".{}", domain)) {
                        subdomain
                    } else {
                        format!("{}.{}", subdomain, domain)
                    };

                    results.push(SubdomainResult {
                        subdomain: full_subdomain,
                        source: self.name.to_string(),
                        resolved: false,
                        ip_addresses: Vec::new(),
                    });
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
        let source = ChaosSource::new();
        assert_eq!(source.name(), "chaos");
        assert!(source.api_keys.is_empty());
    }

    #[test]
    fn test_api_key_management() {
        let source = ChaosSource::new();
        let source_with_keys = source.with_api_keys(vec!["test_key".to_string()]);
        assert_eq!(source_with_keys.get_random_api_key(), Some(&"test_key".to_string()));
    }
}