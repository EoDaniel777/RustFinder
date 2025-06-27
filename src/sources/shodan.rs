// src/sources/shodan.rs
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ShodanResponse {
    domain: String,
    subdomains: Vec<String>,
    result: Option<i32>,
    error: Option<String>,
    more: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ShodanSource {
    name: String,
    api_keys: Vec<String>,
}

impl ShodanSource {
    pub fn new() -> Self {
        Self {
            name: "shodan".to_string(),
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
impl Source for ShodanSource {
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
        let api_key = self.get_random_api_key().ok_or_else(|| {
            RustFinderError::SourceError {
                source_name: self.name.to_string(),
                message: "No API key available".to_string(),
            }
        })?;

        // Rate limiting
        session.check_rate_limit(&self.name).await?;

        let mut results = Vec::new();
        let mut page = 1;

        loop {
            let url = format!("https://api.shodan.io/dns/domain/{}?key={}&page={}", domain, api_key, page);
            
            match session.get(&url).await {
                Ok(response) => {
                    let text = response.text().await
                        .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                    let shodan_response: ShodanResponse = serde_json::from_str(&text)
                        .map_err(|e| RustFinderError::SourceError {
                            source_name: self.name.to_string(),
                            message: format!("Failed to parse JSON: {}", e),
                        })?;

                    // Check for API errors
                    if let Some(error) = shodan_response.error {
                        return Err(RustFinderError::SourceError {
                            source_name: self.name.to_string(),
                            message: format!("Shodan API error: {}", error),
                        });
                    }

                    // Process subdomains
                    for subdomain in shodan_response.subdomains {
                        let full_subdomain = format!("{}.{}", subdomain, shodan_response.domain);
                        results.push(SubdomainResult {
                            subdomain: full_subdomain,
                            source: self.name.to_string(),
                            resolved: false,
                            ip_addresses: Vec::new(),
                        });
                    }

                    // Check if there are more pages
                    if let Some(more) = shodan_response.more {
                        if more {
                            page += 1;
                            continue;
                        }
                    }
                    break;
                }
                Err(e) => {
                    return Err(RustFinderError::SourceError {
                        source_name: self.name.to_string(),
                        message: format!("HTTP request failed: {}", e),
                    });
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_management() {
        let source = ShodanSource::new();
        assert!(source.api_keys.is_empty());
        
        let source_with_keys = source.with_api_keys(vec!["test_key".to_string()]);
        assert_eq!(source_with_keys.get_random_api_key(), Some(&"test_key".to_string()));
    }
}