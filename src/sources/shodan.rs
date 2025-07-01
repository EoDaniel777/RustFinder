// src/sources/shodan.rs
use crate::session::Session;
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use async_trait::async_trait;
use log::{info, warn};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
struct ShodanResponse {
    domain: String,
    subdomains: Vec<String>,
    data: Option<Vec<ShodanData>>,
    more: Option<bool>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanData {
    subdomain: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShodanSource {
    name: String,
    api_keys: Vec<String>,
}

impl Default for ShodanSource {
    fn default() -> Self {
        Self::new()
    }
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
        let mut page = 1;
        let max_pages = 5;

        loop {
            let url = format!("https://api.shodan.io/dns/domain/{}", domain);
            
            let request_builder = session.client
                .get(&url)
                .query(&[
                    ("key", api_key),
                    ("page", &page.to_string())
                ])
                .header("Accept", "application/json");
            
            match session.send_request_with_retry(request_builder, &self.name).await {
                Ok(response) => {
                    let status = response.status();
                    
                    if !status.is_success() {
                        let text = response.text().await
                            .unwrap_or_else(|_| "Failed to read response body".to_string());
                        
                        if status.as_u16() == 429 || text.contains("rate limit") {
                            return Err(RustFinderError::RateLimitError(self.name.to_string()));
                        }
                        
                        return Err(RustFinderError::SourceError {
                            source_name: self.name.to_string(),
                            message: format!("Shodan API returned status: {}. Body: {}", status, text),
                        });
                    }

                    let text = response.text().await
                        .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                    let shodan_response: ShodanResponse = serde_json::from_str(&text)
                        .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                    if let Some(error) = shodan_response.error {
                        return Err(RustFinderError::SourceError {
                            source_name: self.name.to_string(),
                            message: format!("Shodan API error: {}", error),
                        });
                    }

                    for subdomain in shodan_response.subdomains {
                        let full_subdomain = format!("{}.{}", subdomain, shodan_response.domain);
                        if found_subdomains.insert(full_subdomain.clone()) {
                            results.push(SubdomainResult {
                                subdomain: full_subdomain,
                                source: self.name.to_string(),
                                resolved: false,
                                ip_addresses: Vec::new(),
                            });
                        }
                    }

                    if let Some(data_array) = shodan_response.data {
                        for data in data_array {
                            if let Some(subdomain) = data.subdomain {
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
                        }
                    }

                    if let Some(more) = shodan_response.more {
                        if more && page < max_pages {
                            page += 1;
                            continue;
                        }
                    }
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        info!("[{}] Encontrados {} subdomínios únicos", self.name, results.len());
        Ok(results)
    }
}