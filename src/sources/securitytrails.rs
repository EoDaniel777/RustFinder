// src/sources/securitytrails.rs
use crate::session::Session;
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use async_trait::async_trait;
use log::warn;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SecurityTrailsResponse {
    meta: Option<SecurityTrailsMeta>,
    records: Option<Vec<SecurityTrailsRecord>>,
    subdomains: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SecurityTrailsMeta {
    scroll_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SecurityTrailsRecord {
    hostname: String,
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

        // Rate limiting
        session.check_rate_limit(&self.name).await?;

        let mut results = Vec::new();
        let mut scroll_id: Option<String> = None;

        // Try the scroll API first
        loop {
            let url = if let Some(ref sid) = scroll_id {
                format!("https://api.securitytrails.com/v1/scroll/{}", sid)
            } else {
                "https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=true".to_string()
            };

            let response_result = if scroll_id.is_none() {
                // Initial request with POST
                let body = format!(r#"{{"query":"apex_domain='{}'"}}"#, domain);
                session.client
                    .post(&url)
                    .header("APIKEY", api_key)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))
            } else {
                // Subsequent requests with GET
                session.client
                    .get(&url)
                    .header("APIKEY", api_key)
                    .header("Content-Type", "application/json")
                    .send()
                    .await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))
            };

            match response_result {
                Ok(response) => {
                    let text = response.text().await
                        .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                    let st_response: SecurityTrailsResponse = serde_json::from_str(&text)
                        .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text.clone()))?;

                    // Process records from scroll API
                    if let Some(records) = st_response.records {
                        for record in records {
                            results.push(SubdomainResult {
                                subdomain: record.hostname,
                                source: self.name.to_string(),
                                resolved: false,
                                ip_addresses: Vec::new(),
                            });
                        }
                    }

                    // Process subdomains from regular API
                    if let Some(subdomains) = st_response.subdomains {
                        for subdomain in subdomains {
                            let full_subdomain = if subdomain.ends_with('.') {
                                format!("{}{}", subdomain, domain)
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
                    }

                    // Check for next page
                    if let Some(meta) = st_response.meta {
                        if let Some(next_scroll_id) = meta.scroll_id {
                            scroll_id = Some(next_scroll_id);
                        } else {
                            break;
                        }
                    }
                }
                Err(_) => {
                    // If scroll API fails, try the simpler subdomain API
                    if scroll_id.is_none() {
                        let fallback_url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains", domain);
                        
                        match session.client
                            .get(&fallback_url)
                            .header("APIKEY", api_key)
                            .send()
                            .await {
                            Ok(response) => {
                                let text = response.text().await
                                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                                let fallback_response: SecurityTrailsResponse = serde_json::from_str(&text)
                                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                                if let Some(subdomains) = fallback_response.subdomains {
                                    for subdomain in subdomains {
                                        let full_subdomain = format!("{}.{}", subdomain, domain);
                                        results.push(SubdomainResult {
                                            subdomain: full_subdomain,
                                            source: self.name.to_string(),
                                            resolved: false,
                                            ip_addresses: Vec::new(),
                                        });
                                    }
                                }
                            }
                            Err(e) => {
                                return Err(RustFinderError::SourceError {
                                    source_name: self.name.to_string(),
                                    message: format!("Both scroll and subdomain APIs failed: {}", e),
                                });
                            }
                        }
                    }
                    break;
                }
            }
        }

        Ok(results)
    }
}