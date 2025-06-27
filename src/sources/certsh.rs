// src/sources/crtsh.rs
use crate::session::Session;
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use async_trait::async_trait;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CrtShResponse {
    id: u64,
    name_value: String,
}

/// CRT.sh certificate transparency logs source
#[derive(Debug, Clone)]
pub struct CrtShSource {
    name: String,
}

impl CrtShSource {
    pub fn new() -> Self {
        Self { name: "crtsh".to_string() }
    }
}

#[async_trait]
impl Source for CrtShSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn info(&self) -> SourceInfo {
        SourceInfo {
            name: self.name().to_string(),
            is_default: true,
            needs_key: false,
        }
    }

    fn clone_source(&self) -> Box<dyn Source> {
        Box::new(self.clone())
    }

    async fn enumerate(&self, domain: &str, session: &Session) -> Result<Vec<SubdomainResult>, RustFinderError> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        
        match session.get(&url).await {
            Ok(response) => {
                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;
                
                let crt_results: Vec<CrtShResponse> = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::SourceError {
                        source_name: self.name.to_string(),
                        message: format!("Failed to parse JSON: {}", e),
                    })?;

                let mut results = Vec::new();
                for crt_result in crt_results {
                    // name_value can contain multiple subdomains separated by newlines
                    for line in crt_result.name_value.lines() {
                        let subdomain = line.trim().to_lowercase();
                        
                        // Filter out wildcards and ensure it ends with our domain
                        if !subdomain.starts_with('*') && subdomain.ends_with(domain) {
                            results.push(SubdomainResult {
                                subdomain,
                                source: self.name.to_string(),
                                resolved: false,
                                ip_addresses: Vec::new(),
                            });
                        }
                    }
                }

                // Remove duplicates
                results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
                results.dedup_by(|a, b| a.subdomain == b.subdomain);

                Ok(results)
            }
            Err(e) => Err(RustFinderError::SourceError {
                source_name: self.name.to_string(),
                message: format!("HTTP request failed: {}", e),
            }),
        }
    }
}