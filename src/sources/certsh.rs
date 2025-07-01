// src/sources/crtsh.rs
use crate::session::Session;
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
struct CrtShResponse {
    id: u64,
    name_value: String,
}

#[derive(Debug, Clone)]
pub struct CrtShSource {
    name: String,
}

impl Default for CrtShSource {
    fn default() -> Self {
        Self::new()
    }
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

        session.check_rate_limit(&self.name).await?;
        
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        
        let request_builder = session.client
            .get(&url)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(30));
        
        match session.send_request_with_retry(request_builder, &self.name).await {
            Ok(response) => {
                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                if text.trim_start().starts_with("<!DOCTYPE") || text.trim_start().starts_with("<html") {
                    return Err(RustFinderError::SourceError {
                        source_name: self.name.to_string(),
                        message: "Received HTML response instead of JSON".to_string(),
                    });
                }

                if text.trim().is_empty() || text.trim() == "[]" {
                    return Ok(Vec::new());
                }

                let crt_results: Vec<CrtShResponse> = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                let mut found_subdomains = HashSet::new();
                let mut results = Vec::new();
                
                for crt_result in crt_results {

                    for line in crt_result.name_value.lines() {
                        let subdomain = line.trim().to_lowercase();
                        
                        if !subdomain.starts_with('*') && 
                           subdomain.ends_with(domain) && 
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

                log::info!("[{}] Encontrados {} subdomínios únicos", self.name, results.len());
                Ok(results)
            }
            Err(e) => Err(e),
        }
    }
}