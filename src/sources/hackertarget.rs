// src/sources/hackertarget.rs
use crate::session::Session;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use async_trait::async_trait;
use crate::sources::Source;

/// HackerTarget API source
#[derive(Debug, Clone)]
pub struct HackerTargetSource {
    name: String,
}

impl Default for HackerTargetSource {
    fn default() -> Self {
        Self::new()
    }
}

impl HackerTargetSource {
    pub fn new() -> Self {
        Self { name: "hackertarget".to_string() }
    }
}

#[async_trait]
impl crate::sources::Source for HackerTargetSource {
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
        let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
        
        match session.get(&url).await {
            Ok(response) => {
                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;
                let mut results = Vec::new();

                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with("error") {
                        continue;
                    }

                    let parts: Vec<&str> = line.split(',').collect();
                    if !parts.is_empty() {
                        let subdomain = parts[0].trim().to_lowercase();

                        // Garantir que o subdomínio pertence ao domínio-alvo
                        if subdomain.ends_with(&format!(".{}", domain)) {
                            let ip_addresses = if let Some(ip) = parts.get(1) {
                                vec![ip.trim().to_string()]
                            } else {
                                Vec::new()
                            };

                            results.push(SubdomainResult {
                                subdomain,
                                source: self.name.to_string(),
                                resolved: !ip_addresses.is_empty(),
                                ip_addresses,
                            });
                        }
                    }
                }
                Ok(results)
            }
            Err(e) => Err(RustFinderError::SourceError {
                source_name: self.name.to_string(),
                message: format!("Failed to fetch data: {}", e),
            }),
        }
    }
}