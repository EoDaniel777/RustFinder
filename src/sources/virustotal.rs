// src/sources/virustotal.rs
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VirusTotalResponse {
    data: Vec<VirusTotalData>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalData {
    id: String,
    #[serde(default)]
    attributes: Option<VirusTotalAttributes>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalAttributes {
    #[serde(default)]
    last_dns_records: Option<Vec<DnsRecord>>,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    value: String,
}

#[derive(Debug, Clone)]
pub struct VirusTotalSource {
    name: String,
    api_keys: Vec<String>,
}

impl VirusTotalSource {
    pub fn new() -> Self {
        Self {
            name: "virustotal".to_string(),
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
            self.api_keys.choose(&mut rand::thread_rng())
        }
    }
}

#[async_trait]
impl Source for VirusTotalSource {
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
                message: "No API key configured".to_string(),
            }
        })?;

        // Rate limiting
        session.check_rate_limit(&self.name).await?;

        let url = format!(
            "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=100",
            domain
        );

        let response = session
            .client
            .get(&url)
            .header("x-apikey", api_key)
            .send()
            .await
            .map_err(|e| RustFinderError::SourceError {
                source_name: self.name.to_string(),
                message: format!("Request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(RustFinderError::SourceError {
                source_name: self.name.to_string(),
                message: format!("API returned status: {}", response.status()),
            });
        }

        let data: VirusTotalResponse = response.json().await.map_err(|e| {
            RustFinderError::SourceError {
                source_name: self.name.to_string(),
                message: format!("Failed to parse response: {}", e),
            }
        })?;

        let mut results = Vec::new();

        for item in data.data {
            let subdomain = item.id.replace(&format!(".{}", domain), "");
            if !subdomain.is_empty() && subdomain != domain {
                results.push(SubdomainResult {
                    subdomain: subdomain.clone(),
                    source: self.name.to_string(),
                    resolved: false,
                    ip_addresses: Vec::new(),
                });
            }
        }

        Ok(results)
    }
}