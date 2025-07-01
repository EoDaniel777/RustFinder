// src/sources/github.rs
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;
use log::{info, warn};
use serde::Deserialize;
use std::collections::HashSet;
use regex::Regex;

#[derive(Debug, Deserialize)]
struct GitHubSearchResponse {
    total_count: i32,
    incomplete_results: bool,
    items: Vec<GitHubItem>,
}

#[derive(Debug, Deserialize)]
struct GitHubItem {
    name: String,
    html_url: String,
    text_matches: Option<Vec<GitHubTextMatch>>,
}

#[derive(Debug, Deserialize)]
struct GitHubTextMatch {
    fragment: String,
}

#[derive(Debug, Clone)]
pub struct GitHubSource {
    name: String,
    api_keys: Vec<String>,
}

impl Default for GitHubSource {
    fn default() -> Self {
        Self::new()
    }
}

impl GitHubSource {
    pub fn new() -> Self {
        Self {
            name: "github".to_string(),
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

    fn extract_subdomains(&self, text: &str, domain: &str) -> Vec<String> {
        let mut subdomains = HashSet::new();
        
        let pattern = format!(
            r"(?i)(?:^|[^a-zA-Z0-9.-])([a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?)*\.{})",
            regex::escape(domain)
        );
        
        if let Ok(re) = Regex::new(&pattern) {
            for cap in re.captures_iter(text) {
                if let Some(subdomain) = cap.get(1) {
                    let subdomain_str = subdomain.as_str().to_lowercase();
                    // Validate subdomain
                    if subdomain_str != domain && 
                       !subdomain_str.contains("..") &&
                       !subdomain_str.starts_with('.') &&
                       !subdomain_str.ends_with('.') {
                        subdomains.insert(subdomain_str);
                    }
                }
            }
        }
        
        subdomains.into_iter().collect()
    }
}

#[async_trait]
impl Source for GitHubSource {
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
        let mut found_subdomains: HashSet<String> = HashSet::new();

        let search_query = format!("\"{}\"", domain);
        let url = format!(
            "https://api.github.com/search/code?q={}&sort=indexed&order=desc&per_page=30",
            urlencoding::encode(&search_query)
        );

        let request_builder = session.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Accept", "application/vnd.github.v3.text-match+json")
            .header("X-GitHub-Api-Version", "2022-11-28");

        match session.send_request_with_retry(request_builder, &self.name).await {
            Ok(response) => {
                // Check rate limit headers
                if let Some(remaining) = response.headers().get("x-ratelimit-remaining") {
                    if let Ok(remaining_str) = remaining.to_str() {
                        if let Ok(remaining_count) = remaining_str.parse::<i32>() {
                            if remaining_count < 10 {
                                warn!("[{}] GitHub API rate limit baixo: {} requisições restantes", 
                                      self.name, remaining_count);
                            }
                     }
                    }
                }

                let status = response.status();
                
                if !status.is_success() {
                    let text = response.text().await
                        .unwrap_or_else(|_| "Failed to read response body".to_string());
                    
                    if status.as_u16() == 403 && text.contains("rate limit") {
                        return Err(RustFinderError::RateLimitError(self.name.to_string()));
                    }
                    
                    return Err(RustFinderError::SourceError {
                        source_name: self.name.to_string(),
                        message: format!("GitHub API returned status: {}. Body: {}", status, text),
                    });
                }

                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                let github_response: GitHubSearchResponse = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                for item in github_response.items.iter().take(30) {
                    if let Some(text_matches) = &item.text_matches {
                        for text_match in text_matches {
                            let extracted = self.extract_subdomains(&text_match.fragment, domain);
                            for subdomain in extracted {
                                if found_subdomains.insert(subdomain.clone()) {
                                    results.push(SubdomainResult {
                                        subdomain,
                                        source: self.name.to_string(),
                                        resolved: false,
                                        ip_addresses: Vec::new(),
                                    });
                                }
                            }
                        }
                    }
                }

                info!("[{}] Encontrados {} subdomínios únicos de {} resultados", 
                      self.name, results.len(), github_response.total_count);
                Ok(results)
            }
            Err(e) => Err(e),
        }
    }
}