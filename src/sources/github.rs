// src/sources/github.rs
use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;
use log::warn;
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
struct TokenInfo {
    token: String,
    rate_limit_remaining: i32,
    rate_limit_reset: u64,
}

#[derive(Debug, Clone)]
pub struct GitHubSource {
    name: String,
    api_keys: Vec<String>,
    tokens: Vec<TokenInfo>,
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
            tokens: Vec::new(),
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
        
        // Create regex pattern for subdomains
        let pattern = format!(
            r"(?i)(?:^|[^a-zA-Z0-9.-])([a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?)*\.{})",
            regex::escape(domain)
        );
        
        if let Ok(re) = Regex::new(&pattern) {
            for cap in re.captures_iter(text) {
                if let Some(subdomain) = cap.get(1) {
                    let subdomain_str = subdomain.as_str().to_lowercase();
                    // Validate subdomain
                    if subdomain_str != domain && !subdomain_str.contains("..") {
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

        // Rate limiting
        session.check_rate_limit(&self.name).await?;

        let mut results = Vec::new();
        let mut found_subdomains: HashSet<String> = HashSet::new();

        // Search for the domain in code
        let search_query = domain.to_string();
        let url = format!(
            "https://api.github.com/search/code?q={}&sort=indexed&order=desc&per_page=100",
            urlencoding::encode(&search_query)
        );

        match session.client
            .get(&url)
            .header("Authorization", format!("token {}", api_key))
            .header("Accept", "application/vnd.github.v3.text-match+json")
            .header("User-Agent", "RustFinder/1.0")
            .send()
            .await {
            Ok(response) => {
                // Check rate limit headers
                if let Some(remaining) = response.headers().get("x-ratelimit-remaining") {
                    if let Ok(remaining_str) = remaining.to_str() {
                        if let Ok(remaining_count) = remaining_str.parse::<i32>() {
                            let reset_time = response.headers()
                                .get("x-ratelimit-reset")
                                .and_then(|h| h.to_str().ok())
                                .and_then(|s| s.parse::<u64>().ok())
                                .unwrap_or(0);
                            
                            // Update rate limit for the specific token
                            // This requires a mutable self, which is not allowed in async_trait methods directly.
                            // For now, we'll just log it or handle it outside this function if needed.
                            // source_copy.update_rate_limit(&api_key, remaining_count, reset_time);
                        }
                    }
                }

                let status = response.status();
                let text = response.text().await
                    .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

                if !status.is_success() {
                    return Err(RustFinderError::SourceError {
                        source_name: self.name.to_string(),
                        message: format!("GitHub API returned status: {}. Body: {}", status, text),
                    });
                }

                let github_response: GitHubSearchResponse = serde_json::from_str(&text)
                    .map_err(|e| RustFinderError::JsonParseError(e.to_string(), text))?;

                // Extract subdomains from text matches
                for item in github_response.items {
                    if let Some(text_matches) = item.text_matches {
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

                    // Also try to fetch the raw content if it's a reasonable size
                    if item.html_url.contains("blob") && results.len() < 50 {
                        let raw_url = item.html_url
                            .replace("github.com", "raw.githubusercontent.com")
                            .replace("/blob/", "/");

                        match session.get(&raw_url).await {
                            Ok(content_response) => {
                                if let Ok(content) = content_response.text().await {
                                    let extracted = self.extract_subdomains(&content, domain);
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
                            Err(_) => {
                                // Ignore errors for individual file fetches
                                continue;
                            }
                        }
                    }
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
        let source = GitHubSource::new();
        assert_eq!(source.name(), "github");
        assert!(source.api_keys.is_empty());
    }

    #[test]
    fn test_extract_subdomains() {
        let source = GitHubSource::new();
        let text = "Found api.example.com and test.example.com in the code";
        let subdomains = source.extract_subdomains(text, "example.com");
        
        assert_eq!(subdomains.len(), 2);
        assert!(subdomains.contains(&"api.example.com".to_string()));
        assert!(subdomains.contains(&"test.example.com".to_string()));
    }
}