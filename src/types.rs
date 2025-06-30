// src/types.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub timeout: Duration,
    pub user_agent: String,
    pub proxy: Option<String>,
    pub rate_limits: HashMap<String, Option<u32>>,
    pub api_keys: HashMap<String, Vec<String>>,
    pub output: OutputConfig,
    pub resolver: ResolverConfig,
    pub sources: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut rate_limits = HashMap::new();
        rate_limits.insert("virustotal".to_string(), Some(4));
        rate_limits.insert("securitytrails".to_string(), Some(1));
        rate_limits.insert("shodan".to_string(), Some(1));
        rate_limits.insert("chaos".to_string(), Some(60));
        rate_limits.insert("github".to_string(), Some(5));
        rate_limits.insert("netlas".to_string(), Some(1));

        Self {
            timeout: Duration::from_secs(30),
            user_agent: "RustFinder/1.0".to_string(),
            proxy: None,
            rate_limits,
            api_keys: HashMap::new(),
            output: OutputConfig::default(),
            resolver: ResolverConfig::default(),
            sources: vec![
                "virustotal".to_string(),
                "securitytrails".to_string(),
                "shodan".to_string(),
                "chaos".to_string(),
                "github".to_string(),
                "netlas".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: OutputFormat,
    pub file: Option<String>,
    pub verbose: bool,
    pub include_ips: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            file: None,
            verbose: false,
            include_ips: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    pub enabled: bool,
    pub threads: usize,
    pub timeout: Duration,
    pub nameservers: Vec<String>,
    pub use_system_resolver: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threads: 50,
            timeout: Duration::from_secs(5),
            nameservers: vec![
                "8.8.8.8:53".to_string(),
                "8.8.4.4:53".to_string(),
                "1.1.1.1:53".to_string(),
                "1.0.0.1:53".to_string(),
            ],
            use_system_resolver: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
    pub resolved: bool,
    pub ip_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerationStats {
    pub total_found: usize,
    pub unique_subdomains: usize,
    pub resolved_count: usize,
    pub sources_used: Vec<String>,
    pub duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReport {
    pub domain: String,
    pub subdomains: Vec<SubdomainResult>,
    pub stats: EnumerationStats,
    pub timestamp: String,
}

pub struct SourceInfo {
    pub name: String,
    pub needs_key: bool,
    pub is_default: bool,
}

#[derive(Debug, Error)]
pub enum RustFinderError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Source error in {source_name}: {message}")]
    SourceError {
        source_name: String,
        message: String
    },

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("JSON parse error: {0}\nBody: {1}")]
    JsonParseError(String, String),

    #[error("Resolution error: {0}")]
    ResolutionError(String),

    #[error("Output error: {0}")]
    OutputError(String),

    #[error("Rate limit error: {0}")]
    RateLimitError(String),

    #[error("API key error: {0}")]
    ApiKeyError(String),

    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Unknown error: {0}")]
    Unknown(#[from] anyhow::Error),
}