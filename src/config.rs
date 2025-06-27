// src/config.rs
use crate::types::{Config, OutputFormat, RustFinderError};
use std::fs;
use std::path::Path;
use std::time::Duration;
use std::env;

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, RustFinderError> {
    let path = path.as_ref();
    
    if !path.exists() {
        return Err(RustFinderError::ConfigError(format!(
            "Configuration file not found: {}",
            path.display()
        )));
    }

    let contents = fs::read_to_string(path)
        .map_err(|e| RustFinderError::ConfigError(format!("Failed to read config file: {}", e)))?;

    let mut config: Config = toml::from_str(&contents)
        .map_err(|e| RustFinderError::ConfigError(format!("Failed to parse config file: {}", e)))?;

    // Override with environment variables
    apply_env_overrides(&mut config)?;

    validate_config(&config)?;

    Ok(config)
}

pub fn load_config_from_env() -> Result<Config, RustFinderError> {
    let mut config = Config::default();
    apply_env_overrides(&mut config)?;
    validate_config(&config)?;
    Ok(config)
}

fn apply_env_overrides(config: &mut Config) -> Result<(), RustFinderError> {
    // Load .env file if it exists
    if Path::new(".env").exists() {
        dotenv::dotenv().ok();
    }

    // API Keys
    if let Ok(keys) = env::var("VIRUSTOTAL_API_KEYS") {
        let keys: Vec<String> = keys.split(',').map(|s| s.trim().to_string()).collect();
        config.api_keys.insert("virustotal".to_string(), keys);
    }

    if let Ok(keys) = env::var("SECURITYTRAILS_API_KEYS") {
        let keys: Vec<String> = keys.split(',').map(|s| s.trim().to_string()).collect();
        config.api_keys.insert("securitytrails".to_string(), keys);
    }

    if let Ok(keys) = env::var("SHODAN_API_KEYS") {
        let keys: Vec<String> = keys.split(',').map(|s| s.trim().to_string()).collect();
        config.api_keys.insert("shodan".to_string(), keys);
    }

    if let Ok(keys) = env::var("CHAOS_API_KEYS") {
        let keys: Vec<String> = keys.split(',').map(|s| s.trim().to_string()).collect();
        config.api_keys.insert("chaos".to_string(), keys);
    }

    if let Ok(keys) = env::var("GITHUB_API_KEYS") {
        let keys: Vec<String> = keys.split(',').map(|s| s.trim().to_string()).collect();
        config.api_keys.insert("github".to_string(), keys);
    }

    if let Ok(keys) = env::var("NETLAS_API_KEYS") {
        let keys: Vec<String> = keys.split(',').map(|s| s.trim().to_string()).collect();
        config.api_keys.insert("netlas".to_string(), keys);
    }

    // Output Configuration
    if let Ok(file) = env::var("OUTPUT_FILE") {
        config.output.file = Some(file);
    }

    if let Ok(format) = env::var("OUTPUT_FORMAT") {
        config.output.format = match format.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            _ => OutputFormat::Text,
        };
    }

    if let Ok(verbose) = env::var("VERBOSE") {
        config.output.verbose = verbose.to_lowercase() == "true";
    }

    // Resolver Configuration
    if let Ok(enabled) = env::var("RESOLVER_ENABLED") {
        config.resolver.enabled = enabled.to_lowercase() == "true";
    }

    if let Ok(threads) = env::var("RESOLVER_THREADS") {
        config.resolver.threads = threads.parse()
            .map_err(|_| RustFinderError::ConfigError("Invalid RESOLVER_THREADS value".to_string()))?;
    }

    if let Ok(timeout) = env::var("RESOLVER_TIMEOUT") {
        let secs: u64 = timeout.parse()
            .map_err(|_| RustFinderError::ConfigError("Invalid RESOLVER_TIMEOUT value".to_string()))?;
        config.resolver.timeout = Duration::from_secs(secs);
    }

    // Proxy Configuration
    if let Ok(proxy) = env::var("PROXY_URL") {
        config.proxy = Some(proxy);
    }

    // Rate Limits
    if let Ok(limit) = env::var("RATE_LIMIT_VIRUSTOTAL") {
        let limit: u32 = limit.parse()
            .map_err(|_| RustFinderError::ConfigError("Invalid RATE_LIMIT_VIRUSTOTAL".to_string()))?;
        config.rate_limits.insert("virustotal".to_string(), Some(limit));
    }

    if let Ok(limit) = env::var("RATE_LIMIT_SECURITYTRAILS") {
        let limit: u32 = limit.parse()
            .map_err(|_| RustFinderError::ConfigError("Invalid RATE_LIMIT_SECURITYTRAILS".to_string()))?;
        config.rate_limits.insert("securitytrails".to_string(), Some(limit));
    }

    if let Ok(limit) = env::var("RATE_LIMIT_SHODAN") {
        let limit: u32 = limit.parse()
            .map_err(|_| RustFinderError::ConfigError("Invalid RATE_LIMIT_SHODAN".to_string()))?;
        config.rate_limits.insert("shodan".to_string(), Some(limit));
    }

    if let Ok(limit) = env::var("RATE_LIMIT_CHAOS") {
        let limit: u32 = limit.parse()
            .map_err(|_| RustFinderError::ConfigError("Invalid RATE_LIMIT_CHAOS".to_string()))?;
        config.rate_limits.insert("chaos".to_string(), Some(limit));
    }

    if let Ok(limit) = env::var("RATE_LIMIT_GITHUB") {
        let limit: u32 = limit.parse()
            .map_err(|_| RustFinderError::ConfigError("Invalid RATE_LIMIT_GITHUB".to_string()))?;
        config.rate_limits.insert("github".to_string(), Some(limit));
    }

    if let Ok(limit) = env::var("RATE_LIMIT_NETLAS") {
        let limit: u32 = limit.parse()
            .map_err(|_| RustFinderError::ConfigError("Invalid RATE_LIMIT_NETLAS".to_string()))?;
        config.rate_limits.insert("netlas".to_string(), Some(limit));
    }

    // Enabled Sources
    if let Ok(sources) = env::var("ENABLED_SOURCES") {
        config.sources = sources
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    Ok(())
}

pub fn save_config<P: AsRef<Path>>(path: P, config: &Config) -> Result<(), RustFinderError> {
    let contents = toml::to_string_pretty(config)
        .map_err(|e| RustFinderError::ConfigError(format!("Failed to serialize config: {}", e)))?;

    fs::write(path, contents)
        .map_err(|e| RustFinderError::ConfigError(format!("Failed to write config file: {}", e)))?;

    Ok(())
}

fn validate_config(config: &Config) -> Result<(), RustFinderError> {
    // Validate timeout
    if config.timeout.as_secs() == 0 {
        return Err(RustFinderError::ConfigError(
            "Timeout must be greater than 0".to_string(),
        ));
    }

    // Validate resolver configuration
    if config.resolver.threads == 0 {
        return Err(RustFinderError::ConfigError(
            "Resolver threads must be greater than 0".to_string(),
        ));
    }

    if config.resolver.nameservers.is_empty() && !config.resolver.use_system_resolver {
        return Err(RustFinderError::ConfigError(
            "No nameservers configured and system resolver is disabled".to_string(),
        ));
    }

    // Validate rate limits
    for (source, limit) in &config.rate_limits {
        if let Some(limit) = limit {
            if *limit == 0 {
                return Err(RustFinderError::ConfigError(format!(
                    "Rate limit for {} must be greater than 0",
                    source
                )));
            }
        }
    }

    Ok(())
}

pub fn create_default_config<P: AsRef<Path>>(path: P) -> Result<(), RustFinderError> {
    let config = Config::default();
    save_config(path, &config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_validate_config() {
        let mut config = Config::default();
        assert!(validate_config(&config).is_ok());

        // Test invalid timeout
        config.timeout = Duration::from_secs(0);
        assert!(validate_config(&config).is_err());
        config.timeout = Duration::from_secs(30);

        // Test invalid resolver threads
        config.resolver.threads = 0;
        assert!(validate_config(&config).is_err());
        config.resolver.threads = 50;

        // Test invalid rate limit
        config.rate_limits.insert("test".to_string(), Some(0));
        assert!(validate_config(&config).is_err());
    }
}