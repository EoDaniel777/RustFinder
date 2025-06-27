// src/session.rs
use crate::types::{Config, RustFinderError};
use governor::{Jitter, Quota};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

type MyRateLimiter = governor::DefaultKeyedRateLimiter<String>;

#[derive(Clone)]
pub struct Session {
    pub client: Client,
    rate_limiters: Arc<HashMap<String, Arc<governor::DefaultDirectRateLimiter>>>,
}

impl Session {
    pub fn new(config: &Config) -> Result<Self, RustFinderError> {
        // Build HTTP client
        let mut client_builder = Client::builder()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .gzip(true)
            .deflate(true) // Use deflate instead of brotli
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10);

        // Add proxy if configured
        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| RustFinderError::ConfigError(format!("Invalid proxy URL: {}", e)))?;
            client_builder = client_builder.proxy(proxy);
        }

        let client = client_builder.build()
            .map_err(|e| RustFinderError::ConfigError(format!("Failed to build HTTP client: {}", e)))?;

        // Initialize rate limiters for each source
        let mut rate_limiters = HashMap::new();
        
        // Create rate limiters with proper configuration
        for (source, rate_limit) in &config.rate_limits {
            if let Some(limit) = rate_limit {
                let quota = Quota::per_second(std::num::NonZeroU32::new(*limit).unwrap())
                    .allow_burst(std::num::NonZeroU32::new(1).unwrap());
                let limiter = Arc::new(governor::RateLimiter::direct(quota));
                rate_limiters.insert(source.clone(), limiter);
            }
        }

        Ok(Session {
            client,
            rate_limiters: Arc::new(rate_limiters),
        })
    }

    pub async fn check_rate_limit(&self, source: &str) -> Result<(), RustFinderError> {
        if let Some(limiter) = self.rate_limiters.get(source) {
            // Wait until we're allowed to proceed
            limiter.until_ready().await;
        }
        Ok(())
    }

    pub async fn get(&self, url: &str) -> Result<reqwest::Response, RustFinderError> {
        self.client
            .get(url)
            .send()
            .await
            .map_err(|e| RustFinderError::NetworkError(e.to_string()))
    }

    pub async fn get_with_retry(
        &self,
        url: &str,
        max_retries: u32,
    ) -> Result<reqwest::Response, RustFinderError> {
        let mut retries = 0;
        loop {
            match self.get(url).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if retries >= max_retries {
                        return Err(e);
                    }
                    retries += 1;
                    
                    // Exponential backoff
                    let delay = Duration::from_millis(100 * 2u64.pow(retries));
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    pub async fn get_json<T>(&self, url: &str) -> Result<T, RustFinderError>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self.get(url).await?;
        
        if !response.status().is_success() {
            return Err(RustFinderError::NetworkError(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        response
            .json::<T>()
            .await
            .map_err(|e| RustFinderError::ParseError(e.to_string()))
    }

    pub async fn post(&self, url: &str, body: String) -> Result<reqwest::Response, RustFinderError> {
        self.client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| RustFinderError::NetworkError(e.to_string()))
    }

    pub async fn post_json<T, R>(&self, url: &str, json: &T) -> Result<R, RustFinderError>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self.client
            .post(url)
            .json(json)
            .send()
            .await
            .map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(RustFinderError::NetworkError(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        response
            .json::<R>()
            .await
            .map_err(|e| RustFinderError::ParseError(e.to_string()))
    }

    // Rate limit check with specific source
    pub async fn wait_for_rate_limit(&self, source: &str) -> Result<(), RustFinderError> {
        if let Some(limiter) = self.rate_limiters.get(source) {
            limiter.until_ready_with_jitter(Jitter::up_to(Duration::from_millis(100))).await;
        }
        Ok(())
    }
}