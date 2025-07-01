// src/session.rs
use crate::types::{Config, RustFinderError};
use governor::{Jitter, Quota};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use rand::seq::SliceRandom;

type MyRateLimiter = governor::DefaultKeyedRateLimiter<String>;

const USER_AGENTS: &[&str] = &[
    // Chrome on Windows (mais comum)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    
    // Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    
    // Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    
    // Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    
    // Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    
    // Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
];

#[derive(Clone)]
pub struct Session {
    pub client: Client,
    rate_limiters: Arc<HashMap<String, Arc<governor::DefaultDirectRateLimiter>>>,
    retry_attempts: u32,
    retry_delay_ms: u64,
    user_agent: String,
}

impl Session {
    pub fn new(config: &Config) -> Result<Self, RustFinderError> {

        let user_agent = Self::get_random_user_agent();
        
        let mut client_builder = Client::builder()
            .timeout(config.timeout)
            .user_agent(user_agent.clone())
            .gzip(true)
            .deflate(true)
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)

            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".parse().unwrap());
                headers.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());
                headers.insert("Accept-Encoding", "gzip, deflate, br".parse().unwrap());
                headers.insert("DNT", "1".parse().unwrap());
                headers.insert("Connection", "keep-alive".parse().unwrap());
                headers.insert("Upgrade-Insecure-Requests", "1".parse().unwrap());
                headers
            });

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| RustFinderError::ConfigError(format!("Invalid proxy URL: {}", e)))?;
            client_builder = client_builder.proxy(proxy);
        }

        let client = client_builder.build()
            .map_err(|e| RustFinderError::ConfigError(format!("Failed to build HTTP client: {}", e)))?;

        let mut rate_limiters = HashMap::new();

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
            retry_attempts: config.retry_attempts,
            retry_delay_ms: config.retry_delay_ms,
            user_agent,
        })
    }

    pub fn get_random_user_agent() -> String {
        let mut rng = rand::thread_rng();
        USER_AGENTS.choose(&mut rng)
            .unwrap_or(&USER_AGENTS[0])
            .to_string()
    }

    pub fn get_user_agent(&self) -> &str {
        &self.user_agent
    }

    pub async fn check_rate_limit(&self, source: &str) -> Result<(), RustFinderError> {
        if let Some(limiter) = self.rate_limiters.get(source) {

            limiter.until_ready().await;
        }
        Ok(())
    }

    pub async fn get(&self, url: &str, source_name: &str) -> Result<reqwest::Response, RustFinderError> {
        self.send_request_with_retry(self.client.get(url), source_name).await
    }

    pub async fn post(&self, url: &str, body: String, source_name: &str) -> Result<reqwest::Response, RustFinderError> {
        self.send_request_with_retry(
            self.client.post(url)
                .header("Content-Type", "application/json")
                .body(body),
            source_name
        ).await
    }

    pub async fn get_json<T>(&self, url: &str, source_name: &str) -> Result<T, RustFinderError>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self.get(url, source_name).await?;
        let text = response.text().await.map_err(|e| RustFinderError::NetworkError(e.to_string()))?;

        serde_json::from_str(&text).map_err(|e| {
            RustFinderError::JsonParseError(e.to_string(), text)
        })
    }

    pub async fn post_json<T, R>(&self, url: &str, json: &T, source_name: &str) -> Result<R, RustFinderError>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self.send_request_with_retry(self.client.post(url).json(json), source_name).await?;

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

    pub async fn send_request_with_retry(&self, request_builder: reqwest::RequestBuilder, source_name: &str) -> Result<reqwest::Response, RustFinderError> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let request = request_builder.try_clone()
                .ok_or_else(|| RustFinderError::NetworkError("Failed to clone request builder".to_string()))?;
            
            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(response);
                    } else if response.status().as_u16() == 429 || response.status().is_server_error() {
                        let retry_after = response.headers()
                            .get("Retry-After")
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok());

                        let delay = if let Some(seconds) = retry_after {
                            Duration::from_secs(seconds)
                        } else {

                            let base_delay = self.retry_delay_ms * 2u64.pow(attempts - 1);
                            let jitter = rand::random::<u64>() % (base_delay / 4);
                            Duration::from_millis(base_delay + jitter)
                        };

                        log::warn!("[{}] Rate limit hit or server error ({}). Retrying in {:?}. Attempt {}/{}", 
                                   source_name, response.status(), delay, attempts, self.retry_attempts);

                        if attempts >= self.retry_attempts {
                            return Err(RustFinderError::RateLimitExceeded {
                                source_name: source_name.to_string(),
                                message: format!("Max retries ({}) exceeded for status {}", self.retry_attempts, response.status()),
                            });
                        }
                        tokio::time::sleep(delay).await;
                    } else {
                        return Err(RustFinderError::NetworkError(format!(
                            "HTTP error: {} - {}",
                            response.status(),
                            response.text().await.unwrap_or_default()
                        )));
                    }
                },
                Err(e) => {
                    log::warn!("[{}] Network error: {}. Attempt {}/{}", source_name, e, attempts, self.retry_attempts);
                    if attempts >= self.retry_attempts {
                        return Err(RustFinderError::NetworkError(format!("Max retries ({}) exceeded for network error: {}", self.retry_attempts, e)));
                    }
                    let delay = Duration::from_millis(self.retry_delay_ms * 2u64.pow(attempts - 1));
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}