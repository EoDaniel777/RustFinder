// src/resolver.rs
use crate::types::{RustFinderError, SubdomainResult, ResolverConfig};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig as DnsResolverConfig, ResolverOpts};
use futures::stream::{FuturesUnordered, StreamExt};

pub struct Resolver {
    resolver: TokioAsyncResolver,
    semaphore: Arc<Semaphore>,
    config: ResolverConfig,
}

impl Resolver {
    pub fn new(config: ResolverConfig) -> Result<Self, RustFinderError> {
        let resolver = if config.use_system_resolver {
            TokioAsyncResolver::tokio_from_system_conf()
                .map_err(|e| RustFinderError::ResolutionError(format!("Failed to create system resolver: {}", e)))?
        } else {
            let mut resolver_config = DnsResolverConfig::new();
            
            for ns in &config.nameservers {
                let socket_addr = SocketAddr::from_str(ns)
                    .map_err(|e| RustFinderError::ConfigError(format!("Invalid nameserver address {}: {}", ns, e)))?;
                resolver_config.add_name_server(trust_dns_resolver::config::NameServerConfig {
                    socket_addr,
                    protocol: trust_dns_resolver::config::Protocol::Udp,
                    tls_dns_name: None,
                    trust_negative_responses: false,
                    bind_addr: None,
                });
            }
            
            let mut opts = ResolverOpts::default();
            opts.timeout = config.timeout;
            opts.attempts = 2;
            
            TokioAsyncResolver::tokio(resolver_config, opts)
        };

        Ok(Self {
            resolver,
            semaphore: Arc::new(Semaphore::new(config.threads)),
            config,
        })
    }

    pub async fn resolve_batch(&self, mut subdomains: Vec<SubdomainResult>) -> Result<Vec<SubdomainResult>, RustFinderError> {
        let mut futures = FuturesUnordered::new();
        
        for (idx, subdomain) in subdomains.iter().enumerate() {
            let resolver = self.resolver.clone();
            let semaphore = self.semaphore.clone();
            let hostname = subdomain.subdomain.clone();
            
            futures.push(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let ips = Self::resolve_hostname(&resolver, &hostname).await;
                (idx, ips)
            });
        }

        while let Some((idx, ips)) = futures.next().await {
            if !ips.is_empty() {
                subdomains[idx].resolved = true;
                subdomains[idx].ip_addresses = ips;
            }
        }

        Ok(subdomains)
    }

    async fn resolve_hostname(resolver: &TokioAsyncResolver, hostname: &str) -> Vec<String> {
        match resolver.lookup_ip(hostname).await {
            Ok(lookup) => {
                lookup.iter()
                    .map(|ip| ip.to_string())
                    .collect()
            }
            Err(_) => Vec::new(),
        }
    }

    pub async fn resolve_single(&self, hostname: &str) -> Result<Vec<IpAddr>, RustFinderError> {
        let _permit = self.semaphore.acquire().await
            .map_err(|e| RustFinderError::ResolutionError(format!("Failed to acquire semaphore: {}", e)))?;
            
        self.resolver
            .lookup_ip(hostname)
            .await
            .map(|lookup| lookup.iter().collect())
            .map_err(|e| RustFinderError::ResolutionError(format!("Failed to resolve {}: {}", hostname, e)))
    }
}