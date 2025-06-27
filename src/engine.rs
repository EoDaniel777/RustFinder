use crate::cli::Args;
use crate::config;
use crate::output::OutputManager;
use crate::resolver::Resolver;
use crate::session::Session;
use crate::sources::{create_source, get_all_sources, Source};
use crate::types::{Config, DomainReport, EnumerationStats, RustFinderError, SubdomainResult};
use futures::stream::{FuturesUnordered, StreamExt};
use log::{error, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

pub struct RustFinderEngine {
    config: Config,
    session: Session,
    sources: Vec<Box<dyn Source>>,
    resolver: Option<Arc<Resolver>>,
    output_manager: OutputManager,
    results_cache: Arc<Mutex<HashMap<String, HashSet<SubdomainResult>>>>,
    args: Args,
}

impl RustFinderEngine {
    pub async fn new(args: Args) -> Result<Self, RustFinderError> {
        // Load configuration
        let mut config = if let Some(config_path_str) = args.config_path.as_deref() {
            config::load_config(config_path_str)?
        } else {
            Config::default()
        };

        // Override config with command line arguments
        if let Some(output_file_val) = args.output_file.clone() {
            config.output.file = Some(output_file_val);
        }
        if args.verbose {
            config.output.verbose = true;
        }
        if args.json {
            config.output.format = crate::types::OutputFormat::Json;
        }
        if args.csv {
            config.output.format = crate::types::OutputFormat::Csv;
        }
        if args.no_resolve {
            config.resolver.enabled = false;
        }

        Self::new_with_args_and_config(args, config).await
    }

    async fn new_with_args_and_config(
        args: Args,
        config: Config,
    ) -> Result<Self, RustFinderError> {
        // Create session
        let session = Session::new(&config)?;

        // Initialize sources with configuration
        let sources = if let Some(source_names) = &args.sources {
            let mut sources = Vec::new();
            for name in source_names {
                if let Some(source) = create_source(name, &config) {
                    sources.push(source);
                } else {
                    warn!("Unknown source: {}", name);
                }
            }
            sources
        } else if !config.sources.is_empty() {
            let mut sources = Vec::new();
            for name in &config.sources {
                if let Some(source) = create_source(name, &config) {
                    sources.push(source);
                } else {
                    warn!("Unknown source: {}", name);
                }
            }
            sources
        } else {
            get_all_sources(&config)
        };

        if sources.is_empty() {
            return Err(RustFinderError::ConfigError(
                "No valid sources configured".to_string(),
            ));
        }

        // Initialize resolver if enabled
        let resolver = if config.resolver.enabled {
            Some(Arc::new(Resolver::new(config.resolver.clone())?))
        } else {
            None
        };

        // Initialize output manager
        let output_manager = OutputManager::new(config.output.clone());

        Ok(Self {
            config,
            session,
            sources,
            resolver,
            output_manager,
            results_cache: Arc::new(Mutex::new(HashMap::new())),
            args,
        })
    }

    pub fn args(&self) -> &Args {
        &self.args
    }

    pub async fn run(&mut self, domains: Vec<String>) -> Result<EnumerationStats, RustFinderError> {
        if domains.is_empty() {
            return Err(RustFinderError::ConfigError(
                "No domains provided".to_string(),
            ));
        }

        info!("Starting enumeration for {} domains", domains.len());
        let start_time = Instant::now();
        let mut total_found = 0;
        let mut unique_subdomains = 0;
        let mut resolved_count = 0;

        // Process each domain
        for domain in domains {
            match self.enumerate_domain(&domain).await {
                Ok(report) => {
                    total_found += report.stats.total_found;
                    unique_subdomains += report.stats.unique_subdomains;
                    resolved_count += report.stats.resolved_count;
                    // Output results
                    self.output_manager.write_report(&report).await?;

                    info!(
                        "Completed enumeration for {}: found {} unique subdomains",
                        domain,
                        report.stats.unique_subdomains
                    );
                }
                Err(e) => {
                    error!("Failed to enumerate {}: {}", domain, e);
                    if self.config.output.verbose {
                        eprintln!("Error details: {:?}", e);
                    }
                }
            }
        }

        let stats = EnumerationStats {
            total_found,
            unique_subdomains,
            resolved_count,
            sources_used: self.sources.iter().map(|s| s.name().to_string()).collect(),
            duration: start_time.elapsed(),
        };

        Ok(stats)
    }

    pub async fn enumerate_domain(&mut self, domain: &str) -> Result<DomainReport, RustFinderError> {
        // Validate domain
        if !Self::is_valid_domain(domain) {
            return Err(RustFinderError::InvalidDomain(domain.to_string()));
        }

        info!("Enumerating subdomains for: {}", domain);
        let start_time = Instant::now();

        // Enumerate using all configured sources
        let subdomains = self.enumerate_domain_internal(domain).await?;

        // Create report
        let stats = EnumerationStats {
            total_found: subdomains.len(),
            unique_subdomains: subdomains.len(),
            resolved_count: subdomains.iter().filter(|s| s.resolved).count(),
            sources_used: self.sources.iter().map(|s| s.name().to_string()).collect(),
            duration: start_time.elapsed(),
        };

        let report = DomainReport {
            domain: domain.to_string(),
            subdomains,
            stats,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        Ok(report)
    }

    async fn enumerate_domain_internal(
        &mut self,
        domain: &str,
    ) -> Result<Vec<SubdomainResult>, RustFinderError> {
        let mut all_results = HashMap::new();
        let mut futures = FuturesUnordered::new();

        // Create tasks for each source
        for source in &self.sources {
            let source_name = source.name().to_string();
            let domain = domain.to_string();
            let session = self.session.clone();
            let source = source.clone_source();

            futures.push(async move {
                let start = Instant::now();
                let result = source.enumerate(&domain, &session).await;
                let duration = start.elapsed();

                match &result {
                    Ok(subdomains) => {
                        info!(
                            "{}: Found {} subdomains for {} in {:?}",
                            source_name,
                            subdomains.len(),
                            domain,
                            duration
                        );
                    }
                    Err(e) => {
                        error!("{}: Failed to enumerate {}: {}", source_name, domain, e);
                    }
                }

                result
            });
        }

        // Collect results from all sources
        while let Some(result) = futures.next().await {
            if let Ok(subdomains) = result {
                for subdomain in subdomains {
                    let key = subdomain.subdomain.to_lowercase();
                    all_results
                        .entry(key)
                        .and_modify(|existing: &mut SubdomainResult| {
                            // Merge IP addresses if both have them
                            for ip in &subdomain.ip_addresses {
                                if !existing.ip_addresses.contains(ip) {
                                    existing.ip_addresses.push(ip.clone());
                                }
                            }
                            // Update resolved status
                            if subdomain.resolved {
                                existing.resolved = true;
                            }
                        })
                        .or_insert(subdomain);
                }
            }
        }

        // Convert to vector
        let mut results: Vec<SubdomainResult> = all_results.into_values().collect();

        // Resolve subdomains if enabled
        if let Some(resolver) = &self.resolver {
            info!("Resolving {} subdomains...", results.len());
            let resolved_results = resolver.resolve_batch(results).await?;
            results = resolved_results;
        }

        // Sort results
        results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

        Ok(results)
    }

    fn is_valid_domain(domain: &str) -> bool {
        // Basic domain validation
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }

        // Check for valid characters and structure
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return false;
        }

        for part in parts {
            if part.is_empty() || part.len() > 63 {
                return false;
            }

            // Check for valid characters
            if !part.chars().all(|c| c.is_alphanumeric() || c == '-') {
                return false;
            }

            // Cannot start or end with hyphen
            if part.starts_with('-') || part.ends_with('-') {
                return false;
            }
        }

        true
    }
}