use crate::cli::Args;
use crate::config;
use crate::output::OutputManager;
use crate::resolver::Resolver;
use crate::session::Session;
use crate::sources::{create_source, get_all_sources, Source};
use crate::types::{Config, DomainReport, EnumerationStats, RustFinderError, SubdomainResult};
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration as TokioDuration};

pub struct RustFinderEngine {
    config: Config,
    session: Session,
    sources: Vec<Box<dyn Source>>,
    resolver: Option<Arc<Resolver>>,
    output_manager: OutputManager,
    args: Args,
}

impl RustFinderEngine {
    pub async fn new(args: Args, config_path_str: &str) -> Result<Self, RustFinderError> {
        let mut config = config::load_config(config_path_str)?;

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
        let session = Session::new(&config)?;
        let sources = if let Some(source_names) = &args.sources {
            let mut sources = Vec::new();
            for name in source_names {
                if let Some(source) = create_source(name, &config) {
                    sources.push(source);
                } else {
                    warn!("[Engine] Fonte desconhecida: {}", name);
                }
            }
            sources
        } else {
            get_all_sources(&config)
        };

        if sources.is_empty() {
            return Err(RustFinderError::ConfigError(
                "Nenhuma fonte válida configurada".to_string(),
            ));
        }
        info!("[Engine] {} fontes inicializadas", sources.len());

        let resolver = if config.resolver.enabled {
            Some(Arc::new(Resolver::new(config.resolver.clone())?))
        } else {
            None
        };

        let output_manager = OutputManager::new(config.output.clone());

        Ok(Self {
            config,
            session,
            sources,
            resolver,
            output_manager,
            args,
        })
    }

    pub fn args(&self) -> &Args {
        &self.args
    }

    pub async fn run(&mut self, domains: Vec<String>) -> Result<EnumerationStats, RustFinderError> {
        if domains.is_empty() {
            return Err(RustFinderError::ConfigError(
                "Nenhum domínio fornecido".to_string(),
            ));
        }

        info!("[Engine] Iniciando enumeração para {} domínios", domains.len());
        let start_time = Instant::now();
        let mut total_found = 0;
        let mut unique_subdomains = 0;
        let mut resolved_count = 0;

        for domain in domains {
            match self.enumerate_domain(&domain).await {
                Ok(report) => {
                    total_found += report.stats.total_found;
                    unique_subdomains += report.stats.unique_subdomains;
                    resolved_count += report.stats.resolved_count;
                    self.output_manager.write_report(&report).await?;
                    info!(
                        "[Engine] Enumeração para {} concluída: {} subdomínios únicos encontrados",
                        domain,
                        report.stats.unique_subdomains
                    );
                }
                Err(e) => {
                    error!("[Engine] Falha ao enumerar {}: {}", domain, e);
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
        if !Self::is_valid_domain(domain) {
            return Err(RustFinderError::InvalidDomain(domain.to_string()));
        }

        info!("[Engine] Enumerando subdomínios para: {}", domain);
        let start_time = Instant::now();
        let subdomains = self.enumerate_domain_internal(domain).await?;
        let unique_subdomains_count = subdomains.len();
        let resolved_count = subdomains.iter().filter(|s| s.resolved).count();

        let stats = EnumerationStats {
            total_found: unique_subdomains_count,
            unique_subdomains: unique_subdomains_count,
            resolved_count,
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
        let all_results = Arc::new(Mutex::new(HashMap::new()));
        let mut futures = FuturesUnordered::new();
        let timeout_duration = TokioDuration::from_secs(self.config.timeout.as_secs());

        for source in &self.sources {
            let source_name = source.name().to_string();
            let domain = domain.to_string();
            let session = self.session.clone();
            let source = source.clone_source();
            let all_results_clone = all_results.clone();

            futures.push(async move {
                debug!("[{}] Iniciando enumeração para {}", source_name, domain);
                match timeout(timeout_duration, source.enumerate(&domain, &session)).await {
                    Ok(Ok(subdomains)) => {
                        let mut results_guard = all_results_clone.lock().await;
                        for subdomain in subdomains {
                            let key = subdomain.subdomain.to_lowercase();
                            results_guard.entry(key).or_insert(subdomain);
                        }
                        debug!("[{}] Enumeração concluída", source_name);
                    }
                    Ok(Err(e)) => {
                        warn!("[{}] Erro: {}", source_name, e);
                    }
                    Err(_) => {
                        warn!("[{}] Timeout", source_name);
                    }
                }
            });
        }

        futures.collect::<()>().await;

        let mut results: Vec<SubdomainResult> = Arc::try_unwrap(all_results)
            .unwrap()
            .into_inner()
            .into_values()
            .collect();

        if results.is_empty() {
            warn!("[Engine] Nenhuma fonte retornou subdomínios.");
        }

        if let Some(resolver) = &self.resolver {
            info!("[Engine] Resolvendo {} subdomínios...", results.len());
            results = resolver.resolve_batch(results).await?;
        }

        results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
        Ok(results)
    }

    fn is_valid_domain(domain: &str) -> bool {
        !domain.is_empty() && domain.len() <= 253 && domain.split('.').count() >= 2
    }
}
