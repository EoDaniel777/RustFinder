// src/sources/mod.rs
use crate::types::{Config, RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;

// Importar os módulos dos sources
mod virustotal;
mod securitytrails;
mod shodan;
mod chaos;
mod github;
mod netlas;
mod stubs;
mod certsh;
mod hackertarget;

// Re-exportar as implementações específicas
pub use virustotal::VirusTotalSource;
pub use securitytrails::SecurityTrailsSource;
pub use shodan::ShodanSource;
pub use chaos::ChaosSource;
pub use github::GitHubSource;
pub use netlas::NetlasSource;
pub use certsh::CrtShSource;
pub use hackertarget::HackerTargetSource;

// Definir a trait Source
#[async_trait]
pub trait Source: Send + Sync {
    fn name(&self) -> &str;
    fn info(&self) -> SourceInfo;
    async fn enumerate(&self, domain: &str, session: &Session) -> Result<Vec<SubdomainResult>, RustFinderError>;
    fn clone_source(&self) -> Box<dyn Source>;
}

// Função para criar sources dinamicamente com configuração
pub fn create_source(name: &str, config: &Config) -> Option<Box<dyn Source>> {
    // Obter as API keys da configuração
    let api_keys = config.api_keys.get(name)
        .cloned()
        .unwrap_or_else(Vec::new);

    match name.to_lowercase().as_str() {
        "virustotal" => {
            let source = VirusTotalSource::new().with_api_keys(api_keys);
            Some(Box::new(source))
        },
        "securitytrails" => {
            let source = SecurityTrailsSource::new().with_api_keys(api_keys);
            Some(Box::new(source))
        },
        "shodan" => {
            let source = ShodanSource::new().with_api_keys(api_keys);
            Some(Box::new(source))
        },
        "chaos" => {
            let source = ChaosSource::new().with_api_keys(api_keys);
            Some(Box::new(source))
        },
        "github" => {
            let source = GitHubSource::new().with_api_keys(api_keys);
            Some(Box::new(source))
        },
        "netlas" => {
            let source = NetlasSource::new().with_api_keys(api_keys);
            Some(Box::new(source))
        },
        "crtsh" => {
            let source = CrtShSource::new();
            Some(Box::new(source))
        },
        "hackertarget" => {
            let source = HackerTargetSource::new();
            Some(Box::new(source))
        },
        _ => None,
    }
}

// Função para obter todos os sources disponíveis com configuração
pub fn get_all_sources(config: &Config) -> Vec<Box<dyn Source>> {
    vec![
        "virustotal",
        "securitytrails", 
        "shodan",
        "chaos",
        "github",
        "netlas",
        "crtsh",
        "hackertarget",
    ]
    .into_iter()
    .filter_map(|name| create_source(name, config))
    .collect()
}

// Função auxiliar para verificar se um source precisa de API key
pub fn requires_api_key(source_name: &str) -> bool {
    matches!(
        source_name.to_lowercase().as_str(),
        "virustotal" | "securitytrails" | "shodan" | "chaos" | "github" | "netlas"
    )
}

// Testes
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Config;

    #[test]
    fn test_create_source() {
        let config = Config::default();
        
        let source = create_source("virustotal", &config);
        assert!(source.is_some());
        
        let source = create_source("invalid", &config);
        assert!(source.is_none());
    }

    #[test]
    fn test_requires_api_key() {
        assert!(requires_api_key("virustotal"));
        assert!(requires_api_key("shodan"));
        assert!(!requires_api_key("invalid"));
    }
}