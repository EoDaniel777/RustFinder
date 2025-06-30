use crate::types::{Config, RustFinderError};
use std::fs;
use std::path::Path;
use std::env;

pub fn load_config(config_path_str: &str) -> Result<Config, RustFinderError> {
    let mut config = Config::default();

    if Path::new(config_path_str).exists() {
        let contents = fs::read_to_string(config_path_str)
            .map_err(|e| RustFinderError::ConfigError(format!("Falha ao ler o arquivo de configuração: {}", e)))?;
        
        let toml_config: toml::Value = toml::from_str(&contents)
            .map_err(|e| RustFinderError::ConfigError(format!("Falha ao analisar o arquivo de configuração: {}", e)))?;

        if let Some(table) = toml_config.as_table() {
            if let Some(api_keys) = table.get("api_keys") {
                if let Some(api_keys_table) = api_keys.as_table() {
                    for (key, value) in api_keys_table {
                        if let Some(value_array) = value.as_array() {
                            let keys: Vec<String> = value_array.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            config.api_keys.insert(key.clone(), keys);
                        }
                    }
                }
            }
        }
    }

    apply_env_overrides(&mut config)?;
    validate_config(&config)?;

    Ok(config)
}

fn apply_env_overrides(config: &mut Config) -> Result<(), RustFinderError> {
    if let Ok(keys) = env::var("VIRUSTOTAL_API_KEYS") {
        config.api_keys.insert("virustotal".to_string(), keys.split(',').map(|s| s.trim().to_string()).collect());
    }
    Ok(())
}

fn validate_config(config: &Config) -> Result<(), RustFinderError> {
    if config.timeout.as_secs() == 0 {
        return Err(RustFinderError::ConfigError("O timeout deve ser maior que 0".to_string()));
    }
    if config.resolver.threads == 0 {
        return Err(RustFinderError::ConfigError("As threads do resolvedor devem ser maiores que 0".to_string()));
    }
    Ok(())
}
