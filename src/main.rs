use anyhow::Result;use clap::Parser;use log::{error, info};use std::process;use std::io::{self, BufRead};mod cli;mod config;mod engine;mod error;mod output;mod resolver;mod session;mod sources;mod types;mod updater;mod utils;use cli::Args;use engine::RustFinderEngine;use types::Config;const BANNER: &str = r#"

        ██████╗ ██╗   ██╗███████╗████████╗███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
        ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
        ██████╔╝██║   ██║███████╗   ██║   █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
        ██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
        ██║  ██║╚██████╔╝███████║   ██║   ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
        ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝

        Fast Passive Subdomain Enumeration
         Authors: Daniel Alisom
"#;#[tokio::main]async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();    let args = Args::parse();
    if !args.silent {
        println!("{}", BANNER);
    }
    if args.list_sources {
        list_sources();
        return Ok(());
    }    if args.update {
        return updater::check_and_update().await.map_err(|e| anyhow::anyhow!(e));
    }    let domains = get_domains_from_args(&args); 
    if domains.is_empty() && !args.use_stdin() {
        error!("No input provided. Use -d <domain>, -l <file>, or pipe domains to stdin");
        process::exit(1);
    }
    let config_path = args.config_path.clone().unwrap_or_else(|| "config.toml".to_string());
    let mut engine = RustFinderEngine::new(args.clone(), &config_path).await?;

    let stats = engine.run(domains).await.map_err(|e| anyhow::anyhow!("Enumeration failed: {}", e))?;

    if !engine.args().silent {
        info!(
            "Enumeration completed: {} subdomains found from {} sources in {:.2}s",
            stats.unique_subdomains,
            stats.sources_used.len(),
            stats.duration.as_secs_f64()
        );
    }

    Ok(())
}fn list_sources() {    println!("Available sources:\n");

    let config = Config::default();
    let sources = sources::get_all_sources(&config);
    let mut default_sources = Vec::new();
    let mut api_sources = Vec::new();
    let mut free_sources = Vec::new();

    for source in sources {
        let info = source.info();
        let marker = if info.needs_key { " *" } else { "" };

        if info.is_default {
            if info.needs_key {
                api_sources.push(format!("{}{}", info.name, marker));
            } else {
                default_sources.push(format!("{}{}", info.name, marker));
            }
        } else {
            free_sources.push(format!("{}{}", info.name, marker));
        }
    }

    println!("Default sources ({})", default_sources.len());
    for source in default_sources {
        println!("  {}", source);
    }

    println!("\nAPI sources ({})", api_sources.len());
    for source in api_sources {
        println!("  {}", source);
    }

    println!("\nAdditional sources ({})", free_sources.len());
    for source in free_sources {
        println!("  {}", source);
    }

    println!("\n* = Requires API key");
    println!("\nTo configure API keys, edit: ~/.config/rustfinder/config.yaml");
}fn get_domains_from_args(args: &Args) -> Vec<String> {    let mut domains = Vec::new();

    if !args.domain.is_empty() {
        domains.extend(args.domain.clone());
    }

    if let Some(file_path) = &args.domains_file {
        match utils::read_lines(file_path) {
            Ok(lines) => {
                for domain in lines {
                    domains.push(domain.trim().to_string());
                }
            },
            Err(e) => {
                error!("Failed to read domains from file {:?}: {}", file_path, e);
            }
        }
    }
    if !atty::is(atty::Stream::Stdin) {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            if let Ok(domain) = line {
                domains.push(domain.trim().to_string());
            }
        }
    }

    domains
}