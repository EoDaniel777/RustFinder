use anyhow::Result;use clap::Parser;use log::{error, info};use std::process;use std::io::{self, BufRead};mod cli;mod config;mod engine;mod error;mod output;mod resolver;mod session;mod sources;mod types;mod updater;mod utils;use cli::Args;use engine::RustFinderEngine;use types::Config;const BANNER: &str = r#"    ____             __  ______ _           __         
   / __ \__  _______/ /_/ ____/(_)___  ____/ /__  _____
  / /_/ / / / / ___/ __/ /_  / / __ \/ __  / _ \/ ___/
 / _, _/ /_/ (__  ) /_/ __/ / / / / / /_/ /  __/ /    
/_/ |_|\__,_/____/\__/_/   /_/_/_/ /_\__,_/\___/_/     

        Fast Passive Subdomain Enumeration
              Made with ❤️  and 🦀
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
        return Ok(updater::check_and_update().await.map_err(|e| anyhow::anyhow!(e))?);
    }    let domains = get_domains_from_args(&args); 
    if domains.is_empty() && !args.use_stdin() {
        error!("No input provided. Use -d <domain>, -l <file>, or pipe domains to stdin");
        process::exit(1);
    }
    let mut engine = RustFinderEngine::new(args.clone()).await?;

    let stats = engine.run(domains).await.map_err(|e| anyhow::anyhow!("Enumeration failed: {}", e))?;

    if !engine.args().silent {
        info!(
            "Enumeration completed: {} subdomains found from {} sources in {:.2}s",
            stats.unique_subdomains,
            stats.sources_used.len(), // Corrected to use length of sources_used
            stats.duration.as_secs_f64()
        );
    }

    Ok(())
}fn list_sources() {    println!("Available sources:\n");

    let config = Config::default(); // Create a default config for listing sources
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
    }    // Read from stdin if available
    if atty::is(atty::Stream::Stdin) {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            if let Ok(domain) = line {
                domains.push(domain.trim().to_string());
            }
        }
    }

    domains
}