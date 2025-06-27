use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustfinder",
    about = "Fast passive subdomain enumeration tool",
    long_about = "RustFinder is a high-performance passive subdomain enumeration tool written in Rust.\nIt queries multiple sources to discover subdomains without directly interacting with the target."
)]
pub struct Args {
    /// Target domain(s) to enumerate
    #[arg(short = 'd', long = "domain", value_name = "DOMAIN")]
    pub domain: Vec<String>,

    /// File containing list of domains
    #[arg(short = 'l', long = "list", value_name = "FILE")]
    pub domains_file: Option<PathBuf>,

    /// Output file
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output_file: Option<String>,

    /// Output in JSON format
    #[arg(long = "json")]
    pub json: bool,

    /// Output in CSV format
    #[arg(long = "csv")]
    pub csv: bool,

    /// Specific sources to use (comma-separated)
    #[arg(short = 's', long = "sources")]
    pub sources: Option<Vec<String>>,

    /// Silent mode (only output subdomains)
    #[arg(long = "silent")]
    pub silent: bool,

    /// Verbose mode
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Disable DNS resolution
    #[arg(long = "no-resolve")]
    pub no_resolve: bool,

    /// List all available sources
    #[arg(long = "list-sources")]
    pub list_sources: bool,

    /// Check for updates
    #[arg(long = "update")]
    pub update: bool,

    /// Configuration file path
    #[arg(short = 'c', long = "config")]
    pub config_path: Option<String>,
}

impl Args {
    /// Check if we should read from stdin
    pub fn use_stdin(&self) -> bool {
        self.domain.is_empty() && self.domains_file.is_none() && atty::is(atty::Stream::Stdin)
    }
}
