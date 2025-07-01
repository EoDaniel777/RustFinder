use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustfinder",
    about = "Fast passive subdomain enumeration tool",
    long_about = "RustFinder is a high-performance passive subdomain enumeration tool written in Rust.\nIt queries multiple sources to discover subdomains without directly interacting with the target."
)]
pub struct Args {

    #[arg(short = 'd', long = "domain", value_name = "DOMAIN")]
    pub domain: Vec<String>,

    #[arg(short = 'l', long = "list", value_name = "FILE")]
    pub domains_file: Option<PathBuf>,

    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output_file: Option<String>,

    #[arg(long = "json")]
    pub json: bool,

    #[arg(long = "csv")]
    pub csv: bool,

    #[arg(short = 's', long = "sources")]
    pub sources: Option<Vec<String>>,

    #[arg(long = "silent")]
    pub silent: bool,

    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    #[arg(long = "no-resolve")]
    pub no_resolve: bool,

    #[arg(long = "list-sources")]
    pub list_sources: bool,

    #[arg(long = "update")]
    pub update: bool,

    #[arg(short = 'c', long = "config")]
    pub config_path: Option<String>,
}

impl Args {

    pub fn use_stdin(&self) -> bool {
        self.domain.is_empty() && self.domains_file.is_none() && atty::is(atty::Stream::Stdin)
    }
}
