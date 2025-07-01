// src/lib.rs
pub mod cli;
pub mod config;
pub mod engine;
pub mod output;
pub mod resolver;
pub mod session;
pub mod sources;
pub mod types;
pub mod utils;

pub use cli::Args;
pub use engine::RustFinderEngine;
pub use types::{Config, RustFinderError, SubdomainResult, DomainReport};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");