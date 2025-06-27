// src/output.rs
use crate::types::{OutputFormat, OutputConfig, RustFinderError, SubdomainResult, DomainReport};
use std::io::Write;
use std::fs::File;
use std::path::Path;
use serde_json;

pub struct OutputManager {
    config: OutputConfig,
}

impl OutputManager {
    pub fn new(config: OutputConfig) -> Self {
        Self { config }
    }

    pub async fn write_report(&self, report: &DomainReport) -> Result<(), RustFinderError> {
        if let Some(file_path) = &self.config.file {
            self.write_to_file(file_path, report).await
        } else {
            self.write_to_stdout(report).await
        }
    }

    async fn write_to_file(&self, file_path: &str, report: &DomainReport) -> Result<(), RustFinderError> {
        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(file_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RustFinderError::OutputError(format!("Failed to create directory: {}", e)))?;
        }

        let mut file = File::create(file_path)
            .map_err(|e| RustFinderError::OutputError(format!("Failed to create file: {}", e)))?;
            
        self.write_output(&mut file, report)?;
        
        println!("Results written to: {}", file_path);
        Ok(())
    }

    async fn write_to_stdout(&self, report: &DomainReport) -> Result<(), RustFinderError> {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        self.write_output(&mut handle, report)?;
        Ok(())
    }

    fn write_output<W: Write>(&self, writer: &mut W, report: &DomainReport) -> Result<(), RustFinderError> {
        match self.config.format {
            OutputFormat::Text => self.write_text_output(writer, report),
            OutputFormat::Json => self.write_json_output(writer, report),
            OutputFormat::Csv => self.write_csv_output(writer, report),
        }
    }

    fn write_text_output<W: Write>(&self, writer: &mut W, report: &DomainReport) -> Result<(), RustFinderError> {
        writeln!(writer, "\n[*] Domain: {}", report.domain)
            .map_err(|e| RustFinderError::OutputError(e.to_string()))?;
        writeln!(writer, "[*] Found {} unique subdomains", report.stats.unique_subdomains)
            .map_err(|e| RustFinderError::OutputError(e.to_string()))?;
        writeln!(writer, "[*] Resolved: {}/{}", report.stats.resolved_count, report.stats.unique_subdomains)
            .map_err(|e| RustFinderError::OutputError(e.to_string()))?;
        writeln!(writer, "[*] Duration: {:?}", report.stats.duration)
            .map_err(|e| RustFinderError::OutputError(e.to_string()))?;
        writeln!(writer, "\n[*] Results:")
            .map_err(|e| RustFinderError::OutputError(e.to_string()))?;

        for subdomain in &report.subdomains {
            if self.config.include_ips && !subdomain.ip_addresses.is_empty() {
                writeln!(
                    writer,
                    "{} [{}] - {}",
                    subdomain.subdomain,
                    subdomain.source,
                    subdomain.ip_addresses.join(", ")
                ).map_err(|e| RustFinderError::OutputError(e.to_string()))?;
            } else {
                writeln!(
                    writer,
                    "{} [{}]",
                    subdomain.subdomain,
                    subdomain.source
                ).map_err(|e| RustFinderError::OutputError(e.to_string()))?;
            }
        }

        Ok(())
    }

    fn write_json_output<W: Write>(&self, writer: &mut W, report: &DomainReport) -> Result<(), RustFinderError> {
        let json = serde_json::to_string_pretty(report)
            .map_err(|e| RustFinderError::OutputError(format!("Failed to serialize JSON: {}", e)))?;
        
        writeln!(writer, "{}", json)
            .map_err(|e| RustFinderError::OutputError(e.to_string()))?;
        
        Ok(())
    }

    fn write_csv_output<W: Write>(&self, writer: &mut W, report: &DomainReport) -> Result<(), RustFinderError> {
        // Write CSV header
        if self.config.include_ips {
            writeln!(writer, "subdomain,source,resolved,ip_addresses")
                .map_err(|e| RustFinderError::OutputError(e.to_string()))?;
        } else {
            writeln!(writer, "subdomain,source,resolved")
                .map_err(|e| RustFinderError::OutputError(e.to_string()))?;
        }

        // Write CSV rows
        for subdomain in &report.subdomains {
            if self.config.include_ips {
                writeln!(
                    writer,
                    "{},{},{},\"{}\"",
                    subdomain.subdomain,
                    subdomain.source,
                    subdomain.resolved,
                    subdomain.ip_addresses.join(", ")
                ).map_err(|e| RustFinderError::OutputError(e.to_string()))?;
            } else {
                writeln!(
                    writer,
                    "{},{},{}",
                    subdomain.subdomain,
                    subdomain.source,
                    subdomain.resolved
                ).map_err(|e| RustFinderError::OutputError(e.to_string()))?;
            }
        }

        Ok(())
    }

    pub async fn write_subdomains(&self, subdomains: &[SubdomainResult]) -> Result<(), RustFinderError> {
        if self.config.verbose {
            for subdomain in subdomains {
                if self.config.include_ips && !subdomain.ip_addresses.is_empty() {
                    println!(
                        "[{}] {} - {}",
                        subdomain.source,
                        subdomain.subdomain,
                        subdomain.ip_addresses.join(", ")
                    );
                } else {
                    println!("[{}] {}", subdomain.source, subdomain.subdomain);
                }
            }
        }
        Ok(())
    }
}