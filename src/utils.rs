// src/utils.rs
use crate::types::RustFinderError;
use regex::Regex;
use std::collections::HashSet;
use url::Url;
use std::fs::File;
use std::io::{self, BufReader, BufRead};
use std::path::PathBuf;

pub fn read_lines(path: &PathBuf) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    reader.lines().collect()
}

pub fn extract_domain_from_url(url_str: &str) -> Result<String, RustFinderError> {
    let url = Url::parse(url_str)
        .map_err(|e| RustFinderError::InvalidDomain(format!("Invalid URL: {}", e)))?;
    
    url.host_str()
        .ok_or_else(|| RustFinderError::InvalidDomain("No host in URL".to_string()))
        .map(|s| s.to_string())
}

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    for part in parts {
        if part.is_empty() || part.len() > 63 {
            return false;
        }
        
        if !part.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
        
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }

    true
}

pub fn extract_subdomains_from_text(text: &str, domain: &str) -> Result<Vec<String>, RustFinderError> {
    let pattern = format!(
        r"(?i)(?:^|[^a-zA-Z0-9.-])([a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?)*\.{})",
        regex::escape(domain)
    );
    
    let re = Regex::new(&pattern)
        .map_err(|e| RustFinderError::ParseError(format!("Regex error: {}", e)))?;
    
    let mut subdomains = HashSet::new();
    
    for cap in re.captures_iter(text) {
        if let Some(subdomain) = cap.get(1) {
            let subdomain_str = subdomain.as_str().to_lowercase();
            if subdomain_str != domain && !subdomain_str.contains("..") {
                subdomains.insert(subdomain_str);
            }
        }
    }
    
    Ok(subdomains.into_iter().collect())
}

pub fn clean_subdomain(subdomain: &str, domain: &str) -> String {
    let mut cleaned = subdomain.trim().to_lowercase();
    
    while cleaned.ends_with('.') {
        cleaned.pop();
    }
    
    if !cleaned.ends_with(domain) && !cleaned.is_empty() {
        cleaned = format!("{}.{}", cleaned, domain);
    }
    
    cleaned
}

pub fn parse_wildcard(pattern: &str) -> Result<Regex, RustFinderError> {
    if !pattern.contains('*') {
        return Err(RustFinderError::InvalidDomain(
            "Pattern must contain wildcard (*)".to_string()
        ));
    }
    
    let escaped = regex::escape(pattern);
    let regex_pattern = escaped.replace(r"\*", ".*");
    
    Regex::new(&format!("^{}$", regex_pattern))
        .map_err(|e| RustFinderError::ParseError(
            format!("Invalid wildcard pattern: {}", e)
        ))
}

pub fn filter_by_wildcard(subdomains: Vec<String>, pattern: &str) -> Result<Vec<String>, RustFinderError> {
    let re = parse_wildcard(pattern)?;
    
    Ok(subdomains
        .into_iter()
        .filter(|s| re.is_match(s))
        .collect())
}

pub fn deduplicate_subdomains(subdomains: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    
    for subdomain in subdomains {
        let lower = subdomain.to_lowercase();
        if seen.insert(lower.clone()) {
            unique.push(subdomain);
        }
    }
    
    unique
}

pub fn sort_by_level(mut subdomains: Vec<String>) -> Vec<String> {
    subdomains.sort_by(|a, b| {
        let a_parts = a.split('.').count();
        let b_parts = b.split('.').count();
        a_parts.cmp(&b_parts).then(a.cmp(b))
    });
    
    subdomains
}

pub fn terminal_width() -> usize {
    term_size::dimensions().map(|(w, _)| w).unwrap_or(80)
}

pub fn progress_message(current: usize, total: usize, message: &str) -> String {
    let _width = terminal_width();
    let progress_width = 20;
    let filled = (current as f32 / total as f32 * progress_width as f32) as usize;
    let empty = progress_width - filled;
    
    format!(
        "[{}{}] {}/{} - {}",
        "=".repeat(filled),
        " ".repeat(empty),
        current,
        total,
        message
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(!is_valid_domain("example"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example-.com"));
    }

    #[test]
    fn test_clean_subdomain() {
        assert_eq!(clean_subdomain("sub.", "example.com"), "sub.example.com");
        assert_eq!(clean_subdomain("SUB", "example.com"), "sub.example.com");
        assert_eq!(clean_subdomain("sub.example.com", "example.com"), "sub.example.com");
    }

    #[test]
    fn test_deduplicate_subdomains() {
        let subdomains = vec![
            "sub1.example.com".to_string(),
            "SUB1.example.com".to_string(),
            "sub2.example.com".to_string(),
        ];
        
        let unique = deduplicate_subdomains(subdomains);
        assert_eq!(unique.len(), 2);
    }
}