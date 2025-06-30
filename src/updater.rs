use crate::types::RustFinderError;
use log::{info, warn, error};
use serde::Deserialize;
use std::env;

const GITHUB_API_URL: &str = "https://api.github.com/repos/rustfinder/rustfinder/releases/latest";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: String,
    body: String,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    content_type: String,
    size: u64,
}

/// Check for updates and optionally install them
pub async fn check_and_update() -> Result<(), RustFinderError> {
    info!("Checking for updates...");
    
    match check_for_updates().await {
        Ok(Some(latest_version)) => {
            info!("New version available: {} (current: {})", latest_version, CURRENT_VERSION);
            
            if should_auto_update() {
                info!("Attempting to update...");
                perform_update().await?;
            } else {
                info!("To update manually, visit: https://github.com/rustfinder/rustfinder/releases/latest");
            }
        }
        Ok(None) => {
            info!("RustFinder is up to date (version {})", CURRENT_VERSION);
        }
        Err(e) => {
            warn!("Failed to check for updates: {}", e);
        }
    }
    
    Ok(())
}

/// Check if a newer version is available
async fn check_for_updates() -> Result<Option<String>, RustFinderError> {
    let client = reqwest::Client::new();
    
    let response = client
        .get(GITHUB_API_URL)
        .header("User-Agent", format!("RustFinder/{}", CURRENT_VERSION))
        .send()
        .await
        .map_err(RustFinderError::HttpError)?;

    if !response.status().is_success() {
        return Err(RustFinderError::HttpError(
            response.error_for_status().unwrap_err()
        ));
    }

    let release: GitHubRelease = response
        .json()
        .await
        .map_err(RustFinderError::HttpError)?;

    let latest_version = release.tag_name.trim_start_matches('v');
    
    if is_newer_version(latest_version, CURRENT_VERSION) {
        Ok(Some(latest_version.to_string()))
    } else {
        Ok(None)
    }
}

/// Compare version strings to determine if update is needed
fn is_newer_version(latest: &str, current: &str) -> bool {
    use std::cmp::Ordering;
    
    let parse_version = |v: &str| -> Vec<u32> {
        v.split('.')
            .map(|s| s.parse().unwrap_or(0))
            .collect()
    };
    
    let latest_parts = parse_version(latest);
    let current_parts = parse_version(current);
    
    match latest_parts.partial_cmp(&current_parts) {
        Some(Ordering::Greater) => true,
        _ => false,
    }
}

/// Determine if auto-update should be performed
fn should_auto_update() -> bool {
    // Check environment variable
    if let Ok(auto_update) = env::var("RUSTFINDER_AUTO_UPDATE") {
        return auto_update.to_lowercase() == "true" || auto_update == "1";
    }
    
    // Default to false for security
    false
}

/// Perform the actual update using self_update crate
async fn perform_update() -> Result<(), RustFinderError> {
    #[cfg(feature = "self-update")]
    {
        use self_update::cargo_crate_version;
        
        let status = self_update::backends::github::Update::configure()
            .repo_owner("rustfinder")
            .repo_name("rustfinder")
            .bin_name("rustfinder")
            .show_download_progress(true)
            .current_version(cargo_crate_version!())
            .build()
            .map_err(|e| RustFinderError::ConfigError(format!("Update configuration failed: {}", e)))?
            .update()
            .map_err(|e| RustFinderError::ConfigError(format!("Update failed: {}", e)))?;

        info!("Update status: {:?}", status);
        Ok(())
    }
    
    #[cfg(not(feature = "self-update"))]
    {
        error!("Self-update feature not enabled. Please update manually.");
        Err(RustFinderError::ConfigError(
            "Self-update not supported in this build".to_string()
        ))
    }
}

/// Get update information without installing
pub async fn get_update_info() -> Result<Option<UpdateInfo>, RustFinderError> {
    let client = reqwest::Client::new();
    
    let response = client
        .get(GITHUB_API_URL)
        .header("User-Agent", format!("RustFinder/{}", CURRENT_VERSION))
        .send()
        .await
        .map_err(RustFinderError::HttpError)?;

    if !response.status().is_success() {
        return Ok(None);
    }

    let release: GitHubRelease = response
        .json()
        .await
        .map_err(RustFinderError::HttpError)?;

    let latest_version = release.tag_name.trim_start_matches('v');
    
    if is_newer_version(latest_version, CURRENT_VERSION) {
        Ok(Some(UpdateInfo {
            current_version: CURRENT_VERSION.to_string(),
            latest_version: latest_version.to_string(),
            release_notes: release.body,
            download_url: format!("https://github.com/rustfinder/rustfinder/releases/tag/{}", release.tag_name),
        }))
    } else {
        Ok(None)
    }
}

/// Information about available updates
#[derive(Debug)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub release_notes: String,
    pub download_url: String,
}

/// Show update information in a user-friendly format
pub fn display_update_info(info: &UpdateInfo) {
    println!("🦀 RustFinder Update Available!");
    println!("Current version: {}", info.current_version);
    println!("Latest version:  {}", info.latest_version);
    println!();
    println!("Release Notes:");
    println!("{}", info.release_notes);
    println!();
    println!("Download: {}", info.download_url);
    println!();
    println!("To update automatically, run: rustfinder --update");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("1.1.0", "1.0.0"));
        assert!(is_newer_version("2.0.0", "1.9.9"));
        assert!(is_newer_version("1.0.1", "1.0.0"));
        assert!(!is_newer_version("1.0.0", "1.0.0"));
        assert!(!is_newer_version("1.0.0", "1.1.0"));
    }

    #[test]
    fn test_should_auto_update() {
        // Test default behavior
        env::remove_var("RUSTFINDER_AUTO_UPDATE");
        assert!(!should_auto_update());
        
        // Test enabled
        env::set_var("RUSTFINDER_AUTO_UPDATE", "true");
        assert!(should_auto_update());
        
        env::set_var("RUSTFINDER_AUTO_UPDATE", "1");
        assert!(should_auto_update());
        
        // Test disabled
        env::set_var("RUSTFINDER_AUTO_UPDATE", "false");
        assert!(!should_auto_update());
        
        env::set_var("RUSTFINDER_AUTO_UPDATE", "0");
        assert!(!should_auto_update());
        
        // Cleanup
        env::remove_var("RUSTFINDER_AUTO_UPDATE");
    }
}