fn main() {
    // Add build-time information
    println!("cargo:rustc-env=BUILD_TIME={}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    
    // Add git commit hash if available
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_hash = String::from_utf8_lossy(&output.stdout);
            println!("cargo:rustc-env=GIT_HASH={}", git_hash.trim());
        }
    } else {
        println!("cargo:rustc-env=GIT_HASH=unknown");
    }
    
    // Add git branch if available
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_branch = String::from_utf8_lossy(&output.stdout);
            println!("cargo:rustc-env=GIT_BRANCH={}", git_branch.trim());
        }
    } else {
        println!("cargo:rustc-env=GIT_BRANCH=unknown");
    }
}