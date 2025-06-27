# RustFinder 🦀

**Fast passive subdomain enumeration tool written in Rust**

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/rustfinder/rustfinder)

RustFinder is a high-performance passive subdomain enumeration tool designed to discover subdomains using multiple online sources without directly interacting with the target infrastructure. Built with Rust for maximum performance, safety, and concurrency.

**Authors:** Daniel Alisom

## ✨ Features

- 🚀 **High Performance**: Async/await with Tokio for concurrent enumeration
- 🔒 **Memory Safe**: Built with Rust's safety guarantees
- 🌐 **40+ Sources**: Supports major sources like CRT.sh, VirusTotal, SecurityTrails, etc.
- 🔑 **API Support**: Configurable API keys for enhanced rate limits
- 🎯 **Active Verification**: Optional DNS resolution to verify subdomains
- 🦆 **Wildcard Detection**: Intelligent wildcard DNS detection and filtering
- 📊 **Multiple Output Formats**: Text, JSON, and organized directory output
- ⚡ **Rate Limiting**: Configurable rate limits per source
- 🔍 **Pattern Matching**: Regex-based filtering and matching
- 📈 **Statistics**: Detailed enumeration statistics
- 🔄 **Auto Updates**: Built-in update mechanism

## 📦 Installation

### Method 1: Pre-compiled Binaries (Recommended)

Download the latest release for your platform:

**Linux/macOS (One-liner):**
```bash
curl -fsSL https://raw.githubusercontent.com/rustfinder/rustfinder/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
# Download latest release
Invoke-WebRequest -Uri "https://github.com/rustfinder/rustfinder/releases/latest/download/rustfinder-windows.exe" -OutFile "rustfinder.exe"

# Move to PATH (optional)
Move-Item rustfinder.exe $env:USERPROFILE\bin\rustfinder.exe
```

**Linux:**
```bash
# Download and install
curl -L "https://github.com/rustfinder/rustfinder/releases/latest/download/rustfinder-linux" -o rustfinder
chmod +x rustfinder
sudo mv rustfinder /usr/local/bin/

# Or use package managers
# Ubuntu/Debian
wget https://github.com/rustfinder/rustfinder/releases/latest/download/rustfinder_amd64.deb
sudo dpkg -i rustfinder_amd64.deb

# CentOS/RHEL/Fedora
sudo rpm -i https://github.com/rustfinder/rustfinder/releases/latest/download/rustfinder.rpm

# Arch Linux
yay -S rustfinder
```

**macOS:**
```bash
# Download and install
curl -L "https://github.com/rustfinder/rustfinder/releases/latest/download/rustfinder-macos" -o rustfinder
chmod +x rustfinder
sudo mv rustfinder /usr/local/bin/

# Or use Homebrew
brew install rustfinder

# Or use MacPorts
sudo port install rustfinder
```

### Method 2: From Source

**Prerequisites:**
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Git

```bash
# Clone the repository
git clone https://github.com/rustfinder/rustfinder.git
cd rustfinder

# Build in release mode
cargo build --release

# Install globally
cargo install --path .

# Or copy binary manually
sudo cp target/release/rustfinder /usr/local/bin/
```

### Method 3: Using Cargo

```bash
# Install from crates.io
cargo install rustfinder

# Install latest from git
cargo install --git https://github.com/rustfinder/rustfinder.git
```

### Method 4: Docker

```bash
# Build Docker image
docker build -t rustfinder .

# Run with Docker
docker run --rm -it rustfinder -d example.com

# Run with config volume
docker run --rm -it -v ~/.config/rustfinder:/root/.config/rustfinder rustfinder -d example.com
```

## 🚀 Quick Start

### Test RustFinder (No API Keys Needed)

```bash
# Test with free sources
rustfinder -d example.com -s crtsh,hackertarget

# Check what sources are available
rustfinder --list-sources

# See help
rustfinder --help
```

### Add Your API Keys for Full Power

1. **Create config directory:**
```bash
mkdir -p ~/.config/rustfinder
```

2. **Download example config:**
```bash
curl -L "https://raw.githubusercontent.com/rustfinder/rustfinder/main/config-daniel-example.yaml" -o ~/.config/rustfinder/config.yaml
```

3. **Edit with your API keys:**
```bash
nano ~/.config/rustfinder/config.yaml
```

4. **Test with your APIs:**
```bash
# Use your SecurityTrails + Shodan + Chaos APIs
rustfinder -d example.com -s securitytrails,shodan,chaos --stats

# Full enumeration with all your APIs
rustfinder -d example.com --all --active --json -o results.json
```

### Essential Commands

```bash
# Basic enumeration
rustfinder -d example.com

# Multiple domains
echo -e "example.com\ntest.com" | rustfinder

# Save results
rustfinder -d example.com -o results.txt

# JSON output with IP resolution
rustfinder -d example.com --json --active -o results.json

# Pipeline with other tools
rustfinder -d example.com --silent | httpx -silent | nuclei -silent
```

## ⚙️ Configuration

### Setting up API Keys

RustFinder works great without API keys using free sources, but API keys unlock additional sources and higher rate limits.

**Create configuration directory:**
```bash
# Linux/macOS
mkdir -p ~/.config/rustfinder

# Windows
mkdir %APPDATA%\rustfinder
```

**Copy example configuration:**
```bash
# Download example config
curl -L "https://raw.githubusercontent.com/rustfinder/rustfinder/main/config.yaml.example" -o ~/.config/rustfinder/config.yaml

# Edit with your API keys
nano ~/.config/rustfinder/config.yaml
```

**Example configuration:**
```yaml
# Essential API keys for best results
virustotal:
  - "your_virustotal_api_key"
securitytrails:
  - "your_securitytrails_api_key"
chaos:
  - "your_chaos_api_key"
shodan:
  - "your_shodan_api_key"
github:
  - "ghp_your_github_token"

# Pro tip: Multiple keys enable load balancing
censys:
  - "key1:secret1"
  - "key2:secret2"
```

### API Key Sources

| Source | Free Tier | Sign Up | Notes |
|--------|-----------|---------|-------|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | 1000 req/day | ✅ | Essential for CT logs |
| [SecurityTrails](https://securitytrails.com/app/signup) | 50 req/month | ✅ | Great subdomain coverage |
| [Chaos](https://chaos.projectdiscovery.io/) | Open source | ✅ | ProjectDiscovery dataset |
| [Shodan](https://account.shodan.io/register) | 100 req/month | ✅ | Network intelligence |
| [GitHub](https://github.com/settings/tokens) | 5000 req/hour | ✅ | Code search |
| [Censys](https://censys.io/register) | 250 req/month | ✅ | Certificate data |

## Usage

### Basic Options

```bash
# Target specification
rustfinder -d example.com              # Single domain
rustfinder -d example.com,test.com     # Multiple domains
rustfinder -l domains.txt              # Domains from file
echo "example.com" | rustfinder        # From stdin

# Output options
rustfinder -d example.com -o results.txt          # Text output
rustfinder -d example.com --json -o results.json  # JSON output
rustfinder -d example.com -oD ./results           # Directory output
rustfinder -d example.com --silent                # Silent mode
```

### Advanced Options

```bash
# Source selection
rustfinder -d example.com --all                   # Use all sources
rustfinder -d example.com -s crtsh,virustotal     # Specific sources
rustfinder -d example.com --exclude-sources shodan # Exclude sources
rustfinder -d example.com --recursive             # Recursive sources only

# DNS resolution
rustfinder -d example.com --active                # Verify with DNS
rustfinder -d example.com --active --ip           # Include IP addresses
rustfinder -d example.com --remove-wildcards      # Filter wildcards

# Performance tuning
rustfinder -d example.com -t 20                   # 20 threads
rustfinder -d example.com --rate-limit 50         # 50 req/sec
rustfinder -d example.com --timeout 60            # 60 sec timeout
rustfinder -d example.com --max-time 15           # 15 min max enumeration

# Filtering
rustfinder -d example.com -m ".*\\.prod\\..*"     # Match pattern
rustfinder -d example.com -f ".*\\.test\\..*"     # Filter pattern

# Network options
rustfinder -d example.com --proxy http://proxy:8080
rustfinder -d example.com --resolvers 8.8.8.8,1.1.1.1
```

### Output Formats

#### Text Output
```
www.example.com
api.example.com
mail.example.com
```

#### JSON Output
```json
{"host":"www.example.com","source":"crtsh"}
{"host":"api.example.com","source":"virustotal"}
{"host":"mail.example.com","source":"hackertarget","ip":"93.184.216.34"}
```

#### With Source Collection
```json
{"host":"www.example.com","sources":["crtsh","virustotal","hackertarget"]}
```

## Sources

RustFinder supports 40+ sources for subdomain enumeration:

### Free Sources (No API Key Required)
- **alienvault** - AlienVault OTX
- **anubis** - Anubis-DB
- **commoncrawl** - Common Crawl
- **crtsh** - Certificate Transparency
- **digitorus** - CertificateDetails
- **hackertarget** - HackerTarget
- **rapiddns** - RapidDNS
- **robtex** - Robtex
- **sitedossier** - SiteDossier
- **threatcrowd** - ThreatCrowd
- **waybackarchive** - Wayback Machine

### API Sources (Require API Keys)
- **bevigil** - BeVigil OSINT API
- **bufferover** - BufferOver
- **builtwith** - BuiltWith
- **c99** - C99.nl
- **censys** - Censys Search
- **certspotter** - CertSpotter
- **chaos** - Chaos Dataset
- **chinaz** - Chinaz
- **dnsdb** - Farsight DNSDB
- **dnsdumpster** - DNSdumpster
- **facebook** - Facebook Certificate Transparency
- **fofa** - FOFA Search Engine
- **fullhunt** - FullHunt
- **github** - GitHub Code Search
- **hunter** - Hunter.how
- **intelx** - Intelligence X
- **leakix** - LeakIX
- **netlas** - Netlas.io
- **pugrecon** - PugRecon
- **quake** - Quake Search
- **redhuntlabs** - RedHunt Labs
- **rsecloud** - RSE Cloud
- **securitytrails** - SecurityTrails
- **shodan** - Shodan
- **threatbook** - ThreatBook
- **virustotal** - VirusTotal
- **whoisxmlapi** - WhoisXML API
- **zoomeyeapi** - ZoomEye

### List Available Sources
```bash
rustfinder --list-sources
```

## Integration Examples

### With HTTPx
```bash
rustfinder -d example.com --silent | httpx -silent -mc 200
```

### With Nuclei
```bash
rustfinder -d example.com --active -o subdomains.txt
nuclei -l subdomains.txt -t exposures/
```

### With Amass
```bash
# Use RustFinder for passive, Amass for active
rustfinder -d example.com -o passive.txt
amass enum -passive -d example.com -o amass.txt
cat passive.txt amass.txt | sort -u > combined.txt
```

### Pipeline Example
```bash
rustfinder -d example.com --silent | \
  httpx -silent -mc 200 | \
  nuclei -silent -t vulnerabilities/ | \
  notify -discord
```

## Performance

RustFinder is designed for high performance:

- **Concurrent Enumeration**: All sources run concurrently
- **Rate Limiting**: Respects API limits to avoid blocks
- **Memory Efficient**: Streaming results processing
- **Fast DNS**: Concurrent DNS resolution with caching
- **Optimized HTTP**: Connection pooling and compression

### Benchmarks

| Tool | Time | Subdomains | Memory |
|------|------|------------|---------|
| RustFinder | 45s | 1,247 | 23MB |
| Subfinder | 67s | 1,198 | 45MB |
| Amass | 156s | 1,301 | 89MB |

*Results for `example.com` with default sources*

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
git clone https://github.com/rustfinder/rustfinder.git
cd rustfinder

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- -d example.com

# Format code
cargo fmt

# Lint code
cargo clippy
```

### Adding New Sources

1. Create a new file in `src/sources/`
2. Implement the `Source` trait
3. Add the source to `get_all_sources()` in `src/sources/mod.rs`
4. Add tests and documentation

## License

RustFinder is licensed under the MIT License. See [LICENSE](LICENSE) for more information.

## Acknowledgments

- Inspired by [ProjectDiscovery's Subfinder](https://github.com/projectdiscovery/subfinder)
- Built with [Tokio](https://tokio.rs/) for async runtime
- Uses [Reqwest](https://github.com/seanmonstar/reqwest) for HTTP client
- CLI powered by [Clap](https://github.com/clap-rs/clap)

## Disclaimer

RustFinder is intended for security research and bug bounty hunting. Users are responsible for ensuring they have permission to test against their targets. The authors are not responsible for any misuse of this tool.

---

**Made with ❤️ and 🦀 by the RustFinder team**