# CVEHACK Installation Guide

## Quick Start

```bash
# 1. Clone or download CVEHACK
cd /path/to/cvehack

# 2. Run the demo to verify everything works
chmod +x demo.sh
./demo.sh

# 3. Start CVEHACK
./pentest.sh
```

## System Requirements

- **macOS 10.15+** (Catalina or later)
- **Homebrew** package manager
- **Internet connection** for tool installation and CVE updates
- **~2GB disk space** for tools and wordlists

## What Gets Installed

### Core Tools (via Homebrew)
- `nmap` - Network discovery and security auditing
- `masscan` - Fast port scanner
- `nikto` - Web vulnerability scanner
- `whatweb` - Web technology fingerprinting
- `sqlmap` - SQL injection testing tool
- `wpscan` - WordPress security scanner
- `gobuster` - Directory/file brute forcer
- `hydra` - Login brute forcer
- `theharvester` - Information gathering tool
- `sslscan` - SSL/TLS scanner
- `subfinder` - Subdomain discovery tool
- `amass` - Advanced subdomain enumeration
- `dirb` - Web content scanner

### Python Tools (via pip3)
- `dirsearch` - Web path scanner
- `sublist3r` - Subdomain enumeration
- `shodan` - Shodan API client
- `censys` - Censys API client

### Go Tools (via go install)
- `httpx` - HTTP toolkit
- `nuclei` - Vulnerability scanner
- `katana` - Web crawler

## Manual Installation

If automatic installation fails, install tools manually:

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install core tools
brew install nmap masscan nikto whatweb sqlmap wpscan gobuster hydra theharvester sslscan subfinder amass dirb curl wget jq python3 go git

# Install Python tools
pip3 install dirsearch sublist3r shodan censys

# Install Go tools
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Troubleshooting

### Common Issues

**Homebrew not found:**
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add to PATH (Apple Silicon Macs)
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

**Permission errors:**
```bash
# Fix script permissions
find . -name "*.sh" -exec chmod +x {} \;

# Create results directory
mkdir -p results && chmod 755 results
```

**Tool installation failures:**
```bash
# Update Homebrew
brew update && brew doctor

# Install tools individually
brew install nmap
brew install nikto
# etc.
```

## Verification

Run the demo script to verify installation:
```bash
./demo.sh
```

Expected output should show:
- ✅ All libraries loaded successfully
- ✅ All modules loaded successfully
- ✅ CVE system loaded successfully
- Tool availability status

## First Run

1. **Start CVEHACK:**
   ```bash
   ./pentest.sh
   ```

2. **Accept legal disclaimer** (mandatory)

3. **Tool installation check** - CVEHACK will automatically install missing tools

4. **Set your first target** and run a quick scan

## Directory Structure After Installation

```
cvehack/
├── pentest.sh*             # Main executable
├── demo.sh*                # Demo/verification script
├── lib/                    # Core libraries
├── modules/                # Scanning modules
├── cve/                    # CVE integration
├── config/                 # Configuration files
├── results/                # Scan results (created on first run)
├── README.md               # Documentation
├── DISCLAIMER.md           # Legal information
└── examples/               # Sample outputs
```

## Next Steps

- Read `README.md` for detailed usage instructions
- Review `DISCLAIMER.md` for legal and ethical guidelines
- Check `examples/` for sample reports and outputs
- Start with a quick scan on a test target you own

## Support

If you encounter issues:
1. Run `./demo.sh` to verify installation
2. Check the troubleshooting section above
3. Review log files in `results/` directory
4. Ensure you have proper permissions and network access
