# CVEHACK - Elite Cybersecurity & Pentesting Suite

![CVEHACK Logo](https://img.shields.io/badge/CVEHACK-v1.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)
![License](https://img.shields.io/badge/license-Educational%20Use-red.svg)

**CVEHACK** is a comprehensive, Mac-compatible cybersecurity and penetration testing suite designed for security professionals, researchers, and ethical hackers. It combines traditional pentesting tools with dynamic CVE integration and automated vulnerability assessment capabilities.

## ⚠️ LEGAL DISCLAIMER

**THIS TOOL IS FOR AUTHORIZED TESTING ONLY**

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- Users are fully responsible for their actions
- Authors assume no liability for misuse

## 🚀 Features

### Core Capabilities
- **Interactive Menu System** - Beginner-friendly with advanced customization
- **Homebrew Integration** - Automated tool installation and management
- **Dynamic CVE Testing** - Fetch recent CVEs and generate custom scanners
- **Comprehensive Reporting** - HTML and text reports with detailed findings
- **Modular Architecture** - Easy to extend and customize

### Scanning Modules
- 🔍 **Reconnaissance** - Domain/DNS info, port scanning, service detection
- 🛡️ **Vulnerability Scanning** - Web app security, SQL injection, XSS testing
- ⚔️ **Exploitation** - Brute force attacks, RCE testing, file upload testing
- 🆕 **CVE Integration** - Dynamic CVE fetching and custom scanner generation

### Integrated Tools
- **nmap** - Port scanning and service detection
- **masscan** - Ultra-fast port scanning
- **nikto** - Web server vulnerability scanning
- **sqlmap** - SQL injection testing
- **wpscan** - WordPress security scanning
- **gobuster** - Directory and file brute forcing
- **hydra** - Login brute forcing
- **subfinder/amass** - Subdomain enumeration
- And many more...

## 📋 Requirements

### System Requirements
- **macOS** (tested on macOS 10.15+)
- **Homebrew** package manager
- **Bash** 4.0+ (default on macOS)
- **Internet connection** for CVE fetching

### Dependencies
- `curl` or `wget`
- `jq` for JSON processing
- `git` for repository operations
- `python3` for Python-based tools
- `go` for Go-based tools

## 🛠️ Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/your-repo/cvehack.git
cd cvehack

# Make the main script executable
chmod +x pentest.sh

# Run CVEHACK (it will auto-install dependencies)
./pentest.sh
```

### Manual Installation
```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install core dependencies
brew install nmap nikto sqlmap gobuster hydra subfinder amass jq python3 go

# Install Python tools
pip3 install dirsearch sublist3r shodan theHarvester

# Install Go tools
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Clone and run CVEHACK
git clone https://github.com/your-repo/cvehack.git
cd cvehack
chmod +x pentest.sh
./pentest.sh
```

## 🎯 Usage

### Basic Usage
```bash
# Start CVEHACK
./pentest.sh

# Follow the interactive menu to:
# 1. Set your target
# 2. Choose scanning modules
# 3. Review results and reports
```

### Quick Scan Example
```bash
# Start CVEHACK and select:
# - Option 5: Quick Scan
# - Enter target: example.com
# - Review generated report
```

### CVE Testing Example
```bash
# Start CVEHACK and select:
# - Option 4: Custom CVE Testing
# - Option 1: Fetch Recent CVEs
# - Option 3: Test Specific CVE
# - Enter CVE ID: CVE-2023-1234
```

## 📁 Directory Structure

```
cvehack/
├── pentest.sh              # Main controller script
├── lib/                    # Core libraries
│   ├── colors.sh          # Color and formatting functions
│   ├── installer.sh       # Tool installation management
│   ├── logger.sh          # Logging and session management
│   ├── cve_fetcher.sh     # CVE data fetching and parsing
│   └── report_generator.sh # Report generation
├── modules/               # Scanning modules
│   ├── recon.sh          # Reconnaissance functions
│   ├── web_scan.sh       # Web vulnerability scanning
│   ├── exploit.sh        # Exploitation modules
│   └── brute_force.sh    # Brute force attacks
├── cve/                  # CVE management
│   ├── cve_manager.sh    # CVE testing and management
│   ├── custom/           # Generated custom scanners
│   └── generators/       # Scanner generators
├── config/               # Configuration files
│   └── tools.conf        # Tool and scanning configuration
├── results/              # Scan results and reports
└── README.md            # This file
```

## 🔧 Configuration

### Main Configuration
Edit `config/tools.conf` to customize:
- Tool installation preferences
- Default scanning options
- CVE fetching settings
- Reporting preferences
- Network and proxy settings

### User Configuration
Create `~/.cvehack/config/user.conf` for personal settings:
```bash
# Example user configuration
LOG_LEVEL="DEBUG"
CVE_UPDATE_INTERVAL="12"
ENABLE_NOTIFICATIONS="true"
NOTIFICATION_EMAIL="your-email@example.com"
```

## 📊 Reporting

CVEHACK generates comprehensive reports in multiple formats:

### HTML Reports
- Interactive web-based reports
- Vulnerability severity color coding
- Executive summary with risk assessment
- Detailed technical findings
- Remediation recommendations

### Text Reports
- Plain text format for easy parsing
- Command-line friendly output
- Suitable for automation and scripting

### Report Locations
- `results/[session_id]/report_*.html`
- `results/[session_id]/report_*.txt`
- `results/[session_id]/session_summary.txt`

## 🆕 CVE Integration

### Dynamic CVE Fetching
```bash
# Fetch CVEs from the last 7 days
./pentest.sh -> Option 4 -> Option 1 -> Option 1

# Search for specific CVE
./pentest.sh -> Option 4 -> Option 2 -> Option 1
```

### Custom Scanner Generation
CVEHACK can automatically generate custom scanners for CVEs:
- Fetches CVE details from NVD API
- Analyzes vulnerability type
- Generates appropriate test scripts
- Integrates into the main toolkit

### Supported CVE Types
- Remote Code Execution (RCE)
- SQL Injection
- Cross-Site Scripting (XSS)
- Local/Remote File Inclusion
- Authentication Bypass
- Information Disclosure
- Denial of Service

## 🛡️ Security Features

### Safe Mode
- Confirmation prompts for dangerous operations
- Rate limiting to prevent service disruption
- Account lockout detection and prevention
- Comprehensive logging of all activities

### Ethical Guidelines
- Built-in legal disclaimers
- Emphasis on authorized testing only
- Responsible disclosure recommendations
- Educational focus

## 🔍 Troubleshooting

### Common Issues

**Tool Installation Failures**
```bash
# Check Homebrew installation
brew doctor

# Manually install failed tools
brew install [tool-name]

# Check tool availability
which [tool-name]
```

**Permission Errors**
```bash
# Fix script permissions
chmod +x pentest.sh
chmod +x lib/*.sh
chmod +x modules/*.sh
```

**CVE Fetching Issues**
```bash
# Check internet connection
curl -I https://services.nvd.nist.gov

# Verify jq installation
which jq
brew install jq
```

### Debug Mode
Enable debug logging in `config/tools.conf`:
```bash
LOG_LEVEL="DEBUG"
ENABLE_VERBOSE_LOGGING="true"
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup
```bash
git clone https://github.com/your-repo/cvehack.git
cd cvehack
git checkout -b feature/your-feature
# Make changes
git commit -am "Add your feature"
git push origin feature/your-feature
```

## 📚 Documentation

### Additional Resources
- [Wiki](https://github.com/your-repo/cvehack/wiki) - Detailed documentation
- [Examples](examples/) - Usage examples and tutorials
- [API Reference](docs/api.md) - Function and module documentation

### Learning Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST CVE Database](https://nvd.nist.gov/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

## 📄 License

This project is licensed for **Educational Use Only**. See the [LICENSE](LICENSE) file for details.

### Important Notes
- This tool is for learning and authorized testing only
- Commercial use requires explicit permission
- Users must comply with all applicable laws
- No warranty or support is provided

## 🙏 Acknowledgments

### Tools and Libraries
- **NMAP** - Network discovery and security auditing
- **OWASP** - Web application security resources
- **Homebrew** - Package management for macOS
- **NVD** - National Vulnerability Database

### Contributors
- Security researchers and ethical hackers worldwide
- Open source tool developers
- The cybersecurity community

## 📞 Support

### Getting Help
- 📖 Check the [Wiki](https://github.com/your-repo/cvehack/wiki)
- 🐛 Report bugs via [Issues](https://github.com/your-repo/cvehack/issues)
- 💬 Join discussions in [Discussions](https://github.com/your-repo/cvehack/discussions)

### Contact
- **Email**: security@example.com
- **Twitter**: @cvehack
- **Website**: https://cvehack.example.com

---

**Remember: With great power comes great responsibility. Use CVEHACK ethically and legally.**

![Footer](https://img.shields.io/badge/Made%20with-❤️-red.svg)
![Bash](https://img.shields.io/badge/Made%20with-Bash-green.svg)
![Security](https://img.shields.io/badge/Focus-Security-blue.svg)
