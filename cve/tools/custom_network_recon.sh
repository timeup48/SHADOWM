#!/bin/bash

# ============================================================================
# Custom Network Reconnaissance Tool
# Replacement for censys and similar network discovery tools - Built from scratch for CVEHACK
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
TARGET=""
OUTPUT_FILE=""
VERBOSE=false
SCAN_PORTS=false
SCAN_SUBDOMAINS=false
SCAN_CERTIFICATES=false
SCAN_HEADERS=false
DEEP_SCAN=false
TIMEOUT=10

# Common ports to scan
COMMON_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6379,8080,8443,9200,27017"

# ============================================================================
# Core Functions
# ============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    Custom Network Reconnaissance Tool                       ║"
    echo "║                        CVEHACK - Built from Scratch                         ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo -e "${YELLOW}Usage: $0 <target> [options]${NC}"
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo "  -p, --ports          Scan common ports"
    echo "  -s, --subdomains     Enumerate subdomains"
    echo "  -c, --certificates   Analyze SSL certificates"
    echo "  -H, --headers        Analyze HTTP headers"
    echo "  -d, --deep          Deep reconnaissance (all options)"
    echo "  -t, --timeout SEC    Request timeout (default: 10)"
    echo "  -o, --output FILE    Save results to file"
    echo "  -v, --verbose        Verbose output"
    echo "  -h, --help          Show this help"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0 example.com -p -s"
    echo "  $0 192.168.1.1 -d -o recon.txt"
    echo "  $0 target.com -c -H -v"
}

log_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_found() {
    echo -e "${GREEN}[FOUND]${NC} $1"
}

# ============================================================================
# Network Information Gathering
# ============================================================================

get_basic_info() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ Basic Target Information ═══${NC}"
    
    # Resolve IP address
    log_info "Resolving IP address for $target..."
    local ip_address=$(dig +short "$target" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    
    if [[ -n "$ip_address" ]]; then
        log_success "IP Address: $ip_address"
        
        # Get reverse DNS
        local reverse_dns=$(dig +short -x "$ip_address" 2>/dev/null | sed 's/\.$//')
        [[ -n "$reverse_dns" ]] && log_success "Reverse DNS: $reverse_dns"
        
        # Get basic network info
        log_info "Getting network information..."
        local whois_info=$(whois "$ip_address" 2>/dev/null | head -20)
        if [[ -n "$whois_info" ]]; then
            local org=$(echo "$whois_info" | grep -i "orgname\|org-name\|organization" | head -1 | cut -d: -f2- | xargs)
            local country=$(echo "$whois_info" | grep -i "country" | head -1 | cut -d: -f2- | xargs)
            
            [[ -n "$org" ]] && log_success "Organization: $org"
            [[ -n "$country" ]] && log_success "Country: $country"
        fi
        
    else
        log_warning "Could not resolve IP address for $target"
    fi
    
    # Check connectivity
    log_info "Testing connectivity..."
    if ping -c 1 -W 3 "$target" >/dev/null 2>&1; then
        log_success "Target is reachable via ICMP"
    else
        log_warning "Target does not respond to ICMP ping"
    fi
}

# ============================================================================
# Port Scanning Functions
# ============================================================================

scan_ports() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ Port Scanning ═══${NC}"
    
    log_info "Scanning common ports on $target..."
    
    local open_ports=()
    
    # Convert comma-separated ports to array
    IFS=',' read -ra PORT_ARRAY <<< "$COMMON_PORTS"
    
    log_info "Testing ${#PORT_ARRAY[@]} common ports..."
    
    for port in "${PORT_ARRAY[@]}"; do
        [[ "$VERBOSE" == "true" ]] && log_info "Testing port $port..."
        
        # Test TCP connection
        if timeout 3 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null; then
            open_ports+=("$port")
            
            # Try to identify service
            local service=$(identify_service "$target" "$port")
            log_found "Port $port/tcp open - $service"
        fi
    done
    
    if [[ ${#open_ports[@]} -eq 0 ]]; then
        log_warning "No open ports found in common port range"
    else
        log_success "Found ${#open_ports[@]} open ports: ${open_ports[*]}"
    fi
}

identify_service() {
    local target="$1"
    local port="$2"
    
    case "$port" in
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        110) echo "POP3" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        993) echo "IMAPS" ;;
        995) echo "POP3S" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        6379) echo "Redis" ;;
        8080) echo "HTTP Alternate" ;;
        8443) echo "HTTPS Alternate" ;;
        9200) echo "Elasticsearch" ;;
        27017) echo "MongoDB" ;;
        *) echo "Unknown" ;;
    esac
}

# ============================================================================
# Subdomain Enumeration
# ============================================================================

enumerate_subdomains() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ Subdomain Enumeration ═══${NC}"
    
    log_info "Enumerating subdomains for $target..."
    
    local found_subdomains=()
    
    # Common subdomain prefixes
    local subdomains=(
        "www" "mail" "ftp" "admin" "test" "dev" "staging" "api" "blog" "shop"
        "forum" "support" "help" "docs" "cdn" "static" "img" "images" "media"
        "assets" "secure" "vpn" "remote" "portal" "dashboard" "panel" "control"
        "beta" "alpha" "demo" "preview" "m" "mobile" "app" "service" "gateway"
    )
    
    log_info "Testing ${#subdomains[@]} common subdomain patterns..."
    
    for sub in "${subdomains[@]}"; do
        local subdomain="$sub.$target"
        [[ "$VERBOSE" == "true" ]] && log_info "Testing: $subdomain"
        
        # Try to resolve subdomain
        local ip=$(dig +short "$subdomain" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        
        if [[ -n "$ip" ]]; then
            found_subdomains+=("$subdomain")
            log_found "Subdomain: $subdomain -> $ip"
        fi
    done
    
    if [[ ${#found_subdomains[@]} -eq 0 ]]; then
        log_warning "No subdomains found"
    else
        log_success "Found ${#found_subdomains[@]} subdomains"
    fi
}

# ============================================================================
# SSL Certificate Analysis
# ============================================================================

analyze_certificates() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ SSL Certificate Analysis ═══${NC}"
    
    log_info "Analyzing SSL certificates for $target..."
    
    # Test HTTPS connectivity
    if ! timeout 10 bash -c "echo | openssl s_client -connect $target:443 -servername $target" >/dev/null 2>&1; then
        log_warning "No SSL/TLS service found on port 443"
        return 1
    fi
    
    # Get certificate information
    local cert_info=$(timeout 10 bash -c "echo | openssl s_client -connect $target:443 -servername $target 2>/dev/null | openssl x509 -noout -text 2>/dev/null")
    
    if [[ -n "$cert_info" ]]; then
        log_success "SSL certificate found"
        
        # Extract key information
        local subject=$(echo "$cert_info" | grep "Subject:" | cut -d: -f2- | xargs)
        local issuer=$(echo "$cert_info" | grep "Issuer:" | cut -d: -f2- | xargs)
        local not_after=$(echo "$cert_info" | grep "Not After:" | cut -d: -f2- | xargs)
        
        [[ -n "$subject" ]] && log_success "Subject: $subject"
        [[ -n "$issuer" ]] && log_success "Issuer: $issuer"
        [[ -n "$not_after" ]] && log_success "Valid Until: $not_after"
        
        # Check for Subject Alternative Names
        local san=$(echo "$cert_info" | grep -A 1 "Subject Alternative Name:" | tail -1 | xargs)
        if [[ -n "$san" ]]; then
            log_success "Subject Alternative Names found"
            echo "$san" | tr ',' '\n' | grep "DNS:" | sed 's/DNS://g' | while read -r domain; do
                domain=$(echo "$domain" | xargs)
                [[ -n "$domain" && "$domain" != "$target" ]] && log_found "Additional domain: $domain"
            done
        fi
    else
        log_error "Failed to retrieve certificate information"
    fi
}

# ============================================================================
# HTTP Headers Analysis
# ============================================================================

analyze_headers() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ HTTP Headers Analysis ═══${NC}"
    
    log_info "Analyzing HTTP headers for $target..."
    
    # Test both HTTP and HTTPS
    for protocol in "http" "https"; do
        local url="$protocol://$target"
        log_info "Testing $protocol..."
        
        local headers=$(curl -s -I --max-time "$TIMEOUT" "$url" 2>/dev/null)
        
        if [[ -n "$headers" ]]; then
            log_success "$protocol headers retrieved"
            
            # Extract important headers
            local server=$(echo "$headers" | grep -i "server:" | cut -d: -f2- | xargs)
            local powered_by=$(echo "$headers" | grep -i "x-powered-by:" | cut -d: -f2- | xargs)
            local content_type=$(echo "$headers" | grep -i "content-type:" | cut -d: -f2- | xargs)
            
            [[ -n "$server" ]] && log_success "Server: $server"
            [[ -n "$powered_by" ]] && log_success "Powered By: $powered_by"
            [[ -n "$content_type" ]] && log_success "Content Type: $content_type"
            
            # Check security headers
            check_security_headers "$headers"
        else
            log_warning "No $protocol response received"
        fi
    done
}

check_security_headers() {
    local headers="$1"
    
    log_info "Checking security headers..."
    
    # Security headers to check
    local security_headers=(
        "X-Frame-Options"
        "X-XSS-Protection"
        "X-Content-Type-Options"
        "Strict-Transport-Security"
        "Content-Security-Policy"
    )
    
    for header in "${security_headers[@]}"; do
        if echo "$headers" | grep -qi "^$header:"; then
            local value=$(echo "$headers" | grep -i "^$header:" | cut -d: -f2- | xargs)
            log_success "$header: $value"
        else
            log_warning "$header: Missing"
        fi
    done
}

# ============================================================================
# Main Reconnaissance Function
# ============================================================================

perform_reconnaissance() {
    local target="$1"
    
    echo -e "${BLUE}[i] Starting network reconnaissance of: $target${NC}"
    echo -e "${BLUE}[i] Timestamp: $(date)${NC}"
    echo ""
    
    # Always get basic info
    get_basic_info "$target"
    
    # Conditional scans based on options
    [[ "$SCAN_PORTS" == "true" || "$DEEP_SCAN" == "true" ]] && scan_ports "$target"
    [[ "$SCAN_SUBDOMAINS" == "true" || "$DEEP_SCAN" == "true" ]] && enumerate_subdomains "$target"
    [[ "$SCAN_CERTIFICATES" == "true" || "$DEEP_SCAN" == "true" ]] && analyze_certificates "$target"
    [[ "$SCAN_HEADERS" == "true" || "$DEEP_SCAN" == "true" ]] && analyze_headers "$target"
    
    echo -e "\n${GREEN}[+] Network reconnaissance completed${NC}"
    
    # Save to file if specified
    if [[ -n "$OUTPUT_FILE" ]]; then
        {
            echo "CVEHACK Network Reconnaissance Report"
            echo "Target: $target"
            echo "Timestamp: $(date)"
            echo "======================================"
            echo ""
            echo "Reconnaissance completed successfully"
        } > "$OUTPUT_FILE"
        log_success "Results saved to: $OUTPUT_FILE"
    fi
}

# ============================================================================
# Main Script Logic
# ============================================================================

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--ports)
                SCAN_PORTS=true
                shift
                ;;
            -s|--subdomains)
                SCAN_SUBDOMAINS=true
                shift
                ;;
            -c|--certificates)
                SCAN_CERTIFICATES=true
                shift
                ;;
            -H|--headers)
                SCAN_HEADERS=true
                shift
                ;;
            -d|--deep)
                DEEP_SCAN=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$TARGET" ]]; then
                    TARGET="$1"
                else
                    log_error "Multiple targets not supported"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Check if target is provided
    if [[ -z "$TARGET" ]]; then
        log_error "No target specified"
        usage
        exit 1
    fi
    
    # Validate timeout
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 1 || "$TIMEOUT" -gt 60 ]]; then
        log_error "Invalid timeout: $TIMEOUT (must be 1-60 seconds)"
        exit 1
    fi
    
    # If no specific scans requested, enable basic scans
    if [[ "$SCAN_PORTS" == "false" && "$SCAN_SUBDOMAINS" == "false" && "$SCAN_CERTIFICATES" == "false" && "$SCAN_HEADERS" == "false" && "$DEEP_SCAN" == "false" ]]; then
        log_info "No specific scans requested, enabling basic reconnaissance..."
        SCAN_PORTS=true
        SCAN_HEADERS=true
    fi
    
    # Print banner
    print_banner
    
    # Start reconnaissance
    perform_reconnaissance "$TARGET"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
