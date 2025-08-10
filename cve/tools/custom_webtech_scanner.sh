#!/bin/bash

# ============================================================================
# Custom Web Technology Fingerprinting Scanner
# Replacement for whatweb - Built from scratch for CVEHACK
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

# ============================================================================
# Web Technology Signatures Database
# ============================================================================

# Server signatures
declare -A SERVER_SIGNATURES=(
    ["Apache"]="Server:.*Apache|apache"
    ["Nginx"]="Server:.*nginx|nginx"
    ["IIS"]="Server:.*IIS|Microsoft-IIS"
    ["Cloudflare"]="Server:.*cloudflare|cf-ray"
    ["LiteSpeed"]="Server:.*LiteSpeed"
    ["Tomcat"]="Server:.*Tomcat"
    ["Jetty"]="Server:.*Jetty"
    ["Node.js"]="Server:.*Node|x-powered-by.*Express"
)

# Framework signatures
declare -A FRAMEWORK_SIGNATURES=(
    ["WordPress"]="wp-content|wp-includes|wordpress|/wp-json/"
    ["Drupal"]="drupal|sites/default|misc/drupal"
    ["Joomla"]="joomla|com_content|administrator/index.php"
    ["Django"]="csrfmiddlewaretoken|django"
    ["Laravel"]="laravel_session|laravel"
    ["React"]="react|__REACT_DEVTOOLS"
    ["Angular"]="ng-version|angular"
    ["Vue.js"]="vue|__vue__"
    ["Bootstrap"]="bootstrap|btn-primary"
    ["jQuery"]="jquery|\\$\\(document\\)"
)

# CMS version patterns
declare -A VERSION_PATTERNS=(
    ["WordPress"]="wp-includes/js/wp-embed.min.js\\?ver=([0-9.]+)|generator.*WordPress ([0-9.]+)"
    ["Drupal"]="Drupal ([0-9.]+)|drupal.js\\?v=([0-9.]+)"
    ["Joomla"]="generator.*Joomla! ([0-9.]+)"
    ["Apache"]="Server: Apache/([0-9.]+)"
    ["Nginx"]="Server: nginx/([0-9.]+)"
)

# Security headers to check
declare -A SECURITY_HEADERS=(
    ["X-Frame-Options"]="Clickjacking protection"
    ["X-XSS-Protection"]="XSS protection"
    ["X-Content-Type-Options"]="MIME sniffing protection"
    ["Strict-Transport-Security"]="HTTPS enforcement"
    ["Content-Security-Policy"]="Content security policy"
    ["X-Powered-By"]="Technology disclosure (security risk)"
    ["Server"]="Server disclosure (security risk)"
)

# ============================================================================
# Core Functions
# ============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    Custom Web Technology Scanner                            ║"
    echo "║                        CVEHACK - Built from Scratch                         ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo -e "${YELLOW}Usage: $0 <target> [options]${NC}"
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo "  -o, --output FILE    Save results to file"
    echo "  -v, --verbose        Verbose output"
    echo "  -h, --help          Show this help"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0 https://example.com"
    echo "  $0 http://target.com -o results.txt -v"
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

# ============================================================================
# HTTP Analysis Functions
# ============================================================================

get_http_headers() {
    local url="$1"
    local headers
    
    log_info "Fetching HTTP headers from $url"
    
    # Get headers with curl
    headers=$(curl -s -I -L --max-time 10 --user-agent "CVEHACK-WebTech-Scanner/1.0" "$url" 2>/dev/null)
    
    if [[ -z "$headers" ]]; then
        log_error "Failed to retrieve headers from $url"
        return 1
    fi
    
    echo "$headers"
}

get_page_content() {
    local url="$1"
    local content
    
    log_info "Fetching page content from $url"
    
    # Get page content with curl
    content=$(curl -s -L --max-time 15 --user-agent "CVEHACK-WebTech-Scanner/1.0" "$url" 2>/dev/null)
    
    if [[ -z "$content" ]]; then
        log_error "Failed to retrieve content from $url"
        return 1
    fi
    
    echo "$content"
}

# ============================================================================
# Technology Detection Functions
# ============================================================================

detect_server_technology() {
    local headers="$1"
    local detected_servers=()
    
    echo -e "\n${CYAN}═══ Server Technology Detection ═══${NC}"
    
    for server in "${!SERVER_SIGNATURES[@]}"; do
        local pattern="${SERVER_SIGNATURES[$server]}"
        
        if echo "$headers" | grep -iE "$pattern" >/dev/null 2>&1; then
            detected_servers+=("$server")
            log_success "Detected: $server"
            
            # Try to extract version
            if [[ -n "${VERSION_PATTERNS[$server]}" ]]; then
                local version_pattern="${VERSION_PATTERNS[$server]}"
                local version=$(echo "$headers" | grep -iEo "$version_pattern" | head -1)
                if [[ -n "$version" ]]; then
                    echo -e "    ${YELLOW}Version: $version${NC}"
                fi
            fi
        fi
    done
    
    if [[ ${#detected_servers[@]} -eq 0 ]]; then
        log_warning "No server technology signatures detected"
    fi
    
    return 0
}

detect_frameworks() {
    local content="$1"
    local headers="$2"
    local detected_frameworks=()
    
    echo -e "\n${CYAN}═══ Framework & CMS Detection ═══${NC}"
    
    for framework in "${!FRAMEWORK_SIGNATURES[@]}"; do
        local pattern="${FRAMEWORK_SIGNATURES[$framework]}"
        
        if echo "$content" | grep -iE "$pattern" >/dev/null 2>&1 || \
           echo "$headers" | grep -iE "$pattern" >/dev/null 2>&1; then
            detected_frameworks+=("$framework")
            log_success "Detected: $framework"
            
            # Try to extract version
            if [[ -n "${VERSION_PATTERNS[$framework]}" ]]; then
                local version_pattern="${VERSION_PATTERNS[$framework]}"
                local version=$(echo "$content" | grep -iEo "$version_pattern" | head -1 | sed 's/.*[^0-9]\([0-9.]\+\).*/\1/')
                if [[ -n "$version" ]]; then
                    echo -e "    ${YELLOW}Version: $version${NC}"
                fi
            fi
        fi
    done
    
    if [[ ${#detected_frameworks[@]} -eq 0 ]]; then
        log_warning "No framework signatures detected"
    fi
    
    return 0
}

analyze_security_headers() {
    local headers="$1"
    
    echo -e "\n${CYAN}═══ Security Headers Analysis ═══${NC}"
    
    local security_score=0
    local total_headers=${#SECURITY_HEADERS[@]}
    
    for header in "${!SECURITY_HEADERS[@]}"; do
        local description="${SECURITY_HEADERS[$header]}"
        
        if echo "$headers" | grep -i "^$header:" >/dev/null 2>&1; then
            if [[ "$header" == "X-Powered-By" || "$header" == "Server" ]]; then
                log_warning "$header: Present (${description})"
            else
                log_success "$header: Present (${description})"
                ((security_score++))
            fi
        else
            if [[ "$header" == "X-Powered-By" || "$header" == "Server" ]]; then
                log_success "$header: Not present (Good for security)"
                ((security_score++))
            else
                log_error "$header: Missing (${description})"
            fi
        fi
    done
    
    echo -e "\n${YELLOW}Security Score: $security_score/$total_headers${NC}"
    
    if [[ $security_score -ge 6 ]]; then
        echo -e "${GREEN}Security Level: Good${NC}"
    elif [[ $security_score -ge 4 ]]; then
        echo -e "${YELLOW}Security Level: Moderate${NC}"
    else
        echo -e "${RED}Security Level: Poor${NC}"
    fi
}

detect_javascript_libraries() {
    local content="$1"
    
    echo -e "\n${CYAN}═══ JavaScript Libraries Detection ═══${NC}"
    
    # Common JS library patterns
    local js_patterns=(
        "jquery.*([0-9.]+)|jQuery v([0-9.]+)"
        "bootstrap.*([0-9.]+)"
        "angular.*([0-9.]+)"
        "react.*([0-9.]+)"
        "vue.*([0-9.]+)"
        "lodash.*([0-9.]+)"
        "moment.*([0-9.]+)"
        "d3.*([0-9.]+)"
    )
    
    local detected_js=()
    
    for pattern in "${js_patterns[@]}"; do
        local lib_name=$(echo "$pattern" | cut -d'.' -f1)
        if echo "$content" | grep -iE "$pattern" >/dev/null 2>&1; then
            detected_js+=("$lib_name")
            log_success "Detected JavaScript library: $lib_name"
        fi
    done
    
    if [[ ${#detected_js[@]} -eq 0 ]]; then
        log_warning "No common JavaScript libraries detected"
    fi
}

detect_meta_information() {
    local content="$1"
    
    echo -e "\n${CYAN}═══ Meta Information Analysis ═══${NC}"
    
    # Extract title
    local title=$(echo "$content" | grep -i '<title>' | sed 's/<title[^>]*>//i' | sed 's/<\/title>.*//i' | head -1)
    if [[ -n "$title" ]]; then
        log_success "Page Title: $title"
    fi
    
    # Extract generator meta tag
    local generator=$(echo "$content" | grep -i 'name="generator"' | sed 's/.*content="//i' | sed 's/".*//' | head -1)
    if [[ -n "$generator" ]]; then
        log_success "Generator: $generator"
    fi
    
    # Extract description
    local description=$(echo "$content" | grep -i 'name="description"' | sed 's/.*content="//i' | sed 's/".*//' | head -1)
    if [[ -n "$description" && ${#description} -lt 200 ]]; then
        log_success "Description: $description"
    fi
    
    # Check for common CMS indicators
    if echo "$content" | grep -i "wp-content\|wordpress" >/dev/null 2>&1; then
        log_success "WordPress indicators found in content"
    fi
    
    if echo "$content" | grep -i "drupal\|sites/default" >/dev/null 2>&1; then
        log_success "Drupal indicators found in content"
    fi
    
    if echo "$content" | grep -i "joomla\|com_content" >/dev/null 2>&1; then
        log_success "Joomla indicators found in content"
    fi
}

# ============================================================================
# Main Scanning Function
# ============================================================================

scan_target() {
    local target="$1"
    
    echo -e "${BLUE}[i] Starting web technology scan of: $target${NC}"
    echo -e "${BLUE}[i] Timestamp: $(date)${NC}"
    echo ""
    
    # Get HTTP headers
    local headers=$(get_http_headers "$target")
    if [[ $? -ne 0 ]]; then
        log_error "Failed to retrieve headers. Aborting scan."
        return 1
    fi
    
    # Get page content
    local content=$(get_page_content "$target")
    if [[ $? -ne 0 ]]; then
        log_error "Failed to retrieve content. Continuing with headers only."
        content=""
    fi
    
    # Perform detections
    detect_server_technology "$headers"
    detect_frameworks "$content" "$headers"
    analyze_security_headers "$headers"
    
    if [[ -n "$content" ]]; then
        detect_javascript_libraries "$content"
        detect_meta_information "$content"
    fi
    
    echo -e "\n${GREEN}[+] Web technology scan completed${NC}"
    
    # Save to file if specified
    if [[ -n "$OUTPUT_FILE" ]]; then
        {
            echo "CVEHACK Web Technology Scan Report"
            echo "Target: $target"
            echo "Timestamp: $(date)"
            echo "=================================="
            echo ""
            echo "HTTP Headers:"
            echo "$headers"
            echo ""
            echo "Content Analysis:"
            echo "$content" | head -50
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
    
    # Validate target format
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        TARGET="http://$TARGET"
        log_warning "No protocol specified, assuming HTTP: $TARGET"
    fi
    
    # Print banner
    print_banner
    
    # Start scanning
    scan_target "$TARGET"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
