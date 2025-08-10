#!/bin/bash

# ============================================================================
# Custom WordPress Security Scanner
# Replacement for wpscan - Built from scratch for CVEHACK
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
ENUMERATE_USERS=false
ENUMERATE_PLUGINS=false
ENUMERATE_THEMES=false
CHECK_VULNS=true

# ============================================================================
# WordPress Vulnerability Database
# ============================================================================

# Common WordPress vulnerabilities
declare -A WP_VULNS=(
    ["wp-config-backup"]="wp-config.php backup files"
    ["xmlrpc-enabled"]="XML-RPC enabled (DDoS/brute force risk)"
    ["user-enumeration"]="User enumeration possible"
    ["directory-listing"]="Directory listing enabled"
    ["debug-log"]="Debug log exposed"
    ["readme-exposed"]="readme.html exposed"
    ["install-exposed"]="wp-admin/install.php accessible"
)

# Common WordPress paths to check
declare -a WP_PATHS=(
    "/wp-admin/"
    "/wp-content/"
    "/wp-includes/"
    "/wp-config.php"
    "/wp-config.php.bak"
    "/wp-config.php.old"
    "/wp-config.php~"
    "/readme.html"
    "/license.txt"
    "/wp-admin/install.php"
    "/wp-admin/upgrade.php"
    "/xmlrpc.php"
    "/wp-content/debug.log"
    "/wp-json/"
    "/wp-json/wp/v2/users"
)

# Common plugin paths for enumeration
declare -a COMMON_PLUGINS=(
    "akismet"
    "jetpack"
    "yoast-seo"
    "contact-form-7"
    "wordfence"
    "elementor"
    "woocommerce"
    "all-in-one-seo-pack"
    "wp-super-cache"
    "updraftplus"
    "really-simple-ssl"
    "classic-editor"
    "duplicate-post"
    "wp-optimize"
    "smush"
)

# Common theme paths for enumeration
declare -a COMMON_THEMES=(
    "twentytwentythree"
    "twentytwentytwo"
    "twentytwentyone"
    "twentytwenty"
    "twentynineteen"
    "twentyseventeen"
    "twentysixteen"
    "twentyfifteen"
    "astra"
    "oceanwp"
    "generatepress"
    "neve"
    "kadence"
)

# ============================================================================
# Core Functions
# ============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    Custom WordPress Security Scanner                         ║"
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
    echo "  -u, --enumerate-users    Enumerate WordPress users"
    echo "  -p, --enumerate-plugins  Enumerate installed plugins"
    echo "  -t, --enumerate-themes   Enumerate installed themes"
    echo "  --no-vulns          Skip vulnerability checks"
    echo "  -h, --help          Show this help"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0 https://wordpress-site.com"
    echo "  $0 http://target.com -u -p -t -o results.txt"
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

log_vuln() {
    echo -e "${RED}[VULN]${NC} $1"
}

# ============================================================================
# HTTP Request Functions
# ============================================================================

make_request() {
    local url="$1"
    local method="${2:-GET}"
    local follow_redirects="${3:-true}"
    
    local curl_opts="-s --max-time 10 --user-agent 'CVEHACK-WP-Scanner/1.0'"
    
    if [[ "$follow_redirects" == "true" ]]; then
        curl_opts="$curl_opts -L"
    fi
    
    if [[ "$method" == "HEAD" ]]; then
        curl_opts="$curl_opts -I"
    fi
    
    eval "curl $curl_opts '$url' 2>/dev/null"
}

check_url_exists() {
    local url="$1"
    local response
    
    response=$(make_request "$url" "HEAD")
    
    if echo "$response" | grep -q "HTTP/[12].[01] 200\|HTTP/[12].[01] 403"; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# WordPress Detection Functions
# ============================================================================

detect_wordpress() {
    local target="$1"
    
    log_info "Checking if target is running WordPress..."
    
    # Check for WordPress indicators
    local content=$(make_request "$target")
    local wp_indicators=0
    
    # Check for wp-content in HTML
    if echo "$content" | grep -i "wp-content" >/dev/null 2>&1; then
        ((wp_indicators++))
        [[ "$VERBOSE" == "true" ]] && log_info "Found wp-content references"
    fi
    
    # Check for WordPress generator meta tag
    if echo "$content" | grep -i "generator.*wordpress" >/dev/null 2>&1; then
        ((wp_indicators++))
        local version=$(echo "$content" | grep -i "generator.*wordpress" | sed 's/.*WordPress \([0-9.]*\).*/\1/' | head -1)
        if [[ -n "$version" ]]; then
            log_success "WordPress version detected: $version"
        fi
    fi
    
    # Check for wp-includes
    if echo "$content" | grep -i "wp-includes" >/dev/null 2>&1; then
        ((wp_indicators++))
        [[ "$VERBOSE" == "true" ]] && log_info "Found wp-includes references"
    fi
    
    # Check for WordPress REST API
    if check_url_exists "$target/wp-json/"; then
        ((wp_indicators++))
        log_success "WordPress REST API endpoint found: /wp-json/"
    fi
    
    # Check for common WordPress files
    if check_url_exists "$target/wp-login.php"; then
        ((wp_indicators++))
        log_success "WordPress login page found: /wp-login.php"
    fi
    
    if [[ $wp_indicators -ge 2 ]]; then
        log_success "WordPress installation confirmed ($wp_indicators indicators found)"
        return 0
    else
        log_error "WordPress not detected or well-hidden"
        return 1
    fi
}

# ============================================================================
# Vulnerability Scanning Functions
# ============================================================================

check_wordpress_vulnerabilities() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ WordPress Vulnerability Scan ═══${NC}"
    
    local vuln_count=0
    
    # Check for exposed wp-config.php backups
    for backup in "wp-config.php.bak" "wp-config.php.old" "wp-config.php~" "wp-config.php.save"; do
        if check_url_exists "$target/$backup"; then
            log_vuln "Exposed wp-config backup: /$backup"
            ((vuln_count++))
        fi
    done
    
    # Check for XML-RPC
    if check_url_exists "$target/xmlrpc.php"; then
        log_warning "XML-RPC endpoint accessible: /xmlrpc.php"
        
        # Test if XML-RPC is functional
        local xmlrpc_test=$(curl -s --max-time 5 -X POST -d "<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>" "$target/xmlrpc.php" 2>/dev/null)
        if echo "$xmlrpc_test" | grep -q "methodResponse"; then
            log_vuln "XML-RPC is functional (DDoS/brute force risk)"
            ((vuln_count++))
        fi
    fi
    
    # Check for debug.log
    if check_url_exists "$target/wp-content/debug.log"; then
        log_vuln "Debug log exposed: /wp-content/debug.log"
        ((vuln_count++))
    fi
    
    # Check for readme.html
    if check_url_exists "$target/readme.html"; then
        log_warning "WordPress readme file exposed: /readme.html"
        local readme_content=$(make_request "$target/readme.html")
        local version=$(echo "$readme_content" | grep -i "version" | head -1)
        if [[ -n "$version" ]]; then
            log_info "Version info in readme: $version"
        fi
    fi
    
    # Check for directory listing
    for dir in "wp-content" "wp-content/uploads" "wp-content/plugins" "wp-content/themes"; do
        local dir_content=$(make_request "$target/$dir/")
        if echo "$dir_content" | grep -i "index of\|directory listing" >/dev/null 2>&1; then
            log_vuln "Directory listing enabled: /$dir/"
            ((vuln_count++))
        fi
    done
    
    # Check for install.php accessibility
    if check_url_exists "$target/wp-admin/install.php"; then
        log_vuln "WordPress installation page accessible: /wp-admin/install.php"
        ((vuln_count++))
    fi
    
    # Check for user enumeration via REST API
    local users_api="$target/wp-json/wp/v2/users"
    local users_response=$(make_request "$users_api")
    if echo "$users_response" | grep -q '"id":' && echo "$users_response" | grep -q '"name":'; then
        log_vuln "User enumeration possible via REST API: /wp-json/wp/v2/users"
        ((vuln_count++))
    fi
    
    echo -e "\n${YELLOW}Total vulnerabilities found: $vuln_count${NC}"
    
    if [[ $vuln_count -eq 0 ]]; then
        log_success "No obvious vulnerabilities detected"
    elif [[ $vuln_count -le 2 ]]; then
        echo -e "${YELLOW}Security Level: Moderate${NC}"
    else
        echo -e "${RED}Security Level: Poor${NC}"
    fi
}

# ============================================================================
# Enumeration Functions
# ============================================================================

enumerate_users() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ User Enumeration ═══${NC}"
    
    local users_found=()
    
    # Method 1: REST API enumeration
    log_info "Attempting user enumeration via REST API..."
    local users_api="$target/wp-json/wp/v2/users"
    local users_response=$(make_request "$users_api")
    
    if echo "$users_response" | grep -q '"id":'; then
        local user_names=$(echo "$users_response" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
        local user_slugs=$(echo "$users_response" | grep -o '"slug":"[^"]*"' | cut -d'"' -f4)
        
        if [[ -n "$user_names" ]]; then
            log_success "Users found via REST API:"
            echo "$user_names" | while read -r username; do
                if [[ -n "$username" ]]; then
                    echo -e "    ${GREEN}→${NC} $username"
                    users_found+=("$username")
                fi
            done
        fi
    fi
    
    # Method 2: Author page enumeration
    log_info "Attempting user enumeration via author pages..."
    for i in {1..10}; do
        local author_url="$target/?author=$i"
        local author_response=$(make_request "$author_url")
        
        if echo "$author_response" | grep -q "author\|posts by"; then
            local author_name=$(echo "$author_response" | grep -o 'author[^>]*>[^<]*' | sed 's/.*>//' | head -1)
            if [[ -n "$author_name" && ! " ${users_found[@]} " =~ " $author_name " ]]; then
                log_success "User found via author page: $author_name (ID: $i)"
                users_found+=("$author_name")
            fi
        fi
    done
    
    if [[ ${#users_found[@]} -eq 0 ]]; then
        log_warning "No users enumerated"
    else
        echo -e "\n${YELLOW}Total users found: ${#users_found[@]}${NC}"
    fi
}

enumerate_plugins() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ Plugin Enumeration ═══${NC}"
    
    local plugins_found=()
    
    log_info "Enumerating installed plugins..."
    
    for plugin in "${COMMON_PLUGINS[@]}"; do
        local plugin_url="$target/wp-content/plugins/$plugin/"
        
        if check_url_exists "$plugin_url"; then
            log_success "Plugin found: $plugin"
            plugins_found+=("$plugin")
            
            # Try to get plugin version
            local readme_url="$target/wp-content/plugins/$plugin/readme.txt"
            if check_url_exists "$readme_url"; then
                local readme_content=$(make_request "$readme_url")
                local version=$(echo "$readme_content" | grep -i "stable tag\|version" | head -1 | sed 's/.*: *//')
                if [[ -n "$version" ]]; then
                    echo -e "    ${YELLOW}Version: $version${NC}"
                fi
            fi
        elif [[ "$VERBOSE" == "true" ]]; then
            log_info "Plugin not found: $plugin"
        fi
    done
    
    # Check for plugins directory listing
    local plugins_dir="$target/wp-content/plugins/"
    local plugins_listing=$(make_request "$plugins_dir")
    if echo "$plugins_listing" | grep -i "index of\|directory listing" >/dev/null 2>&1; then
        log_warning "Plugins directory listing enabled"
        # Extract additional plugins from directory listing
        local additional_plugins=$(echo "$plugins_listing" | grep -o 'href="[^"]*/"' | cut -d'"' -f2 | grep -v '^\.\.\?/$')
        if [[ -n "$additional_plugins" ]]; then
            log_info "Additional plugins found in directory listing:"
            echo "$additional_plugins" | while read -r plugin_dir; do
                local plugin_name=$(echo "$plugin_dir" | sed 's|/||g')
                if [[ -n "$plugin_name" && ! " ${plugins_found[@]} " =~ " $plugin_name " ]]; then
                    echo -e "    ${GREEN}→${NC} $plugin_name"
                fi
            done
        fi
    fi
    
    if [[ ${#plugins_found[@]} -eq 0 ]]; then
        log_warning "No common plugins detected"
    else
        echo -e "\n${YELLOW}Total plugins found: ${#plugins_found[@]}${NC}"
    fi
}

enumerate_themes() {
    local target="$1"
    
    echo -e "\n${CYAN}═══ Theme Enumeration ═══${NC}"
    
    local themes_found=()
    
    log_info "Enumerating installed themes..."
    
    # Check active theme from page source
    local page_content=$(make_request "$target")
    local active_theme=$(echo "$page_content" | grep -o 'wp-content/themes/[^/]*' | cut -d'/' -f3 | head -1)
    if [[ -n "$active_theme" ]]; then
        log_success "Active theme detected: $active_theme"
        themes_found+=("$active_theme")
    fi
    
    # Enumerate common themes
    for theme in "${COMMON_THEMES[@]}"; do
        local theme_url="$target/wp-content/themes/$theme/"
        
        if check_url_exists "$theme_url"; then
            if [[ ! " ${themes_found[@]} " =~ " $theme " ]]; then
                log_success "Theme found: $theme"
                themes_found+=("$theme")
            fi
            
            # Try to get theme version
            local style_css="$target/wp-content/themes/$theme/style.css"
            if check_url_exists "$style_css"; then
                local style_content=$(make_request "$style_css" | head -20)
                local version=$(echo "$style_content" | grep -i "version:" | head -1 | sed 's/.*: *//')
                if [[ -n "$version" ]]; then
                    echo -e "    ${YELLOW}Version: $version${NC}"
                fi
            fi
        elif [[ "$VERBOSE" == "true" ]]; then
            log_info "Theme not found: $theme"
        fi
    done
    
    # Check for themes directory listing
    local themes_dir="$target/wp-content/themes/"
    local themes_listing=$(make_request "$themes_dir")
    if echo "$themes_listing" | grep -i "index of\|directory listing" >/dev/null 2>&1; then
        log_warning "Themes directory listing enabled"
    fi
    
    if [[ ${#themes_found[@]} -eq 0 ]]; then
        log_warning "No themes detected"
    else
        echo -e "\n${YELLOW}Total themes found: ${#themes_found[@]}${NC}"
    fi
}

# ============================================================================
# Main Scanning Function
# ============================================================================

scan_wordpress() {
    local target="$1"
    
    echo -e "${BLUE}[i] Starting WordPress security scan of: $target${NC}"
    echo -e "${BLUE}[i] Timestamp: $(date)${NC}"
    echo ""
    
    # Detect WordPress
    if ! detect_wordpress "$target"; then
        log_error "Target does not appear to be running WordPress"
        return 1
    fi
    
    # Vulnerability checks
    if [[ "$CHECK_VULNS" == "true" ]]; then
        check_wordpress_vulnerabilities "$target"
    fi
    
    # User enumeration
    if [[ "$ENUMERATE_USERS" == "true" ]]; then
        enumerate_users "$target"
    fi
    
    # Plugin enumeration
    if [[ "$ENUMERATE_PLUGINS" == "true" ]]; then
        enumerate_plugins "$target"
    fi
    
    # Theme enumeration
    if [[ "$ENUMERATE_THEMES" == "true" ]]; then
        enumerate_themes "$target"
    fi
    
    echo -e "\n${GREEN}[+] WordPress security scan completed${NC}"
    
    # Save to file if specified
    if [[ -n "$OUTPUT_FILE" ]]; then
        {
            echo "CVEHACK WordPress Security Scan Report"
            echo "Target: $target"
            echo "Timestamp: $(date)"
            echo "======================================="
            echo ""
            echo "Scan completed successfully"
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
            -u|--enumerate-users)
                ENUMERATE_USERS=true
                shift
                ;;
            -p|--enumerate-plugins)
                ENUMERATE_PLUGINS=true
                shift
                ;;
            -t|--enumerate-themes)
                ENUMERATE_THEMES=true
                shift
                ;;
            --no-vulns)
                CHECK_VULNS=false
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
    scan_wordpress "$TARGET"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
