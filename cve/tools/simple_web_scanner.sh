#!/bin/bash

# Simple Web Vulnerability Scanner - Built from Scratch
CVE_ID="GENERIC-WEB"
DESCRIPTION="Simple Web Vulnerability Scanner"

# Source CVEHACK libraries if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../../lib/colors.sh" ]]; then
    source "$SCRIPT_DIR/../../lib/colors.sh"
else
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
    print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
    print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
fi

scan_web_target() {
    local target="$1"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target>"
        exit 1
    fi
    
    print_info "Starting web vulnerability scan on $target"
    
    # Basic connectivity test
    if command -v curl &> /dev/null; then
        local response=$(curl -s -I --connect-timeout 5 "$target" 2>/dev/null)
        if [[ -n "$response" ]]; then
            print_success "Target is reachable"
            
            # Check server header
            local server=$(echo "$response" | grep -i "server:" | cut -d: -f2- | xargs)
            if [[ -n "$server" ]]; then
                print_info "Server: $server"
            fi
            
            # Test for common vulnerabilities
            test_sql_injection "$target"
            test_xss_vulnerabilities "$target"
            
        else
            print_error "Target not reachable"
        fi
    else
        print_warning "curl not available - limited testing"
    fi
}

test_sql_injection() {
    local target="$1"
    print_info "Testing for SQL injection..."
    
    local sql_payloads=("'" "' OR '1'='1" "'; DROP TABLE")
    for payload in "${sql_payloads[@]}"; do
        local encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed "s/'/%27/g")
        local test_url="$target/?id=$encoded_payload"
        
        if command -v curl &> /dev/null; then
            local response=$(curl -s --connect-timeout 3 "$test_url" 2>/dev/null)
            if echo "$response" | grep -qi "mysql\|sql syntax\|oracle"; then
                print_error "Potential SQL injection found"
                break
            fi
        fi
    done
}

test_xss_vulnerabilities() {
    local target="$1"
    print_info "Testing for XSS vulnerabilities..."
    
    local xss_payloads=("<script>alert('XSS')</script>" "<img src=x onerror=alert('XSS')>")
    for payload in "${xss_payloads[@]}"; do
        local encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed 's/</%3C/g' | sed 's/>/%3E/g')
        local test_url="$target/?q=$encoded_payload"
        
        if command -v curl &> /dev/null; then
            local response=$(curl -s --connect-timeout 3 "$test_url" 2>/dev/null)
            if echo "$response" | grep -q "alert('XSS')"; then
                print_error "Potential XSS vulnerability found"
                break
            fi
        fi
    done
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_web_target "$1"
fi
