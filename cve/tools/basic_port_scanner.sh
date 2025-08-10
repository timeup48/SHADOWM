#!/bin/bash

# Basic Port Scanner - Built from Scratch
DESCRIPTION="Basic Port Scanner"

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

scan_ports() {
    local target="$1"
    local ports="${2:-22,23,25,53,80,110,143,443,993,995}"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target> [ports]"
        exit 1
    fi
    
    print_info "Scanning ports on $target"
    print_info "Ports: $ports"
    
    IFS=',' read -ra PORT_ARRAY <<< "$ports"
    for port in "${PORT_ARRAY[@]}"; do
        scan_single_port "$target" "$port"
    done
}

scan_single_port() {
    local target="$1"
    local port="$2"
    
    if command -v nc &> /dev/null; then
        if nc -z -w 1 "$target" "$port" 2>/dev/null; then
            print_success "Port $port is OPEN"
        else
            print_info "Port $port is closed"
        fi
    elif [[ -e /dev/tcp ]]; then
        if exec 3<>"/dev/tcp/$target/$port" 2>/dev/null; then
            print_success "Port $port is OPEN"
            exec 3>&-
        else
            print_info "Port $port is closed"
        fi
    else
        print_warning "No port scanning method available"
    fi
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_ports "$1" "$2"
fi
