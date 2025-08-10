#!/bin/bash

# ============================================================================
# Custom Directory & File Scanner
# Replacement for dirb - Built from scratch for CVEHACK
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
THREADS=10
TIMEOUT=5
WORDLIST=""
EXTENSIONS=""
RECURSIVE=false
STATUS_CODES="200,301,302,403,401,500"

# ============================================================================
# Built-in Wordlists
# ============================================================================

create_common_wordlist() {
    local wordlist_file="$1"
    
    cat > "$wordlist_file" << 'EOF'
admin
administrator
login
wp-admin
wp-login
phpmyadmin
mysql
database
db
backup
backups
config
configuration
test
testing
dev
development
staging
api
docs
documentation
help
support
images
img
css
js
javascript
assets
uploads
files
download
downloads
temp
tmp
cache
logs
log
error
errors
include
includes
lib
library
src
source
bin
cgi-bin
scripts
data
xml
json
txt
pdf
zip
tar
gz
sql
bak
old
new
1
2
3
home
index
main
default
about
contact
news
blog
forum
shop
store
cart
checkout
search
profile
user
users
member
members
account
accounts
dashboard
panel
control
manage
manager
system
info
phpinfo
readme
license
changelog
install
setup
upgrade
update
migrate
export
import
report
reports
stats
statistics
analytics
monitor
monitoring
health
status
version
build
release
deploy
deployment
production
prod
stage
qa
quality
assurance
security
secure
private
public
internal
external
service
services
resource
resources
component
components
module
modules
plugin
plugins
addon
addons
extension
extensions
theme
themes
template
templates
layout
layouts
style
styles
script
scripts
font
fonts
icon
icons
image
images
media
video
videos
audio
music
document
documents
file
files
archive
archives
backup
backups
EOF
}

create_file_extensions_list() {
    local ext_file="$1"
    
    cat > "$ext_file" << 'EOF'
php
html
htm
asp
aspx
jsp
js
css
txt
xml
json
pdf
doc
docx
xls
xlsx
zip
tar
gz
sql
bak
old
log
conf
config
ini
cfg
properties
yml
yaml
md
readme
license
changelog
EOF
}

# ============================================================================
# Core Functions
# ============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    Custom Directory & File Scanner                          ║"
    echo "║                        CVEHACK - Built from Scratch                         ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo -e "${YELLOW}Usage: $0 <target> [options]${NC}"
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo "  -w, --wordlist FILE  Custom wordlist file"
    echo "  -e, --extensions EXT Comma-separated file extensions (e.g., php,html,txt)"
    echo "  -t, --threads NUM    Number of concurrent threads (default: 10)"
    echo "  -T, --timeout SEC    Request timeout in seconds (default: 5)"
    echo "  -s, --status CODES   HTTP status codes to show (default: 200,301,302,403,401,500)"
    echo "  -r, --recursive      Recursive directory scanning"
    echo "  -o, --output FILE    Save results to file"
    echo "  -v, --verbose        Verbose output"
    echo "  -h, --help          Show this help"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0 https://example.com"
    echo "  $0 http://target.com -w custom.txt -e php,html -t 20"
    echo "  $0 https://site.com -r -s 200,403 -o results.txt"
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
    local status="$1"
    local size="$2"
    local path="$3"
    
    case "$status" in
        "200")
            echo -e "${GREEN}[200]${NC} $path (Size: $size)"
            ;;
        "301"|"302")
            echo -e "${YELLOW}[${status}]${NC} $path (Redirect)"
            ;;
        "403")
            echo -e "${RED}[403]${NC} $path (Forbidden)"
            ;;
        "401")
            echo -e "${PURPLE}[401]${NC} $path (Unauthorized)"
            ;;
        "500")
            echo -e "${RED}[500]${NC} $path (Server Error)"
            ;;
        *)
            echo -e "${BLUE}[${status}]${NC} $path (Size: $size)"
            ;;
    esac
}

# ============================================================================
# Scanning Functions
# ============================================================================

test_url() {
    local url="$1"
    local path="$2"
    local full_url="${url%/}/$path"
    
    # Make HTTP request and capture response
    local response=$(curl -s -w "HTTPSTATUS:%{http_code};SIZE:%{size_download};TIME:%{time_total}" \
                          --max-time "$TIMEOUT" \
                          --user-agent "CVEHACK-Directory-Scanner/1.0" \
                          --connect-timeout 3 \
                          -o /dev/null \
                          "$full_url" 2>/dev/null)
    
    if [[ -n "$response" ]]; then
        local http_status=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        local size=$(echo "$response" | grep -o "SIZE:[0-9]*" | cut -d: -f2)
        local time=$(echo "$response" | grep -o "TIME:[0-9.]*" | cut -d: -f2)
        
        # Check if status code should be reported
        if echo "$STATUS_CODES" | grep -q "$http_status"; then
            log_found "$http_status" "$size" "/$path"
            
            # Save to results if output file specified
            if [[ -n "$OUTPUT_FILE" ]]; then
                echo "[$http_status] $full_url (Size: $size, Time: ${time}s)" >> "$OUTPUT_FILE"
            fi
            
            # If recursive and this is a directory (301/302), add to queue
            if [[ "$RECURSIVE" == "true" && ("$http_status" == "301" || "$http_status" == "302") ]]; then
                echo "$path" >> /tmp/cvehack_dirs_to_scan.tmp
            fi
            
            return 0
        fi
    fi
    
    return 1
}

scan_directory() {
    local target="$1"
    local wordlist="$2"
    local base_path="${3:-}"
    
    local found_count=0
    local total_requests=0
    local current_jobs=0
    
    log_info "Scanning $(wc -l < "$wordlist") entries..."
    
    # Create temporary files for job control
    local job_control_file="/tmp/cvehack_jobs_$$"
    echo "0" > "$job_control_file"
    
    while IFS= read -r word; do
        # Skip empty lines and comments
        [[ -z "$word" || "$word" =~ ^# ]] && continue
        
        # Construct path
        local scan_path="$base_path$word"
        
        # Wait if we have too many background jobs
        while [[ $(jobs -r | wc -l) -ge $THREADS ]]; do
            sleep 0.1
        done
        
        # Test the path in background
        {
            if test_url "$target" "$scan_path"; then
                echo $(($(cat "$job_control_file") + 1)) > "$job_control_file"
            fi
        } &
        
        ((total_requests++))
        
        # Show progress every 50 requests
        if [[ $((total_requests % 50)) -eq 0 ]]; then
            local current_found=$(cat "$job_control_file" 2>/dev/null || echo "0")
            [[ "$VERBOSE" == "true" ]] && log_info "Progress: $total_requests requests, $current_found found"
        fi
        
        # Test with extensions if specified
        if [[ -n "$EXTENSIONS" ]]; then
            IFS=',' read -ra EXT_ARRAY <<< "$EXTENSIONS"
            for ext in "${EXT_ARRAY[@]}"; do
                # Wait for available slot
                while [[ $(jobs -r | wc -l) -ge $THREADS ]]; do
                    sleep 0.1
                done
                
                # Test with extension in background
                {
                    if test_url "$target" "$scan_path.$ext"; then
                        echo $(($(cat "$job_control_file") + 1)) > "$job_control_file"
                    fi
                } &
                
                ((total_requests++))
            done
        fi
        
    done < "$wordlist"
    
    # Wait for all background jobs to complete
    wait
    
    found_count=$(cat "$job_control_file" 2>/dev/null || echo "0")
    rm -f "$job_control_file"
    
    log_info "Scan completed: $total_requests requests made, $found_count items found"
    
    return "$found_count"
}

perform_recursive_scan() {
    local target="$1"
    local wordlist="$2"
    local max_depth="${3:-3}"
    local current_depth=1
    
    log_info "Starting recursive scan (max depth: $max_depth)..."
    
    # Initialize directories to scan
    rm -f /tmp/cvehack_dirs_to_scan.tmp
    touch /tmp/cvehack_dirs_to_scan.tmp
    
    # Initial scan
    scan_directory "$target" "$wordlist" ""
    
    # Recursive scanning
    while [[ $current_depth -lt $max_depth && -s /tmp/cvehack_dirs_to_scan.tmp ]]; do
        ((current_depth++))
        log_info "Recursive scan depth $current_depth..."
        
        # Create new list for next iteration
        local next_dirs="/tmp/cvehack_dirs_next_$$.tmp"
        touch "$next_dirs"
        
        # Scan each discovered directory
        while IFS= read -r dir_path; do
            [[ -z "$dir_path" ]] && continue
            
            log_info "Scanning subdirectory: /$dir_path/"
            scan_directory "$target" "$wordlist" "${dir_path}/"
            
            # Add any new directories found to next iteration
            if [[ -f /tmp/cvehack_dirs_to_scan.tmp ]]; then
                cat /tmp/cvehack_dirs_to_scan.tmp >> "$next_dirs"
                rm -f /tmp/cvehack_dirs_to_scan.tmp
                touch /tmp/cvehack_dirs_to_scan.tmp
            fi
            
        done < /tmp/cvehack_dirs_to_scan.tmp
        
        # Move next dirs to current for next iteration
        mv "$next_dirs" /tmp/cvehack_dirs_to_scan.tmp
    done
    
    # Cleanup
    rm -f /tmp/cvehack_dirs_to_scan.tmp /tmp/cvehack_dirs_next_*.tmp
    
    log_success "Recursive scan completed"
}

# ============================================================================
# Main Scanning Function
# ============================================================================

scan_target() {
    local target="$1"
    
    echo -e "${BLUE}[i] Starting directory and file scan of: $target${NC}"
    echo -e "${BLUE}[i] Timestamp: $(date)${NC}"
    echo -e "${BLUE}[i] Threads: $THREADS, Timeout: ${TIMEOUT}s${NC}"
    echo -e "${BLUE}[i] Status codes: $STATUS_CODES${NC}"
    [[ -n "$EXTENSIONS" ]] && echo -e "${BLUE}[i] Extensions: $EXTENSIONS${NC}"
    [[ "$RECURSIVE" == "true" ]] && echo -e "${BLUE}[i] Recursive scanning enabled${NC}"
    echo ""
    
    # Prepare wordlist
    local scan_wordlist="$WORDLIST"
    if [[ -z "$scan_wordlist" ]]; then
        scan_wordlist="/tmp/cvehack_common_wordlist_$$.txt"
        log_info "Creating built-in wordlist..."
        create_common_wordlist "$scan_wordlist"
    fi
    
    if [[ ! -f "$scan_wordlist" ]]; then
        log_error "Wordlist file not found: $scan_wordlist"
        return 1
    fi
    
    log_info "Using wordlist: $scan_wordlist ($(wc -l < "$scan_wordlist") entries)"
    
    # Test target accessibility
    log_info "Testing target accessibility..."
    local test_response=$(curl -s -w "%{http_code}" -o /dev/null --max-time 10 "$target" 2>/dev/null)
    if [[ -z "$test_response" || "$test_response" == "000" ]]; then
        log_error "Target appears to be unreachable: $target"
        return 1
    else
        log_success "Target accessible (HTTP $test_response)"
    fi
    
    # Initialize output file
    if [[ -n "$OUTPUT_FILE" ]]; then
        {
            echo "CVEHACK Directory Scanner Results"
            echo "Target: $target"
            echo "Timestamp: $(date)"
            echo "Threads: $THREADS, Timeout: ${TIMEOUT}s"
            echo "Status codes: $STATUS_CODES"
            [[ -n "$EXTENSIONS" ]] && echo "Extensions: $EXTENSIONS"
            echo "=================================="
            echo ""
        } > "$OUTPUT_FILE"
        log_info "Results will be saved to: $OUTPUT_FILE"
    fi
    
    # Perform scanning
    if [[ "$RECURSIVE" == "true" ]]; then
        perform_recursive_scan "$target" "$scan_wordlist"
    else
        scan_directory "$target" "$scan_wordlist"
    fi
    
    # Cleanup temporary wordlist if created
    if [[ "$scan_wordlist" =~ /tmp/cvehack_common_wordlist ]]; then
        rm -f "$scan_wordlist"
    fi
    
    echo -e "\n${GREEN}[+] Directory and file scan completed${NC}"
    
    if [[ -n "$OUTPUT_FILE" ]]; then
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
            -w|--wordlist)
                WORDLIST="$2"
                shift 2
                ;;
            -e|--extensions)
                EXTENSIONS="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -T|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -s|--status)
                STATUS_CODES="$2"
                shift 2
                ;;
            -r|--recursive)
                RECURSIVE=true
                shift
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
    
    # Validate target format
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        TARGET="http://$TARGET"
        log_warning "No protocol specified, assuming HTTP: $TARGET"
    fi
    
    # Validate numeric parameters
    if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 || "$THREADS" -gt 100 ]]; then
        log_error "Invalid thread count: $THREADS (must be 1-100)"
        exit 1
    fi
    
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 1 || "$TIMEOUT" -gt 60 ]]; then
        log_error "Invalid timeout: $TIMEOUT (must be 1-60 seconds)"
        exit 1
    fi
    
    # Validate wordlist if specified
    if [[ -n "$WORDLIST" && ! -f "$WORDLIST" ]]; then
        log_error "Wordlist file not found: $WORDLIST"
        exit 1
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
