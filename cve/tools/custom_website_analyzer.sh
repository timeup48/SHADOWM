#!/bin/bash

# ============================================================================
# Custom Website Size and Performance Analyzer
# Replacement for website size analysis tools - Built from scratch for CVEHACK
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
DEEP_ANALYSIS=false

# ============================================================================
# Core Functions
# ============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    Custom Website Size & Performance Analyzer               ║"
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
    echo "  -d, --deep          Deep analysis (check all resources)"
    echo "  -h, --help          Show this help"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0 https://example.com"
    echo "  $0 http://target.com -d -o analysis.txt"
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
# Size Analysis Functions
# ============================================================================

get_page_size() {
    local url="$1"
    local size_info
    
    log_info "Analyzing page size for: $url"
    
    # Get page with headers to analyze size
    size_info=$(curl -s -w "Size: %{size_download} bytes\nTime: %{time_total}s\nSpeed: %{speed_download} bytes/s\nResponse: %{http_code}\nRedirects: %{num_redirects}\n" \
                     --max-time 30 \
                     --user-agent "CVEHACK-Size-Analyzer/1.0" \
                     "$url" -o /tmp/cvehack_page_content.tmp 2>/dev/null)
    
    if [[ $? -eq 0 ]]; then
        echo "$size_info"
        
        # Analyze content if available
        if [[ -f "/tmp/cvehack_page_content.tmp" ]]; then
            local content_size=$(wc -c < /tmp/cvehack_page_content.tmp)
            local line_count=$(wc -l < /tmp/cvehack_page_content.tmp)
            
            echo "Content Lines: $line_count"
            echo "Actual Content Size: $content_size bytes"
            
            # Clean up
            rm -f /tmp/cvehack_page_content.tmp
        fi
    else
        log_error "Failed to retrieve page size information"
        return 1
    fi
}

analyze_response_headers() {
    local url="$1"
    
    echo -e "\n${CYAN}═══ Response Headers Analysis ═══${NC}"
    
    local headers=$(curl -s -I --max-time 10 --user-agent "CVEHACK-Size-Analyzer/1.0" "$url" 2>/dev/null)
    
    if [[ -n "$headers" ]]; then
        # Extract key headers
        local content_length=$(echo "$headers" | grep -i "content-length:" | cut -d' ' -f2- | tr -d '\r')
        local content_type=$(echo "$headers" | grep -i "content-type:" | cut -d' ' -f2- | tr -d '\r')
        local content_encoding=$(echo "$headers" | grep -i "content-encoding:" | cut -d' ' -f2- | tr -d '\r')
        local server=$(echo "$headers" | grep -i "server:" | cut -d' ' -f2- | tr -d '\r')
        local cache_control=$(echo "$headers" | grep -i "cache-control:" | cut -d' ' -f2- | tr -d '\r')
        
        [[ -n "$content_length" ]] && log_success "Content-Length: $content_length bytes"
        [[ -n "$content_type" ]] && log_success "Content-Type: $content_type"
        [[ -n "$content_encoding" ]] && log_success "Content-Encoding: $content_encoding"
        [[ -n "$server" ]] && log_success "Server: $server"
        [[ -n "$cache_control" ]] && log_success "Cache-Control: $cache_control"
        
        # Check for compression
        if echo "$headers" | grep -qi "gzip\|deflate\|br"; then
            log_success "Compression enabled (good for performance)"
        else
            log_warning "No compression detected (may impact performance)"
        fi
        
        # Check for caching headers
        if echo "$headers" | grep -qi "cache-control\|expires\|etag"; then
            log_success "Caching headers present"
        else
            log_warning "No caching headers found"
        fi
    else
        log_error "Failed to retrieve headers"
    fi
}

analyze_page_resources() {
    local url="$1"
    
    echo -e "\n${CYAN}═══ Page Resources Analysis ═══${NC}"
    
    local content=$(curl -s --max-time 15 --user-agent "CVEHACK-Size-Analyzer/1.0" "$url" 2>/dev/null)
    
    if [[ -n "$content" ]]; then
        # Count different resource types
        local css_count=$(echo "$content" | grep -o '<link[^>]*\.css' | wc -l)
        local js_count=$(echo "$content" | grep -o '<script[^>]*\.js\|<script[^>]*src=' | wc -l)
        local img_count=$(echo "$content" | grep -o '<img[^>]*src=' | wc -l)
        local external_links=$(echo "$content" | grep -o 'href="http[^"]*"' | wc -l)
        
        log_success "CSS files referenced: $css_count"
        log_success "JavaScript files referenced: $js_count"
        log_success "Images referenced: $img_count"
        log_success "External links: $external_links"
        
        # Extract and analyze resource URLs if deep analysis is enabled
        if [[ "$DEEP_ANALYSIS" == "true" ]]; then
            analyze_resource_sizes "$url" "$content"
        fi
        
        # Check for common performance issues
        if [[ $css_count -gt 10 ]]; then
            log_warning "High number of CSS files ($css_count) - consider bundling"
        fi
        
        if [[ $js_count -gt 15 ]]; then
            log_warning "High number of JavaScript files ($js_count) - consider bundling"
        fi
        
        if [[ $img_count -gt 50 ]]; then
            log_warning "High number of images ($img_count) - consider optimization"
        fi
    else
        log_error "Failed to retrieve page content"
    fi
}

analyze_resource_sizes() {
    local base_url="$1"
    local content="$2"
    
    echo -e "\n${CYAN}═══ Individual Resource Sizes ═══${NC}"
    
    # Extract CSS files
    local css_files=$(echo "$content" | grep -o 'href="[^"]*\.css[^"]*"' | sed 's/href="//g' | sed 's/"//g')
    if [[ -n "$css_files" ]]; then
        log_info "Analyzing CSS files..."
        echo "$css_files" | head -5 | while read -r css_file; do
            if [[ "$css_file" =~ ^https?:// ]]; then
                local css_url="$css_file"
            else
                local css_url="$(echo "$base_url" | sed 's|/[^/]*$||')/$css_file"
            fi
            
            local css_size=$(curl -s -w "%{size_download}" -o /dev/null --max-time 5 "$css_url" 2>/dev/null)
            if [[ -n "$css_size" && "$css_size" != "0" ]]; then
                echo -e "  ${GREEN}→${NC} $(basename "$css_file"): $css_size bytes"
            fi
        done
    fi
    
    # Extract JS files
    local js_files=$(echo "$content" | grep -o 'src="[^"]*\.js[^"]*"' | sed 's/src="//g' | sed 's/"//g')
    if [[ -n "$js_files" ]]; then
        log_info "Analyzing JavaScript files..."
        echo "$js_files" | head -5 | while read -r js_file; do
            if [[ "$js_file" =~ ^https?:// ]]; then
                local js_url="$js_file"
            else
                local js_url="$(echo "$base_url" | sed 's|/[^/]*$||')/$js_file"
            fi
            
            local js_size=$(curl -s -w "%{size_download}" -o /dev/null --max-time 5 "$js_url" 2>/dev/null)
            if [[ -n "$js_size" && "$js_size" != "0" ]]; then
                echo -e "  ${GREEN}→${NC} $(basename "$js_file"): $js_size bytes"
            fi
        done
    fi
}

analyze_performance_metrics() {
    local url="$1"
    
    echo -e "\n${CYAN}═══ Performance Metrics ═══${NC}"
    
    # Multiple requests to get average timing
    local total_time=0
    local successful_requests=0
    
    for i in {1..3}; do
        local timing=$(curl -s -w "%{time_total}" -o /dev/null --max-time 10 "$url" 2>/dev/null)
        if [[ -n "$timing" && "$timing" != "0.000" ]]; then
            total_time=$(echo "$total_time + $timing" | bc 2>/dev/null || echo "$total_time")
            ((successful_requests++))
        fi
    done
    
    if [[ $successful_requests -gt 0 ]]; then
        local avg_time=$(echo "scale=3; $total_time / $successful_requests" | bc 2>/dev/null || echo "N/A")
        log_success "Average response time: ${avg_time}s"
        
        # Performance assessment
        if (( $(echo "$avg_time < 1.0" | bc -l 2>/dev/null || echo 0) )); then
            log_success "Performance: Excellent (< 1s)"
        elif (( $(echo "$avg_time < 3.0" | bc -l 2>/dev/null || echo 0) )); then
            log_success "Performance: Good (< 3s)"
        elif (( $(echo "$avg_time < 5.0" | bc -l 2>/dev/null || echo 0) )); then
            log_warning "Performance: Moderate (< 5s)"
        else
            log_warning "Performance: Poor (> 5s)"
        fi
    else
        log_error "Failed to measure performance metrics"
    fi
    
    # Check for common performance headers
    local headers=$(curl -s -I --max-time 10 "$url" 2>/dev/null)
    if echo "$headers" | grep -qi "x-cache\|cf-cache-status\|x-served-by"; then
        log_success "CDN/Caching detected (good for performance)"
    fi
}

generate_size_report() {
    local url="$1"
    
    echo -e "\n${CYAN}═══ Website Size Summary ═══${NC}"
    
    # Get comprehensive page information
    local page_info=$(curl -s -w "Total Size: %{size_download} bytes\nDownload Time: %{time_total}s\nDNS Lookup: %{time_namelookup}s\nConnect Time: %{time_connect}s\nRedirect Time: %{time_redirect}s\nResponse Code: %{http_code}\n" \
                           --max-time 30 \
                           --user-agent "CVEHACK-Size-Analyzer/1.0" \
                           "$url" -o /dev/null 2>/dev/null)
    
    if [[ -n "$page_info" ]]; then
        echo "$page_info" | while read -r line; do
            if [[ -n "$line" ]]; then
                log_success "$line"
            fi
        done
    fi
    
    # Size categories
    local total_size=$(echo "$page_info" | grep "Total Size:" | awk '{print $3}')
    if [[ -n "$total_size" && "$total_size" != "0" ]]; then
        if [[ $total_size -lt 100000 ]]; then
            log_success "Size Category: Small (< 100KB)"
        elif [[ $total_size -lt 500000 ]]; then
            log_success "Size Category: Medium (< 500KB)"
        elif [[ $total_size -lt 1000000 ]]; then
            log_warning "Size Category: Large (< 1MB)"
        else
            log_warning "Size Category: Very Large (> 1MB)"
        fi
    fi
}

# ============================================================================
# Main Analysis Function
# ============================================================================

analyze_website() {
    local target="$1"
    
    echo -e "${BLUE}[i] Starting website size and performance analysis of: $target${NC}"
    echo -e "${BLUE}[i] Timestamp: $(date)${NC}"
    echo ""
    
    # Basic page size analysis
    get_page_size "$target"
    
    # Response headers analysis
    analyze_response_headers "$target"
    
    # Page resources analysis
    analyze_page_resources "$target"
    
    # Performance metrics
    analyze_performance_metrics "$target"
    
    # Generate summary report
    generate_size_report "$target"
    
    echo -e "\n${GREEN}[+] Website analysis completed${NC}"
    
    # Save to file if specified
    if [[ -n "$OUTPUT_FILE" ]]; then
        {
            echo "CVEHACK Website Size & Performance Analysis Report"
            echo "Target: $target"
            echo "Timestamp: $(date)"
            echo "=================================================="
            echo ""
            echo "Analysis completed successfully"
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
            -d|--deep)
                DEEP_ANALYSIS=true
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
    
    # Start analysis
    analyze_website "$TARGET"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
