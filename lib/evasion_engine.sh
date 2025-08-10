#!/bin/bash

# ============================================================================
# Advanced Evasion and Stealth Scanning Engine for CVEHACK
# ============================================================================

# Configuration
EVASION_CONFIG_DIR="./config/evasion"
USER_AGENTS_FILE="$EVASION_CONFIG_DIR/user_agents.txt"
PROXY_LIST_FILE="$EVASION_CONFIG_DIR/proxy_list.txt"
TIMING_PROFILES_FILE="$EVASION_CONFIG_DIR/timing_profiles.txt"

# Evasion settings
EVASION_LEVEL="medium"  # low, medium, high, extreme
RANDOMIZE_TIMING=true
RANDOMIZE_USER_AGENT=true
USE_PROXY_ROTATION=false
FRAGMENT_REQUESTS=false
DECOY_SCANNING=false

# Initialize evasion engine
init_evasion_engine() {
    mkdir -p "$EVASION_CONFIG_DIR"
    
    print_info "Initializing Advanced Evasion Engine..."
    
    create_user_agents_database
    create_timing_profiles
    create_proxy_list
    
    print_success "Evasion engine initialized"
}

# ============================================================================
# User Agent Rotation System
# ============================================================================

create_user_agents_database() {
    local ua_file="$USER_AGENTS_FILE"
    
    print_info "Creating user agent rotation database..."
    
    cat > "$ua_file" << 'EOF'
# Comprehensive User Agent Database for Evasion
# Format: CATEGORY|USER_AGENT_STRING|FREQUENCY_WEIGHT
CHROME|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36|HIGH
CHROME|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36|HIGH
FIREFOX|Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0|HIGH
FIREFOX|Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0|HIGH
SAFARI|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15|MEDIUM
EDGE|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0|MEDIUM
MOBILE_CHROME|Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36|LOW
MOBILE_SAFARI|Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1|LOW
CURL|curl/7.68.0|VERY_LOW
WGET|Wget/1.20.3 (linux-gnu)|VERY_LOW
PYTHON|Python-urllib/3.8|VERY_LOW
SCANNER|Nmap Scripting Engine|NEVER
SCANNER|sqlmap/1.6.12|NEVER
SCANNER|Nikto/2.1.6|NEVER
LEGITIMATE_BOT|Googlebot/2.1 (+http://www.google.com/bot.html)|LOW
LEGITIMATE_BOT|Bingbot/2.0 (+http://www.bing.com/bingbot.htm)|LOW
SECURITY_SCANNER|Mozilla/5.0 (compatible; Nessus)|NEVER
EOF

    print_success "User agent database created with $(grep -c "|" "$ua_file") entries"
}

get_random_user_agent() {
    local category="${1:-ANY}"
    local avoid_scanners="${2:-true}"
    
    local ua_pool="$USER_AGENTS_FILE"
    
    # Filter by category if specified
    if [[ "$category" != "ANY" ]]; then
        ua_pool=$(grep "^$category|" "$USER_AGENTS_FILE")
    else
        ua_pool=$(cat "$USER_AGENTS_FILE")
    fi
    
    # Remove scanner user agents if avoiding detection
    if [[ "$avoid_scanners" == "true" ]]; then
        ua_pool=$(echo "$ua_pool" | grep -v "SCANNER\|NEVER")
    fi
    
    # Weight-based selection (prefer HIGH frequency)
    local high_weight_uas=$(echo "$ua_pool" | grep "|HIGH$")
    local medium_weight_uas=$(echo "$ua_pool" | grep "|MEDIUM$")
    local low_weight_uas=$(echo "$ua_pool" | grep "|LOW$")
    
    local selected_ua=""
    local random_choice=$((RANDOM % 100))
    
    if [[ $random_choice -lt 60 && -n "$high_weight_uas" ]]; then
        # 60% chance for high weight
        selected_ua=$(echo "$high_weight_uas" | shuf -n 1)
    elif [[ $random_choice -lt 85 && -n "$medium_weight_uas" ]]; then
        # 25% chance for medium weight
        selected_ua=$(echo "$medium_weight_uas" | shuf -n 1)
    elif [[ -n "$low_weight_uas" ]]; then
        # 15% chance for low weight
        selected_ua=$(echo "$low_weight_uas" | shuf -n 1)
    else
        # Fallback to any available
        selected_ua=$(echo "$ua_pool" | shuf -n 1)
    fi
    
    if [[ -n "$selected_ua" ]]; then
        echo "$selected_ua" | cut -d'|' -f2
    else
        # Ultimate fallback
        echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    fi
}

# ============================================================================
# Timing and Rate Limiting Evasion
# ============================================================================

create_timing_profiles() {
    local timing_file="$TIMING_PROFILES_FILE"
    
    print_info "Creating timing evasion profiles..."
    
    cat > "$timing_file" << 'EOF'
# Timing Profiles for Evasion
# Format: PROFILE|MIN_DELAY|MAX_DELAY|JITTER|DESCRIPTION
AGGRESSIVE|0.1|0.5|0.2|Fast scanning with minimal delays
NORMAL|0.5|2.0|0.5|Balanced speed and stealth
STEALTH|2.0|8.0|2.0|Slow and careful scanning
PARANOID|10.0|30.0|10.0|Extremely slow to avoid detection
HUMAN_LIKE|1.0|15.0|5.0|Mimics human browsing patterns
BURST|0.05|0.1|0.02|Very fast bursts with long pauses
LOW_AND_SLOW|30.0|300.0|60.0|Extended timeframes for APT simulation
EOF

    print_success "Timing profiles created"
}

apply_evasion_delay() {
    local profile="${1:-$EVASION_LEVEL}"
    local custom_min="$2"
    local custom_max="$3"
    
    local min_delay max_delay jitter
    
    if [[ -n "$custom_min" && -n "$custom_max" ]]; then
        min_delay="$custom_min"
        max_delay="$custom_max"
        jitter=$(echo "($max_delay - $min_delay) / 4" | bc -l)
    else
        # Get timing from profile
        local timing_info=$(grep "^$profile|" "$TIMING_PROFILES_FILE" 2>/dev/null)
        
        if [[ -n "$timing_info" ]]; then
            IFS='|' read -r prof min_delay max_delay jitter desc <<< "$timing_info"
        else
            # Default to normal profile
            min_delay=0.5
            max_delay=2.0
            jitter=0.5
        fi
    fi
    
    # Calculate random delay with jitter
    local base_delay=$(echo "$min_delay + ($max_delay - $min_delay) * $RANDOM / 32767" | bc -l)
    local jitter_amount=$(echo "($jitter * 2 * $RANDOM / 32767) - $jitter" | bc -l)
    local final_delay=$(echo "$base_delay + $jitter_amount" | bc -l)
    
    # Ensure minimum delay
    if (( $(echo "$final_delay < 0.01" | bc -l) )); then
        final_delay=0.01
    fi
    
    print_info "Applying evasion delay: ${final_delay}s (profile: $profile)"
    sleep "$final_delay"
}

# ============================================================================
# Request Fragmentation and Obfuscation
# ============================================================================

fragment_http_request() {
    local url="$1"
    local method="${2:-GET}"
    local headers="$3"
    local data="$4"
    
    print_info "Fragmenting HTTP request for evasion..."
    
    # Parse URL components
    local protocol=$(echo "$url" | grep -o "^https\?")
    local host=$(echo "$url" | sed 's|^https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    local port=$(echo "$url" | sed 's|^https\?://||' | cut -d'/' -f1 | grep -o ':[0-9]*' | cut -d':' -f2)
    local path=$(echo "$url" | sed 's|^https\?://[^/]*||')
    
    # Default ports
    if [[ -z "$port" ]]; then
        if [[ "$protocol" == "https" ]]; then
            port=443
        else
            port=80
        fi
    fi
    
    if [[ -z "$path" ]]; then
        path="/"
    fi
    
    # Create fragmented request
    local temp_request="/tmp/cvehack_fragment_$$"
    
    # HTTP request line (fragmented)
    echo -n "$method " > "$temp_request"
    sleep 0.1
    echo -n "$path " >> "$temp_request"
    sleep 0.1
    echo "HTTP/1.1" >> "$temp_request"
    
    # Host header (always required)
    echo "Host: $host" >> "$temp_request"
    
    # Add custom headers with delays
    if [[ -n "$headers" ]]; then
        echo "$headers" | while IFS= read -r header; do
            if [[ -n "$header" ]]; then
                echo "$header" >> "$temp_request"
                sleep 0.05
            fi
        done
    fi
    
    # Connection header
    echo "Connection: close" >> "$temp_request"
    echo "" >> "$temp_request"
    
    # Add data if present
    if [[ -n "$data" ]]; then
        echo "$data" >> "$temp_request"
    fi
    
    # Send fragmented request
    if command -v nc &> /dev/null; then
        print_info "Sending fragmented request via netcat..."
        cat "$temp_request" | nc "$host" "$port"
    else
        print_warning "Netcat not available, falling back to curl"
        curl -s -X "$method" "$url" -H "$headers" -d "$data"
    fi
    
    rm -f "$temp_request"
}

# ============================================================================
# Proxy and Source IP Rotation
# ============================================================================

create_proxy_list() {
    local proxy_file="$PROXY_LIST_FILE"
    
    print_info "Creating proxy rotation list..."
    
    cat > "$proxy_file" << 'EOF'
# Proxy List for Source IP Rotation
# Format: TYPE|HOST|PORT|USERNAME|PASSWORD|RELIABILITY|ANONYMITY
HTTP|127.0.0.1|8080|||HIGH|TRANSPARENT
SOCKS5|127.0.0.1|1080|||HIGH|ANONYMOUS
HTTP|proxy1.example.com|3128|||MEDIUM|ANONYMOUS
HTTP|proxy2.example.com|8080|||MEDIUM|TRANSPARENT
SOCKS5|proxy3.example.com|1080|||LOW|ELITE
# Add your own proxy servers here
EOF

    print_success "Proxy list created (configure with real proxies for production use)"
}

get_random_proxy() {
    local proxy_type="${1:-ANY}"
    local min_reliability="${2:-MEDIUM}"
    
    local available_proxies=$(grep -v "^#" "$PROXY_LIST_FILE" 2>/dev/null)
    
    if [[ "$proxy_type" != "ANY" ]]; then
        available_proxies=$(echo "$available_proxies" | grep "^$proxy_type|")
    fi
    
    # Filter by reliability
    case "$min_reliability" in
        "HIGH")
            available_proxies=$(echo "$available_proxies" | grep "|HIGH|")
            ;;
        "MEDIUM")
            available_proxies=$(echo "$available_proxies" | grep -E "|HIGH|MEDIUM|")
            ;;
        "LOW")
            # Include all
            ;;
    esac
    
    if [[ -n "$available_proxies" ]]; then
        echo "$available_proxies" | shuf -n 1
    fi
}

execute_with_proxy() {
    local command="$1"
    local proxy_info="$2"
    
    if [[ -z "$proxy_info" ]]; then
        proxy_info=$(get_random_proxy)
    fi
    
    if [[ -n "$proxy_info" ]]; then
        IFS='|' read -r type host port username password reliability anonymity <<< "$proxy_info"
        
        print_info "Using proxy: $type://$host:$port ($anonymity)"
        
        # Modify command to use proxy
        case "$type" in
            "HTTP")
                if [[ "$command" == curl* ]]; then
                    command="$command --proxy http://$host:$port"
                fi
                ;;
            "SOCKS5")
                if [[ "$command" == curl* ]]; then
                    command="$command --socks5 $host:$port"
                fi
                ;;
        esac
        
        # Add authentication if provided
        if [[ -n "$username" && -n "$password" ]]; then
            if [[ "$command" == curl* ]]; then
                command="$command --proxy-user $username:$password"
            fi
        fi
    fi
    
    # Execute the modified command
    eval "$command"
}

# ============================================================================
# Decoy Scanning and Traffic Masking
# ============================================================================

generate_decoy_traffic() {
    local target="$1"
    local real_scan_command="$2"
    local decoy_count="${3:-5}"
    
    print_info "Generating decoy traffic to mask real scan..."
    
    # Generate decoy source IPs (RFC 1918 private ranges for testing)
    local decoy_ips=()
    for ((i=1; i<=decoy_count; i++)); do
        local decoy_ip="192.168.$((RANDOM % 255)).$((RANDOM % 255))"
        decoy_ips+=("$decoy_ip")
    done
    
    print_info "Using decoy IPs: ${decoy_ips[*]}"
    
    # Launch decoy scans in background
    for decoy_ip in "${decoy_ips[@]}"; do
        (
            # Generate benign traffic
            generate_benign_request "$target" "$decoy_ip" &
            sleep $((RANDOM % 5))
        ) &
    done
    
    # Wait a random amount before real scan
    sleep $((RANDOM % 10 + 5))
    
    # Execute real scan
    print_info "Executing real scan among decoy traffic..."
    eval "$real_scan_command"
    
    # Wait for decoys to finish
    wait
    
    print_success "Decoy scanning completed"
}

generate_benign_request() {
    local target="$1"
    local source_ip="$2"
    
    # Generate legitimate-looking requests
    local benign_paths=("/" "/robots.txt" "/favicon.ico" "/sitemap.xml" "/index.html")
    local random_path=${benign_paths[$RANDOM % ${#benign_paths[@]}]}
    
    local user_agent=$(get_random_user_agent "CHROME")
    
    # Simulate benign browsing
    if command -v curl &> /dev/null; then
        curl -s -H "User-Agent: $user_agent" \
             -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
             -H "Accept-Language: en-US,en;q=0.5" \
             -H "Accept-Encoding: gzip, deflate" \
             -H "Connection: keep-alive" \
             "$target$random_path" > /dev/null 2>&1
    fi
    
    # Random delay between requests
    sleep $((RANDOM % 30 + 10))
}

# ============================================================================
# Advanced Evasion Techniques
# ============================================================================

evade_waf_detection() {
    local payload="$1"
    local evasion_technique="$2"
    
    local evaded_payload="$payload"
    
    case "$evasion_technique" in
        "case_variation")
            # Randomize case
            evaded_payload=$(echo "$payload" | sed 's/./\L&/g; s/\(.\)/\U\1/g' | \
                           awk '{for(i=1;i<=length($0);i++) if(rand()>0.5) $0=substr($0,1,i-1) toupper(substr($0,i,1)) substr($0,i+1)}1')
            ;;
        "url_encoding")
            # Double URL encoding
            evaded_payload=$(echo "$payload" | sed 's/%/%25/g; s/ /%20/g; s/</%3C/g; s/>/%3E/g; s/"/%22/g; s/'\''/%27/g')
            ;;
        "unicode_encoding")
            # Unicode normalization evasion
            evaded_payload=$(echo "$payload" | sed 's/</\u003c/g; s/>/\u003e/g; s/"/\u0022/g')
            ;;
        "comment_insertion")
            # Insert SQL comments
            evaded_payload=$(echo "$payload" | sed 's/SELECT/SE/**/LECT/g; s/UNION/UN/**/ION/g; s/OR/O/**/R/g')
            ;;
        "whitespace_variation")
            # Use different whitespace characters
            evaded_payload=$(echo "$payload" | sed 's/ /\t/g; s/\t/\n/g' | tr '\n' ' ')
            ;;
        "parameter_pollution")
            # HTTP Parameter Pollution
            evaded_payload="$payload&$payload"
            ;;
    esac
    
    print_info "Applied evasion technique '$evasion_technique'"
    echo "$evaded_payload"
}

bypass_rate_limiting() {
    local target="$1"
    local requests_per_minute="${2:-10}"
    local burst_size="${3:-3}"
    
    print_info "Implementing rate limiting bypass strategy..."
    
    local request_interval=$(echo "60 / $requests_per_minute" | bc -l)
    local burst_interval=$(echo "$request_interval / $burst_size" | bc -l)
    
    print_info "Request interval: ${request_interval}s, Burst interval: ${burst_interval}s"
    
    # Implement token bucket algorithm
    local tokens=$burst_size
    local last_refill=$(date +%s)
    
    while true; do
        local current_time=$(date +%s)
        local time_passed=$((current_time - last_refill))
        
        # Refill tokens
        if [[ $time_passed -ge 60 ]]; then
            tokens=$burst_size
            last_refill=$current_time
        fi
        
        if [[ $tokens -gt 0 ]]; then
            # Execute request
            print_info "Executing request (tokens remaining: $tokens)"
            ((tokens--))
            
            # Your actual request logic here
            # execute_scan_request "$target"
            
            sleep "$burst_interval"
        else
            # Wait for token refill
            local wait_time=$((60 - time_passed))
            print_info "Rate limit reached, waiting ${wait_time}s for token refill..."
            sleep "$wait_time"
        fi
    done
}

# ============================================================================
# Stealth Scanning Modes
# ============================================================================

stealth_port_scan() {
    local target="$1"
    local ports="$2"
    local stealth_level="${3:-medium}"
    
    print_info "Initiating stealth port scan on $target..."
    
    case "$stealth_level" in
        "low")
            # Basic stealth - SYN scan with timing
            if command -v nmap &> /dev/null; then
                nmap -sS -T2 -p "$ports" "$target"
            else
                basic_stealth_scan "$target" "$ports"
            fi
            ;;
        "medium")
            # Advanced stealth - fragmented packets, decoys
            if command -v nmap &> /dev/null; then
                nmap -sS -f -T1 -D RND:10 -p "$ports" "$target"
            else
                advanced_stealth_scan "$target" "$ports"
            fi
            ;;
        "high")
            # Maximum stealth - idle scan, source port manipulation
            if command -v nmap &> /dev/null; then
                nmap -sI zombie_host -T0 -p "$ports" "$target" 2>/dev/null || \
                nmap -sS -f -T0 -D RND:20 --source-port 53 -p "$ports" "$target"
            else
                maximum_stealth_scan "$target" "$ports"
            fi
            ;;
    esac
}

basic_stealth_scan() {
    local target="$1"
    local ports="$2"
    
    print_info "Performing basic stealth scan..."
    
    IFS=',' read -ra PORT_ARRAY <<< "$ports"
    for port in "${PORT_ARRAY[@]}"; do
        # Random delay between port checks
        apply_evasion_delay "stealth"
        
        # Use different source ports
        local source_port=$((RANDOM % 64511 + 1024))
        
        if command -v nc &> /dev/null; then
            timeout 2 nc -z -p "$source_port" "$target" "$port" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "Port $port is open"
            fi
        fi
    done
}

advanced_stealth_scan() {
    local target="$1"
    local ports="$2"
    
    print_info "Performing advanced stealth scan with fragmentation..."
    
    # Implement custom TCP SYN scan with fragmentation
    IFS=',' read -ra PORT_ARRAY <<< "$ports"
    for port in "${PORT_ARRAY[@]}"; do
        # Very long delays
        apply_evasion_delay "paranoid"
        
        # Fragment the scan across multiple packets
        fragment_tcp_scan "$target" "$port"
    done
}

fragment_tcp_scan() {
    local target="$1"
    local port="$2"
    
    # This would require raw socket programming
    # For now, simulate with multiple small requests
    print_info "Fragmenting TCP scan for port $port..."
    
    # Multiple connection attempts with different characteristics
    for i in {1..3}; do
        local user_agent=$(get_random_user_agent)
        
        if [[ "$port" == "80" || "$port" == "443" ]]; then
            local protocol="http"
            [[ "$port" == "443" ]] && protocol="https"
            
            # Fragment HTTP request
            fragment_http_request "$protocol://$target:$port/" "HEAD" "User-Agent: $user_agent"
        else
            # Use netcat for other ports
            if command -v nc &> /dev/null; then
                echo "" | timeout 1 nc "$target" "$port" 2>/dev/null
            fi
        fi
        
        sleep 0.5
    done
}

# ============================================================================
# Configuration and Management
# ============================================================================

configure_evasion_settings() {
    clear_screen
    section_header "Advanced Evasion Configuration"
    
    echo -e "${YELLOW}Current Evasion Settings:${NC}"
    echo -e "  Evasion Level: $EVASION_LEVEL"
    echo -e "  Randomize Timing: $RANDOMIZE_TIMING"
    echo -e "  Randomize User-Agent: $RANDOMIZE_USER_AGENT"
    echo -e "  Use Proxy Rotation: $USE_PROXY_ROTATION"
    echo -e "  Fragment Requests: $FRAGMENT_REQUESTS"
    echo -e "  Decoy Scanning: $DECOY_SCANNING"
    echo ""
    
    echo -e "${YELLOW}Configuration Options:${NC}"
    echo -e "${YELLOW}1.${NC} Set Evasion Level (low/medium/high/extreme)"
    echo -e "${YELLOW}2.${NC} Toggle Timing Randomization"
    echo -e "${YELLOW}3.${NC} Toggle User-Agent Randomization"
    echo -e "${YELLOW}4.${NC} Toggle Proxy Rotation"
    echo -e "${YELLOW}5.${NC} Toggle Request Fragmentation"
    echo -e "${YELLOW}6.${NC} Toggle Decoy Scanning"
    echo -e "${YELLOW}7.${NC} Test Evasion Techniques"
    echo -e "${YELLOW}8.${NC} Update Evasion Databases"
    echo -e "${YELLOW}0.${NC} Back to Main Menu"
    echo ""
    echo -e "${BLUE}Select option: ${NC}"
    read -r evasion_choice
    
    case $evasion_choice in
        1) configure_evasion_level ;;
        2) toggle_timing_randomization ;;
        3) toggle_user_agent_randomization ;;
        4) toggle_proxy_rotation ;;
        5) toggle_request_fragmentation ;;
        6) toggle_decoy_scanning ;;
        7) test_evasion_techniques ;;
        8) update_evasion_databases ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

configure_evasion_level() {
    echo -e "${YELLOW}Select evasion level:${NC}"
    echo -e "${YELLOW}1.${NC} Low - Basic timing delays"
    echo -e "${YELLOW}2.${NC} Medium - User-agent rotation, moderate delays"
    echo -e "${YELLOW}3.${NC} High - Proxy rotation, fragmentation, long delays"
    echo -e "${YELLOW}4.${NC} Extreme - All techniques, maximum stealth"
    echo ""
    echo -e "${BLUE}Select level: ${NC}"
    read -r level_choice
    
    case $level_choice in
        1) EVASION_LEVEL="low" ;;
        2) EVASION_LEVEL="medium" ;;
        3) EVASION_LEVEL="high" ;;
        4) EVASION_LEVEL="extreme" ;;
        *) print_error "Invalid choice" ;;
    esac
    
    print_success "Evasion level set to: $EVASION_LEVEL"
}

test_evasion_techniques() {
    print_info "Testing evasion techniques..."
    
    # Test user agent rotation
    print_info "Testing user agent rotation:"
    for i in {1..3}; do
        local ua=$(get_random_user_agent)
        print_info "  Random UA $i: ${ua:0:50}..."
    done
    
    # Test timing profiles
    print_info "Testing timing profiles:"
    for profile in aggressive normal stealth paranoid; do
        print_info "  Testing $profile profile..."
        local start_time=$(date +%s.%N)
        apply_evasion_delay "$profile"
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        print_info "    Duration: ${duration}s"
    done
    
    # Test payload evasion
    print_info "Testing payload evasion:"
    local test_payload="<script>alert('test')</script>"
    for technique in case_variation url_encoding unicode_encoding; do
        local evaded=$(evade_waf_detection "$test_payload" "$technique")
        print_info "  $technique: ${evaded:0:30}..."
    done
    
    print_success "Evasion technique testing completed"
}

update_evasion_databases() {
    print_info "Updating evasion databases..."
    
    # Backup existing databases
    local backup_dir="$EVASION_CONFIG_DIR/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    cp "$USER_AGENTS_FILE" "$backup_dir/" 2>/dev/null
    cp "$TIMING_PROFILES_FILE" "$backup_dir/" 2>/dev/null
    cp "$PROXY_LIST_FILE" "$backup_dir/" 2>/dev/null
    
    # Recreate databases
    create_user_agents_database
    create_timing_profiles
    create_proxy_list
    
    print_success "Evasion databases updated. Backup saved to: $backup_dir"
}

# ============================================================================
# Utility Functions
# ============================================================================

toggle_timing_randomization() {
    if [[ "$RANDOMIZE_TIMING" == "true" ]]; then
        RANDOMIZE_TIMING="false"
    else
        RANDOMIZE_TIMING="true"
    fi
    print_success "Timing randomization: $RANDOMIZE_TIMING"
}

toggle_user_agent_randomization() {
    if [[ "$RANDOMIZE_USER_AGENT" == "true" ]]; then
        RANDOMIZE_USER_AGENT="false"
    else
        RANDOMIZE_USER_AGENT="true"
    fi
    print_success "User-Agent randomization: $RANDOMIZE_USER_AGENT"
}

toggle_proxy_rotation() {
    if [[ "$USE_PROXY_ROTATION" == "true" ]]; then
        USE_PROXY_ROTATION="false"
    else
        USE_PROXY_ROTATION="true"
    fi
    print_success "Proxy rotation: $USE_PROXY_ROTATION"
}

toggle_request_fragmentation() {
    if [[ "$FRAGMENT_REQUESTS" == "true" ]]; then
        FRAGMENT_REQUESTS="false"
    else
        FRAGMENT_REQUESTS="true
