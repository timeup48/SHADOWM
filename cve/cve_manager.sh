#!/bin/bash

# ============================================================================
# CVE Manager - Dynamic CVE Testing and Management for CVEHACK
# ============================================================================

# Source required libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/colors.sh"
source "$SCRIPT_DIR/../lib/logger.sh"
source "$SCRIPT_DIR/../lib/cve_fetcher.sh"

# CVE Manager configuration
CVE_DATABASE="$CVE_DIR/cve_database.json"
CUSTOM_SCANNERS_DIR="$CVE_DIR/custom"
GENERATORS_DIR="$CVE_DIR/generators"

# ============================================================================
# CVE Management Menu
# ============================================================================

show_cve_menu() {
    while true; do
        clear_screen
        section_header "🆕 Custom CVE Testing & Dynamic Modules"
        
        echo -e "${YELLOW}1.${NC} 📥 Fetch Recent CVEs"
        echo -e "${YELLOW}2.${NC} 🔍 Search CVE Database"
        echo -e "${YELLOW}3.${NC} 🎯 Test Specific CVE"
        echo -e "${YELLOW}4.${NC} 🤖 Generate Custom CVE Scanner"
        echo -e "${YELLOW}5.${NC} 📊 CVE Statistics & Analysis"
        echo -e "${YELLOW}6.${NC} ⚡ Quick CVE Assessment"
        echo -e "${YELLOW}7.${NC} 🔄 Update CVE Database"
        echo -e "${YELLOW}8.${NC} 📋 Manage Custom Scanners"
        echo -e "${YELLOW}9.${NC} 🎯 High-Priority CVE Testing"
        echo -e "${YELLOW}10.${NC} 📈 CVE Trend Analysis"
        echo ""
        echo -e "${YELLOW}0.${NC} 🔙 Back to Main Menu"
        echo ""
        echo -e "${BLUE}Select CVE option: ${NC}"
        read -r cve_choice
        
        case $cve_choice in
            1) fetch_recent_cves_menu ;;
            2) search_cve_database_menu ;;
            3) test_specific_cve_menu ;;
            4) generate_custom_scanner_menu ;;
            5) cve_statistics_analysis ;;
            6) quick_cve_assessment_menu ;;
            7) update_cve_database_menu ;;
            8) manage_custom_scanners_menu ;;
            9) high_priority_cve_testing_menu ;;
            10) cve_trend_analysis ;;
            0) return ;;
            *) print_error "Invalid option. Please try again." ;;
        esac
        
        echo ""
        print_info "Press Enter to continue..."
        read -r
    done
}

# ============================================================================
# Fetch Recent CVEs Menu
# ============================================================================

fetch_recent_cves_menu() {
    clear_screen
    subsection_header "Fetch Recent CVEs"
    
    echo -e "${YELLOW}Select time range for CVE fetching:${NC}"
    echo -e "${YELLOW}1.${NC} Last 7 days"
    echo -e "${YELLOW}2.${NC} Last 30 days"
    echo -e "${YELLOW}3.${NC} Last 90 days"
    echo -e "${YELLOW}4.${NC} Custom date range"
    echo -e "${YELLOW}0.${NC} Back"
    echo ""
    echo -e "${BLUE}Select option: ${NC}"
    read -r fetch_choice
    
    case $fetch_choice in
        1) fetch_recent_cves 7 "HIGH,CRITICAL" "web" ;;
        2) fetch_recent_cves 30 "HIGH,CRITICAL" "web" ;;
        3) fetch_recent_cves 90 "MEDIUM,HIGH,CRITICAL" "web" ;;
        4) fetch_custom_date_range ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

fetch_custom_date_range() {
    echo -e "${YELLOW}Enter number of days back to search: ${NC}"
    read -r days_back
    
    if [[ "$days_back" =~ ^[0-9]+$ ]] && [[ $days_back -gt 0 ]] && [[ $days_back -le 365 ]]; then
        echo -e "${YELLOW}Select severity filter:${NC}"
        echo -e "${YELLOW}1.${NC} Critical only"
        echo -e "${YELLOW}2.${NC} High and Critical"
        echo -e "${YELLOW}3.${NC} Medium, High, and Critical"
        echo -e "${YELLOW}4.${NC} All severities"
        echo ""
        echo -e "${BLUE}Select severity: ${NC}"
        read -r severity_choice
        
        local severity_filter=""
        case $severity_choice in
            1) severity_filter="CRITICAL" ;;
            2) severity_filter="HIGH,CRITICAL" ;;
            3) severity_filter="MEDIUM,HIGH,CRITICAL" ;;
            4) severity_filter="LOW,MEDIUM,HIGH,CRITICAL" ;;
            *) severity_filter="HIGH,CRITICAL" ;;
        esac
        
        fetch_recent_cves "$days_back" "$severity_filter" "web"
    else
        print_error "Invalid number of days. Please enter a number between 1 and 365."
    fi
}

# ============================================================================
# Search CVE Database Menu
# ============================================================================

search_cve_database_menu() {
    clear_screen
    subsection_header "Search CVE Database"
    
    echo -e "${YELLOW}Select search method:${NC}"
    echo -e "${YELLOW}1.${NC} Search by CVE ID"
    echo -e "${YELLOW}2.${NC} Search by keyword"
    echo -e "${YELLOW}3.${NC} Search by technology/product"
    echo -e "${YELLOW}4.${NC} Search by severity"
    echo -e "${YELLOW}0.${NC} Back"
    echo ""
    echo -e "${BLUE}Select search method: ${NC}"
    read -r search_choice
    
    case $search_choice in
        1) search_by_cve_id ;;
        2) search_by_keyword ;;
        3) search_by_technology ;;
        4) search_by_severity ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

search_by_cve_id() {
    echo -e "${YELLOW}Enter CVE ID (e.g., CVE-2023-1234): ${NC}"
    read -r cve_id
    
    if [[ "$cve_id" =~ ^CVE-[0-9]{4}-[0-9]+$ ]]; then
        search_cve_by_id "$cve_id"
    else
        print_error "Invalid CVE ID format. Please use format: CVE-YYYY-NNNN"
    fi
}

search_by_keyword() {
    echo -e "${YELLOW}Enter search keyword: ${NC}"
    read -r keyword
    
    if [[ -n "$keyword" ]]; then
        search_cves_by_keyword "$keyword" 20
    else
        print_error "Keyword cannot be empty"
    fi
}

search_by_technology() {
    echo -e "${YELLOW}Select technology to search:${NC}"
    echo -e "${YELLOW}1.${NC} Apache"
    echo -e "${YELLOW}2.${NC} Nginx"
    echo -e "${YELLOW}3.${NC} WordPress"
    echo -e "${YELLOW}4.${NC} PHP"
    echo -e "${YELLOW}5.${NC} MySQL"
    echo -e "${YELLOW}6.${NC} OpenSSL"
    echo -e "${YELLOW}7.${NC} Custom technology"
    echo ""
    echo -e "${BLUE}Select technology: ${NC}"
    read -r tech_choice
    
    local technology=""
    case $tech_choice in
        1) technology="apache" ;;
        2) technology="nginx" ;;
        3) technology="wordpress" ;;
        4) technology="php" ;;
        5) technology="mysql" ;;
        6) technology="openssl" ;;
        7) 
            echo -e "${YELLOW}Enter technology name: ${NC}"
            read -r technology
            ;;
        *) print_error "Invalid option"; return ;;
    esac
    
    if [[ -n "$technology" ]]; then
        search_cves_by_keyword "$technology" 20
    fi
}

search_by_severity() {
    echo -e "${YELLOW}Select severity level:${NC}"
    echo -e "${YELLOW}1.${NC} Critical"
    echo -e "${YELLOW}2.${NC} High"
    echo -e "${YELLOW}3.${NC} Medium"
    echo -e "${YELLOW}4.${NC} Low"
    echo ""
    echo -e "${BLUE}Select severity: ${NC}"
    read -r severity_choice
    
    local severity=""
    case $severity_choice in
        1) severity="CRITICAL" ;;
        2) severity="HIGH" ;;
        3) severity="MEDIUM" ;;
        4) severity="LOW" ;;
        *) print_error "Invalid option"; return ;;
    esac
    
    search_cves_by_severity "$severity"
}

search_cves_by_severity() {
    local severity="$1"
    
    print_info "Searching for $severity severity CVEs..."
    
    # This would search local CVE database or fetch from API
    local search_results=$(fetch_cves_by_severity "$severity")
    
    if [[ -n "$search_results" ]]; then
        print_success "Found CVEs with $severity severity:"
        echo "$search_results" | head -10 | while read -r cve_line; do
            print_info "$cve_line"
        done
    else
        print_warning "No CVEs found with $severity severity"
    fi
}

# ============================================================================
# Test Specific CVE Menu
# ============================================================================

test_specific_cve_menu() {
    clear_screen
    subsection_header "Test Specific CVE"
    
    echo -e "${YELLOW}Enter target for CVE testing: ${NC}"
    read -r cve_target
    
    if [[ -z "$cve_target" ]]; then
        print_error "Target cannot be empty"
        return
    fi
    
    echo -e "${YELLOW}Enter CVE ID to test (e.g., CVE-2023-1234): ${NC}"
    read -r cve_id
    
    if [[ ! "$cve_id" =~ ^CVE-[0-9]{4}-[0-9]+$ ]]; then
        print_error "Invalid CVE ID format"
        return
    fi
    
    test_specific_cve "$cve_target" "$cve_id"
}

test_specific_cve() {
    local target="$1"
    local cve_id="$2"
    
    print_info "Testing $cve_id against $target..."
    log_scan_start "CVE Testing" "$target"
    
    # Check if custom scanner exists
    local custom_scanner="$CUSTOM_SCANNERS_DIR/${cve_id}_scanner.sh"
    
    if [[ -f "$custom_scanner" ]]; then
        print_success "Custom scanner found for $cve_id"
        print_info "Executing custom scanner..."
        
        # Execute the custom scanner
        if bash "$custom_scanner" "$target"; then
            print_success "Custom CVE scanner executed successfully"
            log_cve_test "$cve_id" "$target" "tested" "Custom scanner executed"
        else
            print_error "Custom CVE scanner failed"
            log_cve_test "$cve_id" "$target" "false" "Custom scanner execution failed"
        fi
    else
        print_warning "No custom scanner found for $cve_id"
        print_info "Generating scanner for $cve_id..."
        
        # Fetch CVE details and generate scanner
        local cve_data_file="$CVE_DIR/${cve_id}.json"
        if search_cve_by_id "$cve_id" > /dev/null; then
            local generated_scanner=$(generate_cve_scanner "$cve_id" "$cve_data_file")
            
            if [[ -n "$generated_scanner" ]] && [[ -f "$generated_scanner" ]]; then
                print_success "Scanner generated for $cve_id"
                print_info "Executing generated scanner..."
                
                if bash "$generated_scanner" "$target"; then
                    print_success "Generated CVE scanner executed successfully"
                    log_cve_test "$cve_id" "$target" "tested" "Generated scanner executed"
                else
                    print_warning "Generated CVE scanner completed with warnings"
                    log_cve_test "$cve_id" "$target" "false" "Generated scanner execution completed"
                fi
            else
                print_error "Failed to generate scanner for $cve_id"
                log_cve_test "$cve_id" "$target" "false" "Scanner generation failed"
            fi
        else
            print_error "Could not fetch details for $cve_id"
            log_cve_test "$cve_id" "$target" "false" "CVE details not found"
        fi
    fi
}

# ============================================================================
# Generate Custom Scanner Menu
# ============================================================================

generate_custom_scanner_menu() {
    clear_screen
    subsection_header "Generate Custom CVE Scanner"
    
    echo -e "${YELLOW}Enter CVE ID to generate scanner for: ${NC}"
    read -r cve_id
    
    if [[ ! "$cve_id" =~ ^CVE-[0-9]{4}-[0-9]+$ ]]; then
        print_error "Invalid CVE ID format"
        return
    fi
    
    print_info "Generating custom scanner for $cve_id..."
    
    # Fetch CVE details first
    local cve_data_file="$CVE_DIR/${cve_id}.json"
    if search_cve_by_id "$cve_id" > /dev/null; then
        local generated_scanner=$(generate_cve_scanner "$cve_id" "$cve_data_file")
        
        if [[ -n "$generated_scanner" ]] && [[ -f "$generated_scanner" ]]; then
            print_success "Custom scanner generated: $generated_scanner"
            
            echo -e "${YELLOW}Would you like to test the scanner now? (y/n): ${NC}"
            read -r test_now
            
            if [[ "$test_now" =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}Enter target to test: ${NC}"
                read -r test_target
                
                if [[ -n "$test_target" ]]; then
                    print_info "Testing generated scanner..."
                    bash "$generated_scanner" "$test_target"
                fi
            fi
        else
            print_error "Failed to generate scanner for $cve_id"
        fi
    else
        print_error "Could not fetch details for $cve_id"
    fi
}

# ============================================================================
# CVE Statistics & Analysis
# ============================================================================

cve_statistics_analysis() {
    clear_screen
    subsection_header "CVE Statistics & Analysis"
    
    print_info "Analyzing CVE database and recent trends..."
    
    # Check if we have recent CVE data
    local recent_cve_files=$(find "$CVE_DIR" -name "recent_cves_*.json" -mtime -7 | head -1)
    
    if [[ -n "$recent_cve_files" ]]; then
        print_success "Analyzing recent CVE data..."
        
        # Analyze severity distribution
        print_info "CVE Severity Distribution (Last 7 days):"
        analyze_cve_severity_distribution "$recent_cve_files"
        
        echo ""
        
        # Analyze technology distribution
        print_info "Most Affected Technologies:"
        analyze_technology_distribution "$recent_cve_files"
        
        echo ""
        
        # Show high-priority CVEs
        print_info "High-Priority CVEs for Web Applications:"
        show_high_priority_web_cves "$recent_cve_files"
        
    else
        print_warning "No recent CVE data found. Fetching latest CVEs..."
        fetch_recent_cves 7 "HIGH,CRITICAL" "web"
        
        # Retry analysis
        recent_cve_files=$(find "$CVE_DIR" -name "recent_cves_*.json" -mtime -1 | head -1)
        if [[ -n "$recent_cve_files" ]]; then
            cve_statistics_analysis
        fi
    fi
    
    # Show custom scanner statistics
    echo ""
    print_info "Custom Scanner Statistics:"
    show_custom_scanner_stats
}

analyze_cve_severity_distribution() {
    local cve_file="$1"
    
    if [[ -f "$cve_file" ]] && command -v jq &> /dev/null; then
        local critical_count=$(jq '[.[] | select(.severity == "CRITICAL")] | length' "$cve_file" 2>/dev/null || echo "0")
        local high_count=$(jq '[.[] | select(.severity == "HIGH")] | length' "$cve_file" 2>/dev/null || echo "0")
        local medium_count=$(jq '[.[] | select(.severity == "MEDIUM")] | length' "$cve_file" 2>/dev/null || echo "0")
        local low_count=$(jq '[.[] | select(.severity == "LOW")] | length' "$cve_file" 2>/dev/null || echo "0")
        
        print_error "  Critical: $critical_count"
        print_warning "  High: $high_count"
        print_info "  Medium: $medium_count"
        print_success "  Low: $low_count"
        
        local total=$((critical_count + high_count + medium_count + low_count))
        if [[ $total -gt 0 ]]; then
            print_info "  Total CVEs: $total"
        fi
    else
        print_warning "Unable to analyze CVE severity distribution"
    fi
}

analyze_technology_distribution() {
    local cve_file="$1"
    
    if [[ -f "$cve_file" ]] && command -v jq &> /dev/null; then
        print_info "Analyzing technology mentions in CVE descriptions..."
        
        # Extract and count technology mentions
        local tech_analysis=$(jq -r '.[] | .description' "$cve_file" 2>/dev/null | \
            grep -oiE "(apache|nginx|wordpress|php|mysql|postgresql|openssl|ssh|ftp|http|ssl|tls)" | \
            tr '[:upper:]' '[:lower:]' | sort | uniq -c | sort -nr | head -10)
        
        if [[ -n "$tech_analysis" ]]; then
            echo "$tech_analysis" | while read -r count tech; do
                print_info "  $tech: $count mentions"
            done
        else
            print_warning "No technology patterns found in CVE descriptions"
        fi
    else
        print_warning "Unable to analyze technology distribution"
    fi
}

show_high_priority_web_cves() {
    local cve_file="$1"
    
    if [[ -f "$cve_file" ]] && command -v jq &> /dev/null; then
        print_info "High-priority web application CVEs:"
        
        # Filter for web-related high/critical CVEs
        jq -r '.[] | select(.severity == "CRITICAL" or .severity == "HIGH") | select(.description | test("web|http|apache|nginx|php|wordpress"; "i")) | "\(.id) - \(.severity) - \(.description[:80])..."' "$cve_file" 2>/dev/null | head -5 | while read -r cve_line; do
            if echo "$cve_line" | grep -q "CRITICAL"; then
                print_error "  $cve_line"
            else
                print_warning "  $cve_line"
            fi
        done
    else
        print_warning "Unable to show high-priority CVEs"
    fi
}

show_custom_scanner_stats() {
    local scanner_count=$(find "$CUSTOM_SCANNERS_DIR" -name "*_scanner.sh" 2>/dev/null | wc -l)
    local generator_count=$(find "$GENERATORS_DIR" -name "*.sh" 2>/dev/null | wc -l)
    
    print_info "  Custom scanners available: $scanner_count"
    print_info "  Scanner generators: $generator_count"
    
    if [[ $scanner_count -gt 0 ]]; then
        print_info "  Recent custom scanners:"
        find "$CUSTOM_SCANNERS_DIR" -name "*_scanner.sh" -mtime -7 2>/dev/null | head -5 | while read -r scanner; do
            local scanner_name=$(basename "$scanner" | sed 's/_scanner.sh//')
            print_info "    - $scanner_name"
        done
    fi
}

# ============================================================================
# Quick CVE Assessment
# ============================================================================

quick_cve_assessment_menu() {
    clear_screen
    subsection_header "Quick CVE Assessment"
    
    echo -e "${YELLOW}Enter target for quick CVE assessment: ${NC}"
    read -r target
    
    if [[ -z "$target" ]]; then
        print_error "Target cannot be empty"
        return
    fi
    
    quick_cve_check "$target"
}

quick_cve_check() {
    local target="$1"
    
    print_info "Starting quick CVE assessment for $target..."
    log_scan_start "Quick CVE Assessment" "$target"
    
    # Ensure target has protocol for web checks
    local web_target="$target"
    if [[ ! "$web_target" =~ ^https?:// ]]; then
        if curl -s --connect-timeout 5 "https://$target" >/dev/null 2>&1; then
            web_target="https://$target"
        else
            web_target="http://$target"
        fi
    fi
    
    # Quick service detection
    print_info "Detecting services for CVE assessment..."
    local services_detected=()
    
    # Check for web services
    if curl -s --connect-timeout 5 "$web_target" >/dev/null 2>&1; then
        services_detected+=("HTTP")
        
        # Detect web server
        local server_header=$(curl -s -I "$web_target" 2>/dev/null | grep -i "server:" | cut -d: -f2- | xargs)
        if [[ -n "$server_header" ]]; then
            print_success "Web server detected: $server_header"
            
            # Check for known vulnerable versions
            check_web_server_cves "$server_header" "$target"
        fi
        
        # Check for WordPress
        if curl -s "$web_target" 2>/dev/null | grep -qi "wp-content\|wordpress"; then
            services_detected+=("WordPress")
            check_wordpress_cves "$web_target"
        fi
    fi
    
    # Check for SSH
    if nmap -p 22 "$target" 2>/dev/null | grep -q "22/tcp open"; then
        services_detected+=("SSH")
        check_ssh_cves "$target"
    fi
    
    # Check for FTP
    if nmap -p 21 "$target" 2>/dev/null | grep -q "21/tcp open"; then
        services_detected+=("FTP")
        check_ftp_cves "$target"
    fi
    
    # Summary
    print_success "Quick CVE assessment completed"
    print_info "Services assessed: ${services_detected[*]}"
    
    log_scan_result "Quick CVE Assessment" "$target" "Services: ${services_detected[*]}"
}

check_web_server_cves() {
    local server_info="$1"
    local target="$2"
    
    print_info "Checking for web server CVEs..."
    
    # Extract server name and version
    local server_name=$(echo "$server_info" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
    local server_version=$(echo "$server_info" | grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" | head -1)
    
    case "$server_name" in
        *apache*)
            check_apache_cves "$server_version" "$target"
            ;;
        *nginx*)
            check_nginx_cves "$server_version" "$target"
            ;;
        *iis*)
            check_iis_cves "$server_version" "$target"
            ;;
        *)
            print_info "Generic web server CVE check for: $server_name"
            ;;
    esac
}

check_apache_cves() {
    local version="$1"
    local target="$2"
    
    print_info "Checking Apache CVEs for version: $version"
    
    # Known Apache CVEs (simplified check)
    local apache_cves=(
        "CVE-2021-44228:Log4j RCE:2.4.1-2.4.51"
        "CVE-2021-41773:Path Traversal:2.4.49-2.4.50"
        "CVE-2021-42013:Path Traversal:2.4.49-2.4.50"
        "CVE-2022-22720:HTTP Request Smuggling:2.4.52"
    )
    
    for cve_info in "${apache_cves[@]}"; do
        local cve_id=$(echo "$cve_info" | cut -d: -f1)
        local cve_desc=$(echo "$cve_info" | cut -d: -f2)
        local affected_versions=$(echo "$cve_info" | cut -d: -f3)
        
        print_warning "Potential vulnerability: $cve_id - $cve_desc"
        print_info "Affected versions: $affected_versions"
        
        # Log potential vulnerability
        log_vulnerability "Apache CVE" "HIGH" "$target" "$cve_id - $cve_desc" "Server version: $version, Affected: $affected_versions"
    done
}

check_nginx_cves() {
    local version="$1"
    local target="$2"
    
    print_info "Checking Nginx CVEs for version: $version"
    
    # Known Nginx CVEs (simplified check)
    local nginx_cves=(
        "CVE-2021-23017:DNS Resolver Off-by-One:1.20.0"
        "CVE-2019-20372:HTTP Request Smuggling:1.17.7"
        "CVE-2017-7529:Integer Overflow:1.13.2"
    )
    
    for cve_info in "${nginx_cves[@]}"; do
        local cve_id=$(echo "$cve_info" | cut -d: -f1)
        local cve_desc=$(echo "$cve_info" | cut -d: -f2)
        local affected_versions=$(echo "$cve_info" | cut -d: -f3)
        
        print_warning "Potential vulnerability: $cve_id - $cve_desc"
        print_info "Affected versions: $affected_versions"
        
        log_vulnerability "Nginx CVE" "HIGH" "$target" "$cve_id - $cve_desc" "Server version: $version, Affected: $affected_versions"
    done
}

check_iis_cves() {
    local version="$1"
    local target="$2"
    
    print_info "Checking IIS CVEs for version: $version"
    
    # Known IIS CVEs (simplified check)
    local iis_cves=(
        "CVE-2021-31207:HTTP Protocol Stack RCE:10.0"
        "CVE-2021-26419:IIS Elevation of Privilege:10.0"
        "CVE-2020-0618:ASP.NET Core Denial of Service:Various"
    )
    
    for cve_info in "${iis_cves[@]}"; do
        local cve_id=$(echo "$cve_info" | cut -d: -f1)
        local cve_desc=$(echo "$cve_info" | cut -d: -f2)
        local affected_versions=$(echo "$cve_info" | cut -d: -f3)
        
        print_warning "Potential vulnerability: $cve_id - $cve_desc"
        print_info "Affected versions: $affected_versions"
        
        log_vulnerability "IIS CVE" "HIGH" "$target" "$cve_id - $cve_desc" "Server version: $version, Affected: $affected_versions"
    done
}

check_wordpress_cves() {
    local target="$1"
    
    print_info "Checking for WordPress CVEs..."
    
    # Try to detect WordPress version
    local wp_version=$(curl -s "$target" 2>/dev/null | grep -o 'content="WordPress [0-9.]*"' | grep -o '[0-9.]*')
    
    if [[ -n "$wp_version" ]]; then
        print_success "WordPress version detected: $wp_version"
        
        # Known WordPress CVEs (simplified check)
        local wp_cves=(
            "CVE-2022-21661:SQL Injection:5.8.3"
            "CVE-2021-29447:XXE Vulnerability:5.6.2"
            "CVE-2020-4047:Authenticated Code Execution:5.4.2"
        )
        
        for cve_info in "${wp_cves[@]}"; do
            local cve_id=$(echo "$cve_info" | cut -d: -f1)
            local cve_desc=$(echo "$cve_info" | cut -d: -f2)
            local affected_versions=$(echo "$cve_info" | cut -d: -f3)
            
            print_warning "Potential WordPress vulnerability: $cve_id - $cve_desc"
            print_info "Affected versions: $affected_versions"
            
            log_vulnerability "WordPress CVE" "HIGH" "$target" "$cve_id - $cve_desc" "WordPress version: $wp_version, Affected: $affected_versions"
        done
    else
        print_warning "Could not detect WordPress version"
    fi
}

check_ssh_cves() {
    local target="$1"
    
    print_info "Checking for SSH CVEs..."
    
    # Try to get SSH version
    local ssh_banner=$(timeout 5 nc "$target" 22 2>/dev/null | head -1)
    
    if [[ -n "$ssh_banner" ]]; then
        print_success "SSH banner: $ssh_banner"
        
        # Check for known SSH vulnerabilities
        if echo "$ssh_banner" | grep -qi "openssh"; then
            local ssh_version=$(echo "$ssh_banner" | grep -oE "[0-9]+\.[0-9]+")
            
            # Known OpenSSH CVEs
            local ssh_cves=(
                "CVE-2021-41617:Privilege Escalation:8.7"
                "CVE-2020-14145:Information Disclosure:8.3"
                "CVE-2019-6109:Character Encoding:7.9"
            )
            
            for cve_info in "${ssh_cves[@]}"; do
                local cve_id=$(echo "$cve_info" | cut -d: -f1)
                local cve_desc=$(echo "$cve_info" | cut -d: -f2)
                local cve_version=$(echo "$cve_info" | cut -d: -f3)
                
                print_info "Testing for $cve_id: $cve_desc"
                
                # Version-based vulnerability check
                if [[ "$ssh_version" == *"$cve_version"* ]]; then
                    print_error "Potentially vulnerable to $cve_id"
                    log_vulnerability "$cve_id" "HIGH" "$target" "$cve_desc - OpenSSH $cve_version" "Version match detected"
                    vulnerable_cves+=("$cve_id")
                else
                    print_success "Not vulnerable to $cve_id (version mismatch)"
                fi
            done
        else
            print_warning "Could not determine SSH version"
        fi
    else
        print_info "SSH service not detected on standard port"
    fi
    
    # Save results
    local ssh_cve_data="SSH CVE Testing Results for $target
Generated: $(date)

SSH Version: $ssh_version
Vulnerable CVEs: $(printf '%s ' "${vulnerable_cves[@]}")
"
    
    save_scan_data "ssh_cve_test" "$target" "$ssh_cve_data"
    log_scan_result "SSH CVE Testing" "$target" "$ssh_cve_data"
    
    print_success "SSH CVE testing completed"
}

# ============================================================================
# Comprehensive CVE Testing
# ============================================================================

comprehensive_cve_test() {
    local target="$1"
    
    section_header "Comprehensive CVE Testing"
    log_scan_start "Comprehensive CVE Testing" "$target"
    
    print_info "Starting comprehensive CVE testing on $target..."
    print_warning "This will test for multiple known vulnerabilities..."
    
    # Test all CVE categories
    web_cve_testing "$target"
    echo ""
    
    ssh_cve_testing "$target"
    echo ""
    
    # Additional service-specific CVE tests can be added here
    
    print_success "Comprehensive CVE testing completed"
    log_scan_result "Comprehensive CVE Testing" "$target" "All CVE tests completed"
}

# ============================================================================
# Quick CVE Check
# ============================================================================

quick_cve_check() {
    local target="$1"
    
    section_header "Quick CVE Check"
    log_scan_start "Quick CVE Check" "$target"
    
    print_info "Performing quick CVE check on $target..."
    
    # Quick web CVE check
    web_cve_testing "$target"
    
    print_success "Quick CVE check completed"
    log_scan_result "Quick CVE Check" "$target" "Quick CVE check completed"
}
