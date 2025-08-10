#!/bin/bash

# ============================================================================
# CVE Fetching and Dynamic Module Generation Library for CVEHACK (NO APIs)
# ============================================================================

# CVE data sources (NO APIs - local/offline sources only)
CVE_DATABASE_DIR="./cve/database"
CVE_PATTERNS_DIR="./cve/patterns"
CVE_SIGNATURES_DIR="./cve/signatures"
CVE_TOOLS_DIR="./cve/tools"
CVES_FOLDER="./cves"

# Initialize CVE database directories
init_cve_database() {
    mkdir -p "$CVE_DATABASE_DIR" "$CVE_PATTERNS_DIR" "$CVE_SIGNATURES_DIR" "$CVE_TOOLS_DIR"
    
    print_info "Initializing local CVE database using CVEs folder..."
    
    # Create local CVE database with known vulnerabilities
    create_local_cve_database
    create_vulnerability_patterns
    create_exploit_signatures
    create_custom_scanning_tools
    
    print_success "CVE database initialized with local data from CVEs folder"
}

# Create comprehensive local CVE database using CVEs folder
create_local_cve_database() {
    local cve_db="$CVE_DATABASE_DIR/known_cves.txt"
    
    print_info "Creating comprehensive local CVE database from CVEs folder..."
    
    # Start with header
    cat > "$cve_db" << 'EOF'
# CVEHACK Local CVE Database - Using Local CVEs Folder
# Format: CVE-ID|SEVERITY|TYPE|DESCRIPTION|AFFECTED_SERVICES|DETECTION_METHOD|YEAR
EOF

    # Process CVEs from the local cves folder
    if [[ -d "$CVES_FOLDER" ]]; then
        local cve_count=0
        
        # Process each year directory
        for year_dir in "$CVES_FOLDER"/*/; do
            if [[ -d "$year_dir" ]]; then
                local year=$(basename "$year_dir")
                
                # Skip non-year directories
                if [[ ! "$year" =~ ^[0-9]{4}$ ]]; then
                    continue
                fi
                
                print_info "Processing CVEs from year: $year"
                
                # Process JSON files in year directory
                for cve_file in "$year_dir"/*.json; do
                    if [[ -f "$cve_file" ]]; then
                        local cve_id=$(basename "$cve_file" .json)
                        
                        # Extract basic info from JSON if jq is available
                        if command -v jq &> /dev/null; then
                            local description=$(jq -r '.description.description_data[0].value // "No description available"' "$cve_file" 2>/dev/null | head -1)
                            local severity="MEDIUM"  # Default severity
                            
                            # Try to determine severity from CVSS if available
                            local cvss_score=$(jq -r '.impact.baseMetricV3.cvssV3.baseScore // .impact.baseMetricV2.cvssV2.baseScore // "0"' "$cve_file" 2>/dev/null)
                            
                            if [[ "$cvss_score" != "0" && "$cvss_score" != "null" ]]; then
                                if (( $(echo "$cvss_score >= 9.0" | bc -l 2>/dev/null || echo 0) )); then
                                    severity="CRITICAL"
                                elif (( $(echo "$cvss_score >= 7.0" | bc -l 2>/dev/null || echo 0) )); then
                                    severity="HIGH"
                                elif (( $(echo "$cvss_score >= 4.0" | bc -l 2>/dev/null || echo 0) )); then
                                    severity="MEDIUM"
                                else
                                    severity="LOW"
                                fi
                            fi
                            
                            # Determine type and affected services from description
                            local vuln_type="UNKNOWN"
                            local services="generic"
                            local detection="manual_check"
                            
                            if echo "$description" | grep -qi "remote code execution\|rce"; then
                                vuln_type="RCE"
                                detection="service_check"
                            elif echo "$description" | grep -qi "sql injection\|sqli"; then
                                vuln_type="SQLi"
                                detection="path_check"
                            elif echo "$description" | grep -qi "cross.site scripting\|xss"; then
                                vuln_type="XSS"
                                detection="path_check"
                            elif echo "$description" | grep -qi "privilege escalation"; then
                                vuln_type="PRIV"
                                detection="version_check"
                            elif echo "$description" | grep -qi "information disclosure"; then
                                vuln_type="INFO"
                                detection="banner_check"
                            elif echo "$description" | grep -qi "denial of service\|dos"; then
                                vuln_type="DoS"
                                detection="service_check"
                            fi
                            
                            # Determine affected services
                            if echo "$description" | grep -qi "apache"; then
                                services="apache,httpd"
                            elif echo "$description" | grep -qi "nginx"; then
                                services="nginx"
                            elif echo "$description" | grep -qi "wordpress"; then
                                services="wordpress"
                            elif echo "$description" | grep -qi "mysql"; then
                                services="mysql"
                            elif echo "$description" | grep -qi "php"; then
                                services="php"
                            elif echo "$description" | grep -qi "openssl"; then
                                services="openssl,ssl"
                            elif echo "$description" | grep -qi "ssh"; then
                                services="ssh,openssh"
                            elif echo "$description" | grep -qi "windows"; then
                                services="windows"
                            elif echo "$description" | grep -qi "linux"; then
                                services="linux,kernel"
                            fi
                            
                            # Clean description (remove newlines and limit length)
                            description=$(echo "$description" | tr '\n' ' ' | cut -c1-200)
                            
                            # Add to database
                            echo "$cve_id|$severity|$vuln_type|$description|$services|$detection|$year" >> "$cve_db"
                            ((cve_count++))
                            
                        else
                            # Fallback without jq - basic entry
                            echo "$cve_id|MEDIUM|UNKNOWN|CVE from local database|generic|manual_check|$year" >> "$cve_db"
                            ((cve_count++))
                        fi
                        
                        # Limit processing to avoid overwhelming the system
                        if [[ $cve_count -ge 1000 ]]; then
                            print_warning "Processed 1000 CVEs, stopping to avoid system overload"
                            break 2
                        fi
                    fi
                done
            fi
        done
        
        print_success "Local CVE database created with $cve_count entries from CVEs folder"
    else
        print_warning "CVEs folder not found, creating basic CVE database"
        
        # Fallback to basic database
        cat >> "$cve_db" << 'EOF'
CVE-2023-0386|HIGH|LPE|Linux Kernel OverlayFS Local Privilege Escalation|linux,kernel|version_check|2023
CVE-2021-44228|CRITICAL|RCE|Apache Log4j Remote Code Execution (Log4Shell)|log4j,java|dependency_check|2021
CVE-2014-6271|CRITICAL|RCE|Bash Remote Code Execution (Shellshock)|bash,shell|version_check|2014
CVE-2014-0160|HIGH|INFO|OpenSSL Heartbleed Information Disclosure|openssl,ssl|ssl_check|2014
CVE-2017-0144|CRITICAL|RCE|Windows SMB Remote Code Execution (EternalBlue)|windows,smb|protocol_check|2017
EOF
    fi
}

# Create vulnerability detection patterns
create_vulnerability_patterns() {
    local patterns_file="$CVE_PATTERNS_DIR/detection_patterns.txt"
    
    print_info "Creating vulnerability detection patterns..."
    
    cat > "$patterns_file" << 'EOF'
# Comprehensive Vulnerability Detection Patterns - NO API REQUIRED
# Format: PATTERN_TYPE|PATTERN|CVE_REFERENCE|DESCRIPTION|SEVERITY

# Web Application Error Patterns
SQL_ERROR|mysql_fetch_array|CVE-2023-2825|MySQL Error Disclosure|MEDIUM
SQL_ERROR|ORA-[0-9]{5}|GENERIC-SQL|Oracle Error Disclosure|MEDIUM
SQL_ERROR|Microsoft OLE DB|GENERIC-SQL|MSSQL Error Disclosure|MEDIUM
XSS_PATTERN|<script|CVE-2023-5631|Potential XSS Vulnerability|HIGH
XSS_PATTERN|javascript:|CVE-2023-5631|JavaScript Protocol XSS|HIGH
LFI_PATTERN|\.\.\/|GENERIC-LFI|Local File Inclusion Pattern|HIGH
RFI_PATTERN|http.*=http|GENERIC-RFI|Remote File Inclusion Pattern|CRITICAL
CMD_INJECTION|;id;|GENERIC-CMD|Unix Command Injection|CRITICAL
CMD_INJECTION|&&whoami|GENERIC-CMD|Windows Command Injection|CRITICAL

# Service Banner Patterns
APACHE_VULN|Apache/2\.4\.[0-4][0-9]|CVE-2023-1326|Vulnerable Apache Version|HIGH
NGINX_VULN|nginx/1\.1[0-9]\.|CVE-2022-41741|Vulnerable Nginx Version|HIGH
OPENSSH_VULN|OpenSSH_[0-7]\.|CVE-2023-0386|Vulnerable OpenSSH Version|HIGH
MYSQL_VULN|MySQL 5\.[0-6]\.|CVE-2022-21245|Vulnerable MySQL Version|HIGH

# Protocol Signatures
SMB_VULN|SMBv1|CVE-2017-0144|SMBv1 EternalBlue Vulnerability|CRITICAL
RDP_VULN|CredSSP|CVE-2019-0708|RDP BlueKeep Vulnerability|CRITICAL
SSL_VULN|TLSv1\.0|CVE-2014-3566|SSL POODLE Vulnerability|MEDIUM

# Application Signatures
WORDPRESS_VULN|wp-content|CVE-2023-5631|WordPress Installation Detected|MEDIUM
JOOMLA_VULN|/administrator/|CVE-2023-23752|Joomla Installation Detected|MEDIUM
DRUPAL_VULN|/sites/default/|CVE-2018-7600|Drupal Installation Detected|HIGH
PHPMYADMIN_VULN|phpMyAdmin|CVE-2023-2825|phpMyAdmin Installation Detected|HIGH
EOF

    print_success "Vulnerability patterns created with $(grep -c "|" "$patterns_file") patterns"
}

# Create exploit signatures for detection
create_exploit_signatures() {
    local signatures_file="$CVE_SIGNATURES_DIR/exploit_signatures.txt"
    
    print_info "Creating exploit signatures..."
    
    cat > "$signatures_file" << 'EOF'
# Comprehensive Exploit Signatures for Detection - NO API REQUIRED
# Format: SIGNATURE_TYPE|SIGNATURE|DESCRIPTION|SEVERITY|CVE_REF

# Command Injection Signatures
CMD_INJECTION|;id;|Unix Command Injection Test|HIGH|GENERIC-CMD
CMD_INJECTION|&&whoami|Windows Command Injection Test|HIGH|GENERIC-CMD
CMD_INJECTION|\|ping -c 1|Command Chaining Test|MEDIUM|GENERIC-CMD
CMD_INJECTION|`uname -a`|Command Substitution Test|HIGH|GENERIC-CMD

# SQL Injection Signatures
SQL_INJECTION|' OR '1'='1|Classic SQL Injection|HIGH|GENERIC-SQL
SQL_INJECTION|' OR 1=1--|SQL Comment Injection|HIGH|GENERIC-SQL
SQL_INJECTION|UNION SELECT|SQL Union Injection|HIGH|GENERIC-SQL
SQL_INJECTION|'; DROP TABLE|SQL Drop Table Attack|CRITICAL|GENERIC-SQL

# XSS Signatures
XSS_PAYLOAD|<script>alert|Basic XSS Payload|MEDIUM|CVE-2023-5631
XSS_PAYLOAD|javascript:alert|JavaScript XSS|MEDIUM|CVE-2023-5631
XSS_PAYLOAD|onload=alert|Event Handler XSS|HIGH|CVE-2023-5631
XSS_PAYLOAD|<img src=x onerror=|Image XSS|HIGH|CVE-2023-5631

# File Inclusion Signatures
LFI_PAYLOAD|../../../etc/passwd|Linux LFI Test|HIGH|GENERIC-LFI
LFI_PAYLOAD|..\\..\\..\\windows\\system32|Windows LFI Test|HIGH|GENERIC-LFI
RFI_PAYLOAD|http://evil.com/shell.txt|Remote File Inclusion|CRITICAL|GENERIC-RFI

# Log4j Exploitation
LOG4J_EXPLOIT|${jndi:ldap://|Log4Shell LDAP Exploit|CRITICAL|CVE-2021-44228
LOG4J_EXPLOIT|${jndi:rmi://|Log4Shell RMI Exploit|CRITICAL|CVE-2021-44228

# Shellshock Exploitation
SHELLSHOCK_EXPLOIT|() { :; }; echo|Shellshock CGI Exploit|CRITICAL|CVE-2014-6271
EOF

    print_success "Exploit signatures created with $(grep -c "|" "$signatures_file") signatures"
}

# Create custom scanning tools from scratch (no existing tools required)
create_custom_scanning_tools() {
    print_info "Creating custom scanning tools from scratch..."
    
    # Create a simple web vulnerability scanner
    create_simple_web_scanner
    
    # Create a basic port scanner
    create_basic_port_scanner
    
    # Create CVE-specific scanners
    create_log4shell_scanner
    create_shellshock_scanner
    
    print_success "Custom scanning tools created"
}

# Create simple web vulnerability scanner
create_simple_web_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/simple_web_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
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
EOF

    chmod +x "$scanner_file"
    print_success "Simple web scanner created: $scanner_file"
}

# Create basic port scanner
create_basic_port_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/basic_port_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
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
EOF

    chmod +x "$scanner_file"
    print_success "Basic port scanner created: $scanner_file"
}

# Create Log4Shell scanner
create_log4shell_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/log4shell_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
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
    print_info() { echo -e "${BLUE}[i]${NC} $1"; }
    print_success() { echo -e "${GREEN}[+]${NC} $1"; }
    print_error() { echo -e "${RED}[-]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
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
EOF

    chmod +x "$scanner_file"
    print_success "Log4Shell scanner created: $scanner_file"
}

# Create Shellshock scanner
create_shellshock_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/shellshock_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
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
    print_info() { echo -e "${BLUE}[i]${NC} $1"; }
    print_success() { echo -e "${GREEN}[+]${NC} $1"; }
    print_error() { echo -e "${RED}[-]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
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
EOF

    chmod +x "$scanner_file"
    print_success "Shellshock scanner created: $scanner_file"
}

# ============================================================================
# CVE Database Management Functions (Using Local CVEs Folder)
# ============================================================================

# Fetch CVEs from local CVEs folder
fetch_recent_cves() {
    local days_back=${1:-7}
    local severity_filter=${2:-"HIGH,CRITICAL"}
    local category_filter=${3:-"web"}
    local output_file="$CVE_DIR/recent_cves_$(date +%Y%m%d).json"
    
    print_info "Loading CVEs from local CVEs folder..."
    
    if [[ ! -f "$CVE_DATABASE_DIR/known_cves.txt" ]]; then
        init_cve_database
    fi
    
    # Filter CVEs by severity from local database
    local temp_file="/tmp/filtered_cves.txt"
    
    # Convert severity filter to grep pattern
    local severity_pattern=$(echo "$severity_filter" | sed 's/,/\\|/g')
    
    grep -E "$severity_pattern" "$CVE_DATABASE_DIR/known_cves.txt" | head -50 > "$temp_file"
    
    # Convert to JSON format for compatibility
    echo "[" > "$output_file"
    local first=true
    
    while IFS='|' read -r cve_id severity type description services detection year; do
        if [[ -n "$cve_id" ]]; then
            [[ "$first" == "false" ]] && echo "," >> "$output_file"
            first=false
            
            cat >> "$output_file" << EOF
{
  "id": "$cve_id",
  "severity": "$severity",
  "type": "$type",
  "description": "$description",
  "services": "$services",
  "detection": "$detection",
  "year": "$year"
}
EOF
        fi
    done < "$temp_file"
    
    echo "]" >> "$output_file"
    
    local cve_count=$(grep -c "id" "$output_file")
    print_success "Loaded $cve_count CVEs from local database"
    
    rm -f "$temp_file"
    return 0
}

# Search for specific CVE by ID
search_cve_by_id() {
    local cve_id="$1"
    
    print_info "Searching for $cve_id in local CVEs folder..."
    
    # First check local database
    if [[ -f "$CVE_DATABASE_DIR/known_cves.txt" ]]; then
        if grep -q "$cve_id" "$CVE_DATABASE_DIR/known_cves.txt"; then
            local cve_data=$(grep "$cve_id" "$CVE_DATABASE_DIR/known_cves.txt")
            print_success "Found $cve_id in local database"
            echo "$cve_data"
            return 0
        fi
    fi
    
    # Check CVEs folder structure
    local year=$(echo "$cve_id" | cut -d'-' -f2)
    local cve_file="$CVES_FOLDER/$year/$cve_id.json"
    
    if [[ -f "$cve_file" ]]; then
        print_success "Found $cve_id in CVEs folder: $cve_file"
        
        if command -v jq &> /dev/null; then
            local description=$(jq -r '.description.description_data[0].value // "No description available"' "$cve_file" 2>/dev/null)
            print_info "Description: $description"
        else
            print_info "CVE file found but jq not available for parsing"
        fi
        
        return 0
    else
        print_error "CVE $cve_id not found in local sources"
        return 1
    fi
}

# Search CVEs by keyword
search_cves_by_keyword() {
    local keyword="$1"
    local limit=${2:-20}
    
    print_info "Searching for CVEs containing '$keyword'..."
    
    if [[ ! -f "$CVE_DATABASE_DIR/known_cves.txt" ]]; then
        init_cve_database
    fi
    
    local results=$(grep -i "$keyword" "$CVE_DATABASE_DIR/
