#!/bin/bash

# ============================================================================
# Logging and Session Management Library for CVEHACK
# ============================================================================

# Global logging variables
LOG_DIR="$RESULTS_DIR"
SESSION_LOG=""
CURRENT_SESSION=""
LOG_LEVEL="INFO"

# Log levels (using simple variables instead of associative arrays)
LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_WARNING=2
LOG_LEVEL_ERROR=3
LOG_LEVEL_CRITICAL=4

# Function to get log level number
get_log_level_num() {
    local level="$1"
    case "$level" in
        "DEBUG") echo $LOG_LEVEL_DEBUG ;;
        "INFO") echo $LOG_LEVEL_INFO ;;
        "WARNING") echo $LOG_LEVEL_WARNING ;;
        "ERROR") echo $LOG_LEVEL_ERROR ;;
        "CRITICAL") echo $LOG_LEVEL_CRITICAL ;;
        *) echo $LOG_LEVEL_INFO ;;
    esac
}

# ============================================================================
# Logging Initialization
# ============================================================================

init_logging() {
    local session_id="$1"
    CURRENT_SESSION="$session_id"
    
    # Create session directory
    local session_dir="$LOG_DIR/$session_id"
    mkdir -p "$session_dir"
    
    # Initialize log files
    SESSION_LOG="$session_dir/session.log"
    SCAN_LOG="$session_dir/scan.log"
    ERROR_LOG="$session_dir/error.log"
    VULN_LOG="$session_dir/vulnerabilities.log"
    
    # Create log files with headers
    cat > "$SESSION_LOG" << EOF
# CVEHACK Session Log
# Session ID: $session_id
# Start Time: $(date)
# System: $(uname -a)
# User: $(whoami)
# Working Directory: $(pwd)
================================================================================

EOF

    cat > "$SCAN_LOG" << EOF
# CVEHACK Scan Results Log
# Session ID: $session_id
# Start Time: $(date)
================================================================================

EOF

    cat > "$ERROR_LOG" << EOF
# CVEHACK Error Log
# Session ID: $session_id
# Start Time: $(date)
================================================================================

EOF

    cat > "$VULN_LOG" << EOF
# CVEHACK Vulnerability Log
# Session ID: $session_id
# Start Time: $(date)
================================================================================

EOF

    log_info "Logging initialized for session: $session_id"
}

# ============================================================================
# Core Logging Functions
# ============================================================================

log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local caller="${BASH_SOURCE[2]##*/}:${BASH_LINENO[1]}"
    
    # Check if log level is enabled using helper function
    local current_level_num=$(get_log_level_num "$LOG_LEVEL")
    local message_level_num=$(get_log_level_num "$level")
    
    if [[ $message_level_num -ge $current_level_num ]]; then
        local log_entry="[$timestamp] [$level] [$caller] $message"
        
        # Write to session log if it exists
        [[ -n "$SESSION_LOG" ]] && echo "$log_entry" >> "$SESSION_LOG"
        
        # Write to specific logs based on level
        case "$level" in
            "ERROR"|"CRITICAL")
                [[ -n "$ERROR_LOG" ]] && echo "$log_entry" >> "$ERROR_LOG"
                ;;
        esac
        
        # Also output to console with colors
        case "$level" in
            "DEBUG") echo -e "${GRAY}[DEBUG] $message${NC}" ;;
            "INFO") echo -e "${BLUE}[INFO] $message${NC}" ;;
            "WARNING") echo -e "${YELLOW}[WARNING] $message${NC}" ;;
            "ERROR") echo -e "${RED}[ERROR] $message${NC}" ;;
            "CRITICAL") echo -e "${BG_RED}${WHITE}[CRITICAL] $message${NC}" ;;
        esac
    fi
}

log_debug() { log_message "DEBUG" "$1"; }
log_info() { log_message "INFO" "$1"; }
log_warning() { log_message "WARNING" "$1"; }
log_error() { log_message "ERROR" "$1"; }
log_critical() { log_message "CRITICAL" "$1"; }

# ============================================================================
# Specialized Logging Functions
# ============================================================================

log_scan_start() {
    local scan_type="$1"
    local target="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local scan_entry="
================================================================================
SCAN START: $scan_type
Target: $target
Start Time: $timestamp
================================================================================
"
    
    echo "$scan_entry" >> "$SCAN_LOG"
    log_info "Started $scan_type scan on $target"
}

log_scan_result() {
    local tool="$1"
    local target="$2"
    local result="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local result_entry="
--- $tool Results ---
Target: $target
Timestamp: $timestamp
$result

"
    
    echo "$result_entry" >> "$SCAN_LOG"
    log_info "$tool scan completed for $target"
}

log_vulnerability() {
    local vuln_type="$1"
    local severity="$2"
    local target="$3"
    local description="$4"
    local evidence="$5"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local vuln_entry="
================================================================================
VULNERABILITY FOUND
================================================================================
Type: $vuln_type
Severity: $severity
Target: $target
Timestamp: $timestamp
Description: $description
Evidence:
$evidence
================================================================================

"
    
    echo "$vuln_entry" >> "$VULN_LOG"
    log_warning "Vulnerability found: $vuln_type ($severity) on $target"
}

log_exploit_attempt() {
    local exploit="$1"
    local target="$2"
    local success="$3"
    local details="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local exploit_entry="
--- Exploit Attempt ---
Exploit: $exploit
Target: $target
Success: $success
Timestamp: $timestamp
Details: $details

"
    
    echo "$exploit_entry" >> "$SCAN_LOG"
    
    if [[ "$success" == "true" ]]; then
        log_critical "Successful exploit: $exploit on $target"
    else
        log_info "Exploit attempt failed: $exploit on $target"
    fi
}

log_cve_test() {
    local cve_id="$1"
    local target="$2"
    local vulnerable="$3"
    local details="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local cve_entry="
--- CVE Test ---
CVE ID: $cve_id
Target: $target
Vulnerable: $vulnerable
Timestamp: $timestamp
Details: $details

"
    
    echo "$cve_entry" >> "$SCAN_LOG"
    
    if [[ "$vulnerable" == "true" ]]; then
        log_vulnerability "CVE-$cve_id" "HIGH" "$target" "System vulnerable to $cve_id" "$details"
    else
        log_info "CVE test completed: $cve_id - Not vulnerable"
    fi
}

# ============================================================================
# Command Output Logging
# ============================================================================

log_command() {
    local command="$1"
    local target="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    log_info "Executing: $command"
    
    local cmd_entry="
--- Command Execution ---
Command: $command
Target: $target
Timestamp: $timestamp
Output:
"
    
    echo "$cmd_entry" >> "$SCAN_LOG"
    
    # Execute command and capture output
    local output
    if output=$(eval "$command" 2>&1); then
        echo "$output" >> "$SCAN_LOG"
        echo "" >> "$SCAN_LOG"
        log_info "Command completed successfully"
        return 0
    else
        echo "$output" >> "$SCAN_LOG"
        echo "" >> "$SCAN_LOG"
        log_error "Command failed: $command"
        return 1
    fi
}

log_command_with_progress() {
    local command="$1"
    local target="$2"
    local description="$3"
    
    print_info "$description"
    log_command "$command" "$target"
}

# ============================================================================
# File and Data Logging
# ============================================================================

save_scan_data() {
    local scan_type="$1"
    local target="$2"
    local data="$3"
    local filename="$4"
    
    local session_dir="$LOG_DIR/$CURRENT_SESSION"
    local data_dir="$session_dir/data"
    mkdir -p "$data_dir"
    
    local filepath="$data_dir/${filename:-${scan_type}_${target//[^a-zA-Z0-9]/_}_$(date +%s).txt}"
    
    echo "$data" > "$filepath"
    log_info "Scan data saved: $filepath"
    
    echo "$filepath"
}

save_raw_output() {
    local tool="$1"
    local target="$2"
    local output="$3"
    
    local session_dir="$LOG_DIR/$CURRENT_SESSION"
    local raw_dir="$session_dir/raw"
    mkdir -p "$raw_dir"
    
    local filename="${tool}_${target//[^a-zA-Z0-9]/_}_$(date +%s).raw"
    local filepath="$raw_dir/$filename"
    
    echo "$output" > "$filepath"
    log_info "Raw output saved: $filepath"
    
    echo "$filepath"
}

# ============================================================================
# Session Management
# ============================================================================

get_session_stats() {
    local session_id="$1"
    local session_dir="$LOG_DIR/$session_id"
    
    if [[ ! -d "$session_dir" ]]; then
        echo "Session not found"
        return 1
    fi
    
    local stats=""
    stats+="Session ID: $session_id\n"
    stats+="Session Directory: $session_dir\n"
    
    if [[ -f "$session_dir/session.log" ]]; then
        local start_time=$(head -5 "$session_dir/session.log" | grep "Start Time" | cut -d: -f2-)
        local log_lines=$(wc -l < "$session_dir/session.log")
        stats+="Start Time:$start_time\n"
        stats+="Log Entries: $log_lines\n"
    fi
    
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        local vuln_count=$(grep -c "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log")
        stats+="Vulnerabilities Found: $vuln_count\n"
    fi
    
    if [[ -d "$session_dir/data" ]]; then
        local data_files=$(find "$session_dir/data" -type f | wc -l)
        stats+="Data Files: $data_files\n"
    fi
    
    echo -e "$stats"
}

list_sessions() {
    if [[ ! -d "$LOG_DIR" ]]; then
        echo "No sessions found"
        return 1
    fi
    
    print_table_header "Session ID" "Start Time" "Vulnerabilities" "Status"
    
    for session_dir in "$LOG_DIR"/*/; do
        if [[ -d "$session_dir" ]]; then
            local session_id=$(basename "$session_dir")
            local start_time="Unknown"
            local vuln_count=0
            local status="Incomplete"
            
            if [[ -f "$session_dir/session.log" ]]; then
                start_time=$(head -5 "$session_dir/session.log" | grep "Start Time" | cut -d: -f2- | xargs)
                if grep -q "Session completed" "$session_dir/session.log"; then
                    status="Complete"
                fi
            fi
            
            if [[ -f "$session_dir/vulnerabilities.log" ]]; then
                vuln_count=$(grep -c "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log")
            fi
            
            print_table_row "$session_id" "$start_time" "$vuln_count" "$status"
        fi
    done
}

cleanup_old_sessions() {
    local days_old=${1:-30}
    
    print_info "Cleaning up sessions older than $days_old days..."
    
    if [[ -d "$LOG_DIR" ]]; then
        find "$LOG_DIR" -type d -name "20*" -mtime +$days_old -exec rm -rf {} \; 2>/dev/null
        print_success "Old sessions cleaned up"
    fi
}

# ============================================================================
# Log Analysis Functions
# ============================================================================

analyze_session_logs() {
    local session_id="$1"
    local session_dir="$LOG_DIR/$session_id"
    
    if [[ ! -d "$session_dir" ]]; then
        print_error "Session not found: $session_id"
        return 1
    fi
    
    section_header "Session Analysis: $session_id"
    
    # Basic statistics
    if [[ -f "$session_dir/session.log" ]]; then
        local total_entries=$(wc -l < "$session_dir/session.log")
        local error_count=$(grep -c "\[ERROR\]" "$session_dir/session.log")
        local warning_count=$(grep -c "\[WARNING\]" "$session_dir/session.log")
        
        echo "Total Log Entries: $total_entries"
        echo "Errors: $error_count"
        echo "Warnings: $warning_count"
    fi
    
    # Vulnerability summary
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        local vuln_count=$(grep -c "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log")
        echo "Vulnerabilities Found: $vuln_count"
        
        if [[ $vuln_count -gt 0 ]]; then
            echo ""
            subsection_header "Vulnerability Summary"
            grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" | \
                grep -E "(Type:|Severity:|Target:)" | \
                while read -r line; do
                    echo "  $line"
                done
        fi
    fi
    
    # Most active tools
    if [[ -f "$session_dir/scan.log" ]]; then
        echo ""
        subsection_header "Tool Usage"
        grep -o "--- .* Results ---" "$session_dir/scan.log" | \
            sed 's/--- \(.*\) Results ---/\1/' | \
            sort | uniq -c | sort -nr | head -5
    fi
}

export_session_data() {
    local session_id="$1"
    local export_format="${2:-json}"
    local session_dir="$LOG_DIR/$session_id"
    
    if [[ ! -d "$session_dir" ]]; then
        print_error "Session not found: $session_id"
        return 1
    fi
    
    local export_file="$session_dir/export.$export_format"
    
    case "$export_format" in
        "json")
            export_session_json "$session_id" > "$export_file"
            ;;
        "csv")
            export_session_csv "$session_id" > "$export_file"
            ;;
        "xml")
            export_session_xml "$session_id" > "$export_file"
            ;;
        *)
            print_error "Unsupported export format: $export_format"
            return 1
            ;;
    esac
    
    print_success "Session data exported to: $export_file"
    echo "$export_file"
}

export_session_json() {
    local session_id="$1"
    local session_dir="$LOG_DIR/$session_id"
    
    echo "{"
    echo "  \"session_id\": \"$session_id\","
    echo "  \"export_time\": \"$(date -Iseconds)\","
    
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        echo "  \"vulnerabilities\": ["
        local first=true
        while IFS= read -r line; do
            if [[ "$line" == *"VULNERABILITY FOUND"* ]]; then
                [[ "$first" == "false" ]] && echo ","
                first=false
                echo -n "    {"
                
                # Read vulnerability details
                local vuln_type severity target description
                read -r line; vuln_type=$(echo "$line" | sed 's/Type: //')
                read -r line; severity=$(echo "$line" | sed 's/Severity: //')
                read -r line; target=$(echo "$line" | sed 's/Target: //')
                read -r line; # timestamp
                read -r line; description=$(echo "$line" | sed 's/Description: //')
                
                echo "\"type\": \"$vuln_type\", \"severity\": \"$severity\", \"target\": \"$target\", \"description\": \"$description\"}"
            fi
        done < "$session_dir/vulnerabilities.log"
        echo ""
        echo "  ]"
    fi
    
    echo "}"
}

export_session_csv() {
    local session_id="$1"
    local session_dir="$LOG_DIR/$session_id"
    
    echo "Type,Severity,Target,Description,Timestamp"
    
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        while IFS= read -r line; do
            if [[ "$line" == *"VULNERABILITY FOUND"* ]]; then
                local vuln_type severity target description timestamp
                read -r line; vuln_type=$(echo "$line" | sed 's/Type: //')
                read -r line; severity=$(echo "$line" | sed 's/Severity: //')
                read -r line; target=$(echo "$line" | sed 's/Target: //')
                read -r line; timestamp=$(echo "$line" | sed 's/Timestamp: //')
                read -r line; description=$(echo "$line" | sed 's/Description: //')
                
                echo "\"$vuln_type\",\"$severity\",\"$target\",\"$description\",\"$timestamp\""
            fi
        done < "$session_dir/vulnerabilities.log"
    fi
}

# ============================================================================
# Log Rotation and Maintenance
# ============================================================================

rotate_logs() {
    local max_size_mb=${1:-100}
    local max_size_bytes=$((max_size_mb * 1024 * 1024))
    
    for log_file in "$SESSION_LOG" "$SCAN_LOG" "$ERROR_LOG" "$VULN_LOG"; do
        if [[ -f "$log_file" ]] && [[ $(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null) -gt $max_size_bytes ]]; then
            local backup_file="${log_file}.$(date +%Y%m%d_%H%M%S)"
            mv "$log_file" "$backup_file"
            gzip "$backup_file"
            log_info "Log rotated: $log_file -> $backup_file.gz"
        fi
    done
}

set_log_level() {
    local level="$1"
    case "$level" in
        "DEBUG"|"INFO"|"WARNING"|"ERROR"|"CRITICAL")
            LOG_LEVEL="$level"
            log_info "Log level set to: $level"
            ;;
        *)
            log_error "Invalid log level: $level"
            return 1
            ;;
    esac
}
