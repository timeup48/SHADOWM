#!/bin/bash

# ============================================================================
# Parallel Scanning Engine for CVEHACK - Multi-threaded Performance
# ============================================================================

# Configuration
MAX_PARALLEL_JOBS=10
JOB_TIMEOUT=300
SCAN_QUEUE="/tmp/cvehack_scan_queue"
RESULTS_QUEUE="/tmp/cvehack_results_queue"

# Job management
declare -A ACTIVE_JOBS
declare -A JOB_PIDS
declare -A JOB_START_TIMES

# ============================================================================
# Parallel Job Management
# ============================================================================

init_parallel_engine() {
    print_info "Initializing parallel scanning engine..."
    
    # Create job queues
    mkdir -p "$(dirname "$SCAN_QUEUE")"
    mkdir -p "$(dirname "$RESULTS_QUEUE")"
    
    # Clean up any existing queues
    rm -f "${SCAN_QUEUE}"*
    rm -f "${RESULTS_QUEUE}"*
    
    # Set up signal handlers for cleanup
    trap cleanup_parallel_engine EXIT INT TERM
    
    print_success "Parallel engine initialized with $MAX_PARALLEL_JOBS max jobs"
}

cleanup_parallel_engine() {
    print_info "Cleaning up parallel scanning engine..."
    
    # Kill any remaining jobs
    for pid in "${JOB_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
            sleep 1
            kill -KILL "$pid" 2>/dev/null
        fi
    done
    
    # Clean up temporary files
    rm -f "${SCAN_QUEUE}"*
    rm -f "${RESULTS_QUEUE}"*
    
    print_success "Parallel engine cleanup completed"
}

# ============================================================================
# Job Queue Management
# ============================================================================

add_scan_job() {
    local job_type="$1"
    local target="$2"
    local options="$3"
    local job_id="$(date +%s)_$$_$RANDOM"
    
    local job_file="${SCAN_QUEUE}_${job_id}"
    
    cat > "$job_file" << EOF
JOB_ID=$job_id
JOB_TYPE=$job_type
TARGET=$target
OPTIONS=$options
CREATED=$(date +%s)
STATUS=queued
EOF
    
    print_info "Added scan job: $job_type -> $target (ID: $job_id)"
    echo "$job_id"
}

get_next_job() {
    local oldest_job=""
    local oldest_time=999999999999
    
    for job_file in "${SCAN_QUEUE}"_*; do
        if [[ -f "$job_file" ]]; then
            local created=$(grep "CREATED=" "$job_file" | cut -d= -f2)
            if [[ $created -lt $oldest_time ]]; then
                oldest_time=$created
                oldest_job="$job_file"
            fi
        fi
    done
    
    if [[ -n "$oldest_job" ]]; then
        echo "$oldest_job"
    fi
}

# ============================================================================
# Parallel Execution Engine
# ============================================================================

start_parallel_scans() {
    local max_jobs=${1:-$MAX_PARALLEL_JOBS}
    
    print_info "Starting parallel scan execution (max jobs: $max_jobs)..."
    
    while true; do
        # Check for completed jobs
        check_completed_jobs
        
        # Start new jobs if slots available
        local active_count=$(get_active_job_count)
        
        if [[ $active_count -lt $max_jobs ]]; then
            local next_job=$(get_next_job)
            
            if [[ -n "$next_job" && -f "$next_job" ]]; then
                start_scan_job "$next_job"
            else
                # No more jobs in queue
                if [[ $active_count -eq 0 ]]; then
                    print_success "All parallel scans completed"
                    break
                fi
            fi
        fi
        
        # Brief pause to prevent CPU spinning
        sleep 0.5
    done
}

start_scan_job() {
    local job_file="$1"
    
    # Parse job details
    source "$job_file"
    
    print_info "Starting job: $JOB_TYPE -> $TARGET (ID: $JOB_ID)"
    
    # Execute job in background
    execute_scan_job "$JOB_TYPE" "$TARGET" "$OPTIONS" "$JOB_ID" &
    local pid=$!
    
    # Track the job
    ACTIVE_JOBS["$JOB_ID"]="$job_file"
    JOB_PIDS["$JOB_ID"]=$pid
    JOB_START_TIMES["$JOB_ID"]=$(date +%s)
    
    # Mark job as running
    sed -i "s/STATUS=queued/STATUS=running/" "$job_file"
    
    # Remove from queue
    rm -f "$job_file"
}

execute_scan_job() {
    local job_type="$1"
    local target="$2"
    local options="$3"
    local job_id="$4"
    
    local result_file="${RESULTS_QUEUE}_${job_id}"
    local start_time=$(date +%s)
    
    # Redirect output to result file
    exec > "$result_file" 2>&1
    
    echo "JOB_ID=$job_id"
    echo "JOB_TYPE=$job_type"
    echo "TARGET=$target"
    echo "START_TIME=$start_time"
    echo "STATUS=running"
    echo "OUTPUT_START"
    
    # Execute the actual scan based on job type
    case "$job_type" in
        "web_tech_scan")
            source "$SCRIPT_DIR/../cve/tools/custom_webtech_scanner.sh"
            scan_web_technology "$target"
            ;;
        "wordpress_scan")
            source "$SCRIPT_DIR/../cve/tools/custom_wordpress_scanner.sh"
            scan_wordpress_security "$target"
            ;;
        "directory_scan")
            source "$SCRIPT_DIR/../cve/tools/custom_directory_scanner.sh"
            scan_directories "$target" "$options"
            ;;
        "network_recon")
            source "$SCRIPT_DIR/../cve/tools/custom_network_recon.sh"
            scan_network_recon "$target" "$options"
            ;;
        "port_scan")
            source "$SCRIPT_DIR/../modules/recon.sh"
            port_scan "$target" "$options"
            ;;
        "cve_test")
            source "$SCRIPT_DIR/../cve/cve_manager.sh"
            test_specific_cve "$target" "$options"
            ;;
        *)
            echo "ERROR: Unknown job type: $job_type"
            exit 1
            ;;
    esac
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "OUTPUT_END"
    echo "END_TIME=$end_time"
    echo "DURATION=$duration"
    echo "STATUS=completed"
}

check_completed_jobs() {
    for job_id in "${!JOB_PIDS[@]}"; do
        local pid="${JOB_PIDS[$job_id]}"
        
        if ! kill -0 "$pid" 2>/dev/null; then
            # Job completed
            local result_file="${RESULTS_QUEUE}_${job_id}"
            
            if [[ -f "$result_file" ]]; then
                process_job_result "$job_id" "$result_file"
            fi
            
            # Clean up tracking
            unset ACTIVE_JOBS["$job_id"]
            unset JOB_PIDS["$job_id"]
            unset JOB_START_TIMES["$job_id"]
        else
            # Check for timeout
            local start_time="${JOB_START_TIMES[$job_id]}"
            local current_time=$(date +%s)
            local elapsed=$((current_time - start_time))
            
            if [[ $elapsed -gt $JOB_TIMEOUT ]]; then
                print_warning "Job $job_id timed out after $elapsed seconds, killing..."
                kill -TERM "$pid" 2>/dev/null
                sleep 2
                kill -KILL "$pid" 2>/dev/null
                
                # Clean up
                unset ACTIVE_JOBS["$job_id"]
                unset JOB_PIDS["$job_id"]
                unset JOB_START_TIMES["$job_id"]
            fi
        fi
    done
}

process_job_result() {
    local job_id="$1"
    local result_file="$2"
    
    # Extract job information
    local job_type=$(grep "JOB_TYPE=" "$result_file" | cut -d= -f2)
    local target=$(grep "TARGET=" "$result_file" | cut -d= -f2)
    local duration=$(grep "DURATION=" "$result_file" | cut -d= -f2)
    local status=$(grep "STATUS=" "$result_file" | tail -1 | cut -d= -f2)
    
    if [[ "$status" == "completed" ]]; then
        print_success "Job completed: $job_type -> $target (${duration}s)"
        
        # Extract and log the output
        sed -n '/OUTPUT_START/,/OUTPUT_END/p' "$result_file" | grep -v "OUTPUT_START\|OUTPUT_END" | while read -r line; do
            echo "  $line"
        done
        
        # Save to session logs if available
        if [[ -n "$SESSION_LOG" ]]; then
            echo "=== Parallel Job Result: $job_id ===" >> "$SESSION_LOG"
            cat "$result_file" >> "$SESSION_LOG"
            echo "" >> "$SESSION_LOG"
        fi
    else
        print_error "Job failed: $job_type -> $target"
    fi
    
    # Clean up result file
    rm -f "$result_file"
}

get_active_job_count() {
    echo "${#ACTIVE_JOBS[@]}"
}

# ============================================================================
# High-Level Parallel Scan Functions
# ============================================================================

parallel_web_scan() {
    local target="$1"
    
    print_info "Starting parallel web scan on $target..."
    
    init_parallel_engine
    
    # Queue multiple scan types
    add_scan_job "web_tech_scan" "$target" ""
    add_scan_job "wordpress_scan" "$target" ""
    add_scan_job "directory_scan" "$target" "common"
    
    # Start parallel execution
    start_parallel_scans 3
    
    print_success "Parallel web scan completed for $target"
}

parallel_network_scan() {
    local target="$1"
    local ports="${2:-common}"
    
    print_info "Starting parallel network scan on $target..."
    
    init_parallel_engine
    
    # Queue network scans
    add_scan_job "network_recon" "$target" ""
    add_scan_job "port_scan" "$target" "$ports"
    
    # Start parallel execution
    start_parallel_scans 2
    
    print_success "Parallel network scan completed for $target"
}

parallel_cve_testing() {
    local target="$1"
    local cve_list="$2"
    
    print_info "Starting parallel CVE testing on $target..."
    
    init_parallel_engine
    
    # Queue CVE tests
    if [[ -n "$cve_list" ]]; then
        IFS=',' read -ra CVES <<< "$cve_list"
        for cve in "${CVES[@]}"; do
            add_scan_job "cve_test" "$target" "$cve"
        done
    else
        # Test top 10 critical CVEs
        local critical_cves=$(grep "CRITICAL" "$CVE_DATABASE_DIR/known_cves.txt" | head -10 | cut -d'|' -f1)
        while read -r cve; do
            if [[ -n "$cve" ]]; then
                add_scan_job "cve_test" "$target" "$cve"
            fi
        done <<< "$critical_cves"
    fi
    
    # Start parallel execution
    start_parallel_scans 5
    
    print_success "Parallel CVE testing completed for $target"
}

# ============================================================================
# Performance Monitoring
# ============================================================================

show_parallel_status() {
    local active_count=$(get_active_job_count)
    local queued_count=$(ls "${SCAN_QUEUE}"_* 2>/dev/null | wc -l)
    
    echo ""
    print_info "Parallel Scan Status:"
    print_info "  Active Jobs: $active_count"
    print_info "  Queued Jobs: $queued_count"
    print_info "  Max Parallel: $MAX_PARALLEL_JOBS"
    
    if [[ $active_count -gt 0 ]]; then
        print_info "  Running Jobs:"
        for job_id in "${!ACTIVE_JOBS[@]}"; do
            local start_time="${JOB_START_TIMES[$job_id]}"
            local current_time=$(date +%s)
            local elapsed=$((current_time - start_time))
            print_info "    Job $job_id: ${elapsed}s elapsed"
        done
    fi
    echo ""
}

# ============================================================================
# Configuration
# ============================================================================

configure_parallel_engine() {
    echo -e "${YELLOW}Configure Parallel Scanning Engine:${NC}"
    echo -e "${YELLOW}1.${NC} Set maximum parallel jobs (current: $MAX_PARALLEL_JOBS)"
    echo -e "${YELLOW}2.${NC} Set job timeout (current: $JOB_TIMEOUT seconds)"
    echo -e "${YELLOW}3.${NC} View current status"
    echo -e "${YELLOW}0.${NC} Back"
    echo ""
    echo -e "${BLUE}Select option: ${NC}"
    read -r config_choice
    
    case $config_choice in
        1)
            echo -e "${YELLOW}Enter maximum parallel jobs (1-50): ${NC}"
            read -r new_max_jobs
            if [[ "$new_max_jobs" =~ ^[0-9]+$ ]] && [[ $new_max_jobs -ge 1 ]] && [[ $new_max_jobs -le 50 ]]; then
                MAX_PARALLEL_JOBS=$new_max_jobs
                print_success "Maximum parallel jobs set to: $MAX_PARALLEL_JOBS"
            else
                print_error "Invalid input. Please enter a number between 1 and 50."
            fi
            ;;
        2)
            echo -e "${YELLOW}Enter job timeout in seconds (60-3600): ${NC}"
            read -r new_timeout
            if [[ "$new_timeout" =~ ^[0-9]+$ ]] && [[ $new_timeout -ge 60 ]] && [[ $new_timeout -le 3600 ]]; then
                JOB_TIMEOUT=$new_timeout
                print_success "Job timeout set to: $JOB_TIMEOUT seconds"
            else
                print_error "Invalid input. Please enter a number between 60 and 3600."
            fi
            ;;
        3)
            show_parallel_status
            ;;
        0)
            return
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
}
