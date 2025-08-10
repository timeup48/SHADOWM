#!/bin/bash

# ============================================================================
# CVE Intelligence Engine - Advanced CVE Processing & Correlation
# ============================================================================

# Configuration
CVE_INTEL_DIR="./cve/intelligence"
CVE_SCORES_DB="$CVE_INTEL_DIR/cve_scores.db"
CVE_CORRELATIONS_DB="$CVE_INTEL_DIR/correlations.db"
CVE_EXPLOITS_DB="$CVE_INTEL_DIR/exploits.db"
THREAT_INTEL_DIR="$CVE_INTEL_DIR/threat_intel"

# Initialize intelligence directories
init_cve_intelligence() {
    mkdir -p "$CVE_INTEL_DIR" "$THREAT_INTEL_DIR"
    
    print_info "Initializing CVE Intelligence Engine..."
    
    # Create intelligence databases
    create_cve_scores_database
    create_correlations_database
    create_exploits_database
    
    # Initialize threat intelligence feeds
    init_threat_intelligence
    
    print_success "CVE Intelligence Engine initialized"
}

# ============================================================================
# CVSS v3.1 Calculator and Scoring Engine
# ============================================================================

create_cve_scores_database() {
    local scores_db="$CVE_SCORES_DB"
    
    print_info "Creating CVE scoring database..."
    
    cat > "$scores_db" << 'EOF'
# CVE Scoring Database - CVSS v3.1 Enhanced
# Format: CVE-ID|BASE_SCORE|TEMPORAL_SCORE|ENVIRONMENTAL_SCORE|EXPLOITABILITY|IMPACT|SEVERITY|PRIORITY
CVE-2021-44228|10.0|9.8|9.5|3.9|6.0|CRITICAL|1
CVE-2014-6271|10.0|9.0|8.8|3.9|6.0|CRITICAL|2
CVE-2017-0144|8.1|7.5|7.8|2.8|5.9|HIGH|3
CVE-2014-0160|7.5|6.9|7.2|2.2|5.3|HIGH|4
CVE-2019-0708|9.8|9.0|9.2|3.8|5.9|CRITICAL|5
EOF

    print_success "CVE scoring database created"
}

calculate_cvss_score() {
    local cve_id="$1"
    local attack_vector="$2"      # N=Network, A=Adjacent, L=Local, P=Physical
    local attack_complexity="$3"  # L=Low, H=High
    local privileges_required="$4" # N=None, L=Low, H=High
    local user_interaction="$5"   # N=None, R=Required
    local scope="$6"              # U=Unchanged, C=Changed
    local confidentiality="$7"    # H=High, L=Low, N=None
    local integrity="$8"          # H=High, L=Low, N=None
    local availability="$9"       # H=High, L=Low, N=None
    
    # CVSS v3.1 Base Score Calculation
    local av_score=0
    case "$attack_vector" in
        "N") av_score=0.85 ;;
        "A") av_score=0.62 ;;
        "L") av_score=0.55 ;;
        "P") av_score=0.2 ;;
    esac
    
    local ac_score=0
    case "$attack_complexity" in
        "L") ac_score=0.77 ;;
        "H") ac_score=0.44 ;;
    esac
    
    local pr_score=0
    case "$privileges_required" in
        "N") pr_score=0.85 ;;
        "L") pr_score=0.62 ;;
        "H") pr_score=0.27 ;;
    esac
    
    local ui_score=0
    case "$user_interaction" in
        "N") ui_score=0.85 ;;
        "R") ui_score=0.62 ;;
    esac
    
    local cia_score=0
    for impact in "$confidentiality" "$integrity" "$availability"; do
        case "$impact" in
            "H") cia_score=$(echo "$cia_score + 0.56" | bc -l) ;;
            "L") cia_score=$(echo "$cia_score + 0.22" | bc -l) ;;
            "N") cia_score=$(echo "$cia_score + 0" | bc -l) ;;
        esac
    done
    
    # Calculate exploitability and impact sub-scores
    local exploitability=$(echo "8.22 * $av_score * $ac_score * $pr_score * $ui_score" | bc -l)
    local impact=$(echo "6.42 * $cia_score" | bc -l)
    
    # Calculate base score
    local base_score
    if (( $(echo "$impact <= 0" | bc -l) )); then
        base_score=0
    elif [[ "$scope" == "U" ]]; then
        base_score=$(echo "scale=1; ($impact + $exploitability)" | bc -l)
    else
        base_score=$(echo "scale=1; (1.08 * ($impact + $exploitability))" | bc -l)
    fi
    
    # Cap at 10.0
    if (( $(echo "$base_score > 10.0" | bc -l) )); then
        base_score=10.0
    fi
    
    # Determine severity
    local severity="LOW"
    if (( $(echo "$base_score >= 9.0" | bc -l) )); then
        severity="CRITICAL"
    elif (( $(echo "$base_score >= 7.0" | bc -l) )); then
        severity="HIGH"
    elif (( $(echo "$base_score >= 4.0" | bc -l) )); then
        severity="MEDIUM"
    fi
    
    # Update scores database
    local score_entry="$cve_id|$base_score|$base_score|$base_score|$exploitability|$impact|$severity|$(get_priority_score "$base_score")"
    
    # Remove existing entry and add new one
    grep -v "^$cve_id|" "$CVE_SCORES_DB" > "${CVE_SCORES_DB}.tmp" 2>/dev/null || touch "${CVE_SCORES_DB}.tmp"
    echo "$score_entry" >> "${CVE_SCORES_DB}.tmp"
    mv "${CVE_SCORES_DB}.tmp" "$CVE_SCORES_DB"
    
    print_success "CVSS Score calculated for $cve_id: $base_score ($severity)"
    echo "$base_score"
}

get_priority_score() {
    local base_score="$1"
    
    if (( $(echo "$base_score >= 9.0" | bc -l) )); then
        echo "1"  # Highest priority
    elif (( $(echo "$base_score >= 7.0" | bc -l) )); then
        echo "2"  # High priority
    elif (( $(echo "$base_score >= 4.0" | bc -l) )); then
        echo "3"  # Medium priority
    else
        echo "4"  # Low priority
    fi
}

# ============================================================================
# CVE Correlation Engine
# ============================================================================

create_correlations_database() {
    local correlations_db="$CVE_CORRELATIONS_DB"
    
    print_info "Creating CVE correlations database..."
    
    cat > "$correlations_db" << 'EOF'
# CVE Correlations Database - Service and Technology Mappings
# Format: SERVICE|TECHNOLOGY|CVE_PATTERN|DETECTION_METHOD|CORRELATION_STRENGTH
apache|httpd|CVE-20[0-9]{2}-[0-9]+|banner_check|HIGH
nginx|web_server|CVE-20[0-9]{2}-[0-9]+|version_check|HIGH
wordpress|cms|CVE-20[0-9]{2}-[0-9]+|path_check|MEDIUM
mysql|database|CVE-20[0-9]{2}-[0-9]+|service_check|HIGH
php|language|CVE-20[0-9]{2}-[0-9]+|version_check|MEDIUM
openssl|crypto|CVE-20[0-9]{2}-[0-9]+|ssl_check|HIGH
openssh|ssh|CVE-20[0-9]{2}-[0-9]+|banner_check|HIGH
windows|os|CVE-20[0-9]{2}-[0-9]+|os_check|HIGH
linux|os|CVE-20[0-9]{2}-[0-9]+|kernel_check|HIGH
java|runtime|CVE-20[0-9]{2}-[0-9]+|dependency_check|MEDIUM
EOF

    print_success "CVE correlations database created"
}

correlate_cves_with_services() {
    local detected_services="$1"
    local target="$2"
    
    print_info "Correlating CVEs with detected services..."
    
    local relevant_cves=()
    local correlation_results="$CVE_INTEL_DIR/correlation_results_$(date +%s).txt"
    
    echo "CVE Correlation Results for $target" > "$correlation_results"
    echo "Generated: $(date)" >> "$correlation_results"
    echo "Detected Services: $detected_services" >> "$correlation_results"
    echo "=================================" >> "$correlation_results"
    
    # Split services and correlate each
    IFS=',' read -ra SERVICES <<< "$detected_services"
    
    for service in "${SERVICES[@]}"; do
        service=$(echo "$service" | tr '[:upper:]' '[:lower:]' | xargs)
        
        print_info "Correlating CVEs for service: $service"
        
        # Find matching correlations
        local matches=$(grep -i "$service" "$CVE_CORRELATIONS_DB" 2>/dev/null)
        
        if [[ -n "$matches" ]]; then
            echo "" >> "$correlation_results"
            echo "Service: $service" >> "$correlation_results"
            echo "-------------------" >> "$correlation_results"
            
            while IFS='|' read -r svc tech cve_pattern detection strength; do
                if [[ "$svc" == "$service" ]]; then
                    # Find CVEs matching the pattern
                    local matching_cves=$(grep -E "$cve_pattern" "$CVE_DATABASE_DIR/known_cves.txt" 2>/dev/null | head -10)
                    
                    if [[ -n "$matching_cves" ]]; then
                        echo "Technology: $tech" >> "$correlation_results"
                        echo "Detection Method: $detection" >> "$correlation_results"
                        echo "Correlation Strength: $strength" >> "$correlation_results"
                        echo "Relevant CVEs:" >> "$correlation_results"
                        
                        while IFS='|' read -r cve_id severity type desc services det year; do
                            if [[ -n "$cve_id" ]]; then
                                echo "  $cve_id ($severity) - $desc" >> "$correlation_results"
                                relevant_cves+=("$cve_id")
                                
                                # Get priority score
                                local priority=$(get_cve_priority "$cve_id")
                                print_warning "Relevant CVE found: $cve_id ($severity, Priority: $priority)"
                            fi
                        done <<< "$matching_cves"
                        
                        echo "" >> "$correlation_results"
                    fi
                fi
            done <<< "$matches"
        else
            print_info "No specific CVE correlations found for: $service"
        fi
    done
    
    # Generate prioritized testing recommendations
    echo "" >> "$correlation_results"
    echo "TESTING RECOMMENDATIONS" >> "$correlation_results"
    echo "======================" >> "$correlation_results"
    
    # Sort CVEs by priority
    local prioritized_cves=()
    for cve in "${relevant_cves[@]}"; do
        local priority=$(get_cve_priority "$cve")
        prioritized_cves+=("$priority:$cve")
    done
    
    # Sort and recommend top 10
    printf '%s\n' "${prioritized_cves[@]}" | sort -n | head -10 | while IFS=':' read -r priority cve; do
        local cve_info=$(grep "$cve" "$CVE_DATABASE_DIR/known_cves.txt" 2>/dev/null)
        if [[ -n "$cve_info" ]]; then
            local severity=$(echo "$cve_info" | cut -d'|' -f2)
            local desc=$(echo "$cve_info" | cut -d'|' -f4)
            echo "Priority $priority: $cve ($severity) - $desc" >> "$correlation_results"
        fi
    done
    
    print_success "CVE correlation completed. Results saved to: $correlation_results"
    
    # Return the correlation results file path
    echo "$correlation_results"
}

get_cve_priority() {
    local cve_id="$1"
    
    # Check scores database first
    local priority=$(grep "^$cve_id|" "$CVE_SCORES_DB" 2>/dev/null | cut -d'|' -f8)
    
    if [[ -n "$priority" ]]; then
        echo "$priority"
    else
        # Fallback to severity-based priority
        local severity=$(grep "$cve_id" "$CVE_DATABASE_DIR/known_cves.txt" 2>/dev/null | cut -d'|' -f2)
        case "$severity" in
            "CRITICAL") echo "1" ;;
            "HIGH") echo "2" ;;
            "MEDIUM") echo "3" ;;
            "LOW") echo "4" ;;
            *) echo "5" ;;
        esac
    fi
}

# ============================================================================
# Exploit Intelligence Database
# ============================================================================

create_exploits_database() {
    local exploits_db="$CVE_EXPLOITS_DB"
    
    print_info "Creating exploits intelligence database..."
    
    cat > "$exploits_db" << 'EOF'
# Exploits Intelligence Database
# Format: CVE-ID|EXPLOIT_AVAILABLE|EXPLOIT_TYPE|DIFFICULTY|PUBLIC_EXPLOIT|METASPLOIT|RELIABILITY
CVE-2021-44228|YES|RCE|LOW|YES|YES|EXCELLENT
CVE-2014-6271|YES|RCE|LOW|YES|YES|EXCELLENT
CVE-2017-0144|YES|RCE|MEDIUM|YES|YES|EXCELLENT
CVE-2014-0160|YES|INFO|LOW|YES|YES|GOOD
CVE-2019-0708|YES|RCE|HIGH|YES|YES|AVERAGE
CVE-2020-1472|YES|PRIV|MEDIUM|YES|YES|GOOD
CVE-2021-26855|YES|RCE|MEDIUM|YES|YES|GOOD
CVE-2022-26134|YES|RCE|LOW|YES|NO|GOOD
CVE-2023-0386|YES|PRIV|MEDIUM|YES|NO|AVERAGE
CVE-2022-40684|YES|AUTH|LOW|YES|NO|GOOD
EOF

    print_success "Exploits intelligence database created"
}

check_exploit_availability() {
    local cve_id="$1"
    
    local exploit_info=$(grep "^$cve_id|" "$CVE_EXPLOITS_DB" 2>/dev/null)
    
    if [[ -n "$exploit_info" ]]; then
        IFS='|' read -r cve available type difficulty public metasploit reliability <<< "$exploit_info"
        
        echo ""
        print_info "Exploit Intelligence for $cve_id:"
        print_info "  Exploit Available: $(if [[ "$available" == "YES" ]]; then echo -e "${GREEN}$available${NC}"; else echo -e "${RED}$available${NC}"; fi)"
        print_info "  Exploit Type: $type"
        print_info "  Difficulty: $difficulty"
        print_info "  Public Exploit: $(if [[ "$public" == "YES" ]]; then echo -e "${YELLOW}$public${NC}"; else echo -e "${GREEN}$public${NC}"; fi)"
        print_info "  Metasploit Module: $(if [[ "$metasploit" == "YES" ]]; then echo -e "${RED}$metasploit${NC}"; else echo -e "${GREEN}$metasploit${NC}"; fi)"
        print_info "  Reliability: $reliability"
        
        # Risk assessment
        local risk_level="LOW"
        if [[ "$available" == "YES" && "$difficulty" == "LOW" && "$public" == "YES" ]]; then
            risk_level="CRITICAL"
        elif [[ "$available" == "YES" && "$difficulty" == "MEDIUM" ]]; then
            risk_level="HIGH"
        elif [[ "$available" == "YES" ]]; then
            risk_level="MEDIUM"
        fi
        
        print_warning "Exploitation Risk Level: $(severity_color "$risk_level")"
        echo ""
        
        return 0
    else
        print_info "No exploit intelligence available for $cve_id"
        return 1
    fi
}

# ============================================================================
# Threat Intelligence Integration
# ============================================================================

init_threat_intelligence() {
    print_info "Initializing threat intelligence feeds..."
    
    # Create threat intelligence structure
    mkdir -p "$THREAT_INTEL_DIR/iocs" "$THREAT_INTEL_DIR/campaigns" "$THREAT_INTEL_DIR/actors"
    
    # Create sample threat intelligence data
    create_sample_threat_intel
    
    print_success "Threat intelligence initialized"
}

create_sample_threat_intel() {
    # IOCs (Indicators of Compromise)
    cat > "$THREAT_INTEL_DIR/iocs/recent_iocs.txt" << 'EOF'
# Recent IOCs related to CVE exploitation
# Format: IOC_TYPE|IOC_VALUE|CVE_REFERENCE|CAMPAIGN|CONFIDENCE
IP|192.168.1.100|CVE-2021-44228|Log4Shell Campaign|HIGH
DOMAIN|malicious-log4j.com|CVE-2021-44228|Log4Shell Campaign|HIGH
URL|http://evil.com/exploit.class|CVE-2021-44228|Log4Shell Campaign|MEDIUM
HASH|d41d8cd98f00b204e9800998ecf8427e|CVE-2014-6271|Shellshock Botnet|HIGH
IP|10.0.0.50|CVE-2017-0144|EternalBlue Campaign|HIGH
EOF

    # Threat Campaigns
    cat > "$THREAT_INTEL_DIR/campaigns/active_campaigns.txt" << 'EOF'
# Active threat campaigns
# Format: CAMPAIGN_NAME|CVE_EXPLOITED|THREAT_ACTOR|STATUS|FIRST_SEEN|LAST_SEEN
Log4Shell Mass Exploitation|CVE-2021-44228|Various APTs|ACTIVE|2021-12-10|2024-01-15
EternalBlue Ransomware|CVE-2017-0144|Lazarus Group|ACTIVE|2017-05-12|2024-01-10
Shellshock Botnet|CVE-2014-6271|Unknown|LOW|2014-09-24|2023-12-01
BlueKeep Exploitation|CVE-2019-0708|APT41|MEDIUM|2019-08-15|2023-11-20
EOF

    # Threat Actors
    cat > "$THREAT_INTEL_DIR/actors/known_actors.txt" << 'EOF'
# Known threat actors and their CVE preferences
# Format: ACTOR_NAME|PREFERRED_CVES|TACTICS|TARGETS|SOPHISTICATION
Lazarus Group|CVE-2017-0144,CVE-2019-0708|Ransomware,Espionage|Financial,Government|HIGH
APT41|CVE-2019-0708,CVE-2021-26855|Espionage,Financial|Healthcare,Government|HIGH
Various APTs|CVE-2021-44228|Mass Exploitation|Opportunistic|MEDIUM
Unknown Actors|CVE-2014-6271|Botnet,Cryptomining|Web Servers|LOW
EOF
}

correlate_with_threat_intel() {
    local target="$1"
    local detected_cves="$2"
    
    print_info "Correlating findings with threat intelligence..."
    
    local threat_report="$CVE_INTEL_DIR/threat_correlation_$(date +%s).txt"
    
    echo "Threat Intelligence Correlation Report" > "$threat_report"
    echo "Target: $target" >> "$threat_report"
    echo "Generated: $(date)" >> "$threat_report"
    echo "Detected CVEs: $detected_cves" >> "$threat_report"
    echo "======================================" >> "$threat_report"
    
    # Check each detected CVE against threat intelligence
    IFS=',' read -ra CVES <<< "$detected_cves"
    
    for cve in "${CVES[@]}"; do
        cve=$(echo "$cve" | xargs)
        
        echo "" >> "$threat_report"
        echo "CVE: $cve" >> "$threat_report"
        echo "----------" >> "$threat_report"
        
        # Check active campaigns
        local campaigns=$(grep "$cve" "$THREAT_INTEL_DIR/campaigns/active_campaigns.txt" 2>/dev/null)
        if [[ -n "$campaigns" ]]; then
            echo "Active Campaigns:" >> "$threat_report"
            while IFS='|' read -r campaign cve_ref actor status first_seen last_seen; do
                echo "  - $campaign (Actor: $actor, Status: $status)" >> "$threat_report"
                print_warning "Threat detected: $campaign targeting $cve"
            done <<< "$campaigns"
        fi
        
        # Check threat actors
        local actors=$(grep "$cve" "$THREAT_INTEL_DIR/actors/known_actors.txt" 2>/dev/null)
        if [[ -n "$actors" ]]; then
            echo "Known Threat Actors:" >> "$threat_report"
            while IFS='|' read -r actor cves tactics targets sophistication; do
                echo "  - $actor (Tactics: $tactics, Sophistication: $sophistication)" >> "$threat_report"
                print_error "High-value target: $actor known to exploit $cve"
            done <<< "$actors"
        fi
        
        # Check IOCs
        local iocs=$(grep "$cve" "$THREAT_INTEL_DIR/iocs/recent_iocs.txt" 2>/dev/null)
        if [[ -n "$iocs" ]]; then
            echo "Related IOCs:" >> "$threat_report"
            while IFS='|' read -r ioc_type ioc_value cve_ref campaign confidence; do
                echo "  - $ioc_type: $ioc_value (Campaign: $campaign, Confidence: $confidence)" >> "$threat_report"
            done <<< "$iocs"
        fi
    done
    
    print_success "Threat intelligence correlation completed: $threat_report"
    echo "$threat_report"
}

# ============================================================================
# Intelligence Reporting
# ============================================================================

generate_intelligence_report() {
    local target="$1"
    local scan_results="$2"
    
    print_info "Generating comprehensive intelligence report..."
    
    local intel_report="$CVE_INTEL_DIR/intelligence_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$intel_report" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>CVEHACK Intelligence Report - $target</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background: #ffebee; border-left: 5px solid #f44336; }
        .high { background: #fff3e0; border-left: 5px solid #ff9800; }
        .medium { background: #f3e5f5; border-left: 5px solid #9c27b0; }
        .low { background: #e8f5e8; border-left: 5px solid #4caf50; }
        .cve-item { margin: 10px 0; padding: 10px; background: #f9f9f9; border-radius: 3px; }
        .exploit-available { color: #d32f2f; font-weight: bold; }
        .no-exploit { color: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CVEHACK Intelligence Report</h1>
        <p>Target: $target | Generated: $(date)</p>
    </div>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <p>This report provides comprehensive vulnerability intelligence for the target system, including CVE correlations, exploit availability, and threat landscape analysis.</p>
    </div>
    
    <div class="section critical">
        <h2>🚨 Critical Findings</h2>
        <div id="critical-findings">
            <!-- Critical findings will be populated here -->
        </div>
    </div>
    
    <div class="section high">
        <h2>⚠️ High Priority Vulnerabilities</h2>
        <div id="high-priority">
            <!-- High priority findings will be populated here -->
        </div>
    </div>
    
    <div class="section">
        <h2>🎯 Threat Intelligence Correlation</h2>
        <div id="threat-intel">
            <!-- Threat intelligence will be populated here -->
        </div>
    </div>
    
    <div class="section">
        <h2>💥 Exploit Intelligence</h2>
        <div id="exploit-intel">
            <!-- Exploit intelligence will be populated here -->
        </div>
    </div>
    
    <div class="section">
        <h2>📈 Risk Assessment Matrix</h2>
        <table>
            <tr>
                <th>CVE ID</th>
                <th>CVSS Score</th>
                <th>Severity</th>
                <th>Exploit Available</th>
                <th>Risk Level</th>
                <th>Priority</th>
            </tr>
            <!-- Risk matrix will be populated here -->
        </table>
    </div>
    
    <div class="section">
        <h2>🔧 Remediation Recommendations</h2>
        <div id="remediation">
            <!-- Remediation recommendations will be populated here -->
        </div>
    </div>
    
    <div class="section">
        <h2>📋 Technical Details</h2>
        <div id="technical-details">
            <pre>$scan_results</pre>
        </div>
    </div>
</body>
</html>
EOF

    print_success "Intelligence report generated: $intel_report"
    echo "$intel_report"
}

# ============================================================================
# Configuration and Management
# ============================================================================

update_intelligence_databases() {
    print_info "Updating intelligence databases..."
    
    # Backup existing databases
    local backup_dir="$CVE_INTEL_DIR/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    cp "$CVE_SCORES_DB" "$backup_dir/" 2>/dev/null
    cp "$CVE_CORRELATIONS_DB" "$backup_dir/" 2>/dev/null
    cp "$CVE_EXPLOITS_DB" "$backup_dir/" 2>/dev/null
    
    # Recreate databases with latest data
    create_cve_scores_database
    create_correlations_database
    create_exploits_database
    
    print_success "Intelligence databases updated. Backup saved to: $backup_dir"
}

show_intelligence_stats() {
    print_info "CVE Intelligence Statistics:"
    
    local cve_count=$(wc -l < "$CVE_DATABASE_DIR/known_cves.txt" 2>/dev/null || echo "0")
    local scores_count=$(wc -l < "$CVE_SCORES_DB" 2>/dev/null || echo "0")
    local correlations_count=$(wc -l < "$CVE_CORRELATIONS_DB" 2>/dev/null || echo "0")
    local exploits_count=$(wc -l < "$CVE_EXPLOITS_DB" 2>/dev/null || echo "0")
    
    echo "  Total CVEs in database: $cve_count"
    echo "  CVEs with CVSS scores: $scores_count"
    echo "  Service correlations: $correlations_count"
    echo "  Exploit intelligence entries: $exploits_count"
    
    # Show severity distribution
    if [[ -f "$CVE_DATABASE_DIR/known_cves.txt" ]]; then
        local critical_count=$(grep -c "CRITICAL" "$CVE_DATABASE_DIR/known_cves.txt" 2>/dev/null || echo "0")
        local high_count=$(grep -c "HIGH" "$CVE_DATABASE_DIR/known_cves.txt" 2>/dev/null || echo "0")
        local medium_count=$(grep -c "MEDIUM" "$CVE_DATABASE_DIR/known_cves.txt" 2>/dev/null || echo "0")
        local low_count=$(grep -c "LOW" "$CVE_DATABASE_DIR/known_cves.txt" 2>/dev/null || echo "0")
        
        echo ""
        echo "  Severity Distribution:"
        echo "    Critical: $critical_count"
        echo "    High: $high_count"
        echo "    Medium: $medium_count"
        echo "    Low: $low_count"
    fi
}
