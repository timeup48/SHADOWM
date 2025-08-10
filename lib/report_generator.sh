#!/bin/bash

# ============================================================================
# Report Generation Library for CVEHACK
# ============================================================================

# Report templates and styling
HTML_STYLE='
<style>
    body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
    .section { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .critical { color: #dc3545; font-weight: bold; }
    .high { color: #fd7e14; font-weight: bold; }
    .medium { color: #ffc107; font-weight: bold; }
    .low { color: #28a745; font-weight: bold; }
    .info { color: #17a2b8; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0; }
    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
    th { background-color: #f8f9fa; font-weight: bold; }
    .vulnerability { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; }
    .exploit { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; }
    .summary-box { display: inline-block; background: #e9ecef; padding: 15px; margin: 10px; border-radius: 5px; text-align: center; min-width: 120px; }
    .port-open { color: #28a745; }
    .port-closed { color: #dc3545; }
    .port-filtered { color: #ffc107; }
    pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
    .timestamp { color: #6c757d; font-size: 0.9em; }
</style>
'

# ============================================================================
# HTML Report Generation
# ============================================================================

generate_html_report() {
    local session_id="$1"
    local target="$2"
    local report_type="${3:-full}"
    
    local session_dir="$LOG_DIR/$session_id"
    local report_file="$session_dir/report_${report_type}_$(date +%Y%m%d_%H%M%S).html"
    
    if [[ ! -d "$session_dir" ]]; then
        print_error "Session directory not found: $session_dir"
        return 1
    fi
    
    print_info "Generating HTML report..."
    
    # Start HTML document
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVEHACK Security Assessment Report - $session_id</title>
    $HTML_STYLE
</head>
<body>
EOF
    
    # Generate report sections
    generate_html_header "$session_id" "$target" >> "$report_file"
    generate_html_executive_summary "$session_dir" >> "$report_file"
    generate_html_scan_results "$session_dir" >> "$report_file"
    generate_html_vulnerabilities "$session_dir" >> "$report_file"
    generate_html_recommendations "$session_dir" >> "$report_file"
    generate_html_appendix "$session_dir" >> "$report_file"
    
    # Close HTML document
    cat >> "$report_file" << EOF
    <div class="section">
        <h2>Report Information</h2>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Tool:</strong> CVEHACK v1.0</p>
        <p><strong>Session ID:</strong> $session_id</p>
    </div>
</body>
</html>
EOF
    
    print_success "HTML report generated: $report_file"
    log_info "HTML report generated: $report_file"
    
    echo "$report_file"
}

generate_html_header() {
    local session_id="$1"
    local target="$2"
    
    cat << EOF
    <div class="header">
        <h1>🛡️ CVEHACK Security Assessment Report</h1>
        <h2>Target: $target</h2>
        <p><strong>Session ID:</strong> $session_id</p>
        <p><strong>Assessment Date:</strong> $(date)</p>
        <p><strong>Report Type:</strong> Comprehensive Security Assessment</p>
    </div>
EOF
}

generate_html_executive_summary() {
    local session_dir="$1"
    
    # Calculate summary statistics
    local total_vulns=0
    local critical_vulns=0
    local high_vulns=0
    local medium_vulns=0
    local low_vulns=0
    local open_ports=0
    
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        total_vulns=$(grep -c "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null || echo "0")
        critical_vulns=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: CRITICAL" || echo "0")
        high_vulns=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: HIGH" || echo "0")
        medium_vulns=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: MEDIUM" || echo "0")
        low_vulns=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: LOW" || echo "0")
    fi
    
    if [[ -f "$session_dir/scan.log" ]]; then
        open_ports=$(grep -c "open" "$session_dir/scan.log" 2>/dev/null || echo "0")
    fi
    
    cat << EOF
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div style="display: flex; flex-wrap: wrap; justify-content: space-around;">
            <div class="summary-box">
                <h3>$total_vulns</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="summary-box">
                <h3 class="critical">$critical_vulns</h3>
                <p>Critical</p>
            </div>
            <div class="summary-box">
                <h3 class="high">$high_vulns</h3>
                <p>High</p>
            </div>
            <div class="summary-box">
                <h3 class="medium">$medium_vulns</h3>
                <p>Medium</p>
            </div>
            <div class="summary-box">
                <h3 class="low">$low_vulns</h3>
                <p>Low</p>
            </div>
            <div class="summary-box">
                <h3>$open_ports</h3>
                <p>Open Ports</p>
            </div>
        </div>
        
        <h3>Risk Assessment</h3>
        <p>$(generate_risk_assessment $critical_vulns $high_vulns $medium_vulns $low_vulns)</p>
    </div>
EOF
}

generate_risk_assessment() {
    local critical=$1
    local high=$2
    local medium=$3
    local low=$4
    
    if [[ $critical -gt 0 ]]; then
        echo "🔴 <strong>CRITICAL RISK:</strong> Immediate action required. Critical vulnerabilities detected that could lead to complete system compromise."
    elif [[ $high -gt 3 ]]; then
        echo "🟠 <strong>HIGH RISK:</strong> Multiple high-severity vulnerabilities detected. Prompt remediation recommended."
    elif [[ $high -gt 0 ]]; then
        echo "🟡 <strong>MODERATE RISK:</strong> High-severity vulnerabilities detected. Remediation should be prioritized."
    elif [[ $medium -gt 5 ]]; then
        echo "🟡 <strong>MODERATE RISK:</strong> Multiple medium-severity vulnerabilities detected."
    elif [[ $medium -gt 0 || $low -gt 0 ]]; then
        echo "🟢 <strong>LOW RISK:</strong> Minor vulnerabilities detected. Regular security maintenance recommended."
    else
        echo "🟢 <strong>MINIMAL RISK:</strong> No significant vulnerabilities detected in this assessment."
    fi
}

generate_html_scan_results() {
    local session_dir="$1"
    
    cat << EOF
    <div class="section">
        <h2>🔍 Scan Results</h2>
EOF
    
    # Port scan results
    if [[ -f "$session_dir/scan.log" ]]; then
        echo "        <h3>Port Scan Results</h3>"
        echo "        <table>"
        echo "            <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>"
        
        grep -E "(open|closed|filtered)" "$session_dir/scan.log" 2>/dev/null | while read -r line; do
            if [[ "$line" =~ ([0-9]+)/tcp.*open.*([a-zA-Z0-9-]+) ]]; then
                local port="${BASH_REMATCH[1]}"
                local service="${BASH_REMATCH[2]}"
                echo "            <tr><td>$port/tcp</td><td class=\"port-open\">Open</td><td>$service</td><td>-</td></tr>"
            fi
        done
        
        echo "        </table>"
    fi
    
    # Web technology detection
    if grep -q "whatweb\|nikto" "$session_dir/scan.log" 2>/dev/null; then
        echo "        <h3>Web Technology Detection</h3>"
        echo "        <pre>"
        grep -A 10 -B 2 "whatweb\|Web Technology" "$session_dir/scan.log" 2>/dev/null | head -20
        echo "        </pre>"
    fi
    
    echo "    </div>"
}

generate_html_vulnerabilities() {
    local session_dir="$1"
    
    cat << EOF
    <div class="section">
        <h2>🚨 Vulnerabilities Detected</h2>
EOF
    
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        local vuln_count=$(grep -c "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log")
        
        if [[ $vuln_count -gt 0 ]]; then
            echo "        <p>Found <strong>$vuln_count</strong> vulnerabilities during the assessment:</p>"
            
            # Parse vulnerabilities
            awk '/VULNERABILITY FOUND/,/^$/' "$session_dir/vulnerabilities.log" | while IFS= read -r line; do
                if [[ "$line" == *"VULNERABILITY FOUND"* ]]; then
                    echo "        <div class=\"vulnerability\">"
                elif [[ "$line" =~ ^Type:\ (.+) ]]; then
                    echo "            <h4>🔍 ${BASH_REMATCH[1]}</h4>"
                elif [[ "$line" =~ ^Severity:\ (.+) ]]; then
                    local severity="${BASH_REMATCH[1],,}"
                    echo "            <p><strong>Severity:</strong> <span class=\"$severity\">${BASH_REMATCH[1]}</span></p>"
                elif [[ "$line" =~ ^Target:\ (.+) ]]; then
                    echo "            <p><strong>Target:</strong> ${BASH_REMATCH[1]}</p>"
                elif [[ "$line" =~ ^Description:\ (.+) ]]; then
                    echo "            <p><strong>Description:</strong> ${BASH_REMATCH[1]}</p>"
                elif [[ "$line" =~ ^Evidence: ]]; then
                    echo "            <p><strong>Evidence:</strong></p>"
                    echo "            <pre>"
                elif [[ "$line" == "================================================================================" ]]; then
                    echo "            </pre>"
                    echo "        </div>"
                elif [[ -n "$line" && "$line" != "Evidence:" ]]; then
                    echo "$line"
                fi
            done
        else
            echo "        <p>✅ No vulnerabilities detected during this assessment.</p>"
        fi
    else
        echo "        <p>ℹ️ No vulnerability data available.</p>"
    fi
    
    echo "    </div>"
}

generate_html_recommendations() {
    local session_dir="$1"
    
    cat << EOF
    <div class="section">
        <h2>💡 Recommendations</h2>
        
        <h3>Immediate Actions</h3>
        <ul>
EOF
    
    # Generate recommendations based on findings
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        local critical_count=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: CRITICAL" || echo "0")
        local high_count=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: HIGH" || echo "0")
        
        if [[ $critical_count -gt 0 ]]; then
            echo "            <li><strong>🔴 URGENT:</strong> Address all critical vulnerabilities immediately</li>"
            echo "            <li>Implement emergency patches for critical security flaws</li>"
            echo "            <li>Consider taking affected systems offline until patched</li>"
        fi
        
        if [[ $high_count -gt 0 ]]; then
            echo "            <li><strong>🟠 HIGH PRIORITY:</strong> Remediate high-severity vulnerabilities within 48 hours</li>"
            echo "            <li>Review and update security configurations</li>"
        fi
    fi
    
    cat << EOF
            <li>Update all software components to latest versions</li>
            <li>Review and strengthen access controls</li>
            <li>Implement network segmentation where possible</li>
            <li>Enable comprehensive logging and monitoring</li>
        </ul>
        
        <h3>Long-term Security Improvements</h3>
        <ul>
            <li>Establish regular vulnerability scanning schedule</li>
            <li>Implement security awareness training</li>
            <li>Develop incident response procedures</li>
            <li>Consider implementing Web Application Firewall (WAF)</li>
            <li>Regular security audits and penetration testing</li>
        </ul>
        
        <h3>Compliance Considerations</h3>
        <ul>
            <li>Review findings against applicable compliance frameworks</li>
            <li>Document remediation efforts for audit purposes</li>
            <li>Implement continuous compliance monitoring</li>
        </ul>
    </div>
EOF
}

generate_html_appendix() {
    local session_dir="$1"
    
    cat << EOF
    <div class="section">
        <h2>📋 Appendix</h2>
        
        <h3>Scan Configuration</h3>
        <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td>Scan Type</td><td>Comprehensive Security Assessment</td></tr>
            <tr><td>Tools Used</td><td>nmap, nikto, sqlmap, gobuster, custom CVE scanners</td></tr>
            <tr><td>Scan Duration</td><td>$(get_scan_duration "$session_dir")</td></tr>
        </table>
        
        <h3>Methodology</h3>
        <p>This assessment followed industry-standard penetration testing methodologies:</p>
        <ol>
            <li><strong>Reconnaissance:</strong> Information gathering and target enumeration</li>
            <li><strong>Scanning:</strong> Port scanning and service identification</li>
            <li><strong>Vulnerability Assessment:</strong> Automated and manual vulnerability detection</li>
            <li><strong>CVE Analysis:</strong> Testing for recent and critical CVEs</li>
            <li><strong>Reporting:</strong> Documentation of findings and recommendations</li>
        </ol>
        
        <h3>Disclaimer</h3>
        <p><em>This report is based on automated scanning tools and may not identify all potential security issues. 
        Manual verification and additional testing may be required for comprehensive security assessment. 
        The findings should be validated in a controlled environment before implementing remediation measures.</em></p>
    </div>
EOF
}

get_scan_duration() {
    local session_dir="$1"
    
    if [[ -f "$session_dir/session.log" ]]; then
        local start_time=$(grep "Start Time:" "$session_dir/session.log" | head -1 | cut -d: -f2- | xargs)
        local end_time=$(grep "Session completed\|ended" "$session_dir/session.log" | tail -1 | awk '{print $1, $2}' | tr -d '[]')
        
        if [[ -n "$start_time" && -n "$end_time" ]]; then
            echo "Started: $start_time, Completed: $end_time"
        else
            echo "In Progress"
        fi
    else
        echo "Unknown"
    fi
}

# ============================================================================
# Text Report Generation
# ============================================================================

generate_text_report() {
    local session_id="$1"
    local target="$2"
    local report_type="${3:-full}"
    
    local session_dir="$LOG_DIR/$session_id"
    local report_file="$session_dir/report_${report_type}_$(date +%Y%m%d_%H%M%S).txt"
    
    if [[ ! -d "$session_dir" ]]; then
        print_error "Session directory not found: $session_dir"
        return 1
    fi
    
    print_info "Generating text report..."
    
    # Generate text report
    cat > "$report_file" << EOF
================================================================================
                    CVEHACK SECURITY ASSESSMENT REPORT
================================================================================

Target: $target
Session ID: $session_id
Assessment Date: $(date)
Report Type: $report_type

================================================================================
EXECUTIVE SUMMARY
================================================================================

$(generate_text_summary "$session_dir")

================================================================================
SCAN RESULTS
================================================================================

$(generate_text_scan_results "$session_dir")

================================================================================
VULNERABILITIES
================================================================================

$(generate_text_vulnerabilities "$session_dir")

================================================================================
RECOMMENDATIONS
================================================================================

$(generate_text_recommendations "$session_dir")

================================================================================
TECHNICAL DETAILS
================================================================================

$(generate_text_technical_details "$session_dir")

================================================================================
REPORT INFORMATION
================================================================================

Generated: $(date)
Tool: CVEHACK v1.0
Session ID: $session_id
Report File: $report_file

================================================================================
EOF
    
    print_success "Text report generated: $report_file"
    log_info "Text report generated: $report_file"
    
    echo "$report_file"
}

generate_text_summary() {
    local session_dir="$1"
    
    local total_vulns=0
    local critical_vulns=0
    local high_vulns=0
    local medium_vulns=0
    local low_vulns=0
    
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        total_vulns=$(grep -c "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null || echo "0")
        critical_vulns=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: CRITICAL" || echo "0")
        high_vulns=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: HIGH" || echo "0")
        medium_vulns=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: MEDIUM" || echo "0")
        low_vulns=$(grep -A 5 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | grep -c "Severity: LOW" || echo "0")
    fi
    
    cat << EOF
Total Vulnerabilities Found: $total_vulns
  - Critical: $critical_vulns
  - High: $high_vulns
  - Medium: $medium_vulns
  - Low: $low_vulns

Risk Level: $(generate_text_risk_level $critical_vulns $high_vulns $medium_vulns $low_vulns)
EOF
}

generate_text_risk_level() {
    local critical=$1
    local high=$2
    local medium=$3
    local low=$4
    
    if [[ $critical -gt 0 ]]; then
        echo "CRITICAL - Immediate action required"
    elif [[ $high -gt 3 ]]; then
        echo "HIGH - Multiple high-severity issues detected"
    elif [[ $high -gt 0 ]]; then
        echo "MODERATE - High-severity issues detected"
    elif [[ $medium -gt 5 ]]; then
        echo "MODERATE - Multiple medium-severity issues"
    elif [[ $medium -gt 0 || $low -gt 0 ]]; then
        echo "LOW - Minor issues detected"
    else
        echo "MINIMAL - No significant issues detected"
    fi
}

generate_text_scan_results() {
    local session_dir="$1"
    
    if [[ -f "$session_dir/scan.log" ]]; then
        echo "Port Scan Results:"
        echo "=================="
        grep -E "open|closed|filtered" "$session_dir/scan.log" 2>/dev/null | head -20
        echo ""
        
        echo "Service Detection:"
        echo "=================="
        grep -A 5 -B 2 "service\|version" "$session_dir/scan.log" 2>/dev/null | head -20
        echo ""
    else
        echo "No scan results available."
    fi
}

generate_text_vulnerabilities() {
    local session_dir="$1"
    
    if [[ -f "$session_dir/vulnerabilities.log" ]]; then
        local vuln_count=$(grep -c "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log")
        
        if [[ $vuln_count -gt 0 ]]; then
            echo "Detailed Vulnerability List:"
            echo "============================"
            echo ""
            
            awk '/VULNERABILITY FOUND/,/^$/' "$session_dir/vulnerabilities.log" | \
            sed 's/================================================================================//g' | \
            sed '/^$/d'
        else
            echo "No vulnerabilities detected."
        fi
    else
        echo "No vulnerability data available."
    fi
}

generate_text_recommendations() {
    local session_dir="$1"
    
    cat << EOF
Immediate Actions:
==================
1. Patch all critical and high-severity vulnerabilities
2. Update software components to latest versions
3. Review and strengthen access controls
4. Implement network segmentation
5. Enable comprehensive logging

Long-term Improvements:
======================
1. Establish regular vulnerability scanning
2. Implement security awareness training
3. Develop incident response procedures
4. Consider Web Application Firewall (WAF)
5. Regular security audits

Compliance:
===========
1. Review findings against compliance frameworks
2. Document remediation efforts
3. Implement continuous monitoring
EOF
}

generate_text_technical_details() {
    local session_dir="$1"
    
    echo "Scan Configuration:"
    echo "==================="
    echo "Tools Used: nmap, nikto, sqlmap, gobuster, custom CVE scanners"
    echo "Scan Duration: $(get_scan_duration "$session_dir")"
    echo ""
    
    echo "Files Generated:"
    echo "================"
    if [[ -d "$session_dir" ]]; then
        find "$session_dir" -type f -name "*.log" -o -name "*.txt" -o -name "*.json" | \
        while read -r file; do
            echo "- $(basename "$file")"
        done
    fi
}

# ============================================================================
# Quick Report Generation
# ============================================================================

generate_quick_report() {
    local target="$1"
    local session_id="$2"
    
    local session_dir="$LOG_DIR/$session_id"
    local report_file="$session_dir/quick_report_$(date +%Y%m%d_%H%M%S).txt"
    
    print_info "Generating quick report..."
    
    cat > "$report_file" << EOF
================================================================================
                         CVEHACK QUICK SCAN REPORT
================================================================================

Target: $target
Session: $session_id
Date: $(date)

SUMMARY:
$(generate_text_summary "$session_dir")

OPEN PORTS:
$(grep -E "open" "$session_dir/scan.log" 2>/dev/null | head -10 || echo "No open ports detected")

VULNERABILITIES:
$(grep -A 3 "VULNERABILITY FOUND" "$session_dir/vulnerabilities.log" 2>/dev/null | head -20 || echo "No vulnerabilities detected")

================================================================================
EOF
    
    print_success "Quick report generated: $report_file"
    echo "$report_file"
}

generate_full_report() {
    local target="$1"
    local session_id="$2"
    
    print_info "Generating comprehensive reports..."
    
    # Generate both HTML and text reports
    local html_report=$(generate_html_report "$session_id" "$target" "full")
    local text_report=$(generate_text_report "$session_id" "$target" "full")
    
    print_success "Full reports generated:"
    print_info "HTML: $html_report"
    print_info "Text: $text_report"
    
    # Open HTML report if possible
    if command -v open &> /dev/null; then
        print_info "Opening HTML report..."
        open "$html_report" 2>/dev/null &
    fi
}

generate_session_report() {
    local session_id="$1"
    
    local session_dir="$LOG_DIR/$session_id"
    
    if [[ ! -d "$session_dir" ]]; then
        print_error "Session not found: $session_id"
        return 1
    fi
    
    print_info "Generating final session report..."
    
    # Determine target from logs
    local target=$(grep "Target:" "$session_dir/session.log" 2>/dev/null | head -1 | cut -d: -f2- | xargs)
    target=${target:-"Unknown"}
    
    # Generate comprehensive report
    generate_full_report "$target" "$session_id"
    
    # Generate session summary
    local summary_file="$session_dir/session_summary.txt"
    cat > "$summary_file" << EOF
================================================================================
                        CVEHACK SESSION SUMMARY
================================================================================

Session ID: $session_id
Target: $target
$(get_session_stats "$session_id")

Files Generated:
$(find "$session_dir" -type f | wc -l) total files

Report Files:
$(find "$session_dir" -name "report_*.html" -o -name "report_*.txt" | while read -r file; do echo "- $(basename "$file")"; done)

================================================================================
EOF
    
    print_success "Session report completed: $summary_file"
}

# ============================================================================
# Report Menu System
# ============================================================================

show_report_menu() {
    local session_id="$1"
    
    clear_screen
    section_header "Report Management"
    
    echo -e "${YELLOW}1.${NC} Generate HTML Report"
    echo -e "${YELLOW}2.${NC} Generate Text Report"
    echo -e "${YELLOW}3.${NC} Generate Quick Report"
    echo -e "${YELLOW}4.${NC} View Session Summary"
    echo -e "${YELLOW}5.${NC} List All Reports"
    echo -e "${YELLOW}6.${NC} Export Session Data"
    echo -e "${YELLOW}7.${NC} Open Report in Browser"
    echo -e "${YELLOW}0.${NC} Back to Main Menu"
    echo ""
    echo -e "${BLUE}Select option: ${NC}"
    read -r report_choice
    
    case $report_choice in
        1) 
            echo -e "${YELLOW}Enter target: ${NC}"
            read -r target
            generate_html_report "$session_id" "$target"
            ;;
        2) 
            echo -e "${YELLOW}Enter target: ${NC}"
            read -r target
            generate_text_report "$session_id" "$target"
            ;;
        3) 
            echo -e "${YELLOW}Enter target: ${NC}"
            read -r target
            generate_quick_report "$target" "$session_id"
            ;;
        4) 
            get_session_stats "$session_id"
            ;;
        5) 
            list_session_reports "$session_id"
            ;;
        6) 
            export_session_data "$session_id"
            ;;
        7) 
            open_latest_report "$session_id"
            ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
    
    echo ""
    print_info "Press Enter to continue..."
    read -r
}

list_session_reports() {
    local session_id="$1"
    local session_dir="$LOG_DIR/$session_id"
    
    if [[ -d "$session_dir" ]]; then
        print_info "Reports for session $session_id:"
        find "$session_dir" -name "report_*.html" -o -name "report_*.txt" -o -name "*_report_*.txt" | \
        while read -r file; do
            local size=$(ls -lh "$file" | awk '{print $5}')
            local date=$(ls -l "$file" | awk '{print $6, $7, $8}')
            print_info "$(basename "$file") ($size) - $date"
        done
    else
        print_error "Session directory not found"
    fi
}

open_latest_report() {
    local session_id="$1"
    local session_dir="$LOG_DIR/$session_id"
    
    if [[ -d "$session_dir" ]]; then
        local latest_html=$(find "$session_dir" -name "report_*.html" | sort | tail -1)
        
        if [[ -n "$latest_html" ]] && command -v open &> /dev/null; then
            print_info "Opening latest HTML report..."
            open "$latest_html"
        else
            print_error "No HTML reports found or 'open' command not available"
        fi
    else
        print_error "Session directory not found"
    fi
}
