#!/bin/bash

# ============================================================================
# Advanced Reporting and Analytics Engine for CVEHACK
# ============================================================================

# Configuration
REPORTS_DIR="./reports"
TEMPLATES_DIR="$REPORTS_DIR/templates"
ASSETS_DIR="$REPORTS_DIR/assets"
ANALYTICS_DIR="$REPORTS_DIR/analytics"

# Report types
REPORT_FORMATS=("html" "pdf" "json" "xml" "csv")
DASHBOARD_THEMES=("dark" "light" "corporate" "hacker")

# Initialize advanced reporting
init_advanced_reporting() {
    mkdir -p "$REPORTS_DIR" "$TEMPLATES_DIR" "$ASSETS_DIR" "$ANALYTICS_DIR"
    
    print_info "Initializing Advanced Reporting Engine..."
    
    create_html_templates
    create_css_assets
    create_javascript_assets
    create_report_schemas
    
    print_success "Advanced reporting engine initialized"
}

# ============================================================================
# HTML Template Generation
# ============================================================================

create_html_templates() {
    print_info "Creating HTML report templates..."
    
    # Executive Dashboard Template
    create_executive_dashboard_template
    
    # Technical Report Template
    create_technical_report_template
    
    # Vulnerability Assessment Template
    create_vulnerability_assessment_template
    
    # Compliance Report Template
    create_compliance_report_template
    
    print_success "HTML templates created"
}

create_executive_dashboard_template() {
    local template_file="$TEMPLATES_DIR/executive_dashboard.html"
    
    cat > "$template_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVEHACK Executive Security Dashboard</title>
    <link rel="stylesheet" href="../assets/dashboard.css">
    <script src="../assets/chart.min.js"></script>
    <script src="../assets/dashboard.js"></script>
</head>
<body class="{{THEME}}">
    <div class="dashboard-container">
        <!-- Header -->
        <header class="dashboard-header">
            <div class="header-content">
                <div class="logo">
                    <h1>🛡️ CVEHACK</h1>
                    <span class="subtitle">Executive Security Dashboard</span>
                </div>
                <div class="scan-info">
                    <div class="info-item">
                        <span class="label">Target:</span>
                        <span class="value">{{TARGET}}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Scan Date:</span>
                        <span class="value">{{SCAN_DATE}}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Duration:</span>
                        <span class="value">{{SCAN_DURATION}}</span>
                    </div>
                </div>
            </div>
        </header>

        <!-- Executive Summary -->
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card critical">
                    <div class="card-icon">🚨</div>
                    <div class="card-content">
                        <h3>{{CRITICAL_COUNT}}</h3>
                        <p>Critical Vulnerabilities</p>
                    </div>
                </div>
                <div class="summary-card high">
                    <div class="card-icon">⚠️</div>
                    <div class="card-content">
                        <h3>{{HIGH_COUNT}}</h3>
                        <p>High Risk Issues</p>
                    </div>
                </div>
                <div class="summary-card medium">
                    <div class="card-icon">⚡</div>
                    <div class="card-content">
                        <h3>{{MEDIUM_COUNT}}</h3>
                        <p>Medium Risk Issues</p>
                    </div>
                </div>
                <div class="summary-card info">
                    <div class="card-icon">ℹ️</div>
                    <div class="card-content">
                        <h3>{{INFO_COUNT}}</h3>
                        <p>Informational</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Risk Assessment -->
        <section class="risk-assessment">
            <div class="section-grid">
                <div class="chart-container">
                    <h3>Risk Distribution</h3>
                    <canvas id="riskChart"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Vulnerability Categories</h3>
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
        </section>

        <!-- Top Vulnerabilities -->
        <section class="top-vulnerabilities">
            <h2>Top Priority Vulnerabilities</h2>
            <div class="vulnerability-list">
                {{TOP_VULNERABILITIES}}
            </div>
        </section>

        <!-- Compliance Status -->
        <section class="compliance-status">
            <h2>Compliance Overview</h2>
            <div class="compliance-grid">
                <div class="compliance-item">
                    <h4>OWASP Top 10</h4>
                    <div class="compliance-bar">
                        <div class="progress" style="width: {{OWASP_COMPLIANCE}}%"></div>
                    </div>
                    <span class="percentage">{{OWASP_COMPLIANCE}}%</span>
                </div>
                <div class="compliance-item">
                    <h4>NIST Framework</h4>
                    <div class="compliance-bar">
                        <div class="progress" style="width: {{NIST_COMPLIANCE}}%"></div>
                    </div>
                    <span class="percentage">{{NIST_COMPLIANCE}}%</span>
                </div>
                <div class="compliance-item">
                    <h4>ISO 27001</h4>
                    <div class="compliance-bar">
                        <div class="progress" style="width: {{ISO_COMPLIANCE}}%"></div>
                    </div>
                    <span class="percentage">{{ISO_COMPLIANCE}}%</span>
                </div>
            </div>
        </section>

        <!-- Recommendations -->
        <section class="recommendations">
            <h2>Strategic Recommendations</h2>
            <div class="recommendation-list">
                {{RECOMMENDATIONS}}
            </div>
        </section>

        <!-- Footer -->
        <footer class="dashboard-footer">
            <p>Generated by CVEHACK v1.0 | {{GENERATION_TIME}}</p>
        </footer>
    </div>

    <script>
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            initializeInteractivity();
        });
    </script>
</body>
</html>
EOF
}

create_technical_report_template() {
    local template_file="$TEMPLATES_DIR/technical_report.html"
    
    cat > "$template_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVEHACK Technical Security Report</title>
    <link rel="stylesheet" href="../assets/technical.css">
    <script src="../assets/prism.js"></script>
    <script src="../assets/technical.js"></script>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <header class="report-header">
            <h1>🔧 Technical Security Assessment Report</h1>
            <div class="report-meta">
                <table>
                    <tr><td>Target System:</td><td>{{TARGET}}</td></tr>
                    <tr><td>Assessment Date:</td><td>{{SCAN_DATE}}</td></tr>
                    <tr><td>Assessor:</td><td>CVEHACK Automated Scanner</td></tr>
                    <tr><td>Report Version:</td><td>{{REPORT_VERSION}}</td></tr>
                </table>
            </div>
        </header>

        <!-- Table of Contents -->
        <nav class="toc">
            <h2>Table of Contents</h2>
            <ul>
                <li><a href="#methodology">1. Methodology</a></li>
                <li><a href="#scope">2. Scope and Limitations</a></li>
                <li><a href="#findings">3. Technical Findings</a></li>
                <li><a href="#vulnerabilities">4. Vulnerability Details</a></li>
                <li><a href="#evidence">5. Evidence and Proof of Concept</a></li>
                <li><a href="#remediation">6. Remediation Guidelines</a></li>
                <li><a href="#appendix">7. Appendix</a></li>
            </ul>
        </nav>

        <!-- Methodology -->
        <section id="methodology" class="report-section">
            <h2>1. Assessment Methodology</h2>
            <div class="methodology-content">
                <h3>Scanning Approach</h3>
                <p>This assessment utilized the CVEHACK automated security testing framework, employing:</p>
                <ul>
                    <li>Network reconnaissance and service enumeration</li>
                    <li>Web application security testing</li>
                    <li>CVE-based vulnerability assessment</li>
                    <li>Configuration security analysis</li>
                </ul>
                
                <h3>Tools and Techniques</h3>
                <div class="tools-grid">
                    {{TOOLS_USED}}
                </div>
            </div>
        </section>

        <!-- Scope -->
        <section id="scope" class="report-section">
            <h2>2. Scope and Limitations</h2>
            <div class="scope-content">
                <h3>Assessment Scope</h3>
                <ul>
                    <li>Target: {{TARGET}}</li>
                    <li>IP Range: {{IP_RANGE}}</li>
                    <li>Services Tested: {{SERVICES_TESTED}}</li>
                    <li>Assessment Type: {{ASSESSMENT_TYPE}}</li>
                </ul>
                
                <h3>Limitations</h3>
                <ul>
                    <li>Automated scanning only - no manual verification</li>
                    <li>Point-in-time assessment</li>
                    <li>Limited to externally accessible services</li>
                    <li>No social engineering or physical security testing</li>
                </ul>
            </div>
        </section>

        <!-- Technical Findings -->
        <section id="findings" class="report-section">
            <h2>3. Technical Findings Summary</h2>
            <div class="findings-summary">
                <div class="finding-stats">
                    <div class="stat-item critical">
                        <span class="count">{{CRITICAL_COUNT}}</span>
                        <span class="label">Critical</span>
                    </div>
                    <div class="stat-item high">
                        <span class="count">{{HIGH_COUNT}}</span>
                        <span class="label">High</span>
                    </div>
                    <div class="stat-item medium">
                        <span class="count">{{MEDIUM_COUNT}}</span>
                        <span class="label">Medium</span>
                    </div>
                    <div class="stat-item low">
                        <span class="count">{{LOW_COUNT}}</span>
                        <span class="label">Low</span>
                    </div>
                </div>
                
                <div class="services-discovered">
                    <h3>Services Discovered</h3>
                    <table class="services-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Version</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{SERVICES_TABLE}}
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Vulnerability Details -->
        <section id="vulnerabilities" class="report-section">
            <h2>4. Detailed Vulnerability Analysis</h2>
            <div class="vulnerabilities-content">
                {{VULNERABILITY_DETAILS}}
            </div>
        </section>

        <!-- Evidence -->
        <section id="evidence" class="report-section">
            <h2>5. Evidence and Proof of Concept</h2>
            <div class="evidence-content">
                {{EVIDENCE_SECTION}}
            </div>
        </section>

        <!-- Remediation -->
        <section id="remediation" class="report-section">
            <h2>6. Remediation Guidelines</h2>
            <div class="remediation-content">
                {{REMEDIATION_GUIDELINES}}
            </div>
        </section>

        <!-- Appendix -->
        <section id="appendix" class="report-section">
            <h2>7. Appendix</h2>
            <div class="appendix-content">
                <h3>Raw Scan Data</h3>
                <pre><code class="language-bash">{{RAW_SCAN_DATA}}</code></pre>
                
                <h3>CVE References</h3>
                <div class="cve-references">
                    {{CVE_REFERENCES}}
                </div>
            </div>
        </section>
    </div>
</body>
</html>
EOF
}

# ============================================================================
# CSS Assets Creation
# ============================================================================

create_css_assets() {
    print_info "Creating CSS assets..."
    
    # Dashboard CSS
    cat > "$ASSETS_DIR/dashboard.css" << 'EOF'
/* CVEHACK Dashboard Styles */
:root {
    --primary-color: #2c3e50;
    --secondary-color: #3498db;
    --success-color: #27ae60;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
    --info-color: #8e44ad;
    --light-bg: #ecf0f1;
    --dark-bg: #34495e;
    --text-color: #2c3e50;
    --border-color: #bdc3c7;
}

.dark {
    --primary-color: #1a1a1a;
    --secondary-color: #0066cc;
    --light-bg: #2d2d2d;
    --dark-bg: #1a1a1a;
    --text-color: #ffffff;
    --border-color: #444444;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: var(--light-bg);
    color: var(--text-color);
    line-height: 1.6;
}

.dashboard-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* Header Styles */
.dashboard-header {
    background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
    color: white;
    padding: 30px;
    border-radius: 10px;
    margin-bottom: 30px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
}

.logo h1 {
    font-size: 2.5em;
    margin-bottom: 5px;
}

.subtitle {
    font-size: 1.2em;
    opacity: 0.9;
}

.scan-info {
    display: flex;
    gap: 30px;
    flex-wrap: wrap;
}

.info-item {
    display: flex;
    flex-direction: column;
    align-items: center;
}

.info-item .label {
    font-size: 0.9em;
    opacity: 0.8;
}

.info-item .value {
    font-size: 1.1em;
    font-weight: bold;
}

/* Summary Cards */
.executive-summary {
    margin-bottom: 40px;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.summary-card {
    background: white;
    padding: 25px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
    gap: 20px;
    transition: transform 0.3s ease;
}

.summary-card:hover {
    transform: translateY(-5px);
}

.summary-card.critical {
    border-left: 5px solid var(--danger-color);
}

.summary-card.high {
    border-left: 5px solid var(--warning-color);
}

.summary-card.medium {
    border-left: 5px solid var(--info-color);
}

.summary-card.info {
    border-left: 5px solid var(--success-color);
}

.card-icon {
    font-size: 2.5em;
}

.card-content h3 {
    font-size: 2em;
    margin-bottom: 5px;
}

.card-content p {
    color: #666;
    font-size: 1.1em;
}

/* Charts */
.risk-assessment {
    margin-bottom: 40px;
}

.section-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 30px;
    margin-top: 20px;
}

.chart-container {
    background: white;
    padding: 25px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.chart-container h3 {
    margin-bottom: 20px;
    text-align: center;
}

/* Vulnerability List */
.vulnerability-list {
    background: white;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    overflow: hidden;
}

.vulnerability-item {
    padding: 20px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.vulnerability-item:last-child {
    border-bottom: none;
}

.vuln-info h4 {
    margin-bottom: 5px;
}

.vuln-info p {
    color: #666;
    font-size: 0.9em;
}

.severity-badge {
    padding: 5px 15px;
    border-radius: 20px;
    color: white;
    font-weight: bold;
    font-size: 0.8em;
}

.severity-critical { background-color: var(--danger-color); }
.severity-high { background-color: var(--warning-color); }
.severity-medium { background-color: var(--info-color); }
.severity-low { background-color: var(--success-color); }

/* Compliance */
.compliance-grid {
    display: grid;
    gap: 20px;
    margin-top: 20px;
}

.compliance-item {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
    gap: 20px;
}

.compliance-item h4 {
    min-width: 150px;
}

.compliance-bar {
    flex: 1;
    height: 20px;
    background-color: #ecf0f1;
    border-radius: 10px;
    overflow: hidden;
}

.compliance-bar .progress {
    height: 100%;
    background: linear-gradient(90deg, var(--danger-color), var(--warning-color), var(--success-color));
    transition: width 0.5s ease;
}

.percentage {
    font-weight: bold;
    min-width: 50px;
    text-align: right;
}

/* Recommendations */
.recommendation-list {
    background: white;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    padding: 25px;
}

.recommendation-item {
    margin-bottom: 20px;
    padding: 15px;
    background: var(--light-bg);
    border-radius: 5px;
    border-left: 4px solid var(--secondary-color);
}

.recommendation-item:last-child {
    margin-bottom: 0;
}

.recommendation-item h4 {
    margin-bottom: 10px;
    color: var(--secondary-color);
}

/* Footer */
.dashboard-footer {
    text-align: center;
    margin-top: 40px;
    padding: 20px;
    color: #666;
    border-top: 1px solid var(--border-color);
}

/* Responsive Design */
@media (max-width: 768px) {
    .header-content {
        flex-direction: column;
        text-align: center;
        gap: 20px;
    }
    
    .scan-info {
        justify-content: center;
    }
    
    .summary-grid {
        grid-template-columns: 1fr;
    }
    
    .section-grid {
        grid-template-columns: 1fr;
    }
}
EOF

    # Technical Report CSS
    cat > "$ASSETS_DIR/technical.css" << 'EOF'
/* CVEHACK Technical Report Styles */
:root {
    --primary-color: #2c3e50;
    --secondary-color: #3498db;
    --success-color: #27ae60;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
    --info-color: #8e44ad;
    --light-bg: #ffffff;
    --dark-bg: #f8f9fa;
    --text-color: #2c3e50;
    --border-color: #dee2e6;
    --code-bg: #f8f9fa;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Georgia', 'Times New Roman', serif;
    background-color: var(--light-bg);
    color: var(--text-color);
    line-height: 1.8;
    font-size: 14px;
}

.report-container {
    max-width: 900px;
    margin: 0 auto;
    padding: 40px;
    background: white;
    box-shadow: 0 0 20px rgba(0,0,0,0.1);
}

/* Header */
.report-header {
    text-align: center;
    margin-bottom: 40px;
    padding-bottom: 30px;
    border-bottom: 3px solid var(--primary-color);
}

.report-header h1 {
    font-size: 2.5em;
    color: var(--primary-color);
    margin-bottom: 20px;
}

.report-meta table {
    margin: 0 auto;
    border-collapse: collapse;
}

.report-meta td {
    padding: 8px 20px;
    border-bottom: 1px solid var(--border-color);
}

.report-meta td:first-child {
    font-weight: bold;
    text-align: right;
}

/* Table of Contents */
.toc {
    background: var(--dark-bg);
    padding: 25px;
    border-radius: 5px;
    margin-bottom: 40px;
}

.toc h2 {
    margin-bottom: 15px;
    color: var(--primary-color);
}

.toc ul {
    list-style: none;
}

.toc li {
    margin-bottom: 8px;
}

.toc a {
    color: var(--secondary-color);
    text-decoration: none;
    font-weight: 500;
}

.toc a:hover {
    text-decoration: underline;
}

/* Report Sections */
.report-section {
    margin-bottom: 50px;
    page-break-inside: avoid;
}

.report-section h2 {
    color: var(--primary-color);
    font-size: 1.8em;
    margin-bottom: 25px;
    padding-bottom: 10px;
    border-bottom: 2px solid var(--secondary-color);
}

.report-section h3 {
    color: var(--secondary-color);
    font-size: 1.4em;
    margin: 25px 0 15px 0;
}

.report-section h4 {
    color: var(--text-color);
    font-size: 1.2em;
    margin: 20px 0 10px 0;
}

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
    font-size: 0.9em;
}

th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}

th {
    background-color: var(--dark-bg);
    font-weight: bold;
    color: var(--primary-color);
}

tr:hover {
    background-color: var(--dark-bg);
}

/* Code Blocks */
pre {
    background: var(--code-bg);
    border: 1px solid var(--border-color);
    border-radius: 5px;
    padding: 20px;
    overflow-x: auto;
    margin: 20px 0;
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
    line-height: 1.4;
}

code {
    background: var(--code-bg);
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
}

/* Vulnerability Cards */
.vulnerability-card {
    border: 1px solid var(--border-color);
    border-radius: 8px;
    margin: 20px 0;
    overflow: hidden;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.vulnerability-header {
    padding: 15px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.vulnerability-header.critical {
    background-color: var(--danger-color);
    color: white;
}

.vulnerability-header.high {
    background-color: var(--warning-color);
    color: white;
}

.vulnerability-header.medium {
    background-color: var(--info-color);
    color: white;
}

.vulnerability-header.low {
    background-color: var(--success-color);
    color: white;
}

.vulnerability-body {
    padding: 20px;
}

.vulnerability-details {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
}

.detail-item {
    display: flex;
    flex-direction: column;
}

.detail-label {
    font-weight: bold;
    color: var(--secondary-color);
    margin-bottom: 5px;
}

.detail-value {
    color: var(--text-color);
}

/* Evidence Sections */
.evidence-item {
    background: var(--dark-bg);
    border-left: 4px solid var(--secondary-color);
    padding: 20px;
    margin: 20px 0;
    border-radius: 0 5px 5px 0;
}

.evidence-item h4 {
    color: var(--secondary-color);
    margin-bottom: 15px;
}

/* Remediation */
.remediation-priority {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 15px;
    font-size: 0.8em;
    font-weight: bold;
    color: white;
    margin-bottom: 10px;
}

.priority-immediate {
    background-color: var(--danger-color);
}

.priority-high {
    background-color: var(--warning-color);
}

.priority-medium {
    background-color: var(--info-color);
}

.priority-low {
    background-color: var(--success-color);
}

/* Statistics */
.finding-stats {
    display: flex;
    justify-content: space-around;
    margin: 30px 0;
    text-align: center;
}

.stat-item {
    padding: 20px;
    border-radius: 8px;
    min-width: 100px;
}

.stat-item.critical {
    background-color: rgba(231, 76, 60, 0.1);
    border: 2px solid var(--danger-color);
}

.stat-item.high {
    background-color: rgba(243, 156, 18, 0.1);
    border: 2px solid var(--warning-color);
}

.stat-item.medium {
    background-color: rgba(142, 68, 173, 0.1);
    border: 2px solid var(--info-color);
}

.stat-item.low {
    background-color: rgba(39, 174, 96, 0.1);
    border: 2px solid var(--success-color);
}

.stat-item .count {
    display: block;
    font-size: 2.5em;
    font-weight: bold;
    margin-bottom: 5px;
}

.stat-item .label {
    font-size: 1.1em;
    font-weight: 500;
}

/* Print Styles */
@media print {
    body {
        font-size: 12px;
    }
    
    .report-container {
        box-shadow: none;
        padding: 20px;
    }
    
    .report-section {
        page-break-inside: avoid;
    }
    
    .vulnerability-card {
        page-break-inside: avoid;
    }
}

/* Responsive Design */
@media (max-width: 768px) {
    .report-container {
        padding:
