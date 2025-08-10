#!/bin/bash

# ============================================================================
# CVEHACK Demo Script
# ============================================================================

echo "🚀 CVEHACK - Elite Cybersecurity & Pentesting Suite Demo"
echo "========================================================"
echo ""

# Check if we're in the right directory
if [[ ! -f "pentest.sh" ]]; then
    echo "❌ Error: Please run this demo from the CVEHACK directory"
    exit 1
fi

echo "📋 System Check:"
echo "- Operating System: $(uname -s)"
echo "- Architecture: $(uname -m)"
echo "- Shell: $SHELL"
echo "- Current Directory: $(pwd)"
echo ""

echo "🔍 File Structure Check:"
echo "- Main Script: $(ls -la pentest.sh | awk '{print $1, $9}')"
echo "- Libraries: $(ls lib/ | wc -l) files"
echo "- Modules: $(ls modules/ | wc -l) files"
echo "- CVE System: $(ls cve/ | wc -l) files"
echo ""

echo "🧪 Library Loading Test:"
source lib/colors.sh && echo "✅ Colors library loaded"
source lib/logger.sh && echo "✅ Logger library loaded"
source lib/installer.sh && echo "✅ Installer library loaded"
source lib/cve_fetcher.sh && echo "✅ CVE fetcher library loaded"
source lib/report_generator.sh && echo "✅ Report generator library loaded"
echo ""

echo "📦 Module Loading Test:"
source modules/recon.sh && echo "✅ Reconnaissance module loaded"
source modules/web_scan.sh && echo "✅ Web scan module loaded"
source modules/exploit.sh && echo "✅ Exploit module loaded"
source modules/brute_force.sh && echo "✅ Brute force module loaded"
echo ""

echo "🆕 CVE System Test:"
source cve/cve_manager.sh && echo "✅ CVE manager loaded"
source cve/generators/web_cve_generator.sh && echo "✅ CVE generator loaded"
echo ""

echo "🛠️ Tool Availability Check:"
tools_to_check="curl wget jq git python3 go"
for tool in $tools_to_check; do
    if command -v "$tool" &> /dev/null; then
        echo "✅ $tool: $(which $tool)"
    else
        echo "❌ $tool: Not found (will be installed automatically)"
    fi
done
echo ""

echo "📊 Demo Complete!"
echo ""
echo "🎯 To start CVEHACK:"
echo "   ./pentest.sh"
echo ""
echo "📚 For help and documentation:"
echo "   cat README.md"
echo ""
echo "⚠️  Remember: Only use on systems you own or have permission to test!"
echo ""
