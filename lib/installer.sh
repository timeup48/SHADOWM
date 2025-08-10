#!/bin/bash

# ============================================================================
# Tool Installation and Management Library for CVEHACK
# ============================================================================

# Required tools configuration
REQUIRED_TOOLS="nmap masscan nikto sqlmap gobuster hydra theharvester sslscan subfinder amass curl wget jq python3 go git"

# Python tools that need pip installation
PYTHON_TOOLS="dirsearch sublist3r shodan"

# Go tools that need go install
GO_TOOLS_HTTPX="github.com/projectdiscovery/httpx/v2/cmd/httpx@latest"
GO_TOOLS_NUCLEI="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
GO_TOOLS_KATANA="github.com/projectdiscovery/katana/cmd/katana@latest"

# ============================================================================
# Installation Functions
# ============================================================================

check_homebrew() {
    if ! command -v brew &> /dev/null; then
        print_error "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH for Apple Silicon Macs
        if [[ -f "/opt/homebrew/bin/brew" ]]; then
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
        
        if command -v brew &> /dev/null; then
            print_success "Homebrew installed successfully"
        else
            print_error "Failed to install Homebrew"
            return 1
        fi
    else
        print_success "Homebrew is already installed"
    fi
    return 0
}

install_homebrew_tool() {
    local tool="$1"
    
    # Check if tool is in our required tools list
    if ! echo "$REQUIRED_TOOLS" | grep -q "$tool"; then
        print_error "Unknown tool: $tool"
        return 1
    fi
    
    print_info "Installing $tool via Homebrew..."
    
    if brew install "$tool" 2>/dev/null; then
        print_success "$tool installed successfully"
        return 0
    else
        print_warning "Failed to install $tool via brew, trying alternative methods..."
        
        # Try installing from different taps
        case "$tool" in
            "masscan")
                brew install masscan 2>/dev/null || {
                    print_info "Installing masscan from source..."
                    install_masscan_from_source
                }
                ;;
            "wpscan")
                gem install wpscan 2>/dev/null || {
                    print_error "Failed to install wpscan"
                    return 1
                }
                ;;
            "theharvester")
                pip3 install theHarvester 2>/dev/null || {
                    print_error "Failed to install theHarvester"
                    return 1
                }
                ;;
            *)
                print_error "Failed to install $tool"
                return 1
                ;;
        esac
    fi
}

install_masscan_from_source() {
    local temp_dir=$(mktemp -d)
    cd "$temp_dir" || return 1
    
    print_info "Cloning masscan repository..."
    git clone https://github.com/robertdavidgraham/masscan.git
    cd masscan || return 1
    
    print_info "Compiling masscan..."
    make -j4
    
    if [[ -f "bin/masscan" ]]; then
        sudo cp bin/masscan /usr/local/bin/
        print_success "masscan installed from source"
        cd - > /dev/null
        rm -rf "$temp_dir"
        return 0
    else
        print_error "Failed to compile masscan"
        cd - > /dev/null
        rm -rf "$temp_dir"
        return 1
    fi
}

install_python_tools() {
    print_info "Installing Python-based tools..."
    
    # Ensure pip3 is available
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found. Please install Python3 first."
        return 1
    fi
    
    for tool in $PYTHON_TOOLS; do
        if ! command -v "$tool" &> /dev/null; then
            print_info "Installing $tool via pip3..."
            if pip3 install "$tool" 2>/dev/null; then
                print_success "$tool installed successfully"
            else
                print_error "Failed to install $tool"
            fi
        else
            print_success "$tool is already installed"
        fi
    done
}

install_go_tools() {
    print_info "Installing Go-based tools..."
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        print_error "Go not found. Installing Go via Homebrew..."
        brew install go
    fi
    
    # Set up Go environment
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    
    # Install httpx
    if ! command -v httpx &> /dev/null; then
        print_info "Installing httpx via go install..."
        if go install "$GO_TOOLS_HTTPX" 2>/dev/null; then
            print_success "httpx installed successfully"
        else
            print_error "Failed to install httpx"
        fi
    else
        print_success "httpx is already installed"
    fi
    
    # Install nuclei
    if ! command -v nuclei &> /dev/null; then
        print_info "Installing nuclei via go install..."
        if go install "$GO_TOOLS_NUCLEI" 2>/dev/null; then
            print_success "nuclei installed successfully"
        else
            print_error "Failed to install nuclei"
        fi
    else
        print_success "nuclei is already installed"
    fi
    
    # Install katana
    if ! command -v katana &> /dev/null; then
        print_info "Installing katana via go install..."
        if go install "$GO_TOOLS_KATANA" 2>/dev/null; then
            print_success "katana installed successfully"
        else
            print_error "Failed to install katana"
        fi
    else
        print_success "katana is already installed"
    fi
}

check_tool_installed() {
    local tool="$1"
    if command -v "$tool" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

check_and_install_tools() {
    section_header "Tool Dependency Check"
    
    local missing_tools=()
    local tool_count=0
    local current=0
    
    # Count tools
    for tool in $REQUIRED_TOOLS; do
        ((tool_count++))
    done
    
    # Check Homebrew first
    check_homebrew || return 1
    
    print_info "Checking required tools..."
    
    # Check each required tool
    for tool in $REQUIRED_TOOLS; do
        ((current++))
        show_progress $current $tool_count
        
        if check_tool_installed "$tool"; then
            echo -e "\n$(tool_status "$tool") $tool"
        else
            echo -e "\n$(tool_status "$tool") $tool"
            missing_tools+=("$tool")
        fi
        sleep 0.1
    done
    
    echo -e "\n"
    
    # Install missing tools
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_warning "Found ${#missing_tools[@]} missing tools. Installing..."
        
        for tool in "${missing_tools[@]}"; do
            install_homebrew_tool "$tool"
        done
        
        # Install Python tools
        install_python_tools
        
        # Install Go tools
        install_go_tools
        
        print_success "Tool installation completed"
    else
        print_success "All required tools are installed"
    fi
    
    # Special installations for tools that need additional setup
    setup_metasploit
    setup_wordlists
}

setup_metasploit() {
    if command -v msfconsole &> /dev/null; then
        print_info "Setting up Metasploit database..."
        msfdb init 2>/dev/null || print_warning "Metasploit database setup failed"
    fi
}

setup_wordlists() {
    local wordlist_dir="$HOME/.cvehack/wordlists"
    mkdir -p "$wordlist_dir"
    
    print_info "Setting up wordlists..."
    
    # Download common wordlists
    if [[ ! -f "$wordlist_dir/common.txt" ]]; then
        curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
            -o "$wordlist_dir/common.txt" 2>/dev/null || \
            print_warning "Failed to download common.txt wordlist"
    fi
    
    if [[ ! -f "$wordlist_dir/directory-list-2.3-medium.txt" ]]; then
        curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt" \
            -o "$wordlist_dir/directory-list-2.3-medium.txt" 2>/dev/null || \
            print_warning "Failed to download directory-list wordlist"
    fi
    
    if [[ ! -f "$wordlist_dir/rockyou.txt" ]]; then
        print_info "Downloading rockyou.txt (this may take a while)..."
        curl -s "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
            -o "$wordlist_dir/rockyou.txt" 2>/dev/null || \
            print_warning "Failed to download rockyou.txt wordlist"
    fi
    
    print_success "Wordlists setup completed"
}

show_tool_menu() {
    clear_screen
    section_header "Tool Management"
    
    echo -e "${YELLOW}1.${NC} Check Tool Status"
    echo -e "${YELLOW}2.${NC} Install Missing Tools"
    echo -e "${YELLOW}3.${NC} Update All Tools"
    echo -e "${YELLOW}4.${NC} Install Custom Tool"
    echo -e "${YELLOW}5.${NC} Remove Tool"
    echo -e "${YELLOW}6.${NC} Tool Configuration"
    echo -e "${YELLOW}0.${NC} Back to Main Menu"
    echo ""
    echo -e "${BLUE}Select option: ${NC}"
    read -r tool_choice
    
    case $tool_choice in
        1) show_tool_status ;;
        2) install_missing_tools ;;
        3) update_all_tools ;;
        4) install_custom_tool ;;
        5) remove_tool ;;
        6) configure_tools ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

show_tool_status() {
    clear_screen
    section_header "Tool Status Report"
    
    print_table_header "Tool" "Status" "Version" "Location"
    
    for tool in "${!REQUIRED_TOOLS[@]}"; do
        local status version location
        
        if check_tool_installed "$tool"; then
            status="${GREEN}●${NC} Installed"
            version=$(get_tool_version "$tool")
            location=$(which "$tool")
        else
            status="${RED}●${NC} Missing"
            version="N/A"
            location="N/A"
        fi
        
        print_table_row "$tool" "$status" "$version" "$location"
    done
    
    echo ""
    print_info "Press Enter to continue..."
    read -r
}

get_tool_version() {
    local tool="$1"
    case "$tool" in
        "nmap") nmap --version 2>/dev/null | head -1 | awk '{print $3}' ;;
        "masscan") masscan --version 2>/dev/null | head -1 ;;
        "nikto") nikto -Version 2>/dev/null | grep "Nikto" | awk '{print $2}' ;;
        "sqlmap") sqlmap --version 2>/dev/null | tail -1 ;;
        *) echo "Unknown" ;;
    esac
}

install_missing_tools() {
    clear_screen
    section_header "Installing Missing Tools"
    
    check_and_install_tools
    
    print_info "Press Enter to continue..."
    read -r
}

update_all_tools() {
    clear_screen
    section_header "Updating All Tools"
    
    print_info "Updating Homebrew..."
    brew update
    
    print_info "Upgrading Homebrew packages..."
    brew upgrade
    
    print_info "Updating Python packages..."
    pip3 list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip3 install -U 2>/dev/null
    
    print_info "Updating Go packages..."
    for tool in "${!GO_TOOLS[@]}"; do
        local package="${GO_TOOLS[$tool]}"
        go install "$package" 2>/dev/null
    done
    
    print_success "All tools updated"
    print_info "Press Enter to continue..."
    read -r
}

install_custom_tool() {
    clear_screen
    section_header "Install Custom Tool"
    
    echo -e "${YELLOW}Enter tool installation method:${NC}"
    echo -e "${YELLOW}1.${NC} Homebrew package"
    echo -e "${YELLOW}2.${NC} Python pip package"
    echo -e "${YELLOW}3.${NC} Go package"
    echo -e "${YELLOW}4.${NC} Git repository"
    echo -e "${YELLOW}0.${NC} Cancel"
    echo ""
    echo -e "${BLUE}Select method: ${NC}"
    read -r method
    
    case $method in
        1) install_custom_homebrew ;;
        2) install_custom_python ;;
        3) install_custom_go ;;
        4) install_custom_git ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

install_custom_homebrew() {
    echo -e "${YELLOW}Enter Homebrew package name: ${NC}"
    read -r package
    
    if [[ -n "$package" ]]; then
        print_info "Installing $package via Homebrew..."
        if brew install "$package"; then
            print_success "$package installed successfully"
        else
            print_error "Failed to install $package"
        fi
    fi
}

install_custom_python() {
    echo -e "${YELLOW}Enter Python package name: ${NC}"
    read -r package
    
    if [[ -n "$package" ]]; then
        print_info "Installing $package via pip3..."
        if pip3 install "$package"; then
            print_success "$package installed successfully"
        else
            print_error "Failed to install $package"
        fi
    fi
}

install_custom_go() {
    echo -e "${YELLOW}Enter Go package URL: ${NC}"
    read -r package
    
    if [[ -n "$package" ]]; then
        print_info "Installing $package via go install..."
        if go install "$package"; then
            print_success "$package installed successfully"
        else
            print_error "Failed to install $package"
        fi
    fi
}

install_custom_git() {
    echo -e "${YELLOW}Enter Git repository URL: ${NC}"
    read -r repo_url
    
    if [[ -n "$repo_url" ]]; then
        local temp_dir=$(mktemp -d)
        cd "$temp_dir" || return 1
        
        print_info "Cloning repository..."
        if git clone "$repo_url"; then
            local repo_name=$(basename "$repo_url" .git)
            cd "$repo_name" || return 1
            
            # Try common installation methods
            if [[ -f "Makefile" ]]; then
                print_info "Found Makefile, compiling..."
                make && make install
            elif [[ -f "setup.py" ]]; then
                print_info "Found setup.py, installing..."
                python3 setup.py install
            elif [[ -f "install.sh" ]]; then
                print_info "Found install.sh, running..."
                bash install.sh
            else
                print_warning "No standard installation method found"
                print_info "Repository cloned to: $temp_dir/$repo_name"
            fi
        else
            print_error "Failed to clone repository"
        fi
        
        cd - > /dev/null
    fi
}

remove_tool() {
    clear_screen
    section_header "Remove Tool"
    
    echo -e "${YELLOW}Enter tool name to remove: ${NC}"
    read -r tool_name
    
    if [[ -n "$tool_name" ]]; then
        if check_tool_installed "$tool_name"; then
            print_warning "Are you sure you want to remove $tool_name? (y/N)"
            read -r confirm
            
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                print_info "Removing $tool_name..."
                if brew uninstall "$tool_name" 2>/dev/null || pip3 uninstall "$tool_name" -y 2>/dev/null; then
                    print_success "$tool_name removed successfully"
                else
                    print_error "Failed to remove $tool_name"
                fi
            fi
        else
            print_error "$tool_name is not installed"
        fi
    fi
}

configure_tools() {
    clear_screen
    section_header "Tool Configuration"
    
    print_info "This feature allows you to configure tool-specific settings"
    print_warning "Configuration feature coming soon..."
    
    print_info "Press Enter to continue..."
    read -r
}
