#!/bin/bash

# ============================================================================
# Color and Formatting Library for CVEHACK
# ============================================================================

# Color definitions
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export WHITE='\033[1;37m'
export GRAY='\033[0;37m'
export NC='\033[0m' # No Color

# Background colors
export BG_RED='\033[41m'
export BG_GREEN='\033[42m'
export BG_YELLOW='\033[43m'
export BG_BLUE='\033[44m'
export BG_PURPLE='\033[45m'
export BG_CYAN='\033[46m'
export BG_WHITE='\033[47m'

# Text formatting
export BOLD='\033[1m'
export DIM='\033[2m'
export UNDERLINE='\033[4m'
export BLINK='\033[5m'
export REVERSE='\033[7m'
export HIDDEN='\033[8m'

# Status indicators
export SUCCESS="[${GREEN}✓${NC}]"
export ERROR="[${RED}✗${NC}]"
export WARNING="[${YELLOW}!${NC}]"
export INFO="[${BLUE}i${NC}]"
export QUESTION="[${PURPLE}?${NC}]"

# ============================================================================
# Formatting Functions
# ============================================================================

# Print colored text
print_red() { echo -e "${RED}$1${NC}"; }
print_green() { echo -e "${GREEN}$1${NC}"; }
print_yellow() { echo -e "${YELLOW}$1${NC}"; }
print_blue() { echo -e "${BLUE}$1${NC}"; }
print_purple() { echo -e "${PURPLE}$1${NC}"; }
print_cyan() { echo -e "${CYAN}$1${NC}"; }

# Status messages
print_success() { echo -e "${SUCCESS} $1"; }
print_error() { echo -e "${ERROR} $1"; }
print_warning() { echo -e "${WARNING} $1"; }
print_info() { echo -e "${INFO} $1"; }
print_question() { echo -e "${QUESTION} $1"; }

# Progress indicators
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))
    
    printf "\r${BLUE}Progress: [${NC}"
    printf "%*s" $completed | tr ' ' '█'
    printf "%*s" $remaining | tr ' ' '░'
    printf "${BLUE}] %d%% (%d/%d)${NC}" $percentage $current $total
}

# Spinner animation
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Box drawing
draw_box() {
    local text="$1"
    local width=${2:-80}
    local padding=$(( (width - ${#text} - 2) / 2 ))
    
    echo -e "${CYAN}╔$(printf '═%.0s' $(seq 1 $((width-2))))╗${NC}"
    printf "${CYAN}║${NC}%*s%s%*s${CYAN}║${NC}\n" $padding "" "$text" $padding ""
    echo -e "${CYAN}╚$(printf '═%.0s' $(seq 1 $((width-2))))╝${NC}"
}

# Section headers
section_header() {
    local title="$1"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $title${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Subsection headers
subsection_header() {
    local title="$1"
    echo ""
    echo -e "${YELLOW}─── $title ───${NC}"
    echo ""
}

# Table formatting
print_table_header() {
    local cols=("$@")
    local separator=""
    
    for col in "${cols[@]}"; do
        printf "%-20s" "$col"
        separator+="────────────────────"
    done
    echo ""
    echo "$separator"
}

print_table_row() {
    local cols=("$@")
    for col in "${cols[@]}"; do
        printf "%-20s" "$col"
    done
    echo ""
}

# Vulnerability severity colors
severity_color() {
    local severity="$1"
    case "${severity,,}" in
        "critical") echo -e "${BG_RED}${WHITE} CRITICAL ${NC}" ;;
        "high") echo -e "${RED} HIGH ${NC}" ;;
        "medium") echo -e "${YELLOW} MEDIUM ${NC}" ;;
        "low") echo -e "${GREEN} LOW ${NC}" ;;
        "info") echo -e "${BLUE} INFO ${NC}" ;;
        *) echo -e "${GRAY} UNKNOWN ${NC}" ;;
    esac
}

# Port status colors
port_status_color() {
    local status="$1"
    case "${status,,}" in
        "open") echo -e "${GREEN}OPEN${NC}" ;;
        "closed") echo -e "${RED}CLOSED${NC}" ;;
        "filtered") echo -e "${YELLOW}FILTERED${NC}" ;;
        *) echo -e "${GRAY}UNKNOWN${NC}" ;;
    esac
}

# Service confidence colors
confidence_color() {
    local confidence="$1"
    if [[ "$confidence" -ge 8 ]]; then
        echo -e "${GREEN}HIGH${NC}"
    elif [[ "$confidence" -ge 5 ]]; then
        echo -e "${YELLOW}MEDIUM${NC}"
    else
        echo -e "${RED}LOW${NC}"
    fi
}

# Clear screen with style
clear_screen() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                              CVEHACK v1.0                                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Animated text
animate_text() {
    local text="$1"
    local delay=${2:-0.05}
    
    for (( i=0; i<${#text}; i++ )); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

# Progress bar for file operations
file_progress() {
    local current=$1
    local total=$2
    local filename="$3"
    local width=40
    local percentage=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))
    
    printf "\r${BLUE}Processing: %-30s [${NC}" "${filename:0:30}"
    printf "%*s" $completed | tr ' ' '█'
    printf "%*s" $remaining | tr ' ' '░'
    printf "${BLUE}] %d%%${NC}" $percentage
}

# Network status indicator
network_status() {
    local host="$1"
    if ping -c 1 -W 1000 "$host" &>/dev/null; then
        echo -e "${GREEN}●${NC} Online"
    else
        echo -e "${RED}●${NC} Offline"
    fi
}

# Tool status indicator
tool_status() {
    local tool="$1"
    if command -v "$tool" &>/dev/null; then
        echo -e "${GREEN}●${NC} Installed"
    else
        echo -e "${RED}●${NC} Missing"
    fi
}
