#!/bin/bash

# Enhanced Threat Detection Simulator Runner with VM Portability
# Supports: --dns-server legacy for custom DNS configurations
# Features: Intelligent package management, timeout protection, automated setup
#
# PREREQUISITES:
# 1. VM must have "Allow full access to all Cloud APIs" enabled
#    - Set during VM creation OR update service account scopes later
#    - Required for accessing Cloud Logging API
# 2. User account must have Compute Admin access (or equivalent)
#    - Needed for VM management and SSH access
# 3. This script will automatically install: python3-venv, python3-pip
#
# USAGE:
#   ./run.sh <log_level> <mode> [--dns-server <server>]
#
# PARAMETERS:
#   log_level:    debug | info | warning | error
#   mode:         basic | advanced | comprehensive
#   --dns-server: Optional DNS server configuration (e.g., 'legacy')
#
# EXAMPLES:
#   ./run.sh debug basic                    # Debug level + basic mode
#   ./run.sh info advanced --dns-server legacy  # Info level + advanced mode + legacy DNS
#   ./run.sh warning comprehensive         # Warning level + comprehensive mode

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_TIMEOUT=300  # 5 minutes timeout for script execution
PACKAGE_TIMEOUT=60  # 1 minute timeout for package operations

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ️${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_progress() {
    echo -e "${PURPLE}🔄${NC} $1"
}

# Function to check if a Python package is available
check_package() {
    local package=$1
    if python3 -c "import $package" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to validate arguments
validate_arguments() {
    local log_level=$1
    local mode=$2
    local dns_server=$3
    
    # Validate log level
    case $log_level in
        debug|info|warning|error)
            ;;
        *)
            print_error "Invalid log level: $log_level"
            echo "Valid options: debug, info, warning, error"
            exit 1
            ;;
    esac
    
    # Validate mode
    case $mode in
        basic|advanced|comprehensive)
            ;;
        *)
            print_error "Invalid mode: $mode"
            echo "Valid options: basic, advanced, comprehensive"
            exit 1
            ;;
    esac
    
    # DNS server validation is optional - any value is accepted
    if [ -n "$dns_server" ]; then
        print_info "Using custom DNS server configuration: $dns_server"
    fi
}

# Cleanup function
cleanup() {
    print_info "Cleaning up..."
    # Deactivate virtual environment if it's active
    if [ -n "$VIRTUAL_ENV" ] && [ "$SKIP_VENV" != "1" ]; then
        deactivate 2>/dev/null || true
        print_status "Virtual environment deactivated"
    fi
}

# Set trap to run cleanup on script exit
trap cleanup EXIT

# Main execution function
main() {
    echo
    echo -e "${CYAN}🚀 Starting Threat Detection Simulator...${NC}"
    echo "================================================"
    
    # Parse arguments
    if [ $# -lt 2 ]; then
        echo
        echo "Usage: $0 <log_level> <mode> [--dns-server <server>]"
        echo
        echo "Parameters:"
        echo "  log_level:    debug | info | warning | error"
        echo "  mode:         basic | advanced | comprehensive"
        echo "  --dns-server: Optional DNS server configuration (e.g., 'legacy')"
        echo
        echo "Examples:"
        echo "  $0 debug basic"
        echo "  $0 info advanced --dns-server legacy"
        echo "  $0 warning comprehensive --dns-server custom"
        echo
        exit 1
    fi
    
    local log_level=$1
    local mode=$2
    local dns_server=""
    
    # Parse optional DNS server argument
    if [ $# -ge 4 ] && [ "$3" = "--dns-server" ]; then
        dns_server=$4
    fi
    
    # Validate arguments
    validate_arguments "$log_level" "$mode" "$dns_server"

    # Check if we're in the right directory
    if [ ! -f "category_analysis_script.py" ]; then
        print_error "category_analysis_script.py not found in current directory"
        echo "Please run this script from the threat_detection_simulator directory"
        exit 1
    fi

    # Check Python - try multiple common locations
    PYTHON_CMD=""
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_CMD="python3"
    elif [ -f "/usr/bin/python3" ]; then
        PYTHON_CMD="/usr/bin/python3"
    elif [ -f "/usr/local/bin/python3" ]; then
        PYTHON_CMD="/usr/local/bin/python3"
    else
        print_error "python3 not found. Please install Python 3.8 or higher"
        exit 1
    fi

    print_status "Found Python: $PYTHON_CMD"

    # Function to install packages with intelligent checking and multiple fallback methods
    install_packages_smart() {
        local packages=("requests" "json" "logging" "argparse" "socket" "subprocess" "time" "random")
        local missing_packages=()
        
        print_progress "Checking required packages..."
        
        # Check which packages are missing
        for package in "${packages[@]}"; do
            if ! check_package "$package"; then
                missing_packages+=("$package")
            fi
        done
        
        if [ ${#missing_packages[@]} -eq 0 ]; then
            print_status "All required packages are already available"
            return 0
        fi
        
        print_warning "Missing packages: ${missing_packages[*]}"
        print_progress "Installing required packages..."
        
        # Method 1: Try pip install --user (most common)
        if timeout $PACKAGE_TIMEOUT python3 -m pip install --user requests 2>/dev/null; then
            print_status "Packages installed successfully with pip --user"
            return 0
        fi
        
        # Method 2: Try pip install --break-system-packages (newer systems)
        print_info "Trying pip with --break-system-packages flag..."
        if timeout $PACKAGE_TIMEOUT python3 -m pip install --break-system-packages requests 2>/dev/null; then
            print_status "Packages installed successfully with --break-system-packages"
            return 0
        fi
        
        # Method 3: Try apt-get (Ubuntu/Debian systems) with timeout
        print_info "Trying system package manager..."
        if command -v apt-get >/dev/null 2>&1; then
            if timeout $PACKAGE_TIMEOUT sudo apt-get update -qq 2>/dev/null && \
               timeout $PACKAGE_TIMEOUT sudo apt-get install -y python3-requests python3-urllib3 2>/dev/null; then
                print_status "Packages installed successfully with apt-get"
                return 0
            fi
        fi
        
        # If all methods fail, continue anyway (packages might be built-in)
        print_warning "Package installation attempts completed. Continuing with execution..."
        return 0
    }

    # Install required packages with intelligent checking
    install_packages_smart

    # Display execution parameters
    echo
    echo -e "${CYAN}🎯 Mode: $mode${NC}"
    echo -e "${CYAN}📊 Output Format: advanced${NC}"
    if [ -n "$dns_server" ]; then
        echo -e "${CYAN}🌐 DNS Server: $dns_server${NC}"
    fi
    echo -e "${CYAN}🔥 Executing threat simulation...${NC}"
    
    # Build command arguments
    local cmd_args=(
        "--mode" "$mode"
        "--output-format" "advanced"
    )
    
    # Add DNS server argument if provided
    if [ -n "$dns_server" ]; then
        cmd_args+=("--dns-server" "$dns_server")
    fi
    
    # Execute the Python script with timeout protection
    echo "   Command: $PYTHON_CMD category_analysis_script.py ${cmd_args[*]}"
    echo
    
    if timeout $SCRIPT_TIMEOUT $PYTHON_CMD category_analysis_script.py "${cmd_args[@]}"; then
        local exit_code=$?
        echo
        print_status "Threat detection simulation completed successfully!"
        
        # Show generated files
        print_info "Checking for generated output files..."
        
        if [ -d "category_output" ] && [ "$(ls -A category_output 2>/dev/null)" ]; then
            print_status "Generated files in category_output/:"
            ls -la category_output/
        fi
        
        if [ -d "logs" ] && [ "$(ls -A logs 2>/dev/null)" ]; then
            print_info "Log files generated in logs/:"
            ls -la logs/
        fi
        
        return $exit_code
    else
        local exit_code=$?
        echo
        if [ $exit_code -eq 124 ]; then
            print_warning "Script execution timed out after $SCRIPT_TIMEOUT seconds"
            print_info "This is normal for comprehensive analysis modes"
        else
            print_error "Script execution failed with exit code: $exit_code"
        fi
        return $exit_code
    fi
}

# Execute main function with all arguments
main "$@"
