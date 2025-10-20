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
#   ./run.sh <log_level> <mode> [--dns-server <server>] [--ttl <seconds>]
#
# PARAMETERS:
#   log_level:    debug | info
#   mode:         basic | advanced
#   --dns-server: Optional DNS server configuration (e.g., 'legacy')
#   --ttl:        Optional TTL in seconds for domain caching (default: 600 = 10 minutes)
#
# EXAMPLES:
#   ./run.sh debug basic                         # Debug level + basic mode
#   ./run.sh info advanced --dns-server legacy  # Info level + advanced mode + legacy DNS
#   ./run.sh info basic --ttl 1800              # Info level + basic mode + 30-minute cache TTL
#   ./run.sh debug advanced --dns-server legacy --ttl 300  # All options combined

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_TIMEOUT=600  # 10 minutes timeout for script execution
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
    local log_level="$1"
    local mode="$2" 
    local ttl="$3"
    
    # Validate TTL only if provided (not empty)
    if [ -n "$ttl" ]; then
        if ! [[ "$ttl" =~ ^[0-9]+$ ]] || [ "$ttl" -le 0 ]; then
            print_error "TTL must be a positive integer"
            exit 1
        fi
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

preflight_checks() {
    local log_level=$1
    local mode=$2
    local ttl=$3
    local output_format=$4
    
    if [ "$SKIP_PREFLIGHT" = "1" ]; then
        print_warning "Skipping preflight checks (SKIP_PREFLIGHT=1)"
        return 0
    fi

    echo -e "${CYAN}🔍 Running preflight checks...${NC}"
    echo
    
    # Display configuration summary
    echo -e "${PURPLE}📋 Configuration Summary:${NC}"
    echo -e "   Log Level:     ${log_level}"
    echo -e "   Mode:          ${mode}"
    echo -e "   Output Format: ${output_format}"
    echo -e "   DNS Server:    Auto-detection enabled (system default → 169.254.169.254 fallback)"
    if [ -n "$ttl" ]; then
        echo -e "   Cache TTL:     ${ttl} seconds"
    else
        echo -e "   Cache TTL:     600 seconds (default)"
    fi
    echo
    
    echo -e "${CYAN}🔧 Environment Checks:${NC}"

    local errors=0

    # 1. Python version
    if command -v python3 >/dev/null 2>&1; then
        pyver=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")
        major=${pyver%%.*}; minor=${pyver#*.}
        if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 8 ]; }; then
            print_error "Python 3.8+ required, found $pyver"
            errors=$((errors+1))
        else
            print_status "Python version OK: $pyver"
        fi
    else
        print_error "python3 not found in PATH"
        errors=$((errors+1))
    fi

    # 2. dig availability
    if command -v dig >/dev/null 2>&1; then
        print_status "dig found: $(command -v dig)"
    else
        print_error "dig command not found (install dnsutils / bind-tools)"
        errors=$((errors+1))
    fi

    # 3. gcloud CLI
    if command -v gcloud >/dev/null 2>&1; then
        print_status "gcloud found: $(command -v gcloud)"
    else
        print_error "gcloud CLI not found (install Google Cloud SDK)"
        errors=$((errors+1))
    fi

    # 4. Metadata server accessibility (only if curl present)
    if command -v curl >/dev/null 2>&1; then
        if curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 http://metadata.google.internal/computeMetadata/v1/instance/id >/dev/null; then
            print_status "Metadata server reachable"
        else
            print_error "Cannot reach metadata server (are you on GCE VM?)"
            errors=$((errors+1))
        fi
    else
        print_warning "curl not installed; skipping metadata reachability test"
    fi

    # 5. Service account email & scopes
    local sa_email=""
    if command -v curl >/dev/null 2>&1; then
        sa_email=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email || true)
        if [ -n "$sa_email" ]; then
            print_status "Service Account: $sa_email"
        else
            print_error "Unable to retrieve service account email from metadata"
            errors=$((errors+1))
        fi
    fi

    # 6. Logging API permission quick test (optional; tolerate failure but warn)
    if command -v gcloud >/dev/null 2>&1; then
        if gcloud logging read 'timestamp>="-5m"' --limit=1 --quiet >/dev/null 2>&1; then
            print_status "Cloud Logging read access OK"
        else
            print_warning "Cloud Logging read test failed (may lack roles/logging.viewer or project not set)"
        fi
    fi

    # 7. Verify network DNS path (attempt a metadata DNS query)
    if command -v dig >/dev/null 2>&1; then
        if dig @169.254.169.254 example.com +short >/dev/null 2>&1; then
            print_status "VPC DNS query successful"
        else
            print_warning "DNS via 169.254.169.254 failed (custom resolver?)"
        fi
    fi

    # Summary
    if [ $errors -gt 0 ]; then
        print_error "Preflight failed with $errors error(s). Fix issues or set SKIP_PREFLIGHT=1 to override."
        exit 2
    else
        print_status "All critical preflight checks passed"
    fi
}

# Main execution function
main() {
    echo
    echo -e "${CYAN}🚀 Starting Threat Detection Simulator...${NC}"
    echo "================================================"
    
    # Parse arguments
    if [ $# -lt 2 ]; then
        echo
        echo "Usage: $0 <log_level> <mode> [--ttl <seconds>]"
        echo
        echo "Parameters:"
        echo "  log_level:    debug | info"
        echo "  mode:         basic | advanced"
        echo "  --ttl:        Optional TTL in seconds for domain caching (default: 300)"
        echo
        echo "Examples:"
        echo "  $0 debug basic"
        echo "  $0 info advanced"
        echo "  $0 info basic --ttl 1800"
        echo "  $0 debug advanced --ttl 300"
        echo
        echo "Note: DNS server is automatically detected (system default → 169.254.169.254 fallback)"
        echo
        exit 1
    fi
    
    local log_level=$1
    local mode=$2
    local ttl=""
    
    # Parse optional arguments (only --ttl now)
    local i=3
    while [ $i -le $# ]; do
        local arg="${!i}"
        local next_i=$((i + 1))
        local next_arg="${!next_i}"
        
        case $arg in
            "--ttl")
                if [ -n "$next_arg" ] && [ $next_i -le $# ]; then
                    ttl="$next_arg"
                    i=$((i + 2))
                else
                    print_error "--ttl requires a value"
                    exit 1
                fi
                ;;
            *)
                print_error "Unknown argument: $arg"
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    validate_arguments "$log_level" "$mode" "$ttl"

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

    # Map log level to output format
    local output_format=""
    case $log_level in
        debug)
            output_format="advanced"  # Debug log level uses advanced output format (includes DNS details)
            ;;
        info)
            output_format="basic"     # Info log level uses basic output format (threat info only)
            ;;
        *)
            echo -e "${RED}❌ Error: Unknown log level '$log_level'.${NC}"
            exit 1
            ;;
    esac

    # Preflight environment & dependency checks
    preflight_checks "$log_level" "$mode" "$ttl" "$output_format"

    # Install required packages with intelligent checking (after preflight)
    install_packages_smart

    # Display execution parameters
    echo
    echo -e "${CYAN}🎯 Mode: $mode${NC}"
    echo -e "${CYAN}📊 Output Format: $output_format${NC}"
    echo -e "${CYAN}🌐 DNS: Auto-detection enabled (system default → 169.254.169.254 fallback)${NC}"
    if [ -n "$ttl" ]; then
        echo -e "${CYAN}⏰ Domain Cache TTL: $ttl seconds${NC}"
    fi
    echo -e "${CYAN}🔥 Executing threat simulation...${NC}"
    
    # Build command arguments
    local cmd_args=(
        "--mode" "$mode"
        "--output-format" "$output_format"
    )
    
    # Add TTL argument if provided
    if [ -n "$ttl" ]; then
        cmd_args+=("--ttl" "$ttl")
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
