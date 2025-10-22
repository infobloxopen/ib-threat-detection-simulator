#!/bin/bash

# Enhanced Threat Detection Simulator Runner with VM Portability & Auto-Installation
# Supports: --dns-server legacy for custom DNS configurations
# Features: Intelligent package management, timeout protection, automated setup, dependency auto-installation
#
# PREREQUISITES:
# 1. VM must have "Allow full access to all Cloud APIs" enabled
#    - Set during VM creation OR update service account scopes later
#    - Required for accessing Cloud Logging API
# 2. User account must have Compute Admin access (or equivalent)
#    - Needed for VM management and SSH access
# 3. This script will automatically install missing dependencies:
#    - dig (dnsutils/bind-tools)
#    - curl
#    - gcloud CLI (Google Cloud SDK)
#    - python3-requests, python3-urllib3
#
# AUTO-INSTALLATION SUPPORT:
#   Supported OS: Ubuntu, Debian, RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, Alpine, openSUSE
#   The script detects your OS and attempts to install missing dependencies automatically
#   Use SKIP_PREFLIGHT=1 to skip all checks, or AUTO_INSTALL_CONTINUE=1 to continue despite errors
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
#   ./run.sh debug basic                         # Debug level + basic mode (auto-installs missing deps)
#   ./run.sh info advanced --dns-server legacy  # Info level + advanced mode + legacy DNS  
#   ./run.sh info basic --ttl 1800              # Info level + basic mode + 30-minute cache TTL
#   ./run.sh debug advanced --dns-server legacy --ttl 300  # All options combined
#
# ENVIRONMENT VARIABLES:
#   SKIP_PREFLIGHT=1         # Skip all preflight checks and auto-installation
#   AUTO_INSTALL_CONTINUE=1  # Continue execution even if auto-installation fails

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

# Function to detect OS and package manager
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif command -v lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        OS_VERSION=$(lsb_release -sr)
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        # Handle macOS specifically
        if [ "$OS" = "darwin" ]; then
            OS="macos"
        fi
    fi
    
    echo "$OS"
}

# Function to install dig based on OS
install_dig() {
    local os=$(detect_os)
    print_progress "Attempting to install dig (DNS utilities) for OS: $os"
    
    case "$os" in
        ubuntu|debian)
            print_info "Installing dnsutils package..."
            if sudo apt-get update -qq && sudo apt-get install -y dnsutils; then
                print_status "dig installed successfully via apt-get"
                return 0
            else
                print_error "Failed to install dig via apt-get"
                return 1
            fi
            ;;
        rhel|centos|fedora|rocky|almalinux)
            print_info "Installing bind-utils package..."
            if command -v dnf >/dev/null 2>&1; then
                if sudo dnf install -y bind-utils; then
                    print_status "dig installed successfully via dnf"
                    return 0
                fi
            elif command -v yum >/dev/null 2>&1; then
                if sudo yum install -y bind-utils; then
                    print_status "dig installed successfully via yum"
                    return 0
                fi
            fi
            print_error "Failed to install dig via package manager"
            return 1
            ;;
        alpine)
            print_info "Installing bind-tools package..."
            if sudo apk add bind-tools; then
                print_status "dig installed successfully via apk"
                return 0
            else
                print_error "Failed to install dig via apk"
                return 1
            fi
            ;;
        suse|opensuse)
            print_info "Installing bind-utils package..."
            if sudo zypper install -y bind-utils; then
                print_status "dig installed successfully via zypper"
                return 0
            else
                print_error "Failed to install dig via zypper"
                return 1
            fi
            ;;
        macos)
            print_info "macOS detected - dig should be available by default"
            if command -v dig >/dev/null 2>&1; then
                print_status "dig is already available on macOS"
                return 0
            else
                print_warning "dig not found on macOS - try installing via Homebrew:"
                print_info "  brew install bind"
                return 1
            fi
            ;;
        *)
            print_warning "Unknown OS '$os' - cannot auto-install dig"
            print_info "Please install DNS utilities manually:"
            print_info "  Ubuntu/Debian: sudo apt-get install dnsutils"
            print_info "  RHEL/CentOS:   sudo yum install bind-utils"
            print_info "  Alpine:        sudo apk add bind-tools"
            print_info "  macOS:         brew install bind"
            return 1
            ;;
    esac
}

# Function to install curl based on OS
install_curl() {
    local os=$(detect_os)
    print_progress "Attempting to install curl for OS: $os"
    
    case "$os" in
        ubuntu|debian)
            if sudo apt-get update -qq && sudo apt-get install -y curl; then
                print_status "curl installed successfully via apt-get"
                return 0
            fi
            ;;
        rhel|centos|fedora|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                if sudo dnf install -y curl; then
                    print_status "curl installed successfully via dnf"
                    return 0
                fi
            elif command -v yum >/dev/null 2>&1; then
                if sudo yum install -y curl; then
                    print_status "curl installed successfully via yum"
                    return 0
                fi
            fi
            ;;
        alpine)
            if sudo apk add curl; then
                print_status "curl installed successfully via apk"
                return 0
            fi
            ;;
        suse|opensuse)
            if sudo zypper install -y curl; then
                print_status "curl installed successfully via zypper"
                return 0
            fi
            ;;
        macos)
            print_info "macOS detected - curl should be available by default"
            if command -v curl >/dev/null 2>&1; then
                print_status "curl is already available on macOS"
                return 0
            else
                print_warning "curl not found on macOS - try installing via Homebrew:"
                print_info "  brew install curl"
                return 1
            fi
            ;;
    esac
    
    print_error "Failed to install curl"
    return 1
}

# Function to install gcloud CLI
install_gcloud() {
    local os=$(detect_os)
    print_progress "Attempting to install gcloud CLI for OS: $os"
    
    case "$os" in
        ubuntu|debian)
            print_info "Installing Google Cloud SDK via APT repository..."
            if curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
               echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
               sudo apt-get update -qq && \
               sudo apt-get install -y google-cloud-cli; then
                print_status "gcloud CLI installed successfully"
                return 0
            else
                print_error "Failed to install gcloud CLI via APT"
                return 1
            fi
            ;;
        rhel|centos|fedora|rocky|almalinux)
            print_info "Installing Google Cloud SDK via YUM repository..."
            if sudo tee -a /etc/yum.repos.d/google-cloud-sdk.repo << 'EOM'
[google-cloud-cli]
name=Google Cloud CLI
baseurl=https://packages.cloud.google.com/yum/repos/cloud-sdk-el8-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOM
            then
                if command -v dnf >/dev/null 2>&1; then
                    if sudo dnf install -y google-cloud-cli; then
                        print_status "gcloud CLI installed successfully via dnf"
                        return 0
                    fi
                elif command -v yum >/dev/null 2>&1; then
                    if sudo yum install -y google-cloud-cli; then
                        print_status "gcloud CLI installed successfully via yum"
                        return 0
                    fi
                fi
            fi
            print_error "Failed to install gcloud CLI via package manager"
            return 1
            ;;
        macos)
            print_info "macOS detected - checking for Homebrew or manual installation"
            if command -v brew >/dev/null 2>&1; then
                print_info "Installing gcloud CLI via Homebrew..."
                if brew install google-cloud-sdk; then
                    print_status "gcloud CLI installed successfully via Homebrew"
                    return 0
                else
                    print_error "Failed to install gcloud CLI via Homebrew"
                fi
            else
                print_warning "Homebrew not found. Please install gcloud CLI manually:"
                print_info "  1. Download from: https://cloud.google.com/sdk/docs/install-sdk"
                print_info "  2. Or install Homebrew first: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
                print_info "  3. Then run: brew install google-cloud-sdk"
                return 1
            fi
            ;;
        *)
            print_warning "Auto-installation of gcloud CLI not supported for OS: $os"
            print_info "Please install manually from: https://cloud.google.com/sdk/docs/install"
            return 1
            ;;
    esac
}

preflight_checks() {
    local log_level=$1
    local mode=$2
    local ttl=$3
    local output_format=$4
    
    if [ "$SKIP_PREFLIGHT" = "1" ]; then
        print_warning "Skipping preflight checks (SKIP_PREFLIGHT=1)"
        return 0
    fi

    echo -e "${CYAN}🔍 Running preflight checks with auto-installation...${NC}"
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
    
    # Detect OS
    local detected_os=$(detect_os)
    print_info "Detected OS: $detected_os"
    echo
    
    echo -e "${CYAN}🔧 Environment Checks & Auto-Installation:${NC}"

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
        print_warning "Python 3.8+ is required but auto-installation is complex"
        print_info "Please install Python 3.8+ manually for your OS"
        errors=$((errors+1))
    fi

    # 2. dig availability with auto-installation
    if command -v dig >/dev/null 2>&1; then
        print_status "dig found: $(command -v dig)"
    else
        print_warning "dig command not found - attempting auto-installation..."
        if install_dig; then
            # Verify installation
            if command -v dig >/dev/null 2>&1; then
                print_status "dig successfully installed: $(command -v dig)"
            else
                print_error "dig installation completed but command still not found"
                errors=$((errors+1))
            fi
        else
            print_error "Failed to auto-install dig"
            errors=$((errors+1))
        fi
    fi

    # 3. curl availability with auto-installation (needed for metadata checks)
    if command -v curl >/dev/null 2>&1; then
        print_status "curl found: $(command -v curl)"
    else
        print_warning "curl command not found - attempting auto-installation..."
        if install_curl; then
            if command -v curl >/dev/null 2>&1; then
                print_status "curl successfully installed: $(command -v curl)"
            else
                print_error "curl installation completed but command still not found"
                errors=$((errors+1))
            fi
        else
            print_warning "Failed to auto-install curl - metadata checks will be skipped"
        fi
    fi

    # 4. gcloud CLI with auto-installation
    if command -v gcloud >/dev/null 2>&1; then
        print_status "gcloud found: $(command -v gcloud)"
    else
        print_warning "gcloud CLI not found - attempting auto-installation..."
        if install_gcloud; then
            # Verify installation and refresh PATH
            export PATH="/usr/bin:$PATH"
            if command -v gcloud >/dev/null 2>&1; then
                print_status "gcloud CLI successfully installed: $(command -v gcloud)"
            else
                print_error "gcloud CLI installation completed but command still not found"
                print_info "You may need to restart your shell or source your profile"
                errors=$((errors+1))
            fi
        else
            print_error "Failed to auto-install gcloud CLI"
            errors=$((errors+1))
        fi
    fi

    # 5. Metadata server accessibility (only if curl present)
    if command -v curl >/dev/null 2>&1; then
        if curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 http://metadata.google.internal/computeMetadata/v1/instance/id >/dev/null; then
            print_status "Metadata server reachable"
        else
            print_error "Cannot reach metadata server (are you on GCE VM?)"
            errors=$((errors+1))
        fi
    else
        print_warning "curl not available; skipping metadata reachability test"
    fi

    # 6. Service account email & scopes
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

    # 7. Logging API permission quick test (optional; tolerate failure but warn)
    if command -v gcloud >/dev/null 2>&1; then
        if gcloud logging read 'timestamp>="-5m"' --limit=1 --quiet >/dev/null 2>&1; then
            print_status "Cloud Logging read access OK"
        else
            print_warning "Cloud Logging read test failed (may lack roles/logging.viewer or project not set)"
        fi
    fi

    # 8. Verify network DNS path (attempt a metadata DNS query)
    if command -v dig >/dev/null 2>&1; then
        if dig @169.254.169.254 example.com +short >/dev/null 2>&1; then
            print_status "VPC DNS query successful"
        else
            print_warning "DNS via 169.254.169.254 failed (custom resolver?)"
        fi
    fi

    # Summary
    echo
    if [ $errors -gt 0 ]; then
        print_error "Preflight completed with $errors error(s) after auto-installation attempts."
        print_warning "You may need to:"
        print_info "  1. Restart your shell to refresh PATH"
        print_info "  2. Manually install missing dependencies"
        print_info "  3. Set SKIP_PREFLIGHT=1 to override these checks"
        
        if [ "$AUTO_INSTALL_CONTINUE" = "1" ]; then
            print_warning "AUTO_INSTALL_CONTINUE=1 set - continuing despite errors"
        else
            print_error "Stopping due to critical errors. Set AUTO_INSTALL_CONTINUE=1 to continue anyway."
            exit 2
        fi
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
        echo "  $0 debug basic                    # Auto-installs missing dependencies"
        echo "  $0 info advanced"
        echo "  $0 info basic --ttl 1800"
        echo "  $0 debug advanced --ttl 300"
        echo
        echo "Environment Variables:"
        echo "  SKIP_PREFLIGHT=1                 # Skip all dependency checks"
        echo "  AUTO_INSTALL_CONTINUE=1          # Continue despite installation failures"
        echo
        echo "Note: DNS server is automatically detected (system default → 169.254.169.254 fallback)"
        echo "      Missing dependencies (dig, curl, gcloud) will be auto-installed for supported OS"
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
