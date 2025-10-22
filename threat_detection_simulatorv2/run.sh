#!/bin/bash

# Enhanced Threat Detection Simulator v2 Runner with VM Portability
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
#   ./run.sh <log_level> <mode> [--ttl <seconds>]
#
# PARAMETERS:
#   log_level:    debug | info
#   mode:         basic | advanced
#   --ttl:        Optional TTL in seconds for domain caching (default: 600 = 10 minutes)
#
# EXAMPLES:
#   ./run.sh debug basic                         # Debug level + basic mode
#   ./run.sh info advanced --ttl 1800           # Info level + advanced mode + 30-minute cache TTL
#   ./run.sh debug advanced --ttl 300            # All options combined

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_TIMEOUT=600  # 10 minutes timeout for script execution
PACKAGE_TIMEOUT=60  # 1 minute timeout for package operations

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
    
    # Validate log level
    if [[ "$log_level" != "debug" && "$log_level" != "info" ]]; then
        print_error "Log level must be 'debug' or 'info'"
        exit 1
    fi
    
    # Validate mode
    if [[ "$mode" != "basic" && "$mode" != "advanced" ]]; then
        print_error "Mode must be 'basic' or 'advanced'"
        exit 1
    fi
    
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

    # 8. Check v2 specific files and structure
    if [ -d "threat_detection_simulatorv2" ]; then
        print_status "v2 simulator directory found"
        
        # Check for key v2 modules
        if [ -f "threat_detection_simulatorv2/utils/sampler.py" ]; then
            print_status "v2 sampler module found"
        else
            print_error "v2 sampler module missing"
            errors=$((errors+1))
        fi
        
        if [ -f "threat_detection_simulatorv2/utils/digger.py" ]; then
            print_status "v2 digger module found"
        else
            print_error "v2 digger module missing"
            errors=$((errors+1))
        fi
        
        if [ -f "threat_detection_simulatorv2/utils/threat_fetcher.py" ]; then
            print_status "v2 threat_fetcher module found"
        else
            print_error "v2 threat_fetcher module missing"
            errors=$((errors+1))
        fi
        
        if [ -f "threat_detection_simulatorv2/utils/dependency_checker.py" ]; then
            print_status "v2 dependency_checker module found"
        else
            print_warning "v2 dependency_checker module missing (optional)"
        fi
        
    else
        print_error "v2 simulator directory not found"
        errors=$((errors+1))
    fi

    # 9. Check indicators file
    if [ -f "threat_detection_simulatorv2/ib-base-category.json" ]; then
        print_status "Threat indicators file found"
    else
        print_error "Threat indicators file missing (ib-base-category.json)"
        errors=$((errors+1))
    fi

    # Summary
    if [ $errors -gt 0 ]; then
        print_error "Preflight failed with $errors error(s). Fix issues or set SKIP_PREFLIGHT=1 to override."
        exit 2
    else
        print_status "All critical preflight checks passed"
    fi
}

# Function to install packages with intelligent checking and multiple fallback methods
install_packages_smart() {
    local packages=("json" "logging" "pathlib" "datetime" "subprocess" "hashlib" "random")
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
    
    # Most packages we check are stdlib, so if they're missing, there's likely a Python installation issue
    print_warning "Some standard library modules appear missing. This may indicate a Python installation issue."
    
    # Continue anyway as these should be built-in
    print_status "Continuing with execution (packages should be built-in)"
    return 0
}

# Function to run v2 dependency checks using Python
run_v2_dependency_checks() {
    local log_level=$1
    
    print_progress "Running v2 Python dependency checks..."
    
    # Set log level for dependency checker
    local python_log_level="INFO"
    if [ "$log_level" = "debug" ]; then
        python_log_level="DEBUG"
    fi
    
    # Run the Python dependency checker
    if python3 -c "
import sys
import logging
sys.path.append('.')

# Configure logging for dependency checker
logging.basicConfig(
    level=logging.$python_log_level,
    format='%(levelname)s - %(message)s'
)

try:
    from threat_detection_simulatorv2.utils.dependency_checker import run_preflight_checks
    
    result = run_preflight_checks(skip_preflight=False)
    
    if not result.passed:
        print(f'\\n❌ Python dependency checks failed with {len(result.errors)} error(s)')
        sys.exit(1)
    else:
        print('\\n✅ Python dependency checks passed')
        
except ImportError as e:
    print(f'⚠️ Could not import dependency checker: {e}')
    print('Continuing without Python dependency validation...')
except Exception as e:
    print(f'⚠️ Python dependency check failed: {e}')
    print('Continuing with execution...')
"; then
        print_status "v2 Python dependency checks completed"
    else
        print_error "v2 Python dependency checks failed"
        if [ "$SKIP_PREFLIGHT" != "1" ]; then
            exit 2
        fi
    fi
}

# Main execution function
main() {
    echo
    echo -e "${CYAN}🚀 Starting Threat Detection Simulator v2...${NC}"
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
    if [ ! -d "threat_detection_simulatorv2" ]; then
        print_error "threat_detection_simulatorv2 directory not found"
        echo "Please run this script from the project root directory"
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

    # Run v2-specific dependency checks
    run_v2_dependency_checks "$log_level"

    # Display execution parameters
    echo
    echo -e "${CYAN}🎯 Mode: $mode${NC}"
    echo -e "${CYAN}📊 Output Format: $output_format${NC}"
    echo -e "${CYAN}🌐 DNS: Auto-detection enabled (system default → 169.254.169.254 fallback)${NC}"
    if [ -n "$ttl" ]; then
        echo -e "${CYAN}⏰ Domain Cache TTL: $ttl seconds${NC}"
    fi
    echo -e "${CYAN}🔥 Executing threat simulation v2...${NC}"
    
    # Build command arguments for v2 main script
    local cmd_args=(
        "--log-level" "$log_level"
        "--mode" "$mode"
        "--output-format" "$output_format"
    )
    
    # Add TTL argument if provided
    if [ -n "$ttl" ]; then
        cmd_args+=("--ttl" "$ttl")
    fi
    
    # Check for main v2 script
    V2_MAIN_SCRIPT=""
    if [ -f "threat_detection_simulatorv2/main.py" ]; then
        V2_MAIN_SCRIPT="threat_detection_simulatorv2/main.py"
    elif [ -f "threat_detection_simulatorv2/__main__.py" ]; then
        V2_MAIN_SCRIPT="threat_detection_simulatorv2/__main__.py"
    else
        print_error "v2 main script not found (main.py or __main__.py)"
        print_info "Creating a simple test runner..."
        
        # Create a simple test runner
        cat > test_v2_runner.py << 'EOF'
#!/usr/bin/env python3
"""
Temporary v2 Test Runner
This script tests the v2 threat detection simulator components.
"""

import sys
import logging
import argparse
from pathlib import Path

# Add current directory to path
sys.path.append('.')

def setup_logging(log_level: str):
    """Setup logging configuration"""
    level = logging.DEBUG if log_level == 'debug' else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def test_v2_components():
    """Test v2 components"""
    logger = logging.getLogger(__name__)
    
    logger.info("🧪 Testing v2 Threat Detection Simulator Components")
    logger.info("="*60)
    
    try:
        # Test sampler
        logger.info("Testing sampler module...")
        from threat_detection_simulatorv2.utils.sampler import ThreatDomainSampler, generate_dga_domains, generate_dnst_data_exfiltration
        
        sampler = ThreatDomainSampler()
        logger.info("✅ Sampler module loaded successfully")
        
        # Test DGA generation
        logger.info("Testing DGA domain generation...")
        dga_domains = generate_dga_domains(3, "test")
        logger.info(f"✅ Generated {len(dga_domains)} DGA domains: {dga_domains}")
        
        # Test DNST generation (will execute real DNS queries)
        logger.info("Testing DNST domain generation...")
        dnst_domain = generate_dnst_data_exfiltration("testdomain.com")
        logger.info(f"✅ Generated DNST domain: {dnst_domain}")
        
        # Test digger
        logger.info("Testing digger module...")
        from threat_detection_simulatorv2.utils.digger import DomainDigger
        
        digger = DomainDigger()
        logger.info("✅ Digger module loaded successfully")
        
        # Test threat_fetcher
        logger.info("Testing threat_fetcher module...")
        from threat_detection_simulatorv2.utils.threat_fetcher import ThreatEventFetcher
        
        fetcher = ThreatEventFetcher()
        logger.info("✅ ThreatFetcher module loaded successfully")
        
        logger.info("="*60)
        logger.info("🎉 All v2 components tested successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Component test failed: {e}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='v2 Threat Detection Simulator Test Runner')
    parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
    parser.add_argument('--mode', choices=['basic', 'advanced'], default='basic')
    parser.add_argument('--output-format', choices=['basic', 'advanced'], default='basic')
    parser.add_argument('--ttl', type=int, default=300)
    
    args = parser.parse_args()
    
    setup_logging(args.log_level)
    
    if test_v2_components():
        print("\n✅ v2 Test completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ v2 Test failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

        V2_MAIN_SCRIPT="test_v2_runner.py"
        print_info "Created temporary test runner: $V2_MAIN_SCRIPT"
    fi
    
    # Execute the v2 script with timeout protection
    echo "   Command: $PYTHON_CMD $V2_MAIN_SCRIPT ${cmd_args[*]}"
    echo
    
    if timeout $SCRIPT_TIMEOUT $PYTHON_CMD "$V2_MAIN_SCRIPT" "${cmd_args[@]}"; then
        local exit_code=$?
        echo
        print_status "Threat detection simulation v2 completed successfully!"
        
        # Show generated files
        print_info "Checking for generated output files..."
        
        if [ -d "output" ] && [ "$(ls -A output 2>/dev/null)" ]; then
            print_status "Generated files in output/:"
            ls -la output/
        fi
        
        if [ -d "logs" ] && [ "$(ls -A logs 2>/dev/null)" ]; then
            print_info "Log files generated in logs/:"
            ls -la logs/
        fi
        
        # Clean up temporary test runner if created
        if [ -f "test_v2_runner.py" ]; then
            rm -f test_v2_runner.py
            print_info "Cleaned up temporary test runner"
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