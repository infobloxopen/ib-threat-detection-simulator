#!/bin/bash

# Simple run script for Threat Detection Simulator
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
#   ./run.sh <OUTPUT_FORMAT> [ANALYSIS_SCOPE] [additional_args]
#
# OUTPUT FORMAT (First Parameter):
#   debug:    All columns including DNS query details (comprehensive CSV)
#   normal:   Only threat info columns (streamlined CSV)
#
# ANALYSIS SCOPE (Second Parameter - Optional):
#   basic:    Only existing domains (50 random from ib-base-category.json)
#   advanced: Existing domains + DGA domains + DNST simulation (default if not specified)
#
# EXAMPLES:
#   ./run.sh debug basic      # All columns + existing domains only
#   ./run.sh debug advanced   # All columns + existing/DGA/DNST domains
#   ./run.sh normal basic     # Threat columns only + existing domains only
#   ./run.sh normal advanced  # Threat columns only + existing/DGA/DNST domains
#   ./run.sh debug            # All columns + full analysis (advanced scope default)
#   ./run.sh normal           # Threat columns only + full analysis (advanced scope default)

# Cleanup function
cleanup() {
    echo "🧹 Cleaning up..."
    # Deactivate virtual environment if it's active
    if [ -n "$VIRTUAL_ENV" ] && [ "$SKIP_VENV" != "1" ]; then
        deactivate 2>/dev/null || true
        echo "✅ Virtual environment deactivated"
    fi
}

# Set trap to run cleanup on script exit
trap cleanup EXIT

echo "🚀 Starting Threat Detection Simulator..."
echo "================================================"

# Check if we're in the right directory
if [ ! -f "category_analysis_script.py" ]; then
    echo "❌ Error: category_analysis_script.py not found in current directory"
    echo "Please run this script from the category_analysis_minimal directory"
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
    echo "❌ Error: python3 not found. Please install Python 3.8 or higher"
    exit 1
fi

echo "✅ Found Python: $PYTHON_CMD"

# Check for dig command availability
if command -v dig >/dev/null 2>&1; then
    echo "✅ Found dig command for DNS queries"
else
    echo "⚠️  dig command not found - will attempt to install DNS utilities"
fi

# Check if we need to install system packages first
echo "🔧 Checking system packages..."
if command -v apt-get >/dev/null 2>&1; then
    # Install essential system packages
    echo "📦 Installing system packages (python3-venv, python3-pip, dnsutils)..."
    sudo apt-get update >/dev/null 2>&1
    sudo apt-get install -y python3-venv python3-pip dnsutils >/dev/null 2>&1
    
    # Check if python3-venv is available after installation
    if ! $PYTHON_CMD -c "import venv" >/dev/null 2>&1; then
        echo "⚠️  python3-venv still not available after installation"
    fi
elif command -v yum >/dev/null 2>&1; then
    # For Red Hat/CentOS systems
    echo "📦 Installing system packages (python3-venv, python3-pip, bind-utils)..."
    sudo yum install -y python3-venv python3-pip bind-utils >/dev/null 2>&1
    
    if ! $PYTHON_CMD -c "import venv" >/dev/null 2>&1; then
        echo "⚠️  python3-venv still not available after installation"
    fi
elif command -v apk >/dev/null 2>&1; then
    # For Alpine Linux
    echo "📦 Installing system packages (python3, py3-venv, py3-pip, bind-tools)..."
    sudo apk add --no-cache python3 py3-venv py3-pip bind-tools >/dev/null 2>&1
fi

# Verify dig installation after package installation
if command -v dig >/dev/null 2>&1; then
    echo "✅ dig command is available for DNS queries"
    # Quick test to verify dig is working
    if dig +short google.com A >/dev/null 2>&1; then
        echo "✅ dig command tested successfully"
    else
        echo "⚠️  dig command found but may have connectivity issues"
    fi
else
    echo "⚠️  dig command still not available after installation attempt"
    echo "   DNS queries may fail. Manual installation may be required:"
    echo "   - Debian/Ubuntu: sudo apt-get install dnsutils"
    echo "   - Red Hat/CentOS: sudo yum install bind-utils"
    echo "   - Alpine Linux: sudo apk add bind-tools"
fi

# Create and activate virtual environment
VENV_DIR="venv"
echo "🔄 Setting up virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    if ! $PYTHON_CMD -m venv "$VENV_DIR" 2>/dev/null; then
        echo "⚠️  Failed to create virtual environment with venv module"
        echo "Trying alternative methods..."
        
        # Try with --system-site-packages as fallback
        if ! $PYTHON_CMD -m venv --system-site-packages "$VENV_DIR" 2>/dev/null; then
            echo "❌ Cannot create virtual environment. Trying system-wide installation..."
            
            # Last resort: try to install packages system-wide with --break-system-packages
            echo "📦 Installing packages system-wide (using --break-system-packages)..."
            $PYTHON_CMD -m pip install --break-system-packages PyYAML requests 2>/dev/null || {
                echo "❌ Failed to install packages. Continuing without package installation..."
                SKIP_PACKAGES=1
            }
            SKIP_VENV=1
        fi
    fi
fi

# Activate virtual environment (if we created one)
if [ "$SKIP_VENV" != "1" ]; then
    echo "Activating virtual environment..."
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
        echo "✅ Virtual environment activated"
        # Update PYTHON_CMD to use the virtual environment
        PYTHON_CMD="python"
    elif [ -f "$VENV_DIR/Scripts/activate" ]; then
        # Windows-style path (unlikely but just in case)
        source "$VENV_DIR/Scripts/activate"
        PYTHON_CMD="python"
    else
        echo "❌ Cannot find virtual environment activation script"
        SKIP_VENV=1
    fi
fi

# Install requirements if packages weren't already installed
if [ "$SKIP_PACKAGES" != "1" ]; then
    if $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
        if [ -f "requirements.txt" ]; then
            echo "📦 Installing requirements..."
            if ! $PYTHON_CMD -m pip install -r requirements.txt --quiet 2>/dev/null; then
                echo "⚠️  Standard pip install failed, trying with --user flag..."
                if ! $PYTHON_CMD -m pip install -r requirements.txt --user --quiet 2>/dev/null; then
                    echo "⚠️  --user install also failed. The system may have externally-managed Python (PEP 668)."
                    echo "    This is normal on newer Linux distributions."
                    echo "    Attempting system-wide install with --break-system-packages..."
                    $PYTHON_CMD -m pip install -r requirements.txt --break-system-packages --quiet 2>/dev/null || {
                        echo "❌ All package installation methods failed. Continuing anyway..."
                        echo "    The script may still work if packages are already available."
                    }
                fi
            fi
        else
            echo "📦 Installing essential packages..."
            if ! $PYTHON_CMD -m pip install PyYAML requests --quiet 2>/dev/null; then
                echo "⚠️  Standard pip install failed, trying with --user flag..."
                if ! $PYTHON_CMD -m pip install PyYAML requests --user --quiet 2>/dev/null; then
                    echo "⚠️  --user install also failed. The system may have externally-managed Python (PEP 668)."
                    echo "    This is normal on newer Linux distributions."
                    echo "    Attempting system-wide install with --break-system-packages..."
                    $PYTHON_CMD -m pip install PyYAML requests --break-system-packages --quiet 2>/dev/null || {
                        echo "❌ All package installation methods failed. Continuing anyway..."
                        echo "    The script may still work if packages are already available."
                    }
                fi
            fi
        fi
    else
        echo "⚠️  pip not available, skipping package installation"
    fi
else
    echo "✅ Packages already installed system-wide"
fi

# Create output directories with proper permissions and ownership
echo "📁 Creating output directories..."
mkdir -p category_output logs

# Set comprehensive permissions
chmod 755 category_output logs 2>/dev/null || echo "⚠️  Could not set directory permissions (non-critical)"

# Ensure current user owns the directories
chown $(whoami):$(id -gn) category_output logs 2>/dev/null || echo "⚠️  Could not change ownership (non-critical)"

# Set write permissions specifically
chmod u+w category_output logs 2>/dev/null || echo "⚠️  Could not set write permissions (non-critical)"

# Test write permissions
echo "🔍 Testing directory write permissions..."
if touch category_output/.write_test 2>/dev/null; then
    rm category_output/.write_test
    echo "✅ category_output/ is writable"
else
    echo "❌ Cannot write to category_output/ directory"
    echo "   Attempting to fix permissions..."
    
    # Try to fix permissions more aggressively
    sudo mkdir -p category_output logs 2>/dev/null || echo "   Could not create with sudo"
    sudo chown -R $(whoami):$(id -gn) category_output logs 2>/dev/null || echo "   Could not change ownership with sudo"
    sudo chmod -R 755 category_output logs 2>/dev/null || echo "   Could not change permissions with sudo"
    
    # Test again
    if touch category_output/.write_test 2>/dev/null; then
        rm category_output/.write_test
        echo "✅ Fixed: category_output/ is now writable"
    else
        echo "⚠️  Still cannot write to category_output/"
        echo "   Trying alternative output directory..."
        
        # Create alternative output directory
        alt_output_dir="$HOME/category_analysis_output_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$alt_output_dir"
        
        if [ -w "$alt_output_dir" ]; then
            echo "✅ Using alternative output directory: $alt_output_dir"
            ln -sf "$alt_output_dir" category_output 2>/dev/null || {
                echo "   Creating environment variable for alternative path"
                export CATEGORY_OUTPUT_DIR="$alt_output_dir"
            }
        fi
    fi
fi

# Test logs directory
if touch logs/.write_test 2>/dev/null; then
    rm logs/.write_test
    echo "✅ logs/ is writable"
else
    echo "⚠️  Cannot write to logs directory, logging will use alternative location"
fi

# Set environment variables
export PYTHONIOENCODING="utf-8"
export PYTHONPATH="$(pwd)/utils:$PYTHONPATH"

echo "▶️  Running category analysis script..."
echo "================================================"

# Parse arguments for new two-parameter system
OUTPUT_FORMAT=""
ANALYSIS_SCOPE=""
REMAINING_ARGS=""

# Check for help flag first
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "🚀 Category Analysis - Enhanced DNS QA Tool"
    echo "============================================="
    echo ""
    echo "DESCRIPTION:"
    echo "  Advanced DNS threat detection analysis tool with whitelist-cleaned categories,"
    echo "  dual-parameter execution system, and comprehensive detection rate calculation."
    echo ""
    echo "USAGE:"
    echo "  ./run.sh <OUTPUT_FORMAT> [ANALYSIS_SCOPE] [FLAGS]"
    echo ""
    echo "OUTPUT FORMATS (Required):"
    echo "  debug     All columns including DNS query details and Detection Rate (%)"
    echo "  normal    Streamlined CSV with only threat-related columns"
    echo ""
    echo "ANALYSIS SCOPES (Optional, defaults to 'advanced'):"
    echo "  basic     Existing domains only (7,057 cleaned threat domains)"
    echo "  advanced  Existing + DGA domains + DNST simulation (comprehensive)"
    echo ""
    echo "OPTIONAL FLAGS:"
    echo "  --dga-count <number>      Number of DGA domains to generate (default: 15)"
    echo "  --dnst-domain <domain>    Domain for DNST simulation (default: ladytisiphone.com)"
    echo "  --dnst-ip <ip>           IP address for DNST queries (default: 8.8.8.8)"
    echo "  --help, -h               Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  # Quick validation with Detection Rate column"
    echo "  ./run.sh debug basic"
    echo ""
    echo "  # Production analysis with comprehensive threat simulation"
    echo "  ./run.sh normal advanced"
    echo ""
    echo "  # Custom DGA count with flag"
    echo "  ./run.sh debug advanced --dga-count 25"
    echo ""
    echo "  # Custom DNST domain with flag"
    echo "  ./run.sh normal advanced --dnst-domain geoffsmith.org"
    echo ""
    echo "  # Combined custom settings"
    echo "  ./run.sh debug advanced --dga-count 20 --dnst-domain custom.com"
    echo ""
    echo "KEY FEATURES:"
    echo "  🎯 Whitelist-cleaned threat categories (943 conflicting domains removed)"
    echo "  📊 Detection Rate calculation (Threat Domains / DNS Domains × 100)"
    echo "  🔗 DNST tunneling simulation with accurate detection metrics"
    echo "  🤖 Real DGA domains from Mylobot and Suppobox malware families"
    echo "  ⚡ Dynamic VM detection and zero-configuration deployment"
    echo ""
    echo "OUTPUT FILES:"
    echo "  category_output/category_analysis.csv       - Summary statistics with detection rates"
    echo "  category_output/threat_event_*.json         - Per-category threat detection logs"
    echo "  category_output/dns_logs_*.json            - Per-category DNS query logs (debug mode)"
    echo "  category_output/non_detected_domains_*.json - Per-category non-detected domains analysis"
    echo "  logs/sales_demo.log                        - Detailed execution logs"
    echo ""
    echo "REQUIREMENTS:"
    echo "  - GCP Compute Engine VM (same project as DNS logs)"
    echo "  - Compute Engine default service account with Cloud Logging API access"
    echo "  - Python 3.8+ (automatically installed if missing)"
    echo "  - dig command for DNS queries (automatically installed if missing)"
    echo ""
    echo "For detailed documentation, see README.md"
    echo ""
    exit 0
fi

if [ $# -gt 0 ]; then
    # First parameter: output format
    case "$1" in
        "debug"|"normal")
            OUTPUT_FORMAT="$1"
            shift
            ;;
        *)
            echo "❌ Invalid output format: $1"
            echo "   Valid formats: debug, normal"
            exit 1
            ;;
    esac
    
    # Second parameter: analysis scope (optional)
    if [ $# -gt 0 ]; then
        case "$1" in
            "basic"|"advanced")
                ANALYSIS_SCOPE="$1"
                shift
                ;;
            *)
                # Not an analysis scope, treat as remaining argument
                ANALYSIS_SCOPE="advanced"  # Default analysis scope
                ;;
        esac
    else
        ANALYSIS_SCOPE="advanced"  # Default analysis scope
    fi
    
    # Collect remaining arguments
    REMAINING_ARGS="$*"
else
    # No arguments provided - use defaults
    OUTPUT_FORMAT="debug"
    ANALYSIS_SCOPE="basic"
fi

echo "📝 Output Format: $OUTPUT_FORMAT"
echo "📊 Analysis Scope: $ANALYSIS_SCOPE"

# Map parameters to Python script arguments
if [ "$OUTPUT_FORMAT" = "debug" ]; then
    PYTHON_OUTPUT_FORMAT="advanced"
else
    PYTHON_OUTPUT_FORMAT="basic"
fi

if [ "$ANALYSIS_SCOPE" = "basic" ]; then
    PYTHON_MODE="debug"  # Only existing domains
else
    PYTHON_MODE="advanced"  # Existing + DGA + DNST
fi

# Build command arguments
PYTHON_ARGS="--mode $PYTHON_MODE --output-format $PYTHON_OUTPUT_FORMAT"

# Handle remaining arguments - support both positional and flag-based arguments
if [ -n "$REMAINING_ARGS" ]; then
    # Process remaining arguments to handle flags properly
    set -- $REMAINING_ARGS
    while [ $# -gt 0 ]; do
        case "$1" in
            --dga-count)
                if [ $# -gt 1 ] && [[ "$2" =~ ^[0-9]+$ ]]; then
                    PYTHON_ARGS="$PYTHON_ARGS --dga-count $2"
                    shift 2
                else
                    echo "❌ Error: --dga-count requires a numeric value"
                    exit 1
                fi
                ;;
            --dnst-domain)
                if [ $# -gt 1 ]; then
                    PYTHON_ARGS="$PYTHON_ARGS --dnst-domain $2"
                    shift 2
                else
                    echo "❌ Error: --dnst-domain requires a domain name"
                    exit 1
                fi
                ;;
            --dnst-ip)
                if [ $# -gt 1 ]; then
                    PYTHON_ARGS="$PYTHON_ARGS --dnst-ip $2"
                    shift 2
                else
                    echo "❌ Error: --dnst-ip requires an IP address"
                    exit 1
                fi
                ;;
            --*)
                echo "⚠️  Unknown flag: $1 - passing to Python script"
                PYTHON_ARGS="$PYTHON_ARGS $1"
                shift
                ;;
            *)
                # Handle positional arguments for backward compatibility
                if [ "$ANALYSIS_SCOPE" = "advanced" ]; then
                    if [[ "$1" =~ ^[0-9]+$ ]]; then
                        # Numeric argument - treat as DGA count
                        PYTHON_ARGS="$PYTHON_ARGS --dga-count $1"
                    else
                        # Non-numeric argument - treat as DNST domain
                        PYTHON_ARGS="$PYTHON_ARGS --dnst-domain $1"
                    fi
                fi
                shift
                ;;
        esac
    done
fi

echo "📝 Python arguments: $PYTHON_ARGS"
$PYTHON_CMD category_analysis_script.py $PYTHON_ARGS
SCRIPT_EXIT_CODE=$?

echo "================================================"
if [ $SCRIPT_EXIT_CODE -eq 0 ]; then
    echo "✅ Script execution completed successfully!"
else
    echo "❌ Script execution failed with exit code: $SCRIPT_EXIT_CODE"
    echo "   Check the error messages above for details."
fi

echo ""

# Show generated files with enhanced output location handling
echo "📊 Checking for generated output files..."

# Check main category_output directory
if [ -d "category_output" ] && [ "$(ls -A category_output 2>/dev/null)" ]; then
    echo "📁 Generated files in category_output/:"
    ls -la category_output/
    echo "✅ Output location: $(pwd)/category_output/"
elif [ -n "$CATEGORY_OUTPUT_DIR" ] && [ -d "$CATEGORY_OUTPUT_DIR" ] && [ "$(ls -A "$CATEGORY_OUTPUT_DIR" 2>/dev/null)" ]; then
    echo "📁 Generated files in alternative directory:"
    ls -la "$CATEGORY_OUTPUT_DIR/"
    echo "✅ Output location: $CATEGORY_OUTPUT_DIR"
else
    # Look for any category analysis output in home directory
    output_dirs=$(find ~ -maxdepth 1 -name "category_analysis_output_*" -type d 2>/dev/null)
    if [ -n "$output_dirs" ]; then
        latest_dir=$(echo "$output_dirs" | sort | tail -n 1)
        if [ -d "$latest_dir" ] && [ "$(ls -A "$latest_dir" 2>/dev/null)" ]; then
            echo "📁 Generated files in fallback directory:"
            ls -la "$latest_dir/"
            echo "✅ Output location: $latest_dir"
        fi
    else
        echo "⚠️  No output files found. Check the script output above for errors."
        echo "   Common issues:"
        echo "   - Permission denied on directory creation"
        echo "   - Insufficient disk space"
        echo "   - Python script execution errors"
    fi
fi

# Show any log files
if [ -d "logs" ] && [ "$(ls -A logs 2>/dev/null)" ]; then
    echo ""
    echo "📋 Log files generated:"
    ls -la logs/
fi

echo ""
echo "🔍 For detailed execution information, check the console output above."

# Final summary
echo ""
echo "📋 EXECUTION SUMMARY"
echo "===================="
if [ $SCRIPT_EXIT_CODE -eq 0 ]; then
    echo "Status: ✅ SUCCESS"
    
    # Find the actual output directory used
    actual_output=""
    if [ -d "category_output" ] && [ "$(ls -A category_output 2>/dev/null)" ]; then
        actual_output="$(pwd)/category_output/"
    elif [ -n "$CATEGORY_OUTPUT_DIR" ] && [ -d "$CATEGORY_OUTPUT_DIR" ]; then
        actual_output="$CATEGORY_OUTPUT_DIR"
    else
        latest_dir=$(find ~ -maxdepth 1 -name "category_analysis_output_*" -type d 2>/dev/null | sort | tail -n 1)
        if [ -n "$latest_dir" ] && [ -d "$latest_dir" ]; then
            actual_output="$latest_dir"
        fi
    fi
    
    if [ -n "$actual_output" ]; then
        echo "Output Directory: $actual_output"
        
        # Count files generated
        csv_files=$(find "$actual_output" -name "*.csv" 2>/dev/null | wc -l)
        json_files=$(find "$actual_output" -name "*.json" 2>/dev/null | wc -l)
        
        echo "Files Generated:"
        echo "  - CSV Reports: $csv_files"
        echo "  - JSON Reports: $json_files"
        echo "  - Total Files: $((csv_files + json_files))"
        
        echo ""
        echo "🎯 To view results:"
        echo "   cd $actual_output"
        echo "   cat category_analysis.csv"
    else
        echo "Output Directory: ⚠️  Not found - check error messages above"
    fi
else
    echo "Status: ❌ FAILED (Exit Code: $SCRIPT_EXIT_CODE)"
    echo "Check the error messages above for troubleshooting steps."
fi

echo "===================="
