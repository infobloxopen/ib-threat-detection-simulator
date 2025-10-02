# Threat Detection Simulator

This tool simulates various DNS-based attack patterns to test threat detection capabilities. Features dynamic VM detection, **dual-parameter execution system**, and enhanced DGA/DNST threat simulation with **advanced domain mapping capabilities** for accurate threat detection.

## Files Included

```
threat_detection_simulator/
├── category_analysis_script.py    # Main simulation script (dynamic VM detection)
├── ib-base-category.json         # Domain categories data
├── requirements.txt              # Python dependencies  
├── run.sh                        # Simple execution script with dual parameters
├── simulation_output/            # Output directory
├── logs/                        # Logs directory
└── utils/                       # Essential utility modules
    ├── __init__.py
    ├── constants.py
    ├── gcp_utils.py              # Dynamic VM metadata detection
    ├── logging_utils.py
    └── threat_categories.py
```

## Key Features

1. **🎯 Advanced Domain Mapping**: Accurate threat correlation for DGA Mylobot domains (handles first 3 character removal in threat events)
2. **🚀 Dual-Parameter System**: Two-parameter execution for flexible output format and analysis scope control
3. **🤖 Real Malware Domains**: Uses actual DGA domains from Mylobot and Suppobox malware families
4. **🔗 DNST Simulation**: DNS tunneling simulation with ladytisiphone.com for advanced threat testing
5. **⚡ Performance Optimization**: Conditional DNS log collection based on analysis scope
6. **🔧 Dynamic VM Detection**: Automatically detects VM metadata from GCP metadata server
7. **📦 Zero Configuration**: No need for values.yaml or manual configuration files
8. **🌐 Multi-VM Support**: Works on any GCP VM without hardcoded instance IDs
9. **🏃 Local Execution**: Runs `dig` commands locally and fetches GCP logs directly
10. **📊 Flexible CSV Output**: Output format-dependent CSV columns for optimal data presentation
11. **🛡️ Robust Logging**: Graceful fallback for log file permissions
12. **❓ Comprehensive Help**: Built-in `--help` flag with usage examples and feature documentation
13. **🔢 Accurate DNST Metrics**: Special detection rate calculation for DNS tunneling (100% when detected)

## Execution System

### 🎛️ Dual-Parameter System

The script uses a **two-parameter system** for flexible execution:

**Usage**: `./run.sh <OUTPUT_FORMAT> [ANALYSIS_SCOPE] [FLAGS]`

**Quick Help**: `./run.sh --help` or `./run.sh -h`

---

#### **First Parameter - OUTPUT FORMAT** (Required)

Controls the CSV output columns:

### 🔍 DEBUG Output Format (`debug`)
**Purpose**: Comprehensive CSV with all available columns

**Features**:
- ✅ Includes all CSV columns with DNS query details
- ✅ Shows "DNS Query in DNS logs" and "Distinct domains in DNS logs" columns  
- ✅ **Detection Rate column**: (Distinct domain Threat Count / Client DNS Query Domain) × 100
- ✅ Complete data visibility for analysis and troubleshooting
- ✅ Best for detailed investigation and debugging

**CSV Output**:
```csv
Domain Category,Client DNS Query Domain,DNS Query in DNS logs,Distinct domains in DNS logs,Total Threat Count,Distinct domain Threat Count,Detection Rate (%)
```

---

### 📊 NORMAL Output Format (`normal`)
**Purpose**: Streamlined CSV with essential threat information

**Features**:
- ✅ Streamlined CSV with only threat-related columns
- ✅ **NEW**: Detection Rate column showing threat detection success rate
- ✅ Clean, focused output for reporting and presentations
- ✅ Optimized for production use and executive summaries
- ✅ Faster processing with reduced data collection

**CSV Output**:
```csv
Domain Category,Client DNS Query Domain,Total Threat Count,Distinct domain Threat Count,Detection Rate (%)
```

---

#### **Second Parameter - ANALYSIS SCOPE** (Optional, defaults to `basic`)

Controls which domains are analyzed:

### 🏗️ BASIC Analysis Scope (`basic`)
**Purpose**: Analysis of existing threat intelligence domains only

**Features**:
- ✅ Uses only existing domains from `ib-base-category.json`
- ✅ 50 random domains per category for manageable analysis
- ✅ Fastest execution (~5-10 minutes)
- ✅ Standard threat categories (Phishing, Malware, C&C, etc.)
- ✅ Ideal for baseline threat detection validation

**Domain Sources**:
- Standard threat categories from Infoblox threat intelligence
- No additional domain generation
- Pure existing threat landscape analysis

---

### 🚀 ADVANCED Analysis Scope (`advanced`)
**Purpose**: Comprehensive analysis with enhanced threat simulation

**Features**:
- ✅ All existing domains from `ib-base-category.json`
- ✅ **NEW**: Actual DGA domains from Mylobot and Suppobox malware families
- ✅ **NEW**: Domain mapping for accurate threat event correlation
- ✅ **NEW**: Handles Mylobot domain transformation (m14.jospife.ru → jospife.ru)
- ✅ **NEW**: DNST (DNS Tunneling) simulation using ladytisiphone.com
- ✅ **NEW**: Data exfiltration pattern generation and execution
- ✅ **NEW**: VM-based DNS tunneling tests with hex-encoded payloads
- ✅ Enhanced threat detection across multiple attack vectors
- ✅ Comprehensive analysis suitable for security research

**Domain Sources**:
- Standard threat categories + Real DGA domains + DNST simulation
- Domain mapping for accurate threat correlation

---

#### **Optional Flags**

The script supports several optional flags to customize the analysis:

### 🎯 `--dga-count <number>`
**Purpose**: Control the number of DGA domains generated in advanced mode

**Default**: 15 DGA domains per run  
**Usage**: `./run.sh debug advanced --dga-count 25`  
**Details**: Increases or decreases the number of real malware DGA domains (Mylobot/Suppobox) used in the analysis

### 🔗 `--dnst-domain <domain>`
**Purpose**: Specify custom domain for DNST (DNS Tunneling) simulation

**Default**: ladytisiphone.com  
**Usage**: `./run.sh normal advanced --dnst-domain geoffsmith.org`  
**Details**: Uses the specified domain for DNS tunneling simulation with hex-encoded payload transmission

### 🌐 `--dnst-ip <ip>`
**Purpose**: Specify custom IP address for DNST queries

**Default**: 8.8.8.8  
**Usage**: `./run.sh debug advanced --dnst-ip 1.1.1.1`  
**Details**: Target IP address for DNS tunneling simulation queries

### ❓ `--help` or `-h`
**Purpose**: Display comprehensive usage information and examples

**Usage**: `./run.sh --help`  
**Details**: Shows all available options, usage examples, feature descriptions, and requirements
- Advanced threat landscape with cutting-edge attack patterns

## Usage Examples

### 🎯 Quick Start with Presets (Recommended for Sales Team)

The tool now includes easy-to-use presets that combine the most common parameter combinations:

```bash
# Quick demonstration mode (debug + basic)
./run.sh demo

# Clean output for customer presentations (normal + basic)
./run.sh sales

# Comprehensive research analysis (debug + advanced)
./run.sh research

# Full production simulation (normal + advanced)
./run.sh production
```

**Presets can be combined with flags**:
```bash
# Sales demo with custom DGA count
./run.sh demo --dga-count 25

# Production analysis with custom DNST domain
./run.sh production --dnst-domain client-domain.com
```

### 📋 Manual Parameter Examples

#### Example 1: Debug Mode with Basic Analysis (Default)
```bash
# Full debug output, existing domains only
./run.sh debug basic

# Same as above (defaults to basic when no scope specified)
./run.sh debug
```
**Output**: Complete CSV with all columns, 50 random existing domains per category

#### Example 2: Normal Mode with Advanced Analysis
```bash
# Streamlined output with comprehensive threat simulation
./run.sh normal advanced

# With custom DGA count (flag-based)
./run.sh normal advanced --dga-count 25

# With custom DNST domain (flag-based)
./run.sh normal advanced --dnst-domain geoffsmith.org

# With both custom DGA count and DNST domain (flag-based)
./run.sh normal advanced --dga-count 20 --dnst-domain geoffsmith.org
```
**Output**: Clean CSV with threat columns and detection rates, includes DGA + DNST analysis

#### Example 3: Debug Mode with Advanced Analysis
```bash
# Full debug output with comprehensive analysis
./run.sh debug advanced

# With custom parameters (flag-based)
./run.sh debug advanced --dga-count 10 --dnst-domain custom.example.com
```
**Output**: Complete CSV with all columns including Detection Rate, includes existing domains + DGA + DNST

#### Example 4: Normal Mode with Basic Analysis
```bash
# Streamlined output, existing domains only
./run.sh normal basic
```
**Output**: Clean CSV with threat columns and detection rates, 50 random existing domains per category

---

### ⚙️ Parameter Combinations

| OUTPUT_FORMAT | ANALYSIS_SCOPE | CSV Columns | Domains Analyzed | Execution Time |
|:-------------:|:-------------:|:-----------:|:----------------:|:--------------:|
| `debug` | `basic` | All columns | Existing only | ~5-10 minutes |
| `debug` | `advanced` | All columns | Existing + DGA + DNST | ~15-25 minutes |
| `normal` | `basic` | Threat + Detection Rate | Existing only | ~5-10 minutes |
| `normal` | `advanced` | Threat + Detection Rate | Existing + DGA + DNST | ~15-25 minutes |

---

### 🎯 Quick Start Commands

```bash
# Quick validation with full debug info (includes Detection Rate column)
./run.sh debug basic

# Production analysis with clean output and detection rates
./run.sh normal advanced

# Comprehensive security research with custom settings
./run.sh debug advanced --dga-count 20 --dnst-domain geoffsmith.org

# Advanced analysis with custom DGA count only
./run.sh normal advanced --dga-count 25

# Advanced analysis with custom DNST domain only  
./run.sh debug advanced --dnst-domain custom.example.com
```

---

### 🔧 VM Deployment Examples

#### Option 1: Simple VM Deployment
```bash
# Copy to VM and run with debug output
scp -r threat_detection_simulator/ your-vm:~/
ssh your-vm "cd threat_detection_simulator && ./run.sh debug basic"

# Run with streamlined output and full analysis
ssh your-vm "cd threat_detection_simulator && ./run.sh normal advanced"
```

#### Option 2: GCloud Compute Integration
```bash
# Deploy and run on specific VM
VM_NAME="your-vm-instance"
ZONE="your-zone"
PROJECT="your-project-id"

# Copy files to VM
gcloud compute scp --recurse threat_detection_simulator/ \
  $VM_NAME:~/ --zone=$ZONE --project=$PROJECT --tunnel-through-iap

# Run with debug output and advanced analysis
gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT --tunnel-through-iap \
  --command="cd threat_detection_simulator && ./run.sh debug advanced"
```

## Command Line Arguments

### 🔧 Script Parameters

The underlying Python script supports legacy command-line arguments for direct execution:

```bash
python3 category_analysis_script.py --help

usage: category_analysis_script.py [-h] [--mode {debug,basic,advanced}] 
                                   [--output-format {debug,normal}]
                                   [--dga-count DGA_COUNT] [--dnst-domain DNST_DOMAIN] 
                                   [--dnst-ip DNST_IP]

GCP DNS Detection Capabilities - Category-Based Analysis Script with Dual-Parameter System

options:
  -h, --help            show this help message and exit
  --mode {debug,basic,advanced}
                        Analysis scope: debug/basic=existing domains only, 
                        advanced=existing+DGA+DNST (default: advanced)
  --output-format {debug,normal}
                        CSV output format: debug=all columns, normal=threat only 
                        (default: debug)
  --dga-count DGA_COUNT
                        Number of DGA domains to generate for basic/advanced modes 
                        (default: 15)
  --dnst-domain DNST_DOMAIN
                        Domain to use for DNS tunneling simulation in advanced mode 
                        (default: ladytisiphone.com)
  --dnst-ip DNST_IP     IP address for DNS tunneling queries (default: 8.8.8.8)
```

**⚠️ Note**: It's recommended to use `./run.sh <OUTPUT_FORMAT> [ANALYSIS_SCOPE]` instead of direct Python execution for consistency with the new dual-parameter system.

---

## Advanced Configuration

### 🔧 Direct Python Execution (Legacy Support)

For advanced users who prefer direct Python script execution:

```bash
# Debug output format with basic analysis scope
python3 category_analysis_script.py --mode basic --output-format debug

# Normal output format with advanced analysis scope  
python3 category_analysis_script.py --mode advanced --output-format normal

# Custom DGA domain count
python3 category_analysis_script.py --mode advanced --output-format debug --dga-count 25

# Custom DNST configuration
python3 category_analysis_script.py --mode advanced --output-format normal \
  --dga-count 10 --dnst-domain custom.example.com --dnst-ip 1.1.1.1
```

### Parameter Mapping

The new dual-parameter system maps to Python arguments as follows:

| run.sh Parameter | Python Argument | Values | Description |
|:----------------:|:---------------:|:------:|:-----------:|
| OUTPUT_FORMAT | `--output-format` | `debug`, `normal` | Controls CSV column output |
| ANALYSIS_SCOPE | `--mode` | `basic`, `advanced` | Controls domain analysis scope |

**Note**: The `--mode debug` Python option is mapped to `basic` scope with `debug` output format in the new system.

- **GCP VM**: Script must run on a Google Cloud Platform Compute Engine VM
- **Python 3.8+**
- **Google Cloud CLI** configured with authentication  
- **dig command** available (usually pre-installed on most systems)
- **VM Metadata Access**: VM must have access to metadata.google.internal (default for GCP VMs)
- **Compute Engine Default Service Account**: VM must use `PROJECT_NUMBER-compute@developer.gserviceaccount.com`
- **Cloud Logging API Access**: VM service account needs appropriate logging permissions

### VM Service Account Permissions

⚠️ **Critical**: Your VM must use the **Compute Engine default service account** with the correct scopes to access Cloud Logging API.

**Required Service Account**: `PROJECT_NUMBER-compute@developer.gserviceaccount.com`
- This is the default service account automatically assigned to Compute Engine VMs
- Format: `[PROJECT_NUMBER]-compute@developer.gserviceaccount.com`
- Example: `123456789012-compute@developer.gserviceaccount.com`

**Option 1: Create VM with Correct Settings (Recommended)**
When creating a VM, ensure:
1. **Service Account**: Use "Compute Engine default service account" 
2. **Access Scopes**: Select "Allow full access to all Cloud APIs"

```bash
# Create VM with correct service account and scopes
gcloud compute instances create VM_NAME \
  --zone=ZONE \
  --project=PROJECT_ID \
  --service-account=PROJECT_NUMBER-compute@developer.gserviceaccount.com \
  --scopes=https://www.googleapis.com/auth/cloud-platform
```

**Option 2: Update Existing VM**
```bash
# Stop the VM first
gcloud compute instances stop VM_NAME --zone=ZONE --project=PROJECT_ID

# Update service account to use Compute Engine default service account
gcloud compute instances set-service-account VM_NAME \
  --service-account=PROJECT_NUMBER-compute@developer.gserviceaccount.com \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --zone=ZONE --project=PROJECT_ID

# Start the VM
gcloud compute instances start VM_NAME --zone=ZONE --project=PROJECT_ID
```

**Verify Service Account**:
```bash
# Check current service account on VM
gcloud compute instances describe VM_NAME \
  --zone=ZONE --project=PROJECT_ID \
  --format="value(serviceAccounts[0].email)"

# Should return: PROJECT_NUMBER-compute@developer.gserviceaccount.com
```

## Step-by-Step VM Deployment Guide

### Method 1: Direct File Copy (Recommended)

#### Step 1: Copy Files to VM
```bash
# From your local machine, copy the minimal folder to VM
gcloud compute scp --recurse threat_detection_simulator/ \
  VM_NAME:~/ --zone=ZONE --project=PROJECT_ID --tunnel-through-iap

# Alternative: Using rsync for faster transfers
gcloud compute ssh VM_NAME --zone=ZONE --project=PROJECT_ID --tunnel-through-iap \
  --command="mkdir -p ~/threat_detection_simulator"
  
rsync -avz -e "gcloud compute ssh VM_NAME --zone=ZONE --project=PROJECT_ID --tunnel-through-iap --" \
  threat_detection_simulator/ :threat_detection_simulator/
```

#### Step 2: SSH into VM and Run
```bash
# SSH into the VM
gcloud compute ssh VM_NAME --zone=ZONE --project=PROJECT_ID --tunnel-through-iap

# Navigate to the directory
cd threat_detection_simulator/

# Make the script executable
chmod +x run.sh

# Run the analysis
./run.sh
```

### Method 2: GitHub Repository Clone

#### Step 1: SSH into VM
```bash
gcloud compute ssh VM_NAME --zone=ZONE --project=PROJECT_ID --tunnel-through-iap
```

#### Step 2: Clone Repository and Navigate
```bash
# Clone the repository (if using GitHub deployment)
git clone https://github.com/infobloxopen/ib-threat-detection-simulator.git
cd ib-threat-detection-simulator/threat_detection_simulator/

# Or if repository structure is different, adjust path accordingly
```

#### Step 3: Run Analysis
```bash
chmod +x run.sh
./run.sh
```

## Detailed Execution Steps

### What happens when you run `./run.sh`:

1. **System Package Installation** (if needed):
   ```bash
   # The script will automatically install:
   sudo apt-get update
   sudo apt-get install -y python3-venv python3-pip dnsutils  # Ubuntu/Debian
   # OR
   sudo yum install -y python3-venv python3-pip bind-utils    # RHEL/CentOS
   # OR  
   sudo apk add python3 py3-venv py3-pip bind-tools          # Alpine Linux
   ```

2. **Python Environment Setup**:
   ```bash
   # Creates virtual environment
   python3 -m venv venv
   source venv/bin/activate
   
   # Installs dependencies
   pip install -r requirements.txt
   ```

3. **DNS Tools Verification**:
   ```bash
   # Verifies dig command is available and functional
   dig --version
   dig +short google.com A   # Quick connectivity test
   ```

4. **VM Metadata Detection**:
   - Queries `http://metadata.google.internal/computeMetadata/v1/`
   - Extracts: instance ID, project ID, zone, VM name

5. **DNS Analysis Execution**:
   - Loads domain categories from `ib-base-category.json`
   - Executes local `dig` queries for each domain
   - Collects logs from GCP Cloud Logging API
   - Generates analysis reports

### Manual Execution (Alternative)

If you prefer manual control:

```bash
# 1. Install dependencies manually
python3 -m pip install -r requirements.txt

# 2. Check VM detection works
python3 -c "
from utils.gcp_utils import get_vm_metadata_with_gcloud_fallback
metadata = get_vm_metadata_with_gcloud_fallback()
print('VM Metadata:', metadata)
"

# 3. Run the main script
python3 category_analysis_script.py
```

## How It Works

1. **VM Detection**: Automatically queries GCP metadata server to get:
   - VM Instance ID (numeric)
   - Project ID  
   - VM Zone and Region
   - VM Name

2. **Dynamic Filtering**: Uses detected VM instance ID in Cloud Logging queries:
   ```
   resource.type="dns_query"
   jsonPayload.vmInstanceId="{detected_instance_id}"
   ```

3. **No Configuration**: No need to manually specify VM details or edit config files

## Output

## Enhanced Output Features

The script generates comprehensive analysis outputs with mode-dependent enhancements:

### CSV Output Enhancement
- **DEBUG MODE**: Includes DNS query columns for detailed analysis
  ```csv
  Domain Category,Client DNS Query Domain,DNS Query in DNS logs,Distinct domains in DNS logs,Total Threat Count,Distinct domain Threat Count,Detection Rate (%)
  ```
- **NORMAL MODE**: Streamlined CSV with threat analysis and detection rates
  ```csv
  Domain Category,Client DNS Query Domain,Total Threat Count,Distinct domain Threat Count,Detection Rate (%)
  ```

### New Domain Categories
- **DGA_Malware**: Real domains from Mylobot and Suppobox malware families (Basic/Advanced modes)
- **DNST_Tunneling**: DNS tunneling simulation domains (Advanced mode only)

### Output Files Generated
- `simulation_output/threat_detection_results.csv` - Mode-dependent summary statistics
- `simulation_output/threat_event_*.json` - Per-category threat detection logs with domain mapping
- `simulation_output/dns_logs_*.json` - Per-category DNS query logs (Debug mode only)
- `simulation_output/non_detected_domains_*.json` - Per-category analysis of non-detected domains
- `logs/sales_demo.log` - Comprehensive execution logs with domain transformation details

### Sample Enhanced Output

#### Console Output with Domain Mapping
```bash
🚀 Starting GCP DNS Category Analysis Script
================================================================================
🎯 Execution Mode: BASIC
🤖 BASIC MODE: Processing existing domains + 15 DGA domains
   - Standard CSV output without DNS query details
================================================================================

🤖 Selecting 15 DGA domains from known malware families...
🎯 DGA domains selected for DNS queries:
    1. m11.liewxwx.com
    2. m0.zbrtimi.net
    3. m35.bwuskfu.net
ℹ️  Note: Mylobot domains will appear in threat events without 'm##.' prefix
    Example: m14.jospife.ru → jospife.ru in threat events
✅ Selected 15 DGA domains from Mylobot and Suppobox families
🔄 Created 8 domain mappings for threat event correlation

📋 Category Overview:
   Phishing: 50 domains
   DGA_Malware: 15 domains (NEW - Real malware patterns)
   TOTAL: 415 domains to process
```

#### Advanced Mode Console Output
```bash
🚀 ADVANCED MODE: Processing existing + 10 DGA + DNST domains
   - DNST domain: ladytisiphone.com
   
🔗 Generating DNST (DNS Tunneling) domains for domain: ladytisiphone.com
🚀 Executing DNST simulation for domain: 058pcck2.scr.02vj3ljema.ladytisiphone.com
✅ DNST simulation completed. Generated domain: 058pcck2.scr.02vj3ljema.ladytisiphone.com
✅ Added 2 additional domain categories
   DGA_Malware: 10 domains
   DNST_Tunneling: 1 domains
```

### Enhanced CSV Sample (Normal Mode)
```csv
Domain Category,Client DNS Query Domain,Total Threat Count,Distinct domain Threat Count,Detection Rate (%)
Phishing,50,89,38,76.00
DGA_Malware,15,23,15,100.00
DNST_Tunneling,1,5,1,100.00
Malicious_Domains,50,76,35,70.00
Command_and_Control,50,45,24,48.00
TOTAL,166,238,113,68.07
```

## Prerequisites

### Sample Output

#### Console Output
```bash
🚀 Starting Threat Detection Simulator
================================================================================
🔍 Detecting VM metadata...
✅ Project ID: your-project-id
✅ Instance ID: 1234567890123456789
✅ Instance Name: your-vm-instance
✅ Zone: your-zone
✅ Region: your-region
✅ VM Detection Successful!

📥 Loading category indicators...
📊 Domain Sampling Summary:
   Original total domains: 8247
   Sampled total domains: 400
   Max per category: 50
   Categories processed: 8
   Reduction: 95.1%

🔍 STEP 1: Executing DNS queries for each category on 1234567890123456789
============================================================
🚀 Starting DNS queries for category 'Phishing' on 1689996928823716783
✅ Phishing: 48/50 queries successful
⏱️ Execution time: 12.3 seconds

📊 STEP 3: Collecting DNS logs and threat detections for each category
============================================================
📊 Collecting logs for category 'Phishing' from 1689996928823716783
✅ Retrieved 156 DNS query log entries
✅ Retrieved 89 threat detection log entries

📈 STEP 4: Generating category analysis reports
============================================================
📁 CSV file generated: /home/user/threat_detection_simulator/simulation_output/threat_detection_results.csv
🎯 Total threat event files: 8
📋 Total DNS logs files: 8

🎉 Category analysis execution completed successfully!
```

#### CSV Output Sample
```csv
Domain Category,Client DNS Query Domain,DNS Query in DNS logs,Distinct domains in DNS logs,Total Threat Count,Distinct domain Threat Count
Phishing,50,156,42,89,38
Malicious_Domains,50,134,39,76,35
Command_and_Control,50,98,28,45,24
DGAS_and_RDGAS,50,67,31,23,19
High_Risk,50,45,29,18,15
Emerging_Domains,50,23,18,8,7
Lookalikes,50,12,9,3,3
TDS,50,8,6,2,2
TOTAL,400,543,202,264,143
```

## Real-World VM Examples

### Example 1: Multi-Mode Testing on Single VM

```bash
# Test all modes for comprehensive validation
VM="your-vm-instance"
ZONE="your-zone"  
PROJECT="your-project-id"

# Debug mode - baseline testing
gcloud compute ssh $VM --zone=$ZONE --project=$PROJECT --tunnel-through-iap \
  --command="cd threat_detection_simulator && python3 category_analysis_script.py --mode debug"

# Basic mode - DGA enhancement  
gcloud compute ssh $VM --zone=$ZONE --project=$PROJECT --tunnel-through-iap \
  --command="cd threat_detection_simulator && python3 category_analysis_script.py --mode basic --dga-count 20"

# Advanced mode - full capabilities
gcloud compute ssh $VM --zone=$ZONE --project=$PROJECT --tunnel-through-iap \
  --command="cd threat_detection_simulator && python3 category_analysis_script.py --mode advanced --dga-count 15 --dnst-domain ladytisiphone.com"

# Download all results with mode identification
for mode in debug basic advanced; do
  gcloud compute scp --recurse $VM:~/threat_detection_simulator/simulation_output/ \
    results_${mode}_$(date +%Y%m%d)/ --zone=$ZONE --project=$PROJECT --tunnel-through-iap
done
```

### Example 2: Production Deployment with Multiple Modes

```bash
# Production VMs with different analysis depths
PROJECT_ID="your-project-id"
PRODUCTION_VMS=(
  "vm-instance-1:zone-a:basic"
  "vm-instance-2:zone-b:advanced"  
  "vm-instance-3:zone-c:debug"
)

# Deploy with mode-specific configurations
for vm_config in "${PRODUCTION_VMS[@]}"; do
  IFS=':' read -r vm zone mode <<< "$vm_config"
  echo "🚀 Deploying $mode mode to $vm in $zone"
  
  # Copy files
  gcloud compute scp --recurse threat_detection_simulator/ \
    $vm:~/ --zone=$zone --project=$PROJECT_ID --tunnel-through-iap
  
  # Run mode-specific analysis
  case $mode in
    "debug")
      gcloud compute ssh $vm --zone=$zone --project=$PROJECT_ID --tunnel-through-iap \
        --command="cd threat_detection_simulator && python3 category_analysis_script.py --mode debug"
      ;;
    "basic") 
      gcloud compute ssh $vm --zone=$zone --project=$PROJECT_ID --tunnel-through-iap \
        --command="cd threat_detection_simulator && python3 category_analysis_script.py --mode basic --dga-count 25"
      ;;
    "advanced")
      gcloud compute ssh $vm --zone=$zone --project=$PROJECT_ID --tunnel-through-iap \
        --command="cd threat_detection_simulator && python3 category_analysis_script.py --mode advanced --dga-count 20 --dnst-domain ladytisiphone.com --dnst-ip 8.8.8.8"
      ;;
  esac
  
  # Download mode-specific results
  mkdir -p results_${mode}_${vm}_$(date +%Y%m%d)/
  gcloud compute scp --recurse $vm:~/threat_detection_simulator/simulation_output/ \
    results_${mode}_${vm}_$(date +%Y%m%d)/ --zone=$zone --project=$PROJECT_ID --tunnel-through-iap
done
```

### Example 3: Automated Mode Selection Script

Create a smart deployment script (`deploy_enhanced_analysis.sh`):

```bash
#!/bin/bash
set -e

# Enhanced deployment with mode selection
PROJECT_ID="your-project-id"
VM_NAME="your-vm-instance"
ZONE="your-zone"
MODE="${1:-basic}"  # Default to basic mode
DGA_COUNT="${2:-15}"
DNST_DOMAIN="${3:-ladytisiphone.com}"

echo "🚀 Starting enhanced deployment to $VM_NAME"
echo "📊 Mode: $MODE | DGA Domains: $DGA_COUNT | DNST Domain: $DNST_DOMAIN"

# Copy files to VM
echo "📁 Copying enhanced files to VM..."
gcloud compute scp --recurse threat_detection_simulator/ \
  $VM_NAME:~/ --zone=$ZONE --project=$PROJECT_ID --tunnel-through-iap

# Build mode-specific command
case $MODE in
  "debug")
    CMD="cd threat_detection_simulator && python3 category_analysis_script.py --mode debug"
    ;;
  "basic")
    CMD="cd threat_detection_simulator && python3 category_analysis_script.py --mode basic --dga-count $DGA_COUNT"
    ;;
  "advanced")
    CMD="cd threat_detection_simulator && python3 category_analysis_script.py --mode advanced --dga-count $DGA_COUNT --dnst-domain $DNST_DOMAIN"
    ;;
  *)
    echo "❌ Invalid mode: $MODE. Use debug, basic, or advanced"
    exit 1
    ;;
esac

# Execute analysis on VM
echo "🔬 Running $MODE mode analysis on VM..."
gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT_ID --tunnel-through-iap \
  --command="$CMD"

# Download results with mode identifier
echo "📊 Downloading enhanced results..."
timestamp=$(date +"%Y%m%d_%H%M%S")
mkdir -p "results_${MODE}_${timestamp}"
gcloud compute scp --recurse $VM_NAME:~/threat_detection_simulator/simulation_output/ \
  "results_${MODE}_${timestamp}/" --zone=$ZONE --project=$PROJECT_ID --tunnel-through-iap

echo "✅ Enhanced analysis complete! Results saved to: results_${MODE}_${timestamp}/"
echo "📋 Mode Summary:"
echo "   🔍 Mode: $MODE"
echo "   🤖 DGA Domains: $DGA_COUNT" 
echo "   🔗 DNST Domain: $DNST_DOMAIN"
echo "   📁 Results: results_${MODE}_${timestamp}/"
```

**Usage**:
```bash
# Debug mode
./deploy_enhanced_analysis.sh debug

# Basic mode with custom DGA count
./deploy_enhanced_analysis.sh basic 25

# Advanced mode with full customization  
./deploy_enhanced_analysis.sh advanced 20 custom.example.com
```

## Enhanced Troubleshooting

### Common Issues and Solutions

#### 1. Directory Permission Issues
```
❌ Cannot write to simulation_output/ directory
```

**Cause**: Insufficient permissions to create or write to the output directory.

**The script now includes robust automatic handling**:
- Automatically tries standard directory creation
- Falls back to elevated permissions (sudo) if needed
- Creates alternative directory in user's home folder as final fallback
- Exports SIMULATION_OUTPUT_DIR environment variable for alternative paths

**Manual Solutions** (if automatic handling fails):
```bash
# Check current directory permissions
ls -la simulation_output/

# Manual permission fix
sudo chown -R $(whoami):$(id -gn) simulation_output logs
chmod -R 755 simulation_output logs

# Alternative: Use custom output directory
export SIMULATION_OUTPUT_DIR="$HOME/threat_analysis_$(date +%Y%m%d_%H%M%S)"
./run.sh demo
```

**Note**: The script will automatically display which directory is being used and handle most permission issues without user intervention.

#### 2. Domain Mapping Issues
```
ℹ️ Created 0 domain mappings for threat event correlation
```

**Cause**: Using Suppobox domains only (no Mylobot domains requiring transformation).

**Solution**: This is normal behavior. Suppobox domains don't require transformation.
```bash
# Verify DGA domain selection is working
python3 -c "
from utils.gcp_utils import generate_dga_domains, get_expected_threat_domains_from_dga
domains = generate_dga_domains(count=10, seed='test')
expected = get_expected_threat_domains_from_dga(domains)
print('Query domains:', domains[:3])
print('Expected domains:', expected[:3])
"
```

#### 2. Mode-Specific Execution Issues
```
❌ Error: DNST domain generation failed in advanced mode
```

**Cause**: DNS resolution issues or network connectivity problems.

**Solutions**:
```bash
# Test DNS resolution
dig ladytisiphone.com

# Test with simpler DNST domain
python3 category_analysis_script.py --mode advanced --dnst-domain example.com

# Check network connectivity
ping 8.8.8.8
```

#### 3. CSV Column Variations
```
Expected DNS columns missing in Basic/Advanced mode
```

**Cause**: Mode-dependent CSV output design (feature, not bug).

**Explanation**:
- **DEBUG MODE**: Includes DNS query columns for detailed analysis
- **BASIC/ADVANCED MODE**: Excludes DNS columns for performance and cleaner output

**Solution**: Use debug mode if DNS query details are needed:
```bash
python3 category_analysis_script.py --mode debug
```

#### 4. DGA Domain Count Issues
```
⚠️ Selected fewer DGA domains than requested
```

**Cause**: Limited available DGA domains in malware families.

**Solution**: The script automatically handles this and reports actual count:
```bash
# Check available DGA domains
python3 -c "
from utils.gcp_utils import generate_dga_domains
domains = generate_dga_domains(count=100, seed='test')  # Request many
print(f'Available DGA domains: {len(domains)}')
"
```

#### 5. VM Metadata Detection Fails
```
❌ Could not detect VM metadata. This script must run on a GCP VM.
```

**Cause**: Script not running on a GCP VM or metadata server unreachable.

**Solutions**:
```bash
# Check if running on GCP VM
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/name

# If that fails, check network connectivity
ping metadata.google.internal

# Verify gcloud is authenticated
gcloud auth list
gcloud config list project
```
```
❌ PERMISSION_DENIED: Request had insufficient authentication scopes
```

**Cause**: VM service account lacks Cloud Logging API access or wrong service account is being used.

**Solution 1**: Verify you're using the Compute Engine default service account:
```bash
# Check current service account
gcloud compute instances describe $VM_NAME \
  --zone=$ZONE --project=$PROJECT_ID \
  --format="value(serviceAccounts[0].email)"

# Should return: PROJECT_NUMBER-compute@developer.gserviceaccount.com
# If not, update the service account (requires VM restart)
```

**Solution 2**: Update VM with proper scopes (requires VM restart):
```bash
# Stop VM
gcloud compute instances stop $VM_NAME --zone=$ZONE --project=$PROJECT_ID

# Update to use Compute Engine default service account with full scopes
gcloud compute instances set-service-account $VM_NAME \
  --service-account=PROJECT_NUMBER-compute@developer.gserviceaccount.com \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --zone=$ZONE --project=$PROJECT_ID

# Start VM  
gcloud compute instances start $VM_NAME --zone=$ZONE --project=$PROJECT_ID
```

#### 3. Python Package Installation Fails
```
error: externally-managed-environment
```

**Cause**: Modern Linux distributions restrict system pip installs.

**Solution**: The `run.sh` script handles this automatically with:
- Virtual environment creation
- User-local installation (`--user`)
- System override (`--break-system-packages`) as last resort

#### 4. No DNS Logs Found
```
ℹ️ No DNS query logs found for the specified criteria
```

**Possible Causes & Solutions**:
```bash
# Check if dig is working
dig google.com

# Verify VM instance ID is numeric
python3 -c "
from utils.gcp_utils import get_vm_metadata_with_gcloud_fallback
print(get_vm_metadata_with_gcloud_fallback())
"

# Check if DNS queries were actually executed
ls -la simulation_output/

# Verify time window - try wider search if needed
# Edit utils/constants.py to adjust LOG_BUFFER_MINUTES (default: 10 minutes)
# or increase LOG_SEARCH_HOURS for broader log search
```

#### 5. SSH Connection Issues
```bash
# Test basic SSH connectivity
gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT_ID --dry-run

# Use IAP tunneling if VM has no public IP
gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT_ID --tunnel-through-iap

# Check firewall rules
gcloud compute firewall-rules list --filter="name~'.*ssh.*'"
```

#### 6. Disk Space Issues
```bash
# Check available space on VM
gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT_ID --tunnel-through-iap \
  --command="df -h"

# Clean up if needed
gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT_ID --tunnel-through-iap \
  --command="cd threat_detection_simulator && rm -rf venv/ __pycache__/ simulation_output/ logs/"
```

### Enhanced Debug Mode

Enable comprehensive debugging for domain mapping analysis:

```bash
# Debug mode with detailed logging
export PYTHONPATH="./utils:$PYTHONPATH" 
export LOGLEVEL=DEBUG
python3 category_analysis_script.py --mode debug

# Verify domain mapping functionality
python3 -c "
from utils.gcp_utils import generate_dga_domains, get_expected_threat_domains_from_dga
print('Testing domain mapping...')
dga_domains = generate_dga_domains(count=5, seed='test')
expected_domains = get_expected_threat_domains_from_dga(dga_domains)
print('DGA Domains:', dga_domains)
print('Expected in Threats:', expected_domains)
for q, e in zip(dga_domains, expected_domains):
    if q != e:
        print(f'Mapping: {q} → {e}')
"

# Test DNST generation
python3 -c "
from utils.gcp_utils import generate_dnst_data_exfiltration
result = generate_dnst_data_exfiltration('ladytisiphone.com', '8.8.8.8')
print('DNST Domain:', result)
"
```

### Mode-Specific Performance Monitoring

Monitor script performance by execution mode:

```bash
# Monitor different modes during execution
# Terminal 1: Start analysis
python3 category_analysis_script.py --mode advanced --dga-count 20

# Terminal 2: Monitor resources
watch -n 1 'ps aux | grep category_analysis'
watch -n 1 'netstat -i | grep -E "(RX|TX).*bytes"'

# Check mode-specific timing
tail -f logs/sales_demo.log | grep -E "(Mode|execution time|Created.*mapping)"
```

## Enhanced VM Requirements Summary

| Requirement | Details | How to Verify | Mode Dependencies |
|-------------|---------|---------------|-------------------|
| **VM Type** | GCP Compute Engine VM | `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name` | All modes |
| **Service Account** | Cloud Platform scope | `gcloud auth list` | All modes |
| **Service Account Type** | Compute Engine default service account | `gcloud compute instances describe VM --format="value(serviceAccounts[0].email)"` | All modes |
| **Python** | 3.8+ | `python3 --version` | All modes |
| **gcloud CLI** | Latest version | `gcloud --version` | All modes |
| **Network** | Internet + GCP API access | `gcloud compute instances list` | All modes |
| **Permissions** | Cloud Logging read access | `gcloud logging read "timestamp>=2024-01-01" --limit=1` | All modes |
| **Storage** | 1GB+ free space | `df -h` | All modes |
| **DNS Tools** | dig command available | `dig --version` | Required for DNST (Advanced mode) - *Auto-installed* |
| **Domain Resolution** | Custom domain access | `dig ladytisiphone.com` | DNST functionality (Advanced mode) |

### Mode-Specific Requirements

#### DEBUG Mode
- ✅ Minimal requirements (all basic VM requirements)
- ✅ Standard DNS logging permissions
- ✅ ~200MB storage for full DNS logs

#### BASIC Mode  
- ✅ All DEBUG mode requirements
- ✅ DGA domain resolution capability
- ✅ Enhanced threat log analysis permissions
- ✅ ~300MB storage for domain mapping data

#### ADVANCED Mode
- ✅ All BASIC mode requirements
- ✅ DNST domain resolution (ladytisiphone.com or custom)
- ✅ Enhanced DNS query capabilities for tunneling simulation
- ✅ ~500MB storage for comprehensive analysis outputs
- ✅ Network access for data exfiltration simulation

## Enhanced Advantages

- **🎯 Accurate Threat Detection**: Domain mapping ensures precise correlation between DNS queries and threat events
- **🤖 Real Malware Simulation**: Uses actual DGA domains from Mylobot and Suppobox malware families  
- **🔗 Advanced DNST Capabilities**: DNS tunneling simulation with configurable domains and data exfiltration
- **⚡ Performance Optimized**: Mode-dependent execution with conditional DNS log collection
- **🚀 Multi-Mode Flexibility**: Debug, Basic, and Advanced modes for different analysis needs
- **📦 Zero Configuration**: No hardcoded values, automatically detects VM environment
- **🔧 Self-Configuring**: Automatically detects all required VM metadata  
- **� Enhanced Reporting**: Mode-dependent CSV outputs optimized for different use cases
- **🛡️ Production Ready**: Maintains backward compatibility while adding new capabilities
- **🔄 Intelligent Mapping**: Handles domain transformations for accurate threat correlation
- **🌐 Portable**: Works on any GCP VM without configuration changes

## Best Practices

### 1. VM Preparation Checklist
```bash
# Before running the analysis, verify:
□ VM uses Compute Engine default service account (PROJECT_NUMBER-compute@developer.gserviceaccount.com)
□ VM has "Allow full access to all Cloud APIs" enabled
□ gcloud CLI is authenticated: gcloud auth list
□ Internet connectivity: ping 8.8.8.8
□ Metadata server access: curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
□ Sufficient disk space: df -h (at least 1GB free)
□ Python 3.8+: python3 --version
```

### 2. Optimal Execution Strategy by Mode

#### DEBUG Mode Optimization
- **Best Time**: Any time - minimal resource usage
- **Log Requirements**: 5-minute buffer sufficient
- **Resource Usage**: ~100MB RAM, minimal network
- **Execution Time**: 5-10 minutes typically
- **Use Case**: Quick validation, troubleshooting, baseline testing

#### BASIC Mode Optimization  
- **Best Time**: Low-traffic periods for cleaner threat correlation
- **Log Requirements**: 10-minute buffer recommended for DGA domain mapping
- **Resource Usage**: ~150MB RAM, moderate network for threat log collection
- **Execution Time**: 10-20 minutes typically
- **Use Case**: Production threat detection, sales demonstrations

#### ADVANCED Mode Optimization
- **Best Time**: Dedicated analysis windows due to DNST simulation
- **Log Requirements**: 15-minute buffer for comprehensive threat and DNST correlation
- **Resource Usage**: ~200MB RAM, higher network for DNS tunneling simulation
- **Execution Time**: 15-30 minutes typically  
- **Use Case**: Security research, comprehensive threat assessment

#### Mode Selection Guidelines
```bash
# Quick validation
python3 category_analysis_script.py --mode debug

# Production analysis  
python3 category_analysis_script.py --mode basic --dga-count 20

# Research and comprehensive testing
python3 category_analysis_script.py --mode advanced --dga-count 15 --dnst-domain ladytisiphone.com
```

### 3. Result Management
```bash
# Create timestamped result folders
timestamp=$(date +"%Y%m%d_%H%M%S")
mv simulation_output results_$timestamp

# Archive results for long-term storage
tar -czf analysis_results_$timestamp.tar.gz results_$timestamp/

# Clean up for next run
rm -rf simulation_output/ logs/
```

### 4. Multi-VM Coordination
```bash
# Run analysis on multiple VMs with staggered timing
for i in {1..3}; do
  vm="dns-vm-$i"
  echo "Starting analysis on $vm (delay: ${i}0 minutes)"
  # Add delay to prevent concurrent DNS queries
  sleep $((i * 600))  # 10 minute intervals
  # Run analysis...
done
```

### 5. Resource Optimization
- **Memory**: Script uses ~100-200MB RAM typically
- **Network**: Expect ~50-100MB network usage for log collection
- **CPU**: DNS queries are I/O bound, minimal CPU usage
- **Storage**: Reserve 500MB for outputs and temporary files

## Quick Reference Commands

### Essential Commands
```bash
# Quick deployment and execution
gcloud compute scp --recurse threat_detection_simulator/ VM:~/ --zone=ZONE --project=PROJECT --tunnel-through-iap
gcloud compute ssh VM --zone=ZONE --project=PROJECT --tunnel-through-iap --command="cd threat_detection_simulator && ./run.sh"

# Download results
gcloud compute scp --recurse VM:~/threat_detection_simulator/simulation_output/ ./results/ --zone=ZONE --project=PROJECT --tunnel-through-iap

# Clean up VM after analysis
gcloud compute ssh VM --zone=ZONE --project=PROJECT --tunnel-through-iap --command="rm -rf threat_detection_simulator/"
```

### Monitoring Commands
```bash
# Check script progress (run from VM)
tail -f logs/sales_demo.log

# Monitor system resources
htop
iostat 1
netstat -i

# Check GCP API quota usage
gcloud logging read "timestamp>=2024-01-01" --limit=1 --project=PROJECT
```

### Troubleshooting Commands
```bash
# Verify VM metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id

# Test DNS resolution
dig google.com +short

# Check Python packages
python3 -m pip list | grep -E "(PyYAML|requests|certifi)"

# Verify gcloud authentication
gcloud auth print-access-token
gcloud config list
```

## Support and Maintenance

### Regular Updates
The script automatically handles most scenarios, but consider:
- **Monthly**: Update Python packages: `pip install -r requirements.txt --upgrade`
- **Quarterly**: Update domain categories in `ib-base-category.json`
- **As Needed**: Adjust constants in `utils/constants.py` for performance tuning

### Contact and Support
- **Issues**: Check troubleshooting section first
- **Performance**: Monitor execution times and adjust batch sizes if needed
- **Custom Categories**: Modify `ib-base-category.json` for organization-specific threats
- **Integration**: Script outputs standard CSV/JSON for easy integration with other tools

---

**📝 Documentation Version**: 2.0  
**🛠️ Last Updated**: September 2025  
**✨ Features**: Dynamic VM detection, zero-configuration deployment, comprehensive troubleshooting
