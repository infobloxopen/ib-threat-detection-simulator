# Threat Detection Simulator

DNS-based threat detection testing tool for GCP environments.

## Quick Start

### Prerequisites
- GCP Compute Engine VM with `roles/logging.viewer` IAM permission
- Python 3.8+

### Deploy and Run

#### Method 1: Direct File Copy
```bash
# Copy specific folder to VM
gcloud compute scp --recurse threat_detection_simulator/ VM_NAME:~/ --zone=ZONE --tunnel-through-iap

# Run analysis
gcloud compute ssh VM_NAME --zone=ZONE --tunnel-through-iap
cd threat_detection_simulator && chmod +x run.sh && ./run.sh debug basic
```

#### Method 2: Clone Repository
```bash
# Clone repository to VM
gcloud compute ssh VM_NAME --zone=ZONE --tunnel-through-iap
git clone https://github.com/infobloxopen/ib-threat-detection-simulator.git
cd ib-threat-detection-simulator/threat_detection_simulator && chmod +x run.sh && ./run.sh debug basic
```

## Usage Commands

# Debug mode with detailed CSV columns (includes DNS query details)
./run.sh debug basic
./run.sh debug advanced

# Info mode with clean CSV columns (threat info only)  
./run.sh info basic
./run.sh info advanced

# With DNS server options
./run.sh debug basic
./run.sh info advanced 

## Parameters
- **First Parameter**: `debug` | `info` (log level) 
- **Second Parameter**: `basic` | `advanced` (analysis mode)


## Output

The tool generates analysis files in `category_output/`:
- `threat_detection_results.csv` - Main results summary
- `threat_event_*.json` - Per-category threat events  
- `logs/threat_detection_simulator.log` - Execution logs

### Sample CSV Output
```csv
Domain Category,Client DNS Query Domain,Total Threat Count,Detection Rate (%)
Phishing,50,50,100.00
DGA_Malware,15,15,100.00
Malicious_Domains,50,50,100.00
TOTAL,115,115,100.00
```

## VM Setup Requirements

### Service Account Permissions
Your VM needs the **Compute Engine default service account** with:
- `roles/logging.viewer` IAM role
- "Allow full access to all Cloud APIs" scope

### Grant Required Permissions
```bash
# Get project number
PROJECT_NUMBER=$(gcloud projects describe PROJECT_ID --format="value(projectNumber)")

# Grant logging permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/logging.viewer"
```

### Verify Setup
```bash
# Test from VM
gcloud logging read "timestamp>=2024-01-01" --limit=1
```

## Troubleshooting

### Permission Errors
```bash
# Check service account
gcloud compute instances describe VM_NAME --zone=ZONE \
  --format="value(serviceAccounts[0].email)"

# Should return: PROJECT_NUMBER-compute@developer.gserviceaccount.com
```

### Script Timeout (>10 minutes)
The script has a 10-minute timeout. For slower VMs or regions, this is normal for advanced analysis modes.
