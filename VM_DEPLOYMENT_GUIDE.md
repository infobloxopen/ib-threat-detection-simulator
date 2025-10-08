# VM Deployment and Testing Guide

## 📋 Pre-Deployment Checklist

Before copying to your VM (`dns-1-us-east4-qa-1` in `gcp-eng-dns-proc-qa-1`), ensure:

1. **VM Metadata Detection**: ✅ Already confirmed working
   - Project: `gcp-eng-dns-proc-qa-1`
   - Instance: `dns-1-us-east4-qa-1` (ID: 5964017149633528448)
   - Zone: `us-east4-a`

## 🚀 Deployment Steps

### Step 1: Copy Files to VM
```bash
# Copy the entire project to the VM
gcloud compute scp --recurse ib-threat-detection-simulator/ \
  dns-1-us-east4-qa-1:~/ \
  --zone=us-east4-a \
  --project=gcp-eng-dns-proc-qa-1 \
  --tunnel-through-iap
```

### Step 2: SSH into VM and Verify Setup
```bash
# SSH into the VM
gcloud compute ssh dns-1-us-east4-qa-1 \
  --zone=us-east4-a \
  --project=gcp-eng-dns-proc-qa-1 \
  --tunnel-through-iap

# Navigate to the project directory
cd ib-threat-detection-simulator

# Run the comprehensive verification script
./verify_vm_setup.sh
```

### Step 3: Fix Any Permission Issues (if needed)
```bash
# If you get PERMISSION_DENIED errors, run these commands:

# Get your project number
PROJECT_NUMBER=$(gcloud projects describe gcp-eng-dns-proc-qa-1 --format="value(projectNumber)")
echo "Project Number: $PROJECT_NUMBER"

# Grant logging.viewer role to the compute service account
gcloud projects add-iam-policy-binding gcp-eng-dns-proc-qa-1 \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/logging.viewer"

# Verify the role was granted
gcloud projects get-iam-policy gcp-eng-dns-proc-qa-1 \
  --flatten="bindings[].members" \
  --format="table(bindings.role)" \
  --filter="bindings.members:*-compute@developer.gserviceaccount.com AND bindings.role:roles/logging.viewer"
```

## 🧪 Testing Commands

### Quick Test (Basic Mode - Existing Domains Only)
```bash
cd threat_detection_simulator
./run.sh debug basic
```
**Expected**: 
- Creates `category_output/` directory
- Processes ~400 existing domains (50 per category)
- Generates CSV with full debug columns
- Execution time: ~5-10 minutes

### Production Test (Advanced Mode - Full Analysis)
```bash
cd threat_detection_simulator
./run.sh normal advanced
```
**Expected**:
- Processes existing domains + DGA domains + DNST simulation
- Generates streamlined CSV with threat detection rates
- Execution time: ~15-25 minutes

### Custom Test (Debug Mode with Custom DGA Count)
```bash
cd threat_detection_simulator
./run.sh debug advanced --dga-count 10
```

## 📊 Expected Output Files

After successful execution, you should see:
```
threat_detection_simulator/
├── category_output/              # ✅ All output files here
│   ├── threat_detection_results.csv
│   ├── threat_event_*.json
│   ├── dns_logs_*.json (debug mode only)
│   └── non_detected_domains_*.json
└── logs/
    └── sales_demo.log
```

## 🔍 Verification Commands

### Check Output Files Were Created
```bash
# List all output files
ls -la category_output/
ls -la logs/

# Check CSV content
head -5 category_output/threat_detection_results.csv

# Count JSON files generated
echo "Threat event files: $(ls category_output/threat_event_*.json 2>/dev/null | wc -l)"
echo "DNS log files: $(ls category_output/dns_logs_*.json 2>/dev/null | wc -l)"
```

### Check Logging Permissions
```bash
# Test direct logging access
gcloud logging read "timestamp>=\"$(date -d '1 hour ago' -Iseconds)\"" \
  --limit=1 --project=gcp-eng-dns-proc-qa-1

# Check service account
gcloud compute instances describe dns-1-us-east4-qa-1 \
  --zone=us-east4-a \
  --project=gcp-eng-dns-proc-qa-1 \
  --format="value(serviceAccounts[0].email)"
```

## 🚨 Common Issues and Quick Fixes

### Issue: "No output files found"
```bash
# Check directory permissions
ls -la category_output/
sudo chown -R $(whoami):$(id -gn) category_output logs
```

### Issue: "PERMISSION_DENIED"
```bash
# Re-run the IAM role assignment
PROJECT_NUMBER=$(gcloud projects describe gcp-eng-dns-proc-qa-1 --format="value(projectNumber)")
gcloud projects add-iam-policy-binding gcp-eng-dns-proc-qa-1 \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/logging.viewer"
```

### Issue: "dig command not found"
```bash
# The script will auto-install, but you can manually install:
sudo apt-get update && sudo apt-get install -y dnsutils

# Test with the specific DNS server
dig @169.154.169.254 +short google.com
```

## 📈 Expected Results

Based on your VM metadata detection working correctly, you should see:
- ✅ VM metadata detection successful
- ✅ DNS queries execute successfully  
- ✅ Cloud Logging API access works (with proper IAM roles)
- ✅ Output files created in `category_output/` directory
- ✅ No "simulation_output vs category_output" confusion

The fixes we implemented should resolve all the original issues:
1. **Directory consistency**: All files go to `category_output/`
2. **Mode defaults**: Python defaults to `basic`, run.sh to `advanced` (documented)
3. **Permissions**: Clear guidance on required IAM roles (`roles/logging.viewer`)