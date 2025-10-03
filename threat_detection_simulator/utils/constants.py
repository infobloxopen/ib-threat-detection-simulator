"""
Constants and Settings for Threat Detection Simulator

Contains all constants and configuration settings used by the threat detection simulator.
"""

# GCP Configuration
GCP_DEFAULT_LOCATION = "us-central1"

# SSH and Connection Settings
SSH_BATCH_TIMEOUT = 300  # 5 minutes timeout for SSH batch operations
SSH_DIG_TIMEOUT = 10     # 10 seconds timeout for individual dig commands
DNS_BATCH_SIZE = 50      # Number of domains to query per batch to optimize SSH connections

# Logging Configuration
LOG_BATCH_SIZE = 1000    # Maximum number of logs to fetch per batch
MAX_LOG_ENTRIES = 5000   # Maximum total log entries to process

# DNS Query Filtering
EXCLUDED_DOMAINS = [
    "googleapis.com",
    "internal",
    "local", 
    "infoblox.com",
    "github.com"
]

# Timing and Propagation Settings
LOG_SEARCH_HOURS = 1.5   # Hours back to search for logs (increased for 500 domains)
PROPAGATION_DELAY = 30   # Seconds to wait for log propagation (reduced for efficiency)
LOG_BUFFER_MINUTES = 10  # Minutes to extend log search window after queries complete

# Query execution timing estimates (for 500 domains across 5 VMs)
ESTIMATED_QUERY_TIME_PER_VM = 180  # ~3 minutes per VM for 100 domains (batch processing)
TOTAL_VM_PROCESSING_TIME = 900     # ~15 minutes for all 5 VMs sequentially
LOG_COLLECTION_BUFFER = 600        # 10 minutes buffer for log collection and processing

# Output Configuration
OUTPUT_CSV_FILE = "sales_demo.csv"
OUTPUT_THREAT_EVENTS_FILE = "threat_events.json"
OUTPUT_DNS_LOGS_FILE = "dns_logs.json"
OUTPUT_DIR = "output"

# CSV Headers - Mode-dependent configuration
# Debug mode includes DNS query details, Normal mode focuses on threat analysis
CSV_HEADERS_DEBUG = [
    "Domain Category",
    "Domains Tested",
    "DNS Queries Found in Logs",
    "Unique Domains in DNS Logs", 
    "Total Alerts Generated",
    "Domains Detected as Threats",
    "Detection Rate (%)"
]

CSV_HEADERS_BASIC_ADVANCED = [
    "Domain Category",
    "Domains Tested",
    "Total Alerts Generated",
    "Domains Detected as Threats",
    "Detection Rate (%)"
]

# Legacy headers for compatibility
CSV_HEADERS = CSV_HEADERS_DEBUG

# Indicator file configuration
INDICATORS_FILE = "sorted_infoblox-base_indicators.ndjson"
GCP_TEST_REPO = "https://github.com/infobloxopen/ib-threat-detection-simulator.git"
INDICATORS_REMOTE_PATH = "sorted_infoblox-base_indicators.ndjson"
