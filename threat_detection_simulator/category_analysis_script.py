"""
Threat Detection Simulator

This script demonstrates DNS threat detection capabilities by simulating various attack patterns and analyzing detection rates.
It processes domains from ib-base-category.json and runs analysis on a single VM with optimized performance.

Key Features:
1. Loads domain categories from ib-base-category.json
2. Randomly samples exactly 50 domains per category for manageable scale and better accuracy
3. Runs DNS queries on the first configured VM only using batch processing
4. Processes domains in a single batch of 50 for optimal timing and accuracy
5. Generates analytics by domain category instead of region
6. Provides comprehensive threat detection analysis per category
7. Outputs CSV with category-based statistics and per-category JSON files

Performance Optimizations:
- Domain sampling: Reduces 8,000+ domains to ~400 (95% reduction)
- Accuracy focus: 50 domains per category for better log correlation
- Single batch processing: All domains processed together for optimal timing
- Extended time windows: T1 to T2+{LOG_BUFFER_MINUTES}min for comprehensive log capture
- Domain-filtered logs: Only captures DNS logs for queried domains
- Single VM focus: Eliminates multi-region complexity

Author: Infoblox Security Team  
Date: September 2025
"""

import os
import sys
import csv
import json
import time
import random
import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

# Add utils to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))

from utils.constants import *
from utils.logging_utils import configure_logging, get_logger, flush_logs
from utils.threat_categories import get_threat_filter, get_supported_categories, is_category_supported
from utils.gcp_utils import (
    get_vm_metadata,
    fetch_dns_logs, 
    fetch_threat_detection_logs,
    extract_unique_domains_from_dns_logs,
    extract_unique_domains_from_threats,
    generate_dnst_data_exfiltration,
    generate_dga_domains,
    get_expected_threat_domains_from_dga
)

# Configure logging
configure_logging()
logger = get_logger(__name__)

# Category-based constants
CATEGORY_INDICATORS_FILE = "ib-base-category.json"
CATEGORY_OUTPUT_CSV_FILE = "threat_detection_results.csv"
CATEGORY_OUTPUT_DIR = "category_output"
DOMAIN_CACHE_FILE = "domain_cache.json"

# Domain sampling configuration
MAX_DOMAINS_PER_CATEGORY = 50   # Reduced to 50 domains per category for better accuracy
CATEGORY_BATCH_SIZE = 50        # Process all 50 domains in a single batch

# Updated CSV headers for category analysis (mode-dependent)
# Use constants.py for mode-specific column configurations

# Execution mode constants
EXECUTION_MODES = ['debug', 'basic', 'advanced']


def get_csv_headers_for_output_format(output_format: str) -> List[str]:
    """
    Get CSV headers based on output format.
    
    Args:
        output_format (str): Output format (basic, advanced)
        
    Returns:
        List[str]: CSV headers for the specified output format
    """
    if output_format == 'advanced':
        return CSV_HEADERS_DEBUG  # Use debug headers for advanced output (includes DNS details)
    else:
        return CSV_HEADERS_BASIC_ADVANCED  # Use basic headers (threat info only)


def parse_arguments():
    """
    Parse command line arguments for different execution modes.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Threat Detection Simulator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available execution modes:

DEBUG MODE (--mode debug):
  - Only processes existing domains from ib-base-category.json
  - No additional domain generation
  - Quick execution for testing and debugging
  - Includes DNS log details in CSV output
  - CSV includes: "DNS Query in DNS logs" and "Distinct domains in DNS logs"

BASIC MODE (--mode basic):
  - Processes existing domains from ib-base-category.json
  - Adds actual DGA domains from known malware families (Mylobot, Suppobox)
  - Enhanced threat detection with real-world DGA patterns
  - Standard CSV output without DNS query details
  - CSV excludes DNS log columns for cleaner output

ADVANCED MODE (--mode advanced):
  - Processes existing domains from ib-base-category.json
  - Adds actual DGA domains from known malware families for threat simulation
  - Generates DNST (DNS Tunneling) domains with data exfiltration simulation using ladytisiphone.com
  - Comprehensive threat detection and analysis
  - Includes VM-based DNS tunneling tests
  - Standard CSV output without DNS query details

Examples:
  python category_analysis_script.py --mode debug
  python category_analysis_script.py --mode basic --dga-count 20
  python category_analysis_script.py --mode advanced --dga-count 15 --dnst-domain ladytisiphone.com
  python category_analysis_script.py --mode basic --ttl 1800  # Use 30-minute TTL for domain caching

Domain Caching (--ttl):
  - Tracks used domains and avoids reusing them within TTL period
  - Creates cache file in category_output/ with domains grouped by category and timestamps
  - Default TTL: 300 seconds (5 minutes)
  - Set --ttl 0 to disable caching and allow immediate domain reuse
        """)
    
    parser.add_argument(
        '--mode',
        choices=EXECUTION_MODES,
        default='basic',
        help='Execution mode: debug (basic+DNS details), basic (+DGA), advanced (+DGA+DNST)'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['basic', 'advanced'],
        default='basic',
        help='Output format: basic (threat info only), advanced (includes DNS query details)'
    )
    
    parser.add_argument(
        '--dga-count',
        type=int,
        default=15,
        help='Number of DGA domains to select from known malware families (basic/advanced mode, default: 15)'
    )
    
    parser.add_argument(
        '--dnst-domain',
        type=str,
        default='ladytisiphone.com',
        help='Domain to use for DNST simulation (advanced mode, default: ladytisiphone.com)'
    )
    
    parser.add_argument(
        '--dnst-ip',
        type=str,
        default='',
        help='Anycast IP for DNST queries (advanced mode, default: empty for system default)'
    )
    
    parser.add_argument(
        '--ttl',
        type=int,
        default=300,
        help='TTL in seconds to avoid reusing recently tested domains (default: 300 seconds = 5 minutes)'
    )
    
    return parser.parse_args()


def detect_best_dns_server() -> str:
    """
    Detect the best DNS server to use by testing system default first, then fallback to GCP DNS.
    
    Returns:
        str: The best DNS server to use ('system' for default, or IP address)
    """
    import subprocess
    
    # Test 1: Try system default DNS (no @ specified)
    try:
        logger.info("🔍 Testing system default DNS resolver...")
        result = subprocess.run(['dig', 'example.com', '+short'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            logger.info("✅ System default DNS working correctly")
            return 'system'
        else:
            logger.warning(f"⚠️ System default DNS failed: {result.stderr.strip()}")
    except Exception as e:
        logger.warning(f"⚠️ System default DNS test failed: {e}")
    
    # Test 2: Fallback to GCP metadata server DNS
    try:
        logger.info("🔍 Testing fallback DNS (169.254.169.254)...")
        result = subprocess.run(['dig', '@169.254.169.254', 'example.com', '+short'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            logger.info("✅ Fallback DNS (169.254.169.254) working correctly")
            return '169.254.169.254'
        else:
            logger.warning(f"⚠️ Fallback DNS failed: {result.stderr.strip()}")
    except Exception as e:
        logger.warning(f"⚠️ Fallback DNS test failed: {e}")
    
    # If both fail, still return system default as last resort
    logger.error("❌ Both DNS tests failed, using system default as last resort")
    return 'system'


def execute_dig_with_fallback(domain: str, dns_server: str) -> dict:
    """
    Execute dig command with error logging and fallback logic.
    
    Args:
        domain (str): Domain to query
        dns_server (str): DNS server to use ('system' or IP address)
        
    Returns:
        dict: Result with status, output, and error information
    """
    import subprocess
    
    # Build dig command
    if dns_server == 'system':
        dig_cmd = ['dig', domain, '+short']
        server_desc = "system default"
    else:
        dig_cmd = ['dig', f'@{dns_server}', domain, '+short']
        server_desc = dns_server
    
    try:
        result = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            return {
                "status": "success",
                "output": result.stdout.strip(),
                "error": "",
                "dns_server": dns_server,
                "command": ' '.join(dig_cmd)
            }
        else:
            # Log the failure
            error_msg = result.stderr.strip()
            logger.warning(f"🔍 DNS query failed for {domain} using {server_desc}: {error_msg}")
            
            # Check for common error patterns
            if "timed out" in error_msg.lower():
                logger.warning(f"⏰ DNS timeout for {domain} on {server_desc}")
            elif "connection refused" in error_msg.lower():
                logger.warning(f"🚫 DNS connection refused for {domain} on {server_desc}")
            
            return {
                "status": "error",
                "output": "",
                "error": error_msg,
                "dns_server": dns_server,
                "command": ' '.join(dig_cmd)
            }
            
    except subprocess.TimeoutExpired:
        error_msg = "DNS query timeout after 10 seconds"
        logger.warning(f"⏰ {error_msg} for {domain} using {server_desc}")
        return {
            "status": "error",
            "output": "",
            "error": error_msg,
            "dns_server": dns_server,
            "command": ' '.join(dig_cmd)
        }
    except Exception as e:
        error_msg = str(e)
        logger.warning(f"❌ DNS query exception for {domain} using {server_desc}: {error_msg}")
        return {
            "status": "error",
            "output": "",
            "error": error_msg,
            "dns_server": dns_server,
            "command": ' '.join(dig_cmd)
        }


def load_domain_cache(output_dir: str, ttl_seconds: int) -> Dict[str, List[str]]:
    """
    Load domain cache and return still-valid cached domains per category.
    
    Args:
        output_dir (str): Output directory where cache file is stored
        ttl_seconds (int): TTL in seconds for cache validity
        
    Returns:
        Dict[str, List[str]]: Dictionary of valid cached domains per category
    """
    cache_path = os.path.join(output_dir, DOMAIN_CACHE_FILE)
    valid_cached_domains = {}
    
    if not os.path.exists(cache_path):
        logger.info("📄 No domain cache file found, starting fresh")
        return valid_cached_domains
    
    try:
        with open(cache_path, 'r') as f:
            cache_data = json.load(f)
        
        current_time = datetime.now()
        for category, category_data in cache_data.items():
            if 'domains' not in category_data or 'timestamp' not in category_data:
                continue
                
            # Parse the timestamp and check if still valid
            cache_timestamp = datetime.fromisoformat(category_data['timestamp'])
            time_diff = (current_time - cache_timestamp).total_seconds()
            
            if time_diff < ttl_seconds:
                valid_cached_domains[category] = category_data['domains']
                logger.info(f"📚 Cache HIT for {category}: {len(category_data['domains'])} domains still valid (cached {time_diff:.0f}s ago)")
            else:
                logger.info(f"⏰ Cache EXPIRED for {category}: {len(category_data['domains'])} domains too old ({time_diff:.0f}s > {ttl_seconds}s)")
        
        if valid_cached_domains:
            total_cached = sum(len(domains) for domains in valid_cached_domains.values())
            logger.info(f"✅ Loaded cache with {total_cached} valid domains across {len(valid_cached_domains)} categories")
        else:
            logger.info("🆕 All cached domains expired, starting fresh")
            
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.warning(f"⚠️ Cache file corrupted, ignoring: {e}")
    except Exception as e:
        logger.warning(f"⚠️ Error reading cache file, ignoring: {e}")
    
    return valid_cached_domains


def save_domain_cache(output_dir: str, used_domains: Dict[str, List[str]]) -> None:
    """
    Save used domains to cache file with current timestamp.
    
    Args:
        output_dir (str): Output directory where cache file will be saved
        used_domains (Dict[str, List[str]]): Dictionary of used domains per category
    """
    cache_path = os.path.join(output_dir, DOMAIN_CACHE_FILE)
    current_timestamp = datetime.now().isoformat()
    
    # Create cache data structure
    cache_data = {}
    for category, domains in used_domains.items():
        cache_data[category] = {
            'domains': domains,
            'timestamp': current_timestamp
        }
    
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        with open(cache_path, 'w') as f:
            json.dump(cache_data, f, indent=2)
        
        total_domains = sum(len(domains) for domains in used_domains.values())
        logger.info(f"💾 Saved domain cache: {total_domains} domains across {len(used_domains)} categories")
        logger.info(f"📁 Cache file: {cache_path}")
        
    except Exception as e:
        logger.error(f"❌ Failed to save domain cache: {e}")


def generate_additional_domains(mode: str, dga_count: int = 15, dnst_domain: str = 'ladytisiphone.com', dnst_ip: str = '', dns_server: str = 'legacy') -> Tuple[Dict[str, List[str]], Dict[str, str], Dict[str, Dict]]:
    """
    Generate additional domains based on execution mode.
    NOTE: This now only prepares domains - actual execution happens later with proper timing.
    
    Args:
        mode (str): Execution mode (debug, basic, advanced)
        dga_count (int): Number of DGA domains to generate
        dnst_domain (str): Domain for DNST simulation
        dnst_ip (str): IP for DNST queries
        dns_server (str): DNS server to use for queries (default: legacy mode with no DNS server specification)
        
    Returns:
        Tuple[Dict[str, List[str]], Dict[str, str], Dict[str, Dict]]: Additional domains, domain mapping, execution config
    """
    additional_domains = {}
    domain_mapping = {}  # Maps query domains to expected threat event domains
    execution_config = {}  # Configuration for executing additional domain types
    
    if mode == 'debug':
        logger.info("🔍 DEBUG MODE: Using only existing domains from ib-base-category.json")
        return additional_domains, domain_mapping, execution_config
    
    if mode in ['basic', 'advanced']:
        logger.info(f"🤖 Selecting {dga_count} DGA domains from known malware families...")
        dga_domains = generate_dga_domains(count=dga_count, seed="category_analysis")
        additional_domains['DGA_Malware'] = dga_domains
        
        # Create domain mapping for DGA domains (Mylobot mapping)
        expected_threat_domains = get_expected_threat_domains_from_dga(dga_domains)
        for query_domain, threat_domain in zip(dga_domains, expected_threat_domains):
            if query_domain != threat_domain:  # Only map if different
                domain_mapping[query_domain] = threat_domain
        
        logger.info(f"✅ Selected {len(dga_domains)} DGA domains from Mylobot and Suppobox families")
        if domain_mapping:
            logger.info(f"🔄 Created {len(domain_mapping)} domain mappings for threat event correlation")
        
        # Configure DGA execution (just DNS queries for DGA domains)
        execution_config['DGA_Malware'] = {
            'type': 'dga',
            'domains': dga_domains,
            'execution_needed': True
        }
    
    if mode == 'advanced':
        logger.info(f"🔗 Preparing DNST (DNS Tunneling) simulation for domain: {dnst_domain}")
        
        # For DNST, we need to generate and execute the actual tunneling simulation
        # We'll create a placeholder domain and configure the execution
        dnst_base_domain = f"dnst-placeholder.{dnst_domain}"  # This will be replaced during execution
        additional_domains['DNST_Tunneling'] = [dnst_base_domain]
        
        # Configure DNST execution
        execution_config['DNST_Tunneling'] = {
            'type': 'dnst',
            'base_domain': dnst_domain,
            'anycast_ip': dnst_ip,
            'execution_needed': True
        }
        
        logger.info(f"✅ Configured DNST simulation for: {dnst_domain}")
    
    return additional_domains, domain_mapping, execution_config


def execute_additional_domains(execution_config: Dict[str, Dict], categories: Dict[str, List[str]]) -> Dict[str, Dict]:
    """
    Execute additional domain queries (DGA and DNST) with precise timing for log correlation.
    
    Args:
        execution_config (Dict[str, Dict]): Configuration for additional domain execution
        categories (Dict[str, List[str]]): Categories dict to update with actual domains
        dns_server (str): DNS server IP to use for queries
        
    Returns:
        Dict[str, Dict]: Execution timing results for each additional category
    """
    execution_results = {}
    # Detect best DNS server to use
    dns_server = detect_best_dns_server()
    logger.info(f"🌐 Using DNS server: {dns_server if dns_server != 'system' else 'system default'}")
    
    for category, config in execution_config.items():
        if not config.get('execution_needed', False):
            continue
            
        logger.info(f"🚀 Executing {config['type'].upper()} queries for category: {category}")
        start_time = datetime.utcnow()
        
        try:
            if config['type'] == 'dga':
                # DGA domains just need regular DNS queries - already generated
                domains = config['domains']
                
                # Execute DNS queries for DGA domains
                logger.info(f"🔍 Executing DNS queries for {len(domains)} DGA domains...")
                dig_results = {}
                for domain in domains:
                    # Execute DNS query with fallback and logging
                    result = execute_dig_with_fallback(domain, dns_server)
                    dig_results[domain] = result
                    if result['status'] == 'success':
                        logger.debug(f"   DGA query: {domain} -> success")
                    else:
                        logger.debug(f"   DGA query: {domain} -> failed: {result['error']}")
                
                end_time = datetime.utcnow()
                logger.info(f"✅ Completed DGA queries in {(end_time - start_time).total_seconds():.1f} seconds")
                
            elif config['type'] == 'dnst':
                # DNST needs special tunneling simulation
                base_domain = config['base_domain']
                anycast_ip = config['anycast_ip']
                
                logger.info(f"🔗 Executing DNST tunneling simulation for: {base_domain}")
                dnst_result = generate_dnst_data_exfiltration(domain=base_domain, anycast_ip=anycast_ip, dns_server=dns_server if dns_server != 'system' else '169.254.169.254')
                
                # Also capture dig results for the DNST base domain for correlation
                dig_results = {}
                result = execute_dig_with_fallback(dnst_result, dns_server)
                dig_results[dnst_result] = result
                if result['status'] == 'success':
                    logger.debug(f"   DNST base domain query: {dnst_result} -> success")
                else:
                    logger.debug(f"   DNST base domain query: {dnst_result} -> failed: {result['error']}")
                
                # Update the category with the actual DNST domain
                categories[category] = [dnst_result]
                
                end_time = datetime.utcnow()
                logger.info(f"✅ Completed DNST simulation in {(end_time - start_time).total_seconds():.1f} seconds")
                logger.info(f"   Generated domain: {dnst_result}")
            
            execution_results[category] = {
                'start_time': start_time,
                'end_time': end_time,
                'execution_time': (end_time - start_time).total_seconds(),
                'domains': categories.get(category, []),
                'dig_results': dig_results,  # Use dig_results for both DGA and DNST
                'success': True
            }
            
        except Exception as e:
            end_time = datetime.utcnow()
            logger.error(f"❌ Error executing {config['type']} for {category}: {e}")
            execution_results[category] = {
                'start_time': start_time,
                'end_time': end_time,
                'execution_time': (end_time - start_time).total_seconds(),
                'domains': categories.get(category, []),
                'dig_results': {},
                'success': False,
                'error': str(e)
            }
    
    return execution_results


def load_category_indicators(file_path: str, output_dir: str = CATEGORY_OUTPUT_DIR, ttl_seconds: int = 0) -> Dict[str, List[str]]:
    """
    Load domain indicators organized by category from JSON file.
    Randomly samples up to MAX_DOMAINS_PER_CATEGORY domains from each category.
    Filters out recently used domains based on TTL cache.
    
    Args:
        file_path (str): Path to the category indicators JSON file
        output_dir (str): Output directory for cache file (default: CATEGORY_OUTPUT_DIR)
        ttl_seconds (int): TTL in seconds for domain caching (0 = no caching)
        
    Returns:
        dict: Dictionary with categories as keys and sampled domain lists as values
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"❌ Category indicators file not found: {file_path}")
            return {}
            
        with open(file_path, 'r') as f:
            categories = json.load(f)
        
        # Load cached domains if TTL is enabled
        cached_domains = {}
        if ttl_seconds > 0:
            cached_domains = load_domain_cache(output_dir, ttl_seconds)
        
        # Filter out empty categories, apply cache filtering, sample domains, and log statistics
        filtered_categories = {}
        total_domains = 0
        total_original_domains = 0
        total_cached_filtered = 0
        
        for category, domains in categories.items():
            if domains:  # Only include categories with domains
                total_original_domains += len(domains)
                
                # Filter out cached domains for this category
                available_domains = domains
                if ttl_seconds > 0 and category in cached_domains:
                    cached_set = set(cached_domains[category])
                    available_domains = [d for d in domains if d not in cached_set]
                    filtered_count = len(domains) - len(available_domains)
                    total_cached_filtered += filtered_count
                    if filtered_count > 0:
                        logger.info(f"🚫 Category '{category}': Filtered out {filtered_count} cached domains, {len(available_domains)} available")
                
                # Sample up to MAX_DOMAINS_PER_CATEGORY domains randomly from available domains
                if len(available_domains) > MAX_DOMAINS_PER_CATEGORY:
                    sampled_domains = random.sample(available_domains, MAX_DOMAINS_PER_CATEGORY)
                    logger.info(f"🎯 Category '{category}': Sampled {MAX_DOMAINS_PER_CATEGORY} from {len(available_domains)} available domains")
                elif len(available_domains) > 0:
                    sampled_domains = available_domains
                    logger.info(f"✅ Category '{category}': Using all {len(available_domains)} available domains")
                else:
                    # No available domains after cache filtering
                    logger.warning(f"⚠️ Category '{category}': No available domains after cache filtering (all {len(domains)} domains recently used)")
                    sampled_domains = []
                
                if sampled_domains:
                    filtered_categories[category] = sampled_domains
                    total_domains += len(sampled_domains)
            else:
                logger.info(f"ℹ️ Category '{category}': Empty, skipping")
        
        # Log comprehensive statistics
        logger.info("📊 Domain Sampling Summary:")
        logger.info(f"   Original total domains: {total_original_domains}")
        if ttl_seconds > 0:
            logger.info(f"   Cache filtered domains: {total_cached_filtered}")
            logger.info(f"   Available after cache: {total_original_domains - total_cached_filtered}")
        logger.info(f"   Final sampled domains: {total_domains}")
        logger.info(f"   Max per category: {MAX_DOMAINS_PER_CATEGORY}")
        logger.info(f"   Categories processed: {len(filtered_categories)}")
        reduction_pct = ((total_original_domains - total_domains) / total_original_domains * 100) if total_original_domains > 0 else 0
        logger.info(f"   Total reduction: {reduction_pct:.1f}%")
        
        return filtered_categories
        
    except json.JSONDecodeError as e:
        logger.error(f"❌ Error parsing category indicators JSON: {e}")
        return {}
    except Exception as e:
        logger.error(f"❌ Error loading category indicators file: {e}")
        return {}


def create_empty_log_result(category: str, domains: List[str]) -> Dict:
    """
    Create an empty log result structure for categories without threat filters.
    
    Args:
        category (str): The category name
        domains (List[str]): List of domains for this category
        
    Returns:
        Dict: Empty log result structure
    """
    return {
        'category': category,
        'domains': domains,
        'dns_logs': [],
        'threat_logs': [],
        'unique_threat_domains': [],
        'unique_dns_domains': [],
        'log_summary': {
            'dns_logs_count': 0,
            'threat_logs_count': 0,
            'unique_threat_domains_count': 0,
            'unique_dns_domains_count': 0
        },
        'query_timing': {
            'log_start_time': datetime.utcnow(),
            'log_end_time': datetime.utcnow()
        }
    }


def execute_queries_for_category(vm_id: str, vm_config: Dict, category: str, domains: List[str]) -> Dict:
    """
    Execute DNS queries for a specific domain category on a single VM using batching.
    Processes domains in batches of CATEGORY_BATCH_SIZE for optimal performance.
    
    Args:
        vm_id (str): VM identifier
        vm_config (dict): VM configuration
        category (str): Domain category name
        domains (list): List of domains to query for this category
        
    Returns:
        dict: Query execution results with timing information
    """
    try:
        # Detect best DNS server for this category
        dns_server = detect_best_dns_server()
        logger.info(f"🌐 Using DNS server for {category}: {dns_server if dns_server != 'system' else 'system default'}")
        
        start_time = datetime.utcnow()
        logger.info(f"🚀 Starting DNS queries for category '{category}' on {vm_id}")
        logger.info(f"📋 VM: {vm_config['name']} in {vm_config['zone']}")
        logger.info(f"🎯 Category: {category} ({len(domains)} domains)")
        logger.info(f"🔄 Will process in batches of {CATEGORY_BATCH_SIZE} domains")
        logger.info(f"⏰ Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        flush_logs()
        
        # Execute dig queries locally for all domains
        all_dig_results = {}
        for domain in domains:
            # Use the new execute_dig_with_fallback function
            result = execute_dig_with_fallback(domain, dns_server)
            all_dig_results[domain] = result

        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()
        successful_queries = sum(1 for result in all_dig_results.values() if result.get('status') == 'success')

        logger.info(f"✅ {category}: {successful_queries}/{len(domains)} queries successful")
        logger.info(f"⏱️ Execution time: {execution_time:.1f} seconds")
        logger.info(f"⏰ End time: {end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        flush_logs()

        return {
            'vm_id': vm_id,
            'vm_config': vm_config,
            'category': category,
            'domains': domains,
            'total_queries': len(domains),
            'successful_queries': successful_queries,
            'failed_queries': len(domains) - successful_queries,
            'execution_time': execution_time,
            'start_time': start_time,
            'end_time': end_time,
            'dig_results': all_dig_results,
            'batches_processed': 1
        }
        
    except Exception as e:
        end_time = datetime.utcnow()
        logger.error(f"❌ Error executing queries for category {category}: {e}")
        return {
            'vm_id': vm_id,
            'vm_config': vm_config,
            'category': category,
            'domains': domains,
            'total_queries': len(domains),
            'successful_queries': 0,
            'failed_queries': len(domains),
            'execution_time': 0,
            'start_time': start_time,
            'end_time': end_time,
            'error': str(e),
            'dig_results': {},
            'batches_processed': 0
        }


def collect_logs_for_category(vm_id: str, vm_config: Dict, category: str, query_start_time: datetime, 
                             query_end_time: datetime, domains: List[str] = None, mode: str = 'debug',
                             domain_mapping: Dict[str, str] = None, output_format: str = 'basic') -> Dict:
    """
    Collect DNS query logs and threat detection logs for a specific category.
    Optimized to collect DNS logs only when output_format is 'advanced' (debug output) for better performance.
    
    Args:
        vm_id (str): VM identifier
        vm_config (dict): VM configuration
        category (str): Domain category name
        query_start_time (datetime): When queries started for this category
        query_end_time (datetime): When queries ended for this category
        domains (list): List of domains that were queried for this category
        mode (str): Execution mode (debug, basic, advanced) - affects threat analysis scope
        domain_mapping (Dict[str, str], optional): Mapping of query domains to expected threat domains
        output_format (str): Output format (basic, advanced) - affects DNS log collection
        
    Returns:
        dict: Log collection results for the category
    """
    try:
        logger.info(f"📊 Collecting logs for category '{category}' from {vm_id}")
        
        # Calculate expanded time window for comprehensive category-specific log capture
        # Use expanded window: exactly during query execution + LOG_BUFFER_MINUTES buffer for better log coverage
        log_start_time = query_start_time  # Start exactly when queries began
        log_end_time = query_end_time + timedelta(minutes=LOG_BUFFER_MINUTES)     # End with configured buffer after queries finished
        
        # Calculate hours back from current time to the log start time
        time_diff = datetime.utcnow() - log_start_time
        hours_back = time_diff.total_seconds() / 3600.0
        
        logger.info(f"📊 Expanded time window for category '{category}' ({LOG_BUFFER_MINUTES}-minute buffer):")
        logger.info(f"   Query execution: {query_start_time.strftime('%H:%M:%S')} - {query_end_time.strftime('%H:%M:%S')}")
        logger.info(f"   Log search window: {log_start_time.strftime('%H:%M:%S')} - {log_end_time.strftime('%H:%M:%S')}")
        logger.info(f"   Buffer duration: {LOG_BUFFER_MINUTES} minutes after query completion")
        logger.info(f"   Total window duration: {((log_end_time - log_start_time).total_seconds() / 60):.1f} minutes")
        flush_logs()
        
        # Simplified approach: Since we know which category each batch of 50 domains belongs to,
        # we'll fetch all logs and filter post-collection by matching against our category domains
        logger.info(f"🎯 Processing category '{category}' - will capture all log types and filter by domain match")
        flush_logs()
        
        # Fetch DNS query logs locally and filter by domains (only when output_format is 'advanced' for debug CSV)
        dns_logs = []
        unique_dns_domains = []
        
        if output_format == 'advanced':
            logger.info(f"🔍 DEBUG OUTPUT MODE: Fetching DNS query logs locally and filtering by domains...")
            dns_logs = fetch_dns_logs(
                project_id=vm_config.get('project_id', vm_config.get('project', 'your-project-id')),
                vm_instance_id=vm_config.get('instance_id', vm_id),
                vm_zone=vm_config.get('zone', 'your-zone'),
                start_time=log_start_time,
                end_time=log_end_time,
                max_entries=MAX_LOG_ENTRIES,
                domains=domains  # Filter logs by domains
            )
            # Extract unique domains from DNS logs and filter by category domains
            unique_dns_domains = extract_unique_domains_from_dns_logs(dns_logs)
            # Filter DNS domains to only include ones from this category
            category_dns_domains = [domain for domain in unique_dns_domains 
                                   if any(domain.lower() == cat_domain.lower() or 
                                         domain.lower().endswith('.' + cat_domain.lower()) or
                                         cat_domain.lower().endswith('.' + domain.lower())
                                         for cat_domain in domains)]
            unique_dns_domains = category_dns_domains
            logger.info(f"✅ DEBUG OUTPUT MODE: Found {len(dns_logs)} DNS query logs, {len(unique_dns_domains)} unique domains")
        else:
            logger.info(f"⚡ NORMAL OUTPUT MODE: Skipping DNS log collection for better performance")
            logger.info("   DNS query details not needed for CSV output in this mode")

        # Fetch threat detection logs locally and filter by domains
        logger.info(f"🔍 Fetching threat detection logs locally and filtering by domains...")
        threat_logs = fetch_threat_detection_logs(
            project_id=vm_config.get('project_id', vm_config.get('project', 'your-project-id')),
            vm_instance_id=vm_config.get('instance_id', vm_id),
            vm_zone=vm_config.get('zone', 'your-zone'),
            start_time=log_start_time,
            end_time=log_end_time,
            max_entries=MAX_LOG_ENTRIES,
            domains=domains,  # Filter logs by domains
            domain_mapping=domain_mapping  # Pass domain mapping for DGA domains
        )
        
        # Extract unique domains from threat logs and filter by category domains
        unique_threat_domains = extract_unique_domains_from_threats(threat_logs)
        # Filter threat domains to only include ones from this category
        category_threat_domains = [domain for domain in unique_threat_domains 
                                 if any(domain.lower() == cat_domain.lower() or 
                                       domain.lower().endswith('.' + cat_domain.lower()) or
                                       cat_domain.lower().endswith('.' + domain.lower())
                                       for cat_domain in domains)]
        
        # Filter the actual log entries to only include ones matching our category domains
        filtered_threat_logs = []
        for log in threat_logs:
            query_name = log.get('query_name', '').rstrip('.').lower()
            if any(query_name == cat_domain.lower() or 
                  query_name.endswith('.' + cat_domain.lower()) or
                  cat_domain.lower().endswith('.' + query_name)
                  for cat_domain in domains):
                filtered_threat_logs.append(log)
                
        # Filter DNS logs only when output_format is 'advanced' (conditional processing)
        filtered_dns_logs = []
        if output_format == 'advanced':
            for log in dns_logs:
                # Get query name from various possible locations in DNS log structure
                query_name = ''
                if 'query_name' in log:
                    query_name = log.get('query_name', '')
                elif 'jsonPayload' in log and 'dnsQuery' in log['jsonPayload']:
                    query_name = log['jsonPayload']['dnsQuery'].get('queryName', '')
                elif 'jsonPayload' in log and 'queryName' in log['jsonPayload']:
                    query_name = log['jsonPayload'].get('queryName', '')
                    
                query_name = query_name.rstrip('.').lower()
                if any(query_name == cat_domain.lower() or 
                      query_name.endswith('.' + cat_domain.lower()) or
                      cat_domain.lower().endswith('.' + query_name)
                      for cat_domain in domains):
                    filtered_dns_logs.append(log)
        
        # Log summary based on output_format
        if output_format == 'advanced':
            logger.info(f"📊 Category '{category}' Log Summary (DEBUG OUTPUT):")
            logger.info(f"   DNS Query Logs (all): {len(dns_logs)} -> (category-filtered): {len(filtered_dns_logs)}")
            logger.info(f"   Threat Detection Logs (all): {len(threat_logs)} -> (category-filtered): {len(filtered_threat_logs)}")
            logger.info(f"   Unique DNS Domains (category-filtered): {len(unique_dns_domains)}")
            logger.info(f"   Unique Threat Domains (category-filtered): {len(category_threat_domains)}")
        else:
            logger.info(f"📊 Category '{category}' Log Summary (NORMAL OUTPUT):")
            logger.info(f"   DNS Query Logs: SKIPPED (not needed for normal output)")
            logger.info(f"   Threat Detection Logs (all): {len(threat_logs)} -> (category-filtered): {len(filtered_threat_logs)}")
            logger.info(f"   Unique Threat Domains (category-filtered): {len(category_threat_domains)}")
        flush_logs()
        
        return {
            'vm_id': vm_id,
            'vm_config': vm_config,
            'category': category,
            'dns_logs': filtered_dns_logs,  # Empty list for normal output modes
            'threat_logs': filtered_threat_logs,  # Use filtered logs
            'unique_threat_domains': category_threat_domains,  # Use filtered domains
            'unique_dns_domains': unique_dns_domains,  # Empty list for normal output modes
            'log_search_hours': hours_back,
            'log_start_time': log_start_time,
            'log_end_time': log_end_time,
            'mode': mode,  # Include mode for reference
            'output_format': output_format  # Include output_format for reference
        }
        
    except Exception as e:
        logger.error(f"❌ Error collecting logs for category '{category}': {e}")
        return {
            'vm_id': vm_id,
            'vm_config': vm_config,
            'category': category,
            'dns_logs': [],
            'threat_logs': [],
            'unique_threat_domains': [],
            'unique_dns_domains': [],
            'error': str(e)
        }


def generate_category_csv(query_results: List[Dict], log_results: List[Dict], output_dir: str, output_format: str = 'basic'):
    """
    Generate category-based CSV file with comprehensive analytics.
    
    Args:
        query_results (list): Results from DNS query execution per category
        log_results (list): Results from log collection per category
        output_dir (str): Output directory for CSV file
        output_format (str): Output format to determine CSV headers ('basic' or 'advanced')
    """
    try:
        # Check for alternative output directory from environment
        alt_output_dir = os.environ.get('CATEGORY_OUTPUT_DIR')
        if alt_output_dir and os.path.exists(alt_output_dir) and os.access(alt_output_dir, os.W_OK):
            output_dir = alt_output_dir
            logger.info(f"📁 Using alternative output directory: {output_dir}")
        
        # Ensure output directory exists with error handling
        try:
            os.makedirs(output_dir, exist_ok=True)
        except PermissionError:
            logger.error(f"❌ Permission denied creating directory: {output_dir}")
            # Try alternative in user's home directory
            fallback_dir = os.path.expanduser(f"~/category_analysis_output_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
            logger.info(f"🔄 Trying fallback directory: {fallback_dir}")
            os.makedirs(fallback_dir, exist_ok=True)
            output_dir = fallback_dir
        
        output_path = os.path.join(output_dir, CATEGORY_OUTPUT_CSV_FILE)
        
        # Test write permissions before proceeding
        try:
            test_file = os.path.join(output_dir, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except (PermissionError, OSError) as e:
            logger.error(f"❌ Cannot write to output directory {output_dir}: {e}")
            # Final fallback to temp directory
            import tempfile
            output_dir = tempfile.mkdtemp(prefix='category_analysis_')
            output_path = os.path.join(output_dir, CATEGORY_OUTPUT_CSV_FILE)
            logger.info(f"🔄 Using temporary directory: {output_dir}")
        
        # Create analytics data based on output format
        csv_headers = get_csv_headers_for_output_format(output_format)
        csv_data = []
        all_unique_domains = set()
        all_unique_dns_domains = set()
        
        # Create category results lookup
        category_log_lookup = {result['category']: result for result in log_results}
        
        for query_result in query_results:
            category = query_result['category']
            
            # Get corresponding log results
            log_result = category_log_lookup.get(category, {})
            
            # Calculate metrics with selective deduplication
            client_dns_query_domain = query_result.get('total_queries', 0)  # Total domains queried (not deduplicated)
            total_threat_count = len(log_result.get('threat_logs', []))  # Total threat logs found (not deduplicated)
            unique_domains_for_category = log_result.get('unique_threat_domains', [])
            
            # Get dig results to calculate corrected detection rate
            dig_results = query_result.get('dig_results', {})
            successful_dig_domains = set()
            for domain in query_result.get('domains', []):
                dig_result = dig_results.get(domain, {})
                if dig_result.get('status') == 'success':
                    successful_dig_domains.add(domain)
            
            # Calculate domains that had successful DNS queries AND were detected as threats
            dig_success_threat_domains = successful_dig_domains.intersection(set(unique_domains_for_category))
            dig_success_threat_count = len(dig_success_threat_domains)
            
            # Add to global unique domains sets
            all_unique_domains.update(unique_domains_for_category)
            
            # Calculate corrected detection rate: (Successful Dig Threats / Total Queried Domains) * 100
            # This accounts for DNS query failures properly
            if client_dns_query_domain > 0:
                if category == 'DNST_Tunneling':
                    # For DNST: 100% if any threats detected, 0% if none
                    # This accounts for the fact that DNST generates many DNS queries (segments)
                    # but only one threat event that represents detection of the entire session
                    detection_rate = 100.0 if dig_success_threat_count > 0 else 0.0
                    logger.info(f"🔗 DNST Detection Logic for {category}: {client_dns_query_domain} domain(s) tested, "
                              f"{dig_success_threat_count} threat event(s) detected → {detection_rate}% detection rate")
                else:
                    # Corrected calculation: successful dig threats / total domains attempted
                    detection_rate = round((dig_success_threat_count / client_dns_query_domain) * 100, 2)
                    logger.info(f"📊 Detection Rate Calculation for {category}: {dig_success_threat_count} successful dig threats "
                              f"from {client_dns_query_domain} domains attempted → {detection_rate}%")
            else:
                detection_rate = 0.0
            
            # Create CSV row based on output format
            if output_format == 'advanced':
                # Advanced output format: Include DNS query details
                dns_query_in_dns_logs = len(log_result.get('dns_logs', []))  # Total DNS logs found (not deduplicated)
                unique_dns_domains_for_category = log_result.get('unique_dns_domains', [])
                distinct_domains_in_dns_logs = len(unique_dns_domains_for_category)  # Distinct DNS domains count
                
                all_unique_dns_domains.update(unique_dns_domains_for_category)
                
                csv_row = {
                    'Domain Category': category,
                    'Client DNS Query Domain': client_dns_query_domain,
                    'DNS Query in DNS logs': dns_query_in_dns_logs,
                    'Distinct domains in DNS logs': distinct_domains_in_dns_logs,
                    'Total Threat Count': total_threat_count,
                    'Distinct domain Threat Count': dig_success_threat_count,  # Use corrected count
                    'Detection Rate (%)': detection_rate
                }
            else:
                # Normal mode: Include threat analysis with detection rates (no DNS log details)
                csv_row = {
                    'Domain Category': category,
                    'Client DNS Query Domain': client_dns_query_domain,
                    'Total Threat Count': total_threat_count,
                    'Distinct domain Threat Count': dig_success_threat_count,  # Use corrected count
                    'Detection Rate (%)': detection_rate
                }
            
            csv_data.append(csv_row)
        
        # Add summary row with totals based on output format
        total_client_dns_queries = sum(row['Client DNS Query Domain'] for row in csv_data)
        total_threat_counts = sum(row['Total Threat Count'] for row in csv_data)
        total_unique_domains = len(all_unique_domains)
        
        if output_format == 'advanced':
            total_dns_queries = sum(row['DNS Query in DNS logs'] for row in csv_data)
            total_distinct_dns_domains = len(all_unique_dns_domains)
            
            # Calculate overall detection rate using corrected formula for debug mode
            if total_client_dns_queries > 0:
                overall_detection_rate = round((total_unique_domains / total_client_dns_queries) * 100, 2)
            else:
                overall_detection_rate = 0.0
            
            total_row = {
                'Domain Category': 'TOTAL',
                'Client DNS Query Domain': total_client_dns_queries,
                'DNS Query in DNS logs': total_dns_queries,
                'Distinct domains in DNS logs': total_distinct_dns_domains,
                'Total Threat Count': total_threat_counts,
                'Distinct domain Threat Count': total_unique_domains,
                'Detection Rate (%)': overall_detection_rate
            }
        else:
            # Calculate overall detection rate using corrected formula for normal mode
            if total_client_dns_queries > 0:
                overall_detection_rate = round((total_unique_domains / total_client_dns_queries) * 100, 2)
            else:
                overall_detection_rate = 0.0
                
            total_row = {
                'Domain Category': 'TOTAL',
                'Client DNS Query Domain': total_client_dns_queries,
                'Total Threat Count': total_threat_counts,
                'Distinct domain Threat Count': total_unique_domains,
                'Detection Rate (%)': overall_detection_rate
            }
        
        csv_data.append(total_row)
        
        # Write CSV file
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
            writer.writeheader()
            
            # Add file exfiltration simulation note
            note_row = {}
            for header in csv_headers:
                if header == 'Domain Category':
                    note_row[header] = "NOTE: SIMULATION"
                elif header == 'Client DNS Query Domain':
                    note_row[header] = "For simulating DNST we are using 1 TLD as input for exfiltration and we get multiple events with same TLD "
                else:
                    note_row[header] = ""
            writer.writerow(note_row)
            
            # Add empty row for separation
            empty_row = {header: "" for header in csv_headers}
            writer.writerow(empty_row)
            
            # Write actual data
            writer.writerows(csv_data)
        
        logger.info("="*80)
        logger.info("📊 THREAT DETECTION SIMULATION SUMMARY")
        logger.info("="*80)
        logger.info("⚠️  NOTE: SIMULATION - For simulating DNST we are using 1 TLD as input for exfiltration and we get multiple events with same TLD ")
        logger.info("="*80)
        logger.info(f"📁 CSV file generated: {output_path}")
        logger.info(f"🎯 Output Format: {output_format.upper()}")
        logger.info("")
        logger.info("📈 Category Breakdown:")
        
        for row in csv_data:
            if row['Domain Category'] != 'TOTAL':
                if output_format == 'advanced':
                    logger.info(f"   {row['Domain Category']:20} | Client: {row['Client DNS Query Domain']:3} | DNS: {row['DNS Query in DNS logs']:3} | DNS Domains: {row['Distinct domains in DNS logs']:3} | Threats: {row['Total Threat Count']:3} | Threat Domains: {row['Distinct domain Threat Count']:3} | Detection: {row['Detection Rate (%)']:6.2f}%")
                else:
                    logger.info(f"   {row['Domain Category']:20} | Client: {row['Client DNS Query Domain']:3} | Threats: {row['Total Threat Count']:3} | Threat Domains: {row['Distinct domain Threat Count']:3}")
        
        logger.info("-"*130)
        if output_format == 'advanced':
            total_row = next((row for row in csv_data if row['Domain Category'] == 'TOTAL'), None)
            if total_row:
                logger.info(f"   {'TOTAL':20} | Client: {total_client_dns_queries:3} | DNS: {total_dns_queries:3} | DNS Domains: {total_distinct_dns_domains:3} | Threats: {total_threat_counts:3} | Threat Domains: {total_unique_domains:3} | Detection: {total_row['Detection Rate (%)']:6.2f}%")
            else:
                logger.info(f"   {'TOTAL':20} | Client: {total_client_dns_queries:3} | DNS: {total_dns_queries:3} | DNS Domains: {total_distinct_dns_domains:3} | Threats: {total_threat_counts:3} | Threat Domains: {total_unique_domains:3}")
        else:
            logger.info(f"   {'TOTAL':20} | Client: {total_client_dns_queries:3} | Threats: {total_threat_counts:3} | Threat Domains: {total_unique_domains:3}")
        logger.info("="*80)
        flush_logs()
        
    except Exception as e:
        logger.error(f"❌ Error generating category CSV file: {e}")
        raise


def generate_category_json_files(query_results: List[Dict], log_results: List[Dict], output_dir: str):
    """
    Generate per-category JSON files for threat events, DNS logs, and non-detected domains.
    Creates separate files for each domain category with comprehensive analysis data.
    
    Args:
        query_results (list): Results from DNS query execution per category
        log_results (list): Results from log collection per category
        output_dir (str): Output directory for JSON files
        
    Generated Files:
        - threat_event_{category}.json: Threat detection events for the category
        - dns_logs_{category}.json: DNS query logs for the category  
        - non_detected_domains_{category}.json: Analysis of non-detected domains
    """
    try:
        # Check for alternative output directory from environment
        alt_output_dir = os.environ.get('CATEGORY_OUTPUT_DIR')
        if alt_output_dir and os.path.exists(alt_output_dir) and os.access(alt_output_dir, os.W_OK):
            output_dir = alt_output_dir
            logger.info(f"📁 Using alternative output directory: {output_dir}")
        
        # Ensure output directory exists with error handling
        try:
            os.makedirs(output_dir, exist_ok=True)
        except PermissionError:
            logger.error(f"❌ Permission denied creating directory: {output_dir}")
            # Try alternative in user's home directory
            fallback_dir = os.path.expanduser(f"~/category_analysis_output_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
            logger.info(f"🔄 Trying fallback directory: {fallback_dir}")
            os.makedirs(fallback_dir, exist_ok=True)
            output_dir = fallback_dir
        
        # Test write permissions before proceeding
        try:
            test_file = os.path.join(output_dir, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except (PermissionError, OSError) as e:
            logger.error(f"❌ Cannot write to output directory {output_dir}: {e}")
            # Final fallback to temp directory
            import tempfile
            output_dir = tempfile.mkdtemp(prefix='category_analysis_')
            logger.info(f"🔄 Using temporary directory: {output_dir}")
        
        # Create category results lookup
        category_log_lookup = {result['category']: result for result in log_results}
        
        total_threat_files = 0
        total_dns_files = 0
        total_non_detected_files = 0
        
        for query_result in query_results:
            category = query_result['category']
            vm_config = query_result['vm_config']
            
            # Get corresponding log results
            log_result = category_log_lookup.get(category, {})
            
            # Create safe filename from category name
            safe_category = category.replace('&', 'and').replace(' ', '_').replace('/', '_')
            
            # Generate threat events JSON for this category
            threat_events = log_result.get('threat_logs', [])
            if threat_events:
                threat_filename = f"threat_event_{safe_category}.json"
                threat_path = os.path.join(output_dir, threat_filename)
                
                threat_data = {
                    "category_metadata": {
                        "domain_category": category,
                        "vm_id": query_result['vm_id'],
                        "region": vm_config.get('region'),
                        "zone": vm_config.get('zone'),
                        "instance_name": vm_config.get('name'),
                        "external_ip": vm_config.get('external_ip'),
                        "internal_ip": vm_config.get('internal_ip')
                    },
                    "query_summary": {
                        "total_domains_queried": query_result.get('total_queries', 0),
                        "successful_queries": query_result.get('successful_queries', 0),
                        "failed_queries": query_result.get('failed_queries', 0),
                        "execution_time_seconds": query_result.get('execution_time', 0)
                    },
                    "threat_detection_summary": {
                        "total_threat_events": len(threat_events),
                        "unique_threat_domains": len(log_result.get('unique_threat_domains', [])),
                        "threat_domains": log_result.get('unique_threat_domains', [])
                    },
                    "threat_events": threat_events
                }
                
                with open(threat_path, 'w') as f:
                    json.dump(threat_data, f, indent=2, default=str)
                
                total_threat_files += 1
                logger.info(f"📄 Generated threat events file: {threat_filename} ({len(threat_events)} events)")
            
            # Generate DNS logs JSON for this category
            dns_logs = log_result.get('dns_logs', [])
            if dns_logs:
                dns_filename = f"dns_logs_{safe_category}.json"
                dns_path = os.path.join(output_dir, dns_filename)
                
                dns_data = {
                    "category_metadata": {
                        "domain_category": category,
                        "vm_id": query_result['vm_id'],
                        "region": vm_config.get('region'),
                        "zone": vm_config.get('zone'),
                        "instance_name": vm_config.get('name'),
                        "external_ip": vm_config.get('external_ip'),
                        "internal_ip": vm_config.get('internal_ip')
                    },
                    "query_summary": {
                        "total_domains_queried": query_result.get('total_queries', 0),
                        "successful_queries": query_result.get('successful_queries', 0),
                        "failed_queries": query_result.get('failed_queries', 0),
                        "execution_time_seconds": query_result.get('execution_time', 0)
                    },
                    "dns_logs_summary": {
                        "total_dns_logs": len(dns_logs),
                        "unique_queried_domains": len(log_result.get('unique_dns_domains', [])),
                        "unique_domains_list": log_result.get('unique_dns_domains', []),
                        "log_time_range": {
                            "earliest": min(log.get('timestamp', '') for log in dns_logs) if dns_logs else None,
                            "latest": max(log.get('timestamp', '') for log in dns_logs) if dns_logs else None
                        }
                    },
                    "dns_logs": dns_logs
                }
                
                with open(dns_path, 'w') as f:
                    json.dump(dns_data, f, indent=2, default=str)
                
                total_dns_files += 1
                logger.info(f"📋 Generated DNS logs file: {dns_filename} ({len(dns_logs)} logs)")
            
            # Generate non-detected domains JSON for this category
            queried_domains = set(query_result.get('domains', []))
            threat_domains = set(log_result.get('unique_threat_domains', []))
            
            # Get dig results to analyze DNS query success/failure
            dig_results = query_result.get('dig_results', {})
            
            # Categorize domains based on dig results
            successful_dig_domains = set()
            failed_dig_domains = {}  # domain -> error info
            
            for domain in queried_domains:
                dig_result = dig_results.get(domain, {})
                if dig_result.get('status') == 'success':
                    successful_dig_domains.add(domain)
                else:
                    # This domain had a dig failure
                    failed_dig_domains[domain] = {
                        'error': dig_result.get('error', 'Unknown dig error'),
                        'command': dig_result.get('command', 'Unknown command')
                    }
            
            # Calculate domains that had successful DNS queries AND were detected as threats
            dig_success_threat_domains = successful_dig_domains.intersection(threat_domains)
            
            # For DNST tunneling, detection should be based on any queried domain that appears in threats
            # (regardless of dig success/failure) since DNST is designed to fail DNS queries
            if 'DNST' in category.upper() or 'TUNNELING' in category.upper():
                # DNST detection: any queried domain that appears in threat domains
                actual_threat_detected_domains = queried_domains.intersection(threat_domains)
                actual_threat_detected_count = len(actual_threat_detected_domains)
                # For DNST, non-detected are queried domains that are NOT in threat domains
                non_detected_domains = list(queried_domains - threat_domains)
            else:
                # Standard detection: only successful dig queries that are also in threat domains
                actual_threat_detected_domains = dig_success_threat_domains
                actual_threat_detected_count = len(dig_success_threat_domains)
                # For standard categories, non-detected are successful digs that are NOT in threat domains
                non_detected_domains = list(successful_dig_domains - threat_domains)
            
            # Domains that were successfully queried but NOT detected as threats (kept for backward compatibility)
            # This is now only used for the old-style non_detected_domains field
            
            if queried_domains:  # Always create file if domains were queried
                non_detected_filename = f"non_detected_domains_{safe_category}.json"
                non_detected_path = os.path.join(output_dir, non_detected_filename)
                
                non_detected_data = {
                    "category_metadata": {
                        "domain_category": category,
                        "vm_id": query_result['vm_id'],
                        "region": vm_config.get('region'),
                        "zone": vm_config.get('zone'),
                        "instance_name": vm_config.get('name'),
                        "external_ip": vm_config.get('external_ip'),
                        "internal_ip": vm_config.get('internal_ip')
                    },
                    "analysis_summary": {
                        "total_queried_domains": len(queried_domains),
                        "successful_dig_queries": len(successful_dig_domains),
                        "failed_dig_queries": len(failed_dig_domains),
                        "total_threat_detected_domains": len(actual_threat_detected_domains),
                        "total_non_detected_domains": len(non_detected_domains),
                        "detection_rate_percent": round((len(actual_threat_detected_domains) / len(queried_domains) * 100), 2) if queried_domains else 0.0
                    },
                    "queried_domains": sorted(queried_domains),
                    "successful_dig_domains": sorted(successful_dig_domains),
                    "failed_dig_domains": [
                        {
                            "domain": domain,
                            "error": error_info['error'],
                            "command": error_info.get('command', 'Unknown command')
                        }
                        for domain, error_info in failed_dig_domains.items()
                    ],
                    "threat_detected_domains": sorted(actual_threat_detected_domains),
                    "non_detected_domains": sorted(non_detected_domains)
                }
                
                with open(non_detected_path, 'w') as f:
                    json.dump(non_detected_data, f, indent=2, default=str)
                
                total_non_detected_files += 1
                logger.info(f"📊 Generated non-detected domains file: {non_detected_filename}")
                logger.info(f"   • Total queried domains: {len(queried_domains)}")
                logger.info(f"   • Successful dig queries: {len(successful_dig_domains)}")
                logger.info(f"   • Failed dig queries: {len(failed_dig_domains)}")
                logger.info(f"   • Threat detected domains: {len(dig_success_threat_domains)}")
                logger.info(f"   • Non-detected domains: {len(non_detected_domains)}")
                logger.info(f"   • Detection rate: {round((len(dig_success_threat_domains) / len(queried_domains) * 100), 2) if queried_domains else 0.0}%")
        
        logger.info("="*80)
        logger.info("📁 PER-CATEGORY JSON FILES SUMMARY")
        logger.info("="*80)
        logger.info(f"🎯 Total threat event files: {total_threat_files}")
        logger.info(f"📋 Total DNS logs files: {total_dns_files}")
        logger.info(f"📊 Total non-detected domains files: {total_non_detected_files}")
        logger.info(f"📁 All files saved to: {output_dir}")
        logger.info("="*80)
        flush_logs()
        
    except Exception as e:
        logger.error(f"❌ Error generating per-category JSON files: {e}")
        raise


def main():
    """
    Main function to execute the category-based analysis script.
    """
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        logger.info("🚀 Starting Threat Detection Simulator")
        logger.info("="*80)
        logger.info(f"🎯 Execution Mode: {args.mode.upper()}")
        
        if args.mode == 'debug':
            logger.info("🔍 DEBUG MODE: Processing existing domains only")
            logger.info("   - Includes DNS query details in CSV output")
        elif args.mode == 'basic':
            logger.info(f"🤖 BASIC MODE: Processing existing domains + {args.dga_count} DGA domains")
            logger.info("   - Standard CSV output without DNS query details")
        elif args.mode == 'advanced':
            logger.info(f"🚀 ADVANCED MODE: Processing existing + {args.dga_count} DGA + DNST domains")
            logger.info(f"   - DNST domain: {args.dnst_domain}")
            if args.dnst_ip:
                logger.info(f"   - DNST IP: {args.dnst_ip}")
            logger.info("   - Standard CSV output without DNS query details")
        
        logger.info("="*80)
        flush_logs()
        
        # Dynamically detect VM metadata from GCP metadata server
        logger.info("Detecting VM metadata...")
        vm_config = get_vm_metadata()
        
        if not vm_config:
            logger.error("❌ Could not detect VM metadata. This script must run on a GCP VM.")
            logger.error("   Please ensure:")
            logger.error("   1. You are running this script on a GCP Compute Engine VM")
            logger.error("   2. The VM has access to metadata server (metadata.google.internal)")
            logger.error("   3. gcloud CLI is installed and authenticated")
            sys.exit(1)
        
        # Use the detected VM information
        vm_id = vm_config['instance_id']
        logger.info("✅ VM Detection Successful!")
        logger.info(f"📍 VM Instance ID: {vm_id}")
        logger.info(f"📍 VM Name: {vm_config.get('name', 'N/A')}")
        logger.info(f"📍 Project ID: {vm_config.get('project_id', 'N/A')}")
        logger.info(f"📍 Zone: {vm_config.get('zone', 'N/A')}")
        logger.info(f"📍 Region: {vm_config.get('region', 'N/A')}")
        flush_logs()
        
        # Load category indicators with TTL cache support
        logger.info("📥 Loading category indicators...")
        if args.ttl > 0:
            logger.info(f"⏰ TTL-based domain caching enabled: {args.ttl} seconds ({args.ttl/60:.1f} minutes)")
        category_file = os.path.join(os.path.dirname(__file__), CATEGORY_INDICATORS_FILE)
        all_categories = load_category_indicators(category_file, CATEGORY_OUTPUT_DIR, args.ttl)
        
        if not all_categories:
            raise Exception("No domain categories loaded from indicators file")
        
        # Filter to only include supported threat categories
        logger.info("🎯 Filtering for supported threat categories...")
        supported_categories = get_supported_categories()
        categories = {}
        
        for category, domains in all_categories.items():
            if is_category_supported(category):
                categories[category] = domains
                logger.info(f"✅ {category}: Supported (has threat filter)")
            else:
                logger.info(f"⚠️ {category}: Not supported (no threat filter defined), skipping...")
        
        if not categories:
            raise Exception("No supported threat categories found. Please check threat_categories.py")
        
        logger.info(f"📋 Processing {len(categories)} supported categories out of {len(all_categories)} total categories")
        
        # Generate additional domains based on execution mode
        logger.info(f"\n🎲 Generating additional domains for {args.mode} mode...")
        additional_domains, domain_mapping, execution_config = generate_additional_domains(
            mode=args.mode,
            dga_count=args.dga_count,
            dnst_domain=args.dnst_domain,
            dnst_ip=args.dnst_ip
        )
        
        # Merge additional domains with existing categories
        if additional_domains:
            categories.update(additional_domains)
            logger.info(f"✅ Added {len(additional_domains)} additional domain categories")
            for category, domains in additional_domains.items():
                logger.info(f"   {category}: {len(domains)} domains")
        
        flush_logs()
        
        # Log category overview
        logger.info("📋 Category Overview:")
        total_sampled_domains = 0
        for category, domains in categories.items():
            total_sampled_domains += len(domains)
            logger.info(f"   {category}: {len(domains)} domains (showing first 3: {domains[:3]})")
        logger.info(f"📊 Total domains to process: {total_sampled_domains}")
        flush_logs()
        
        # STEP 1: Execute DNS queries for each category
        logger.info(f"\n🔍 STEP 1: Executing DNS queries for each category on {vm_id}")
        logger.info("="*60)
        flush_logs()
        
        query_results = []
        additional_execution_results = {}
        
        # First execute additional domains (DGA/DNST) with precise timing
        if execution_config:
            logger.info(f"\n🎯 Executing additional domain queries with precise timing...")
            additional_execution_results = execute_additional_domains(execution_config, categories)
            flush_logs()
        
        # Then execute regular category domains
        for category, domains in categories.items():
            try:
                logger.info(f"🔄 Processing category: {category}")
                
                # Check if this is an additional domain category that was already executed
                if category in additional_execution_results and additional_execution_results[category].get('success', False):
                    # Use the precise timing from additional execution
                    exec_result = additional_execution_results[category]
                    dig_results = exec_result.get('dig_results', {})
                    successful_queries = sum(1 for result in dig_results.values() if result.get('status') == 'success')
                    result = {
                        'vm_id': vm_id,
                        'vm_config': vm_config,
                        'category': category,
                        'domains': exec_result['domains'],
                        'total_queries': len(exec_result['domains']),
                        'successful_queries': successful_queries,
                        'failed_queries': len(exec_result['domains']) - successful_queries,
                        'execution_time': exec_result['execution_time'],
                        'start_time': exec_result['start_time'],
                        'end_time': exec_result['end_time'],
                        'dig_results': dig_results,
                        'batches_processed': 1,
                        'additional_domain_category': True
                    }
                    query_results.append(result)
                    logger.info(f"✅ Used precise timing for {category}: {exec_result['execution_time']:.1f}s")
                    continue
                result = execute_queries_for_category(vm_id, vm_config, category, domains)
                query_results.append(result)
            except Exception as e:
                logger.error(f"❌ Category {category} query execution failed: {e}")
                # Add error result
                query_results.append({
                    'vm_id': vm_id,
                    'vm_config': vm_config,
                    'category': category,
                    'domains': domains,
                    'total_queries': len(domains),
                    'successful_queries': 0,
                    'error': str(e),
                    'dig_results': {}
                })
        
        # Summary of query execution
        total_successful_queries = sum(result.get('successful_queries', 0) for result in query_results)
        total_domains = sum(result.get('total_queries', 0) for result in query_results)
        total_execution_time = sum(result.get('execution_time', 0) for result in query_results)
        total_batches = sum(result.get('batches_processed', 0) for result in query_results)
        
        logger.info(f"\n📊 Query Execution Summary:")
        logger.info(f"   Total categories: {len(categories)}")
        logger.info(f"   Total domains: {total_domains}")
        logger.info(f"   Total successful queries: {total_successful_queries}")
        logger.info(f"   Total execution time: {total_execution_time:.1f} seconds")
        logger.info(f"   Total batches processed: {total_batches}")
        logger.info(f"   Average batch size: {total_domains / total_batches:.1f} domains" if total_batches > 0 else "")
        flush_logs()
        
        # STEP 2: Wait time for log propagation with extended time windows
        propagation_delay = 30  # 30 seconds initial delay - extended time windows provide better coverage
        logger.info(f"\n⏳ STEP 2: Waiting {propagation_delay} seconds for log propagation...")
        logger.info(f"   (Extended {LOG_BUFFER_MINUTES}-minute time windows ensure comprehensive log capture)")
        logger.info("="*60)
        time.sleep(propagation_delay)
        flush_logs()
        
        # STEP 3: Collect logs for each category using dynamic time windows
        logger.info(f"\n📊 STEP 3: Collecting DNS logs and threat detections for each category")
        logger.info("="*60)
        flush_logs()
        
        log_results = []
        for query_result in query_results:
            try:
                result = collect_logs_for_category(
                    query_result['vm_id'],
                    query_result['vm_config'],
                    query_result['category'],
                    query_result['start_time'],
                    query_result['end_time'],
                    query_result['domains'],
                    args.mode,  # Pass the execution mode
                    domain_mapping,  # Pass domain mapping for DGA domains
                    args.output_format  # Pass the output format for DNS log collection control
                )
                log_results.append(result)
            except Exception as e:
                logger.error(f"❌ Category {query_result['category']} log collection failed: {e}")
                # Add error result
                log_results.append({
                    'vm_id': query_result['vm_id'],
                    'vm_config': query_result['vm_config'],
                    'category': query_result['category'],
                    'dns_logs': [],
                    'threat_logs': [],
                    'unique_threat_domains': [],
                    'unique_dns_domains': [],
                    'error': str(e)
                })
        
        # Summary of log collection
        total_dns_logs = sum(len(result.get('dns_logs', [])) for result in log_results)
        total_threat_logs = sum(len(result.get('threat_logs', [])) for result in log_results)
        all_unique_domains = set()
        for result in log_results:
            all_unique_domains.update(result.get('unique_threat_domains', []))
        
        logger.info(f"\n📊 Log Collection Summary:")
        logger.info(f"   Total DNS query logs: {total_dns_logs}")
        logger.info(f"   Total threat detection logs: {total_threat_logs}")
        logger.info(f"   Total unique threat domains: {len(all_unique_domains)}")
        
        # Show per-category details
        logger.info(f"\n🔍 Per-Category Log Collection Details:")
        for result in log_results:
            category = result['category']
            dns_count = len(result.get('dns_logs', []))
            threat_count = len(result.get('threat_logs', []))
            unique_count = len(result.get('unique_threat_domains', []))
            logger.info(f"   {category:20} | DNS: {dns_count:3} | Threats: {threat_count:3} | Unique: {unique_count:2}")
        flush_logs()
        
        # STEP 4: Generate CSV report and per-category JSON files
        logger.info(f"\n📈 STEP 4: Generating category analysis reports")
        logger.info("="*60)
        flush_logs()
        
        output_dir = os.path.join(os.path.dirname(__file__), CATEGORY_OUTPUT_DIR)
        generate_category_csv(query_results, log_results, output_dir, args.output_format)
        generate_category_json_files(query_results, log_results, output_dir)
        
        # STEP 5: Save domain cache for TTL-based filtering
        if args.ttl > 0:
            logger.info(f"\n💾 STEP 5: Saving domain cache with TTL {args.ttl} seconds")
            logger.info("="*60)
            logger.info("ℹ️  DNST domains excluded from cache (dynamically generated per run)")
            
            # Collect all used domains from query results (exclude DNST domains)
            used_domains = {}
            for result in query_results:
                category = result['category']
                
                # Skip DNST domains as they are dynamically generated and unique per run
                if category == 'DNST_Tunneling':
                    continue
                    
                if category not in used_domains:
                    used_domains[category] = []
                
                # Add domain from this query result
                domain = result.get('domain', '')
                if domain and domain not in used_domains[category]:
                    used_domains[category].append(domain)
            
            # Also include additional domains if they were processed (exclude DNST)
            if additional_domains:
                for category, domains in additional_domains.items():
                    # Skip DNST domains as they are dynamically generated and unique per run
                    if category == 'DNST_Tunneling':
                        continue
                        
                    if category not in used_domains:
                        used_domains[category] = []
                    for domain in domains:
                        if domain not in used_domains[category]:
                            used_domains[category].append(domain)
            
            # Save the cache
            save_domain_cache(output_dir, used_domains)
            flush_logs()
        
        logger.info("🎉 Category analysis execution completed successfully!")
        logger.info("="*80)
        flush_logs()
        
    except Exception as e:
        logger.error(f"💥 Category analysis execution failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
