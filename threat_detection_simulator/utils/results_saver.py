"""
Results saver module for v2 threat detection simulator.
Implements v1-compatible output file generation.
"""

import os
import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Constants from v1
CATEGORY_OUTPUT_CSV_FILE = "threat_detection_results.csv"
CATEGORY_OUTPUT_DIR = "category_output"
DOMAIN_CACHE_FILE = "domain_cache.json"

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


def generate_category_json_files(threat_results: Dict, dig_results: Dict, output_dir: str, vm_metadata: Dict):
    """
    Generate per-category JSON files for threat events, DNS logs, and non-detected domains.
    Creates separate files for each domain category with comprehensive analysis data.
    
    Args:
        threat_results (Dict): Results from threat detection per category
        dig_results (Dict): Results from DNS resolution per category  
        output_dir (str): Output directory for JSON files
        vm_metadata (Dict): VM metadata for enrichment
        
    Generated Files:
        - threat_event_{category}.json: Threat detection events for the category
        - dns_logs_{category}.json: DNS query logs for the category  
        - non_detected_domains_{category}.json: Analysis of non-detected domains
    """
    try:
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
        
        total_threat_files = 0
        total_dns_files = 0
        total_non_detected_files = 0
        
        for category_name, threat_result in threat_results.items():
            # Get corresponding dig results
            dig_result = dig_results.get(category_name)
            if not dig_result:
                logger.warning(f"⚠️ No dig results found for category {category_name}")
                continue
            
            # Create safe filename from category name
            safe_category = category_name.replace('&', 'and').replace(' ', '_').replace('/', '_')
            
            # Generate threat events JSON for this category
            threat_events = getattr(threat_result, 'threat_events', [])
            if threat_events:
                threat_filename = f"threat_event_{safe_category}.json"
                threat_path = os.path.join(output_dir, threat_filename)
                
                threat_data = {
                    "category_metadata": {
                        "domain_category": category_name,
                        "vm_id": vm_metadata.get('instance_id', 'unknown'),
                        "region": vm_metadata.get('region', 'unknown'),
                        "zone": vm_metadata.get('zone', 'unknown'),
                        "instance_name": vm_metadata.get('instance_name', 'unknown'),
                        "external_ip": vm_metadata.get('external_ip', 'unknown'),
                        "internal_ip": vm_metadata.get('internal_ip', 'unknown')
                    },
                    "query_summary": {
                        "total_domains_queried": len(dig_result.domains),
                        "successful_queries": len(dig_result.successful_domains),
                        "failed_queries": len(dig_result.domains) - len(dig_result.successful_domains),
                        "execution_time_seconds": getattr(dig_result, 'execution_time', 0)
                    },
                    "threat_detection_summary": {
                        "total_threat_events": len(threat_events),
                        "unique_threat_domains": len(threat_result.detected_domains),
                        "threat_domains": list(threat_result.detected_domains)
                    },
                    "threat_events": threat_events
                }
                
                with open(threat_path, 'w') as f:
                    json.dump(threat_data, f, indent=2, default=str)
                
                total_threat_files += 1
                logger.info(f"📄 Generated threat events file: {threat_filename} ({len(threat_events)} events)")
            else:
                # Create empty threat events file
                threat_filename = f"threat_event_{safe_category}.json"
                threat_path = os.path.join(output_dir, threat_filename)
                
                empty_threat_data = {
                    "category_metadata": {
                        "domain_category": category_name,
                        "vm_id": vm_metadata.get('instance_id', 'unknown'),
                        "region": vm_metadata.get('region', 'unknown'),
                        "zone": vm_metadata.get('zone', 'unknown'),
                        "instance_name": vm_metadata.get('instance_name', 'unknown'),
                        "external_ip": vm_metadata.get('external_ip', 'unknown'),
                        "internal_ip": vm_metadata.get('internal_ip', 'unknown')
                    },
                    "query_summary": {
                        "total_domains_queried": len(dig_result.domains),
                        "successful_queries": len(dig_result.successful_domains),
                        "failed_queries": len(dig_result.domains) - len(dig_result.successful_domains),
                        "execution_time_seconds": getattr(dig_result, 'execution_time', 0)
                    },
                    "threat_detection_summary": {
                        "total_threat_events": 0,
                        "unique_threat_domains": 0,
                        "threat_domains": []
                    },
                    "threat_events": []
                }
                
                with open(threat_path, 'w') as f:
                    json.dump(empty_threat_data, f, indent=2, default=str)
                
                total_threat_files += 1
                logger.info(f"📄 Generated empty threat events file: {threat_filename}")
            
            # Generate DNS logs JSON for this category - always create, but may be empty
            dns_logs = getattr(threat_result, 'dns_logs', [])
            dns_filename = f"dns_logs_{safe_category}.json"
            dns_path = os.path.join(output_dir, dns_filename)
            
            dns_data = {
                "category_metadata": {
                    "domain_category": category_name,
                    "vm_id": vm_metadata.get('instance_id', 'unknown'),
                    "region": vm_metadata.get('region', 'unknown'),
                    "zone": vm_metadata.get('zone', 'unknown'),
                    "instance_name": vm_metadata.get('instance_name', 'unknown'),
                    "external_ip": vm_metadata.get('external_ip', 'unknown'),
                    "internal_ip": vm_metadata.get('internal_ip', 'unknown')
                },
                "query_summary": {
                    "total_domains_queried": len(dig_result.domains),
                    "successful_queries": len(dig_result.successful_domains),
                    "failed_queries": len(dig_result.domains) - len(dig_result.successful_domains),
                    "execution_time_seconds": getattr(dig_result, 'execution_time', 0)
                },
                "dns_logs_summary": {
                    "total_dns_logs": len(dns_logs),
                    "unique_queried_domains": len(set(dig_result.successful_domains)),
                    "unique_domains_list": list(set(dig_result.successful_domains)),
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
            if dns_logs:
                logger.info(f"📋 Generated DNS logs file: {dns_filename} ({len(dns_logs)} logs)")
            else:
                logger.info(f"📋 Generated empty DNS logs file: {dns_filename}")
            
            # Generate non-detected domains JSON for this category
            # Use raw sampled domains count (may include duplicates) for consistency with CSV/logs.
            raw_queried_domains = list(dig_result.domains)
            distinct_queried_domains = list(dict.fromkeys(dig_result.domains))
            threat_domains = set(threat_result.detected_domains)
            successful_dig_domains = set(dig_result.successful_domains)  # distinct successful domains
            failed_dig_domains = set(dig_result.domains) - set(dig_result.successful_domains)
            
            # DNST logic remains based on queried domains intersection with threat domains
            if 'DNST' in category_name.upper() or 'TUNNELING' in category_name.upper():
                # DNST: treat any raw queried domain intersecting threat domains as detected
                non_detected_domains = list(set(raw_queried_domains) - threat_domains)
            else:
                non_detected_domains = list(successful_dig_domains - threat_domains)
            
            if raw_queried_domains:
                non_detected_filename = f"non_detected_domains_{safe_category}.json"
                non_detected_path = os.path.join(output_dir, non_detected_filename)
                
                non_detected_data = {
                    "category_metadata": {
                        "domain_category": category_name,
                        "vm_id": vm_metadata.get('instance_id', 'unknown'),
                        "region": vm_metadata.get('region', 'unknown'),
                        "zone": vm_metadata.get('zone', 'unknown'),
                        "instance_name": vm_metadata.get('instance_name', 'unknown'),
                        "external_ip": vm_metadata.get('external_ip', 'unknown'),
                        "internal_ip": vm_metadata.get('internal_ip', 'unknown')
                    },
                    "sampling_analysis": {
                        "total_sampled_domains": len(raw_queried_domains),  # raw (may include duplicates)
                        "distinct_sampled_domains": len(distinct_queried_domains),
                        "successful_dns_queries": len(successful_dig_domains),
                        "failed_dns_queries": len(failed_dig_domains),
                        "filtered_out_domains": []
                    },
                    "threat_detection_analysis": {
                        "total_threat_events": len(getattr(threat_result, 'threat_events', [])),
                        "unique_threat_domains": len(threat_domains),
                        "domains_with_threats": list(threat_domains),
                        "detection_rate_percent": (
                            len(threat_domains) / len(successful_dig_domains) * 100
                        ) if successful_dig_domains else 0
                    },
                    "domain_classification": {
                        "queried_domains": raw_queried_domains,
                        "distinct_queried_domains": distinct_queried_domains,
                        "successful_dig_domains": list(successful_dig_domains),
                        "failed_dig_domains": list(failed_dig_domains),
                        "threat_detected_domains": list(threat_domains),
                        "non_detected_domains": non_detected_domains
                    },
                    "failed_dig_details": {
                        domain: {"error": "DNS resolution failed", "command": f"dig {domain}"}
                        for domain in failed_dig_domains
                    },
                    "analysis_metadata": {
                        "is_dnst_category": 'DNST' in category_name.upper() or 'TUNNELING' in category_name.upper(),
                        "detection_logic": "Threat rate: distinct threat domains / distinct successful DNS domains",
                        "generation_timestamp": datetime.now().astimezone().isoformat()
                    }
                }
                
                with open(non_detected_path, 'w') as f:
                    json.dump(non_detected_data, f, indent=2, default=str)
                
                total_non_detected_files += 1
                logger.info(f"🔍 Generated non-detected domains file: {non_detected_filename} ({len(non_detected_domains)} non-detected)")
        
        # Summary log
        logger.info(f"📊 Generated JSON files summary:")
        logger.info(f"   Threat event files: {total_threat_files}")
        logger.info(f"   DNS logs files: {total_dns_files}")
        logger.info(f"   Non-detected analysis files: {total_non_detected_files}")
        logger.info(f"   Output directory: {output_dir}")
        
    except Exception as e:
        logger.error(f"❌ Error generating category JSON files: {e}")
        logger.debug("Stack trace:", exc_info=True)


def save_v1_compatible_results(threat_results: Dict, dig_results: Dict, output_format: str, mode: str, vm_metadata: Dict) -> None:
    """
    Save analysis results to files in v1-compatible format including all JSON files.
    
    Args:
        threat_results (Dict): Results from threat detection per category
        dig_results (Dict): Results from DNS resolution per category
        output_format (str): Output format ('basic' or 'advanced')
        mode (str): Execution mode
        vm_metadata (Dict): VM metadata for enrichment
    """
    import csv
    
    # Create output directory (same as v1)
    output_dir = Path(CATEGORY_OUTPUT_DIR)
    output_dir.mkdir(exist_ok=True)
    
    # Define CSV headers based on output format (same as v1)
    if output_format == 'advanced':
        csv_headers = [
            "Domain Category",
            "Client DNS Query Domain", 
            "DNS Query in DNS logs",
            "Distinct domains in DNS logs",
            "Total Threat Count",
            "Distinct domain Threat Count", 
            "Detection Rate (%)"
        ]
    else:
        csv_headers = [
            "Domain Category",
            "Client DNS Query Domain",
            "Total Threat Count", 
            "Distinct domain Threat Count",
            "Detection Rate (%)"
        ]
    
    # Build CSV data and calculate totals
    csv_data = []
    total_client_queries = 0
    total_dns_queries = 0
    total_dns_domains = 0
    total_threat_counts = 0
    total_threat_domains = 0
    
    # Process each category
    for category_name, threat_result in threat_results.items():
        dig_result = dig_results.get(category_name)
        if not dig_result:
            logger.warning(f"⚠️ No dig results found for category {category_name}")
            continue
        
        detected_domains = set(threat_result.detected_domains)
        threat_count = len(getattr(threat_result, 'threat_events', []))
        
        # Threat rate: distinct threat domains / distinct successful DNS domains * 100
        client_count = len(dig_result.domains)
        dns_count = len(dig_result.successful_domains)
        dns_domains = len(set(dig_result.successful_domains))
        threat_domains = len(detected_domains)
        detection_rate = (threat_domains / dns_domains * 100) if dns_domains else 0.0
        
        total_client_queries += client_count
        total_dns_queries += dns_count
        total_dns_domains += dns_domains
        total_threat_counts += threat_count
        total_threat_domains += threat_domains
        
        row = {
            "Domain Category": category_name,
            "Client DNS Query Domain": client_count,
            "Total Threat Count": threat_count,
            "Distinct domain Threat Count": threat_domains,
            "Detection Rate (%)": f"{detection_rate:.2f}"
        }
        if output_format == 'advanced':
            row["DNS Query in DNS logs"] = dns_count
            row["Distinct domains in DNS logs"] = dns_domains
        csv_data.append(row)
    
    # Overall threat rate: aggregate distinct threat domains / aggregate distinct DNS domains
    overall_detection_rate = (total_threat_domains / total_dns_domains * 100) if total_dns_domains > 0 else 0.0
    total_row = {
        "Domain Category": "TOTAL",
        "Client DNS Query Domain": total_client_queries,
        "Total Threat Count": total_threat_counts,
        "Distinct domain Threat Count": total_threat_domains,
        "Detection Rate (%)": f"{overall_detection_rate:.2f}"
    }
    if output_format == 'advanced':
        total_row["DNS Query in DNS logs"] = total_dns_queries
        total_row["Distinct domains in DNS logs"] = total_dns_domains
    csv_data.append(total_row)
    
    # Write CSV
    csv_file = output_dir / CATEGORY_OUTPUT_CSV_FILE
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
        writer.writeheader()
        note_row = {}
        for header in csv_headers:
            if header == 'Domain Category':
                note_row[header] = "NOTE: SIMULATION"
            elif header == 'Client DNS Query Domain':
                note_row[header] = "For simulating DNST we are using 1 TLD as input for exfiltration and we get multiple events with same TLD"
            else:
                note_row[header] = ""
        writer.writerow(note_row)
        empty_row = dict.fromkeys(csv_headers, "")
        writer.writerow(empty_row)
        writer.writerows(csv_data)
    logger.info(f"📄 Generated CSV results: {csv_file}")
    
    # Save domain cache
    used_domains = {cat: dig.domains for cat, dig in dig_results.items()}
    save_domain_cache(str(output_dir), used_domains)
    
    # Generate per-category JSON files
    generate_category_json_files(threat_results, dig_results, str(output_dir), vm_metadata)
    
    # Detailed summary
    logger.info("="*80)
    logger.info("📊 THREAT DETECTION SIMULATION SUMMARY")
    logger.info("="*80)
    logger.info("⚠️  NOTE: SIMULATION - For simulating DNST we are using 1 TLD as input for exfiltration and we get multiple events with same TLD")
    logger.info("="*80)
    logger.info(f"📁 CSV file generated: {csv_file}")
    logger.info(f"🎯 Output Format: {output_format.upper()}")
    logger.info("")
    logger.info("📈 Category Breakdown:")
    
    for category_name, threat_result in threat_results.items():
        dig_result = dig_results.get(category_name)
        if not dig_result:
            continue
        detected_domains = set(threat_result.detected_domains)
        threat_count = len(getattr(threat_result, 'threat_events', []))
        client_count = len(dig_result.domains)
        dns_count = len(dig_result.successful_domains)
        dns_domains = len(set(dig_result.successful_domains))
        threat_domains = len(detected_domains)
        detection_rate = (threat_domains / dns_domains * 100) if dns_domains else 0.0
        logger.info(f"{category_name:<20} | Client: {client_count:3} | DNS: {dns_count:3} | DNS Domains: {dns_domains:3} | Threats: {threat_count:3} | Threat Domains: {threat_domains:3} | Threat Rate: {detection_rate:6.2f}%")
    
    logger.info(f"✅ All results saved to: {output_dir}")